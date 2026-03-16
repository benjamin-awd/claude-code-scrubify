use std::cmp::Reverse;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use scrub_history::allowlist;
use scrub_history::cache;
use scrub_history::entropy::EntropyConfig;
use scrub_history::jsonl::{self, LineDiff};
use scrub_history::patterns::PatternSet;
use scrub_history::stats;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

pub(crate) fn run_scan(fix: bool, no_truncate: bool, no_cache: bool, entropy_cfg: &EntropyConfig) {
    let dry_run = !fix;
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        error!("HOME not set");
        return;
    };
    let projects_dir = home.join(".claude").join("projects");

    if !projects_dir.exists() {
        warn!(path = %projects_dir.display(), "no projects directory found");
        return;
    }

    let jsonl_files: Vec<PathBuf> = WalkDir::new(&projects_dir)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
        .map(walkdir::DirEntry::into_path)
        .collect();

    let total_files = jsonl_files.len();
    info!(
        dry_run,
        total_files,
        path = %projects_dir.display(),
        "scanning JSONL files"
    );

    let pattern_set = match PatternSet::load(false) {
        Ok(ps) => ps,
        Err(e) => {
            error!(error = %e, "failed to load patterns");
            return;
        }
    };

    let settings = match allowlist::load_config() {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to load config");
            return;
        }
    };
    let allowlist = settings.allowlist;
    let blacklist = settings.blacklist;
    let mut entropy_cfg = entropy_cfg.clone();
    entropy_cfg
        .exclude_patterns
        .extend(settings.entropy_exclude_patterns);
    let entropy_cfg = &entropy_cfg;

    // Load mtime-based cache to skip unchanged files
    let fingerprint = cache::compute_config_fingerprint(entropy_cfg.enabled, entropy_cfg.threshold);
    let mut scan_cache = if no_cache {
        cache::ScanCache::default()
    } else {
        cache::load(&fingerprint)
    };

    // Partition into cached (skip) vs uncached (need scan)
    let existing_paths: std::collections::HashSet<String> = jsonl_files
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    let (cached_files, uncached_files): (Vec<&PathBuf>, Vec<&PathBuf>) =
        jsonl_files.iter().partition(|path| {
            let key = path.display().to_string();
            scan_cache
                .entries
                .get(&key)
                .is_some_and(|entry| cache::file_metadata_matches(path, entry))
        });

    let files_cached = cached_files.len() as u64;
    let files_to_scan = uncached_files.len();

    info!(files_to_scan, files_cached, "cache partitioned files");

    let files_modified = AtomicU64::new(0);
    let redaction_counts: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    let errors = AtomicU64::new(0);

    let pb = ProgressBar::new(files_to_scan as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{bar:30.cyan/dim}] {pos}/{len} files ({elapsed} elapsed, {eta} remaining)",
        )
        .expect("valid template")
        .progress_chars("=> "),
    );

    let scan_start = Instant::now();
    uncached_files.par_iter().for_each(|path| {
        match jsonl::scrub_jsonl_file(
            path,
            &pattern_set,
            entropy_cfg,
            &allowlist,
            &blacklist,
            dry_run,
            None,
        ) {
            Ok(result) => {
                if !result.redactions.is_empty() {
                    files_modified.fetch_add(1, Ordering::Relaxed);
                    let mut counts = redaction_counts.lock().unwrap();
                    for r in &result.redactions {
                        *counts.entry(r.pattern_name.clone()).or_insert(0) += 1;
                    }
                    pb.suspend(|| {
                        info!(
                            count = result.redactions.len(),
                            file = %path.display(),
                            "redaction(s) found"
                        );
                        if dry_run && !result.diffs.is_empty() {
                            print_unified_diff(path, &result.diffs, no_truncate);
                        }
                    });
                    for r in &result.redactions {
                        let preview = truncate_secret(&r.matched_text, 40);
                        debug!(pattern = %r.pattern_name, preview, "matched secret");
                    }
                }
            }
            Err(e) => {
                pb.suspend(|| {
                    error!(file = %path.display(), error = %e, "failed to process file");
                });
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        pb.inc(1);
    });
    pb.finish_and_clear();

    #[allow(clippy::cast_possible_truncation)] // duration in ms won't exceed u64
    let duration_ms = scan_start.elapsed().as_millis() as u64;
    let modified = files_modified.load(Ordering::Relaxed);
    let errs = errors.load(Ordering::Relaxed);
    let counts = redaction_counts.lock().unwrap();

    info!(
        files_scanned = files_to_scan,
        files_cached,
        files_modified = modified,
        errors = errs,
        duration_ms,
        "scan complete"
    );

    if !counts.is_empty() {
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by_key(|&(_, count)| Reverse(count));
        for (name, count) in sorted {
            info!(pattern = %name, count, "redactions by pattern");
        }
    }

    // Update cache with new entries for scanned files (skip during dry-run)
    if !dry_run {
        for path in &uncached_files {
            let key = path.display().to_string();
            if let Some(entry) = cache::cache_entry_from_path(path) {
                scan_cache.entries.insert(key, entry);
            }
        }
        // Prune entries for files that no longer exist
        scan_cache.entries.retain(|k, _| existing_paths.contains(k));
        scan_cache.config_fingerprint = fingerprint;

        if let Err(e) = cache::save(&scan_cache) {
            warn!(error = %e, "failed to persist scan cache");
        }
    }

    // Persist stats for `scrub-history status`
    let total_redactions: u64 = counts.values().sum();
    if let Ok(mut persistent) = stats::load() {
        persistent.last_scan = Some(stats::ScanRunStats {
            timestamp_epoch: stats::now_epoch(),
            files_scanned: files_to_scan as u64,
            files_modified: modified,
            total_redactions,
            errors: errs,
            duration_ms,
            dry_run,
            files_cached,
            redactions_by_pattern: counts.clone(),
        });
        if let Err(e) = stats::save(&persistent) {
            warn!(error = %e, "failed to persist scan stats");
        }
    }
}

#[allow(clippy::print_stderr)] // intentional user-facing dry-run output
fn print_unified_diff(path: &Path, diffs: &[LineDiff], no_truncate: bool) {
    use colored::Colorize;

    let path_str = path.display().to_string();
    eprintln!("  {}", path_str.bold());
    for diff in diffs {
        for r in &diff.redactions {
            let preview = if no_truncate {
                r.matched_text.replace('\n', "\\n").replace('\r', "\\r")
            } else {
                truncate_secret(&r.matched_text, 40)
            };
            let redacted = format!("[REDACTED:{}]", r.pattern_name);
            eprintln!(
                "    L{}: {} → {}",
                diff.line_number,
                preview.red(),
                redacted.green(),
            );
        }
    }
}

/// Show the first `max_len` chars, masking the middle portion to avoid
/// printing full secrets to the terminal while still being identifiable.
pub(crate) fn truncate_secret(s: &str, max_len: usize) -> String {
    let s = s.replace('\n', "\\n").replace('\r', "\\r");
    if s.len() <= max_len {
        let visible = s.len().min(8);
        format!("{}...{}", &s[..visible], &s[s.len().saturating_sub(4)..])
    } else {
        let prefix = &s[..8.min(s.len())];
        let suffix = &s[s.len().saturating_sub(4)..];
        format!("{prefix}...{suffix}")
    }
}
