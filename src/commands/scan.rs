use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use scrub_history::allowlist;
use scrub_history::cache;
use scrub_history::entropy::EntropyConfig;
use scrub_history::jsonl::{self, LineDiff};
use scrub_history::locations::{self, Format, Location, LocationSet, Target};
use scrub_history::patterns::PatternSet;
use scrub_history::plaintext::{self, Finding, Outcome};
use scrub_history::stats::{self, LocationRunStats};
use tracing::{debug, error, info, warn};

pub(crate) struct ScanOptions {
    pub(crate) fix: bool,
    pub(crate) no_truncate: bool,
    pub(crate) no_cache: bool,
    pub(crate) jobs: Option<usize>,
    pub(crate) locations: LocationSet,
}

/// Dry-run listing for plain-text files: pattern name and line only, never
/// the matched text.
#[allow(clippy::print_stderr)] // intentional user-facing dry-run output
fn print_plaintext_findings(path: &Path, findings: &[Finding]) {
    use colored::Colorize;
    eprintln!("  {}", path.display().to_string().bold());
    for f in findings {
        let redacted = format!("[REDACTED:{}]", f.pattern_name);
        eprintln!("    L{}: {}", f.line, redacted.green());
    }
}

/// Per-file outcome, reduced to what the summary needs.
enum FileResult {
    Scanned {
        redactions: Vec<String>,
        written: bool,
    },
    Skipped,
}

/// Returns `(result, cacheable)`.
#[allow(clippy::too_many_arguments)]
fn process_target(
    target: &Target,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    allowlist: &allowlist::Allowlist,
    blacklist: &allowlist::Blacklist,
    dry_run: bool,
    no_truncate: bool,
    pb: &ProgressBar,
) -> anyhow::Result<(FileResult, bool)> {
    let path = &target.path;
    match target.format {
        Format::Jsonl => {
            let result = jsonl::scrub_jsonl_file(
                path,
                pattern_set,
                entropy_cfg,
                allowlist,
                blacklist,
                dry_run,
                None,
            )?;
            if !result.redactions.is_empty() {
                pb.suspend(|| {
                    info!(
                        count = result.redactions.len(),
                        location = %target.location,
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
            let written = !dry_run && !result.redactions.is_empty();
            let names = result
                .redactions
                .into_iter()
                .map(|r| r.pattern_name)
                .collect();
            Ok((
                FileResult::Scanned {
                    redactions: names,
                    written,
                },
                true,
            ))
        }
        Format::PlainText => {
            let result = plaintext::scrub_file(
                path,
                pattern_set,
                entropy_cfg,
                allowlist,
                blacklist,
                dry_run,
            )?;
            let names = || {
                result
                    .findings
                    .iter()
                    .map(|f| f.pattern_name.clone())
                    .collect()
            };
            match &result.outcome {
                Outcome::Clean => Ok((
                    FileResult::Scanned {
                        redactions: Vec::new(),
                        written: false,
                    },
                    true,
                )),
                Outcome::Redacted { written } => {
                    pb.suspend(|| {
                        info!(
                            count = result.findings.len(),
                            location = %target.location,
                            file = %path.display(),
                            "redaction(s) found"
                        );
                        if dry_run {
                            print_plaintext_findings(path, &result.findings);
                        }
                    });
                    Ok((
                        FileResult::Scanned {
                            redactions: names(),
                            written: *written,
                        },
                        *written,
                    ))
                }
                Outcome::SkippedBinary | Outcome::SkippedSymlink => {
                    debug!(file = %path.display(), outcome = ?result.outcome, "skipped");
                    Ok((FileResult::Skipped, true))
                }
                Outcome::SkippedTooLarge { size } => {
                    pb.suspend(|| {
                        warn!(
                            file = %path.display(),
                            size,
                            limit = plaintext::MAX_FILE_SIZE,
                            "file too large, skipped"
                        );
                    });
                    Ok((FileResult::Skipped, false))
                }
                Outcome::SkippedWouldBreakJson => {
                    pb.suspend(|| {
                        warn!(
                            file = %path.display(),
                            count = result.findings.len(),
                            "secrets found but redaction would produce invalid JSON; left untouched"
                        );
                    });
                    Ok((FileResult::Skipped, false))
                }
                Outcome::SkippedChanged => {
                    pb.suspend(|| {
                        warn!(file = %path.display(), "file changed during scan; left untouched, rerun to retry");
                    });
                    Ok((FileResult::Skipped, false))
                }
            }
        }
    }
}

fn handle_orphans(orphans: &[locations::Orphan], dry_run: bool, now: SystemTime) -> (u64, u64) {
    let mut removed = 0u64;
    for orphan in orphans {
        let age_mins = orphan.age.map_or(0, |a| a.as_secs() / 60);
        if !orphan.is_stale() {
            info!(
                file = %orphan.path.display(),
                age_mins,
                "orphaned temp file is less than 1h old, leaving it (may be in use)"
            );
            continue;
        }
        if dry_run {
            info!(file = %orphan.path.display(), age_mins, "would delete orphaned temp file");
            continue;
        }
        match locations::remove_stale_orphan(orphan, now) {
            Ok(true) => {
                removed += 1;
                info!(file = %orphan.path.display(), age_mins, "deleted orphaned temp file");
            }
            Ok(false) => debug!(file = %orphan.path.display(), "orphan no longer eligible"),
            Err(e) => warn!(file = %orphan.path.display(), error = %e, "failed to delete orphan"),
        }
    }
    (orphans.len() as u64, removed)
}

fn report_config_files(
    files: &[PathBuf],
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    allowlist: &allowlist::Allowlist,
    blacklist: &allowlist::Blacklist,
) -> u64 {
    let mut total = 0u64;
    for path in files {
        match locations::report_claude_json(path, pattern_set, entropy_cfg, allowlist, blacklist) {
            Ok(findings) => {
                for f in &findings {
                    warn!(
                        file = %path.display(),
                        key = %f.key_path,
                        pattern = %f.pattern_name,
                        "secret-looking value in MCP config (not modified)"
                    );
                }
                total += findings.len() as u64;
            }
            Err(e) => warn!(file = %path.display(), error = %e, "could not inspect config file"),
        }
    }
    if total > 0 {
        warn!(
            "~/.claude.json is never rewritten (that would break your MCP servers). \
             Move these secrets out: reference environment variables instead \
             (e.g. \"env\": {{\"API_TOKEN\": \"${{API_TOKEN}}\"}}) exported from your shell \
             or a keychain helper, rotate the exposed values, then delete stale \
             ~/.claude/backups/.claude.json.backup.* copies"
        );
    }
    total
}

pub(crate) fn run_scan(opts: &ScanOptions, entropy_cfg: &EntropyConfig) {
    let num_threads = opts.jobs.unwrap_or_else(|| {
        (std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(4)
            / 2)
        .max(1)
    });
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .ok(); // may fail if already initialized, that's fine
    info!(threads = num_threads, "thread pool configured");
    let dry_run = !opts.fix;
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        error!("HOME not set");
        return;
    };
    let claude_dir = home.join(".claude");
    let claude_json = home.join(".claude.json");

    let now = SystemTime::now();
    let discovery = locations::discover(&claude_dir, &claude_json, &opts.locations, now);
    for link in &discovery.symlinks_skipped {
        debug!(path = %link.display(), "symlink not followed");
    }

    let total_files = discovery.targets.len();
    info!(
        dry_run,
        total_files,
        locations = %opts.locations.iter().map(Location::name).collect::<Vec<_>>().join(","),
        path = %claude_dir.display(),
        "scanning files"
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
    let mut scan_cache = if opts.no_cache {
        cache::ScanCache::default()
    } else {
        cache::load(&fingerprint)
    };

    let (cached_files, uncached_files): (Vec<&Target>, Vec<&Target>) =
        discovery.targets.iter().partition(|t| {
            let key = t.path.display().to_string();
            scan_cache
                .entries
                .get(&key)
                .is_some_and(|entry| cache::file_metadata_matches(&t.path, entry))
        });

    let mut loc_init: BTreeMap<Location, LocationRunStats> = BTreeMap::new();
    for t in &discovery.targets {
        loc_init.entry(t.location).or_default().files_found += 1;
    }
    for t in &cached_files {
        loc_init.entry(t.location).or_default().files_cached += 1;
    }

    let files_cached = cached_files.len() as u64;
    let files_to_scan = uncached_files.len();

    info!(files_to_scan, files_cached, "cache partitioned files");

    let files_modified = AtomicU64::new(0);
    let redaction_counts: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    let errors = AtomicU64::new(0);
    let by_location: Mutex<BTreeMap<Location, LocationRunStats>> = Mutex::new(loc_init);
    let cacheable: Mutex<Vec<&Path>> = Mutex::new(Vec::new());

    let pb = ProgressBar::new(files_to_scan as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{bar:30.cyan/dim}] {pos}/{len} files ({elapsed} elapsed, {eta} remaining)",
        )
        .expect("valid template")
        .progress_chars("=> "),
    );

    let scan_start = Instant::now();
    uncached_files.par_iter().for_each(|target| {
        let res = process_target(
            target,
            &pattern_set,
            entropy_cfg,
            &allowlist,
            &blacklist,
            dry_run,
            opts.no_truncate,
            &pb,
        );
        let mut locs = by_location.lock().unwrap();
        let loc = locs.entry(target.location).or_default();
        match res {
            Ok((result, can_cache)) => {
                if can_cache {
                    cacheable.lock().unwrap().push(&target.path);
                }
                match result {
                    FileResult::Scanned {
                        redactions,
                        written,
                    } => {
                        loc.files_scanned += 1;
                        if !redactions.is_empty() {
                            // In dry-run, "modified" means "would be modified".
                            if written || dry_run {
                                loc.files_modified += 1;
                                files_modified.fetch_add(1, Ordering::Relaxed);
                            }
                            loc.redactions += redactions.len() as u64;
                            let mut counts = redaction_counts.lock().unwrap();
                            for name in redactions {
                                *counts.entry(name).or_insert(0) += 1;
                            }
                        }
                    }
                    FileResult::Skipped => loc.files_skipped += 1,
                }
            }
            Err(e) => {
                loc.errors += 1;
                pb.suspend(|| {
                    error!(file = %target.path.display(), error = %e, "failed to process file");
                });
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(locs);
        pb.inc(1);
    });
    pb.finish_and_clear();

    #[allow(clippy::cast_possible_truncation)] // duration in ms won't exceed u64
    let duration_ms = scan_start.elapsed().as_millis() as u64;

    let (orphans_found, orphans_removed) = handle_orphans(&discovery.orphans, dry_run, now);
    let config_findings = report_config_files(
        &discovery.config_files,
        &pattern_set,
        entropy_cfg,
        &allowlist,
        &blacklist,
    );

    let modified = files_modified.load(Ordering::Relaxed);
    let errs = errors.load(Ordering::Relaxed);
    let counts = redaction_counts.lock().unwrap();
    let by_location = by_location.into_inner().unwrap();

    for (loc, s) in &by_location {
        info!(
            location = %loc,
            found = s.files_found,
            scanned = s.files_scanned,
            cached = s.files_cached,
            modified = s.files_modified,
            redactions = s.redactions,
            skipped = s.files_skipped,
            errors = s.errors,
            "location summary"
        );
    }

    info!(
        files_scanned = files_to_scan,
        files_cached,
        files_modified = modified,
        errors = errs,
        orphans_found,
        orphans_removed,
        config_findings,
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
        for path in cacheable.into_inner().unwrap() {
            if let Some(entry) = cache::cache_entry_from_path(path) {
                scan_cache.entries.insert(path.display().to_string(), entry);
            }
        }
        // Prune entries for files that no longer exist. Entries for locations
        // skipped this run are kept so re-enabling them stays incremental.
        scan_cache.entries.retain(|k, _| Path::new(k).exists());
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
            by_location: by_location
                .into_iter()
                .map(|(l, s)| (l.name().to_string(), s))
                .collect(),
            config_findings,
            orphans_found,
            orphans_removed,
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
