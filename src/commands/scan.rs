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

pub(crate) fn run_scan(
    fix: bool,
    no_truncate: bool,
    no_cache: bool,
    jobs: Option<usize>,
    entropy_cfg: &EntropyConfig,
) {
    let num_threads = jobs.unwrap_or_else(|| {
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

/// Printed to stderr once, before the first full secret, under `--no-truncate`.
const NO_TRUNCATE_WARNING: &str = "WARNING: --no-truncate prints FULL SECRET VALUES to your terminal. \
If this runs inside Claude Code (or anything else that records output), those secrets \
will be written to a NEW transcript. Only use it in a plain terminal and clear the scrollback afterwards.";

#[allow(clippy::print_stderr)] // intentional user-facing dry-run output
fn print_unified_diff(path: &Path, diffs: &[LineDiff], no_truncate: bool) {
    use colored::Colorize;
    static WARNED: std::sync::Once = std::sync::Once::new();

    if no_truncate {
        WARNED.call_once(|| eprintln!("{}", NO_TRUNCATE_WARNING.red().bold()));
    }

    for line in diff_lines(path, diffs, no_truncate) {
        eprintln!("{line}");
    }
}

/// Render the dry-run report for one file. Without `no_truncate` this shows
/// only the file, line, pattern name and secret length (see [`secret_preview`]).
fn diff_lines(path: &Path, diffs: &[LineDiff], no_truncate: bool) -> Vec<String> {
    use colored::Colorize;

    let mut out = vec![format!("  {}", path.display().to_string().bold())];
    for diff in diffs {
        for r in &diff.redactions {
            let preview = if no_truncate {
                r.matched_text.replace('\n', "\\n").replace('\r', "\\r")
            } else {
                secret_preview(&r.matched_text)
            };
            let redacted = format!("[REDACTED:{}]", r.pattern_name);
            out.push(format!(
                "    L{}: {} → {}",
                diff.line_number,
                preview.red(),
                redacted.green(),
            ));
        }
    }
    out
}

/// Minimum length (in chars) before any part of a secret is shown.
const PREVIEW_MIN_CHARS: usize = 20;
/// Number of leading chars shown for long secrets.
const PREVIEW_PREFIX_CHARS: usize = 4;

/// Describe a matched secret without revealing it.
///
/// Dry-run output is often captured into a new Claude Code transcript, so this
/// must never print a recoverable secret: secrets shorter than
/// [`PREVIEW_MIN_CHARS`] chars show only their length; longer ones show at most
/// a [`PREVIEW_PREFIX_CHARS`]-char prefix (enough to recognise e.g. `ghp_`).
/// Cuts on `char_indices`, so non-ASCII input never panics.
pub(crate) fn secret_preview(s: &str) -> String {
    let len = s.chars().count();
    if len < PREVIEW_MIN_CHARS {
        return format!("<{len} chars>");
    }
    let cut = s
        .char_indices()
        .nth(PREVIEW_PREFIX_CHARS)
        .map_or(s.len(), |(i, _)| i);
    let prefix: String = s[..cut]
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    format!("{prefix}… <{len} chars>")
}

/// Legacy name kept for existing callers (hook/scan debug logging). Now
/// identical to [`secret_preview`]; `_max_len` is ignored.
pub(crate) fn truncate_secret(s: &str, _max_len: usize) -> String {
    secret_preview(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_secrets_show_only_length() {
        for s in ["", "a", "abcd1234", "abcd1234efgh", "0123456789abcdefghi"] {
            assert_eq!(secret_preview(s), format!("<{} chars>", s.chars().count()));
        }
    }

    #[test]
    fn long_secrets_show_at_most_four_char_prefix() {
        let secret = "sk_fake_0123456789abcdefWXYZ";
        let p = secret_preview(secret);
        assert_eq!(p, format!("sk_f… <{} chars>", secret.len()));
        assert!(!p.contains("WXYZ"), "suffix must not be shown");
    }

    #[test]
    fn non_ascii_does_not_panic() {
        // Multi-byte chars straddling the old byte-slice boundaries (8, len-4).
        assert!(secret_preview("pässwörd-ünïcödé-sëcrét-välüé").starts_with("päss…"));
        assert_eq!(secret_preview("日本語の秘密"), "<6 chars>");
        let long = "\u{1f511}".repeat(25);
        assert_eq!(
            secret_preview(&long),
            format!("{}… <25 chars>", "\u{1f511}".repeat(4))
        );
        // Legacy wrapper used by the hook's debug logging is safe too.
        assert_eq!(truncate_secret("ñññññññññññ", 40), "<11 chars>");
    }

    #[test]
    fn dry_run_report_never_contains_short_or_medium_secrets() {
        use scrub_history::scrubber::Redaction;
        colored::control::set_override(false);
        let short = "pw-12chars!!"; // 12 bytes: old code printed it in full
        let long = "tok_fake_ABCDEFGHIJKLMNOP_tail";
        let diffs = vec![LineDiff {
            line_number: 7,
            redactions: vec![
                Redaction {
                    pattern_name: "blacklist".into(),
                    start: 0,
                    end: short.len(),
                    matched_text: short.into(),
                },
                Redaction {
                    pattern_name: "generic".into(),
                    start: 0,
                    end: long.len(),
                    matched_text: long.into(),
                },
            ],
        }];
        let text = diff_lines(Path::new("/x/s.jsonl"), &diffs, false).join("\n");
        assert!(text.contains("/x/s.jsonl"));
        assert!(
            text.contains("L7: <12 chars> → [REDACTED:blacklist]"),
            "{text}"
        );
        assert!(
            text.contains("tok_… <30 chars> → [REDACTED:generic]"),
            "{text}"
        );
        assert!(!text.contains(short) && !text.contains("tail"), "{text}");

        // --no-truncate shows full values (warning is printed separately).
        let full = diff_lines(Path::new("/x/s.jsonl"), &diffs, true).join("\n");
        assert!(full.contains(short) && full.contains(long));
        assert!(NO_TRUNCATE_WARNING.contains("FULL SECRET VALUES"));
    }

    #[test]
    fn control_chars_are_not_emitted() {
        let p = secret_preview("a\nbcdefghijklmnopqrstuvwxyz");
        assert!(!p.contains('\n'));
        assert!(p.starts_with("a?bc"));
    }
}
