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
