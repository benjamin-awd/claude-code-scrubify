use rayon::prelude::*;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

use crate::entropy::EntropyConfig;
use crate::jsonl::{self, LineDiff};
use crate::patterns::PatternSet;

pub fn run_scan(dry_run: bool, no_truncate: bool, entropy_cfg: &EntropyConfig) {
    let projects_dir = match std::env::var_os("HOME").map(PathBuf::from) {
        Some(home) => home.join(".claude").join("projects"),
        None => {
            error!("HOME not set");
            std::process::exit(1);
        }
    };

    if !projects_dir.exists() {
        warn!(path = %projects_dir.display(), "no projects directory found");
        return;
    }

    let jsonl_files: Vec<PathBuf> = WalkDir::new(&projects_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "jsonl")
        })
        .map(|e| e.into_path())
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
            std::process::exit(1);
        }
    };

    let files_modified = AtomicU64::new(0);
    let redaction_counts: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    let errors = AtomicU64::new(0);

    jsonl_files.par_iter().for_each(|path| {
        match jsonl::scrub_jsonl_file(path, &pattern_set, entropy_cfg, dry_run) {
            Ok(result) => {
                if !result.redactions.is_empty() {
                    files_modified.fetch_add(1, Ordering::Relaxed);
                    let mut counts = redaction_counts.lock().unwrap();
                    for r in &result.redactions {
                        *counts.entry(r.pattern_name.clone()).or_insert(0) += 1;
                    }
                    info!(
                        count = result.redactions.len(),
                        file = %path.display(),
                        "redaction(s) found"
                    );
                    if dry_run && !result.diffs.is_empty() {
                        print_unified_diff(path, &result.diffs, no_truncate);
                    }
                    for r in &result.redactions {
                        let preview = truncate_secret(&r.matched_text, 40);
                        debug!(pattern = %r.pattern_name, preview, "matched secret");
                    }
                }
            }
            Err(e) => {
                error!(file = %path.display(), error = %e, "failed to process file");
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    let modified = files_modified.load(Ordering::Relaxed);
    let errs = errors.load(Ordering::Relaxed);
    let counts = redaction_counts.lock().unwrap();

    info!(
        files_scanned = total_files,
        files_modified = modified,
        errors = errs,
        "scan complete"
    );

    if !counts.is_empty() {
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by_key(|&(_, count)| Reverse(count));
        for (name, count) in sorted {
            info!(pattern = %name, count, "redactions by pattern");
        }
    }
}

fn print_unified_diff(path: &Path, diffs: &[LineDiff], no_truncate: bool) {
    let path_str = path.display();
    eprintln!("\x1b[1m  {path_str}\x1b[0m");
    for diff in diffs {
        for r in &diff.redactions {
            let preview = if no_truncate {
                r.matched_text.replace('\n', "\\n").replace('\r', "\\r")
            } else {
                truncate_secret(&r.matched_text, 40)
            };
            eprintln!(
                "    L{}: \x1b[31m{preview}\x1b[0m → \x1b[32m[REDACTED:{}]\x1b[0m",
                diff.line_number, r.pattern_name,
            );
        }
    }
}

/// Show the first `max_len` chars, masking the middle portion to avoid
/// printing full secrets to the terminal while still being identifiable.
fn truncate_secret(s: &str, max_len: usize) -> String {
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
