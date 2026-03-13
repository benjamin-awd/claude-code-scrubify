use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

use scrub_history::allowlist;
use scrub_history::entropy::EntropyConfig;
use scrub_history::jsonl;
use scrub_history::patterns::PatternSet;
use scrub_history::stats;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

#[derive(Deserialize)]
struct HookInput {
    transcript_path: Option<String>,
    #[serde(default)]
    stop_hook_active: bool,
}

pub(crate) fn run_hook(entropy_cfg: &EntropyConfig) {
    // Always exit 0 — hook failures block Claude Code
    if let Err(e) = run_hook_inner(entropy_cfg) {
        error!(error = %e, "scrub-history hook error");
    }
}

fn run_hook_inner(entropy_cfg: &EntropyConfig) -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let hook_input: HookInput = serde_json::from_str(&input)?;

    // Prevent infinite loops if this hook triggers another stop
    if hook_input.stop_hook_active {
        return Ok(());
    }

    let transcript_path = hook_input
        .transcript_path
        .ok_or_else(|| anyhow::anyhow!("no transcript_path in hook input"))?;

    // Expand ~ to home directory
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME not set"))?;
    let path = if transcript_path.starts_with('~') {
        PathBuf::from(transcript_path.replacen('~', &home.to_string_lossy(), 1))
    } else {
        PathBuf::from(&transcript_path)
    };

    if !path.exists() {
        return Ok(());
    }

    // Canonicalize to resolve symlinks and ../ components, then validate
    // the path is under ~/.claude/ to prevent arbitrary file writes.
    let canonical = path.canonicalize()?;
    let allowed_prefix = home.join(".claude");
    if !canonical.starts_with(&allowed_prefix) {
        warn!(
            path = %canonical.display(),
            allowed = %allowed_prefix.display(),
            "transcript path is outside ~/.claude/, refusing to process"
        );
        return Ok(());
    }

    let pattern_set = PatternSet::load(false)?;
    let settings = allowlist::load_config()?;
    let allowlist = settings.allowlist;
    let blacklist = settings.blacklist;

    // Merge file-based exclude patterns into the CLI-supplied entropy config
    let mut entropy_cfg = entropy_cfg.clone();
    entropy_cfg
        .exclude_patterns
        .extend(settings.entropy_exclude_patterns);

    // Collect all files to scrub: the main transcript + any subagent transcripts
    let mut files_to_scrub = vec![canonical.clone()];

    // Look for subagent JSONL files in the same session directory
    if let Some(session_dir) = canonical.parent() {
        let subagents_dir = session_dir.join("subagents");
        if subagents_dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(&subagents_dir)
        {
            for entry in entries.filter_map(Result::ok) {
                let p = entry.path();
                if p.extension().is_some_and(|ext| ext == "jsonl") {
                    files_to_scrub.push(p);
                }
            }
        }
    }

    let mut persistent = stats::load().ok();

    for file in &files_to_scrub {
        let start = Instant::now();
        let result = match jsonl::scrub_jsonl_file(
            file,
            &pattern_set,
            &entropy_cfg,
            &allowlist,
            &blacklist,
            false,
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, file = %file.display(), "failed to scrub file");
                continue;
            }
        };
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        let redaction_count = result.redactions.len() as u64;
        if redaction_count > 0 {
            info!(
                count = redaction_count,
                duration_ms,
                file = %file.display(),
                "scrub-history: redacted secret(s)"
            );
            for r in &result.redactions {
                let preview = super::scan::truncate_secret(&r.matched_text, 40);
                debug!(
                    pattern = %r.pattern_name,
                    matched = preview,
                    "redacted"
                );
            }
        }

        if let Some(ref mut persistent) = persistent {
            let file_size_bytes = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
            persistent.push_hook_run(stats::HookRunStats {
                timestamp_epoch: stats::now_epoch(),
                file: file.display().to_string(),
                redactions: redaction_count,
                duration_ms,
                file_size_bytes,
            });
        }
    }

    if let Some(ref persistent) = persistent
        && let Err(e) = stats::save(persistent)
    {
        warn!(error = %e, "failed to persist hook stats");
    }

    Ok(())
}
