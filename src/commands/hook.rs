use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

use scrub_history::allowlist;
use scrub_history::cache;
use scrub_history::entropy::EntropyConfig;
use scrub_history::hook_state;
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

    let files_to_scrub = collect_files_to_scrub(&canonical);

    let fingerprint = cache::compute_config_fingerprint(entropy_cfg.enabled, entropy_cfg.threshold);
    let mut hook_state = hook_state::load(&fingerprint);

    let mut persistent = stats::load().ok();

    for file in &files_to_scrub {
        let file_key = file.display().to_string();
        let skip_bytes = hook_state.file_offsets.get(&file_key).copied();

        let start = Instant::now();
        let result = match jsonl::scrub_jsonl_file(
            file,
            &pattern_set,
            &entropy_cfg,
            &allowlist,
            &blacklist,
            false,
            skip_bytes,
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, file = %file.display(), "failed to scrub file");
                continue;
            }
        };
        hook_state
            .file_offsets
            .insert(file_key.clone(), result.final_size);

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

    hook_state.config_fingerprint = fingerprint;
    if let Err(e) = hook_state::save(&hook_state) {
        warn!(error = %e, "failed to persist hook state");
    }

    if let Some(ref persistent) = persistent
        && let Err(e) = stats::save(persistent)
    {
        warn!(error = %e, "failed to persist hook stats");
    }

    Ok(())
}

/// Collect the main transcript and any subagent JSONL files for scrubbing.
///
/// Claude Code stores subagents at `{project}/{conversation-id}/subagents/*.jsonl`
/// where the conversation transcript is `{project}/{conversation-id}.jsonl`.
fn collect_files_to_scrub(transcript: &std::path::Path) -> Vec<PathBuf> {
    let mut files = vec![transcript.to_path_buf()];

    if let Some(parent_dir) = transcript.parent()
        && let Some(stem) = transcript.file_stem()
    {
        let subagents_dir = parent_dir.join(stem).join("subagents");
        if subagents_dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(&subagents_dir)
        {
            for entry in entries.filter_map(Result::ok) {
                let p = entry.path();
                if p.extension().is_some_and(|ext| ext == "jsonl") {
                    files.push(p);
                }
            }
        }
    }

    files
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn collect_files_finds_subagents_in_session_subdirectory() {
        let tmp = TempDir::new().unwrap();
        let project_dir = tmp.path();

        // Create: {project}/abc-123.jsonl
        let transcript = project_dir.join("abc-123.jsonl");
        fs::write(&transcript, "{}").unwrap();

        // Create: {project}/abc-123/subagents/agent-x.jsonl
        let subagents_dir = project_dir.join("abc-123").join("subagents");
        fs::create_dir_all(&subagents_dir).unwrap();
        let agent_file = subagents_dir.join("agent-x.jsonl");
        fs::write(&agent_file, "{}").unwrap();
        let agent_file2 = subagents_dir.join("agent-y.jsonl");
        fs::write(&agent_file2, "{}").unwrap();

        let files = collect_files_to_scrub(&transcript);
        assert_eq!(files.len(), 3);
        assert_eq!(files[0], transcript);
        let mut subagent_files: Vec<_> = files[1..].to_vec();
        subagent_files.sort();
        assert_eq!(subagent_files[0], agent_file);
        assert_eq!(subagent_files[1], agent_file2);
    }

    #[test]
    fn collect_files_ignores_non_jsonl_in_subagents() {
        let tmp = TempDir::new().unwrap();
        let project_dir = tmp.path();

        let transcript = project_dir.join("abc-123.jsonl");
        fs::write(&transcript, "{}").unwrap();

        let subagents_dir = project_dir.join("abc-123").join("subagents");
        fs::create_dir_all(&subagents_dir).unwrap();
        fs::write(subagents_dir.join("agent-x.jsonl"), "{}").unwrap();
        fs::write(subagents_dir.join("notes.txt"), "{}").unwrap();

        let files = collect_files_to_scrub(&transcript);
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn collect_files_works_without_subagents_dir() {
        let tmp = TempDir::new().unwrap();
        let transcript = tmp.path().join("abc-123.jsonl");
        fs::write(&transcript, "{}").unwrap();

        let files = collect_files_to_scrub(&transcript);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], transcript);
    }

    #[test]
    fn collect_files_does_not_use_parent_subagents_dir() {
        // Regression: the old code looked at {parent}/subagents/ instead of
        // {parent}/{stem}/subagents/, which would never find the right files.
        let tmp = TempDir::new().unwrap();
        let project_dir = tmp.path();

        let transcript = project_dir.join("abc-123.jsonl");
        fs::write(&transcript, "{}").unwrap();

        // Create a WRONG-location subagents dir at {project}/subagents/
        let wrong_dir = project_dir.join("subagents");
        fs::create_dir_all(&wrong_dir).unwrap();
        fs::write(wrong_dir.join("agent-wrong.jsonl"), "{}").unwrap();

        let files = collect_files_to_scrub(&transcript);
        // Should NOT pick up agent-wrong.jsonl from the wrong directory
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], transcript);
    }
}
