use std::io::Read;
use std::path::{Path, PathBuf};
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
    // Always exit 0 — hook failures block Claude Code. Errors are logged to
    // stderr (the tracing writer); messages never include file contents or
    // hook input values, only paths and error kinds.
    if let Err(e) = run_hook_inner(entropy_cfg) {
        error!(error = %e, "scrub-history hook error");
    }
}

fn run_hook_inner(entropy_cfg: &EntropyConfig) -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let hook_input = parse_hook_input(&input)?;

    // Prevent infinite loops if this hook triggers another stop
    if hook_input.stop_hook_active {
        return Ok(());
    }

    let transcript_path = hook_input
        .transcript_path
        .ok_or_else(|| anyhow::anyhow!("no transcript_path in hook input"))?;

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME not set"))?;
    let projects_root = home.join(".claude").join("projects");

    let path = expand_tilde(&transcript_path, &home);
    if !path.exists() {
        return Ok(());
    }

    let Some((canonical, projects_root)) = validate_transcript_path(&path, &projects_root) else {
        warn!(
            path = %path.display(),
            "transcript path is not a .jsonl file under ~/.claude/projects/, refusing to process"
        );
        return Ok(());
    };

    let pattern_set = PatternSet::load(false)?;
    let settings = allowlist::load_config()?;
    let allowlist = settings.allowlist;
    let blacklist = settings.blacklist;

    // Merge file-based exclude patterns into the CLI-supplied entropy config
    let mut entropy_cfg = entropy_cfg.clone();
    entropy_cfg
        .exclude_patterns
        .extend(settings.entropy_exclude_patterns);

    let files_to_scrub = collect_files_to_scrub(&canonical, &projects_root);

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
                error!(error = %e, file = %file.display(), "failed to scrub file");
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
        error!(error = %e, "failed to persist hook state");
    }

    if let Some(ref persistent) = persistent
        && let Err(e) = stats::save(persistent)
    {
        error!(error = %e, "failed to persist hook stats");
    }

    Ok(())
}

/// Parse the hook's stdin JSON. serde's error messages can echo input values
/// (e.g. `invalid type: string "..."`), so only the position is reported.
fn parse_hook_input(input: &str) -> anyhow::Result<HookInput> {
    serde_json::from_str(input).map_err(|e| {
        anyhow::anyhow!(
            "invalid hook input ({:?} error at line {}, column {})",
            e.classify(),
            e.line(),
            e.column()
        )
    })
}

fn expand_tilde(raw: &str, home: &Path) -> PathBuf {
    match raw.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if raw == "~" => home.to_path_buf(),
        None => PathBuf::from(raw),
    }
}

/// Resolve `path` and check it is a regular `.jsonl` file strictly inside
/// `projects_root` (normally `~/.claude/projects`). Both sides are
/// canonicalized so symlinks and `..` components cannot escape.
///
/// Returns the canonical path and the canonical projects root.
fn validate_transcript_path(path: &Path, projects_root: &Path) -> Option<(PathBuf, PathBuf)> {
    let root = projects_root.canonicalize().ok()?;
    let canonical = path.canonicalize().ok()?;
    is_allowed_transcript(&canonical, &root).then_some((canonical, root))
}

/// `canonical` and `root` must already be canonicalized.
fn is_allowed_transcript(canonical: &Path, root: &Path) -> bool {
    canonical != root
        && canonical.starts_with(root)
        && canonical.extension().is_some_and(|ext| ext == "jsonl")
        && canonical.is_file()
}

/// Collect the main transcript and any subagent JSONL files for scrubbing.
///
/// Claude Code stores subagents at `{project}/{conversation-id}/subagents/*.jsonl`
/// where the conversation transcript is `{project}/{conversation-id}.jsonl`.
/// Every subagent path is canonicalized and must pass the same check as the
/// transcript, so a symlinked `subagents` dir or file cannot escape `root`.
fn collect_files_to_scrub(transcript: &Path, root: &Path) -> Vec<PathBuf> {
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
                if p.extension().is_none_or(|ext| ext != "jsonl") {
                    continue;
                }
                match p.canonicalize() {
                    Ok(c) if is_allowed_transcript(&c, root) => files.push(c),
                    _ => warn!(
                        path = %p.display(),
                        "subagent transcript resolves outside ~/.claude/projects/, skipping"
                    ),
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
        let root = tmp.path().canonicalize().unwrap();
        let project_dir = root.as_path();

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

        let files = collect_files_to_scrub(&transcript, &root);
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
        let root = tmp.path().canonicalize().unwrap();
        let project_dir = root.as_path();

        let transcript = project_dir.join("abc-123.jsonl");
        fs::write(&transcript, "{}").unwrap();

        let subagents_dir = project_dir.join("abc-123").join("subagents");
        fs::create_dir_all(&subagents_dir).unwrap();
        fs::write(subagents_dir.join("agent-x.jsonl"), "{}").unwrap();
        fs::write(subagents_dir.join("notes.txt"), "{}").unwrap();

        let files = collect_files_to_scrub(&transcript, &root);
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn collect_files_works_without_subagents_dir() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let transcript = root.join("abc-123.jsonl");
        fs::write(&transcript, "{}").unwrap();

        let files = collect_files_to_scrub(&transcript, &root);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], transcript);
    }

    #[test]
    fn collect_files_does_not_use_parent_subagents_dir() {
        // Regression: the old code looked at {parent}/subagents/ instead of
        // {parent}/{stem}/subagents/, which would never find the right files.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let project_dir = root.as_path();

        let transcript = project_dir.join("abc-123.jsonl");
        fs::write(&transcript, "{}").unwrap();

        // Create a WRONG-location subagents dir at {project}/subagents/
        let wrong_dir = project_dir.join("subagents");
        fs::create_dir_all(&wrong_dir).unwrap();
        fs::write(wrong_dir.join("agent-wrong.jsonl"), "{}").unwrap();

        let files = collect_files_to_scrub(&transcript, &root);
        // Should NOT pick up agent-wrong.jsonl from the wrong directory
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], transcript);
    }

    /// Build a fake `$HOME` with `.claude/projects/proj/abc.jsonl` and
    /// `.claude/.credentials.json`. Nothing touches the real home dir.
    fn fake_home() -> (TempDir, PathBuf, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().to_path_buf();
        let projects = home.join(".claude").join("projects");
        fs::create_dir_all(projects.join("proj")).unwrap();
        fs::write(projects.join("proj").join("abc.jsonl"), "{}\n").unwrap();
        fs::write(home.join(".claude").join(".credentials.json"), "{}").unwrap();
        (tmp, home, projects)
    }

    #[test]
    fn accepts_jsonl_under_projects() {
        let (_tmp, _home, projects) = fake_home();
        let (canonical, root) =
            validate_transcript_path(&projects.join("proj").join("abc.jsonl"), &projects).unwrap();
        assert!(canonical.starts_with(&root));
        assert_eq!(canonical.file_name().unwrap(), "abc.jsonl");
    }

    #[test]
    fn rejects_credentials_file_under_dot_claude() {
        let (_tmp, home, projects) = fake_home();
        let creds = home.join(".claude").join(".credentials.json");
        assert!(validate_transcript_path(&creds, &projects).is_none());
        // Also via `..` traversal from inside projects.
        let sneaky = projects
            .join("proj")
            .join("..")
            .join("..")
            .join(".credentials.json");
        assert!(validate_transcript_path(&sneaky, &projects).is_none());
    }

    #[test]
    fn rejects_non_jsonl_under_projects() {
        let (_tmp, _home, projects) = fake_home();
        let other = projects.join("proj").join("notes.json");
        fs::write(&other, "{}").unwrap();
        assert!(validate_transcript_path(&other, &projects).is_none());
        // A directory named *.jsonl is not a file.
        let dir = projects.join("proj").join("dir.jsonl");
        fs::create_dir(&dir).unwrap();
        assert!(validate_transcript_path(&dir, &projects).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escaping_projects() {
        let (_tmp, home, projects) = fake_home();
        let outside = home.join("outside.jsonl");
        fs::write(&outside, "{}\n").unwrap();
        let link = projects.join("proj").join("link.jsonl");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(validate_transcript_path(&link, &projects).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn subagents_symlink_cannot_escape_projects() {
        let (_tmp, home, projects) = fake_home();
        let root = projects.canonicalize().unwrap();
        let transcript = root.join("proj").join("abc.jsonl");

        // {proj}/abc/subagents -> ~/.claude (outside projects)
        let escape_target = home.join(".claude").join("evil");
        fs::create_dir_all(&escape_target).unwrap();
        fs::write(escape_target.join("agent.jsonl"), "{}\n").unwrap();
        fs::create_dir_all(root.join("proj").join("abc")).unwrap();
        std::os::unix::fs::symlink(
            &escape_target,
            root.join("proj").join("abc").join("subagents"),
        )
        .unwrap();

        let files = collect_files_to_scrub(&transcript, &root);
        assert_eq!(files, vec![transcript]);
    }

    #[cfg(unix)]
    #[test]
    fn subagent_file_symlink_cannot_escape_projects() {
        let (_tmp, home, projects) = fake_home();
        let root = projects.canonicalize().unwrap();
        let transcript = root.join("proj").join("abc.jsonl");
        let subagents = root.join("proj").join("abc").join("subagents");
        fs::create_dir_all(&subagents).unwrap();
        fs::write(subagents.join("ok.jsonl"), "{}\n").unwrap();
        std::os::unix::fs::symlink(
            home.join(".claude").join(".credentials.json"),
            subagents.join("creds.jsonl"),
        )
        .unwrap();

        let files = collect_files_to_scrub(&transcript, &root);
        assert_eq!(files, vec![transcript, subagents.join("ok.jsonl")]);
    }

    #[test]
    fn expand_tilde_only_expands_home_prefix() {
        let home = Path::new("/h");
        assert_eq!(expand_tilde("~/a.jsonl", home), PathBuf::from("/h/a.jsonl"));
        assert_eq!(expand_tilde("~other/a", home), PathBuf::from("~other/a"));
        assert_eq!(expand_tilde("/abs", home), PathBuf::from("/abs"));
    }

    #[test]
    fn hook_input_errors_do_not_echo_values() {
        let secret = concat!("ghp_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE");
        let input = format!(r#"{{"transcript_path":"/x","stop_hook_active":"{secret}"}}"#);
        let Err(err) = parse_hook_input(&input) else {
            panic!("expected parse error");
        };
        assert!(!format!("{err:#}").contains(secret));
    }
}
