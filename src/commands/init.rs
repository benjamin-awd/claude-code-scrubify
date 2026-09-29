use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use scrub_history::{allowlist, display, fsutil};
use serde_json::Value;

/// Hook events `init` registers. Every one of these carries `transcript_path`
/// in its stdin payload, which is all `scrub-history hook` needs:
/// - `Stop`: end of each main-agent turn.
/// - `SubagentStop`: a subagent finished (its transcript lives under the
///   session directory, which the hook also scrubs).
/// - `PreCompact`: before the transcript is compacted.
/// - `SessionEnd`: session exit / `/clear`, so interrupted turns still get
///   scrubbed.
pub(crate) const HOOK_EVENTS: &[&str] = &["Stop", "SubagentStop", "PreCompact", "SessionEnd"];

/// Pre-0.5 command, resolved through `PATH`. Recognised so it can be upgraded.
const LEGACY_HOOK_COMMAND: &str = "scrub-history hook";

/// `SessionEnd` hooks share a 1.5s default budget; raising the per-hook
/// timeout raises the budget so large transcripts can finish scrubbing.
const SESSION_END_TIMEOUT_SECS: u64 = 30;

const DEFAULT_CONFIG: &str = r#"# scrub-history configuration.
# This file can contain plaintext secrets (blacklist.strings): keep it private (mode 0600).

[allowlist]
# SHA-256 hex digests of values that should NOT be redacted.
hashes = []

[entropy]
# Regexes for tokens to exclude from entropy-based detection.
exclude_patterns = []

[blacklist]
# Exact strings that are always redacted wherever they appear (min 8 chars by default).
strings = []
# SHA-256 hex digests of values that are always redacted on exact match.
# These are UNSALTED hashes: they only protect high-entropy values. A short or
# guessable password can be recovered from its hash by brute force.
hashes = []

# Custom secret patterns:
# [[patterns]]
# name = "internal-token"
# regex = "itk_[A-Za-z0-9]{32}"
# keywords = ["itk_"]
"#;

/// Whether the hook for `event` may run in the background.
///
/// `PreCompact` stays synchronous so scrubbing finishes before compaction;
/// `SessionEnd` hooks are always synchronous in Claude Code.
fn event_allows_async(event: &str) -> bool {
    matches!(event, "Stop" | "SubagentStop")
}

/// Quote `s` for a POSIX shell (single quotes, `'` escaped as `'\''`).
pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The hook command for a given `scrub-history` binary: its absolute path,
/// shell-quoted, followed by ` hook`.
pub(crate) fn hook_command_for(exe: &Path) -> String {
    format!("{} hook", shell_quote(&exe.to_string_lossy()))
}

/// Hook command for the currently running binary. Uses the canonical absolute
/// path so a different `scrub-history` earlier in `PATH` can't take over the
/// hook (and with it, read every transcript).
fn current_hook_command() -> Result<String> {
    let exe = std::env::current_exe()
        .context("locating the scrub-history binary")?
        .canonicalize()
        .context("resolving the scrub-history binary path")?;
    Ok(hook_command_for(&exe))
}

/// Split a shell command into its first word (unquoted) and the remainder.
pub(crate) fn split_program(cmd: &str) -> (String, &str) {
    let cmd = cmd.trim_start();
    let mut program = String::new();
    let mut chars = cmd.char_indices().peekable();
    let mut end = cmd.len();
    while let Some((i, c)) = chars.next() {
        match c {
            '\'' => {
                for (_, c) in chars.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    program.push(c);
                }
            }
            '"' => {
                while let Some((_, c)) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => {
                            if let Some((_, n)) = chars.next() {
                                program.push(n);
                            }
                        }
                        _ => program.push(c),
                    }
                }
            }
            '\\' => {
                if let Some((_, n)) = chars.next() {
                    program.push(n);
                }
            }
            c if c.is_whitespace() => {
                end = i;
                break;
            }
            _ => program.push(c),
        }
    }
    (program, &cmd[end..])
}

/// True if `cmd` runs `scrub-history hook`, in either the legacy bare form or
/// the absolute-path form (possibly pointing at an older install location).
pub(crate) fn is_scrub_history_hook_command(cmd: &str) -> bool {
    if cmd.trim() == LEGACY_HOOK_COMMAND {
        return true;
    }
    let (program, rest) = split_program(cmd);
    Path::new(&program)
        .file_name()
        .is_some_and(|n| n == "scrub-history")
        && rest.split_whitespace().any(|a| a == "hook")
}

/// True if the command's program is an absolute path (not resolved via PATH).
pub(crate) fn hook_command_is_absolute(cmd: &str) -> bool {
    Path::new(&split_program(cmd).0).is_absolute()
}

fn is_our_hook(h: &Value) -> bool {
    h.get("command")
        .and_then(Value::as_str)
        .is_some_and(is_scrub_history_hook_command)
}

/// A `scrub-history` hook found in settings.json.
pub(crate) struct InstalledHook {
    pub command: String,
    pub is_async: bool,
}

/// Find the first `scrub-history` hook registered for `event`.
pub(crate) fn find_installed_hook(root: &Value, event: &str) -> Option<InstalledHook> {
    root.get("hooks")?
        .get(event)?
        .as_array()?
        .iter()
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .find(|h| is_our_hook(h))
        .map(|h| InstalledHook {
            command: h
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            is_async: h.get("async").and_then(Value::as_bool).unwrap_or(false),
        })
}

fn configure_hook(hook: &mut Value, event: &str, command: &str, async_hook: bool) {
    let Some(obj) = hook.as_object_mut() else {
        return;
    };
    obj.insert("type".into(), Value::from("command"));
    obj.insert("command".into(), Value::from(command));
    if async_hook && event_allows_async(event) {
        obj.insert("async".into(), Value::Bool(true));
    } else {
        obj.remove("async");
    }
    if event == "SessionEnd" && !obj.contains_key("timeout") {
        obj.insert("timeout".into(), Value::from(SESSION_END_TIMEOUT_SECS));
    }
}

fn build_hook_entry(event: &str, command: &str, async_hook: bool) -> Value {
    let mut hook = serde_json::json!({});
    configure_hook(&mut hook, event, command, async_hook);
    serde_json::json!({
        "matcher": "",
        "hooks": [hook]
    })
}

/// What `install_hook` did to one event.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HookChange {
    Added,
    Updated,
    Unchanged,
}

/// Register the hook for every event in [`HOOK_EVENTS`] in `root`.
/// Existing `scrub-history` hooks (legacy bare or old absolute path) are
/// upgraded in place; duplicates are removed.
fn upsert_hooks(root: &mut Value, command: &str, async_hook: bool) -> Result<Vec<HookChange>> {
    let hooks = root
        .as_object_mut()
        .context("settings.json root is not an object")?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .context("`hooks` in settings.json is not an object")?;

    let mut changes = Vec::new();
    for &event in HOOK_EVENTS {
        let arr = hooks
            .entry(event)
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
            .with_context(|| format!("`hooks.{event}` in settings.json is not an array"))?;

        let mut change = None;
        let mut emptied = Vec::new();
        for (i, entry) in arr.iter_mut().enumerate() {
            let Some(entry_hooks) = entry.get_mut("hooks").and_then(Value::as_array_mut) else {
                continue;
            };
            let before = entry_hooks.len();
            entry_hooks.retain_mut(|h| {
                if !is_our_hook(h) {
                    return true;
                }
                if change.is_some() {
                    return false; // duplicate
                }
                let old = h.clone();
                configure_hook(h, event, command, async_hook);
                change = Some(if *h == old {
                    HookChange::Unchanged
                } else {
                    HookChange::Updated
                });
                true
            });
            if entry_hooks.len() != before {
                change = Some(HookChange::Updated);
                if entry_hooks.is_empty() {
                    emptied.push(i);
                }
            }
        }
        for i in emptied.into_iter().rev() {
            arr.remove(i);
        }
        let change = change.unwrap_or_else(|| {
            arr.push(build_hook_entry(event, command, async_hook));
            HookChange::Added
        });
        changes.push(change);
    }
    Ok(changes)
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
pub(crate) fn run_init() {
    if !std::io::stdin().is_terminal() {
        eprintln!("error: `scrub-history init` requires an interactive terminal");
        return;
    }

    if let Err(e) = run_init_inner() {
        eprintln!("error: {e:#}");
    }
}

#[allow(clippy::print_stdout)]
fn run_init_inner() -> Result<()> {
    let home = home_dir()?;
    let claude_dir = home.join(".claude");
    let hook_command = current_hook_command()?;

    println!();

    println!("{}", "Configuring scrub-history...".bold());
    println!();

    // Step 1: Ask whether the hook should run in the background
    let async_hook = prompt_yes_no(
        "Run the Stop/SubagentStop hooks in the background (async)? If no, Claude waits for scrubbing to finish",
        true,
    )?;

    // Step 2: Install hooks
    let settings_path = claude_dir.join("settings.json");
    let (changes, backup) = install_hook(&settings_path, async_hook, &hook_command)?;
    if changes.iter().all(|c| *c == HookChange::Unchanged) {
        println!(
            "2. Hooks already up to date in {} {}",
            settings_path.display(),
            "\u{2713}".green(),
        );
    } else {
        println!(
            "2. Hooks installed in {} {}",
            settings_path.display(),
            "\u{2713}".green(),
        );
        for (event, change) in HOOK_EVENTS.iter().zip(&changes) {
            let what = match change {
                HookChange::Added => "added",
                HookChange::Updated => "updated",
                HookChange::Unchanged => "unchanged",
            };
            println!("   {event:<13} {what}");
        }
        println!("   command: {hook_command}");
        if let Some(backup) = backup {
            println!("   backup:  {}", backup.display());
        }
    }

    // Step 3: Write config
    println!();
    let config_path = claude_dir.join("scrubber.toml");
    write_config(&config_path)?;
    println!(
        "3. Writing config to {} (mode 0600) {}",
        config_path.display(),
        "\u{2713}".green(),
    );

    println!();
    Ok(())
}

/// Install/upgrade the hooks in `settings_path`.
///
/// If the file changes, a timestamped backup is written first, then the new
/// contents replace it atomically (temp file + rename) with the original
/// permissions and key order preserved. Returns per-event changes and the
/// backup path, if one was made.
fn install_hook(
    settings_path: &Path,
    async_hook: bool,
    hook_command: &str,
) -> Result<(Vec<HookChange>, Option<PathBuf>)> {
    let original = match std::fs::read_to_string(settings_path) {
        Ok(d) => Some(d),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).context("reading settings.json"),
    };
    let mut root: Value = match &original {
        Some(data) if !data.trim().is_empty() => {
            serde_json::from_str(data).context("parsing settings.json (left unchanged)")?
        }
        _ => serde_json::json!({}),
    };

    let changes = upsert_hooks(&mut root, hook_command, async_hook)?;

    let mut pretty = serde_json::to_string_pretty(&root).context("serializing settings.json")?;
    pretty.push('\n');
    if original.as_deref() == Some(pretty.as_str()) {
        return Ok((changes, None));
    }

    let backup = if original.is_some() {
        Some(backup_file(settings_path)?)
    } else {
        if let Some(parent) = settings_path.parent() {
            std::fs::create_dir_all(parent).context("creating ~/.claude directory")?;
        }
        None
    };
    let mode = fsutil::file_mode(settings_path).unwrap_or(fsutil::PRIVATE_MODE);
    fsutil::write_atomic(settings_path, pretty.as_bytes(), mode)
        .context("writing settings.json")?;
    Ok((changes, backup))
}

/// Copy `path` to `path.bak-YYYYMMDD-HHMMSS[-N]` (permissions preserved).
fn backup_file(path: &Path) -> Result<PathBuf> {
    let stamp = display::format_epoch_compact(display::now_epoch());
    let name = path.file_name().map_or_else(
        || "settings.json".into(),
        |n| n.to_string_lossy().into_owned(),
    );
    let mut backup = path.with_file_name(format!("{name}.bak-{stamp}"));
    let mut n = 1;
    while backup.exists() {
        backup = path.with_file_name(format!("{name}.bak-{stamp}-{n}"));
        n += 1;
    }
    std::fs::copy(path, &backup)
        .with_context(|| format!("backing up {} to {}", path.display(), backup.display()))?;
    Ok(backup)
}

/// Ensure `scrubber.toml` exists with the standard sections, preserving every
/// existing key, comment and custom pattern. Refuses to touch a file that
/// isn't valid TOML. The file is (re)written with mode 0600.
fn write_config(config_path: &Path) -> Result<()> {
    let mut doc: toml_edit::DocumentMut = match std::fs::read_to_string(config_path) {
        Ok(data) => match data.parse() {
            Ok(doc) => doc,
            Err(e) => {
                let e: toml_edit::TomlError = e;
                bail!(
                    "{} is not valid TOML ({}). Refusing to modify it; fix the file \
                     (or move it aside) and re-run `scrub-history init`",
                    config_path.display(),
                    allowlist::describe_toml_error(&data, e.message(), e.span()),
                );
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DEFAULT_CONFIG
            .parse()
            .context("parsing built-in config template")?,
        Err(e) => return Err(e).context("reading existing scrubber.toml"),
    };

    for (section, key) in [
        ("allowlist", "hashes"),
        ("entropy", "exclude_patterns"),
        ("blacklist", "strings"),
        ("blacklist", "hashes"),
    ] {
        let item = doc.entry(section).or_insert_with(toml_edit::table);
        if let Some(table) = item.as_table_like_mut()
            && !table.contains_key(key)
        {
            table.insert(key, toml_edit::value(toml_edit::Array::new()));
        }
    }

    fsutil::write_private_atomic(config_path, doc.to_string().as_bytes())
        .context("writing scrubber.toml")
}

#[allow(clippy::print_stdout)]
fn prompt_yes_no(question: &str, default: bool) -> Result<bool> {
    use std::io::Write;
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    print!("{question} {hint} ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();
    Ok(if answer.is_empty() {
        default
    } else {
        answer.starts_with('y')
    })
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME environment variable not set")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD: &str = "'/opt/scrub history/bin/scrub-history' hook";

    fn read_json(path: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn our_hooks(root: &Value, event: &str) -> Vec<Value> {
        root["hooks"][event]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|e| e["hooks"].as_array().unwrap().clone())
            .filter(is_our_hook)
            .collect()
    }

    fn backups(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().contains(".bak-"))
            .collect()
    }

    #[test]
    fn hook_command_is_quoted_absolute_path() {
        let cmd = hook_command_for(Path::new("/Users/o'neil/My Bin/scrub-history"));
        assert_eq!(cmd, r"'/Users/o'\''neil/My Bin/scrub-history' hook");
        let (program, rest) = split_program(&cmd);
        assert_eq!(program, "/Users/o'neil/My Bin/scrub-history");
        assert_eq!(rest.trim(), "hook");
        assert!(hook_command_is_absolute(&cmd));
        assert!(is_scrub_history_hook_command(&cmd));
    }

    #[test]
    fn recognises_legacy_and_other_forms() {
        assert!(is_scrub_history_hook_command("scrub-history hook"));
        assert!(!hook_command_is_absolute("scrub-history hook"));
        assert!(is_scrub_history_hook_command(
            "/usr/local/bin/scrub-history hook"
        ));
        assert!(is_scrub_history_hook_command(
            "\"/a b/scrub-history\" -q hook"
        ));
        assert!(!is_scrub_history_hook_command("scrub-history scan"));
        assert!(!is_scrub_history_hook_command("/bin/other-tool hook"));
    }

    #[test]
    fn install_hook_registers_all_events_with_absolute_command() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");

        let (changes, backup) = install_hook(&settings_path, true, CMD).unwrap();
        assert!(changes.iter().all(|c| *c == HookChange::Added));
        assert!(backup.is_none());

        let root = read_json(&settings_path);
        for event in HOOK_EVENTS {
            let hooks = our_hooks(&root, event);
            assert_eq!(hooks.len(), 1, "{event}");
            assert_eq!(hooks[0]["command"], CMD);
            assert_eq!(hooks[0]["type"], "command");
            assert_eq!(root["hooks"][event][0]["matcher"], "");
        }
        assert_eq!(our_hooks(&root, "Stop")[0]["async"], true);
        assert_eq!(our_hooks(&root, "SubagentStop")[0]["async"], true);
        assert!(our_hooks(&root, "PreCompact")[0].get("async").is_none());
        let session_end = &our_hooks(&root, "SessionEnd")[0];
        assert!(session_end.get("async").is_none());
        assert_eq!(session_end["timeout"], SESSION_END_TIMEOUT_SECS);
    }

    #[test]
    fn install_hook_sync_mode_has_no_async() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        install_hook(&settings_path, false, CMD).unwrap();
        let root = read_json(&settings_path);
        assert!(our_hooks(&root, "Stop")[0].get("async").is_none());
    }

    #[test]
    fn install_hook_upgrades_legacy_command_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        let existing = serde_json::json!({
            "hooks": {
                "Stop": [
                    {"matcher": "", "hooks": [
                        {"type": "command", "command": "echo before"},
                        {"type": "command", "command": "scrub-history hook", "async": true}
                    ]},
                    {"matcher": "", "hooks": [
                        {"type": "command", "command": "/old/place/scrub-history hook"}
                    ]}
                ]
            }
        });
        std::fs::write(&settings_path, existing.to_string()).unwrap();

        let (changes, _) = install_hook(&settings_path, true, CMD).unwrap();
        assert_eq!(changes[0], HookChange::Updated);

        let root = read_json(&settings_path);
        let stop = root["hooks"]["Stop"].as_array().unwrap();
        // Upgraded in place (same entry, same position), duplicate entry removed.
        assert_eq!(stop.len(), 1);
        assert_eq!(stop[0]["hooks"][0]["command"], "echo before");
        assert_eq!(stop[0]["hooks"][1]["command"], CMD);
        assert_eq!(our_hooks(&root, "Stop").len(), 1);
    }

    #[test]
    fn install_hook_is_idempotent_and_skips_write_when_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");

        install_hook(&settings_path, false, CMD).unwrap();
        let first = std::fs::read_to_string(&settings_path).unwrap();
        let (changes, backup) = install_hook(&settings_path, false, CMD).unwrap();

        assert!(changes.iter().all(|c| *c == HookChange::Unchanged));
        assert!(backup.is_none());
        assert_eq!(std::fs::read_to_string(&settings_path).unwrap(), first);
        assert!(backups(dir.path()).is_empty());
        for event in HOOK_EVENTS {
            assert_eq!(our_hooks(&read_json(&settings_path), event).len(), 1);
        }
    }

    #[test]
    fn install_hook_backs_up_and_preserves_order_keys_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        let original = r#"{
  "theme": "dark",
  "model": "opus",
  "hooks": {
    "PreToolUse": [{"matcher": "Bash", "hooks": []}]
  },
  "apiKeyHelper": "x"
}"#;
        std::fs::write(&settings_path, original).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&settings_path, std::fs::Permissions::from_mode(0o640))
                .unwrap();
        }

        let (_, backup) = install_hook(&settings_path, false, CMD).unwrap();

        let backup = backup.expect("backup should be written");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), original);
        assert_eq!(backups(dir.path()), vec![backup]);

        let data = std::fs::read_to_string(&settings_path).unwrap();
        let root: Value = serde_json::from_str(&data).unwrap();
        let keys: Vec<_> = root.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, vec!["theme", "model", "hooks", "apiKeyHelper"]);
        let hook_keys: Vec<_> = root["hooks"].as_object().unwrap().keys().cloned().collect();
        assert_eq!(hook_keys[0], "PreToolUse");
        assert!(root["hooks"]["PreToolUse"].is_array());
        #[cfg(unix)]
        assert_eq!(fsutil::file_mode(&settings_path), Some(0o640));
    }

    #[test]
    fn install_hook_refuses_invalid_settings_json() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        std::fs::write(&settings_path, "{ not json").unwrap();
        assert!(install_hook(&settings_path, false, CMD).is_err());
        assert_eq!(
            std::fs::read_to_string(&settings_path).unwrap(),
            "{ not json"
        );
        assert!(backups(dir.path()).is_empty());
    }

    #[test]
    fn find_installed_hook_reports_command_and_mode() {
        let mut root = serde_json::json!({});
        upsert_hooks(&mut root, CMD, true).unwrap();
        let h = find_installed_hook(&root, "Stop").unwrap();
        assert_eq!(h.command, CMD);
        assert!(h.is_async);
        assert!(find_installed_hook(&serde_json::json!({}), "Stop").is_none());
    }

    #[test]
    fn write_config_preserves_custom_patterns_and_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("scrubber.toml");
        let original = r#"# my notes
[allowlist]
hashes = ["hash1", "hash2"]

[blacklist]
strings = ["blacklisted1"] # keep me
min_string_length = 12

[[patterns]]
name = "internal-token"
regex = "itk_[A-Za-z0-9]{32}"
keywords = ["itk_"]
secret_group = 0

[future_section]
some_key = true
"#;
        std::fs::write(&config_path, original).unwrap();

        write_config(&config_path).unwrap();

        let data = std::fs::read_to_string(&config_path).unwrap();
        // Everything original is still there verbatim (only missing keys added).
        for line in original.lines().filter(|l| !l.is_empty()) {
            assert!(data.contains(line), "lost line {line:?} in:\n{data}");
        }
        let settings = allowlist::load_config_from(&config_path);
        assert!(settings.config_errors.is_empty());
        assert_eq!(settings.custom_patterns.len(), 1);
        assert_eq!(settings.custom_patterns[0].name, "internal-token");
        assert_eq!(settings.allowlist.len(), 2);
        let parsed: toml::Table = toml::from_str(&data).unwrap();
        assert_eq!(
            parsed["blacklist"]["min_string_length"].as_integer(),
            Some(12)
        );
        assert!(parsed["blacklist"]["hashes"].as_array().unwrap().is_empty());
        assert!(parsed["entropy"]["exclude_patterns"].is_array());
        assert_eq!(parsed["future_section"]["some_key"].as_bool(), Some(true));
    }

    #[test]
    fn write_config_refuses_invalid_toml_and_leaves_file_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("scrubber.toml");
        let broken = "[blacklist]\nstrings = [\"do-not-print-this-secret\"\n";
        std::fs::write(&config_path, broken).unwrap();

        let err = write_config(&config_path).unwrap_err().to_string();

        assert!(err.contains("Refusing"), "{err}");
        assert!(err.contains("line"), "{err}");
        assert!(!err.contains("do-not-print-this-secret"), "{err}");
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), broken);
    }

    #[cfg(unix)]
    #[test]
    fn write_config_creates_private_file_and_tightens_existing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("scrubber.toml");

        write_config(&config_path).unwrap();
        assert_eq!(fsutil::file_mode(&config_path), Some(0o600));
        let data = std::fs::read_to_string(&config_path).unwrap();
        assert!(data.contains("UNSALTED"));
        assert!(
            allowlist::load_config_from(&config_path)
                .config_errors
                .is_empty()
        );

        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_config(&config_path).unwrap();
        assert_eq!(fsutil::file_mode(&config_path), Some(0o600));
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), data);
    }
}
