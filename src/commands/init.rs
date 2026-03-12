use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use scrub_history::display::{BOLD, GREEN, RESET};

#[derive(Serialize, Deserialize, Default)]
struct ScrubberConfig {
    #[serde(default)]
    allowlist: AllowlistConfig,
}

#[derive(Serialize, Deserialize, Default)]
struct AllowlistConfig {
    #[serde(default)]
    hashes: Vec<String>,
}

const HOOK_COMMAND: &str = "scrub-history hook";

fn build_hook_entry(async_hook: bool) -> serde_json::Value {
    let mut hook = serde_json::json!({
        "type": "command",
        "command": HOOK_COMMAND
    });
    if async_hook {
        hook.as_object_mut()
            .unwrap()
            .insert("async".into(), serde_json::Value::Bool(true));
    }
    serde_json::json!({
        "matcher": "",
        "hooks": [hook]
    })
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

    println!();

    println!("{BOLD}Configuring scrub-history...{RESET}");
    println!();

    // Step 1: Ask whether the hook should run in the background
    let async_hook = prompt_yes_no(
        "Run hook in the background (async)? If no, Claude waits for scrubbing to finish",
        true,
    )?;

    // Step 2: Install hook
    let settings_path = claude_dir.join("settings.json");
    install_hook(&settings_path, async_hook)?;

    // Step 3: Write config
    println!();
    let config_path = claude_dir.join("scrubber.toml");
    write_config(&config_path)?;

    println!();
    Ok(())
}

#[allow(clippy::print_stdout)]
fn install_hook(settings_path: &Path, async_hook: bool) -> Result<()> {
    let mut root: serde_json::Value = if settings_path.exists() {
        let data = std::fs::read_to_string(settings_path).context("reading settings.json")?;
        serde_json::from_str(&data).context("parsing settings.json")?
    } else {
        // Ensure parent directory exists
        if let Some(parent) = settings_path.parent() {
            std::fs::create_dir_all(parent).context("creating ~/.claude directory")?;
        }
        serde_json::json!({})
    };

    let hooks = root
        .as_object_mut()
        .context("settings.json root is not an object")?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));

    let stop_hooks = hooks
        .as_object_mut()
        .context("hooks is not an object")?
        .entry("Stop")
        .or_insert_with(|| serde_json::json!([]));

    let stop_array = stop_hooks
        .as_array_mut()
        .context("hooks.Stop is not an array")?;

    // Check if our hook already exists
    let already_installed = stop_array.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(|h| h.as_array())
            .is_some_and(|hooks| {
                hooks.iter().any(|h| {
                    h.get("command").and_then(serde_json::Value::as_str) == Some(HOOK_COMMAND)
                })
            })
    });

    if already_installed {
        println!(
            "2. Hook already present in {} {GREEN}\u{2713}{RESET}",
            settings_path.display(),
        );
    } else {
        stop_array.push(build_hook_entry(async_hook));
        let pretty = serde_json::to_string_pretty(&root).context("serializing settings.json")?;
        std::fs::write(settings_path, pretty.as_bytes()).context("writing settings.json")?;
        let mode = if async_hook { "async" } else { "sync" };
        println!(
            "2. Hook installed ({mode}) in {} {GREEN}\u{2713}{RESET}",
            settings_path.display(),
        );
    }

    Ok(())
}

#[allow(clippy::print_stdout)]
fn write_config(config_path: &Path) -> Result<()> {
    // Preserve existing allowlist hashes if the file already exists
    let existing_hashes: Vec<String> = if config_path.exists() {
        let data =
            std::fs::read_to_string(config_path).context("reading existing scrubber.toml")?;
        let existing: ScrubberConfig = toml::from_str(&data).unwrap_or_default();
        existing.allowlist.hashes
    } else {
        Vec::new()
    };

    let config = ScrubberConfig {
        allowlist: AllowlistConfig {
            hashes: existing_hashes,
        },
    };

    let toml_str = toml::to_string_pretty(&config).context("serializing scrubber.toml")?;
    std::fs::write(config_path, toml_str.as_bytes()).context("writing scrubber.toml")?;

    println!(
        "3. Writing config to {} {GREEN}\u{2713}{RESET}",
        config_path.display(),
    );

    Ok(())
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

    #[test]
    fn build_hook_entry_sync() {
        let entry = build_hook_entry(false);
        let hooks = entry["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["type"], "command");
        assert_eq!(hooks[0]["command"], HOOK_COMMAND);
        assert!(hooks[0].get("async").is_none());
        assert_eq!(entry["matcher"], "");
    }

    #[test]
    fn build_hook_entry_async() {
        let entry = build_hook_entry(true);
        let hooks = entry["hooks"].as_array().unwrap();
        assert_eq!(hooks[0]["async"], true);
    }

    #[test]
    fn scrubber_config_round_trips_through_toml() {
        let config = ScrubberConfig {
            allowlist: AllowlistConfig {
                hashes: vec!["abc123".into()],
            },
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: ScrubberConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.allowlist.hashes, vec!["abc123"]);
    }

    #[test]
    fn install_hook_creates_new_settings_file() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");

        install_hook(&settings_path, false).unwrap();

        let data = std::fs::read_to_string(&settings_path).unwrap();
        let root: serde_json::Value = serde_json::from_str(&data).unwrap();
        let stop = root["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop.len(), 1);
        assert_eq!(stop[0]["hooks"][0]["command"], HOOK_COMMAND);
    }

    #[test]
    fn install_hook_preserves_existing_settings() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");

        let existing = serde_json::json!({
            "theme": "dark",
            "hooks": {
                "PreToolUse": [{"matcher": "Bash", "hooks": []}]
            }
        });
        std::fs::write(
            &settings_path,
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        install_hook(&settings_path, false).unwrap();

        let data = std::fs::read_to_string(&settings_path).unwrap();
        let root: serde_json::Value = serde_json::from_str(&data).unwrap();
        // Original keys preserved
        assert_eq!(root["theme"], "dark");
        assert!(root["hooks"]["PreToolUse"].is_array());
        // New hook added
        let stop = root["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop.len(), 1);
    }

    #[test]
    fn install_hook_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");

        install_hook(&settings_path, false).unwrap();
        install_hook(&settings_path, false).unwrap();

        let data = std::fs::read_to_string(&settings_path).unwrap();
        let root: serde_json::Value = serde_json::from_str(&data).unwrap();
        let stop = root["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop.len(), 1, "hook should not be duplicated");
    }

    #[test]
    fn write_config_preserves_existing_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("scrubber.toml");

        let existing = ScrubberConfig {
            allowlist: AllowlistConfig {
                hashes: vec!["hash1".into(), "hash2".into()],
            },
        };
        std::fs::write(&config_path, toml::to_string_pretty(&existing).unwrap()).unwrap();

        write_config(&config_path).unwrap();

        let data = std::fs::read_to_string(&config_path).unwrap();
        let parsed: ScrubberConfig = toml::from_str(&data).unwrap();
        assert_eq!(parsed.allowlist.hashes, vec!["hash1", "hash2"]);
    }

    #[test]
    fn write_config_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("scrubber.toml");

        write_config(&config_path).unwrap();

        let data = std::fs::read_to_string(&config_path).unwrap();
        let parsed: ScrubberConfig = toml::from_str(&data).unwrap();
        assert!(parsed.allowlist.hashes.is_empty());
    }
}
