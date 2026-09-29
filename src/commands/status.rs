use std::path::{Path, PathBuf};

use anyhow::Result;
use colored::Colorize;
use scrub_history::allowlist::{self, ScrubberSettings};
use scrub_history::display;
use scrub_history::fsutil;
use scrub_history::patterns::PatternSet;
use scrub_history::stats;
use walkdir::WalkDir;

use super::init::{HOOK_EVENTS, find_installed_hook, hook_command_is_absolute};

#[allow(clippy::print_stdout, clippy::print_stderr)]
pub(crate) fn run_status() {
    if let Err(e) = run_status_inner() {
        eprintln!("error: {e:#}");
    }
}

#[allow(clippy::print_stdout, clippy::cast_precision_loss)]
fn run_status_inner() -> Result<()> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME not set"))?;
    let claude_dir = home.join(".claude");

    // Header
    println!(
        "\n{} {}",
        "scrub-history".bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed()
    );

    // ── Hook Configuration ──────────────────────────
    display::section("Hook Configuration");

    let settings_path = claude_dir.join("settings.json");
    for (key, value) in hook_report(&settings_path) {
        display::kv(&key, value);
    }

    // ── Config ──────────────────────────────────────
    display::section("Config");

    let config_path = claude_dir.join("scrubber.toml");
    let settings = allowlist::load_config_from(&config_path);
    for (key, value) in config_report(&config_path, &settings) {
        display::kv(&key, value);
    }

    // ── Detection ───────────────────────────────────
    display::section("Detection");

    match PatternSet::load(true) {
        Ok(ps) => {
            let builtin = ps.patterns.len();
            match PatternSet::load(false) {
                Ok(full) => {
                    let custom = full.patterns.len() - builtin;
                    if custom > 0 {
                        display::kv(
                            "Patterns",
                            format!(
                                "{builtin} built-in + {custom} custom = {} total",
                                full.patterns.len()
                            ),
                        );
                    } else {
                        display::kv("Patterns", format!("{builtin} built-in"));
                    }
                }
                Err(_) => display::kv("Patterns", format!("{builtin} built-in")),
            }
        }
        Err(e) => display::kv(
            "Patterns",
            format!("{}", format!("error loading: {e}").red()),
        ),
    }

    let count = settings.allowlist.len();
    if count > 0 {
        display::kv(
            "Allowlist",
            format!("{count} hash{}", if count == 1 { "" } else { "es" }),
        );
    } else {
        display::kv("Allowlist", "empty".dimmed());
    }
    let ep_count = settings.entropy_exclude_patterns.len();
    if ep_count > 0 {
        display::kv(
            "Entropy exclusions",
            format!("{ep_count} pattern{}", if ep_count == 1 { "" } else { "s" }),
        );
    }
    let bl_count = settings.blacklist.len();
    if bl_count > 0 {
        display::kv(
            "Blacklist",
            format!("{bl_count} entr{}", if bl_count == 1 { "y" } else { "ies" }),
        );
    } else {
        display::kv("Blacklist", "empty".dimmed());
    }

    let persistent = stats::load().unwrap_or_default();

    // ── Recent Redactions ───────────────────────────
    display::section("Recent Redactions");
    let redaction_runs: Vec<&stats::HookRunStats> = persistent
        .hook_history
        .iter()
        .filter(|r| r.redactions > 0)
        .collect();
    if redaction_runs.is_empty() {
        display::empty("No redactions recorded yet");
    } else {
        for run in redaction_runs.iter().rev().take(3) {
            let short_file = std::path::Path::new(&run.file)
                .file_name()
                .map_or(run.file.as_str(), |f| f.to_str().unwrap_or(&run.file));
            let label = if run.redactions == 1 {
                "redaction"
            } else {
                "redactions"
            };
            println!(
                "  {}  {} {label}  {}",
                display::format_epoch(run.timestamp_epoch).dimmed(),
                format!("{}", run.redactions).red(),
                format!("[...]/{short_file}").dimmed(),
            );
        }
        if redaction_runs.len() > 3 {
            let remaining = redaction_runs.len() - 3;
            println!(
                "  {}",
                format!(
                    "… and {remaining} more (of {} total runs with redactions)",
                    redaction_runs.len()
                )
                .dimmed()
            );
        }
    }

    // ── Stats ───────────────────────────────────────
    display::section("Stats");
    if let Some(ref hook) = persistent.last_hook {
        display::kv(
            "Last run",
            format!(
                "{} ({})",
                display::format_epoch(hook.timestamp_epoch),
                display::format_relative(hook.timestamp_epoch),
            ),
        );
        let short_file = std::path::Path::new(&hook.file)
            .file_name()
            .map_or(hook.file.as_str(), |f| f.to_str().unwrap_or(&hook.file));
        display::kv(
            "Last file",
            format!(
                "{} ({})",
                format!("[...]/{short_file}").dimmed(),
                display::format_bytes(hook.file_size_bytes),
            ),
        );
        display::kv("Last time", display::format_duration_ms(hook.duration_ms));
    }
    if persistent.hook_history.len() >= 2 {
        let durations: Vec<u64> = persistent
            .hook_history
            .iter()
            .map(|r| r.duration_ms)
            .collect();
        let redactions: Vec<u64> = persistent
            .hook_history
            .iter()
            .map(|r| r.redactions)
            .collect();
        let shown = durations.len().min(30);
        display::kv(
            "Latency",
            format!(
                "{}  (last {shown} runs)",
                display::sparkline(&durations).green()
            ),
        );
        let total_redactions: u64 = redactions.iter().sum();
        display::kv(
            "Redactions",
            format!(
                "{}  ({total_redactions} total)",
                display::sparkline(&redactions).green()
            ),
        );
    } else if persistent.last_hook.is_none() {
        display::empty("No hook runs recorded yet");
    }

    // ── Last Scan Run ───────────────────────────────
    display::section("Last Scan Run");
    if let Some(ref scan) = persistent.last_scan {
        display::kv(
            "When",
            format!(
                "{} ({})",
                display::format_epoch(scan.timestamp_epoch),
                display::format_relative(scan.timestamp_epoch),
            ),
        );
        display::kv("Mode", if scan.dry_run { "dry-run" } else { "live" });
        if scan.files_cached > 0 {
            display::kv(
                "Files",
                format!(
                    "{} scanned, {} cached, {} modified",
                    scan.files_scanned, scan.files_cached, scan.files_modified
                ),
            );
        } else {
            display::kv(
                "Files",
                format!(
                    "{} scanned, {} modified",
                    scan.files_scanned, scan.files_modified
                ),
            );
        }
        display::kv("Redactions", format!("{}", scan.total_redactions));
        if scan.errors > 0 {
            display::kv("Errors", format!("{}", scan.errors).red());
        } else {
            display::kv("Errors", "0");
        }
        display::kv("Duration", display::format_duration_ms(scan.duration_ms));
        if scan.files_scanned > 0 {
            let per_file = scan.duration_ms as f64 / scan.files_scanned as f64;
            display::kv("Throughput", format!("{per_file:.1}ms/file"));
        }
    } else {
        display::empty("No scan runs recorded yet");
    }

    // ── Coverage ────────────────────────────────────
    display::section("Coverage");

    let projects_dir = claude_dir.join("projects");
    if projects_dir.exists() {
        let mut total_files: u64 = 0;
        let mut total_bytes: u64 = 0;
        for entry in WalkDir::new(&projects_dir)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
        {
            total_files += 1;
            if let Ok(meta) = entry.metadata() {
                total_bytes += meta.len();
            }
        }

        display::kv("History files", format!("{total_files}"));
        display::kv("Total size", display::format_bytes(total_bytes));
    } else {
        display::empty("No projects directory found (~/.claude/projects/)");
    }

    println!();
    Ok(())
}

fn not_installed() -> String {
    format!(
        "{}  {}",
        "not installed".red(),
        "(run `scrub-history init`)".dimmed()
    )
}

/// Per-event hook status rows for the dashboard.
fn hook_report(settings_path: &Path) -> Vec<(String, String)> {
    let root: Option<serde_json::Value> = match std::fs::read_to_string(settings_path) {
        Ok(data) => match serde_json::from_str(&data) {
            Ok(v) => Some(v),
            Err(e) => {
                return vec![(
                    "settings.json".into(),
                    format!("could not parse: {e}").red().to_string(),
                )];
            }
        },
        Err(_) => None,
    };
    let mut rows = Vec::new();
    for &event in HOOK_EVENTS {
        let key = format!("{event} hook");
        let Some(hook) = root.as_ref().and_then(|r| find_installed_hook(r, event)) else {
            rows.push((key, not_installed()));
            continue;
        };
        let mode = if hook.is_async { "async" } else { "sync" };
        rows.push((key, format!("{} ({mode})", "installed".green())));
        if !hook_command_is_absolute(&hook.command) {
            rows.push((
                String::new(),
                format!(
                    "{}  {}",
                    "WARNING: command is resolved via PATH (another binary could hijack it)"
                        .yellow(),
                    "(re-run `scrub-history init`)".dimmed()
                ),
            ));
        }
    }
    rows
}

/// Config file status rows: presence, permissions, load errors and skipped
/// custom patterns.
fn config_report(config_path: &Path, settings: &ScrubberSettings) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    if config_path.exists() {
        rows.push(("scrubber.toml".into(), "present".green().to_string()));
        if fsutil::is_group_or_world_readable(config_path) {
            let mode = fsutil::file_mode(config_path).unwrap_or_default();
            rows.push((
                "Permissions".into(),
                format!(
                    "{}  {}",
                    format!(
                        "WARNING: {mode:o} is readable by other users (holds blacklist secrets)"
                    )
                    .red(),
                    format!("(chmod 600 {})", config_path.display()).dimmed()
                ),
            ));
        }
    } else {
        rows.push((
            "scrubber.toml".into(),
            format!(
                "{}  {}",
                "absent".yellow(),
                "(run `scrub-history init`)".dimmed()
            ),
        ));
    }
    for err in &settings.config_errors {
        rows.push(("Config error".into(), err.red().to_string()));
    }
    if settings
        .config_errors
        .iter()
        .any(|e| e.contains("TOML syntax error") || e.contains("could not read"))
    {
        rows.push((
            String::new(),
            "using built-in patterns and defaults only; blacklist, allowlist and custom \
             patterns are NOT applied"
                .red()
                .bold()
                .to_string(),
        ));
    }
    for c in &settings.custom_patterns {
        if let Err(reason) = allowlist::compile_custom_pattern(c) {
            rows.push((
                "Skipped pattern".into(),
                format!("'{}': {reason}", c.name).yellow().to_string(),
            ));
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined(rows: &[(String, String)]) -> String {
        rows.iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn hook_report_warns_on_path_resolved_command() {
        colored::control::set_override(false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"hooks": {"Stop": [{"matcher": "", "hooks": [
                {"type": "command", "command": "scrub-history hook"}]}],
              "SessionEnd": [{"matcher": "", "hooks": [
                {"type": "command", "command": "'/opt/bin/scrub-history' hook"}]}]}}"#,
        )
        .unwrap();
        let text = joined(&hook_report(&path));
        assert!(text.contains("Stop hook: installed (sync)"), "{text}");
        assert!(text.contains("resolved via PATH"), "{text}");
        assert_eq!(text.matches("resolved via PATH").count(), 1, "{text}");
        assert!(text.contains("SessionEnd hook: installed"), "{text}");
        assert!(text.contains("SubagentStop hook: not installed"), "{text}");
    }

    #[test]
    fn hook_report_missing_settings() {
        let dir = tempfile::tempdir().unwrap();
        let rows = hook_report(&dir.path().join("settings.json"));
        assert_eq!(rows.len(), HOOK_EVENTS.len());
    }

    #[cfg(unix)]
    #[test]
    fn config_report_warns_when_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        colored::control::set_override(false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scrubber.toml");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let settings = allowlist::load_config_from(&path);
        let text = joined(&config_report(&path, &settings));
        assert!(text.contains("readable by other users"), "{text}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let text = joined(&config_report(&path, &settings));
        assert!(!text.contains("readable by other users"), "{text}");
    }

    #[test]
    fn config_report_shows_parse_errors_and_skipped_patterns() {
        colored::control::set_override(false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scrubber.toml");

        std::fs::write(&path, "[blacklist\nstrings = [\"sekrit-value-123\"]\n").unwrap();
        let settings = allowlist::load_config_from(&path);
        let text = joined(&config_report(&path, &settings));
        assert!(text.contains("TOML syntax error"), "{text}");
        assert!(text.contains("NOT applied"), "{text}");
        assert!(!text.contains("sekrit"), "{text}");

        std::fs::write(
            &path,
            "[[patterns]]\nname = \"bad\"\nregex = \"sekrit(\"\n\n[[patterns]]\nname = \"ok\"\nregex = \"ok_[a-z]{8}\"\n",
        )
        .unwrap();
        let settings = allowlist::load_config_from(&path);
        let text = joined(&config_report(&path, &settings));
        assert!(
            text.contains("Skipped pattern: 'bad': invalid regex syntax"),
            "{text}"
        );
        assert!(!text.contains("'ok'"), "{text}");
        assert!(!text.contains("sekrit"), "{text}");
    }
}
