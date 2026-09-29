use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use colored::Colorize;
use scrub_history::allowlist::{self, ScrubberSettings};
use scrub_history::display;
use scrub_history::fsutil;
use scrub_history::locations::{self, Discovery, Location};
use scrub_history::patterns::PatternSet;
use scrub_history::stats::{self, PersistentStats, ScanRunStats};

use super::init::{HOOK_EVENTS, find_installed_hook, hook_command_is_absolute};

/// Detail views gated behind `scrub-history status <section>`.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum StatusSection {
    /// Per-event hook install state and mode
    Hooks,
    /// Per-location breakdown of the last scan and on-disk coverage
    Scan,
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
pub(crate) fn run_status(section: Option<StatusSection>, all: bool) {
    if let Err(e) = run_status_inner(section, all) {
        eprintln!("error: {e:#}");
    }
}

#[allow(clippy::print_stdout)]
fn run_status_inner(section: Option<StatusSection>, all: bool) -> Result<()> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME not set"))?;
    let claude_dir = home.join(".claude");
    let settings_path = claude_dir.join("settings.json");
    let discover = || {
        locations::discover(
            &claude_dir,
            &home.join(".claude.json"),
            &locations::LocationSet::all(),
            std::time::SystemTime::now(),
        )
    };

    // Header
    println!(
        "\n{} {}",
        "scrub-history".bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed()
    );

    let persistent = stats::load().unwrap_or_default();

    match section {
        Some(StatusSection::Hooks) => print_hooks_detail(&settings_path),
        Some(StatusSection::Scan) => {
            print_scan_detail(persistent.last_scan.as_ref(), &discover());
        }
        None => {
            let discovery = discover();
            print_overview(&claude_dir, &settings_path, &persistent, &discovery, all);
            if all {
                print_scan_detail(persistent.last_scan.as_ref(), &discovery);
            } else {
                println!(
                    "\n  {}",
                    "More: `scrub-history status hooks`, `status scan`, or `status --all`".dimmed()
                );
            }
        }
    }

    println!();
    Ok(())
}

#[allow(clippy::print_stdout, clippy::cast_precision_loss)]
fn print_overview(
    claude_dir: &Path,
    settings_path: &Path,
    persistent: &PersistentStats,
    discovery: &Discovery,
    all: bool,
) {
    // ── Hooks ───────────────────────────────────────
    // Collapsed to one line when every hook is healthy; any problem expands it.
    let (rows, healthy) = hook_report(settings_path);
    if healthy && !all {
        display::section("Hooks");
        display::kv(
            "Installed",
            format!(
                "{}/{} {}",
                HOOK_EVENTS.len(),
                HOOK_EVENTS.len(),
                format!("({})", HOOK_EVENTS.join(", ")).dimmed()
            ),
        );
    } else {
        display::section("Hook Configuration");
        for (key, value) in rows {
            display::kv(&key, value);
        }
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
            "Last hook run",
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

    // ── Last Scan ───────────────────────────────────
    display::section("Last Scan");
    if let Some(scan) = &persistent.last_scan {
        display::kv(
            "When",
            format!(
                "{} ({}) · {}",
                display::format_epoch(scan.timestamp_epoch),
                display::format_relative(scan.timestamp_epoch),
                if scan.dry_run { "dry-run" } else { "live" },
            ),
        );
        let mut files = format!("{} scanned", scan.files_scanned);
        if scan.files_cached > 0 {
            let _ = write!(files, ", {} cached", scan.files_cached);
        }
        let _ = write!(
            files,
            ", {} {}",
            scan.files_modified,
            if scan.dry_run {
                "would change"
            } else {
                "modified"
            }
        );
        display::kv("Files", files);
        display::kv("Redactions", format!("{}", scan.total_redactions));
        let mut duration = display::format_duration_ms(scan.duration_ms);
        if scan.files_scanned > 0 {
            let per_file = scan.duration_ms as f64 / scan.files_scanned as f64;
            let _ = write!(duration, " ({per_file:.1}ms per scanned file)");
        }
        display::kv("Duration", duration);
    } else {
        display::empty("No scan runs recorded yet");
    }

    // ── Needs Attention ─────────────────────────────
    let items = attention_items(persistent.last_scan.as_ref(), discovery.orphans.len());
    if !items.is_empty() {
        display::section("Needs Attention");
        for (msg, hint) in items {
            println!("  {} {msg}  {}", "!".yellow().bold(), hint.dimmed());
        }
    }
}

/// Actionable problems for the overview, as `(message, hint)` pairs.
fn attention_items(scan: Option<&ScanRunStats>, orphans: usize) -> Vec<(String, String)> {
    let mut items = Vec::new();
    if let Some(scan) = scan {
        if scan.dry_run && scan.total_redactions > 0 {
            items.push((
                format!(
                    "Last scan was a dry-run: {} redaction(s) in {} file(s) not applied",
                    scan.total_redactions, scan.files_modified
                ),
                "→ scrub-history scan --fix".into(),
            ));
        }
        if scan.errors > 0 {
            items.push((
                format!("Last scan hit {} error(s)", scan.errors),
                "→ scrub-history scan -v".into(),
            ));
        }
        if scan.config_findings > 0 {
            items.push((
                format!(
                    "~/.claude.json has {} secret-looking MCP value(s) (never modified)",
                    scan.config_findings
                ),
                "→ scrub-history scan".into(),
            ));
        }
    }
    if orphans > 0 {
        items.push((
            format!("{orphans} orphan temp file(s)"),
            "→ scrub-history scan --fix removes stale ones".into(),
        ));
    }
    items
}

fn print_hooks_detail(settings_path: &Path) {
    display::section("Hook Configuration");
    display::kv(
        "settings.json",
        settings_path.display().to_string().dimmed(),
    );
    for (key, value) in hook_report(settings_path).0 {
        display::kv(&key, value);
    }
}

/// One row per location, merging on-disk coverage with the last scan's counts.
#[allow(clippy::print_stdout)]
fn print_scan_detail(scan: Option<&ScanRunStats>, discovery: &Discovery) {
    display::section("Locations");

    let mut per_loc: BTreeMap<Location, (u64, u64)> = BTreeMap::new();
    for t in &discovery.targets {
        let e = per_loc.entry(t.location).or_default();
        e.0 += 1;
        e.1 += std::fs::metadata(&t.path).map_or(0, |m| m.len());
    }
    if per_loc.is_empty() {
        display::empty("No history files found under ~/.claude/");
    } else {
        let header = format!(
            "{:<18}{:>7}{:>11}{:>9}{:>10}{:>12}",
            "", "files", "size", "scanned", "modified", "redactions"
        );
        println!("  {}", header.dimmed());
        let cell = |v: Option<u64>| v.map_or_else(|| "-".to_string(), |n| n.to_string());
        let (mut total_files, mut total_bytes) = (0u64, 0u64);
        for (loc, (files, bytes)) in &per_loc {
            total_files += files;
            total_bytes += bytes;
            let last = scan.and_then(|s| s.by_location.get(loc.name()));
            let mut line = format!(
                "{:<18}{files:>7}{:>11}{:>9}{:>10}{:>12}",
                loc.name(),
                display::format_bytes(*bytes),
                cell(last.map(|l| l.files_scanned)),
                cell(last.map(|l| l.files_modified)),
                cell(last.map(|l| l.redactions)),
            );
            if let Some(l) = last {
                if l.files_skipped > 0 {
                    let _ = write!(line, "  {} skipped", l.files_skipped);
                }
                if l.errors > 0 {
                    let _ = write!(line, "  {}", format!("{} errors", l.errors).red());
                }
            }
            println!("  {line}");
        }
        println!(
            "  {}",
            format!(
                "{:<18}{total_files:>7}{:>11}",
                "total",
                display::format_bytes(total_bytes)
            )
            .bold()
        );
    }

    if !discovery.orphans.is_empty() {
        display::kv(
            "Orphan temps",
            format!(
                "{} (run `scrub-history scan --fix` to remove stale ones)",
                discovery.orphans.len()
            ),
        );
    }
    if let Some(scan) = scan.filter(|s| s.config_findings > 0) {
        display::kv(
            "~/.claude.json",
            format!(
                "{} secret-looking MCP value(s), not modified (see `scan` output)",
                scan.config_findings
            )
            .yellow(),
        );
    }
}

fn not_installed() -> String {
    format!(
        "{}  {}",
        "not installed".red(),
        "(run `scrub-history init`)".dimmed()
    )
}

/// Per-event hook status rows for the dashboard, plus whether every hook is
/// installed with an absolute command.
fn hook_report(settings_path: &Path) -> (Vec<(String, String)>, bool) {
    let root: Option<serde_json::Value> = match std::fs::read_to_string(settings_path) {
        Ok(data) => match serde_json::from_str(&data) {
            Ok(v) => Some(v),
            Err(e) => {
                return (
                    vec![(
                        "settings.json".into(),
                        format!("could not parse: {e}").red().to_string(),
                    )],
                    false,
                );
            }
        },
        Err(_) => None,
    };
    let mut rows = Vec::new();
    let mut healthy = true;
    for &event in HOOK_EVENTS {
        let key = format!("{event} hook");
        let Some(hook) = root.as_ref().and_then(|r| find_installed_hook(r, event)) else {
            rows.push((key, not_installed()));
            healthy = false;
            continue;
        };
        let mode = if hook.is_async { "async" } else { "sync" };
        rows.push((key, format!("{} ({mode})", "installed".green())));
        if !hook_command_is_absolute(&hook.command) {
            healthy = false;
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
    (rows, healthy)
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
        let (rows, healthy) = hook_report(&path);
        assert!(!healthy, "PATH-resolved and missing hooks are unhealthy");
        let text = joined(&rows);
        assert!(text.contains("Stop hook: installed (sync)"), "{text}");
        assert!(text.contains("resolved via PATH"), "{text}");
        assert_eq!(text.matches("resolved via PATH").count(), 1, "{text}");
        assert!(text.contains("SessionEnd hook: installed"), "{text}");
        assert!(text.contains("SubagentStop hook: not installed"), "{text}");
    }

    fn scan_stats(dry_run: bool, redactions: u64, errors: u64, config: u64) -> ScanRunStats {
        serde_json::from_value(serde_json::json!({
            "timestamp_epoch": 0, "files_scanned": 3, "files_modified": 2,
            "total_redactions": redactions, "errors": errors, "duration_ms": 10,
            "dry_run": dry_run, "config_findings": config,
        }))
        .unwrap()
    }

    #[test]
    fn attention_items_flag_actionable_problems() {
        assert!(attention_items(None, 0).is_empty());
        assert!(attention_items(Some(&scan_stats(false, 5, 0, 0)), 0).is_empty());
        assert!(attention_items(Some(&scan_stats(true, 0, 0, 0)), 0).is_empty());

        let items = attention_items(Some(&scan_stats(true, 59, 1, 6)), 3);
        let text = items
            .iter()
            .map(|(m, h)| format!("{m} {h}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(items.len(), 4, "{text}");
        assert!(
            text.contains("59 redaction(s) in 2 file(s) not applied"),
            "{text}"
        );
        assert!(text.contains("1 error(s)"), "{text}");
        assert!(text.contains("6 secret-looking MCP value(s)"), "{text}");
        assert!(text.contains("3 orphan temp file(s)"), "{text}");
    }

    #[test]
    fn hook_report_healthy_when_all_installed_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let hook = serde_json::json!([{"matcher": "", "hooks": [
            {"type": "command", "command": "'/opt/bin/scrub-history' hook"}]}]);
        let hooks: serde_json::Map<String, serde_json::Value> = HOOK_EVENTS
            .iter()
            .map(|e| ((*e).to_string(), hook.clone()))
            .collect();
        std::fs::write(&path, serde_json::json!({ "hooks": hooks }).to_string()).unwrap();
        let (rows, healthy) = hook_report(&path);
        assert!(healthy, "{}", joined(&rows));
    }

    #[test]
    fn hook_report_missing_settings() {
        let dir = tempfile::tempdir().unwrap();
        let (rows, healthy) = hook_report(&dir.path().join("settings.json"));
        assert!(!healthy);
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
