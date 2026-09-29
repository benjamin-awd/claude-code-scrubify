use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;
use scrub_history::allowlist;
use scrub_history::display;
use scrub_history::locations::{self, Location};
use scrub_history::patterns::PatternSet;
use scrub_history::stats;

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
    if settings_path.exists() {
        let data = std::fs::read_to_string(&settings_path)?;
        let root: serde_json::Value = serde_json::from_str(&data)?;
        let hook_entry = root
            .get("hooks")
            .and_then(|h| h.get("Stop"))
            .and_then(|s| s.as_array())
            .and_then(|arr| {
                arr.iter().find(|entry| {
                    entry
                        .get("hooks")
                        .and_then(|h| h.as_array())
                        .is_some_and(|hooks| {
                            hooks.iter().any(|h| {
                                h.get("command").and_then(serde_json::Value::as_str)
                                    == Some("scrub-history hook")
                            })
                        })
                })
            });
        if let Some(entry) = hook_entry {
            let is_async = entry
                .get("hooks")
                .and_then(|h| h.as_array())
                .and_then(|hooks| hooks.first())
                .and_then(|h| h.get("async"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let mode = if is_async { "async" } else { "sync" };
            display::kv("Stop hook", format!("{} ({mode})", "installed".green()));
        } else {
            display::kv(
                "Stop hook",
                format!(
                    "{}  {}",
                    "not installed".red(),
                    "(run `scrub-history init`)".dimmed()
                ),
            );
        }
    } else {
        display::kv(
            "Stop hook",
            format!(
                "{}  {}",
                "not installed".red(),
                "(run `scrub-history init`)".dimmed()
            ),
        );
    }

    // ── Config ──────────────────────────────────────
    display::section("Config");

    let config_path = claude_dir.join("scrubber.toml");
    if config_path.exists() {
        display::kv("scrubber.toml", "present".green());
    } else {
        display::kv(
            "scrubber.toml",
            format!(
                "{}  {}",
                "absent".yellow(),
                "(run `scrub-history init`)".dimmed()
            ),
        );
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

    match allowlist::load_config() {
        Ok(settings) => {
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
        }
        Err(e) => display::kv("Allowlist", format!("{}", format!("error: {e}").red())),
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
        for (name, loc) in &scan.by_location {
            let mut line = format!(
                "{} files, {} scanned, {} modified, {} redactions",
                loc.files_found, loc.files_scanned, loc.files_modified, loc.redactions
            );
            if loc.files_skipped > 0 {
                let _ = write!(line, ", {} skipped", loc.files_skipped);
            }
            if loc.errors > 0 {
                let _ = write!(line, ", {} errors", loc.errors);
            }
            display::kv(&format!("  {name}"), line);
        }
        if scan.orphans_found > 0 {
            display::kv(
                "Orphan temps",
                format!(
                    "{} found, {} removed",
                    scan.orphans_found, scan.orphans_removed
                ),
            );
        }
        if scan.config_findings > 0 {
            display::kv(
                "~/.claude.json",
                format!(
                    "{} secret-looking MCP value(s), not modified (see `scan` output)",
                    scan.config_findings
                )
                .yellow(),
            );
        }
    } else {
        display::empty("No scan runs recorded yet");
    }

    // ── Coverage ────────────────────────────────────
    display::section("Coverage");

    let discovery = locations::discover(
        &claude_dir,
        &home.join(".claude.json"),
        &locations::LocationSet::all(),
        std::time::SystemTime::now(),
    );
    if discovery.targets.is_empty() {
        display::empty("No history files found under ~/.claude/");
    } else {
        let mut per_loc: BTreeMap<Location, (u64, u64)> = BTreeMap::new();
        for t in &discovery.targets {
            let e = per_loc.entry(t.location).or_default();
            e.0 += 1;
            e.1 += std::fs::metadata(&t.path).map_or(0, |m| m.len());
        }
        let (mut total_files, mut total_bytes) = (0u64, 0u64);
        for (loc, (files, bytes)) in &per_loc {
            total_files += files;
            total_bytes += bytes;
            display::kv(
                loc.name(),
                format!("{files} files ({})", display::format_bytes(*bytes)),
            );
        }
        display::kv("History files", format!("{total_files}"));
        display::kv("Total size", display::format_bytes(total_bytes));
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

    println!();
    Ok(())
}
