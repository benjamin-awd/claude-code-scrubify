use std::path::PathBuf;

use anyhow::Result;
use scrub_history::allowlist;
use scrub_history::display::{self, BOLD, DIM, GREEN, RED, RESET, YELLOW};
use scrub_history::patterns::PatternSet;
use scrub_history::stats;
use walkdir::WalkDir;

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

    println!();
    println!("{BOLD}scrub-history status{RESET}");
    println!();

    println!("{BOLD}Hook Configuration{RESET}");

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
            println!("  Stop hook:  {GREEN}installed{RESET} ({mode})");
        } else {
            println!(
                "  Stop hook:  {RED}not installed{RESET}  {DIM}(run `scrub-history init`){RESET}"
            );
        }
    } else {
        println!("  Stop hook:  {RED}not installed{RESET}  {DIM}(run `scrub-history init`){RESET}");
    }

    println!();
    println!("{BOLD}Config Files{RESET}");

    let config_path = claude_dir.join("scrubber.toml");
    if config_path.exists() {
        println!("  scrubber.toml:         {GREEN}present{RESET}");
    } else {
        println!(
            "  scrubber.toml:         {YELLOW}absent{RESET}  {DIM}(run `scrub-history init`){RESET}"
        );
    }

    println!();
    println!("{BOLD}Detection{RESET}");

    match PatternSet::load(true) {
        Ok(ps) => {
            let builtin = ps.patterns.len();
            match PatternSet::load(false) {
                Ok(full) => {
                    let custom = full.patterns.len() - builtin;
                    if custom > 0 {
                        println!(
                            "  Patterns:    {builtin} built-in + {custom} custom = {} total",
                            full.patterns.len()
                        );
                    } else {
                        println!("  Patterns:    {builtin} built-in");
                    }
                }
                Err(_) => println!("  Patterns:    {builtin} built-in"),
            }
        }
        Err(e) => println!("  Patterns:    {RED}error loading: {e}{RESET}"),
    }

    match allowlist::load_config() {
        Ok(settings) => {
            let count = settings.allowlist.len();
            if count > 0 {
                println!(
                    "  Allowlist:   {count} hash{}",
                    if count == 1 { "" } else { "es" }
                );
            } else {
                println!("  Allowlist:   {DIM}empty{RESET}");
            }
            let ep_count = settings.entropy_exclude_patterns.len();
            if ep_count > 0 {
                println!(
                    "  Entropy exclusions: {ep_count} pattern{}",
                    if ep_count == 1 { "" } else { "s" }
                );
            }
            let bl_count = settings.blacklist.len();
            if bl_count > 0 {
                println!(
                    "  Blacklist:   {bl_count} entr{}",
                    if bl_count == 1 { "y" } else { "ies" }
                );
            } else {
                println!("  Blacklist:   {DIM}empty{RESET}");
            }
        }
        Err(e) => println!("  Allowlist:   {RED}error: {e}{RESET}"),
    }

    println!();
    println!("{BOLD}Coverage{RESET}");

    let projects_dir = claude_dir.join("projects");
    if projects_dir.exists() {
        let jsonl_files: Vec<PathBuf> = WalkDir::new(&projects_dir)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
            .map(walkdir::DirEntry::into_path)
            .collect();

        let total_files = jsonl_files.len();
        let total_bytes: u64 = jsonl_files
            .iter()
            .filter_map(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .sum();

        println!("  History files: {total_files}");
        println!("  Total size:    {}", display::format_bytes(total_bytes));

        let scrubbed_count = jsonl_files
            .iter()
            .filter(|p| file_contains_redaction(p))
            .count();

        if scrubbed_count > 0 {
            println!(
                "  Files with redactions: {scrubbed_count}/{total_files} ({:.0}%)",
                (scrubbed_count as f64 / total_files as f64) * 100.0
            );
        } else {
            println!("  Files with redactions: 0/{total_files}");
        }
    } else {
        println!("  {DIM}No projects directory found (~/.claude/projects/){RESET}");
    }

    let persistent = stats::load().unwrap_or_default();

    println!();
    println!("{BOLD}Stats{RESET}");
    if let Some(ref hook) = persistent.last_hook {
        println!(
            "  Last run:   {} ({})",
            display::format_epoch(hook.timestamp_epoch),
            display::format_relative(hook.timestamp_epoch),
        );
        println!(
            "  Last file:  {} ({})",
            hook.file,
            display::format_bytes(hook.file_size_bytes),
        );
        println!(
            "  Last time:  {}",
            display::format_duration_ms(hook.duration_ms),
        );
    }
    if let Some(summary) = persistent.hook_latency() {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let avg_ms = summary.avg_ms.round() as u64;
        println!(
            "  Avg:        {} over {} run{}",
            display::format_duration_ms(avg_ms),
            summary.count,
            if summary.count == 1 { "" } else { "s" },
        );
        if summary.count >= 2 {
            println!(
                "  p50:        {}",
                display::format_duration_ms(summary.p50_ms),
            );
        }
        if summary.count >= 5 {
            println!(
                "  p95:        {}",
                display::format_duration_ms(summary.p95_ms),
            );
        }
        println!(
            "  Max:        {}",
            display::format_duration_ms(summary.max_ms),
        );
        println!(
            "  Total:      {} added across all recorded runs",
            display::format_duration_ms(summary.total_ms),
        );
    } else if persistent.last_hook.is_none() {
        println!("  {DIM}No hook runs recorded yet{RESET}");
    }

    println!();
    println!("{BOLD}Last Scan Run{RESET}");
    if let Some(ref scan) = persistent.last_scan {
        let mode = if scan.dry_run { " (dry-run)" } else { "" };
        println!(
            "  When:       {} ({})",
            display::format_epoch(scan.timestamp_epoch),
            display::format_relative(scan.timestamp_epoch),
        );
        println!(
            "  Mode:       {}{mode}",
            if scan.dry_run { "dry-run" } else { "live" }
        );
        println!(
            "  Files:      {} scanned, {} modified",
            scan.files_scanned, scan.files_modified
        );
        println!("  Redactions: {}", scan.total_redactions);
        if scan.errors > 0 {
            println!("  Errors:     {RED}{}{RESET}", scan.errors);
        } else {
            println!("  Errors:     0");
        }
        println!(
            "  Duration:   {}",
            display::format_duration_ms(scan.duration_ms),
        );
        if scan.files_scanned > 0 {
            let per_file = scan.duration_ms as f64 / scan.files_scanned as f64;
            println!("  Throughput: {per_file:.1}ms/file");
        }
    } else {
        println!("  {DIM}No scan runs recorded yet{RESET}");
    }

    println!();
    Ok(())
}

/// Quick check whether a file contains any [REDACTED:...] markers.
/// Reads only the first 256KB to keep the coverage check fast.
fn file_contains_redaction(path: &PathBuf) -> bool {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = vec![0u8; 256 * 1024];
    let Ok(n) = file.read(&mut buf) else {
        return false;
    };
    let chunk = &buf[..n];
    chunk.windows(10).any(|w| w == b"[REDACTED:")
}
