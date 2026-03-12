mod hook;
mod scan;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use scrub_history::entropy::EntropyConfig;

#[derive(Parser)]
#[command(
    name = "scrub-history",
    about = "Redact secrets from Claude Code chat history"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Increase log verbosity (-v for debug, -vv for trace)
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress all output except errors
    #[arg(long, short, global = true)]
    quiet: bool,

    /// Disable entropy-based detection
    #[arg(long, global = true)]
    no_entropy: bool,

    /// Shannon entropy threshold (default: 4.5)
    #[arg(long, global = true, default_value_t = 4.5)]
    entropy_threshold: f64,
}

#[derive(Subcommand)]
enum Command {
    /// Run as a Claude Code Stop hook (reads session info from stdin)
    Hook,
    /// Scan all JSONL files under ~/.claude/projects/
    Scan {
        /// Preview redactions without modifying files
        #[arg(long)]
        dry_run: bool,

        /// Show full secret values in dry-run output (no truncation)
        #[arg(long)]
        no_truncate: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let default_level = if cli.quiet {
        "error"
    } else {
        match cli.verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
    };

    // RUST_LOG overrides --verbose/--quiet when set
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(false)
        .init();

    let entropy_cfg = EntropyConfig {
        enabled: !cli.no_entropy,
        threshold: cli.entropy_threshold,
        ..Default::default()
    };

    match cli.command {
        Command::Hook => hook::run_hook(&entropy_cfg),
        Command::Scan {
            dry_run,
            no_truncate,
        } => scan::run_scan(dry_run, no_truncate, &entropy_cfg),
    }
}
