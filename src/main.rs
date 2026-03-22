mod commands;

use clap::{Parser, Subcommand};
use scrub_history::entropy::EntropyConfig;
use tracing_subscriber::EnvFilter;

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
    /// Interactive setup wizard — installs hook and writes config
    Init,
    /// Scan all JSONL files under ~/.claude/projects/
    Scan {
        /// Apply redactions to files (default: preview only)
        #[arg(long)]
        fix: bool,

        /// Show full secret values in output (no truncation)
        #[arg(long)]
        no_truncate: bool,

        /// Disable mtime-based cache, force full rescan
        #[arg(long)]
        no_cache: bool,

        /// Max parallel threads (default: half of available cores)
        #[arg(short, long)]
        jobs: Option<usize>,
    },
    /// Show hook config, last run stats, coverage, and performance info
    Status,
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
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .without_time()
        .with_target(false)
        .init();

    let entropy_cfg = EntropyConfig {
        enabled: !cli.no_entropy,
        threshold: cli.entropy_threshold,
        ..Default::default()
    };

    match cli.command {
        Command::Init => commands::init::run_init(),
        Command::Hook => commands::hook::run_hook(&entropy_cfg),
        Command::Scan {
            fix,
            no_truncate,
            no_cache,
            jobs,
        } => commands::scan::run_scan(fix, no_truncate, no_cache, jobs, &entropy_cfg),
        Command::Status => commands::status::run_status(),
    }
}
