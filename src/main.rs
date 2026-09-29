mod commands;

use clap::{Parser, Subcommand};
use scrub_history::entropy::EntropyConfig;
use scrub_history::locations::{Location, LocationSet};
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
    /// Scan Claude Code history: transcripts, tool results, jobs, prompt
    /// history, paste cache, file-history, plans and shell snapshots.
    /// `~/.claude.json` is reported on but never modified.
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

        /// Only scan session transcripts (projects/**/*.jsonl), the original behaviour
        #[arg(long)]
        only_transcripts: bool,

        /// Skip a location (repeatable or comma-separated). E.g. `--skip file-history`
        /// keeps Claude's rewind snapshots untouched.
        #[arg(long, value_enum, value_delimiter = ',')]
        skip: Vec<Location>,
    },
    /// Show hook health, config, recent redactions and performance.
    /// Pass a section for more detail.
    Status {
        /// Show one detail view instead of the overview
        #[arg(value_enum)]
        section: Option<commands::status::StatusSection>,

        /// Show the overview plus every detail view
        #[arg(long, conflicts_with = "section")]
        all: bool,
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
            only_transcripts,
            skip,
        } => commands::scan::run_scan(
            &commands::scan::ScanOptions {
                fix,
                no_truncate,
                no_cache,
                jobs,
                locations: LocationSet::from_flags(only_transcripts, &skip),
            },
            &entropy_cfg,
        ),
        Command::Status { section, all } => commands::status::run_status(section, all),
    }
}
