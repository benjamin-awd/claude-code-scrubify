use serde::Deserialize;
use std::io::Read;
use std::path::PathBuf;
use tracing::{error, info};

use crate::entropy::EntropyConfig;
use crate::jsonl;
use crate::patterns::{self, PatternSet};

#[derive(Deserialize)]
struct HookInput {
    transcript_path: Option<String>,
    #[serde(default)]
    stop_hook_active: bool,
}

pub fn run_hook(entropy_cfg: &EntropyConfig) {
    // Always exit 0 — hook failures block Claude Code
    if let Err(e) = run_hook_inner(entropy_cfg) {
        error!(error = %e, "scrub-history hook error");
    }
}

fn run_hook_inner(entropy_cfg: &EntropyConfig) -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let hook_input: HookInput = serde_json::from_str(&input)?;

    // Prevent infinite loops if this hook triggers another stop
    if hook_input.stop_hook_active {
        return Ok(());
    }

    let transcript_path = hook_input
        .transcript_path
        .ok_or_else(|| anyhow::anyhow!("no transcript_path in hook input"))?;

    // Expand ~ to home directory
    let path = if transcript_path.starts_with('~') {
        let home = patterns::home_dir()
            .ok_or_else(|| anyhow::anyhow!("HOME not set"))?;
        PathBuf::from(transcript_path.replacen('~', &home.to_string_lossy(), 1))
    } else {
        PathBuf::from(&transcript_path)
    };

    if !path.exists() {
        return Ok(());
    }

    let pattern_set = PatternSet::load(false);

    let result = jsonl::scrub_jsonl_file(&path, &pattern_set, entropy_cfg, false)?;

    if !result.redactions.is_empty() {
        info!(
            count = result.redactions.len(),
            file = %path.display(),
            "scrub-history: redacted secret(s)"
        );
    }

    Ok(())
}
