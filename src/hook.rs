use serde::Deserialize;
use std::io::Read;
use std::path::PathBuf;
use tracing::{error, info, warn};

use crate::allowlist::Allowlist;
use crate::entropy::EntropyConfig;
use crate::jsonl;
use crate::patterns::PatternSet;

#[derive(Deserialize)]
struct HookInput {
    transcript_path: Option<String>,
    #[serde(default)]
    stop_hook_active: bool,
}

pub(crate) fn run_hook(entropy_cfg: &EntropyConfig) {
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
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME not set"))?;
    let path = if transcript_path.starts_with('~') {
        PathBuf::from(transcript_path.replacen('~', &home.to_string_lossy(), 1))
    } else {
        PathBuf::from(&transcript_path)
    };

    if !path.exists() {
        return Ok(());
    }

    // Canonicalize to resolve symlinks and ../ components, then validate
    // the path is under ~/.claude/ to prevent arbitrary file writes.
    let canonical = path.canonicalize()?;
    let allowed_prefix = home.join(".claude");
    if !canonical.starts_with(&allowed_prefix) {
        warn!(
            path = %canonical.display(),
            allowed = %allowed_prefix.display(),
            "transcript path is outside ~/.claude/, refusing to process"
        );
        return Ok(());
    }

    let pattern_set = PatternSet::load(false)?;
    let allowlist = Allowlist::load()?;

    let result = jsonl::scrub_jsonl_file(&canonical, &pattern_set, entropy_cfg, &allowlist, false)?;

    if !result.redactions.is_empty() {
        info!(
            count = result.redactions.len(),
            file = %canonical.display(),
            "scrub-history: redacted secret(s)"
        );
    }

    Ok(())
}
