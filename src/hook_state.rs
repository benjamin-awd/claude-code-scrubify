use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const STATE_FILENAME: &str = "scrubber-hook-state.json";

#[derive(Serialize, Deserialize, Default)]
pub struct HookState {
    pub config_fingerprint: String,
    pub file_offsets: HashMap<String, u64>,
}

fn state_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".claude").join(STATE_FILENAME))
}

pub fn load(expected_fingerprint: &str) -> HookState {
    let Some(path) = state_path() else {
        return HookState::default();
    };
    let Ok(data) = std::fs::read_to_string(&path) else {
        return HookState::default();
    };
    let Ok(state) = serde_json::from_str::<HookState>(&data) else {
        return HookState::default();
    };
    if state.config_fingerprint != expected_fingerprint {
        tracing::info!("config changed, invalidating hook state");
        return HookState::default();
    }
    state
}

pub fn save(state: &HookState) -> Result<()> {
    let Some(path) = state_path() else {
        return Ok(());
    };
    let data = serde_json::to_string(state).context("serializing hook state")?;
    std::fs::write(&path, data.as_bytes()).context(format!("writing {}", path.display()))
}
