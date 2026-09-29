use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const STATE_FILENAME: &str = "scrubber-hook-state.json";

#[derive(Serialize, Deserialize, Default)]
pub struct HookState {
    pub config_fingerprint: String,
    /// Per-file byte offset of the end of the last complete line already
    /// scrubbed (see `jsonl::ScrubResult::final_size`).
    pub file_offsets: HashMap<String, u64>,
}

fn state_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".claude").join(STATE_FILENAME))
}

pub fn load(expected_fingerprint: &str) -> HookState {
    state_path().map_or_else(HookState::default, |p| load_from(&p, expected_fingerprint))
}

pub fn save(state: &HookState) -> Result<()> {
    match state_path() {
        Some(path) => save_to(&path, state),
        None => Ok(()),
    }
}

pub fn load_from(path: &Path, expected_fingerprint: &str) -> HookState {
    let Ok(data) = std::fs::read_to_string(path) else {
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

/// Write the state atomically (temp file + rename) so a crash or a
/// concurrent hook run never leaves a truncated file behind.
pub fn save_to(path: &Path, state: &HookState) -> Result<()> {
    let data = serde_json::to_string(state).context("serializing hook state")?;
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("creating temp file in {}", dir.display()))?;
    temp.write_all(data.as_bytes())?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_invalidates_on_fingerprint_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILENAME);
        let mut state = HookState {
            config_fingerprint: "fp1".into(),
            ..Default::default()
        };
        state.file_offsets.insert("/a.jsonl".into(), 42);
        save_to(&path, &state).unwrap();

        assert_eq!(
            load_from(&path, "fp1").file_offsets.get("/a.jsonl"),
            Some(&42)
        );
        assert!(load_from(&path, "fp2").file_offsets.is_empty());
        // No temp files left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn corrupt_state_loads_as_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILENAME);
        std::fs::write(&path, "{not json").unwrap();
        assert!(load_from(&path, "fp").file_offsets.is_empty());
    }
}
