use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::display;

const STATS_FILENAME: &str = "scrubber-stats.json";

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct PersistentStats {
    #[serde(default)]
    pub last_hook: Option<HookRunStats>,
    #[serde(default)]
    pub last_scan: Option<ScanRunStats>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HookRunStats {
    pub timestamp_epoch: u64,
    pub file: String,
    pub redactions: u64,
    pub duration_ms: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ScanRunStats {
    pub timestamp_epoch: u64,
    pub files_scanned: u64,
    pub files_modified: u64,
    pub total_redactions: u64,
    pub errors: u64,
    pub duration_ms: u64,
    pub dry_run: bool,
    #[serde(default)]
    pub redactions_by_pattern: HashMap<String, u64>,
}

pub fn stats_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".claude").join(STATS_FILENAME))
}

pub fn load() -> Result<PersistentStats> {
    let Some(path) = stats_path() else {
        return Ok(PersistentStats::default());
    };
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PersistentStats::default());
        }
        Err(e) => return Err(e).context(format!("reading {}", path.display())),
    };
    serde_json::from_str(&data).context(format!("parsing {}", path.display()))
}

pub fn save(stats: &PersistentStats) -> Result<()> {
    let Some(path) = stats_path() else {
        return Ok(());
    };
    let data = serde_json::to_string_pretty(stats).context("serializing stats")?;
    std::fs::write(&path, data.as_bytes()).context(format!("writing {}", path.display()))
}

pub fn now_epoch() -> u64 {
    display::now_epoch()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_stats() {
        let stats = PersistentStats {
            last_hook: Some(HookRunStats {
                timestamp_epoch: 1_700_000_000,
                file: "test.jsonl".into(),
                redactions: 5,
                duration_ms: 42,
            }),
            last_scan: None,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: PersistentStats = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.last_hook.as_ref().unwrap().redactions, 5);
    }

    #[test]
    fn default_stats_are_empty() {
        let stats = PersistentStats::default();
        assert!(stats.last_hook.is_none());
        assert!(stats.last_scan.is_none());
    }
}
