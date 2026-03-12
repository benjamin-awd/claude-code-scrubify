use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::display;

const STATS_FILENAME: &str = "scrubber-stats.json";
const MAX_HOOK_HISTORY: usize = 100;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct PersistentStats {
    #[serde(default)]
    pub last_hook: Option<HookRunStats>,
    #[serde(default)]
    pub hook_history: Vec<HookRunStats>,
    #[serde(default)]
    pub last_scan: Option<ScanRunStats>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HookRunStats {
    pub timestamp_epoch: u64,
    pub file: String,
    pub redactions: u64,
    pub duration_ms: u64,
    #[serde(default)]
    pub file_size_bytes: u64,
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
    pub files_cached: u64,
    #[serde(default)]
    pub redactions_by_pattern: HashMap<String, u64>,
}

pub struct LatencySummary {
    pub count: usize,
    pub avg_ms: f64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub max_ms: u64,
    pub total_ms: u64,
}

impl PersistentStats {
    pub fn push_hook_run(&mut self, run: HookRunStats) {
        self.last_hook = Some(run.clone());
        self.hook_history.push(run);
        if self.hook_history.len() > MAX_HOOK_HISTORY {
            let excess = self.hook_history.len() - MAX_HOOK_HISTORY;
            self.hook_history.drain(..excess);
        }
    }

    pub fn hook_latency(&self) -> Option<LatencySummary> {
        if self.hook_history.is_empty() {
            return None;
        }
        let mut durations: Vec<u64> = self.hook_history.iter().map(|r| r.duration_ms).collect();
        durations.sort_unstable();
        Some(LatencySummary::from_sorted(&durations))
    }
}

impl LatencySummary {
    fn from_sorted(sorted: &[u64]) -> Self {
        let count = sorted.len();
        let total_ms: u64 = sorted.iter().sum();
        #[allow(clippy::cast_precision_loss)]
        let avg_ms = total_ms as f64 / count as f64;
        let p50_ms = percentile(sorted, 50);
        let p95_ms = percentile(sorted, 95);
        let max_ms = sorted[count - 1];
        LatencySummary {
            count,
            avg_ms,
            p50_ms,
            p95_ms,
            max_ms,
            total_ms,
        }
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn percentile(sorted: &[u64], pct: u64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (pct as f64 / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
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

    fn make_hook_run(duration_ms: u64) -> HookRunStats {
        HookRunStats {
            timestamp_epoch: 1_700_000_000,
            file: "test.jsonl".into(),
            redactions: 0,
            duration_ms,
            file_size_bytes: 1024,
        }
    }

    #[test]
    fn round_trip_stats() {
        let stats = PersistentStats {
            last_hook: Some(make_hook_run(42)),
            hook_history: vec![make_hook_run(42)],
            last_scan: None,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: PersistentStats = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.last_hook.as_ref().unwrap().duration_ms, 42);
        assert_eq!(parsed.hook_history.len(), 1);
    }

    #[test]
    fn default_stats_are_empty() {
        let stats = PersistentStats::default();
        assert!(stats.last_hook.is_none());
        assert!(stats.hook_history.is_empty());
        assert!(stats.last_scan.is_none());
    }

    #[test]
    fn push_hook_run_caps_at_max() {
        let mut stats = PersistentStats::default();
        for i in 0..150 {
            stats.push_hook_run(make_hook_run(i));
        }
        assert_eq!(stats.hook_history.len(), MAX_HOOK_HISTORY);
        // Oldest entries were drained, newest kept
        assert_eq!(stats.hook_history[0].duration_ms, 50);
        assert_eq!(stats.hook_history.last().unwrap().duration_ms, 149);
        assert_eq!(stats.last_hook.as_ref().unwrap().duration_ms, 149);
    }

    #[test]
    fn latency_summary_percentiles() {
        let mut stats = PersistentStats::default();
        // 10, 20, 30, ..., 100
        for i in 1..=10 {
            stats.push_hook_run(make_hook_run(i * 10));
        }
        let summary = stats.hook_latency().unwrap();
        assert_eq!(summary.count, 10);
        assert!((summary.avg_ms - 55.0).abs() < 0.01);
        assert_eq!(summary.p50_ms, 60); // index 4.5 rounds to 5 → sorted[5] = 60
        assert_eq!(summary.max_ms, 100);
    }

    #[test]
    fn latency_empty_returns_none() {
        let stats = PersistentStats::default();
        assert!(stats.hook_latency().is_none());
    }

    #[test]
    fn percentile_single_element() {
        assert_eq!(percentile(&[42], 50), 42);
        assert_eq!(percentile(&[42], 95), 42);
    }
}
