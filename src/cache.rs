use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CACHE_FILENAME: &str = "scrubber-cache.json";

#[derive(Serialize, Deserialize, Default)]
pub struct ScanCache {
    pub config_fingerprint: String,
    pub entries: HashMap<String, CacheEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CacheEntry {
    pub mtime_secs: u64,
    pub mtime_nanos: u32,
    pub size: u64,
}

pub fn cache_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".claude").join(CACHE_FILENAME))
}

pub fn load(expected_fingerprint: &str) -> ScanCache {
    let Some(path) = cache_path() else {
        return ScanCache::default();
    };
    let Ok(data) = std::fs::read_to_string(&path) else {
        return ScanCache::default();
    };
    let Ok(cache) = serde_json::from_str::<ScanCache>(&data) else {
        return ScanCache::default();
    };
    if cache.config_fingerprint != expected_fingerprint {
        tracing::info!("config changed, invalidating scan cache");
        return ScanCache::default();
    }
    cache
}

pub fn save(cache: &ScanCache) -> Result<()> {
    let Some(path) = cache_path() else {
        return Ok(());
    };
    let data = serde_json::to_string(cache).context("serializing scan cache")?;
    std::fs::write(&path, data.as_bytes()).context(format!("writing {}", path.display()))
}

/// Compute a fingerprint from scrubber.toml contents and entropy config flags.
pub fn compute_config_fingerprint(entropy_enabled: bool, entropy_threshold: f64) -> String {
    let mut hasher = Sha256::new();

    // Hash scrubber.toml contents if present
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let toml_path = home.join(".claude").join("scrubber.toml");
        if let Ok(contents) = std::fs::read(&toml_path) {
            hasher.update(&contents);
        }
    }

    // Hash entropy settings
    if entropy_enabled {
        hasher.update(b"entropy:on");
    } else {
        hasher.update(b"entropy:off");
    }
    hasher.update(entropy_threshold.to_le_bytes());

    format!("{:x}", hasher.finalize())
}

/// Check whether a file's current metadata matches a cache entry.
pub fn file_metadata_matches(path: &Path, entry: &CacheEntry) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    #[allow(clippy::cast_possible_truncation)]
    if let Ok(mtime) = meta.modified()
        && let Ok(dur) = mtime.duration_since(std::time::UNIX_EPOCH)
    {
        dur.as_secs() == entry.mtime_secs
            && dur.subsec_nanos() == entry.mtime_nanos
            && meta.len() == entry.size
    } else {
        false
    }
}

/// Build a `CacheEntry` from the current file metadata.
pub fn cache_entry_from_path(path: &Path) -> Option<CacheEntry> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?;
    let dur = mtime.duration_since(std::time::UNIX_EPOCH).ok()?;
    #[allow(clippy::cast_possible_truncation)]
    Some(CacheEntry {
        mtime_secs: dur.as_secs(),
        mtime_nanos: dur.subsec_nanos(),
        size: meta.len(),
    })
}
