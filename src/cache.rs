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

/// Compute a fingerprint from scrubber.toml contents, entropy config flags, the
/// binary version and the built-in pattern set. Any change invalidates the scan
/// cache and hook offsets, so upgrades that add patterns rescan old history.
pub fn compute_config_fingerprint(entropy_enabled: bool, entropy_threshold: f64) -> String {
    let toml = std::env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|h| std::fs::read(h.join(".claude").join("scrubber.toml")).ok());
    let engine = format!(
        "{}:{}",
        env!("CARGO_PKG_VERSION"),
        crate::patterns::built_in_fingerprint()
    );
    fingerprint_from_parts(toml.as_deref(), entropy_enabled, entropy_threshold, &engine)
}

fn fingerprint_from_parts(
    toml: Option<&[u8]>,
    entropy_enabled: bool,
    entropy_threshold: f64,
    engine: &str,
) -> String {
    let mut hasher = Sha256::new();

    if let Some(contents) = toml {
        hasher.update(contents);
    }

    if entropy_enabled {
        hasher.update(b"entropy:on");
    } else {
        hasher.update(b"entropy:off");
    }
    hasher.update(entropy_threshold.to_le_bytes());

    hasher.update(b"engine:");
    hasher.update(engine.as_bytes());

    crate::allowlist::to_hex(&hasher.finalize())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_change_invalidates_fingerprint() {
        let a = fingerprint_from_parts(Some(b"x"), true, 4.5, "0.4.0:aaa");
        let b = fingerprint_from_parts(Some(b"x"), true, 4.5, "0.4.0:bbb");
        let c = fingerprint_from_parts(Some(b"x"), true, 4.5, "0.5.0:aaa");
        assert_ne!(a, b, "pattern set change must invalidate");
        assert_ne!(a, c, "version change must invalidate");
        assert_eq!(
            a,
            fingerprint_from_parts(Some(b"x"), true, 4.5, "0.4.0:aaa")
        );
    }
}
