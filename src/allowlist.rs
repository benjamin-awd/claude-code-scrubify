use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;

use serde::Deserialize;
use tracing::debug;

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    allowlist: AllowlistConfig,
    #[serde(default)]
    entropy: EntropyTomlConfig,
}

#[derive(Deserialize, Default)]
struct AllowlistConfig {
    /// SHA-256 hashes of values that should not be redacted.
    #[serde(default)]
    hashes: Vec<String>,
}

#[derive(Deserialize, Default)]
struct EntropyTomlConfig {
    /// Regex patterns for tokens to exclude from entropy detection.
    #[serde(default)]
    exclude_patterns: Vec<String>,
}

/// Everything loaded from `~/.claude/scrubber.toml`.
pub struct ScrubberSettings {
    pub allowlist: Allowlist,
    /// User-defined regex patterns to exclude from entropy detection.
    pub entropy_exclude_patterns: Vec<String>,
}

pub struct Allowlist {
    hashes: HashSet<String>,
}

impl Allowlist {
    /// Load the allowlist from `~/.claude/scrubber.toml`.
    /// Returns an empty allowlist if the file doesn't exist.
    pub fn load() -> Result<Self> {
        Ok(load_config()?.allowlist)
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn empty() -> Self {
        Allowlist {
            hashes: HashSet::new(),
        }
    }

    #[cfg(test)]
    pub fn from_hashes(hashes: Vec<String>) -> Self {
        Allowlist {
            hashes: hashes.into_iter().map(|h| h.to_lowercase()).collect(),
        }
    }

    /// Returns true if the given value is allowlisted (its SHA-256 hash is in
    /// the set).
    pub fn is_allowed(&self, value: &str) -> bool {
        if self.hashes.is_empty() {
            return false;
        }
        let hash = sha256_hex(value);
        self.hashes.contains(&hash)
    }
}

/// Load all settings from `~/.claude/scrubber.toml`.
/// Returns defaults if the file doesn't exist.
pub fn load_config() -> Result<ScrubberSettings> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Ok(ScrubberSettings {
            allowlist: Allowlist::empty(),
            entropy_exclude_patterns: Vec::new(),
        });
    };
    let path = home.join(".claude").join("scrubber.toml");
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ScrubberSettings {
                allowlist: Allowlist::empty(),
                entropy_exclude_patterns: Vec::new(),
            });
        }
        Err(e) => return Err(e).context(format!("reading {}", path.display())),
    };
    let config: Config = toml::from_str(&data).context(format!("parsing {}", path.display()))?;
    let hashes: HashSet<String> = config
        .allowlist
        .hashes
        .into_iter()
        .map(|h| h.to_lowercase())
        .collect();
    debug!(count = hashes.len(), "loaded allowlist hashes");
    if !config.entropy.exclude_patterns.is_empty() {
        debug!(
            count = config.entropy.exclude_patterns.len(),
            "loaded entropy exclude patterns"
        );
    }
    Ok(ScrubberSettings {
        allowlist: Allowlist { hashes },
        entropy_exclude_patterns: config.entropy.exclude_patterns,
    })
}

/// Compute the lowercase hex SHA-256 digest of a string.
pub fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_known_value() {
        // echo -n "hello" | sha256sum
        assert_eq!(
            sha256_hex("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn empty_allowlist_allows_nothing() {
        let al = Allowlist::empty();
        assert!(!al.is_allowed("anything"));
    }

    #[test]
    fn allowlist_matches_by_hash() {
        let hash = sha256_hex("my-secret-value");
        let al = Allowlist {
            hashes: HashSet::from([hash]),
        };
        assert!(al.is_allowed("my-secret-value"));
        assert!(!al.is_allowed("other-value"));
    }

    #[test]
    fn allowlist_case_insensitive_hash() {
        let hash = sha256_hex("test").to_uppercase();
        let al = Allowlist {
            hashes: HashSet::from([hash.to_lowercase()]),
        };
        assert!(al.is_allowed("test"));
    }
}
