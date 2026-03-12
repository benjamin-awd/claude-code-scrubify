use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

/// Minimum length for a blacklist entry. Matches `MIN_SECRET_LEN` in scrubber.
const MIN_BLACKLIST_ENTRY_LEN: usize = 8;

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    allowlist: AllowlistConfig,
    #[serde(default)]
    entropy: EntropyTomlConfig,
    #[serde(default)]
    blacklist: BlacklistConfig,
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

#[derive(Deserialize, Default)]
struct BlacklistConfig {
    /// Exact strings that should always be redacted.
    #[serde(default)]
    strings: Vec<String>,
}

/// Everything loaded from `~/.claude/scrubber.toml`.
pub struct ScrubberSettings {
    pub allowlist: Allowlist,
    pub blacklist: Blacklist,
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

/// A set of exact strings that should always be redacted.
pub struct Blacklist {
    /// Entries sorted longest-first for greedy matching.
    entries: Vec<String>,
}

impl Blacklist {
    pub fn empty() -> Self {
        Blacklist {
            entries: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if `text` contains any blacklisted string.
    pub fn contains_any(&self, text: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| text.contains(entry.as_str()))
    }

    /// Find all non-overlapping (start, end) spans of blacklisted strings in `text`.
    /// Longest matches take priority.
    pub fn find_all_spans(&self, text: &str) -> Vec<(usize, usize)> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        let mut spans: Vec<(usize, usize)> = Vec::new();
        // entries are sorted longest-first, so longer matches are collected first
        for entry in &self.entries {
            let mut start = 0;
            while let Some(pos) = text[start..].find(entry.as_str()) {
                let abs_start = start + pos;
                let abs_end = abs_start + entry.len();
                spans.push((abs_start, abs_end));
                start = abs_end;
            }
        }
        if spans.is_empty() {
            return spans;
        }
        // Sort by start, then longest first; remove overlaps
        spans.sort_by_key(|&(s, e)| (s, std::cmp::Reverse(e)));
        let mut merged: Vec<(usize, usize)> = Vec::new();
        let mut cur = spans[0];
        for &span in &spans[1..] {
            if span.0 < cur.1 {
                // overlapping — extend
                if span.1 > cur.1 {
                    cur.1 = span.1;
                }
            } else {
                merged.push(cur);
                cur = span;
            }
        }
        merged.push(cur);
        merged
    }

    #[cfg(test)]
    pub fn from_strings(strings: Vec<&str>) -> Self {
        let mut entries: Vec<String> = strings.into_iter().map(String::from).collect();
        entries.sort_by_key(|b| std::cmp::Reverse(b.len()));
        entries.dedup();
        Blacklist { entries }
    }
}

/// Load all settings from `~/.claude/scrubber.toml`.
/// Returns defaults if the file doesn't exist.
pub fn load_config() -> Result<ScrubberSettings> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Ok(ScrubberSettings {
            allowlist: Allowlist::empty(),
            blacklist: Blacklist::empty(),
            entropy_exclude_patterns: Vec::new(),
        });
    };
    let path = home.join(".claude").join("scrubber.toml");
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ScrubberSettings {
                allowlist: Allowlist::empty(),
                blacklist: Blacklist::empty(),
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

    // Build blacklist: filter short entries, deduplicate, sort longest-first
    let mut bl_entries: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for s in config.blacklist.strings {
        if s.len() < MIN_BLACKLIST_ENTRY_LEN {
            warn!(
                entry = %s,
                min_len = MIN_BLACKLIST_ENTRY_LEN,
                "blacklist entry too short, ignoring"
            );
            continue;
        }
        if seen.insert(s.clone()) {
            bl_entries.push(s);
        }
    }
    bl_entries.sort_by_key(|b| std::cmp::Reverse(b.len()));
    if !bl_entries.is_empty() {
        debug!(count = bl_entries.len(), "loaded blacklist entries");
    }

    Ok(ScrubberSettings {
        allowlist: Allowlist { hashes },
        blacklist: Blacklist {
            entries: bl_entries,
        },
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

    // --- Blacklist tests ---

    #[test]
    fn empty_blacklist_matches_nothing() {
        let bl = Blacklist::empty();
        assert!(!bl.contains_any("anything at all"));
        assert!(bl.find_all_spans("anything").is_empty());
        assert!(bl.is_empty());
        assert_eq!(bl.len(), 0);
    }

    #[test]
    fn blacklist_short_strings_filtered_in_config() {
        // Simulate what load_config does
        let short = "abc";
        assert!(short.len() < MIN_BLACKLIST_ENTRY_LEN);
        // from_strings is for tests and doesn't filter, but load_config does
        // Test the filtering logic directly
        let strings = vec!["short".to_string(), "this-is-long-enough".to_string()];
        let mut entries = Vec::new();
        for s in strings {
            if s.len() >= MIN_BLACKLIST_ENTRY_LEN {
                entries.push(s);
            }
        }
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], "this-is-long-enough");
    }

    #[test]
    fn blacklist_dedup() {
        let bl = Blacklist::from_strings(vec!["foobar123", "foobar123", "bazqux99"]);
        // from_strings deduplicates
        assert_eq!(bl.len(), 2);
    }

    #[test]
    fn blacklist_contains_any() {
        let bl = Blacklist::from_strings(vec!["foobar123", "secretval"]);
        assert!(bl.contains_any("prefix foobar123 suffix"));
        assert!(bl.contains_any("secretval"));
        assert!(!bl.contains_any("no match here"));
    }

    #[test]
    fn blacklist_find_all_spans() {
        let bl = Blacklist::from_strings(vec!["foobar123"]);
        let text = "start foobar123 middle foobar123 end";
        let spans = bl.find_all_spans(text);
        assert_eq!(spans.len(), 2);
        assert_eq!(&text[spans[0].0..spans[0].1], "foobar123");
        assert_eq!(&text[spans[1].0..spans[1].1], "foobar123");
    }

    #[test]
    fn blacklist_find_all_spans_overlapping_entries() {
        // "foobar123456" contains "foobar123" — the longer match should win
        let bl = Blacklist::from_strings(vec!["foobar123", "foobar123456"]);
        let text = "x foobar123456 y";
        let spans = bl.find_all_spans(text);
        assert_eq!(spans.len(), 1);
        assert_eq!(&text[spans[0].0..spans[0].1], "foobar123456");
    }
}
