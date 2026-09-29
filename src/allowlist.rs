use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, error, warn};

/// Default minimum length for a blacklist entry. Matches `MIN_SECRET_LEN` in scrubber.
const DEFAULT_MIN_BLACKLIST_ENTRY_LEN: usize = 8;

/// Compiled-size limit for user-supplied regexes (same as the `regex` crate
/// default). Oversized patterns are skipped instead of aborting the load.
const CUSTOM_PATTERN_SIZE_LIMIT: usize = 10 * (1 << 20);

#[derive(Deserialize, Clone)]
pub struct CustomPatternConfig {
    pub name: String,
    pub regex: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub secret_group: Option<usize>,
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
    /// Exact strings that should always be redacted (substring match).
    #[serde(default)]
    strings: Vec<String>,
    /// SHA-256 hashes of values that should always be redacted (exact match).
    #[serde(default)]
    hashes: Vec<String>,
    /// Minimum string length for blacklist entries (default: 8).
    #[serde(default)]
    min_string_length: Option<usize>,
}

/// Everything loaded from `~/.claude/scrubber.toml`.
pub struct ScrubberSettings {
    pub allowlist: Allowlist,
    pub blacklist: Blacklist,
    /// User-defined regex patterns to exclude from entropy detection.
    pub entropy_exclude_patterns: Vec<String>,
    /// User-defined secret detection patterns.
    pub custom_patterns: Vec<CustomPatternConfig>,
    /// Problems found while loading the config. These messages never contain
    /// config values (which may be secrets), only locations and section names.
    pub config_errors: Vec<String>,
}

impl ScrubberSettings {
    /// Built-in defaults: no allowlist, no blacklist, no custom patterns.
    pub fn defaults() -> Self {
        ScrubberSettings {
            allowlist: Allowlist::empty(),
            blacklist: Blacklist::empty(),
            entropy_exclude_patterns: Vec::new(),
            custom_patterns: Vec::new(),
            config_errors: Vec::new(),
        }
    }
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
    /// Plaintext entries sorted longest-first for greedy substring matching.
    entries: Vec<String>,
    /// SHA-256 hashes for exact whole-value matching.
    hashes: HashSet<String>,
}

impl Blacklist {
    pub fn empty() -> Self {
        Blacklist {
            entries: Vec::new(),
            hashes: HashSet::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.hashes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len() + self.hashes.len()
    }

    /// Returns true if `text` contains any blacklisted substring, or if
    /// `text` exactly matches a blacklisted hash.
    pub fn contains_any(&self, text: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| text.contains(entry.as_str()))
            || self.is_hash_match(text)
    }

    /// Returns true if `value`'s SHA-256 hash is in the blacklist hash set.
    pub fn is_hash_match(&self, value: &str) -> bool {
        if self.hashes.is_empty() {
            return false;
        }
        let hash = sha256_hex(value);
        self.hashes.contains(&hash)
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
        Blacklist {
            entries,
            hashes: HashSet::new(),
        }
    }

    #[cfg(test)]
    pub fn from_hashes(hashes: Vec<String>) -> Self {
        Blacklist {
            entries: Vec::new(),
            hashes: hashes.into_iter().map(|h| h.to_lowercase()).collect(),
        }
    }
}

/// Path of the config file: `~/.claude/scrubber.toml`.
pub fn config_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".claude").join("scrubber.toml"))
}

/// Load all settings from `~/.claude/scrubber.toml`.
///
/// Returns defaults if the file doesn't exist. A config that can't be read
/// or parsed never disables redaction: the problem is logged loudly, recorded
/// in [`ScrubberSettings::config_errors`], and built-in defaults are used.
pub fn load_config() -> Result<ScrubberSettings> {
    Ok(config_path().map_or_else(ScrubberSettings::defaults, |p| load_config_from(&p)))
}

/// Load settings from an explicit path. See [`load_config`].
pub fn load_config_from(path: &Path) -> ScrubberSettings {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return ScrubberSettings::defaults();
        }
        Err(e) => {
            let msg = format!("could not read {}: {}", path.display(), e.kind());
            return fallback_to_defaults(msg);
        }
    };
    parse_config(&data, path)
}

fn fallback_to_defaults(msg: String) -> ScrubberSettings {
    error!(
        problem = %msg,
        "scrubber.toml is unusable; FALLING BACK to built-in patterns and default settings. \
         Your custom patterns, blacklist and allowlist are NOT being applied until it is fixed"
    );
    let mut settings = ScrubberSettings::defaults();
    settings.config_errors.push(msg);
    settings
}

/// Describe a TOML syntax error by location and message only. The `Display`
/// impl of `toml::de::Error` quotes the offending source line, which may
/// contain a blacklisted secret, so it must never be logged.
pub fn describe_toml_error(
    data: &str,
    message: &str,
    span: Option<std::ops::Range<usize>>,
) -> String {
    match span {
        Some(span) => {
            let (line, col) = line_col(data, span.start);
            format!("TOML syntax error at line {line}, column {col}: {message}")
        }
        None => format!("TOML syntax error: {message}"),
    }
}

fn line_col(data: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(data.len());
    let before = data.get(..offset).unwrap_or(data);
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
    (line, col)
}

/// Deserialize one top-level section. On failure the section falls back to its
/// default and a sanitized error is recorded (serde messages can echo values).
fn parse_section<T: serde::de::DeserializeOwned + Default>(
    table: &toml::Table,
    name: &str,
    errors: &mut Vec<String>,
) -> T {
    let Some(value) = table.get(name) else {
        return T::default();
    };
    if let Ok(v) = value.clone().try_into::<T>() {
        v
    } else {
        let msg = format!("[{name}] section has the wrong shape and was ignored");
        error!(section = name, "invalid scrubber.toml section, ignoring it");
        errors.push(msg);
        T::default()
    }
}

fn parse_custom_patterns(
    table: &toml::Table,
    errors: &mut Vec<String>,
) -> Vec<CustomPatternConfig> {
    let Some(value) = table.get("patterns") else {
        return Vec::new();
    };
    let Some(arr) = value.as_array() else {
        let msg = "`patterns` must be an array of tables ([[patterns]]); ignored".to_string();
        error!("{msg}");
        errors.push(msg);
        return Vec::new();
    };
    let mut out = Vec::new();
    for (index, v) in arr.iter().enumerate() {
        if let Ok(p) = v.clone().try_into::<CustomPatternConfig>() {
            out.push(p);
        } else {
            let name = v
                .get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or("<unnamed>");
            let msg = format!(
                "custom pattern #{} ('{name}') is malformed (needs `name` and `regex` strings); skipped",
                index + 1
            );
            warn!(index, pattern = name, "malformed custom pattern, skipping");
            errors.push(msg);
        }
    }
    out
}

fn parse_config(data: &str, path: &Path) -> ScrubberSettings {
    let table: toml::Table = match toml::from_str(data) {
        Ok(t) => t,
        Err(e) => {
            let msg = format!(
                "{}: {}",
                path.display(),
                describe_toml_error(data, e.message(), e.span())
            );
            return fallback_to_defaults(msg);
        }
    };
    let mut config_errors = Vec::new();
    let allowlist: AllowlistConfig = parse_section(&table, "allowlist", &mut config_errors);
    let entropy: EntropyTomlConfig = parse_section(&table, "entropy", &mut config_errors);
    let blacklist: BlacklistConfig = parse_section(&table, "blacklist", &mut config_errors);
    let custom_patterns = parse_custom_patterns(&table, &mut config_errors);

    let hashes: HashSet<String> = allowlist
        .hashes
        .into_iter()
        .map(|h| h.to_lowercase())
        .collect();
    debug!(count = hashes.len(), "loaded allowlist hashes");
    if !entropy.exclude_patterns.is_empty() {
        debug!(
            count = entropy.exclude_patterns.len(),
            "loaded entropy exclude patterns"
        );
    }

    // Build blacklist: filter short entries, deduplicate, sort longest-first
    let min_len = blacklist
        .min_string_length
        .unwrap_or(DEFAULT_MIN_BLACKLIST_ENTRY_LEN);
    let mut bl_entries: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for (index, s) in blacklist.strings.into_iter().enumerate() {
        if s.len() < min_len {
            // Never log the entry itself: it is a secret.
            warn!(
                index,
                len = s.len(),
                min_len,
                "blacklist.strings entry too short, ignoring"
            );
            continue;
        }
        if seen.insert(s.clone()) {
            bl_entries.push(s);
        }
    }
    bl_entries.sort_by_key(|b| std::cmp::Reverse(b.len()));
    if !bl_entries.is_empty() {
        debug!(count = bl_entries.len(), "loaded blacklist string entries");
    }

    let bl_hashes: HashSet<String> = blacklist
        .hashes
        .into_iter()
        .map(|h| h.to_lowercase())
        .collect();
    if !bl_hashes.is_empty() {
        debug!(count = bl_hashes.len(), "loaded blacklist hashes");
    }

    ScrubberSettings {
        allowlist: Allowlist { hashes },
        blacklist: Blacklist {
            entries: bl_entries,
            hashes: bl_hashes,
        },
        entropy_exclude_patterns: entropy.exclude_patterns,
        custom_patterns,
        config_errors,
    }
}

/// Compile a user-defined pattern, validating it for use in a `PatternSet`.
///
/// The error string never contains the regex source (a custom pattern may
/// embed a literal secret), only the kind of problem.
pub fn compile_custom_pattern(c: &CustomPatternConfig) -> std::result::Result<Regex, String> {
    let regex = RegexBuilder::new(&c.regex)
        .size_limit(CUSTOM_PATTERN_SIZE_LIMIT)
        .build()
        .map_err(|e| match e {
            regex::Error::CompiledTooBig(limit) => {
                format!("regex is too large (compiled size exceeds {limit} bytes)")
            }
            _ => "invalid regex syntax".to_string(),
        })?;
    if regex.is_match("") {
        return Err("regex matches the empty string".to_string());
    }
    if let Some(group) = c.secret_group
        && group >= regex.captures_len()
    {
        return Err(format!(
            "secret_group {group} does not exist (regex has {} capture group(s))",
            regex.captures_len() - 1
        ));
    }
    Ok(regex)
}

/// Compute the lowercase hex SHA-256 digest of a string.
pub fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    to_hex(&hasher.finalize())
}

/// Encode bytes as a lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
pub(crate) mod tests {
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

    /// Capture everything logged (at any level) while running `f`.
    pub(crate) fn capture_logs<R>(f: impl FnOnce() -> R) -> (R, String) {
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let r = tracing::subscriber::with_default(subscriber, f);
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        (r, out)
    }

    #[test]
    fn short_blacklist_entry_warning_does_not_print_the_entry() {
        let toml = r#"
[blacklist]
strings = ["pw-7Qx", "this-is-long-enough"]
"#;
        let (settings, logs) = capture_logs(|| parse_config(toml, Path::new("scrubber.toml")));
        assert_eq!(settings.blacklist.len(), 1);
        assert!(settings.blacklist.contains_any("x this-is-long-enough y"));
        assert!(logs.contains("too short"), "expected a warning: {logs}");
        assert!(logs.contains("index=0"), "{logs}");
        assert!(logs.contains("len=6"), "{logs}");
        assert!(!logs.contains("pw-7Qx"), "secret leaked into logs: {logs}");
    }

    #[test]
    fn toml_syntax_error_falls_back_to_defaults_without_echoing_config() {
        let toml = "[blacklist]\nstrings = [\"hunter2-hunter2-secret\"\n[allowlist\n";
        let (settings, logs) = capture_logs(|| parse_config(toml, Path::new("scrubber.toml")));
        assert!(settings.blacklist.is_empty());
        assert!(settings.custom_patterns.is_empty());
        assert_eq!(settings.config_errors.len(), 1);
        let err = &settings.config_errors[0];
        assert!(err.contains("line"), "{err}");
        assert!(!err.contains("hunter2"), "secret leaked into error: {err}");
        assert!(logs.contains("FALLING BACK"), "{logs}");
        assert!(!logs.contains("hunter2"), "secret leaked into logs: {logs}");
    }

    #[test]
    fn unreadable_or_missing_config_uses_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let settings = load_config_from(&dir.path().join("missing.toml"));
        assert!(settings.config_errors.is_empty());
        // A directory where the file should be -> read error -> fallback
        let settings = load_config_from(dir.path());
        assert_eq!(settings.config_errors.len(), 1);
    }

    #[test]
    fn bad_section_does_not_discard_other_sections() {
        let toml = r#"
entropy = "not-a-table"

[blacklist]
strings = ["this-is-long-enough"]
min_string_length = "eight-chars-secret"

[allowlist]
hashes = ["ABC"]
"#;
        let (settings, logs) = capture_logs(|| parse_config(toml, Path::new("scrubber.toml")));
        // blacklist had a bad key -> whole section ignored, but allowlist loads
        assert_eq!(settings.allowlist.len(), 1);
        assert_eq!(settings.config_errors.len(), 2);
        assert!(
            settings
                .config_errors
                .iter()
                .any(|e| e.contains("[entropy]"))
        );
        assert!(
            settings
                .config_errors
                .iter()
                .any(|e| e.contains("[blacklist]"))
        );
        assert!(!logs.contains("eight-chars-secret"), "{logs}");
    }

    #[test]
    fn malformed_custom_pattern_is_skipped_others_kept() {
        let toml = r#"
[[patterns]]
name = "good"
regex = "itk_[a-z]{8}"

[[patterns]]
name = "no-regex"

[[patterns]]
name = "good2"
regex = "itk2_[a-z]{8}"
"#;
        let settings = parse_config(toml, Path::new("scrubber.toml"));
        let names: Vec<_> = settings
            .custom_patterns
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, vec!["good", "good2"]);
        assert_eq!(settings.config_errors.len(), 1);
        assert!(settings.config_errors[0].contains("no-regex"));
    }

    fn custom(regex: &str, secret_group: Option<usize>) -> CustomPatternConfig {
        CustomPatternConfig {
            name: "p".into(),
            regex: regex.into(),
            keywords: Vec::new(),
            secret_group,
        }
    }

    #[test]
    fn compile_custom_pattern_errors_never_echo_the_regex() {
        let err = compile_custom_pattern(&custom("literal-s3cret-value(", None)).unwrap_err();
        assert_eq!(err, "invalid regex syntax");
        assert!(!err.contains("s3cret"));

        let err = compile_custom_pattern(&custom(r"\w{5000}\w{5000}", None)).unwrap_err();
        assert!(err.contains("too large"), "{err}");

        let err = compile_custom_pattern(&custom("a*", None)).unwrap_err();
        assert!(err.contains("empty string"));

        let err = compile_custom_pattern(&custom("k=(v+)", Some(2))).unwrap_err();
        assert!(err.contains("secret_group"));

        assert!(compile_custom_pattern(&custom("k=(v+)", Some(1))).is_ok());
    }

    #[test]
    fn line_col_counts_from_one() {
        assert_eq!(line_col("ab\ncd", 0), (1, 1));
        assert_eq!(line_col("ab\ncd", 4), (2, 2));
        assert_eq!(line_col("ab", 99), (1, 3));
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

    // --- Blacklist hash tests ---

    #[test]
    fn blacklist_hash_match() {
        let value = "my-secret-value";
        let hash = sha256_hex(value);
        let bl = Blacklist::from_hashes(vec![hash]);
        assert!(bl.is_hash_match(value));
        assert!(!bl.is_hash_match("other-value"));
    }

    #[test]
    fn blacklist_hash_no_substring_match() {
        // Hash-based matching should NOT do substring matching
        let value = "my-secret-value";
        let hash = sha256_hex(value);
        let bl = Blacklist::from_hashes(vec![hash]);
        assert!(!bl.contains_any("prefix my-secret-value suffix"));
        // But exact match via contains_any works
        assert!(bl.contains_any(value));
    }

    #[test]
    fn empty_blacklist_hash_matches_nothing() {
        let bl = Blacklist::empty();
        assert!(!bl.is_hash_match("anything"));
    }

    #[test]
    fn blacklist_hash_case_insensitive() {
        let hash = sha256_hex("test").to_uppercase();
        let bl = Blacklist::from_hashes(vec![hash]);
        assert!(bl.is_hash_match("test"));
    }

    #[test]
    fn blacklist_combined_strings_and_hashes() {
        let hash = sha256_hex("exact-match-value");
        let bl = Blacklist {
            entries: vec!["substring1".to_string()],
            hashes: HashSet::from([hash.to_lowercase()]),
        };
        assert_eq!(bl.len(), 2);
        assert!(!bl.is_empty());
        // Substring match
        assert!(bl.contains_any("has substring1 in it"));
        // Hash exact match
        assert!(bl.is_hash_match("exact-match-value"));
        // Hash doesn't do substring
        assert!(!bl.is_hash_match("has exact-match-value in it"));
    }
}
