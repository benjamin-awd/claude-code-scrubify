use std::sync::LazyLock;

use regex::Regex;

#[derive(Clone)]
pub struct EntropyConfig {
    pub enabled: bool,
    /// Entropy threshold (bits/char) for long base62/base64 tokens. Shorter
    /// tokens use a length-scaled threshold capped at this value; see
    /// [`base64_threshold`].
    pub threshold: f64,
    pub min_len: usize,
    /// Additional regex patterns for tokens that should be excluded from
    /// entropy-based detection (e.g. `"toolu_[A-Za-z0-9]{20,}"`).
    pub exclude_patterns: Vec<String>,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        EntropyConfig {
            enabled: true,
            threshold: 4.5,
            min_len: 20,
            exclude_patterns: Vec::new(),
        }
    }
}

pub struct EntropyMatch {
    pub start: usize,
    pub end: usize,
}

/// Fraction of the maximum attainable entropy, `log2(min(len, 64))`, that a
/// base62/base64 token must reach. 0.85 sits near the 1st–5th percentile of
/// random base62 tokens at every length from 20 to 40 chars.
const BASE64_SCALE: f64 = 0.85;

/// Hex tokens top out at 4.0 bits/char; random 32-hex averages 3.61 (p1 3.27).
const HEX_THRESHOLD: f64 = 3.0;
/// Shorter hex runs are commit SHAs / short hashes far more often than keys.
const HEX_MIN_LEN: usize = 32;
/// How far back (bytes, same line) to look for a key-like word before a hex token.
const HEX_CONTEXT_BYTES: usize = 40;
/// Words that make a nearby hex token look like a credential.
const HEX_KEY_WORDS: &[&str] = &[
    "key",
    "token",
    "secret",
    "passw",
    "auth",
    "credential",
    "bearer",
];
/// Words that mark a nearby hex token as a hash/identifier instead.
const HEX_HASH_WORDS: &[&str] = &[
    "sha",
    "hash",
    "commit",
    "digest",
    "checksum",
    "integrity",
    "md5",
    "rev",
    "blob",
    "tree",
    "object",
    "etag",
    "fingerprint",
    "nonce",
    "salt",
    "uuid",
];
/// A token is "word-like" (an identifier, not a secret) when at least this
/// share of its characters sit in alphabetic segments of 4+ chars.
const WORDY_FRACTION: f64 = 0.5;
/// From this length a token may skip the character-class gate if it
/// reaches the full (un-scaled) threshold.
const LONG_TOKEN_LEN: usize = 32;
/// `/`-separated segments shorter than this always count as path-like.
const PATH_SEGMENT_MIN_CHECK_LEN: usize = 8;

/// Tokens that are never secrets: UUIDs, Claude Code message/tool IDs and
/// Subresource-Integrity hashes from lockfiles.
static BUILTIN_EXCLUSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        ^(?:
            [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}  # UUIDs
            | (?:toolu|srvtoolu|msg|req)_[A-Za-z0-9_]{16,}                                 # Claude IDs
            | sha(?:1|256|384|512)-[A-Za-z0-9+/]{20,}={0,2}                               # SRI hashes
        )$
    ",
    )
    .unwrap()
});

/// Shortest run of token bytes considered at all (`min_len` may raise it).
const TOKEN_MIN_LEN: usize = 20;

/// Bytes that make up a candidate token: `[A-Za-z0-9+/=_-]`.
static TOKEN_BYTES: [bool; 256] = {
    let mut t = [false; 256];
    let mut b = 0;
    while b < 256 {
        #[allow(clippy::cast_possible_truncation)]
        let c = b as u8;
        t[b] = c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'_' | b'-');
        b += 1;
    }
    t
};

/// `(start, end)` of every maximal run of token bytes at least
/// `TOKEN_MIN_LEN` long: the same spans `[A-Za-z0-9+/=_-]{20,}` finds, without
/// the regex engine's forward-then-reverse search per match.
fn candidate_tokens(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let b = text.as_bytes();
    let mut i = 0;
    std::iter::from_fn(move || {
        while i < b.len() {
            if !TOKEN_BYTES[b[i] as usize] {
                i += 1;
                continue;
            }
            let start = i;
            while i < b.len() && TOKEN_BYTES[b[i] as usize] {
                i += 1;
            }
            if i - start >= TOKEN_MIN_LEN {
                return Some((start, i));
            }
        }
        None
    })
}

pub fn shannon_entropy(s: &str) -> f64 {
    #[allow(clippy::cast_precision_loss)] // precision loss irrelevant for entropy calc
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }

    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let freq = f64::from(c) / len;
            -freq * freq.log2()
        })
        .sum()
}

/// Entropy a base62/base64 token of `len` chars must reach:
/// `min(cap, 0.85 * log2(min(len, 64)))`. A 20-char token can hold at most
/// log2(20) = 4.32 bits/char, so a flat 4.5 could never fire on it.
pub fn base64_threshold(len: usize, cap: f64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let max = (len.min(64) as f64).log2();
    (BASE64_SCALE * max).min(cap)
}

fn is_hex(token: &str) -> bool {
    token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Split an identifier into `camelCase` / `snake_case` / acronym / digit
/// segments: `ZodBase64URLInternals` → `Zod`, `Base`, `64`, `URL`, `Internals`.
fn identifier_segments(token: &str) -> impl Iterator<Item = &str> {
    let b = token.as_bytes();
    let mut start = 0;
    let mut i = 1;
    std::iter::from_fn(move || {
        while i < b.len() {
            let (prev, cur) = (b[i - 1], b[i]);
            let boundary = (prev.is_ascii_alphabetic() != cur.is_ascii_alphabetic())
                || (prev.is_ascii_digit() != cur.is_ascii_digit())
                || (prev.is_ascii_lowercase() && cur.is_ascii_uppercase())
                // Acronym followed by a word: the last capital starts the word.
                || (prev.is_ascii_uppercase()
                    && cur.is_ascii_uppercase()
                    && b.get(i + 1).is_some_and(u8::is_ascii_lowercase));
            i += 1;
            if boundary {
                let seg = &token[start..i - 1];
                start = i - 1;
                return Some(seg);
            }
        }
        if start < b.len() {
            let seg = &token[start..];
            start = b.len();
            return Some(seg);
        }
        None
    })
}

/// An alphabetic segment with at least one vowel per four letters. English
/// words average ~40% vowels; random base62 letter runs ~19%.
fn is_pronounceable(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    if !bytes.iter().all(u8::is_ascii_alphabetic) {
        return false;
    }
    let vowels = bytes
        .iter()
        .filter(|b| {
            matches!(
                b.to_ascii_lowercase(),
                b'a' | b'e' | b'i' | b'o' | b'u' | b'y'
            )
        })
        .count();
    vowels * 4 >= bytes.len()
}

/// True when most of the token is made of dictionary-ish segments
/// (`SnowflakeS3BackupMode`, `deep_readonly_schemas_0`).
fn is_wordy(token: &str) -> bool {
    let word_chars: usize = identifier_segments(token)
        .filter(|s| {
            (s.len() >= 4 && is_pronounceable(s))
                || (s.len() >= 3 && s.bytes().all(|b| b.is_ascii_uppercase()))
        })
        .map(str::len)
        .sum();
    #[allow(clippy::cast_precision_loss)]
    let ratio = word_chars as f64 / token.len() as f64;
    ratio >= WORDY_FRACTION
}

/// Upper, lower and digit all present (random 20-char base62 has all three
/// ~97% of the time; identifiers and words rarely do).
fn has_all_classes(token: &str) -> bool {
    let (mut up, mut lo, mut dg) = (false, false, false);
    for b in token.bytes() {
        up |= b.is_ascii_uppercase();
        lo |= b.is_ascii_lowercase();
        dg |= b.is_ascii_digit();
    }
    up && lo && dg
}

/// Does this non-hex token look like a random base62/base64 secret?
///
/// Rejects word-like identifiers, then either: all three character classes
/// and the length-scaled threshold, or (for 32+ chars, where a class can be
/// missing by chance) the full un-scaled threshold.
fn looks_random(token: &str, cap: f64) -> bool {
    let all_classes = has_all_classes(token);
    if !all_classes && token.len() < LONG_TOKEN_LEN {
        return false;
    }
    let entropy = shannon_entropy(token);
    // Word check last: it is the costliest test and most tokens fail earlier.
    ((all_classes && entropy >= base64_threshold(token.len(), cap))
        || (token.len() >= LONG_TOKEN_LEN && entropy >= cap))
        && !is_wordy(token)
}

/// A `/`-containing token is a path when it has 2+ segments, no base64-only
/// characters (`+`, `=`), and every segment reads like a path component:
/// short, hex, word-like, or missing a character class. A leading `/` alone
/// no longer makes a token a path (`/Xq7Rk…` is checked like any token).
fn is_path_like(token: &str) -> bool {
    if token.contains(['+', '=']) {
        return false;
    }
    let mut segments = token.split('/').filter(|s| !s.is_empty());
    segments.clone().nth(1).is_some()
        && segments.all(|s| {
            s.len() < PATH_SEGMENT_MIN_CHECK_LEN || is_hex(s) || is_wordy(s) || !has_all_classes(s)
        })
}

/// Is there a key-like word (and no hash-like word) shortly before `start`
/// on the same line?
fn has_key_context(text: &str, start: usize) -> bool {
    let bytes = text.as_bytes();
    let mut lo = start.saturating_sub(HEX_CONTEXT_BYTES);
    if let Some(nl) = bytes[lo..start].iter().rposition(|&b| b == b'\n') {
        lo += nl + 1;
    }
    let ctx = bytes[lo..start].to_ascii_lowercase();
    let has = |words: &[&str]| {
        words
            .iter()
            .any(|w| ctx.windows(w.len()).any(|win| win == w.as_bytes()))
    };
    has(HEX_KEY_WORDS) && !has(HEX_HASH_WORDS)
}

/// Compile user-supplied exclude patterns into a single optional `Regex`.
/// Each pattern is anchored with `^(?:...)$` and combined with alternation.
/// Returns `None` when the list is empty. Invalid patterns are logged and skipped.
pub fn compile_exclude_patterns(patterns: &[String]) -> Option<Regex> {
    if patterns.is_empty() {
        return None;
    }
    // Validate each pattern individually so one bad pattern doesn't break the rest
    // Log only the index and length: users sometimes paste secret fragments
    // into these patterns, so the pattern text must never reach the logs.
    let valid: Vec<&str> = patterns
        .iter()
        .enumerate()
        .filter(|(index, p)| {
            if Regex::new(p).is_err() {
                tracing::warn!(
                    index,
                    len = p.len(),
                    "ignoring invalid entropy exclude pattern"
                );
                false
            } else {
                true
            }
        })
        .map(|(_, p)| p.as_str())
        .collect();
    if valid.is_empty() {
        return None;
    }
    let combined = format!("^(?:{})$", valid.join("|"));
    Regex::new(&combined).ok()
}

thread_local! {
    /// Last compiled exclude set, keyed by its source patterns. Compiling a
    /// `Regex` per scanned string made a cold scan ~6x slower with a single
    /// exclude pattern configured (and logged invalid patterns per string).
    static EXCLUDE_CACHE: std::cell::RefCell<Option<(Vec<String>, Option<Regex>)>> =
        const { std::cell::RefCell::new(None) };
}

fn cached_exclude_patterns(patterns: &[String]) -> Option<Regex> {
    if patterns.is_empty() {
        return None;
    }
    EXCLUDE_CACHE.with_borrow_mut(|cache| {
        if let Some((key, re)) = cache.as_ref()
            && key.as_slice() == patterns
        {
            return re.clone();
        }
        let re = compile_exclude_patterns(patterns);
        *cache = Some((patterns.to_vec(), re.clone()));
        re
    })
}

pub fn find_high_entropy_tokens(text: &str, config: &EntropyConfig) -> Vec<EntropyMatch> {
    find_high_entropy_tokens_inner(
        text,
        config,
        cached_exclude_patterns(&config.exclude_patterns).as_ref(),
    )
}

fn find_high_entropy_tokens_inner(
    text: &str,
    config: &EntropyConfig,
    user_exclusions: Option<&Regex>,
) -> Vec<EntropyMatch> {
    if !config.enabled {
        return Vec::new();
    }

    candidate_tokens(text)
        .filter(|&(start, end)| {
            let token = &text[start..end];
            if token.len() < config.min_len {
                return false;
            }
            let flagged = if is_hex(token) {
                // Bare hex is usually a hash (git SHA, checksum); only flag it
                // when a key-like word sits right before it.
                token.len() >= HEX_MIN_LEN
                    && token.bytes().any(|b| b.is_ascii_digit())
                    && token.bytes().any(|b| b.is_ascii_alphabetic())
                    && shannon_entropy(token) >= HEX_THRESHOLD
                    && has_key_context(text, start)
            } else if token.contains('/') && is_path_like(token) {
                false
            } else {
                looks_random(token, config.threshold)
            };
            // Exclusions only matter for tokens that would be flagged, which
            // are rare, so check them last.
            flagged
                && !BUILTIN_EXCLUSION_RE.is_match(token)
                && !user_exclusions.is_some_and(|re| re.is_match(token))
        })
        .map(|(start, end)| EntropyMatch { start, end })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flagged(text: &str) -> Vec<&str> {
        find_high_entropy_tokens(text, &EntropyConfig::default())
            .into_iter()
            .map(|m| &text[m.start..m.end])
            .collect()
    }

    #[test]
    fn low_entropy_string() {
        assert!(shannon_entropy("aaaaaaaaaaaaaaaaaaaaaa") < 1.0);
    }

    #[test]
    fn high_entropy_string() {
        assert!(shannon_entropy("aB3$kL9@mN2&pQ5!rT8*") > 4.0);
    }

    #[test]
    fn detects_high_entropy_token() {
        let config = EntropyConfig::default();
        let text = "token=aB3kL9mN2pQ5rT8vX1yZ4cF7gH0jK6wE";
        let matches = find_high_entropy_tokens(text, &config);
        assert!(!matches.is_empty(), "should detect high entropy token");
    }

    #[test]
    fn detects_short_random_tokens() {
        // 20-22 chars can never reach a flat 4.5 bits (log2(20) = 4.32).
        for tok in [
            "Xq7Rk2mPz9LwB4vN8cTd",   // 20
            "hG5tY8nQ2wE6rZ1pK9sLm",  // 21
            "Fk3Jd8Qm2Zx7Lp4Wn9Rt5B", // 22
        ] {
            assert_eq!(flagged(tok), [tok], "{tok} should be flagged");
        }
    }

    #[test]
    fn splits_identifier_segments() {
        assert_eq!(
            identifier_segments("ZodBase64URLInternals").collect::<Vec<_>>(),
            ["Zod", "Base", "64", "URL", "Internals"]
        );
        assert_eq!(
            identifier_segments("deep_readonly-x").collect::<Vec<_>>(),
            ["deep", "_", "readonly", "-", "x"]
        );
    }

    #[test]
    fn candidate_tokens_match_token_regex() {
        let re = Regex::new(r"[A-Za-z0-9+/=_\-]{20,}").unwrap();
        let long = "Q".repeat(20);
        for text in [
            "",
            "short words only",
            "aB3kL9mN2pQ5rT8vX1yZ4cF7gH0jK6wE",
            "x=aB3kL9mN2pQ5rT8vX1yZ4cF7gH0jK6wE; y=/usr/local/lib/python3.12/site",
            "é→aB3kL9mN2pQ5rT8vX1yZ4cF7—gH0jK6wEaB3kL9mN2pQ5rT8vX1yZ4cF7—",
            "0123456789012345678 01234567890123456789 ",
            long.as_str(),
        ] {
            let expected: Vec<_> = re.find_iter(text).map(|m| (m.start(), m.end())).collect();
            assert_eq!(
                candidate_tokens(text).collect::<Vec<_>>(),
                expected,
                "{text}"
            );
        }
    }

    #[test]
    fn scaled_threshold_values() {
        assert!((base64_threshold(20, 4.5) - 3.674).abs() < 0.01);
        assert!((base64_threshold(32, 4.5) - 4.25).abs() < 0.01);
        assert!((base64_threshold(64, 4.5) - 4.5).abs() < f64::EPSILON);
        // The CLI threshold still caps the scaled value.
        assert!((base64_threshold(64, 4.0) - 4.0).abs() < f64::EPSILON);
    }

    #[test]
    fn hex_key_needs_key_context() {
        let hex40 = "3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c8e2b4d6f0a";
        assert_eq!(flagged(&format!("DD-API-KEY: {hex40}")), [hex40]);
        assert_eq!(flagged(&format!("the api token is {hex40}")), [hex40]);
        // Bare hex, commit SHAs and checksums are left alone.
        assert!(flagged(hex40).is_empty());
        assert!(flagged(&format!("commit {hex40}")).is_empty());
        assert!(flagged(&format!("git log key commit {hex40}")).is_empty());
        let sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert!(flagged(&format!(r#"checksum = "{sha256}""#)).is_empty());
        assert!(flagged(&format!("sha256:{sha256}")).is_empty());
        // Context does not leak across lines.
        assert!(flagged(&format!("api key below\n{hex40}")).is_empty());
    }

    #[test]
    fn hex_needs_min_length() {
        assert!(flagged("secret: 3f9a1c7e5b2d8f4a6c0e9b1d").is_empty()); // 24 hex
    }

    #[test]
    fn slash_prefixed_secret_is_not_a_path() {
        let secret = "/Xq7Rk2mPz9LwB4vN8cTdHg5tY8nQ2wE";
        assert_eq!(flagged(secret), [secret]);
        let with_plus = "/Xq7Rk2mPz9/LwB4vN8cTd+Hg5tY8nQ2wE";
        assert_eq!(flagged(with_plus), [with_plus]);
        // A 40-char base64 secret with two slashes and no +/= is not a path.
        let aws_like = "Xq7Rk2mPz9Lw/B4vN8cTdHg5tY8/nQ2wEFk3Jd8Qm2";
        assert_eq!(flagged(aws_like), [aws_like]);
        let in_path = "/tmp/Xq7Rk2mPz9LwB4vN8cTdHg5tY8nQ2wE";
        assert_eq!(flagged(in_path), [in_path]);
    }

    #[test]
    fn real_paths_are_not_flagged() {
        for path in [
            "/usr/local/lib/python3",
            "/Users/someone/playground/claude-code-scrubify/src/entropy",
            "/home/runner/work/MyRepo2/MyRepo2/target/release/deps",
            "src/commands/scan_command_handler",
            "org/licenses/BSD-3-Clause",
            "src/components/Button2Group/index",
            "home/runner/work/MyRepo2/MyRepo2/target",
            "claude/projects/-Users-someone-playground/5f0c7b1e-8a3d-4e2f-9b6a-1c2d3e4f5a6b",
        ] {
            assert!(flagged(path).is_empty(), "{path} flagged");
        }
    }

    #[test]
    fn realistic_non_secrets_are_not_flagged() {
        let corpus = [
            // git SHAs, UUIDs, hashes
            "9fceb02d0ae598e95dc970b74767f19372d61af8",
            "550e8400-e29b-41d4-a716-446655440000",
            "d41d8cd98f00b204e9800998ecf8427e",
            "sha512-Y4bVJ9l5UqAa5bVr4r7mQ3dW8QTbZ3Dh3hUMWb9T0oR8t2mYjkzA0f6ZgVnqKqY3M0Mv9oAqV5QPVG0Ur0aYbQ==",
            // Claude Code IDs
            "toolu_01WcKqikcTdC72gZJhSFfmYf",
            "msg_01XFDUDYJgAACzvnptvVoYEL",
            "req_011CUHfKzBqzH2XhU2eQnBqY",
            "srvtoolu_01AbCdEfGhIjKlMnOpQrStUv",
            // identifiers
            "SnowflakeS3BackupMode",
            "HttpEndpointS3BackupMode",
            "JSONSchema7Definition",
            "deepReadonlySchemas_0",
            "Uint8ArrayMaxByteLength",
            "validateOpenAPI30Schema",
            "scrub_all_strings_inner",
            "prose_mentioning_new_token_types_is_not_matched",
            "flex-items-center-justify-between",
            "RightCurriedFunction2",
            "getElementsByClassName",
            "NSISO8601DateFormatter",
            "x86_64-unknown-linux-gnu",
            "aarch64-apple-darwin",
            "python3-pip-install-2024",
            "feat/grafana-and-more-secret-patterns",
            "test_redacts_sensitive_field_by_key_name",
        ];
        for tok in corpus {
            assert!(flagged(tok).is_empty(), "{tok} flagged");
        }
    }

    #[test]
    fn skips_file_paths() {
        let config = EntropyConfig::default();
        let text = "nothing secret here just normal text";
        let matches = find_high_entropy_tokens(text, &config);
        assert!(matches.is_empty());
    }

    #[test]
    fn skips_already_redacted() {
        let config = EntropyConfig::default();
        let text = "[REDACTED:aws-access-key]";
        let matches = find_high_entropy_tokens(text, &config);
        assert!(matches.is_empty());
    }

    #[test]
    fn exclude_cache_tracks_pattern_changes() {
        let token = "toolu_01WcKqikcTdC72gZJhSFfmYf";
        let a = vec![r"toolu_[A-Za-z0-9]+".to_string()];
        let b = vec![r"other_[A-Za-z0-9]+".to_string()];
        assert!(cached_exclude_patterns(&a).unwrap().is_match(token));
        // Same thread, different list: must recompile, not reuse `a`.
        assert!(!cached_exclude_patterns(&b).unwrap().is_match(token));
        assert!(cached_exclude_patterns(&a).unwrap().is_match(token));
        assert!(cached_exclude_patterns(&[]).is_none());
    }

    #[test]
    fn user_exclude_pattern_skips_matching_tokens() {
        let config = EntropyConfig {
            exclude_patterns: vec![r"myid_[A-Za-z0-9]+".to_string()],
            ..Default::default()
        };
        let text = "myid_01WcKqikcTdC72gZJhSFfmYf";
        let matches = find_high_entropy_tokens(text, &config);
        assert!(
            matches.is_empty(),
            "user exclude pattern should suppress match"
        );
    }

    #[test]
    fn user_exclude_does_not_suppress_other_tokens() {
        let config = EntropyConfig {
            exclude_patterns: vec![r"toolu_[A-Za-z0-9]+".to_string()],
            ..Default::default()
        };
        let text = "aB3kL9mN2pQ5rT8vX1yZ4cF7gH0jK6wE";
        let matches = find_high_entropy_tokens(text, &config);
        assert!(
            !matches.is_empty(),
            "non-matching token should still be detected"
        );
    }

    /// The only test that hits the invalid-pattern `warn!` callsite: a second
    /// one running in parallel without a subscriber could cache the callsite
    /// as disabled and make the log assertions flaky.
    #[test]
    fn invalid_exclude_pattern_is_skipped_and_log_omits_pattern_text() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buf = Buf(Arc::new(Mutex::new(Vec::new())));
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let fragment = "[FAKEsecretFRAGMENT";
        let re = tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            compile_exclude_patterns(&["ok_.+".to_string(), fragment.to_string()])
        });
        assert!(re.is_some(), "valid pattern should still compile");
        let logged = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("ignoring invalid entropy exclude pattern"));
        assert!(logged.contains("index=1"), "{logged}");
        assert!(!logged.contains("FAKEsecretFRAGMENT"), "{logged}");
    }

    #[test]
    fn disabled_returns_empty() {
        let config = EntropyConfig {
            enabled: false,
            ..Default::default()
        };
        let text = "aB3kL9mN2pQ5rT8vX1yZ4cF7gH0jK6wE";
        let matches = find_high_entropy_tokens(text, &config);
        assert!(matches.is_empty());
    }

    #[test]
    fn short_tokens_ignored() {
        let config = EntropyConfig::default();
        let text = "short";
        let matches = find_high_entropy_tokens(text, &config);
        assert!(matches.is_empty());
    }
}
