use std::fmt::Write as _;

use serde_json::Value;

use crate::allowlist::{Allowlist, Blacklist};
use crate::entropy::{EntropyConfig, find_high_entropy_tokens};
use crate::patterns::PatternSet;

/// Well-known example/placeholder values that should not be redacted.
const KNOWN_EXAMPLES: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",                     // AWS docs example key
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // AWS docs example secret
];

/// Minimum length for a matched secret value to be redacted. Short strings are
/// rarely actual secrets and cause false positives.
const MIN_SECRET_LEN: usize = 8;

/// Minimum length for a value to be redacted by key-name alone.
const SENSITIVE_KEY_MIN_VALUE_LEN: usize = 8;

/// Field names whose string values should always be redacted (case-insensitive).
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "api_secret",
    "access_token",
    "auth_token",
    "token",
    "private_key",
    "secret_key",
    "credentials",
    "authorization",
];

#[derive(Debug, Clone)]
pub struct Redaction {
    pub pattern_name: String,
    pub start: usize,
    pub end: usize,
    pub matched_text: String,
}

pub fn scrub_text(
    text: &str,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    allowlist: &Allowlist,
    blacklist: &Blacklist,
) -> (String, Vec<Redaction>) {
    // Fast bail-out: if no regex matches at all, entropy is disabled, and no
    // blacklist entries match, return early
    if !pattern_set.quick_check.is_match(text)
        && !entropy_cfg.enabled
        && !blacklist.contains_any(text)
    {
        return (text.to_string(), Vec::new());
    }

    let mut spans: Vec<Redaction> = Vec::new();

    // Collect regex matches
    // Use quick_check to find which patterns matched, then keyword pre-filter,
    // then get exact spans.
    let text_lower = text.to_lowercase();
    let matching_indices: Vec<_> = pattern_set.quick_check.matches(text).into_iter().collect();
    for idx in matching_indices {
        let pat = &pattern_set.patterns[idx];
        if !pat.keyword_hit(&text_lower) {
            continue;
        }
        for caps in pat.regex.captures_iter(text) {
            let full = caps.get(0).unwrap();
            if KNOWN_EXAMPLES.iter().any(|ex| full.as_str().contains(ex)) {
                continue;
            }
            // If secret_group is set, redact only that capture group
            let (start, end) = if let Some(group) = pat.secret_group {
                if let Some(g) = caps.get(group) {
                    (g.start(), g.end())
                } else {
                    (full.start(), full.end())
                }
            } else {
                (full.start(), full.end())
            };
            if end - start < MIN_SECRET_LEN {
                continue;
            }
            // Skip already-redacted placeholders to stay idempotent when
            // a secret_group pattern preserves surrounding context.
            if text[start..end].starts_with("[REDACTED:") {
                continue;
            }
            if allowlist.is_allowed(&text[start..end]) {
                continue;
            }
            spans.push(Redaction {
                pattern_name: pat.name.clone(),
                start,
                end,
                matched_text: String::new(), // filled after merging
            });
        }
    }

    // Collect entropy matches
    for em in find_high_entropy_tokens(text, entropy_cfg) {
        // Don't flag tokens already covered by regex matches
        let already_covered = spans.iter().any(|s| s.start <= em.start && s.end >= em.end);
        if !already_covered && !allowlist.is_allowed(&text[em.start..em.end]) {
            spans.push(Redaction {
                pattern_name: "high-entropy".to_string(),
                start: em.start,
                end: em.end,
                matched_text: String::new(),
            });
        }
    }

    // Collect blacklist matches
    for (bl_start, bl_end) in blacklist.find_all_spans(text) {
        // Skip if already covered by a regex/entropy span
        let already_covered = spans.iter().any(|s| s.start <= bl_start && s.end >= bl_end);
        if already_covered {
            continue;
        }
        // Skip if the matched text is allowlisted
        if allowlist.is_allowed(&text[bl_start..bl_end]) {
            continue;
        }
        // Skip already-redacted placeholders for idempotency
        if text[bl_start..bl_end].starts_with("[REDACTED:") {
            continue;
        }
        spans.push(Redaction {
            pattern_name: "blacklist".to_string(),
            start: bl_start,
            end: bl_end,
            matched_text: String::new(),
        });
    }

    if spans.is_empty() {
        return (text.to_string(), Vec::new());
    }

    // Sort by start offset
    spans.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));

    // Merge overlapping spans and build output in a single pass
    let mut result = String::with_capacity(text.len());
    let mut redactions: Vec<Redaction> = Vec::new();
    let mut pos = 0;
    let mut cur_start = spans[0].start;
    let mut cur_end = spans[0].end;
    let mut cur_name = &spans[0].pattern_name;

    for span in &spans[1..] {
        if span.start <= cur_end {
            // Overlapping — extend
            if span.end > cur_end {
                cur_end = span.end;
            }
        } else {
            // Emit the previous merged span
            result.push_str(&text[pos..cur_start]);
            write!(result, "[REDACTED:{cur_name}]").unwrap();
            redactions.push(Redaction {
                pattern_name: cur_name.clone(),
                start: cur_start,
                end: cur_end,
                matched_text: text[cur_start..cur_end].to_string(),
            });
            pos = cur_end;
            cur_start = span.start;
            cur_end = span.end;
            cur_name = &span.pattern_name;
        }
    }

    // Emit the last merged span
    result.push_str(&text[pos..cur_start]);
    write!(result, "[REDACTED:{cur_name}]").unwrap();
    redactions.push(Redaction {
        pattern_name: cur_name.clone(),
        start: cur_start,
        end: cur_end,
        matched_text: text[cur_start..cur_end].to_string(),
    });
    pos = cur_end;

    if pos < text.len() {
        result.push_str(&text[pos..]);
    }

    (result, redactions)
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_KEYS.iter().any(|&k| {
        lower == k
            || (lower.ends_with(k)
                && lower.as_bytes().get(lower.len() - k.len() - 1) == Some(&b'_'))
    })
}

/// Recursively scrub all string values in a JSON value tree.
pub fn scrub_all_strings(
    value: &mut Value,
    ps: &PatternSet,
    ec: &EntropyConfig,
    al: &Allowlist,
    bl: &Blacklist,
) -> Vec<Redaction> {
    scrub_all_strings_inner(value, ps, ec, al, bl, false)
}

fn scrub_all_strings_inner(
    value: &mut Value,
    ps: &PatternSet,
    ec: &EntropyConfig,
    al: &Allowlist,
    bl: &Blacklist,
    force_redact: bool,
) -> Vec<Redaction> {
    match value {
        Value::String(s) => {
            // Key-value awareness: if the parent key was sensitive and the
            // value is long enough, redact the whole thing unconditionally.
            if force_redact && s.len() >= SENSITIVE_KEY_MIN_VALUE_LEN {
                if al.is_allowed(s) {
                    return Vec::new();
                }
                let redaction = Redaction {
                    pattern_name: "sensitive-field".to_string(),
                    start: 0,
                    end: s.len(),
                    matched_text: s.clone(),
                };
                *s = "[REDACTED:sensitive-field]".to_string();
                return vec![redaction];
            }
            // Hash-based blacklist: redact the whole string if its hash matches
            if bl.is_hash_match(s) && !al.is_allowed(s) {
                let redaction = Redaction {
                    pattern_name: "blacklist".to_string(),
                    start: 0,
                    end: s.len(),
                    matched_text: s.clone(),
                };
                *s = "[REDACTED:blacklist]".to_string();
                return vec![redaction];
            }
            let (scrubbed, redactions) = scrub_text(s, ps, ec, al, bl);
            if !redactions.is_empty() {
                *s = scrubbed;
            }
            redactions
        }
        Value::Array(arr) => arr
            .iter_mut()
            .flat_map(|v| scrub_all_strings_inner(v, ps, ec, al, bl, force_redact))
            .collect(),
        Value::Object(map) => {
            let mut redactions = Vec::new();
            for (key, val) in map.iter_mut() {
                let sensitive = is_sensitive_key(key);
                redactions.extend(scrub_all_strings_inner(val, ps, ec, al, bl, sensitive));
            }
            redactions
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pattern_set() -> PatternSet {
        PatternSet::load(true).unwrap()
    }

    fn no_entropy() -> EntropyConfig {
        EntropyConfig {
            enabled: false,
            ..Default::default()
        }
    }

    fn no_allowlist() -> Allowlist {
        Allowlist::empty()
    }

    fn no_blacklist() -> Blacklist {
        Blacklist::empty()
    }

    #[test]
    fn no_secrets() {
        let ps = test_pattern_set();
        let (result, redactions) = scrub_text(
            "hello world",
            &ps,
            &no_entropy(),
            &no_allowlist(),
            &no_blacklist(),
        );
        assert_eq!(result, "hello world");
        assert!(redactions.is_empty());
    }

    #[test]
    fn redacts_github_token() {
        let ps = test_pattern_set();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let (result, redactions) =
            scrub_text(input, &ps, &no_entropy(), &no_allowlist(), &no_blacklist());
        assert!(result.contains("[REDACTED:github-token]"));
        assert!(!result.contains("ghp_"));
        assert_eq!(redactions.len(), 1);
    }

    #[test]
    fn redacts_multiple_secrets() {
        let ps = test_pattern_set();
        let input = "key1: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl and key2: sk-ant-abcdefghijklmnopqrstuvwxyz";
        let (result, redactions) =
            scrub_text(input, &ps, &no_entropy(), &no_allowlist(), &no_blacklist());
        assert!(result.contains("[REDACTED:github-token]"));
        assert!(result.contains("[REDACTED:anthropic-key]"));
        assert_eq!(redactions.len(), 2);
    }

    #[test]
    fn idempotent() {
        let ps = test_pattern_set();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let (first_pass, _) =
            scrub_text(input, &ps, &no_entropy(), &no_allowlist(), &no_blacklist());
        let (second_pass, redactions) = scrub_text(
            &first_pass,
            &ps,
            &no_entropy(),
            &no_allowlist(),
            &no_blacklist(),
        );
        assert_eq!(first_pass, second_pass);
        assert!(redactions.is_empty());
    }

    #[test]
    fn idempotent_secret_group() {
        let ps = test_pattern_set();
        let input = r#"password = "my_super_secret_password""#;
        let (first_pass, r1) =
            scrub_text(input, &ps, &no_entropy(), &no_allowlist(), &no_blacklist());
        assert_eq!(r1.len(), 1);
        // Second pass on already-redacted text should find nothing
        let (second_pass, r2) = scrub_text(
            &first_pass,
            &ps,
            &no_entropy(),
            &no_allowlist(),
            &no_blacklist(),
        );
        assert_eq!(first_pass, second_pass);
        assert!(
            r2.is_empty(),
            "re-scrubbing should not match [REDACTED:...] placeholders"
        );
    }

    #[test]
    fn skips_short_matches() {
        let ps = test_pattern_set();
        // "SK" + 32 hex chars = 34 chars, should be redacted
        let long_input = format!("key: SK{}", "1234567890abcdef".repeat(2));
        let (_, redactions) = scrub_text(
            &long_input,
            &ps,
            &no_entropy(),
            &no_allowlist(),
            &no_blacklist(),
        );
        assert!(!redactions.is_empty(), "long twilio key should be redacted");
    }

    #[test]
    fn secret_group_redacts_only_value() {
        let ps = test_pattern_set();
        let input = r#"password = "my_super_secret_password""#;
        let (result, redactions) =
            scrub_text(input, &ps, &no_entropy(), &no_allowlist(), &no_blacklist());
        // The key name should be preserved, only the value redacted
        assert!(
            result.contains("password"),
            "key name should be preserved: {result}"
        );
        assert!(result.contains("[REDACTED:password-assignment]"));
        assert!(!result.contains("my_super_secret_password"));
        assert_eq!(redactions.len(), 1);
    }

    #[test]
    fn allowlisted_value_not_redacted() {
        let ps = test_pattern_set();
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let hash = crate::allowlist::sha256_hex(token);
        let al = Allowlist::from_hashes(vec![hash]);
        let input = format!("token: {token}");
        let (result, redactions) = scrub_text(&input, &ps, &no_entropy(), &al, &no_blacklist());
        assert!(result.contains(token), "allowlisted value should remain");
        assert!(redactions.is_empty());
    }

    #[test]
    fn entropy_detection() {
        let ps = test_pattern_set();
        let cfg = EntropyConfig::default();
        let input = "secret=aB3kL9mN2pQ5rT8vX1yZ4cF7gH0jK6wE";
        let (result, redactions) = scrub_text(input, &ps, &cfg, &no_allowlist(), &no_blacklist());
        // Should detect via entropy or regex
        assert!(!redactions.is_empty() || result != input);
    }

    // --- Blacklist tests ---

    #[test]
    fn blacklist_redacts_exact_string() {
        let ps = test_pattern_set();
        let bl = Blacklist::from_strings(vec!["foobar123"]);
        let input = "some text with foobar123 in it";
        let (result, redactions) = scrub_text(input, &ps, &no_entropy(), &no_allowlist(), &bl);
        assert!(result.contains("[REDACTED:blacklist]"));
        assert!(!result.contains("foobar123"));
        assert_eq!(redactions.len(), 1);
        assert_eq!(redactions[0].pattern_name, "blacklist");
    }

    #[test]
    fn blacklist_bypasses_fast_bailout() {
        let ps = test_pattern_set();
        let bl = Blacklist::from_strings(vec!["foobar123"]);
        // This text has no regex matches and no entropy — only blacklist
        let input = "plain text foobar123 here";
        let (result, redactions) = scrub_text(input, &ps, &no_entropy(), &no_allowlist(), &bl);
        assert!(
            !redactions.is_empty(),
            "blacklist should bypass fast bail-out"
        );
        assert!(result.contains("[REDACTED:blacklist]"));
    }

    #[test]
    fn blacklist_multiple_occurrences() {
        let ps = test_pattern_set();
        let bl = Blacklist::from_strings(vec!["foobar123"]);
        let input = "first foobar123 second foobar123 end";
        let (result, redactions) = scrub_text(input, &ps, &no_entropy(), &no_allowlist(), &bl);
        assert_eq!(redactions.len(), 2);
        assert!(!result.contains("foobar123"));
    }

    #[test]
    fn allowlist_overrides_blacklist() {
        let ps = test_pattern_set();
        let bl = Blacklist::from_strings(vec!["foobar123"]);
        let hash = crate::allowlist::sha256_hex("foobar123");
        let al = Allowlist::from_hashes(vec![hash]);
        let input = "text foobar123 here";
        let (result, redactions) = scrub_text(input, &ps, &no_entropy(), &al, &bl);
        assert!(
            result.contains("foobar123"),
            "allowlisted should not be redacted"
        );
        assert!(redactions.is_empty());
    }

    #[test]
    fn blacklist_overlap_with_regex_no_double_redact() {
        let ps = test_pattern_set();
        // Use a string that is also a GitHub token
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let bl = Blacklist::from_strings(vec![token]);
        let input = format!("token: {token}");
        let (result, redactions) = scrub_text(&input, &ps, &no_entropy(), &no_allowlist(), &bl);
        // Should be redacted exactly once (by regex, since it matches first)
        assert_eq!(redactions.len(), 1);
        assert!(result.contains("[REDACTED:"));
        assert!(!result.contains(token));
    }

    #[test]
    fn blacklist_idempotent() {
        let ps = test_pattern_set();
        let bl = Blacklist::from_strings(vec!["foobar123"]);
        let input = "text foobar123 here";
        let (first_pass, _) = scrub_text(input, &ps, &no_entropy(), &no_allowlist(), &bl);
        let (second_pass, redactions) =
            scrub_text(&first_pass, &ps, &no_entropy(), &no_allowlist(), &bl);
        assert_eq!(first_pass, second_pass);
        assert!(redactions.is_empty(), "second pass should find nothing");
    }

    // --- Blacklist hash tests ---

    #[test]
    fn blacklist_hash_redacts_whole_string_value() {
        let ps = test_pattern_set();
        let secret = "my-secret-company-value";
        let hash = crate::allowlist::sha256_hex(secret);
        let bl = Blacklist::from_hashes(vec![hash]);
        let mut value = serde_json::json!({"key": secret});
        let redactions = scrub_all_strings(&mut value, &ps, &no_entropy(), &no_allowlist(), &bl);
        assert_eq!(redactions.len(), 1);
        assert_eq!(redactions[0].pattern_name, "blacklist");
        assert_eq!(value["key"], "[REDACTED:blacklist]");
    }

    #[test]
    fn blacklist_hash_does_not_match_substring() {
        let ps = test_pattern_set();
        let secret = "my-secret-company-value";
        let hash = crate::allowlist::sha256_hex(secret);
        let bl = Blacklist::from_hashes(vec![hash]);
        // The secret appears as a substring but the whole string value is different
        let input = format!("prefix {secret} suffix");
        let (result, redactions) = scrub_text(&input, &ps, &no_entropy(), &no_allowlist(), &bl);
        assert!(redactions.is_empty(), "hash should not match substrings");
        assert_eq!(result, input);
    }

    #[test]
    fn blacklist_hash_allowlist_overrides() {
        let ps = test_pattern_set();
        let secret = "my-secret-company-value";
        let bl_hash = crate::allowlist::sha256_hex(secret);
        let al_hash = crate::allowlist::sha256_hex(secret);
        let bl = Blacklist::from_hashes(vec![bl_hash]);
        let al = Allowlist::from_hashes(vec![al_hash]);
        let mut value = serde_json::json!({"key": secret});
        let redactions = scrub_all_strings(&mut value, &ps, &no_entropy(), &al, &bl);
        assert!(
            redactions.is_empty(),
            "allowlist should override blacklist hash"
        );
        assert_eq!(value["key"], secret);
    }

    #[test]
    fn blacklist_hash_idempotent() {
        let ps = test_pattern_set();
        let secret = "my-secret-company-value";
        let hash = crate::allowlist::sha256_hex(secret);
        let bl = Blacklist::from_hashes(vec![hash]);
        let mut value = serde_json::json!({"key": secret});
        scrub_all_strings(&mut value, &ps, &no_entropy(), &no_allowlist(), &bl);
        assert_eq!(value["key"], "[REDACTED:blacklist]");
        // Second pass should not re-redact
        let redactions = scrub_all_strings(&mut value, &ps, &no_entropy(), &no_allowlist(), &bl);
        assert!(redactions.is_empty());
        assert_eq!(value["key"], "[REDACTED:blacklist]");
    }
}
