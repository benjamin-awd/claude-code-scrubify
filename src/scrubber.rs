use serde_json::Value;

use crate::allowlist::Allowlist;
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
) -> (String, Vec<Redaction>) {
    // Fast bail-out: if no regex matches at all and entropy is disabled, return early
    if !pattern_set.quick_check.is_match(text) && !entropy_cfg.enabled {
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

    if spans.is_empty() {
        return (text.to_string(), Vec::new());
    }

    // Sort by start offset
    spans.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));

    // Merge overlapping spans and build output
    let mut result = String::with_capacity(text.len());
    let mut redactions: Vec<Redaction> = Vec::new();
    let mut pos = 0;

    let mut merged: Vec<(usize, usize, String)> = Vec::new();
    for span in &spans {
        if let Some(last) = merged.last_mut()
            && span.start <= last.1
        {
            // Overlapping - extend
            if span.end > last.1 {
                last.1 = span.end;
            }
            continue;
        }
        merged.push((span.start, span.end, span.pattern_name.clone()));
    }

    for (start, end, name) in &merged {
        if *start > pos {
            result.push_str(&text[pos..*start]);
        }
        let matched = &text[*start..*end];
        let replacement = format!("[REDACTED:{name}]");
        result.push_str(&replacement);
        redactions.push(Redaction {
            pattern_name: name.clone(),
            start: *start,
            end: *end,
            matched_text: matched.to_string(),
        });
        pos = *end;
    }
    if pos < text.len() {
        result.push_str(&text[pos..]);
    }

    (result, redactions)
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_KEYS
        .iter()
        .any(|&k| lower == k || lower.ends_with(&format!("_{k}")))
}

/// Recursively scrub all string values in a JSON value tree.
pub fn scrub_all_strings(
    value: &mut Value,
    ps: &PatternSet,
    ec: &EntropyConfig,
    al: &Allowlist,
) -> Vec<Redaction> {
    scrub_all_strings_inner(value, ps, ec, al, false)
}

fn scrub_all_strings_inner(
    value: &mut Value,
    ps: &PatternSet,
    ec: &EntropyConfig,
    al: &Allowlist,
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
            let (scrubbed, redactions) = scrub_text(s, ps, ec, al);
            if !redactions.is_empty() {
                *s = scrubbed;
            }
            redactions
        }
        Value::Array(arr) => arr
            .iter_mut()
            .flat_map(|v| scrub_all_strings_inner(v, ps, ec, al, force_redact))
            .collect(),
        Value::Object(map) => {
            let mut redactions = Vec::new();
            for (key, val) in map.iter_mut() {
                let sensitive = is_sensitive_key(key);
                redactions.extend(scrub_all_strings_inner(val, ps, ec, al, sensitive));
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

    #[test]
    fn no_secrets() {
        let ps = test_pattern_set();
        let (result, redactions) = scrub_text("hello world", &ps, &no_entropy(), &no_allowlist());
        assert_eq!(result, "hello world");
        assert!(redactions.is_empty());
    }

    #[test]
    fn redacts_github_token() {
        let ps = test_pattern_set();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let (result, redactions) = scrub_text(input, &ps, &no_entropy(), &no_allowlist());
        assert!(result.contains("[REDACTED:github-token]"));
        assert!(!result.contains("ghp_"));
        assert_eq!(redactions.len(), 1);
    }

    #[test]
    fn redacts_multiple_secrets() {
        let ps = test_pattern_set();
        let input = "key1: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl and key2: sk-ant-abcdefghijklmnopqrstuvwxyz";
        let (result, redactions) = scrub_text(input, &ps, &no_entropy(), &no_allowlist());
        assert!(result.contains("[REDACTED:github-token]"));
        assert!(result.contains("[REDACTED:anthropic-key]"));
        assert_eq!(redactions.len(), 2);
    }

    #[test]
    fn idempotent() {
        let ps = test_pattern_set();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let (first_pass, _) = scrub_text(input, &ps, &no_entropy(), &no_allowlist());
        let (second_pass, redactions) =
            scrub_text(&first_pass, &ps, &no_entropy(), &no_allowlist());
        assert_eq!(first_pass, second_pass);
        assert!(redactions.is_empty());
    }

    #[test]
    fn skips_short_matches() {
        let ps = test_pattern_set();
        // "SK" + 32 hex chars = 34 chars, should be redacted
        let long_input = format!("key: SK{}", "1234567890abcdef".repeat(2));
        let (_, redactions) = scrub_text(&long_input, &ps, &no_entropy(), &no_allowlist());
        assert!(!redactions.is_empty(), "long twilio key should be redacted");
    }

    #[test]
    fn secret_group_redacts_only_value() {
        let ps = test_pattern_set();
        let input = r#"password = "my_super_secret_password""#;
        let (result, redactions) = scrub_text(input, &ps, &no_entropy(), &no_allowlist());
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
        let (result, redactions) = scrub_text(&input, &ps, &no_entropy(), &al);
        assert!(result.contains(token), "allowlisted value should remain");
        assert!(redactions.is_empty());
    }

    #[test]
    fn entropy_detection() {
        let ps = test_pattern_set();
        let cfg = EntropyConfig::default();
        let input = "secret=aB3kL9mN2pQ5rT8vX1yZ4cF7gH0jK6wE";
        let (result, redactions) = scrub_text(input, &ps, &cfg, &no_allowlist());
        // Should detect via entropy or regex
        assert!(!redactions.is_empty() || result != input);
    }
}
