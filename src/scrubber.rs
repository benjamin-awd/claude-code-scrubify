use crate::entropy::{find_high_entropy_tokens, EntropyConfig};
use crate::patterns::PatternSet;

/// Well-known example/placeholder values that should not be redacted.
const KNOWN_EXAMPLES: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",  // AWS docs example key
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  // AWS docs example secret
];

#[derive(Debug, Clone)]
pub struct Redaction {
    pub pattern_name: String,
    pub start: usize,
    pub end: usize,
    pub matched_text: String,
}

pub fn scrub_text(text: &str, pattern_set: &PatternSet, entropy_cfg: &EntropyConfig) -> (String, Vec<Redaction>) {
    // Fast bail-out: if no regex matches at all and entropy is disabled, return early
    if !pattern_set.quick_check.is_match(text) && !entropy_cfg.enabled {
        return (text.to_string(), Vec::new());
    }

    let mut spans: Vec<Redaction> = Vec::new();

    // Collect regex matches
    // Use quick_check to find which patterns matched, then get exact spans
    let matching_indices: Vec<_> = pattern_set.quick_check.matches(text).into_iter().collect();
    for idx in matching_indices {
        let pat = &pattern_set.patterns[idx];
        for m in pat.regex.find_iter(text) {
            let matched = m.as_str();
            if KNOWN_EXAMPLES.iter().any(|ex| matched.contains(ex)) {
                continue;
            }
            spans.push(Redaction {
                pattern_name: pat.name.clone(),
                start: m.start(),
                end: m.end(),
                matched_text: String::new(), // filled after merging
            });
        }
    }

    // Collect entropy matches
    for em in find_high_entropy_tokens(text, entropy_cfg) {
        // Don't flag tokens already covered by regex matches
        let already_covered = spans.iter().any(|s| s.start <= em.start && s.end >= em.end);
        if !already_covered {
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
        if let Some(last) = merged.last_mut() {
            if span.start <= last.1 {
                // Overlapping - extend
                if span.end > last.1 {
                    last.1 = span.end;
                }
                continue;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pattern_set() -> PatternSet {
        PatternSet::load(true)
    }

    fn no_entropy() -> EntropyConfig {
        EntropyConfig { enabled: false, ..Default::default() }
    }

    #[test]
    fn no_secrets() {
        let ps = test_pattern_set();
        let (result, redactions) = scrub_text("hello world", &ps, &no_entropy());
        assert_eq!(result, "hello world");
        assert!(redactions.is_empty());
    }

    #[test]
    fn redacts_github_token() {
        let ps = test_pattern_set();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let (result, redactions) = scrub_text(input, &ps, &no_entropy());
        assert!(result.contains("[REDACTED:github-token]"));
        assert!(!result.contains("ghp_"));
        assert_eq!(redactions.len(), 1);
    }

    #[test]
    fn redacts_multiple_secrets() {
        let ps = test_pattern_set();
        let input = "key1: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl and key2: sk-ant-abcdefghijklmnopqrstuvwxyz";
        let (result, redactions) = scrub_text(input, &ps, &no_entropy());
        assert!(result.contains("[REDACTED:github-token]"));
        assert!(result.contains("[REDACTED:anthropic-key]"));
        assert_eq!(redactions.len(), 2);
    }

    #[test]
    fn idempotent() {
        let ps = test_pattern_set();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let (first_pass, _) = scrub_text(input, &ps, &no_entropy());
        let (second_pass, redactions) = scrub_text(&first_pass, &ps, &no_entropy());
        assert_eq!(first_pass, second_pass);
        assert!(redactions.is_empty());
    }

    #[test]
    fn entropy_detection() {
        let ps = test_pattern_set();
        let cfg = EntropyConfig::default();
        let input = "secret=aB3kL9mN2pQ5rT8vX1yZ4cF7gH0jK6wE";
        let (result, redactions) = scrub_text(input, &ps, &cfg);
        // Should detect via entropy or regex
        assert!(!redactions.is_empty() || result != input);
    }
}
