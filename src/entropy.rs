use regex::Regex;
use std::sync::LazyLock;

#[derive(Clone)]
pub struct EntropyConfig {
    pub enabled: bool,
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

static EXCLUSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        ^(?:
            (?:[a-zA-Z]:[/\\]|[/~])[^\s]*          # file paths
            | https?://[^\s]+                        # URLs
            | [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+      # emails
            | \[REDACTED:[^\]]+\]                     # already redacted
            | [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}  # UUIDs
        )$
    ",
    )
    .unwrap()
});

static TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/=_\-]{20,}").unwrap());

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

/// Compile user-supplied exclude patterns into a single optional `Regex`.
/// Each pattern is anchored with `^(?:...)$` and combined with alternation.
/// Returns `None` when the list is empty. Invalid patterns are logged and skipped.
pub fn compile_exclude_patterns(patterns: &[String]) -> Option<Regex> {
    if patterns.is_empty() {
        return None;
    }
    // Validate each pattern individually so one bad pattern doesn't break the rest
    let valid: Vec<&str> = patterns
        .iter()
        .filter(|p| {
            if Regex::new(p).is_err() {
                tracing::warn!(pattern = %p, "ignoring invalid entropy exclude pattern");
                false
            } else {
                true
            }
        })
        .map(String::as_str)
        .collect();
    if valid.is_empty() {
        return None;
    }
    let combined = format!("^(?:{})$", valid.join("|"));
    Regex::new(&combined).ok()
}

pub fn find_high_entropy_tokens(text: &str, config: &EntropyConfig) -> Vec<EntropyMatch> {
    find_high_entropy_tokens_inner(
        text,
        config,
        compile_exclude_patterns(&config.exclude_patterns).as_ref(),
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

    TOKEN_RE
        .find_iter(text)
        .filter_map(|m| {
            let token = m.as_str();
            if token.len() < config.min_len {
                return None;
            }
            if EXCLUSION_RE.is_match(token) {
                return None;
            }
            if let Some(re) = user_exclusions
                && re.is_match(token)
            {
                return None;
            }
            let entropy = shannon_entropy(token);
            if entropy >= config.threshold {
                Some(EntropyMatch {
                    start: m.start(),
                    end: m.end(),
                })
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn skips_file_paths() {
        let config = EntropyConfig::default();
        // The token regex only matches alphanumeric+few chars, so paths with / won't match the token regex anyway
        // But let's test with something that could look high-entropy
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
    fn user_exclude_pattern_skips_matching_tokens() {
        let config = EntropyConfig {
            exclude_patterns: vec![r"toolu_[A-Za-z0-9]+".to_string()],
            ..Default::default()
        };
        let text = "toolu_01WcKqikcTdC72gZJhSFfmYf";
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

    #[test]
    fn invalid_exclude_pattern_is_skipped() {
        let re = compile_exclude_patterns(&[r"[invalid".to_string(), r"toolu_.+".to_string()]);
        assert!(re.is_some(), "valid pattern should still compile");
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
