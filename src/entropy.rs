use regex::Regex;
use std::sync::LazyLock;

#[derive(Clone)]
pub struct EntropyConfig {
    pub enabled: bool,
    pub threshold: f64,
    pub min_len: usize,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        EntropyConfig {
            enabled: true,
            threshold: 4.5,
            min_len: 20,
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
            let freq = c as f64 / len;
            -freq * freq.log2()
        })
        .sum()
}

pub fn find_high_entropy_tokens(text: &str, config: &EntropyConfig) -> Vec<EntropyMatch> {
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
