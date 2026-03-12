use anyhow::{Context, Result};
use regex::{Regex, RegexSet};
use serde::Deserialize;
use std::path::PathBuf;

pub struct SecretPattern {
    pub name: String,
    pub regex: Regex,
    /// Cheap substring keywords — if non-empty, at least one must appear in the
    /// text before we bother running the regex.
    pub keywords: Vec<String>,
    /// If set, only the capture group at this index is the actual secret to
    /// redact. The rest of the regex match is context. `None` = redact the
    /// entire match.
    pub secret_group: Option<usize>,
}

pub struct PatternSet {
    pub patterns: Vec<SecretPattern>,
    pub quick_check: RegexSet,
}

#[derive(Deserialize)]
struct CustomPattern {
    name: String,
    regex: String,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    secret_group: Option<usize>,
}

impl SecretPattern {
    /// Returns true if the text contains at least one keyword (case-insensitive).
    /// If no keywords are defined, always returns true.
    ///
    /// `text_lower` must be the pre-lowercased version of the text being
    /// searched. Accepting it as a parameter avoids re-allocating a lowercase
    /// copy for every pattern.
    pub fn keyword_hit(&self, text_lower: &str) -> bool {
        if self.keywords.is_empty() {
            return true;
        }
        self.keywords.iter().any(|kw| text_lower.contains(kw))
    }
}

impl PatternSet {
    pub fn load(skip_custom: bool) -> Result<Self> {
        let mut patterns = built_in_patterns()?;

        if !skip_custom && let Some(custom) = load_custom_patterns()? {
            patterns.extend(custom);
        }

        let raw: Vec<&str> = patterns.iter().map(|p| p.regex.as_str()).collect();
        let quick_check = RegexSet::new(&raw).context("compiling pattern set")?;

        Ok(PatternSet {
            patterns,
            quick_check,
        })
    }
}

fn built_in_patterns() -> Result<Vec<SecretPattern>> {
    // (name, regex, keywords, secret_group)
    //
    // keywords: cheap substring checks run before the regex.  If the list is
    //   non-empty, at least one keyword must appear (case-insensitive) for the
    //   regex to fire.  Empty list = always run regex.
    //
    // secret_group: when Some(n), only capture group n is the secret to redact;
    //   the surrounding match is context.  None = redact the entire match.
    let defs: Vec<(&str, &str, &[&str], Option<usize>)> = vec![
        // AWS
        (
            "aws-access-key",
            r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
            &["akia", "abia", "acca", "asia"],
            None,
        ),
        (
            "aws-secret-key",
            r#"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
            &["aws_secret", "secret_access_key"],
            Some(1),
        ),
        // GitHub
        (
            "github-token",
            r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}",
            &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
            None,
        ),
        (
            "github-fine-grained",
            r"github_pat_[A-Za-z0-9_]{22,255}",
            &["github_pat_"],
            None,
        ),
        // GitLab
        (
            "gitlab-token",
            r"glpat-[A-Za-z0-9\-_]{20,}",
            &["glpat-"],
            None,
        ),
        // JWT
        (
            "jwt",
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            &["eyj"],
            None,
        ),
        // Private keys
        (
            "private-key",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            &["private key"],
            None,
        ),
        // Generic connection strings
        (
            "connection-string",
            r#"(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s'"]{10,}"#,
            &[
                "mysql://", "postgres", "mongodb", "redis://", "amqp://", "mssql://",
            ],
            None,
        ),
        // Password assignments — capture group 1 is the value (exclude variable refs)
        (
            "password-assignment",
            r#"(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]([^\s'"$]{8,})['"]"#,
            &["password", "passwd", "pwd"],
            Some(1),
        ),
        // Stripe
        (
            "stripe-key",
            r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}",
            &[
                "sk_live", "sk_test", "pk_live", "pk_test", "rk_live", "rk_test",
            ],
            None,
        ),
        // Slack
        (
            "slack-token",
            r"xox[bprs]-[A-Za-z0-9\-]{10,}",
            &["xoxb-", "xoxp-", "xoxr-", "xoxs-"],
            None,
        ),
        (
            "slack-webhook",
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
            &["hooks.slack.com"],
            None,
        ),
        // Anthropic
        (
            "anthropic-key",
            r"sk-ant-[A-Za-z0-9\-_]{20,}",
            &["sk-ant-"],
            None,
        ),
        // OpenAI (no hyphens after sk- prefix; real keys are alphanumeric only)
        ("openai-key", r"sk-[A-Za-z0-9]{20,}", &["sk-"], None),
        // Google
        ("google-api-key", r"AIza[A-Za-z0-9\-_]{35}", &["aiza"], None),
        (
            "google-oauth-secret",
            r#"(?i)client_secret['"]?\s*[=:]\s*['"]?(GOCSPX-[A-Za-z0-9\-_]+)"#,
            &["gocspx-"],
            Some(1),
        ),
        // npm
        ("npm-token", r"npm_[A-Za-z0-9]{36}", &["npm_"], None),
        // Generic API key assignment — capture group 1 is the value
        (
            "generic-api-key",
            r#"(?i)(?:api_key|apikey|api_secret|secret_key|access_token)\s*[=:]\s*['"]([A-Za-z0-9\-_./+=]{20,})['"]"#,
            &[
                "api_key",
                "apikey",
                "api_secret",
                "secret_key",
                "access_token",
            ],
            Some(1),
        ),
        // Heroku — capture group 1 is the UUID value
        (
            "heroku-api-key",
            r#"(?i)heroku[_\s]*api[_\s]*key\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"#,
            &["heroku"],
            Some(1),
        ),
        // Twilio
        ("twilio-api-key", r"SK[0-9a-fA-F]{32}", &["sk"], None),
        // SendGrid
        (
            "sendgrid-key",
            r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}",
            &["sg."],
            None,
        ),
    ];

    defs.into_iter()
        .map(|(name, pattern, keywords, secret_group)| {
            let regex = Regex::new(pattern)
                .with_context(|| format!("invalid regex for pattern '{name}'"))?;
            Ok(SecretPattern {
                name: name.to_string(),
                regex,
                keywords: keywords.iter().map(|k| (*k).to_string()).collect(),
                secret_group,
            })
        })
        .collect()
}

fn load_custom_patterns() -> Result<Option<Vec<SecretPattern>>> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Ok(None);
    };
    let path = home.join(".claude").join("scrubber-patterns.json");
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context(format!("reading {}", path.display())),
    };
    let custom: Vec<CustomPattern> =
        serde_json::from_str(&data).context(format!("parsing {}", path.display()))?;

    let patterns: Vec<SecretPattern> = custom
        .into_iter()
        .map(|c| {
            let regex = Regex::new(&c.regex)
                .with_context(|| format!("invalid regex for custom pattern '{}'", c.name))?;
            Ok(SecretPattern {
                name: c.name,
                regex,
                keywords: c.keywords,
                secret_group: c.secret_group,
            })
        })
        .collect::<Result<_>>()?;

    Ok(Some(patterns))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(pattern_name: &str, positives: &[&str], negatives: &[&str]) {
        let patterns = built_in_patterns().unwrap();
        let pat = patterns
            .iter()
            .find(|p| p.name == pattern_name)
            .unwrap_or_else(|| panic!("pattern not found: {pattern_name}"));

        for s in positives {
            assert!(pat.regex.is_match(s), "{pattern_name} should match: {s}");
        }
        for s in negatives {
            assert!(
                !pat.regex.is_match(s),
                "{pattern_name} should NOT match: {s}"
            );
        }
    }

    #[test]
    fn aws_access_key() {
        check(
            "aws-access-key",
            &["AKIAVCODYLSA53PQK4ZA", " ASIA1234567890ABCDEF "],
            &["NOTAKEY1234567890123", "akiaiosfodnn7example1"],
        );
    }

    #[test]
    fn aws_secret_key() {
        check(
            "aws-secret-key",
            &[
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "aws_secret_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
            ],
            &["aws_secret_access_key = short", "random text here"],
        );
    }

    #[test]
    fn github_token() {
        check(
            "github-token",
            &[
                "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl",
                "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl",
            ],
            &["ghp_short", "xxx_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"],
        );
    }

    #[test]
    fn github_fine_grained() {
        check(
            "github-fine-grained",
            &["github_pat_11ABCDEFGH0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS"],
            &["github_pat_short", "github_token_something"],
        );
    }

    #[test]
    fn gitlab_token() {
        check(
            "gitlab-token",
            &[
                "glpat-abcdefghijklmnopqrst",
                "glpat-ABC_DEF-GHI_123456789012",
            ],
            &["glpat-short", "glxyz-abcdefghijklmnopqrst"],
        );
    }

    #[test]
    fn jwt() {
        check(
            "jwt",
            &[
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            ],
            &["eyJshort.eyJshort.short", "notajwt"],
        );
    }

    #[test]
    fn private_key() {
        check(
            "private-key",
            &[
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN EC PRIVATE KEY-----",
            ],
            &["-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----"],
        );
    }

    #[test]
    fn connection_string() {
        check(
            "connection-string",
            &[
                "postgres://user:pass@localhost:5432/dbname",
                "mongodb+srv://admin:secret@cluster.mongodb.net/db",
            ],
            &["postgres://short", "http://example.com"],
        );
    }

    #[test]
    fn password_assignment() {
        check(
            "password-assignment",
            &[
                r#"password = "my_super_secret_password""#,
                r"PASSWORD: 'longpassword123'",
            ],
            &[
                r#"password = "short""#,
                "password reset link",
                r#"password: "${CLICKHOUSE_CLOUD_KEY_SECRET}""#, // variable ref
                r#"password = "${DB_PASSWORD}""#,                // variable ref
            ],
        );
    }

    #[test]
    fn stripe_key() {
        check(
            "stripe-key",
            &[
                "sk_live_abcdefghijklmnopqrst",
                "pk_test_1234567890abcdefghij",
            ],
            &["sk_live_short", "xx_live_abcdefghijklmnopqrst"],
        );
    }

    #[test]
    fn slack_token() {
        check(
            "slack-token",
            &["xoxb-1234567890-abcdefghij", "xoxp-9876543210-1234567890"],
            &["xoxb-short", "xoxa-1234567890-abcdefghij"],
        );
    }

    #[test]
    fn anthropic_key() {
        check(
            "anthropic-key",
            &[
                "sk-ant-api03-abcdefghijklmnopqrst",
                "sk-ant-ABCDEFGHIJKLMNOPQRST",
            ],
            &["sk-ant-short", "sk-other-abcdefghijklmnopqrst"],
        );
    }

    #[test]
    fn openai_key() {
        check(
            "openai-key",
            &["sk-abcdefghijklmnopqrstuvwx", "sk-1234567890abcdefghijklmn"],
            &[
                "sk-short",
                "xx-abcdefghijklmnopqrstuvwx",
                "sk-deploy-confd-flowdesk-0-0",    // K8s resource name
                "sk-output-waiting-1771554457934", // Claude Code internal ID
                "sk-pv-claim-sink-connector-light", // K8s PVC
                "sk-ant-abcdefghijklmnopqrst",     // anthropic key, not openai
            ],
        );
    }

    #[test]
    fn google_api_key() {
        check(
            "google-api-key",
            &["AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"],
            &["AIza_short", "BIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"],
        );
    }

    #[test]
    fn npm_token() {
        check(
            "npm-token",
            &["npm_abcdefghijklmnopqrstuvwxyz1234567890"],
            &["npm_short", "npx_abcdefghijklmnopqrstuvwxyz1234567890"],
        );
    }

    #[test]
    fn generic_api_key() {
        check(
            "generic-api-key",
            &[
                r#"api_key = "abcdefghijklmnopqrstuvwxyz""#,
                r#"apikey: "12345678901234567890""#,
            ],
            &[r#"api_key = "short""#, "api_key documentation"],
        );
    }

    #[test]
    fn sendgrid_key() {
        check(
            "sendgrid-key",
            &["SG.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQRS"],
            &["SG.short.short", "XX.abcdefghijklmnopqrstuv.wxyzABCDEF"],
        );
    }

    #[test]
    fn pattern_set_loads() {
        let ps = PatternSet::load(true).unwrap();
        assert!(ps.patterns.len() >= 20);
        assert_eq!(ps.patterns.len(), ps.quick_check.len());
    }

    #[test]
    fn keyword_prefilter() {
        let patterns = built_in_patterns().unwrap();
        let aws = patterns
            .iter()
            .find(|p| p.name == "aws-access-key")
            .unwrap();
        assert!(aws.keyword_hit(&"contains AKIA somewhere".to_lowercase()));
        assert!(!aws.keyword_hit(&"no relevant keywords here".to_lowercase()));
    }
}
