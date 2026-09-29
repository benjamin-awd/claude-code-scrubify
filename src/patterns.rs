use anyhow::{Context, Result};
use regex::{Regex, RegexSet};

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
    /// All unique keywords across every pattern, for cheap line-level pre-filtering.
    pub all_keywords: Vec<String>,
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
    /// Cheap check: does the text contain any keyword from any pattern?
    /// Operates on already-lowercased text.
    pub fn any_keyword_hit(&self, text_lower: &str) -> bool {
        self.all_keywords
            .iter()
            .any(|kw| text_lower.contains(kw.as_str()))
    }

    pub fn load(skip_custom: bool) -> Result<Self> {
        let mut patterns = built_in_patterns()?;

        if !skip_custom {
            let settings = crate::allowlist::load_config()?;
            patterns.extend(compile_custom_patterns(settings.custom_patterns));
        }

        let raw: Vec<&str> = patterns.iter().map(|p| p.regex.as_str()).collect();
        let quick_check = RegexSet::new(&raw).context("compiling pattern set")?;

        let mut seen = std::collections::HashSet::new();
        let all_keywords: Vec<String> = patterns
            .iter()
            .flat_map(|p| p.keywords.iter().cloned())
            .filter(|kw| seen.insert(kw.clone()))
            .collect();

        Ok(PatternSet {
            patterns,
            quick_check,
            all_keywords,
        })
    }
}

/// Stable hash of the built-in pattern definitions (name, regex, keywords,
/// secret group). Feeds the cache fingerprint so pattern changes force a rescan.
pub fn built_in_fingerprint() -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for p in built_in_patterns().unwrap_or_default() {
        hasher.update(p.name.as_bytes());
        hasher.update([0]);
        hasher.update(p.regex.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(p.keywords.join(",").as_bytes());
        hasher.update([0]);
        hasher.update(format!("{:?}", p.secret_group).as_bytes());
        hasher.update([0xff]);
    }
    crate::allowlist::to_hex(&hasher.finalize())
}

/// Built-in patterns whose unquoted values may be code rather than a literal
/// (`password: userPassword`, `TOKEN = settings.TOKEN`). The scrubber skips
/// identifier-like and path-like values for these.
pub const LOOSE_VALUE_PATTERNS: &[&str] = &[
    "env-credential",
    "config-credential",
    "bearer-token",
    "docker-config-auth",
];

/// Built-in patterns with strong credential context (URL userinfo, CLI flag)
/// where even short values are real passwords.
pub const SHORT_VALUE_PATTERNS: &[&str] = &[
    "url-userinfo",
    "netrc-password",
    "mysql-cli-password",
    "curl-user-password",
];

/// Compile user-defined patterns. A bad custom pattern must not disable
/// redaction: it is skipped with a warning (built-ins and the other custom
/// patterns still load). The warning never includes the regex source, which
/// may embed a literal secret.
fn compile_custom_patterns(
    custom: Vec<crate::allowlist::CustomPatternConfig>,
) -> Vec<SecretPattern> {
    let mut out = Vec::with_capacity(custom.len());
    for c in custom {
        let regex = match crate::allowlist::compile_custom_pattern(&c) {
            Ok(r) => r,
            Err(reason) => {
                tracing::warn!(
                    pattern = %c.name,
                    %reason,
                    "skipping invalid custom pattern from scrubber.toml"
                );
                continue;
            }
        };
        out.push(SecretPattern {
            name: c.name,
            // Keywords are matched against lowercased text.
            keywords: c.keywords.iter().map(|k| k.to_lowercase()).collect(),
            regex,
            secret_group: c.secret_group,
        });
    }
    out
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
    //
    // Key/value patterns accept `['"\\]*` after the key and `\\?['"`]` before
    // the value so JSON (`"password": "…"`), JSON inside a JSON string
    // (`\"password\":\"…\"`) and backtick-quoted values all match.
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
            r#"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)['"\\]*\s*[=:]\s*\\?['"`]?([A-Za-z0-9/+=]{40})"#,
            &["aws_secret", "secret_access_key"],
            Some(1),
        ),
        // STS session tokens are several hundred base64 chars
        (
            "aws-session-token",
            r#"(?i)(?:aws_session_token|aws_security_token|x-amz-security-token)['"\\]*\s*[=:]\s*\\?['"`]?([A-Za-z0-9/+=]{100,})"#,
            &[
                "aws_session_token",
                "aws_security_token",
                "x-amz-security-token",
            ],
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
        // GCP service-account JSON — capture group 1 is the whole PEM value.
        // Listed before private-key so the more specific name wins when both
        // cover the same span. Optional backslashes cover JSON nested inside a
        // JSON string (e.g. tool inputs).
        (
            "gcp-service-account-key",
            r#"private_key\\?"\s*:\s*\\?"(-----BEGIN PRIVATE KEY-----[^"]*?-----END PRIVATE KEY-----)"#,
            &["private_key"],
            Some(1),
        ),
        // PEM private keys (PKCS#8, RSA, EC, DSA, OPENSSH, ENCRYPTED, PGP): the
        // whole block through the END line, across real or literal `\n`
        // newlines. Without an END line (truncated output) the header plus
        // the base64 lines that follow it are redacted.
        (
            "private-key",
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:(?s:.*?)-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|(?:(?:\s|\\[rn])+[A-Za-z0-9+/=]{16,})*)",
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
        // Stripe
        (
            "stripe-key",
            r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}",
            &[
                "sk_live", "sk_test", "pk_live", "pk_test", "rk_live", "rk_test",
            ],
            None,
        ),
        // Slack: bot, user, app-config (xoxa/xoxe/xoxo), refresh and legacy tokens
        (
            "slack-token",
            r"xox[abeoprs]-[A-Za-z0-9\-]{10,}",
            &[
                "xoxa-", "xoxb-", "xoxe-", "xoxo-", "xoxp-", "xoxr-", "xoxs-",
            ],
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
        // OpenAI legacy keys (no hyphens after sk- prefix; alphanumeric only)
        ("openai-key", r"sk-[A-Za-z0-9]{20,}", &["sk-"], None),
        // OpenAI project / service-account / admin keys
        (
            "openai-project-key",
            r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}",
            &["sk-proj-", "sk-svcacct-", "sk-admin-"],
            None,
        ),
        // Google
        ("google-api-key", r"AIza[A-Za-z0-9\-_]{35}", &["aiza"], None),
        (
            "google-oauth-secret",
            r#"(?i)client_secret['"]?\s*[=:]\s*['"]?(GOCSPX-[A-Za-z0-9\-_]+)"#,
            &["gocspx-"],
            Some(1),
        ),
        // GCS HMAC access IDs: 61 chars for service accounts, 24 for user
        // accounts (https://cloud.google.com/storage/docs/authentication/hmackeys).
        // The 40-char secret has no prefix and is left to entropy detection.
        (
            "gcs-hmac-access-id",
            r"\bGOOG(?:[0-9A-Z]{57}|[0-9A-Z]{20})\b",
            &["goog"],
            None,
        ),
        // npm
        ("npm-token", r"npm_[A-Za-z0-9]{36}", &["npm_"], None),
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
        // Grafana
        (
            "grafana-service-account-token",
            r"glsa_[A-Za-z0-9]{32}_[0-9a-f]{8}",
            &["glsa_"],
            None,
        ),
        (
            "grafana-cloud-token",
            r"glc_[A-Za-z0-9+/=_-]{32,}",
            &["glc_"],
            None,
        ),
        // Legacy API keys are base64 JSON starting with {"k":" (no dots, so disjoint from jwt)
        (
            "grafana-api-key",
            r"eyJrIjoi[A-Za-z0-9+/=]{30,}",
            &["eyjrijoi"],
            None,
        ),
        // Slack app-level token: xapp-<version>-<app id>-<numeric id>-<secret>
        (
            "slack-app-token",
            r"(?i)xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]+",
            &["xapp-"],
            None,
        ),
        // HashiCorp Vault service (hvs.) and batch (hvb.) tokens
        (
            "vault-token",
            r"hv[sb]\.[A-Za-z0-9_-]{24,}",
            &["hvs.", "hvb."],
            None,
        ),
        // Doppler; service tokens may carry an environment slug (dp.st.<env>.<token>)
        (
            "doppler-token",
            r"dp\.(?:pt|st|sa|ct|scim|audit)\.(?:[a-z0-9_-]+\.)?[A-Za-z0-9]{40,}",
            &[
                "dp.pt.",
                "dp.st.",
                "dp.sa.",
                "dp.ct.",
                "dp.scim.",
                "dp.audit.",
            ],
            None,
        ),
        // DigitalOcean personal access, OAuth and refresh tokens
        (
            "digitalocean-token",
            r"do[oprt]_v1_[a-f0-9]{64}",
            &["dop_v1_", "doo_v1_", "dor_v1_", "dot_v1_"],
            None,
        ),
        // PyPI macaroons: base64 prefix encodes the "pypi.org" / "test.pypi.org" location
        (
            "pypi-token",
            r"pypi-AgE(?:IcHlwaS5vcmc|NdGVzdC5weXBpLm9yZw)[A-Za-z0-9_-]{50,}",
            &["pypi-age"],
            None,
        ),
        // age: Bech32 payload (uppercase alphabet, no 1/B/I/O)
        (
            "age-secret-key",
            r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
            &["age-secret-key-1"],
            None,
        ),
        // Terraform Cloud / Enterprise API token (also in ~/.terraform.d/credentials.tfrc.json)
        (
            "terraform-cloud-token",
            r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,}",
            &[".atlasv1."],
            None,
        ),
        // ---- Generic key/value and CLI context patterns ----
        // Kept last: on an identical span the scrubber keeps the first
        // pattern's name, so provider-specific names win over these.
        // Password in any URL's userinfo (rediss://, postgresql+psycopg2://,
        // https://user:pass@…) — capture group 1 is the password.
        (
            "url-userinfo",
            r#"(?i)\b[a-z][a-z0-9+.-]*://[^:/\s@'"]*:([^@\s/?#'"]+)@"#,
            &["://"],
            Some(1),
        ),
        // Password assignments — capture group 1 is the value (exclude variable refs)
        (
            "password-assignment",
            r#"(?i)(?:password|passwd|pwd)['"\\]*\s*[=:]\s*\\?['"`]([^\s'"`$\\][^\s'"`\\]{7,})\\?['"`]"#,
            &["password", "passwd", "pwd"],
            Some(1),
        ),
        // Upper-case env-style assignments: `export DB_PASSWORD=…`,
        // `PGPASSWORD=…`, `API_KEY: …`. `\b` after the key word keeps
        // `TOKEN_TYPE=`, `PASSWORD_MIN_LENGTH=` and `MAX_TOKENS=` out; bare
        // `PASS`/`PWD` need a prefix so `--- PASS: TestX` and `PWD=/home` don't fire.
        (
            "env-credential",
            r#"\b[A-Z0-9_]*(?:PASSWORD|PASSWD|_PASS|_PWD|SECRET|TOKEN|API_?KEY|(?:SECRET|ACCESS|PRIVATE|SIGNING|ENCRYPTION|MASTER|AUTH)_KEY|CREDENTIALS?)\b\s*[=:]\s*['"]?([^\s'"$\\<>{}()\[\],;`]{8,})"#,
            &["pass", "pwd", "secret", "token", "key", "credential"],
            Some(1),
        ),
        // Line-anchored YAML / INI / .pypirc / kubeconfig values:
        // `password: …`, `password = …`, `token: …`, `client_secret: …`.
        (
            "config-credential",
            r#"(?im)^[ \t]*(?:-[ \t]+)?["']?[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key)["']?[ \t]*[:=][ \t]*["']?([^\s'"$\\<>{}()\[\],;`]{8,})["']?(?:[ \t]+#.*)?[ \t]*$"#,
            &["pass", "secret", "token", "key"],
            Some(1),
        ),
        // ~/.netrc: `machine host login user password secret` (also `default`)
        (
            "netrc-password",
            r"\b(?:machine(?:\s|\\[nt])+[^\s\\]+|default)(?:\s|\\[nt])+login(?:\s|\\[nt])+[^\s\\]+(?:\s|\\[nt])+password(?:\s|\\[nt])+([^\s\\$]+)",
            &["machine", "default"],
            Some(1),
        ),
        // `mysql -pSECRET` / `--password=SECRET` (a bare `-p` prompts instead)
        (
            "mysql-cli-password",
            r#"\b(?:mysql|mysqldump|mysqladmin|mysqlsh|mariadb)\b[^\n|;&]*?\s(?:-p|--password=)['"]?([^\s'"$<-][^\s'"]*)"#,
            &["mysql", "mariadb"],
            Some(1),
        ),
        // `curl -u user:pass` / `curl --user user:pass`
        (
            "curl-user-password",
            r#"\bcurl\b[^\n|;&]*?\s(?:-u|--user)(?:\s+|=)['"]?[^\s:'"]+:([^\s'"$<][^\s'"]*)"#,
            &["curl"],
            Some(1),
        ),
        // HTTP auth headers
        (
            "basic-auth-header",
            r#"(?i)\bauthorization\\?["']?\s*[:=]\s*\\?["']?basic\s+([A-Za-z0-9+/]{8,}={0,2})"#,
            &["basic"],
            Some(1),
        ),
        (
            "bearer-token",
            r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{16,}=*)",
            &["bearer"],
            Some(1),
        ),
        // Kubernetes Secret manifests (`kubectl get secret -o yaml|json`): the
        // whole `data:` / `stringData:` block. Only runs when the text says
        // `kind: Secret`, so ConfigMaps and other `data:` maps are untouched.
        (
            "k8s-secret-data",
            r"(?m)^[ \t]*(?:-[ \t]+)?(?:data|stringData):[ \t]*\r?\n((?:[ \t]+[\w.-]+:[ \t]*\S[^\n]*)(?:\n[ \t]+[\w.-]+:[ \t]*\S[^\n]*)*)",
            &["kind: secret"],
            Some(1),
        ),
        (
            "k8s-secret-data-json",
            r#"\\?"(?:data|stringData)\\?"\s*:\s*\{((?:\s*\\?"[\w.-]+\\?"\s*:\s*\\?"[^"\\]*\\?"\s*,?)+)\s*\}"#,
            &[
                r#""kind": "secret""#,
                r#""kind":"secret""#,
                r#"\"kind\": \"secret\""#,
                r#"\"kind\":\"secret\""#,
            ],
            Some(1),
        ),
        // Docker config.json / .dockerconfigjson: "auth" is base64(user:pass)
        (
            "docker-config-auth",
            r#"\\?"(?:auth|identitytoken)\\?"\s*:\s*\\?"([A-Za-z0-9+/=._-]{8,})\\?""#,
            &[r#"auth""#, r#"auth\""#, "identitytoken"],
            Some(1),
        ),
        // base64 of a whole docker config ({"auths": …}), as stored in k8s
        (
            "docker-config-b64",
            r"eyJhdXRocyI6[A-Za-z0-9+/]{20,}={0,2}",
            &["eyjhdxrocyi6"],
            None,
        ),
        // kubeconfig user credentials (`token:` is covered by config-credential)
        (
            "kubeconfig-credential",
            r#"(?i)\b(?:client-key-data|id-token|refresh-token|access-token)\\?["']?\s*:\s*\\?["']?([A-Za-z0-9+/=._~-]{16,})"#,
            &[
                "client-key-data",
                "id-token",
                "refresh-token",
                "access-token",
            ],
            Some(1),
        ),
        // Generic API key assignment — capture group 1 is the value
        (
            "generic-api-key",
            r#"(?i)(?:api[_-]?key|api_secret|secret_key|access_token|auth_token)['"\\]*\s*[=:]\s*\\?['"`]?([A-Za-z0-9\-_./+=]{20,})\\?['"`]"#,
            &[
                "api_key",
                "apikey",
                "api-key",
                "api_secret",
                "secret_key",
                "access_token",
                "auth_token",
            ],
            Some(1),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_custom_patterns_are_skipped_not_fatal() {
        use crate::allowlist::CustomPatternConfig;
        let mk = |name: &str, regex: &str| CustomPatternConfig {
            name: name.into(),
            regex: regex.into(),
            keywords: vec!["ITK_".into()],
            secret_group: None,
        };
        let custom = vec![
            mk("broken", "itk_secretliteral("),
            mk("huge", r"\w{5000}\w{5000}"),
            mk("good", "itk_[a-z0-9]{12}"),
        ];
        let (compiled, logs) =
            crate::allowlist::tests::capture_logs(|| compile_custom_patterns(custom));
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].name, "good");
        assert_eq!(compiled[0].keywords, vec!["itk_"]);
        assert!(logs.contains("broken") && logs.contains("huge"), "{logs}");
        assert!(!logs.contains("secretliteral"), "regex leaked: {logs}");

        // Built-ins plus the surviving custom pattern still form a valid set.
        let mut all = built_in_patterns().unwrap();
        let builtin = all.len();
        all.extend(compiled);
        assert_eq!(all.len(), builtin + 1);
        let raw: Vec<&str> = all.iter().map(|p| p.regex.as_str()).collect();
        assert!(RegexSet::new(&raw).is_ok());
    }

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
                r#"password: "${CLOUD_KEY_SECRET}""#, // variable ref
                r#"password = "${DB_PASSWORD}""#,     // variable ref
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
            &[
                "xoxb-1234567890-abcdefghij",
                "xoxp-9876543210-1234567890",
                concat!("xoxa-", "2-1234567890-abcdefghij"),
                concat!("xoxe-", "1-FAKEfakeFAKEfake"),
                concat!("xoxo-", "1234567890-abcdefghij"),
            ],
            &["xoxb-short", "xoxz-1234567890-abcdefghij"],
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
                "sk-deploy-confd-example-0-0",      // K8s resource name
                "sk-output-waiting-1771554457934",  // Claude Code internal ID
                "sk-pv-claim-sink-connector-light", // K8s PVC
                "sk-ant-abcdefghijklmnopqrst",      // anthropic key, not openai
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

    // Synthetic vectors: "FAKE"/"fake"/"deadbeef" filler shaped to each format.
    const GRAFANA_SA: &str = "glsa_FAKEfakeFAKEfakeFAKEfakeFAKEfake_0123abcd";
    const GRAFANA_CLOUD: &str = "glc_FAKEfakeFAKEfakeFAKEfakeFAKEfake==";
    const GRAFANA_LEGACY: &str = "eyJrIjoiRkFLRWZha2VGQUtFZmFrZUZBS0VmYWtl";
    const SLACK_APP: &str = "xapp-1-A0FAKEFAKE0-1234567890123-fakefakefakefake0123456789";
    const VAULT_SERVICE: &str = "hvs.FAKEfakeFAKEfakeFAKEfake00";
    const VAULT_BATCH: &str = "hvb.FAKEfakeFAKEfakeFAKEfake_-00";
    // Split with concat! so GitHub push protection doesn't flag the fake literals.
    const DOPPLER_PERSONAL: &str = concat!("dp.pt.", "FAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfake000");
    const DOPPLER_SERVICE: &str =
        concat!("dp.st.dev.", "FAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfake000");
    const DIGITALOCEAN: &str =
        "dop_v1_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const PYPI: &str =
        "pypi-AgEIcHlwaS5vcmcFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfake";
    const TEST_PYPI: &str =
        "pypi-AgENdGVzdC5weXBpLm9yZwFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfake";
    const AGE: &str = "AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE";
    const TERRAFORM: &str =
        "FAKEfakeFAKE00.atlasv1.FAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfake";
    const OPENAI_PROJECT: &str = concat!("sk-proj-", "FAKEfakeFAKEfake_FAKE-fakeFAKEfake");
    const OPENAI_SVCACCT: &str = concat!("sk-svcacct-", "FAKEfakeFAKEfakeFAKEfake");
    const OPENAI_ADMIN: &str = concat!("sk-admin-", "FAKEfakeFAKEfakeFAKEfake");
    const SLACK_CONFIG: &str = concat!("xoxe-", "1-FAKEfakeFAKEfake0123");
    const SLACK_APP_CONFIG: &str = concat!("xoxa-", "2-FAKEfakeFAKEfake0123");
    const SLACK_ORG: &str = concat!("xoxo-", "FAKEfakeFAKEfake0123");
    // GCS HMAC access IDs: 61 chars (service account) and 24 chars (user).
    const GCS_HMAC_SA: &str = concat!(
        "GOOG1",
        "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
    );
    const GCS_HMAC_USER: &str = concat!("GOOG", "FAKEFAKEFAKEFAKE0123");
    // base64 of {"auths":{"fake.example.com":{"auth":"ZmFrZTpmYWtl"}}}
    const DOCKER_B64: &str =
        "eyJhdXRocyI6eyJmYWtlLmV4YW1wbGUuY29tIjp7ImF1dGgiOiJabUZyWlRwbVlXdGwifX19";
    const PEM_RSA: &str = concat!(
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "MIIEFAKEfakeFAKEfakeFAKEfake\n",
        "-----END RSA PRIVATE KEY-----"
    );

    #[test]
    fn grafana_service_account_token() {
        check(
            "grafana-service-account-token",
            &[GRAFANA_SA, &format!("GRAFANA_TOKEN={GRAFANA_SA}")],
            &[
                "glsa_short_0123abcd",
                "glsa_FAKEfakeFAKEfakeFAKEfakeFAKEfake_ZZZZZZZZ", // non-hex checksum
            ],
        );
    }

    #[test]
    fn gcp_service_account_key() {
        check(
            "gcp-service-account-key",
            &[
                r#""private_key": "-----BEGIN PRIVATE KEY-----\nFAKEfakeFAKEfake\n-----END PRIVATE KEY-----\n","#,
                // JSON embedded in a JSON string (escaped quotes and newlines)
                r#"\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nFAKEfakeFAKEfake\\n-----END PRIVATE KEY-----\\n\""#,
            ],
            &[
                r#""private_key": "${GCP_PRIVATE_KEY}""#,
                r#""private_key_id": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef""#,
            ],
        );
    }

    #[test]
    fn grafana_cloud_token() {
        check(
            "grafana-cloud-token",
            &[GRAFANA_CLOUD],
            &["glc_short", "glx_FAKEfakeFAKEfakeFAKEfakeFAKEfake=="],
        );
    }

    #[test]
    fn grafana_api_key() {
        check(
            "grafana-api-key",
            &[GRAFANA_LEGACY],
            &[
                "eyJrIjoishort",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", // JWT header, not {"k":
            ],
        );
    }

    #[test]
    fn slack_app_token() {
        check(
            "slack-app-token",
            &[SLACK_APP],
            &["xapp-1-", "xapp-release-notes"],
        );
    }

    #[test]
    fn vault_token() {
        check(
            "vault-token",
            &[VAULT_SERVICE, VAULT_BATCH],
            &["hvs.short", "hvx.FAKEfakeFAKEfakeFAKEfake00"],
        );
    }

    #[test]
    fn doppler_token() {
        check(
            "doppler-token",
            &[DOPPLER_PERSONAL, DOPPLER_SERVICE],
            &[
                "dp.pt.short",
                "dp.xx.FAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfake000",
            ],
        );
    }

    #[test]
    fn digitalocean_token() {
        check(
            "digitalocean-token",
            &[DIGITALOCEAN],
            &[
                "dop_v1_short",
                "dop_v2_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            ],
        );
    }

    #[test]
    fn pypi_token() {
        check(
            "pypi-token",
            &[PYPI, TEST_PYPI],
            &["pypi-short", "pypi-AgEIcHlwaS5vcmcshort"],
        );
    }

    #[test]
    fn age_secret_key() {
        check(
            "age-secret-key",
            &[AGE],
            &[
                "AGE-SECRET-KEY-1SHORT",
                // 'B' is outside the Bech32 alphabet
                "AGE-SECRET-KEY-1BPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE",
            ],
        );
    }

    #[test]
    fn terraform_cloud_token() {
        check(
            "terraform-cloud-token",
            &[TERRAFORM],
            &[
                "abc.atlasv1.xyz",
                "FAKEfakeFAKE00.atlasv2.FAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfake",
            ],
        );
    }

    #[test]
    fn openai_project_key() {
        check(
            "openai-project-key",
            &[OPENAI_PROJECT, OPENAI_SVCACCT, OPENAI_ADMIN],
            &[
                "sk-proj-short",
                "sk-deploy-confd-example-0-0",
                "sk-pv-claim-sink-connector-light",
                "sk-output-waiting-1771554457934",
            ],
        );
    }

    #[test]
    fn gcs_hmac_access_id() {
        check(
            "gcs-hmac-access-id",
            &[GCS_HMAC_SA, GCS_HMAC_USER],
            &[
                concat!("GOOG", "FAKEFAKEFAKEFAKEFAKEFAKEFAKE"), // 32: neither length
                "GOOGLE_APPLICATION_CREDENTIALS",
            ],
        );
    }

    #[test]
    fn private_key_covers_whole_block() {
        let pat = built_in_patterns()
            .unwrap()
            .into_iter()
            .find(|p| p.name == "private-key")
            .unwrap();
        for block in [
            PEM_RSA.to_string(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaFAKE\n-----END OPENSSH PRIVATE KEY-----"
                .to_string(),
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQFAKE\n-----END PGP PRIVATE KEY BLOCK-----"
                .to_string(),
        ] {
            assert_eq!(pat.regex.find(&block).unwrap().as_str(), block);
        }
        assert!(!pat.regex.is_match("-----BEGIN PUBLIC KEY-----"));
        assert!(!pat.regex.is_match("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn url_userinfo() {
        check(
            "url-userinfo",
            &[
                "rediss://default:FAKEpass@cache:6380",
                "postgresql+psycopg2://app:FAKEpass@db/app",
                "https://u:FAKEpass@git.example.com/r.git",
            ],
            &[
                "https://example.com:8443/path",
                "ssh://git@github.com/org/repo",
                "git@github.com:org/repo.git",
            ],
        );
    }

    #[test]
    fn env_credential() {
        check(
            "env-credential",
            &[
                "export DB_PASSWORD=FAKEpass123",
                "PGPASSWORD=FAKEpass123",
                "REDIS_PASS=FAKEpass123",
                "API_KEY: FAKEpass123",
                "AWS_SECRET_ACCESS_KEY=FAKEpass123",
            ],
            &[
                "TOKEN_TYPE=bearer",
                "PASSWORD_MIN_LENGTH=12345678",
                "MAX_TOKENS=40964096",
                "export API_KEY=$API_KEY",
                "API_KEY=${API_KEY}",
                "--- PASS: TestFooBarBaz",
                "PWD=/home/someone",
                "password=lowercase_is_not_env_style",
            ],
        );
    }

    #[test]
    fn cli_credentials() {
        check(
            "mysql-cli-password",
            &[
                "mysql -u root -pFAKEpass app",
                "mysqldump --password=FAKE app",
            ],
            &[
                "mysql -u root -p app",
                "mysql -p$MYSQL_PWD",
                "mysql -P 3306 -h db",
            ],
        );
        check(
            "curl-user-password",
            &[
                "curl -u admin:FAKEpass https://x",
                "curl -s --user=a:FAKEpass x",
            ],
            &["curl -u admin https://x", "curl -u $U:$P https://x"],
        );
        check(
            "netrc-password",
            &[
                "machine example.com login me password FAKEpass",
                r"machine example.com\n  login me\n  password FAKEpass",
                "default login me password FAKEpass",
            ],
            &[
                "log in with your password",
                "login me password",
                "machine learning models log in with a password manager",
            ],
        );
    }

    #[test]
    fn k8s_secret_data() {
        check(
            "k8s-secret-data",
            &["data:\n  password: RkFLRQ==\n  user: RkFLRQ==\n"],
            &["data: {}\n", "metadata:\n  name: x\n"],
        );
    }

    #[test]
    fn new_patterns_do_not_overlap_existing() {
        let patterns = built_in_patterns().unwrap();
        let cases = [
            ("grafana-service-account-token", GRAFANA_SA),
            ("grafana-cloud-token", GRAFANA_CLOUD),
            ("grafana-api-key", GRAFANA_LEGACY),
            ("slack-app-token", SLACK_APP),
            ("vault-token", VAULT_SERVICE),
            ("vault-token", VAULT_BATCH),
            ("doppler-token", DOPPLER_PERSONAL),
            ("doppler-token", DOPPLER_SERVICE),
            ("digitalocean-token", DIGITALOCEAN),
            ("pypi-token", PYPI),
            ("pypi-token", TEST_PYPI),
            ("age-secret-key", AGE),
            ("terraform-cloud-token", TERRAFORM),
            ("openai-project-key", OPENAI_PROJECT),
            ("openai-project-key", OPENAI_SVCACCT),
            ("openai-project-key", OPENAI_ADMIN),
            ("slack-token", SLACK_CONFIG),
            ("slack-token", SLACK_APP_CONFIG),
            ("slack-token", SLACK_ORG),
            ("gcs-hmac-access-id", GCS_HMAC_SA),
            ("gcs-hmac-access-id", GCS_HMAC_USER),
            ("docker-config-b64", DOCKER_B64),
            ("private-key", PEM_RSA),
        ];
        for (expected, vector) in cases {
            let own = patterns.iter().find(|p| p.name == expected).unwrap();
            assert!(
                own.keyword_hit(&vector.to_lowercase()),
                "{expected} keywords miss {vector}"
            );
            let hits: Vec<_> = patterns
                .iter()
                .filter(|p| p.regex.is_match(vector))
                .map(|p| p.name.as_str())
                .collect();
            assert_eq!(hits, [expected], "unexpected matches for {vector}");
        }
    }

    #[test]
    fn prose_mentioning_new_token_types_is_not_matched() {
        let patterns = built_in_patterns().unwrap();
        let prose = "Rotate the Grafana service account token (glsa_ prefix) and the glc_ \
                     cloud token. Vault hvs. and hvb. tokens expire; Doppler dp.pt tokens \
                     and DigitalOcean dop_v1_ tokens should be revoked. Upload with a pypi- \
                     token, decrypt with an AGE-SECRET-KEY-1 identity, and log in to \
                     app.terraform.io for an atlasv1 token. Slack xapp-1 tokens enable \
                     Socket Mode. OpenAI sk-proj- and sk-svcacct- keys, Slack xoxe- \
                     and xoxa- tokens, GOOG1 HMAC access IDs and aws_session_token values \
                     must be rotated. Store the password in ~/.netrc or .pypirc, run \
                     mysql -p and type it at the prompt, or pass curl -u user to be \
                     prompted. The Authorization header takes Basic or Bearer credentials; \
                     a kubeconfig holds a token and client-key-data, a kind: Secret keeps \
                     base64 data, and docker login writes an auth entry. Connection URLs \
                     like rediss:// and postgresql+psycopg2:// carry a user and password. \
                     Set TOKEN_TYPE=bearer, PASSWORD_MIN_LENGTH=12 and MAX_TOKENS=4096, then \
                     export API_KEY=$API_KEY. The password reset link expires; log in with \
                     your password manager.";
        for p in &patterns {
            assert!(!p.regex.is_match(prose), "{} matched prose", p.name);
        }
    }

    #[test]
    fn built_in_fingerprint_is_stable() {
        let fp = built_in_fingerprint();
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, built_in_fingerprint());
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
