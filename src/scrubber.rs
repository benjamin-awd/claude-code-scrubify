use std::borrow::Cow;
use std::fmt::Write as _;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::allowlist::{Allowlist, Blacklist};
use crate::entropy::{EntropyConfig, find_high_entropy_tokens};
use crate::patterns::{LOOSE_VALUE_PATTERNS, PatternSet, SHORT_VALUE_PATTERNS};

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

/// Minimum value length for patterns with strong credential context
/// (`patterns::SHORT_VALUE_PATTERNS`), e.g. `mysql -proot`.
const SHORT_SECRET_MIN_LEN: usize = 4;

/// Field names whose string values should always be redacted. Keys are
/// normalised to `snake_case` first (`dbPassword` → `db_password`,
/// `x-api-key` → `x_api_key`); a key matches when it equals an entry or ends
/// with `_<entry>`. So `token_count`, `max_tokens` and `auth_method` do not.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pass",
    "passphrase",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "api_secret",
    "access_token",
    "auth_token",
    "session_token",
    "refresh_token",
    "token",
    "auth",
    "private_key",
    "private_key_id",
    "secret_key",
    "credentials",
    "authorization",
    "cookie",
];

/// Obvious placeholder values for key/value patterns (compared lowercase).
const PLACEHOLDERS: &[&str] = &[
    "changeme",
    "change_me",
    "change-me",
    "changeit",
    "placeholder",
    "password",
    "passw0rd",
    "pass",
    "secret",
    "token",
    "example",
    "dummy",
    "redacted",
    "undefined",
    "null",
    "none",
    "true",
    "false",
];

static REDACTED_PLACEHOLDER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\[REDACTED:[^\]]+\]$").unwrap());

/// Placeholder shapes: `xxx…`, `***`, `<…>`, `{{…}}`, `${…}`, `your_…`, `...`.
static PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:x{3,}.*|\*{3,}|<.*>|\{\{.*\}\}|\$\{.*\}|your[_-].*|\.{3,}|%s)$").unwrap()
});

/// `settings.SECRET_KEY`, `process.env.TOKEN`, `request.form.password`.
static DOTTED_IDENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$").unwrap());

/// `userPassword`, `api_key_from_config`, `ObjectIdentifier`: multi-word
/// identifiers without digits.
static MULTIWORD_IDENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[a-z]+(?:_[a-z]+)+|[A-Z]+(?:_[A-Z]+)+|[a-z]+(?:[A-Z][a-z]+)+|(?:[A-Z][a-z]+){2,})$",
    )
    .unwrap()
});

static PERCENT_ESCAPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"%[0-9A-Fa-f]{2}").unwrap());

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    PLACEHOLDERS.contains(&lower.as_str()) || PLACEHOLDER_RE.is_match(value)
}

/// For loosely-anchored patterns: is the captured "value" really code or a
/// file reference rather than a literal secret?
fn looks_like_code_or_path(value: &str) -> bool {
    let dotted_code = DOTTED_IDENT_RE.is_match(value)
        && value.split('.').all(|seg| {
            let up = seg.bytes().any(|b| b.is_ascii_uppercase());
            let lo = seg.bytes().any(|b| b.is_ascii_lowercase());
            let dg = seg.bytes().any(|b| b.is_ascii_digit());
            !(up && lo && dg)
        });
    let path = ["/", "./", "../", "~/", "http://", "https://"]
        .iter()
        .any(|p| value.starts_with(p))
        && !value.contains(['+', '=']);
    dotted_code || path || value.contains("::") || MULTIWORD_IDENT_RE.is_match(value)
}

#[derive(Debug, Clone)]
pub struct Redaction {
    pub pattern_name: String,
    pub start: usize,
    pub end: usize,
    pub matched_text: String,
}

/// Should a pattern hit with this secret text be kept?
fn keep_pattern_hit(pattern_name: &str, secret: &str, has_group: bool) -> bool {
    let min_len = if SHORT_VALUE_PATTERNS.contains(&pattern_name) {
        SHORT_SECRET_MIN_LEN
    } else {
        MIN_SECRET_LEN
    };
    if secret.len() < min_len {
        return false;
    }
    // Documentation examples, matched exactly: a real secret that merely sits
    // next to (or contains) an example value is still redacted.
    if KNOWN_EXAMPLES.contains(&secret) {
        return false;
    }
    // Skip values that are exactly an earlier redaction, to stay idempotent
    // when a secret_group pattern preserves surrounding context.
    // `[REDACTED:x]<secret>` is not skipped.
    if REDACTED_PLACEHOLDER_RE.is_match(secret) {
        return false;
    }
    if has_group && is_placeholder(secret) {
        return false;
    }
    !(LOOSE_VALUE_PATTERNS.contains(&pattern_name) && looks_like_code_or_path(secret))
}

/// Regex and entropy spans for one text (no blacklist).
fn collect_pattern_and_entropy_spans(
    text: &str,
    matching_indices: Vec<usize>,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    allowlist: &Allowlist,
) -> Vec<Redaction> {
    let mut spans: Vec<Redaction> = Vec::new();

    // Keyword pre-filter, then exact spans. Lowercasing is only needed for
    // the keyword check, so skip it when nothing matched.
    let text_lower = if matching_indices.is_empty() {
        String::new()
    } else {
        text.to_lowercase()
    };
    for idx in matching_indices {
        let pat = &pattern_set.patterns[idx];
        if !pat.keyword_hit(&text_lower) {
            continue;
        }
        for caps in pat.regex.captures_iter(text) {
            let full = caps.get(0).unwrap();
            // If secret_group is set, redact only that capture group
            let group = pat.secret_group.and_then(|g| caps.get(g));
            let (start, end) = group.map_or((full.start(), full.end()), |g| (g.start(), g.end()));
            let secret = &text[start..end];
            if !keep_pattern_hit(&pat.name, secret, group.is_some()) || allowlist.is_allowed(secret)
            {
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

    for em in find_high_entropy_tokens(text, entropy_cfg) {
        // Don't flag tokens already covered by regex matches
        let already_covered = spans.iter().any(|s| s.start <= em.start && s.end >= em.end);
        let token = &text[em.start..em.end];
        if !already_covered && !KNOWN_EXAMPLES.contains(&token) && !allowlist.is_allowed(token) {
            spans.push(Redaction {
                pattern_name: "high-entropy".to_string(),
                start: em.start,
                end: em.end,
                matched_text: String::new(),
            });
        }
    }

    spans
}

/// Decode `%XX` escapes that map to printable ASCII (other bytes are left
/// encoded so the result stays valid UTF-8). Returns the decoded text and,
/// for every decoded byte offset (plus one past the end), the matching
/// offset in the original. `None` if nothing was decoded.
fn percent_decode_ascii(text: &str) -> Option<(String, Vec<usize>)> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len() + 1);
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
            && (0x21..0x7f).contains(&(hi << 4 | lo))
        {
            out.push(hi << 4 | lo);
            offsets.push(i);
            i += 3;
            changed = true;
        } else {
            out.push(bytes[i]);
            offsets.push(i);
            i += 1;
        }
    }
    offsets.push(bytes.len());
    if !changed {
        return None;
    }
    String::from_utf8(out).ok().map(|s| (s, offsets))
}

fn hex_val(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// Redact secrets in `text`. Returns the input borrowed when nothing was
/// redacted, so clean strings (the vast majority) are never copied.
pub fn scrub_text<'a>(
    text: &'a str,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    allowlist: &Allowlist,
    blacklist: &Blacklist,
) -> (Cow<'a, str>, Vec<Redaction>) {
    // One RegexSet pass tells us which patterns matched; a separate is_match()
    // for the bail-out would scan the text twice.
    let matching_indices: Vec<_> = pattern_set.quick_check.matches(text).into_iter().collect();
    let has_percent = PERCENT_ESCAPE_RE.is_match(text);

    // Fast bail-out: if no regex matches at all, entropy is disabled, no
    // blacklist entries match and nothing is percent-encoded, return early
    if matching_indices.is_empty()
        && !entropy_cfg.enabled
        && !blacklist.contains_any(text)
        && !has_percent
    {
        return (Cow::Borrowed(text), Vec::new());
    }

    let mut spans = collect_pattern_and_entropy_spans(
        text,
        matching_indices,
        pattern_set,
        entropy_cfg,
        allowlist,
    );

    // Second pass over the percent-decoded text so `%2F`-style escapes can't
    // split a secret; spans are mapped back onto the original text.
    if has_percent && let Some((decoded, offsets)) = percent_decode_ascii(text) {
        let decoded_matches = pattern_set
            .quick_check
            .matches(&decoded)
            .into_iter()
            .collect();
        for mut span in collect_pattern_and_entropy_spans(
            &decoded,
            decoded_matches,
            pattern_set,
            entropy_cfg,
            allowlist,
        ) {
            span.start = offsets[span.start];
            span.end = offsets[span.end];
            if !spans
                .iter()
                .any(|s| s.start <= span.start && s.end >= span.end)
            {
                spans.push(span);
            }
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
        if REDACTED_PLACEHOLDER_RE.is_match(&text[bl_start..bl_end]) {
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
        return (Cow::Borrowed(text), Vec::new());
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

    (Cow::Owned(result), redactions)
}

/// `dbPassword` / `X-Api-Key` / `client.secret` → `db_password` /
/// `x_api_key` / `client_secret`.
fn normalize_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    let mut prev_lower_or_digit = false;
    for c in key.chars() {
        if c.is_ascii_uppercase() {
            if prev_lower_or_digit {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
            prev_lower_or_digit = false;
        } else if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_lower_or_digit = true;
        } else {
            if !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
            prev_lower_or_digit = false;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

fn is_sensitive_key(key: &str) -> bool {
    let norm = normalize_key(key);
    SENSITIVE_KEYS.iter().any(|&k| {
        norm == k
            || (norm.len() > k.len()
                && norm.ends_with(k)
                && norm.as_bytes()[norm.len() - k.len() - 1] == b'_')
    })
}

/// Opaque fields that must survive byte-for-byte (resume verifies them, and
/// base64 image data would be corrupted by entropy hits).
fn is_opaque_field(obj_type: Option<&str>, key: &str) -> bool {
    key == "signature"
        || (obj_type == Some("redacted_thinking") && key == "data")
        || (obj_type == Some("image") && matches!(key, "source" | "file" | "data"))
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
                if al.is_allowed(s) || REDACTED_PLACEHOLDER_RE.is_match(s) {
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
            if let Cow::Owned(scrubbed) = scrubbed {
                *s = scrubbed;
            }
            redactions
        }
        Value::Array(arr) => arr
            .iter_mut()
            .flat_map(|v| scrub_all_strings_inner(v, ps, ec, al, bl, force_redact))
            .collect(),
        Value::Object(map) => {
            let obj_type = map.get("type").and_then(Value::as_str).map(str::to_owned);
            let mut redactions = Vec::new();
            for (key, val) in map.iter_mut() {
                if is_opaque_field(obj_type.as_deref(), key) {
                    continue;
                }
                // A sensitive key forces redaction of everything beneath it:
                // {"credentials": {"pass": "…"}} and {"auth": ["…"]}.
                let sensitive = force_redact || is_sensitive_key(key);
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

    fn test_pattern_set() -> &'static PatternSet {
        static PS: std::sync::LazyLock<PatternSet> =
            std::sync::LazyLock::new(|| PatternSet::load(true).unwrap());
        &PS
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
            ps,
            &no_entropy(),
            &no_allowlist(),
            &no_blacklist(),
        );
        assert_eq!(result, "hello world");
        assert!(redactions.is_empty());
    }

    #[test]
    fn redacts_grafana_token_with_entropy_enabled() {
        let ps = test_pattern_set();
        let input = "export GRAFANA_TOKEN=glsa_FAKEfakeFAKEfakeFAKEfakeFAKEfake_0123abcd";
        let (result, redactions) = scrub_text(
            input,
            ps,
            &EntropyConfig::default(),
            &no_allowlist(),
            &no_blacklist(),
        );
        assert_eq!(
            result,
            "export GRAFANA_TOKEN=[REDACTED:grafana-service-account-token]"
        );
        assert_eq!(redactions.len(), 1);
    }

    #[test]
    fn redacts_whole_gcp_service_account_key() {
        let ps = test_pattern_set();
        let input = r#"{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\nFAKEfakeFAKEfake\n-----END PRIVATE KEY-----\n", "client_email": "fake@fake-project.iam.gserviceaccount.com"}"#;
        let (result, redactions) =
            scrub_text(input, ps, &no_entropy(), &no_allowlist(), &no_blacklist());
        assert_eq!(
            result,
            r#"{"type": "service_account", "private_key": "[REDACTED:gcp-service-account-key]\n", "client_email": "fake@fake-project.iam.gserviceaccount.com"}"#
        );
        assert_eq!(redactions.len(), 1);
    }

    #[test]
    fn redacts_github_token() {
        let ps = test_pattern_set();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let (result, redactions) =
            scrub_text(input, ps, &no_entropy(), &no_allowlist(), &no_blacklist());
        assert!(result.contains("[REDACTED:github-token]"));
        assert!(!result.contains("ghp_"));
        assert_eq!(redactions.len(), 1);
    }

    #[test]
    fn redacts_multiple_secrets() {
        let ps = test_pattern_set();
        let input = "key1: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl and key2: sk-ant-abcdefghijklmnopqrstuvwxyz";
        let (result, redactions) =
            scrub_text(input, ps, &no_entropy(), &no_allowlist(), &no_blacklist());
        assert!(result.contains("[REDACTED:github-token]"));
        assert!(result.contains("[REDACTED:anthropic-key]"));
        assert_eq!(redactions.len(), 2);
    }

    #[test]
    fn idempotent() {
        let ps = test_pattern_set();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let (first_pass, _) =
            scrub_text(input, ps, &no_entropy(), &no_allowlist(), &no_blacklist());
        let (second_pass, redactions) = scrub_text(
            &first_pass,
            ps,
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
            scrub_text(input, ps, &no_entropy(), &no_allowlist(), &no_blacklist());
        assert_eq!(r1.len(), 1);
        // Second pass on already-redacted text should find nothing
        let (second_pass, r2) = scrub_text(
            &first_pass,
            ps,
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
            ps,
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
            scrub_text(input, ps, &no_entropy(), &no_allowlist(), &no_blacklist());
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
        let (result, redactions) = scrub_text(&input, ps, &no_entropy(), &al, &no_blacklist());
        assert!(result.contains(token), "allowlisted value should remain");
        assert!(redactions.is_empty());
    }

    #[test]
    fn entropy_detection() {
        let ps = test_pattern_set();
        let cfg = EntropyConfig::default();
        let input = "secret=aB3kL9mN2pQ5rT8vX1yZ4cF7gH0jK6wE";
        let (result, redactions) = scrub_text(input, ps, &cfg, &no_allowlist(), &no_blacklist());
        // Should detect via entropy or regex
        assert!(!redactions.is_empty() || result != input);
    }

    // --- Blacklist tests ---

    #[test]
    fn blacklist_redacts_exact_string() {
        let ps = test_pattern_set();
        let bl = Blacklist::from_strings(vec!["foobar123"]);
        let input = "some text with foobar123 in it";
        let (result, redactions) = scrub_text(input, ps, &no_entropy(), &no_allowlist(), &bl);
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
        let (result, redactions) = scrub_text(input, ps, &no_entropy(), &no_allowlist(), &bl);
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
        let (result, redactions) = scrub_text(input, ps, &no_entropy(), &no_allowlist(), &bl);
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
        let (result, redactions) = scrub_text(input, ps, &no_entropy(), &al, &bl);
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
        let (result, redactions) = scrub_text(&input, ps, &no_entropy(), &no_allowlist(), &bl);
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
        let (first_pass, _) = scrub_text(input, ps, &no_entropy(), &no_allowlist(), &bl);
        let (second_pass, redactions) =
            scrub_text(&first_pass, ps, &no_entropy(), &no_allowlist(), &bl);
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
        let redactions = scrub_all_strings(&mut value, ps, &no_entropy(), &no_allowlist(), &bl);
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
        let (result, redactions) = scrub_text(&input, ps, &no_entropy(), &no_allowlist(), &bl);
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
        let redactions = scrub_all_strings(&mut value, ps, &no_entropy(), &al, &bl);
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
        scrub_all_strings(&mut value, ps, &no_entropy(), &no_allowlist(), &bl);
        assert_eq!(value["key"], "[REDACTED:blacklist]");
        // Second pass should not re-redact
        let redactions = scrub_all_strings(&mut value, ps, &no_entropy(), &no_allowlist(), &bl);
        assert!(redactions.is_empty());
        assert_eq!(value["key"], "[REDACTED:blacklist]");
    }

    // --- Detection-bypass regression tests ---
    //
    // All values are synthetic ("FAKE"/"fake" filler or arbitrary strings).

    /// 12-char mixed password used across the bypass tests.
    const PW: &str = "Fk9qZ2xLm4Np";

    fn scrub(input: &str) -> String {
        scrub_text(
            input,
            test_pattern_set(),
            &no_entropy(),
            &no_allowlist(),
            &no_blacklist(),
        )
        .0
        .into_owned()
    }

    fn scrub_entropy(input: &str) -> String {
        scrub_text(
            input,
            test_pattern_set(),
            &EntropyConfig::default(),
            &no_allowlist(),
            &no_blacklist(),
        )
        .0
        .into_owned()
    }

    fn assert_redacted(input: &str, secret: &str) {
        let out = scrub(input);
        assert!(!out.contains(secret), "{secret} survived in: {out}");
        assert!(out.contains("[REDACTED:"), "nothing redacted: {out}");
        // Idempotent: a second pass changes nothing.
        assert_eq!(scrub(&out), out, "second pass changed output");
    }

    fn assert_untouched(input: &str) {
        let out = scrub_entropy(input);
        assert_eq!(out, input, "false positive");
    }

    #[test]
    fn json_key_value_text_is_redacted() {
        let aws = "FAKEfakeFAKEfake/FAKEfakeFAKEfake+FAKE01";
        for (input, secret) in [
            (format!(r#"{{"password": "{PW}"}}"#), PW),
            (format!(r#"{{"db_password":"{PW}"}}"#), PW),
            (format!(r#"{{\"password\":\"{PW}\"}}"#), PW),
            (format!("password = `{PW}`"), PW),
            (
                r#"{"api_key": "FAKEfakeFAKEfake0123456789"}"#.to_string(),
                "FAKEfakeFAKEfake0123456789",
            ),
            (
                r#"{\"apiKey\":\"FAKEfakeFAKEfake0123456789\"}"#.to_string(),
                "FAKEfakeFAKEfake0123456789",
            ),
            (format!(r#"{{"aws_secret_access_key": "{aws}"}}"#), aws),
            (format!(r#"\"aws_secret_access_key\":\"{aws}\""#), aws),
        ] {
            assert_redacted(&input, secret);
        }
        // Only the value is redacted; the key survives.
        assert_eq!(
            scrub(&format!(r#"{{"password": "{PW}"}}"#)),
            r#"{"password": "[REDACTED:password-assignment]"}"#
        );
    }

    #[test]
    fn unquoted_and_cli_credentials_are_redacted() {
        for input in [
            format!("export DB_PASSWORD={PW}"),
            format!("PGPASSWORD={PW} psql -h db.internal -U app"),
            format!("REDIS_PASS={PW}"),
            format!("STRIPE_SECRET_KEY={PW}"),
            format!("database:\n  host: db\n  password: {PW}\n"),
            format!("machine api.example.com login deploy password {PW}"),
            format!("machine api.example.com\n  login deploy\n  password {PW}\n"),
            format!("[pypi]\nusername = __token__\npassword = {PW}\n"),
            format!("mysql -h db -u root -p{PW} app"),
            format!("mysqldump --password={PW} app > dump.sql"),
            format!("curl -u admin:{PW} https://api.example.com/v1"),
            format!("curl --user admin:{PW} https://api.example.com/v1"),
        ] {
            assert_redacted(&input, PW);
        }
        let punct = "Fk!9#qZ@2x%Lm*Tr";
        assert_redacted(&format!("DB_PASSWORD='{punct}'"), punct);
        assert_redacted(&format!("export ADMIN_PASSWORD={punct}"), punct);
        assert_redacted(&format!("password: {punct}"), punct);
        assert_eq!(
            scrub(&format!("export DB_PASSWORD={PW}")),
            "export DB_PASSWORD=[REDACTED:env-credential]"
        );
    }

    #[test]
    fn code_identifiers_and_placeholders_are_not_credentials() {
        for input in [
            "TOKEN_TYPE=bearer",
            "PASSWORD_MIN_LENGTH=8",
            "MAX_TOKENS=4096",
            "export API_KEY=$API_KEY",
            "API_KEY=${API_KEY}",
            "SECRET_KEY = settings.SECRET_KEY",
            "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
            r#"API_KEY = os.environ["API_KEY"]"#,
            "const token = process.env.API_TOKEN",
            "TOKEN = get_token_from_vault()",
            "pub const USER_PASSWORD: crate::ObjectIdentifier = oid();",
            "SESSION_TOKEN: SessionTokenProvider",
            "password: changeme",
            "password: <your-password>",
            "API_KEY=xxxxxxxxxxxxxxxx",
            "AUTH_TOKEN=your_token_here",
            "password = request.form.password",
            "    self.token = token_value",
            "    password: str",
            "token: Optional[str] = None",
            "SECRET_FILE=/run/secrets/db_password",
            "mysql -u root -p app",
            "curl -u $USER:$TOKEN https://api.example.com",
            "curl -u deploy https://api.example.com",
            "--- PASS: TestScrubText (0.00s)",
            "PWD=/home/someone/project",
            "echo $DB_PASSWORD | wc -c",
            "The password reset link expires in 24 hours.",
            "Log in with your password, then open the Secrets page.",
            "machine learning models log in with a password manager",
        ] {
            assert_untouched(input);
        }
    }

    #[test]
    fn url_userinfo_is_redacted() {
        for input in [
            format!("rediss://default:{PW}@cache.example.com:6380/0"),
            format!("postgresql+psycopg2://app:{PW}@db.internal/app"),
            format!("https://deploy:{PW}@git.example.com/org/repo.git"),
            format!("amqps://guest:{PW}@mq.example.com"),
            format!("clickhouse://default:{PW}@ch.internal:9000"),
        ] {
            assert_redacted(&input, PW);
        }
        // Only the password is redacted for schemes connection-string doesn't know.
        assert_eq!(
            scrub(&format!("rediss://default:{PW}@cache.example.com")),
            "rediss://default:[REDACTED:url-userinfo]@cache.example.com"
        );
        for input in [
            "https://example.com:8443/path?q=1",
            "git@github.com:org/repo.git",
            "ssh://git@github.com/org/repo",
            "see https://docs.example.com/a:b@c for details",
            "https://user:password@example.com",
        ] {
            assert_untouched(input);
        }
    }

    #[test]
    fn auth_headers_are_redacted() {
        let basic = "ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk";
        assert_redacted(&format!("Authorization: Basic {basic}"), basic);
        assert_redacted(&format!(r#"{{"Authorization": "Basic {basic}"}}"#), basic);
        let bearer = "FAKEfakeFAKEfake0123456789";
        assert_redacted(&format!("-H 'Authorization: Bearer {bearer}'"), bearer);
        assert_eq!(
            scrub(&format!("Authorization: Bearer {bearer}")),
            "Authorization: Bearer [REDACTED:bearer-token]"
        );
        assert_untouched("Use bearer authentication for the API.");
        assert_untouched("Authorization: Bearer ${TOKEN}");
        assert_untouched("Authorization: Basic auth is disabled");
    }

    #[test]
    fn kubernetes_secrets_and_docker_auth_are_redacted() {
        let yaml = "apiVersion: v1\ndata:\n  password: RmFrZVBhc3N3b3JkMTIz\n  username: YWRtaW4=\nkind: Secret\nmetadata:\n  name: db\n";
        let out = scrub(yaml);
        assert!(
            !out.contains("RmFrZVBhc3N3b3JkMTIz") && !out.contains("YWRtaW4="),
            "{out}"
        );
        assert!(out.contains("kind: Secret\nmetadata:\n  name: db"), "{out}");
        assert_eq!(scrub(&out), out);

        let json = r#"{"apiVersion":"v1","data":{"token":"RmFrZVRva2VuMTIz","ca.crt":"RmFrZUNB"},"kind":"Secret"}"#;
        let out = scrub(json);
        assert!(
            !out.contains("RmFrZVRva2VuMTIz") && !out.contains("RmFrZUNB"),
            "{out}"
        );

        // A ConfigMap's data block is left alone.
        let cm =
            "apiVersion: v1\ndata:\n  app.mode: production\n  log.level: debug\nkind: ConfigMap\n";
        assert_untouched(cm);

        let docker =
            r#"{"auths":{"registry.example.com":{"auth":"ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk"}}}"#;
        assert_redacted(docker, "ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk");
        let escaped =
            r#"{\"auths\":{\"r.example.com\":{\"auth\":\"ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk\"}}}"#;
        assert_redacted(escaped, "ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk");
        assert_untouched(r#"{"auth": "oauth2", "authType": "service_account"}"#);
    }

    #[test]
    fn kubeconfig_and_session_tokens_are_redacted() {
        let kubeconfig = "users:\n- name: admin\n  user:\n    token: FAKEfakeFAKEfake0123456789\n    client-key-data: LS0tLS1GQUtFZmFrZUZBS0VmYWtlRkFLRQ==\n";
        let out = scrub(kubeconfig);
        assert!(!out.contains("FAKEfakeFAKEfake0123456789"), "{out}");
        assert!(
            !out.contains("LS0tLS1GQUtFZmFrZUZBS0VmYWtlRkFLRQ=="),
            "{out}"
        );

        let session = "FAKEfakeFAKEfake".repeat(8);
        assert_redacted(&format!("aws_session_token = {session}"), &session);
        assert_redacted(&format!(r#""aws_session_token": "{session}""#), &session);
    }

    #[test]
    fn pem_private_key_body_is_redacted() {
        let body = "MIIEFAKEfakeFAKEfakeFAKEfakeFAKEfake0123456789";
        for kind in [
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK",
        ] {
            let real = format!("-----BEGIN {kind}-----\n{body}\n{body}\n-----END {kind}-----\n");
            assert_eq!(scrub(&real), "[REDACTED:private-key]\n", "{kind}");
            let literal = format!(r"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----\n");
            assert_eq!(scrub(&literal), r"[REDACTED:private-key]\n", "{kind}");
        }
        // Truncated output (no END line): header and body lines still go.
        let truncated = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n{body}\n...");
        assert_redacted(&truncated, body);
        assert_untouched(&format!(
            "-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----"
        ));
        assert_untouched(&format!(
            "-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----"
        ));
    }

    #[test]
    fn provider_tokens_are_redacted() {
        let openai = concat!("sk-proj-", "FAKEfakeFAKEfake_FAKE-fakeFAKEfake");
        let svc = concat!("sk-svcacct-", "FAKEfakeFAKEfakeFAKEfake");
        let slack = concat!("xoxe-", "1-FAKEfakeFAKEfake0123");
        let hmac_sa = concat!(
            "GOOG1",
            "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
        );
        let hmac_user = concat!("GOOG", "FAKEFAKEFAKEFAKE0123");
        for (secret, name) in [
            (openai, "openai-project-key"),
            (svc, "openai-project-key"),
            (slack, "slack-token"),
            (hmac_sa, "gcs-hmac-access-id"),
            (hmac_user, "gcs-hmac-access-id"),
        ] {
            assert_eq!(
                scrub(&format!("key {secret} end")),
                format!("key [REDACTED:{name}] end")
            );
        }
    }

    #[test]
    fn known_example_only_skips_exact_match() {
        let (ex_key, ex_secret) = (KNOWN_EXAMPLES[0], KNOWN_EXAMPLES[1]);
        // The documented example on its own is not redacted...
        assert_untouched(&format!("aws_secret_access_key = {ex_secret}"));
        assert_untouched(&format!("AWS_ACCESS_KEY_ID={ex_key}"));
        // ...but it no longer shields a real secret in the same match.
        assert_redacted(&format!("postgres://{ex_key}:{PW}@db.internal/app"), PW);
        assert_redacted(&format!(r#"password = "{ex_key}{PW}""#), PW);
    }

    #[test]
    fn redacted_prefix_does_not_shield_a_secret() {
        let input = format!(r#"password = "[REDACTED:x]{PW}""#);
        assert_redacted(&input, PW);
        assert_eq!(
            scrub(&input),
            r#"password = "[REDACTED:password-assignment]""#
        );
    }

    #[test]
    fn percent_encoded_secrets_are_redacted() {
        // `%2F` / `%2B` split the value for both regex and entropy detection.
        let enc = "FAKEfakeFAKEfake%2FFAKEfakeFAKEfake%2BFAKE01";
        let out = scrub(&format!("aws_secret_access_key={enc}"));
        assert_eq!(out, "aws_secret_access_key=[REDACTED:aws-secret-key]");

        let out =
            scrub_entropy("https://api.example.com/x?sig=Xq7Rk2mPz9%2BLwB4vN8cTdHg5tY8nQ2wE&v=2");
        assert!(!out.contains("LwB4vN8cTd"), "{out}");
        assert!(out.ends_with("&v=2"), "{out}");

        // Ordinary encoded URLs are untouched.
        assert_untouched("https://example.com/search?q=hello%20world%2C%20again&lang=en");
    }

    #[test]
    fn percent_decode_maps_offsets() {
        let (decoded, offsets) = percent_decode_ascii("a%2Fb%20c%zz").unwrap();
        assert_eq!(decoded, "a/b%20c%zz"); // %20 (space) and %zz stay encoded
        assert_eq!(offsets[1], 1);
        assert_eq!(offsets[2], 4);
        assert_eq!(offsets[decoded.len()], 12);
        assert!(percent_decode_ascii("no escapes").is_none());
    }

    #[test]
    fn sensitive_keys_are_normalised() {
        for key in [
            "password",
            "dbPassword",
            "DB_PASSWORD",
            "clientSecret",
            "client-secret",
            "x-api-key",
            "X-Api-Key",
            "apiKey",
            "sshPass",
            "passphrase",
            "auth",
            "basicAuth",
            "private_key_id",
            "sessionToken",
            "refresh_token",
            "Cookie",
            "set-cookie",
        ] {
            assert!(is_sensitive_key(key), "{key} should be sensitive");
        }
        for key in [
            "token_count",
            "max_tokens",
            "maxTokens",
            "input_tokens",
            "auth_method",
            "authMethod",
            "oauth",
            "bypass",
            "compass",
            "password_min_length",
            "secret_name",
            "author",
        ] {
            assert!(!is_sensitive_key(key), "{key} should not be sensitive");
        }
    }

    #[test]
    fn forced_redaction_propagates_into_nested_values() {
        let ps = test_pattern_set();
        let mut value = serde_json::json!({
            "credentials": {"pass": "plainvalue1", "user": {"name": "someone_long"}},
            "auth": ["first-value", {"k": "second-value"}],
            "dbPassword": "plainvalue2",
            "token_count": "1234567890",
            "max_tokens": "4096000000",
            "auth_method": "oauth_device_flow",
        });
        let redactions = scrub_all_strings(
            &mut value,
            ps,
            &no_entropy(),
            &no_allowlist(),
            &no_blacklist(),
        );
        assert_eq!(redactions.len(), 5, "{value}");
        assert_eq!(value["credentials"]["pass"], "[REDACTED:sensitive-field]");
        assert_eq!(
            value["credentials"]["user"]["name"],
            "[REDACTED:sensitive-field]"
        );
        assert_eq!(value["auth"][0], "[REDACTED:sensitive-field]");
        assert_eq!(value["auth"][1]["k"], "[REDACTED:sensitive-field]");
        assert_eq!(value["dbPassword"], "[REDACTED:sensitive-field]");
        assert_eq!(value["token_count"], "1234567890");
        assert_eq!(value["max_tokens"], "4096000000");
        assert_eq!(value["auth_method"], "oauth_device_flow");
        // Second pass is a no-op.
        let again = scrub_all_strings(
            &mut value,
            ps,
            &no_entropy(),
            &no_allowlist(),
            &no_blacklist(),
        );
        assert!(again.is_empty());
    }

    #[test]
    fn normal_transcript_corpus_has_no_false_positives() {
        let corpus = r#"
I'll fix the failing test in src/scrubber.rs. Let me read the file first.

$ git log --oneline -3
7c48519 fix: invalidate scan cache and hook offsets when binary or built-in patterns change
0a185b9 feat: add Grafana, Vault, Terraform Cloud, GCP SA key and other secret patterns
commit 9fceb02d0ae598e95dc970b74767f19372d61af8
Merge: 1a2b3c4 5d6e7f8
Author: Someone <someone@example.com>

$ cargo test --locked
   Compiling scrub-history v0.4.0 (/Users/someone/playground/claude-code-scrubify)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 15.77s
     Running unittests src/lib.rs (target/debug/deps/scrub_history-726fcffa2cba9d94)
test scrubber::tests::redacts_sensitive_field_by_key_name ... ok
test result: ok. 150 passed; 0 failed; 0 ignored

fn scrub_all_strings_inner(value: &mut Value, force_redact: bool) -> Vec<Redaction> {
    let token_count = tokens.len();
    let max_tokens = config.max_tokens.unwrap_or(4096);
    let password_hash = hash_password(&password, &salt)?;
    let auth_method = AuthMethod::from_str("oauth")?;
}

def get_token(self):
    self.token = token_value
    return self.access_token

const apiKey = process.env.OPENAI_API_KEY;
export const PASSWORD_MIN_LENGTH = 12;
TOKEN_TYPE=bearer
export API_KEY=$API_KEY
DATABASE_URL=${DATABASE_URL}

The tool_use id was toolu_01WcKqikcTdC72gZJhSFfmYf and the message msg_01XFDUDYJgAACzvnptvVoYEL.
Session 550e8400-e29b-41d4-a716-446655440000 started at 2026-01-01T12:00:00Z.
"integrity": "sha512-Tq3Vwq8xJmS4YkNLfUyuB1YJmKBnDqWb2Ih3ZvbZ9sLx0oYfXk3JrNwQhZgSRyNHJjL0d4oRxHbFRr8ZqZsLtw==",
Digest: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
md5sum: d41d8cd98f00b204e9800998ecf8427e  README.md

<div className="flex items-center justify-between rounded-lg bg-gray-100 px-4 py-2">
.btn-primary-outline-hover, .MuiButtonBase-root-MuiIconButton-root { color: red; }
import { useQueryClient, QueryClientProvider } from "@tanstack/react-query";
node_modules/@babel/plugin-transform-runtime/lib/index.js
/home/runner/work/MyRepo2/MyRepo2/target/release/deps/libserde_json-8a1b2c3d4e5f6a7b.rlib
~/.claude/projects/-Users-someone-playground-claude-code-scrubify/5f0c7b1e-8a3d-4e2f-9b6a-1c2d3e4f5a6b.jsonl

Visit https://docs.rs/regex/latest/regex/struct.Regex.html#method.captures_iter for details.
See https://example.com/search?q=hello%20world%2C%20again&lang=en
Connect with psql "host=db.internal user=app sslmode=require" and enter the password when prompted.
Run `mysql -u root -p` and type the password at the prompt.
Use bearer authentication; the Authorization header must start with "Bearer ".
The password reset link expires in 24 hours. Rotate the API token monthly.
x86_64-unknown-linux-gnu aarch64-apple-darwin wasm32-unknown-unknown
SnowflakeS3BackupMode HttpEndpointS3BackupMode JSONSchema7Definition getElementsByClassName
"#;
        assert_untouched(corpus);
    }
}
