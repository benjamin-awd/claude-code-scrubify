use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use tracing::warn;

use crate::entropy::EntropyConfig;
use crate::patterns::PatternSet;
use crate::scrubber::{Redaction, scrub_text};

pub(crate) struct LineDiff {
    pub line_number: usize, // 1-based
    pub redactions: Vec<Redaction>,
}

pub(crate) struct ScrubResult {
    pub redactions: Vec<Redaction>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub lines_modified: usize,
    pub diffs: Vec<LineDiff>,
}

pub(crate) fn scrub_jsonl_file(
    path: &Path,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    dry_run: bool,
) -> Result<ScrubResult> {
    let file = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let reader = BufReader::new(file);

    let dir = path.parent().unwrap_or(Path::new("."));
    let mut temp = NamedTempFile::new_in(dir).context("creating temp file")?;
    let mut writer = BufWriter::new(&mut temp);

    let mut all_redactions: Vec<Redaction> = Vec::new();
    let mut lines_modified = 0;
    let mut diffs: Vec<LineDiff> = Vec::new();
    for (line_number, line_result) in reader.lines().enumerate() {
        let line_number = line_number + 1;
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                warn!(file = %path.display(), error = %e, "error reading line");
                continue;
            }
        };

        if line.trim().is_empty() {
            writeln!(writer, "{line}")?;
            continue;
        }

        if let Ok(mut value) = serde_json::from_str::<Value>(&line) {
            let redactions = scrub_value(&mut value, pattern_set, entropy_cfg);
            if redactions.is_empty() {
                writeln!(writer, "{line}")?;
            } else {
                lines_modified += 1;
                if dry_run {
                    diffs.push(LineDiff {
                        line_number,
                        redactions: redactions.clone(),
                    });
                }
                all_redactions.extend(redactions);
                let scrubbed = serde_json::to_string(&value)?;
                writeln!(writer, "{scrubbed}")?;
            }
        } else {
            // Malformed JSON line — write unchanged
            warn!(file = %path.display(), "malformed JSON line");
            writeln!(writer, "{line}")?;
        }
    }

    writer.flush()?;
    drop(writer);

    if !dry_run && !all_redactions.is_empty() {
        temp.persist(path)
            .with_context(|| format!("persisting {}", path.display()))?;
    }

    Ok(ScrubResult {
        redactions: all_redactions,
        lines_modified,
        diffs,
    })
}

fn scrub_value(
    value: &mut Value,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
) -> Vec<Redaction> {
    let msg_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match msg_type {
        "system" | "file-history-snapshot" => Vec::new(),
        "user" => scrub_at_path(value, &["message", "content"], pattern_set, entropy_cfg),
        "assistant" => scrub_assistant_message(value, pattern_set, entropy_cfg),
        "progress" => scrub_at_path(
            value,
            &["data", "message", "message", "content"],
            pattern_set,
            entropy_cfg,
        ),
        "queue-operation" => scrub_at_path(value, &["content"], pattern_set, entropy_cfg),
        _ => {
            // Unknown type — recursively scrub all strings as a safety net
            scrub_all_strings(value, pattern_set, entropy_cfg)
        }
    }
}

fn scrub_assistant_message(
    value: &mut Value,
    ps: &PatternSet,
    ec: &EntropyConfig,
) -> Vec<Redaction> {
    let mut redactions = Vec::new();

    // Navigate to .message.content which is an array
    if let Some(content_array) = value
        .get_mut("message")
        .and_then(|m| m.get_mut("content"))
        .and_then(|c| c.as_array_mut())
    {
        for item in content_array.iter_mut() {
            // .text field
            if let Some(Value::String(text)) = item.get_mut("text") {
                let (scrubbed, r) = scrub_text(text, ps, ec);
                if !r.is_empty() {
                    *text = scrubbed;
                    redactions.extend(r);
                }
            }

            // .thinking field
            if let Some(Value::String(thinking)) = item.get_mut("thinking") {
                let (scrubbed, r) = scrub_text(thinking, ps, ec);
                if !r.is_empty() {
                    *thinking = scrubbed;
                    redactions.extend(r);
                }
            }

            // .input (tool_use) — recursively scrub all strings
            if let Some(input) = item.get_mut("input") {
                redactions.extend(scrub_all_strings(input, ps, ec));
            }

            // .content (tool_result) — recursively scrub all strings
            if let Some(content) = item.get_mut("content") {
                redactions.extend(scrub_all_strings(content, ps, ec));
            }
        }
    }

    redactions
}

fn scrub_at_path(
    value: &mut Value,
    path: &[&str],
    ps: &PatternSet,
    ec: &EntropyConfig,
) -> Vec<Redaction> {
    let mut current = value as &mut Value;
    for &key in &path[..path.len().saturating_sub(1)] {
        match current.get_mut(key) {
            Some(v) => current = v,
            None => return Vec::new(),
        }
    }

    if let Some(&last_key) = path.last()
        && let Some(target) = current.get_mut(last_key)
    {
        return scrub_all_strings(target, ps, ec);
    }

    Vec::new()
}

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

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_KEYS
        .iter()
        .any(|&k| lower == k || lower.ends_with(&format!("_{k}")))
}

fn scrub_all_strings(value: &mut Value, ps: &PatternSet, ec: &EntropyConfig) -> Vec<Redaction> {
    scrub_all_strings_inner(value, ps, ec, false)
}

fn scrub_all_strings_inner(
    value: &mut Value,
    ps: &PatternSet,
    ec: &EntropyConfig,
    force_redact: bool,
) -> Vec<Redaction> {
    match value {
        Value::String(s) => {
            // Key-value awareness: if the parent key was sensitive and the
            // value is long enough, redact the whole thing unconditionally.
            if force_redact && s.len() >= SENSITIVE_KEY_MIN_VALUE_LEN {
                let redaction = Redaction {
                    pattern_name: "sensitive-field".to_string(),
                    start: 0,
                    end: s.len(),
                    matched_text: s.clone(),
                };
                *s = "[REDACTED:sensitive-field]".to_string();
                return vec![redaction];
            }
            let (scrubbed, redactions) = scrub_text(s, ps, ec);
            if !redactions.is_empty() {
                *s = scrubbed;
            }
            redactions
        }
        Value::Array(arr) => arr
            .iter_mut()
            .flat_map(|v| scrub_all_strings_inner(v, ps, ec, force_redact))
            .collect(),
        Value::Object(map) => {
            let mut redactions = Vec::new();
            for (key, val) in map.iter_mut() {
                let sensitive = is_sensitive_key(key);
                redactions.extend(scrub_all_strings_inner(val, ps, ec, sensitive));
            }
            redactions
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_test_file(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "{content}").unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn scrubs_user_message() {
        let line = r#"{"type":"user","message":{"content":"my token is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig {
            enabled: false,
            ..Default::default()
        };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, false).unwrap();
        assert_eq!(result.lines_modified, 1);
        assert!(!result.redactions.is_empty());

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("[REDACTED:github-token]"));
        assert!(!content.contains("ghp_"));
    }

    #[test]
    fn dry_run_does_not_modify() {
        let line = r#"{"type":"user","message":{"content":"token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}"#;
        let original = format!("{line}\n");
        let file = make_test_file(&original);
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig {
            enabled: false,
            ..Default::default()
        };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, true).unwrap();
        assert!(!result.redactions.is_empty());

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("ghp_"), "dry run should not modify file");

        // Verify diffs are populated
        assert_eq!(result.diffs.len(), 1);
        assert_eq!(result.diffs[0].line_number, 1);
        assert!(!result.diffs[0].redactions.is_empty());
        assert!(result.diffs[0].redactions[0].matched_text.contains("ghp_"));
    }

    #[test]
    fn dry_run_diffs_have_correct_line_numbers() {
        let lines = concat!(
            r#"{"type":"system","content":"safe"}"#,
            "\n",
            r#"{"type":"user","message":{"content":"token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}"#,
            "\n",
            r#"{"type":"system","content":"also safe"}"#,
            "\n",
            r#"{"type":"user","message":{"content":"key AKIAVCODYLSA53PQK4ZA"}}"#,
            "\n",
        );
        let file = make_test_file(lines);
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig {
            enabled: false,
            ..Default::default()
        };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, true).unwrap();
        assert_eq!(result.diffs.len(), 2);
        assert_eq!(result.diffs[0].line_number, 2);
        assert_eq!(result.diffs[1].line_number, 4);
    }

    #[test]
    fn non_dry_run_does_not_collect_diffs() {
        let line = r#"{"type":"user","message":{"content":"token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig {
            enabled: false,
            ..Default::default()
        };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, false).unwrap();
        assert!(!result.redactions.is_empty());
        assert!(
            result.diffs.is_empty(),
            "non-dry-run should not collect diffs"
        );
    }

    #[test]
    fn handles_malformed_json() {
        let content = "not json at all\n{\"type\":\"system\"}\n";
        let file = make_test_file(content);
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig {
            enabled: false,
            ..Default::default()
        };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, false);
        assert!(result.is_ok());
    }

    #[test]
    fn skips_system_type() {
        let line = r#"{"type":"system","content":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}"#;
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig {
            enabled: false,
            ..Default::default()
        };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, false).unwrap();
        assert!(result.redactions.is_empty());
    }

    #[test]
    fn scrubs_assistant_tool_use() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","input":{"command":"echo ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}]}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig {
            enabled: false,
            ..Default::default()
        };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, false).unwrap();
        assert!(!result.redactions.is_empty());

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("[REDACTED:github-token]"));
    }

    #[test]
    fn redacts_sensitive_field_by_key_name() {
        // The value doesn't match any regex pattern, but the key "password" triggers redaction
        let line =
            r#"{"type":"user","message":{"content":{"password":"not_a_known_pattern_value"}}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig {
            enabled: false,
            ..Default::default()
        };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, false).unwrap();
        assert!(!result.redactions.is_empty());

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("[REDACTED:sensitive-field]"));
        assert!(!content.contains("not_a_known_pattern_value"));
    }

    #[test]
    fn skips_short_sensitive_field_values() {
        let line = r#"{"type":"user","message":{"content":{"password":"short"}}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig {
            enabled: false,
            ..Default::default()
        };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, false).unwrap();
        assert!(
            result.redactions.is_empty(),
            "short values under sensitive keys should not be redacted"
        );
    }
}
