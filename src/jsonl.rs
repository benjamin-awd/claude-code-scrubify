use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use tracing::warn;

use crate::entropy::EntropyConfig;
use crate::patterns::PatternSet;
use crate::scanner::{scrub_text, Redaction};

pub struct LineDiff {
    pub line_number: usize, // 1-based
    pub redactions: Vec<Redaction>,
}

pub struct ScrubResult {
    pub redactions: Vec<Redaction>,
    pub lines_modified: usize,
    pub diffs: Vec<LineDiff>,
}

pub fn scrub_jsonl_file(
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
    let mut line_number: usize = 0;

    for line_result in reader.lines() {
        line_number += 1;
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

        match serde_json::from_str::<Value>(&line) {
            Ok(mut value) => {
                let redactions = scrub_value(&mut value, pattern_set, entropy_cfg);
                if !redactions.is_empty() {
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
                } else {
                    writeln!(writer, "{line}")?;
                }
            }
            Err(_) => {
                // Malformed JSON line — write unchanged
                warn!(file = %path.display(), "malformed JSON line");
                writeln!(writer, "{line}")?;
            }
        }
    }

    writer.flush()?;
    drop(writer);

    if !dry_run && !all_redactions.is_empty() {
        temp.persist(path).with_context(|| format!("persisting {}", path.display()))?;
    }

    Ok(ScrubResult {
        redactions: all_redactions,
        lines_modified,
        diffs,
    })
}

fn scrub_value(value: &mut Value, pattern_set: &PatternSet, entropy_cfg: &EntropyConfig) -> Vec<Redaction> {
    let msg_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match msg_type {
        "system" | "file-history-snapshot" => Vec::new(),
        "user" => scrub_at_path(value, &["message", "content"], pattern_set, entropy_cfg),
        "assistant" => scrub_assistant_message(value, pattern_set, entropy_cfg),
        "progress" => scrub_at_path(value, &["data", "message", "message", "content"], pattern_set, entropy_cfg),
        "queue-operation" => scrub_at_path(value, &["content"], pattern_set, entropy_cfg),
        _ => {
            // Unknown type — recursively scrub all strings as a safety net
            scrub_all_strings(value, pattern_set, entropy_cfg)
        }
    }
}

fn scrub_assistant_message(value: &mut Value, ps: &PatternSet, ec: &EntropyConfig) -> Vec<Redaction> {
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

fn scrub_at_path(value: &mut Value, path: &[&str], ps: &PatternSet, ec: &EntropyConfig) -> Vec<Redaction> {
    let mut current = value as &mut Value;
    for &key in &path[..path.len().saturating_sub(1)] {
        match current.get_mut(key) {
            Some(v) => current = v,
            None => return Vec::new(),
        }
    }

    if let Some(&last_key) = path.last() {
        if let Some(target) = current.get_mut(last_key) {
            return scrub_all_strings(target, ps, ec);
        }
    }

    Vec::new()
}

fn scrub_all_strings(value: &mut Value, ps: &PatternSet, ec: &EntropyConfig) -> Vec<Redaction> {
    match value {
        Value::String(s) => {
            let (scrubbed, redactions) = scrub_text(s, ps, ec);
            if !redactions.is_empty() {
                *s = scrubbed;
            }
            redactions
        }
        Value::Array(arr) => {
            arr.iter_mut().flat_map(|v| scrub_all_strings(v, ps, ec)).collect()
        }
        Value::Object(map) => {
            map.values_mut().flat_map(|v| scrub_all_strings(v, ps, ec)).collect()
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
        let ps = PatternSet::load(true);
        let ec = EntropyConfig { enabled: false, ..Default::default() };

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
        let ps = PatternSet::load(true);
        let ec = EntropyConfig { enabled: false, ..Default::default() };

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
            r#"{"type":"system","content":"safe"}"#, "\n",
            r#"{"type":"user","message":{"content":"token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}"#, "\n",
            r#"{"type":"system","content":"also safe"}"#, "\n",
            r#"{"type":"user","message":{"content":"key AKIAVCODYLSA53PQK4ZA"}}"#, "\n",
        );
        let file = make_test_file(lines);
        let ps = PatternSet::load(true);
        let ec = EntropyConfig { enabled: false, ..Default::default() };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, true).unwrap();
        assert_eq!(result.diffs.len(), 2);
        assert_eq!(result.diffs[0].line_number, 2);
        assert_eq!(result.diffs[1].line_number, 4);
    }

    #[test]
    fn non_dry_run_does_not_collect_diffs() {
        let line = r#"{"type":"user","message":{"content":"token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true);
        let ec = EntropyConfig { enabled: false, ..Default::default() };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, false).unwrap();
        assert!(!result.redactions.is_empty());
        assert!(result.diffs.is_empty(), "non-dry-run should not collect diffs");
    }

    #[test]
    fn handles_malformed_json() {
        let content = "not json at all\n{\"type\":\"system\"}\n";
        let file = make_test_file(content);
        let ps = PatternSet::load(true);
        let ec = EntropyConfig { enabled: false, ..Default::default() };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, false);
        assert!(result.is_ok());
    }

    #[test]
    fn skips_system_type() {
        let line = r#"{"type":"system","content":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}"#;
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true);
        let ec = EntropyConfig { enabled: false, ..Default::default() };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, false).unwrap();
        assert!(result.redactions.is_empty());
    }

    #[test]
    fn scrubs_assistant_tool_use() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","input":{"command":"echo ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}]}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true);
        let ec = EntropyConfig { enabled: false, ..Default::default() };

        let result = scrub_jsonl_file(file.path(), &ps, &ec, false).unwrap();
        assert!(!result.redactions.is_empty());

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("[REDACTED:github-token]"));
    }
}
