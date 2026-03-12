use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use tracing::warn;

use crate::allowlist::Allowlist;
use crate::entropy::EntropyConfig;
use crate::message;
use crate::patterns::PatternSet;
use crate::scrubber::Redaction;

pub struct LineDiff {
    pub line_number: usize, // 1-based
    pub redactions: Vec<Redaction>,
}

pub struct ScrubResult {
    pub redactions: Vec<Redaction>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub lines_modified: usize,
    pub diffs: Vec<LineDiff>,
}

pub fn scrub_jsonl_file(
    path: &Path,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    allowlist: &Allowlist,
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

        // Cheap pre-filter: skip lines for message types we know don't need
        // scrubbing, without paying for a full JSON parse.
        if is_skippable_message_type(&line) {
            writeln!(writer, "{line}")?;
            continue;
        }

        if let Ok(mut value) = serde_json::from_str::<Value>(&line) {
            let redactions = message::scrub_value(&mut value, pattern_set, entropy_cfg, allowlist);
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

/// Message types that `message::scrub_value` skips entirely.
/// We detect them via cheap substring checks to avoid JSON parsing.
const SKIP_PREFIXES: &[&str] = &[r#""type":"system""#, r#""type":"file-history-snapshot""#];

fn is_skippable_message_type(line: &str) -> bool {
    // Only inspect the first 60 bytes — the "type" field is always near the start.
    let prefix = &line[..line.len().min(60)];
    SKIP_PREFIXES.iter().any(|p| prefix.contains(p))
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

    fn no_allowlist() -> Allowlist {
        Allowlist::empty()
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

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &no_allowlist(), false).unwrap();
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

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &no_allowlist(), true).unwrap();
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

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &no_allowlist(), true).unwrap();
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

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &no_allowlist(), false).unwrap();
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

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &no_allowlist(), false);
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

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &no_allowlist(), false).unwrap();
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

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &no_allowlist(), false).unwrap();
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

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &no_allowlist(), false).unwrap();
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

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &no_allowlist(), false).unwrap();
        assert!(
            result.redactions.is_empty(),
            "short values under sensitive keys should not be redacted"
        );
    }
}
