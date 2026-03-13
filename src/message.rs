use serde_json::Value;

use crate::allowlist::{Allowlist, Blacklist};
use crate::entropy::EntropyConfig;
use crate::patterns::PatternSet;
use crate::scrubber::{Redaction, scrub_all_strings, scrub_text};

/// Route a parsed JSON value through message-type-aware scrubbing.
///
/// Understands the Claude conversation schema (`type` field) and selectively
/// scrubs the paths that carry user/assistant content while skipping
/// system metadata.
pub fn scrub_value(
    value: &mut Value,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    al: &Allowlist,
    bl: &Blacklist,
) -> Vec<Redaction> {
    let msg_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match msg_type {
        "system" | "file-history-snapshot" => Vec::new(),
        "user" => scrub_user_message(value, pattern_set, entropy_cfg, al, bl),
        "assistant" => scrub_assistant_message(value, pattern_set, entropy_cfg, al, bl),
        "progress" => scrub_at_path(
            value,
            &["data", "message", "message", "content"],
            pattern_set,
            entropy_cfg,
            al,
            bl,
        ),
        "queue-operation" => scrub_at_path(value, &["content"], pattern_set, entropy_cfg, al, bl),
        _ => {
            // Unknown type — recursively scrub all strings as a safety net
            scrub_all_strings(value, pattern_set, entropy_cfg, al, bl)
        }
    }
}

fn scrub_user_message(
    value: &mut Value,
    ps: &PatternSet,
    ec: &EntropyConfig,
    al: &Allowlist,
    bl: &Blacklist,
) -> Vec<Redaction> {
    let mut redactions = scrub_at_path(value, &["message", "content"], ps, ec, al, bl);

    // toolUseResult contains stdout/stderr from tool executions
    if let Some(tool_result) = value.get_mut("toolUseResult") {
        redactions.extend(scrub_all_strings(tool_result, ps, ec, al, bl));
    }

    redactions
}

fn scrub_assistant_message(
    value: &mut Value,
    ps: &PatternSet,
    ec: &EntropyConfig,
    al: &Allowlist,
    bl: &Blacklist,
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
                let (scrubbed, r) = scrub_text(text, ps, ec, al, bl);
                if !r.is_empty() {
                    *text = scrubbed;
                    redactions.extend(r);
                }
            }

            // .thinking field
            if let Some(Value::String(thinking)) = item.get_mut("thinking") {
                let (scrubbed, r) = scrub_text(thinking, ps, ec, al, bl);
                if !r.is_empty() {
                    *thinking = scrubbed;
                    redactions.extend(r);
                }
            }

            // .input (tool_use) — recursively scrub all strings
            if let Some(input) = item.get_mut("input") {
                redactions.extend(scrub_all_strings(input, ps, ec, al, bl));
            }

            // .content (tool_result) — recursively scrub all strings
            if let Some(content) = item.get_mut("content") {
                redactions.extend(scrub_all_strings(content, ps, ec, al, bl));
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
    al: &Allowlist,
    bl: &Blacklist,
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
        return scrub_all_strings(target, ps, ec, al, bl);
    }

    Vec::new()
}
