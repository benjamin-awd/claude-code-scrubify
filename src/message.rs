use serde_json::Value;

use crate::allowlist::{Allowlist, Blacklist};
use crate::entropy::EntropyConfig;
use crate::patterns::PatternSet;
use crate::scrubber::{Redaction, scrub_all_strings};

/// Top-level transcript fields that are identifiers or structure, never
/// free text. Leaving them untouched keeps the parent/child chain and
/// session linkage intact for `claude --resume`.
const STRUCTURAL_TOP_KEYS: &[&str] = &[
    "type",
    "uuid",
    "parentUuid",
    "logicalParentUuid",
    "leafUuid",
    "sessionId",
    "requestId",
    "messageId",
    "promptId",
    "toolUseID",
    "parentToolUseID",
    "sourceToolAssistantUUID",
    "timestamp",
    "version",
    "userType",
    "isSidechain",
    "isMeta",
];

/// Structural fields of the `message` object (API message envelope).
const STRUCTURAL_MESSAGE_KEYS: &[&str] = &[
    "id",
    "type",
    "role",
    "model",
    "stop_reason",
    "stop_sequence",
    "usage",
];

/// Scrub every free-text field of a transcript line.
///
/// Every message type — `user`, `assistant`, `system`, `progress`,
/// `summary`, `file-history-snapshot` and anything unknown — gets a full
/// recursive scrub, so content in fields added by future Claude Code
/// versions is covered by default. Only structural identifiers
/// (`STRUCTURAL_TOP_KEYS`, `STRUCTURAL_MESSAGE_KEYS`) and opaque blobs
/// (image data, thinking `signature`, `redacted_thinking.data`; see
/// `scrubber::scrub_all_strings`) are left untouched.
pub fn scrub_value(
    value: &mut Value,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    al: &Allowlist,
    bl: &Blacklist,
) -> Vec<Redaction> {
    let Value::Object(map) = value else {
        return scrub_all_strings(value, pattern_set, entropy_cfg, al, bl);
    };

    let mut redactions = Vec::new();
    for (key, val) in map.iter_mut() {
        if STRUCTURAL_TOP_KEYS.contains(&key.as_str()) {
            continue;
        }
        if key == "message"
            && let Value::Object(message) = val
        {
            for (mkey, mval) in message.iter_mut() {
                if STRUCTURAL_MESSAGE_KEYS.contains(&mkey.as_str()) {
                    continue;
                }
                redactions.extend(scrub_all_strings(mval, pattern_set, entropy_cfg, al, bl));
            }
            continue;
        }
        redactions.extend(scrub_all_strings(val, pattern_set, entropy_cfg, al, bl));
    }
    redactions
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // Split with concat! so GitHub push protection doesn't flag the fake literal.
    const GH: &str = concat!("ghp_", "FAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKE");

    fn run(value: &mut Value) -> Vec<Redaction> {
        let ps = PatternSet::load(true).unwrap();
        scrub_value(
            value,
            &ps,
            &EntropyConfig::default(),
            &Allowlist::empty(),
            &Blacklist::empty(),
        )
    }

    #[test]
    fn system_lines_are_scrubbed() {
        let mut v = json!({"type": "system", "subtype": "hook", "content": format!("token {GH}")});
        assert_eq!(run(&mut v).len(), 1);
        assert_eq!(v["content"], "token [REDACTED:github-token]");
    }

    #[test]
    fn assistant_plain_string_content_is_scrubbed() {
        let mut v = json!({"type": "assistant", "message": {"role": "assistant", "content": GH}});
        assert_eq!(run(&mut v).len(), 1);
        assert_eq!(v["message"]["content"], "[REDACTED:github-token]");
    }

    #[test]
    fn unknown_fields_on_content_items_are_scrubbed() {
        let mut v = json!({"type": "assistant", "message": {"content": [
            {"type": "server_tool_use", "query": GH},
            {"type": "text", "text": "ok", "citations": [{"cited_text": GH}]},
        ]}});
        assert_eq!(run(&mut v).len(), 2);
        let s = v.to_string();
        assert!(!s.contains("ghp_"), "{s}");
    }

    #[test]
    fn user_fields_outside_content_are_scrubbed() {
        let mut v = json!({
            "type": "user",
            "message": {"role": "user", "content": "hi"},
            "summary": GH,
            "attachment": {"text": format!("export TOKEN={GH}")},
        });
        assert_eq!(run(&mut v).len(), 2);
        assert!(!v.to_string().contains("ghp_"));
    }

    #[test]
    fn progress_and_queue_lines_are_scrubbed_outside_known_paths() {
        let mut v = json!({"type": "progress", "data": {"output": GH}, "extra": GH});
        assert_eq!(run(&mut v).len(), 2);
        let mut v = json!({"type": "queue-operation", "content": GH, "operation": GH});
        assert_eq!(run(&mut v).len(), 2);
    }

    #[test]
    fn structural_ids_and_opaque_blobs_are_untouched() {
        let sig = "EqQBCkYIBBgCKkBFAKEfakeFAKEfakeFAKEfake0123456789abcdefFAKE";
        let blob = "EmwKAhgQEgxFAKEfakeFAKEfake0123456789AbCdEfGhIjKlMnOp";
        let img = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg";
        let mut v = json!({
            "type": "assistant",
            "uuid": "5f0c7b1e-8a3d-4e2f-9b6a-1c2d3e4f5a6b",
            "requestId": "req_011CFAKEfakeFAKEfake0123",
            "message": {"id": "msg_01FAKEfakeFAKEfake012345", "model": "claude-x", "content": [
                {"type": "thinking", "thinking": "hmm", "signature": sig},
                {"type": "redacted_thinking", "data": blob},
                {"type": "image", "source": {"type": "base64", "data": img}},
                {"type": "tool_result", "tool_use_id": "toolu_01FAKEfakeFAKEfake0123",
                 "content": [{"type": "image", "source": {"type": "base64", "data": img}}]},
            ]},
        });
        let before = v.clone();
        assert!(run(&mut v).is_empty());
        assert_eq!(v, before);
    }

    #[test]
    fn tool_use_result_image_is_preserved_but_text_scrubbed() {
        let img = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg";
        let mut v = json!({"type": "user", "message": {"content": []},
            "toolUseResult": {"type": "image", "file": {"base64": img}, "stdout": GH}});
        assert_eq!(run(&mut v).len(), 1);
        assert_eq!(v["toolUseResult"]["file"]["base64"], img);
    }
}
