use std::borrow::Cow;
use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::allowlist::{Allowlist, Blacklist};
use crate::entropy::EntropyConfig;
use crate::patterns::PatternSet;
use crate::scrubber::{
    Redaction, is_opaque_field, is_sensitive_key, scrub_all_strings, scrub_string,
};

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

/// Would [`scrub_value`] leave this JSON line untouched? Walks the line with
/// serde instead of building a `Value` tree, which is most of the cost for
/// the clean lines that make up nearly every transcript.
///
/// `true` guarantees that parsing `line` into a `Value` succeeds and
/// `scrub_value` finds nothing. `false` means "take the full path": the line
/// may need redaction, or may not be valid JSON (the walk uses
/// `deserialize_any` everywhere, like `Value`, so both reject the same
/// input). Duplicate keys are all checked, a superset of what `Value` keeps.
pub fn is_clean(
    line: &str,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    al: &Allowlist,
    bl: &Blacklist,
) -> bool {
    let ctx = Ctx {
        ps: pattern_set,
        ec: entropy_cfg,
        al,
        bl,
    };
    let mut de = serde_json::Deserializer::from_str(line);
    let walk = Walk {
        ctx: &ctx,
        level: Level::Root,
        want_string: false,
    };
    matches!(walk.deserialize(&mut de), Ok(seen) if !seen.dirty) && de.end().is_ok()
}

struct Ctx<'a> {
    ps: &'a PatternSet,
    ec: &'a EntropyConfig,
    al: &'a Allowlist,
    bl: &'a Blacklist,
}

/// Which of `scrub_value`'s rules apply to the value being walked.
#[derive(Clone, Copy)]
enum Level {
    /// The line itself: an object gets `STRUCTURAL_TOP_KEYS` skipped.
    Root,
    /// The top-level `message` field: an object gets `STRUCTURAL_MESSAGE_KEYS` skipped.
    Message,
    /// `scrub_all_strings` territory; `force` = under a sensitive key.
    Any { force: bool },
    /// Not scrubbed, only parsed.
    Skip,
}

impl Level {
    /// Rules for the elements of an array at this level.
    fn element(self) -> Level {
        match self {
            Level::Root | Level::Message => Level::Any { force: false },
            other => other,
        }
    }
}

struct Walk<'a> {
    ctx: &'a Ctx<'a>,
    level: Level,
    /// Return the value when it is a string (only needed for `type`).
    want_string: bool,
}

struct Seen<'de> {
    dirty: bool,
    string: Option<Cow<'de, str>>,
}

impl Seen<'_> {
    const CLEAN: Self = Seen {
        dirty: false,
        string: None,
    };
}

impl<'a> Walk<'a> {
    fn child(&self, level: Level) -> Walk<'a> {
        Walk {
            ctx: self.ctx,
            level,
            want_string: false,
        }
    }

    fn string<'de>(&self, s: Cow<'de, str>) -> Seen<'de> {
        let dirty = match self.level {
            Level::Skip => false,
            Level::Root | Level::Message => self.redacts(&s, false),
            Level::Any { force } => self.redacts(&s, force),
        };
        Seen {
            dirty,
            string: self.want_string.then_some(s),
        }
    }

    fn redacts(&self, s: &str, force: bool) -> bool {
        let c = self.ctx;
        !scrub_string(s, c.ps, c.ec, c.al, c.bl, force).1.is_empty()
    }
}

impl<'de> DeserializeSeed<'de> for Walk<'_> {
    type Value = Seen<'de>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Seen<'de>, D::Error> {
        d.deserialize_any(self)
    }
}

/// Object keys, borrowed from the line unless they contain escapes.
struct Key;

impl<'de> DeserializeSeed<'de> for Key {
    type Value = Cow<'de, str>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Cow<'de, str>, D::Error> {
        d.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for Key {
    type Value = Cow<'de, str>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object key")
    }

    fn visit_borrowed_str<E>(self, s: &'de str) -> Result<Cow<'de, str>, E> {
        Ok(Cow::Borrowed(s))
    }

    fn visit_str<E>(self, s: &str) -> Result<Cow<'de, str>, E> {
        Ok(Cow::Owned(s.to_owned()))
    }
}

/// Fields whose opacity depends on the object's final `type`.
const TYPE_DEPENDENT_FIELDS: &[&str] = &["source", "file", "data"];

impl<'de> Visitor<'de> for Walk<'_> {
    type Value = Seen<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Seen<'de>, E> {
        Ok(Seen::CLEAN)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Seen<'de>, E> {
        Ok(Seen::CLEAN)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Seen<'de>, E> {
        Ok(Seen::CLEAN)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Seen<'de>, E> {
        Ok(Seen::CLEAN)
    }

    fn visit_unit<E>(self) -> Result<Seen<'de>, E> {
        Ok(Seen::CLEAN)
    }

    fn visit_borrowed_str<E>(self, s: &'de str) -> Result<Seen<'de>, E> {
        Ok(self.string(Cow::Borrowed(s)))
    }

    fn visit_str<E>(self, s: &str) -> Result<Seen<'de>, E> {
        // Escaped strings arrive in a scratch buffer: scrub in place, copy
        // only when the caller wants the value back.
        let seen = self.string(Cow::Borrowed(s));
        Ok(Seen {
            dirty: seen.dirty,
            string: seen.string.map(|s| Cow::Owned(s.into_owned())),
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Seen<'de>, A::Error> {
        let element = self.level.element();
        let mut dirty = false;
        while let Some(seen) = seq.next_element_seed(self.child(element))? {
            dirty |= seen.dirty;
        }
        Ok(Seen {
            dirty,
            string: None,
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Seen<'de>, A::Error> {
        let mut dirty = false;
        let force = match self.level {
            Level::Root => {
                while let Some(key) = map.next_key_seed(Key)? {
                    let level = if STRUCTURAL_TOP_KEYS.contains(&key.as_ref()) {
                        Level::Skip
                    } else if key == "message" {
                        Level::Message
                    } else {
                        Level::Any { force: false }
                    };
                    dirty |= map.next_value_seed(self.child(level))?.dirty;
                }
                return Ok(Seen {
                    dirty,
                    string: None,
                });
            }
            Level::Message => {
                while let Some(key) = map.next_key_seed(Key)? {
                    let level = if STRUCTURAL_MESSAGE_KEYS.contains(&key.as_ref()) {
                        Level::Skip
                    } else {
                        Level::Any { force: false }
                    };
                    dirty |= map.next_value_seed(self.child(level))?.dirty;
                }
                return Ok(Seen {
                    dirty,
                    string: None,
                });
            }
            Level::Skip => {
                while map.next_key_seed(Key)?.is_some() {
                    map.next_value_seed(self.child(Level::Skip))?;
                }
                return Ok(Seen::CLEAN);
            }
            Level::Any { force } => force,
        };

        // `scrub_all_strings` object rules. Opacity of `source`/`file`/`data`
        // depends on the object's `type`, which `Value` takes from the last
        // `type` key, possibly after those fields: decide provisionally and
        // settle once the object ends.
        let mut obj_type: Option<Cow<'de, str>> = None;
        // (field, skipped as opaque, dirty if scrubbed)
        let mut deferred: Vec<(&'static str, bool, bool)> = Vec::new();
        while let Some(key) = map.next_key_seed(Key)? {
            let sensitive = force || is_sensitive_key(&key);
            if key == "type" {
                let mut walk = self.child(Level::Any { force: sensitive });
                walk.want_string = true;
                let seen = map.next_value_seed(walk)?;
                dirty |= seen.dirty;
                obj_type = seen.string;
            } else if let Some(&field) = TYPE_DEPENDENT_FIELDS.iter().find(|f| **f == key) {
                if is_opaque_field(obj_type.as_deref(), field) {
                    map.next_value_seed(self.child(Level::Skip))?;
                    deferred.push((field, true, false));
                } else {
                    let seen = map.next_value_seed(self.child(Level::Any { force: sensitive }))?;
                    deferred.push((field, false, seen.dirty));
                }
            } else if is_opaque_field(None, &key) {
                // Opaque whatever the type (`signature`).
                map.next_value_seed(self.child(Level::Skip))?;
            } else {
                dirty |= map
                    .next_value_seed(self.child(Level::Any { force: sensitive }))?
                    .dirty;
            }
        }
        for (field, skipped, field_dirty) in deferred {
            if !is_opaque_field(obj_type.as_deref(), field) {
                // Skipped on a provisional `type` that a later one overrode:
                // unknown, so let the full path decide.
                dirty |= skipped || field_dirty;
            }
        }
        Ok(Seen {
            dirty,
            string: None,
        })
    }
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

    /// What the full path decides: parses and `scrub_value` finds nothing.
    fn value_path_clean(line: &str) -> bool {
        serde_json::from_str::<Value>(line).is_ok_and(|mut v| run(&mut v).is_empty())
    }

    fn probe(line: &str) -> bool {
        let ps = PatternSet::load(true).unwrap();
        is_clean(
            line,
            &ps,
            &EntropyConfig::default(),
            &Allowlist::empty(),
            &Blacklist::empty(),
        )
    }

    #[test]
    fn clean_probe_agrees_with_value_path() {
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        let cases = [
            // (line, expected is_clean)
            (
                json!({"type": "user", "message": {"content": "hello"}}).to_string(),
                true,
            ),
            (
                json!({"type": "user", "message": {"content": GH}}).to_string(),
                false,
            ),
            (json!({"uuid": GH, "sessionId": GH}).to_string(), true),
            (
                json!({"message": {"id": GH, "model": GH, "content": "x"}}).to_string(),
                true,
            ),
            (json!({"message": GH}).to_string(), false),
            (json!({"message": [GH]}).to_string(), false),
            (json!([{"text": GH}]).to_string(), false),
            (json!(GH).to_string(), false),
            // `signature` is only opaque below the top level.
            (json!({"signature": GH}).to_string(), false),
            (
                json!({"message": {"content": [{"signature": GH}]}}).to_string(),
                true,
            ),
            // Opaque image data, whichever side of `type` it is on.
            (
                json!({"message": {"content": [{"type": "image", "source": {"data": GH}}]}})
                    .to_string(),
                true,
            ),
            (
                r#"{"message":{"content":[{"data":"DATA","type":"image"}]}}"#.replace("DATA", GH),
                true,
            ),
            (
                r#"{"message":{"content":[{"data":"DATA","type":"text"}]}}"#.replace("DATA", GH),
                false,
            ),
            (
                json!({"message": {"content": [{"type": "redacted_thinking", "data": GH}]}})
                    .to_string(),
                true,
            ),
            // Sensitive keys force redaction beneath them.
            (
                json!({"message": {"content": [{"input": {"password": "hunter2hunter2"}}]}})
                    .to_string(),
                false,
            ),
            (
                json!({"message": {"content": [{"credentials": ["hunter2hunter2"]}]}}).to_string(),
                false,
            ),
            (
                json!({"message": {"content": [{"pass": "short"}]}}).to_string(),
                true,
            ),
            // Escapes are decoded before matching.
            (
                r#"{"message":{"content":"ghp\u005fREST"}}"#.replace("REST", &GH[4..]),
                false,
            ),
            (
                r#"{"k\u0065y":"v","message":{"content":"a\nb"}}"#.to_string(),
                true,
            ),
            // Anything `Value` rejects must take the full path.
            ("{\"message\": ".to_string(), false),
            ("{\"a\": 1} trailing".to_string(), false),
            (format!(r#"{{"message":{{"usage":{deep}}}}}"#), false),
            (format!(r#"{{"uuid":{deep}}}"#), false),
            ("1e400".to_string(), false),
        ];
        for (line, expected) in cases {
            assert_eq!(probe(&line), expected, "probe: {line}");
            assert_eq!(value_path_clean(&line), expected, "value path: {line}");
        }
    }

    #[test]
    fn clean_probe_is_conservative_on_duplicate_keys() {
        // `Value` keeps the last duplicate; the probe checks them all.
        let dup = format!(r#"{{"message":{{"content":"{GH}","content":"hi"}}}}"#);
        assert!(value_path_clean(&dup));
        assert!(!probe(&dup));
        // A later `type` makes skipped image data scrubbable again.
        let retyped = format!(
            r#"{{"message":{{"content":[{{"type":"image","data":"{GH}","type":"text"}}]}}}}"#
        );
        assert!(!value_path_clean(&retyped));
        assert!(!probe(&retyped));
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
