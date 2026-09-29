//! Deterministic synthetic Claude Code transcripts for benchmarks.
//!
//! Line shapes mirror real transcripts: metadata on every line, assistant
//! text, thinking, `tool_use`, `tool_result` with code or logs (occasionally
//! large), and rare base64 screenshots. The mix averages ~2.5-3 KB per line,
//! close to real history (~2.4 KB). Fake secrets are rare, as in practice.
//!
//! Content is fully self-contained so the corpus is byte-identical across
//! commits: benchmark deltas come from code changes, never corpus drift.
//! Changing anything here changes every benchmark's baseline.

#![allow(dead_code)] // each bench target uses a different subset

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use scrub_history::allowlist::{Allowlist, Blacklist};
use scrub_history::entropy::EntropyConfig;
use scrub_history::jsonl::scrub_jsonl_file;
use scrub_history::patterns::PatternSet;
use serde_json::json;

/// Real transcript sizes (bytes) the benchmarks are calibrated against.
pub(crate) const P50_BYTES: usize = 616_000;

/// `SplitMix64`: tiny, fast, and stable across platforms and Rust versions.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in `lo..=hi`.
    pub(crate) fn range(&mut self, lo: usize, hi: usize) -> usize {
        #[allow(clippy::cast_possible_truncation)]
        let span = (self.next_u64() % (hi - lo + 1) as u64) as usize;
        lo + span
    }
    /// True with probability `per_mille / 1000`.
    pub(crate) fn chance(&mut self, per_mille: u64) -> bool {
        self.next_u64() % 1000 < per_mille
    }
    pub(crate) fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.range(0, items.len() - 1)]
    }
}

const WORDS: &[&str] = &[
    "the", "a", "to", "of", "and", "in", "is", "that", "for", "it", "with", "as", "on", "this",
    "refactor", "function", "test", "error", "config", "file", "parse", "value", "return",
    "struct", "impl", "trait", "match", "option", "result", "string", "path", "line", "hook",
    "pattern", "redact", "token", "scan", "cache", "offset", "build", "deploy", "cluster",
];

const IDENTS: &[&str] = &[
    "config",
    "reader",
    "writer",
    "offset",
    "buf",
    "line",
    "state",
    "result",
    "path",
    "entry",
    "pattern_set",
    "spans",
    "matches",
    "cursor",
    "payload",
    "request",
    "response",
    "handle",
];

const TYPES: &[&str] = &[
    "String",
    "Vec<u8>",
    "Option<usize>",
    "Result<()>",
    "&str",
    "PathBuf",
    "HashMap<String, u64>",
];

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn prose(rng: &mut Rng, words: usize) -> String {
    let mut s = String::with_capacity(words * 7);
    for i in 0..words {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(rng.pick(WORDS));
    }
    s.push('.');
    s
}

fn code(rng: &mut Rng, lines: usize) -> String {
    let mut s = String::new();
    for _ in 0..lines {
        let (a, b, t) = (rng.pick(IDENTS), rng.pick(IDENTS), rng.pick(TYPES));
        match rng.range(0, 4) {
            0 => writeln!(
                s,
                "    let {a}: {t} = {b}.get(\"{a}\").cloned().unwrap_or_default();"
            ),
            1 => writeln!(
                s,
                "    if {a}.len() > {} {{ return Err(anyhow!(\"{b} too long\")); }}",
                rng.range(1, 4096)
            ),
            2 => writeln!(s, "fn {a}_{b}(&mut self, {b}: {t}) -> Result<{t}> {{"),
            3 => writeln!(s, "    // {}", prose(rng, 8)),
            _ => writeln!(s, "    self.{a}.push({b}.clone());"),
        }
        .unwrap();
    }
    s
}

fn hex(rng: &mut Rng, nibbles: usize) -> String {
    let mut s = String::with_capacity(nibbles);
    while s.len() < nibbles {
        write!(s, "{:016x}", rng.next_u64()).unwrap();
    }
    s.truncate(nibbles);
    s
}

fn uuid(rng: &mut Rng) -> String {
    let h = hex(rng, 32);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

fn logs(rng: &mut Rng, lines: usize) -> String {
    let mut s = String::new();
    for _ in 0..lines {
        writeln!(
            s,
            "2026-09-29T07:{:02}:{:02}Z INFO request_id={} commit={} status={} dur_ms={}",
            rng.range(0, 59),
            rng.range(0, 59),
            uuid(rng),
            hex(rng, 40),
            rng.pick(&[200, 200, 200, 404, 500]),
            rng.range(1, 900)
        )
        .unwrap();
    }
    s
}

fn base64ish(rng: &mut Rng, len: usize) -> String {
    (0..len).map(|_| char::from(rng.pick(B64))).collect()
}

/// Obviously fake, but shaped so built-in patterns fire. Built with
/// `concat!` so push protection doesn't flag the literals.
fn fake_secret(rng: &mut Rng) -> &'static str {
    rng.pick(&[
        concat!(" ghp_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"),
        concat!(" AKIA", "FAKEFAKEFAKEFAKE"),
    ])
}

pub(crate) struct Transcript {
    rng: Rng,
    session: String,
    parent: Option<String>,
}

impl Transcript {
    pub(crate) fn new(seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let session = uuid(&mut rng);
        Self {
            rng,
            session,
            parent: None,
        }
    }

    fn meta(&mut self, kind: &str) -> serde_json::Map<String, serde_json::Value> {
        let id = uuid(&mut self.rng);
        let (mm, ss) = (self.rng.range(0, 59), self.rng.range(0, 59));
        let ts = format!("2026-09-29T07:{mm:02}:{ss:02}.000Z");
        let m = json!({
            "parentUuid": self.parent, "isSidechain": false, "userType": "external",
            "cwd": "/Users/fake/dev/project", "sessionId": self.session, "version": "2.1.0",
            "gitBranch": "main", "type": kind, "uuid": id,
            "timestamp": ts,
        });
        self.parent = Some(id);
        m.as_object().unwrap().clone()
    }

    /// One JSONL line (with trailing `\n`). About 1 in 2000 carries a fake secret.
    pub(crate) fn line(&mut self) -> String {
        let r = self.rng.range(0, 999);
        let secret = if self.rng.next_u64().is_multiple_of(2000) {
            fake_secret(&mut self.rng)
        } else {
            ""
        };
        let rng = &mut self.rng;
        let (kind, message, extra) = if r < 250 {
            let n = rng.range(20, 400);
            let text = prose(rng, n) + secret;
            (
                "assistant",
                json!({"role": "assistant", "model": "claude-opus-5-5",
                "content": [{"type": "text", "text": text}],
                "usage": {"input_tokens": rng.range(1, 9000), "output_tokens": rng.range(1, 4000)}}),
                None,
            )
        } else if r < 350 {
            let n = rng.range(50, 800);
            let thinking = prose(rng, n);
            (
                "assistant",
                json!({"role": "assistant", "content": [{"type": "thinking",
                "thinking": thinking, "signature": base64ish(rng, 400)}]}),
                None,
            )
        } else if r < 600 {
            let cmd = format!("cargo test --locked -- {}{secret}", rng.pick(WORDS));
            (
                "assistant",
                json!({"role": "assistant", "content": [{"type": "tool_use",
                "id": format!("toolu_{}", hex(rng, 22)), "name": rng.pick(&["Bash", "Read", "Edit", "Grep"]),
                "input": {"command": cmd, "description": prose(rng, 8)}}]}),
                None,
            )
        } else if r < 995 {
            let size = rng.pick(&[1, 1, 1, 1, 1, 2, 4, 10]);
            let body = if rng.chance(600) {
                let n = rng.range(4, 30) * size;
                code(rng, n)
            } else {
                let n = rng.range(2, 12) * size;
                logs(rng, n)
            } + secret;
            let stdout: String = body.chars().take(2000).collect();
            (
                "user",
                json!({"role": "user", "content": [{"type": "tool_result",
                "tool_use_id": format!("toolu_{}", hex(rng, 22)), "content": body}]}),
                Some(json!({"stdout": stdout, "stderr": "", "interrupted": false})),
            )
        } else {
            let n = rng.range(27_000, 200_000);
            let data = base64ish(rng, n);
            (
                "user",
                json!({"role": "user", "content": [{"type": "image",
                "source": {"type": "base64", "media_type": "image/png", "data": data}}]}),
                None,
            )
        };
        let mut obj = self.meta(kind);
        obj.insert("message".into(), message);
        if let Some(extra) = extra {
            obj.insert("toolUseResult".into(), extra);
        }
        let mut s = serde_json::to_string(&obj).unwrap();
        s.push('\n');
        s
    }

    /// Lines until at least `bytes` have been produced.
    pub(crate) fn bytes(&mut self, bytes: usize) -> String {
        let mut out = String::with_capacity(bytes + 4096);
        while out.len() < bytes {
            out.push_str(&self.line());
        }
        out
    }
}

/// A ~20 KB block of tool output and prose (code, logs, text; no secrets,
/// no base64), as a single string: the input shape `scrub_text` usually sees.
pub(crate) fn text_chunk() -> String {
    let mut rng = Rng::new(7);
    let mut s = String::new();
    while s.len() < 20_000 {
        match rng.range(0, 2) {
            0 => s.push_str(&code(&mut rng, 20)),
            1 => s.push_str(&logs(&mut rng, 6)),
            _ => {
                let n = rng.range(40, 200);
                s.push_str(&prose(&mut rng, n));
                s.push('\n');
            }
        }
    }
    s
}

/// A transcript of about `bytes` bytes (seed fixed, so always identical).
pub(crate) fn transcript(bytes: usize) -> String {
    Transcript::new(1).bytes(bytes)
}

/// One assistant turn (~15 KB, no secret) to append for incremental runs.
pub(crate) fn turn() -> String {
    Transcript::new(99).bytes(15_000)
}

/// A line carrying a fake secret, to force the incremental rewrite path.
pub(crate) fn secret_line() -> String {
    format!(
        "{}\n",
        json!({"type": "user", "message": {"content": concat!("token ghp_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE")}})
    )
}

pub(crate) fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    path
}

pub(crate) fn append(path: &Path, content: &str) {
    let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

pub(crate) struct Fixture {
    pub patterns: PatternSet,
    pub entropy: EntropyConfig,
    pub allowlist: Allowlist,
    pub blacklist: Blacklist,
}

impl Fixture {
    /// Built-in patterns only, default entropy settings (the common config).
    pub(crate) fn new() -> Self {
        Self::with_entropy(EntropyConfig::default())
    }

    pub(crate) fn with_entropy(entropy: EntropyConfig) -> Self {
        Self {
            patterns: PatternSet::load(true).unwrap(),
            entropy,
            allowlist: Allowlist::empty(),
            blacklist: Blacklist::empty(),
        }
    }

    pub(crate) fn scrub(&self, path: &Path, skip_bytes: Option<u64>) -> u64 {
        scrub_jsonl_file(
            path,
            &self.patterns,
            &self.entropy,
            &self.allowlist,
            &self.blacklist,
            false,
            skip_bytes,
        )
        .unwrap()
        .final_size
    }
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}
