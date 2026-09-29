//! Scrubber for arbitrary text files (tool results, paste cache, file-history
//! snapshots, plans, shell snapshots, job scratch files).
//!
//! Guarantees:
//! - Files with no findings are never rewritten, so they stay byte-identical
//!   (trailing newline, CRLF and all).
//! - Binary files (by extension, or a NUL byte in the first 8 KiB) and files
//!   over [`MAX_FILE_SIZE`] are skipped.
//! - Symlinks are never followed or written through.
//! - Rewrites go to a temp file in the same directory, are `sync_all`'d, get
//!   the original file's permissions (never wider), and are atomically
//!   persisted. The rewrite is abandoned if the file changed during the scan.

use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use tempfile::NamedTempFile;

use crate::allowlist::{Allowlist, Blacklist};
use crate::entropy::EntropyConfig;
use crate::patterns::PatternSet;
use crate::scrubber::scrub_text;

/// Files larger than this are skipped with a warning.
pub const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// How many leading bytes are checked for NUL when sniffing binaries.
const BINARY_SNIFF_LEN: usize = 8 * 1024;

/// Target chunk size. Content is streamed in line-aligned chunks of about this
/// size so memory stays bounded; any pattern spanning lines still matches as
/// long as it doesn't straddle a chunk boundary.
const CHUNK_TARGET: usize = 1024 * 1024;

const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tif", "tiff", "heic", "avif", "pdf", "zip",
    "gz", "tgz", "bz2", "xz", "zst", "7z", "tar", "jar", "class", "so", "dylib", "dll", "exe", "o",
    "a", "wasm", "mp3", "mp4", "m4a", "mov", "wav", "webm", "woff", "woff2", "ttf", "otf",
    "sqlite", "db", "pyc",
];

/// A redaction location. Deliberately carries no matched text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub pattern_name: String,
    /// 1-based line number of the start of the match.
    pub line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Scanned, nothing found. File untouched.
    Clean,
    /// Findings present. `written` is true if the file was rewritten.
    Redacted {
        written: bool,
    },
    SkippedSymlink,
    SkippedBinary,
    SkippedTooLarge {
        size: u64,
    },
    /// `.json` file whose redacted form would no longer parse; left untouched.
    SkippedWouldBreakJson,
    /// File changed on disk while it was being scanned; left untouched.
    SkippedChanged,
}

#[derive(Debug)]
pub struct PlainResult {
    pub outcome: Outcome,
    pub findings: Vec<Finding>,
}

impl PlainResult {
    fn new(outcome: Outcome, findings: Vec<Finding>) -> Self {
        PlainResult { outcome, findings }
    }
    fn skipped(outcome: Outcome) -> Self {
        Self::new(outcome, Vec::new())
    }
}

pub fn is_binary_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| BINARY_EXTENSIONS.iter().any(|b| b.eq_ignore_ascii_case(e)))
}

struct Ctx<'a> {
    ps: &'a PatternSet,
    ec: &'a EntropyConfig,
    al: &'a Allowlist,
    bl: &'a Blacklist,
}

pub fn scrub_file(
    path: &Path,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    allowlist: &Allowlist,
    blacklist: &Blacklist,
    dry_run: bool,
) -> Result<PlainResult> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Ok(PlainResult::skipped(Outcome::SkippedSymlink));
    }
    if is_binary_extension(path) {
        return Ok(PlainResult::skipped(Outcome::SkippedBinary));
    }
    if meta.len() > MAX_FILE_SIZE {
        return Ok(PlainResult::skipped(Outcome::SkippedTooLarge {
            size: meta.len(),
        }));
    }

    let mut reader = open(path)?;
    {
        let head = reader.fill_buf()?;
        let n = head.len().min(BINARY_SNIFF_LEN);
        if head[..n].contains(&0) {
            return Ok(PlainResult::skipped(Outcome::SkippedBinary));
        }
    }

    let ctx = Ctx {
        ps: pattern_set,
        ec: entropy_cfg,
        al: allowlist,
        bl: blacklist,
    };
    let dir = path.parent().unwrap_or(Path::new("."));

    let (temp, findings) = if path.extension().is_some_and(|e| e == "json") {
        // JSON is processed whole so the redacted result can be validated.
        let mut raw = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
        reader.read_to_end(&mut raw)?;
        let mut findings = Vec::new();
        let Some(new) = scrub_chunk(&raw, 0, &ctx, &mut findings) else {
            return Ok(PlainResult::skipped(Outcome::Clean));
        };
        if dry_run {
            return Ok(PlainResult::new(
                Outcome::Redacted { written: false },
                findings,
            ));
        }
        if serde_json::from_slice::<serde_json::Value>(&raw).is_ok()
            && serde_json::from_slice::<serde_json::Value>(&new).is_err()
        {
            return Ok(PlainResult::new(Outcome::SkippedWouldBreakJson, findings));
        }
        let mut temp = NamedTempFile::new_in(dir).context("creating temp file")?;
        temp.write_all(&new)?;
        (temp, findings)
    } else {
        // Pass 1: find, without writing anything. Clean files (the vast
        // majority) are never touched.
        let findings = process_chunks(&mut reader, &ctx, None)?;
        if findings.is_empty() {
            return Ok(PlainResult::skipped(Outcome::Clean));
        }
        if dry_run {
            return Ok(PlainResult::new(
                Outcome::Redacted { written: false },
                findings,
            ));
        }
        // Pass 2: stream the rewrite into a temp file next to the original.
        let mut reader = open(path)?;
        let temp = NamedTempFile::new_in(dir).context("creating temp file")?;
        let mut w = BufWriter::new(temp);
        process_chunks(&mut reader, &ctx, Some(&mut w))?;
        let temp = w
            .into_inner()
            .map_err(|e| anyhow::anyhow!("flushing temp file: {}", e.error()))?;
        (temp, findings)
    };

    // Abandon if the file changed while we were reading it.
    let now_meta = fs::symlink_metadata(path)?;
    if now_meta.len() != meta.len()
        || now_meta.modified().ok() != meta.modified().ok()
        || now_meta.file_type().is_symlink()
    {
        return Ok(PlainResult::new(Outcome::SkippedChanged, findings));
    }

    // Same permissions as the original: never wider.
    temp.as_file()
        .set_permissions(meta.permissions())
        .context("setting permissions on temp file")?;
    temp.as_file().sync_all().context("syncing temp file")?;
    temp.persist(path)
        .with_context(|| format!("persisting {}", path.display()))?;

    Ok(PlainResult::new(
        Outcome::Redacted { written: true },
        findings,
    ))
}

fn open(path: &Path) -> Result<BufReader<fs::File>> {
    let file = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    Ok(BufReader::with_capacity(64 * 1024, file))
}

/// Read `reader` in line-aligned chunks, scrubbing each. When `sink` is set,
/// every chunk (scrubbed or original bytes) is written to it.
fn process_chunks(
    reader: &mut impl BufRead,
    ctx: &Ctx<'_>,
    mut sink: Option<&mut dyn Write>,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut line_base = 0usize;
    let mut chunk: Vec<u8> = Vec::with_capacity(CHUNK_TARGET + 4096);
    loop {
        chunk.clear();
        // Fill a chunk with whole lines (a single long line may exceed it).
        while chunk.len() < CHUNK_TARGET {
            if reader.read_until(b'\n', &mut chunk)? == 0 {
                break;
            }
        }
        if chunk.is_empty() {
            break;
        }
        let scrubbed = scrub_chunk(&chunk, line_base, ctx, &mut findings);
        if let Some(w) = sink.as_mut() {
            w.write_all(scrubbed.as_deref().unwrap_or(&chunk))?;
        }
        line_base += bytecount::count(&chunk, b'\n');
    }
    Ok(findings)
}

/// Scrub one chunk. Returns `Some(new_bytes)` only if something was redacted.
/// Valid UTF-8 chunks are scrubbed as a whole; otherwise each valid-UTF-8 line
/// is scrubbed on its own and invalid lines are kept verbatim.
fn scrub_chunk(
    chunk: &[u8],
    line_base: usize,
    ctx: &Ctx<'_>,
    findings: &mut Vec<Finding>,
) -> Option<Vec<u8>> {
    if let Ok(text) = std::str::from_utf8(chunk) {
        return scrub_str(text, line_base, ctx, findings).map(String::into_bytes);
    }
    let mut changed = false;
    let mut out = Vec::with_capacity(chunk.len());
    for (line_no, line) in (line_base..).zip(chunk.split_inclusive(|&b| b == b'\n')) {
        match std::str::from_utf8(line) {
            Ok(text) => {
                if let Some(new) = scrub_str(text, line_no, ctx, findings) {
                    changed = true;
                    out.extend_from_slice(new.as_bytes());
                } else {
                    out.extend_from_slice(line);
                }
            }
            Err(_) => out.extend_from_slice(line),
        }
    }
    changed.then_some(out)
}

fn scrub_str(
    text: &str,
    line_base: usize,
    ctx: &Ctx<'_>,
    findings: &mut Vec<Finding>,
) -> Option<String> {
    let (scrubbed, redactions) = scrub_text(text, ctx.ps, ctx.ec, ctx.al, ctx.bl);
    if redactions.is_empty() {
        return None;
    }
    for r in &redactions {
        let line = line_base + bytecount::count(&text.as_bytes()[..r.start], b'\n') + 1;
        findings.push(Finding {
            pattern_name: r.pattern_name.clone(),
            line,
        });
    }
    Some(scrubbed.into_owned())
}
