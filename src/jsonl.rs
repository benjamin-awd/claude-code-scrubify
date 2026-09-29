use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tempfile::NamedTempFile;
use tracing::warn;

use crate::allowlist::{Allowlist, Blacklist};
use crate::entropy::EntropyConfig;
use crate::message;
use crate::patterns::PatternSet;
use crate::scrubber::{Redaction, scrub_text};

/// How many times we re-read a tail that grew while we were rewriting before
/// giving up. Each round only processes the bytes appended since the last one,
/// so this only trips on a writer that never pauses.
const MAX_TAIL_ROUNDS: usize = 32;

/// How many times we retry opening + locking when the file is replaced by
/// another rewriter between `open` and `flock`.
const MAX_LOCK_ATTEMPTS: usize = 8;

pub struct LineDiff {
    pub line_number: usize, // 1-based
    pub redactions: Vec<Redaction>,
}

pub struct ScrubResult {
    pub redactions: Vec<Redaction>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub lines_modified: usize,
    pub diffs: Vec<LineDiff>,
    /// Byte offset of the end of the last complete (`\n`-terminated) line in
    /// the file as it exists after this call. Used as the `skip_bytes` offset
    /// for the next incremental run, so a trailing line that was still being
    /// written is re-read (and scrubbed) once it is complete.
    pub final_size: u64,
}

/// Scrub a JSONL transcript in place.
///
/// Guarantees:
/// - Every input byte is preserved unless it is part of a redaction: lines
///   that are not valid UTF-8 or not valid JSON are copied verbatim (malformed
///   UTF-8 JSON still gets a plain-text scrub).
/// - A trailing line without `\n` is never processed or modified.
/// - Lines appended while the rewrite runs are carried over to the new file.
/// - The rewrite holds an exclusive advisory lock on the source file, and is
///   abandoned if the file is replaced or truncated underneath it.
pub fn scrub_jsonl_file(
    path: &Path,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    allowlist: &Allowlist,
    blacklist: &Blacklist,
    dry_run: bool,
    skip_bytes: Option<u64>,
) -> Result<ScrubResult> {
    let ctx = ScrubCtx {
        path,
        pattern_set,
        entropy_cfg,
        allowlist,
        blacklist,
        dry_run,
    };
    scrub_jsonl_file_with_hook(&ctx, skip_bytes, &mut || {})
}

struct ScrubCtx<'a> {
    path: &'a Path,
    pattern_set: &'a PatternSet,
    entropy_cfg: &'a EntropyConfig,
    allowlist: &'a Allowlist,
    blacklist: &'a Blacklist,
    dry_run: bool,
}

/// `before_commit` runs each time the reader reaches EOF, just before the file
/// is re-checked for growth. It is a no-op in production and an injection
/// point for tests that simulate concurrent writers.
fn scrub_jsonl_file_with_hook(
    ctx: &ScrubCtx<'_>,
    skip_bytes: Option<u64>,
    before_commit: &mut dyn FnMut(),
) -> Result<ScrubResult> {
    let path = ctx.path;

    // Unlocked fast path: nothing appended since the last scrub.
    if let Some(offset) = skip_bytes {
        let file_size = fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .len();
        if file_size == offset {
            return Ok(ScrubResult::unchanged(offset));
        }
    }

    let mut file = if ctx.dry_run {
        File::open(path).with_context(|| format!("opening {}", path.display()))?
    } else {
        open_locked(path)?
    };
    let orig_meta = file.metadata()?;
    let file_size = orig_meta.len();

    let skip_bytes = match skip_bytes {
        Some(offset) if offset == file_size => return Ok(ScrubResult::unchanged(offset)),
        Some(offset) if offset > file_size => {
            warn!(
                file = %path.display(),
                file_size,
                offset,
                "file smaller than recorded offset, performing full scan"
            );
            None
        }
        Some(offset) if offset > 0 && !byte_before_is_newline(&mut file, offset)? => {
            warn!(
                file = %path.display(),
                offset,
                "recorded offset is not at a line boundary, performing full scan"
            );
            None
        }
        other => other,
    };

    // Incremental fast path: scan only the appended tail, read-only. A clean
    // tail (the common case after a turn) needs no temp file and no O(file)
    // prefix copy; only when it contains a secret do we fall through to the
    // full rewrite below, which rescans that small tail.
    if let Some(offset) = skip_bytes
        && !ctx.dry_run
    {
        let mut probe = LineState {
            ctx,
            line_number: 0,
            out_len: offset,
            redactions: Vec::new(),
            lines_modified: 0,
            diffs: Vec::new(),
        };
        let (pos, _eof) = probe.process_complete_lines(&mut file, offset, &mut io::sink())?;
        if probe.redactions.is_empty() {
            return Ok(probe.into_result(pos));
        }
    }

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temp = NamedTempFile::new_in(dir).context("creating temp file")?;
    let mut writer = BufWriter::with_capacity(1 << 20, temp.as_file().try_clone()?);

    // If incremental, raw-copy the already-scrubbed prefix, then process only the tail.
    let (mut pos, line_number_offset) = match skip_bytes {
        Some(offset) => {
            file.seek(SeekFrom::Start(0))?;
            let lines = copy_counting_lines(&mut file, &mut writer, offset)?;
            (offset, lines)
        }
        None => (0, 0),
    };

    let mut state = LineState {
        ctx,
        line_number: line_number_offset,
        out_len: pos,
        redactions: Vec::new(),
        lines_modified: 0,
        diffs: Vec::new(),
    };

    let mut rounds = 0;
    loop {
        let eof;
        (pos, eof) = state.process_complete_lines(&mut file, pos, &mut writer)?;

        if ctx.dry_run || state.redactions.is_empty() {
            // Source is left untouched: the next run resumes after the last
            // complete line we examined.
            return Ok(state.into_result(pos));
        }

        before_commit();

        // Re-check for bytes appended since we hit EOF (Claude Code does not
        // take our lock). Growth is processed and appended; anything else
        // aborts so we never persist a file missing someone else's data.
        let cur_len = file.metadata()?.len();
        if cur_len < eof {
            bail!("{} shrank during rewrite, not persisting", path.display());
        }
        if cur_len > eof {
            rounds += 1;
            if rounds >= MAX_TAIL_ROUNDS {
                bail!(
                    "{} kept growing during rewrite, not persisting",
                    path.display()
                );
            }
            continue;
        }

        // Trailing partial line (still being written): copy it through as-is.
        let mut tail = Vec::new();
        file.seek(SeekFrom::Start(pos))?;
        (&mut file).take(cur_len - pos).read_to_end(&mut tail)?;
        if file.metadata()?.len() != cur_len {
            rounds += 1;
            if rounds >= MAX_TAIL_ROUNDS {
                bail!(
                    "{} kept growing during rewrite, not persisting",
                    path.display()
                );
            }
            continue;
        }

        if !same_file(&orig_meta, &fs::metadata(path)?) {
            bail!(
                "{} was replaced during rewrite, not persisting",
                path.display()
            );
        }

        writer.write_all(&tail)?;
        writer.flush()?;
        drop(writer);
        temp.as_file().sync_all()?;
        copy_permissions(&orig_meta, temp.path())?;
        temp.persist(path)
            .with_context(|| format!("persisting {}", path.display()))?;
        sync_dir(dir);

        let final_size = state.out_len;
        return Ok(state.into_result(final_size));
    }
}

impl ScrubResult {
    fn unchanged(offset: u64) -> Self {
        Self {
            redactions: Vec::new(),
            lines_modified: 0,
            diffs: Vec::new(),
            final_size: offset,
        }
    }
}

struct LineState<'a> {
    ctx: &'a ScrubCtx<'a>,
    /// Number of complete lines consumed so far (1-based number of the last one).
    line_number: usize,
    /// Bytes written to the temp file for complete lines.
    out_len: u64,
    redactions: Vec<Redaction>,
    lines_modified: usize,
    diffs: Vec<LineDiff>,
}

impl LineState<'_> {
    /// Process every complete line from `pos` to the current EOF.
    ///
    /// Returns `(end_of_last_complete_line, eof_position)`. A trailing
    /// partial line is read but neither processed nor written.
    fn process_complete_lines(
        &mut self,
        file: &mut File,
        mut pos: u64,
        writer: &mut impl Write,
    ) -> Result<(u64, u64)> {
        file.seek(SeekFrom::Start(pos))?;
        let mut reader = BufReader::new(&mut *file);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)? as u64;
            if n == 0 {
                return Ok((pos, pos));
            }
            if buf.last() != Some(&b'\n') {
                return Ok((pos, pos + n));
            }
            self.out_len += self.process_line(&buf, writer)?;
            pos += n;
        }
    }

    /// Scrub one `\n`-terminated line and write it. Returns bytes written.
    fn process_line(&mut self, line: &[u8], writer: &mut impl Write) -> Result<u64> {
        self.line_number += 1;
        let (content, terminator) = split_terminator(line);
        if let Some(scrubbed) = self.scrub_line(content)? {
            writer.write_all(scrubbed.as_bytes())?;
            writer.write_all(terminator)?;
            Ok((scrubbed.len() + terminator.len()) as u64)
        } else {
            writer.write_all(line)?;
            Ok(line.len() as u64)
        }
    }

    /// Returns the replacement text for a line, or `None` to copy it verbatim.
    fn scrub_line(&mut self, content: &[u8]) -> Result<Option<String>> {
        let ctx = self.ctx;
        let Ok(text) = std::str::from_utf8(content) else {
            warn!(
                file = %ctx.path.display(),
                line = self.line_number,
                "line is not valid UTF-8, copying unchanged"
            );
            return Ok(None);
        };
        if text.trim().is_empty() {
            return Ok(None);
        }

        let (redactions, output) = if let Ok(mut value) = serde_json::from_str::<Value>(text) {
            let redactions = message::scrub_value(
                &mut value,
                ctx.pattern_set,
                ctx.entropy_cfg,
                ctx.allowlist,
                ctx.blacklist,
            );
            if redactions.is_empty() {
                return Ok(None);
            }
            (redactions, serde_json::to_string(&value)?)
        } else {
            // Malformed (or too deeply nested) JSON: keep the bytes, but
            // still redact anything that looks like a secret in the raw text.
            warn!(
                file = %ctx.path.display(),
                line = self.line_number,
                "malformed JSON line, falling back to plain-text scrub"
            );
            let (scrubbed, redactions) = scrub_text(
                text,
                ctx.pattern_set,
                ctx.entropy_cfg,
                ctx.allowlist,
                ctx.blacklist,
            );
            if redactions.is_empty() {
                return Ok(None);
            }
            (redactions, scrubbed)
        };

        self.lines_modified += 1;
        // Deduplicate: the same secret value may appear in multiple JSON
        // fields within a single JSONL line (e.g. a command and its echoed
        // output). Count and report it only once per line.
        let mut deduped = redactions;
        deduped.sort_by(|a, b| {
            a.pattern_name
                .cmp(&b.pattern_name)
                .then_with(|| a.matched_text.cmp(&b.matched_text))
        });
        deduped
            .dedup_by(|a, b| a.pattern_name == b.pattern_name && a.matched_text == b.matched_text);
        if ctx.dry_run {
            self.diffs.push(LineDiff {
                line_number: self.line_number,
                redactions: deduped.clone(),
            });
        }
        self.redactions.extend(deduped);
        Ok(Some(output))
    }

    fn into_result(self, final_size: u64) -> ScrubResult {
        ScrubResult {
            redactions: self.redactions,
            lines_modified: self.lines_modified,
            diffs: self.diffs,
            final_size,
        }
    }
}

/// Split a `\n`-terminated line into content and its original terminator
/// (`\n` or `\r\n`).
fn split_terminator(line: &[u8]) -> (&[u8], &[u8]) {
    let cut = if line.ends_with(b"\r\n") {
        line.len() - 2
    } else if line.ends_with(b"\n") {
        line.len() - 1
    } else {
        line.len()
    };
    line.split_at(cut)
}

/// Open `path` and take an exclusive advisory lock on it.
///
/// If another rewriter replaced the file (rename over `path`) while we were
/// waiting for the lock, our descriptor points at the stale inode, so reopen.
fn open_locked(path: &Path) -> Result<File> {
    for _ in 0..MAX_LOCK_ATTEMPTS {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        file.lock()
            .with_context(|| format!("locking {}", path.display()))?;
        let current = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if same_file(&file.metadata()?, &current) {
            return Ok(file);
        }
    }
    bail!("{} keeps being replaced, could not lock it", path.display())
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    true
}

/// Give the new file the original's permission bits (the temp file starts at
/// 0600, and we never widen beyond what the original had).
#[cfg(unix)]
fn copy_permissions(orig: &fs::Metadata, target: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = orig.permissions().mode() & 0o777;
    fs::set_permissions(target, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions on {}", target.display()))
}

#[cfg(not(unix))]
fn copy_permissions(orig: &fs::Metadata, target: &Path) -> Result<()> {
    fs::set_permissions(target, orig.permissions())
        .with_context(|| format!("setting permissions on {}", target.display()))
}

/// Best-effort fsync of the directory so the rename itself is durable.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

fn byte_before_is_newline(file: &mut File, offset: u64) -> Result<bool> {
    file.seek(SeekFrom::Start(offset - 1))?;
    let mut b = [0u8; 1];
    file.read_exact(&mut b)?;
    Ok(b[0] == b'\n')
}

/// Copy exactly `len` bytes from `reader` to `writer`, returning the number of
/// newlines seen (so diff line numbers stay correct in incremental mode).
fn copy_counting_lines(reader: &mut impl Read, writer: &mut impl Write, len: u64) -> Result<usize> {
    let mut reader = reader.take(len);
    let mut buf = [0u8; 8192];
    let mut count = 0;
    let mut copied = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count += bytecount::count(&buf[..n], b'\n');
        writer.write_all(&buf[..n])?;
        copied += n as u64;
    }
    if copied != len {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
    }
    Ok(count)
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

    fn test_fixtures() -> (PatternSet, EntropyConfig, Allowlist, Blacklist) {
        (
            PatternSet::load(true).unwrap(),
            EntropyConfig {
                enabled: false,
                ..Default::default()
            },
            Allowlist::empty(),
            Blacklist::empty(),
        )
    }

    #[test]
    fn scrubs_user_message() {
        let line = r#"{"type":"user","message":{"content":"my token is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
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
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, true, None).unwrap();
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
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, true, None).unwrap();
        assert_eq!(result.diffs.len(), 2);
        assert_eq!(result.diffs[0].line_number, 2);
        assert_eq!(result.diffs[1].line_number, 4);
    }

    #[test]
    fn non_dry_run_does_not_collect_diffs() {
        let line = r#"{"type":"user","message":{"content":"token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
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
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None);
        assert!(result.is_ok());
    }

    const FAKE_TOKEN: &str = concat!("ghp_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE");

    fn user_line(text: &str) -> String {
        format!(r#"{{"type":"user","message":{{"content":"{text}"}}}}"#)
    }

    fn ctx<'a>(
        path: &'a Path,
        fx: &'a (PatternSet, EntropyConfig, Allowlist, Blacklist),
    ) -> ScrubCtx<'a> {
        ScrubCtx {
            path,
            pattern_set: &fx.0,
            entropy_cfg: &fx.1,
            allowlist: &fx.2,
            blacklist: &fx.3,
            dry_run: false,
        }
    }

    fn append(path: &Path, data: &[u8]) {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(data).unwrap();
    }

    // --- Bug 4: no jsonl-level pre-filter on message type ---

    #[test]
    fn system_and_snapshot_lines_go_through_scrub_value() {
        // Whatever message::scrub_value decides for these types, jsonl must
        // produce exactly the same redactions (i.e. it must not skip them).
        let (ps, ec, al, bl) = test_fixtures();
        for ty in ["system", "file-history-snapshot"] {
            let line = format!(r#"{{"type":"{ty}","content":"token {FAKE_TOKEN}"}}"#);
            let mut value: Value = serde_json::from_str(&line).unwrap();
            let expected = message::scrub_value(&mut value, &ps, &ec, &al, &bl).len();

            let file = make_test_file(&format!("{line}\n"));
            let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, true, None).unwrap();
            assert_eq!(result.redactions.len(), expected, "type {ty}");
        }
    }

    #[test]
    fn nested_system_type_does_not_skip_user_line() {
        // The old 60-byte peek saw `"type":"system"` in a nested object and
        // skipped the whole line, leaking the secret in a user message.
        for ty in ["system", "file-history-snapshot"] {
            let line = format!(
                r#"{{"meta":{{"type":"{ty}"}},"type":"user","message":{{"content":"token {FAKE_TOKEN}"}}}}"#
            );
            let file = make_test_file(&format!("{line}\n"));
            let (ps, ec, al, bl) = test_fixtures();
            let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
            assert_eq!(result.lines_modified, 1, "type {ty}");
            let content = fs::read_to_string(file.path()).unwrap();
            assert!(!content.contains(FAKE_TOKEN), "type {ty}");
        }
    }

    #[test]
    fn handles_multibyte_chars() {
        let line = user_line(&format!("# ── Failure alerting ── {FAKE_TOKEN}"));
        let file = make_test_file(&format!("{line}\n"));
        let (ps, ec, al, bl) = test_fixtures();
        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
        assert_eq!(result.lines_modified, 1);
        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("── Failure alerting ──"));
    }

    // --- Bug 1: invalid UTF-8 / malformed lines are preserved ---

    #[test]
    fn preserves_invalid_utf8_lines_byte_for_byte() {
        let mut input = Vec::new();
        input.extend_from_slice(
            b"{\"type\":\"user\",\"message\":{\"content\":\"bad \xff\xfe bytes\"}}\n",
        );
        input.extend_from_slice(user_line(&format!("t {FAKE_TOKEN}")).as_bytes());
        input.extend_from_slice(b"\n\xc3\x28 not json either\r\n");
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), &input).unwrap();
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
        assert_eq!(result.lines_modified, 1);

        let output = fs::read(file.path()).unwrap();
        let lines: Vec<&[u8]> = output.split_inclusive(|&b| b == b'\n').collect();
        assert_eq!(lines.len(), 3, "no line may be dropped");
        assert_eq!(
            lines[0],
            b"{\"type\":\"user\",\"message\":{\"content\":\"bad \xff\xfe bytes\"}}\n"
        );
        assert!(String::from_utf8_lossy(lines[1]).contains("[REDACTED:github-token]"));
        assert_eq!(lines[2], b"\xc3\x28 not json either\r\n");
        assert_eq!(result.final_size, output.len() as u64);
    }

    #[test]
    fn malformed_json_is_kept_but_plain_text_scrubbed() {
        let malformed = format!(r#"{{"type":"user","message":"oops {FAKE_TOKEN}"#);
        let content = format!("not json at all\n{malformed}\n");
        let file = make_test_file(&content);
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
        assert_eq!(result.lines_modified, 1);
        let out = fs::read_to_string(file.path()).unwrap();
        assert!(!out.contains(FAKE_TOKEN));
        assert_eq!(
            out,
            format!(
                "not json at all\n{}\n",
                malformed.replace(FAKE_TOKEN, "[REDACTED:github-token]")
            )
        );
    }

    #[test]
    fn too_deeply_nested_json_is_plain_text_scrubbed() {
        // serde_json rejects nesting deeper than 128.
        let open = "[".repeat(200);
        let close = "]".repeat(200);
        let line = format!("{open}\"{FAKE_TOKEN}\"{close}");
        assert!(serde_json::from_str::<Value>(&line).is_err());
        let file = make_test_file(&format!("{line}\n"));
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
        assert_eq!(result.lines_modified, 1);
        let out = fs::read_to_string(file.path()).unwrap();
        assert!(!out.contains(FAKE_TOKEN));
        assert!(out.starts_with(&open) && out.ends_with(&format!("{close}\n")));
    }

    // --- Bug 3: partial trailing lines ---

    #[test]
    fn partial_trailing_line_is_left_untouched() {
        let complete = user_line(&format!("a {FAKE_TOKEN}"));
        let partial = format!(r#"{{"type":"user","message":{{"content":"b {FAKE_TOKEN}"#);
        let file = make_test_file(&format!("{complete}\n{partial}"));
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
        assert_eq!(result.lines_modified, 1);

        let out = fs::read_to_string(file.path()).unwrap();
        let (first, rest) = out.split_once('\n').unwrap();
        assert!(first.contains("[REDACTED:github-token]"));
        assert_eq!(
            rest, partial,
            "partial line must be copied as-is, no newline"
        );
        assert_eq!(result.final_size, first.len() as u64 + 1);

        // The writer finishes the line; the next incremental run scrubs it.
        append(file.path(), b"\"}}\n");
        let result = scrub_jsonl_file(
            file.path(),
            &ps,
            &ec,
            &al,
            &bl,
            false,
            Some(result.final_size),
        )
        .unwrap();
        assert_eq!(result.lines_modified, 1);
        let out = fs::read_to_string(file.path()).unwrap();
        assert!(!out.contains(FAKE_TOKEN), "{out}");
        assert_eq!(out.lines().count(), 2);
        assert_eq!(result.final_size, out.len() as u64);
    }

    #[test]
    fn partial_line_offset_without_redactions_points_at_line_end() {
        let complete = user_line("clean");
        let file = make_test_file(&format!("{complete}\n{{\"type\":\"us"));
        let (ps, ec, al, bl) = test_fixtures();
        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
        assert_eq!(result.final_size, complete.len() as u64 + 1);
    }

    #[test]
    fn mid_line_offset_falls_back_to_full_scan() {
        // Offsets written by older versions could point mid-line.
        let line = user_line(&format!("a {FAKE_TOKEN}"));
        let file = make_test_file(&format!("{line}\n"));
        let (ps, ec, al, bl) = test_fixtures();
        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, Some(20)).unwrap();
        assert_eq!(result.lines_modified, 1);
        assert!(
            !fs::read_to_string(file.path())
                .unwrap()
                .contains(FAKE_TOKEN)
        );
    }

    // --- Bug 2: concurrent appends, locking, durability, permissions ---

    #[test]
    fn lines_appended_during_rewrite_are_kept_and_scrubbed() {
        let fx = test_fixtures();
        let file = make_test_file(&format!("{}\n", user_line(&format!("a {FAKE_TOKEN}"))));
        let path = file.path().to_path_buf();

        let mut calls = 0;
        let mut hook = || {
            calls += 1;
            if calls <= 3 {
                // Simulate Claude Code appending from another thread between
                // our EOF and the persist. Round 3 appends only a partial line.
                let p = path.clone();
                let n = calls;
                std::thread::spawn(move || {
                    let data = if n < 3 {
                        format!("{}\n", user_line(&format!("appended {n} {FAKE_TOKEN}")))
                    } else {
                        "{\"type\":\"user\",\"mess".to_string()
                    };
                    append(&p, data.as_bytes());
                })
                .join()
                .unwrap();
            }
        };
        let result = scrub_jsonl_file_with_hook(&ctx(&path, &fx), None, &mut hook).unwrap();

        let out = fs::read_to_string(&path).unwrap();
        assert!(out.contains("appended 1"), "{out}");
        assert!(out.contains("appended 2"), "{out}");
        assert!(out.ends_with("\n{\"type\":\"user\",\"mess"), "{out}");
        assert!(
            !out.contains(FAKE_TOKEN),
            "appended lines must be scrubbed too"
        );
        assert_eq!(result.lines_modified, 3);
        assert_eq!(
            result.final_size,
            (out.len() - "{\"type\":\"user\",\"mess".len()) as u64
        );
    }

    #[test]
    fn replaced_file_aborts_without_persisting() {
        let fx = test_fixtures();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        fs::write(
            &path,
            format!("{}\n", user_line(&format!("a {FAKE_TOKEN}"))),
        )
        .unwrap();

        let replacement = "{\"type\":\"user\",\"message\":{\"content\":\"new\"}}\n";
        let mut hook = || {
            let other = dir.path().join("other.jsonl");
            fs::write(&other, replacement).unwrap();
            fs::rename(&other, &path).unwrap();
        };
        let err = scrub_jsonl_file_with_hook(&ctx(&path, &fx), None, &mut hook);
        assert!(err.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), replacement);
    }

    #[test]
    fn truncated_file_aborts_without_persisting() {
        let fx = test_fixtures();
        let file = make_test_file(&format!("{}\n", user_line(&format!("a {FAKE_TOKEN}"))));
        let path = file.path().to_path_buf();
        let mut hook = || fs::write(&path, "").unwrap();
        assert!(scrub_jsonl_file_with_hook(&ctx(&path, &fx), None, &mut hook).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"");
    }

    #[test]
    fn rewrite_holds_exclusive_lock() {
        let fx = test_fixtures();
        let file = make_test_file(&format!("{}\n", user_line(&format!("a {FAKE_TOKEN}"))));
        let path = file.path().to_path_buf();
        let mut locked_by_us = None;
        let mut hook = || {
            let other = File::open(&path).unwrap();
            locked_by_us = Some(matches!(
                other.try_lock(),
                Err(fs::TryLockError::WouldBlock)
            ));
        };
        scrub_jsonl_file_with_hook(&ctx(&path, &fx), None, &mut hook).unwrap();
        assert_eq!(locked_by_us, Some(true));
        // Released afterwards.
        File::open(&path).unwrap().try_lock().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn preserves_permission_bits() {
        use std::os::unix::fs::PermissionsExt;
        let (ps, ec, al, bl) = test_fixtures();
        for mode in [0o600, 0o640, 0o644] {
            let file = make_test_file(&format!("{}\n", user_line(&format!("a {FAKE_TOKEN}"))));
            fs::set_permissions(file.path(), fs::Permissions::from_mode(mode)).unwrap();
            let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
            assert_eq!(result.lines_modified, 1);
            let got = fs::metadata(file.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(got, mode);
        }
    }

    #[test]
    fn scrubs_assistant_tool_use() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","input":{"command":"echo ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}]}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
        assert!(!result.redactions.is_empty());

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("[REDACTED:github-token]"));
    }

    #[test]
    fn preserves_base64_image_in_user_message() {
        // Simulate a user message with an image content block containing base64 data.
        // The base64 data has high entropy and matches TOKEN_RE, so without the
        // image-block skip it would be corrupted by the entropy detector.
        let base64_data = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
        let line = format!(
            r#"{{"type":"user","message":{{"content":[{{"type":"text","text":"here is a screenshot"}},{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{base64_data}"}}}}]}}}}"#,
        );
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig::default(); // entropy enabled
        let al = Allowlist::empty();
        let bl = Blacklist::empty();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(
            content.contains(base64_data),
            "base64 image data should be preserved, got: {content}"
        );
        assert!(result.redactions.is_empty());
    }

    #[test]
    fn preserves_base64_image_in_assistant_message() {
        let base64_data = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
        let line = format!(
            r#"{{"type":"assistant","message":{{"content":[{{"type":"text","text":"here is the image"}},{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{base64_data}"}}}}]}}}}"#,
        );
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig::default(); // entropy enabled
        let al = Allowlist::empty();
        let bl = Blacklist::empty();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(
            content.contains(base64_data),
            "base64 image data should be preserved, got: {content}"
        );
        assert!(result.redactions.is_empty());
    }

    #[test]
    fn redacts_sensitive_field_by_key_name() {
        // The value doesn't match any regex pattern, but the key "password" triggers redaction
        let line =
            r#"{"type":"user","message":{"content":{"password":"not_a_known_pattern_value"}}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
        assert!(!result.redactions.is_empty());

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("[REDACTED:sensitive-field]"));
        assert!(!content.contains("not_a_known_pattern_value"));
    }

    #[test]
    fn deduplicates_same_secret_across_fields() {
        // Same token appears in both .text and .input within the same JSONL line.
        // The redaction should be applied to both, but counted/reported only once.
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let line = format!(
            r#"{{"type":"assistant","message":{{"content":[{{"type":"text","text":"token {token}"}},{{"type":"tool_use","input":{{"command":"echo {token}"}}}}]}}}}"#,
        );
        let file = make_test_file(&format!("{line}\n"));
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, true, None).unwrap();
        // Both occurrences are redacted in the file
        assert_eq!(result.lines_modified, 1);
        // But deduplicated: same pattern + same matched_text = 1 redaction
        assert_eq!(
            result.redactions.len(),
            1,
            "same secret in multiple fields should be deduplicated"
        );
        assert_eq!(result.diffs.len(), 1);
        assert_eq!(
            result.diffs[0].redactions.len(),
            1,
            "diff should also be deduplicated"
        );
    }

    #[test]
    fn skips_short_sensitive_field_values() {
        let line = r#"{"type":"user","message":{"content":{"password":"short"}}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let (ps, ec, al, bl) = test_fixtures();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
        assert!(
            result.redactions.is_empty(),
            "short values under sensitive keys should not be redacted"
        );
    }

    // --- Blacklist tests ---

    #[test]
    fn blacklist_prefilter_does_not_skip_blacklisted_lines() {
        // A "system" line that would normally be skipped, but contains a blacklisted string
        // Note: system messages are skipped by message::scrub_value, not by the pre-filter.
        // The pre-filter only skips parsing. With blacklist, we still parse system lines
        // but scrub_value skips them. So test with a user message that has no regex match.
        let bl = Blacklist::from_strings(vec!["foobar123"]);
        let line = r#"{"type":"user","message":{"content":"this has foobar123 in it"}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig {
            enabled: false,
            ..Default::default()
        };
        let al = Allowlist::empty();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, None).unwrap();
        assert!(
            !result.redactions.is_empty(),
            "blacklist entry should be redacted"
        );

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("[REDACTED:blacklist]"));
        assert!(!content.contains("foobar123"));
    }

    #[test]
    fn blacklist_end_to_end_user_message() {
        let bl = Blacklist::from_strings(vec!["my-company-internal.com"]);
        let line =
            r#"{"type":"user","message":{"content":"visit my-company-internal.com for details"}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let ps = PatternSet::load(true).unwrap();
        let ec = EntropyConfig {
            enabled: false,
            ..Default::default()
        };
        let al = Allowlist::empty();

        let result = scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, true, None).unwrap();
        assert_eq!(result.lines_modified, 1);
        assert_eq!(result.redactions.len(), 1);
        assert_eq!(result.redactions[0].pattern_name, "blacklist");
    }

    // --- Incremental processing tests ---

    #[test]
    fn incremental_early_return_unchanged() {
        let line = r#"{"type":"user","message":{"content":"hello world"}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let (ps, ec, al, bl) = test_fixtures();

        let file_size = fs::metadata(file.path()).unwrap().len();
        let result =
            scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, Some(file_size)).unwrap();

        assert!(result.redactions.is_empty());
        assert_eq!(result.lines_modified, 0);
        assert_eq!(result.final_size, file_size);
    }

    #[test]
    fn incremental_skips_prefix() {
        let clean_line = r#"{"type":"user","message":{"content":"hello world"}}"#;
        let secret_line = r#"{"type":"user","message":{"content":"token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}"#;

        // Write clean content first
        let file = make_test_file(&format!("{clean_line}\n"));
        let offset = fs::metadata(file.path()).unwrap().len();

        // Append a line with a secret
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(file.path())
                .unwrap();
            writeln!(f, "{secret_line}").unwrap();
        }

        let (ps, ec, al, bl) = test_fixtures();
        let result =
            scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, Some(offset)).unwrap();

        assert_eq!(result.lines_modified, 1);
        assert!(!result.redactions.is_empty());

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("[REDACTED:github-token]"));
        // The clean prefix line should still be present
        assert!(content.contains("hello world"));
    }

    #[cfg(unix)]
    #[test]
    fn incremental_clean_tail_does_not_rewrite() {
        use std::os::unix::fs::MetadataExt;

        let clean = r#"{"type":"user","message":{"content":"hello world"}}"#;
        let file = make_test_file(&format!("{clean}\n"));
        let offset = fs::metadata(file.path()).unwrap().len();
        {
            let mut f = fs::OpenOptions::new()
                .append(true)
                .open(file.path())
                .unwrap();
            writeln!(
                f,
                r#"{{"type":"assistant","message":{{"content":"still clean"}}}}"#
            )
            .unwrap();
        }
        let before = fs::read(file.path()).unwrap();
        let ino = fs::metadata(file.path()).unwrap().ino();

        let (ps, ec, al, bl) = test_fixtures();
        let result =
            scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, Some(offset)).unwrap();

        assert!(result.redactions.is_empty());
        assert_eq!(
            result.final_size,
            before.len() as u64,
            "offset must advance"
        );
        assert_eq!(
            fs::metadata(file.path()).unwrap().ino(),
            ino,
            "clean tail must not replace the file"
        );
        assert_eq!(fs::read(file.path()).unwrap(), before);
    }

    #[test]
    fn incremental_truncated_falls_back() {
        let line = r#"{"type":"user","message":{"content":"token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}"#;
        let file = make_test_file(&format!("{line}\n"));
        let (ps, ec, al, bl) = test_fixtures();

        // Pass an offset larger than the file — should fall back to full scan
        let result =
            scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, Some(999_999)).unwrap();

        assert!(!result.redactions.is_empty());
        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("[REDACTED:github-token]"));
    }

    #[test]
    fn incremental_copies_prefix_exactly() {
        let clean_line = r#"{"type":"user","message":{"content":"hello world"}}"#;
        let secret_line = r#"{"type":"user","message":{"content":"token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"}}"#;

        let file = make_test_file(&format!("{clean_line}\n"));
        let prefix_bytes = fs::read(file.path()).unwrap();
        let offset = prefix_bytes.len() as u64;

        // Append secret line
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(file.path())
                .unwrap();
            writeln!(f, "{secret_line}").unwrap();
        }

        let (ps, ec, al, bl) = test_fixtures();
        scrub_jsonl_file(file.path(), &ps, &ec, &al, &bl, false, Some(offset)).unwrap();

        let output = fs::read(file.path()).unwrap();
        // First N bytes should be identical to the original prefix
        assert_eq!(&output[..prefix_bytes.len()], &prefix_bytes[..]);
    }
}
