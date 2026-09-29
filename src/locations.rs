//! Registry of the places under `~/.claude` (and `~/.claude.json`) where
//! Claude Code persists user content, plus discovery of the files to scan in
//! each one.
//!
//! Every function here takes its root directories as arguments so tests can
//! point it at a synthetic tree instead of the real home directory.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::Value;
use tracing::{debug, warn};
use walkdir::WalkDir;

use crate::allowlist::{Allowlist, Blacklist};
use crate::entropy::EntropyConfig;
use crate::patterns::PatternSet;
use crate::scrubber::scrub_all_strings;

/// Orphaned temp files younger than this are left alone: they may belong to a
/// rewrite that is still in flight (e.g. a concurrent hook run).
pub const ORPHAN_MIN_AGE: Duration = Duration::from_hours(1);

/// A place where Claude Code stores content that may contain secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, clap::ValueEnum)]
pub enum Location {
    /// `projects/**/*.jsonl` — session transcripts (the original scan target).
    Transcripts,
    /// `projects/*/<session>/tool-results/*` — offloaded large tool outputs.
    ToolResults,
    /// `jobs/**` — background job transcripts, timelines and scratch files.
    Jobs,
    /// `history.jsonl` — every typed prompt plus pasted content.
    History,
    /// `paste-cache/*` — large pasted blobs.
    PasteCache,
    /// `file-history/**` — pre-edit snapshots used by rewind.
    FileHistory,
    /// `plans/*.md` — plan-mode documents.
    Plans,
    /// `shell-snapshots/*.sh` — captured shell environments.
    ShellSnapshots,
    /// `~/.claude.json` and `backups/.claude.json.backup.*` — report only, never rewritten.
    ClaudeJson,
    /// Orphaned `.tmpXXXXXX` files left behind by an interrupted rewrite.
    OrphanTemps,
}

impl Location {
    pub const ALL: [Location; 10] = [
        Location::Transcripts,
        Location::ToolResults,
        Location::Jobs,
        Location::History,
        Location::PasteCache,
        Location::FileHistory,
        Location::Plans,
        Location::ShellSnapshots,
        Location::ClaudeJson,
        Location::OrphanTemps,
    ];

    /// Stable, CLI-facing name (matches the `--skip` value).
    pub fn name(self) -> &'static str {
        match self {
            Location::Transcripts => "transcripts",
            Location::ToolResults => "tool-results",
            Location::Jobs => "jobs",
            Location::History => "history",
            Location::PasteCache => "paste-cache",
            Location::FileHistory => "file-history",
            Location::Plans => "plans",
            Location::ShellSnapshots => "shell-snapshots",
            Location::ClaudeJson => "claude-json",
            Location::OrphanTemps => "orphan-temps",
        }
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How a discovered file is scrubbed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// JSONL — routed through `jsonl::scrub_jsonl_file`.
    Jsonl,
    /// Arbitrary text — routed through `plaintext::scrub_file`.
    PlainText,
}

/// The set of locations enabled for a scan.
#[derive(Clone, Debug)]
pub struct LocationSet(BTreeSet<Location>);

impl LocationSet {
    /// Every location enabled (the default).
    pub fn all() -> Self {
        LocationSet(Location::ALL.into_iter().collect())
    }

    /// Build from CLI flags. `only_transcripts` restores the original behaviour
    /// of scanning `projects/**/*.jsonl` and nothing else.
    pub fn from_flags(only_transcripts: bool, skip: &[Location]) -> Self {
        let mut set = if only_transcripts {
            LocationSet([Location::Transcripts].into_iter().collect())
        } else {
            Self::all()
        };
        for loc in skip {
            set.0.remove(loc);
        }
        set
    }

    pub fn contains(&self, loc: Location) -> bool {
        self.0.contains(&loc)
    }

    pub fn iter(&self) -> impl Iterator<Item = Location> + '_ {
        self.0.iter().copied()
    }
}

/// A file to scrub.
#[derive(Clone, Debug)]
pub struct Target {
    pub path: PathBuf,
    pub location: Location,
    pub format: Format,
}

/// An orphaned temp file found during discovery.
#[derive(Clone, Debug)]
pub struct Orphan {
    pub path: PathBuf,
    /// Age at discovery time (`None` if the mtime could not be read).
    pub age: Option<Duration>,
}

impl Orphan {
    /// Only orphans at least [`ORPHAN_MIN_AGE`] old are eligible for deletion.
    pub fn is_stale(&self) -> bool {
        self.age.is_some_and(|a| a >= ORPHAN_MIN_AGE)
    }
}

#[derive(Default, Debug)]
pub struct Discovery {
    pub targets: Vec<Target>,
    pub orphans: Vec<Orphan>,
    /// `~/.claude.json` and its backups (report-only).
    pub config_files: Vec<PathBuf>,
    /// Symlinks that were skipped (never followed).
    pub symlinks_skipped: Vec<PathBuf>,
}

/// Does `name` look exactly like a temp file created by
/// `tempfile::NamedTempFile::new_in` with default settings (`.tmp` followed by
/// six ASCII alphanumerics, no suffix)? This is the only naming this tool uses
/// for its atomic rewrites, so it's the only thing orphan cleanup touches.
pub fn is_own_tempfile_name(name: &str) -> bool {
    name.len() == 10
        && name.starts_with(".tmp")
        && name.as_bytes()[4..].iter().all(u8::is_ascii_alphanumeric)
}

/// Discover every file to scan under `claude_dir` for the enabled locations.
/// `claude_json` is the path of `~/.claude.json` (lives outside `claude_dir`).
pub fn discover(
    claude_dir: &Path,
    claude_json: &Path,
    enabled: &LocationSet,
    now: SystemTime,
) -> Discovery {
    let mut d = Discovery::default();
    let Some(canon_root) = fs::canonicalize(claude_dir).ok() else {
        debug!(path = %claude_dir.display(), "claude dir not found");
        if enabled.contains(Location::ClaudeJson) && claude_json.is_file() {
            d.config_files.push(claude_json.to_path_buf());
        }
        return d;
    };
    let orphans = enabled.contains(Location::OrphanTemps);

    // projects/ holds two locations: transcripts and tool-results.
    let want_transcripts = enabled.contains(Location::Transcripts);
    let want_tool_results = enabled.contains(Location::ToolResults);
    if want_transcripts || want_tool_results {
        walk(
            &claude_dir.join("projects"),
            &canon_root,
            now,
            &mut d,
            orphans,
            |rel| {
                let in_tool_results = rel.components().any(|c| c.as_os_str() == "tool-results");
                if in_tool_results {
                    want_tool_results.then_some((Location::ToolResults, Format::PlainText))
                } else if want_transcripts && has_ext(rel, "jsonl") {
                    Some((Location::Transcripts, Format::Jsonl))
                } else {
                    None
                }
            },
        );
    }

    if enabled.contains(Location::Jobs) {
        walk(
            &claude_dir.join("jobs"),
            &canon_root,
            now,
            &mut d,
            orphans,
            |rel| {
                if has_ext(rel, "jsonl") {
                    Some((Location::Jobs, Format::Jsonl))
                } else {
                    Some((Location::Jobs, Format::PlainText))
                }
            },
        );
    }

    for (loc, dir) in [
        (Location::PasteCache, "paste-cache"),
        (Location::FileHistory, "file-history"),
        (Location::Plans, "plans"),
        (Location::ShellSnapshots, "shell-snapshots"),
    ] {
        if enabled.contains(loc) {
            walk(
                &claude_dir.join(dir),
                &canon_root,
                now,
                &mut d,
                orphans,
                |_| Some((loc, Format::PlainText)),
            );
        }
    }

    if enabled.contains(Location::History) {
        let path = claude_dir.join("history.jsonl");
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                d.symlinks_skipped.push(path);
            } else if meta.is_file() {
                d.targets.push(Target {
                    path,
                    location: Location::History,
                    format: Format::Jsonl,
                });
            }
        }
        // Rewrites of history.jsonl leave their temp files in the top level.
        if orphans {
            collect_top_level_orphans(claude_dir, now, &mut d);
        }
    }

    if enabled.contains(Location::ClaudeJson) {
        if claude_json.is_file() {
            d.config_files.push(claude_json.to_path_buf());
        }
        if let Ok(rd) = fs::read_dir(claude_dir.join("backups")) {
            let mut backups: Vec<PathBuf> = rd
                .filter_map(Result::ok)
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.starts_with(".claude.json.backup"))
                        && e.file_type().is_ok_and(|t| t.is_file())
                })
                .map(|e| e.path())
                .collect();
            backups.sort();
            d.config_files.extend(backups);
        }
    }

    d
}

fn has_ext(p: &Path, ext: &str) -> bool {
    p.extension().is_some_and(|e| e == ext)
}

fn file_age(meta: &fs::Metadata, now: SystemTime) -> Option<Duration> {
    let mtime = meta.modified().ok()?;
    Some(now.duration_since(mtime).unwrap_or(Duration::ZERO))
}

fn collect_top_level_orphans(dir: &Path, now: SystemTime, d: &mut Discovery) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.filter_map(Result::ok) {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        if entry.file_name().to_str().is_some_and(is_own_tempfile_name) {
            let age = entry.metadata().ok().and_then(|m| file_age(&m, now));
            d.orphans.push(Orphan {
                path: entry.path(),
                age,
            });
        }
    }
}

/// Walk `root` without following symlinks, classifying each regular file with
/// `classify(relative_path)`. Temp-file-named entries are never scan targets;
/// they're collected as orphans when `collect_orphans` is set.
fn walk(
    root: &Path,
    canon_claude_dir: &Path,
    now: SystemTime,
    d: &mut Discovery,
    collect_orphans: bool,
    classify: impl Fn(&Path) -> Option<(Location, Format)>,
) {
    let Ok(root_meta) = fs::symlink_metadata(root) else {
        debug!(path = %root.display(), "location not present");
        return;
    };
    // WalkDir always follows a symlinked root, so check it resolves inside
    // ~/.claude before descending.
    if root_meta.file_type().is_symlink() {
        let inside = fs::canonicalize(root).is_ok_and(|c| c.starts_with(canon_claude_dir));
        if !inside {
            warn!(path = %root.display(), "location is a symlink pointing outside ~/.claude, skipping");
            d.symlinks_skipped.push(root.to_path_buf());
            return;
        }
    }

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        let ft = entry.file_type();
        if ft.is_symlink() {
            d.symlinks_skipped.push(entry.into_path());
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let name = entry.file_name().to_str().unwrap_or("");
        if is_own_tempfile_name(name) {
            if collect_orphans {
                let age = entry.metadata().ok().and_then(|m| file_age(&m, now));
                d.orphans.push(Orphan {
                    path: entry.into_path(),
                    age,
                });
            }
            continue;
        }
        let rel = entry.path().strip_prefix(root).unwrap_or(entry.path());
        if let Some((location, format)) = classify(rel) {
            d.targets.push(Target {
                path: entry.into_path(),
                location,
                format,
            });
        }
    }
}

/// Delete `orphan` if it is stale and still a regular (non-symlink) file whose
/// name matches this tool's temp-file naming. Returns `true` if deleted.
pub fn remove_stale_orphan(orphan: &Orphan, now: SystemTime) -> std::io::Result<bool> {
    let name_ok = orphan
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(is_own_tempfile_name);
    if !name_ok {
        return Ok(false);
    }
    // Re-check on disk right before deleting: type and age may have changed.
    let meta = fs::symlink_metadata(&orphan.path)?;
    if !meta.file_type().is_file() {
        return Ok(false);
    }
    if file_age(&meta, now).is_none_or(|a| a < ORPHAN_MIN_AGE) {
        return Ok(false);
    }
    fs::remove_file(&orphan.path)?;
    Ok(true)
}

/// A secret-looking value found in `~/.claude.json` (or a backup). Holds only
/// the pattern name and the JSON key path — never the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigFinding {
    pub pattern_name: String,
    pub key_path: String,
}

/// Inspect every `mcpServers` subtree (top-level or per-project) of a
/// `.claude.json`-shaped file and report secret-looking string values.
///
/// This is strictly read-only: the file is never modified, because redacting
/// `mcpServers.*.env` would break the user's MCP servers.
pub fn report_claude_json(
    path: &Path,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    allowlist: &Allowlist,
    blacklist: &Blacklist,
) -> anyhow::Result<Vec<ConfigFinding>> {
    use anyhow::Context;
    let data = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let root: Value =
        serde_json::from_str(&data).with_context(|| format!("parsing {}", path.display()))?;
    let mut findings = Vec::new();
    let ctx = ReportCtx {
        ps: pattern_set,
        ec: entropy_cfg,
        al: allowlist,
        bl: blacklist,
    };
    find_mcp_servers(&root, &mut Vec::new(), &ctx, &mut findings);
    Ok(findings)
}

struct ReportCtx<'a> {
    ps: &'a PatternSet,
    ec: &'a EntropyConfig,
    al: &'a Allowlist,
    bl: &'a Blacklist,
}

fn find_mcp_servers(
    value: &Value,
    path: &mut Vec<String>,
    ctx: &ReportCtx<'_>,
    out: &mut Vec<ConfigFinding>,
) {
    let Value::Object(map) = value else { return };
    for (k, v) in map {
        path.push(k.clone());
        if k == "mcpServers" {
            scan_leaves(v, path, ctx, out);
        } else {
            find_mcp_servers(v, path, ctx, out);
        }
        path.pop();
    }
}

fn scan_leaves(
    value: &Value,
    path: &mut Vec<String>,
    ctx: &ReportCtx<'_>,
    out: &mut Vec<ConfigFinding>,
) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                path.push(k.clone());
                scan_leaves(v, path, ctx, out);
                path.pop();
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                path.push(i.to_string());
                scan_leaves(v, path, ctx, out);
                path.pop();
            }
        }
        Value::String(s) if is_env_reference(s) => {}
        Value::String(s) => {
            // Wrap as {key: value} so the scrubber's sensitive-key-name logic
            // applies (e.g. `API_TOKEN` with an opaque value). Works on a copy.
            let key = path.last().cloned().unwrap_or_default();
            let mut probe = Value::Object(
                [(key, Value::String(s.clone()))]
                    .into_iter()
                    .collect::<serde_json::Map<_, _>>(),
            );
            let mut names: Vec<String> =
                scrub_all_strings(&mut probe, ctx.ps, ctx.ec, ctx.al, ctx.bl)
                    .into_iter()
                    .map(|r| r.pattern_name)
                    .collect();
            names.sort();
            names.dedup();
            for pattern_name in names {
                out.push(ConfigFinding {
                    pattern_name,
                    key_path: join_key_path(path),
                });
            }
        }
        _ => {}
    }
}

/// `$VAR`, `${VAR}` or `${VAR:-default}` — already the recommended way to
/// keep a secret out of the config, so not a finding.
fn is_env_reference(s: &str) -> bool {
    let ident = |t: &str| {
        !t.is_empty()
            && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !t.as_bytes()[0].is_ascii_digit()
    };
    if let Some(inner) = s.strip_prefix("${").and_then(|r| r.strip_suffix('}')) {
        let name = inner.split_once(":-").map_or(inner, |(n, _)| n);
        return ident(name);
    }
    s.strip_prefix('$').is_some_and(ident)
}

fn join_key_path(path: &[String]) -> String {
    path.iter()
        .map(|seg| {
            if seg.contains('.') || seg.contains('/') {
                format!("[{seg:?}]")
            } else {
                seg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}
