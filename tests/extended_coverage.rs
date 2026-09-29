//! End-to-end tests for the extended location coverage, run against a
//! synthetic `~/.claude` tree in a temp dir. HOME is never touched: every
//! entry point takes its root directories explicitly.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use scrub_history::allowlist::{Allowlist, Blacklist};
use scrub_history::entropy::EntropyConfig;
use scrub_history::jsonl;
use scrub_history::locations::{
    self, Discovery, Format, Location, LocationSet, Orphan, is_own_tempfile_name,
};
use scrub_history::patterns::PatternSet;
use scrub_history::plaintext::{self, Outcome};

// Fake, realistic-looking tokens. Split with concat! so no full token literal
// appears in the source.
const GH_TOKEN: &str = concat!("ghp_", "Zq3xV8mN2pL7", "rT4wY9kB1cF6", "hJ5sD0gA8eUi");
const AWS_KEY: &str = concat!("AKIA", "QX7M3PLN", "V2RT8KWZ");

fn fixtures() -> (PatternSet, EntropyConfig, Allowlist, Blacklist) {
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

fn write(path: &Path, content: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn set_age(path: &Path, age: Duration) {
    let f = fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() - age).unwrap();
}

struct Tree {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    claude: PathBuf,
    claude_json: PathBuf,
    outside: PathBuf,
}

/// Build a fake home with one file per location, each containing a secret.
fn build_tree() -> Tree {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let claude = home.join(".claude");
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();

    let user_line = format!(r#"{{"type":"user","message":{{"content":"token {GH_TOKEN}"}}}}"#);
    let proj = claude.join("projects").join("-Users-me-repo");
    let session = "0b1c2d3e-0000-4000-8000-000000000001";
    write(
        &proj.join(format!("{session}.jsonl")),
        format!("{user_line}\n"),
    );
    write(
        &proj.join(session).join("tool-results").join("toolu_01.txt"),
        format!("output line\nexport GITHUB_TOKEN={GH_TOKEN}\n"),
    );
    write(
        &proj.join(session).join("tool-results").join("shot.jpg"),
        format!("\u{ff}\u{d8} fake jpeg {GH_TOKEN}"),
    );

    let job = claude.join("jobs").join("job-1");
    write(
        &job.join("tmp").join("parent-transcript.jsonl"),
        format!("{user_line}\n"),
    );
    write(
        &job.join("timeline.jsonl"),
        format!(r#"{{"event":"tool","output":"{AWS_KEY}"}}"#) + "\n",
    );
    write(&job.join("scratch.txt"), format!("key={AWS_KEY}\n"));

    write(
        &claude.join("history.jsonl"),
        format!(
            r#"{{"display":"see paste","pastedContents":{{"1":{{"id":1,"type":"text","content":"{GH_TOKEN}"}}}},"timestamp":1,"project":"/r"}}"#
        ) + "\n",
    );
    write(
        &claude.join("paste-cache").join("abc.txt"),
        format!("{GH_TOKEN}\n"),
    );
    write(
        &claude
            .join("file-history")
            .join(session)
            .join("deadbeef@v1"),
        format!("aws_access_key_id = {AWS_KEY}\n"),
    );
    write(
        &claude.join("plans").join("plan.md"),
        format!("# Plan\nuse {GH_TOKEN}\n"),
    );
    write(
        &claude.join("shell-snapshots").join("snapshot-zsh-1.sh"),
        format!("export GH={GH_TOKEN}\n"),
    );

    let claude_json = home.join(".claude.json");
    let cfg = format!(
        r#"{{
  "numStartups": 3,
  "mcpServers": {{
    "github": {{"command": "gh-mcp", "env": {{"GITHUB_TOKEN": "{GH_TOKEN}", "REF_TOKEN": "${{GITHUB_TOKEN}}"}}}}
  }},
  "projects": {{
    "/Users/me/repo": {{"mcpServers": {{"aws": {{"env": {{"AWS_ACCESS_KEY_ID": "{AWS_KEY}"}}}}}}}}
  }}
}}
"#
    );
    write(&claude_json, &cfg);
    write(
        &claude
            .join("backups")
            .join(".claude.json.backup.1700000000"),
        &cfg,
    );

    Tree {
        _tmp: tmp,
        home,
        claude,
        claude_json,
        outside,
    }
}

fn discover(t: &Tree, set: &LocationSet) -> Discovery {
    locations::discover(&t.claude, &t.claude_json, set, SystemTime::now())
}

fn target_loc(d: &Discovery, suffix: &str) -> Option<(Location, Format)> {
    d.targets
        .iter()
        .find(|t| t.path.ends_with(suffix))
        .map(|t| (t.location, t.format))
}

/// Scrub every discovered target the way `scan --fix` does.
fn scrub_all(d: &Discovery) {
    let (ps, ec, al, bl) = fixtures();
    for t in &d.targets {
        match t.format {
            Format::Jsonl => {
                jsonl::scrub_jsonl_file(&t.path, &ps, &ec, &al, &bl, false, None).unwrap();
            }
            Format::PlainText => {
                plaintext::scrub_file(&t.path, &ps, &ec, &al, &bl, false).unwrap();
            }
        }
    }
}

#[test]
fn discovers_every_location_with_the_right_format() {
    use Format::{Jsonl, PlainText};

    let t = build_tree();
    let d = discover(&t, &LocationSet::all());

    let cases = [
        (
            "0b1c2d3e-0000-4000-8000-000000000001.jsonl",
            Location::Transcripts,
            Jsonl,
        ),
        (
            "tool-results/toolu_01.txt",
            Location::ToolResults,
            PlainText,
        ),
        ("tmp/parent-transcript.jsonl", Location::Jobs, Jsonl),
        ("job-1/timeline.jsonl", Location::Jobs, Jsonl),
        ("job-1/scratch.txt", Location::Jobs, PlainText),
        (".claude/history.jsonl", Location::History, Jsonl),
        ("paste-cache/abc.txt", Location::PasteCache, PlainText),
        ("deadbeef@v1", Location::FileHistory, PlainText),
        ("plans/plan.md", Location::Plans, PlainText),
        ("snapshot-zsh-1.sh", Location::ShellSnapshots, PlainText),
    ];
    for (suffix, loc, fmt) in cases {
        assert_eq!(target_loc(&d, suffix), Some((loc, fmt)), "{suffix}");
    }
    // ~/.claude.json and its backup are report-only, never scan targets.
    assert_eq!(d.config_files.len(), 2);
    assert!(
        d.targets
            .iter()
            .all(|t| !t.path.to_string_lossy().contains(".claude.json"))
    );
}

#[test]
fn only_transcripts_restores_old_behaviour() {
    let t = build_tree();
    let d = discover(&t, &LocationSet::from_flags(true, &[]));
    assert_eq!(d.targets.len(), 1);
    assert_eq!(d.targets[0].location, Location::Transcripts);
    assert!(d.config_files.is_empty());
}

#[test]
fn skip_excludes_a_location() {
    let t = build_tree();
    let d = discover(
        &t,
        &LocationSet::from_flags(false, &[Location::FileHistory, Location::ClaudeJson]),
    );
    assert!(
        d.targets
            .iter()
            .all(|t| t.location != Location::FileHistory)
    );
    assert!(target_loc(&d, "plans/plan.md").is_some());
    assert!(d.config_files.is_empty());
}

#[test]
fn full_fix_run_redacts_every_location_and_skips_binaries() {
    let t = build_tree();
    let d = discover(&t, &LocationSet::all());
    let jpg = t
        .claude
        .join("projects/-Users-me-repo/0b1c2d3e-0000-4000-8000-000000000001/tool-results/shot.jpg");
    let jpg_before = fs::read(&jpg).unwrap();

    scrub_all(&d);

    for target in &d.targets {
        let content = fs::read(&target.path).unwrap();
        let text = String::from_utf8_lossy(&content);
        if target.path == jpg {
            continue;
        }
        assert!(
            !text.contains(GH_TOKEN),
            "{} still has secret",
            target.path.display()
        );
        assert!(
            !text.contains(AWS_KEY),
            "{} still has secret",
            target.path.display()
        );
        assert!(text.contains("[REDACTED:"), "{}", target.path.display());
    }
    assert_eq!(
        fs::read(&jpg).unwrap(),
        jpg_before,
        "binary must be untouched"
    );

    // history.jsonl stays valid JSONL.
    let hist = fs::read_to_string(t.claude.join("history.jsonl")).unwrap();
    for line in hist.lines() {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }

    // No temp files left behind anywhere.
    for e in walkdir::WalkDir::new(&t.home) {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy();
        assert!(
            !is_own_tempfile_name(&name),
            "leftover {}",
            e.path().display()
        );
    }
}

#[test]
fn claude_json_is_report_only_and_byte_identical() {
    let t = build_tree();
    let before = fs::read(&t.claude_json).unwrap();
    let backup = t
        .claude
        .join("backups")
        .join(".claude.json.backup.1700000000");
    let backup_before = fs::read(&backup).unwrap();

    // A full fix run must not touch it...
    let d = discover(&t, &LocationSet::all());
    scrub_all(&d);

    // ...and neither does reporting.
    let (ps, ec, al, bl) = fixtures();
    let findings = locations::report_claude_json(&t.claude_json, &ps, &ec, &al, &bl).unwrap();
    let backup_findings = locations::report_claude_json(&backup, &ps, &ec, &al, &bl).unwrap();

    assert_eq!(fs::read(&t.claude_json).unwrap(), before);
    assert_eq!(fs::read(&backup).unwrap(), backup_before);

    let paths: Vec<_> = findings.iter().map(|f| f.key_path.as_str()).collect();
    assert!(
        paths.contains(&"mcpServers.github.env.GITHUB_TOKEN"),
        "{paths:?}"
    );
    assert!(
        paths.contains(&r#"projects.["/Users/me/repo"].mcpServers.aws.env.AWS_ACCESS_KEY_ID"#),
        "{paths:?}"
    );
    // `${VAR}` references are the recommended fix, not a finding.
    assert!(!paths.iter().any(|p| p.ends_with("REF_TOKEN")), "{paths:?}");
    // Findings never carry the secret value.
    let dbg = format!("{findings:?}");
    assert!(!dbg.contains(GH_TOKEN) && !dbg.contains(AWS_KEY));
    assert_eq!(findings.len(), backup_findings.len());
}

#[test]
fn clean_plaintext_files_stay_byte_identical() {
    let tmp = tempfile::tempdir().unwrap();
    let (ps, ec, al, bl) = fixtures();
    let cases: &[&[u8]] = &[
        b"no secrets here\r\nsecond line\r\n",
        b"no trailing newline",
        b"mixed\nendings\r\n\n\n",
        b"",
        b"latin-1 \xe9t\xe9 bytes\nplain\n",
    ];
    for (i, content) in cases.iter().enumerate() {
        let p = tmp.path().join(format!("f{i}.txt"));
        fs::write(&p, content).unwrap();
        let mtime = fs::metadata(&p).unwrap().modified().unwrap();
        let r = plaintext::scrub_file(&p, &ps, &ec, &al, &bl, false).unwrap();
        assert_eq!(r.outcome, Outcome::Clean, "case {i}");
        assert_eq!(&fs::read(&p).unwrap(), content, "case {i}");
        assert_eq!(
            fs::metadata(&p).unwrap().modified().unwrap(),
            mtime,
            "case {i}"
        );
    }
    assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), cases.len());
}

#[test]
fn redaction_preserves_surrounding_bytes_line_numbers_and_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let (ps, ec, al, bl) = fixtures();
    let p = tmp.path().join("notes.txt");
    let original = format!("line one\r\ncaf\u{e9}\r\ntoken {GH_TOKEN} end\r\nlast");
    // Include a non-UTF-8 line so the per-line fallback is exercised.
    let mut bytes = original.clone().into_bytes();
    bytes.extend_from_slice(b"\n\xff\xfe raw\n");
    fs::write(&p, &bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Dry run: findings, file untouched.
    let r = plaintext::scrub_file(&p, &ps, &ec, &al, &bl, true).unwrap();
    assert_eq!(r.outcome, Outcome::Redacted { written: false });
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].line, 3);
    assert_eq!(r.findings[0].pattern_name, "github-token");
    assert_eq!(fs::read(&p).unwrap(), bytes);

    let r = plaintext::scrub_file(&p, &ps, &ec, &al, &bl, false).unwrap();
    assert_eq!(r.outcome, Outcome::Redacted { written: true });
    let mut expected = original
        .replace(GH_TOKEN, "[REDACTED:github-token]")
        .into_bytes();
    expected.extend_from_slice(b"\n\xff\xfe raw\n");
    assert_eq!(fs::read(&p).unwrap(), expected);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "permissions must not widen");
    }
    assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 1, "no temp left");

    // Idempotent.
    let r = plaintext::scrub_file(&p, &ps, &ec, &al, &bl, false).unwrap();
    assert_eq!(r.outcome, Outcome::Clean);
}

#[test]
fn binary_files_are_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let (ps, ec, al, bl) = fixtures();

    let pdf = tmp.path().join("doc.pdf");
    fs::write(&pdf, format!("%PDF-1.4 {GH_TOKEN}")).unwrap();
    let nul = tmp.path().join("blob.txt");
    let mut nul_bytes = b"head\0".to_vec();
    nul_bytes.extend_from_slice(GH_TOKEN.as_bytes());
    fs::write(&nul, &nul_bytes).unwrap();

    for p in [&pdf, &nul] {
        let before = fs::read(p).unwrap();
        let r = plaintext::scrub_file(p, &ps, &ec, &al, &bl, false).unwrap();
        assert_eq!(r.outcome, Outcome::SkippedBinary, "{}", p.display());
        assert_eq!(fs::read(p).unwrap(), before);
    }
}

#[test]
fn oversized_files_are_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let (ps, ec, al, bl) = fixtures();
    let p = tmp.path().join("huge.txt");
    let f = fs::File::create(&p).unwrap();
    f.set_len(plaintext::MAX_FILE_SIZE + 1).unwrap(); // sparse
    drop(f);
    let r = plaintext::scrub_file(&p, &ps, &ec, &al, &bl, false).unwrap();
    assert!(matches!(r.outcome, Outcome::SkippedTooLarge { .. }));
}

#[test]
fn json_files_stay_valid_after_redaction() {
    let tmp = tempfile::tempdir().unwrap();
    let (ps, ec, al, bl) = fixtures();
    // A valid JSON file with a secret gets redacted and stays valid.
    let ok = tmp.path().join("state.json");
    fs::write(&ok, format!(r#"{{"t":"{GH_TOKEN}"}}"#)).unwrap();
    let r = plaintext::scrub_file(&ok, &ps, &ec, &al, &bl, false).unwrap();
    assert_eq!(r.outcome, Outcome::Redacted { written: true });
    serde_json::from_slice::<serde_json::Value>(&fs::read(&ok).unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn symlinks_are_never_followed_out_of_claude_dir() {
    use std::os::unix::fs::symlink;

    let t = build_tree();
    let secret_outside = t.outside.join("secrets.txt");
    fs::write(&secret_outside, format!("{GH_TOKEN}\n")).unwrap();
    let outside_dir = t.outside.join("dir");
    fs::create_dir_all(&outside_dir).unwrap();
    fs::write(
        outside_dir.join("x.jsonl"),
        format!(r#"{{"k":"{GH_TOKEN}"}}"#) + "\n",
    )
    .unwrap();
    let outside_plans = t.outside.join("plans");
    fs::create_dir_all(&outside_plans).unwrap();
    fs::write(outside_plans.join("p.md"), format!("{GH_TOKEN}\n")).unwrap();

    // File symlink, directory symlink, and a whole location root symlinked out.
    symlink(
        &secret_outside,
        t.claude.join("file-history").join("link@v1"),
    )
    .unwrap();
    symlink(&outside_dir, t.claude.join("projects").join("linked-proj")).unwrap();
    fs::remove_dir_all(t.claude.join("plans")).unwrap();
    symlink(&outside_plans, t.claude.join("plans")).unwrap();

    let d = discover(&t, &LocationSet::all());
    for target in &d.targets {
        let canon = fs::canonicalize(&target.path).unwrap();
        assert!(
            !canon.starts_with(fs::canonicalize(&t.outside).unwrap()),
            "{}",
            target.path.display()
        );
    }
    assert!(d.symlinks_skipped.len() >= 3, "{:?}", d.symlinks_skipped);

    scrub_all(&d);
    assert!(
        fs::read_to_string(&secret_outside)
            .unwrap()
            .contains(GH_TOKEN)
    );
    assert!(
        fs::read_to_string(outside_dir.join("x.jsonl"))
            .unwrap()
            .contains(GH_TOKEN)
    );
    assert!(
        fs::read_to_string(outside_plans.join("p.md"))
            .unwrap()
            .contains(GH_TOKEN)
    );

    // The plain-text scrubber also refuses a symlink given to it directly.
    let (ps, ec, al, bl) = fixtures();
    let r = plaintext::scrub_file(
        &t.claude.join("file-history").join("link@v1"),
        &ps,
        &ec,
        &al,
        &bl,
        false,
    )
    .unwrap();
    assert_eq!(r.outcome, Outcome::SkippedSymlink);
}

#[test]
fn tempfile_name_matcher_matches_what_the_tool_creates() {
    let tmp = tempfile::tempdir().unwrap();
    for _ in 0..20 {
        let f = tempfile::NamedTempFile::new_in(tmp.path()).unwrap();
        let name = f.path().file_name().unwrap().to_str().unwrap().to_string();
        assert!(is_own_tempfile_name(&name), "{name}");
    }
    for name in [
        ".tmp",
        ".tmpABC12",
        ".tmpABC1234",
        "tmpABC123",
        ".tmpAB-123",
        "x.tmpABC123",
        ".tmpABC123.jsonl",
        "history.jsonl.tmp",
    ] {
        assert!(!is_own_tempfile_name(name), "{name}");
    }
}

#[test]
fn orphan_cleanup_respects_age_and_naming() {
    let t = build_tree();
    let proj = t.claude.join("projects").join("-Users-me-repo");
    let old = proj.join(".tmpAb12Cd");
    let fresh = proj.join(".tmpZz99Yy");
    let top = t.claude.join(".tmpQw34Er"); // left by a history.jsonl rewrite
    let not_ours = proj.join(".tmp-something");
    let fh_old = t.claude.join("file-history").join(".tmpOl0Df1");
    for p in [&old, &fresh, &top, &not_ours, &fh_old] {
        write(p, format!(r#"{{"k":"{GH_TOKEN}"}}"#));
    }
    set_age(&old, Duration::from_hours(2));
    set_age(&top, Duration::from_hours(2));
    set_age(&not_ours, Duration::from_hours(2));
    set_age(&fh_old, Duration::from_mins(90));
    set_age(&fresh, Duration::from_mins(10));

    let now = SystemTime::now();
    let d = discover(&t, &LocationSet::all());
    let listed: Vec<&PathBuf> = d.orphans.iter().map(|o| &o.path).collect();
    assert!(listed.contains(&&old) && listed.contains(&&fresh));
    assert!(listed.contains(&&top) && listed.contains(&&fh_old));
    assert!(!listed.contains(&&not_ours));
    // Orphans are never scan targets.
    assert!(
        d.targets
            .iter()
            .all(|t| !is_own_tempfile_name(&t.path.file_name().unwrap().to_string_lossy()))
    );

    for o in &d.orphans {
        locations::remove_stale_orphan(o, now).unwrap();
    }
    assert!(!old.exists() && !top.exists() && !fh_old.exists());
    assert!(fresh.exists(), "orphans younger than 1h must be kept");
    assert!(not_ours.exists());

    // Skipping orphan-temps means nothing is even listed.
    let d = discover(
        &t,
        &LocationSet::from_flags(false, &[Location::OrphanTemps]),
    );
    assert!(d.orphans.is_empty());
}

#[cfg(unix)]
#[test]
fn orphan_removal_ignores_symlinks_and_recent_files() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("real");
    fs::write(&target, "x").unwrap();
    set_age(&target, Duration::from_hours(3));
    let link = tmp.path().join(".tmpLnk123");
    symlink(&target, &link).unwrap();

    let orphan = Orphan {
        path: link.clone(),
        age: Some(Duration::from_hours(3)),
    };
    assert!(!locations::remove_stale_orphan(&orphan, SystemTime::now()).unwrap());
    assert!(link.exists() && target.exists());

    // Stale at discovery time but touched since: re-checked on disk, kept.
    let recent = tmp.path().join(".tmpNew456");
    fs::write(&recent, "x").unwrap();
    let orphan = Orphan {
        path: recent.clone(),
        age: Some(Duration::from_hours(3)),
    };
    assert!(!locations::remove_stale_orphan(&orphan, SystemTime::now()).unwrap());
    assert!(recent.exists());
}
