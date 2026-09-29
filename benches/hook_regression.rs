//! Instruction-count regression benchmarks for the hook hot paths.
//!
//! Runs under Valgrind/Callgrind via gungraun (Linux only), so results are
//! deterministic enough to gate CI on. See README "Benchmarks".
//!
//! Setup functions (fixtures, writing and pre-scrubbing files) are not
//! measured; only the call inside each benchmark body is.

// gungraun's `main!` harness exits the process itself.
#![allow(clippy::exit)]

mod common;

use std::hint::black_box;
use std::path::PathBuf;

use common::{Fixture, P50_BYTES};
use gungraun::{library_benchmark, library_benchmark_group, main};
use scrub_history::entropy::EntropyConfig;
use scrub_history::patterns::PatternSet;
use scrub_history::scrubber::scrub_text;
use tempfile::TempDir;

// Per-invocation startup: compiling the built-in pattern set.
#[library_benchmark]
fn load_patterns() -> PatternSet {
    black_box(PatternSet::load(true).unwrap())
}

fn clean_text() -> (Fixture, String) {
    (Fixture::new(), common::text_chunk())
}

/// Real transcripts are full of `→`, `—`, emoji…; non-ASCII text is what
/// used to push the pattern `RegexSet` off its lazy DFA.
fn non_ascii_text() -> (Fixture, String) {
    (Fixture::new(), common::text_chunk().replace('\n', " →\n"))
}

fn secret_text() -> (Fixture, String) {
    let (fx, mut text) = clean_text();
    text.push_str(&common::secret_line());
    (fx, text)
}

// The dominant case: text with nothing to redact.
#[library_benchmark]
#[bench::clean(setup = clean_text)]
#[bench::non_ascii(setup = non_ascii_text)]
#[bench::with_secret(setup = secret_text)]
fn scrub_text_chunk((fx, text): (Fixture, String)) -> usize {
    let (out, redactions) = scrub_text(
        black_box(&text),
        &fx.patterns,
        &fx.entropy,
        &fx.allowlist,
        &fx.blacklist,
    );
    black_box(out.len() + redactions.len())
}

type FileCase = (Fixture, TempDir, PathBuf, Option<u64>);

fn cold(fx: Fixture) -> FileCase {
    let dir = TempDir::new().unwrap();
    let path = common::write_file(dir.path(), "s.jsonl", &common::transcript(P50_BYTES));
    (fx, dir, path, None)
}

fn cold_default() -> FileCase {
    cold(Fixture::new())
}

/// Entropy exclude patterns configured: catches per-string regex compiles.
fn cold_with_exclude() -> FileCase {
    cold(Fixture::with_entropy(EntropyConfig {
        exclude_patterns: vec![r"toolu_[A-Za-z0-9]+".to_string()],
        ..Default::default()
    }))
}

/// Already-scrubbed p50 transcript plus one appended turn (the Stop hook case).
fn incremental(extra: &str) -> FileCase {
    let (fx, dir, path, _) = cold_default();
    let offset = fx.scrub(&path, None);
    common::append(&path, &common::turn());
    common::append(&path, extra);
    (fx, dir, path, Some(offset))
}

fn incremental_clean() -> FileCase {
    incremental("")
}

fn incremental_secret() -> FileCase {
    incremental(&common::secret_line())
}

#[library_benchmark]
#[bench::cold(setup = cold_default)]
#[bench::cold_with_exclude(setup = cold_with_exclude)]
#[bench::incremental_clean(setup = incremental_clean)]
#[bench::incremental_secret(setup = incremental_secret)]
fn scrub_file((fx, _dir, path, offset): FileCase) -> u64 {
    black_box(fx.scrub(black_box(&path), offset))
}

library_benchmark_group!(
    name = hook;
    benchmarks = load_patterns, scrub_text_chunk, scrub_file
);

main!(library_benchmark_groups = hook);
