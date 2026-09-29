//! Wall-clock benchmarks (criterion) for local use. Same cases and corpus as
//! the instruction-count regression benches in `hook_regression.rs`, which
//! are the ones CI gates on. See README "Benchmarks".

mod common;

use std::hint::black_box;

use common::{Fixture, P50_BYTES};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use scrub_history::scrubber::scrub_text;
use tempfile::TempDir;

fn bench_scrub_text(c: &mut Criterion) {
    let fx = Fixture::new();
    let clean = common::text_chunk();
    let non_ascii = clean.replace('\n', " →\n");
    let with_secret = clean.clone() + &common::secret_line();

    let mut group = c.benchmark_group("scrub_text");
    for (name, text) in [
        ("clean", &clean),
        ("non_ascii", &non_ascii),
        ("with_secret", &with_secret),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| {
                scrub_text(
                    black_box(text),
                    &fx.patterns,
                    &fx.entropy,
                    &fx.allowlist,
                    &fx.blacklist,
                )
            });
        });
    }
    group.finish();
}

fn bench_scrub_file(c: &mut Criterion) {
    let fx = Fixture::new();
    let base = common::transcript(P50_BYTES);
    let turn = common::turn();
    let secret = common::secret_line();

    // Already-scrubbed transcript and its offset, as the hook sees it.
    let dir = TempDir::new().unwrap();
    let seed = common::write_file(dir.path(), "seed.jsonl", &base);
    let offset = fx.scrub(&seed, None);
    let scrubbed = std::fs::read_to_string(&seed).unwrap();

    let mut group = c.benchmark_group("scrub_file_p50");
    group.bench_function("cold", |b| {
        b.iter_batched(
            || {
                let d = TempDir::new().unwrap();
                let p = common::write_file(d.path(), "s.jsonl", &base);
                (d, p)
            },
            |(_d, p)| fx.scrub(&p, None),
            BatchSize::PerIteration,
        );
    });
    for (name, extra) in [
        ("incremental_clean", ""),
        ("incremental_secret", secret.as_str()),
    ] {
        group.bench_function(name, |b| {
            b.iter_batched(
                || {
                    let d = TempDir::new().unwrap();
                    let p = common::write_file(d.path(), "s.jsonl", &scrubbed);
                    common::append(&p, &turn);
                    common::append(&p, extra);
                    (d, p)
                },
                |(_d, p)| fx.scrub(&p, Some(offset)),
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_scrub_text, bench_scrub_file);
criterion_main!(benches);
