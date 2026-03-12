use std::io::Write;

use criterion::{Criterion, criterion_group, criterion_main};
use scrub_history::allowlist::Allowlist;
use scrub_history::entropy::EntropyConfig;
use scrub_history::jsonl::scrub_jsonl_file;
use scrub_history::patterns::PatternSet;

/// Fake secrets sprinkled into synthetic messages.
const FAKE_GH_TOKEN: &str = "ghp_R4nd0mF4keT0kenV4lueABCDEFGHIJKLMnopqr";
const FAKE_AWS_KEY: &str = "AKIAIOSFODNN7FAKEXYZ";
const FAKE_ANTHROPIC_KEY: &str = "sk-ant-api03-fakekey1234567890abcdefghijklmnop";

/// Build a synthetic JSONL corpus that exercises the hot-path of hook mode:
/// mixed message types, scattered secrets, and realistic sizes.
fn build_corpus(num_lines: usize) -> String {
    let mut lines = Vec::with_capacity(num_lines);

    for i in 0..num_lines {
        let line = match i % 6 {
            // System message (should be skipped entirely)
            0 => r#"{"type":"system","content":"You are a helpful assistant."}"#.to_string(),

            // User message — clean (majority of lines in a real transcript)
            1 => r#"{"type":"user","message":{"content":"Please refactor the parse_config function in src/config.rs to use the builder pattern. I want it to validate inputs eagerly and return descriptive errors. Here is the current implementation which is about 120 lines of Rust code."}}"#.to_string(),

            // User message — contains a GitHub token
            2 => format!(
                r#"{{"type":"user","message":{{"content":"I set the env var GITHUB_TOKEN={FAKE_GH_TOKEN} but the CI still fails. Can you check why?"}}}}"#
            ),

            // Assistant text reply — contains AWS key in a code block
            3 => format!(
                r#"{{"type":"assistant","message":{{"content":[{{"type":"text","text":"I found the issue. Your config has the access key {FAKE_AWS_KEY} hard-coded. You should use an IAM role instead. Let me show you the recommended approach using environment variables and the AWS SDK credential chain."}}]}}}}"#
            ),

            // Assistant tool_use — clean
            4 => r#"{"type":"assistant","message":{"content":[{"type":"tool_use","input":{"command":"cargo test --release -- --nocapture"}}]}}"#.to_string(),

            // User message — contains Anthropic key in a JSON blob
            5 => format!(
                r#"{{"type":"user","message":{{"content":{{"api_key":"{FAKE_ANTHROPIC_KEY}","model":"claude-sonnet-4-20250514"}}}}}}"#
            ),

            _ => unreachable!(),
        };
        lines.push(line);
    }

    lines.join("\n") + "\n"
}

fn bench_scrub_jsonl(c: &mut Criterion) {
    let pattern_set = PatternSet::load(true).expect("failed to load patterns");
    let entropy_cfg = EntropyConfig {
        enabled: true,
        ..Default::default()
    };
    let allowlist = Allowlist::empty();

    // ~500 lines ≈ a medium-length Claude conversation
    let corpus_500 = build_corpus(500);

    // ~2000 lines ≈ a long session
    let corpus_2000 = build_corpus(2000);

    let mut group = c.benchmark_group("scrub_jsonl");

    group.bench_function("500_lines", |b| {
        b.iter_batched(
            || {
                let mut f = tempfile::NamedTempFile::new().unwrap();
                f.write_all(corpus_500.as_bytes()).unwrap();
                f.flush().unwrap();
                f
            },
            |f| {
                scrub_jsonl_file(f.path(), &pattern_set, &entropy_cfg, &allowlist, false).unwrap();
            },
            criterion::BatchSize::PerIteration,
        );
    });

    group.bench_function("2000_lines", |b| {
        b.iter_batched(
            || {
                let mut f = tempfile::NamedTempFile::new().unwrap();
                f.write_all(corpus_2000.as_bytes()).unwrap();
                f.flush().unwrap();
                f
            },
            |f| {
                scrub_jsonl_file(f.path(), &pattern_set, &entropy_cfg, &allowlist, false).unwrap();
            },
            criterion::BatchSize::PerIteration,
        );
    });

    group.finish();
}

/// Hard gate: hook mode must finish a 500-line transcript in under 100ms.
/// This runs as a standalone benchmark so CI can assert on it.
fn bench_hook_latency_gate(c: &mut Criterion) {
    let pattern_set = PatternSet::load(true).expect("failed to load patterns");
    let entropy_cfg = EntropyConfig {
        enabled: true,
        ..Default::default()
    };
    let allowlist = Allowlist::empty();
    let corpus = build_corpus(500);

    c.bench_function("hook_latency_gate_500_lines", |b| {
        b.iter_batched(
            || {
                let mut f = tempfile::NamedTempFile::new().unwrap();
                f.write_all(corpus.as_bytes()).unwrap();
                f.flush().unwrap();
                f
            },
            |f| {
                scrub_jsonl_file(f.path(), &pattern_set, &entropy_cfg, &allowlist, false).unwrap();
            },
            criterion::BatchSize::PerIteration,
        );
    });
}

criterion_group!(benches, bench_scrub_jsonl, bench_hook_latency_gate);
criterion_main!(benches);
