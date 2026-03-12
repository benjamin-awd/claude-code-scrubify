# ADR-001: Error Handling Strategy

## Status

Accepted

## Context

We need to decide on an error handling approach for scrub-history. The Rust ecosystem offers several options:

- **`anyhow`** — Opaque, context-rich errors for applications. No custom types needed.
- **`thiserror`** — Derive macro for `std::error::Error` on custom enum types. Good for libraries or when callers need to match on variants.
- **`snafu`** — Similar to `thiserror` but with context selectors, backtrace support, and module-scoped error types. Designed for large codebases with many distinct error domains.

scrub-history currently has a small error surface:
- File I/O errors (open, read lines, write temp, persist)
- JSON parse errors
- Missing `HOME` environment variable
- Hook input deserialization errors

All error paths today either bubble up to `main()` (which prints and exits) or are logged as warnings and skipped (malformed JSON lines, unreadable lines).

## Decision

Use **`anyhow`** for error handling. Do not introduce `thiserror` or `snafu` at this time.

### Rationale

1. **Small error surface** — We have ~4 error cases, all handled uniformly (log or propagate). There are no callers that need to match on specific error variants.
2. **Application, not library** — `anyhow` is designed for applications where errors are ultimately displayed to a human. We don't expose a public API where typed errors help downstream consumers.
3. **Low boilerplate** — `anyhow::Result` + `.context()` gives us rich error messages with zero enum definitions.
4. **`snafu` is overkill** — `snafu`'s context selectors and module-scoped error types pay off in large codebases with hundreds of components and distinct failure modes. scrub-history doesn't have this problem.

## When to Reconsider

Migrate to `thiserror` or `snafu` if any of these become true:

- **Library extraction** — If `scrub_jsonl_file` or the scanner are published as a crate, callers will need typed errors to decide how to handle failures (e.g., skip vs retry vs abort).
- **Variant-specific recovery** — If we need to handle different errors differently at the call site (e.g., retry on I/O timeout, skip on parse error, abort on permission denied).
- **Error count exceeds ~8-10 variants** — At that point, ad-hoc strings become hard to maintain and typed enums pay for themselves.
- **Multiple modules with distinct error domains** — If scan, hook, and jsonl each develop their own failure modes that callers need to distinguish.

## What It Could Look Like

If we migrated to `thiserror`, the jsonl module would define:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScrubError {
    #[error("failed to open {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to create temp file in {dir}")]
    TempFile {
        dir: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to persist temp file to {path}")]
    Persist {
        path: PathBuf,
        #[source]
        source: tempfile::PersistError,
    },

    #[error("JSON serialization error")]
    Json(#[from] serde_json::Error),
}
```

The `snafu` equivalent would use context selectors instead:

```rust
use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
pub enum ScrubError {
    #[snafu(display("failed to open {path}"))]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to create temp file in {dir}"))]
    TempFile {
        dir: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to persist to {path}"))]
    Persist {
        path: PathBuf,
        source: tempfile::PersistError,
    },

    #[snafu(display("JSON serialization error"))]
    Json { source: serde_json::Error },
}

// Usage with snafu context selectors:
// fs::File::open(&path).context(OpenSnafu { path: &path })?;
```

The key `snafu` advantage is that `OpenSnafu { path }` context selectors are generated automatically and are type-safe — you can't accidentally attach the wrong context to the wrong error. In `thiserror`, you'd manually construct the enum variant. This matters more as variant count grows.

For scrub-history today, both would be unnecessary ceremony around what `anyhow::context("opening {path}")` already does in one line.

## Consequences

- Error messages are freeform strings — typos or inconsistencies won't be caught at compile time.
- Callers cannot `match` on error variants (acceptable since all callers just log and continue or propagate to `main`).
- If we later extract a library crate, we'll need to retrofit typed errors at that boundary.
