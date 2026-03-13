# RFC-002: Status Output Redesign

**Status:** Draft
**Date:** 2026-03-13

## Problem

`scrub-history status` currently produces functional but rough terminal output. Specific issues:

1. **Hand-rolled ANSI escapes.** Six `pub const` values (`BOLD`, `DIM`, `GREEN`, etc.) in `display.rs` are raw `\x1b[…m` strings. This bypasses TTY detection — ANSI codes are emitted even when piped to a file or `less`. The `colored` crate (already in `Cargo.toml`) handles this automatically and supports `NO_COLOR`/`FORCE_COLOR` per the [console standards](https://no-color.org/).

2. **Fragile manual alignment.** Key-value pairs use hardcoded spaces (`"  Stop hook:  "`, `"  Patterns:    "`) with inconsistent column widths across sections. Adding or renaming a key requires recounting spaces.

3. **No visual section separation.** Section headers are plain bold text (`{BOLD}Stats{RESET}`) with blank lines above. In a 40+ line output, sections blur together — especially in a busy terminal with other output above.

4. **Repetitive println patterns.** Each key-value line is a bespoke `println!` with inline ANSI interpolation. The status function is ~180 lines of formatting boilerplate that obscures the actual logic.

5. **Inconsistent empty states.** Some sections show `{DIM}empty{RESET}`, others `{DIM}No scan runs recorded yet{RESET}`, others show nothing. No unified convention.

## Goals

- Clean, scannable output with clear section boundaries
- Consistent key-value alignment within and across sections
- Proper TTY/color detection (no ANSI when piped)
- Minimal new dependencies (use what's already in `Cargo.toml`)
- Maintainable: adding a new key-value pair should be a one-liner

## Non-Goals

- Interactive/TUI dashboard (ratatui) — this is a one-shot print
- Machine-readable output (`--json`) — can be added later orthogonally
- Replacing `colored` with `owo-colors` — `colored` is already a dep and works fine

## Design

### Visual Style

```
scrub-history v0.3.0

── Hook Configuration ──────────────────────────
  Stop hook           installed (async)

── Config ──────────────────────────────────────
  scrubber.toml       present

── Detection ───────────────────────────────────
  Patterns            12 built-in + 3 custom = 15 total
  Allowlist           5 hashes
  Blacklist           empty

── Recent Redactions ───────────────────────────
  2026-03-12 14:22 UTC   3 redactions  [...]/conversation.jsonl
  2026-03-11 09:15 UTC   1 redaction   [...]/history.jsonl

── Stats ───────────────────────────────────────
  Last run            2026-03-12 14:22:01 UTC (1 hour ago)
  Last file           [...]/conversation.jsonl (42.3 KB)
  Last time           312ms
  Latency             ▁▃▅▂▇▄▁▃  (last 8 runs)
  Redactions          ▁▁▃▁█▁▁▃  (24 total)

── Last Scan Run ───────────────────────────────
  When                2026-03-12 10:00:00 UTC (5 hours ago)
  Mode                live
  Files               128 scanned, 45 cached, 3 modified
  Redactions          7
  Errors              0
  Duration            1.2s
  Throughput          9.4ms/file

── Coverage ────────────────────────────────────
  History files       312
  Total size          48.2 MB
```

### Visual Rules

| Element | Style | Rationale |
|---|---|---|
| Section separator `──` | dimmed | Visible structure without dominating |
| Section name | bold | Scannable anchors for the eye |
| Section rule fill `────` | dimmed | Extends separator to fixed width, guides the eye |
| Key column | plain text, left-aligned, fixed 20-char width | Consistent alignment across all sections |
| Value: good status | green (`installed`, `present`) | Convention: green = healthy |
| Value: bad status | red (`not installed`, errors) | Convention: red = needs attention |
| Value: warning | yellow (`absent`) | Convention: yellow = degraded but not broken |
| Value: empty/placeholder | dimmed (`empty`, `No data yet`) | De-emphasizes missing data |
| Hint text | dimmed (`(run \`scrub-history init\`)`) | Actionable but secondary |
| Sparklines | green | Draws attention to the visual data |
| Indent | 2 spaces | Consistent nesting under section headers |

Section headers use the box-drawing character `─` (U+2500) at a fixed total width of 50 characters. This pattern is widely used (Python Rich's `console.rule()`, pixi, cargo-info) and renders correctly on all modern terminals.

### Rendering Helpers

Three new public functions in `display.rs`, replacing the six raw ANSI constants:

```rust
use colored::Colorize;

const SECTION_WIDTH: usize = 50;

/// Print a section header: `── Name ────────────────`
pub fn section(name: &str) {
    // Note: assumes ASCII section names. "── " is 3 display columns
    // (2 box-drawing chars + 1 space), but 7 bytes. We count display
    // columns here since "─".repeat(fill) also produces one display
    // column per repeat.
    let used = 3 + name.len() + 1; // "── " + name + " "
    let fill = SECTION_WIDTH.saturating_sub(used);
    println!("\n{} {} {}",
        "──".dimmed(), name.bold(), "─".repeat(fill).dimmed());
}

/// Print an aligned key-value row.
pub fn kv(key: &str, value: impl std::fmt::Display) {
    println!("  {:<20}{}", key, value);
}

/// Print a dimmed placeholder line.
pub fn empty(msg: &str) {
    println!("  {}", msg.dimmed());
}
```

These live in `display.rs` rather than locally in `status.rs` because:
- `display.rs` is already the shared formatting module
- `init.rs` and future commands can reuse the same visual vocabulary
- Keeps the section/kv rendering testable in one place

### Status.rs Transformation

The rewrite replaces bespoke `println!` calls with helper calls. Before:

```rust
println!("{BOLD}Hook Configuration{RESET}");
// ...
println!("  Stop hook:  {GREEN}installed{RESET} ({mode})");
// ...
println!("  {DIM}No hook runs recorded yet{RESET}");
```

After:

```rust
display::section("Hook Configuration");
display::kv("Stop hook", format!("{} ({mode})", "installed".green()));
display::empty("No hook runs recorded yet");
```

The `Recent Redactions` section has a non-standard layout (timestamp + count + filename), so it uses `colored` directly in `println!` rather than forcing through `kv()`. The helpers are conveniences, not straitjackets.

### Init.rs Migration

Three lines in `init.rs` use the raw ANSI constants. Migrate to `colored`:

```rust
// Before
println!("{BOLD}Configuring scrub-history...{RESET}");
println!("2. Hook already present in {} {GREEN}✓{RESET}", path);

// After
println!("{}", "Configuring scrub-history...".bold());
println!("2. Hook already present in {} {}", path, "✓".green());
```

### Constant Removal

After migrating both consumers, delete the six `pub const` ANSI escapes from `display.rs`. This prevents regression back to raw escapes.

## Changes Required

| File | Change |
|---|---|
| `src/display.rs` | Add `section()`, `kv(impl Display)`, `empty()` helpers; remove 6 ANSI constants; add `use colored::Colorize` |
| `src/commands/status.rs` | Full rewrite of `run_status_inner()` using helpers and `colored`; remove ANSI constant imports |
| `src/commands/init.rs` | Replace 3 lines using ANSI constants with `colored` equivalents |

### New Dependencies

None. `colored = "3"` is already in `Cargo.toml`.

## Alternatives Considered

**1. `rich_rust` (Rust port of Python's Rich)**
Provides `Panel`, `Table`, `Rule` primitives with a markup DSL (`[bold]text[/]`). Beautiful output, but adds a heavy dependency for what amounts to three small helper functions. The visual result would be nearly identical — `rich_rust`'s `console.rule()` produces the same `── Name ────` pattern we're implementing directly.

**2. `comfy-table` / `tabled`**
Table-formatting crates with borders, alignment, and column auto-sizing. Better suited for actual tabular data (rows × columns). Our status output is key-value pairs grouped into sections — not really a table. Forcing it into a table adds borders and structure that make it look more cluttered, not cleaner.

**3. `termimad`**
Renders Markdown in the terminal. We'd write status output as Markdown with tables, and `termimad` handles styling and wrapping. Clever for documentation-heavy output, but indirect for a status dashboard. Also adds a dependency.

**4. `owo-colors` instead of `colored`**
Recommended by Rain's Rust CLI guide as the best color crate (zero-alloc, better `NO_COLOR` support). However, `colored` is already in `Cargo.toml` and used elsewhere. Switching gains marginal improvement for unnecessary churn in unrelated code. Could be done separately if desired.

**5. `ratatui` TUI**
Full terminal UI framework with widgets, layouts, and event loops. Massive overkill for a one-shot status print. Would also change the UX from "print and exit" to "launch an app".

**6. Keep raw ANSI, just add alignment helpers**
Lowest churn, but leaves the TTY detection gap. Users piping `scrub-history status` to a file or `grep` would get garbage ANSI escapes. `colored` solves this for free.

**7. Use `console::style()` from `indicatif`'s transitive `console` dep**
`indicatif = "0.18.4"` is already in `Cargo.toml` and pulls in the `console` crate, which has its own `style()` API. However, `colored` is a direct dependency and provides a simpler trait-based API (`"text".green()` vs `style("text").green()`). Standardizing on `colored` avoids coupling our formatting to a transitive dependency that could change if `indicatif` is updated or removed.

## Clippy Considerations

The `print_stdout` restriction lint is enabled project-wide. The new `display.rs` helpers print directly to stdout (that's their purpose), so they need `#[allow(clippy::print_stdout)]`. The alternative — returning `String` and having callers `println!` — adds boilerplate for no real benefit, since these functions are inherently about terminal output.

## Resolved Questions

1. **Column width: 20 vs dynamic?** Fixed 20. The longest current key is "Throughput" at 10 chars, so there's plenty of headroom. Dynamic widths create visual instability across runs (adding a key shifts all alignment). Revisit only if a key approaches 20 chars.

2. **Should `display.rs` expose a `StatusLine` builder?** Not now. Three helper functions serve current needs. A builder is warranted when there's combinatorial styling (key + value + suffix + hint, each with independent colors). We're not there yet. Revisit if a second command needs rich multi-part status lines.

3. **Section width: 50 fixed vs terminal width?** Fixed 50. Terminal-width detection adds runtime edge cases (what if `terminal_size` returns `None`? what about CI?). Fixed 50 looks fine on any width ≥50, which covers all reasonable terminals.
