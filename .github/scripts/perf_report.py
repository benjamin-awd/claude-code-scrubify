#!/usr/bin/env python3
"""Render gungraun `summary.json` files as a markdown instruction-count table.

Usage: perf_report.py GUNGRAUN_HOME MODE

MODE is how the head run was compared: `enforced` (limits applied),
`report-only` (benchmark corpus changed, numbers not comparable) or
`no-base` (base commit has no regression benchmarks). The failure threshold
is read from `PERF_LIMITS` (e.g. `ir=10%`), same as the CI gate.
"""

import json
import os
import re
import sys
from pathlib import Path

# Changes smaller than this are within run-to-run noise (~0.5%).
NOISE_PCT = 2.0


def limit_pct() -> float:
    m = re.search(r"\bir=([0-9.]+)%", os.environ.get("PERF_LIMITS", ""))
    return float(m.group(1)) if m else 10.0


def rows(home: Path):
    for path in sorted(home.rglob("summary.json")):
        s = json.loads(path.read_text())
        name = s["function_name"] + (f" / {s['id']}" if s.get("id") else "")
        ir = s["profiles"][0]["data"]["total"]["metrics"]["Ir"]
        values = ir["values"]
        change = ir.get("change")
        pct = float(change["diff_pct"]) if change else None
        yield name, values.get("old"), values["new"], pct


def marker(pct, limit):
    if pct is None:
        return "🆕"
    if pct > limit:
        return "🔴"
    if pct > NOISE_PCT:
        return "🟠"
    if pct < -NOISE_PCT:
        return "🟢"
    return "⚪"


def main() -> None:
    home, mode = Path(sys.argv[1]), sys.argv[2]
    limit = limit_pct()
    table = list(rows(home))

    out = ["## Perf: instruction counts (Callgrind)", ""]
    if mode == "report-only":
        out += ["> ⚠️ The benchmark corpus (`benches/common`) changed in this PR, so base and head ran on different inputs. Limits were not enforced.", ""]
    elif mode == "no-base":
        out += ["> The base commit has no regression benchmarks; showing head only.", ""]
    if not table:
        out.append("No benchmark results found.")
    else:
        out += ["| | Benchmark | Base | Head | Change |", "|---|---|--:|--:|--:|"]
        for name, old, new, pct in table:
            base = f"{old:,}" if old is not None else "–"
            delta = f"{pct:+.2f}%" if pct is not None else "new"
            out.append(f"| {marker(pct, limit)} | `{name}` | {base} | {new:,} | {delta} |")
        out += [
            "",
            f"🔴 over the {limit:g}% limit (fails CI) · 🟠 slower · 🟢 faster · ⚪ within ±{NOISE_PCT:g}% (noise) · 🆕 no base",
        ]
    print("\n".join(out))


if __name__ == "__main__":
    main()
