# scrub-history

A tool that automatically redacts secrets and sensitive information from [Claude Code](https://docs.anthropic.com/en/docs/claude-code) chat history files.

## Why

Claude Code stores conversation transcripts as JSONL files under `~/.claude/projects/`. These transcripts can inadvertently capture API keys, tokens, passwords, and other secrets that appear in your terminal or code. `scrub-history` finds and replaces these with `[REDACTED:pattern-name]` tags.

## Features

- **30+ built-in secret patterns** — AWS keys, GitHub/GitLab tokens, JWTs, private keys, GCP service-account keys, database connection strings, Stripe/Slack/OpenAI/Anthropic/Grafana/Vault keys, and more
- **Entropy-based detection** — catches high-entropy strings that look like tokens even without a known pattern
- **Two modes** — run as a Claude Code hook (real-time) or bulk-scan all history files
- **Custom patterns** — add your own as `[[patterns]]` in `~/.claude/scrubber.toml`
- **Dry-run** — preview what would be redacted before modifying anything
- **Safe writes** — atomic temp-file writes prevent corruption

## Status dashboard

```
scrub-history status
```

<img src="docs/status.png" alt="scrub-history status output" width="500">

## Install

```bash
cargo install --path .
```

## Usage

### Scan mode

Preview what would be redacted without modifying files:

```bash
scrub-history scan
```

Scan all JSONL history files under `~/.claude/projects/` and redact secrets in place:

```bash
scrub-history scan --fix
```

### Hook mode

Run the setup wizard (interactive) to install the hooks and create the config:

```bash
scrub-history init
```

It registers `scrub-history hook` for these Claude Code [hook events](https://code.claude.com/docs/en/hooks), all of which pass the session's `transcript_path` on stdin:

| Event | When | Mode |
|---|---|---|
| `Stop` | after each assistant turn | async or sync (your choice) |
| `SubagentStop` | when a subagent finishes | async or sync (your choice) |
| `PreCompact` | before the transcript is compacted | always sync |
| `SessionEnd` | on exit / `/clear`, so interrupted turns still get scrubbed | always sync (Claude Code runs these synchronously), 30s timeout |

The resulting `~/.claude/settings.json` looks like this (event names are case-sensitive):

```json
{
  "hooks": {
    "Stop": [
      {
        "matcher": "",
        "hooks": [
          { "type": "command", "command": "'/Users/you/.cargo/bin/scrub-history' hook", "async": true }
        ]
      }
    ],
    "SubagentStop": [
      {
        "matcher": "",
        "hooks": [
          { "type": "command", "command": "'/Users/you/.cargo/bin/scrub-history' hook", "async": true }
        ]
      }
    ],
    "PreCompact": [
      {
        "matcher": "",
        "hooks": [
          { "type": "command", "command": "'/Users/you/.cargo/bin/scrub-history' hook" }
        ]
      }
    ],
    "SessionEnd": [
      {
        "matcher": "",
        "hooks": [
          { "type": "command", "command": "'/Users/you/.cargo/bin/scrub-history' hook", "timeout": 30 }
        ]
      }
    ]
  }
}
```

Notes:

- The command is the **absolute, canonical path** of the binary that ran `init`, shell-quoted. It is not looked up through `PATH`, so another `scrub-history` earlier in `PATH` can't take over the hook and read your chat history. If you move or reinstall the binary, re-run `init`. `scrub-history status` warns if a hook command is not an absolute path.
- Re-running `init` is safe. It upgrades existing entries in place, including the old bare `scrub-history hook` form, and doesn't add duplicates. Before changing `settings.json` it writes a timestamped backup (`settings.json.bak-YYYYMMDD-HHMMSS`). It then replaces the file atomically, keeping its permissions and key order.
- The hook scrubs the transcript in place, along with any subagent transcripts for that session.

### Options

```
-v, --verbose              Enable debug logging (-vv for trace)
-q, --quiet                Suppress all output except errors
--no-entropy               Disable entropy-based detection
--entropy-threshold <F>    Shannon entropy threshold (default: 4.5)
```

Scan-specific:

```
--fix                      Apply redactions (default: dry-run preview only)
--no-truncate              Show FULL secret values in the dry-run preview (dangerous)
--no-cache                 Ignore the mtime cache and rescan everything
-j, --jobs <N>             Max parallel threads
```

The dry-run preview never prints a recoverable secret. For each match it shows the file, line number, pattern name and length. Secrets of 20 or more characters also show their first 4 characters (e.g. `ghp_… <40 chars>`). Debug logging (`-v`) uses the same format. This matters because dry-run output often ends up in a *new* Claude Code transcript when you run it from inside Claude Code. `--no-truncate` prints a warning to stderr and then shows full values. Only use it in a plain terminal.

## Configuration

Settings live in `~/.claude/scrubber.toml` (`scrub-history init` creates it):

```toml
[allowlist]
# SHA-256 hex digests of values that should NOT be redacted.
hashes = []

[entropy]
# Regexes for tokens to exclude from entropy-based detection.
exclude_patterns = []

[blacklist]
# Exact strings that are always redacted wherever they appear.
strings = []
# SHA-256 hex digests of values that are always redacted on exact match.
hashes = []
# Minimum length of blacklist.strings entries (shorter entries are ignored).
min_string_length = 8

# Custom secret patterns, merged with the built-in ones.
[[patterns]]
name = "internal-token"
regex = "itk_[A-Za-z0-9]{32}"
keywords = ["itk_"]   # optional: cheap pre-filter, case-insensitive
secret_group = 0      # optional: capture group to redact (default: whole match)
```

Security notes:

- **This file contains secrets.** `blacklist.strings` holds plaintext values. `scrub-history init` writes it atomically with mode `0600`, and also tightens the mode of an existing file. `scrub-history status` warns if it is readable by group or others. Fix that with `chmod 600 ~/.claude/scrubber.toml`.
- **Hash entries are unsalted SHA-256.** They only protect high-entropy values such as API keys and tokens. A short or guessable password can be recovered from its hash by brute force, so it isn't hidden by hashing.
- Log messages never echo config values. For example, a too-short blacklist entry is reported by index and length only.

A bad config never silently turns redaction off:

- An invalid, oversized, empty-matching or malformed custom pattern is skipped with a warning that names the pattern but doesn't echo its regex. The built-in and other custom patterns still load.
- If `scrubber.toml` isn't valid TOML, the tool logs an error and falls back to the built-in patterns and default settings, so your blacklist, allowlist and custom patterns aren't applied until you fix it. Nothing is overwritten. `init` refuses to modify an unparseable config.
- If one section has the wrong shape, only that section is ignored.
- `scrub-history status` lists all of these problems.

## Built-in patterns

| Category | Examples |
|---|---|
| AWS | Access keys (`AKIA*`), secret keys |
| GitHub | Classic tokens (`ghp_*`), fine-grained (`github_pat_*`) |
| GitLab | Personal access tokens (`glpat-*`) |
| JWT | `eyJ*` tokens |
| Private keys | PEM-format `-----BEGIN *PRIVATE KEY-----` |
| Database | Connection strings (`postgres://`, `mongodb://`, etc.) |
| Stripe | `sk_live_*`, `pk_test_*`, `rk_*` |
| Slack | Bot/user tokens (`xoxb-*`, `xoxp-*`), app-level tokens (`xapp-*`), webhooks |
| Anthropic | `sk-ant-*` |
| OpenAI | `sk-*` (with false-positive filtering) |
| Google | API keys (`AIza*`), OAuth secrets, service-account JSON `private_key` values |
| npm | `npm_*` |
| Grafana | Service-account tokens (`glsa_*`), Cloud access-policy tokens (`glc_*`), legacy API keys (`eyJrIjoi*`) |
| HashiCorp Vault | Service/batch tokens (`hvs.*`, `hvb.*`) |
| Terraform Cloud | API tokens (`*.atlasv1.*`) |
| Doppler | `dp.pt.*`, `dp.st.*`, `dp.sa.*`, `dp.ct.*`, `dp.scim.*`, `dp.audit.*` |
| DigitalOcean | `dop_v1_*`, `doo_v1_*`, `dor_v1_*` |
| PyPI | Upload tokens for pypi.org and test.pypi.org (`pypi-AgE*`) |
| age | Secret keys (`AGE-SECRET-KEY-1*`) |
| Twilio / SendGrid / Heroku | `SK*`, `SG.*`, Heroku API keys |
| Generic | `api_key=`, `apikey=`, password assignments |

## License

AGPL-3.0
