# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately through GitHub's private vulnerability reporting:
go to the repository's **Security** tab and choose **Report a vulnerability**
(<https://github.com/benjamin-awd/claude-code-scrubify/security/advisories/new>).

Include what you found, how to reproduce it, and the impact you expect. You
should get an acknowledgement within a few days. Once a fix is released, the
advisory will be published and you will be credited unless you ask not to be.

## Supported versions

Only the latest tagged release gets security fixes. Upgrade to the newest
release before reporting, if you can.

| Version        | Supported |
|----------------|-----------|
| latest release | yes       |
| older releases | no        |

## Threat model (brief)

`scrub-history` runs as a Claude Code hook and reads and rewrites your Claude
Code chat history (`~/.claude/projects/**/*.jsonl`). Those transcripts often
contain secrets, source code and other sensitive data, so the tool is trusted
with all of it.

What that means:

- **Hook binary integrity matters most.** Whatever binary the hook command
  resolves to runs automatically with access to every transcript. A malicious
  or substituted binary, for example one placed earlier on `PATH`, could read
  or exfiltrate your history. Reference the binary by absolute path in the hook,
  install from a tagged release with `cargo install --locked`, and check
  `which -a scrub-history` for shadowing copies.
- **Supply chain.** Dependencies are locked (`Cargo.lock`) and checked in CI
  with `cargo-deny` for RustSec advisories, yanked crates, licences and
  unknown sources. CI actions are pinned to commit SHAs.
- **No network access.** The tool only reads and writes local files. Any code
  path that makes network requests would be a vulnerability.
- **Redaction is best-effort.** Missed secrets, meaning false negatives in the
  built-in patterns or entropy detection, are worth reporting. They're usually
  ordinary bugs, not vulnerabilities, unless they come from something like a
  crash or a bypass that stops scrubbing entirely.
- **Data integrity.** A bug that corrupts or truncates transcripts, or leaves
  unredacted copies behind (temp files, caches), is in scope.

Out of scope: an attacker who can already run code as your user or modify
`~/.claude/settings.json`, because they can read the history directly.
