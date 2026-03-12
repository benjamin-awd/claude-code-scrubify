# RFC-001: Pre-Scrub Backup & Restore

**Status:** Draft
**Date:** 2026-03-12

## Problem

`scrub-history` performs irreversible, in-place mutations on Claude Code JSONL history files via atomic temp-file-and-rename in `jsonl.rs`. Once a file is overwritten, the original content is gone — there is no git history, snapshot mechanism, or undo path for `~/.claude/projects/`.

This creates three concrete risks:

1. **Overly aggressive patterns or entropy thresholds redact legitimate content** (e.g., a long base64-encoded image, a code snippet with high entropy, a UUID mistaken for a token). The user discovers the damage after the fact with no way to recover.
2. **Pattern tuning requires a destructive loop.** Users need to iterate: run scan, inspect results, adjust thresholds, re-run. Without backup, each iteration permanently alters files, making comparison impossible.
3. **First-run trust barrier.** Users won't run a tool that permanently mutates ~2,900 files without a safety net. A backup makes the first `--scan` feel safe enough to try.

### The Backup Paradox

Naive backup (copy files before scrubbing) creates a new problem: the backup contains the very secrets we're trying to eliminate. A `.bak` file sitting next to the scrubbed original is a plaintext copy of every redacted credential. This is worse than no backup — it gives users a false sense of security while leaving secrets on disk.

The solution: **ephemeral backups by default** (auto-deleted on successful completion), with **encrypted persistent backups** as an opt-in for users who need a longer recovery window.

## Proposal

### Tier 1: Ephemeral Backup (default, both modes)

Backups exist only for the duration of the scrub operation and are automatically cleaned up on success.

#### Scan Mode

1. Before the parallel scrub loop, create a temp directory via `tempfile::tempdir()` (auto-cleaned on drop).
2. As each file is about to be modified, copy the original into the temp directory, preserving relative path structure.
3. If the scan **completes successfully**: the temp directory is dropped, backups are gone. No secrets left on disk.
4. If the scan **crashes or is interrupted**: the temp directory persists in the OS temp location (e.g., `/tmp/`). The user can recover files manually. The OS temp cleaner will eventually purge it.
5. On the next `scrub-history --scan` invocation, check for orphaned backup dirs (identified by a marker file) and warn the user: `Found interrupted backup from 2026-03-12T14:30:00Z at /tmp/.scrub-backup-abc123. Restore with: scrub-history restore --from /tmp/.scrub-backup-abc123`.

This gives crash protection without leaving secrets on disk during normal operation.

#### Hook Mode

1. Before `temp.persist(path)`, copy the original file to a `.bak` sibling.
2. After `temp.persist(path)` succeeds, delete the `.bak`.
3. If the hook **crashes** between steps 1 and 2, the `.bak` survives for manual recovery.

The `.bak` exists for milliseconds during normal operation — just long enough to protect against a crash during the atomic rename.

### Tier 2: Encrypted Persistent Backup (opt-in)

For users who want a longer recovery window (e.g., during initial pattern tuning), provide `--keep-backup` which encrypts and persists the backup.

#### Encryption via Platform Keyring

Use the platform's native secret storage to hold a symmetric encryption key:

| Platform | Backend | Crate |
|---|---|---|
| macOS | Apple Keychain (`Security.framework`) | `keyring` or `security-framework` |
| Linux | Secret Service API (GNOME Keyring, KDE Wallet) or kernel keyring | `keyring` |
| Linux (headless) | File-based key at `~/.claude/scrubber-key`, permissions `0600` | Manual |

The [`keyring`](https://crates.io/crates/keyring) crate provides a unified API across platforms:

```rust
let entry = keyring::Entry::new("scrub-history", "backup-key")?;

// First run: generate and store a 256-bit key
let key = generate_random_key();
entry.set_password(&hex::encode(key))?;

// Subsequent runs: retrieve
let key = hex::decode(entry.get_password()?)?;
```

#### Encrypted Backup Flow

1. `scrub-history --scan --keep-backup`:
   - Before scrubbing, retrieve (or generate) the encryption key from the platform keyring.
   - Copy files to `~/.claude/scrubber-backup/`, encrypting each with AES-256-GCM.
   - Write an unencrypted `manifest.json` (metadata only, no secrets):

```json
{
  "created_at": "2026-03-12T14:30:00Z",
  "scrub_history_version": "0.1.0",
  "files_backed_up": 2847,
  "encryption": "aes-256-gcm",
  "key_source": "keyring:scrub-history/backup-key",
  "expires_at": "2026-03-19T14:30:00Z"
}
```

2. **Auto-expiry**: Encrypted backups are deleted after 7 days by default (configurable via `--backup-ttl <days>`). Checked at the start of each scan or hook invocation.

3. `scrub-history restore --from-backup`:
   - Retrieve the decryption key from the platform keyring.
   - Decrypt and restore files to `~/.claude/projects/`.
   - Requires `--yes` or interactive confirmation.

4. `scrub-history restore --list`:
   - Show backup metadata: date, file count, size, expiry, encryption status.

#### Encryption Implementation

Use `aes-gcm` crate (pure Rust, audited):

```rust
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

fn encrypt_file(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from(random_96_bits());  // unique per file
    let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
    // Prepend nonce to ciphertext for storage
    [nonce.as_slice(), &ciphertext].concat()
}
```

Each `.jsonl.enc` file is `nonce (12 bytes) || ciphertext || tag (16 bytes)`. Simple, no custom format.

### Tier 3: Restore Command

`scrub-history restore` subcommand:

- `scrub-history restore --from <path>` — restore from an orphaned ephemeral backup (crash recovery). Path is printed in the warning message on next run.
- `scrub-history restore --from-backup` — decrypt and restore from encrypted persistent backup.
- `scrub-history restore --list` — show available backups (ephemeral orphans + encrypted persistent).
- `scrub-history restore --purge` — delete all backups (encrypted + orphaned) and remove the keyring entry.

## Changes Required

### New file: `src/backup.rs`

```rust
/// Ephemeral backup — lives in OS temp dir, auto-cleaned on drop
pub struct EphemeralBackup { /* tempfile::TempDir wrapper */ }
impl EphemeralBackup {
    pub fn new() -> Result<Self>;
    pub fn add_file(&self, original: &Path, projects_dir: &Path) -> Result<()>;
    pub fn persist_on_failure(self);  // prevents cleanup, for crash recovery
}

/// Encrypted persistent backup
pub struct EncryptedBackup { /* ~/.claude/scrubber-backup/ */ }
impl EncryptedBackup {
    pub fn create(projects_dir: &Path, ttl_days: u16) -> Result<Self>;
    pub fn add_file(&self, original: &Path, projects_dir: &Path) -> Result<()>;
    pub fn restore(&self, projects_dir: &Path) -> Result<u64>;
    pub fn is_expired(&self) -> bool;
    pub fn purge(&self) -> Result<()>;
}

/// Keyring operations
fn get_or_create_key() -> Result<[u8; 32]>;
fn delete_key() -> Result<()>;

/// Orphan detection
pub fn find_orphaned_backups() -> Vec<PathBuf>;

/// Auto-expiry: called at startup
pub fn cleanup_expired_backups() -> Result<()>;
```

### `scan.rs`

```rust
pub fn run_scan(dry_run: bool, entropy_cfg: &EntropyConfig, keep_backup: bool, backup_ttl: u16) {
    // Cleanup expired encrypted backups on every run
    backup::cleanup_expired_backups().ok();

    // Warn about orphaned ephemeral backups
    for orphan in backup::find_orphaned_backups() {
        warn!("Found interrupted backup at {}. Restore with: scrub-history restore --from {}", ...);
    }

    // Create backup (ephemeral or encrypted depending on --keep-backup)
    let backup = if keep_backup {
        Backup::Encrypted(EncryptedBackup::create(&projects_dir, backup_ttl)?)
    } else {
        Backup::Ephemeral(EphemeralBackup::new()?)
    };

    // In par_iter, before persisting each file:
    backup.add_file(&path, &projects_dir)?;

    // Ephemeral backup auto-drops here on success
}
```

### `jsonl.rs`

`scrub_jsonl_file()` signature gains an optional backup handle:

```rust
pub fn scrub_jsonl_file(
    path: &Path,
    pattern_set: &PatternSet,
    entropy_cfg: &EntropyConfig,
    dry_run: bool,
    backup: Option<&dyn BackupTarget>,  // new
) -> Result<ScrubResult>
```

The backup copy happens before `temp.persist(path)`.

### `hook.rs`

Hook mode uses the ephemeral `.bak` strategy (copy before persist, delete after persist). No encryption needed — the `.bak` exists for <1ms during normal operation.

### `main.rs`

New CLI flags:
- `--keep-backup` — encrypt and persist backup (scan mode).
- `--backup-ttl <days>` — auto-expiry for encrypted backups (default 7).
- `--no-backup` — skip even ephemeral backup (scan mode).

New subcommand:
- `restore` with `--from <path>`, `--from-backup`, `--list`, `--purge`.

### New dependencies

```toml
keyring = "3"          # platform keyring (macOS Keychain, Linux Secret Service)
aes-gcm = "0.10"       # AES-256-GCM encryption
rand = "0.8"           # key and nonce generation
hex = "0.4"            # key encoding for keyring storage
```

## Security Properties

| Property | Ephemeral (default) | Encrypted (--keep-backup) |
|---|---|---|
| Secrets on disk during scrub | Yes (temp dir) | Yes (encrypted) |
| Secrets on disk after scrub | No (auto-deleted) | Encrypted only |
| Secrets on disk after crash | Yes (temp dir, OS will purge) | Encrypted only |
| Secrets on disk after expiry | No | No (auto-purged) |
| Key storage | N/A | Platform keyring |
| Recoverable after success | No | Yes, until TTL expires |
| Recoverable after crash | Yes (manual, from temp dir) | Yes (via restore command) |

**Threat model:** The encrypted backup protects against casual disk inspection and data-at-rest exposure. It does **not** protect against an attacker with access to both the filesystem and the platform keyring (which requires the user's login session). This matches the threat model of the secrets themselves — if an attacker has your login session, they can read `~/.claude/projects/` directly.

## Performance Impact

**Ephemeral backup (scan mode):** One `fs::copy` per modified file into the OS temp directory. Temp directories are typically on the same filesystem, so this is a metadata + data copy. For a typical scan modifying ~100 files, adds <500ms.

**Ephemeral backup (hook mode):** One `fs::copy` + one `fs::remove_file`. Adds <1ms on SSD. Well within the <100ms budget.

**Encrypted backup:** `fs::read` + AES-256-GCM encrypt + `fs::write` per file. AES-GCM on modern hardware (AES-NI) processes ~4 GB/s. For ~200 MB of JSONL, encryption adds <100ms. Key retrieval from the platform keyring adds ~5–20ms (one-time per invocation). Total overhead: ~2–5 seconds for a full scan, comparable to the original snapshot proposal.

**Auto-expiry check:** One `fs::metadata` call on the manifest file per invocation. Negligible.

## Migration Path

- **v0.1:** Ephemeral backup only (Tier 1). Minimal code: `tempfile::tempdir()`, `fs::copy` before persist, auto-drop on success. No new dependencies beyond `tempfile` (already in `Cargo.toml`). No encryption, no restore command, no keyring.
- **v0.2:** Encrypted persistent backup (Tier 2) + restore command (Tier 3). Adds `keyring`, `aes-gcm`, `rand`, `hex` dependencies. Adds `restore` subcommand and `--keep-backup` / `--backup-ttl` flags.
- **v0.3:** Orphan detection, `--purge`, backup disk usage reporting.

## Alternatives Considered

**1. Plaintext persistent backup (original RFC draft)**
Copy files to `~/.claude/scrubber-backup/` unencrypted. Rejected because: the backup contains the secrets we're trying to eliminate. A plaintext backup sitting on disk indefinitely defeats the purpose of scrubbing.

**2. Git-based versioning of `~/.claude/projects/`**
Initialize a git repo, commit before each scan. Rejected because: invasive to a directory Claude Code owns, large repo growth, secrets persist in git history (same problem, different format).

**3. Copy-on-write filesystem snapshots (APFS/Btrfs)**
Zero-copy, instant, space-efficient. Rejected because: not portable, requires elevated permissions for APFS, platform-specific complexity.

**4. In-place undo markers: `[REDACTED:aws_key|AKIA...]`**
Enables undo without extra files. Rejected because: the secret is still in the file.

**5. Append-only redaction log**
Log `(file, offset, original_bytes)` for each redaction. Reverse by replaying in reverse. Rejected because: it's a concentrated file of *just* secrets — worse attack surface than the original files. Would need the same encryption treatment as Tier 2, at which point you might as well encrypt the full backup.

**6. Time-bombed plaintext backups (auto-delete after N days)**
Simpler than encryption but leaves secrets in plaintext for the entire TTL window. Rejected in favor of encryption: the marginal cost of AES-256-GCM is near zero on modern hardware, and it eliminates the at-rest exposure window entirely.

**7. `age`/`gpg` for encryption instead of AES-GCM + keyring**
Using `age` or GPG would avoid implementing crypto directly and leverage existing key management. Rejected for v0.2 because: adds an external tool dependency (`age` binary or GPG), complicates the user setup, and the keyring approach is self-contained. Could be offered as an alternative backend in the future for users who prefer file-based keys.

## Install-Time Configuration

The backup strategy is chosen once during `scrub-history init` (v0.5 roadmap) and persisted to `~/.claude/scrubber.toml`. Users shouldn't need to think about it after setup.

### Interactive Setup Flow

```
$ scrub-history init

Configuring scrub-history...

1. Hook installed in ~/.claude/settings.json ✓

2. Backup strategy (recovers from bad redactions):
   [1] Ephemeral only (default) — backups exist only during scrub, auto-deleted after
   [2] Encrypted persistent — backups encrypted via Keychain, auto-expire after N days

   Choose [1/2]: 2
   Backup TTL in days [7]: 14
   ✓ Generated encryption key and stored in Keychain

3. Writing config to ~/.claude/scrubber.toml ✓

Done. Run `scrub-history --scan --dry-run` to preview redactions.
```

### Resulting Config

```toml
# ~/.claude/scrubber.toml

[backup]
strategy = "encrypted"  # "ephemeral" | "encrypted"
ttl_days = 14
# key_source is auto-detected: "keyring" if available, "file" as fallback
```

If no `scrubber.toml` exists (user skipped `init` or installed manually), the default is `strategy = "ephemeral"`. The `--keep-backup` and `--backup-ttl` CLI flags override the config for a single invocation.

Users can re-run `scrub-history init` at any time to change their choice, or edit the TOML directly.

## Open Questions

1. **Keyring unavailability on headless Linux.** If no Secret Service provider is running (e.g., SSH-only server, CI), `keyring` will fail. Fallback: generate a key file at `~/.claude/scrubber-key` with `0600` permissions and warn that it's less secure than the platform keyring. The `keyring` crate supports custom backends, so this can be a built-in fallback.

2. **Should `--keep-backup` be rememberable in config?** Users doing pattern tuning will want persistent backups for multiple runs. Rather than requiring the flag every time, allow `keep_backup = true` in `~/.claude/scrubber.toml`. The TTL still applies — backups expire regardless of config.

3. **Backup granularity for encrypted mode.** Current design encrypts each file individually (one `.jsonl.enc` per `.jsonl`). Alternative: encrypt a single tarball. Individual files enable granular restore; tarball is simpler and slightly more space-efficient. Leaning toward individual files for restore flexibility.

4. **Hook mode persistent backup.** Currently hook mode only uses ephemeral `.bak` (exists for <1ms). Should `--keep-backup` in config also encrypt hook-mode backups? This would add ~5–20ms for keyring access per hook invocation. Probably not worth it — the hook runs frequently and the recovery window is tiny.
