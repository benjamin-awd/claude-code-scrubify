//! Filesystem helpers for writing files that may contain sensitive data.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Permission bits for files that may hold secrets (scrubber.toml, cache,
/// stats, hook state): owner read/write only.
pub const PRIVATE_MODE: u32 = 0o600;

/// Atomically write `data` to `path` with mode `0600`.
///
/// The data is written to a temp file in the same directory (created `0600`
/// from the start, so there is no window where it is world-readable), fsynced
/// and renamed over the destination.
pub fn write_private_atomic(path: &Path, data: &[u8]) -> Result<()> {
    write_atomic(path, data, PRIVATE_MODE)
}

/// Atomically write `data` to `path`, giving the result permission bits
/// `mode` (ignored on non-Unix platforms).
///
/// If `path` is a symlink, the symlink's target is replaced rather than the
/// link itself, so dotfile-managed configs keep working.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let target = resolve_symlink(path);
    let dir = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".scrub-history-")
        .suffix(".tmp")
        .tempfile_in(dir)
        .with_context(|| format!("creating temp file in {}", dir.display()))?;
    set_mode(tmp.path(), mode)?;
    tmp.write_all(data)
        .with_context(|| format!("writing temp file for {}", target.display()))?;
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("syncing temp file for {}", target.display()))?;
    tmp.persist(&target)
        .map_err(|e| e.error)
        .with_context(|| format!("replacing {}", target.display()))?;
    Ok(())
}

/// Current permission bits of `path` (`None` if it doesn't exist, or on
/// non-Unix platforms).
pub fn file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Returns true if `path` exists and is readable by group or others.
pub fn is_group_or_world_readable(path: &Path) -> bool {
    file_mode(path).is_some_and(|m| m & 0o044 != 0)
}

fn resolve_symlink(path: &Path) -> PathBuf {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
        }
        _ => path.to_path_buf(),
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions on {}", path.display()))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_private_atomic_creates_0600_even_with_permissive_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scrubber.toml");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(is_group_or_world_readable(&path));

        write_private_atomic(&path, b"new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(file_mode(&path), Some(0o600));
        assert!(!is_group_or_world_readable(&path));
        // No temp files left behind
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_follows_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        let link = dir.path().join("link.json");
        std::fs::write(&real, "{}").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        write_atomic(&link, b"{\"a\":1}", 0o644).unwrap();

        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "{\"a\":1}");
        assert_eq!(file_mode(&real), Some(0o644));
    }
}
