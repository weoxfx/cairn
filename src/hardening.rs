//! Process hardening: no core dumps, no ptrace/memory reads by other processes
//! of the same user, private default file permissions, plus symlink-safe
//! helpers for writing the wallet directory, config and mainnet marker.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub fn init() {
    #[cfg(unix)]
    unsafe {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
        libc::umask(0o077);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            libc::prctl(
                libc::PR_SET_DUMPABLE,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            );
        }
    }
}

/// Best-effort `mlock` of a secret allocation. Returns `false` when the OS
/// refuses (for example a low `RLIMIT_MEMLOCK`); callers must continue and must
/// not treat this as a guarantee.
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    if ptr.is_null() || len == 0 {
        return false;
    }
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

/// Undo [`lock_memory`]. Safe to call even if locking failed.
pub fn unlock_memory(ptr: *const u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let _ = libc::munlock(ptr as *const libc::c_void, len);
    }
}

/// Create `dir` with mode 0700, or verify that an existing path is a real
/// directory we can lock down. Symlinks and non-directories are refused.
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(format!(
                "refusing to use symlinked directory {}",
                dir.display()
            ))
        }
        Ok(m) if !m.is_dir() => return Err(format!("{} is not a directory", dir.display())),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            let meta = fs::symlink_metadata(dir)
                .map_err(|e| format!("cannot inspect {}: {e}", dir.display()))?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(format!(
                    "refusing to use unsafe directory {}",
                    dir.display()
                ));
            }
        }
        Err(e) => return Err(format!("cannot inspect {}: {e}", dir.display())),
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot secure {}: {e}", dir.display()))
}

/// Atomically replace `path` with `data`, mode 0600. The temp file is created
/// with `O_NOFOLLOW` and the rename replaces any existing symlink instead of
/// writing through it.
pub fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("cairn");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(".{name}.{}.{nanos}.tmp", std::process::id()));

    let result = (|| -> Result<(), String> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        f.write_all(data).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))?;
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cairn-hardening-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn private_dir_refuses_symlinks_and_sets_mode() {
        let base = temp("dir");
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(ensure_private_dir(&link).is_err());

        let private = base.join("private");
        ensure_private_dir(&private).unwrap();
        assert_eq!(
            std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn private_write_never_follows_a_symlink() {
        let base = temp("write");
        let victim = base.join("victim");
        std::fs::write(&victim, b"original").unwrap();
        let target = base.join("target");
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        write_private(&target, b"replaced").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"original");
        assert_eq!(std::fs::read(&target).unwrap(), b"replaced");
        assert!(!std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
