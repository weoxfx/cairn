//! Process hardening: no core dumps, no ptrace/memory reads by other processes
//! of the same user, private default file permissions, plus symlink-safe
//! helpers for writing the wallet directory and config.

use crate::error::Result;

use std::fs::{self, OpenOptions};
use std::io::Write;
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
#[cfg(unix)]
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    if ptr.is_null() || len == 0 {
        return false;
    }
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

/// Windows has no `mlock` here; callers already treat this as best effort.
#[cfg(not(unix))]
pub fn lock_memory(_ptr: *const u8, _len: usize) -> bool {
    false
}

/// Undo [`lock_memory`]. Safe to call even if locking failed.
#[cfg(unix)]
pub fn unlock_memory(ptr: *const u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let _ = libc::munlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(not(unix))]
pub fn unlock_memory(_ptr: *const u8, _len: usize) {}

/// Create `dir` with mode 0700, or verify that an existing path is a real
/// directory we can lock down. Symlinks and non-directories are refused.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(format!("refusing to use symlinked directory {}", dir.display()).into())
        }
        Ok(m) if !m.is_dir() => return Err(format!("{} is not a directory", dir.display()).into()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            let meta = fs::symlink_metadata(dir)
                .map_err(|e| format!("cannot inspect {}: {e}", dir.display()))?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(format!("refusing to use unsafe directory {}", dir.display()).into());
            }
        }
        Err(e) => return Err(format!("cannot inspect {}: {e}", dir.display()).into()),
    }
    set_dir_mode(dir)
        .map_err(|e| format!("cannot secure {}: {e}", dir.display()))
        .map_err(crate::error::Error::from)
}

/// Owner-only permissions on a directory. A no-op where POSIX modes do not exist.
fn set_dir_mode(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Open an existing file for reading, refusing symlinks and blocking on FIFOs
/// where the OS supports those flags.
pub fn open_read(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    opts.open(path)
}

/// Create a new file that only this user can read or write.
pub fn create_private(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

/// Permission bits of a file. Windows has no POSIX modes, so this reports the
/// private mode callers expect rather than failing every check.
pub fn mode_of(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0o600
    }
}

/// Whether a file looks executable. Windows has no execute bit, so any file
/// counts and the OS decides when it is run.
pub fn is_executable(meta: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        meta.is_file() && mode_of(meta) & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

/// Tighten a file to owner-only access (a no-op without POSIX modes).
pub fn restrict(file: &fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

/// Atomically replace `path` with `data`, mode 0600. The temp file is created
/// with `O_NOFOLLOW` and the rename replaces any existing symlink instead of
/// writing through it.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
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

    let result = (|| -> Result<()> {
        let mut f =
            create_private(&tmp).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
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

    #[cfg(unix)]
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
        assert_eq!(mode_of(&std::fs::metadata(&private).unwrap()), 0o700);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
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
        assert_eq!(mode_of(&std::fs::metadata(&target).unwrap()), 0o600);
        let _ = std::fs::remove_dir_all(&base);
    }
}
