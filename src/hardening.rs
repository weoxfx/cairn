//! Process hardening: no core dumps, no ptrace/memory reads by other processes
//! of the same user, and private default file permissions.

pub fn init() {
    #[cfg(unix)]
    unsafe {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
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

