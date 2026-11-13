//! `cairn security check` — report the security properties this build can
//! actually observe for one wallet.
//!
//! Two rules shape this module:
//!
//! 1. A line is only PASS because something was inspected. Anything that would
//!    need a feature Cairn does not have is SKIP with the reason, never PASS.
//! 2. Passing checks are not a security guarantee. The report says what was and
//!    was not checked and never calls a wallet "secure".

use crate::keystore::{self, KdfParams};
use crate::{esplora, ui};
use console::style;
use std::collections::BTreeSet;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Status {
    Pass,
    Skip,
    Warn,
    Fail,
}

impl Status {
    fn tag(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Skip => "SKIP",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }

    fn machine(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Skip => "not_checked",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }

    /// Padded before colouring so the columns stay aligned despite escape codes.
    fn styled(self) -> String {
        let tag = format!("[{:<4}]", self.tag());
        match self {
            Status::Pass => style(tag).green().bold().to_string(),
            Status::Skip => style(tag).dim().to_string(),
            Status::Warn => style(tag).yellow().bold().to_string(),
            Status::Fail => style(tag).red().bold().to_string(),
        }
    }
}

pub struct Check {
    name: String,
    status: Status,
    detail: String,
}

pub struct Report {
    wallet: String,
    network: String,
    fingerprint: Option<String>,
    checks: Vec<Check>,
    /// Print each line as it is inspected, so the screen fills in like a scan
    /// instead of showing nothing until the end. Off for `--json` and for any
    /// non-terminal stdout, where the rows would corrupt machine output.
    live: bool,
}

impl Report {
    fn new(wallet: &str, info: &keystore::FileInfo) -> Self {
        Report {
            wallet: wallet.to_string(),
            network: info.network.clone(),
            fingerprint: None,
            checks: Vec::new(),
            live: false,
        }
    }

    fn add(&mut self, name: &str, status: Status, detail: impl Into<String>) {
        let check = Check {
            name: name.to_string(),
            status,
            detail: detail.into(),
        };
        if self.live {
            print_row(&check);
        }
        self.checks.push(check);
    }

    fn count(&self, status: Status) -> usize {
        self.checks.iter().filter(|c| c.status == status).count()
    }

    /// Worst status wins, so a single FAIL cannot be averaged away.
    pub fn overall(&self) -> Status {
        self.checks
            .iter()
            .map(|c| c.status)
            .max()
            .unwrap_or(Status::Skip)
    }

    fn verdict(&self) -> &'static str {
        match self.overall() {
            Status::Fail => "FAILED",
            Status::Warn => "REVIEW RECOMMENDED",
            Status::Skip => "INCOMPLETE",
            Status::Pass => "NO ISSUES FOUND BY THESE CHECKS",
        }
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "security_check",
            "wallet": self.wallet,
            "network": self.network,
            "fingerprint": self.fingerprint,
            "overall": self.verdict(),
            "summary": {
                "passed": self.count(Status::Pass),
                "not_checked": self.count(Status::Skip),
                "warnings": self.count(Status::Warn),
                "failures": self.count(Status::Fail),
            },
            "checks": self
                .checks
                .iter()
                .map(|c| serde_json::json!({
                    "name": c.name,
                    "status": c.status.machine(),
                    "detail": c.detail,
                }))
                .collect::<Vec<_>>(),
            "note": "Not a security audit. These checks inspect local configuration and \
                     files only; passing them does not prove the wallet is secure.",
        })
    }

    /// Title plus the wallet facts known before the scan starts.
    fn render_header(&self) {
        ui::set_context(format!("Security check  ·  {}", self.wallet));
        ui::banner();
        ui::kv("Wallet", &self.wallet);
        ui::kv("Network", &self.network);
        println!();
    }

    fn render(&self) {
        if !self.live {
            self.render_header();
            if let Some(fp) = &self.fingerprint {
                ui::kv("Fingerprint", fp);
            }
            for c in &self.checks {
                print_row(c);
            }
        }
        println!();
        self.render_summary();
    }

    fn render_summary(&self) {
        ui::grid(&[
            ("Passed", &self.count(Status::Pass).to_string()),
            ("Not checked", &self.count(Status::Skip).to_string()),
            ("Warnings", &self.count(Status::Warn).to_string()),
            ("Failures", &self.count(Status::Fail).to_string()),
        ]);
        println!();
        let verdict = match self.overall() {
            Status::Fail => style(self.verdict()).red().bold(),
            Status::Warn => style(self.verdict()).yellow().bold(),
            _ => style(self.verdict()).cyan().bold(),
        };
        println!("  {:<16}{}", style("Overall").dim(), verdict);
        println!();
        ui::hint(
            "This is not an audit and not a security guarantee. It reports what this build \
             could inspect; SKIP lines are features Cairn does not have.",
        );
    }
}

// ---------- individual checks ----------

fn print_row(c: &Check) {
    println!(
        "  {} {:<32} {}",
        c.status.styled(),
        c.name,
        style(&c.detail).dim()
    );
}

fn encryption_check(info: &keystore::FileInfo) -> (Status, String) {
    match info.version {
        2 => (
            Status::Pass,
            "ChaCha20-Poly1305 with Argon2id; network and fingerprint bound into the AAD (v2)"
                .into(),
        ),
        3 => (
            Status::Pass,
            "ChaCha20-Poly1305 with Argon2id; network, fingerprint and passphrase flag bound (v3)"
                .into(),
        ),
        1 => (
            Status::Warn,
            "legacy v1 format: the AAD does not bind the network or fingerprint, and it is \
             testnet-only"
                .into(),
        ),
        other => (
            Status::Fail,
            format!("unsupported wallet format version {other}"),
        ),
    }
}

fn permissions_check(file_mode: u32, dir_mode: u32, size: u64) -> (Status, String) {
    let file_open = file_mode & 0o077 != 0;
    let dir_open = dir_mode & 0o077 != 0;
    if file_open {
        (
            Status::Warn,
            format!(
                "wallet file was {:04o} (other users could read it); Cairn tightened it to 0600 \
                 when opening it",
                file_mode
            ),
        )
    } else if dir_open {
        (
            Status::Warn,
            format!(
                "wallet directory was {:04o}; Cairn sets 0700 when it creates it",
                dir_mode
            ),
        )
    } else {
        (
            Status::Pass,
            format!("wallet file 0600 in a 0700 directory ({size} bytes, owner-only)"),
        )
    }
}

fn kdf_check(kdf: &str, p: &KdfParams) -> (Status, String) {
    if kdf != "argon2id" {
        return (Status::Fail, format!("unsupported KDF '{kdf}'"));
    }
    if let Err(e) = keystore::validate_params(p) {
        return (Status::Fail, e);
    }
    let default = KdfParams::default_strong();
    let detail = |p: &KdfParams| {
        format!(
            "Argon2id, {} MiB memory, {} pass(es), parallelism {}",
            p.memory_kib / 1024,
            p.iterations,
            p.parallelism
        )
    };
    if p.memory_kib < default.memory_kib || p.iterations < default.iterations {
        (
            Status::Warn,
            format!(
                "{} — below the {} MiB / {} passes used for new wallets (still above the accepted \
                 minimum)",
                detail(p),
                default.memory_kib / 1024,
                default.iterations
            ),
        )
    } else {
        (Status::Pass, detail(p))
    }
}

fn network_check(
    wallet_net: &str,
    api: esplora::Net,
    custom_api: bool,
    proxy: Option<&str>,
) -> (Status, String) {
    let net_matches = (wallet_net == "mainnet") == api.is_mainnet();
    let transport = match (custom_api, proxy) {
        (true, Some(p)) => format!("own Esplora server via {p}"),
        (true, None) => "own Esplora server (direct connection: that server sees your IP)".into(),
        (false, Some(p)) => format!("public Esplora providers via {p}"),
        (false, None) => {
            "public Esplora providers over HTTPS with no Tor/proxy: they see your IP and every \
             address you query"
                .into()
        }
    };
    let detail = format!("HTTPS only, {transport}");
    if !net_matches {
        return (
            Status::Warn,
            format!(
                "API is set to {} but this wallet is {wallet_net}; syncing would be refused \
                 (signing is unaffected)",
                api.label()
            ),
        );
    }
    if !custom_api && proxy.is_none() {
        return (Status::Warn, detail);
    }
    (Status::Pass, detail)
}

/// What this process did to keep secrets out of core dumps, ptrace and swap.
/// Those controls are Unix kernel features, so Windows reports it as unchecked.
#[cfg(not(unix))]
fn memory_check() -> (Status, String) {
    (
        Status::Skip,
        "not checked: core dumps and ptrace are Unix controls".into(),
    )
}

/// What this process did to keep secrets out of core dumps, ptrace and swap.
#[cfg(unix)]
fn memory_check() -> (Status, String) {
    let mut core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let mut memlock = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let core_disabled =
        unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) } == 0 && core.rlim_cur == 0;
    let memlock_bytes = if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut memlock) } == 0 {
        memlock.rlim_cur
    } else {
        0
    };
    // PR_GET_DUMPABLE returns 0 when core dumps and ptrace are disabled for this
    // process, which is what `hardening::init` asks for.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let ptrace_protected = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let ptrace_protected = false;

    let mut parts = vec![
        if core_disabled {
            "core dumps disabled".to_string()
        } else {
            "core dumps are enabled".to_string()
        },
        if ptrace_protected {
            "ptrace/memory reads by other processes blocked".to_string()
        } else {
            "process is not ptrace-protected".to_string()
        },
    ];
    if memlock_bytes > 0 {
        parts.push(format!(
            "memory locking available ({} KiB limit)",
            (memlock_bytes / 1024).min(u64::from(u32::MAX))
        ));
    } else {
        parts.push("mlock unavailable".to_string());
    }
    let detail = parts.join(", ");

    if !core_disabled || !ptrace_protected {
        return (Status::Warn, detail);
    }
    if memlock_bytes == 0 {
        return (
            Status::Warn,
            format!("{detail}: secrets may reach swap. Raise RLIMIT_MEMLOCK to change this"),
        );
    }
    (Status::Pass, detail)
}

fn recovery_check(
    info: &keystore::FileInfo,
    words: Option<usize>,
    entropy_bits: Option<usize>,
) -> (Status, String) {
    if info.version >= 3 && info.passphrase {
        return (
            Status::Warn,
            "BIP39 passphrase in use: recovery needs the words AND the passphrase, which is \
             stored nowhere and cannot be recovered"
                .into(),
        );
    }
    match (words, entropy_bits) {
        (Some(words), Some(bits)) => (
            Status::Pass,
            format!(
                "{words}-word / {bits}-bit seed decrypts and re-derives fingerprint {}; watch-only \
                 descriptors exportable with `cairn --descriptor`",
                info.fingerprint
            ),
        ),
        _ => (
            Status::Skip,
            "wallet not unlocked: the seed was not re-derived or checked against the stored \
             fingerprint"
                .into(),
        ),
    }
}

// ---------- host environment ----------
//
// Everything here observes the machine Cairn is running on, not the wallet. It
// catches the surroundings an attacker would need: a remote session, a loaded
// library, a writable PATH entry, a service listening for the network.

/// Host text (PATH entries, locale-dependent names) is untrusted input for the
/// screen, so it is reduced to printable ASCII and bounded, like server text.
fn safe(s: &str, max_chars: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(max_chars)
        .collect()
}

fn session_check(ssh: bool, is_tty: bool) -> (Status, String) {
    if ssh {
        return (
            Status::Warn,
            "SSH session: keystrokes, the password and the decrypted seed cross the network and \
             the remote host's terminal. Run Cairn on the machine that holds the wallet"
                .into(),
        );
    }
    if !is_tty {
        return (
            Status::Warn,
            "stdin/stdout is not a terminal: typed secrets would not be hidden, and this report \
             may be going to a pipe or a log file"
                .into(),
        );
    }
    (
        Status::Pass,
        "local terminal, not an SSH session: nothing in this session leaves the machine".into(),
    )
}

const LOADER_VARS: [&str; 5] = [
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
];

fn loader_check(set: &[&str], preload: Option<&str>) -> (Status, String) {
    let mut causes = Vec::new();
    if let Some(preload) = preload {
        causes.push(format!("/etc/ld.so.preload lists {}", safe(preload, 120)));
    }
    if !set.is_empty() {
        causes.push(format!("{} set", set.join(", ")));
    }
    if causes.is_empty() {
        return (
            Status::Pass,
            "no loader-injection variables are set and /etc/ld.so.preload is empty or absent"
                .into(),
        );
    }
    (
        Status::Warn,
        format!(
            "{}: a library loaded this way runs inside Cairn and can read every keystroke and \
             secret. If you did not set it yourself, start Cairn from a clean shell",
            causes.join("; ")
        ),
    )
}

/// A system-wide preload hook, the usual way a rootkit enters every process on
/// a Linux machine. `None` when the file is absent or has no live entries.
fn ld_preload() -> Option<String> {
    let text = std::fs::read_to_string("/etc/ld.so.preload").ok()?;
    let entries: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if entries.is_empty() {
        None
    } else {
        Some(entries.join(", "))
    }
}

/// `TracerPid` from `/proc/self/status`: `Some(0)` when nothing is attached,
/// `Some(pid)` when a tracer is, `None` when the file cannot be read.
fn parse_tracer(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .and_then(|value| value.trim().parse().ok())
}

fn tracer_check(tracer: Option<u32>) -> (Status, String) {
    match tracer {
        Some(0) => (
            Status::Pass,
            "no process is tracing Cairn: ptrace would let it read the password and the decrypted \
             seed"
                .into(),
        ),
        Some(pid) => (
            Status::Warn,
            format!(
                "process {pid} is tracing Cairn (TracerPid): a debugger or an injected library can \
                 read the password and the decrypted seed"
            ),
        ),
        None => (
            Status::Skip,
            "not checked: /proc/self/status cannot be read on this machine".into(),
        ),
    }
}

/// One of the two command-line ClamAV clients, if this machine has one. Cairn
/// carries no signatures, so an installed engine is the only way to actually
/// look for known malware.
fn find_scanner() -> Option<(std::path::PathBuf, &'static str)> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in ["clamscan", "clamdscan"] {
            let candidate = dir.join(name);
            let executable = std::fs::metadata(&candidate)
                .map(|m| crate::hardening::is_executable(&m))
                .unwrap_or(false);
            if executable {
                return Some((candidate, name));
            }
        }
    }
    None
}

/// Turns a finished scanner run into a report line. ClamAV exits 0 for clean,
/// 1 for a signature match and anything else for a failure it could not act on.
fn scan_report(
    engine: &str,
    paths: usize,
    code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> (Status, String) {
    match code {
        Some(0) => (
            Status::Pass,
            format!(
                "{engine} scanned {paths} path(s) (the running binary and the wallet directory) \
                 with no signature match"
            ),
        ),
        Some(1) => {
            let hits: Vec<String> = stdout
                .lines()
                .filter(|line| line.trim_end().ends_with("FOUND"))
                .take(3)
                .map(|line| safe(line.trim(), 160))
                .collect();
            let detail = if hits.is_empty() {
                "a signature matched but the scanner printed no file names".to_string()
            } else {
                hits.join("; ")
            };
            (
                Status::Fail,
                format!("{engine} reported malware: {detail}. Do not type your password here"),
            )
        }
        _ => (
            Status::Skip,
            format!(
                "not checked: {engine} could not finish ({}). Check its signature database",
                safe(last_meaningful_line(stdout, stderr), 140)
            ),
        ),
    }
}

fn last_meaningful_line<'a>(stdout: &'a str, stderr: &'a str) -> &'a str {
    let last = |text: &'a str| {
        text.lines()
            .rev()
            .map(str::trim)
            .find(|line| !line.is_empty())
    };
    last(stderr).or_else(|| last(stdout)).unwrap_or("no output")
}

fn malware_check() -> (Status, String) {
    let Some((scanner, engine)) = find_scanner() else {
        return (
            Status::Skip,
            "not checked: no antivirus engine on this machine. Cairn ships no signatures or \
             heuristics, so install ClamAV (`clamscan`) and this line scans the running binary and \
             the wallet directory with it"
                .into(),
        );
    };
    let mut targets = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        targets.push(exe);
    }
    if let Ok(dir) = keystore::wallet_dir() {
        targets.push(dir);
    }
    if targets.is_empty() {
        return (
            Status::Skip,
            format!("not checked: {engine} found but there is nothing it can be pointed at"),
        );
    }
    let run = std::process::Command::new(&scanner)
        .args(["--no-summary", "--infected"])
        .args(&targets)
        .stdin(std::process::Stdio::null())
        .output();
    let output = match run {
        Ok(output) => output,
        Err(e) => {
            return (
                Status::Skip,
                format!("not checked: cannot run {engine}: {e}"),
            )
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let label = format!("{engine} (ClamAV)");
    scan_report(
        &label,
        targets.len(),
        output.status.code(),
        &stdout,
        &stderr,
    )
}

/// `entries` is each PATH component with the directory's permission bits, or
/// `None` when it does not exist.
fn path_check(entries: &[(String, Option<u32>)]) -> (Status, String) {
    if entries.is_empty() {
        return (
            Status::Skip,
            "PATH is not set, so there is nothing to inspect".into(),
        );
    }
    let mut writable = Vec::new();
    let mut relative = Vec::new();
    let mut existing = 0usize;
    for (dir, mode) in entries {
        if let Some(mode) = mode {
            existing += 1;
            if mode & 0o022 != 0 {
                writable.push(format!("{} ({:04o})", safe(dir, 80), mode & 0o777));
            }
        }
        if dir.is_empty() || !dir.starts_with('/') {
            relative.push(if dir.is_empty() {
                "empty entry".to_string()
            } else {
                safe(dir, 80)
            });
        }
    }
    if !writable.is_empty() {
        return (
            Status::Warn,
            format!(
                "writable by other users, where a fake `cairn` can be planted: {}",
                writable.join(", ")
            ),
        );
    }
    if !relative.is_empty() {
        return (
            Status::Warn,
            format!(
                "relative entries resolve against whatever directory you are in: {}",
                relative.join(", ")
            ),
        );
    }
    (
        Status::Pass,
        format!("{existing} directories, none writable by other users of this machine"),
    )
}

/// One LISTEN row per socket, from `/proc/net/tcp{,6}`: (address hex, port).
fn parse_listeners(table: &str) -> Vec<(String, u16)> {
    let mut out = Vec::new();
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st ... ; st 0A is TCP_LISTEN.
        if fields.len() < 4 || fields[3] != "0A" {
            continue;
        }
        let Some((addr, port)) = fields[1].split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port, 16) else {
            continue;
        };
        out.push((addr.to_string(), port));
    }
    out
}

/// True only for a loopback bind. ``0.0.0.0`` and ``::`` are *not* loopback:
/// they accept connections from other machines.
fn is_loopback(addr: &str) -> bool {
    if addr.len() == 8 {
        let Ok(value) = u32::from_str_radix(addr, 16) else {
            return false;
        };
        return std::net::Ipv4Addr::from(value.to_le_bytes()).is_loopback();
    }
    // IPv6 rows are 32 hex digits; only the loopback word pattern matters here.
    addr == "00000000000000000000000001000000"
}

fn port_list(ports: &BTreeSet<u16>) -> String {
    let mut shown: Vec<String> = ports.iter().take(5).map(u16::to_string).collect();
    if ports.len() > 5 {
        shown.push(format!("and {} more", ports.len() - 5));
    }
    shown.join(", ")
}

fn listeners_check() -> (Status, String) {
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        return (
            Status::Skip,
            "listening sockets can only be read from /proc/net on Linux and Android".into(),
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut sockets = Vec::new();
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(text) = std::fs::read_to_string(table) {
                sockets.extend(parse_listeners(&text));
            }
        }
        if sockets.is_empty() {
            return (Status::Pass, "no listening TCP sockets".into());
        }
        let (mut local, mut exposed) = (BTreeSet::new(), BTreeSet::new());
        for (addr, port) in &sockets {
            if is_loopback(addr) {
                local.insert(*port);
            } else {
                exposed.insert(*port);
            }
        }
        if !exposed.is_empty() {
            return (
                Status::Warn,
                format!(
                    "{} listening socket(s), {} reachable from other machines ({}); Cairn needs \
                     none of them",
                    sockets.len(),
                    exposed.len(),
                    port_list(&exposed)
                ),
            );
        }
        (
            Status::Pass,
            format!(
                "{} listening socket(s), loopback only ({})",
                sockets.len(),
                port_list(&local)
            ),
        )
    }
}

fn usb_check() -> (Status, String) {
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        return (
            Status::Skip,
            "USB device inventory needs /sys/bus/usb, which Linux and Android have".into(),
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") else {
            return (
                Status::Skip,
                "not verified: /sys/bus/usb/devices cannot be read on this machine".into(),
            );
        };
        let (mut devices, mut hid, mut storage) = (0usize, 0usize, 0usize);
        for entry in entries.flatten() {
            let path = entry.path();
            if path.join("idVendor").exists() {
                devices += 1;
            }
            // Interfaces are the `<bus>-<port>:<config>.<if>` directories.
            if let Ok(class) = std::fs::read_to_string(path.join("bInterfaceClass")) {
                match class.trim() {
                    "03" => hid += 1,     // HID: keyboards, mice, keystroke injectors
                    "08" => storage += 1, // mass storage
                    _ => {}
                }
            }
        }
        if devices == 0 {
            return (
                Status::Skip,
                "not verified: no USB devices are attached".into(),
            );
        }
        (
            Status::Skip,
            format!(
                "not verified: {devices} USB device(s), {hid} keyboard/HID interface(s), \
                 {storage} storage interface(s). A keyboard can type into Cairn and a stick can \
                 carry a BadUSB payload; check that you recognise every one"
            ),
        )
    }
}

fn terminal_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn ssh_session() -> bool {
    ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"]
        .iter()
        .any(|name| std::env::var_os(name).is_some())
}

fn loader_vars_set() -> Vec<&'static str> {
    LOADER_VARS
        .into_iter()
        .filter(|name| {
            std::env::var(name)
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
        })
        .collect()
}

fn path_entries() -> Vec<(String, Option<u32>)> {
    let Some(path) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    let path = path.to_string_lossy();
    path.split(if cfg!(windows) { ';' } else { ':' })
        .map(|dir| {
            let mode = std::fs::metadata(dir)
                .ok()
                .filter(|m| m.is_dir())
                .map(|m| crate::hardening::mode_of(&m));
            (dir.to_string(), mode)
        })
        .collect()
}

// ---------- command ----------

pub fn check(name: &str, json: bool) -> Result<(), String> {
    let info = keystore::inspect(name)?;
    let mut report = Report::new(name, &info);
    report.live = !json && ui::interactive();
    if report.live {
        report.render_header();
    }

    let (s, d) = encryption_check(&info);
    report.add("Wallet encryption", s, d);
    let (s, d) = permissions_check(info.mode, info.dir_mode, info.size);
    report.add("File permissions", s, d);
    let (s, d) = kdf_check(&info.kdf, &info.kdf_params);
    report.add("KDF configuration", s, d);

    // Integrity can only be shown by actually authenticating the ciphertext.
    let mut words = None;
    let mut bits = None;
    match crate::unlock_wallet(name) {
        Ok(opened) => {
            words = Some(opened.mnemonic.words().count());
            bits = Some(opened.mnemonic.to_entropy().len() * 8);
            report.fingerprint = Some(opened.fingerprint.clone());
            report.add(
                "Wallet integrity",
                Status::Pass,
                "authentication tag verified with your password and the fingerprint re-derived \
                 from the decrypted seed",
            );
            if report.live {
                ui::kv("Fingerprint", &opened.fingerprint);
            }
        }
        Err(e) => {
            report.add(
                "Wallet integrity",
                Status::Skip,
                format!("not checked: {e}"),
            );
        }
    }

    // Mainnet is bound to the wallet, not to the global config, so a mainnet
    // wallet is always talking to the mainnet API. Testnet wallets inherit the
    // configured network.
    let api = if info.network == "mainnet" {
        esplora::Net::Mainnet
    } else {
        esplora::net()
    };
    let (s, d) = network_check(
        &info.network,
        api,
        esplora::custom_api(),
        esplora::proxy_desc().as_deref(),
    );
    report.add("Network configuration", s, d);
    let (s, d) = recovery_check(&info, words, bits);
    report.add("Recovery metadata", s, d);
    let (s, d) = memory_check();
    report.add("Secret memory", s, d);

    // The machine, not the wallet: what an attacker would need to be in place
    // before the password or the seed is typed.
    let (s, d) = session_check(ssh_session(), terminal_is_tty());
    report.add("Terminal session", s, d);
    let self_status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let (s, d) = tracer_check(parse_tracer(&self_status));
    report.add("Debugger / tracer", s, d);
    let (s, d) = loader_check(&loader_vars_set(), ld_preload().as_deref());
    report.add("Loader environment", s, d);
    let (s, d) = path_check(&path_entries());
    report.add("PATH safety", s, d);

    // The slow, animated part: real work happens under the spinner, which
    // `ui::spin` skips entirely when stdout is not a terminal.
    let ((ns, nd), (us, ud)) = if report.live {
        ui::spin("Scanning sockets, USB devices and terminal state", || {
            (listeners_check(), usb_check())
        })
    } else {
        (listeners_check(), usb_check())
    };
    report.add("Network exposure", ns, nd);
    report.add("USB devices", us, ud);
    let (ms, md) = if report.live {
        ui::spin("Scanning for malware signatures (ClamAV)", malware_check)
    } else {
        malware_check()
    };
    report.add("Malware scan", ms, md);

    // Features this build does not have. Never PASS, never silent.
    report.add(
        "Backup verification",
        Status::Skip,
        "not implemented: check a backup by restoring it on a second device",
    );
    report.add(
        "Hardware signer",
        Status::Skip,
        "not implemented: the seed is used on this computer and there is no way to pair a signing \
         device",
    );
    report.add(
        "Multisig",
        Status::Skip,
        "not implemented: single-key wallets only, so one device compromise spends the funds",
    );
    report.add(
        "Final transaction verification",
        Status::Skip,
        "not implemented: the signed transaction is rebuilt from the approved plan, not \
         re-displayed from the final signed bytes",
    );
    report.add(
        "Independent audit",
        Status::Skip,
        "no third-party audit is recorded for this build",
    );

    if json {
        println!("{}", report.json());
    } else {
        report.render();
    }

    let failures = report.count(Status::Fail);
    if failures > 0 {
        return Err(format!(
            "security check found {failures} failing check(s); see the report above"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(version: u32, passphrase: bool) -> keystore::FileInfo {
        keystore::FileInfo {
            version,
            kdf: "argon2id".into(),
            kdf_params: KdfParams::default_strong(),
            passphrase,
            fingerprint: "73c5da0a".into(),
            network: "mainnet".into(),
            size: 512,
            mode: 0o600,
            dir_mode: 0o700,
        }
    }

    #[test]
    fn known_versions_pass_and_legacy_warns() {
        assert_eq!(encryption_check(&info(2, false)).0, Status::Pass);
        assert_eq!(encryption_check(&info(3, true)).0, Status::Pass);
        assert_eq!(encryption_check(&info(1, false)).0, Status::Warn);
        assert_eq!(encryption_check(&info(9, false)).0, Status::Fail);
    }

    #[test]
    fn weak_but_accepted_kdf_warns_and_absurd_kdf_fails() {
        let default = KdfParams::default_strong();
        assert_eq!(kdf_check("argon2id", &default).0, Status::Pass);

        let weak = KdfParams {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        };
        assert_eq!(kdf_check("argon2id", &weak).0, Status::Warn);

        let absurd = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        assert_eq!(kdf_check("argon2id", &absurd).0, Status::Fail);
        assert_eq!(kdf_check("scrypt", &default).0, Status::Fail);
    }

    #[test]
    fn open_permissions_are_reported() {
        assert_eq!(permissions_check(0o600, 0o700, 512).0, Status::Pass);
        assert_eq!(permissions_check(0o644, 0o700, 512).0, Status::Warn);
        assert_eq!(permissions_check(0o600, 0o755, 512).0, Status::Warn);
    }

    #[test]
    fn public_providers_without_a_proxy_warn() {
        use esplora::Net;
        assert_eq!(
            network_check("mainnet", Net::Mainnet, false, None).0,
            Status::Warn
        );
        assert_eq!(
            network_check(
                "mainnet",
                Net::Mainnet,
                false,
                Some("socks5://127.0.0.1:9050")
            )
            .0,
            Status::Pass
        );
        assert_eq!(
            network_check("mainnet", Net::Mainnet, true, None).0,
            Status::Pass
        );
        assert_eq!(
            network_check("testnet", Net::Testnet4, true, None).0,
            Status::Pass
        );
        // A testnet wallet left pointing at the mainnet API, or the reverse.
        assert_eq!(
            network_check("testnet", Net::Mainnet, true, None).0,
            Status::Warn
        );
        assert_eq!(
            network_check("mainnet", Net::Testnet4, true, None).0,
            Status::Warn
        );
    }

    #[test]
    fn loader_injection_is_a_warning() {
        assert_eq!(loader_check(&[], None).0, Status::Pass);
        assert_eq!(loader_check(&["LD_PRELOAD"], None).0, Status::Warn);
        assert_eq!(
            loader_check(&["LD_PRELOAD", "LD_LIBRARY_PATH"], None).0,
            Status::Warn
        );
        // A system-wide preload hook is the same threat as an env var.
        let hooked = loader_check(&[], Some("/opt/hide.so"));
        assert_eq!(hooked.0, Status::Warn);
        assert!(hooked.1.contains("/opt/hide.so"));
    }

    #[test]
    fn only_an_unattached_process_is_not_traced() {
        let idle = "Name:\tcairn\nTracerPid:\t0\nUid:\t1000\n";
        assert_eq!(parse_tracer(idle), Some(0));
        assert_eq!(tracer_check(parse_tracer(idle)).0, Status::Pass);

        assert_eq!(parse_tracer("TracerPid:\t4242\n"), Some(4242));
        assert_eq!(tracer_check(Some(4242)).0, Status::Warn);

        assert_eq!(parse_tracer("Name:\tcairn\n"), None);
        assert_eq!(tracer_check(None).0, Status::Skip);
    }

    #[test]
    fn scanner_results_map_to_pass_fail_and_skip() {
        assert_eq!(scan_report("clamscan", 2, Some(0), "", "").0, Status::Pass);

        let infected = "/home/u/.cairn/wallets/main.cairn: Win.Trojan.Agent-1 FOUND\n";
        let found = scan_report("clamscan", 2, Some(1), infected, "");
        assert_eq!(
            found.0,
            Status::Fail,
            "a signature match must fail the check"
        );
        assert!(found.1.contains("Trojan"));

        let broken = scan_report("clamscan", 2, Some(2), "", "Database error\n");
        assert_eq!(broken.0, Status::Skip);
        assert!(broken.1.contains("Database error"));

        // Killed by a signal: no exit code at all, so nothing was inspected.
        assert_eq!(scan_report("clamscan", 2, None, "", "").0, Status::Skip);
    }

    #[test]
    fn writable_or_relative_path_entries_warn() {
        let root_owned = vec![("/usr/bin".to_string(), Some(0o040755))];
        assert_eq!(path_check(&root_owned).0, Status::Pass);

        let writable = vec![("/tmp/bin".to_string(), Some(0o041777))];
        assert_eq!(path_check(&writable).0, Status::Warn);

        let group_write = vec![("/opt/bin".to_string(), Some(0o040775))];
        assert_eq!(path_check(&group_write).0, Status::Warn);

        let relative = vec![("bin".to_string(), Some(0o040755))];
        assert_eq!(path_check(&relative).0, Status::Warn);

        let empty = vec![("".to_string(), None)];
        assert_eq!(path_check(&empty).0, Status::Warn);

        assert_eq!(path_check(&[]).0, Status::Skip);
    }

    #[test]
    fn proc_net_listeners_are_parsed_and_classified() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1\n\
             1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2\n\
             2: 0100007F:C001 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 3\n";
        let listeners = parse_listeners(table);
        assert_eq!(listeners.len(), 2, "only LISTEN rows count");
        assert!(is_loopback(&listeners[0].0));
        assert_eq!(listeners[0].1, 8080);
        assert!(!is_loopback(&listeners[1].0), "0.0.0.0 is not loopback");
        assert_eq!(listeners[1].1, 22);
        assert!(!is_loopback("00000000000000000000000000000000"));
        assert!(is_loopback("00000000000000000000000001000000"));
    }

    #[test]
    fn sessions_are_only_passes_when_local_and_interactive() {
        assert_eq!(session_check(false, true).0, Status::Pass);
        assert_eq!(session_check(true, true).0, Status::Warn);
        assert_eq!(session_check(false, false).0, Status::Warn);
    }

    #[test]
    fn passphrase_wallet_warns_and_unlocked_seed_passes() {
        assert_eq!(
            recovery_check(&info(3, true), Some(24), Some(256)).0,
            Status::Warn
        );
        assert_eq!(
            recovery_check(&info(2, false), Some(24), Some(256)).0,
            Status::Pass
        );
        assert_eq!(recovery_check(&info(2, false), None, None).0, Status::Skip);
    }

    #[test]
    fn worst_status_wins_and_nothing_claims_secure() {
        let mut r = Report::new("main", &info(2, false));
        r.add("a", Status::Pass, "ok");
        r.add("b", Status::Skip, "missing feature");
        assert_eq!(r.overall(), Status::Skip);
        assert_eq!(r.verdict(), "INCOMPLETE");

        r.add("c", Status::Warn, "review");
        assert_eq!(r.verdict(), "REVIEW RECOMMENDED");

        r.add("d", Status::Fail, "broken");
        assert_eq!(r.verdict(), "FAILED");

        let text = serde_json::to_string(&r.json()).unwrap();
        assert!(text.contains("\"fail\""));
        assert!(text.contains("not a security audit") || text.contains("Not a security audit"));
        assert!(!text.contains("\"secure\""));
    }
}
