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
}

impl Report {
    fn new(wallet: &str, info: &keystore::FileInfo) -> Self {
        Report {
            wallet: wallet.to_string(),
            network: info.network.clone(),
            fingerprint: None,
            checks: Vec::new(),
        }
    }

    fn add(&mut self, name: &str, status: Status, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.to_string(),
            status,
            detail: detail.into(),
        });
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

    fn render(&self) {
        ui::set_context(format!("Security check  ·  {}", self.wallet));
        ui::banner();
        if let Some(fp) = &self.fingerprint {
            ui::kv("Fingerprint", fp);
        }
        ui::kv("Network", &self.network);
        println!();
        for c in &self.checks {
            println!(
                "  {} {:<32} {}",
                c.status.styled(),
                c.name,
                style(&c.detail).dim()
            );
        }
        println!();
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

// ---------- command ----------

pub fn check(name: &str, json: bool) -> Result<(), String> {
    let info = keystore::inspect(name)?;
    let mut report = Report::new(name, &info);

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
