mod esplora;
mod hardening;
mod keystore;
mod labels;
mod network;
mod offline;
mod psbt_guard;
mod qr;
mod send;
mod ui;
mod wallet;

use bip39::{Language, Mnemonic};
use bitcoin::Network;
use console::style;
use dialoguer::{Confirm, Input, Password};
use qrcode::{render::unicode, QrCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use ui::{banner, boxed, clear, fail, fmt_btc, menu, ok, pause, short, spin, theme};
use wallet::Watch;
use zeroize::Zeroizing;

const MIN_PASSWORD_LEN: usize = 12;
const IDLE_LOCK: Duration = Duration::from_secs(300);
static MAINNET_SESSION: AtomicBool = AtomicBool::new(false);
const MAINNET_NOTICE: &str = "\
Cairn is experimental and has completed multiple independent AI-assisted source reviews.
Mainnet uses real bitcoin; testnet is recommended for trying it out.";

fn main() {
    hardening::init();
    esplora::load_config();
    let interactive = std::env::args().nth(1).is_none();
    if let Err(e) = run() {
        println!();
        fail(&e);
        pause();
        std::process::exit(1);
    }
    if interactive {
        clear();
    }
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    args.retain(|a| a != "--json");
    let Some(cmd) = args.first() else {
        return interactive();
    };
    match cmd.as_str() {
        "-h" | "--help" => {
            help();
            Ok(())
        }
        "-V" | "--version" => version(json),
        "--descriptor" => {
            let (pos, out) = parse_args(&args[1..])?;
            if out.is_some() || pos.len() > 1 {
                return Err("usage: cairn --descriptor [WALLET] [--json]".into());
            }
            descriptor(pos.first().cloned(), json)
        }
        "--seedqr" => {
            let (pos, out) = parse_args(&args[1..])?;
            if out.is_some() || pos.len() > 1 {
                return Err("usage: cairn --seedqr [WALLET]".into());
            }
            seedqr(pos.first().cloned())
        }
        "--label" => {
            if args.len() < 3 {
                return Err("usage: cairn --label <TXID> <LABEL>".into());
            }
            label_tx(&args[1], &args[2..].join(" "), json)
        }
        "--create-psbt" => {
            let (pos, out) = parse_args(&args[1..])?;
            if pos.len() > 1 {
                return Err("usage: cairn --create-psbt [WALLET] [--out FILE]".into());
            }
            offline::create_psbt(pos.first().cloned(), out)
        }
        "--offline" => {
            let (pos, out) = parse_args(&args[1..])?;
            if pos.len() != 1 {
                return Err("usage: cairn --offline <UNSIGNED.psbt> [--out SIGNED.psbt]".into());
            }
            offline::sign_psbt(pos[0].clone(), out)
        }
        "--broadcast" => {
            let (pos, out) = parse_args(&args[1..])?;
            if out.is_some() || pos.len() != 2 {
                return Err("usage: cairn --broadcast <UNSIGNED.psbt> <SIGNED.psbt>".into());
            }
            offline::broadcast(pos[0].clone(), pos[1].clone())
        }
        "--qr-show" => {
            let (pos, out) = parse_args(&args[1..])?;
            if out.is_some() || pos.len() != 1 {
                return Err("usage: cairn --qr-show <FILE.psbt>".into());
            }
            offline::show_qr(pos[0].clone())
        }
        "--qr-scan" => {
            let (pos, out) = parse_args(&args[1..])?;
            if pos.is_empty() {
                return Err("usage: cairn --qr-scan [--out FILE.psbt] <IMAGE>...".into());
            }
            offline::scan_qr(pos, out)
        }
        other => Err(format!("unknown option '{other}' (try cairn --help)")),
    }
}

fn parse_args(args: &[String]) -> Result<(Vec<String>, Option<String>), String> {
    let mut pos = vec![];
    let mut out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" | "-o" => {
                i += 1;
                out = Some(args.get(i).ok_or("--out needs a file path")?.clone());
            }
            s if s.starts_with('-') => return Err(format!("unknown option '{s}'")),
            s => pos.push(s.to_string()),
        }
        i += 1;
    }
    Ok((pos, out))
}

fn version(json: bool) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::json!({"name": "cairn", "version": env!("CARGO_PKG_VERSION")})
        );
    } else {
        println!("cairn {}", env!("CARGO_PKG_VERSION"));
    }
    Ok(())
}

/// Export BIP84 watch-only descriptors for one wallet.
fn descriptor(wallet: Option<String>, json: bool) -> Result<(), String> {
    let name = choose_wallet(wallet.as_deref())?;
    let opened = unlock_wallet(&name)?;
    let network = opened.network;
    ui::set_network(network);
    let watch =
        Watch::from_mnemonic_with_passphrase(&opened.mnemonic, network, &opened.passphrase)?;
    let fp = opened.fingerprint.clone();
    drop(opened);
    let receive = watch.descriptor(0)?;
    let change = watch.descriptor(1)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "wallet": name,
                "network": network::label(network),
                "fingerprint": fp,
                "descriptors": {"receive": receive, "change": change},
            })
        );
    } else {
        banner();
        println!("{}\n", style("Watch-only descriptors (BIP84)").bold());
        println!("  Wallet:      {name}");
        println!("  Network:     {}", network::label(network));
        println!("  Fingerprint: {fp}\n");
        println!("  Receive: {}", style(receive).cyan());
        println!("  Change:  {}", style(change).cyan());
        println!(
            "\n{}",
            style("  These descriptors can see every address and balance, but cannot spend.")
                .yellow()
        );
    }
    Ok(())
}

/// Numeric SeedQR payload: each BIP39 word as a 4-digit index (1..=2048).
fn numeric_seedqr(mnemonic: &Mnemonic) -> Result<Zeroizing<String>, String> {
    let words = Language::English.word_list();
    let mut out = Zeroizing::new(String::with_capacity(24 * 4));
    for word in mnemonic.words() {
        let idx = words
            .iter()
            .position(|w| *w == word)
            .ok_or("seed word is not in the English BIP39 list")?
            + 1;
        out.push_str(&format!("{idx:04}"));
    }
    Ok(out)
}

/// Display a numeric SeedQR on the alternate screen. This reveals the seed, so
/// it is never written to disk and is wiped from the screen afterwards.
fn seedqr(wallet: Option<String>) -> Result<(), String> {
    let name = choose_wallet(wallet.as_deref())?;
    let opened = unlock_wallet(&name)?;
    let network = opened.network;
    ui::set_network(network);
    let payload = numeric_seedqr(&opened.mnemonic)?;
    drop(opened);

    let answer: String = Input::with_theme(&theme())
        .with_prompt("Type SHOW to display your SeedQR (anything else cancels)")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| e.to_string())?;
    if answer.trim() != "SHOW" {
        println!("\nCancelled. Nothing was shown.");
        return Ok(());
    }

    let code = QrCode::new(payload.as_bytes()).map_err(|e| e.to_string())?;
    let art = Zeroizing::new(
        code.render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .build(),
    );
    ui::secret_screen(|| {
        banner();
        println!("{}", style("NUMERIC SEEDQR — YOUR SEED").red().bold());
        println!(
            "{}",
            style("Scan only with a trusted offline device. This screen leaves no scrollback.")
                .yellow()
        );
        println!("\n{}\n", art.as_str());
        println!(
            "{}",
            style("Anyone who photographs this can take your coins.")
                .red()
                .bold()
        );
        pause();
    });
    Ok(())
}

fn label_tx(txid: &str, label: &str, json: bool) -> Result<(), String> {
    let mut labels = labels::Labels::load()?;
    labels.set(txid, label)?;
    if json {
        println!(
            "{}",
            serde_json::json!({"type": "tx", "ref": txid, "label": label})
        );
    } else {
        ok(&format!("Labelled {} as '{}'", short(txid), label));
    }
    Ok(())
}

fn help() {
    println!(
        "\
Cairn - experimental Bitcoin wallet (testnet by default)

Usage:
  cairn                                      Interactive wallet
  cairn --create-psbt [WALLET] [--out FILE]  Build an unsigned PSBT (online)
  cairn --offline <UNSIGNED.psbt> [--out SIGNED.psbt]
                                             Verify and sign a PSBT (offline)
  cairn --broadcast <UNSIGNED.psbt> <SIGNED.psbt>
                                             Broadcast a signed PSBT (online)
  cairn --qr-show <FILE.psbt>                Show a PSBT as QR frame(s)
  cairn --qr-scan [--out FILE.psbt] <IMAGE>...
                                             Rebuild a PSBT from QR photos
  cairn --descriptor [WALLET] [--json]       Export BIP84 watch-only descriptors
  cairn --seedqr [WALLET]                    Show a numeric SeedQR (reveals seed)
  cairn --label <TXID> <LABEL> [--json]      Store a BIP329 transaction label
  cairn --version [--json]                   Show the version
  cairn --help                               Show this help

Global:
  --json                                     Machine-readable output where supported

Environment:
  CAIRN_API=https://your-server/api          Use your own Esplora server
  CAIRN_PROXY=socks5://127.0.0.1:9050        Route API traffic through a proxy
  CAIRN_TOR=1                                Shorthand for the local Tor SOCKS port"
    );
}

/// Ask when a mainnet wallet is created or imported. Existing wallets use
/// their recorded network without another prompt.
pub(crate) fn confirm_mainnet() -> Result<(), String> {
    ui::set_network(Network::Bitcoin);
    banner();
    println!("{}\n", style(MAINNET_NOTICE).yellow());
    let proceed = Confirm::with_theme(&theme())
        .with_prompt("Use Mainnet with real bitcoin?")
        .default(false)
        .interact()
        .map_err(|e| e.to_string())?;
    if !proceed {
        ui::set_network(Network::Testnet);
        return Err("Mainnet session cancelled.".into());
    }
    MAINNET_SESSION.store(true, Ordering::SeqCst);
    Ok(())
}

/// One typed confirmation per process before any mainnet wallet is unlocked,
/// PSBT is created/signed, or transaction is broadcast (M-02). The flag is
/// process-local and resets when Cairn exits.
pub(crate) fn confirm_mainnet_session() -> Result<(), String> {
    if MAINNET_SESSION.load(Ordering::SeqCst) {
        return Ok(());
    }
    ui::set_network(Network::Bitcoin);
    banner();
    println!("{}\n", style(MAINNET_NOTICE).yellow());
    let answer: String = Input::with_theme(&theme())
        .with_prompt("Type MAINNET to use real bitcoin in this session")
        .allow_empty(true)
        .interact_text()
        .map_err(|e| e.to_string())?;
    if answer.trim() != "MAINNET" {
        return Err("Mainnet session not confirmed. Nothing was done.".into());
    }
    MAINNET_SESSION.store(true, Ordering::SeqCst);
    Ok(())
}

fn interactive() -> Result<(), String> {
    loop {
        banner();
        let choice = menu(&[
            "Create New Wallet",
            "Open Existing Wallet",
            "Import Wallet (seed phrase)",
            "Settings",
            "Exit",
        ])
        .unwrap_or(4);
        let result = match choice {
            0 => create_wallet(),
            1 => open_wallet(),
            2 => import_wallet(),
            3 => settings(),
            _ => break,
        };
        if let Err(e) = result {
            println!();
            fail(&e);
            pause();
        }
    }
    Ok(())
}

// ---------- input ----------

fn ask_name() -> Result<String, String> {
    let name: String = Input::with_theme(&theme())
        .with_prompt("Wallet name")
        .interact_text()
        .map_err(|e| e.to_string())?;
    if !keystore::valid_name(&name) {
        return Err("Name may only use letters, numbers, - and _ (max 32)".into());
    }
    Ok(name)
}

fn weak_password(pw: &str) -> Option<String> {
    let lower = pw.to_lowercase();
    let common = [
        "password1234",
        "123456789012",
        "qwertyuiop12",
        "iloveyou1234",
        "letmein12345",
    ];
    let mut uniq: Vec<char> = pw.chars().collect();
    uniq.sort();
    uniq.dedup();
    if pw.chars().count() < MIN_PASSWORD_LEN {
        Some(format!(
            "Password must be at least {MIN_PASSWORD_LEN} characters"
        ))
    } else if uniq.len() < 6 {
        Some("Password is too repetitive".into())
    } else if common.iter().any(|c| lower.contains(c)) {
        Some("Password is too common".into())
    } else {
        None
    }
}

fn ask_new_password() -> Result<Zeroizing<String>, String> {
    println!(
        "{}",
        style("Tip: 5+ random words make a strong, memorable passphrase.").dim()
    );
    let pw = Password::with_theme(&theme())
        .with_prompt("Set password")
        .with_confirmation("Repeat password", "Passwords don't match")
        .interact()
        .map_err(|e| e.to_string())?;
    let pw = Zeroizing::new(pw);
    if let Some(msg) = weak_password(&pw) {
        return Err(msg);
    }
    Ok(pw)
}

/// Optional BIP39 passphrase. It is never stored: losing it loses the wallet,
/// and every unlock must re-enter it. This is separate from the file password.
fn ask_passphrase() -> Result<Option<Zeroizing<String>>, String> {
    let add = Confirm::with_theme(&theme())
        .with_prompt("Add a BIP39 passphrase? (advanced; default no)")
        .default(false)
        .interact()
        .map_err(|e| e.to_string())?;
    if !add {
        return Ok(None);
    }
    println!(
        "{}",
        style("  The passphrase is never stored. If you lose it, the wallet is unrecoverable.")
            .yellow()
    );
    let pass = Password::with_theme(&theme())
        .with_prompt("BIP39 passphrase")
        .with_confirmation("Repeat passphrase", "Passphrases don't match")
        .interact()
        .map_err(|e| e.to_string())?;
    if pass.is_empty() {
        return Err("An empty passphrase is the same as no passphrase. Nothing was saved.".into());
    }
    Ok(Some(Zeroizing::new(pass)))
}

// ---------- create / import / open ----------

/// Testnet is the recommended default. Mainnet is always available and still
/// gets a one-time confirmation.
fn ask_network() -> Result<Network, String> {
    let i = menu(&[
        "Testnet (recommended; no real funds)",
        "Mainnet (real bitcoin; experimental)",
    ])?;
    if i == 1 {
        confirm_mainnet()?;
        Ok(Network::Bitcoin)
    } else {
        Ok(Network::Testnet)
    }
}

fn create_wallet() -> Result<(), String> {
    banner();
    println!("{}\n", style("Create New Wallet").bold());
    let network = ask_network()?;
    ui::set_network(network);
    let name = ask_name()?;
    let password = ask_new_password()?;
    let passphrase = ask_passphrase()?;

    // 256 bits of OS randomness -> 24 words.
    let entropy = Zeroizing::new(keystore::random_bytes::<32>()?);
    let mnemonic = Mnemonic::from_entropy(entropy.as_ref()).map_err(|e| e.to_string())?;
    let words: Vec<&str> = mnemonic.words().collect();

    // Shown on the terminal's alternate screen: never enters scrollback, wiped afterwards.
    ui::secret_screen(|| {
        banner();
        println!("{}", style("WRITE THESE 24 WORDS ON PAPER").red().bold());
        println!(
            "{}\n",
            style("Anyone with them can take your coins. No photos, no screenshots.").yellow()
        );
        for i in 0..12 {
            println!(
                "  {:>2}. {:<9}  {:>2}. {}",
                i + 1,
                style(words[i]).bold(),
                i + 13,
                style(words[i + 12]).bold()
            );
        }
        println!();
        pause();
    });

    // Quiz: 3 distinct random positions (rejection sampling avoids modulo bias).
    let mut picks: Vec<usize> = vec![];
    while picks.len() < 3 {
        let r = keystore::random_bytes::<1>()?[0] as usize;
        if r < 240 {
            let idx = r % 24;
            if !picks.contains(&idx) {
                picks.push(idx);
            }
        }
    }
    picks.sort();
    banner();
    println!(
        "{}\n",
        style("Backup check: enter these words from your paper copy").bold()
    );
    for idx in picks {
        let answer: String = Input::with_theme(&theme())
            .with_prompt(format!("Word #{}", idx + 1))
            .interact_text()
            .map_err(|e| e.to_string())?;
        if answer.trim().to_lowercase() != words[idx] {
            return Err(
                "Wrong word. Wallet NOT saved. Check your paper backup and start again.".into(),
            );
        }
    }

    spin("Encrypting wallet…", || {
        keystore::save_with_passphrase(
            &name,
            &password,
            &mnemonic,
            network,
            passphrase.as_ref().map(|p| p.as_str()),
            keystore::KdfParams::default_strong(),
        )
    })?;
    let fp = keystore::fingerprint_with(
        &mnemonic,
        network,
        passphrase.as_ref().map(|p| p.as_str()).unwrap_or(""),
    )?;
    banner();
    ok(&format!("Wallet '{}' created", style(&name).bold()));
    println!("  Fingerprint: {fp}");
    println!("  Stored encrypted at ~/.cairn/wallets/{name}.cairn");
    println!(
        "{}\n",
        style("  Your paper backup is the real recovery path. Keep it safe.").yellow()
    );
    pause();
    Ok(())
}

fn import_wallet() -> Result<(), String> {
    banner();
    println!("{}\n", style("Import Wallet").bold());
    let network = ask_network()?;
    ui::set_network(network);
    let name = ask_name()?;
    let phrase = Zeroizing::new(
        Password::with_theme(&theme())
            .with_prompt("Seed phrase (hidden)")
            .interact()
            .map_err(|e| e.to_string())?,
    );
    let again = Zeroizing::new(
        Password::with_theme(&theme())
            .with_prompt("Seed phrase again (hidden)")
            .interact()
            .map_err(|e| e.to_string())?,
    );
    if phrase.trim() != again.trim() {
        return Err("Seed phrases do not match. Nothing was saved.".into());
    }
    let mnemonic =
        Mnemonic::parse(phrase.trim()).map_err(|e| format!("Invalid seed phrase: {e}"))?;
    let password = ask_new_password()?;
    let passphrase = ask_passphrase()?;
    spin("Encrypting wallet…", || {
        keystore::save_with_passphrase(
            &name,
            &password,
            &mnemonic,
            network,
            passphrase.as_ref().map(|p| p.as_str()),
            keystore::KdfParams::default_strong(),
        )
    })?;
    ok(&format!(
        "Imported. Fingerprint: {}",
        keystore::fingerprint_with(
            &mnemonic,
            network,
            passphrase.as_ref().map(|p| p.as_str()).unwrap_or(""),
        )?
    ));
    pause();
    Ok(())
}

pub(crate) fn choose_wallet(preselect: Option<&str>) -> Result<String, String> {
    let wallets = keystore::list_wallets()?;
    if wallets.is_empty() {
        return Err("No wallets found. Create or import one first.".into());
    }
    if let Some(name) = preselect {
        if wallets.iter().any(|w| w == name) {
            return Ok(name.to_string());
        }
        return Err(format!("No wallet named '{name}'"));
    }
    let items: Vec<&str> = wallets.iter().map(|s| s.as_str()).collect();
    let i = menu(&items)?;
    Ok(wallets[i].clone())
}

pub(crate) fn unlock_wallet(name: &str) -> Result<keystore::Opened, String> {
    unlock_wallet_with(name, None, "Password")
}

/// Single password-retry policy for opening a wallet and for re-authenticating
/// before signing. The expected fingerprint is optional, but when supplied it is
/// checked *before* any spending key is derived.
pub(crate) fn unlock_wallet_with(
    name: &str,
    expected_fp: Option<&str>,
    prompt: &str,
) -> Result<keystore::Opened, String> {
    let needs_passphrase = keystore::requires_passphrase(name)?;
    // Growing delay after each wrong attempt, 5 tries max.
    let mut unlocked = None;
    for attempt in 0..5u32 {
        let pw = Zeroizing::new(
            Password::with_theme(&theme())
                .with_prompt(prompt)
                .interact()
                .map_err(|e| e.to_string())?,
        );
        let passphrase = if needs_passphrase {
            Some(Zeroizing::new(
                Password::with_theme(&theme())
                    .with_prompt("BIP39 passphrase (hidden)")
                    .interact()
                    .map_err(|e| e.to_string())?,
            ))
        } else {
            None
        };
        let opened = spin("Unlocking…", || {
            keystore::open_with(name, &pw, passphrase.as_ref().map(|p| p.as_str()))
        });
        match opened {
            Ok(opened) => {
                if expected_fp
                    .map(|fp| opened.fingerprint.as_str() != fp)
                    .unwrap_or(false)
                {
                    return Err("Wallet fingerprint changed. Nothing was signed.".into());
                }
                if opened.network == Network::Bitcoin {
                    confirm_mainnet_session()?;
                }
                unlocked = Some(opened);
                break;
            }
            Err(e) => {
                fail(&e);
                std::thread::sleep(Duration::from_secs(1u64 << attempt.min(3)));
            }
        }
    }
    unlocked.ok_or_else(|| "Too many failed attempts".to_string())
}

fn open_wallet() -> Result<(), String> {
    banner();
    println!("{}\n", style("Open Wallet").bold());
    let name = choose_wallet(None)?;
    let opened = unlock_wallet(&name)?;
    let network = opened.network;
    ui::set_network(network);
    // Keep only the public account key; the seed is wiped from memory right here.
    let watch =
        Watch::from_mnemonic_with_passphrase(&opened.mnemonic, network, &opened.passphrase)?;
    let fp = opened.fingerprint.clone();
    drop(opened);
    dashboard(&name, &fp, &watch)
}

// ---------- dashboard ----------

fn run_sync(
    watch: &Watch,
    gap: u32,
    prev: Option<&esplora::WalletState>,
) -> Result<esplora::WalletState, String> {
    spin("Syncing with network…", || {
        esplora::sync(watch, gap, prev)
    })
}

fn dashboard(name: &str, fp: &str, watch: &Watch) -> Result<(), String> {
    // The last good balance is kept in memory; a failed refresh never wipes it.
    let mut state: Option<esplora::WalletState> = None;
    let mut synced_at: Option<Instant> = None;
    let mut last_err: Option<String> = None;
    match run_sync(watch, esplora::FULL_GAP, None) {
        Ok(s) => {
            state = Some(s);
            synced_at = Some(Instant::now());
        }
        Err(e) => last_err = Some(e),
    }
    loop {
        banner();
        println!(
            "{} {}   {} {}
",
            style("wallet").dim(),
            style(name).bold(),
            style("fp").dim(),
            fp
        );
        match &state {
            Some(s) => {
                let mut lines = vec![
                    style("BALANCE").dim().to_string(),
                    format!(
                        "{} {}",
                        style(fmt_btc(s.confirmed)).green().bold(),
                        style(network::unit(watch.network())).dim()
                    ),
                ];
                if s.unconfirmed != 0 {
                    lines.push(
                        style(format!("{} pending", fmt_btc(s.unconfirmed)))
                            .yellow()
                            .to_string(),
                    );
                }
                lines.push(
                    style(format!(
                        "{} address(es) used · next receive #{}",
                        s.used.len(),
                        s.next_receive
                    ))
                    .dim()
                    .to_string(),
                );
                if let Some(t) = synced_at {
                    lines.push(
                        style(format!("updated {}s ago", t.elapsed().as_secs()))
                            .dim()
                            .to_string(),
                    );
                }
                if last_err.is_some() {
                    lines.push(
                        style("⚠ refresh failed, showing last balance")
                            .yellow()
                            .to_string(),
                    );
                }
                boxed(&lines);
            }
            None => boxed(&[
                style("BALANCE").dim().to_string(),
                style("not synced (choose Refresh)").yellow().to_string(),
            ]),
        }
        if let Some(p) = esplora::proxy_desc() {
            ui::info(&format!("proxy: {p}"));
        }
        if let Some(e) = &last_err {
            ui::warn(e);
        }
        println!();
        let asked = Instant::now();
        let choice = menu(&[
            "Send  ↗",
            "Receive  ↙",
            "Transactions",
            "Refresh",
            "Wallet Info",
            "Lock & Exit",
        ])
        .unwrap_or(5);
        if asked.elapsed() > IDLE_LOCK {
            banner();
            fail("Locked after 5 minutes of inactivity. Open the wallet again.");
            pause();
            return Ok(());
        }
        match choice {
            0 => match state.as_ref() {
                None => {
                    println!();
                    fail("Not synced. Choose Refresh first.");
                    pause();
                }
                Some(s) => match send::send_flow(name, fp, watch, s) {
                    Ok(true) => match run_sync(watch, esplora::QUICK_GAP, state.as_ref()) {
                        Ok(ns) => {
                            state = Some(ns);
                            synced_at = Some(Instant::now());
                            last_err = None;
                        }
                        Err(e) => last_err = Some(e),
                    },
                    Ok(false) => {}
                    Err(e) => {
                        println!();
                        fail(&e);
                        pause();
                    }
                },
            },
            1 => receive_screen(watch, state.as_ref())?,
            2 => transactions_screen(watch.network(), state.as_ref())?,
            3 => {
                // Quick re-check of everything known; falls back to a full scan if nothing is cached.
                let gap = if state.is_some() {
                    esplora::QUICK_GAP
                } else {
                    esplora::FULL_GAP
                };
                match run_sync(watch, gap, state.as_ref()) {
                    Ok(s) => {
                        state = Some(s);
                        synced_at = Some(Instant::now());
                        last_err = None;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            4 => info_screen(fp, watch)?,
            _ => return Ok(()),
        }
    }
}

fn receive_screen(watch: &Watch, state: Option<&esplora::WalletState>) -> Result<(), String> {
    let network = watch.network();
    let mut index = state.map(|s| s.next_receive).unwrap_or(0);
    loop {
        banner();
        let addr = watch.address_at(0, index)?;
        println!(
            "{}\n",
            style(format!("Receive ({})", network::label(network))).bold()
        );
        println!("  {}", style(&addr).cyan().bold());
        println!(
            "  {}\n",
            style(wallet::derivation_path(network, 0, index)).dim()
        );
        if network == Network::Bitcoin {
            println!(
                "{}",
                style("  Mainnet address. Verify it on your device before sharing.").yellow()
            );
        } else {
            println!("  Send only TESTNET coins here (e.g. from a faucet).");
        }
        println!("  Use a fresh address for each payment.");
        if state.is_none() {
            println!(
                "{}",
                style("  Not synced: this address may already be used.").yellow()
            );
        }
        println!();
        match menu(&["Show QR code", "Next address", "Back"])? {
            0 => show_qr(&addr)?,
            1 => index += 1,
            _ => return Ok(()),
        }
    }
}

fn show_qr(addr: &str) -> Result<(), String> {
    banner();
    // Uppercase bech32 uses the compact QR alphanumeric mode.
    let code = QrCode::new(addr.to_uppercase().as_bytes()).map_err(|e| e.to_string())?;
    let art = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{}\n", art);
    println!("  {}", style(addr).cyan());
    println!(
        "{}\n",
        style("  If it won't scan, zoom out the terminal or check colors.").dim()
    );
    pause();
    Ok(())
}

fn transactions_screen(
    network: Network,
    state: Option<&esplora::WalletState>,
) -> Result<(), String> {
    banner();
    println!("{}\n", style("Transactions").bold());
    let Some(s) = state else {
        fail("Not synced. Go back and Refresh first.");
        pause();
        return Ok(());
    };
    if s.used.is_empty() {
        println!("  No transactions yet.");
        println!();
        pause();
        return Ok(());
    }
    let txs = match spin("Loading transactions…", || {
        esplora::transactions(esplora::net_for(network)?, s)
    }) {
        Ok(txs) => txs,
        Err(e) => {
            fail(&e);
            println!();
            pause();
            return Ok(());
        }
    };
    if txs.is_empty() {
        println!("  No transactions yet.");
        println!();
        pause();
        return Ok(());
    }
    let mut labels = labels::Labels::load().unwrap_or_else(|_| labels::Labels::empty());
    for t in txs.iter().take(15) {
        let (icon, amount) = if t.net >= 0 {
            (
                style("↙").green(),
                style(format!("+{}", fmt_btc(t.net))).green().bold(),
            )
        } else {
            (style("↗").red(), style(fmt_btc(t.net)).red().bold())
        };
        let status = match t.height {
            Some(h) => style(format!("block {h}")).dim(),
            None => style("pending".to_string()).yellow(),
        };
        let label = labels
            .get(&t.txid)
            .map(|l| format!("  {}", style(l).magenta()))
            .unwrap_or_default();
        println!("  {} {}  {}{}", icon, amount, status, label);
        println!("    {}\n", style(short(&t.txid)).dim());
    }

    // BIP329 labels are local-only metadata; they are never sent to a server.
    let mut items: Vec<String> = txs
        .iter()
        .take(15)
        .map(|t| format!("Label {}", short(&t.txid)))
        .collect();
    items.push("Back".to_string());
    let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
    if let Ok(i) = menu(&refs) {
        if i < txs.len().min(15) {
            let txid = txs[i].txid.clone();
            let current = labels.get(&txid).unwrap_or("").to_string();
            let label: String = Input::with_theme(&theme())
                .with_prompt("Label (empty removes)")
                .with_initial_text(current)
                .allow_empty(true)
                .interact_text()
                .map_err(|e| e.to_string())?;
            let result = if label.trim().is_empty() {
                labels.remove(&txid)
            } else {
                labels.set(&txid, &label)
            };
            match result {
                Ok(()) => ok("Label saved (BIP329, local only)"),
                Err(e) => fail(&e),
            }
        }
    }
    println!();
    pause();
    Ok(())
}

fn info_screen(fp: &str, watch: &Watch) -> Result<(), String> {
    let net = esplora::net_for(watch.network())?;
    banner();
    ui::section("Wallet Info");
    println!();
    ui::kv("Fingerprint", fp);
    ui::kv("Address type", "native SegWit (BIP84)");
    ui::kv(
        "Network",
        &format!(
            "{} (wallet: {})",
            net.label(),
            network::label(watch.network())
        ),
    );
    ui::kv("API servers", &esplora::providers_desc(net));
    ui::kv(
        "Proxy",
        &esplora::proxy_desc().unwrap_or_else(|| "off (direct connection)".into()),
    );
    ui::kv("Seed in memory", "no (wiped after unlock)");
    ui::kv("Idle lock", "5 minutes");
    println!("\n  Account xpub (watch-only; can see balance, cannot spend):");
    println!("  {}", style(watch.xpub_string()).cyan());
    println!("\n  Watch-only descriptors (BIP84):");
    println!("  Receive: {}", style(watch.descriptor(0)?).cyan());
    println!("  Change:  {}", style(watch.descriptor(1)?).cyan());
    println!(
        "\n{}",
        style("  Anyone with the xpub or descriptors can see all your addresses and balance.")
            .yellow()
    );
    println!(
        "{}\n",
        style("  Seed words are never shown here. Use your paper backup.").dim()
    );
    if watch.network() == Network::Bitcoin {
        println!(
            "{}\n",
            style("  Mainnet: real bitcoin; experimental software.").yellow()
        );
    }
    pause();
    Ok(())
}

fn settings() -> Result<(), String> {
    loop {
        banner();
        println!("{}\n", style("Settings").bold());
        let current = esplora::net();
        println!("  Network:     {}", style(current.label()).cyan().bold());
        println!(
            "  API servers: {}",
            style(esplora::providers_desc(current)).dim()
        );
        println!(
            "  Proxy:       {}",
            style(esplora::proxy_desc().unwrap_or_else(|| "off (direct connection)".into())).dim()
        );
        println!(
            "{}\n",
            style(
                "  Set CAIRN_API=https://your-server/api for your own node, or \
                 CAIRN_TOR=1 / CAIRN_PROXY=socks5://host:port for Tor."
            )
            .dim()
        );
        let nets = esplora::selectable_nets();
        let items: Vec<String> = nets
            .iter()
            .map(|n| format!("Use {}", n.label()))
            .chain(std::iter::once("Back".to_string()))
            .collect();
        let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
        let i = menu(&refs)?;
        if i >= nets.len() {
            return Ok(());
        }
        esplora::set_net(nets[i])?;
    }
}
