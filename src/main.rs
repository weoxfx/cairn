mod bump;
mod esplora;
mod evm;
mod evm_cli;
mod hardening;
mod keystore;
mod labels;
mod network;
mod offline;
mod passphrase;
mod psbt_guard;
mod qr;
mod security;
mod send;
mod ui;
mod wallet;

use bip39::{Language, Mnemonic};
use bitcoin::Network;
use console::style;
use dialoguer::{Confirm, Input, Password};
use qrcode::{render::unicode, QrCode};
use std::time::{Duration, Instant};
use ui::{
    banner, card, clear, fail, fmt_btc, fmt_sats, hint, menu, ok, pause, section, short, spin,
    theme,
};
use wallet::Watch;
use zeroize::Zeroizing;

const MIN_PASSWORD_LEN: usize = 12;
const IDLE_LOCK: Duration = Duration::from_secs(300);

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
        "security" => {
            if args.get(1).map(|a| a.as_str()) != Some("check") {
                return Err("usage: cairn security check [WALLET] [--json]".into());
            }
            security_check(&args[2..], json)
        }
        "--security-check" => security_check(&args[1..], json),
        "evm" => evm_cli::run(&args[1..], json),
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

/// `cairn security check` — report what this build can and cannot verify.
fn security_check(args: &[String], json: bool) -> Result<(), String> {
    let (pos, out) = parse_args(args)?;
    if out.is_some() || pos.len() > 1 {
        return Err("usage: cairn security check [WALLET] [--json]".into());
    }
    let name = choose_wallet(pos.first().map(|s| s.as_str()))?;
    security::check(&name, json)
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
    let watch = Watch::from_opened(&opened)?;
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
        section("Watch-only descriptors");
        println!();
        ui::kv("Wallet", &name);
        ui::kv("Network", network::label(network));
        ui::kv("Fingerprint", &fp);
        println!();
        ui::kv("Receive", &style(receive).cyan().to_string());
        ui::kv("Change", &style(change).cyan().to_string());
        println!();
        hint("Watch-only: these descriptors can see every address and balance, but cannot spend.");
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
        section("Numeric SeedQR");
        println!(
            "  {}",
            style("Your seed as a numeric QR code. Scan it only on a trusted offline device.")
                .dim()
        );
        println!("\n{}\n", art.as_str());
        hint("This screen is not kept in scrollback. Clear the terminal when finished.");
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
Cairn — self-custody Bitcoin wallet

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
  cairn security check [WALLET] [--json]     Report what this build can verify
  cairn --security-check [WALLET] [--json]   Same as `security check`
  cairn evm <command>                        EVM accounts, tokens and transfers
                                             (see `cairn evm help`)
  cairn --version [--json]                   Show the version
  cairn --help                               Show this help

Global:
  --json                                     Machine-readable output where supported

Environment:
  CAIRN_API=https://your-server/api          Use your own Esplora server
  CAIRN_PROXY=socks5://127.0.0.1:9050        Route API traffic through a proxy
  CAIRN_TOR=1                                Shorthand for the local Tor SOCKS port

Network:
  Mainnet is used by default for new wallets. Testnet (Testnet4, Testnet3
  and Signet) can be selected when creating or importing a wallet."
    );
}

fn interactive() -> Result<(), String> {
    loop {
        ui::set_context("Home");
        banner();
        match keystore::list_wallets() {
            Ok(list) if !list.is_empty() => {
                section("Wallets");
                println!();
                // Public header fields only: no password, no key material.
                let rows: Vec<Vec<String>> = list
                    .iter()
                    .take(6)
                    .map(|n| {
                        let info = keystore::inspect(n).ok();
                        let net = info.as_ref().map(|i| i.network.clone()).unwrap_or_default();
                        let fp = info
                            .as_ref()
                            .map(|i| i.fingerprint.clone())
                            .unwrap_or_default();
                        vec![
                            style(n).bold().to_string(),
                            style(net).dim().to_string(),
                            style(fp).cyan().dim().to_string(),
                        ]
                    })
                    .collect();
                ui::table(
                    &["Wallet", "Network", "Fingerprint"],
                    &rows,
                    &[false, false, false],
                );
                if list.len() > 6 {
                    println!();
                    hint(&format!("and {} more", list.len() - 6));
                }
            }
            _ => {
                card(
                    "Getting started",
                    &[
                        style("No wallets yet — create one or import a seed phrase.")
                            .dim()
                            .to_string(),
                    ],
                );
            }
        }
        println!();
        hint("The seed is stored encrypted and only decrypted while signing.");
        println!();
        let choice = menu(&[
            "＋  Create a new wallet",
            "◇  Open existing wallet",
            "⇩  Import seed phrase",
            "⚙  Settings",
            "⏻  Exit",
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
    if ui::confirm("Generate a strong random password for you?", false) {
        return suggest_password();
    }
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

/// Generate a password, show it once on the alternate screen (no scrollback) and
/// keep it only if the user confirms they wrote it down.
fn suggest_password() -> Result<Zeroizing<String>, String> {
    let pw = passphrase::generate(passphrase::DEFAULT_WORDS)?;
    ui::secret_screen(|| {
        banner();
        section("Wallet password");
        println!();
        println!("  {}", style(pw.as_str()).bold().cyan());
        println!();
        hint(&format!(
            "{} words from a 2048-word list: {} bits of entropy.",
            passphrase::DEFAULT_WORDS,
            passphrase::entropy_bits(passphrase::DEFAULT_WORDS)
        ));
        hint("Write it down now, on paper and not in this terminal.");
        hint("It is not stored anywhere: without it the wallet cannot be opened.");
        println!();
        pause();
    });
    if !ui::confirm("Have you written this password down?", false) {
        return Err(
            "No wallet was created. Start again when you can write the password down.".into(),
        );
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

/// Mainnet is the default. Testnet remains available for development and testing.
fn ask_network() -> Result<Network, String> {
    hint("Mainnet is for real bitcoin. Testnet is for testing.");
    println!();
    let i = menu(&["Mainnet", "Testnet"])?;
    Ok(if i == 0 {
        Network::Bitcoin
    } else {
        Network::Testnet
    })
}

/// Which script type this wallet derives. Funds sit behind whichever addresses
/// the wallet showed, so the choice is stored (and authenticated) in the wallet
/// file rather than kept as a global preference.
fn ask_address_type() -> Result<keystore::AddressType, String> {
    println!();
    let items = [
        "Native SegWit (BIP84)  ·  bc1q…  accepted everywhere",
        "Taproot (BIP86)  ·  bc1p…  cheaper to spend, key-path only",
    ];
    let refs = items.to_vec();
    Ok(match menu(&refs)? {
        0 => keystore::AddressType::P2wpkh,
        _ => keystore::AddressType::P2tr,
    })
}

fn create_wallet() -> Result<(), String> {
    banner();
    section("Create wallet");
    println!();
    let network = ask_network()?;
    ui::set_network(network);
    let address_type = ask_address_type()?;
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
        section("Recovery phrase");
        println!(
            "  {}",
            style("Write down these 24 words in order and keep them offline.").dim()
        );
        println!();
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
    section("Backup check");
    println!();
    hint("Enter three words from your paper backup.");
    println!();
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
            address_type,
        )
    })?;
    let fp = keystore::fingerprint_with(
        &mnemonic,
        network,
        passphrase.as_ref().map(|p| p.as_str()).unwrap_or(""),
    )?;
    banner();
    ok(&format!("Wallet '{}' created", style(&name).bold()));
    println!();
    ui::kv("Fingerprint", &fp);
    ui::kv("Location", &format!("~/.cairn/wallets/{name}.cairn"));
    println!();
    hint("Keep your paper recovery phrase somewhere safe.");
    pause();
    Ok(())
}

fn import_wallet() -> Result<(), String> {
    banner();
    section("Import wallet");
    println!();
    let network = ask_network()?;
    ui::set_network(network);
    let address_type = ask_address_type()?;
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
            address_type,
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
    section("Open wallet");
    println!();
    let name = choose_wallet(None)?;
    let opened = unlock_wallet(&name)?;
    let network = opened.network;
    ui::set_network(network);
    // Keep only the public account key; the seed is wiped from memory right here.
    let watch = Watch::from_opened(&opened)?;
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
        ui::set_context(format!("{name}  ·  {fp}"));
        banner();
        let unit = network::unit(watch.network());
        match &state {
            Some(s) => {
                let mut lines = vec![
                    format!(
                        "{}  {}",
                        style(fmt_btc(s.confirmed)).cyan().bold(),
                        style(unit).dim()
                    ),
                    style(format!("{} sats", fmt_sats(s.confirmed)))
                        .dim()
                        .to_string(),
                ];
                if s.unconfirmed != 0 {
                    lines.push(
                        style(format!("{} {} pending", fmt_btc(s.unconfirmed), unit))
                            .yellow()
                            .bold()
                            .to_string(),
                    );
                }
                card("Balance", &lines);
                println!();
                let updated = synced_at
                    .map(|t| format!("{}s ago", t.elapsed().as_secs()))
                    .unwrap_or_else(|| "just now".into());
                ui::grid(&[
                    ("Addresses", &format!("{} used", s.used.len())),
                    ("Next receive", &format!("#{}", s.next_receive)),
                    ("Change", &format!("#{}", s.next_change)),
                    ("Updated", &updated),
                ]);
            }
            None => card(
                "Balance",
                &[
                    style("Not synced").yellow().bold().to_string(),
                    style("Choose Refresh to load your balance.")
                        .dim()
                        .to_string(),
                ],
            ),
        }
        if let Some(p) = esplora::proxy_desc() {
            println!();
            ui::info(&format!("Tor/proxy {p}"));
        }
        if let Some(e) = &last_err {
            println!();
            ui::warn(e);
            hint("Showing the last known balance.");
        }
        println!();
        let asked = Instant::now();
        let choice = menu(&[
            "↑  Send bitcoin",
            "↓  Receive",
            "☰  Transactions",
            "⚡  Bump fee",
            "⟳  Refresh",
            "ⓘ  Wallet information",
            "⛨  Security check",
            "⏻  Lock and exit",
        ])
        .unwrap_or(7);
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
            3 => match state.as_ref() {
                None => {
                    println!();
                    fail("Not synced. Choose Refresh first.");
                    pause();
                }
                Some(s) => match bump::bump_flow(name, fp, watch, s) {
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
            4 => {
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
            5 => info_screen(fp, watch)?,
            6 => {
                // Re-authenticates: proving the ciphertext still decrypts is the
                // point of the integrity check, so the password is asked again.
                if let Err(e) = security::check(name, false) {
                    println!();
                    fail(&e);
                }
                pause();
            }
            _ => return Ok(()),
        }
    }
}

fn receive_screen(watch: &Watch, state: Option<&esplora::WalletState>) -> Result<(), String> {
    let network = watch.network();
    let mut index = state.map(|s| s.next_receive).unwrap_or(0);
    loop {
        ui::set_context(format!("Receive  ·  {}", network::label(network)));
        banner();
        let addr = watch.address_at(0, index)?;
        card(
            "Receiving address",
            &[
                style(&addr).cyan().bold().to_string(),
                style(wallet::derivation_path(network, watch.kind(), 0, index))
                    .dim()
                    .to_string(),
            ],
        );
        println!();
        hint("Use a fresh address for every payment and verify it before sharing.");
        if state.is_none() {
            ui::warn("Not synced yet: this address may already have been used.");
        }
        println!();
        match menu(&["⊞  Show QR code", "＋  New address", "←  Back"])? {
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
    println!("  {}", style(addr).cyan().bold());
    println!();
    hint("Scan with any Bitcoin wallet. If it does not scan, enlarge the terminal.");
    pause();
    Ok(())
}

fn transactions_screen(
    network: Network,
    state: Option<&esplora::WalletState>,
) -> Result<(), String> {
    banner();
    section("Transactions");
    println!();
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
    let unit = network::unit(network);
    let rows: Vec<Vec<String>> = txs
        .iter()
        .take(15)
        .map(|t| {
            let (dir, amount) = if t.net >= 0 {
                (
                    style("↓ in").green().bold().to_string(),
                    style(format!("+{}", fmt_btc(t.net)))
                        .green()
                        .bold()
                        .to_string(),
                )
            } else {
                (
                    style("↑ out").red().bold().to_string(),
                    style(fmt_btc(t.net)).red().bold().to_string(),
                )
            };
            let status = match t.height {
                Some(h) => style(format!("confirmed {h}")).dim().to_string(),
                None => style("pending".to_string()).yellow().to_string(),
            };
            let label = labels.get(&t.txid).unwrap_or("").to_string();
            vec![
                dir,
                amount,
                status,
                label,
                style(short(&t.txid)).dim().to_string(),
            ]
        })
        .collect();
    ui::table(
        &["Type", "Amount", "Status", "Label", "Txid"],
        &rows,
        &[false, true, false, false, false],
    );
    println!();
    hint(&format!(
        "Amounts in {unit} · the {} most recent transactions",
        rows.len()
    ));
    println!();

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
                Ok(()) => ok("Label saved"),
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
    ui::set_context(format!("Wallet information  ·  {fp}"));
    banner();
    let identity = vec![
        format!(
            "{:<12}{}",
            style("Fingerprint").dim(),
            style(fp).cyan().to_string()
        ),
        format!(
            "{:<12}{}",
            style("Network").dim(),
            format!(
                "{} (wallet: {})",
                net.label(),
                network::label(watch.network())
            )
        ),
        format!(
            "{:<12}{}",
            style("Script type").dim(),
            "Native SegWit · BIP84"
        ),
        format!(
            "{:<12}{}",
            style("Keys").dim(),
            "watch-only session (seed wiped after unlock)"
        ),
    ];
    card("Identity", &identity);
    println!();
    section("Connection");
    println!();
    ui::kv("API servers", &esplora::providers_desc(net));
    ui::kv(
        "Proxy",
        &esplora::proxy_desc().unwrap_or_else(|| "off (direct connection)".into()),
    );
    ui::kv("Idle lock", "5 minutes");
    println!();
    section("Account xpub");
    println!();
    println!("  {}", style(watch.xpub_string()).cyan());
    println!();
    section("Watch-only descriptors (BIP84)");
    println!();
    ui::kv("Addresses", watch.kind().label());
    ui::kv("Receive", &style(watch.descriptor(0)?).cyan().to_string());
    ui::kv("Change", &style(watch.descriptor(1)?).cyan().to_string());
    println!();
    hint("Your xpub and descriptors can see every address and balance, but cannot spend.");
    println!();
    pause();
    Ok(())
}

fn settings() -> Result<(), String> {
    loop {
        ui::set_context("Settings");
        banner();
        section("Network");
        println!();
        let current = esplora::net();
        ui::kv("Default network", "Mainnet");
        ui::kv("Testnet network", current.label());
        ui::kv(
            "API servers",
            &style(esplora::providers_desc(current)).dim().to_string(),
        );
        ui::kv(
            "Proxy",
            &style(esplora::proxy_desc().unwrap_or_else(|| "direct connection".into()))
                .dim()
                .to_string(),
        );
        println!();
        hint("Set CAIRN_API for your own Esplora server, or CAIRN_TOR=1 for Tor.");
        hint("Testnet switching applies to testnet wallets; mainnet wallets stay on mainnet.");
        println!();
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
