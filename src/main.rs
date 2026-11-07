mod esplora;
mod hardening;
mod keystore;
mod offline;
mod qr;
mod send;
mod ui;
mod wallet;

use bip39::Mnemonic;
use bitcoin::Network;
use console::style;
use dialoguer::{Input, Password};
use qrcode::{render::unicode, QrCode};
use std::time::{Duration, Instant};
use ui::{banner, boxed, clear, fail, fmt_btc, menu, ok, pause, short, spin, theme};
use wallet::Watch;
use zeroize::Zeroizing;

// All supported nets (testnet3/4, signet) share the test network kind: tb1
// addresses, tpub keys and coin type 1. `esplora::Net` only picks the server.
const NETWORK: Network = Network::Testnet;
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        return interactive();
    };
    match cmd.as_str() {
        "-h" | "--help" => {
            help();
            Ok(())
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

fn help() {
    println!(
        "\
Cairn - experimental testnet Bitcoin wallet

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
  cairn --help                               Show this help"
    );
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

// ---------- create / import / open ----------

fn create_wallet() -> Result<(), String> {
    banner();
    println!("{}\n", style("Create New Wallet").bold());
    let name = ask_name()?;
    let password = ask_new_password()?;

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
        keystore::save(&name, &password, &mnemonic)
    })?;
    let fp = keystore::fingerprint(&mnemonic)?;
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
    let name = ask_name()?;
    let phrase = Zeroizing::new(
        Password::with_theme(&theme())
            .with_prompt("Seed phrase (hidden)")
            .interact()
            .map_err(|e| e.to_string())?,
    );
    let mnemonic =
        Mnemonic::parse(phrase.trim()).map_err(|e| format!("Invalid seed phrase: {e}"))?;
    let password = ask_new_password()?;
    spin("Encrypting wallet…", || {
        keystore::save(&name, &password, &mnemonic)
    })?;
    ok(&format!(
        "Imported. Fingerprint: {}",
        keystore::fingerprint(&mnemonic)?
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

pub(crate) fn unlock_wallet(name: &str) -> Result<(Mnemonic, String), String> {
    // Growing delay after each wrong attempt, 5 tries max.
    let mut unlocked = None;
    for attempt in 0..5u32 {
        let pw = Zeroizing::new(
            Password::with_theme(&theme())
                .with_prompt("Password")
                .interact()
                .map_err(|e| e.to_string())?,
        );
        match spin("Unlocking…", || keystore::open(name, &pw)) {
            Ok(r) => {
                unlocked = Some(r);
                break;
            }
            Err(e) => {
                fail(&e);
                std::thread::sleep(Duration::from_secs(2u64.pow(attempt)));
            }
        }
    }
    unlocked.ok_or_else(|| "Too many failed attempts".to_string())
}

fn open_wallet() -> Result<(), String> {
    banner();
    println!("{}\n", style("Open Wallet").bold());
    let name = choose_wallet(None)?;
    let (mnemonic, fp) = unlock_wallet(&name)?;
    // Keep only the public account key; the seed is wiped from memory right here.
    let watch = Watch::from_mnemonic(&mnemonic, NETWORK)?;
    drop(mnemonic);
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
                        style("tBTC").dim()
                    ),
                ];
                if s.unconfirmed != 0 {
                    lines.push(
                        style(format!("{} pending", fmt_btc(s.unconfirmed)))
                            .yellow()
                            .to_string(),
                    );
                }
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
        if let Some(e) = &last_err {
            println!("{}", style(format!("  {e}")).dim());
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
            2 => transactions_screen(state.as_ref())?,
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
    let mut index = state.map(|s| s.next_receive).unwrap_or(0);
    loop {
        banner();
        let addr = watch.address_at(0, index)?;
        println!("{}\n", style("Receive (testnet)").bold());
        println!("  {}", style(&addr).cyan().bold());
        println!(
            "  {}\n",
            style(wallet::derivation_path(NETWORK, 0, index)).dim()
        );
        println!("  Send only TESTNET coins here (e.g. from a faucet).");
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

fn transactions_screen(state: Option<&esplora::WalletState>) -> Result<(), String> {
    banner();
    println!("{}\n", style("Transactions").bold());
    let Some(s) = state else {
        fail("Not synced. Go back and Refresh first.");
        pause();
        return Ok(());
    };
    if s.used.is_empty() {
        println!("  No transactions yet.");
    } else {
        match spin("Loading transactions…", || esplora::transactions(s)) {
            Ok(txs) => {
                if txs.is_empty() {
                    println!("  No transactions yet.");
                }
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
                    println!("  {} {}  {}", icon, amount, status);
                    println!("    {}\n", style(short(&t.txid)).dim());
                }
            }
            Err(e) => fail(&e),
        }
    }
    println!();
    pause();
    Ok(())
}

fn info_screen(fp: &str, watch: &Watch) -> Result<(), String> {
    banner();
    println!("{}\n", style("Wallet Info").bold());
    println!("  Fingerprint:   {fp}");
    println!("  Address type:  native SegWit (BIP84)");
    println!("  Network:       {}", esplora::net().label());
    println!("  API servers:   {}", esplora::providers_desc());
    println!(
        "  Seed in memory: {}",
        style("no (wiped after unlock)").green()
    );
    println!("  Idle lock:     5 minutes");
    println!("\n  Account xpub (watch-only; can see balance, cannot spend):");
    println!("  {}", style(watch.xpub_string()).cyan());
    println!(
        "\n{}",
        style("  Anyone with the xpub can see all your addresses and balance.").yellow()
    );
    println!(
        "{}\n",
        style("  Seed words are never shown here. Use your paper backup.").dim()
    );
    pause();
    Ok(())
}

fn settings() -> Result<(), String> {
    loop {
        banner();
        println!("{}\n", style("Settings").bold());
        println!(
            "  Network:     {}",
            style(esplora::net().label()).cyan().bold()
        );
        println!("  API servers: {}", style(esplora::providers_desc()).dim());
        println!(
            "{}\n",
            style("  Set CAIRN_API=https://your-server/api to use your own server.").dim()
        );
        let items: Vec<String> = esplora::Net::ALL
            .iter()
            .map(|n| format!("Use {}", n.label()))
            .chain(std::iter::once("Back".to_string()))
            .collect();
        let refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
        let i = menu(&refs)?;
        if i >= esplora::Net::ALL.len() {
            return Ok(());
        }
        esplora::set_net(esplora::Net::ALL[i])?;
    }
}
