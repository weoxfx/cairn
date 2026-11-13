//! `cairn evm` — the EVM side of the wallet.
//!
//! One mnemonic, two chains: an existing Cairn wallet derives its EVM account
//! at `m/44'/60'/0'/0/index`, so no second seed phrase or second keystore is
//! introduced. The screens use the same banner, sections, tables and menus as
//! the Bitcoin side, so the whole product reads as one wallet.

use crate::evm::abi;
use crate::evm::address::{self, EvmSigner, EvmWatch};
use crate::evm::chains::{self, Chain};
use crate::evm::price;
use crate::evm::rpc::Rpc;
use crate::evm::tx::{self, SignedTx, TokenInfo, UnsignedTx};
use crate::evm::units;
use crate::{choose_wallet, ui, unlock_wallet};
use console::style;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_FILE: u64 = 256 * 1024;
const IDLE_LOCK: Duration = Duration::from_secs(300);

pub fn run(args: &[String], json: bool) -> Result<(), String> {
    // `--json` is consumed at the top level; drop any that reached us so it is
    // never mistaken for a subcommand.
    let args: Vec<String> = args.iter().filter(|a| *a != "--json").cloned().collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        if json || !ui::interactive() {
            return usage();
        }
        return dashboard();
    };
    let rest = &args[1..];
    match cmd {
        "chains" => chains_cmd(json),
        "use" => use_cmd(rest),
        "address" | "receive" => address_cmd(rest, json),
        "balance" => balance_cmd(rest, json),
        "send" => send_cmd(rest, json),
        "sign" => sign_cmd(rest, json),
        "broadcast" => broadcast_cmd(rest, json),
        "token" => token_cmd(rest, json),
        "help" | "-h" | "--help" => usage(),
        other => Err(format!(
            "unknown evm command '{other}' (try: cairn evm help)"
        )),
    }
}

fn usage() -> Result<(), String> {
    println!(
        "\
Cairn EVM — one seed, many chains

Usage:
  cairn evm                                          Interactive EVM dashboard
  cairn evm chains                                   Supported chains and IDs
  cairn evm use <chain>                              Save the default chain
  cairn evm address [WALLET] [--chain C] [--index N] [--qr]
                                                     Show the receive address
  cairn evm balance [WALLET] [--chain C] [--json]    Native and token balances
  cairn evm send [WALLET] --to 0x.. --amount 0.05 [--token 0x..] [--chain C]
                [--build FILE] [--yes]               Build, review and broadcast
  cairn evm sign <UNSIGNED.json> [WALLET] [--out FILE]
                                                     Sign offline (no network)
  cairn evm broadcast <SIGNED.json>                  Broadcast a signed file
  cairn evm token <list|add|remove> ...              Manage tracked ERC-20 tokens

Options:
  --chain C          chain key or id (default: saved chain, else ethereum)
  --index N          address index under m/44'/60'/0'/0 (default 0)
  --max-fee-gwei N   cap the maximum fee per gas
  --priority-gwei N  set the priority fee
  --force-fee        allow a fee above the built-in ceiling
  --yes              do not ask for confirmation before broadcasting
  --qr               print the address as a QR code
  --json             machine-readable output

Environment:
  CAIRN_EVM_CHAIN    default chain key
  CAIRN_EVM_RPC      comma-separated RPC URLs for the selected chain
  CAIRN_PROXY        SOCKS5 proxy (or CAIRN_TOR=1)
  CAIRN_NO_PRICE=1   never fetch a USD price
  CAIRN_PRICE_API    override the price endpoint"
    );
    Ok(())
}

// ───────────────────────────── shell ─────────────────────────────

/// The same header the Bitcoin screens use, with the chain in the status slot
/// so an EVM test network is never mistaken for real money.
fn header(crumb: &str, chain: &Chain) {
    ui::set_context(crumb);
    ui::banner_with(
        &format!("{} · {}", chain.key, chain.chain_id),
        chain.testnet,
    );
}

fn print_qr(text: &str) -> Result<(), String> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| e.to_string())?;
    let art = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Light)
        .light_color(qrcode::render::unicode::Dense1x2::Dark)
        .build();
    println!("{art}");
    Ok(())
}

// ───────────────────────────── options ─────────────────────────────

#[derive(Default)]
struct Opts {
    pos: Vec<String>,
    chain: Option<String>,
    index: u32,
    to: Option<String>,
    amount: Option<String>,
    token: Option<String>,
    decimals: Option<u32>,
    symbol: Option<String>,
    max_fee_gwei: Option<f64>,
    priority_gwei: Option<f64>,
    build: Option<String>,
    out: Option<String>,
    qr: bool,
    yes: bool,
    force_fee: bool,
    json: bool,
}

fn value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn parse_number(s: &str, flag: &str) -> Result<u32, String> {
    s.trim()
        .parse::<u32>()
        .map_err(|_| format!("{flag} must be a whole number"))
}

fn parse_opts(args: &[String], json: bool) -> Result<Opts, String> {
    let mut o = Opts {
        json,
        ..Opts::default()
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--chain" | "-c" => o.chain = Some(value(args, &mut i, a)?),
            "--index" => o.index = parse_number(&value(args, &mut i, a)?, a)?,
            "--to" | "-t" => o.to = Some(value(args, &mut i, a)?),
            "--amount" | "-a" => o.amount = Some(value(args, &mut i, a)?),
            "--token" => o.token = Some(value(args, &mut i, a)?),
            "--decimals" => o.decimals = Some(parse_number(&value(args, &mut i, a)?, a)?),
            "--symbol" => o.symbol = Some(value(args, &mut i, a)?),
            "--max-fee-gwei" => o.max_fee_gwei = Some(parse_gwei(&value(args, &mut i, a)?, a)?),
            "--priority-gwei" => o.priority_gwei = Some(parse_gwei(&value(args, &mut i, a)?, a)?),
            "--build" | "--build-only" => o.build = Some(value(args, &mut i, a)?),
            "--out" | "-o" => o.out = Some(value(args, &mut i, a)?),
            "--qr" => o.qr = true,
            "--yes" | "-y" => o.yes = true,
            "--force-fee" => o.force_fee = true,
            "--json" => o.json = true,
            s if s.starts_with('-') => return Err(format!("unknown option '{s}'")),
            s => o.pos.push(s.to_string()),
        }
        i += 1;
    }
    Ok(o)
}

fn parse_gwei(s: &str, flag: &str) -> Result<f64, String> {
    let v: f64 = s
        .trim()
        .parse()
        .map_err(|_| format!("{flag} must be a number"))?;
    if !v.is_finite() || v <= 0.0 || v > 1_000_000.0 {
        return Err(format!("{flag} must be between 0 and 1000000 gwei"));
    }
    Ok(v)
}

fn gwei_value(g: f64) -> Result<U256, String> {
    if !g.is_finite() || g <= 0.0 || g > 1_000_000.0 {
        return Err("fee must be a positive number of gwei".into());
    }
    let s = format!("{g}");
    units::parse_units(&s, 9).map_err(|_| "fee has more than 9 decimal places".to_string())
}

fn chain_for(opt: &Option<String>) -> Result<&'static Chain, String> {
    match opt {
        Some(s) => chains::by_key_or_id(s)
            .ok_or_else(|| format!("unknown chain '{s}' (try: cairn evm chains)")),
        None => Ok(chains::default_chain()),
    }
}

/// `--json` output must stay parseable, so it never falls back to the
/// interactive wallet picker.
fn pick_wallet(name: Option<&String>, json: bool) -> Result<String, String> {
    if json && name.is_none() {
        return Err("wallet name is required with --json".into());
    }
    choose_wallet(name.map(String::as_str))
}

// ───────────────────────────── chains ─────────────────────────────

fn chains_cmd(json: bool) -> Result<(), String> {
    let current = chains::default_chain();
    if json {
        let list: Vec<serde_json::Value> = chains::CHAINS
            .iter()
            .map(|c| {
                serde_json::json!({
                    "key": c.key, "name": c.name, "chain_id": c.chain_id,
                    "symbol": c.symbol, "testnet": c.testnet,
                    "explorer": c.explorer, "default": c.key == current.key,
                })
            })
            .collect();
        println!("{}", serde_json::json!(list));
        return Ok(());
    }
    ui::set_context("EVM · chains");
    ui::banner_with(&format!("{} chains", chains::CHAINS.len()), false);
    let rows: Vec<Vec<String>> = chains::CHAINS
        .iter()
        .map(|c| {
            vec![
                if c.key == current.key {
                    format!("{} *", c.key)
                } else {
                    c.key.to_string()
                },
                c.name.to_string(),
                c.chain_id.to_string(),
                c.symbol.to_string(),
                if c.testnet { "test" } else { "main" }.to_string(),
            ]
        })
        .collect();
    ui::table(
        &["key", "network", "chain id", "coin", "net"],
        &rows,
        &[false, false, true, false, false],
    );
    println!();
    ui::hint("Set a default with `cairn evm use base`. RPC endpoints are verified by chain id.");
    Ok(())
}

fn use_cmd(args: &[String]) -> Result<(), String> {
    let key = args.first().ok_or("usage: cairn evm use <chain>")?;
    let chain = chains::by_key_or_id(key)
        .ok_or_else(|| format!("unknown chain '{key}' (try: cairn evm chains)"))?;
    chains::set_default(chain)?;
    println!("Default EVM chain: {} (id {})", chain.name, chain.chain_id);
    Ok(())
}

fn pick_chain(current: &Chain) -> Result<Option<&'static Chain>, String> {
    let items: Vec<String> = chains::CHAINS
        .iter()
        .map(|c| {
            let mark = if c.key == current.key { "*" } else { " " };
            format!("{mark} {}  ·  {} ({})", c.key, c.name, c.chain_id)
        })
        .collect();
    let refs: Vec<&str> = items.iter().map(String::as_str).collect();
    let i = ui::menu_titled("Chain", &refs)?;
    let chosen = &chains::CHAINS[i];
    if chosen.key != current.key {
        chains::set_default(chosen)?;
    }
    Ok(Some(chosen))
}

// ───────────────────────────── address ─────────────────────────────

fn address_cmd(args: &[String], json: bool) -> Result<(), String> {
    let o = parse_opts(args, json)?;
    let chain = chain_for(&o.chain)?;
    let name = pick_wallet(o.pos.first(), o.json)?;
    let opened = unlock_wallet(&name)?;
    let watch = EvmWatch::from_opened(&opened)?;
    let fp = opened.fingerprint.clone();
    drop(opened);
    let addr = watch.address_string(o.index)?;
    let path = address::derivation_path(o.index);

    if o.json {
        println!(
            "{}",
            serde_json::json!({
                "wallet": name, "chain": chain.key, "chain_id": chain.chain_id,
                "symbol": chain.symbol, "address": addr, "path": path,
                "xpub": watch.xpub_string(), "fingerprint": fp,
            })
        );
        return Ok(());
    }

    header(&format!("EVM · {name}"), chain);
    ui::section("Receive address");
    println!();
    ui::kv("Chain", &format!("{} (id {})", chain.name, chain.chain_id));
    ui::kv("Path", &path);
    println!();
    println!("  {}", style(&addr).cyan().bold());
    println!();
    if o.qr {
        print_qr(&addr)?;
    }
    ui::warn(
        "This address is shared by every EVM chain; tokens sent here on another chain still arrive.",
    );
    println!();
    ui::hint("Use a fresh index with --index for a new address.");
    println!();
    Ok(())
}

fn receive_screen(addr: &str) -> Result<(), String> {
    ui::section("Receive address");
    println!();
    println!("  {}", style(addr).cyan().bold());
    println!();
    print_qr(addr)?;
    ui::hint("This address is shared by every EVM chain.");
    Ok(())
}

// ───────────────────────────── tokens ─────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
struct StoredToken {
    address: String,
    symbol: String,
    decimals: u32,
    /// `name()` from the contract, when it answered. Older store files have
    /// no name and still load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct TokenStore {
    #[serde(default)]
    chains: BTreeMap<String, Vec<StoredToken>>,
}

fn store_path() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".cairn").join("evm-tokens.json"))
}

fn read_small(path: &Path) -> Result<String, String> {
    let f = crate::hardening::open_read(path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let meta = f.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return Err(format!(
            "{} is not a regular file of a sane size",
            path.display()
        ));
    }
    let mut s = String::new();
    f.take(MAX_FILE + 1)
        .read_to_string(&mut s)
        .map_err(|e| e.to_string())?;
    Ok(s)
}

fn load_store() -> TokenStore {
    let Some(p) = store_path() else {
        return TokenStore::default();
    };
    read_small(&p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_store(store: &TokenStore) -> Result<(), String> {
    let p = store_path().ok_or("HOME not set")?;
    if let Some(dir) = p.parent() {
        crate::hardening::ensure_private_dir(dir)?;
    }
    let body = serde_json::to_vec_pretty(store).map_err(|e| e.to_string())?;
    crate::hardening::write_private(&p, &body)
}

fn tokens_for(chain_key: &str) -> Vec<StoredToken> {
    load_store()
        .chains
        .get(chain_key)
        .cloned()
        .unwrap_or_default()
}

fn add_token(chain_key: &str, token: StoredToken) -> Result<(), String> {
    let mut store = load_store();
    let list = store.chains.entry(chain_key.to_string()).or_default();
    list.retain(|t| !t.address.eq_ignore_ascii_case(&token.address));
    list.push(token);
    save_store(&store)
}

fn remove_token(chain_key: &str, addr: &str) -> Result<bool, String> {
    let mut store = load_store();
    let mut removed = false;
    if let Some(list) = store.chains.get_mut(chain_key) {
        let before = list.len();
        list.retain(|t| !t.address.eq_ignore_ascii_case(addr));
        removed = list.len() != before;
    }
    save_store(&store)?;
    Ok(removed)
}

fn find_token(chain_key: &str, addr: &[u8; 20]) -> Option<StoredToken> {
    let want = address::checksum(addr);
    tokens_for(chain_key)
        .into_iter()
        .find(|t| t.address.eq_ignore_ascii_case(&want))
}

/// On-chain metadata. `decimals()` is required; `symbol()` and `name()` fall
/// back gracefully because plenty of tokens implement only one of them.
fn token_meta(rpc: &Rpc, contract: &[u8; 20]) -> Result<(Option<String>, String, u32), String> {
    let raw = rpc.eth_call(contract, &abi::DECIMALS)?;
    let decimals = abi::decode_decimals(&raw)?;
    let symbol = rpc
        .eth_call(contract, &abi::SYMBOL)
        .ok()
        .and_then(|r| abi::decode_symbol(&r))
        .unwrap_or_else(|| "TOKEN".to_string());
    let name = rpc
        .eth_call(contract, &abi::NAME)
        .ok()
        .and_then(|r| abi::decode_symbol(&r));
    Ok((name, symbol, decimals))
}

fn token_balance(rpc: &Rpc, contract: &[u8; 20], owner: &[u8; 20]) -> Result<U256, String> {
    let raw = rpc.eth_call(contract, &abi::balance_of_data(owner))?;
    abi::decode_uint(&raw, 0)
}

fn token_cmd(args: &[String], json: bool) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Err("usage: cairn evm token <list|add|remove> [ADDRESS]".into());
    };
    let o = parse_opts(&args[1..], json)?;
    let chain = chain_for(&o.chain)?;
    match sub {
        "list" => {
            let list = tokens_for(chain.key);
            if o.json {
                let rows: Vec<serde_json::Value> = list
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "address": t.address, "symbol": t.symbol, "name": t.name,
                            "decimals": t.decimals,
                        })
                    })
                    .collect();
                println!("{}", serde_json::json!(rows));
                return Ok(());
            }
            header("EVM · tokens", chain);
            if list.is_empty() {
                ui::empty("No tokens tracked. Add one with `cairn evm token add 0x...`.");
            } else {
                let rows: Vec<Vec<String>> = list
                    .iter()
                    .map(|t| {
                        vec![
                            t.symbol.clone(),
                            t.name.clone().unwrap_or_else(|| "—".into()),
                            t.address.clone(),
                            t.decimals.to_string(),
                        ]
                    })
                    .collect();
                ui::table(
                    &["token", "name", "contract", "decimals"],
                    &rows,
                    &[false, false, false, true],
                );
            }
            println!();
            Ok(())
        }
        "add" => {
            let raw = o
                .pos
                .first()
                .ok_or("usage: cairn evm token add <ADDRESS> [--symbol S] [--decimals N]")?;
            let addr = address::parse_address(raw)?;
            let mut symbol = o.symbol.clone();
            let mut decimals = o.decimals;
            let mut name = None;
            if symbol.is_none() || decimals.is_none() {
                if let Some(t) = find_token(chain.key, &addr) {
                    symbol = symbol.or(Some(t.symbol));
                    decimals = decimals.or(Some(t.decimals));
                    name = t.name;
                }
            }
            if symbol.is_none() || decimals.is_none() || name.is_none() {
                let rpc = Rpc::connect(chain)?;
                let (n, s, d) = token_meta(&rpc, &addr)?;
                symbol = symbol.or(Some(s));
                decimals = decimals.or(Some(d));
                name = name.or(n);
            }
            let token = StoredToken {
                address: address::checksum(&addr),
                symbol: symbol.unwrap_or_else(|| "TOKEN".into()),
                decimals: decimals.unwrap_or(18),
                name,
            };
            if token.decimals > units::MAX_DECIMALS {
                return Err("token reports impossible decimals".into());
            }
            add_token(chain.key, token.clone())?;
            if o.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "chain": chain.key, "address": token.address,
                        "symbol": token.symbol, "name": token.name,
                        "decimals": token.decimals,
                    })
                );
            } else {
                let label = match &token.name {
                    Some(n) => format!("{} ({})", n, token.symbol),
                    None => token.symbol.clone(),
                };
                println!(
                    "Tracking {label} on {} with {} decimals.",
                    chain.name, token.decimals
                );
            }
            Ok(())
        }
        "remove" => {
            let raw = o
                .pos
                .first()
                .ok_or("usage: cairn evm token remove <ADDRESS>")?;
            let addr = address::parse_address(raw)?;
            let removed = remove_token(chain.key, &address::checksum(&addr))?;
            if o.json {
                println!(
                    "{}",
                    serde_json::json!({"chain": chain.key, "address": address::checksum(&addr), "removed": removed})
                );
            } else if removed {
                println!("Removed {} from {}.", address::checksum(&addr), chain.name);
            } else {
                println!("That token was not tracked on {}.", chain.name);
            }
            Ok(())
        }
        other => Err(format!(
            "unknown token command '{other}' (try: list, add, remove)"
        )),
    }
}

// ───────────────────────────── balance ─────────────────────────────

struct Holding {
    token: StoredToken,
    balance: Option<U256>,
    price: Option<f64>,
}

impl Holding {
    fn value(&self) -> Option<String> {
        Some(units::usd(self.balance?, self.token.decimals, self.price?))
    }
}

fn holdings_for(rpc: &Rpc, chain: &Chain, owner: &[u8; 20]) -> Vec<Holding> {
    let mut out = Vec::new();
    for t in tokens_for(chain.key) {
        let Ok(contract) = address::parse_address(&t.address) else {
            continue;
        };
        let balance = token_balance(rpc, &contract, owner).ok();
        let price = price::token_usd(chain, &t.address);
        out.push(Holding {
            token: t,
            balance,
            price,
        });
    }
    out
}

fn balance_cmd(args: &[String], json: bool) -> Result<(), String> {
    let o = parse_opts(args, json)?;
    let chain = chain_for(&o.chain)?;
    let name = pick_wallet(o.pos.first(), o.json)?;
    let opened = unlock_wallet(&name)?;
    let watch = EvmWatch::from_opened(&opened)?;
    drop(opened);
    let owner = watch.address_at(o.index)?;
    let addr = address::checksum(&owner);
    let rpc = Rpc::connect(chain)?;
    let native = rpc.balance(&owner)?;
    let rate = price::usd(chain);
    let holdings = holdings_for(&rpc, chain, &owner);

    if o.json {
        let tok: Vec<serde_json::Value> = holdings
            .iter()
            .map(|h| {
                serde_json::json!({
                    "address": h.token.address,
                    "symbol": h.token.symbol,
                    "name": h.token.name,
                    "decimals": h.token.decimals,
                    "raw": h.balance.map(|b| b.to_string()),
                    "balance": h.balance.map(|b| units::format_units(b, h.token.decimals)),
                    "usd_price": h.price,
                    "usd": h.value(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "wallet": name, "chain": chain.key, "chain_id": chain.chain_id,
                "address": addr,
                "native": {
                    "symbol": chain.symbol,
                    "wei": native.to_string(),
                    "balance": units::format_units(native, chain.decimals),
                    "usd_price": rate,
                    "usd": rate.map(|p| units::usd(native, chain.decimals, p)),
                },
                "tokens": tok,
            })
        );
        return Ok(());
    }

    header(&format!("EVM · {name}"), chain);
    ui::section("Balance");
    println!();
    ui::kv("Chain", &format!("{} (id {})", chain.name, chain.chain_id));
    ui::kv("Address", &addr);
    println!();
    println!(
        "  {} {}",
        style(units::format_amount(native, chain.decimals, 8))
            .cyan()
            .bold(),
        style(chain.symbol).dim()
    );
    if let Some(p) = rate {
        println!("  {}", style(units::usd(native, chain.decimals, p)).dim());
    }
    println!();
    if holdings.is_empty() {
        ui::hint("No tokens tracked. Add one with `cairn evm token add 0x...`.");
    } else {
        let rows: Vec<Vec<String>> = holdings
            .iter()
            .map(|h| {
                vec![
                    h.token.symbol.clone(),
                    h.token.name.clone().unwrap_or_else(|| "—".into()),
                    match h.balance {
                        Some(b) => units::format_amount(b, h.token.decimals, 6),
                        None => "unavailable".into(),
                    },
                    h.value().unwrap_or_else(|| "—".into()),
                ]
            })
            .collect();
        ui::table(
            &["token", "name", "balance", "value"],
            &rows,
            &[false, false, true, true],
        );
    }
    println!();
    Ok(())
}

// ───────────────────────────── send ─────────────────────────────

fn resolve_token(
    rpc: &Rpc,
    chain: &Chain,
    raw: &str,
    symbol: Option<String>,
    decimals: Option<u32>,
) -> Result<StoredToken, String> {
    let contract = address::parse_address(raw)?;
    let mut symbol = symbol;
    let mut decimals = decimals;
    let mut name = None;
    if symbol.is_none() || decimals.is_none() {
        if let Some(t) = find_token(chain.key, &contract) {
            symbol = symbol.or(Some(t.symbol));
            decimals = decimals.or(Some(t.decimals));
            name = t.name;
        }
    }
    if symbol.is_none() || decimals.is_none() {
        let (n, s, d) = token_meta(rpc, &contract)?;
        symbol = symbol.or(Some(s));
        decimals = decimals.or(Some(d));
        name = name.or(n);
    }
    let token = StoredToken {
        address: address::checksum(&contract),
        symbol: symbol.unwrap_or_else(|| "TOKEN".into()),
        decimals: decimals.unwrap_or(18),
        name,
    };
    if token.decimals > units::MAX_DECIMALS {
        return Err("token reports impossible decimals".into());
    }
    Ok(token)
}

fn fees(rpc: &Rpc, o: &Opts) -> Result<(U256, U256), String> {
    let base = rpc.base_fee()?;
    let gas_price = if base.is_none() {
        Some(rpc.gas_price()?)
    } else {
        None
    };
    let tip = match o.priority_gwei {
        Some(g) => gwei_value(g)?,
        None => rpc
            .max_priority_fee()
            .unwrap_or_else(|| U256::from(1_000_000_000u64)),
    };
    let max = match o.max_fee_gwei {
        Some(g) => gwei_value(g)?,
        None => match (base, gas_price) {
            (Some(b), _) => b
                .checked_mul(U256::from(2u8))
                .and_then(|v| v.checked_add(tip))
                .ok_or("fee overflows")?,
            (None, Some(gp)) => gp,
            _ => return Err("the node did not report a fee".into()),
        },
    };
    if max < tip {
        return Err("maximum fee is below the priority fee".into());
    }
    Ok((max, tip))
}

fn headroom(estimate: U256) -> Result<U256, String> {
    let floor = U256::from(tx::MIN_GAS_LIMIT);
    if estimate <= floor {
        return Ok(floor);
    }
    let padded = estimate
        .checked_mul(U256::from(11u8))
        .and_then(|v| v.checked_div(U256::from(10u8)))
        .ok_or("gas estimate overflows")?;
    Ok(padded.min(U256::from(tx::MAX_GAS_LIMIT)))
}

fn send_cmd(args: &[String], json: bool) -> Result<(), String> {
    let o = parse_opts(args, json)?;
    let chain = chain_for(&o.chain)?;
    let to = address::parse_address(o.to.as_deref().ok_or("--to is required")?)?;
    let amount_str = o.amount.clone().ok_or("--amount is required")?;
    let name = pick_wallet(o.pos.first(), o.json)?;

    let opened = unlock_wallet(&name)?;
    let signer = EvmSigner::from_opened(&opened)?;
    drop(opened);
    let from = signer.address_at(o.index)?;
    let rpc = Rpc::connect(chain)?;

    let (token_info, value, call_to, calldata, send_amount) = match &o.token {
        Some(raw) => {
            let stored = resolve_token(&rpc, chain, raw, o.symbol.clone(), o.decimals)?;
            let contract = address::parse_address(&stored.address)?;
            let amt = units::parse_units(&amount_str, stored.decimals)?;
            if amt.is_zero() {
                return Err("amount must be greater than zero".into());
            }
            let data = abi::transfer_data(&to, amt);
            let info = TokenInfo {
                address: stored.address,
                recipient: address::checksum(&to),
                symbol: stored.symbol,
                decimals: stored.decimals,
                amount: amount_str.clone(),
            };
            (Some(info), U256::zero(), contract, data, amt)
        }
        None => {
            let amt = units::parse_units(&amount_str, chain.decimals)?;
            if amt.is_zero() {
                return Err("amount must be greater than zero".into());
            }
            (None, amt, to, Vec::new(), amt)
        }
    };

    let nonce = rpc.nonce(&from)?;
    let (max_fee, tip) = fees(&rpc, &o)?;
    let estimate = rpc.estimate_gas(&from, &call_to, value, &calldata)?;
    let gas = headroom(estimate)?;

    let transaction = UnsignedTx {
        kind: "eip1559".into(),
        chain: chain.key.into(),
        chain_id: chain.chain_id,
        from: address::checksum(&from),
        to: address::checksum(&call_to),
        value: value.to_string(),
        data: format!("0x{}", hex::encode(&calldata)),
        gas: gas.to_string(),
        max_fee_per_gas: max_fee.to_string(),
        max_priority_fee_per_gas: tip.to_string(),
        nonce: nonce.to_string(),
        token: token_info,
        created_at: tx::now(),
    };
    transaction.validate(o.force_fee)?;

    // The fee is paid in the native coin, so it is checked even for tokens.
    let native = rpc.balance(&from)?;
    let cost = transaction.max_native_cost()?;
    if native < cost {
        return Err(format!(
            "not enough {} for the amount plus the maximum fee: need {} {}, have {} {}",
            chain.symbol,
            units::format_units(cost, chain.decimals),
            chain.symbol,
            units::format_units(native, chain.decimals),
            chain.symbol
        ));
    }
    if let Some(t) = &transaction.token {
        let contract = transaction.to_bytes()?;
        let held = token_balance(&rpc, &contract, &from)?;
        if held < send_amount {
            return Err(format!(
                "not enough {}: need {}, have {}",
                t.symbol,
                t.amount,
                units::format_units(held, t.decimals)
            ));
        }
    }

    if !o.json {
        review(&transaction, chain)?;
    }

    if let Some(path) = &o.build {
        write_json(path, &transaction)?;
        if o.json {
            println!(
                "{}",
                serde_json::json!({"kind": "unsigned", "path": path, "tx": transaction})
            );
        } else {
            println!();
            ui::ok(&format!("Unsigned transaction written to {path}"));
            ui::hint("Sign it on an offline machine with: cairn evm sign <file>");
            println!();
        }
        return Ok(());
    }

    if !o.yes {
        if o.json {
            return Err("refusing to broadcast in --json mode without --yes".into());
        }
        if !ui::confirm("Sign and broadcast this transaction?", false) {
            println!();
            ui::info("Cancelled. Nothing was signed.");
            return Ok(());
        }
    }

    let mut key = signer.key_at(o.index)?;
    let signed = transaction.sign(&key, o.force_fee)?;
    key.non_secure_erase();
    let hash = rpc.send_raw(&signed.raw_bytes()?)?;
    if hash != signed.hash {
        return Err(format!(
            "the node returned hash {hash} but the signed transaction hashes to {}; verify before trusting this node",
            signed.hash
        ));
    }
    report_broadcast(chain, &hash, o.json);
    Ok(())
}

fn send_prompt(name: &str, chain: &Chain) -> Result<(), String> {
    let to = ui::ask("Recipient address (0x…)")?;
    let token = ui::ask("Token contract (blank for native)")?;
    let amount = ui::ask("Amount")?;
    let mut args = vec![
        name.to_string(),
        "--to".into(),
        to.trim().to_string(),
        "--amount".into(),
        amount.trim().to_string(),
        "--chain".into(),
        chain.key.into(),
    ];
    if !token.trim().is_empty() {
        args.push("--token".into());
        args.push(token.trim().to_string());
    }
    send_cmd(&args, false)
}

fn report_broadcast(chain: &Chain, hash: &str, json: bool) {
    let url = format!("{}/tx/{}", chain.explorer, hash);
    if json {
        println!(
            "{}",
            serde_json::json!({
                "chain": chain.key, "chain_id": chain.chain_id,
                "hash": hash, "explorer": url,
            })
        );
        return;
    }
    println!();
    ui::ok("Broadcast");
    ui::kv("Hash", hash);
    ui::kv("Explorer", &url);
    println!();
}

fn review(tx: &UnsignedTx, chain: &Chain) -> Result<(), String> {
    header("EVM · review", chain);
    ui::section("Transaction");
    println!();
    if chain.testnet {
        ui::warn("Test network: these coins have no value.");
        println!();
    }
    ui::kv(
        "Network",
        &format!("{} (id {})", chain.name, chain.chain_id),
    );
    ui::kv("From", &tx.from);
    let rate = price::usd(chain);
    if let Some(t) = &tx.token {
        let label = match find_token(chain.key, &(tx.to_bytes()?)) {
            Some(stored) => match stored.name {
                Some(n) => format!("{} ({})", n, t.symbol),
                None => t.symbol.clone(),
            },
            None => t.symbol.clone(),
        };
        ui::kv("Token", &format!("{label}  {}", address::short(&t.address)));
        ui::kv("To", &t.recipient);
        ui::kv("Amount", &format!("{} {}", t.amount, t.symbol));
        if let (Some(p), Ok(v)) = (
            price::token_usd(chain, &t.address),
            units::parse_units(&t.amount, t.decimals),
        ) {
            ui::kv("Value", &units::usd(v, t.decimals, p));
        }
    } else {
        ui::kv("To", &tx.to);
        let v = tx.value_wei()?;
        ui::kv(
            "Amount",
            &format!(
                "{} {}",
                units::format_amount(v, chain.decimals, 8),
                chain.symbol
            ),
        );
        if let Some(p) = rate {
            ui::kv("Value", &units::usd(v, chain.decimals, p));
        }
    }
    ui::kv("Nonce", &tx.nonce);
    ui::kv("Gas limit", &tx.gas);
    ui::kv(
        "Max fee",
        &format!("{} gwei", units::format_units(tx.max_fee()?, 9)),
    );
    let total = tx.max_native_cost()?;
    let mut line = format!(
        "{} {}",
        units::format_amount(total, chain.decimals, 8),
        chain.symbol
    );
    if let Some(p) = rate {
        line.push_str(&format!("  ({})", units::usd(total, chain.decimals, p)));
    }
    ui::kv("Max cost", &line);
    println!();
    ui::hint("The maximum cost is reserved up front; unused gas is refunded.");
    println!();
    Ok(())
}

// ───────────────────────────── offline sign / broadcast ─────────────────────────────

fn write_json<T: Serialize>(path: &str, value: &T) -> Result<(), String> {
    let body = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    let p = Path::new(path);
    if let Some(dir) = p.parent() {
        if !dir.as_os_str().is_empty() {
            crate::hardening::ensure_private_dir(dir)?;
        }
    }
    crate::hardening::write_private(p, &body)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    let text = read_small(Path::new(path))?;
    serde_json::from_str(&text).map_err(|e| format!("{path} is not a valid transaction file: {e}"))
}

fn sign_cmd(args: &[String], json: bool) -> Result<(), String> {
    let o = parse_opts(args, json)?;
    let path = o
        .pos
        .first()
        .cloned()
        .ok_or("usage: cairn evm sign <UNSIGNED.json> [WALLET] [--out FILE]")?;
    let transaction: UnsignedTx = read_json(&path)?;
    transaction.validate(o.force_fee)?;

    let chain = chains::for_id(transaction.chain_id).ok_or_else(|| {
        format!(
            "this transaction is for chain {}, which this build does not know",
            transaction.chain_id
        )
    })?;
    if let Some(c) = &o.chain {
        transaction.ensure_chain(chain_for(&Some(c.clone()))?)?;
    }

    let name = pick_wallet(o.pos.get(1), o.json)?;
    let opened = unlock_wallet(&name)?;
    let signer = EvmSigner::from_opened(&opened)?;
    drop(opened);
    let ours = address::checksum(&signer.address_at(o.index)?);
    if !ours.eq_ignore_ascii_case(&transaction.from) {
        return Err(format!(
            "this transaction is from {} but wallet '{name}' index {} is {ours}; refusing to sign",
            transaction.from, o.index
        ));
    }

    if !o.json {
        review(&transaction, chain)?;
        ui::info("Signing offline. No network request is made.");
        println!();
    }

    let mut key = signer.key_at(o.index)?;
    let signed = transaction.sign(&key, o.force_fee)?;
    key.non_secure_erase();
    signed.validate(o.force_fee)?;

    let out = o
        .out
        .clone()
        .unwrap_or_else(|| format!("{path}.signed.json"));
    write_json(&out, &signed)?;

    if o.json {
        println!(
            "{}",
            serde_json::json!({"kind": "signed", "path": out, "hash": signed.hash, "tx": signed})
        );
        return Ok(());
    }
    println!();
    ui::ok(&format!("Signed transaction written to {out}"));
    ui::kv("Hash", &signed.hash);
    println!();
    ui::hint("Broadcast it with: cairn evm broadcast <file>");
    println!();
    Ok(())
}

fn broadcast_cmd(args: &[String], json: bool) -> Result<(), String> {
    let o = parse_opts(args, json)?;
    let path = o
        .pos
        .first()
        .cloned()
        .ok_or("usage: cairn evm broadcast <SIGNED.json>")?;
    let signed: SignedTx = read_json(&path)?;
    signed.validate(o.force_fee)?;
    let chain = chains::for_id(signed.tx.chain_id)
        .ok_or_else(|| format!("unknown chain id {}", signed.tx.chain_id))?;
    if let Some(c) = &o.chain {
        signed.tx.ensure_chain(chain_for(&Some(c.clone()))?)?;
    }
    let rpc = Rpc::connect(chain)?;
    let hash = rpc.send_raw(&signed.raw_bytes()?)?;
    if hash != signed.hash {
        return Err(format!(
            "the node returned hash {hash} but the signature hashes to {}; do not trust this node",
            signed.hash
        ));
    }
    report_broadcast(chain, &hash, o.json);
    Ok(())
}

// ───────────────────────────── interactive dashboard ─────────────────────────────

struct Snapshot {
    native: U256,
    holdings: Vec<Holding>,
}

fn sync_snapshot(chain: &'static Chain, owner: &[u8; 20]) -> Result<Snapshot, String> {
    let rpc = Rpc::connect(chain)?;
    let native = rpc.balance(owner)?;
    let holdings = holdings_for(&rpc, chain, owner);
    Ok(Snapshot { native, holdings })
}

fn tokens_prompt(chain: &Chain) -> Result<(), String> {
    loop {
        header("EVM · tokens", chain);
        let list = tokens_for(chain.key);
        if list.is_empty() {
            ui::empty("No tokens tracked.");
            println!();
        } else {
            let rows: Vec<Vec<String>> = list
                .iter()
                .map(|t| {
                    vec![
                        t.symbol.clone(),
                        t.name.clone().unwrap_or_else(|| "—".into()),
                        address::short(&t.address),
                    ]
                })
                .collect();
            ui::table(
                &["token", "name", "contract"],
                &rows,
                &[false, false, false],
            );
            println!();
        }
        match ui::menu(&["⊕  Add token", "⊖  Remove token", "←  Back"])? {
            0 => {
                let addr = ui::ask("Token contract (0x…)")?;
                let args = vec![
                    "add".to_string(),
                    addr.trim().to_string(),
                    "--chain".into(),
                    chain.key.into(),
                ];
                if let Err(e) = token_cmd(&args, false) {
                    println!();
                    ui::fail(&e);
                }
                ui::pause();
            }
            1 => {
                if list.is_empty() {
                    ui::info("Nothing to remove.");
                    ui::pause();
                    continue;
                }
                let items: Vec<String> = list.iter().map(Holding::label_from).collect();
                let refs: Vec<&str> = items.iter().map(String::as_str).collect();
                let i = ui::menu_titled("Remove which token?", &refs)?;
                if ui::confirm(&format!("Stop tracking {}?", list[i].symbol), false) {
                    remove_token(chain.key, &list[i].address)?;
                    ui::ok(&format!("Removed {}.", list[i].symbol));
                }
                ui::pause();
            }
            _ => return Ok(()),
        }
    }
}

impl Holding {
    fn label_from(t: &StoredToken) -> String {
        match &t.name {
            Some(n) => format!("{} ({})  {}", n, t.symbol, address::short(&t.address)),
            None => format!("{}  {}", t.symbol, address::short(&t.address)),
        }
    }
}

fn dashboard() -> Result<(), String> {
    let name = choose_wallet(None)?;
    let opened = unlock_wallet(&name)?;
    let watch = EvmWatch::from_opened(&opened)?;
    let fp = opened.fingerprint.clone();
    drop(opened);
    let owner = watch.address_at(0)?;
    let addr = address::checksum(&owner);
    let mut chain = chains::default_chain();
    let mut snapshot: Option<Snapshot> = None;
    let mut last_err: Option<String> = None;
    let mut need_sync = true;

    loop {
        if need_sync {
            match ui::spin("Syncing with network…", || sync_snapshot(chain, &owner)) {
                Ok(s) => {
                    snapshot = Some(s);
                    last_err = None;
                }
                Err(e) => last_err = Some(e),
            }
            need_sync = false;
        }
        header(&format!("EVM · {name}  ·  {fp}"), chain);
        match &snapshot {
            Some(s) => {
                let mut lines = vec![format!(
                    "{}  {}",
                    style(units::format_amount(s.native, chain.decimals, 8))
                        .cyan()
                        .bold(),
                    style(chain.symbol).dim()
                )];
                if let Some(p) = price::usd(chain) {
                    lines.push(
                        style(units::usd(s.native, chain.decimals, p))
                            .dim()
                            .to_string(),
                    );
                }
                ui::card("Balance", &lines);
                println!();
                if s.holdings.is_empty() {
                    ui::hint("No tokens tracked. Add one from the Tokens screen.");
                } else {
                    let rows: Vec<Vec<String>> = s
                        .holdings
                        .iter()
                        .take(6)
                        .map(|h| {
                            vec![
                                h.token.symbol.clone(),
                                match h.balance {
                                    Some(b) => units::format_amount(b, h.token.decimals, 6),
                                    None => "unavailable".into(),
                                },
                                h.value().unwrap_or_else(|| "—".into()),
                            ]
                        })
                        .collect();
                    ui::table(&["token", "balance", "value"], &rows, &[false, true, true]);
                    if s.holdings.len() > 6 {
                        ui::hint(&format!("and {} more", s.holdings.len() - 6));
                    }
                }
                println!();
                let short_addr = address::short(&addr);
                ui::grid(&[("Address", short_addr.as_str()), ("Index", "0")]);
            }
            None => ui::card(
                "Balance",
                &[
                    style("Not synced").yellow().bold().to_string(),
                    style("Choose Refresh to load your balance.")
                        .dim()
                        .to_string(),
                ],
            ),
        }
        if let Some(e) = &last_err {
            println!();
            ui::warn(e);
            ui::hint("Showing the last known balance.");
        }
        println!();
        let asked = Instant::now();
        let choice = ui::menu(&[
            "↓  Receive",
            "↑  Send",
            "◈  Tokens",
            "⟳  Refresh",
            "⛓  Switch chain",
            "⏻  Lock and exit",
        ])
        .unwrap_or(5);
        if asked.elapsed() > IDLE_LOCK {
            ui::clear();
            ui::fail("Locked after 5 minutes of inactivity. Open the wallet again.");
            ui::pause();
            return Ok(());
        }
        match choice {
            0 => {
                receive_screen(&addr)?;
                ui::pause();
            }
            1 => {
                if let Err(e) = send_prompt(&name, chain) {
                    println!();
                    ui::fail(&e);
                    ui::pause();
                } else {
                    need_sync = true;
                }
            }
            2 => {
                if let Err(e) = tokens_prompt(chain) {
                    println!();
                    ui::fail(&e);
                    ui::pause();
                }
                need_sync = true;
            }
            3 => need_sync = true,
            4 => {
                if let Some(c) = pick_chain(chain)? {
                    chain = c;
                    need_sync = true;
                }
            }
            _ => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cairn-evm-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample() -> UnsignedTx {
        UnsignedTx {
            kind: "eip1559".into(),
            chain: "ethereum".into(),
            chain_id: 1,
            from: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".into(),
            to: "0x3535353535353535353535353535353535353535".into(),
            value: "1000".into(),
            data: "0x".into(),
            gas: "21000".into(),
            max_fee_per_gas: "20000000000".into(),
            max_priority_fee_per_gas: "1000000000".into(),
            nonce: "1".into(),
            token: None,
            created_at: 0,
        }
    }

    #[test]
    fn transaction_files_round_trip_and_refuse_unsafe_paths() {
        let dir = temp("txfile");
        let path = dir.join("tx.json");
        let p = path.to_str().unwrap();
        write_json(p, &sample()).unwrap();
        let read: UnsignedTx = read_json(p).unwrap();
        assert_eq!(read.to, sample().to);
        read.validate(false).unwrap();
        #[cfg(unix)]
        assert_eq!(
            crate::hardening::mode_of(&std::fs::metadata(&path).unwrap()),
            0o600
        );

        // A symlink is never followed.
        #[cfg(unix)]
        {
            let link = dir.join("link.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_json::<UnsignedTx>(link.to_str().unwrap()).is_err());
        }

        // Junk and missing files are reported, never panicked on.
        let junk = dir.join("junk.json");
        std::fs::write(&junk, b"not json").unwrap();
        assert!(read_json::<UnsignedTx>(junk.to_str().unwrap()).is_err());
        assert!(read_json::<UnsignedTx>(dir.join("missing.json").to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fee_and_gas_parsing_is_bounded() {
        assert_eq!(gwei_value(2.1).unwrap(), U256::from(2_100_000_000u64));
        assert!(gwei_value(0.0).is_err());
        assert!(gwei_value(-1.0).is_err());
        assert!(parse_gwei("abc", "--x").is_err());
        assert!(parse_gwei("0", "--x").is_err());
        assert_eq!(
            headroom(U256::from(21_000u64)).unwrap(),
            U256::from(21_000u64)
        );
        assert_eq!(
            headroom(U256::from(100_000u64)).unwrap(),
            U256::from(110_000u64)
        );
        assert_eq!(
            headroom(U256::from(100_000_000u64)).unwrap(),
            U256::from(tx::MAX_GAS_LIMIT)
        );
    }

    #[test]
    fn options_are_parsed_and_unknown_flags_rejected() {
        let args: Vec<String> = [
            "--to",
            "0x3535353535353535353535353535353535353535",
            "--amount",
            "0.5",
            "--chain",
            "base",
            "--yes",
            "wallet1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let o = parse_opts(&args, false).unwrap();
        assert_eq!(o.chain.as_deref(), Some("base"));
        assert_eq!(o.amount.as_deref(), Some("0.5"));
        assert!(o.yes);
        assert_eq!(o.pos, vec!["wallet1".to_string()]);
        assert_eq!(
            chains::by_key(o.chain.as_deref().unwrap())
                .unwrap()
                .chain_id,
            8453
        );

        let bad = vec!["--nope".to_string()];
        assert!(parse_opts(&bad, false).is_err());
        assert!(parse_opts(&["--index".to_string()], false).is_err());
    }

    #[test]
    fn stored_tokens_tolerate_missing_names() {
        // A store written before names existed must still load.
        let old = r#"{"chains":{"ethereum":[{"address":"0xabc","symbol":"OLD","decimals":6}]}}"#;
        let store: TokenStore = serde_json::from_str(old).unwrap();
        let list = store.chains.get("ethereum").unwrap();
        assert_eq!(list[0].symbol, "OLD");
        assert!(list[0].name.is_none());
    }

    #[test]
    fn holdings_render_values_only_when_priced() {
        let token = StoredToken {
            address: "0x0000000000000000000000000000000000000001".into(),
            symbol: "TKN".into(),
            decimals: 6,
            name: Some("Token".into()),
        };
        let priced = Holding {
            token: token.clone(),
            balance: Some(U256::from(1_500_000u64)),
            price: Some(2.0),
        };
        assert_eq!(priced.value().unwrap(), "$3.00");
        assert!(Holding::label_from(&token).starts_with("Token (TKN)"));

        let unpriced = Holding {
            token: token.clone(),
            balance: Some(U256::from(1u64)),
            price: None,
        };
        assert!(unpriced.value().is_none());

        let missing = Holding {
            token,
            balance: None,
            price: Some(1.0),
        };
        assert!(missing.value().is_none());
    }
}
