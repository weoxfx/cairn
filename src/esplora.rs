//! Network layer (Esplora API: mempool.space / Blockstream). It never sees keys or the seed.
//! The server can see your IP and which addresses you query.
//!
//! Everything the server returns is untrusted. Balances/history are display-only;
//! for sending we only take UTXO txid/vout/value, and signatures commit to those
//! values (a lying server can make a transaction invalid, not steal coins).

use crate::network;
use crate::wallet::Watch;
use bitcoin::{Network, Txid};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const FULL_GAP: u32 = 10; // full scan on open
pub const QUICK_GAP: u32 = 3; // cheap scan on refresh
pub const MAX_INDEX: u32 = 200;
const MAX_BODY: u64 = 2_000_000; // cap on any response body
const MAX_PARALLEL: usize = 4; // gentle on public APIs (avoids rate limits)
const MAX_UTXOS_PER_ADDRESS: usize = 10_000; // reject absurd server responses
const MAX_UTXOS_TOTAL: usize = 20_000;
const MAX_TX_SUMMARIES: usize = 100_000;
const COOLDOWN: Duration = Duration::from_secs(60);
const MIN_GAP: Duration = Duration::from_millis(200); // at most ~5 requests/second overall

// ---------- network choice + providers ----------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Net {
    Mainnet,
    Testnet4,
    Testnet3,
    Signet,
}

impl Net {
    pub const TESTNETS: [Net; 3] = [Net::Testnet4, Net::Testnet3, Net::Signet];

    pub fn label(self) -> &'static str {
        match self {
            Net::Mainnet => "Mainnet",
            Net::Testnet4 => "Testnet4",
            Net::Testnet3 => "Testnet3",
            Net::Signet => "Signet",
        }
    }

    pub fn is_mainnet(self) -> bool {
        self == Net::Mainnet
    }

    #[cfg(test)]
    pub fn network(self) -> Network {
        match self {
            Net::Mainnet => Network::Bitcoin,
            _ => Network::Testnet,
        }
    }

    /// Public providers in order of preference (failover goes down this list).
    fn providers(self) -> &'static [&'static str] {
        match self {
            Net::Mainnet => &["https://mempool.space/api", "https://blockstream.info/api"],
            Net::Testnet4 => &["https://mempool.space/testnet4/api"],
            Net::Testnet3 => &[
                "https://mempool.space/testnet/api",
                "https://blockstream.info/testnet/api",
            ],
            Net::Signet => &[
                "https://mempool.space/signet/api",
                "https://blockstream.info/signet/api",
            ],
        }
    }
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

static NET: Mutex<Net> = Mutex::new(Net::Testnet4);

pub fn net() -> Net {
    *NET.lock().unwrap_or_else(|e| e.into_inner())
}

/// Networks the settings screen may offer. Mainnet only appears after opt-in.
pub fn selectable_nets() -> Vec<Net> {
    let mut out = Net::TESTNETS.to_vec();
    if network::enabled() {
        out.insert(0, Net::Mainnet);
    }
    out
}

/// Pick the API server that matches the wallet's chain. This is the single place
/// that prevents a testnet wallet from talking to a mainnet server, and it keeps
/// mainnet wallets behind the explicit opt-in gate.
pub fn net_for(wallet: Network) -> Result<Net, String> {
    if wallet == Network::Bitcoin {
        network::require_enabled()?;
        return Ok(Net::Mainnet);
    }
    let configured = net();
    if configured.is_mainnet() {
        return Err(
            "The API is set to mainnet, but this wallet is testnet. Choose a testnet in Settings."
                .into(),
        );
    }
    Ok(configured)
}

fn config_path() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".cairn").join("config"))
}

pub fn load_config() {
    if let Some(p) = config_path() {
        // The config is a single network name; a huge or special file is not
        // a valid config and must not be read into memory.
        let small = std::fs::metadata(&p)
            .map(|m| m.is_file() && m.len() <= 1024)
            .unwrap_or(false);
        if small {
            if let Ok(s) = std::fs::read_to_string(p) {
                let mut all = Net::TESTNETS.to_vec();
                all.insert(0, Net::Mainnet);
                if let Some(n) = all
                    .iter()
                    .find(|n| n.label().eq_ignore_ascii_case(s.trim()))
                {
                    if n.is_mainnet() && !network::enabled() {
                        return;
                    }
                    *NET.lock().unwrap_or_else(|e| e.into_inner()) = *n;
                }
            }
        }
    }
}

pub fn set_net(n: Net) -> Result<(), String> {
    if n.is_mainnet() {
        network::require_enabled()?;
    }
    *NET.lock().unwrap_or_else(|e| e.into_inner()) = n;
    let p = config_path().ok_or("HOME not set")?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(p, n.label()).map_err(|e| e.to_string())
}

/// CAIRN_API (comma separated) overrides the built-in list, e.g. your own server.
fn providers(net: Net) -> Vec<String> {
    if let Ok(v) = std::env::var("CAIRN_API") {
        let l: Vec<String> = v
            .split(',')
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !l.is_empty() {
            return l;
        }
    }
    net.providers().iter().map(|s| s.to_string()).collect()
}

pub fn providers_desc(net: Net) -> String {
    providers(net).join(", ")
}

fn cooling() -> &'static Mutex<HashMap<String, Instant>> {
    static C: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn is_cooling(p: &str) -> bool {
    cooling()
        .lock()
        .map(|m| m.get(p).map(|t| t.elapsed() < COOLDOWN).unwrap_or(false))
        .unwrap_or(false)
}

fn mark_cooling(p: &str) {
    if let Ok(mut m) = cooling().lock() {
        m.insert(p.to_string(), Instant::now());
    }
}

// ---------- HTTP with failover ----------

fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(30))
            .timeout(Duration::from_secs(45))
            .user_agent("cairn/0.3 (open-source bitcoin wallet)")
            .https_only(true) // refuse http and HTTPS->HTTP redirects
            .max_idle_connections(0) // fresh connection each time: no stale pooled sockets
            .build()
    })
}

/// Server-controlled text is untrusted: strip terminal control characters and
/// bound it before it can reach the screen.
fn safe_text(s: &str, max_chars: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect()
}

fn read_resp(r: Result<ureq::Response, ureq::Error>) -> Result<String, String> {
    match r {
        Ok(resp) => {
            let mut body = String::new();
            resp.into_reader()
                .take(MAX_BODY)
                .read_to_string(&mut body)
                .map_err(|e| format!("read error: {e}"))?;
            Ok(body)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let mut b = String::new();
            let _ = resp.into_reader().take(2000).read_to_string(&mut b);
            if code == 429 || code >= 500 {
                Err(format!("server busy or down (HTTP {code})"))
            } else {
                // Definitive answer (e.g. a transaction rejected): don't retry elsewhere.
                Err(format!("REJECTED: {}", safe_text(b.trim(), 500)))
            }
        }
        Err(e) => Err(format!("network error: {e}")),
    }
}

/// Global pacing: request start times are spaced out across all threads so bursts
/// can't trip the public servers' rate limits.
fn pace() {
    static NEXT: OnceLock<Mutex<Instant>> = OnceLock::new();
    let m = NEXT.get_or_init(|| Mutex::new(Instant::now()));
    let wait = {
        let mut next = m.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let slot = if *next > now { *next } else { now };
        *next = slot + MIN_GAP;
        slot.saturating_duration_since(now)
    };
    if !wait.is_zero() {
        std::thread::sleep(wait);
    }
}

fn http_get(url: &str) -> Result<String, String> {
    pace();
    read_resp(agent().get(url).call())
}

fn http_post(url: &str, body: &str) -> Result<String, String> {
    pace();
    read_resp(
        agent()
            .post(url)
            .set("Content-Type", "text/plain")
            .send_string(body),
    )
}

fn url_parts(p: &str) -> Option<(&str, &str)> {
    let rest = p.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    let path = rest.strip_prefix(authority).unwrap_or("");
    Some((host, path))
}

fn is_testnet_segment(seg: &str) -> bool {
    matches!(
        seg.to_ascii_lowercase().as_str(),
        "testnet" | "testnet3" | "testnet4" | "signet"
    )
}

/// Chain-aware URL guard. Testnets must name a test network; mainnet must be
/// HTTPS and must not name a test network. This stops the common accident of
/// pointing a wallet at the other chain; it does not prove what a server serves.
fn looks_like_url_for(net: Net, p: &str) -> bool {
    let Some((host, path)) = url_parts(p) else {
        return false;
    };
    let names_testnet = host
        .split('.')
        .chain(path.split(['/', '?', '#']))
        .any(is_testnet_segment);
    if net.is_mainnet() {
        !names_testnet
    } else {
        names_testnet
    }
}

/// Try each provider (healthy ones first). A provider that fails is rested for a minute.
fn try_providers(
    net: Net,
    path: &str,
    call: &dyn Fn(&str) -> Result<String, String>,
) -> Result<String, String> {
    let provs = providers(net);
    for p in &provs {
        if !looks_like_url_for(net, p) {
            return Err(if net.is_mainnet() {
                "Refusing: mainnet API URLs must be https and must not name a testnet/signet endpoint"
                    .into()
            } else {
                "Refusing: API URL must be https and name a testnet/signet endpoint".into()
            });
        }
    }
    let (mut order, resting): (Vec<String>, Vec<String>) =
        provs.into_iter().partition(|p| !is_cooling(p));
    order.extend(resting);
    let mut last = String::new();
    for p in order {
        let url = format!("{p}{path}");
        for attempt in 0..3u64 {
            match call(&url) {
                Ok(b) => return Ok(b),
                Err(e) => {
                    if let Some(msg) = e.strip_prefix("REJECTED:") {
                        return Err(msg.trim().to_string());
                    }
                    last = e;
                    if attempt < 2 {
                        // Rate limited (429): back off much longer than for other errors.
                        let ms = if last.contains("429") {
                            2000 * (attempt + 1)
                        } else {
                            700
                        };
                        std::thread::sleep(Duration::from_millis(ms));
                    }
                }
            }
        }
        mark_cooling(&p);
    }
    Err(last)
}

fn get(net: Net, path: &str) -> Result<Value, String> {
    let body = try_providers(net, path, &|u| http_get(u))?;
    serde_json::from_str(&body).map_err(|e| format!("bad response: {e}"))
}

/// Run `f` over items in parallel, MAX_PARALLEL at a time, keeping order.
fn par_map<T: Sync, R: Send>(
    items: &[T],
    f: impl Fn(&T) -> Result<R, String> + Sync,
) -> Result<Vec<R>, String> {
    let mut out = Vec::with_capacity(items.len());
    for chunk in items.chunks(MAX_PARALLEL) {
        let results: Vec<Result<R, String>> = std::thread::scope(|s| {
            let f = &f;
            let handles: Vec<_> = chunk.iter().map(|it| s.spawn(move || f(it))).collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|_| Err("worker panicked".to_string()))
                })
                .collect()
        });
        for r in results {
            out.push(r?);
        }
    }
    Ok(out)
}

// ---------- balances ----------

pub struct AddrInfo {
    pub confirmed: i64,
    pub unconfirmed: i64,
    pub tx_count: u64,
}

pub fn address_info(net: Net, addr: &str) -> Result<AddrInfo, String> {
    let v = get(net, &format!("/address/{addr}"))?;
    let delta = |k: &str| {
        v[k]["funded_txo_sum"]
            .as_i64()
            .unwrap_or(0)
            .saturating_sub(v[k]["spent_txo_sum"].as_i64().unwrap_or(0))
    };
    let count = |k: &str| v[k]["tx_count"].as_u64().unwrap_or(0);
    Ok(AddrInfo {
        confirmed: delta("chain_stats"),
        unconfirmed: delta("mempool_stats"),
        tx_count: count("chain_stats").saturating_add(count("mempool_stats")),
    })
}

#[derive(Default)]
pub struct WalletState {
    pub confirmed: i64,
    pub unconfirmed: i64,
    pub used: Vec<String>,
    pub next_receive: u32,
    pub next_change: u32,
}

#[derive(Default)]
struct ChainScan {
    confirmed: i64,
    unconfirmed: i64,
    used: Vec<String>,
    next: u32,
}

/// Scan one chain in parallel batches. Stops after `gap_limit` unused addresses in a row,
/// but never before `min_index` (addresses we already know about from the last sync).
fn scan_chain(
    net: Net,
    watch: &Watch,
    chain: u32,
    gap_limit: u32,
    min_index: u32,
) -> Result<ChainScan, String> {
    let mut res = ChainScan::default();
    let (mut gap, mut idx) = (0u32, 0u32);
    while (gap < gap_limit || idx < min_index) && idx < MAX_INDEX {
        let addrs = watch.addresses(chain, idx, gap_limit)?;
        let infos = par_map(&addrs, |a| address_info(net, a))?;
        for (i, (addr, info)) in addrs.into_iter().zip(infos).enumerate() {
            if info.tx_count > 0 {
                gap = 0;
                res.confirmed = res.confirmed.saturating_add(info.confirmed);
                res.unconfirmed = res.unconfirmed.saturating_add(info.unconfirmed);
                res.used.push(addr);
                res.next = idx + i as u32 + 1;
            } else {
                gap += 1;
            }
        }
        idx += gap_limit;
    }
    Ok(res)
}

/// `prev` (if any) makes a quick refresh safe: we always re-check everything known before.
pub fn sync(
    watch: &Watch,
    gap_limit: u32,
    prev: Option<&WalletState>,
) -> Result<WalletState, String> {
    let net = net_for(watch.network())?;
    let (min_r, min_c) = prev
        .map(|p| (p.next_receive, p.next_change))
        .unwrap_or((0, 0));
    let (r, c) = std::thread::scope(|s| {
        let h0 = s.spawn(|| scan_chain(net, watch, 0, gap_limit, min_r));
        let h1 = s.spawn(|| scan_chain(net, watch, 1, gap_limit.min(5), min_c));
        (h0.join(), h1.join())
    });
    let r = r.map_err(|_| "worker panicked".to_string())??;
    let c = c.map_err(|_| "worker panicked".to_string())??;
    let mut used = r.used;
    used.extend(c.used);
    Ok(WalletState {
        confirmed: r.confirmed.saturating_add(c.confirmed),
        unconfirmed: r.unconfirmed.saturating_add(c.unconfirmed),
        used,
        next_receive: r.next,
        next_change: c.next,
    })
}

// ---------- history ----------

pub struct TxSummary {
    pub txid: String,
    pub net: i64,
    pub height: Option<u64>,
}

fn net_for_tx(tx: &Value, ours: &HashSet<String>) -> i64 {
    let mut net = 0i64;
    for o in tx["vout"].as_array().into_iter().flatten() {
        if let Some(a) = o["scriptpubkey_address"].as_str() {
            if ours.contains(a) {
                net = net.saturating_add(o["value"].as_i64().unwrap_or(0));
            }
        }
    }
    for i in tx["vin"].as_array().into_iter().flatten() {
        if let Some(a) = i["prevout"]["scriptpubkey_address"].as_str() {
            if ours.contains(a) {
                net = net.saturating_sub(i["prevout"]["value"].as_i64().unwrap_or(0));
            }
        }
    }
    net
}

pub fn transactions(net: Net, state: &WalletState) -> Result<Vec<TxSummary>, String> {
    let ours: HashSet<String> = state.used.iter().cloned().collect();
    let mut seen: HashMap<String, TxSummary> = HashMap::new();
    // Fetch in bounded batches so a malicious server cannot make us hold a
    // response for every address at once.
    for chunk in state.used.chunks(MAX_PARALLEL) {
        let pages = par_map(chunk, |addr| get(net, &format!("/address/{addr}/txs")))?;
        for v in pages {
            for tx in v.as_array().into_iter().flatten() {
                let Some(txid) = tx["txid"].as_str().and_then(|s| Txid::from_str(s).ok()) else {
                    continue; // never display an unchecked server string
                };
                let txid = txid.to_string();
                if seen.contains_key(&txid) {
                    continue;
                }
                if seen.len() >= MAX_TX_SUMMARIES {
                    return Err("server returned too many transactions".into());
                }
                let height = if tx["status"]["confirmed"].as_bool().unwrap_or(false) {
                    tx["status"]["block_height"].as_u64()
                } else {
                    None
                };
                seen.insert(
                    txid.clone(),
                    TxSummary {
                        txid,
                        net: net_for_tx(tx, &ours),
                        height,
                    },
                );
            }
        }
    }
    let mut out: Vec<TxSummary> = seen.into_values().collect();
    out.sort_by(|a, b| match (a.height, b.height) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(x), Some(y)) => y.cmp(&x),
    });
    Ok(out)
}

// ---------- sending ----------

#[derive(Clone, Debug)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub value: u64,
    pub address: String,
}

/// Confirmed unspent outputs of one of our own addresses.
fn parse_utxo(u: &Value, addr: &str) -> Result<Utxo, String> {
    let txid = u["txid"]
        .as_str()
        .and_then(|s| Txid::from_str(s).ok())
        .ok_or("bad txid from server")?;
    let vout = u32::try_from(u["vout"].as_u64().ok_or("bad vout from server")?)
        .map_err(|_| "bad vout from server")?;
    let value = u["value"].as_u64().ok_or("bad value from server")?;
    if value > network::MAX_MONEY_SATS {
        return Err("UTXO value from server exceeds the 21 million BTC supply".into());
    }
    Ok(Utxo {
        txid,
        vout,
        value,
        address: addr.to_string(),
    })
}

pub fn utxos(net: Net, addr: &str) -> Result<Vec<Utxo>, String> {
    let v = get(net, &format!("/address/{addr}/utxo"))?;
    let mut out = vec![];
    for u in v.as_array().into_iter().flatten() {
        if !u["status"]["confirmed"].as_bool().unwrap_or(false) {
            continue;
        }
        if out.len() >= MAX_UTXOS_PER_ADDRESS {
            return Err("server returned too many UTXOs for one address".into());
        }
        out.push(parse_utxo(u, addr)?);
    }
    Ok(out)
}

pub fn utxos_for(net: Net, addrs: &[String]) -> Result<Vec<Utxo>, String> {
    let mut out = vec![];
    for chunk in addrs.chunks(MAX_PARALLEL) {
        let pages = par_map(chunk, |a| utxos(net, a))?;
        for page in pages {
            if out.len().saturating_add(page.len()) > MAX_UTXOS_TOTAL {
                return Err("server returned too many UTXOs across this wallet".into());
            }
            out.extend(page);
        }
    }
    Ok(out)
}

pub struct Rates {
    pub slow: f64,
    pub normal: f64,
    pub fast: f64,
}

/// Fee estimates in sat/vB (clamped to 1..=1000).
pub fn fee_rates(net: Net) -> Result<Rates, String> {
    let v = get(net, "/fee-estimates")?;
    let pick = |keys: &[&str]| -> Option<f64> { keys.iter().find_map(|k| v[*k].as_f64()) };
    // Reject NaN/inf from the server instead of turning them into a zero fee.
    let clamp = |x: f64| {
        if x.is_finite() {
            x.clamp(1.0, 1000.0)
        } else {
            1.0
        }
    };
    let fast = clamp(pick(&["1", "2", "3"]).ok_or("no fee estimate available")?);
    let normal = clamp(pick(&["6", "5", "4", "3"]).unwrap_or(fast)).min(fast);
    let slow = clamp(pick(&["144", "72", "25", "12"]).unwrap_or(normal)).min(normal);
    Ok(Rates { slow, normal, fast })
}

/// Broadcast a signed transaction (hex). Returns the txid the server reports.
pub fn broadcast(net: Net, hex: &str) -> Result<String, String> {
    let body = try_providers(net, "/tx", &|u| http_post(u, hex))?;
    let text = body.trim();
    Ok(match Txid::from_str(text) {
        Ok(txid) => txid.to_string(),
        // A 200 response that is not a txid is still not trusted; show a
        // sanitised, bounded version for the mismatch note.
        Err(_) => safe_text(text, 128),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_url_guard_is_chain_aware() {
        assert!(looks_like_url_for(
            Net::Testnet4,
            "https://mempool.space/testnet4/api"
        ));
        assert!(looks_like_url_for(
            Net::Testnet3,
            "https://mempool.space/testnet/api"
        ));
        assert!(looks_like_url_for(
            Net::Signet,
            "https://blockstream.info/signet/api"
        ));
        assert!(looks_like_url_for(
            Net::Testnet3,
            "https://testnet.example/api"
        ));
        assert!(!looks_like_url_for(
            Net::Testnet3,
            "http://mempool.space/testnet/api"
        ));
        assert!(!looks_like_url_for(
            Net::Testnet3,
            "https://mempool.space/api"
        ));
        assert!(!looks_like_url_for(
            Net::Testnet3,
            "https://example.com/mainnet/api"
        ));
        assert!(!looks_like_url_for(
            Net::Testnet3,
            "https://example.com/testnetfoo/api"
        ));

        assert!(looks_like_url_for(
            Net::Mainnet,
            "https://mempool.space/api"
        ));
        assert!(looks_like_url_for(
            Net::Mainnet,
            "https://blockstream.info/api"
        ));
        assert!(looks_like_url_for(
            Net::Mainnet,
            "https://node.example/mainnet/api"
        ));
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "http://mempool.space/api"
        ));
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "https://mempool.space/testnet/api"
        ));
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "https://example.com/signet/api"
        ));

        // Scheme is case-sensitive and must be exactly https.
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "HTTPS://mempool.space/api"
        ));
        assert!(!looks_like_url_for(Net::Mainnet, "ftp://mempool.space/api"));
        assert!(!looks_like_url_for(Net::Mainnet, "mempool.space/api"));

        // A testnet name anywhere in the host or path disqualifies mainnet.
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "https://mempool.space/testnet/api?x=1"
        ));
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "https://testnet.mempool.space/api"
        ));
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "https://user:pass@mempool.space/testnet/api"
        ));
        assert!(looks_like_url_for(
            Net::Mainnet,
            "https://user:pass@mempool.space/api"
        ));

        // Testnets need an explicit test-network segment.
        assert!(!looks_like_url_for(Net::Testnet4, "https://"));
        assert!(!looks_like_url_for(Net::Testnet4, "https:///api"));
        assert!(!looks_like_url_for(
            Net::Testnet4,
            "https://example.com/api"
        ));
        assert!(looks_like_url_for(
            Net::Signet,
            "https://example.com/signet/api?x=1"
        ));
    }

    #[test]
    fn net_maps_to_the_matching_chain() {
        assert_eq!(Net::Mainnet.network(), Network::Bitcoin);
        for n in Net::TESTNETS {
            assert_eq!(n.network(), Network::Testnet);
        }
    }

    #[test]
    fn server_values_are_bounded_and_display_text_is_clean() {
        let txid = "11".repeat(32);
        let good = serde_json::json!({
            "txid": txid,
            "vout": 3,
            "value": 50_000,
            "status": { "confirmed": true }
        });
        let u = parse_utxo(&good, "addr").unwrap();
        assert_eq!(u.value, 50_000);
        assert_eq!(u.vout, 3);

        let mut too_rich = good.clone();
        too_rich["value"] = serde_json::json!(network::MAX_MONEY_SATS + 1);
        assert!(parse_utxo(&too_rich, "addr").is_err());

        let mut bad_vout = good.clone();
        bad_vout["vout"] = serde_json::json!(u64::from(u32::MAX) + 1);
        assert!(parse_utxo(&bad_vout, "addr").is_err());

        let mut bad_txid = good;
        bad_txid["txid"] = serde_json::json!("not-a-txid");
        assert!(parse_utxo(&bad_txid, "addr").is_err());

        // Terminal control characters from a server must never reach the screen.
        assert_eq!(safe_text("ab\u{1b}[31mcd\n", 64), "ab[31mcd");
        assert_eq!(safe_text("abcdef", 3), "abc");
    }
}
