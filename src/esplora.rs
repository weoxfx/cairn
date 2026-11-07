//! Network layer (Esplora API: mempool.space / Blockstream). It never sees keys or the seed.
//! The server can see your IP and which addresses you query. Testnet/signet only for now.
//! Everything the server returns is untrusted. Balances/history are display-only;
//! for sending we only take UTXO txid/vout/value, and signatures commit to those values.

use crate::wallet::Watch;
use bitcoin::Txid;
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
const COOLDOWN: Duration = Duration::from_secs(60);
const MIN_GAP: Duration = Duration::from_millis(200); // at most ~5 requests/second overall

// ---------- network choice + providers ----------

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Net {
    Testnet4,
    Testnet3,
    Signet,
}

impl Net {
    pub const ALL: [Net; 3] = [Net::Testnet4, Net::Testnet3, Net::Signet];

    pub fn label(self) -> &'static str {
        match self {
            Net::Testnet4 => "Testnet4",
            Net::Testnet3 => "Testnet3",
            Net::Signet => "Signet",
        }
    }

    /// Public providers in order of preference (failover goes down this list).
    fn providers(self) -> &'static [&'static str] {
        match self {
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

static NET: Mutex<Net> = Mutex::new(Net::Testnet4);

pub fn net() -> Net {
    *NET.lock().unwrap_or_else(|e| e.into_inner())
}

fn config_path() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".cairn").join("config"))
}

pub fn load_config() {
    if let Some(p) = config_path() {
        if let Ok(s) = std::fs::read_to_string(p) {
            if let Some(n) = Net::ALL
                .iter()
                .find(|n| n.label().eq_ignore_ascii_case(s.trim()))
            {
                *NET.lock().unwrap_or_else(|e| e.into_inner()) = *n;
            }
        }
    }
}

pub fn set_net(n: Net) -> Result<(), String> {
    *NET.lock().unwrap_or_else(|e| e.into_inner()) = n;
    let p = config_path().ok_or("HOME not set")?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(p, n.label()).map_err(|e| e.to_string())
}

/// CAIRN_API (comma separated) overrides the built-in list, e.g. your own server.
fn providers() -> Vec<String> {
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
    net().providers().iter().map(|s| s.to_string()).collect()
}

pub fn providers_desc() -> String {
    providers().join(", ")
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
            .user_agent("cairn/0.2 (open-source testnet wallet)")
            .max_idle_connections(0) // fresh connection each time: no stale pooled sockets
            .build()
    })
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
                Err(format!("REJECTED: {}", b.trim()))
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

/// Footgun guard: only HTTPS URLs whose host or path names a test network are
/// accepted. This stops an accidental mainnet URL; it does not prove which chain
/// a server actually serves (use your own node for that).
fn looks_like_testnet_url(p: &str) -> bool {
    let Some(rest) = p.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    let path = rest.strip_prefix(authority).unwrap_or("");
    host.split('.')
        .chain(path.split(['/', '?', '#']))
        .any(|seg| {
            matches!(
                seg.to_ascii_lowercase().as_str(),
                "testnet" | "testnet3" | "testnet4" | "signet"
            )
        })
}

/// Try each provider (healthy ones first). A provider that fails is rested for a minute.
fn try_providers(
    path: &str,
    call: &dyn Fn(&str) -> Result<String, String>,
) -> Result<String, String> {
    let provs = providers();
    for p in &provs {
        if !looks_like_testnet_url(p) {
            return Err(
                "Refusing: API URL must be https and name a testnet/signet endpoint".into(),
            );
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

fn get(path: &str) -> Result<Value, String> {
    let body = try_providers(path, &|u| http_get(u))?;
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

pub fn address_info(addr: &str) -> Result<AddrInfo, String> {
    let v = get(&format!("/address/{addr}"))?;
    let delta = |k: &str| {
        v[k]["funded_txo_sum"].as_i64().unwrap_or(0) - v[k]["spent_txo_sum"].as_i64().unwrap_or(0)
    };
    let count = |k: &str| v[k]["tx_count"].as_u64().unwrap_or(0);
    Ok(AddrInfo {
        confirmed: delta("chain_stats"),
        unconfirmed: delta("mempool_stats"),
        tx_count: count("chain_stats") + count("mempool_stats"),
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
    watch: &Watch,
    chain: u32,
    gap_limit: u32,
    min_index: u32,
) -> Result<ChainScan, String> {
    let mut res = ChainScan::default();
    let (mut gap, mut idx) = (0u32, 0u32);
    while (gap < gap_limit || idx < min_index) && idx < MAX_INDEX {
        let addrs = watch.addresses(chain, idx, gap_limit)?;
        let infos = par_map(&addrs, |a| address_info(a))?;
        for (i, (addr, info)) in addrs.into_iter().zip(infos).enumerate() {
            if info.tx_count > 0 {
                gap = 0;
                res.confirmed += info.confirmed;
                res.unconfirmed += info.unconfirmed;
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
    let (min_r, min_c) = prev
        .map(|p| (p.next_receive, p.next_change))
        .unwrap_or((0, 0));
    let (r, c) = std::thread::scope(|s| {
        let h0 = s.spawn(|| scan_chain(watch, 0, gap_limit, min_r));
        let h1 = s.spawn(|| scan_chain(watch, 1, gap_limit.min(5), min_c));
        (h0.join(), h1.join())
    });
    let r = r.map_err(|_| "worker panicked".to_string())??;
    let c = c.map_err(|_| "worker panicked".to_string())??;
    let mut used = r.used;
    used.extend(c.used);
    Ok(WalletState {
        confirmed: r.confirmed + c.confirmed,
        unconfirmed: r.unconfirmed + c.unconfirmed,
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
                net += o["value"].as_i64().unwrap_or(0);
            }
        }
    }
    for i in tx["vin"].as_array().into_iter().flatten() {
        if let Some(a) = i["prevout"]["scriptpubkey_address"].as_str() {
            if ours.contains(a) {
                net -= i["prevout"]["value"].as_i64().unwrap_or(0);
            }
        }
    }
    net
}

pub fn transactions(state: &WalletState) -> Result<Vec<TxSummary>, String> {
    let ours: HashSet<String> = state.used.iter().cloned().collect();
    let pages = par_map(&state.used, |addr| get(&format!("/address/{addr}/txs")))?;
    let mut seen: HashMap<String, TxSummary> = HashMap::new();
    for v in pages {
        for tx in v.as_array().into_iter().flatten() {
            let txid = tx["txid"].as_str().unwrap_or("").to_string();
            if txid.is_empty() || seen.contains_key(&txid) {
                continue;
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
pub fn utxos(addr: &str) -> Result<Vec<Utxo>, String> {
    let v = get(&format!("/address/{addr}/utxo"))?;
    let mut out = vec![];
    for u in v.as_array().into_iter().flatten() {
        if !u["status"]["confirmed"].as_bool().unwrap_or(false) {
            continue;
        }
        let txid = u["txid"]
            .as_str()
            .and_then(|s| Txid::from_str(s).ok())
            .ok_or("bad txid from server")?;
        let vout = u["vout"].as_u64().ok_or("bad vout from server")? as u32;
        let value = u["value"].as_u64().ok_or("bad value from server")?;
        out.push(Utxo {
            txid,
            vout,
            value,
            address: addr.to_string(),
        });
    }
    Ok(out)
}

pub fn utxos_for(addrs: &[String]) -> Result<Vec<Utxo>, String> {
    Ok(par_map(addrs, |a| utxos(a))?
        .into_iter()
        .flatten()
        .collect())
}

pub struct Rates {
    pub slow: f64,
    pub normal: f64,
    pub fast: f64,
}

/// Fee estimates in sat/vB (clamped to 1..=1000).
pub fn fee_rates() -> Result<Rates, String> {
    let v = get("/fee-estimates")?;
    let pick = |keys: &[&str]| -> Option<f64> { keys.iter().find_map(|k| v[*k].as_f64()) };
    let clamp = |x: f64| x.clamp(1.0, 1000.0);
    let fast = clamp(pick(&["1", "2", "3"]).ok_or("no fee estimate available")?);
    let normal = clamp(pick(&["6", "5", "4", "3"]).unwrap_or(fast)).min(fast);
    let slow = clamp(pick(&["144", "72", "25", "12"]).unwrap_or(normal)).min(normal);
    Ok(Rates { slow, normal, fast })
}

/// Broadcast a signed transaction (hex). Returns the txid the server reports.
pub fn broadcast(hex: &str) -> Result<String, String> {
    let body = try_providers("/tx", &|u| http_post(u, hex))?;
    Ok(body.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_url_guard() {
        assert!(looks_like_testnet_url("https://mempool.space/testnet4/api"));
        assert!(looks_like_testnet_url("https://mempool.space/testnet/api"));
        assert!(looks_like_testnet_url(
            "https://blockstream.info/signet/api"
        ));
        assert!(looks_like_testnet_url("https://testnet.example/api"));
        assert!(!looks_like_testnet_url("http://mempool.space/testnet/api"));
        assert!(!looks_like_testnet_url("https://mempool.space/api"));
        assert!(!looks_like_testnet_url("https://example.com/mainnet/api"));
        assert!(!looks_like_testnet_url(
            "https://example.com/testnetfoo/api"
        ));
    }
}
