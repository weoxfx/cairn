//! Network layer (Esplora API: mempool.space / Blockstream). It never sees keys or the seed.
//! The server can see your IP and which addresses you query.
//!
//! Everything the server returns is untrusted. Balances/history are display-only;
//! for sending we take UTXO txid/vout/value and re-check the creating transaction,
//! and signatures commit to those values (a lying server can make a transaction
//! invalid, not steal coins).

use crate::hardening;
use crate::network;
use crate::wallet::Watch;
use bitcoin::{Network, Txid};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const FULL_GAP: u32 = 10; // full scan on open
pub const QUICK_GAP: u32 = 3; // cheap scan on refresh
pub const MAX_INDEX: u32 = 200;
const MAX_BODY: u64 = 2_000_000; // cap on any response body
const MAX_REDIRECTS: usize = 3; // a redirect may stay on the same host only
const MAX_PARALLEL: usize = 4; // gentle on public APIs (avoids rate limits)
const MAX_UTXOS_PER_ADDRESS: usize = 10_000; // reject absurd server responses
const MAX_UTXOS_TOTAL: usize = 20_000;
const MAX_PREVOUT_TXIDS: usize = 100; // bound extra verification requests
const MAX_TX_SUMMARIES: usize = 100_000;
const MAX_HISTORY_VALUE: i64 = network::MAX_MONEY_SATS as i64;
const MAX_BLOCK_HEIGHT: u64 = 10_000_000; // far above any plausible chain tip
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

/// Testnet variants the settings screen may offer. Mainnet is bound to the
/// wallet at creation/import and always uses the mainnet API.
pub fn selectable_nets() -> Vec<Net> {
    Net::TESTNETS.to_vec()
}

/// Pick the API server that matches the wallet's chain. This is the single place
/// that prevents a testnet wallet from talking to a mainnet server.
pub fn net_for(wallet: Network) -> Result<Net, String> {
    if wallet == Network::Bitcoin {
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

/// Only testnet names are accepted from the config file. Mainnet is bound to a
/// wallet, never to a global setting, so an old `Mainnet` value is ignored
/// instead of making every testnet wallet fail its network/API check.
fn config_net(s: &str) -> Option<Net> {
    Net::TESTNETS
        .iter()
        .find(|n| n.label().eq_ignore_ascii_case(s.trim()))
        .copied()
}

pub fn load_config() {
    if let Some(p) = config_path() {
        // The config is a single network name. Refuse symlinks and special
        // files, and read through one descriptor so the checks and the read
        // cannot race with a swap.
        let Ok(f) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&p)
        else {
            return;
        };
        let small = f
            .metadata()
            .map(|m| m.is_file() && m.len() <= 1024)
            .unwrap_or(false);
        if small {
            let mut s = String::new();
            if f.take(1025).read_to_string(&mut s).is_ok() {
                if let Some(n) = config_net(&s) {
                    *NET.lock().unwrap_or_else(|e| e.into_inner()) = n;
                }
            }
        }
    }
}

pub fn set_net(n: Net) -> Result<(), String> {
    let p = config_path().ok_or("HOME not set")?;
    if let Some(dir) = p.parent() {
        hardening::ensure_private_dir(dir)?;
    }
    hardening::write_private(&p, n.label().as_bytes())?;
    *NET.lock().unwrap_or_else(|e| e.into_inner()) = n;
    Ok(())
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

/// Whether `CAIRN_API` replaced the built-in provider list with the user's own
/// server. Reported by `cairn security check`.
pub fn custom_api() -> bool {
    std::env::var("CAIRN_API")
        .map(|v| v.split(',').any(|s| !s.trim().is_empty()))
        .unwrap_or(false)
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

/// Optional SOCKS5/Tor proxy. `CAIRN_PROXY` wins; `CAIRN_TOR=1` is shorthand
/// for the standard local Tor SOCKS port. DNS is resolved by the proxy for
/// hostnames, so an own-node hostname is not leaked to the local resolver.
fn proxy_from_values(proxy: Option<&str>, tor: Option<&str>) -> Option<String> {
    if let Some(v) = proxy {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    match tor {
        Some("1") | Some("true") | Some("yes") => Some("socks5://127.0.0.1:9050".into()),
        _ => None,
    }
}

fn proxy_setting() -> Option<String> {
    proxy_from_values(
        std::env::var("CAIRN_PROXY").ok().as_deref(),
        std::env::var("CAIRN_TOR").ok().as_deref(),
    )
}

/// Human-readable proxy description with credentials removed.
fn proxy_desc_for(p: &str) -> String {
    if let Some(at) = p.rfind('@') {
        let scheme = p.split("://").next().unwrap_or("proxy");
        format!("{scheme}://***@{}", &p[at + 1..])
    } else {
        p.to_string()
    }
}

pub fn proxy_desc() -> Option<String> {
    proxy_setting().map(|p| proxy_desc_for(&p))
}

fn agent() -> Result<&'static ureq::Agent, String> {
    static AGENT: OnceLock<Result<ureq::Agent, String>> = OnceLock::new();
    let built = AGENT.get_or_init(|| {
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(30))
            .timeout(Duration::from_secs(45))
            .user_agent(concat!(
                "cairn/",
                env!("CARGO_PKG_VERSION"),
                " (open-source bitcoin wallet)"
            ))
            .https_only(true) // refuse http outright
            .redirects(0) // redirects are followed manually below, same host only
            .max_idle_connections(0); // fresh connection each time: no stale pooled sockets
        if let Some(p) = proxy_setting() {
            // A configured privacy proxy must never be silently ignored: an
            // invalid value fails closed before any request is made.
            let proxy = ureq::Proxy::new(&p)
                .map_err(|e| format!("invalid CAIRN_PROXY/CAIRN_TOR setting: {e}"))?;
            builder = builder.proxy(proxy);
        }
        Ok(builder.build())
    });
    built.as_ref().map_err(|e| e.clone())
}

/// Server-controlled text is untrusted. This is an allowlist, not a denylist:
/// only printable ASCII (and spaces) can reach the screen, so no future Unicode
/// control, bidi, zero-width, line-breaking or terminal-escape character can
/// slip through. The result is also bounded by character count.
fn safe_text(s: &str, max_chars: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(max_chars)
        .collect()
}

fn read_body(resp: ureq::Response) -> Result<String, String> {
    let mut body = String::new();
    resp.into_reader()
        .take(MAX_BODY + 1)
        .read_to_string(&mut body)
        .map_err(|e| format!("read error: {e}"))?;
    if body.len() as u64 > MAX_BODY {
        return Err("server response exceeds the size limit".into());
    }
    Ok(body)
}

fn status_error(code: u16, resp: ureq::Response) -> String {
    let mut b = String::new();
    let _ = resp.into_reader().take(2000).read_to_string(&mut b);
    if code == 429 || code >= 500 {
        format!("server busy or down (HTTP {code})")
    } else {
        // Definitive answer (e.g. a transaction rejected): don't retry elsewhere.
        format!("REJECTED: {}", safe_text(b.trim(), 500))
    }
}

fn read_resp(r: Result<ureq::Response, ureq::Error>) -> Result<String, String> {
    match r {
        Ok(resp) => read_body(resp),
        Err(ureq::Error::Status(code, resp)) => Err(status_error(code, resp)),
        Err(e) => Err(format!("network error: {e}")),
    }
}

fn is_redirect(code: u16) -> bool {
    matches!(code, 301 | 302 | 303 | 307 | 308)
}

fn redirect_target(resp: &ureq::Response) -> Result<String, String> {
    let location = resp
        .header("location")
        .ok_or("redirect without a Location header")?;
    resolve_redirect(resp.get_url(), location)
}

/// Resolve a Location header against the request URL. Only standard forms are
/// accepted; anything ambiguous fails closed rather than being guessed at.
fn resolve_redirect(base: &str, location: &str) -> Result<String, String> {
    // Validate the raw header value: trimming first could hide a control
    // character that a URL parser would treat differently.
    if !url_chars_ok(location) {
        return Err("redirect target contains control or ambiguous characters".into());
    }
    let location = location.trim();
    let (_, path) = url_parts(base).ok_or("invalid API URL")?;
    let authority = authority_of(base).ok_or("invalid API URL")?;
    if location.is_empty() {
        return Err("empty redirect target".into());
    }
    if location.starts_with("https://") {
        if url_parts(location).is_none() {
            return Err("invalid absolute redirect target".into());
        }
        return Ok(location.to_string());
    }
    if let Some(rest) = location.strip_prefix("//") {
        let out = format!("https://{rest}");
        if url_parts(&out).is_none() {
            return Err("invalid redirect target".into());
        }
        return Ok(out);
    }
    if location.starts_with('/') {
        return Ok(format!("https://{authority}{location}"));
    }
    if location.starts_with('?') {
        let bare = path.split('?').next().unwrap_or(path);
        return Ok(format!("https://{authority}{bare}{location}"));
    }
    let dir = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "/",
    };
    Ok(format!("https://{authority}{dir}{location}"))
}

enum GetStep {
    Body(String),
    Redirect(String),
}

fn one_get(url: &str) -> Result<GetStep, String> {
    match agent()?.get(url).call() {
        Ok(resp) if is_redirect(resp.status()) => Ok(GetStep::Redirect(redirect_target(&resp)?)),
        Ok(resp) => Ok(GetStep::Body(read_body(resp)?)),
        Err(ureq::Error::Status(code, resp)) if is_redirect(code) => {
            Ok(GetStep::Redirect(redirect_target(&resp)?))
        }
        Err(ureq::Error::Status(code, resp)) => Err(status_error(code, resp)),
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

/// GET with manual redirect handling. A redirect may only stay on the same
/// origin and must still satisfy the chain guard, so a provider cannot hand our
/// requests (and metadata) to an unrelated host.
fn http_get(net: Net, url: &str) -> Result<String, String> {
    pace();
    authority_of(url).ok_or("invalid API URL")?;
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        match one_get(&current)? {
            GetStep::Body(body) => return Ok(body),
            GetStep::Redirect(next) => {
                if !same_origin(url, &next) || !looks_like_url_for(net, &next) {
                    return Err("refusing API redirect to another host or chain".into());
                }
                current = next;
            }
        }
    }
    Err("too many API redirects".into())
}

fn http_post(url: &str, body: &str) -> Result<String, String> {
    pace();
    match agent()?
        .post(url)
        .set("Content-Type", "text/plain")
        .send_string(body)
    {
        // A signed transaction must go to the endpoint we chose, never to
        // wherever a server points us.
        Ok(resp) if is_redirect(resp.status()) => Err("refusing a redirect on broadcast".into()),
        other => read_resp(other),
    }
}

fn same_origin(a: &str, b: &str) -> bool {
    match (authority_of(a), authority_of(b)) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

fn authority_of(p: &str) -> Option<&str> {
    if !url_chars_ok(p) {
        return None;
    }
    let rest = p.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    // Reject IPv6 authorities instead of splitting on ':' and comparing only
    // the first hextet. This guard only accepts hostnames and IPv4 literals.
    if authority.starts_with('[') || authority.contains(']') || authority.matches(':').count() > 1 {
        return None;
    }
    let mut parts = authority.split(':');
    let host = parts.next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    if let Some(port) = parts.next() {
        if port.is_empty() {
            return None;
        }
    }
    Some(authority)
}

fn url_parts(p: &str) -> Option<(&str, &str)> {
    let authority = authority_of(p)?;
    let rest = p.strip_prefix("https://")?;
    let host = authority.split(':').next().unwrap_or(authority);
    let path = rest.strip_prefix(authority).unwrap_or("");
    Some((host, path))
}

/// Reject URLs whose meaning could differ between this parser and the HTTP
/// client. The WHATWG parser treats `\` as `/` for https URLs, so a URL like
/// `https://evil.example\@mempool.space/api` would connect to `evil.example`
/// while a naive host check sees `mempool.space`. Fail closed instead.
fn url_chars_ok(s: &str) -> bool {
    !s.chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
}

/// Fuzzing entry point: parse a configured URL and a redirect target, checking
/// that the manual resolver cannot emit a URL the guard would misread. Enabled
/// only by the `fuzzing` feature.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_url(base: &str, location: &str) {
    let _ = url_parts(base);
    let _ = url_parts(location);
    let _ = authority_of(base);
    let _ = authority_of(location);
    for net in [Net::Mainnet, Net::Testnet4, Net::Testnet3, Net::Signet] {
        let _ = looks_like_url_for(net, base);
        let _ = looks_like_url_for(net, location);
    }

    if let Some((host, path)) = url_parts(location) {
        assert!(url_chars_ok(host) && url_chars_ok(path));
    }

    if let Ok(out) = resolve_redirect(base, location) {
        assert!(out.starts_with("https://"), "redirect escaped HTTPS: {out}");
        assert!(url_chars_ok(&out), "ambiguous redirect target: {out}");
        let (host, path) = url_parts(&out).expect("resolved URL must parse");
        assert!(url_chars_ok(host) && url_chars_ok(path));
    }
}

fn is_testnet_segment(seg: &str) -> bool {
    matches!(
        seg.to_ascii_lowercase().as_str(),
        "testnet" | "testnet3" | "testnet4" | "signet"
    )
}

fn chain_segments(net: Net) -> &'static [&'static str] {
    match net {
        Net::Mainnet => &[],
        Net::Testnet4 => &["testnet4"],
        Net::Testnet3 => &["testnet", "testnet3"],
        Net::Signet => &["signet"],
    }
}

/// Chain-aware URL guard. Each testnet must name its own chain; mainnet must be
/// HTTPS and must not name any test network. This stops the common accident of
/// pointing a wallet at another chain; it does not prove what a server serves.
fn looks_like_url_for(net: Net, p: &str) -> bool {
    let Some((host, path)) = url_parts(p) else {
        return false;
    };
    let path_only = path.split(['?', '#']).next().unwrap_or(path);
    if net.is_mainnet() {
        // Keep checking the whole path and query for mainnet: a testnet name
        // anywhere in a mainnet API URL is a misconfiguration or a bypass.
        !host
            .split('.')
            .chain(path.split(['/', '?', '#', '&', '=']))
            .any(is_testnet_segment)
    } else {
        let mut segments = host.split('.').chain(path_only.split('/'));
        let wanted = chain_segments(net);
        segments.any(|seg| wanted.iter().any(|w| seg.eq_ignore_ascii_case(w)))
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
    let body = try_providers(net, path, &|u| http_get(net, u))?;
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
    let delta = |k: &str| -> Result<i64, String> {
        let funded = v[k]["funded_txo_sum"].as_u64().unwrap_or(0);
        let spent = v[k]["spent_txo_sum"].as_u64().unwrap_or(0);
        let max = network::MAX_MONEY_SATS as i128;
        if funded > network::MAX_MONEY_SATS || spent > network::MAX_MONEY_SATS {
            return Err("server returned an impossible balance".into());
        }
        // A mempool delta is legitimately negative when an address spends a
        // confirmed coin; chain deltas are never negative. Don't clamp either.
        let value = funded as i128 - spent as i128;
        let allowed = if k == "mempool_stats" {
            (-max..=max).contains(&value)
        } else {
            (0..=max).contains(&value)
        };
        if !allowed {
            return Err("server returned an impossible balance".into());
        }
        Ok(value as i64)
    };
    let count = |k: &str| v[k]["tx_count"].as_u64().unwrap_or(0);
    Ok(AddrInfo {
        confirmed: delta("chain_stats")?,
        unconfirmed: delta("mempool_stats")?,
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
                res.confirmed = res
                    .confirmed
                    .saturating_add(info.confirmed)
                    .min(network::MAX_MONEY_SATS as i64);
                res.unconfirmed = res
                    .unconfirmed
                    .saturating_add(info.unconfirmed)
                    .min(network::MAX_MONEY_SATS as i64);
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
    let confirmed = r
        .confirmed
        .saturating_add(c.confirmed)
        .min(network::MAX_MONEY_SATS as i64);
    let unconfirmed = r
        .unconfirmed
        .saturating_add(c.unconfirmed)
        .min(network::MAX_MONEY_SATS as i64);
    Ok(WalletState {
        confirmed,
        // Pending spends can make this negative, but never below zero total.
        unconfirmed: unconfirmed.max(-confirmed),
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

/// History is display-only, but it must still be bounded: a malicious provider
/// could otherwise print impossible amounts or heights. Every value is checked
/// against the 21M BTC supply and the running total is kept in range.
fn net_for_tx(tx: &Value, ours: &HashSet<String>) -> Result<i64, String> {
    let mut net: i64 = 0;
    let mut add = |value: &Value, sign: i64| -> Result<(), String> {
        let v = value
            .as_u64()
            .ok_or("server returned a non-numeric history value")?;
        if v > network::MAX_MONEY_SATS {
            return Err("server returned an impossible history amount".into());
        }
        let delta = i64::try_from(v).map_err(|_| "history amount overflow")?;
        net = net
            .checked_add(sign * delta)
            .ok_or("history amount overflow")?;
        if !(-MAX_HISTORY_VALUE..=MAX_HISTORY_VALUE).contains(&net) {
            return Err("server returned an impossible history total".into());
        }
        Ok(())
    };
    for o in tx["vout"].as_array().into_iter().flatten() {
        if let Some(a) = o["scriptpubkey_address"].as_str() {
            if ours.contains(a) {
                add(&o["value"], 1)?;
            }
        }
    }
    for i in tx["vin"].as_array().into_iter().flatten() {
        if let Some(a) = i["prevout"]["scriptpubkey_address"].as_str() {
            if ours.contains(a) {
                add(&i["prevout"]["value"], -1)?;
            }
        }
    }
    Ok(net)
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
                    let h = tx["status"]["block_height"]
                        .as_u64()
                        .ok_or("confirmed transaction has no block height")?;
                    if h > MAX_BLOCK_HEIGHT {
                        return Err("server returned an impossible block height".into());
                    }
                    Some(h)
                } else {
                    None
                };
                seen.insert(
                    txid.clone(),
                    TxSummary {
                        txid,
                        net: net_for_tx(tx, &ours)?,
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

/// Check one server-supplied UTXO against the transaction that created it.
fn check_prevout(tx: &Value, u: &Utxo) -> Result<(), String> {
    let expected = u.txid.to_string();
    let txid = tx["txid"]
        .as_str()
        .ok_or("previous transaction has no txid")?;
    if txid != expected {
        return Err("previous transaction id does not match the coin".into());
    }
    if !tx["status"]["confirmed"].as_bool().unwrap_or(false) {
        return Err("coin's previous transaction is not confirmed".into());
    }
    let vout = tx["vout"]
        .as_array()
        .and_then(|v| v.get(u.vout as usize))
        .ok_or("previous transaction has no such output")?;
    let value = vout["value"]
        .as_u64()
        .ok_or("previous output has no value")?;
    if value > network::MAX_MONEY_SATS {
        return Err("previous output exceeds the 21 million BTC supply".into());
    }
    if value != u.value {
        return Err("server lied about the coin's value".into());
    }
    let addr = vout["scriptpubkey_address"]
        .as_str()
        .ok_or("previous output has no address")?;
    if addr != u.address {
        return Err("server lied about the coin's address".into());
    }
    Ok(())
}

/// Re-fetch the creating transaction for every coin being spent and compare the
/// output's value and address with what the UTXO endpoint claimed. This is
/// defense in depth: BIP143 already commits to the value, so a lie makes the
/// transaction invalid rather than stealing, but failing closed here stops the
/// wallet from signing metadata it has not cross-checked.
pub fn verify_prevouts(net: Net, utxos: &[Utxo]) -> Result<(), String> {
    if utxos.is_empty() {
        return Ok(());
    }
    let mut txids: Vec<String> = utxos.iter().map(|u| u.txid.to_string()).collect();
    txids.sort();
    txids.dedup();
    if txids.len() > MAX_PREVOUT_TXIDS {
        return Err(format!(
            "refusing to verify {} coins in one transaction (limit {MAX_PREVOUT_TXIDS}); consolidate first",
            txids.len()
        ));
    }
    let fetched = par_map(&txids, |t| get(net, &format!("/tx/{t}")))?;
    let by_txid: HashMap<&str, &Value> = txids
        .iter()
        .map(|s| s.as_str())
        .zip(fetched.iter())
        .collect();
    for u in utxos {
        let key = u.txid.to_string();
        let tx = by_txid
            .get(key.as_str())
            .ok_or("internal error: missing verified transaction")?;
        check_prevout(tx, u)?;
    }
    Ok(())
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
            x.clamp(1.0, network::MAX_FEE_RATE)
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
    use bitcoin::hashes::Hash;

    #[test]
    fn prevout_checks_reject_server_lies() {
        use serde_json::json;
        let txid = Txid::from_byte_array([7u8; 32]);
        let txid_str = txid.to_string();
        let address = "tb1qexample".to_string();
        let u = Utxo {
            txid,
            vout: 1,
            value: 50_000,
            address: address.clone(),
        };
        let mut tx = json!({
            "txid": txid_str,
            "status": {"confirmed": true},
            "vout": [
                {"value": 1, "scriptpubkey_address": "tb1qother"},
                {"value": 50_000, "scriptpubkey_address": address.clone()}
            ]
        });
        assert!(check_prevout(&tx, &u).is_ok());

        tx["vout"][1]["value"] = json!(49_999);
        assert!(check_prevout(&tx, &u).is_err());
        tx["vout"][1]["value"] = json!(50_000);

        tx["vout"][1]["scriptpubkey_address"] = json!("tb1qother");
        assert!(check_prevout(&tx, &u).is_err());
        tx["vout"][1]["scriptpubkey_address"] = json!(address);

        tx["status"]["confirmed"] = json!(false);
        assert!(check_prevout(&tx, &u).is_err());
        tx["status"]["confirmed"] = json!(true);

        tx["txid"] = json!(Txid::from_byte_array([8u8; 32]).to_string());
        assert!(check_prevout(&tx, &u).is_err());
    }

    #[test]
    fn mainnet_is_wallet_bound_not_a_global_setting() {
        assert_eq!(net_for(Network::Bitcoin).unwrap(), Net::Mainnet);
        assert!(!selectable_nets().contains(&Net::Mainnet));
    }

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

        // A WHATWG parser treats `\` as `/`; the guard must not be fooled.
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "https://evil.example\\@mempool.space/api"
        ));
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "https://mempool.space/api\n"
        ));

        // IPv6 authorities are rejected outright: a naive split on ':' would
        // make different IPv6 hosts compare equal and bypass the redirect guard.
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "https://[2001:db8::1]/api"
        ));
        assert!(!looks_like_url_for(Net::Mainnet, "https://[::1]/api"));
        assert!(!looks_like_url_for(Net::Mainnet, "https://2001:db8::1/api"));
        assert_eq!(
            url_parts("https://mempool.space:443/api").unwrap().0,
            "mempool.space"
        );
        assert!(resolve_redirect("https://[2001:db8::1]/api", "/x").is_err());

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
        // API credentials are not supported: userinfo is ambiguous and rejected.
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "https://user:pass@mempool.space/api"
        ));

        // Testnets need an explicit segment naming their own chain.
        assert!(!looks_like_url_for(Net::Testnet4, "https://"));
        assert!(!looks_like_url_for(Net::Testnet4, "https:///api"));
        assert!(!looks_like_url_for(
            Net::Testnet4,
            "https://example.com/api"
        ));
        assert!(looks_like_url_for(
            Net::Testnet4,
            "https://mempool.space/testnet4/api"
        ));
        assert!(!looks_like_url_for(
            Net::Testnet4,
            "https://mempool.space/testnet/api"
        ));
        assert!(!looks_like_url_for(
            Net::Testnet4,
            "https://mempool.space/signet/api"
        ));
        assert!(looks_like_url_for(
            Net::Testnet3,
            "https://mempool.space/testnet/api"
        ));
        assert!(looks_like_url_for(
            Net::Testnet3,
            "https://mempool.space/testnet3/api"
        ));
        assert!(!looks_like_url_for(
            Net::Testnet3,
            "https://mempool.space/testnet4/api"
        ));
        assert!(looks_like_url_for(
            Net::Signet,
            "https://example.com/signet/api?x=1"
        ));
        assert_eq!(
            authority_of("https://mempool.space:8443/api"),
            Some("mempool.space:8443")
        );
        assert!(authority_of("https://user:pass@mempool.space/api").is_none());
        assert!(same_origin(
            "https://mempool.space/a",
            "https://mempool.space/b"
        ));
        assert!(!same_origin(
            "https://mempool.space:8443/a",
            "https://mempool.space/b"
        ));
        assert!(!same_origin(
            "https://user:pass@mempool.space/a",
            "https://mempool.space/b"
        ));
        assert!(!looks_like_url_for(
            Net::Testnet4,
            "https://mempool.space/signet/api?next=/testnet4"
        ));
        assert!(!looks_like_url_for(
            Net::Mainnet,
            "https://mempool.space/api?chain=testnet"
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
        // Bidi overrides and zero-width characters must not spoof the display.
        assert_eq!(safe_text("a\u{202E}b\u{200B}c\u{FEFF}", 64), "abc");
        // The allowlist also drops every non-ASCII character, including
        // line separators, Unicode tags and variation selectors.
        assert_eq!(safe_text("ok\u{2028}\u{2029}\u{E0041}\u{FE0F}✓", 64), "ok");
    }

    #[test]
    fn history_values_and_heights_are_bounded() {
        let mut ours = HashSet::new();
        ours.insert("tb1qme".to_string());
        let tx = serde_json::json!({
            "vout": [{"value": 50_000, "scriptpubkey_address": "tb1qme"}],
            "vin": [{"prevout": {"value": 20_000, "scriptpubkey_address": "tb1qme"}}]
        });
        assert_eq!(net_for_tx(&tx, &ours).unwrap(), 30_000);

        // A value above the 21M BTC supply is rejected.
        let too_big = serde_json::json!({
            "vout": [{"value": network::MAX_MONEY_SATS + 1, "scriptpubkey_address": "tb1qme"}],
            "vin": []
        });
        assert!(net_for_tx(&too_big, &ours).is_err());

        // Missing or non-numeric values are not silently treated as zero.
        let missing = serde_json::json!({
            "vout": [{"scriptpubkey_address": "tb1qme"}],
            "vin": []
        });
        assert!(net_for_tx(&missing, &ours).is_err());

        // The running total cannot exceed the supply even with many outputs.
        let many: Vec<serde_json::Value> = (0..3)
            .map(|_| {
                serde_json::json!({
                    "value": network::MAX_MONEY_SATS,
                    "scriptpubkey_address": "tb1qme"
                })
            })
            .collect();
        let overflow = serde_json::json!({ "vout": many, "vin": [] });
        assert!(net_for_tx(&overflow, &ours).is_err());
    }

    #[test]
    fn config_ignores_stale_mainnet_and_keeps_testnets() {
        assert_eq!(config_net("Testnet4"), Some(Net::Testnet4));
        assert_eq!(config_net("  signet\n"), Some(Net::Signet));
        assert_eq!(config_net("Mainnet"), None);
        assert_eq!(config_net("garbage"), None);
    }

    #[test]
    fn proxy_settings_are_parsed_and_redacted() {
        assert_eq!(
            proxy_from_values(Some("socks5://127.0.0.1:9050"), None).as_deref(),
            Some("socks5://127.0.0.1:9050")
        );
        assert_eq!(
            proxy_from_values(Some("  "), Some("1")).as_deref(),
            Some("socks5://127.0.0.1:9050")
        );
        assert_eq!(
            proxy_from_values(Some("socks5://user:pass@host:1080"), Some("1")).as_deref(),
            Some("socks5://user:pass@host:1080")
        );
        assert_eq!(proxy_from_values(None, Some("0")), None);
        assert_eq!(
            proxy_desc_for("socks5://user:pass@host:1080"),
            "socks5://***@host:1080"
        );
        assert_eq!(proxy_desc_for("socks5://host:1080"), "socks5://host:1080");
    }

    #[test]
    fn redirects_resolve_without_leaving_https() {
        assert_eq!(
            resolve_redirect("https://mempool.space/api", "/testnet4/api").unwrap(),
            "https://mempool.space/testnet4/api"
        );
        assert_eq!(
            resolve_redirect(
                "https://mempool.space/testnet4/api",
                "https://mempool.space/testnet4/tx"
            )
            .unwrap(),
            "https://mempool.space/testnet4/tx"
        );
        assert_eq!(
            resolve_redirect("https://mempool.space/testnet4/api", "tx").unwrap(),
            "https://mempool.space/testnet4/tx"
        );
        assert_eq!(
            resolve_redirect("https://mempool.space:8443/testnet4/api", "tx").unwrap(),
            "https://mempool.space:8443/testnet4/tx"
        );
        assert!(resolve_redirect(
            "https://mempool.space/testnet4/api",
            "https://user:pass@mempool.space/testnet4/tx"
        )
        .is_err());
        assert!(resolve_redirect("http://mempool.space/api", "/api").is_err());
        assert!(resolve_redirect("https://mempool.space/api", "").is_err());
        assert!(resolve_redirect("https://mempool.space/api", "https://").is_err());
        assert!(resolve_redirect("https://mempool.space/api", "//").is_err());
        assert!(resolve_redirect(
            "https://mempool.space/api",
            "https://evil.example\\@mempool.space/api"
        )
        .is_err());
        assert!(resolve_redirect(
            "https://mempool.space/api",
            "//evil.example\\@mempool.space/api"
        )
        .is_err());
        assert!(resolve_redirect("https://mempool.space/api", "/api\n").is_err());
    }
}
