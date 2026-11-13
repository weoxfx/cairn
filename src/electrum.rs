//! Electrum protocol backend: JSON-RPC over a TCP/TLS socket.
//!
//! The Electrum protocol is a line-delimited JSON-RPC 2.0 conversation with a
//! server. Cairn only uses the read-only and broadcast methods it needs:
//! `server.features`, `blockchain.scripthash.*`, `blockchain.transaction.get`,
//! `blockchain.transaction.broadcast` and `blockchain.estimatefee`.
//!
//! Before anything else, the server's `genesis_hash` is compared with the genesis
//! block of the wallet's own chain. A server for another chain is refused, the
//! same way the HTTP backend refuses a cross-chain endpoint.
//!
//! Select it with `CAIRN_BACKEND=electrum` (or by setting `CAIRN_ELECTRUM` to a
//! `host:port`). TLS is used unless the address starts with `tcp://`, which is
//! only sensible for a local node.

use crate::error::Result;

use crate::esplora::{Net, Rates, Utxo, WalletState, MAX_INDEX};
use crate::network;
use crate::wallet::Watch;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Network, Script, Transaction, Txid};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

/// A single JSON-RPC reply larger than this is treated as hostile.
const MAX_LINE: u64 = 4 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SERVER_NAME: usize = 255;

/// The Bitcoin chain behind an API selection.
pub fn network_of(net: Net) -> Network {
    match net {
        Net::Mainnet => Network::Bitcoin,
        Net::Testnet4 => Network::Testnet4,
        Net::Testnet3 => Network::Testnet,
        Net::Signet => Network::Signet,
    }
}

/// Genesis block hashes, used to bind a server to one chain.
fn genesis_hash(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        Network::Testnet => "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        Network::Testnet4 => "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
        Network::Signet => "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
        _ => "",
    }
}

fn check_genesis(network: Network, reported: &str) -> Result<()> {
    let want = genesis_hash(network);
    if want.is_empty() {
        return Err("this chain has no known genesis hash".into());
    }
    if reported.trim().to_lowercase() != want {
        return Err(format!(
            "refusing server: it is on another chain (genesis {}…)",
            reported.chars().take(12).collect::<String>()
        )
        .into());
    }
    Ok(())
}

/// Whether the Electrum backend is selected.
pub fn selected() -> bool {
    std::env::var("CAIRN_BACKEND")
        .map(|b| b.eq_ignore_ascii_case("electrum"))
        .unwrap_or(false)
        || std::env::var("CAIRN_ELECTRUM")
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
}

/// Server for this chain: `CAIRN_ELECTRUM` wins, then a public default.
pub fn server_for(network: Network) -> Result<String> {
    if let Ok(s) = std::env::var("CAIRN_ELECTRUM") {
        let s = s.trim().to_string();
        if !s.is_empty() {
            return Ok(s);
        }
    }
    match network {
        Network::Bitcoin => Ok("electrum.blockstream.info:50002".into()),
        Network::Testnet => Ok("electrum.blockstream.info:60002".into()),
        _ => Err("no default Electrum server for this chain: set CAIRN_ELECTRUM=host:port".into()),
    }
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

pub struct Client {
    reader: BufReader<Stream>,
    id: u64,
    /// Chain tip reported when the connection was opened, bounded to a sane range.
    pub height: u64,
}

/// Split `host:port` (optionally `tcp://`), rejecting anything odd.
fn split_server(spec: &str) -> Result<(String, u16, bool)> {
    let (spec, tls) = match spec.strip_prefix("tcp://") {
        Some(rest) => (rest, false),
        None => (spec, true),
    };
    let (host, port) = spec
        .rsplit_once(':')
        .ok_or_else(|| "server must be host:port".to_string())?;
    if host.is_empty() || host.len() > MAX_SERVER_NAME {
        return Err("invalid server host".into());
    }
    if host.starts_with('[') || host.contains('/') || host.contains(char::is_whitespace) {
        return Err("invalid server host".into());
    }
    let port: u16 = port.parse().map_err(|_| "invalid server port")?;
    Ok((host.to_string(), port, tls))
}

impl Client {
    pub fn connect(spec: &str, network: Network) -> Result<Self> {
        let (host, port, tls) = split_server(spec)?;
        let addr = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {host}: {e}"))?
            .next()
            .ok_or_else(|| format!("{host} did not resolve"))?;
        let sock = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| format!("cannot connect to {host}:{port}: {e}"))?;
        let _ = sock.set_read_timeout(Some(IO_TIMEOUT));
        let _ = sock.set_write_timeout(Some(IO_TIMEOUT));
        let _ = sock.set_nodelay(true);

        let stream = if tls {
            // Ring is bundled with rustls here; installing the default provider is
            // idempotent and makes the choice explicit.
            let _ = rustls::crypto::ring::default_provider().install_default();
            let roots: rustls::RootCertStore =
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|_| "invalid server name".to_string())?;
            let conn = rustls::ClientConnection::new(Arc::new(config), name)
                .map_err(|e| format!("TLS setup failed: {e}"))?;
            Stream::Tls(Box::new(rustls::StreamOwned::new(conn, sock)))
        } else {
            Stream::Plain(sock)
        };

        let mut client = Client {
            reader: BufReader::new(stream),
            id: 0,
            height: 0,
        };

        // Bind the server to the wallet's chain before trusting anything it says.
        let features = client.request("server.features", json!([]))?;
        let reported = features["genesis_hash"]
            .as_str()
            .ok_or_else(|| "server did not report a genesis hash".to_string())?;
        check_genesis(network, reported)?;
        if let Ok(header) = client.request("blockchain.headers.subscribe", json!([])) {
            let h = header["height"].as_u64().unwrap_or(0);
            if h > 0 && h <= 10_000_000 {
                client.height = h;
            }
        }
        Ok(client)
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        self.id += 1;
        let id = self.id;
        let line = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|e| e.to_string())?;
        {
            let w = self.reader.get_mut();
            w.write_all(line.as_bytes())
                .and_then(|_| w.write_all(b"\n"))
                .and_then(|_| w.flush())
                .map_err(|e| format!("{method} failed: {e}"))?;
        }
        loop {
            let mut buf = String::new();
            let n = self
                .reader
                .by_ref()
                .take(MAX_LINE + 1)
                .read_line(&mut buf)
                .map_err(|e| format!("{method} failed: {e}"))?;
            if n == 0 {
                return Err(format!("{method}: server closed the connection").into());
            }
            if buf.len() as u64 > MAX_LINE {
                return Err(format!("{method}: server reply is too large").into());
            }
            let reply: Value = match serde_json::from_str(&buf) {
                Ok(v) => v,
                Err(_) => return Err(format!("{method}: server sent malformed JSON").into()),
            };
            // Notifications (no id) are ignored; only our own reply is returned.
            if reply["id"].as_u64() != Some(id) {
                continue;
            }
            if !reply["error"].is_null() {
                let msg = reply["error"]["message"].as_str().unwrap_or("server error");
                return Err(crate::error::Error::rejected(safe_text(msg)));
            }
            return Ok(reply["result"].clone());
        }
    }

    pub fn history(&mut self, scripthash: &str) -> Result<Vec<(String, i64)>> {
        let v = self.request("blockchain.scripthash.get_history", json!([scripthash]))?;
        parse_history(&v)
    }

    pub fn list_unspent(&mut self, scripthash: &str) -> Result<Vec<Unspent>> {
        let v = self.request("blockchain.scripthash.listunspent", json!([scripthash]))?;
        parse_unspent(&v)
    }

    pub fn estimate_fee(&mut self, blocks: u32) -> Result<f64> {
        let v = self.request("blockchain.estimatefee", json!([blocks]))?;
        let btc_per_kb = v.as_f64().unwrap_or(-1.0);
        Ok(btc_per_kb_to_sat_vb(btc_per_kb))
    }

    pub fn broadcast(&mut self, hex: &str) -> Result<String> {
        let v = self.request("blockchain.transaction.broadcast", json!([hex]))?;
        let txid = v
            .as_str()
            .ok_or_else(|| "server did not return a transaction id".to_string())?;
        Txid::from_str(txid)
            .map_err(|_| "server returned an invalid transaction id".to_string())?;
        Ok(txid.to_string())
    }

    pub fn raw_tx(&mut self, txid: &str) -> Result<Transaction> {
        let v = self.request("blockchain.transaction.get", json!([txid, false]))?;
        let hex = v
            .as_str()
            .ok_or_else(|| "server did not return a raw transaction".to_string())?;
        if hex.len() > 1_600_000 {
            return Err("server returned an oversized transaction".into());
        }
        let bytes = hex::decode(hex).map_err(|_| "server returned invalid hex".to_string())?;
        bitcoin::consensus::encode::deserialize(&bytes)
            .map_err(|_| crate::error::Error::network("server returned an unparseable transaction"))
    }
}

/// One unspent output, as reported by the server.
pub struct Unspent {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub height: i64,
}

/// Electrum's scripthash: SHA-256 of the scriptPubKey, byte-reversed, hex.
pub fn scripthash(script: &Script) -> String {
    let mut h = sha256::Hash::hash(script.as_bytes()).to_byte_array();
    h.reverse();
    hex::encode(h)
}

/// `blockchain.estimatefee` returns BTC per kB, or -1 when it has no estimate.
pub fn btc_per_kb_to_sat_vb(btc_per_kb: f64) -> f64 {
    if !(btc_per_kb.is_finite()) || btc_per_kb <= 0.0 {
        return 2.0;
    }
    let rate = btc_per_kb * 1e8 / 1000.0;
    rate.clamp(1.0, network::MAX_FEE_RATE)
}

fn safe_text(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(200)
        .collect()
}

fn parse_history(v: &Value) -> Result<Vec<(String, i64)>> {
    let items = v.as_array().ok_or("history is not a list")?;
    if items.len() > 100_000 {
        return Err("server returned an impossibly long history".into());
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let txid = item["tx_hash"]
            .as_str()
            .ok_or("history entry has no txid")?;
        Txid::from_str(txid).map_err(|_| "history entry has an invalid txid")?;
        let height = item["height"].as_i64().unwrap_or(0);
        out.push((txid.to_string(), height));
    }
    Ok(out)
}

fn parse_unspent(v: &Value) -> Result<Vec<Unspent>> {
    let items = v.as_array().ok_or("unspent list is not a list")?;
    if items.len() > 5000 {
        return Err("server returned too many unspent outputs".into());
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let txid = item["tx_hash"].as_str().ok_or("unspent has no txid")?;
        Txid::from_str(txid).map_err(|_| "unspent has an invalid txid")?;
        let vout = item["tx_pos"]
            .as_u64()
            .filter(|v| *v <= u32::MAX as u64)
            .ok_or("unspent has an invalid position")? as u32;
        let value = item["value"]
            .as_u64()
            .filter(|v| *v <= network::MAX_MONEY_SATS)
            .ok_or("unspent has an invalid value")?;
        let height = item["height"].as_i64().unwrap_or(0);
        out.push(Unspent {
            txid: txid.to_string(),
            vout,
            value,
            height,
        });
    }
    Ok(out)
}

// ---------------- wallet operations ----------------

fn open(net: Net) -> Result<Client> {
    let network = network_of(net);
    Client::connect(&server_for(network)?, network)
}

#[derive(Default)]
struct ChainScan {
    confirmed: i64,
    unconfirmed: i64,
    used: Vec<String>,
    next: u32,
}

fn scan_chain(
    client: &mut Client,
    watch: &Watch,
    chain: u32,
    gap_limit: u32,
    min_index: u32,
) -> Result<ChainScan> {
    let mut res = ChainScan::default();
    let (mut gap, mut idx) = (0u32, 0u32);
    while (gap < gap_limit || idx < min_index) && idx < MAX_INDEX {
        let addrs = watch.addresses(chain, idx, gap_limit)?;
        for (i, addr) in addrs.iter().enumerate() {
            let script = crate::send::script_of(addr).map_err(|e| format!("{addr}: {e}"))?;
            if !script.is_p2wpkh() && !script.is_p2tr() {
                return Err("wallet produced an unexpected script type".into());
            }
            let sh = scripthash(&script);
            let hist = client.history(&sh)?;
            if hist.is_empty() {
                gap += 1;
                continue;
            }
            gap = 0;
            let unspent = client.list_unspent(&sh)?;
            for u in unspent {
                if u.height > 0 {
                    res.confirmed = res
                        .confirmed
                        .saturating_add(u.value as i64)
                        .min(network::MAX_MONEY_SATS as i64);
                } else {
                    res.unconfirmed = res
                        .unconfirmed
                        .saturating_add(u.value as i64)
                        .min(network::MAX_MONEY_SATS as i64);
                }
            }
            res.used.push(addr.clone());
            res.next = idx + i as u32 + 1;
        }
        idx += gap_limit;
    }
    Ok(res)
}

/// Same shape and semantics as the HTTP backend's sync.
pub fn sync(watch: &Watch, gap_limit: u32, prev: Option<&WalletState>) -> Result<WalletState> {
    let (min_r, min_c) = prev
        .map(|p| (p.next_receive, p.next_change))
        .unwrap_or((0, 0));
    let mut client = open(crate::esplora::net_for(watch.network())?)?;
    let r = scan_chain(&mut client, watch, 0, gap_limit, min_r)?;
    let c = scan_chain(&mut client, watch, 1, gap_limit.min(5), min_c)?;
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
        unconfirmed: unconfirmed.max(-confirmed),
        used,
        next_receive: r.next,
        next_change: c.next,
    })
}

pub fn utxos_for(net: Net, addrs: &[String]) -> Result<Vec<Utxo>> {
    let mut client = open(net)?;
    let mut out = vec![];
    for addr in addrs {
        let script = crate::send::script_of(addr)?;
        for u in client.list_unspent(&scripthash(&script))? {
            out.push(Utxo {
                txid: Txid::from_str(&u.txid).map_err(|_| "invalid txid".to_string())?,
                vout: u.vout,
                value: u.value,
                address: addr.clone(),
            });
        }
    }
    Ok(out)
}

pub fn fee_rates(net: Net) -> Result<Rates> {
    let mut client = open(net)?;
    Ok(Rates {
        slow: client.estimate_fee(12)?,
        normal: client.estimate_fee(6)?,
        fast: client.estimate_fee(2)?,
    })
}

pub fn broadcast(net: Net, hex: &str) -> Result<String> {
    let mut client = open(net)?;
    client.broadcast(hex)
}

/// Re-fetch each spent coin's creating transaction and compare value and script,
/// exactly as the HTTP backend does.
pub fn verify_prevouts(net: Net, utxos: &[Utxo]) -> Result<()> {
    if utxos.is_empty() {
        return Ok(());
    }
    let mut client = open(net)?;
    let mut cache: std::collections::HashMap<String, Transaction> =
        std::collections::HashMap::new();
    for u in utxos {
        let key = u.txid.to_string();
        let tx = match cache.get(&key) {
            Some(t) => t.clone(),
            None => {
                if cache.len() > 200 {
                    return Err("refusing to verify too many coins at once".into());
                }
                let t = client.raw_tx(&key)?;
                if t.compute_txid().to_string() != key {
                    return Err("server returned a different transaction".into());
                }
                cache.insert(key.clone(), t.clone());
                t
            }
        };
        let out = tx
            .output
            .get(u.vout as usize)
            .ok_or("server transaction has no such output")?;
        if out.value.to_sat() != u.value {
            return Err(format!("coin {key}:{} value does not match", u.vout).into());
        }
        let spk = crate::send::script_of(&u.address)?;
        if out.script_pubkey != spk {
            return Err(format!("coin {key}:{} is not this address", u.vout).into());
        }
    }
    Ok(())
}

/// Fuzz entry point: a hostile Electrum server's reply, as JSON.
///
/// History and unspent lists are the largest server-controlled structures in the
/// protocol, and both are parsed field by field even when the types are wrong.
#[cfg(feature = "fuzzing")]
pub fn fuzz_reply(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let _ = parse_history(&value);
    let _ = parse_unspent(&value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripthash_matches_the_documented_example() {
        // Electrum protocol docs, "Script Hashes": the genesis-block P2PKH address
        // 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa has script 76a91462e9…88ac, whose
        // SHA-256 is 6191c3b5… and whose scripthash (reversed) is 8b01df4e…61.
        let addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse().unwrap();
        let script = addr.assume_checked().script_pubkey();
        assert_eq!(
            hex::encode(script.as_bytes()),
            "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac"
        );
        assert_eq!(
            hex::encode(sha256::Hash::hash(script.as_bytes()).to_byte_array()),
            "6191c3b590bfcfa0475e877c302da1e323497acf3b42c08d8fa28e364edf018b"
        );
        assert_eq!(
            scripthash(&script),
            "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161"
        );
    }

    #[test]
    fn fee_estimates_are_converted_and_bounded() {
        // 0.0001 BTC/kB is 10 sat/vB.
        assert!((btc_per_kb_to_sat_vb(0.0001) - 10.0).abs() < 1e-9);
        // No estimate, or nonsense, falls back to a safe default.
        assert_eq!(btc_per_kb_to_sat_vb(-1.0), 2.0);
        assert_eq!(btc_per_kb_to_sat_vb(f64::NAN), 2.0);
        assert_eq!(btc_per_kb_to_sat_vb(0.0), 2.0);
        assert_eq!(btc_per_kb_to_sat_vb(1e9), network::MAX_FEE_RATE);
        assert_eq!(btc_per_kb_to_sat_vb(1e-12), 1.0);
    }

    #[test]
    fn history_and_unspent_replies_are_validated() {
        let ok = json!([
            {"tx_hash": "1111111111111111111111111111111111111111111111111111111111111111", "height": 0},
            {"tx_hash": "2222222222222222222222222222222222222222222222222222222222222222", "height": 800000},
        ]);
        let h = parse_history(&ok).unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[1].1, 800000);

        // An invalid txid is refused rather than displayed.
        let bad = json!([{"tx_hash": "zz", "height": 1}]);
        assert!(parse_history(&bad).is_err());
        assert!(parse_history(&json!({"not": "a list"})).is_err());

        let coins = json!([
            {"tx_hash": "1111111111111111111111111111111111111111111111111111111111111111", "tx_pos": 0, "value": 5000, "height": 1},
            {"tx_hash": "2222222222222222222222222222222222222222222222222222222222222222", "tx_pos": 3, "value": 1, "height": 0},
        ]);
        let u = parse_unspent(&coins).unwrap();
        assert_eq!(u.len(), 2);
        assert_eq!(u[1].vout, 3);
        // Values beyond the money supply, and positions beyond u32, are refused.
        assert!(parse_unspent(&json!([{"tx_hash": "1111111111111111111111111111111111111111111111111111111111111111", "tx_pos": 0, "value": network::MAX_MONEY_SATS + 1, "height": 1}])).is_err());
        assert!(parse_unspent(&json!([{"tx_hash": "1111111111111111111111111111111111111111111111111111111111111111", "tx_pos": u32::MAX as u64 + 1, "value": 1, "height": 1}])).is_err());
    }

    #[test]
    fn a_server_on_another_chain_is_refused() {
        assert!(check_genesis(
            Network::Bitcoin,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        )
        .is_ok());
        // A testnet server must not serve a mainnet wallet.
        assert!(check_genesis(
            Network::Bitcoin,
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        )
        .is_err());
        assert!(check_genesis(Network::Bitcoin, "not-a-hash").is_err());
    }

    #[test]
    fn server_specs_are_parsed_strictly() {
        assert_eq!(
            split_server("electrum.example.org:50002").unwrap(),
            ("electrum.example.org".to_string(), 50002, true)
        );
        assert_eq!(
            split_server("tcp://127.0.0.1:50001").unwrap(),
            ("127.0.0.1".to_string(), 50001, false)
        );
        assert!(split_server("no-port").is_err());
        assert!(split_server("host:notaport").is_err());
        assert!(split_server(":50002").is_err());
        assert!(split_server("http://host:50002").is_err());
    }

    /// Real server, opt-in: `cargo test --bin cairn electrum::tests::live -- --ignored`
    #[test]
    #[ignore]
    fn live_server_answers_and_matches_the_chain() {
        let mut client =
            Client::connect("electrum.blockstream.info:50002", Network::Bitcoin).unwrap();
        assert!(client.height > 0);
        let fee = client.estimate_fee(6).unwrap();
        assert!(fee >= 1.0);
    }
}
