//! JSON-RPC client for EVM chains.
//!
//! Mirrors the Bitcoin API layer's posture: HTTPS only, no redirects, bounded
//! response bodies, failover, optional Tor/SOCKS, and untrusted replies. In
//! addition every endpoint is probed with `eth_chainId` before it is trusted,
//! so a node that answers with the wrong chain can never be used to build a
//! transaction for this wallet.

use crate::evm::chains::Chain;
use primitive_types::U256;
use serde_json::{json, Value};
use std::io::Read;
use std::time::Duration;

const MAX_BODY: u64 = 4_000_000;
const TIMEOUT: Duration = Duration::from_secs(20);

pub struct Rpc {
    chain: &'static Chain,
    endpoints: Vec<String>,
    agent: ureq::Agent,
}

impl Rpc {
    /// Connect and verify. Fails closed: if no endpoint reports the expected
    /// chain id, no transaction can be built or broadcast.
    pub fn connect(chain: &'static Chain) -> Result<Self, String> {
        let endpoints = endpoints_for(chain);
        if endpoints.is_empty() {
            return Err(format!("no RPC endpoints configured for {}", chain.name));
        }
        let rpc = Rpc {
            chain,
            endpoints,
            agent: agent()?,
        };
        rpc.verified()
    }

    fn verified(mut self) -> Result<Self, String> {
        let mut good = Vec::new();
        let mut problems = Vec::new();
        for ep in &self.endpoints {
            match chain_id_at(&self.agent, ep) {
                Ok(id) if id == self.chain.chain_id => good.push(ep.clone()),
                Ok(id) => problems.push(format!(
                    "{} reports chain id {id}, not {}",
                    host_of(ep),
                    self.chain.chain_id
                )),
                Err(e) => problems.push(format!("{}: {e}", host_of(ep))),
            }
        }
        if good.is_empty() {
            return Err(format!(
                "no usable {} RPC endpoint ({})",
                self.chain.name,
                problems.join("; ")
            ));
        }
        self.endpoints = good;
        Ok(self)
    }

    #[cfg(test)]
    pub fn chain(&self) -> &'static Chain {
        self.chain
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        })
        .to_string();
        let mut last = format!("no {} RPC endpoint answered", self.chain.name);
        for ep in &self.endpoints {
            match post_json(&self.agent, ep, &body) {
                Ok(v) => {
                    if let Some(err) = v.get("error") {
                        let msg = err
                            .get("message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("RPC returned an error");
                        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                        return Err(safe_text(&format!("{msg} (code {code})"), 300));
                    }
                    return v
                        .get("result")
                        .cloned()
                        .ok_or_else(|| "RPC response has no result".to_string());
                }
                // Transport failures fail over; a JSON-RPC error does not.
                Err(e) => last = format!("{}: {e}", host_of(ep)),
            }
        }
        Err(last)
    }

    #[cfg(test)]
    pub fn block_number(&self) -> Result<u64, String> {
        let v = self.call("eth_blockNumber", json!([]))?;
        let n = quantity(&v)?;
        if n > U256::from(u64::MAX) {
            return Err("node reported an impossible block number".into());
        }
        Ok(n.low_u64())
    }

    pub fn balance(&self, address: &[u8; 20]) -> Result<U256, String> {
        let v = self.call("eth_getBalance", json!([hex_address(address), "latest"]))?;
        quantity(&v)
    }

    pub fn nonce(&self, address: &[u8; 20]) -> Result<u64, String> {
        let v = self.call(
            "eth_getTransactionCount",
            json!([hex_address(address), "pending"]),
        )?;
        let n = quantity(&v)?;
        if n > U256::from(u64::MAX) {
            return Err("node reported an impossible nonce".into());
        }
        Ok(n.low_u64())
    }

    pub fn base_fee(&self) -> Result<Option<U256>, String> {
        let v = self.call("eth_getBlockByNumber", json!(["latest", false]))?;
        match v.get("baseFeePerGas") {
            Some(x) if !x.is_null() => Ok(Some(quantity(x)?)),
            _ => Ok(None),
        }
    }

    pub fn gas_price(&self) -> Result<U256, String> {
        let v = self.call("eth_gasPrice", json!([]))?;
        quantity(&v)
    }

    /// `eth_maxPriorityFeePerGas` is not implemented everywhere; `None` means
    /// "the caller should fall back".
    pub fn max_priority_fee(&self) -> Option<U256> {
        let v = self.call("eth_maxPriorityFeePerGas", json!([])).ok()?;
        quantity(&v).ok()
    }

    pub fn estimate_gas(
        &self,
        from: &[u8; 20],
        to: &[u8; 20],
        value: U256,
        data: &[u8],
    ) -> Result<U256, String> {
        let mut obj = json!({"from": hex_address(from), "to": hex_address(to)});
        if !value.is_zero() {
            obj["value"] = json!(to_quantity(value));
        }
        if !data.is_empty() {
            obj["data"] = json!(format!("0x{}", hex::encode(data)));
        }
        let v = self.call("eth_estimateGas", json!([obj]))?;
        quantity(&v)
    }

    pub fn eth_call(&self, to: &[u8; 20], data: &[u8]) -> Result<Vec<u8>, String> {
        let v = self.call(
            "eth_call",
            json!([{"to": hex_address(to), "data": format!("0x{}", hex::encode(data))}, "latest"]),
        )?;
        let s = v.as_str().ok_or("eth_call did not return hex")?;
        let body = s.strip_prefix("0x").unwrap_or(s);
        if body.len() > 2 * 4096 {
            return Err("contract returned too much data".into());
        }
        hex::decode(body).map_err(|_| "contract returned invalid hex".to_string())
    }

    pub fn send_raw(&self, raw: &[u8]) -> Result<String, String> {
        let v = self.call(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(raw))]),
        )?;
        let hash = v.as_str().ok_or("node did not return a transaction hash")?;
        let hash = hash.trim();
        if hash.len() != 66 || !hash.starts_with("0x") {
            return Err("node returned a malformed transaction hash".into());
        }
        Ok(hash.to_ascii_lowercase())
    }
}

fn endpoints_for(chain: &Chain) -> Vec<String> {
    if let Ok(v) = std::env::var("CAIRN_EVM_RPC") {
        let list: Vec<String> = v
            .split(',')
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.is_empty() {
            return list;
        }
    }
    chain.rpc.iter().map(|s| s.to_string()).collect()
}

fn agent() -> Result<ureq::Agent, String> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(TIMEOUT)
        .timeout(TIMEOUT)
        .user_agent(concat!(
            "cairn/",
            env!("CARGO_PKG_VERSION"),
            " (evm wallet)"
        ))
        .https_only(true)
        .redirects(0)
        .max_idle_connections(0);
    if let Some(p) = proxy_setting() {
        let proxy = ureq::Proxy::new(&p)
            .map_err(|e| format!("invalid CAIRN_PROXY/CAIRN_TOR setting: {e}"))?;
        builder = builder.proxy(proxy);
    }
    Ok(builder.build())
}

fn proxy_setting() -> Option<String> {
    if let Ok(v) = std::env::var("CAIRN_PROXY") {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    match std::env::var("CAIRN_TOR").ok().as_deref() {
        Some("1") | Some("true") | Some("yes") => Some("socks5://127.0.0.1:9050".into()),
        _ => None,
    }
}

fn post_json(agent: &ureq::Agent, url: &str, body: &str) -> Result<Value, String> {
    let resp = agent
        .post(url)
        .set("content-type", "application/json")
        .send_string(body);
    match resp {
        Ok(r) => {
            let text = read_body(r)?;
            serde_json::from_str(&text).map_err(|_| "RPC returned invalid JSON".to_string())
        }
        Err(ureq::Error::Status(code, _)) => Err(format!("HTTP {code}")),
        Err(e) => Err(format!("network error: {e}")),
    }
}

fn chain_id_at(agent: &ureq::Agent, url: &str) -> Result<u64, String> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}).to_string();
    let v = post_json(agent, url, &body)?;
    let result = v.get("result").ok_or("no result")?;
    let id = quantity(result)?;
    if id > U256::from(u64::MAX) {
        return Err("impossible chain id".into());
    }
    Ok(id.low_u64())
}

fn read_body(resp: ureq::Response) -> Result<String, String> {
    let mut body = String::new();
    resp.into_reader()
        .take(MAX_BODY + 1)
        .read_to_string(&mut body)
        .map_err(|e| format!("read error: {e}"))?;
    if body.len() as u64 > MAX_BODY {
        return Err("RPC response exceeds the size limit".into());
    }
    Ok(body)
}

/// Allowlist of printable ASCII so node-supplied text cannot carry terminal
/// escapes or bidi controls into the UI.
fn safe_text(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(max)
        .collect()
}

pub fn host_of(url: &str) -> &str {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split(['/', '?'])
        .next()
        .unwrap_or(url)
}

pub fn hex_address(a: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(a))
}

/// Parse a JSON-RPC quantity (`"0x1"`) or a plain JSON number.
pub fn quantity(v: &Value) -> Result<U256, String> {
    if let Some(n) = v.as_u64() {
        return Ok(U256::from(n));
    }
    let s = v.as_str().ok_or("expected a hex quantity")?;
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or("quantity is not hex-prefixed")?;
    if body.is_empty() || body.len() > 64 {
        return Err("quantity has an impossible width".into());
    }
    let padded = if body.len() % 2 == 1 {
        format!("0{body}")
    } else {
        body.to_string()
    };
    let bytes = hex::decode(&padded).map_err(|_| "quantity is not hex".to_string())?;
    Ok(U256::from_big_endian(&bytes))
}

pub fn to_quantity(v: U256) -> String {
    if v.is_zero() {
        return "0x0".into();
    }
    let mut buf = [0u8; 32];
    v.to_big_endian(&mut buf);
    let start = buf.iter().position(|b| *b != 0).unwrap_or(buf.len());
    let encoded = hex::encode(&buf[start..]);
    // Quantities are minimal: no leading zero nibble, no even-width padding.
    format!("0x{}", encoded.trim_start_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantities_round_trip() {
        for n in [0u64, 1, 21000, 1_000_000_000u64] {
            let v = U256::from(n);
            assert_eq!(quantity(&json!(to_quantity(v))).unwrap(), v);
        }
        assert_eq!(to_quantity(U256::zero()), "0x0");
        assert_eq!(to_quantity(U256::from(1u8)), "0x1");
        assert_eq!(to_quantity(U256::from(21000u32)), "0x5208");
        assert!(quantity(&json!("0x")).is_err());
        assert!(quantity(&json!("nope")).is_err());
        assert!(quantity(&json!("0x".to_string() + &"f".repeat(65))).is_err());
    }

    #[test]
    fn text_and_hosts_are_sanitised() {
        assert_eq!(safe_text("ok\x1b[2Jhere", 100), "ok[2Jhere");
        assert_eq!(host_of("https://eth.llamarpc.com/rpc"), "eth.llamarpc.com");
    }

    /// Touches the network; run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "requires network access"]
    fn live_rpc_reports_the_expected_chain() {
        let chain = crate::evm::chains::by_key("ethereum").unwrap();
        let rpc = Rpc::connect(chain).unwrap();
        assert_eq!(rpc.chain().chain_id, 1);
        assert!(rpc.block_number().unwrap() > 20_000_000);
        // The burn address accumulates fees and is never empty.
        assert!(rpc.balance(&[0u8; 20]).unwrap() > U256::zero());
    }

    #[test]
    fn custom_endpoints_are_tls_only() {
        std::env::set_var("CAIRN_EVM_RPC", "http://127.0.0.1:8545");
        let list = endpoints_for(&crate::evm::chains::CHAINS[0]);
        assert_eq!(list, vec!["http://127.0.0.1:8545".to_string()]);
        std::env::remove_var("CAIRN_EVM_RPC");
    }
}
