//! Display-only USD estimates for the native coin and for ERC-20 tokens.
//!
//! This is the only part of the EVM path that talks to a non-RPC host. It is
//! cosmetic: nothing here can change an amount, a fee, an address or a
//! signature. Failures return `None` and the UI simply omits the fiat value.
//! Set `CAIRN_NO_PRICE=1` to disable every request, or `CAIRN_PRICE_API` to
//! point at another endpoint with the same shape.

use crate::evm::chains::Chain;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const DEFAULT_API: &str = "https://api.coingecko.com/api/v3/simple/price";
const DEFAULT_TOKEN_API: &str = "https://api.coingecko.com/api/v3/simple/token_price";
const CACHE_TTL: Duration = Duration::from_secs(120);
const MAX_BODY: u64 = 64 * 1024;

fn cache() -> &'static Mutex<HashMap<String, (Instant, f64)>> {
    static C: OnceLock<Mutex<HashMap<String, (Instant, f64)>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached(key: &str) -> Option<f64> {
    let m = cache().lock().ok()?;
    let (at, price) = m.get(key)?;
    if at.elapsed() < CACHE_TTL {
        Some(*price)
    } else {
        None
    }
}

fn remember(key: &str, price: f64) {
    if let Ok(mut m) = cache().lock() {
        m.insert(key.to_string(), (Instant::now(), price));
    }
}

pub fn enabled() -> bool {
    !matches!(
        std::env::var("CAIRN_NO_PRICE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// USD per whole native coin, or `None` when there is no feed, it is disabled,
/// or the answer looks implausible.
pub fn usd(chain: &Chain) -> Option<f64> {
    if !enabled() || chain.price_id.is_empty() {
        return None;
    }
    if let Some(p) = cached(chain.price_id) {
        return Some(p);
    }
    let sep = if api_base().contains('?') { '&' } else { '?' };
    let url = format!(
        "{}{sep}ids={}&vs_currencies=usd",
        api_base(),
        chain.price_id
    );
    let v = get_json(&url)?;
    let p = v.get(chain.price_id)?.get("usd")?.as_f64()?;
    plausible(p).then(|| {
        remember(chain.price_id, p);
        p
    })
}

/// USD per whole token, looked up by contract address. Tokens the price feed
/// does not know simply have no fiat value.
pub fn token_usd(chain: &Chain, contract: &str) -> Option<f64> {
    let platform = chain.price_platform();
    if !enabled() || platform.is_empty() {
        return None;
    }
    let contract = contract.trim().to_ascii_lowercase();
    let key = format!("{platform}:{contract}");
    if let Some(p) = cached(&key) {
        return Some(p);
    }
    let v = get_json(&token_url(platform, &contract))?;
    let obj = v.as_object()?;
    for (addr, entry) in obj {
        if addr.eq_ignore_ascii_case(&contract) {
            let p = entry.get("usd")?.as_f64()?;
            if plausible(p) {
                remember(&key, p);
                return Some(p);
            }
        }
    }
    None
}

fn plausible(p: f64) -> bool {
    p.is_finite() && p > 0.0 && p < 10_000_000.0
}

fn api_base() -> String {
    std::env::var("CAIRN_PRICE_API")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_API.to_string())
}

fn token_url(platform: &str, contract: &str) -> String {
    let base = std::env::var("CAIRN_PRICE_API")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|b| b.replace("/simple/price", "/simple/token_price"))
        .unwrap_or_else(|| DEFAULT_TOKEN_API.to_string());
    format!("{base}/{platform}?contract_addresses={contract}&vs_currencies=usd")
}

fn get_json(url: &str) -> Option<serde_json::Value> {
    // A configured but unparseable proxy makes this fail closed: no price is
    // better than a request that leaks the user's address around the proxy.
    let agent = crate::http::agent(
        "evm price",
        Duration::from_secs(4),
        Duration::from_secs(6),
        Duration::from_secs(6),
    )
    .ok()?;
    let resp = agent.get(url).call().ok()?;
    let body = crate::http::read_body(resp, MAX_BODY, "price response").ok()?;
    serde_json::from_str(&body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_out_is_honoured() {
        std::env::set_var("CAIRN_NO_PRICE", "1");
        assert!(!enabled());
        std::env::remove_var("CAIRN_NO_PRICE");
        assert!(enabled());
    }

    #[test]
    fn token_urls_are_well_formed() {
        std::env::remove_var("CAIRN_PRICE_API");
        let u = token_url("base", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913");
        assert!(u.starts_with("https://api.coingecko.com/api/v3/simple/token_price/base?"));
        assert!(u.contains("vs_currencies=usd"));
        assert!(!u.contains(' '));

        // A custom native endpoint is reused for tokens.
        std::env::set_var("CAIRN_PRICE_API", "https://example.test/simple/price");
        assert!(token_url("polygon-pos", "0xabcd")
            .starts_with("https://example.test/simple/token_price/polygon-pos?"));
        std::env::remove_var("CAIRN_PRICE_API");
    }

    /// The price lookup used to ignore `CAIRN_TOR` and drop an unparseable
    /// `CAIRN_PROXY`, sending the request out direct. It must now fail closed:
    /// no price is better than one that leaks the user's address around the proxy.
    #[test]
    fn an_unusable_proxy_disables_pricing_instead_of_going_direct() {
        std::env::remove_var("CAIRN_NO_PRICE");
        std::env::remove_var("CAIRN_TOR");
        std::env::set_var("CAIRN_PROXY", "socks5h://127.0.0.1:9050");
        let url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd";
        assert!(get_json(url).is_none());
        std::env::remove_var("CAIRN_PROXY");
    }

    #[test]
    fn implausible_prices_are_rejected() {
        assert!(plausible(1.0));
        assert!(!plausible(0.0));
        assert!(!plausible(-1.0));
        assert!(!plausible(f64::NAN));
        assert!(!plausible(1e12));
    }

    #[test]
    fn testnets_have_no_fiat_value() {
        for c in crate::evm::chains::CHAINS {
            if c.testnet {
                assert!(token_usd(c, "0x0000000000000000000000000000000000000000").is_none());
            }
        }
    }
}
