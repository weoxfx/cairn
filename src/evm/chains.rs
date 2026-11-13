//! Supported EVM chains and the persisted default.
//!
//! Chain IDs are the authority: every RPC endpoint is probed with `eth_chainId`
//! and refused if it answers with a different chain, so a bad or malicious
//! endpoint cannot make this wallet build a transfer for another network.

use crate::error::Result;

use crate::hardening;
use std::io::Read;
use std::path::PathBuf;

pub struct Chain {
    pub key: &'static str,
    pub name: &'static str,
    pub chain_id: u64,
    pub symbol: &'static str,
    pub decimals: u32,
    pub rpc: &'static [&'static str],
    pub explorer: &'static str,
    pub testnet: bool,
    /// CoinGecko id for the USD estimate. Empty means "no price feed".
    pub price_id: &'static str,
}

pub const CHAINS: &[Chain] = &[
    Chain {
        key: "ethereum",
        name: "Ethereum",
        chain_id: 1,
        symbol: "ETH",
        decimals: 18,
        rpc: &[
            "https://ethereum-rpc.publicnode.com",
            "https://eth.llamarpc.com",
            "https://cloudflare-eth.com",
        ],
        explorer: "https://etherscan.io",
        testnet: false,
        price_id: "ethereum",
    },
    Chain {
        key: "base",
        name: "Base",
        chain_id: 8453,
        symbol: "ETH",
        decimals: 18,
        rpc: &[
            "https://mainnet.base.org",
            "https://base-rpc.publicnode.com",
        ],
        explorer: "https://basescan.org",
        testnet: false,
        price_id: "ethereum",
    },
    Chain {
        key: "arbitrum",
        name: "Arbitrum One",
        chain_id: 42161,
        symbol: "ETH",
        decimals: 18,
        rpc: &[
            "https://arb1.arbitrum.io/rpc",
            "https://arbitrum-one-rpc.publicnode.com",
        ],
        explorer: "https://arbiscan.io",
        testnet: false,
        price_id: "ethereum",
    },
    Chain {
        key: "optimism",
        name: "OP Mainnet",
        chain_id: 10,
        symbol: "ETH",
        decimals: 18,
        rpc: &[
            "https://mainnet.optimism.io",
            "https://optimism-rpc.publicnode.com",
        ],
        explorer: "https://optimistic.etherscan.io",
        testnet: false,
        price_id: "ethereum",
    },
    Chain {
        key: "polygon",
        name: "Polygon",
        chain_id: 137,
        symbol: "POL",
        decimals: 18,
        rpc: &[
            "https://polygon-rpc.com",
            "https://polygon-bor-rpc.publicnode.com",
        ],
        explorer: "https://polygonscan.com",
        testnet: false,
        price_id: "polygon-ecosystem-token",
    },
    Chain {
        key: "sepolia",
        name: "Sepolia",
        chain_id: 11155111,
        symbol: "ETH",
        decimals: 18,
        rpc: &[
            "https://ethereum-sepolia-rpc.publicnode.com",
            "https://rpc.sepolia.org",
        ],
        explorer: "https://sepolia.etherscan.io",
        testnet: true,
        price_id: "",
    },
];

impl Chain {
    /// CoinGecko asset-platform id, used only for ERC-20 price lookups on the
    /// mainnet chains. Test networks never have a fiat value.
    pub fn price_platform(&self) -> &'static str {
        if self.testnet {
            return "";
        }
        match self.key {
            "ethereum" => "ethereum",
            "base" => "base",
            "arbitrum" => "arbitrum-one",
            "optimism" => "optimistic-ethereum",
            "polygon" => "polygon-pos",
            _ => "",
        }
    }
}

pub fn by_key(key: &str) -> Option<&'static Chain> {
    let k = key.trim();
    CHAINS.iter().find(|c| c.key.eq_ignore_ascii_case(k))
}

/// Accepts a chain key or a decimal chain id.
pub fn by_key_or_id(s: &str) -> Option<&'static Chain> {
    let s = s.trim();
    if let Some(c) = by_key(s) {
        return Some(c);
    }
    let id: u64 = s.parse().ok()?;
    CHAINS.iter().find(|c| c.chain_id == id)
}

pub fn for_id(id: u64) -> Option<&'static Chain> {
    CHAINS.iter().find(|c| c.chain_id == id)
}

fn config_path() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".cairn").join("evm-chain"))
}

/// `CAIRN_EVM_CHAIN` wins, then the saved setting, then Ethereum.
pub fn default_chain() -> &'static Chain {
    if let Ok(v) = std::env::var("CAIRN_EVM_CHAIN") {
        if let Some(c) = by_key_or_id(&v) {
            return c;
        }
    }
    if let Some(p) = config_path() {
        if let Ok(f) = crate::hardening::open_read(&p) {
            let small = f
                .metadata()
                .map(|m| m.is_file() && m.len() <= 128)
                .unwrap_or(false);
            if small {
                let mut s = String::new();
                if f.take(129).read_to_string(&mut s).is_ok() {
                    if let Some(c) = by_key(s.trim()) {
                        return c;
                    }
                }
            }
        }
    }
    &CHAINS[0]
}

pub fn set_default(chain: &Chain) -> Result<()> {
    let p = config_path().ok_or("HOME not set")?;
    if let Some(dir) = p.parent() {
        hardening::ensure_private_dir(dir)?;
    }
    hardening::write_private(&p, chain.key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_consistent() {
        let mut ids: Vec<u64> = CHAINS.iter().map(|c| c.chain_id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), CHAINS.len(), "duplicate chain id in registry");
        for c in CHAINS {
            assert!(!c.rpc.is_empty(), "{} has no RPC endpoint", c.key);
            for r in c.rpc {
                assert!(
                    r.starts_with("https://"),
                    "{} has a non-TLS endpoint",
                    c.key
                );
            }
            assert!(c.explorer.starts_with("https://"));
        }
    }

    #[test]
    fn price_platforms_are_set_for_value_bearing_chains_only() {
        for c in CHAINS {
            if c.testnet {
                assert!(c.price_platform().is_empty(), "{} is a testnet", c.key);
                assert!(c.price_id.is_empty(), "{} is a testnet", c.key);
            } else {
                assert!(!c.price_platform().is_empty(), "{} has no platform", c.key);
                assert!(!c.price_id.is_empty(), "{} has no price id", c.key);
            }
        }
        assert!(by_key("UNKNOWN").is_none());
    }

    #[test]
    fn lookup_by_key_and_id() {
        assert_eq!(by_key("BASE").unwrap().chain_id, 8453);
        assert_eq!(by_key_or_id("8453").unwrap().key, "base");
        assert_eq!(for_id(1).unwrap().key, "ethereum");
        assert!(by_key("no-such-chain").is_none());
        assert!(by_key_or_id("0").is_none());
    }
}
