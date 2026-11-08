//! Network labels, units and hard limits shared by the wallet modules.
//!
//! Cairn is testnet-first: testnet is the default network. Mainnet is available
//! from the network menu, but it is experimental and has not had an independent
//! audit. Selecting it is confirmed in the UI; there is no separate marker file
//! or environment token.

use bitcoin::Network;

/// Hard ceiling for fee rates, applied to server estimates and manual entry.
pub const MAX_FEE_RATE: f64 = 1000.0;

/// Hard consensus cap: 21 million BTC in satoshis. Reject anything above it,
/// including values supplied by servers or PSBT files.
pub const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;

pub fn label(network: Network) -> &'static str {
    if network == Network::Bitcoin {
        "mainnet"
    } else {
        "testnet"
    }
}

pub fn unit(network: Network) -> &'static str {
    if network == Network::Bitcoin {
        "BTC"
    } else {
        "tBTC"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_units() {
        assert_eq!(label(Network::Bitcoin), "mainnet");
        assert_eq!(label(Network::Testnet), "testnet");
        assert_eq!(unit(Network::Bitcoin), "BTC");
        assert_eq!(unit(Network::Testnet), "tBTC");
    }
}
