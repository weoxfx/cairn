//! One place that decides which network backend the wallet talks to.
//!
//! Everything above this layer asks for a balance, coins, fee estimates or a
//! broadcast without caring whether that is an Esplora HTTP server or an Electrum
//! socket. Both backends validate the chain they are talking to: Esplora through
//! its endpoint guard, Electrum through the server's genesis hash.
//!
//! The default stays Esplora. Set `CAIRN_BACKEND=electrum` (or `CAIRN_ELECTRUM`
//! to a `host:port`) to use Electrum instead.

use crate::error::Result;

use crate::electrum;
use crate::esplora::{self, Net, Rates, Utxo, WalletState};
use crate::wallet::Watch;

pub fn uses_electrum() -> bool {
    electrum::selected()
}

pub fn backend_name() -> &'static str {
    if uses_electrum() {
        "electrum"
    } else {
        "esplora"
    }
}

pub fn sync(watch: &Watch, gap: u32, prev: Option<&WalletState>) -> Result<WalletState> {
    if uses_electrum() {
        electrum::sync(watch, gap, prev)
    } else {
        esplora::sync(watch, gap, prev)
    }
}

pub fn utxos_for(net: Net, addrs: &[String]) -> Result<Vec<Utxo>> {
    if uses_electrum() {
        electrum::utxos_for(net, addrs)
    } else {
        esplora::utxos_for(net, addrs)
    }
}

pub fn fee_rates(net: Net) -> Result<Rates> {
    if uses_electrum() {
        electrum::fee_rates(net)
    } else {
        esplora::fee_rates(net)
    }
}

pub fn broadcast(net: Net, hex: &str) -> Result<String> {
    if uses_electrum() {
        electrum::broadcast(net, hex)
    } else {
        esplora::broadcast(net, hex)
    }
}

pub fn verify_prevouts(net: Net, utxos: &[Utxo]) -> Result<()> {
    if uses_electrum() {
        electrum::verify_prevouts(net, utxos)
    } else {
        esplora::verify_prevouts(net, utxos)
    }
}
