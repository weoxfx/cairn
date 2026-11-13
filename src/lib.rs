//! Cairn: a self-custody Bitcoin and EVM wallet for the command line.
//!
//! The whole wallet is a library. `main.rs` only calls [`cli::main`], and the
//! fuzz targets and integration tests link these same modules, so there is one
//! copy of every parser, one set of process globals (network selection, HTTP
//! agents) and no second, untested build of the same code.

pub mod bump;
pub mod chain;
pub mod cli;
pub mod electrum;
pub mod error;
pub mod esplora;
pub mod evm;
pub mod evm_cli;
pub mod hardening;
pub mod http;
pub mod keystore;
pub mod labels;
pub mod multisig;
pub mod network;
pub mod offline;
pub mod passphrase;
pub mod psbt_guard;
pub mod qr;
pub mod security;
pub mod send;
pub mod ui;
pub mod wallet;
