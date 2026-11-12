//! EVM support: derivation, RPC, balances and EIP-1559 transfers.
//!
//! This is a separate chain backend from the Bitcoin wallet. It shares only the
//! BIP39 seed and BIP32 derivation from the unlocked keystore: everything else
//! (address encoding, fee model, signing, broadcast) is EVM-specific, so nothing
//! here can build or sign a Bitcoin transaction, and nothing in the Bitcoin
//! modules can reach an EVM endpoint. The RPC layer verifies `eth_chainId`
//! against the selected chain before any request is signed or sent.

pub mod abi;
pub mod address;
pub mod chains;
pub mod price;
pub mod rlp;
pub mod rpc;
pub mod tx;
pub mod units;
