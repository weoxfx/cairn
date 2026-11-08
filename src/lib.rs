//! Library surface for external harnesses (fuzzing and integration tests).
//!
//! The shipped binary declares its own module tree in `main.rs`; this target
//! exists so fuzz targets link the real parsers instead of a copy. Unit tests
//! stay in the binary target (`[lib] test = false`).

pub mod esplora;
pub mod hardening;
pub mod keystore;
pub mod network;
pub mod psbt_guard;
pub mod qr;
pub mod ui;
pub mod wallet;
