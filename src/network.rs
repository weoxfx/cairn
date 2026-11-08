//! Network selection and the mainnet opt-in gate.
//!
//! Cairn is testnet-only by default. Mainnet stays disabled until someone
//! deliberately runs `cairn --enable-mainnet` (typed confirmation) or sets
//! `CAIRN_ENABLE_MAINNET=I_UNDERSTAND_UNAUDITED_MAINNET` for a single session.
//! This is a guard against accidents, not a replacement for an audit.

use bitcoin::Network;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

pub const MAINNET_ENV: &str = "CAIRN_ENABLE_MAINNET";
pub const MAINNET_TOKEN: &str = "I_UNDERSTAND_UNAUDITED_MAINNET";
const MARKER: &str = "mainnet-enabled";

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

pub fn marker_path() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".cairn").join(MARKER))
}

/// True when the user has explicitly opted in, either persistently or for this
/// process. Environment opt-in is intentionally an exact, hard-to-typo token.
pub fn enabled() -> bool {
    if std::env::var(MAINNET_ENV)
        .map(|v| v == MAINNET_TOKEN)
        .unwrap_or(false)
    {
        return true;
    }
    marker_path().map(|p| p.is_file()).unwrap_or(false)
}

pub fn require_enabled() -> Result<(), String> {
    if enabled() {
        Ok(())
    } else {
        Err(format!(
            "Mainnet is disabled. It is unaudited and can lose real funds.\n\
             To enable it deliberately, run: cairn --enable-mainnet\n\
             (or set {MAINNET_ENV}={MAINNET_TOKEN} for this session only)"
        ))
    }
}

/// Fail closed for any wallet whose network is mainnet.
pub fn require_supported(network: Network) -> Result<(), String> {
    if network == Network::Bitcoin {
        require_enabled()?;
    }
    Ok(())
}

/// Persist the opt-in marker with private permissions.
pub fn enable() -> Result<PathBuf, String> {
    let path = marker_path().ok_or("HOME not set")?;
    let dir = path.parent().ok_or("invalid mainnet marker path")?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| e.to_string())?;
    f.write_all(
        b"Mainnet was enabled by an explicit opt-in.\n\
          Cairn is unaudited. Real funds can be lost.\n\
          Disable with: cairn --disable-mainnet\n",
    )
    .map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    Ok(path)
}

pub fn disable() -> Result<bool, String> {
    let path = marker_path().ok_or("HOME not set")?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cairn-net-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("HOME", &dir);
        dir
    }

    #[test]
    fn labels_units_and_gate() {
        assert_eq!(label(Network::Bitcoin), "mainnet");
        assert_eq!(label(Network::Testnet), "testnet");
        assert_eq!(unit(Network::Bitcoin), "BTC");
        assert_eq!(unit(Network::Testnet), "tBTC");
        // The test process must not accidentally depend on a developer marker.
        std::env::remove_var(MAINNET_ENV);
        assert_eq!(require_supported(Network::Testnet), Ok(()));
    }

    #[test]
    fn marker_roundtrip_env_token_and_fail_closed() {
        let dir = temp_home("gate");
        std::env::remove_var(MAINNET_ENV);

        // Default: mainnet is closed.
        assert!(!enabled());
        assert!(require_enabled().is_err());
        assert!(require_supported(Network::Bitcoin).is_err());
        assert_eq!(require_supported(Network::Testnet), Ok(()));

        // Persistent marker with private permissions.
        let path = enable().unwrap();
        assert_eq!(path, dir.join(".cairn").join(MARKER));
        assert!(path.is_file());
        assert!(enabled());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(require_supported(Network::Bitcoin), Ok(()));
        assert!(disable().unwrap());
        assert!(!enabled());
        assert!(!disable().unwrap());

        // Environment opt-in is exact: a typo must stay closed.
        std::env::set_var(MAINNET_ENV, "yes");
        assert!(!enabled());
        std::env::set_var(MAINNET_ENV, MAINNET_TOKEN);
        assert!(enabled());
        assert_eq!(require_supported(Network::Bitcoin), Ok(()));
        std::env::remove_var(MAINNET_ENV);
        assert!(!enabled());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
