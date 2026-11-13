//! The small slice of the Ethereum ABI (Solidity contract ABI) the wallet
//! needs: `transfer`, `balanceOf`, `decimals` and `symbol` on ERC-20 tokens.
//!
//! Return data is untrusted: every word is bounds-checked, and token text is
//! reduced to safe printable ASCII before it can reach the screen.

use crate::error::Result;

use primitive_types::U256;

pub const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
pub const BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
pub const DECIMALS: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];
pub const SYMBOL: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];
pub const NAME: [u8; 4] = [0x06, 0xfd, 0xde, 0x03];

/// Longest token symbol/name we will display.
const MAX_TEXT: usize = 32;

/// `erc20::transfer(to, amount)`.
pub fn transfer_data(to: &[u8; 20], amount: U256) -> Vec<u8> {
    let mut out = Vec::with_capacity(68);
    out.extend_from_slice(&TRANSFER);
    out.extend_from_slice(&pad_address(to));
    out.extend_from_slice(&pad_u256(amount));
    out
}

/// `erc20::balanceOf(owner)`.
pub fn balance_of_data(owner: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&BALANCE_OF);
    out.extend_from_slice(&pad_address(owner));
    out
}

pub fn pad_address(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

pub fn pad_u256(v: U256) -> [u8; 32] {
    let mut w = [0u8; 32];
    v.to_big_endian(&mut w);
    w
}

/// Read one 32-byte word.
pub fn word(data: &[u8], index: usize) -> Result<&[u8]> {
    let start = index
        .checked_mul(32)
        .ok_or_else(|| "return data offset overflow".to_string())?;
    let end = start
        .checked_add(32)
        .ok_or_else(|| "return data offset overflow".to_string())?;
    data.get(start..end)
        .ok_or_else(|| "token returned short data".to_string())
        .map_err(crate::error::Error::from)
}

pub fn decode_uint(data: &[u8], index: usize) -> Result<U256> {
    Ok(U256::from_big_endian(word(data, index)?))
}

/// Decode `decimals()`; a token that answers with something outside 0..=36 is
/// rejected rather than guessed at.
pub fn decode_decimals(data: &[u8]) -> Result<u32> {
    let v = decode_uint(data, 0)?;
    if v > U256::from(crate::evm::units::MAX_DECIMALS) {
        return Err("token reported implausible decimals".into());
    }
    Ok(v.low_u32())
}

/// Decode `symbol()`. Covers both the common `string` return and the legacy
/// fixed `bytes32` form (MKR and others). The result is an allowlist of
/// printable ASCII, never server text passed through.
pub fn decode_symbol(data: &[u8]) -> Option<String> {
    if let Some(s) = decode_dynamic_string(data) {
        return Some(s);
    }
    let raw = data.get(0..32)?;
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    clean_text(raw.get(..end)?)
}

fn decode_dynamic_string(data: &[u8]) -> Option<String> {
    let offset = to_usize(U256::from_big_endian(data.get(0..32)?))?;
    if offset > 1024 || offset.checked_add(32)? > data.len() {
        return None;
    }
    let len = to_usize(U256::from_big_endian(data.get(offset..offset + 32)?))?;
    if len > MAX_TEXT || offset.checked_add(32)?.checked_add(len)? > data.len() {
        return None;
    }
    let start = offset + 32;
    clean_text(data.get(start..start + len)?)
}

/// `U256::as_usize` panics on overflow, and this value comes from a contract,
/// so the conversion is explicit and checked.
fn to_usize(v: U256) -> Option<usize> {
    if v > U256::from(u64::MAX) {
        return None;
    }
    let n = v.low_u64();
    if n > usize::MAX as u64 {
        return None;
    }
    Some(n as usize)
}

fn clean_text(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(MAX_TEXT)
        .collect();
    if cleaned.trim().is_empty() {
        None
    } else {
        Some(cleaned.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::address::keccak;

    #[test]
    fn selectors_match_the_spec() {
        assert_eq!(&keccak(b"transfer(address,uint256)")[..4], &TRANSFER);
        assert_eq!(&keccak(b"balanceOf(address)")[..4], &BALANCE_OF);
        assert_eq!(&keccak(b"decimals()")[..4], &DECIMALS);
        assert_eq!(&keccak(b"symbol()")[..4], &SYMBOL);
        assert_eq!(&keccak(b"name()")[..4], &NAME);
    }

    #[test]
    fn calldata_is_zero_padded() {
        let to = [0x11u8; 20];
        let d = transfer_data(&to, U256::from(1_000_000u64));
        assert_eq!(d.len(), 68);
        assert_eq!(&d[4..16], &[0u8; 12]);
        assert_eq!(&d[16..36], &to);
        assert_eq!(d[67], 0x40); // 1_000_000 = 0x0f4240
        assert_eq!(balance_of_data(&to).len(), 36);
    }

    #[test]
    fn decodes_string_and_bytes32_symbols() {
        // "USDC" as an ABI string: offset 32, length 4, data padded.
        let mut ret = vec![0u8; 96];
        ret[31] = 0x20;
        ret[63] = 4;
        ret[64..68].copy_from_slice(b"USDC");
        assert_eq!(decode_symbol(&ret).unwrap(), "USDC");

        let mut b32 = vec![0u8; 32];
        b32[..3].copy_from_slice(b"MKR");
        assert_eq!(decode_symbol(&b32).unwrap(), "MKR");

        assert_eq!(decode_symbol(&[]), None);
        // A length far past the buffer must not panic or allocate.
        let mut bad = vec![0u8; 64];
        bad[31] = 0x20;
        bad[32..64].copy_from_slice(&[0xff; 32]);
        assert_eq!(decode_symbol(&bad), None);
    }

    #[test]
    fn rejects_absurd_decimals() {
        let mut w = vec![0u8; 32];
        w[31] = 200;
        assert!(decode_decimals(&w).is_err());
        w[31] = 6;
        assert_eq!(decode_decimals(&w).unwrap(), 6);
    }

    #[test]
    fn control_characters_never_reach_the_symbol() {
        let mut ret = vec![0u8; 96];
        ret[31] = 0x20;
        ret[63] = 4;
        ret[64..68].copy_from_slice(b"US\x1bC");
        assert_eq!(decode_symbol(&ret).unwrap(), "USC");
    }
}
