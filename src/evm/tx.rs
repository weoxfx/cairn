//! EIP-1559 transactions: build, validate, sign, and the on-disk form used by
//! the offline signing path.
//!
//! An unsigned transaction is a small JSON document. It carries every value
//! that will be signed, so the signer can re-validate it from scratch without
//! trusting the machine that built it, and `cairn evm sign` performs no network
//! I/O at all.

use crate::error::Result;

use crate::evm::abi;
use crate::evm::address;
use crate::evm::chains::Chain;
use crate::evm::rlp;
use crate::evm::units;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use primitive_types::U256;
use serde::{Deserialize, Serialize};

pub const TX_TYPE: u8 = 0x02;
pub const MAX_DATA_BYTES: usize = 65_536;
pub const MIN_GAS_LIMIT: u64 = 21_000;
pub const MAX_GAS_LIMIT: u64 = 30_000_000;
/// Anything above this is almost certainly a mistake or a hostile estimate.
pub const FEE_CEILING_GWEI: u64 = 2_000;
/// Sanity bound on a single transfer; larger values are only reachable by
/// tokens with extreme supplies and are refused rather than formatted badly.
const MAX_VALUE: &str = "340282366920938463463374607431768211455"; // 2^128 - 1

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenInfo {
    pub address: String,
    /// Where the tokens are actually going. The contract is `to`; this is the
    /// recipient encoded in the calldata, and both are checked against each
    /// other on every validation pass.
    pub recipient: String,
    pub symbol: String,
    pub decimals: u32,
    /// Human-readable amount, kept for the review screen.
    pub amount: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsignedTx {
    pub kind: String,
    pub chain: String,
    pub chain_id: u64,
    pub from: String,
    pub to: String,
    /// Wei, decimal.
    pub value: String,
    /// `0x`-prefixed calldata.
    pub data: String,
    pub gas: String,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenInfo>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedTx {
    pub tx: UnsignedTx,
    /// `0x`-prefixed signed transaction, ready for `eth_sendRawTransaction`.
    pub raw: String,
    pub hash: String,
    pub signed_at: u64,
}

impl UnsignedTx {
    pub fn parse_field(name: &str, s: &str) -> Result<U256> {
        U256::from_dec_str(s.trim())
            .map_err(|_| format!("{name} is not a decimal integer"))
            .map_err(crate::error::Error::from)
    }

    pub fn value_wei(&self) -> Result<U256> {
        Self::parse_field("value", &self.value)
    }

    pub fn gas_limit(&self) -> Result<U256> {
        Self::parse_field("gas", &self.gas)
    }

    pub fn max_fee(&self) -> Result<U256> {
        Self::parse_field("max_fee_per_gas", &self.max_fee_per_gas)
    }

    pub fn priority_fee(&self) -> Result<U256> {
        Self::parse_field("max_priority_fee_per_gas", &self.max_priority_fee_per_gas)
    }

    pub fn nonce_value(&self) -> Result<U256> {
        Self::parse_field("nonce", &self.nonce)
    }

    pub fn to_bytes(&self) -> Result<[u8; 20]> {
        address::parse_address(&self.to)
    }

    pub fn data_bytes(&self) -> Result<Vec<u8>> {
        let body = self
            .data
            .strip_prefix("0x")
            .or_else(|| self.data.strip_prefix("0X"))
            .unwrap_or(&self.data);
        if body.len() > 2 * MAX_DATA_BYTES {
            return Err("calldata is too large".into());
        }
        if !body.len().is_multiple_of(2) {
            return Err("calldata has an odd number of hex digits".into());
        }
        hex::decode(body)
            .map_err(|_| "calldata is not valid hex".to_string())
            .map_err(crate::error::Error::from)
    }

    /// Full structural check. Used before signing and again before broadcast,
    /// so a file that was edited between the two steps is rejected.
    pub fn validate(&self, allow_high_fee: bool) -> Result<()> {
        if self.kind != "eip1559" {
            return Err(format!("unsupported transaction kind '{}'", self.kind).into());
        }
        if self.chain_id == 0 {
            return Err("transaction has no chain id".into());
        }
        let from = address::parse_address(&self.from)?;
        let to = address::parse_address(&self.to)?;
        if address::is_zero(&to) {
            return Err("refusing to send to the zero address (0x000…000 burns the funds)".into());
        }
        if address::is_zero(&from) {
            return Err("transaction has an invalid sender".into());
        }
        let value = self.value_wei()?;
        if value > U256::from_dec_str(MAX_VALUE).unwrap() {
            return Err("value is implausibly large".into());
        }
        let data = self.data_bytes()?;
        let gas = self.gas_limit()?;
        if gas < U256::from(MIN_GAS_LIMIT) || gas > U256::from(MAX_GAS_LIMIT) {
            return Err(format!(
                "gas limit {} is outside {MIN_GAS_LIMIT}..={MAX_GAS_LIMIT}",
                gas
            )
            .into());
        }
        let nonce = self.nonce_value()?;
        if nonce > U256::from(u64::MAX) {
            return Err("nonce is out of range".into());
        }
        let max_fee = self.max_fee()?;
        let tip = self.priority_fee()?;
        if tip > max_fee {
            return Err("priority fee is higher than the maximum fee".into());
        }
        let ceiling = U256::from(FEE_CEILING_GWEI) * units::pow10(9);
        if max_fee > ceiling && !allow_high_fee {
            return Err(format!(
                "maximum fee {} gwei is above the {} gwei safety ceiling; pass --force-fee if this is intended",
                units::format_units(max_fee, 9),
                FEE_CEILING_GWEI
            ).into());
        }
        if let Some(t) = &self.token {
            let token_addr = address::parse_address(&t.address)?;
            if token_addr != to {
                return Err("token contract and recipient do not match".into());
            }
            if !value.is_zero() {
                return Err("a token transfer must not also send the native coin".into());
            }
            if data.len() != 68 || data[..4] != abi::TRANSFER {
                return Err("token transaction is not an ERC-20 transfer".into());
            }
            if data[4..16].iter().any(|b| *b != 0) {
                return Err("token calldata has non-zero address padding".into());
            }
            let recipient = address::parse_address(&t.recipient)?;
            if data[16..36] != recipient {
                return Err("token calldata recipient does not match the reviewed address".into());
            }
            if t.decimals > units::MAX_DECIMALS {
                return Err("token decimals out of range".into());
            }
            if t.symbol.len() > 32 || t.symbol.chars().any(|c| c.is_control()) {
                return Err("token symbol is not displayable".into());
            }
            units::parse_units(&t.amount, t.decimals)?;
        } else if !data.is_empty() {
            return Err("native transfers cannot carry calldata".into());
        }
        Ok(())
    }

    /// The nine RLP items of the unsigned EIP-1559 payload.
    pub fn payload_items(&self) -> Result<Vec<Vec<u8>>> {
        let to = self.to_bytes()?;
        let data = self.data_bytes()?;
        Ok(vec![
            rlp::encode_u64(self.chain_id),
            rlp::encode_u256(self.nonce_value()?),
            rlp::encode_u256(self.priority_fee()?),
            rlp::encode_u256(self.max_fee()?),
            rlp::encode_u256(self.gas_limit()?),
            rlp::encode_bytes(&to),
            rlp::encode_u256(self.value_wei()?),
            rlp::encode_bytes(&data),
            rlp::encode_list(&[]), // access list
        ])
    }

    /// `keccak256(0x02 || rlp([...]))` — the digest that gets signed.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut payload = vec![TX_TYPE];
        payload.extend(rlp::encode_list(&self.payload_items()?));
        Ok(address::keccak(&payload))
    }

    /// Worst-case native cost: value plus the full gas limit at the maximum fee.
    pub fn max_native_cost(&self) -> Result<U256> {
        let gas_cost = self
            .gas_limit()?
            .checked_mul(self.max_fee()?)
            .ok_or_else(|| "gas cost overflows".to_string())?;
        self.value_wei()?
            .checked_add(gas_cost)
            .ok_or_else(|| "total cost overflows".to_string())
            .map_err(crate::error::Error::from)
    }

    pub fn ensure_chain(&self, chain: &Chain) -> Result<()> {
        if self.chain_id != chain.chain_id {
            return Err(format!(
                "transaction is for chain {} but {} (chain {}) was selected",
                self.chain_id, chain.name, chain.chain_id
            )
            .into());
        }
        Ok(())
    }

    pub fn sign(&self, key: &SecretKey, allow_high_fee: bool) -> Result<SignedTx> {
        self.validate(allow_high_fee)?;
        let secp = Secp256k1::new();
        let msg = Message::from_digest(self.digest()?);
        let sig = secp.sign_ecdsa_recoverable(&msg, key);
        let (recid, compact) = sig.serialize_compact();
        let r = U256::from_big_endian(&compact[..32]);
        let s = U256::from_big_endian(&compact[32..]);
        if r.is_zero() || s.is_zero() {
            return Err("signer produced an invalid signature".into());
        }
        let mut items = self.payload_items()?;
        items.push(rlp::encode_u64(recid.to_i32() as u64));
        items.push(rlp::encode_u256(r));
        items.push(rlp::encode_u256(s));
        let mut raw = vec![TX_TYPE];
        raw.extend(rlp::encode_list(&items));
        let hash = address::keccak(&raw);
        Ok(SignedTx {
            tx: self.clone(),
            raw: format!("0x{}", hex::encode(&raw)),
            hash: format!("0x{}", hex::encode(hash)),
            signed_at: now(),
        })
    }
}

impl SignedTx {
    pub fn raw_bytes(&self) -> Result<Vec<u8>> {
        let body = self
            .raw
            .strip_prefix("0x")
            .ok_or("signed transaction is not hex-prefixed")?;
        hex::decode(body)
            .map_err(|_| "signed transaction is not valid hex".to_string())
            .map_err(crate::error::Error::from)
    }

    pub fn validate(&self, allow_high_fee: bool) -> Result<()> {
        self.tx.validate(allow_high_fee)?;
        let raw = self.raw_bytes()?;
        if raw.len() < 9 || raw.len() > MAX_DATA_BYTES + 4096 {
            return Err("signed transaction has an impossible length".into());
        }
        if raw[0] != TX_TYPE {
            return Err("signed transaction is not EIP-1559".into());
        }
        // The bytes are authoritative, so the review document must agree with
        // them field by field. Otherwise an edited file could describe one
        // transfer while broadcasting another.
        let items = list_items(&raw[1..])?;
        if items.len() != 12 {
            return Err("signed transaction does not have 12 fields".into());
        }
        for (i, expected) in self.tx.payload_items()?.iter().enumerate() {
            if expected.as_slice() != items[i] {
                return Err(format!(
                    "signed transaction disagrees with its description at field {i}"
                )
                .into());
            }
        }
        let hash = format!("0x{}", hex::encode(address::keccak(&raw)));
        if hash != self.hash.to_ascii_lowercase() {
            return Err("signed transaction hash does not match its bytes".into());
        }
        Ok(())
    }
}

// ── minimal RLP reader (validation only) ──

/// Read one RLP header: `(payload start, payload length, is_list)`.
fn read_header(buf: &[u8], at: usize) -> Result<(usize, usize, bool)> {
    let b = *buf.get(at).ok_or("truncated RLP")?;
    if b < 0x80 {
        return Ok((at, 1, false));
    }
    let (is_list, offset, len) = if b <= 0xb7 {
        (false, 1usize, (b - 0x80) as usize)
    } else if b <= 0xbf {
        let n = (b - 0xb7) as usize;
        (false, 1 + n, be_len(buf, at + 1, n)?)
    } else if b <= 0xf7 {
        (true, 1usize, (b - 0xc0) as usize)
    } else {
        let n = (b - 0xf7) as usize;
        (true, 1 + n, be_len(buf, at + 1, n)?)
    };
    let start = at.checked_add(offset).ok_or("RLP offset overflow")?;
    Ok((start, len, is_list))
}

fn be_len(buf: &[u8], at: usize, n: usize) -> Result<usize> {
    if n == 0 || n > 8 {
        return Err("RLP length has an impossible width".into());
    }
    let bytes = buf.get(at..at + n).ok_or("truncated RLP length")?;
    let mut v: u64 = 0;
    for b in bytes {
        v = (v << 8) | u64::from(*b);
    }
    usize::try_from(v)
        .map_err(|_| "RLP length overflow".to_string())
        .map_err(crate::error::Error::from)
}

/// Payload bytes of one encoded string item.
#[cfg(any(test, feature = "fuzzing"))]
fn item_payload(encoded: &[u8]) -> Result<&[u8]> {
    let (start, len, is_list) = read_header(encoded, 0)?;
    if is_list {
        return Err("expected an RLP string, found a list".into());
    }
    let end = start.checked_add(len).ok_or("RLP overflow")?;
    encoded
        .get(start..end)
        .ok_or_else(|| "truncated RLP item".into())
}

/// Fully encoded items of a top-level RLP list.
fn list_items(buf: &[u8]) -> Result<Vec<&[u8]>> {
    let (start, len, is_list) = read_header(buf, 0)?;
    if !is_list {
        return Err("expected an RLP list".into());
    }
    let end = start.checked_add(len).ok_or("RLP overflow")?;
    if end > buf.len() {
        return Err("truncated RLP list".into());
    }
    let mut out = Vec::new();
    let mut at = start;
    while at < end {
        let (ps, pl, _) = read_header(buf, at)?;
        let item_end = ps.checked_add(pl).ok_or("RLP overflow")?;
        if item_end > end {
            return Err("RLP item runs past its list".into());
        }
        out.push(&buf[at..item_end]);
        at = item_end;
    }
    Ok(out)
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fuzz entry point: the RLP reader the signed-transaction checks walk.
///
/// Its inputs come from transaction files and from a node's replies, so a
/// malformed length or nesting must never panic or allocate unbounded memory.
#[cfg(feature = "fuzzing")]
pub fn fuzz_rlp(data: &[u8]) {
    let _ = read_header(data, 0);
    let _ = item_payload(data);
    let _ = list_items(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};

    fn sample() -> UnsignedTx {
        UnsignedTx {
            kind: "eip1559".into(),
            chain: "ethereum".into(),
            chain_id: 1,
            from: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".into(),
            to: "0x3535353535353535353535353535353535353535".into(),
            value: "1000000000000000000".into(),
            data: "0x".into(),
            gas: "21000".into(),
            max_fee_per_gas: "20000000000".into(),
            max_priority_fee_per_gas: "1000000000".into(),
            nonce: "9".into(),
            token: None,
            created_at: 0,
        }
    }

    #[test]
    fn payload_is_well_formed() {
        let tx = sample();
        tx.validate(false).unwrap();
        let items = tx.payload_items().unwrap();
        assert_eq!(items.len(), 9);
        assert_eq!(items[0], vec![0x01]); // chain id 1
        assert_eq!(items[8], vec![0xc0]); // empty access list
        assert_eq!(
            tx.max_native_cost().unwrap(),
            U256::from(1_000_000_000_000_000_000u128)
                + U256::from(21_000u64) * U256::from(20_000_000_000u64)
        );
    }

    #[test]
    fn signature_recovers_to_the_signer() {
        let key = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let owner = address::address_from_public_key(&key.public_key(&Secp256k1::new()));
        let tx = sample();
        let signed = tx.sign(&key, false).unwrap();
        signed.validate(false).unwrap();

        // Recover the public key from the signature we just produced over the
        // digest and confirm it is the key we signed with.
        let raw = signed.raw_bytes().unwrap();
        assert_eq!(raw[0], 0x02);
        let items = list_items(&raw[1..]).unwrap();
        assert_eq!(items.len(), 12);
        let y = match item_payload(items[9]).unwrap() {
            [] => 0,
            [b] => *b as i32,
            _ => panic!("y parity is not a single byte"),
        };
        let r = item_payload(items[10]).unwrap();
        let s = item_payload(items[11]).unwrap();
        assert!(r.len() <= 32 && s.len() <= 32);
        let mut compact = [0u8; 64];
        compact[32 - r.len()..32].copy_from_slice(r);
        compact[64 - s.len()..].copy_from_slice(s);
        let sig =
            RecoverableSignature::from_compact(&compact, RecoveryId::from_i32(y).unwrap()).unwrap();
        let secp = Secp256k1::new();
        let msg = Message::from_digest(tx.digest().unwrap());
        let recovered = secp.recover_ecdsa(&msg, &sig).unwrap();
        assert_eq!(address::address_from_public_key(&recovered), owner);
    }

    #[test]
    fn signing_is_deterministic_and_rejects_tampering() {
        let key = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let a = sample().sign(&key, false).unwrap();
        let b = sample().sign(&key, false).unwrap();
        assert_eq!(a.raw, b.raw);
        assert_eq!(a.hash, b.hash);

        let mut tampered = a.clone();
        tampered.tx.value = "2000000000000000000".into();
        assert!(
            tampered.validate(false).is_err(),
            "value change must break the hash check"
        );

        let mut bad_raw = a.clone();
        bad_raw.raw = "0x02c0".into();
        assert!(bad_raw.validate(false).is_err());
    }

    #[test]
    fn guards_reject_dangerous_transactions() {
        let mut tx = sample();
        tx.to = "0x0000000000000000000000000000000000000000".into();
        assert!(tx.validate(false).unwrap_err().contains("zero address"));

        let mut tx = sample();
        tx.kind = "legacy".into();
        assert!(tx.validate(false).is_err());

        let mut tx = sample();
        tx.max_fee_per_gas = (U256::from(FEE_CEILING_GWEI + 1) * units::pow10(9)).to_string();
        assert!(tx.validate(false).is_err());
        assert!(tx.validate(true).is_ok());

        let mut tx = sample();
        tx.gas = "40000000".into();
        assert!(tx.validate(false).is_err());

        let mut tx = sample();
        tx.data = "0xdeadbeef".into();
        assert!(tx.validate(false).is_err());

        let mut tx = sample();
        tx.chain_id = 0;
        assert!(tx.validate(false).is_err());
    }

    #[test]
    fn token_transactions_are_checked() {
        let contract = [0x42u8; 20];
        let to = [0x99u8; 20];
        let data = abi::transfer_data(&to, U256::from(1_000_000u64));
        let mut tx = sample();
        tx.to = address::checksum(&contract);
        tx.value = "0".into();
        tx.data = format!("0x{}", hex::encode(&data));
        tx.token = Some(TokenInfo {
            address: address::checksum(&contract),
            recipient: address::checksum(&to),
            symbol: "USDC".into(),
            decimals: 6,
            amount: "1".into(),
        });
        tx.validate(false).unwrap();

        // Sending native value alongside a token transfer is refused.
        let mut bad = tx.clone();
        bad.value = "1".into();
        assert!(bad.validate(false).is_err());

        // A token record for a different contract is refused.
        let mut bad = tx.clone();
        bad.token.as_mut().unwrap().address = address::checksum(&[0x11; 20]);
        assert!(bad.validate(false).is_err());

        // A recipient that disagrees with the signed calldata is refused.
        let mut bad = tx.clone();
        bad.token.as_mut().unwrap().recipient = address::checksum(&[0x77; 20]);
        assert!(bad.validate(false).is_err());
    }
}
