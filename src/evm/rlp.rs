//! Minimal RLP encoder (Yellow Paper, Appendix B).
//!
//! Only encoding is implemented, and only for the shapes EIP-1559 needs:
//! byte strings, canonical integers and lists. This is serialisation, not
//! cryptography; correctness is pinned by the specification's own vectors.

use primitive_types::U256;

/// Encode one byte string.
pub fn encode_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return vec![b[0]];
    }
    let mut out = Vec::with_capacity(b.len() + 9);
    encode_len(b.len(), 0x80, &mut out);
    out.extend_from_slice(b);
    out
}

/// Encode a list from items that are already RLP-encoded.
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: usize = items.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(payload + 9);
    encode_len(payload, 0xc0, &mut out);
    for i in items {
        out.extend_from_slice(i);
    }
    out
}

/// Encode an integer as its shortest big-endian byte string. Zero is the empty
/// string, which RLP encodes as `0x80`.
pub fn encode_u256(v: U256) -> Vec<u8> {
    let mut buf = [0u8; 32];
    v.to_big_endian(&mut buf);
    let start = buf.iter().position(|b| *b != 0).unwrap_or(buf.len());
    encode_bytes(&buf[start..])
}

pub fn encode_u64(v: u64) -> Vec<u8> {
    encode_u256(U256::from(v))
}

fn encode_len(len: usize, offset: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(offset + len as u8);
        return;
    }
    let be = len.to_be_bytes();
    let start = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let bytes = &be[start..];
    out.push(offset + 55 + bytes.len() as u8);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yellow_paper_vectors() {
        assert_eq!(encode_bytes(b"dog"), hex::decode("83646f67").unwrap());
        assert_eq!(encode_bytes(b""), vec![0x80]);
        assert_eq!(encode_u64(0), vec![0x80]);
        assert_eq!(encode_u64(15), vec![0x0f]);
        assert_eq!(encode_u64(1024), vec![0x82, 0x04, 0x00]);
        assert_eq!(encode_list(&[]), vec![0xc0]);
        assert_eq!(
            encode_list(&[encode_bytes(b"cat"), encode_bytes(b"dog")]),
            hex::decode("c88363617483646f67").unwrap()
        );
        // The 56-byte string is the first case that needs a length prefix.
        let long = vec![b'a'; 56];
        let enc = encode_bytes(&long);
        assert_eq!(enc[0], 0xb8);
        assert_eq!(enc[1], 56);
        assert_eq!(enc.len(), 58);
    }

    #[test]
    fn integers_are_minimal() {
        assert_eq!(encode_u256(U256::from(0x7fu8)), vec![0x7f]);
        assert_eq!(encode_u256(U256::from(0x80u16)), vec![0x81, 0x80]);
        assert_eq!(
            encode_u256(U256::from(1_000_000u64)),
            vec![0x83, 0x0f, 0x42, 0x40]
        );
    }
}
