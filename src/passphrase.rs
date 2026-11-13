//! Random wallet-password generation.
//!
//! The password protects the wallet file, so it only has to be unpredictable and
//! long. Independently chosen words are both, and unlike random characters they
//! can be written down by hand and typed back without mistakes.
//!
//! Words come from the BIP39 English list (`bip39` already ships it), which is
//! used here purely as a 2048-word alphabet. This is not a seed phrase and is
//! never labelled as one.

use crate::error::Result;

use bip39::Language;
use zeroize::Zeroizing;

/// Words in a generated password: 66 bits of entropy, ~40 characters.
pub const DEFAULT_WORDS: usize = 6;

/// Bits of entropy in `words` independently chosen words from the 2048-word list.
pub fn entropy_bits(words: usize) -> usize {
    words * 11
}

/// Generate a `-`-separated password of `words` words.
///
/// Each word is drawn from the OS random source. The index is the low 11 bits of
/// a uniform 16-bit value; 2048 divides 65536 exactly, so no rejection loop is
/// needed to keep the choice unbiased.
pub fn generate(words: usize) -> Result<Zeroizing<String>> {
    if words == 0 {
        return Err("a password needs at least one word".into());
    }
    let list = Language::English.word_list();
    let mut out = String::new();
    for i in 0..words {
        let bytes = crate::keystore::random_bytes::<2>()?;
        let index = usize::from(u16::from_le_bytes(bytes) & 0x07ff);
        let word = list
            .get(index)
            .ok_or("the word list is shorter than 2048 entries")?;
        if i > 0 {
            out.push('-');
        }
        out.push_str(word);
    }
    Ok(Zeroizing::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words_of(pw: &str) -> Vec<&str> {
        pw.split('-').collect()
    }

    #[test]
    fn generates_the_requested_number_of_real_words() {
        let list = Language::English.word_list();
        let pw = generate(DEFAULT_WORDS).unwrap();
        let parts = words_of(&pw);
        assert_eq!(parts.len(), DEFAULT_WORDS);
        for w in parts {
            assert!(list.contains(&w), "{w} is not in the BIP39 list");
        }
    }

    #[test]
    fn entropy_matches_the_word_count() {
        assert_eq!(entropy_bits(DEFAULT_WORDS), 66);
        assert_eq!(entropy_bits(1), 11);
    }

    #[test]
    fn two_passwords_differ() {
        let a = generate(DEFAULT_WORDS).unwrap();
        let b = generate(DEFAULT_WORDS).unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn zero_words_is_refused() {
        assert!(generate(0).is_err());
    }
}
