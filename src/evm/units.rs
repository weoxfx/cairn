//! Fixed-point decimal <-> integer conversion for 18-decimal native coins and
//! ERC-20 tokens with any `decimals()` value.
//!
//! Everything is exact: amounts are parsed into wei-like integers and only
//! become floating point at the very edge, for a display-only USD estimate.

use primitive_types::U256;

/// Token decimals are a `uint8` on-chain; 36 is the widest a decimal string
/// can reasonably express and is well beyond every deployed token.
pub const MAX_DECIMALS: u32 = 36;

pub fn pow10(decimals: u32) -> U256 {
    let mut v = U256::one();
    for _ in 0..decimals {
        v = v * U256::from(10u8);
    }
    v
}

/// `"1.5"`, 18 -> `1500000000000000000`. Rejects signs, exponents, empty
/// input and more fractional digits than the token has (no silent rounding: a
/// user who types 0.0000001 USDC should be told, not rounded to zero).
pub fn parse_units(input: &str, decimals: u32) -> Result<U256, String> {
    if decimals > MAX_DECIMALS {
        return Err(format!("unsupported decimals value {decimals}"));
    }
    let s = input.trim();
    if s.is_empty() {
        return Err("amount is empty".into());
    }
    if s.starts_with('-') || s.starts_with('+') {
        return Err("amount must be positive".into());
    }
    let mut parts = s.splitn(2, '.');
    let whole = parts.next().unwrap_or("");
    let frac = parts.next().unwrap_or("");
    if whole.is_empty() && frac.is_empty() {
        return Err("amount is empty".into());
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("'{s}' is not a plain decimal amount"));
    }
    if frac.len() as u32 > decimals {
        return Err(format!("at most {decimals} decimal places are allowed"));
    }
    let whole_v = if whole.is_empty() {
        U256::zero()
    } else {
        U256::from_dec_str(whole).map_err(|_| "amount is too large".to_string())?
    };
    let mut frac_padded = frac.to_string();
    while (frac_padded.len() as u32) < decimals {
        frac_padded.push('0');
    }
    let frac_v = if frac_padded.is_empty() {
        U256::zero()
    } else {
        U256::from_dec_str(&frac_padded).map_err(|_| "amount is too large".to_string())?
    };
    whole_v
        .checked_mul(pow10(decimals))
        .and_then(|v| v.checked_add(frac_v))
        .ok_or_else(|| "amount is too large".to_string())
}

/// Exact decimal rendering with trailing zeros trimmed: `1500000000000000000`
/// at 18 decimals is `"1.5"`.
pub fn format_units(v: U256, decimals: u32) -> String {
    if decimals == 0 {
        return v.to_string();
    }
    let base = pow10(decimals);
    let whole = v / base;
    let frac = v % base;
    let mut f = frac.to_string();
    while f.len() < decimals as usize {
        f.insert(0, '0');
    }
    while f.ends_with('0') {
        f.pop();
    }
    if f.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{f}")
    }
}

/// Rounded display form with a thousands-grouped integer part, e.g.
/// `12 345.6789`.
pub fn format_amount(v: U256, decimals: u32, max_frac: usize) -> String {
    let exact = format_units(v, decimals);
    let (whole, frac) = match exact.split_once('.') {
        Some((w, f)) => (w.to_string(), f.to_string()),
        None => (exact, String::new()),
    };
    let grouped = group_digits(&whole);
    if frac.is_empty() || max_frac == 0 {
        grouped
    } else {
        let f: String = frac.chars().take(max_frac).collect();
        format!("{grouped}.{f}")
    }
}

fn group_digits(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push('\u{2009}');
        }
        out.push(c);
    }
    out
}

/// `1234.5` -> `$1 234.50`. Display only; never used for accounting.
pub fn usd(amount_units: U256, decimals: u32, price: f64) -> String {
    let base = pow10(decimals);
    let whole: f64 = (amount_units / base).to_string().parse().unwrap_or(0.0);
    let frac = (amount_units % base).low_u128() as f64 / pow10(decimals).low_u128() as f64;
    let v = (whole + frac) * price;
    let sign = if v < 0.0 { "-" } else { "" };
    let v = v.abs();
    let int = v.trunc();
    let cents = (v.fract() * 100.0).round();
    // Rounding can carry into the integer part (e.g. 9.999 -> 10.00).
    let (int, cents) = if cents >= 100.0 {
        (int + 1.0, cents - 100.0)
    } else {
        (int, cents)
    };
    format!(
        "{sign}${}.{cents:02}",
        group_digits(&format!("{int:.0}")),
        cents = cents as u64
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_exactly() {
        assert_eq!(
            parse_units("1.5", 18).unwrap(),
            U256::from(1_500_000_000_000_000_000u64)
        );
        assert_eq!(parse_units("0.000001", 6).unwrap(), U256::from(1u64));
        assert_eq!(parse_units("12", 6).unwrap(), U256::from(12_000_000u64));
        assert_eq!(parse_units("0", 18).unwrap(), U256::zero());
        assert_eq!(
            format_units(U256::from(1_500_000_000_000_000_000u64), 18),
            "1.5"
        );
        assert_eq!(format_units(U256::from(1u64), 18), "0.000000000000000001");
        assert_eq!(format_units(U256::from(0u64), 6), "0");
        assert_eq!(format_units(U256::from(1_000_000u64), 6), "1");
    }

    #[test]
    fn rejects_lossy_input() {
        assert!(parse_units("0.0000001", 6).is_err());
        assert!(parse_units("1e18", 18).is_err());
        assert!(parse_units("-1", 18).is_err());
        assert!(parse_units(" ", 18).is_err());
        assert!(parse_units("1.2.3", 18).is_err());
        assert!(parse_units("", 18).is_err());
    }

    #[test]
    fn huge_values_survive() {
        let wei = parse_units("123456789.123456789123456789", 18).unwrap();
        assert_eq!(format_units(wei, 18), "123456789.123456789123456789");
        let u = U256::from_dec_str(
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        )
        .unwrap();
        assert_eq!(format_units(u, 18).len() > 60, true);
    }

    #[test]
    fn groups_and_rounds_for_display() {
        assert_eq!(
            format_amount(U256::from(12_345_678_900u64), 6, 4),
            "12\u{2009}345.6789"
        );
        assert_eq!(usd(U256::from(1_500_000u64), 6, 2.0), "$3.00");
    }
}
