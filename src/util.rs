use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt::Write as _;

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

pub fn unhex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if !s.is_ascii() {
        bail!("hex string contains non-ASCII characters");
    }
    if !bytes.len().is_multiple_of(2) {
        bail!("odd-length hex string");
    }
    (0..bytes.len())
        .step_by(2)
        // SAFETY of indexing: `s.is_ascii()` guarantees one byte per char, so
        // every 2-byte window is a valid &str slice (no char-boundary panic).
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!(e)))
        .collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finalize())
}

/// Compare two version strings the way a package manager should: split into
/// runs of digits and non-digits, compare digit runs numerically (so `1.10`
/// sorts after `1.9`) and non-digit runs lexically. Not full dpkg semantics,
/// but correct for the common numeric-dotted case.
pub fn version_cmp(a: &str, b: &str) -> Ordering {
    let mut ai = a.chars().peekable();
    let mut bi = b.chars().peekable();
    loop {
        match (ai.peek().copied(), bi.peek().copied()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(ca), Some(cb)) => {
                if ca.is_ascii_digit() && cb.is_ascii_digit() {
                    let na = take_number(&mut ai);
                    let nb = take_number(&mut bi);
                    match na.cmp(&nb) {
                        Ordering::Equal => continue,
                        other => return other,
                    }
                } else {
                    match ca.cmp(&cb) {
                        Ordering::Equal => {
                            ai.next();
                            bi.next();
                            continue;
                        }
                        other => return other,
                    }
                }
            }
        }
    }
}

fn take_number(it: &mut std::iter::Peekable<std::str::Chars>) -> u128 {
    let mut n: u128 = 0;
    while let Some(&c) = it.peek() {
        if let Some(d) = c.to_digit(10) {
            n = n.saturating_mul(10).saturating_add(d as u128);
            it.next();
        } else {
            break;
        }
    }
    n
}

/// Reject a manifest field that will be interpolated into a filesystem path or
/// signed metadata. Allows a conservative, Debian-ish charset and forbids path
/// separators, `..`, leading dots, and control characters.
pub fn validate_field(kind: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{kind} must not be empty");
    }
    if value == "." || value == ".." || value.starts_with('.') {
        bail!("{kind} '{value}' must not start with '.'");
    }
    if value.contains("..") {
        bail!("{kind} '{value}' must not contain '..'");
    }
    for c in value.chars() {
        let ok = c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~' | '-' | ':');
        if !ok {
            bail!("{kind} '{value}' contains an invalid character '{c}' (allowed: A-Z a-z 0-9 . _ + ~ - :)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_unhex_roundtrip() {
        let data = [0x00u8, 0x01, 0xfe, 0xff, 0x42];
        assert_eq!(unhex(&hex(&data)).unwrap(), data);
    }

    #[test]
    fn unhex_rejects_odd_and_non_ascii() {
        assert!(unhex("abc").is_err());
        assert!(unhex("éé").is_err()); // 4 bytes, even, but non-ASCII — must not panic
        assert!(unhex("zz").is_err());
    }

    #[test]
    fn version_ordering_is_numeric() {
        assert_eq!(version_cmp("1.9", "1.10"), Ordering::Less);
        assert_eq!(version_cmp("9", "10"), Ordering::Less);
        assert_eq!(version_cmp("1.0", "1.0"), Ordering::Equal);
        assert_eq!(version_cmp("2.0", "1.99"), Ordering::Greater);
        assert_eq!(version_cmp("1.0.1", "1.0"), Ordering::Greater);
    }

    #[test]
    fn validate_field_rejects_traversal() {
        assert!(validate_field("version", "1.2.3").is_ok());
        assert!(validate_field("version", "../../etc/passwd").is_err());
        assert!(validate_field("version", "..").is_err());
        assert!(validate_field("id", ".hidden").is_err());
        assert!(validate_field("id", "a/b").is_err());
        assert!(validate_field("id", "a b").is_err());
        assert!(validate_field("id", "").is_err());
    }
}
