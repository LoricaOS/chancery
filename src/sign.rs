//! ECDSA P-256 / SHA-256 signing, compatible with herald's BearSSL verifier
//! (`br_ecdsa_i31_vrfy_asn1`): signatures are ASN.1 DER over SHA-256 of the
//! message; the public key is the 65-byte uncompressed point (0x04 || X || Y).
//!
//! The private key is stored as a raw 32-byte scalar in hex (simple + no PEM
//! parsing). It lives under .chancery/ and is never part of the served tree.

use crate::util;
use anyhow::{bail, Context, Result};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_core::OsRng;
use std::path::Path;

pub fn generate() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

/// Import an existing P-256 private key: either a 64-char hex scalar (chancery's
/// own format) or an EC PEM (SEC1 `EC PRIVATE KEY` or PKCS#8), as produced by
/// `openssl ecparam -genkey` — so a repo can sign with herald's existing key.
pub fn import(path: &Path) -> Result<SigningKey> {
    use p256::pkcs8::DecodePrivateKey;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading key {}", path.display()))?;
    let t = raw.trim();

    if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        let bytes = util::unhex(t)?;
        return SigningKey::from_slice(&bytes).map_err(|e| anyhow::anyhow!("invalid key: {e}"));
    }
    if let Ok(sk) = p256::SecretKey::from_sec1_pem(t) {
        return Ok(SigningKey::from(sk));
    }
    let sk = p256::SecretKey::from_pkcs8_pem(t)
        .map_err(|e| anyhow::anyhow!("cannot parse key (not hex, SEC1 PEM, or PKCS#8 PEM): {e}"))?;
    Ok(SigningKey::from(sk))
}

pub fn save_key(key: &SigningKey, path: &Path) -> Result<()> {
    let bytes = key.to_bytes();
    std::fs::write(path, format!("{}\n", util::hex(bytes.as_ref())))
        .with_context(|| format!("writing signing key {}", path.display()))?;
    Ok(())
}

pub fn load_key(path: &Path) -> Result<SigningKey> {
    let s = std::fs::read_to_string(path)
        .with_context(|| format!("reading signing key {}", path.display()))?;
    let bytes = util::unhex(s.trim())?;
    if bytes.len() != 32 {
        bail!("signing key must be a 32-byte scalar, got {} bytes", bytes.len());
    }
    SigningKey::from_slice(&bytes).map_err(|e| anyhow::anyhow!("invalid signing key: {e}"))
}

/// The 65-byte uncompressed public point (0x04 || X || Y) — herald's trust anchor.
pub fn public_point(key: &SigningKey) -> [u8; 65] {
    let vk = key.verifying_key();
    let ep = vk.to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(ep.as_bytes());
    out
}

/// Detached ASN.1 DER ECDSA-P256 signature over SHA-256(msg).
pub fn sign(key: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let sig: Signature = key.sign(msg);
    sig.to_der().as_bytes().to_vec()
}
