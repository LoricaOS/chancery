//! ECDSA P-256 / SHA-256 signing, compatible with herald's BearSSL verifier
//! (`br_ecdsa_i31_vrfy_asn1`): signatures are ASN.1 DER over SHA-256 of the
//! message; the public key is the 65-byte uncompressed point (0x04 || X || Y).
//!
//! The private key is stored as a raw 32-byte scalar in hex (simple + no PEM
//! parsing). It lives under .chancery/ and is never part of the served tree.
//! On disk it is written with `0600` permissions, and in-memory copies of the
//! secret are zeroized on drop.

use crate::util;
use anyhow::{bail, Context, Result};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_core::OsRng;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

pub fn generate() -> SigningKey {
    // OsRng draws from the OS CSPRNG (getrandom); correct for key generation.
    SigningKey::random(&mut OsRng)
}

/// Import an existing P-256 private key: either a 64-char hex scalar (chancery's
/// own format) or an EC PEM (SEC1 `EC PRIVATE KEY` or PKCS#8), as produced by
/// `openssl ecparam -genkey` — so a repo can sign with herald's existing key.
pub fn import(path: &Path) -> Result<SigningKey> {
    use p256::pkcs8::DecodePrivateKey;
    let raw = Zeroizing::new(
        std::fs::read_to_string(path).with_context(|| format!("reading key {}", path.display()))?,
    );
    let t = raw.trim();

    if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        let bytes = Zeroizing::new(util::unhex(t)?);
        return SigningKey::from_slice(&bytes).map_err(|e| anyhow::anyhow!("invalid key: {e}"));
    }
    if let Ok(sk) = p256::SecretKey::from_sec1_pem(t) {
        return Ok(SigningKey::from(sk));
    }
    let sk = p256::SecretKey::from_pkcs8_pem(t)
        .map_err(|e| anyhow::anyhow!("cannot parse key (not hex, SEC1 PEM, or PKCS#8 PEM): {e}"))?;
    Ok(SigningKey::from(sk))
}

/// Write a file containing secret material with owner-only (`0600`) permissions,
/// creating it with that mode up front so the secret is never briefly readable.
fn write_secret(path: &Path, contents: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub fn save_key(key: &SigningKey, path: &Path) -> Result<()> {
    let bytes = Zeroizing::new(key.to_bytes());
    let text = Zeroizing::new(format!("{}\n", util::hex(bytes.as_ref())));
    write_secret(path, text.as_bytes())
}

pub fn load_key(path: &Path) -> Result<SigningKey> {
    let s = Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("reading signing key {}", path.display()))?,
    );
    let bytes = Zeroizing::new(util::unhex(s.trim())?);
    if bytes.len() != 32 {
        bail!(
            "signing key must be a 32-byte scalar, got {} bytes",
            bytes.len()
        );
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
///
/// `p256` 0.13 uses RFC6979 deterministic nonces, so this is reproducible and
/// not vulnerable to RNG nonce reuse — the `signs_deterministically` test pins
/// that contract.
pub fn sign(key: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let sig: Signature = key.sign(msg);
    sig.to_der().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{DerSignature, VerifyingKey};

    #[test]
    fn sign_verify_roundtrip() {
        let key = generate();
        let msg = b"hello herald";
        let der = sign(&key, msg);
        let pt = public_point(&key);
        assert_eq!(pt.len(), 65);
        assert_eq!(pt[0], 0x04);

        let vk = VerifyingKey::from_sec1_bytes(&pt).unwrap();
        let sig = DerSignature::try_from(der.as_slice()).unwrap();
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn signs_deterministically() {
        let key = generate();
        let msg = b"reproducible";
        assert_eq!(sign(&key, msg), sign(&key, msg));
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.key");
        let key = generate();
        save_key(&key, &path).unwrap();
        let loaded = load_key(&path).unwrap();
        assert_eq!(key.to_bytes(), loaded.to_bytes());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
