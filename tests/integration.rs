//! End-to-end test: build a minimal `.hpkg`, run the real binary through
//! init → add → publish, and verify the produced `Release.sig` against the
//! published `key.pub` trust anchor.

use std::path::Path;
use std::process::Command;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use tar::{Builder, Header};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_chancery")
}

fn run(repo: &Path, args: &[&str]) {
    let status = Command::new(bin())
        .arg("-C")
        .arg(repo)
        .args(args)
        .status()
        .expect("spawn chancery");
    assert!(status.success(), "chancery {args:?} failed");
}

fn make_hpkg(path: &Path, manifest: &[u8]) {
    let mut ar = Builder::new(Vec::new());
    let mut h = Header::new_ustar();
    h.set_path("manifest").unwrap();
    h.set_size(manifest.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    ar.append(&h, manifest).unwrap();
    let data = ar.into_inner().unwrap();
    std::fs::write(path, data).unwrap();
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn init_add_publish_produces_verifiable_signature() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();

    let hpkg = repo.join("foo.hpkg");
    make_hpkg(
        &hpkg,
        b"id=foo\nname=Foo\nversion=1.0\nexec=/usr/bin/foo\ncaps=net\n",
    );

    run(repo, &["init", "--origin", "Test Repo"]);
    run(repo, &["add", hpkg.to_str().unwrap()]);
    run(repo, &["publish"]);

    // The pool file exists with the bucketed path.
    assert!(repo.join("pool/f/foo/foo_1.0_x86_64.hpkg").exists());

    // The Packages stanza carries the metadata.
    let packages =
        std::fs::read_to_string(repo.join("dists/stable/main/binary-x86_64/Packages")).unwrap();
    assert!(packages.contains("Package: foo\n"));
    assert!(packages.contains("Caps: net\n"));

    // Verify Release.sig against the published trust anchor.
    let pubhex = std::fs::read_to_string(repo.join("key.pub")).unwrap();
    let vk = VerifyingKey::from_sec1_bytes(&unhex(&pubhex)).unwrap();
    let release = std::fs::read(repo.join("dists/stable/Release")).unwrap();
    let sig_der = std::fs::read(repo.join("dists/stable/Release.sig")).unwrap();
    let sig = DerSignature::try_from(sig_der.as_slice()).unwrap();
    vk.verify(&release, &sig).expect("Release.sig must verify");

    // The signing key must not be world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(repo.join(".chancery/signing.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn rejects_package_with_malicious_version() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    let hpkg = repo.join("evil.hpkg");
    make_hpkg(
        &hpkg,
        b"id=evil\nname=Evil\nversion=../../../../tmp/pwned\nexec=/bin/sh\n",
    );

    run(repo, &["init"]);
    // add must fail (non-zero exit) rather than write outside the pool.
    let status = Command::new(bin())
        .arg("-C")
        .arg(repo)
        .args(["add", hpkg.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success(), "malicious version must be rejected");
}
