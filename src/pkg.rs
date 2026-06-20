//! Read a herald `.hpkg` (uncompressed ustar) package's manifest.

use crate::util;
use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::Path;

/// Cap on the manifest member size — guards against a hostile `.hpkg` declaring
/// a multi-gigabyte `manifest` entry that would exhaust memory.
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub exec: String,
    pub caps: String,
    pub depends: String,
    pub arch: String,
}

pub fn read_manifest(hpkg: &Path) -> Result<Manifest> {
    let f =
        std::fs::File::open(hpkg).with_context(|| format!("opening package {}", hpkg.display()))?;
    let mut ar = tar::Archive::new(f);
    for entry in ar.entries()? {
        let e = entry?;
        let name = e
            .path()?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        if name == "manifest" {
            let mut s = String::new();
            // Read at most MAX_MANIFEST_BYTES + 1 so we can detect overflow.
            e.take(MAX_MANIFEST_BYTES as u64 + 1)
                .read_to_string(&mut s)
                .with_context(|| format!("reading manifest of {}", hpkg.display()))?;
            if s.len() > MAX_MANIFEST_BYTES {
                bail!(
                    "manifest of {} exceeds {} bytes",
                    hpkg.display(),
                    MAX_MANIFEST_BYTES
                );
            }
            return parse(&s);
        }
    }
    bail!("package {} has no manifest", hpkg.display())
}

fn reject_control(kind: &str, value: &str) -> Result<()> {
    if let Some(c) = value.chars().find(|c| c.is_control()) {
        bail!("{kind} contains a control character (0x{:02x})", c as u32);
    }
    Ok(())
}

fn parse(text: &str) -> Result<Manifest> {
    let mut id = String::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut exec = String::new();
    let mut caps = String::new();
    let mut depends = String::new();
    let mut arch = String::from("x86_64");

    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "id" => id = v.to_string(),
            "name" => name = v.to_string(),
            "version" => version = v.to_string(),
            "exec" => exec = v.to_string(),
            "caps" => caps = v.to_string(),
            "depends" => depends = v.to_string(),
            "arch" => arch = v.to_string(),
            _ => {}
        }
    }

    if id.is_empty() || name.is_empty() || version.is_empty() || exec.is_empty() {
        bail!("manifest missing a required field (id/name/version/exec)");
    }

    // id/version/arch are interpolated into on-disk pool paths — strict charset.
    util::validate_field("id", &id)?;
    util::validate_field("version", &version)?;
    util::validate_field("arch", &arch)?;

    // The remaining fields are emitted into the signed Packages stanza; reject
    // control characters so they cannot distort the RFC822 record.
    reject_control("name", &name)?;
    reject_control("exec", &exec)?;
    reject_control("caps", &caps)?;
    reject_control("depends", &depends)?;

    Ok(Manifest {
        id,
        name,
        version,
        exec,
        caps,
        depends,
        arch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> String {
        "id=foo\nname=Foo\nversion=1.0\nexec=/usr/bin/foo\n".to_string()
    }

    #[test]
    fn parses_required_fields_and_defaults_arch() {
        let m = parse(&base()).unwrap();
        assert_eq!(m.id, "foo");
        assert_eq!(m.version, "1.0");
        assert_eq!(m.arch, "x86_64");
    }

    #[test]
    fn skips_comments_and_blanks_and_keeps_equals_in_value() {
        let text = "# a comment\n\nid=foo\nname=Foo\nversion=1.0\nexec=/bin/foo\ncaps=net=on\n";
        let m = parse(text).unwrap();
        assert_eq!(m.caps, "net=on");
    }

    #[test]
    fn rejects_missing_required() {
        let text = "id=foo\nname=Foo\n";
        assert!(parse(text).is_err());
    }

    #[test]
    fn rejects_path_traversal_in_version() {
        let text = "id=foo\nname=Foo\nversion=../../../etc/x\nexec=/bin/foo\n";
        assert!(parse(text).is_err());
    }

    #[test]
    fn rejects_slash_in_id() {
        let text = "id=a/b\nname=Foo\nversion=1.0\nexec=/bin/foo\n";
        assert!(parse(text).is_err());
    }

    #[test]
    fn rejects_control_chars_in_name() {
        let text = "id=foo\nname=Foo\u{7}Bar\nversion=1.0\nexec=/bin/foo\n";
        assert!(parse(text).is_err());
    }
}
