//! Read a herald `.hpkg` (uncompressed ustar) package's manifest.

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::Path;

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
    let f = std::fs::File::open(hpkg)
        .with_context(|| format!("opening package {}", hpkg.display()))?;
    let mut ar = tar::Archive::new(f);
    for entry in ar.entries()? {
        let mut e = entry?;
        let name = e.path()?.to_string_lossy().trim_start_matches("./").to_string();
        if name == "manifest" {
            let mut s = String::new();
            e.read_to_string(&mut s)?;
            return parse(&s);
        }
    }
    bail!("package {} has no manifest", hpkg.display())
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
        let Some((k, v)) = line.split_once('=') else { continue };
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
    if id.contains('/') || exec.contains('/') || arch.contains('/') {
        bail!("manifest id/exec/arch must not contain '/'");
    }
    Ok(Manifest { id, name, version, exec, caps, depends, arch })
}
