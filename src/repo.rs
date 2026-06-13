//! Repository layout, on-disk state, and the management commands.

use crate::{pkg, sign, util};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
struct Config {
    origin: String,
    suites: Vec<String>,
    components: Vec<String>,
    architectures: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    name: String,
    version: String,
    arch: String,
    suite: String,
    component: String,
    filename: String, // relative to repo root
    size: u64,
    sha256: String,
    display_name: String,
    exec: String,
    #[serde(default)]
    caps: String,
    #[serde(default)]
    depends: String,
}

fn chancery_dir(repo: &Path) -> PathBuf { repo.join(".chancery") }
fn config_path(repo: &Path) -> PathBuf { chancery_dir(repo).join("config.toml") }
fn db_path(repo: &Path) -> PathBuf { chancery_dir(repo).join("db.json") }
fn key_path(repo: &Path) -> PathBuf { chancery_dir(repo).join("signing.key") }

fn load_config(repo: &Path) -> Result<Config> {
    let s = std::fs::read_to_string(config_path(repo))
        .context("not a chancery repository (no .chancery/config.toml) — run `chancery init`")?;
    Ok(toml::from_str(&s)?)
}
fn save_config(repo: &Path, c: &Config) -> Result<()> {
    std::fs::write(config_path(repo), toml::to_string_pretty(c)?)?;
    Ok(())
}
fn load_db(repo: &Path) -> Result<Vec<Entry>> {
    let p = db_path(repo);
    if !p.exists() {
        return Ok(vec![]);
    }
    Ok(serde_json::from_str(&std::fs::read_to_string(p)?)?)
}
fn save_db(repo: &Path, db: &[Entry]) -> Result<()> {
    std::fs::write(db_path(repo), serde_json::to_string_pretty(db)?)?;
    Ok(())
}

fn pool_path(name: &str, version: &str, arch: &str) -> String {
    let prefix = name.chars().next().unwrap_or('_').to_ascii_lowercase();
    format!("pool/{prefix}/{name}/{name}_{version}_{arch}.hpkg")
}

// ── commands ────────────────────────────────────────────────────────────

pub fn init(repo: &Path, origin: &str, import_key: Option<&Path>) -> Result<()> {
    if config_path(repo).exists() {
        bail!("repository already initialized at {}", repo.display());
    }
    std::fs::create_dir_all(chancery_dir(repo))?;
    std::fs::create_dir_all(repo.join("pool"))?;
    std::fs::create_dir_all(repo.join("dists"))?;

    let key = match import_key {
        Some(p) => sign::import(p)?,
        None => sign::generate(),
    };
    sign::save_key(&key, &key_path(repo))?;
    std::fs::write(repo.join("key.pub"), format!("{}\n", util::hex(&sign::public_point(&key))))?;

    let cfg = Config {
        origin: origin.to_string(),
        suites: vec!["stable".into()],
        components: vec!["main".into()],
        architectures: vec!["x86_64".into()],
    };
    save_config(repo, &cfg)?;
    save_db(repo, &[])?;

    println!("Initialized chancery repository at {}", repo.display());
    println!("  signing key:  {}", key_path(repo).display());
    println!("  trust anchor: {} (give this to clients)", repo.join("key.pub").display());
    println!("Next: `chancery add <pkg.hpkg>` then `chancery publish`.");
    Ok(())
}

pub fn add(repo: &Path, hpkg: &Path, suite: &str, component: &str) -> Result<()> {
    let mut cfg = load_config(repo)?;
    let m = pkg::read_manifest(hpkg)?;
    let data = std::fs::read(hpkg).with_context(|| format!("reading {}", hpkg.display()))?;
    let sha = util::sha256_hex(&data);
    let size = data.len() as u64;

    let filename = pool_path(&m.id, &m.version, &m.arch);
    let dest = repo.join(&filename);
    std::fs::create_dir_all(dest.parent().unwrap())?;
    std::fs::write(&dest, &data)?;

    if !cfg.suites.iter().any(|s| s == suite) {
        cfg.suites.push(suite.to_string());
    }
    if !cfg.components.iter().any(|c| c == component) {
        cfg.components.push(component.to_string());
    }
    if !cfg.architectures.iter().any(|a| a == &m.arch) {
        cfg.architectures.push(m.arch.clone());
    }
    save_config(repo, &cfg)?;

    let mut db = load_db(repo)?;
    db.retain(|e| {
        !(e.name == m.id && e.version == m.version && e.arch == m.arch && e.suite == suite && e.component == component)
    });
    db.push(Entry {
        name: m.id.clone(),
        version: m.version.clone(),
        arch: m.arch.clone(),
        suite: suite.to_string(),
        component: component.to_string(),
        filename,
        size,
        sha256: sha,
        display_name: m.name,
        exec: m.exec,
        caps: m.caps,
        depends: m.depends,
    });
    save_db(repo, &db)?;

    println!("Added {} {} ({}) to {}/{}", m.id, m.version, m.arch, suite, component);
    println!("Run `chancery publish` to update the signed metadata.");
    Ok(())
}

pub fn remove(repo: &Path, name: &str, version: Option<&str>, suite: Option<&str>) -> Result<()> {
    let mut db = load_db(repo)?;
    let matches = |e: &Entry| {
        e.name == name
            && version.map_or(true, |v| e.version == v)
            && suite.map_or(true, |s| e.suite == s)
    };
    let removed: Vec<Entry> = db.iter().filter(|e| matches(e)).cloned().collect();
    db.retain(|e| !matches(e));

    // Delete pool files no longer referenced by any remaining entry.
    for e in &removed {
        if !db.iter().any(|x| x.filename == e.filename) {
            let _ = std::fs::remove_file(repo.join(&e.filename));
        }
    }
    save_db(repo, &db)?;

    if removed.is_empty() {
        println!("No matching packages for '{name}'.");
    } else {
        println!("Removed {} entr{}.", removed.len(), if removed.len() == 1 { "y" } else { "ies" });
        println!("Run `chancery publish` to update the signed metadata.");
    }
    Ok(())
}

pub fn promote(repo: &Path, name: &str, from: &str, to: &str) -> Result<()> {
    let mut cfg = load_config(repo)?;
    let mut db = load_db(repo)?;
    let src: Vec<Entry> = db.iter().filter(|e| e.name == name && e.suite == from).cloned().collect();
    if src.is_empty() {
        bail!("no '{name}' in suite '{from}'");
    }
    if !cfg.suites.iter().any(|s| s == to) {
        cfg.suites.push(to.to_string());
        save_config(repo, &cfg)?;
    }
    for mut e in src {
        e.suite = to.to_string();
        db.retain(|x| {
            !(x.name == e.name && x.version == e.version && x.arch == e.arch && x.suite == e.suite && x.component == e.component)
        });
        db.push(e);
    }
    save_db(repo, &db)?;
    println!("Promoted {name} from {from} to {to}.");
    println!("Run `chancery publish` to update the signed metadata.");
    Ok(())
}

pub fn list(repo: &Path) -> Result<()> {
    let mut db = load_db(repo)?;
    if db.is_empty() {
        println!("(no packages)");
        return Ok(());
    }
    db.sort_by(|a, b| (&a.name, &a.version, &a.suite).cmp(&(&b.name, &b.version, &b.suite)));
    println!("{:<20} {:<12} {:<8} {:<10} {}", "PACKAGE", "VERSION", "ARCH", "SUITE", "COMPONENT");
    for e in &db {
        println!("{:<20} {:<12} {:<8} {:<10} {}", e.name, e.version, e.arch, e.suite, e.component);
    }
    Ok(())
}

pub fn publish(repo: &Path) -> Result<()> {
    let cfg = load_config(repo)?;
    let db = load_db(repo)?;
    let key = sign::load_key(&key_path(repo))?;
    let dists = repo.join("dists");

    let mut total = 0usize;
    for suite in &cfg.suites {
        let sentries: Vec<&Entry> = db.iter().filter(|e| &e.suite == suite).collect();
        // Regenerate this suite from scratch (drops stale Packages files).
        let sdir = dists.join(suite);
        let _ = std::fs::remove_dir_all(&sdir);
        std::fs::create_dir_all(&sdir)?;

        let mut packages_refs: Vec<(String, u64, String)> = vec![];
        for comp in &cfg.components {
            for arch in &cfg.architectures {
                let mut body = String::new();
                let mut any = false;
                for e in sentries.iter().filter(|e| &e.component == comp && &e.arch == arch) {
                    any = true;
                    body.push_str(&packages_stanza(e));
                    body.push('\n');
                }
                if !any {
                    continue;
                }
                let rel = format!("{comp}/binary-{arch}/Packages");
                let full = sdir.join(&rel);
                std::fs::create_dir_all(full.parent().unwrap())?;
                std::fs::write(&full, &body)?;
                packages_refs.push((rel, body.len() as u64, util::sha256_hex(body.as_bytes())));
            }
        }

        let release = build_release(&cfg, suite, &packages_refs);
        std::fs::write(sdir.join("Release"), &release)?;
        std::fs::write(sdir.join("Release.sig"), sign::sign(&key, release.as_bytes()))?;

        println!("Published suite '{}' ({} package entries)", suite, sentries.len());
        total += sentries.len();
    }
    if total == 0 {
        println!("(repository is empty — add packages with `chancery add`)");
    }
    Ok(())
}

pub fn key_export(repo: &Path, header: bool) -> Result<()> {
    let hex = std::fs::read_to_string(repo.join("key.pub"))
        .context("no key.pub — run `chancery init`")?
        .trim()
        .to_string();
    if !header {
        println!("{hex}");
        return Ok(());
    }
    let bytes = util::unhex(&hex)?;
    if bytes.len() != 65 {
        bail!("public key is {} bytes, expected 65", bytes.len());
    }
    println!("/* GENERATED by `chancery key --header` — repository trust anchor. */");
    println!("#ifndef HERALD_TRUSTED_KEY_H");
    println!("#define HERALD_TRUSTED_KEY_H");
    println!("static const unsigned char herald_trusted_key[65] = {{");
    let mut line = String::from("    ");
    for (i, b) in bytes.iter().enumerate() {
        line.push_str(&format!("0x{b:02x},"));
        if (i + 1) % 12 == 0 {
            println!("{line}");
            line = String::from("    ");
        }
    }
    if line.trim_end() != "" {
        println!("{line}");
    }
    println!("}};");
    println!("#endif");
    Ok(())
}

// ── metadata rendering (Debian-style) ─────────────────────────────────────

fn packages_stanza(e: &Entry) -> String {
    let mut s = String::new();
    s.push_str(&format!("Package: {}\n", e.name));
    s.push_str(&format!("Version: {}\n", e.version));
    s.push_str(&format!("Architecture: {}\n", e.arch));
    if !e.depends.is_empty() {
        s.push_str(&format!("Depends: {}\n", e.depends));
    }
    s.push_str(&format!("Filename: {}\n", e.filename));
    s.push_str(&format!("Size: {}\n", e.size));
    s.push_str(&format!("SHA256: {}\n", e.sha256));
    s.push_str(&format!("Display-Name: {}\n", e.display_name));
    s.push_str(&format!("Exec: {}\n", e.exec));
    if !e.caps.is_empty() {
        s.push_str(&format!("Caps: {}\n", e.caps));
    }
    s
}

fn build_release(cfg: &Config, suite: &str, packages: &[(String, u64, String)]) -> String {
    let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S UTC").to_string();
    let mut s = String::new();
    s.push_str(&format!("Origin: {}\n", cfg.origin));
    s.push_str(&format!("Suite: {suite}\n"));
    s.push_str(&format!("Codename: {suite}\n"));
    s.push_str(&format!("Architectures: {}\n", cfg.architectures.join(" ")));
    s.push_str(&format!("Components: {}\n", cfg.components.join(" ")));
    s.push_str(&format!("Date: {date}\n"));
    s.push_str("SHA256:\n");
    for (rel, size, sha) in packages {
        s.push_str(&format!(" {sha} {size} {rel}\n"));
    }
    s
}
