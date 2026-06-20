//! Repository layout, on-disk state, and the management commands.

use crate::{pkg, sign, util};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const CONTROL_DIR: &str = ".chancery";
const POOL_DIR: &str = "pool";
const DISTS_DIR: &str = "dists";
const PUBKEY_FILE: &str = "key.pub";
const DEFAULT_SUITE: &str = "stable";
const DEFAULT_COMPONENT: &str = "main";
const DEFAULT_ARCH: &str = "x86_64";
/// Length of an uncompressed P-256 public point (0x04 || X || Y).
const PUBKEY_LEN: usize = 65;

#[derive(Serialize, Deserialize)]
struct Config {
    origin: String,
    suites: Vec<String>,
    components: Vec<String>,
    architectures: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    /// The manifest `id` (the package's stable identifier).
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

impl Entry {
    /// Two entries occupy the same "slot" (and so supersede each other) when
    /// they share id, version, arch, suite, and component.
    fn same_slot(&self, o: &Entry) -> bool {
        self.name == o.name
            && self.version == o.version
            && self.arch == o.arch
            && self.suite == o.suite
            && self.component == o.component
    }
}

fn chancery_dir(repo: &Path) -> PathBuf {
    repo.join(CONTROL_DIR)
}
fn config_path(repo: &Path) -> PathBuf {
    chancery_dir(repo).join("config.toml")
}
fn db_path(repo: &Path) -> PathBuf {
    chancery_dir(repo).join("db.json")
}
fn key_path(repo: &Path) -> PathBuf {
    chancery_dir(repo).join("signing.key")
}
fn pubkey_path(repo: &Path) -> PathBuf {
    repo.join(PUBKEY_FILE)
}

// ── filesystem helpers ─────────────────────────────────────────────────────

/// Atomically replace a file: write to a sibling temp file, then rename over the
/// target (atomic on POSIX). Prevents a truncated/partial file on interruption.
fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("path has no file name: {}", path.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    std::fs::write(&tmp, contents).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// `remove_dir_all` that treats a missing directory as success but surfaces any
/// other error (instead of silently swallowing it).
fn remove_dir_all_if_exists(p: &Path) -> Result<()> {
    match std::fs::remove_dir_all(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", p.display())),
    }
}

/// Create a directory tree owner-only (`0700`) — used for `.chancery/`, which
/// holds the private signing key.
fn create_private_dir(path: &Path) -> Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
        .with_context(|| format!("creating {}", path.display()))
}

// ── config / db persistence ────────────────────────────────────────────────

fn load_config(repo: &Path) -> Result<Config> {
    let s = std::fs::read_to_string(config_path(repo))
        .context("not a chancery repository (no .chancery/config.toml) — run `chancery init`")?;
    Ok(toml::from_str(&s)?)
}
fn save_config(repo: &Path, c: &Config) -> Result<()> {
    write_atomic(&config_path(repo), toml::to_string_pretty(c)?.as_bytes())
}
fn load_db(repo: &Path) -> Result<Vec<Entry>> {
    let p = db_path(repo);
    if !p.exists() {
        return Ok(vec![]);
    }
    Ok(serde_json::from_str(&std::fs::read_to_string(p)?)?)
}
fn save_db(repo: &Path, db: &[Entry]) -> Result<()> {
    write_atomic(&db_path(repo), serde_json::to_string_pretty(db)?.as_bytes())
}

fn pool_path(name: &str, version: &str, arch: &str) -> String {
    let prefix = name.chars().next().unwrap_or('_').to_ascii_lowercase();
    format!("{POOL_DIR}/{prefix}/{name}/{name}_{version}_{arch}.hpkg")
}

// ── commands ────────────────────────────────────────────────────────────

pub fn init(repo: &Path, origin: &str, import_key: Option<&Path>) -> Result<()> {
    if config_path(repo).exists() {
        bail!("repository already initialized at {}", repo.display());
    }
    create_private_dir(&chancery_dir(repo))?;
    std::fs::create_dir_all(repo.join(POOL_DIR))?;
    std::fs::create_dir_all(repo.join(DISTS_DIR))?;

    let key = match import_key {
        Some(p) => sign::import(p)?,
        None => sign::generate(),
    };
    sign::save_key(&key, &key_path(repo))?;
    write_atomic(
        &pubkey_path(repo),
        format!("{}\n", util::hex(&sign::public_point(&key))).as_bytes(),
    )?;

    let cfg = Config {
        origin: origin.to_string(),
        suites: vec![DEFAULT_SUITE.into()],
        components: vec![DEFAULT_COMPONENT.into()],
        architectures: vec![DEFAULT_ARCH.into()],
    };
    save_config(repo, &cfg)?;
    save_db(repo, &[])?;

    println!("Initialized chancery repository at {}", repo.display());
    println!("  signing key:  {}", key_path(repo).display());
    println!(
        "  trust anchor: {} (give this to clients)",
        pubkey_path(repo).display()
    );
    println!("Next: `chancery add <pkg.hpkg>` then `chancery publish`.");
    Ok(())
}

pub fn add(repo: &Path, hpkg: &Path, suite: &str, component: &str) -> Result<()> {
    util::validate_field("suite", suite)?;
    util::validate_field("component", component)?;

    let mut cfg = load_config(repo)?;
    let m = pkg::read_manifest(hpkg)?;
    let data = std::fs::read(hpkg).with_context(|| format!("reading {}", hpkg.display()))?;
    let sha = util::sha256_hex(&data);
    let size = data.len() as u64;

    let filename = pool_path(&m.id, &m.version, &m.arch);
    let dest = repo.join(&filename);
    // Belt-and-suspenders: manifest fields are validated, but never let a pool
    // path escape the pool/ directory.
    if !dest.starts_with(repo.join(POOL_DIR)) {
        bail!(
            "refusing to write package outside the pool: {}",
            dest.display()
        );
    }
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow!("pool path has no parent: {}", dest.display()))?;
    std::fs::create_dir_all(parent)?;
    write_atomic(&dest, &data)?;

    let mut db = load_db(repo)?;
    let new = Entry {
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
    };
    db.retain(|e| !e.same_slot(&new));
    db.push(new);
    // Persist the index before mutating config so the DB is the source of truth.
    save_db(repo, &db)?;

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

    println!(
        "Added {} {} ({}) to {}/{}",
        m.id, m.version, m.arch, suite, component
    );
    println!("Run `chancery publish` to update the signed metadata.");
    Ok(())
}

pub fn remove(repo: &Path, name: &str, version: Option<&str>, suite: Option<&str>) -> Result<()> {
    let mut db = load_db(repo)?;
    let matches = |e: &Entry| {
        e.name == name
            && version.is_none_or(|v| e.version == v)
            && suite.is_none_or(|s| e.suite == s)
    };
    let removed: Vec<Entry> = db.iter().filter(|e| matches(e)).cloned().collect();
    db.retain(|e| !matches(e));

    // Persist the index first: a leaked pool file is far safer than a dangling
    // index reference to a file we already deleted.
    save_db(repo, &db)?;

    // Delete pool files no longer referenced by any remaining entry.
    for e in &removed {
        if !db.iter().any(|x| x.filename == e.filename) {
            let p = repo.join(&e.filename);
            if let Err(err) = std::fs::remove_file(&p) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("warning: could not delete {}: {err}", p.display());
                }
            }
        }
    }

    if removed.is_empty() {
        println!("No matching packages for '{name}'.");
    } else {
        println!(
            "Removed {} entr{}.",
            removed.len(),
            if removed.len() == 1 { "y" } else { "ies" }
        );
        println!("Run `chancery publish` to update the signed metadata.");
    }
    Ok(())
}

pub fn promote(repo: &Path, name: &str, from: &str, to: &str) -> Result<()> {
    util::validate_field("suite", to)?;
    let mut cfg = load_config(repo)?;
    let mut db = load_db(repo)?;
    let src: Vec<Entry> = db
        .iter()
        .filter(|e| e.name == name && e.suite == from)
        .cloned()
        .collect();
    if src.is_empty() {
        bail!("no '{name}' in suite '{from}'");
    }
    for mut e in src {
        e.suite = to.to_string();
        db.retain(|x| !x.same_slot(&e));
        db.push(e);
    }
    save_db(repo, &db)?;

    if !cfg.suites.iter().any(|s| s == to) {
        cfg.suites.push(to.to_string());
        save_config(repo, &cfg)?;
    }
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
    db.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| util::version_cmp(&a.version, &b.version))
            .then_with(|| a.suite.cmp(&b.suite))
    });
    println!(
        "{:<20} {:<12} {:<8} {:<10} COMPONENT",
        "PACKAGE", "VERSION", "ARCH", "SUITE"
    );
    for e in &db {
        println!(
            "{:<20} {:<12} {:<8} {:<10} {}",
            e.name, e.version, e.arch, e.suite, e.component
        );
    }
    Ok(())
}

pub fn publish(repo: &Path) -> Result<()> {
    let cfg = load_config(repo)?;
    let db = load_db(repo)?;
    let key = sign::load_key(&key_path(repo))?;
    let dists = repo.join(DISTS_DIR);
    // One timestamp for the whole run, so all suites are internally consistent.
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S UTC")
        .to_string();

    let mut total = 0usize;
    for suite in &cfg.suites {
        let sentries: Vec<&Entry> = db.iter().filter(|e| &e.suite == suite).collect();

        // Build the suite into a temp dir, sign it, then atomically swap it in,
        // so a crash mid-publish never serves a half-written or unsigned suite.
        let sdir = dists.join(suite);
        let tmp = dists.join(format!(".{suite}.tmp.{}", std::process::id()));
        remove_dir_all_if_exists(&tmp)?;
        std::fs::create_dir_all(&tmp)?;

        let mut packages_refs: Vec<(String, u64, String)> = vec![];
        for comp in &cfg.components {
            for arch in &cfg.architectures {
                let mut body = String::new();
                let mut any = false;
                for e in sentries
                    .iter()
                    .filter(|e| &e.component == comp && &e.arch == arch)
                {
                    any = true;
                    body.push_str(&packages_stanza(e));
                    body.push('\n');
                }
                if !any {
                    continue;
                }
                let rel = format!("{comp}/binary-{arch}/Packages");
                let full = tmp.join(&rel);
                let parent = full
                    .parent()
                    .ok_or_else(|| anyhow!("bad Packages path: {}", full.display()))?;
                std::fs::create_dir_all(parent)?;
                std::fs::write(&full, &body)?;
                packages_refs.push((rel, body.len() as u64, util::sha256_hex(body.as_bytes())));
            }
        }

        let release = build_release(&cfg, suite, &packages_refs, &date);
        std::fs::write(tmp.join("Release"), &release)?;
        std::fs::write(
            tmp.join("Release.sig"),
            sign::sign(&key, release.as_bytes()),
        )?;

        remove_dir_all_if_exists(&sdir)?;
        std::fs::rename(&tmp, &sdir)
            .with_context(|| format!("installing suite {}", sdir.display()))?;

        println!(
            "Published suite '{}' ({} package entries)",
            suite,
            sentries.len()
        );
        total += sentries.len();
    }
    if total == 0 {
        println!("(repository is empty — add packages with `chancery add`)");
    }
    Ok(())
}

pub fn key_export(repo: &Path, header: bool) -> Result<()> {
    let hex = std::fs::read_to_string(pubkey_path(repo))
        .context("no key.pub — run `chancery init`")?
        .trim()
        .to_string();
    if !header {
        println!("{hex}");
        return Ok(());
    }
    let bytes = util::unhex(&hex)?;
    if bytes.len() != PUBKEY_LEN {
        bail!("public key is {} bytes, expected {PUBKEY_LEN}", bytes.len());
    }
    println!("/* GENERATED by `chancery key --header` — repository trust anchor. */");
    println!("#ifndef HERALD_TRUSTED_KEY_H");
    println!("#define HERALD_TRUSTED_KEY_H");
    println!("static const unsigned char herald_trusted_key[{PUBKEY_LEN}] = {{");
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
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Package: {}", e.name);
    let _ = writeln!(s, "Version: {}", e.version);
    let _ = writeln!(s, "Architecture: {}", e.arch);
    if !e.depends.is_empty() {
        let _ = writeln!(s, "Depends: {}", e.depends);
    }
    let _ = writeln!(s, "Filename: {}", e.filename);
    let _ = writeln!(s, "Size: {}", e.size);
    let _ = writeln!(s, "SHA256: {}", e.sha256);
    let _ = writeln!(s, "Display-Name: {}", e.display_name);
    let _ = writeln!(s, "Exec: {}", e.exec);
    if !e.caps.is_empty() {
        let _ = writeln!(s, "Caps: {}", e.caps);
    }
    s
}

fn build_release(
    cfg: &Config,
    suite: &str,
    packages: &[(String, u64, String)],
    date: &str,
) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "Origin: {}", cfg.origin);
    let _ = writeln!(s, "Suite: {suite}");
    let _ = writeln!(s, "Codename: {suite}");
    let _ = writeln!(s, "Architectures: {}", cfg.architectures.join(" "));
    let _ = writeln!(s, "Components: {}", cfg.components.join(" "));
    let _ = writeln!(s, "Date: {date}");
    s.push_str("SHA256:\n");
    for (rel, size, sha) in packages {
        let _ = writeln!(s, " {sha} {size} {rel}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            name: "foo".into(),
            version: "1.0".into(),
            arch: "x86_64".into(),
            suite: "stable".into(),
            component: "main".into(),
            filename: "pool/f/foo/foo_1.0_x86_64.hpkg".into(),
            size: 42,
            sha256: "deadbeef".into(),
            display_name: "Foo".into(),
            exec: "/usr/bin/foo".into(),
            caps: String::new(),
            depends: String::new(),
        }
    }

    #[test]
    fn pool_path_is_buckets() {
        assert_eq!(
            pool_path("foo", "1.0", "x86_64"),
            "pool/f/foo/foo_1.0_x86_64.hpkg"
        );
    }

    #[test]
    fn packages_stanza_omits_empty_optional_fields() {
        let s = packages_stanza(&entry());
        assert!(s.contains("Package: foo\n"));
        assert!(s.contains("SHA256: deadbeef\n"));
        assert!(!s.contains("Depends:"));
        assert!(!s.contains("Caps:"));
    }

    #[test]
    fn build_release_is_deterministic_given_date() {
        let cfg = Config {
            origin: "Test".into(),
            suites: vec!["stable".into()],
            components: vec!["main".into()],
            architectures: vec!["x86_64".into()],
        };
        let pkgs = vec![(
            "main/binary-x86_64/Packages".to_string(),
            10u64,
            "abcd".to_string(),
        )];
        let date = "Mon, 01 Jan 2024 00:00:00 UTC";
        let a = build_release(&cfg, "stable", &pkgs, date);
        let b = build_release(&cfg, "stable", &pkgs, date);
        assert_eq!(a, b);
        assert!(a.contains("Date: Mon, 01 Jan 2024 00:00:00 UTC\n"));
        assert!(a.contains(" abcd 10 main/binary-x86_64/Packages\n"));
    }
}
