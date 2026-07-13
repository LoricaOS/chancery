//! Chancery — a Debian-style signed package repository manager for Aegis/herald.
//!
//! Produces a static, signed repository tree that any web server can host:
//!
//!   <repo>/
//!     .chancery/{config.toml, signing.key, db.json}   (private; not served)
//!     key.pub                                          (public trust anchor)
//!     pool/<p>/<name>/<name>_<version>_<arch>.hpkg     (the packages)
//!     dists/<suite>/
//!       Release        (signed: suites, components, archs, sha256 of each Packages)
//!       Release.sig     (detached ECDSA-P256/SHA-256 over Release)
//!       <component>/binary-<arch>/Packages
//!
//! The trust chain mirrors Debian: one signature over Release, which pins the
//! Packages hashes, which pin the package hashes.

mod pkg;
mod repo;
mod serve;
mod sign;
mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "chancery",
    version,
    about = "Debian-style signed repo manager for herald"
)]
struct Cli {
    /// Repository directory (default: current directory)
    #[arg(short = 'C', long, global = true, default_value = ".")]
    repo: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new repository (generates a signing key)
    Init {
        /// Human-readable origin name recorded in Release
        #[arg(long, default_value = "Aegis Repository")]
        origin: String,
        /// Use an existing P-256 key (PEM or 64-char hex scalar) instead of generating one
        #[arg(long)]
        import_key: Option<PathBuf>,
    },
    /// Add a .hpkg package to a suite/component
    Add {
        /// Path to the .hpkg package to add
        package: PathBuf,
        #[arg(long, default_value = "stable")]
        suite: String,
        #[arg(long, default_value = "main")]
        component: String,
    },
    /// Remove a package (all versions, or a specific one)
    Remove {
        /// Package id to remove
        name: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        suite: Option<String>,
    },
    /// Copy a package's membership from one suite to another
    Promote {
        /// Package id to promote
        name: String,
        /// Source suite
        from: String,
        /// Destination suite
        to: String,
    },
    /// Regenerate and sign all Packages + Release metadata
    Publish,
    /// List packages in the repository
    List,
    /// Print/export the public trust anchor (hex, or a C header for herald)
    Key {
        /// Emit a C header (trusted_key.h) instead of hex
        #[arg(long)]
        header: bool,
    },
    /// Serve the repository over HTTP for local testing
    Serve {
        #[arg(long, default_value_t = 8000)]
        port: u16,
        /// Address to bind (use 0.0.0.0 to expose on the network)
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { origin, import_key } => repo::init(&cli.repo, &origin, import_key.as_deref()),
        Cmd::Add {
            package,
            suite,
            component,
        } => repo::add(&cli.repo, &package, &suite, &component),
        Cmd::Remove {
            name,
            version,
            suite,
        } => repo::remove(&cli.repo, &name, version.as_deref(), suite.as_deref()),
        Cmd::Promote { name, from, to } => repo::promote(&cli.repo, &name, &from, &to),
        Cmd::Publish => repo::publish(&cli.repo),
        Cmd::List => repo::list(&cli.repo),
        Cmd::Key { header } => repo::key_export(&cli.repo, header),
        Cmd::Serve { port, bind } => serve::serve(&cli.repo, &bind, port),
    }
}
