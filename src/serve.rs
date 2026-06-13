//! A minimal static file server for local testing. Production deployments serve
//! the repo tree with any web server (nginx, Caddy, S3, GitHub Pages, …).

use anyhow::{anyhow, Result};
use std::path::Path;
use tiny_http::{Response, Server};

pub fn serve(repo: &Path, port: u16) -> Result<()> {
    let root = repo
        .canonicalize()
        .map_err(|e| anyhow!("cannot open repo {}: {e}", repo.display()))?;
    let server = Server::http(("0.0.0.0", port)).map_err(|e| anyhow!("bind :{port}: {e}"))?;
    println!("chancery: serving {} on http://0.0.0.0:{port}", root.display());
    println!("(dev server — use a real web server in production)");

    for req in server.incoming_requests() {
        let url = req.url().split('?').next().unwrap_or("/").to_string();
        let rel = url.trim_start_matches('/');

        // Never serve the private control dir; reject traversal.
        if rel.contains("..") || rel.split('/').next() == Some(".chancery") {
            let _ = req.respond(Response::from_string("forbidden").with_status_code(403));
            continue;
        }
        let path = root.join(rel);
        match std::fs::File::open(&path) {
            Ok(f) if path.is_file() => {
                let _ = req.respond(Response::from_file(f));
            }
            _ => {
                let _ = req.respond(Response::from_string("not found").with_status_code(404));
            }
        }
    }
    Ok(())
}
