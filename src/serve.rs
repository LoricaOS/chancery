//! A minimal static file server for local testing. Production deployments serve
//! the repo tree with any web server (nginx, Caddy, S3, GitHub Pages, …).

use anyhow::{anyhow, Result};
use std::path::Path;
use tiny_http::{Response, Server};

pub fn serve(repo: &Path, bind: &str, port: u16) -> Result<()> {
    let root = repo
        .canonicalize()
        .map_err(|e| anyhow!("cannot open repo {}: {e}", repo.display()))?;
    let control = root.join(".chancery");
    let server = Server::http((bind, port)).map_err(|e| anyhow!("bind {bind}:{port}: {e}"))?;
    println!(
        "chancery: serving {} on http://{bind}:{port}",
        root.display()
    );
    println!("(dev server — use a real web server in production)");

    for req in server.incoming_requests() {
        let url = req.url().split('?').next().unwrap_or("/").to_string();
        let rel = url.trim_start_matches('/');

        // Resolve the request to a real path and require it to stay inside the
        // repo root and outside .chancery. canonicalize() resolves `..` and
        // follows symlinks, so this also blocks symlink-escape, not just `..`.
        let resolved = root.join(rel).canonicalize();
        let ok = match &resolved {
            Ok(p) => p.starts_with(&root) && !p.starts_with(&control) && p.is_file(),
            Err(_) => false,
        };
        if !ok {
            // 403 for anything that resolves outside the allowed tree; 404 for
            // paths that simply don't exist.
            let outside =
                matches!(&resolved, Ok(p) if !p.starts_with(&root) || p.starts_with(&control));
            let (code, msg) = if outside {
                (403, "forbidden")
            } else {
                (404, "not found")
            };
            let _ = req.respond(Response::from_string(msg).with_status_code(code));
            continue;
        }
        match std::fs::File::open(resolved.unwrap()) {
            Ok(f) => {
                let _ = req.respond(Response::from_file(f));
            }
            Err(_) => {
                let _ = req.respond(Response::from_string("not found").with_status_code(404));
            }
        }
    }
    Ok(())
}
