# Chancery

A Debian-style **signed package repository manager** for Aegis/herald. Chancery
produces a static, signed repository tree that any web server (nginx, Caddy, S3,
GitHub Pages, …) can host, and that herald clients verify with a single pinned
public key.

The trust chain mirrors Debian: one ECDSA-P256/SHA-256 signature over `Release`,
which pins the SHA-256 of each `Packages` file, which pins the SHA-256 of each
package. Verify the `Release` signature and the whole tree is authenticated.

## Install

```sh
cargo install --path .
```

## Workflow

```sh
# 1. Create a repository (generates a P-256 signing key under .chancery/)
chancery -C /srv/repo init --origin "Aegis Repository"

# 2. Add packages to a suite/component (default: stable/main)
chancery -C /srv/repo add ./foo_1.0_x86_64.hpkg
chancery -C /srv/repo add ./bar_2.1_x86_64.hpkg --suite testing

# 3. Regenerate and sign all Packages + Release metadata
chancery -C /srv/repo publish

# 4. Serve locally for testing (binds 127.0.0.1 by default)
chancery -C /srv/repo serve --port 8000
#   ...or expose on the network explicitly:
chancery -C /srv/repo serve --bind 0.0.0.0 --port 8000

# 5. Export the trust anchor for clients
chancery -C /srv/repo key              # hex public point
chancery -C /srv/repo key --header     # C header for herald (trusted_key.h)
```

Other commands: `chancery list`, `chancery remove <id> [--version V] [--suite S]`,
`chancery promote <id> <from-suite> <to-suite>`.

## On-disk layout

```
<repo>/
  .chancery/                                      # private, 0700, never served
    config.toml                                   # origin, suites, components, arches
    signing.key                                   # raw 32-byte P-256 scalar (hex), 0600
    db.json                                       # the package index
  key.pub                                         # public trust anchor (hex point)
  pool/<p>/<name>/<name>_<version>_<arch>.hpkg    # the packages
  dists/<suite>/
    Release                                       # signed metadata
    Release.sig                                   # detached ECDSA-P256/SHA-256 over Release
    <component>/binary-<arch>/Packages
```

## Security notes

- The signing key (`.chancery/signing.key`) is written `0600` and the control
  directory `0700`; keep `.chancery/` out of the served tree (the bundled dev
  server refuses to serve it and rejects any path that resolves outside the repo
  root, including via symlinks).
- Package manifests are untrusted input: `id`, `version`, and `arch` are
  validated against a strict charset before being used in pool paths, and all
  metadata fields are rejected if they contain control characters, so a hostile
  `.hpkg` cannot escape the pool or inject fields into the signed `Packages`.
- State files (`db.json`, `config.toml`, `Packages`, `Release`) are written
  atomically (temp file + rename); `publish` builds each suite in a temp
  directory and swaps it in, so an interrupted run never serves half-written or
  unsigned metadata.

## Package format

A `.hpkg` is an uncompressed ustar archive containing a `manifest` file of
`key=value` lines:

```
id=foo
name=Foo
version=1.0
exec=/usr/bin/foo
arch=x86_64        # optional, defaults to x86_64
caps=net           # optional
depends=bar        # optional
```

## License

Licensed under either of MIT or Apache-2.0 at your option.
