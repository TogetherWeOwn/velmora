#!/usr/bin/env python3
"""Prints rustc flags that remap registry source directories to `crates.io`.

Reads `cargo metadata --format-version 1` on stdin. A package from a
registry has its manifest at `<registry src dir>/<name>-<version>/Cargo.toml`;
each distinct `<registry src dir>` (for crates.io
`$CARGO_HOME/registry/src/index.crates.io-<hash>`) gets one
` --remap-path-prefix=<dir>=crates.io`, printed on one line for
bundle.sh to append to RUSTFLAGS. The panic locations in the wasm then
name `crates.io/<name>-<version>/src/..` instead of the build host's path.

RUSTFLAGS is split on whitespace, so a directory with whitespace (or an
`=`, which would end the prefix early) is not remapped: it is reported
on stderr and left out. Only the size of the wasm changes in that case.
Workspace and path packages are never remapped (their paths are already
relative to the workspace).
"""

import json
import os
import sys


def registry_src_dirs(metadata):
    dirs = set()
    for pkg in metadata.get("packages", []):
        source = pkg.get("source") or ""
        if not (source.startswith("registry+") or source.startswith("sparse+")):
            continue
        pkg_dir = os.path.dirname(pkg["manifest_path"])
        if os.path.basename(pkg_dir) != f"{pkg['name']}-{pkg['version']}":
            continue
        dirs.add(os.path.dirname(pkg_dir))
    return sorted(dirs)


def flags(dirs, warn=lambda msg: None):
    out = []
    for d in dirs:
        if not d or any(c.isspace() for c in d) or "=" in d:
            warn(f"registry_src_dirs: not remapped (whitespace or '='): {d!r}")
            continue
        out.append(f" --remap-path-prefix={d}=crates.io")
    return "".join(out)


def main():
    metadata = json.load(sys.stdin)
    sys.stdout.write(flags(registry_src_dirs(metadata), lambda m: print(m, file=sys.stderr)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
