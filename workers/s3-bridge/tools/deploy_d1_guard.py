#!/usr/bin/env python3
"""Print whether CI may apply remote D1 migrations, or fail before deploy."""

from hashlib import file_digest, sha256
import json
from pathlib import Path
import sys
import tomllib


MANIFEST = Path(__file__).with_name("d1-frozen-migrations.sha256")


def frozen_directory(config_path, catalog):
    # Wrangler 4 uses the config's directory and defaults to ./migrations.
    # Only inspect relative paths inside the Worker checkout, not host files.
    raw_dir = catalog.get("migrations_dir", "migrations")
    if not isinstance(raw_dir, str) or not raw_dir or "\0" in raw_dir:
        sys.exit("D1 deploy guard: invalid migrations_dir")
    relative = Path(raw_dir.replace("\\", "/"))
    root = config_path.parent.resolve()
    if relative.is_absolute() or ".." in relative.parts:
        sys.exit("D1 deploy guard: migrations_dir must be inside the Worker directory")
    directory = (root / relative).resolve()
    if not directory.is_relative_to(root):
        sys.exit("D1 deploy guard: migrations_dir must be inside the Worker directory")
    return directory


def check_frozen(directory, frozen_at, manifest_sha256):
    try:
        raw = MANIFEST.read_bytes()
    except OSError:
        sys.exit("D1 deploy guard: cannot read frozen D1 manifest")
    if sha256(raw).hexdigest() != manifest_sha256:
        sys.exit("D1 deploy guard: frozen D1 manifest checksum does not match")
    expected = {name: digest for digest, name in
                (line.split("  ", 1) for line in raw.decode("ascii").splitlines())}
    try:
        actual = {path.name: path for path in directory.iterdir()}
        changed = []
        for name in expected.keys() & actual.keys():
            path = actual[name]
            if path.is_symlink() or not path.is_file():
                changed.append(name)
                continue
            with path.open("rb") as sql:
                if file_digest(sql, "sha256").hexdigest() != expected[name]:
                    changed.append(name)
    except OSError:
        sys.exit("D1 deploy guard: cannot read D1 migrations directory or files")

    differences = []
    for kind, names in (("added", actual.keys() - expected.keys()),
                        ("removed", expected.keys() - actual.keys()), ("changed", changed)):
        if names:
            quoted = ", ".join(json.dumps(name) for name in sorted(names))
            differences.append(f"{kind}: {quoted}")
    if differences:
        sys.exit(f"D1 deploy guard: frozen D1 migrations differ from {frozen_at}: " + "; ".join(differences))


def should_apply(config_path, frozen_at, manifest_sha256):
    try:
        with config_path.open("rb") as config_file:
            config = tomllib.load(config_file)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        sys.exit("D1 deploy guard: cannot read rendered Wrangler config as TOML")

    if config.get("keep_vars", False) is not False:
        sys.exit("D1 deploy guard: keep_vars must be disabled")
    variables = config.get("vars", {})
    if not isinstance(variables, dict):
        sys.exit("D1 deploy guard: rendered vars must be a table")
    if "CATALOG_BACKEND" not in variables:
        sys.exit("D1 deploy guard: rendered CATALOG_BACKEND must be explicit")
    backend = variables["CATALOG_BACKEND"]
    if backend not in ("d1", "d1-frozen", "pg", "pg-frozen"):
        sys.exit("D1 deploy guard: invalid CATALOG_BACKEND in rendered vars")

    # Match Wrangler's name-or-binding lookup for the CLI argument CATALOG.
    bindings = config.get("d1_databases", [])
    if not isinstance(bindings, list) or not all(isinstance(item, dict) for item in bindings):
        sys.exit("D1 deploy guard: invalid d1_databases in rendered config")
    matches = [item for item in bindings if "CATALOG" in (item.get("binding"), item.get("database_name"))]
    if len(matches) != 1 or matches[0].get("binding") != "CATALOG":
        sys.exit("D1 deploy guard: expected one unambiguous CATALOG D1 binding")
    if backend == "d1":
        return True
    check_frozen(frozen_directory(config_path, matches[0]), frozen_at, manifest_sha256)
    return False


if __name__ == "__main__":
    _, config, frozen_at, manifest_sha256 = sys.argv
    print("true" if should_apply(Path(config), frozen_at, manifest_sha256) else "false")
