#!/usr/bin/env python3
"""Tests for registry_src_dirs.py. Run: python3 -I tools/test_registry_src_dirs.py"""

import importlib.util
import json
import os
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("registry_src_dirs", os.path.join(_HERE, "registry_src_dirs.py"))
rs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rs)

REG = "/home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f"


def pkg(name, version, source, manifest_path):
    return {"name": name, "version": version, "source": source, "manifest_path": manifest_path}


class RegistrySrcDirs(unittest.TestCase):
    def test_one_dir_per_registry(self):
        meta = {"packages": [
            pkg("ring", "0.17.14", "registry+https://github.com/rust-lang/crates.io-index", f"{REG}/ring-0.17.14/Cargo.toml"),
            pkg("rustls", "0.23.46", "registry+https://github.com/rust-lang/crates.io-index", f"{REG}/rustls-0.23.46/Cargo.toml"),
            pkg("other", "1.0.0", "sparse+https://example.test/index/", "/c/registry/src/example.test-0123/other-1.0.0/Cargo.toml"),
        ]}
        self.assertEqual(rs.registry_src_dirs(meta), ["/c/registry/src/example.test-0123", REG])

    def test_workspace_path_and_git_packages_are_left_alone(self):
        meta = {"packages": [
            pkg("velmora-bridge", "0.1.0", None, "/w/crates/velmora-bridge/Cargo.toml"),
            pkg("dep", "0.1.0", "git+https://example.test/dep#abc", "/c/git/checkouts/dep-1/abc/Cargo.toml"),
        ]}
        self.assertEqual(rs.registry_src_dirs(meta), [])

    def test_unexpected_layout_is_left_alone(self):
        meta = {"packages": [pkg("ring", "0.17.14", "registry+x", f"{REG}/vendored/ring/Cargo.toml")]}
        self.assertEqual(rs.registry_src_dirs(meta), [])

    def test_flags(self):
        self.assertEqual(rs.flags([REG]), f" --remap-path-prefix={REG}=crates.io")
        self.assertEqual(rs.flags([]), "")

    def test_whitespace_or_equals_is_not_remapped(self):
        warned = []
        self.assertEqual(rs.flags(["/a b/src/x", "/a=b/src/x", REG], warned.append), f" --remap-path-prefix={REG}=crates.io")
        self.assertEqual(len(warned), 2)

    def test_cli(self):
        meta = {"packages": [pkg("ring", "0.17.14", "registry+x", f"{REG}/ring-0.17.14/Cargo.toml")]}
        out = subprocess.run(
            [sys.executable, "-I", os.path.join(_HERE, "registry_src_dirs.py")],
            input=json.dumps(meta), capture_output=True, text=True, check=True,
        )
        self.assertEqual(out.stdout, f" --remap-path-prefix={REG}=crates.io")
        self.assertEqual(out.stderr, "")


if __name__ == "__main__":
    unittest.main()
