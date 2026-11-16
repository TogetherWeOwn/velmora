#!/usr/bin/env python3
"""Tests for strip_wasm.py. Run: python3 -I tools/test_strip_wasm.py"""

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("strip_wasm", os.path.join(_HERE, "strip_wasm.py"))
sw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sw)

HEADER = b"\x00asm\x01\x00\x00\x00"


def leb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def section(sid, body):
    return bytes([sid]) + leb(len(body)) + body


def custom(name, payload):
    raw = name.encode()
    return section(0, leb(len(raw)) + raw + payload)


# A minimal valid module: one type, one function, its code.
TYPE = section(1, b"\x01\x60\x00\x00")
FUNC = section(3, b"\x01\x00")
CODE = section(10, b"\x01\x02\x00\x0b")
NAME = custom("name", b"\x01\x05\x01\x00\x02hi")
PRODUCERS = custom("producers", b"\x00" * 200)  # multi-byte size LEB
TARGET = custom("target_features", b"\x01+\x0bbulk-memory")


class StripTest(unittest.TestCase):
    def test_drops_name_keeps_the_rest_byte_for_byte(self):
        mod = HEADER + TYPE + FUNC + CODE + NAME + PRODUCERS + TARGET
        out, dropped = sw.strip(mod)
        self.assertEqual(out, HEADER + TYPE + FUNC + CODE + PRODUCERS + TARGET)
        self.assertEqual(dropped, [("name", len(NAME))])

    def test_refuses_name_before_code(self):
        # Dropping it would shift every code offset against the symbols copy.
        with self.assertRaises(sw.WasmError):
            sw.strip(HEADER + TYPE + FUNC + NAME + CODE)

    def test_drops_every_name_section(self):
        out, dropped = sw.strip(HEADER + CODE + NAME + NAME)
        self.assertEqual(out, HEADER + CODE)
        self.assertEqual(len(dropped), 2)

    def test_empty_custom_section_and_padded_sizes(self):
        empty = custom("", b"")
        padded = b"\x0a\x84\x80\x00" + CODE[2:]  # size 4 as a 3-byte LEB
        mod = HEADER + TYPE + FUNC + padded + empty
        self.assertEqual(sw.strip(mod + NAME)[0], mod)

    def test_idempotent(self):
        mod = HEADER + TYPE + FUNC + CODE + NAME
        once, _ = sw.strip(mod)
        twice, dropped = sw.strip(once)
        self.assertEqual(once, twice)
        self.assertEqual(dropped, [])

    def test_keeps_other_custom_sections(self):
        other = custom("namex", b"x")
        mod = HEADER + other + CODE
        self.assertEqual(sw.strip(mod)[0], mod)

    def test_rejects_malformed(self):
        for bad in (
            b"\x00asx\x01\x00\x00\x00",           # wrong magic
            b"\x00asm\x02\x00\x00\x00",           # wrong version
            HEADER + b"\x0a\x05\x00",             # section past the end
            HEADER + b"\x00\x03\x09ab",           # name past the section
            HEADER + b"\x0a\x80\x80\x80\x80\x80", # LEB too long
            HEADER + b"\x0a\x80",                 # truncated LEB
            HEADER + b"\x0a\xff\xff\xff\xff\x7f", # LEB over u32
            HEADER + b"\x00\x02\x01\xff",         # name not UTF-8
        ):
            with self.subTest(bad=bad), self.assertRaises(sw.WasmError):
                sw.strip(bad)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix="velmora-strip-test-")
        self.wasm = os.path.join(self.dir.name, "index_bg.wasm")
        self.copy = os.path.join(self.dir.name, "symbols", "index_bg.unstripped.wasm")

    def tearDown(self):
        self.dir.cleanup()

    def write(self, data):
        with open(self.wasm, "wb") as f:
            f.write(data)

    def read(self, path):
        with open(path, "rb") as f:
            return f.read()

    def test_strip_keeps_unstripped_copy_then_check_passes(self):
        mod = HEADER + TYPE + FUNC + CODE + NAME + PRODUCERS
        self.write(mod)
        os.chmod(self.wasm, 0o644)
        self.assertEqual(sw.main(["x", "check", self.wasm]), 1)
        self.assertEqual(sw.main(["x", "strip", self.wasm, "--unstripped", self.copy]), 0)
        self.assertEqual(self.read(self.wasm), HEADER + TYPE + FUNC + CODE + PRODUCERS)
        self.assertEqual(os.stat(self.wasm).st_mode & 0o777, 0o644)
        self.assertEqual(self.read(self.copy), mod)
        self.assertEqual(sw.main(["x", "check", self.wasm]), 0)

    def test_nothing_to_drop_removes_stale_copy(self):
        os.makedirs(os.path.dirname(self.copy))
        with open(self.copy, "wb") as f:
            f.write(b"stale")
        self.write(HEADER + CODE)
        self.assertEqual(sw.main(["x", "strip", self.wasm, "--unstripped", self.copy]), 0)
        self.assertFalse(os.path.exists(self.copy))
        self.assertEqual(self.read(self.wasm), HEADER + CODE)

    def test_process_exit_codes(self):
        script = os.path.join(_HERE, "strip_wasm.py")

        def run(*args):
            return subprocess.run([sys.executable, "-I", script, *args], capture_output=True).returncode

        self.write(HEADER + b"\x0a\x05\x00")  # malformed
        self.assertEqual(run("strip", self.wasm), 1)
        self.assertEqual(run("check", self.wasm), 1)
        self.assertEqual(run("check", self.wasm + ".missing"), 1)
        self.write(HEADER + CODE + NAME)
        self.assertEqual(run("check", self.wasm), 1)
        self.assertEqual(run("strip", self.wasm), 0)
        self.assertEqual(run("check", self.wasm), 0)
        self.assertEqual(run(), 2)

    def test_bad_usage(self):
        self.assertEqual(sw.main(["x"]), 2)
        self.assertEqual(sw.main(["x", "strip", self.wasm, "--bogus", self.copy]), 2)


if __name__ == "__main__":
    unittest.main()
