"""Exercise the catalogue scripts against local Wrangler and rclone stubs."""

import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "fixture-catalog"
BUCKET = "fixture-exports"
PART_BYTES = 4096
ARGS = ["--env", "dev"]

STUB = """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import sys

args = sys.argv[1:]
bucket = Path(os.environ["FAKE_BUCKET"])
with open(os.environ["FAKE_LOG"], "a") as log:
    print(json.dumps([Path(sys.argv[0]).name, *args]), file=log)

if Path(sys.argv[0]).name == "rclone":
    assert args[0] == "copyto"
    source, dest = args[1:3]
    if source.startswith("r2x:"):
        source = bucket / source.removeprefix("r2x:")
    else:
        assert dest.startswith("r2x:")
        dest = bucket / dest.removeprefix("r2x:")
        dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)
elif args[:3] == ["wrangler", "d1", "export"]:
    shutil.copyfile(os.environ["FAKE_FIXTURE"], args[args.index("--output") + 1])
elif args[:3] == ["wrangler", "r2", "object"]:
    obj = bucket / args[4]
    path = Path(args[args.index("--file") + 1])
    if args[3] == "put":
        if args[4].endswith(os.environ.get("FAKE_FAIL_PUT", "\\0")):
            sys.exit("stub upload failure")
        obj.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, obj)
    else:
        assert args[3] == "get"
        shutil.copyfile(obj, path)
elif args[:3] == ["wrangler", "d1", "execute"]:
    if "--command" in args:
        assert "--json" in args
        print(json.dumps([{"results": [{"n": int(os.environ.get("FAKE_TABLES", 0))}]}]))
    else:
        assert "--yes" in args
        shutil.copyfile(args[args.index("--file") + 1], Path(os.environ["FAKE_DB"]) / args[3])
else:
    sys.exit("unexpected stub command")
"""


class CatalogueScripts(unittest.TestCase):
    def setUp(self):
        work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.bucket = work / "bucket"
        self.db = work / "db"
        self.db.mkdir()
        self.log = work / "calls.jsonl"
        self.fixture = work / "fixture.sql"
        rng = random.Random(12)
        with self.fixture.open("w", encoding="ascii") as sql:
            sql.write("CREATE TABLE fixture (value TEXT);\n")
            for _ in range(800):
                sql.write(f"INSERT INTO fixture VALUES ('{rng.getrandbits(256):064x}');\n")
        for name in ("npx", "rclone"):
            stub = work / name
            stub.write_text(STUB)
            stub.chmod(0o755)
        self.env = {
            "PATH": f"{work}{os.pathsep}{os.defpath}",
            "TMPDIR": str(work),
            "VELMORA_D1": SOURCE,
            "VELMORA_EXPORT_BUCKET": BUCKET,
            "VELMORA_EXPORT_PART_BYTES": str(PART_BYTES),
            "FAKE_BUCKET": str(self.bucket),
            "FAKE_DB": str(self.db),
            "FAKE_LOG": str(self.log),
            "FAKE_FIXTURE": str(self.fixture),
        }

    def run_script(self, action, *args):
        return subprocess.run(
            [str(ROOT / "ops" / f"catalog-{action}.sh"), *args, *ARGS],
            cwd=ROOT, env=self.env, text=True, capture_output=True,
        )

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def object_path(self, key):
        return self.bucket / BUCKET / key

    def export(self):
        result = self.run_script("export")
        self.assertEqual(result.returncode, 0, result.stderr)
        summary, restore_line = result.stdout.splitlines()
        self.assertRegex(restore_line, r"^restore point: [0-9]+$")
        ms = restore_line.split()[-1]
        prefix = f"d1/{SOURCE}/{ms}"
        manifest = json.loads(self.object_path(f"{prefix}.manifest.json").read_text())
        return ms, prefix, manifest, summary

    def check_export(self):
        ms, prefix, manifest, summary = self.export()
        self.assertEqual(manifest["format"], 1)
        self.assertEqual(manifest["database"], SOURCE)
        self.assertEqual(manifest["restore_point_ms"], int(ms))
        self.assertGreater(len(manifest["parts"]), 1)
        compressed = bytearray()
        for index, part in enumerate(manifest["parts"]):
            self.assertEqual(part["key"], f"{prefix}.sql.zst.part-{index:03d}")
            data = self.object_path(part["key"]).read_bytes()
            self.assertGreater(len(data), 0)
            self.assertLessEqual(len(data), PART_BYTES)
            self.assertEqual(part["bytes"], len(data))
            self.assertEqual(part["sha256"], hashlib.sha256(data).hexdigest())
            compressed.extend(data)
        self.assertEqual(manifest["zst_bytes"], len(compressed))
        self.assertEqual(manifest["zst_sha256"], hashlib.sha256(compressed).hexdigest())
        sql = subprocess.run(["zstd", "-q", "-d", "-c"], input=compressed,
                             capture_output=True, check=True).stdout
        self.assertEqual(sql, self.fixture.read_bytes())
        self.assertEqual(manifest["sql_bytes"], len(sql))
        self.assertEqual(manifest["sql_sha256"], hashlib.sha256(sql).hexdigest())
        self.assertEqual(
            summary,
            f"catalog-export: sql {len(sql)} bytes, sha256 {manifest['sql_sha256']}, "
            f"zst {len(compressed)} bytes in {len(manifest['parts'])} part(s), "
            f"manifest {BUCKET}/{prefix}.manifest.json",
        )
        return ms, prefix, manifest

    def test_export(self):
        _, prefix, manifest = self.check_export()
        calls = self.calls()
        self.assertTrue(all(call[-2:] == ARGS for call in calls))
        puts = [call for call in calls if call[:5] == ["npx", "wrangler", "r2", "object", "put"]]
        keys = [part["key"] for part in manifest["parts"]] + [f"{prefix}.manifest.json"]
        self.assertEqual([call[5] for call in puts], [f"{BUCKET}/{key}" for key in keys])
        self.assertEqual([call[call.index("--content-type") + 1] for call in puts],
                         ["application/zstd"] * (len(keys) - 1) + ["application/json"])

    def test_rclone_export_and_import(self):
        self.env["VELMORA_EXPORT_RCLONE_REMOTE"] = "r2x"
        ms, prefix, _ = self.check_export()
        self.assertEqual(self.calls()[-1][3], f"r2x:{BUCKET}/{prefix}.manifest.json")
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.db / "scratch-db").read_bytes(), self.fixture.read_bytes())
        self.assertFalse(any(call[:3] == ["npx", "wrangler", "r2"] for call in self.calls()))

    def test_invalid_export_settings(self):
        for name, value in [
            ("VELMORA_EXPORT_RCLONE_REMOTE", "bad:name"),
            ("VELMORA_EXPORT_PART_BYTES", "0"),
            ("VELMORA_EXPORT_PART_BYTES", "abc"),
            ("VELMORA_EXPORT_PART_BYTES", "300000001"),
        ]:
            with self.subTest(name=name, value=value):
                original = self.env.copy()
                self.env[name] = value
                result = self.run_script("export")
                self.env = original
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(name, result.stderr)
                self.assertEqual(self.calls(), [])
                self.assertEqual(list(self.bucket.rglob("*.manifest.json")), [])

    def test_failed_put(self):
        self.env["FAKE_FAIL_PUT"] = ".sql.zst.part-001"
        result = self.run_script("export")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertRegex(result.stderr, r"catalog-export: put of .+\.sql\.zst\.part-001 failed:")
        self.assertIn("stub upload failure", result.stderr)
        self.assertEqual(list(self.bucket.rglob("*.manifest.json")), [])

    def assert_loaded(self, result, ms, leading_lines=()):
        self.assertEqual(result.returncode, 0, result.stderr)
        loaded = (self.db / "scratch-db").read_bytes()
        self.assertEqual(loaded, self.fixture.read_bytes())
        self.assertEqual(result.stdout.splitlines(), [
            *leading_lines,
            f"catalog-import: loaded {len(loaded)} bytes into scratch-db from restore point {ms}",
            "catalog-import: next: migrations apply, then ops/restore-arm.sql (README, Restore step 2)",
        ])

    def assert_refused(self, result, message):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(message, result.stderr)
        self.assertEqual(list(self.db.iterdir()), [])

    def test_import_round_trip(self):
        ms, _, _, _ = self.export()
        self.assert_loaded(self.run_script("import", "scratch-db", ms), ms)
        self.assertTrue(all(call[-2:] == ARGS for call in self.calls()))

    def test_import_refuses_production_and_non_digit_restore_point(self):
        self.assert_refused(
            self.run_script("import", "velmora-catalog", "123"),
            "catalog-import: refusing to load into velmora-catalog without VELMORA_IMPORT_PRODUCTION=yes",
        )
        self.assert_refused(self.run_script("import", "scratch-db", "12x"), "only digits")
        self.assertEqual(self.calls(), [])

    def test_corrupted_part(self):
        ms, _, manifest, _ = self.export()
        key = manifest["parts"][0]["key"]
        path = self.object_path(key)
        data = bytearray(path.read_bytes())
        data[0] ^= 1
        path.write_bytes(data)
        self.assert_refused(self.run_script("import", "scratch-db", ms),
                            f"sha256 mismatch for {key}")

    def test_wrong_restore_point_in_manifest(self):
        ms, prefix, manifest, _ = self.export()
        manifest["restore_point_ms"] += 1
        key = f"{prefix}.manifest.json"
        self.object_path(key).write_text(json.dumps(manifest))
        self.assert_refused(self.run_script("import", "scratch-db", ms), f"invalid manifest {key}")

    def test_nonempty_target(self):
        ms, _, _, _ = self.export()
        self.env["FAKE_TABLES"] = "3"
        self.assert_refused(self.run_script("import", "scratch-db", ms),
                            "catalog-import: scratch-db is not empty")

    def test_legacy_export(self):
        ms = "123"
        path = self.object_path(f"d1/{SOURCE}/{ms}.sql")
        path.parent.mkdir(parents=True)
        path.write_bytes(self.fixture.read_bytes())
        self.assert_loaded(self.run_script("import", "scratch-db", ms), ms, [
            "catalog-import: legacy export without a manifest; no checksum to check",
        ])

    def test_bash_syntax(self):
        for action in ("export", "import"):
            with self.subTest(action=action):
                subprocess.run(["bash", "-n", ROOT / "ops" / f"catalog-{action}.sh"], check=True)


if __name__ == "__main__":
    unittest.main()
