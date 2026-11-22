"""Exercise the catalogue scripts against local Wrangler and rclone stubs."""

import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "fixture-catalog"
BUCKET = "fixture-exports"
PART_BYTES = 4096
ARGS = ["--env", "dev"]
MS = "1760000000123"
MISSING = "✘ [ERROR] The specified key does not exist."
COLOURED_MISSING = "\x1b[31m✘ \x1b[1;41m[ERROR]\x1b[0m\x1b[31m The specified key does not exist.\x1b[0m"

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
if os.fstat(0).st_rdev != os.stat("/dev/null").st_rdev or os.read(0, 1) != b"":
    Path(os.environ["FAKE_LOG"] + ".stdin").touch()
    sys.exit("stub stdin was not /dev/null")

def download(source, dest):
    fail_get = os.environ.get("FAKE_FAIL_GET")
    if source.name.endswith(".manifest.json") and (
            fail_get == "yes" or (fail_get == "readback" and source.exists())):
        for line in range(25):
            print(f"stub manifest error line {line:02d}", file=sys.stderr)
        sys.exit(1)
    if not source.exists():
        sys.exit(os.environ.get("FAKE_MISSING", "✘ [ERROR] The specified key does not exist."))
    if source.name.endswith(".manifest.json") and os.environ.get("FAKE_BAD_READBACK"):
        Path(dest).write_bytes(b"other bytes")
    else:
        shutil.copyfile(source, dest)

if Path(sys.argv[0]).name == "rclone":
    if args[0] == "lsf":
        if os.environ.get("FAKE_FAIL_LISTING"):
            sys.exit(os.environ["FAKE_FAIL_LISTING"])
        obj = bucket / args[1].removeprefix("r2x:")
        if obj.exists():
            print(obj.name)
        sys.exit(0)
    assert args[0] == "copyto"
    source, dest = args[1:3]
    if source.startswith("r2x:"):
        src = bucket / source.removeprefix("r2x:")
        # Like rclone: without --ignore-times, a destination of the same
        # size (and here, any time) counts as up to date and is skipped.
        if ("--ignore-times" not in args and Path(dest).exists() and src.exists()
                and Path(dest).stat().st_size == src.stat().st_size):
            sys.exit(0)
        download(src, dest)
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
        if os.environ.get("FAKE_MISSING_BUCKET"):
            sys.exit("HTTP 404: NoSuchBucket")
        if args[4].endswith(os.environ.get("FAKE_FAIL_PUT", "\\0")):
            sys.exit("stub upload failure")
        obj.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, obj)
    else:
        assert args[3] == "get"
        download(obj, path)
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
        date = work / "date"
        date.write_text('#!/bin/sh\ncase "$1" in\n'
                        '+%s%3N) printf "%s\\n" "${FAKE_DATE:-1760000000123}" ;;\n'
                        '+%s) printf "%s\\n" 1760000000 ;;\nesac\n')
        date.chmod(0o755)
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
        result = subprocess.run(
            [str(ROOT / "ops" / f"catalog-{action}.sh"), *args, *ARGS],
            cwd=ROOT, env=self.env, text=True, input="unexpected stdin\n", capture_output=True,
        )
        for pattern in ("velmora-export.*", "velmora-import.*"):
            self.assertEqual(list(Path(self.env["TMPDIR"]).glob(pattern)), [])
        self.assertFalse(self.log.with_suffix(".jsonl.stdin").exists())
        for call in self.calls():
            if call[:2] == ["npx", "wrangler"] and call[2] in ("d1", "r2"):
                self.assertIn("--remote", call)
        return result

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
        ms, prefix, manifest = self.check_export()
        self.assertEqual(ms, MS)
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
        self.assertEqual(self.calls()[-1][2], f"r2x:{BUCKET}/{prefix}.manifest.json")
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

    def test_more_than_1000_parts_is_refused_before_any_upload(self):
        self.env["VELMORA_EXPORT_PART_BYTES"] = "1"
        result = self.run_script("export")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("more than 1000 parts", result.stderr)
        self.assertEqual(list(self.bucket.rglob("*")), [])

    def test_failed_put(self):
        self.env["FAKE_FAIL_PUT"] = ".sql.zst.part-001"
        result = self.run_script("export")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertRegex(result.stderr, r"catalog-export: put of .+\.sql\.zst\.part-001 failed:")
        self.assertIn("stub upload failure", result.stderr)
        self.assertEqual(list(self.bucket.rglob("*.manifest.json")), [])

    def test_failed_manifest_put(self):
        self.env["FAKE_FAIL_PUT"] = ".manifest.json"
        result = self.run_script("export")
        self.assert_refused(result, f"put of d1/{SOURCE}/{MS}.manifest.json failed")
        self.assertEqual(result.stdout, "")
        self.assertEqual(list(self.bucket.rglob("*.manifest.json")), [])

    def test_manifest_readback_mismatch(self):
        self.env["FAKE_BAD_READBACK"] = "yes"
        result = self.run_script("export")
        key = f"d1/{SOURCE}/{MS}.manifest.json"
        self.assert_refused(result, f"the manifest read back from {BUCKET}/{key} differs")
        self.assertEqual(result.stdout, "")
        self.assertTrue(self.object_path(key).is_file())
        self.assertTrue(list(self.bucket.rglob("*.part-*")))

    def test_manifest_readback_failure(self):
        self.env["FAKE_FAIL_GET"] = "readback"
        result = self.run_script("export")
        key = f"d1/{SOURCE}/{MS}.manifest.json"
        self.assert_refused(result, f"the manifest read back from {BUCKET}/{key} differs")
        self.assertEqual(result.stdout, "")
        self.assertTrue(self.object_path(key).is_file())

    def test_manifest_lookup_failure_stops_export_before_upload(self):
        for offset, (error, remote) in enumerate([
            ("Authentication error [code: 10000]", False),
            ("HTTP 403: account not found", False),
            ("npm warn config not found\nError: network request failed", False),
            (f"npm warn {MISSING}", False),
            (f"{MISSING} HTTP 500", False),
            ("NoSuchKey", False),
            ("Connection timed out", False),
            ("HTTP 503: Service Unavailable", False),
            ("rclone: connection timed out", True),
        ]):
            with self.subTest(error=error):
                ms = str(int(MS) + offset)
                key = f"d1/{SOURCE}/{ms}.manifest.json"
                self.env["FAKE_DATE"] = ms
                if remote:
                    self.env["VELMORA_EXPORT_RCLONE_REMOTE"] = "r2x"
                    self.env["FAKE_FAIL_LISTING"] = error
                else:
                    self.env["FAKE_MISSING"] = error
                before = len(self.calls())
                result = self.run_script("export")
                message = f"catalog-export: could not check {BUCKET}/{key}, see "
                self.assert_refused(result, message)
                self.assertEqual(len(self.calls()) - before, 1)
                self.assertFalse(self.object_path(key).exists())
                log = Path(result.stderr.strip().removeprefix(message))
                self.assertEqual(log.read_text().strip(), error)
                self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_wrangler_404_with_colour_allows_export(self):
        self.env["FAKE_MISSING"] = COLOURED_MISSING
        self.check_export()

    def test_missing_bucket_404_stops_on_first_put(self):
        self.env["FAKE_MISSING_BUCKET"] = "yes"
        result = self.run_script("export")
        key = f"d1/{SOURCE}/{MS}.sql.zst.part-000"
        self.assert_refused(result, f"put of {key} failed")
        self.assertIn("HTTP 404: NoSuchBucket", result.stderr)
        puts = [call[5] for call in self.calls() if call[:5] ==
                ["npx", "wrangler", "r2", "object", "put"]]
        self.assertEqual(puts, [f"{BUCKET}/{key}"])
        self.assertEqual(list(self.bucket.rglob("*")), [])

    def test_export_rejects_file_over_limit_before_any_upload(self):
        self.env["VELMORA_TEST_SQL_FILE_BYTES"] = "100"
        result = self.run_script("export")
        self.assert_refused(result, f"the SQL export is {self.fixture.stat().st_size} bytes, "
                                    "over the 100 bytes one D1 import takes; "
                                    "this export could not be restored by catalog-import.sh")
        self.assertEqual(list(self.bucket.rglob("*")), [])

    def oversized_multiline_dump(self):
        # Neither physical line is over the 100,000-byte limit; together
        # they are one statement with an embedded semicolon and newline.
        self.fixture.write_text("CREATE TABLE fixture (value TEXT);\n"
                                "INSERT INTO fixture VALUES ('" + "a" * 55_000 + ";\n" +
                                "b" * 55_989 + "');\n", encoding="utf-8")

    def test_export_rejects_111024_byte_statement_before_any_upload(self):
        self.oversized_multiline_dump()
        result = self.run_script("export")
        self.assert_refused(result, "statement starting at line 2 is 111024 bytes, "
                                    "over the D1 statement limit of 100000 bytes; "
                                    "this export could not be restored by catalog-import.sh")
        self.assertEqual(list(self.bucket.rglob("*")), [])

    def test_export_and_import_allow_multiline_statement_at_byte_limit(self):
        # SQL bytes count both the embedded and final newlines, and the
        # multibyte characters. Neither the first ';' nor newline ends it.
        self.fixture.write_bytes("CREATE TABLE t (x);\r\nINSERT INTO t VALUES ('é;\r\n雪');\r\n"
                                 .encode("utf-8"))
        self.env["VELMORA_TEST_SQL_FILE_BYTES"] = str(self.fixture.stat().st_size)
        self.env["VELMORA_TEST_SQL_STATEMENT_BYTES"] = "36"
        ms, _, _, _ = self.export()
        self.assert_loaded(self.run_script("import", "scratch-db", ms), ms)

        self.env["VELMORA_TEST_SQL_STATEMENT_BYTES"] = "35"
        self.env["FAKE_DATE"] = str(int(MS) + 1)
        (self.db / "scratch-db").unlink()
        result = self.run_script("export")
        self.assert_refused(result, "statement starting at line 2 is 36 bytes")
        self.assertEqual(list(self.bucket.rglob(f"{self.env['FAKE_DATE']}*")), [])

    def test_export_bounds_reading_of_oversized_sql_line(self):
        self.fixture.write_text("CREATE TABLE fixture (value TEXT);\n"
                                "INSERT INTO fixture VALUES ('" + "a" * 200_000 + "');\n",
                                encoding="utf-8")
        result = self.run_script("export")
        self.assert_refused(result, "statement starting at line 2 is at least 100001 bytes, "
                                    "over the D1 statement limit of 100000 bytes")
        self.assertEqual(list(self.bucket.rglob("*")), [])

    def test_scripts_require_python_with_sqlite_before_remote_calls(self):
        self.env["FAKE_PYTHON_EXE"] = sys.executable
        python = Path(self.env["TMPDIR"]) / "python3"
        python.write_text('#!/bin/sh\n'
                          'if [ "$1" = -I ]; then\n'
                          '    echo "ModuleNotFoundError: No module named _sqlite3" >&2\n'
                          '    exit 1\n'
                          'fi\n'
                          'exec "$FAKE_PYTHON_EXE" "$@"\n')
        python.chmod(0o755)
        for action, args in (("export", ()), ("import", ("scratch-db", MS))):
            with self.subTest(action=action):
                result = self.run_script(action, *args)
                self.assert_refused(result, f"catalog-{action}: python3 requires sqlite3 support")
                self.assertEqual(self.calls(), [])

    def test_export_rejects_incomplete_sql_before_any_upload(self):
        self.fixture.write_text("CREATE TABLE fixture (value TEXT);\n"
                                "INSERT INTO fixture VALUES ('unclosed;\n", encoding="utf-8")
        result = self.run_script("export")
        self.assert_refused(result, "the dump ends inside a statement")
        self.assertEqual(list(self.bucket.rglob("*")), [])

    def test_export_refuses_existing_manifest(self):
        key = f"d1/{SOURCE}/{MS}.manifest.json"
        path = self.object_path(key)
        path.parent.mkdir(parents=True)
        path.write_bytes(b"existing manifest")
        for remote in (False, True):
            with self.subTest(rclone=remote):
                if remote:
                    self.env["VELMORA_EXPORT_RCLONE_REMOTE"] = "r2x"
                result = self.run_script("export")
                self.assert_refused(result, f"an export at restore point {MS} exists already")
                self.assertEqual(result.stdout, "")
        self.assertEqual(path.read_bytes(), b"existing manifest")
        self.assertEqual([call[1:3] for call in self.calls()], [["wrangler", "r2"],
                                                               ["lsf", f"r2x:{BUCKET}/{key}"]])

    def test_export_falls_back_to_seconds(self):
        self.env["FAKE_DATE"] = "1760000000%3N"
        self.assertEqual(self.export()[0], "1760000000000")

    def test_export_part_boundaries(self):
        compressed = subprocess.run(["zstd", "-q", "-T0", "-10", "-c", self.fixture],
                                    capture_output=True, check=True).stdout
        for size in (len(compressed), 1):
            with self.subTest(part_bytes=size):
                if size == 1:
                    # Use a small fixture so one-byte parts stay within the suffix limit.
                    self.fixture.write_text("CREATE TABLE fixture (value TEXT);\n")
                    self.env["FAKE_DATE"] = "1760000000124"
                self.env["VELMORA_EXPORT_PART_BYTES"] = str(size)
                ms, _, manifest, _ = self.export()
                self.assertEqual(manifest["zst_bytes"] % size, 0)
                self.assertEqual(len(manifest["parts"]), manifest["zst_bytes"] // size)
                self.assertTrue(all(part["bytes"] == size for part in manifest["parts"]))
                self.assert_loaded(self.run_script("import", "scratch-db", ms), ms)

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

    def test_import_rejects_manifest_file_size_before_fetching_parts(self):
        ms, _, manifest, _ = self.export()
        self.env["VELMORA_TEST_SQL_FILE_BYTES"] = "100"
        before = len(self.calls())
        result = self.run_script("import", "scratch-db", ms)
        self.assert_refused(result, f"the SQL export is {manifest['sql_bytes']} bytes, "
                                    "over the 100 bytes one D1 import takes; "
                                    "this export could not be restored by catalog-import.sh")
        self.assertEqual(len(self.calls()) - before, 1)

    def test_import_rejects_oversized_reassembled_statement_before_loading(self):
        # Simulate a manifest made by an exporter that had no statement cap.
        self.oversized_multiline_dump()
        sql = self.fixture.read_bytes()
        compressed = subprocess.run(["zstd", "-q", "-c"], input=sql,
                                    capture_output=True, check=True).stdout
        prefix = f"d1/{SOURCE}/{MS}"
        key = f"{prefix}.sql.zst.part-000"
        path = self.object_path(key)
        path.parent.mkdir(parents=True)
        path.write_bytes(compressed)
        compressed_sha = hashlib.sha256(compressed).hexdigest()
        self.object_path(f"{prefix}.manifest.json").write_text(json.dumps({
            "format": 1, "database": SOURCE, "restore_point_ms": int(MS),
            "sql_bytes": len(sql), "sql_sha256": hashlib.sha256(sql).hexdigest(),
            "zst_bytes": len(compressed), "zst_sha256": compressed_sha,
            "parts": [{"key": key, "bytes": len(compressed), "sha256": compressed_sha}],
        }))
        result = self.run_script("import", "scratch-db", MS)
        self.assert_refused(result, "statement starting at line 2 is 111024 bytes, "
                                    "over the D1 statement limit of 100000 bytes; "
                                    "this export could not be restored by catalog-import.sh")
        self.assertTrue(any(call[:5] == ["npx", "wrangler", "r2", "object", "get"]
                            and call[5] == f"{BUCKET}/{key}" for call in self.calls()))
        self.assertFalse(any(call[:3] == ["npx", "wrangler", "d1"] for call in self.calls()))

    def test_import_refuses_production_and_non_digit_restore_point(self):
        for target in ("velmora-catalog", "CATALOG", SOURCE):
            with self.subTest(target=target):
                self.assert_refused(self.run_script("import", target, "123"),
                                    f"refusing to load into {target} without VELMORA_IMPORT_PRODUCTION=yes")
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

    def test_missing_part(self):
        ms, _, manifest, _ = self.export()
        key = manifest["parts"][0]["key"]
        self.object_path(key).unlink()
        self.assert_refused(self.run_script("import", "scratch-db", ms),
                            f"download failed for {key}")

    def test_wrong_restore_point_in_manifest(self):
        ms, prefix, manifest, _ = self.export()
        manifest["restore_point_ms"] += 1
        key = f"{prefix}.manifest.json"
        self.object_path(key).write_text(json.dumps(manifest))
        self.assert_refused(self.run_script("import", "scratch-db", ms), f"invalid manifest {key}")

    def test_manifest_without_format_is_format_1(self):
        # Exports made before the manifest carried "format" have the same
        # layout; they load like format 1. Another format is refused.
        ms, prefix, manifest, _ = self.export()
        key = f"{prefix}.manifest.json"
        del manifest["format"]
        self.object_path(key).write_text(json.dumps(manifest))
        self.assert_loaded(self.run_script("import", "scratch-db", ms), ms)
        manifest["format"] = 2
        self.object_path(key).write_text(json.dumps(manifest))
        (self.db / "scratch-db").unlink()
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
        for missing in (MISSING, COLOURED_MISSING, ""):
            with self.subTest(missing=missing):
                self.env["FAKE_MISSING"] = missing
                if not missing:
                    self.env["VELMORA_EXPORT_RCLONE_REMOTE"] = "r2x"
                self.assert_loaded(self.run_script("import", "scratch-db", ms), ms, [
                    "catalog-import: legacy export without a manifest; no checksum to check",
                ])

    def test_import_reports_missing_export(self):
        prefix = f"d1/{SOURCE}/{MS}"
        self.assert_refused(self.run_script("import", "scratch-db", MS),
                            f"no export at restore point {MS} (neither {prefix}.manifest.json nor {prefix}.sql)")

    def test_manifest_403_does_not_fall_back_to_legacy(self):
        prefix = f"d1/{SOURCE}/{MS}"
        path = self.object_path(f"{prefix}.sql")
        path.parent.mkdir(parents=True)
        path.write_bytes(self.fixture.read_bytes())
        self.env["FAKE_MISSING"] = "HTTP 403: account not found"
        result = self.run_script("import", "scratch-db", MS)
        self.assert_refused(result, f"could not read {prefix}.manifest.json")
        self.assertIn(self.env["FAKE_MISSING"], result.stderr)
        self.assertEqual(len(self.calls()), 1)

    def test_manifest_get_failure_does_not_load_legacy(self):
        prefix = f"d1/{SOURCE}/{MS}"
        path = self.object_path(f"{prefix}.sql")
        path.parent.mkdir(parents=True)
        path.write_bytes(self.fixture.read_bytes())
        self.env["FAKE_FAIL_GET"] = "yes"
        for remote in (False, True):
            with self.subTest(rclone=remote):
                if remote:
                    self.env["VELMORA_EXPORT_RCLONE_REMOTE"] = "r2x"
                    self.object_path(f"{prefix}.manifest.json").write_text("{}")
                before = len(self.calls())
                result = self.run_script("import", "scratch-db", MS)
                self.assert_refused(result, f"could not read {prefix}.manifest.json")
                self.assertEqual(result.stderr.splitlines(), [
                    *(f"stub manifest error line {line:02d}" for line in range(5, 25)),
                    f"catalog-import: could not read {prefix}.manifest.json",
                ])
                self.assertEqual(len(self.calls()) - before, 2 if remote else 1)

    def test_empty_downloads(self):
        ms, prefix, manifest, _ = self.export()
        part = manifest["parts"][0]["key"]
        for key in (part, f"{prefix}.manifest.json"):
            with self.subTest(key=key):
                self.object_path(key).write_bytes(b"")
                self.assert_refused(self.run_script("import", "scratch-db", ms),
                                    f"empty download for {key}")
        self.object_path(f"{prefix}.manifest.json").unlink()
        self.object_path(f"{prefix}.sql").write_bytes(b"")
        self.assert_refused(self.run_script("import", "scratch-db", ms),
                            f"empty download for {prefix}.sql")

    def test_legacy_export_without_schema(self):
        key = f"d1/{SOURCE}/{MS}.sql"
        path = self.object_path(key)
        path.parent.mkdir(parents=True)
        path.write_text("SELECT 1;\n")
        self.assert_refused(self.run_script("import", "scratch-db", MS), f"no schema in {key}")

    def test_bash_syntax(self):
        for action in ("export", "import"):
            with self.subTest(action=action):
                subprocess.run(["bash", "-n", ROOT / "ops" / f"catalog-{action}.sh"], check=True)


if __name__ == "__main__":
    unittest.main()
