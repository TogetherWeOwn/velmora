"""Exercise the catalogue scripts against local Wrangler and rclone stubs."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import fcntl
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import random
import runpy
import select
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "fixture-catalog"
BUCKET = "fixture-exports"
PART_BYTES = 4096
ARGS = ["--config", "fixture.toml", "--env", "dev"]
MS = "1760000000123"
DATABASE_ID = "11111111-2222-4333-8444-555555555555"
OTHER_DATABASE_ID = "22222222-3333-4444-8555-666666666666"
MISSING = "✘ [ERROR] The specified key does not exist."
COLOURED_MISSING = "\x1b[31m✘ \x1b[1;41m[ERROR]\x1b[0m\x1b[31m The specified key does not exist.\x1b[0m"


def is_batch_load(call):
    return (call[2:4] == ["d1", "execute"] and "--file" in call and
            Path(call[call.index("--file") + 1]).name.startswith("batch-"))


def is_d1_write(call):
    return (call[2:4] == ["d1", "execute"] and
            ("--file" in call or not call[call.index("--command") + 1].startswith(("SELECT ", "WITH "))))


STUB = """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import sys

args = sys.argv[1:]
tool = Path(sys.argv[0]).name
if tool == "wrangler" and args == ["--version"]:
    print(os.environ.get("FAKE_WRANGLER_VERSION", "4.161.0"))
    sys.exit(0)
if tool == "wrangler":
    args.insert(0, "wrangler")
    tool = "local"
bucket = Path(os.environ["FAKE_BUCKET"])
with open(os.environ["FAKE_LOG"], "a") as log:
    print(json.dumps([tool, *args]), file=log)
if os.fstat(0).st_rdev != os.stat("/dev/null").st_rdev or os.read(0, 1) != b"":
    Path(os.environ["FAKE_LOG"] + ".stdin").touch()
    sys.exit("stub stdin was not /dev/null")

def rendezvous(name, mode):
    # FIFO handshakes order the concurrent PUT and GET without timing assumptions.
    signal.alarm(15)
    with (Path(os.environ.get("FAKE_RACE_DIR", os.environ["TMPDIR"])) / name).open(mode) as gate:
        if mode == "w":
            gate.write("go")
        else:
            assert gate.read() == "go"
    signal.alarm(0)

def download(source, dest):
    if source.name.endswith(".manifest.json") and Path(dest).name == "readback.json":
        if os.environ.get("FAKE_RACE") == "loser":
            rendezvous("loser-published", "w")
            rendezvous("winner-readback", "r")
        elif os.environ.get("FAKE_RACE") == "winner":
            shutil.copyfile(source, dest)
            rendezvous("winner-readback", "w")
            return
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

def stream(source, limit=-1):
    if not source.exists():
        sys.exit(os.environ.get("FAKE_MISSING", "✘ [ERROR] The specified key does not exist."))
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    with source.open("rb") as incoming:
        if limit < 0:
            shutil.copyfileobj(incoming, sys.stdout.buffer)
        else:
            sys.stdout.buffer.write(incoming.read(limit))

if Path(sys.argv[0]).name == "rclone":
    if args[0] == "cat":
        stream(bucket / args[1].removeprefix("r2x:"), int(args[args.index("--head") + 1]))
        sys.exit(0)
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
    if os.environ.get("FAKE_RACE") == "winner":
        rendezvous("winner-checked", "w")
        rendezvous("loser-published", "r")
    shutil.copyfile(os.environ["FAKE_FIXTURE"], args[args.index("--output") + 1])
    if os.environ.get("FAKE_EXPORT_SIGNED_URL"):
        signed_url = "https://example.invalid/catalog.sql?foo=bar&X-Amz-Signature=fixture-signature"
        print(f"Download URL: {signed_url}")
        print(f"Download URL: {signed_url}", file=sys.stderr)
        if os.environ.get("WRANGLER_WRITE_LOGS") != "false":
            (Path(os.environ["TMPDIR"]) / "wrangler-debug.log").write_text(signed_url)
elif args[:3] == ["wrangler", "d1", "info"]:
    assert "--json" in args
    assert "--remote" not in args
    if os.environ.get("FAKE_FAIL_INFO"):
        sys.exit("stub D1 info unavailable")
    info = {"uuid": os.environ["FAKE_DATABASE_ID"], "name": os.environ.get("FAKE_DATABASE_NAME", args[3])}
    if not os.environ.get("FAKE_OMIT_SIZE"):
        info["database_size"] = int(os.environ.get("FAKE_DATABASE_SIZE", 32768))
    print(json.dumps(info))
elif args[:3] == ["wrangler", "r2", "object"]:
    obj = bucket / args[4]
    if args[3] == "get" and "--pipe" in args:
        stream(obj)
        sys.exit(0)
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
    db = Path(os.environ["FAKE_DB"])
    remapped = db / "binding-remapped"
    if args[3] == os.environ["FAKE_DATABASE_ID"]:
        database = "scratch-db"
    elif remapped.exists():
        database = os.environ["FAKE_REMAP_TARGET"]
    else:
        database = args[3]
    target_file = db / database
    batches = db / "batches"
    sqlite_file = db / "sqlite" / (database + ".sqlite")
    if "--command" in args:
        assert "--json" in args
        query = args[args.index("--command") + 1]
        if query.startswith("SELECT EXISTS(SELECT 1 FROM sqlite_master"):
            with sqlite3.connect(sqlite_file if sqlite_file.exists() else ":memory:") as conn:
                incomplete, nonempty = conn.execute(query).fetchone()
            if os.environ.get("FAKE_STALE_EMPTY_PREFLIGHT"):
                # Simulate an earlier 'empty' observation without deleting
                # the committed catalogue that another host left behind.
                incomplete, nonempty = 0, 0
            rows = [{"incomplete": incomplete, "nonempty": nonempty}]
            if os.environ.get("FAKE_REMAP_TARGET"):
                remapped.touch()
        elif query.startswith(("CREATE TABLE _velmora_import_incomplete", "DROP TABLE _velmora_import_incomplete",
                               "UPDATE _velmora_import_incomplete")):
            sqlite_file.parent.mkdir(exist_ok=True)
            with sqlite3.connect(sqlite_file) as conn:
                conn.executescript(query)
            rows = []
        else:
            if query.startswith("WITH ") and os.environ.get("FAKE_FAIL_VERIFY"):
                sys.exit("stub verification unavailable")
            if query.startswith("WITH ") and os.environ.get("FAKE_STALLED_CURSOR"):
                pages = db / "stalled-cursor-pages"
                n = int(pages.read_text()) if pages.exists() else 0
                if n == 2:
                    sys.exit("stub received a third query for the stalled cursor")
                pages.write_text(str(n + 1))
                rows = [{"n": 5000, "cursor": json.dumps([["integer", "5000"]])}]
            else:
                with sqlite3.connect(sqlite_file) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = [dict(row) for row in conn.execute(query)]
            if 'FROM "' + os.environ.get("FAKE_MISMATCH_TABLE", '\\0') + '"' in query:
                rows[0]["n"] += 1
        print(json.dumps([{"results": rows}]))
    else:
        assert "--yes" in args
        source = Path(args[args.index("--file") + 1])
        if source.name == "claim.sql":
            sqlite_file.parent.mkdir(exist_ok=True)
            with sqlite3.connect(sqlite_file) as conn:
                conn.executescript("BEGIN IMMEDIATE;\\n" + source.read_text() + "\\nCOMMIT;")
            sys.exit(0)
        assert source.name.startswith("batch-")
        assert not list(source.parent.glob("spool-*"))
        assert not any((source.parent / name).exists() for name in ("catalog.sql", "catalog.sql.zst", "part"))
        fail_batch = os.environ.get("FAKE_FAIL_BATCH")
        if ((fail_batch == "footer" and b"CREATE INDEX child_idx" in source.read_bytes())
                or (fail_batch and fail_batch.isdigit() and int(source.stem.split("-")[-1]) == int(fail_batch))):
            sys.exit("stub batch failure")
        sqlite_file.parent.mkdir(exist_ok=True)
        with sqlite3.connect(sqlite_file) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            # Simulate one D1 file import and commit boundary per batch.
            conn.executescript("BEGIN;\\n" + source.read_text() + "\\nCOMMIT;")
        batches.mkdir(exist_ok=True)
        shutil.copyfile(source, batches / source.name)
        with target_file.open("ab") as loaded:
            loaded.write(source.read_bytes())
        if os.environ.get("FAKE_MUTATE_NEXT_BATCH") and source.name == "batch-00000000.sql":
            with source.with_name("batch-00000001.sql").open("ab") as next_batch:
                next_batch.write(b"-- changed after splitting\\n")
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
        self.root = work / "bridge"
        self.root.mkdir()
        shutil.copytree(ROOT / "ops", self.root / "ops")
        shutil.copyfile(ROOT / "package-lock.json", self.root / "package-lock.json")
        self.wrangler = self.root / "node_modules" / ".bin" / "wrangler"
        self.wrangler.parent.mkdir(parents=True)
        for stub in (self.wrangler, work / "rclone", work / "npx"):
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
            "FAKE_DATABASE_ID": DATABASE_ID,
            "VELMORA_IMPORT_DATABASE_ID": DATABASE_ID,
        }

    def call_script(self, action, *args, **overrides):
        return subprocess.run(
            [str(self.root / "ops" / f"catalog-{action}.sh"), *args, *ARGS],
            cwd=self.root, env={**self.env, **overrides}, text=True, input="unexpected stdin\n",
            capture_output=True, timeout=40,
        )

    def run_script(self, action, *args):
        work = Path(self.env["TMPDIR"])
        preexisting_logs = set(work.glob("velmora-catalog-*-logs.*"))
        result = self.call_script(action, *args)
        if result.returncode == 0:
            self.assertEqual(set(work.glob("velmora-catalog-*-logs.*")), preexisting_logs)
        for pattern in ("velmora-export.*", "velmora-import.*"):
            self.assertEqual(list(Path(self.env["TMPDIR"]).glob(pattern)), [])
        self.assertFalse(self.log.with_suffix(".jsonl.stdin").exists())
        for call in self.calls():
            if call[:2] == ["local", "wrangler"] and call[2] in ("d1", "r2") and call[3] != "info":
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
        self.assertEqual(manifest["format"], 2)
        self.assertRegex(manifest["attempt"], r"\A[0-9a-f]{16}\Z")
        self.assertEqual(manifest["database"], SOURCE)
        self.assertEqual(manifest["restore_point_ms"], int(ms))
        self.assertGreater(len(manifest["parts"]), 1)
        compressed = bytearray()
        for index, part in enumerate(manifest["parts"]):
            self.assertEqual(part["key"], f"{prefix}.{manifest['attempt']}.part-{index:03d}")
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
            f"manifest {BUCKET}/{prefix}.manifest.json, "
            "longest statement 97 bytes, database 32768 bytes",
        )
        return ms, prefix, manifest

    def test_import_refuses_host_sqlite_before_337_before_remote_calls(self):
        self.env["FAKE_PYTHON_EXE"] = sys.executable
        python = Path(self.env["TMPDIR"]) / "python3"
        python.write_text('#!/bin/sh\n'
                          'case "${3-}" in *sqlite3.sqlite_version*) printf "%s\\n" 3.36.0; exit 0;; esac\n'
                          'exec "$FAKE_PYTHON_EXE" "$@"\n')
        python.chmod(0o755)
        self.assert_refused(self.run_script("import", "scratch-db", MS), "SQLite 3.37 or later is required (found 3.36.0)")
        self.assertEqual(self.calls(), [])

    def test_missing_or_wrong_wrangler_pin_makes_no_remote_calls(self):
        for version in ("4.166.0", None):
            with self.subTest(version=version):
                if version is None:
                    self.wrangler.unlink()
                else:
                    self.env["FAKE_WRANGLER_VERSION"] = version
                for action, args in (("export", ()), ("import", ("scratch-db", MS))):
                    result = self.run_script(action, *args)
                    self.assert_refused(result, "Wrangler 4.161.0")
                    self.assertEqual(self.calls(), [])

    def test_export_contention_refuses_before_api_calls(self):
        lock_dir = Path(self.env["TMPDIR"]) / f"velmora-catalog-locks-{os.getuid()}"
        lock_dir.mkdir(mode=0o700)
        lock = lock_dir / f"export-{hashlib.sha256(SOURCE.encode()).hexdigest()}.lock"
        with lock.open("w") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_refused(self.run_script("export"), f"another export of {SOURCE} is running")
        self.assertEqual(self.calls(), [])

    def test_import_contention_only_resolves_target(self):
        lock_dir = Path(self.env["TMPDIR"]) / f"velmora-catalog-locks-{os.getuid()}"
        lock_dir.mkdir(mode=0o700)
        self.env["FAKE_DATABASE_NAME"] = "scratch-db"
        with (lock_dir / f"import-{DATABASE_ID}.lock").open("w") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_refused(self.run_script("import", "another-binding", MS),
                                f"another import of {DATABASE_ID} is running")
        self.assertEqual(self.calls(), [["local", "wrangler", "d1", "info", "another-binding", "--json", *ARGS]])

    def test_export(self):
        ms, prefix, manifest = self.check_export()
        self.assertEqual(ms, MS)
        calls = self.calls()
        self.assertTrue(all(call[-len(ARGS):] == ARGS for call in calls))
        puts = [call for call in calls if call[:5] == ["local", "wrangler", "r2", "object", "put"]]
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
        self.assertFalse(any(call[:3] == ["local", "wrangler", "r2"] for call in self.calls()))

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
        self.env["FAKE_FAIL_PUT"] = ".part-001"
        result = self.run_script("export")
        self.assertRegex(result.stderr, r"catalog-export: put of .+\.[0-9a-f]{16}\.part-001 failed, see ")
        prefix = result.stderr.splitlines()[0].split(", see ")[0] + ", see "
        log = self.assert_kept_log(result, prefix)
        self.assertEqual(log.read_text().strip(), "stub upload failure")
        self.assertTrue((log.parent / "catalog.sql.zst.part-000.put.log").is_file())
        self.assertEqual(list(self.bucket.rglob("*.manifest.json")), [])

    def test_failed_export_never_saves_signed_url_query_strings(self):
        self.env.update(FAKE_EXPORT_SIGNED_URL="yes", FAKE_FAIL_PUT=".part-001")
        result = self.run_script("export")
        self.assert_refused(result, "put of ")
        logs = list(Path(self.env["TMPDIR"]).rglob("*.log"))
        self.assertTrue(logs)
        self.assertFalse(any(path.name == "wrangler-debug.log" for path in logs),
                         "Wrangler debug logging was not disabled")
        for output in [result.stdout, result.stderr, *(path.read_text() for path in logs)]:
            self.assertNotIn("X-Amz-Signature", output)
            self.assertNotIn("?", output)
        export_log = next(path for path in logs if path.name == "d1-export.log")
        self.assertIn("https://example.invalid/catalog.sql", export_log.read_text())

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
        log = self.assert_kept_log(result, f"catalog-export: could not read {key}, see ")
        self.assertEqual(log.read_text().splitlines(),
                         [f"stub manifest error line {line:02d}" for line in range(25)])
        self.assertEqual(result.stdout, "")
        self.assertTrue(self.object_path(key).is_file())

    def assert_kept_log(self, result, message):
        self.assert_refused(result, message)
        log = Path(next(line.removeprefix(message) for line in result.stderr.splitlines()
                        if line.startswith(message)))
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        self.assertEqual(log.parent.stat().st_mode & 0o777, 0o700)
        return log

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
                log = self.assert_kept_log(result, message)
                self.assertEqual(len(self.calls()) - before, 1)
                self.assertFalse(self.object_path(key).exists())
                self.assertEqual(log.read_text().strip(), error)

    def test_wrangler_404_with_colour_allows_export(self):
        self.env["FAKE_MISSING"] = COLOURED_MISSING
        self.check_export()

    def test_missing_bucket_404_stops_on_first_put(self):
        self.env["FAKE_MISSING_BUCKET"] = "yes"
        result = self.run_script("export")
        puts = [call[5] for call in self.calls() if call[:5] ==
                ["local", "wrangler", "r2", "object", "put"]]
        self.assertEqual(len(puts), 1)
        self.assertRegex(puts[0], rf"^{BUCKET}/d1/{SOURCE}/{MS}\.[0-9a-f]{{16}}\.part-000$")
        key = puts[0].removeprefix(f"{BUCKET}/")
        log = self.assert_kept_log(result, f"catalog-export: put of {key} failed, see ")
        self.assertEqual(log.read_text().strip(), "HTTP 404: NoSuchBucket")
        self.assertEqual(list(self.bucket.rglob("*")), [])

    def test_export_has_no_single_file_size_limit(self):
        self.env["VELMORA_TEST_SQL_FILE_BYTES"] = "100"
        _, _, manifest, _ = self.export()
        self.assertEqual(manifest["sql_bytes"], self.fixture.stat().st_size)

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

    def test_export_rejects_dump_without_schema_before_any_upload(self):
        self.fixture.write_text("SELECT 1;\n")
        self.assert_refused(self.run_script("export"), "the export has no schema")
        self.assertEqual(list(self.bucket.rglob("*")), [])

    def test_export_rejects_create_table_inside_data_before_any_upload(self):
        self.fixture.write_text("INSERT INTO fixture VALUES ('CREATE TABLE fake (id INTEGER);');\n")
        result = self.run_script("export")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("the export has no schema", result.stderr)
        self.assertFalse(self.bucket.exists())

    def test_export_refuses_options_that_omit_schema_or_data(self):
        for i, flags in enumerate((["--no-schema"], ["--no-data"], ["--schema=false"], ["--data=false"],
                                   ["--schema", "false"], ["--data", "false"],
                                   ["--table", "fixture"], ["--table=fixture"])):
            with self.subTest(flags=flags):
                self.env["FAKE_DATE"] = str(int(MS) + i)
                result = self.run_script("export", *flags)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("catalogue backups must include schema and data", result.stderr)
                self.assertEqual(self.calls(), [])

    def test_rclone_export_refuses_wrangler_mode_and_dump_overrides(self):
        self.env["VELMORA_EXPORT_RCLONE_REMOTE"] = "r2x"
        for i, flags in enumerate((["--data=0"], ["--schema=0"], ["--remote=false"], ["--local"],
                                   ["--compatibility", "sqlite3_cli_only"])):
            with self.subTest(flags=flags):
                self.env["FAKE_DATE"] = str(int(MS) + i)
                result = self.run_script("export", *flags)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("only Wrangler configuration options are allowed", result.stderr)
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

    def test_concurrent_exports_publish_only_the_winners_parts(self):
        work = Path(self.env["TMPDIR"])
        loser_sql = work / "loser.sql"
        loser_sql.write_text("CREATE TABLE other (value INTEGER);\n")
        for name in ("winner-checked", "loser-published", "winner-readback"):
            os.mkfifo(work / name)
        with ThreadPoolExecutor(max_workers=1) as pool:
            winner = pool.submit(self.call_script, "export", FAKE_RACE="winner")
            with os.fdopen(os.open(work / "winner-checked", os.O_RDWR), "rb") as gate:
                self.assertTrue(select.select([gate], [], [], 10)[0], "winner did not check manifest")
                self.assertEqual(gate.read(2), b"go")
            # Simulate another host (different lock directory, same R2 store).
            other_host = work / "other-host"
            other_host.mkdir()
            loser = self.call_script("export", FAKE_RACE="loser", FAKE_FIXTURE=str(loser_sql),
                                     TMPDIR=str(other_host), FAKE_RACE_DIR=str(work))
            won = winner.result()
        self.assertEqual(won.returncode, 0, won.stderr)
        puts = [call[5].removeprefix(f"{BUCKET}/") for call in self.calls()
                if call[:5] == ["local", "wrangler", "r2", "object", "put"]]
        manifest_key = f"d1/{SOURCE}/{MS}.manifest.json"
        loser_parts = puts[:puts.index(manifest_key)]
        manifest = json.loads(self.object_path(manifest_key).read_text())
        winner_parts = [part["key"] for part in manifest["parts"]]
        self.assertTrue(set(loser_parts).isdisjoint(winner_parts), "export attempts reused part keys")
        self.assert_refused(loser, f"another export published restore point {MS}")
        self.assert_loaded(self.run_script("import", "scratch-db", MS), MS)
        for part in manifest["parts"]:
            self.assertEqual(hashlib.sha256(self.object_path(part["key"]).read_bytes()).hexdigest(),
                             part["sha256"])
        data = b"".join(self.object_path(key).read_bytes() for key in loser_parts)
        sql = subprocess.run(["zstd", "-q", "-dc"], input=data, capture_output=True, check=True)
        self.assertEqual(sql.stdout, loser_sql.read_bytes())

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
                self.reset_scratch_target()
                self.assert_loaded(self.run_script("import", "scratch-db", ms), ms)

    def reset_scratch_target(self):
        (self.db / "scratch-db").unlink(missing_ok=True)
        (self.db / "sqlite" / "scratch-db.sqlite").unlink(missing_ok=True)
        batches = self.db / "batches"
        if batches.exists():
            shutil.rmtree(batches)

    def assert_loaded(self, result, ms, leading_lines=()):
        self.assertEqual(result.returncode, 0, result.stderr)
        loaded = (self.db / "scratch-db").read_bytes()
        self.assertEqual(loaded, self.fixture.read_bytes())
        with sqlite3.connect(self.db / "sqlite" / "scratch-db.sqlite") as target:
            self.assertEqual(target.execute("SELECT 1 FROM sqlite_master WHERE name='_velmora_import_incomplete'").fetchall(), [])
        lines = result.stdout.splitlines()
        self.assertEqual(lines[:len(leading_lines)], list(leading_lines))
        self.assertRegex(lines[len(leading_lines)], r"^split verified: \d+ statements, \d+ bytes in \d+ batches$")
        for line in lines[len(leading_lines) + 1:-2]:
            self.assertRegex(line, r"^catalog-import: row count for .+: expected (\d+), found \1$")
        self.assertEqual(lines[-2:], [
            f"catalog-import: loaded {len(loaded)} bytes into scratch-db from restore point {ms}",
            "catalog-import: next: migrations apply, then ops/restore-arm.sql (README, Restore step 2)",
        ])

    def assert_refused(self, result, message):
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(message, result.stderr)
        self.assertEqual([path for path in self.db.iterdir() if path.is_file()], [])

    def test_import_uses_confirmed_uuid_even_if_binding_is_remapped_after_preflight(self):
        ms, _, _, _ = self.export()
        before = len(self.calls())
        self.env["FAKE_REMAP_TARGET"] = OTHER_DATABASE_ID
        result = self.run_script("import", "scratch-db", ms)
        self.assertTrue((self.db / "binding-remapped").exists())
        self.assertFalse((self.db / "sqlite" / f"{OTHER_DATABASE_ID}.sqlite").exists(),
                         "a later D1 call wrote to the remapped database")
        self.assert_loaded(result, ms)
        calls = [call for call in self.calls()[before:] if call[2:3] == ["d1"]]
        self.assertEqual(calls[0][3:5], ["info", "scratch-db"])
        self.assertGreater(len(calls), 1)
        self.assertTrue(all(call[3:5] == ["execute", DATABASE_ID] for call in calls[1:]), calls)

    def test_import_round_trip(self):
        ms, _, _, _ = self.export()
        self.assert_loaded(self.run_script("import", "scratch-db", ms), ms)
        self.assertTrue(all(call[-len(ARGS):] == ARGS for call in self.calls()))

    def test_import_rejects_manifest_file_size_before_fetching_parts(self):
        ms, _, manifest, _ = self.export()
        self.env["VELMORA_TEST_SQL_FILE_BYTES"] = "100"
        before = len(self.calls())
        result = self.run_script("import", "scratch-db", ms)
        self.assert_refused(result, f"the SQL export is {manifest['sql_bytes']} bytes, "
                                    "over the 100 bytes allowed for this test; "
                                    "this export could not be restored by catalog-import.sh")
        self.assertEqual(len(self.calls()) - before, 3)  # d1 info, bounded preflight, then manifest GET

    def test_import_stops_decompression_one_byte_past_the_bound(self):
        ms, prefix, manifest, _ = self.export()
        work = Path(self.env["TMPDIR"])
        fake_rm = work / "rm"
        fake_rm.write_text('#!/bin/sh\n'
                           'case "${3-}" in\n'
                           '  */velmora-import.*)\n'
                           '    [ ! -f "$3/catalog.sql" ] || wc -c <"$3/catalog.sql" >"$TMPDIR/size";;\n'
                           'esac\nexec /bin/rm "$@"\n')
        fake_rm.chmod(0o755)
        self.env["VELMORA_TEST_SQL_FILE_BYTES"] = "100"
        for declared in (100, 60):
            with self.subTest(declared=declared):
                manifest["sql_bytes"] = declared
                self.object_path(f"{prefix}.manifest.json").write_text(json.dumps(manifest))
                result = self.run_script("import", "scratch-db", ms)
                self.assertEqual(int((work / "size").read_text()), declared + 1)
                self.assert_refused(result, f"decompressed SQL exceeds {declared} bytes")
                self.assertFalse(any(map(is_d1_write, self.calls())))

    def test_import_bounds_oversized_part_downloads_for_both_transports(self):
        ms, _, manifest, _ = self.export()
        part = manifest["parts"][0]
        self.assertEqual(part["bytes"], 4096)
        self.object_path(part["key"]).write_bytes(b"x" * 1_000_000)
        work = Path(self.env["TMPDIR"])
        fake_rm = work / "rm"
        fake_rm.write_text('#!/bin/sh\n'
                           'case "${3-}" in\n'
                           '  */velmora-import.*)\n'
                           '    [ ! -f "$3/part" ] || wc -c <"$3/part" >"$TMPDIR/part-size";;\n'
                           'esac\nexec /bin/rm "$@"\n')
        fake_rm.chmod(0o755)
        for transport in ("wrangler", "rclone"):
            with self.subTest(transport=transport):
                if transport == "rclone":
                    self.env["VELMORA_EXPORT_RCLONE_REMOTE"] = "r2x"
                size = work / "part-size"
                size.unlink(missing_ok=True)
                result = self.run_script("import", "scratch-db", ms)
                self.assert_refused(result, f"size mismatch for {part['key']}")
                self.assertFalse(any(map(is_d1_write, self.calls())))
                self.assertEqual(int(size.read_text()), 4097)

    def test_import_rejects_whole_file_checksum_mismatches(self):
        ms, prefix, manifest, _ = self.export()
        manifest_path = self.object_path(f"{prefix}.manifest.json")
        for field, suffix in (("zst_sha256", ".sql.zst"), ("sql_sha256", ".sql")):
            with self.subTest(field=field):
                manifest_path.write_text(json.dumps({**manifest, field: "0" * 64}))
                self.assert_refused(self.run_script("import", "scratch-db", ms),
                                    f"sha256 mismatch for {prefix}{suffix} (from {prefix}.manifest.json)")

    def test_import_rejects_truncated_zstd_after_part_and_stream_checksums_pass(self):
        self.fixture.write_text("CREATE TABLE fixture (value INTEGER);\n")
        ms, prefix, manifest, _ = self.export()
        part, = manifest["parts"]
        path = self.object_path(part["key"])
        truncated = path.read_bytes()[:-1]
        path.write_bytes(truncated)
        manifest["zst_bytes"] = part["bytes"] = len(truncated)
        manifest["zst_sha256"] = part["sha256"] = hashlib.sha256(truncated).hexdigest()
        self.object_path(f"{prefix}.manifest.json").write_text(json.dumps(manifest))
        self.assert_refused(self.run_script("import", "scratch-db", ms),
                            f"decompression failed for {prefix}.sql.zst")

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
        self.assertTrue(any(call[:5] == ["local", "wrangler", "r2", "object", "get"]
                            and call[5] == f"{BUCKET}/{key}" for call in self.calls()))
        self.assertFalse(any(map(is_d1_write, self.calls())))

    def test_import_refuses_non_digit_restore_point(self):
        self.assert_refused(self.run_script("import", "scratch-db", "12x"), "only digits")
        self.assertEqual(self.calls(), [])

    def test_import_requires_production_opt_in_for_resolved_name(self):
        ms, _, _, _ = self.export()
        self.env["FAKE_DATABASE_NAME"] = "velmora-catalog"
        self.assert_refused(self.run_script("import", "scratch-db", ms),
                            "velmora-catalog without VELMORA_IMPORT_PRODUCTION=yes")
        self.assertEqual(self.calls()[-1],
                         ["local", "wrangler", "d1", "info", "scratch-db", "--json", *ARGS])
        self.env["VELMORA_IMPORT_PRODUCTION"] = "yes"
        self.assert_loaded(self.run_script("import", "scratch-db", ms), ms)

    def test_import_checks_resolved_database_id_before_emptiness_check(self):
        ms, _, _, _ = self.export()
        for expected in (None, "22222222-3333-4444-8555-666666666666"):
            with self.subTest(expected=expected):
                if expected is None:
                    del self.env["VELMORA_IMPORT_DATABASE_ID"]
                else:
                    self.env["VELMORA_IMPORT_DATABASE_ID"] = expected
                before = len(self.calls())
                self.assert_refused(self.run_script("import", "scratch-db", ms),
                                    f"resolved UUID {DATABASE_ID}, VELMORA_IMPORT_DATABASE_ID={expected or '<unset>'}")
                self.assertFalse(any(call[:4] == ["local", "wrangler", "d1", "execute"]
                                     for call in self.calls()[before:]))

    def test_import_rejects_inconsistent_manifest_sizes_before_part_downloads(self):
        ms, prefix, manifest, _ = self.export()
        key = f"{prefix}.manifest.json"
        first = manifest["parts"][0]
        for changes in ({"parts": [first] * 1001, "zst_bytes": first["bytes"] * 1001},
                        {"zst_bytes": manifest["zst_bytes"] + 1},
                        {"parts": [{**manifest["parts"][0], "bytes": 300000001}],
                         "zst_bytes": 300000001}):
            with self.subTest(fields=list(changes)):
                self.object_path(key).write_text(json.dumps({**manifest, **changes}))
                before = len(self.calls())
                self.assert_refused(self.run_script("import", "scratch-db", ms), f"invalid manifest {key}")
                self.assertEqual([call[5] for call in self.calls()[before:]
                                  if call[2:5] == ["r2", "object", "get"]], [f"{BUCKET}/{key}"])

    def use_nearly_full_disk(self):
        df = Path(self.env["TMPDIR"]) / "df"
        df.write_text('#!/bin/sh\n[ "$1" = -Pk ] || { echo "df: illegal option -- B" >&2; exit 1; }\n'
                      'printf "Filesystem 1024-blocks Used Available Capacity Mounted on\\n"\n'
                      'printf "fixture 10000 9999 1 99%% /tmp\\n"\n')
        df.chmod(0o755)

    def test_import_checks_disk_before_fetching_any_parts(self):
        ms, prefix, _, _ = self.export()
        self.use_nearly_full_disk()
        before = len(self.calls())
        self.assert_refused(self.run_script("import", "scratch-db", ms),
                            "insufficient local disk space")
        self.assertEqual([call[5] for call in self.calls()[before:]
                          if call[2:5] == ["r2", "object", "get"]], [f"{BUCKET}/{prefix}.manifest.json"])

    def test_import_checks_legacy_disk_before_splitting_or_writing(self):
        key = f"d1/{SOURCE}/{MS}.sql"
        path = self.object_path(key)
        path.parent.mkdir(parents=True)
        shutil.copyfile(self.fixture, path)
        self.use_nearly_full_disk()
        self.assert_refused(self.run_script("import", "scratch-db", MS), "insufficient local disk space")
        self.assertFalse(any(map(is_d1_write, self.calls())))
        self.assertEqual([call[5] for call in self.calls() if call[2:5] == ["r2", "object", "get"]],
                         [f"{BUCKET}/d1/{SOURCE}/{MS}.manifest.json", f"{BUCKET}/{key}"])

    def test_export_records_sizes_and_warns_at_sixty_percent(self):
        sizes = Path(self.env["TMPDIR"]) / "sizes.log"
        sizes.write_text('{}\n')
        self.fixture.write_bytes(b"CREATE TABLE t (x);\nINSERT INTO t VALUES ('" +
                                 b"x" * (60_000 - len("INSERT INTO t VALUES ('');\n")) + b"');\n")
        self.env.update(VELMORA_EXPORT_SIZES_LOG=str(sizes), FAKE_DATABASE_SIZE="6000000000")
        result = self.run_script("export")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = sizes.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        entry = json.loads(lines[1])
        self.assertEqual(entry["restore_point_ms"], int(MS))
        self.assertEqual(entry["sql_bytes"], self.fixture.stat().st_size)
        self.assertEqual(entry["longest_statement_bytes"], 60_000)
        self.assertEqual(entry["database_size_bytes"], 6_000_000_000)
        self.assertRegex(result.stderr, r"WARNING .*60000 is 60% of 100000")
        self.assertRegex(result.stderr, r"WARNING .*6000000000 is 60% of 10000000000")

    def test_export_publishes_when_database_size_is_unavailable(self):
        sizes = Path(self.env["TMPDIR"]) / "sizes.jsonl"
        self.env["VELMORA_EXPORT_SIZES_LOG"] = str(sizes)
        for i, (setting, reason) in enumerate((
                ("FAKE_FAIL_INFO", "wrangler d1 info failed"),
                ("FAKE_OMIT_SIZE", "missing or invalid size in d1 info"))):
            with self.subTest(reason=reason):
                self.env["FAKE_DATE"] = str(int(MS) + i)
                self.env[setting] = "yes"
                try:
                    result = self.run_script("export")
                finally:
                    del self.env[setting]
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"catalog-export: WARNING database size unavailable ({reason}", result.stderr)
                self.assertNotIn("WARNING database_size_bytes", result.stderr)
                self.assertTrue(self.object_path(f"d1/{SOURCE}/{self.env['FAKE_DATE']}.manifest.json").is_file())
                self.assertIsNone(json.loads(sizes.read_text().splitlines()[-1])["database_size_bytes"])

    def batched_fixture(self):
        header = b"PRAGMA defer_foreign_keys=TRUE;\n"
        schema = [b"CREATE TABLE parent (id INTEGER PRIMARY KEY, label TEXT);\n",
                  b"CREATE TABLE child (pid INTEGER REFERENCES parent(id), label TEXT);\n",
                  b"CREATE TABLE other (label TEXT);\n"]
        children = [f"INSERT INTO child VALUES (1, '{i};\n{'x' * 45}');\n".encode()
                    for i in range(3)]
        parents = [b"INSERT INTO parent VALUES (1, 'parent');\n"]
        others = [b"INSERT INTO other VALUES ('" + b"z" * 65 + b"');\n"] * 3
        final = [b"CREATE INDEX child_idx ON child (pid);\n"]
        self.fixture.write_bytes(header + b"".join(schema + children + parents + others + final))
        self.env["VELMORA_IMPORT_BATCH_BYTES"] = "215"
        return header, schema, children, parents, others, final

    def test_batched_import_orders_foreign_keys_and_preserves_statements(self):
        header, schema, children, parents, others, final = self.batched_fixture()
        ms, _, _, _ = self.export()
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 0, result.stderr)
        batches = sorted((self.db / "batches").glob("*.sql"))
        self.assertGreaterEqual(len(batches), 4)
        statements = []
        for batch in batches:
            body = batch.read_bytes()
            self.assertTrue(body.startswith(header))
            self.assertLessEqual(len(body), 215)
            statements.append(body.removeprefix(header))
        self.assertEqual(statements[0], b"".join(schema))
        self.assertEqual(statements[-1], b"".join(final))
        data = b"".join(statements[1:-1])
        expected = parents + children + others
        for statement in set(expected):
            self.assertEqual(data.count(statement), expected.count(statement))
        self.assertEqual(len(data), sum(map(len, expected)))
        original_order = schema + children + parents + others + final
        self.assertEqual(header + b"".join(original_order), self.fixture.read_bytes())
        self.assertEqual(len(b"".join(statements)), sum(map(len, original_order)))
        self.assertLess(data.index(parents[0]), data.index(children[0]))
        self.assertIn("split verified", result.stdout)
        self.assertIn("row count for child: expected 3, found 3", result.stdout)

    def test_schema_and_footer_each_rotate_at_statement_boundaries(self):
        header = b"PRAGMA defer_foreign_keys=TRUE;\n"
        schema = [b"CREATE TABLE one (id INTEGER PRIMARY KEY, v TEXT, w TEXT);\n",
                  b"CREATE TABLE two (id INTEGER PRIMARY KEY, v TEXT, w TEXT);\n"]
        footer = [b"CREATE INDEX one_v_w ON one (v, w);\n", b"CREATE INDEX two_v_w ON two (v, w);\n"]
        cap = 95
        for offset, statements in enumerate((schema, [schema[0], footer[0], footer[0].replace(b"one_v_w", b"one_w_v")])):
            with self.subTest(statements=statements):
                self.env.update(FAKE_DATE=str(int(MS) + offset), VELMORA_IMPORT_BATCH_BYTES=str(cap))
                self.fixture.write_bytes(header + b"".join(statements))
                ms, _, _, _ = self.export()
                self.reset_scratch_target()
                result = self.run_script("import", "scratch-db", ms)
                self.assertEqual(result.returncode, 0, result.stderr)
                batches = sorted((self.db / "batches").glob("*.sql"))
                self.assertEqual([file.read_bytes() for file in batches], [header + stmt for stmt in statements])
                self.assertTrue(all(file.stat().st_size <= cap for file in batches))

    def test_batch_failure_stops_before_later_batches_and_requires_recreation(self):
        self.batched_fixture()
        ms, _, _, _ = self.export()
        self.env["FAKE_FAIL_BATCH"] = "3"
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("batch 3 failed", result.stderr)
        self.assertIn("partial load", result.stderr)
        self.assertIn("deleted and recreated", result.stderr)
        self.assertEqual(sum(map(is_batch_load, self.calls())), 4)
        with sqlite3.connect(self.db / "sqlite" / "scratch-db.sqlite") as target:
            self.assertEqual(target.execute("SELECT restore_point FROM _velmora_import_incomplete").fetchall(),
                             [(int(ms),)])
            target.execute("CREATE TABLE restore_state (id PRIMARY KEY, state, since_ms, started_at, "
                           "finished_at, reached_phase, reached_after, reached_extent)")
            arm = (ROOT / "ops" / "restore-arm.sql").read_text()
            with self.assertRaisesRegex(sqlite3.OperationalError, "malformed JSON"):
                target.executescript(arm)
            self.assertEqual(target.execute("SELECT count(*) FROM restore_state").fetchone(), (0,))
            target.execute("DROP TABLE _velmora_import_incomplete")
            target.executescript(arm)
            self.assertEqual(target.execute("SELECT state FROM restore_state").fetchall(), [("replaying",)])

    def test_failure_in_last_batch_cannot_resume_verification(self):
        self.batched_fixture()
        ms, _, _, _ = self.export()
        self.env["FAKE_FAIL_BATCH"] = "footer"
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("partial load", result.stderr)
        del self.env["FAKE_FAIL_BATCH"]
        before = len(self.calls())
        retry = self.run_script("import", "scratch-db", ms)
        self.assertEqual(retry.returncode, 1, retry.stderr)
        self.assertIn("did not finish loading", retry.stderr)
        self.assertFalse(any("--file" in call for call in self.calls()[before:]))
        with sqlite3.connect(self.db / "sqlite" / "scratch-db.sqlite") as target:
            self.assertEqual(target.execute("SELECT phase FROM _velmora_import_incomplete").fetchall(), [("loading",)])
            self.assertEqual(target.execute("SELECT COUNT(1) FROM child").fetchone(), (3,))
            self.assertEqual(target.execute("SELECT 1 FROM sqlite_master WHERE name='child_idx'").fetchall(), [])

    def test_import_rechecks_each_batch_immediately_before_loading(self):
        self.batched_fixture()
        ms, _, _, _ = self.export()
        self.env["FAKE_MUTATE_NEXT_BATCH"] = "yes"
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("batch 1 failed its pre-load checksum", result.stderr)
        self.assertEqual(sum(map(is_batch_load, self.calls())), 1)

    def test_batched_import_reports_incorrect_row_count(self):
        self.batched_fixture()
        ms, _, _, _ = self.export()
        self.env["FAKE_MISMATCH_TABLE"] = "child"
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("row count for child: expected 3, found 4", result.stderr)
        marker = "SELECT phase FROM _velmora_import_incomplete"
        with sqlite3.connect(self.db / "sqlite" / "scratch-db.sqlite") as target:
            self.assertEqual(target.execute(marker).fetchall(), [("mismatch",)])
        before = len(self.calls())
        self.env["VELMORA_IMPORT_SKIP_ROW_COUNTS"] = "yes"
        skip = self.run_script("import", "scratch-db", ms)
        self.assertEqual(skip.returncode, 1, skip.stderr)
        self.assertIn("verification cannot be skipped on a retry", skip.stderr)
        del self.env["VELMORA_IMPORT_SKIP_ROW_COUNTS"]
        retry = self.run_script("import", "scratch-db", ms)
        self.assertEqual(retry.returncode, 1, retry.stderr)
        self.assertIn("previous verification found a row-count mismatch", retry.stderr)
        self.assertFalse(any(map(is_d1_write, self.calls()[before:])))
        with sqlite3.connect(self.db / "sqlite" / "scratch-db.sqlite") as target:
            self.assertEqual(target.execute(marker).fetchall(), [("mismatch",)])

    def test_verified_retry_uses_dump_counts_without_downloading_or_loading_batches(self):
        self.batched_fixture()
        ms, _, _, _ = self.export()
        self.env["FAKE_FAIL_VERIFY"] = "yes"
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("retry to resume verification", result.stderr)
        target_path = self.db / "sqlite" / "scratch-db.sqlite"
        marker = "SELECT phase FROM _velmora_import_incomplete"
        with sqlite3.connect(target_path) as target:
            self.assertEqual(target.execute(marker).fetchall(), [("verify",)])
            verification, = target.execute("SELECT verification FROM _velmora_import_incomplete").fetchone()
            self.assertIn({"name": "child", "expected": 3, "keys": ["rowid"]}, json.loads(verification)["tables"])
        del self.env["FAKE_FAIL_VERIFY"]

        self.env["VELMORA_IMPORT_DATABASE_ID"] = "22222222-3333-4444-8555-666666666666"
        wrong_id = self.run_script("import", "scratch-db", ms)
        self.assertIn("resolved UUID", wrong_id.stderr)
        self.assertEqual(wrong_id.returncode, 1)
        self.env["VELMORA_IMPORT_DATABASE_ID"] = DATABASE_ID
        wrong_point = self.run_script("import", "scratch-db", str(int(ms) + 1))
        self.assertIn("marker belongs to a different restore point or source", wrong_point.stderr)
        self.assertEqual(wrong_point.returncode, 1)

        before = len(self.calls())
        resumed = self.run_script("import", "scratch-db", ms)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertIn("resuming verification", resumed.stdout)
        self.assertTrue(all(call[2] == "d1" and "--file" not in call for call in self.calls()[before:]))
        with sqlite3.connect(target_path) as target:
            self.assertEqual(target.execute("SELECT 1 FROM sqlite_master WHERE name='_velmora_import_incomplete'").fetchall(), [])

    def test_retry_rejects_invalid_saved_verification_plan_without_clearing_marker(self):
        self.batched_fixture()
        ms, _, _, _ = self.export()
        self.env["FAKE_FAIL_VERIFY"] = "yes"
        self.assertEqual(self.run_script("import", "scratch-db", ms).returncode, 1)
        del self.env["FAKE_FAIL_VERIFY"]
        target_path = self.db / "sqlite" / "scratch-db.sqlite"
        with sqlite3.connect(target_path) as target:
            target.execute("UPDATE _velmora_import_incomplete SET verification=?",
                           (json.dumps({"format": 1, "tables": [{"name": "child", "expected": 3, "keys": []}]}),))
        before = len(self.calls())
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("invalid saved verification plan", result.stderr)
        self.assertFalse(any(map(is_d1_write, self.calls()[before:])))
        with sqlite3.connect(target_path) as target:
            self.assertEqual(target.execute("SELECT phase FROM _velmora_import_incomplete").fetchall(), [("verify",)])

    def test_explicit_verification_skip_allows_nocase_primary_key(self):
        self.fixture.write_text("CREATE TABLE t (k TEXT PRIMARY KEY COLLATE NOCASE) WITHOUT ROWID;\n"
                                "INSERT INTO t VALUES ('a');\n")
        ms, _, _, _ = self.export()
        self.assert_refused(self.run_script("import", "scratch-db", ms), "cannot verify t with an indexed")
        self.assertFalse(any(map(is_d1_write, self.calls())))
        self.env["VELMORA_IMPORT_SKIP_ROW_COUNTS"] = "yes"
        result = self.run_script("import", "scratch-db", ms)
        self.assert_loaded(result, ms)
        self.assertIn("WARNING verification skipped", result.stderr)

    def test_integer_cursor_is_text_even_on_older_sqlite_json(self):
        make_query = runpy.run_path(str(ROOT / "ops" / "sql_longest_statement.py"))["verification_query"]
        with sqlite3.connect(":memory:") as target:
            # Emulate SQLite 3.37.2's numeric quote() output inside JSON.
            target.create_function("quote", 1, lambda value: value)
            target.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            target.execute("INSERT INTO t VALUES (9007199254740993)")
            n, raw = target.execute(make_query({"name": "t", "keys": ["rowid"]}, None)).fetchone()
            self.assertEqual((n, json.loads(raw)), (1, [["integer", "9007199254740993"]]))
            self.assertEqual(target.execute(make_query({"name": "t", "keys": ["rowid"]}, json.loads(raw))).fetchone(),
                             (0, None))

    def test_composite_text_cursor_seeks_on_every_primary_key_column(self):
        make_query = runpy.run_path(str(ROOT / "ops" / "sql_longest_statement.py"))["verification_query"]
        plan_row = {"name": "objects", "keys": ["bucket_id", "key"]}
        with sqlite3.connect(":memory:") as target:
            target.execute("CREATE TABLE objects(bucket_id TEXT, key TEXT, PRIMARY KEY(bucket_id,key)) WITHOUT ROWID")
            target.executemany("INSERT INTO objects VALUES ('B',?)", ((f"{n:05}",) for n in range(50_000)))
            work = []
            for suffix in (b"00010", b"44000"):
                query = make_query(plan_row, [["text", "42"], ["text", suffix.hex().upper()]])
                plan = [row[3] for row in target.execute("EXPLAIN QUERY PLAN " + query)]
                self.assertTrue(any("SEARCH objects USING PRIMARY KEY (bucket_id=? AND key>?)" in step
                                    for step in plan), plan)
                self.assertTrue(any("SEARCH objects USING PRIMARY KEY (bucket_id>?)" in step for step in plan), plan)
                steps = []
                target.set_progress_handler(lambda: steps.append(None) or 0, 1000)
                self.assertEqual(target.execute(query).fetchone()[0], 5000)
                target.set_progress_handler(None, 0)
                work.append(len(steps))
            self.assertLessEqual(abs(work[1] - work[0]), 2, work)

    def test_verification_refuses_stalled_cursor_and_leaves_marker(self):
        self.fixture.write_text("CREATE TABLE fixture (id INTEGER PRIMARY KEY);\n"
                                "INSERT INTO fixture VALUES (1);\n")
        ms, _, _, _ = self.export()
        self.env["FAKE_STALLED_CURSOR"] = "yes"
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("verification cursor did not advance for fixture", result.stderr)
        self.assertEqual((self.db / "stalled-cursor-pages").read_text(), "2")
        with sqlite3.connect(self.db / "sqlite" / "scratch-db.sqlite") as target:
            self.assertEqual(target.execute("SELECT phase FROM _velmora_import_incomplete").fetchall(), [("verify",)])

    def test_verification_uses_bounded_keyset_pages_for_rowid_and_composite_pk(self):
        with self.fixture.open("w") as dump:
            dump.write("CREATE TABLE r (id INTEGER PRIMARY KEY);\n"
                       "CREATE TABLE p (a BLOB, b TEXT, PRIMARY KEY (a,b)) WITHOUT ROWID;\n")
            for i in range(10_001):
                dump.write(f"INSERT INTO r VALUES ({i * 2});\n"
                           f"INSERT INTO p VALUES (X'{i // 3:08x}', 'v''{i % 3}');\n")
        ms, _, _, _ = self.export()
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 0, result.stderr)
        for table in ("r", "p"):
            pages = [call[call.index("--command") + 1] for call in self.calls() if "--command" in call
                     and f'FROM "{table}"' in call[call.index("--command") + 1]]
            self.assertGreaterEqual(len(pages), 2)
            self.assertTrue(all("LIMIT 5000" in sql for sql in pages))
            self.assertTrue(any("WHERE" in sql and ">" in sql for sql in pages[1:]))
            with sqlite3.connect(self.db / "sqlite" / "scratch-db.sqlite") as target:
                for sql in pages[1:]:
                    plan = [row[3] for row in target.execute("EXPLAIN QUERY PLAN " + sql)]
                    self.assertTrue(any(f"SEARCH {table} USING " in step for step in plan), plan)
            self.assertIn(f"row count for {table}: expected 10001, found 10001", result.stdout)

    def test_batched_import_accepts_current_migration_schema(self):
        with sqlite3.connect(":memory:") as db:
            for migration in sorted((ROOT / "migrations").glob("*.sql")):
                db.executescript(migration.read_text())
            dump = [stmt for stmt in db.iterdump() if stmt not in ("BEGIN TRANSACTION;", "COMMIT;")]
        self.fixture.write_text("PRAGMA defer_foreign_keys=TRUE;\n" + "\n".join(dump) + "\n")
        ms, _, _, _ = self.export()
        self.env["VELMORA_IMPORT_SKIP_ROW_COUNTS"] = "yes"
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WARNING verification skipped", result.stderr)
        self.assertFalse(any("--command" in call and call[call.index("--command") + 1].startswith("WITH page ")
                             for call in self.calls()))

    def test_restore_preserves_wrangler_migration_autoincrement_footer(self):
        with sqlite3.connect(":memory:") as source:
            source.executescript("CREATE TABLE d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                 "name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL);"
                                 "INSERT INTO d1_migrations (id, name) VALUES (1, 'first'), (20, 'removed');"
                                 "DELETE FROM d1_migrations WHERE id = 20;")
            dump = [stmt for stmt in source.iterdump() if stmt not in ("BEGIN TRANSACTION;", "COMMIT;")]
        self.fixture.write_text("PRAGMA defer_foreign_keys=TRUE;\n" + "\n".join(dump) + "\n")
        ms, _, _, _ = self.export()
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("row count for d1_migrations: expected 1, found 1", result.stdout)
        self.assertNotIn("row count for sqlite_sequence:", result.stdout)
        with sqlite3.connect(self.db / "sqlite" / "scratch-db.sqlite") as restored:
            self.assertEqual(restored.execute("SELECT seq FROM sqlite_sequence WHERE name='d1_migrations'").fetchone(), (20,))
            next_id = restored.execute("INSERT INTO d1_migrations (name) VALUES ('next')").lastrowid
            self.assertEqual(next_id, 21)

    def test_split_works_without_python311_authorizer_clearing(self):
        # Python 3.10's sqlite binding registers None as the callback instead
        # of removing it; any authorized operation then gets SQLITE_DENY.
        connect = sqlite3.connect

        class Python310Connection:
            def __init__(self, *args, **kwargs):
                self.inner = connect(*args, **kwargs)

            def set_authorizer(self, callback):
                self.inner.set_authorizer(callback if callback is not None else lambda *_: sqlite3.SQLITE_DENY)

            def __getattr__(self, key):
                return getattr(self.inner, key)

        tool = self.root / "ops" / "sql_longest_statement.py"
        self.fixture.write_text("CREATE TABLE t (x);\nINSERT INTO t VALUES (1);\n")
        output = StringIO()
        with patch.object(sqlite3, "connect", Python310Connection), redirect_stdout(output):
            runpy.run_path(str(tool))["split_dump"](self.fixture, self.env["TMPDIR"], 1000, 100000)
        self.assertIn("split verified: 2 statements", output.getvalue())

    def test_split_authorizer_denies_ddl_that_can_execute_non_schema_sql(self):
        for statement in ("CREATE TABLE t AS SELECT 1;", "CREATE TABLE t (x CHECK(abs(x)>0));"):
            with self.subTest(statement=statement):
                self.fixture.write_text(statement + "\n")
                self.env["FAKE_DATE"] = str(int(self.env.get("FAKE_DATE", MS)) + 1)
                ms, _, _, _ = self.export()
                self.assert_refused(self.run_script("import", "scratch-db", ms), "could not split catalogue dump")
                self.assertFalse(any(map(is_d1_write, self.calls())))

    def test_batched_import_refuses_cycles_before_loading(self):
        self.fixture.write_text("CREATE TABLE a (id INTEGER PRIMARY KEY, bid REFERENCES b(id));\n"
                                "CREATE TABLE b (id INTEGER PRIMARY KEY, aid REFERENCES a(id));\n")
        ms, _, _, _ = self.export()
        result = self.run_script("import", "scratch-db", ms)
        self.assert_refused(result, "foreign key cycle")
        self.assertFalse(any(map(is_d1_write, self.calls())))

    def test_self_referencing_rows_are_loaded_together_when_parent_used_batch_space(self):
        parent = "INSERT INTO a VALUES (1, '" + "x" * 30 + "');\n"
        self.assertEqual(len(parent.encode()), 60)
        first = "INSERT INTO t VALUES (1,2,1,'123456789');\n"
        second = "INSERT INTO t VALUES (2,1,1,'123456789');\n"
        self.fixture.write_text(
            "PRAGMA defer_foreign_keys=TRUE;\n"
            "CREATE TABLE a(id INTEGER PRIMARY KEY,v TEXT);\n"
            "CREATE TABLE t(id INTEGER PRIMARY KEY,p REFERENCES t(id),a REFERENCES a(id),v TEXT);\n"
            + parent + first + second
        )
        ms, _, _, _ = self.export()
        self.env["VELMORA_IMPORT_BATCH_BYTES"] = "160"
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("row count for t: expected 2, found 2", result.stdout)
        batches = [path.read_text() for path in (self.db / "batches").glob("batch-*.sql")]
        self.assertEqual(sum(first in batch or second in batch for batch in batches), 1)
        self.assertTrue(any(first in batch and second in batch for batch in batches))

    def test_self_referencing_table_must_fit_in_one_data_batch(self):
        self.fixture.write_text("PRAGMA defer_foreign_keys=TRUE;\n"
                                "CREATE TABLE t (id INTEGER PRIMARY KEY, pid REFERENCES t(id), label TEXT);\n"
                                "INSERT INTO t VALUES (1, 2, '" + "a" * 50 + "');\n"
                                "INSERT INTO t VALUES (2, 1, '" + "b" * 50 + "');\n")
        ms, _, _, _ = self.export()
        self.env["VELMORA_IMPORT_BATCH_BYTES"] = "140"
        self.assert_refused(self.run_script("import", "scratch-db", ms),
                            "rows for self-referencing table t do not fit in one batch")
        self.assertFalse(any(map(is_d1_write, self.calls())))
        self.env["VELMORA_IMPORT_BATCH_BYTES"] = "220"
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("row count for t: expected 2, found 2", result.stdout)
        self.assertEqual(len(list((self.db / "batches").glob("*.sql"))), 2)

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
        log = self.assert_kept_log(self.run_script("import", "scratch-db", ms),
                                   f"catalog-import: could not read {key}, see ")
        self.assertEqual(log.read_text().strip(), MISSING)

    def test_wrong_restore_point_in_manifest(self):
        ms, prefix, manifest, _ = self.export()
        manifest["restore_point_ms"] += 1
        key = f"{prefix}.manifest.json"
        self.object_path(key).write_text(json.dumps(manifest))
        self.assert_refused(self.run_script("import", "scratch-db", ms), f"invalid manifest {key}")

    def test_manifest_without_format_is_format_1(self):
        # Both formats used before attempt IDs had the same part keys.
        ms, prefix, manifest, _ = self.export()
        key = f"{prefix}.manifest.json"
        del manifest["format"]
        del manifest["attempt"]
        for index, part in enumerate(manifest["parts"]):
            legacy_key = f"{prefix}.sql.zst.part-{index:03d}"
            self.object_path(part["key"]).rename(self.object_path(legacy_key))
            part["key"] = legacy_key
        self.object_path(key).write_text(json.dumps(manifest))
        self.assert_loaded(self.run_script("import", "scratch-db", ms), ms)
        manifest["format"] = 1
        self.object_path(key).write_text(json.dumps(manifest))
        self.reset_scratch_target()
        self.assert_loaded(self.run_script("import", "scratch-db", ms), ms)
        manifest["format"] = 3
        self.object_path(key).write_text(json.dumps(manifest))
        self.reset_scratch_target()
        self.assert_refused(self.run_script("import", "scratch-db", ms), f"invalid manifest {key}")

    def test_import_refuses_manifest_naming_another_database(self):
        ms, prefix, manifest, _ = self.export()
        key = f"{prefix}.manifest.json"
        manifest["database"] = "other-catalog"
        self.object_path(key).write_text(json.dumps(manifest))
        before = len(self.calls())
        self.assert_refused(self.run_script("import", "scratch-db", ms), f"invalid manifest {key}")
        self.assertEqual(sum(call[2:5] == ["r2", "object", "get"]
                             for call in self.calls()[before:]), 1)

    def test_import_refuses_parts_from_another_attempt(self):
        ms, prefix, manifest, _ = self.export()
        key = f"{prefix}.manifest.json"
        part = manifest["parts"][0]
        another_attempt = "f" * 16 if manifest["attempt"] != "f" * 16 else "e" * 16
        foreign_key = f"{prefix}.{another_attempt}.part-000"
        self.object_path(foreign_key).write_bytes(self.object_path(part["key"]).read_bytes())
        part["key"] = foreign_key
        self.object_path(key).write_text(json.dumps(manifest))
        before = len(self.calls())
        self.assert_refused(self.run_script("import", "scratch-db", ms), f"invalid manifest {key}")
        self.assertEqual(len(self.calls()) - before, 3)  # d1 info, bounded preflight, then manifest GET

    def test_nonempty_target(self):
        ms, _, _, _ = self.export()
        self.assert_loaded(self.run_script("import", "scratch-db", ms), ms)
        before = len(self.calls())
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("catalog-import: scratch-db is not empty", result.stderr)
        resolve, probe = self.calls()[before:]
        self.assertEqual(resolve[2:4], ["d1", "info"])
        self.assertEqual(probe[2:4], ["d1", "execute"])
        self.assertFalse(is_d1_write(probe))
        sql = probe[probe.index("--command") + 1]
        self.assertNotIn("COUNT(", sql.upper())
        self.assertEqual(sql.upper().count("LIMIT 1"), 2)

    def test_stale_preflight_cannot_mark_a_completed_restore(self):
        ms, _, _, _ = self.export()
        self.assert_loaded(self.run_script("import", "scratch-db", ms), ms)
        target_path = self.db / "sqlite" / "scratch-db.sqlite"
        before_db = target_path.read_bytes()
        before = len(self.calls())
        self.env["FAKE_STALE_EMPTY_PREFLIGHT"] = "yes"
        result = self.run_script("import", "scratch-db", ms)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("could not claim an empty target", result.stderr)
        self.assertFalse(any(map(is_batch_load, self.calls()[before:])))
        self.assertEqual(target_path.read_bytes(), before_db)
        with sqlite3.connect(target_path) as target:
            self.assertEqual(target.execute("SELECT 1 FROM sqlite_master WHERE name='_velmora_import_incomplete'").fetchall(), [])

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
                self.reset_scratch_target()
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
        log = self.assert_kept_log(result, f"catalog-import: could not read {prefix}.manifest.json, see ")
        self.assertEqual(log.read_text().strip(), self.env["FAKE_MISSING"])
        self.assertEqual(len(self.calls()), 3)  # d1 info, bounded preflight, then manifest GET

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
                log = self.assert_kept_log(result, f"catalog-import: could not read {prefix}.manifest.json, see ")
                self.assertEqual(log.read_text().splitlines(),
                                 [f"stub manifest error line {line:02d}" for line in range(25)])
                self.assertNotIn("stub manifest error", result.stderr)
                self.assertEqual(len(self.calls()) - before, 4 if remote else 3)  # includes d1 info and preflight

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

    def test_import_rejects_legacy_sql_over_test_cap_before_executing(self):
        key = f"d1/{SOURCE}/{MS}.sql"
        path = self.object_path(key)
        path.parent.mkdir(parents=True)
        path.write_bytes(self.fixture.read_bytes())
        self.env["VELMORA_TEST_SQL_FILE_BYTES"] = "100"
        self.assert_refused(self.run_script("import", "scratch-db", MS),
                            f"the SQL export is {self.fixture.stat().st_size} bytes, over the 100 bytes")
        self.assertFalse(any(map(is_d1_write, self.calls())))

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
