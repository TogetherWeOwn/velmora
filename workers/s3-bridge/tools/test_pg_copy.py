"""Local-only D1 export, Postgres COPY/verify, and rollback integration tests."""

from hashlib import sha256
import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid

BRIDGE = Path(__file__).resolve().parents[1]
OPS = BRIDGE / "ops"
sys.path.insert(0, str(OPS))
from pg_catalog import Failure, capture_boundaries, pg_settings, seal_path, sqlite_boundaries, write_seal

ATTEMPT = "0" * 31 + "1"
D1_ID = "00000000-0000-0000-0000-000000000005"
BEFORE = dict(id=1, state="complete", since_ms=4, started_at=9, finished_at=12,
              reached_phase=5, reached_after="é'\n", reached_extent=2)
ARMED = dict(id=1, state="replaying", since_ms=-1, started_at=10, finished_at=None,
             reached_phase=None, reached_after=ATTEMPT, reached_extent=None)
F1 = dict(f1_started_at_ms=1_000_000, restore_state_before=BEFORE, restore_state_armed=ARMED,
          f1_attempt_id=ATTEMPT, d1_uuid=D1_ID, worker_name="wp5-local")
LIMIT = 2**53 - 1


def migrations(db):
    files = sorted((BRIDGE / "migrations").glob("*.sql"))
    assert [int(p.name[:4]) for p in files] == [*range(1, 23), 25, 26, 27]
    for path in files:
        db.executescript(path.read_text())


def fixture(db):
    migrations(db)
    db.execute("INSERT INTO buckets VALUES ('b', 'demo', 'owner', x'01', 1, 0, ?)", (LIMIT,))
    db.execute("INSERT INTO access_keys VALUES ('id','abc',x'02',1,'active',?)", (-LIMIT,))
    db.execute("INSERT INTO grants VALUES ('id','b','rw')")
    db.execute("""INSERT INTO generations
        (id,bucket_id,key,state,size,etag,content_json,user_meta_json,extent_count,created_at)
        VALUES ('g','b','é🌊','live',2,'etag','a','bc',2,100)""")
    db.execute("INSERT INTO objects VALUES ('b','é🌊','g')")
    for index, id_, wrapped in [(0, "z", b""), (1, "a", None)]:
        db.execute("""INSERT INTO extents
          (id,bucket_id,generation_id,state,seq,plain_offset,plain_size,cipher_size,media_header,
           wrapped_file_key,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at)
          VALUES (?, 'b', 'g', 'committed', ?, ?, 1, 1, x'00', ?, x'', x'', x'', 'held', ?)""",
                   (id_, index, index, wrapped, 100 + index))
        db.execute("""INSERT INTO outbox (rowid,extent_id,generation_id,stage,next_at,updated_at)
                      VALUES (?,?,'g','post',500,100)""", (2 + index * 100, id_))
    db.execute("""INSERT INTO articles
      (extent_id,idx,message_id,newsgroup,headers,cipher_offset,cipher_len,payload_sha256,state,yenc_name)
      VALUES ('z',0,'m','newsgroup',x'000102',0,1,x'','planned','valid9')""")
    db.execute("INSERT INTO scan_cursors VALUES ('revive','999'),('keep','cursor')")
    db.execute("INSERT INTO tx_guard VALUES (1),(1)")
    db.execute("INSERT INTO recovery_copy_log (at,kind,pass,detail) VALUES (1,'job',1,'nonempty'),(1,'job',1,NULL)")
    db.execute("INSERT INTO gc (id,extent_id,action,due_at) VALUES (15,'missing','delete_cache',123)")
    db.execute("INSERT INTO usage_recounts (id,started_at,finished_at,rows,adopted,drift) VALUES (18,1,2,3,0,0)")
    db.execute("INSERT INTO restore_state VALUES (?,?,?,?,?,?,?,?)", tuple(ARMED.values()))
    db.commit()


def run(name, *args):
    return subprocess.run([sys.executable, str(OPS / name), *map(str, args)], capture_output=True, text=True)


class CopyTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="velmora-pg-test-")
        self.addCleanup(scratch.cleanup)
        self.path = Path(scratch.name)
        self.db = self.path / "source.sqlite"
        self.f1 = self.path / "f1.json"
        self.manifest = self.path / "export-manifest.json"
        self.boundaries = self.path / "source-boundaries.json"
        self.f1.write_text(json.dumps(F1))
        self.f1.chmod(0o600)
        with sqlite3.connect(self.db) as db:
            fixture(db)
        self.db.chmod(0o600)
        self.seal_fixture()

    def seal_fixture(self):
        # Direct SQLite edge fixtures simulate a sealed export, including
        # intentional malformed values that the SQL loader itself rejects.
        with sqlite3.connect(self.db) as db:
            dump = "\n".join(db.iterdump()).encode()
            boundaries = sqlite_boundaries(db, F1)
        manifest = self.manifest_for(dump)
        self.boundaries.write_text(json.dumps(boundaries))
        seal_path(self.db).unlink(missing_ok=True)
        write_seal(self.db, manifest, F1, boundaries)

    def manifest_for(self, contents):
        manifest = dict(format=2, restore_point_ms=F1["f1_started_at_ms"],
                        sql_bytes=len(contents), sql_sha256=sha256(contents).hexdigest())
        self.manifest.write_text(json.dumps(manifest))
        return manifest

    def source_args(self):
        return ["--f1", self.f1, "--manifest", self.manifest, "--source-boundaries", self.boundaries]

    def copy(self, *args):
        return run("pg-copy.py", "--sqlite", self.db, *self.source_args(), *args)

    def test_dump_load_and_census_reports_held_for_replay(self):
        dump = self.path / "export.sql"
        with sqlite3.connect(self.db) as db, dump.open("w") as out:
            out.writelines(line + "\n" for line in db.iterdump())
        loaded = self.path / "loaded.sqlite"
        self.manifest_for(dump.read_bytes())
        result = run("pg-copy.py", "--export", dump, "--sqlite", loaded, *self.source_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report["s_held_ms"], report["held_count"], report["extent_count"]), (100, 2, 2))
        self.assertEqual(report["census"]["extents"]["wrapped_file_key"], {"blob": 1, "null": 1})
        result = subprocess.run(
            [sys.executable, str(OPS / "pg-cutover-disarm.py"), "--f1", str(self.f1), "--r1b-census", "-"],
            input=result.stdout, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["since_ms"], 0)

    def test_truncated_export_without_seal_must_not_load(self):
        dump = self.path / "truncated.sql"
        dest = self.path / "unsealed.sqlite"
        with sqlite3.connect(self.db) as db, dump.open("w") as out:
            out.write("PRAGMA defer_foreign_keys=TRUE;\n")
            out.writelines(line + "\n" for line in db.iterdump() if line not in ("BEGIN TRANSACTION;", "COMMIT;"))
        # Even a syntactically complete file must not load without provenance.
        result = run("pg-copy.py", "--export", dump, "--sqlite", dest, "--f1", self.f1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--manifest", result.stderr)
        self.assertFalse(dest.exists())
        original = dump.read_bytes()
        self.manifest_for(original)
        data = b"\n".join(line for line in original.split(b"\n")
                           if not line.startswith(b"INSERT INTO \"scan_cursors\" VALUES('revive'"))
        self.assertNotEqual(data, original)
        dump.write_bytes(data)
        result = run("pg-copy.py", "--export", dump, "--sqlite", dest, *self.source_args())
        self.assertIn("byte count or SHA-256", result.stderr)
        self.assertFalse(dest.exists())
        # A short export sealed as-is must still fail the independent D1 witness.
        self.manifest_for(data)
        result = run("pg-copy.py", "--export", dump, "--sqlite", dest, *self.source_args())
        self.assertIn("scan_cursors: frozen D1 source boundary mismatch", result.stderr)
        self.assertFalse(dest.exists())

    def test_wrangler_style_export_is_transactional_and_rejects_raw_nul(self):
        dump = self.path / "wrangler.sql"
        dest = self.path / "loaded.sqlite"
        with sqlite3.connect(self.db) as db, dump.open("w") as out:
            out.write("PRAGMA defer_foreign_keys=TRUE;\n")
            out.writelines(line + "\n" for line in db.iterdump() if line not in ("BEGIN TRANSACTION;", "COMMIT;"))
        with dump.open("a") as out:
            out.write("INSERT INTO scan_cursors VALUES ('new','before\0after');\n")
        self.manifest_for(dump.read_bytes())
        result = run("pg-copy.py", "--export", dump, "--sqlite", dest, *self.source_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("literal NUL", result.stderr)
        self.assertFalse(dest.exists())
        dump.write_bytes(dump.read_bytes().replace(b"before\0after", b"clean"))
        self.manifest_for(dump.read_bytes())
        result = run("pg-copy.py", "--export", dump, "--sqlite", dest, *self.source_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["extent_count"], 2)

    def test_census_rejects_unrepresentable_columns_and_arm_mismatch(self):
        cases = [
            ("UPDATE buckets SET created_at=1.5", "buckets.created_at", "UPDATE buckets SET created_at=1"),
            ("UPDATE buckets SET created_at=9007199254740992", "buckets.created_at", "UPDATE buckets SET created_at=1"),
            ("UPDATE generations SET key='a'||char(0)||'b'", "generations.key", "UPDATE generations SET key='safe'"),
            ("UPDATE articles SET yenc_name='bad-name'", "articles.yenc_name", "UPDATE articles SET yenc_name='fine'"),
            ("UPDATE restore_state SET reached_phase=1", "exported restore_state", "UPDATE restore_state SET reached_phase=NULL"),
            ("UPDATE access_keys SET access_key_id=NULL", "access_keys.access_key_id", "UPDATE access_keys SET access_key_id='id'"),
        ]
        for update, label, undo in cases:
            with self.subTest(label=label), sqlite3.connect(self.db) as db:
                db.execute("PRAGMA ignore_check_constraints=ON")
                db.execute(update)
                db.commit()
                self.seal_fixture()
                result = self.copy()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(label, result.stderr)
                db.execute(undo)

    def test_prepare_f1_creates_distinct_private_attempts(self):
        pre = self.path / "pre.json"
        pre.write_text(json.dumps({k: v for k, v in F1.items() if k not in ("f1_attempt_id", "restore_state_armed")}))
        attempts = []
        for seq in range(2):
            target = self.path / f"attempt{seq}.json"
            result = run("pg-cutover-disarm.py", "--f1", pre, "--prepare-f1", target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            receipt = json.loads(target.read_text())
            attempts.append(receipt["f1_attempt_id"])
            self.assertEqual(receipt["restore_state_armed"], dict(ARMED, reached_after=attempts[-1]))
        self.assertNotEqual(*attempts)

    def test_source_witness_uses_bounded_index_plans(self):
        with sqlite3.connect(self.db) as db:
            db.row_factory = sqlite3.Row
            def query(uuid, sql, params):
                self.assertEqual(uuid, D1_ID)
                rows = [dict(row) for row in db.execute(sql, params)]
                return {"results": rows, "meta": {"rows_read": len(rows)}}
            manifest = capture_boundaries(F1, query=query)
            proof = manifest.pop("proof")
            self.assertGreater(proof["indexed_lookups"], 60)
            self.assertEqual(proof["max_data_rows_read"], 2)
            self.assertEqual(manifest, sqlite_boundaries(db, F1))

    def test_branch_suffix_must_match_configured_branch(self):
        path = self.path / "branch.env"
        lines = "PGHOST=/local\nPGDATABASE=db\nPGBRANCHID=right\n"
        path.write_text(lines + "PGUSER=kofra_ro.wrong\n")
        path.chmod(0o600)
        with self.assertRaisesRegex(Failure, "configured PGBRANCHID"):
            pg_settings(path, "kofra_ro")
        path.write_text(lines + "PGUSER=kofra_ro.right\n")
        self.assertEqual(pg_settings(path, "kofra_ro")[0]["user"], "kofra_ro.right")

    def test_worker_history_allows_only_f6_pg_versions(self):
        verify = runpy.run_path(str(OPS / "pg-cutover-disarm.py"))["verify_deploy_history"]
        def deploy(name, when):
            return dict(id=name, created_on=when, versions=[dict(version_id=D1_ID)])
        post = deploy("post", "1970-01-01T00:17:00Z")
        pre = deploy("pre", "1970-01-01T00:16:00Z")
        def cf(mode, page1, page2=None):
            def query(path):
                if "/versions/" in path:
                    bindings = [dict(name="CATALOG_BACKEND", type="plain_text", text="pg")]
                    if mode is not None:
                        bindings.append(dict(name="MAINTENANCE", type="plain_text", text=mode))
                    return dict(result=dict(resources=dict(bindings=bindings)))
                if page2 is not None and "page=1&" in path:
                    return dict(result=dict(deployments=page1), result_info=dict(page=1, total_pages=2))
                return dict(result=dict(deployments=page2 if page2 is not None else page1))
            return query
        verify("wp5-local", F1, cf("restore", [post, pre]))
        verify("wp5-local", F1, cf("restore", [post], [pre]))
        for maintenance in ("off", None):
            with self.assertRaisesRegex(Failure, "admitted writes"):
                verify("wp5-local", F1, cf(maintenance, [post, pre]))
        with self.assertRaisesRegex(Failure, "truncated"):
            verify("wp5-local", F1, cf("restore", [post]))
        with self.assertRaisesRegex(Failure, "does not match"):
            verify("wrong-worker", F1, cf("restore", [post, pre]))

    def pg(self):
        if not os.environ.get("WP5_TEST_PG_SOCKET"):
            self.skipTest("set WP5_TEST_PG_SOCKET to an isolated local PG socket directory")
        import psycopg
        from psycopg import sql

        socket = Path(os.environ["WP5_TEST_PG_SOCKET"])
        self.assertTrue(socket.is_absolute() and socket.is_dir())
        port = int(os.environ.get("WP5_TEST_PG_PORT", 5432))
        options = {"host": str(socket), "port": port, "dbname": "postgres"}
        conn = psycopg.connect(**options, autocommit=True)
        self.addCleanup(conn.close)
        schema = "wp5_" + uuid.uuid4().hex
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        self.addCleanup(conn.execute, sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        for role in ("kofra_app", "kofra_ro", "kofra_migrate"):
            if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone():
                conn.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(role)))
        applied = subprocess.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-v", f"schema={schema}",
                                  "-f", str(BRIDGE / "pg" / "roles.sql")], capture_output=True, text=True,
                                 env=dict(os.environ, PGHOST=str(socket), PGPORT=str(port),
                                          PGDATABASE="postgres", PGUSER=conn.info.user))
        self.assertEqual(applied.returncode, 0, applied.stderr)
        env = self.path / "pg.env"
        env.write_text(f"PGHOST={socket}\nPGPORT={port}\nPGDATABASE=postgres\nPGUSER=kofra_migrate\n"
                       f"PGSCHEMA={schema}\nPGLOCKKEY=7413000555\n")
        env.chmod(0o600)
        return conn, env

    def test_binary_copy_verify_and_activate(self):
        conn, env = self.pg()
        result = self.copy("--pg-env", env, "--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(conn.execute("SELECT extent_id,seq FROM outbox ORDER BY seq").fetchall(), [("z", 1), ("a", 2)])
        self.assertEqual(conn.execute("SELECT k FROM scan_cursors").fetchall(), [("keep",)])
        self.assertEqual(conn.execute("SELECT * FROM restore_state").fetchone(), tuple(BEFORE.values()))
        self.assertTrue(conn.execute("SELECT NOT has_schema_privilege('kofra_app', current_schema(),'USAGE')").fetchone()[0])
        cases = [
            ("UPDATE articles SET headers=decode('000103','hex')", "articles chunk 1", "UPDATE articles SET headers=decode('000102','hex')"),
            ("UPDATE generations SET content_json='ab', user_meta_json='c'", "generations chunk 1", "UPDATE generations SET content_json='a', user_meta_json='bc'"),
            ("UPDATE recovery_copy_log SET detail='other' WHERE detail IS NOT NULL", "recovery_copy_log", "UPDATE recovery_copy_log SET detail='nonempty' WHERE detail IS NOT NULL"),
            ("UPDATE outbox SET seq=90 WHERE seq=1", "outbox.seq", "UPDATE outbox SET seq=1 WHERE seq=90"),
        ]
        for update, label, undo in cases:
            with self.subTest(label=label):
                conn.execute(update)
                result = self.verify(env, "--activate")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(label, result.stderr)
                self.assertTrue(conn.execute("SELECT to_regclass('_velmora_import_incomplete') IS NOT NULL").fetchone()[0])
                conn.execute(undo)
        result = self.verify(env, "--activate", "--chunk-rows", "1")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["tables"]["tx_guard"]["postgres"]["count"], 2)
        self.assertFalse(conn.execute("SELECT to_regclass('_velmora_import_incomplete') IS NOT NULL").fetchone()[0])
        self.assertTrue(conn.execute("SELECT has_schema_privilege('kofra_app', current_schema(),'USAGE')").fetchone()[0])
        self.assertEqual(conn.execute("SELECT nextval(pg_get_serial_sequence('gc','id')), nextval(pg_get_serial_sequence('usage_recounts','id')), nextval(pg_get_serial_sequence('outbox','seq'))").fetchone(), (16, 19, 3))
        conn.execute("SELECT set_config('velmora.lock_key','7413000555',false)")
        arm = (OPS / "pg-restore-arm.sql").read_text()
        conn.execute(arm, prepare=False)
        self.assertEqual(conn.execute("SELECT * FROM restore_state").fetchone(), tuple(dict(ARMED, reached_after=None).values()))
        conn.execute("UPDATE restore_state SET since_ms=3,reached_phase=7")
        conn.execute(arm, prepare=False)
        self.assertEqual(conn.execute("SELECT since_ms,started_at,reached_phase FROM restore_state").fetchone(), (3, 11, None))

    def verify(self, env, *args):
        return run("pg-verify.py", "--pg-env", env, "--sqlite", self.db, *self.source_args(), *args)

    def test_interrupted_copy_keeps_claim_and_disallows_arm(self):
        conn, env = self.pg()
        # An orphan late in FK order fails COPY after earlier tables were sent.
        with sqlite3.connect(self.db) as db:
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute("UPDATE outbox SET extent_id='missing' WHERE extent_id='a'")
        self.seal_fixture()
        result = self.copy("--pg-env", env, "--apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("23503", result.stderr)
        self.assertEqual(conn.execute("SELECT count(*) FROM buckets").fetchone()[0], 0)
        self.assertTrue(conn.execute("SELECT to_regclass('_velmora_import_incomplete') IS NOT NULL").fetchone()[0])
        self.assertFalse(conn.execute("SELECT has_schema_privilege('kofra_app', current_schema(),'USAGE')").fetchone()[0])
        conn.execute("SELECT set_config('velmora.lock_key','7413000555',false)")
        with self.assertRaisesRegex(Exception, "catalogue import incomplete"):
            conn.execute((OPS / "pg-restore-arm.sql").read_text(), prepare=False)
        conn.execute("ROLLBACK")
        result = self.copy("--pg-env", env, "--apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already claimed", result.stderr)

    def test_claim_refuses_active_or_nonempty(self):
        conn, env = self.pg()
        migrate = OPS / "pg-migrate.sh"
        result = subprocess.run(["bash", str(migrate), str(env), "--to", "0001", "--import-mode"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        conn.execute("INSERT INTO tx_guard VALUES (1)")
        result = self.copy("--pg-env", env, "--apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-empty", result.stderr)
        conn.execute("DELETE FROM tx_guard")
        from psycopg import sql
        conn.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO kofra_app").format(sql.Identifier(conn.info.parameter_status("search_path"))))
        result = self.copy("--pg-env", env, "--apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("USAGE", result.stderr)
        self.assertFalse(conn.execute("SELECT to_regclass('_velmora_import_incomplete') IS NOT NULL").fetchone()[0])

    def test_r0_local_d1_restores_deletes_refuses(self):
        wrangler = os.environ.get("WP5_TEST_WRANGLER")
        if not wrangler:
            self.skipTest("set WP5_TEST_WRANGLER to an installed Wrangler executable")
        config = self.path / "wrangler.toml"
        config.write_text('name="wp5-local"\ncompatibility_date="2025-01-01"\n[[d1_databases]]\n'
                          'binding="DB"\ndatabase_name="wp5-local"\n'
                          'database_id="00000000-0000-0000-0000-000000000005"\n')
        local = ["--wrangler", wrangler, "--config", str(config), "--database", "wp5-local",
                 "--local", "--persist-to", str(self.path / "d1")]

        def d1(command):
            result = subprocess.run([wrangler, "d1", "execute", "wp5-local", "--config", str(config),
                                     "--local", "--persist-to", str(self.path / "d1"), "--json", "--command", command],
                                    cwd=self.path, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)[0]["results"]

        d1("CREATE TABLE restore_state(id INTEGER PRIMARY KEY,state TEXT,since_ms INTEGER,started_at INTEGER,"
           "finished_at INTEGER,reached_phase INTEGER,reached_after TEXT,reached_extent INTEGER)")
        d1("CREATE TABLE meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL)")
        d1("INSERT INTO restore_state VALUES (1,'complete',4,9,12,5,CAST(X'c3a9270a' AS TEXT),2)")
        result = run("pg-cutover-disarm.py", "--f1", self.f1, *local, "--operation", "arm-f1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(d1("SELECT * FROM restore_state"), [ARMED])
        stale_f1 = self.path / "stale.json"
        other = "2" * 32
        stale_f1.write_text(json.dumps(dict(F1, f1_attempt_id=other, restore_state_armed=dict(ARMED, reached_after=other),
                                               f7_started=False)))
        stale = run("pg-cutover-disarm.py", "--f1", stale_f1, *local)
        self.assertNotEqual(stale.returncode, 0, "an equal epoch from another F1 disarmed the live row")
        marked = run("pg-cutover-disarm.py", "--f1", self.f1, *local, "--operation", "mark-f7")
        self.assertEqual(marked.returncode, 0, marked.stderr)
        stale = run("pg-cutover-disarm.py", "--f1", self.f1, *local)
        self.assertNotEqual(stale.returncode, 0, "a stale F1 receipt accepted an already-started F7")
        self.assertEqual(d1("SELECT * FROM restore_state"), [ARMED])
        d1("DELETE FROM meta")  # fixture reset only; operators never clear it
        result = run("pg-cutover-disarm.py", "--f1", self.f1, *local)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(d1("SELECT * FROM restore_state"), [BEFORE])
        result = run("pg-cutover-disarm.py", "--f1", self.f1, *local)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changed 0 rows", result.stderr)
        self.assertEqual(d1("SELECT * FROM restore_state"), [BEFORE])
        self.assertIn("already matches the pre-arm row", result.stderr)
        d1("DELETE FROM restore_state")
        self.f1.write_text(json.dumps(dict(F1, restore_state_before=None, restore_state_armed=dict(ARMED, started_at=0))))
        result = run("pg-cutover-disarm.py", "--f1", self.f1, *local, "--operation", "arm-f1")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = run("pg-cutover-disarm.py", "--f1", self.f1, *local)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(d1("SELECT * FROM restore_state"), [])


if __name__ == "__main__":
    unittest.main()
