"""The unit's Durable Object class in workerd: unit-smoke.py <base-url>

Drives the real class (velmora_unit_do::UnitObject) through the suite
Worker: rule 7 (unborn, listed and not), the name check of an object
made without a name, rule 6 (birth, a replayed token), rule 5 (numbers),
rule 11 (what runs without authentication), and the whole-call
transaction of DoSql (/atomic). Prints one line per check and exits 1 on
the first difference.
"""
import glob
import json
import os
import sys
import urllib.request

BASE = sys.argv[1].rstrip("/")
TENANT = "t_00000000000005e1"
REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
# unit::schema::SCHEMA_VERSION: every migration a unit applies.
SCHEMA_VERSION = len(glob.glob(os.path.join(REPO, "workers/s3-bridge/migrations/*.sql"))) + len(
    glob.glob(os.path.join(REPO, "crates/velmora-bridge/src/unit/migrations/*.sql")))
failures = 0


def post(path, body):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def check(label, got, want):
    global failures
    ok = got == want
    print(("ok   " if ok else "FAIL ") + label + ("" if ok else f"\n     want {want}\n     got  {got}"))
    if not ok:
        failures += 1


def call(unit, kind, op, seqs=None, authenticated=True, listed=True):
    body = {"name": {"tenant": TENANT, "unit": unit}, "kind": kind, "authenticated": authenticated,
            "listed": listed, "op": op}
    if seqs is not None:
        body["seqs"] = {"state_seq": seqs[0], "keys_seq": seqs[1]}
    return body


def unit_post(unit, body):
    return post(f"/unit/{TENANT}/{unit}", body)


PING = {"op": "ping"}
S = {"state_seq": 3, "keys_seq": 0}

# Rule 7.
check("unborn, not listed", unit_post(0, call(0, "request", PING, (3, 0), listed=False)),
      {"answer": "unborn", "listed": False})
check("unborn, listed", unit_post(0, call(0, "request", PING, (3, 0))), {"answer": "unborn", "listed": True})

# An object without a name matches no call.
check("an object made without a name", post("/unit-unnamed", call(0, "request", PING, (3, 0))),
      {"answer": "refused", "reason": {"identity": "wrong_name"}, "alarm": True})
# A call for another unit than the object.
check("a call for another unit", unit_post(0, call(1, "request", PING, (3, 0))),
      {"answer": "refused", "reason": {"identity": "wrong_name"}, "alarm": True})

# Rule 6.
version = SCHEMA_VERSION
token = {"name": {"tenant": TENANT, "unit": 0}, "jurisdiction": "", "record_seq": 3,
         "schema_version": version, "key_scheme": 2, "kind": "birth"}
born = unit_post(0, call(0, "worker", {"op": "provision", "token": token, "sealed": "c2VhbGVk"}, (3, 0)))
check("a birth", born, {"answer": "ok", "seqs": S, "body": {"born": "birth", "restoring": None}})
check("the replayed birth token", unit_post(0, call(0, "worker", {"op": "provision", "token": token, "sealed": "c2VhbGVk"}, (3, 0))),
      {"answer": "refused", "reason": {"provision": "already_born"}, "alarm": False})
check("provisioning until the first sync", unit_post(0, call(0, "request", PING, (3, 0))),
      {"answer": "closed", "seqs": S, "why": "provisioning"})
sync = {"op": "sync", "head": {"seqs": S, "tenant_state": "active"}}
check("sync to active", unit_post(0, call(0, "worker", sync)), {"answer": "ok", "seqs": S, "body": {"synced": 3}})

# Rule 5.
check("equal numbers", unit_post(0, call(0, "request", PING, (3, 0))),
      {"answer": "ok", "seqs": S, "body": {"tenant_state": "active", "tenant_mode": None}})
check("a higher number", unit_post(0, call(0, "request", PING, (4, 0))), {"answer": "sync_needed", "seqs": S})
check("a lower number from a request", unit_post(0, call(0, "request", PING, (2, 0))), {"answer": "stale", "seqs": S})
check("a job without numbers", unit_post(0, call(0, "job", PING)),
      {"answer": "refused", "reason": {"identity": "stale_job"}, "alarm": False})

# Rule 11.
check("an unauthenticated ping", unit_post(0, call(0, "request", PING, (3, 0), authenticated=False)),
      {"answer": "refused", "reason": "unauthenticated", "alarm": False})
check("an unauthenticated key-row fetch", unit_post(0, call(0, "request", {"op": "key_row", "access_key_id": "AKNOSUCHKEY000000000"}, (3, 0), authenticated=False)),
      {"answer": "ok", "seqs": S, "body": {"key": None, "state": {"tenant_state": "active", "tenant_mode": None}}})
check("a read plan of a missing bucket", unit_post(0, call(0, "request", {"op": "read_plan", "bucket": "nope", "key": "k", "start": 0, "end": 1}, (3, 0))),
      {"answer": "refused", "reason": "not_found", "alarm": False})

# The whole-call transaction.
atomic = post("/atomic/smoke", {}).get("ok", {})
check("a call keeps its writes", atomic["kept"], {"ok": True, "rows": [1]})
check("a failed call keeps nothing", atomic["failed"], {"error": "invalid: the call fails after a write", "rows": [1]})
check("a refused batch rolls back only itself", atomic["inner"], {"ok": True, "rows": [1, 3]})

print(f"unit smoke: {failures} failed")
sys.exit(1 if failures else 0)
