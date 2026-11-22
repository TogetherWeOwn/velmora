"""The unit's Durable Object class in workerd: unit-smoke.py <base-url>

Drives the real class (velmora_unit_do::UnitObject) through the suite
Worker: rule 7 (unborn, listed and not), the name check of an object
made without a name, rule 6 (birth, a replayed token), rule 5 (numbers),
rule 11 (what runs without authentication), and the whole-call
transaction of DoSql (/atomic), and rule 12 (no call before a renewal,
the lease every answer carries). Prints one line per check, runs every
check, and exits 1 if any differed.
"""
import glob
import json
import os
import sys
import time
import urllib.error
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


# unit_lease::lease::LeaseRules::DEFAULT.term_ms
LEASE_TERM_MS = 10 * 60 * 1000


def check(label, got, want, lease=None):
    """Compares the answer without the numbers every answer carries
    (`lease_left_ms`, `revoked`); `lease`: what `lease_left_ms` must be,
    "none" (0) or "fresh" (above 0, at most T)."""
    global failures
    if isinstance(got, dict) and "answer" in got:
        got = dict(got)
        left = got.pop("lease_left_ms", None)
        got.pop("revoked", None)
        if not isinstance(left, int) or left < 0 or left > LEASE_TERM_MS:
            got["lease_left_ms"] = left
        elif lease == "none" and left != 0:
            got["lease_left_ms"] = left
        elif lease == "fresh" and left == 0:
            got["lease_left_ms"] = left
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
    try:
        return post(f"/unit/{TENANT}/{unit}", body)
    except urllib.error.HTTPError as e:
        # A body that is not a call is answered 400 and touches nothing.
        return None if e.code == 400 else {"http": e.code}


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

# Rule 12: nothing is served before a renewal.
check("no lease yet", unit_post(0, call(0, "request", PING, (3, 0))),
      {"answer": "renew_needed", "seqs": S}, lease="none")
proof_start = int(time.time() * 1000)
renewed = unit_post(0, call(0, "worker", {"op": "renew", "proof_start": proof_start,
                                          "proven": {"state_seq": 3, "keys_seq": 0, "revoked": 0}}))
check("a renewal", renewed, {"answer": "ok", "seqs": S,
                             "body": {"fresh_until": proof_start + LEASE_TERM_MS, "applied": 0}}, lease="fresh")
check("a proof from long ago", unit_post(0, call(0, "worker", {"op": "renew", "proof_start": proof_start - 3_600_000,
      "proven": {"state_seq": 3, "keys_seq": 0, "revoked": 0}})),
      {"answer": "renew_needed", "seqs": S, "why": "proof_too_old"}, lease="fresh")

# Rule 5.
check("equal numbers", unit_post(0, call(0, "request", PING, (3, 0))),
      {"answer": "ok", "seqs": S, "body": {"tenant_state": "active", "tenant_mode": None}}, lease="fresh")
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
      {"answer": "ok", "seqs": S, "body": {"bucket": None, "generation": None, "key_row": None,
                                            "state": {"tenant_state": "active", "tenant_mode": None}}})
check("an unknown field beside an operation", unit_post(0, dict(call(0, "request", PING, (3, 0)), op={"op": "ping", "evil": 1})),
      None)

# The restore calls go through the class (AM-2): an open unit refuses
# both, and nothing is armed.
check("restore_prepare on an open unit", unit_post(0, call(0, "worker", {"op": "restore_prepare", "since": 3})),
      {"answer": "refused", "reason": {"restore": "not_restoring"}, "alarm": False})
rtoken = dict(token, kind="restore")
check("restore on an open unit", unit_post(0, call(0, "worker", {"op": "restore", "token": rtoken,
      "target": {"to": "time", "at_ms": 1}, "expect_undo": "bm"})),
      {"answer": "refused", "reason": {"restore": "not_restoring"}, "alarm": False})
check("a restore entry closes the unit", unit_post(0, call(0, "worker", {"op": "sync", "head": {"seqs": {"state_seq": 4, "keys_seq": 0},
      "tenant_state": "active", "restoring_since": 4}})), {"answer": "ok", "seqs": {"state_seq": 4, "keys_seq": 0}, "body": {"synced": 4}})
check("the close ended the lease", unit_post(0, call(0, "request", PING, (4, 0))),
      {"answer": "closed", "seqs": {"state_seq": 4, "keys_seq": 0}, "why": "restoring"}, lease="none")
check("restore_prepare while the lease could still be held", unit_post(0, call(0, "worker", {"op": "restore_prepare", "since": 4})),
      {"answer": "refused", "reason": {"restore": "too_soon"}, "alarm": False})
check("the entry is not cleared without the lift check", unit_post(0, call(0, "worker", {"op": "sync", "head": {"seqs": {"state_seq": 5, "keys_seq": 0},
      "tenant_state": "active"}})), {"answer": "refused", "reason": {"gate": "no_report"}, "alarm": False})

# The whole-call transaction.
atomic = post("/atomic/smoke", {}).get("ok", {})
check("a call keeps its writes", atomic["kept"], {"ok": True, "rows": [1]})
check("a failed call keeps nothing", atomic["failed"], {"error": "invalid: the call fails after a write", "rows": [1]})
check("a refused batch rolls back only itself", atomic["inner"], {"ok": True, "rows": [1, 3]})

print(f"unit smoke: {failures} failed")
sys.exit(1 if failures else 0)
