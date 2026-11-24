#!/usr/bin/env python3
"""F1/F7 fences and R0 disarm on D1, or compute the R1b replay start offline."""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
from secrets import token_hex
import subprocess
import tempfile
from time import time_ns

from pg_catalog import (
    F7_PREFIX, D1_UUID, RESTORE_COLUMNS, cloudflare, d1_query, diagnostic_main, f1_receipt,
    ident, idents, json_input, require, safe_int, validate_f1,
)


def prepare_receipt(source, target):
    receipt = json_input(source)
    require("restore_state_before" in receipt and "f1_attempt_id" not in receipt and "restore_state_armed" not in receipt,
            "prepare F1 from an unarmed receipt containing the exact pre-arm row")
    before = receipt["restore_state_before"]
    require(before is None or (isinstance(before, dict) and safe_int(before.get("started_at"))),
            "invalid pre-arm epoch")
    attempt = token_hex(16)
    armed = dict.fromkeys(RESTORE_COLUMNS)
    armed.update(id=1, state="replaying", since_ms=-1, reached_after=attempt,
                 started_at=0 if before is None else before["started_at"] + 1)
    receipt.update(f1_attempt_id=attempt, restore_state_armed=armed)
    validate_f1(receipt)
    with target.open("x", encoding="utf-8") as out:
        json.dump(receipt, out, sort_keys=True)
        out.write("\n")


def literal(value):
    if value is None:
        return "NULL"
    if type(value) is int:
        return str(value)
    return f"CAST(X'{value.encode('utf-8').hex()}' AS TEXT)"


def guard(record):
    cols = RESTORE_COLUMNS[1:]
    return "id = 1 AND " + " AND ".join(f"{ident(k)} IS ?" for k in cols), [record[k] for k in cols]


def statement(operation, receipt):
    before, armed = receipt["restore_state_before"], receipt["restore_state_armed"]
    key = F7_PREFIX + receipt["f1_attempt_id"]
    cols = RESTORE_COLUMNS[1:]
    if operation == "mark-f7":
        where, match = guard(armed)
        return ("INSERT INTO meta(k,v) SELECT ?,? WHERE EXISTS (SELECT 1 FROM restore_state WHERE "
                + where + ") ON CONFLICT(k) DO NOTHING RETURNING 1 AS id", [key, time_ns()//1_000_000, *match])
    if operation == "arm-f1":
        if before is None:
            sql = (f"INSERT INTO restore_state ({idents(RESTORE_COLUMNS)}) SELECT {', '.join(['?']*8)} "
                   "WHERE NOT EXISTS (SELECT 1 FROM sqlite_schema WHERE name='_velmora_import_incomplete') "
                   "ON CONFLICT(id) DO NOTHING RETURNING id")
            return sql, [armed[k] for k in RESTORE_COLUMNS]
        where, match = guard(before)
        set_to = armed
        where += " AND NOT EXISTS (SELECT 1 FROM sqlite_schema WHERE name='_velmora_import_incomplete')"
    else:
        where, match = guard(armed)
        where += " AND NOT EXISTS (SELECT 1 FROM meta WHERE k=?)"
        match.append(key)
        if before is None:
            return f"DELETE FROM restore_state WHERE {where} RETURNING id", match
        set_to = before
    sets = ", ".join(f"{ident(k)} = ?" for k in cols)
    return f"UPDATE restore_state SET {sets} WHERE {where} RETURNING id", [*(set_to[k] for k in cols), *match]


def local_query(args, sql, params):
    require(args.config and args.database and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", args.database),
            "local operation requires a Wrangler config and D1 binding or database name")
    with tempfile.TemporaryDirectory(prefix="velmora-d1-cutover-") as tmp:
        path = Path(tmp) / "cutover.sql"
        path.write_text(sql.replace("?", "{}").format(*map(literal, params)) + ";\n")
        cmd = [args.wrangler, "d1", "execute", args.database, "--config", str(args.config),
               "--local", "--file", str(path), "--json"]
        if args.persist_to:
            cmd.extend(["--persist-to", str(args.persist_to)])
        env = dict(os.environ, WRANGLER_SEND_METRICS="false", WRANGLER_WRITE_LOGS="false")
        env.pop("WRANGLER_LOG", None)
        result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env)
    require(result.returncode == 0, f"Wrangler D1 operation exited {result.returncode}; outcome unknown, stop")
    data = json.loads(result.stdout)
    require(isinstance(data, list) and len(data) == 1 and data[0].get("success") is True,
            "D1 local response invalid; stop")
    return data[0]


def timestamp_ms(value):
    require(isinstance(value, str), "invalid Worker deployment timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "invalid Worker deployment timezone")
    return int(parsed.timestamp() * 1000)


def verify_deploy_history(worker, receipt, cf=cloudflare):
    require(isinstance(worker, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", worker)
            and worker == receipt.get("worker_name"), "Worker does not match the F1 receipt")
    path = f"/workers/scripts/{worker}"
    cutoff = receipt["f1_started_at_ms"]
    previous, seen, checked = None, set(), set()
    for page in range(1, 51):
        data = cf(path + f"/deployments?page={page}&per_page=50")
        result = data.get("result")
        entries = result.get("deployments") if isinstance(result, dict) else None
        require(isinstance(entries, list) and entries, "Worker deploy history does not cover F1")
        for deployment in entries:
            when = timestamp_ms(deployment.get("created_on"))
            ident_ = deployment.get("id")
            require(isinstance(ident_, str) and ident_ not in seen and (previous is None or when <= previous),
                    "Worker deploy history has a gap or invalid order")
            seen.add(ident_)
            previous = when
            if when < cutoff:
                return
            versions = deployment.get("versions")
            require(isinstance(versions, list) and versions, "Worker deployment versions are unreadable")
            for item in versions:
                version = item.get("version_id")
                require(isinstance(version, str) and D1_UUID.fullmatch(version), "Worker deployment version is unreadable")
                if version in checked:
                    continue
                props = cf(path + f"/versions/{version}").get("result")
                bindings = props.get("resources", {}).get("bindings") if isinstance(props, dict) else None
                require(isinstance(bindings, list), "Worker version bindings are unreadable")

                def plain(name):
                    values = [b.get("text") for b in bindings if b.get("name") == name and b.get("type") == "plain_text"]
                    return values[0] if len(values) == 1 else None

                backend = plain("CATALOG_BACKEND")
                require(backend in ("d1", "d1-frozen", "pg", "pg-frozen"), "Worker catalogue backend is unreadable")
                require(backend not in ("pg", "pg-frozen") or plain("MAINTENANCE") == "restore",
                        "a Postgres deployment admitted writes after F1; R0 is forbidden")
                checked.add(version)
        info = data.get("result_info", {})
        require(isinstance(info, dict) and info.get("page") == page and type(info.get("total_pages")) is int
                and page < info["total_pages"], "Worker deploy history is truncated before F1")
    require(False, "Worker deploy history exceeds the F1 safety window")


def run_d1(args, receipt):
    if args.remote:
        require(not args.config and not args.persist_to, "--config and --persist-to are local only")
        require(args.database == receipt["d1_uuid"], "D1 UUID does not match the F1 receipt")
        if args.operation == "r0":
            require(args.confirm_r0, "remote R0 requires --confirm-r0")
            verify_deploy_history(args.worker, receipt)
        else:
            require(args.confirm_fence, "remote fence operation requires --confirm-fence")
        query = lambda sql, p: d1_query(args.database, sql, p)
    else:
        query = lambda sql, p: local_query(args, sql, p)
    sql, params = statement(args.operation, receipt)
    result = query(sql, params)
    rows = result.get("results")
    require(rows == [] or (rows == [{"id": 1}] and type(rows[0]["id"]) is int),
            "D1 returning rows invalid; outcome unknown, stop")
    changes = result["meta"].get("changes") if args.remote else len(rows)
    require(type(changes) is int and changes == len(rows), "D1 change count inconsistent; stop")
    if changes == 0 and args.operation == "r0":
        current = query(f"SELECT {idents(RESTORE_COLUMNS)} FROM restore_state WHERE id=1", ())
        before = receipt["restore_state_before"]
        if current["results"] == ([] if before is None else [before]):
            require(False, "R0 changed 0 rows; D1 already matches the pre-arm row, but this did not authorize a version rollback")
        require(False, "D1 disarm changed 0 rows; live row differs or F7 started, stop")
    require(changes == 1, "D1 fence changed 0 rows; do not deploy or continue")
    report = dict(changes=changes, f1_attempt_id=receipt["f1_attempt_id"], d1_uuid=receipt["d1_uuid"])
    if args.operation == "mark-f7":
        report["f7_marked_at_ms"] = params[1]
    print(json.dumps(report))


def replay_start(receipt, census):
    require(all(census.get(k) == receipt[k] for k in ("f1_attempt_id", "d1_uuid")), "F3 census does not match the F1 attempt")
    held, count = census.get("s_held_ms"), census.get("held_count")
    require(type(count) is int and count >= 0 and "s_held_ms" in census and
            (held is None if count == 0 else safe_int(held)), "invalid F3 held-extent census")
    start = receipt["f1_started_at_ms"]
    since = max(0, min(start, held if held is not None else start) - 600_000)
    print(json.dumps({"since_ms": since, "margin_ms": 0}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--f1", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare-f1", type=Path, help="write a new private F1 receipt from the pre-arm record")
    mode.add_argument("--r1b-census", help="read pg-copy JSON (or - for stdin) and report the replay start")
    mode.add_argument("--local", action="store_true")
    mode.add_argument("--remote", action="store_true")
    parser.add_argument("--operation", choices=("r0", "arm-f1", "mark-f7"), default="r0")
    parser.add_argument("--confirm-r0", action="store_true")
    parser.add_argument("--confirm-fence", action="store_true")
    parser.add_argument("--worker")
    parser.add_argument("--database")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--persist-to", type=Path)
    parser.add_argument("--wrangler", default="wrangler")
    args = parser.parse_args()
    if args.prepare_f1:
        prepare_receipt(args.f1, args.prepare_f1)
        return
    receipt = f1_receipt(args.f1)
    if args.r1b_census:
        replay_start(receipt, json_input(args.r1b_census))
    else:
        run_d1(args, receipt)


if __name__ == "__main__":
    raise SystemExit(diagnostic_main(main))
