#!/usr/bin/env python3
"""R0: restore D1's pre-freeze row once; R1b: compute the D1 replay start."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.request

from pg_catalog import Failure, JSON_CAP, RESTORE_COLUMNS, diagnostic_main, f1_receipt, ident, json_input, require, safe_int


def literal(value):
    if value is None:
        return "NULL"
    if type(value) is int:
        return str(value)
    # A text cursor may contain quotes or newlines. Never put it in argv or logs.
    return f"CAST(X'{value.encode('utf-8').hex()}' AS TEXT)"


def disarm_statement(receipt):
    before, armed = receipt["restore_state_before"], receipt["restore_state_armed"]
    where = ("WHERE id = 1 AND state = 'replaying' AND since_ms = -1 AND started_at = ? "
             "AND finished_at IS NULL AND reached_phase IS NULL "
             "AND reached_after IS NULL AND reached_extent IS NULL")
    if before is None:
        return f"DELETE FROM restore_state {where} RETURNING id;", [armed["started_at"]]
    cols = [k for k in RESTORE_COLUMNS if k != "id"]
    sets = ", ".join(f"{ident(k)} = ?" for k in cols)
    return f"UPDATE restore_state SET {sets} {where} RETURNING id;", [*(before[k] for k in cols), armed["started_at"]]


def local_query(args, sql, params):
    require(args.config and args.database and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", args.database),
            "local R0 requires a Wrangler config and D1 binding or database name")
    with tempfile.TemporaryDirectory(prefix="velmora-d1-disarm-") as tmp:
        path = Path(tmp) / "disarm.sql"
        path.write_text(sql.replace("?", "{}").format(*map(literal, params)) + "\n")
        cmd = [args.wrangler, "d1", "execute", args.database, "--config", str(args.config),
               "--local", "--file", str(path), "--json"]
        if args.persist_to:
            cmd.extend(["--persist-to", str(args.persist_to)])
        env = dict(os.environ, WRANGLER_SEND_METRICS="false", WRANGLER_WRITE_LOGS="false")
        env.pop("WRANGLER_LOG", None)  # warn/error log levels suppress the JSON result
        result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env)
    require(result.returncode == 0, f"Wrangler D1 disarm exited {result.returncode}; outcome unknown, stop")
    return result.stdout


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def remote_query(args, sql, params):
    require(args.confirm_r0, "remote R0 requires --confirm-r0 before F7 deployment")
    require(not args.config and not args.persist_to, "--config and --persist-to are local only")
    account = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    require(re.fullmatch(r"[0-9a-f]{32}", account) and token, "missing Cloudflare API credentials")
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", args.database or ""),
            "remote R0 requires a D1 database UUID")
    # Remote Wrangler --file goes through /import and drops RETURNING rows.
    # Use /query once, with bind parameters and no URL or credentials in argv.
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{account}/d1/database/{args.database}/query",
        data=json.dumps(dict(sql=sql, params=params)).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "velmora-r0"},
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=30) as response:
            body = response.read(JSON_CAP + 1)
    except urllib.error.HTTPError as error:
        raise Failure(f"D1 disarm HTTP {error.code}; outcome unknown, stop") from None
    except (OSError, ValueError):
        raise Failure("D1 disarm network failure; outcome unknown, stop") from None
    return body


def disarm(args, receipt):
    require(not receipt["f7_started"], "R0 is forbidden after F7 starts; use R1b")
    sql, params = disarm_statement(receipt)
    raw = (remote_query if args.remote else local_query)(args, sql, params)
    require(len(raw) <= JSON_CAP, "D1 disarm response too large; outcome unknown, stop")
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError):
        raise Failure("D1 disarm response is not JSON; outcome unknown, stop") from None
    if args.remote:
        require(isinstance(payload, dict) and payload.get("success") is True,
                "D1 disarm response invalid; outcome unknown, stop")
        payload = payload.get("result")
    require(isinstance(payload, list) and len(payload) == 1 and isinstance(payload[0], dict)
            and payload[0].get("success") is True, "D1 disarm response invalid; outcome unknown, stop")
    rows = payload[0].get("results")
    require(rows == [] or (rows == [{"id": 1}] and type(rows[0]["id"]) is int),
            "D1 disarm returning rows invalid; outcome unknown, stop")
    # Local Wrangler omits the change count; RETURNING reports the target row.
    meta = payload[0].get("meta")
    changes = meta.get("changes") if args.remote and isinstance(meta, dict) else len(rows) if not args.remote else None
    require(type(changes) is int and changes == len(rows), "D1 disarm change count inconsistent; stop")
    require(changes == 1, "D1 disarm changed 0 rows; stop and use R1b steps 3–8")
    print(json.dumps({"changes": changes}))


def replay_start(receipt, census):
    held, count = census.get("s_held_ms"), census.get("held_count")
    require(type(count) is int and count >= 0 and "s_held_ms" in census and
            (held is None if count == 0 else safe_int(held) and held >= 0), "invalid F3 held-extent census")
    start = receipt["f1_started_at_ms"]
    since = max(0, min(start, held if held is not None else start) - 600_000)
    print(json.dumps({"since_ms": since, "margin_ms": 0}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--f1", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--r1b-census", help="read pg-copy JSON (or - for stdin) and report the replay start")
    mode.add_argument("--local", action="store_true")
    mode.add_argument("--remote", action="store_true")
    parser.add_argument("--confirm-r0", action="store_true")
    parser.add_argument("--database")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--persist-to", type=Path)
    parser.add_argument("--wrangler", default="wrangler")
    args = parser.parse_args()
    receipt = f1_receipt(args.f1)
    if args.r1b_census:
        replay_start(receipt, json_input(args.r1b_census))
    else:
        disarm(args, receipt)


if __name__ == "__main__":
    raise SystemExit(diagnostic_main(main))
