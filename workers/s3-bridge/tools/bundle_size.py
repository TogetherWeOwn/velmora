#!/usr/bin/env python3
"""Size of the Worker upload: one hard limit and a non-blocking report.

Cloudflare's limits are the only blocking ones
(https://developers.cloudflare.com/workers/platform/limits/#worker-size):
64 MiB uncompressed on every plan, with no compressed limit. The size
checked is what `wrangler deploy` uploads, measured with
`wrangler deploy --dry-run --outdir <dir>` on the built bundle: the
modules it writes there (the bundled JS and the wasm; not README.md, not
the source map, which is not uploaded). Their sum is wrangler's own
"Total Upload" line, which is cross-checked, so a change in what wrangler
uploads fails loudly here instead of being measured wrong.

The second limit, 1 s of start-up, has no measurement in CI: the dry run
reports none. Cloudflare measures it on every real upload and refuses a
deploy over it (error 10021), and the previous version stays live.

Size below 64 MiB never blocks. `report` compares the upload with the
latest one measured on main and prints a GitHub `::warning` when it grew
by more than 1 % or 50,000 bytes, with the cost measured for it: a
request served by a new isolate takes about 10.5 ms more per MB of wasm
(throwaway Workers, 2026-11-21: 209 ms at 3.0 MB to 345 ms at 16.0 MB).

Subcommands:
  config SRC DST          SRC without its top-level [build] table, so the
                          dry run packages the bundle already built
                          instead of building it again.
  measure OUTDIR LOG OUT  checks the limit; writes OUT (JSON). Exit 1 over
                          the limit or if wrangler's total disagrees.
  report CUR [BASE [SHA]] markdown and `::warning` lines on stdout; the
                          markdown is also appended to $GITHUB_STEP_SUMMARY
                          when set. A missing BASE file is reported, not an
                          error. SHA, the PR's base commit, is named when
                          BASE is from another commit. Always exit 0.
"""

import json
import os
import re
import sys

LIMIT_BYTES = 64 * 1024 * 1024  # 64 MiB, uncompressed, every plan
WARN_FRACTION = 0.01
WARN_BYTES = 50_000
MS_PER_MB = 10.5  # per 1,000,000 bytes, new isolate; see the docstring

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_TOTAL = re.compile(r"Total Upload:\s*([0-9.]+)\s*KiB\s*/\s*gzip:\s*([0-9.]+)\s*KiB")


def strip_build_table(text):
    """Drops the top-level [build] table (header to the next table)."""
    out, skip = [], False
    for line in text.split("\n"):
        s = line.strip()
        if s.startswith("["):
            skip = s == "[build]"
        if not skip:
            out.append(line)
    return "\n".join(out)


def uploaded_files(outdir):
    """The modules wrangler uploads, from its --outdir: name -> bytes."""
    files = {}
    for name in sorted(os.listdir(outdir)):
        path = os.path.join(outdir, name)
        if not os.path.isfile(path) or name == "README.md" or name.endswith(".map"):
            continue
        files[name] = os.path.getsize(path)
    return files


def parse_total(log):
    """wrangler's "Total Upload: X KiB / gzip: Y KiB" as (bytes, gzip bytes)."""
    m = _TOTAL.search(_ANSI.sub("", log))
    if not m:
        return None
    return float(m.group(1)) * 1024, float(m.group(2)) * 1024


def measure(outdir, log):
    """Returns (record, errors). The record is written even with errors."""
    files = uploaded_files(outdir)
    upload = sum(files.values())
    wasm = sum(v for k, v in files.items() if k.endswith(".wasm"))
    errors = []
    total = parse_total(log)
    gzip = None
    if total is None:
        errors.append("wrangler printed no 'Total Upload: .. KiB / gzip: .. KiB' line")
    else:
        # wrangler rounds to 0.01 KiB (10.24 bytes).
        if abs(total[0] - upload) > 6:
            errors.append(
                f"wrangler's Total Upload ({total[0] / 1024:.2f} KiB) is not the sum of "
                f"the modules in its outdir ({upload} bytes): what it uploads changed"
            )
        gzip = round(total[1])
    if not files:
        errors.append("the dry run wrote no module")
    if upload > LIMIT_BYTES:
        errors.append(
            f"upload is {upload:,} bytes, over Cloudflare's {LIMIT_BYTES:,}-byte "
            "(64 MiB) uncompressed Worker size limit"
        )
    record = {"upload_bytes": upload, "wasm_bytes": wasm, "gzip_bytes": gzip, "files": files}
    return record, errors


def _mb(n):
    return n / 1_000_000


def report(cur, base=None, expected_base=""):
    """Returns (markdown, warnings). expected_base: the PR's base commit;
    when main's measurement is from another commit, both say so."""
    up = cur["upload_bytes"]
    lines = [
        "### Worker upload size",
        "",
        f"- Upload (uncompressed): **{up:,} bytes** ({_mb(up):.3f} MB); "
        f"wasm {cur['wasm_bytes']:,} bytes"
        + (f"; gzip {cur['gzip_bytes']:,} bytes" if cur.get("gzip_bytes") else ""),
        f"- Cloudflare limit: {LIMIT_BYTES:,} bytes (64 MiB), {100 * up / LIMIT_BYTES:.1f} % used. "
        "Only this limit blocks.",
    ]
    warnings = []
    if not base:
        lines.append("- No measurement from main to compare with.")
        return "\n".join(lines) + "\n", warnings
    b = base["upload_bytes"]
    d = up - b
    pct = 100 * d / b if b else 0.0
    ms = MS_PER_MB * _mb(d)
    src = f" at {base['sha'][:12]}" if base.get("sha") else ""
    other = ""
    if expected_base and base.get("sha") != expected_base:
        other = (
            f"main's measurement is from {base.get('sha', '')[:12] or 'an unknown commit'}, not this "
            f"PR's base {expected_base[:12]}; the delta also includes the changes between those two "
            f"commits (on main, or on the branch this PR targets). "
        )
    lines.append(
        f"- Against main{src}: {b:,} bytes, delta **{d:+,} bytes ({pct:+.2f} %)**, "
        f"about {ms:+.1f} ms per request on a new isolate"
    )
    if other:
        lines.append(f"- Note: {other.strip()}")
    if d > WARN_BYTES or (b and d > WARN_FRACTION * b):
        warnings.append(
            other + f"Worker upload grew by {d:,} bytes ({pct:+.2f} %) against main, to {up:,} bytes. "
            f"Measured cost: about {MS_PER_MB} ms per MB on every request served by a new "
            f"isolate (after a deploy, or on a machine that has not run this version), so "
            f"about {ms:.1f} ms here. Not blocking; keep the bundle small."
        )
    return "\n".join(lines) + "\n", warnings


def main(argv):
    if len(argv) >= 3 and argv[0] == "config":
        with open(argv[1]) as f:
            text = f.read()
        with open(argv[2], "w") as f:
            f.write(strip_build_table(text))
        return 0
    if len(argv) == 4 and argv[0] == "measure":
        with open(argv[2], errors="replace") as f:
            log = f.read()
        record, errors = measure(argv[1], log)
        record["sha"] = os.environ.get("GITHUB_SHA", "")
        with open(argv[3], "w") as f:
            json.dump(record, f, indent=1, sort_keys=True)
        for name, n in record["files"].items():
            print(f"  {name}: {n:,} bytes")
        print(f"upload: {record['upload_bytes']:,} bytes (limit {LIMIT_BYTES:,})")
        for e in errors:
            print(f"::error::{e}")
        return 1 if errors else 0
    if len(argv) in (2, 3, 4) and argv[0] == "report":
        with open(argv[1]) as f:
            cur = json.load(f)
        base = None
        if len(argv) >= 3 and os.path.isfile(argv[2]) and os.path.getsize(argv[2]) > 0:
            with open(argv[2]) as f:
                base = json.load(f)
        md, warnings = report(cur, base, argv[3] if len(argv) == 4 else "")
        sys.stdout.write(md)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as f:
                f.write(md)
        for w in warnings:
            print(f"::warning title=Worker size grew::{w}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
