#!/usr/bin/env python3
"""report.py: the tables and the cost model of one local benchmark run.

    python3 -I bench/report.py <run dir> [--prices bench/prices.json] [--cpu cpu.json] [--name NAME]

<run dir> holds counts.json (tests/bench_counts.rs) and d1.json
(bench/d1-replay.mjs). Writes <run dir>/results.json and results.md.
D1 rows read and written are D1's own counts from the replay; the native
meter's rows written are kept as d1_rows_written_native and compared with
them (rows_written_check, a warning when they differ).

    python3 -I bench/report.py --compare <run dir A> <run dir B> [--out FILE]

prints (or writes) a side-by-side table of two runs, with the change.

Cost model (list prices of prices.json, no included allowance):
- one extent is 16 MiB of plaintext, so 1 TB (1e12 bytes) is 59,605 extents;
- ingest per extent = the multipart path per part (CreateMultipartUpload and
  CompleteMultipartUpload shared by the parts) + post + verify + release of a
  16 MiB extent + its eviction from the hot tier + the SAFETY storage of the
  copy while it is held (SAFETY_MIN_AGE_SECS + VERIFY_DELAY_SECS);
- the dispatcher (cron) runs while work is due are charged per extent (they
  send the releases); its runs with nothing due are the fixed cost: per run
  x 8,640 runs a month;
- stored per TB-month: catalogue bytes per extent (dbstat) x D1 storage;
  released data is on Usenet, so R2 holds only the bounded hot tier
  (HOT_CAP_BYTES, a fixed cost) and the recovery records;
- served per TB: a 16 MiB GET per extent, hot (from R2) or cold (from
  Usenet, which also fills the cache, later evicted).
Worker CPU is not measured locally (the native run is not the Worker). It
is priced from --cpu (ms per extent ingested, per MiB served hot and cold,
measured on a deployed Worker); without it the CPU lines are 0 and say so.
"""
import json
import sys
from pathlib import Path

MIB = 1024 * 1024
EXTENT = 16 * MIB
TB = 1e12
EXTENTS_PER_TB = TB / EXTENT
CRON_RUNS_PER_MONTH = 12 * 24 * 30

FIELDS = [
    ("invocations", "inv"),
    ("d1_calls", "D1 calls"),
    ("d1_statements", "D1 stmts"),
    ("d1_rows_read", "D1 rows read"),
    ("d1_rows_written", "D1 rows written"),
    ("r2_class_a", "R2 A"),
    ("r2_class_b", "R2 B"),
    ("r2_mib_in", "R2 MiB in"),
    ("r2_mib_out", "R2 MiB out"),
    ("queue_messages", "queue msgs"),
    ("nntp_connects", "NNTP conn"),
    ("nntp_posts", "posts"),
    ("nntp_asks", "STAT/size"),
    ("nntp_bodies", "bodies"),
    ("wall_ms", "native ms"),
]


def load(run):
    run = Path(run)
    counts = json.loads((run / "counts.json").read_text())
    d1 = json.loads((run / "d1.json").read_text())
    if d1.get("disagreements"):
        sys.exit(f"{run}: the D1 replay disagrees with the native run ({d1['disagreements']} calls)")
    labels = {}
    for label, c in counts["counts"].items():
        c = dict(c)
        r = d1["by_label"].get(label, {})
        c["d1_rows_read"] = r.get("d1_rows_read", 0)
        # Rows written are D1's own count (the replay), which is what is
        # reported and priced. The native meter (src/meter.rs) is a model
        # of that count; where the two differ the model is wrong, and the
        # report says so (rows_written_check).
        c["d1_rows_written_native"] = c["d1_rows_written"]
        c["d1_rows_written"] = r.get("d1_rows_written_replay", 0)
        c["r2_mib_in"] = c["r2_bytes_in"] / MIB
        c["r2_mib_out"] = c["r2_bytes_out"] / MIB
        c["wall_ms"] = c["wall_us"] / 1000
        labels[label] = c
    return counts, d1, labels


def rows_written_check(labels):
    """The native meter against D1's own count, label by label."""
    differ = {
        k: {"native": c["d1_rows_written_native"], "d1": c["d1_rows_written"]}
        for k, c in sorted(labels.items())
        if c["d1_rows_written_native"] != c["d1_rows_written"]
    }
    return {
        "native": sum(c["d1_rows_written_native"] for c in labels.values()),
        "d1": sum(c["d1_rows_written"] for c in labels.values()),
        "labels": len(labels),
        "labels_differing": differ,
    }


def check_line(chk):
    if not chk["labels_differing"]:
        return f"Rows-written check: the native meter equals D1's count on all {chk['labels']} labels ({chk['d1']:,} rows)."
    worst = sorted(chk["labels_differing"].items(), key=lambda kv: -abs(kv[1]["native"] - kv[1]["d1"]))[:5]
    return (
        f"WARNING, rows-written check: the native meter gives {chk['native']:,} rows, D1 {chk['d1']:,} "
        f"({len(chk['labels_differing'])} of {chk['labels']} labels differ; largest: "
        + ", ".join(f"{k} {v['native']:,} vs {v['d1']:,}" for k, v in worst)
        + "). The figures below are D1's; the native meter (src/meter.rs) miscounts a statement of this run."
    )


def per(c, n):
    return {k: (v / n if isinstance(v, (int, float)) else v) for k, v in c.items()} if n else {}


def add(*cs):
    out = {}
    for c in cs:
        for k, v in c.items():
            if isinstance(v, (int, float)):
                out[k] = out.get(k, 0) + v
    return out


def fmt(v):
    if v == 0:
        return "0"
    if abs(v) >= 100:
        return f"{v:,.0f}"
    if abs(v) >= 10:
        return f"{v:.1f}"
    return f"{v:.2f}"


def table(rows, first="label"):
    head = "| " + first + " | " + " | ".join(h for _, h in FIELDS) + " |"
    sep = "|---|" + "---:|" * len(FIELDS)
    lines = [head, sep]
    for name, c in rows:
        lines.append("| " + name + " | " + " | ".join(fmt(c.get(k, 0)) for k, _ in FIELDS) + " |")
    return lines


def model(counts, labels, prices, cpu):
    usd = prices["usd"]
    calls = counts["calls"]
    classes = counts["classes"]
    vars_ = counts["vars"]
    z = {}

    def op(name):
        return per(labels.get("op:" + name, z), calls.get("op:" + name, 0))

    parts = calls.get("op:mpu_upload_part", 0)
    ingest_s3 = per(
        add(labels.get("op:mpu_create", z), labels.get("op:mpu_upload_part", z), labels.get("op:mpu_complete", z)),
        parts,
    )
    big = classes["big"]["extents"]
    stages = {s: per(labels.get(f"stage:big:{s}", z), big) for s in ("post", "verify", "release")}
    all_extents = sum(c["extents"] for c in classes.values())
    evict = per(labels.get("stage:evict", z), all_extents)
    # The dispatcher's runs while work was due send that work (a release
    # is sent by it): charged per extent. Its runs with nothing due are
    # the fixed cost.
    cron = per(labels.get("stage:cron", z), all_extents)
    cron_idle = per(labels.get("stage:cron_idle", z), calls.get("stage:cron_idle", 0))
    hold_days = (int(vars_.get("SAFETY_MIN_AGE_SECS", 0)) + int(vars_.get("VERIFY_DELAY_SECS", 0))) / 86400

    def dollars(c, cpu_ms=0.0):
        return {
            "workers_requests": c.get("invocations", 0) * usd["workers_requests_per_m"] / 1e6,
            "workers_cpu": cpu_ms * usd["workers_cpu_ms_per_m"] / 1e6,
            "d1_rows_read": c.get("d1_rows_read", 0) * usd["d1_rows_read_per_m"] / 1e6,
            "d1_rows_written": c.get("d1_rows_written", 0) * usd["d1_rows_written_per_m"] / 1e6,
            "r2_class_a": c.get("r2_class_a", 0) * usd["r2_class_a_per_m"] / 1e6,
            "r2_class_b": c.get("r2_class_b", 0) * usd["r2_class_b_per_m"] / 1e6,
            "queues": (3 * c.get("queue_messages", 0) + c.get("queue_redeliveries", 0)) * usd["queues_ops_per_m"] / 1e6,
        }

    def scale(d, k):
        return {a: v * k for a, v in d.items()}

    cpu = cpu or {}
    ingest_parts = {
        "s3_upload": ingest_s3,
        "post": stages["post"],
        "verify": stages["verify"],
        "release": stages["release"],
        "evict": evict,
        "dispatch": cron,
    }
    ingest_extent = add(*ingest_parts.values())
    ingest_tb = scale(dollars(ingest_extent, cpu.get("ingest_ms_per_extent", 0.0)), EXTENTS_PER_TB)
    ingest_tb["r2_storage_while_held"] = 1000 * usd["r2_storage_gb_month"] * hold_days / 30
    by_stage_tb = {
        k: sum(scale(dollars(v), EXTENTS_PER_TB).values()) for k, v in ingest_parts.items()
    }

    hot = op("get_hot_big")
    cold = add(op("get_cold_big"), evict)
    mib_per_extent = EXTENT / MIB
    served_hot_tb = scale(dollars(hot, cpu.get("hot_get_ms_per_mib", 0.0) * mib_per_extent), EXTENTS_PER_TB)
    served_cold_tb = scale(dollars(cold, cpu.get("cold_get_ms_per_mib", 0.0) * mib_per_extent), EXTENTS_PER_TB)

    cat_bytes = counts.get("catalogue_bytes", {}).get("per_extent", 0)
    stored_tb_month = {
        "d1_storage": EXTENTS_PER_TB * cat_bytes / 1e9 * usd["d1_storage_gb_month"],
        "r2_storage_released": 0.0,
    }
    hot_cap_gb = int(vars_.get("HOT_CAP_BYTES", 0)) / 1e9
    fixed_month = {
        "cron_idle": sum(dollars(cron_idle).values()) * CRON_RUNS_PER_MONTH,
        "r2_hot_tier_at_cap": hot_cap_gb * usd["r2_storage_gb_month"],
    }
    ranked = sorted(ingest_tb.items(), key=lambda kv: kv[1], reverse=True)
    return {
        "assumptions": {
            "extent_bytes": EXTENT,
            "extents_per_tb": EXTENTS_PER_TB,
            "hold_days": hold_days,
            "cpu_source": cpu.get("source", "none: CPU priced at 0"),
            "cpu": {k: v for k, v in cpu.items() if k != "source"},
        },
        "per_extent_ingest": {k: v for k, v in ingest_parts.items()},
        "per_extent_ingest_total": ingest_extent,
        "cron_idle_per_run": cron_idle,
        "usd_per_tb_ingested": ingest_tb,
        "usd_per_tb_ingested_total": sum(ingest_tb.values()),
        "usd_per_tb_ingested_by_stage": by_stage_tb,
        "usd_per_tb_stored_month": stored_tb_month,
        "usd_per_tb_served_hot": served_hot_tb,
        "usd_per_tb_served_hot_total": sum(served_hot_tb.values()),
        "usd_per_tb_served_cold": served_cold_tb,
        "usd_per_tb_served_cold_total": sum(served_cold_tb.values()),
        "usd_fixed_per_month": fixed_month,
        "top_drivers_ingest": ranked[:5],
    }


def render(name, counts, d1, labels, m, chk):
    ops = sorted((k for k in labels if k.startswith("op:")))
    rows = [(k[3:] + f" (x{counts['calls'].get(k, 0)})", per(labels[k], counts["calls"].get(k, 1))) for k in ops]
    L = [f"# Local benchmark: {name}", ""]
    L += [
        "Layer 1 (native rig, fake NNTP, production `[vars]` with the overrides in tests/bench_counts.rs). "
        "Figures per call; D1 rows read and written are D1's own counters from the replay through local D1; "
        "native ms is the wall time of the native run (indicative only).",
        "",
        check_line(chk),
        "",
        "Variables: " + ", ".join(f"{k}={v}" for k, v in counts["vars"].items()),
        "",
        "BENCH_VARS (changed for this run): "
        + (", ".join(f"{k}={v}" for k, v in counts.get("bench_vars", {}).items()) or "none"),
        "",
        "## Per S3 operation (per call)",
        "",
    ]
    L += table(rows, "operation")
    stages = sorted(k for k in labels if k.startswith("stage:"))
    srows = []
    for k in stages:
        parts = k.split(":")
        if len(parts) == 3 and parts[1] in counts["classes"]:
            n = counts["classes"][parts[1]]["extents"]
            srows.append((f"{parts[1]} {parts[2]} (per extent, {n})", per(labels[k], n)))
        else:
            n = counts["calls"].get(k, 1)
            srows.append((f"{parts[-1]} (per run, x{n})", per(labels[k], n)))
    L += ["", "## Per pipeline stage", "", "Classes: " + ", ".join(
        f"{c}: {v['extents']} extents, {v['plain_bytes'] / MIB:.1f} MiB" for c, v in counts["classes"].items()), ""]
    L += table(srows, "stage")
    L += ["", "## Cost model (list prices, no allowance)", ""]
    a = m["assumptions"]
    L += [f"CPU: {a['cpu_source']}. SAFETY hold {a['hold_days']:.2f} days. {a['extents_per_tb']:,.0f} extents per TB.", ""]
    L += ["| $ per TB ingested | $ |", "|---|---:|"]
    for k, v in sorted(m["usd_per_tb_ingested"].items(), key=lambda kv: -kv[1]):
        L.append(f"| {k} | {v:.3f} |")
    L.append(f"| **total** | **{m['usd_per_tb_ingested_total']:.3f}** |")
    L += ["", "| ingest stage | $ per TB (without CPU and storage) |", "|---|---:|"]
    for k, v in m["usd_per_tb_ingested_by_stage"].items():
        L.append(f"| {k} | {v:.3f} |")
    L += ["", "| $ per TB served | hot | cold |", "|---|---:|---:|"]
    for k in m["usd_per_tb_served_hot"]:
        L.append(f"| {k} | {m['usd_per_tb_served_hot'][k]:.4f} | {m['usd_per_tb_served_cold'][k]:.4f} |")
    L.append(f"| **total** | **{m['usd_per_tb_served_hot_total']:.4f}** | **{m['usd_per_tb_served_cold_total']:.4f}** |")
    L += ["", "| $ per TB stored per month | $ |", "|---|---:|"]
    for k, v in m["usd_per_tb_stored_month"].items():
        L.append(f"| {k} | {v:.4f} |")
    L += ["", "| fixed $ per month | $ |", "|---|---:|"]
    for k, v in m["usd_fixed_per_month"].items():
        L.append(f"| {k} | {v:.3f} |")
    L += ["", "## Statements that read the most rows (whole run)", "", "| rows read | calls | statement |", "|---:|---:|---|"]
    for s in d1["top_statements"][:12]:
        q = s["q"].replace("|", "\\|")[:160]
        L.append(f"| {s['rows_read']:,} | {s['n']:,} | `{q}` |")
    return "\n".join(L) + "\n"


def d1_written(r):
    """Results written before rows written were taken from D1 hold the
    native meter's figure under d1_rows_written and D1's under
    d1_rows_written_replay: compare D1's. Their model totals stay priced
    with the native figure; returns whether that is the case."""
    old = False
    for section in ("ops", "stages"):
        for c in r[section].values():
            if "d1_rows_written_native" not in c and "d1_rows_written_replay" in c:
                old = old or c["d1_rows_written"] != c["d1_rows_written_replay"]
                c["d1_rows_written"] = c["d1_rows_written_replay"]
    return old


def compare(a_dir, b_dir, out):
    ra = json.loads((Path(a_dir) / "results.json").read_text())
    rb = json.loads((Path(b_dir) / "results.json").read_text())
    stale = [r["name"] for r in (ra, rb) if d1_written(r)]
    L = [f"| per call / per extent | {ra['name']} | {rb['name']} | change |", "|---|---:|---:|---:|"]
    va, vb = ra.get("bench_vars", {}), rb.get("bench_vars", {})
    if va or vb:
        show = lambda v: ", ".join(f"{k}={x}" for k, x in v.items()) or "none"
        L.append(f"| BENCH_VARS | {show(va)} | {show(vb)} | |")
    keys = ["invocations", "d1_calls", "d1_rows_read", "d1_rows_written", "r2_class_a", "r2_class_b", "queue_messages", "nntp_asks", "nntp_bodies"]
    for section in ("ops", "stages"):
        for label in sorted(set(ra[section]) | set(rb[section])):
            ca, cb = ra[section].get(label, {}), rb[section].get(label, {})
            for k in keys:
                va, vb = ca.get(k, 0), cb.get(k, 0)
                if va == 0 and vb == 0:
                    continue
                ch = "" if va == vb else (f"{(vb - va) / va * 100:+.0f}%" if va else "new")
                L.append(f"| {label} {k} | {fmt(va)} | {fmt(vb)} | {ch} |")
    for k in ("usd_per_tb_ingested_total", "usd_per_tb_served_hot_total", "usd_per_tb_served_cold_total"):
        va, vb = ra["model"][k], rb["model"][k]
        ch = f"{(vb - va) / va * 100:+.1f}%" if va else ("" if va == vb else "new")
        L.append(f"| model {k} | {va:.3f} | {vb:.3f} | {ch} |")
    for name in stale:
        L.append(
            f"| note | | | the model totals of {name} price the native meter's rows written, "
            "which differ from D1's in that run: run report.py on it again |"
        )
    text = "\n".join(L) + "\n"
    if out:
        Path(out).write_text(text)
    else:
        sys.stdout.write(text)


def main(argv):
    if argv and argv[0] == "--compare":
        out = argv[argv.index("--out") + 1] if "--out" in argv else None
        return compare(argv[1], argv[2], out)
    run = Path(argv[0])
    opts = dict(zip(argv[1::2], argv[2::2]))
    prices = json.loads(Path(opts.get("--prices", Path(__file__).with_name("prices.json"))).read_text())
    cpu = json.loads(Path(opts["--cpu"]).read_text()) if "--cpu" in opts else None
    name = opts.get("--name", run.name)
    counts, d1, labels = load(run)
    m = model(counts, labels, prices, cpu)
    chk = rows_written_check(labels)
    ops = {k[3:]: per(v, counts["calls"].get(k, 1)) for k, v in labels.items() if k.startswith("op:")}
    stages = {}
    for k, v in labels.items():
        parts = k.split(":")
        if len(parts) == 3 and parts[1] in counts["classes"]:
            stages[f"{parts[1]}:{parts[2]}"] = per(v, counts["classes"][parts[1]]["extents"])
        elif k.startswith("stage:"):
            stages[parts[-1]] = per(v, counts["calls"].get(k, 1))
    result = {
        "name": name,
        "vars": counts["vars"],
        "bench_vars": counts.get("bench_vars", {}),
        "classes": counts["classes"],
        "replay": {"calls": d1["calls"], "disagreements": d1["disagreements"]},
        "rows_written_check": chk,
        "ops": ops,
        "stages": stages,
        "model": m,
        "top_statements": d1["top_statements"][:20],
    }
    (run / "results.json").write_text(json.dumps(result, indent=1))
    (run / "results.md").write_text(render(name, counts, d1, labels, m, chk))
    print(f"report: {run / 'results.md'}")
    if chk["labels_differing"]:
        print(check_line(chk), file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
