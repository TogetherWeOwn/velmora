// d1-replay.mjs: runs the D1 trace of the local benchmark through the local
// D1 runtime (workerd, via wrangler's getPlatformProxy) and sums D1's own
// meta.rows_read and meta.rows_written by label and by statement.
//
//   node bench/d1-replay.mjs <trace.jsonl> <migrations dir> <work dir> <out.json>
//
// The replay works in a new directory it makes inside <work dir> and
// removes at the end; nothing else in <work dir> is touched.
//
// NODE_DIR names a directory with wrangler installed (npm ci of
// workers/s3-bridge/package.json); run-local.sh sets it up.
//
// The trace is the exact sequence of D1 calls of the native run, with their
// parameters, after the same migrations. Replayed in order from the same
// schema, every statement meets the same rows, so the figures are what D1
// reports for that run. Each call is replayed as the Worker makes it: a
// query with .all() (the Worker uses .raw(); same execution), a write with
// .run(), a batch with db.batch() (one transaction). A call that failed in
// the native run must fail here too, and the other way round: the number
// of disagreements is reported and must be 0.

import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";

const [tracePath, migrations, workRoot, outPath] = process.argv.slice(2).map((p) => path.resolve(p));
if (!outPath) {
  console.error("usage: d1-replay.mjs <trace.jsonl> <migrations dir> <work dir> <out.json>");
  process.exit(2);
}
const nodeDir = process.env.NODE_DIR;
if (!nodeDir) {
  console.error("NODE_DIR is not set");
  process.exit(2);
}
const require = createRequire(path.join(nodeDir, "package.json"));

fs.mkdirSync(workRoot, { recursive: true });
const work = fs.mkdtempSync(path.join(workRoot, "replay-"));
// wrangler writes its own scratch (.wrangler/) into the working directory.
process.chdir(work);
const config = path.join(work, "wrangler.toml");
fs.writeFileSync(
  config,
  [
    'name = "velmora-bench-d1"',
    'compatibility_date = "2026-11-01"',
    "[[d1_databases]]",
    'binding = "DB"',
    'database_name = "bench"',
    'database_id = "00000000-0000-0000-0000-000000000000"',
    `migrations_dir = ${JSON.stringify(path.resolve(migrations))}`,
    "",
  ].join("\n"),
);
const state = path.join(work, "state");
const wrangler = path.join(nodeDir, "node_modules", ".bin", "wrangler");
execFileSync(
  wrangler,
  ["d1", "migrations", "apply", "bench", "--local", "--persist-to", state, "-c", config],
  { stdio: ["ignore", "ignore", "inherit"], env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1" } },
);

const { getPlatformProxy } = await import(require.resolve("wrangler"));
const { env, dispose } = await getPlatformProxy({ configPath: config, persist: { path: path.join(state, "v3") } });
const db = env.DB;

function bind(p) {
  if (p === null) return null;
  if (typeof p === "number" || typeof p === "string") return p;
  if (p && typeof p.b === "string") {
    const buf = Buffer.from(p.b, "base64");
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  throw new Error(`unknown parameter ${JSON.stringify(p)}`);
}

const norm = (q) => q.replace(/\s+/g, " ").trim();
const byLabel = {};
const byStatement = {};
const byLabelStatement = {};
const disagree = [];
let calls = 0;
let refusedBatches = 0;

function charge(label, q, meta) {
  const rr = meta?.rows_read ?? 0;
  const rw = meta?.rows_written ?? 0;
  const l = (byLabel[label] ??= { d1_rows_read: 0, d1_rows_written_replay: 0, d1_statements_replay: 0 });
  l.d1_rows_read += rr;
  l.d1_rows_written_replay += rw;
  l.d1_statements_replay += 1;
  const key = norm(q);
  const s = (byStatement[key] ??= { n: 0, rows_read: 0, rows_written: 0 });
  s.n += 1;
  s.rows_read += rr;
  s.rows_written += rw;
  const ls = ((byLabelStatement[label] ??= {})[key] ??= { n: 0, rows_read: 0, rows_written: 0 });
  ls.n += 1;
  ls.rows_read += rr;
  ls.rows_written += rw;
}

const rl = readline.createInterface({ input: fs.createReadStream(tracePath), crlfDelay: Infinity });
const t0 = Date.now();
for await (const line of rl) {
  if (!line) continue;
  const call = JSON.parse(line);
  calls += 1;
  const stmts = call.s.map((s) => db.prepare(s.q).bind(...s.p.map(bind)));
  let ok = true;
  let metas = [];
  try {
    if (call.k === "q") metas = [(await stmts[0].all()).meta];
    else if (call.k === "e") metas = [(await stmts[0].run()).meta];
    else metas = (await db.batch(stmts)).map((r) => r.meta);
  } catch (e) {
    ok = false;
    if (call.k === "b") refusedBatches += 1;
    if (call.ok) disagree.push({ i: call.i, l: call.l, native: "ok", d1: String(e).slice(0, 200) });
  }
  if (ok && !call.ok) disagree.push({ i: call.i, l: call.l, native: "error", d1: "ok" });
  if (ok) call.s.forEach((s, j) => charge(call.l, s.q, metas[j]));
  else {
    const l = (byLabel[call.l] ??= { d1_rows_read: 0, d1_rows_written_replay: 0, d1_statements_replay: 0 });
    l.d1_refused_calls = (l.d1_refused_calls ?? 0) + 1;
  }
}
await dispose();

// The 8 statements that read the most, for each label.
const topByLabel = {};
for (const [label, stmts] of Object.entries(byLabelStatement)) {
  topByLabel[label] = Object.entries(stmts)
    .sort((a, b) => b[1].rows_read - a[1].rows_read)
    .slice(0, 8)
    .map(([q, v]) => ({ q: q.slice(0, 300), ...v }));
}
const top = Object.entries(byStatement)
  .sort((a, b) => b[1].rows_read - a[1].rows_read)
  .slice(0, 40)
  .map(([q, v]) => ({ q: q.slice(0, 400), ...v }));
fs.writeFileSync(
  outPath,
  JSON.stringify(
    { calls, seconds: (Date.now() - t0) / 1000, refused_batches: refusedBatches, disagreements: disagree.length, disagree: disagree.slice(0, 20), by_label: byLabel, top_statements: top, top_by_label: topByLabel },
    null,
    1,
  ),
);
console.error(`d1-replay: ${calls} calls in ${((Date.now() - t0) / 1000).toFixed(1)} s, ${disagree.length} disagreements`);
process.chdir(workRoot);
fs.rmSync(work, { recursive: true, force: true });
if (disagree.length) process.exit(1);
