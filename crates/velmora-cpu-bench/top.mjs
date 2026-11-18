#!/usr/bin/env node
// Ranks the functions of a V8 CPU profile by self time.
//
//   node --cpu-prof --cpu-prof-dir=prof run.mjs <bench.wasm>
//   node top.mjs prof/*.cpuprofile [--top 25]
//
// Rust symbol hashes and generic arguments are trimmed so that one
// function is one line.
import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const at = args.indexOf("--top");
const top = at < 0 ? 25 : Number(args.splice(at, 2)[1]);
const profile = JSON.parse(readFileSync(args[0], "utf8"));

const short = (name) =>
  name
    .replace(/::h[0-9a-f]{16}$/, "")
    .replace(/<([^<>]|<[^<>]*>)*>/g, "<..>")
    .slice(0, 110);

const byId = new Map(profile.nodes.map((n) => [n.id, n]));
const self = new Map();
let total = 0;
const deltas = profile.timeDeltas;
profile.samples.forEach((id, i) => {
  const frame = byId.get(id).callFrame;
  const name = short(frame.functionName || `(anonymous ${frame.url.split("/").pop()}:${frame.lineNumber})`);
  const dt = deltas[i] / 1000;
  self.set(name, (self.get(name) ?? 0) + dt);
  total += dt;
});
const idle = (self.get("(idle)") ?? 0) + (self.get("(program)") ?? 0);
const busy = total - idle;
console.log(`sampled ${total.toFixed(0)} ms, ${busy.toFixed(0)} ms outside (idle)/(program)`);
console.log("self ms".padStart(9) + "  share  function");
[...self.entries()]
  .filter(([name]) => name !== "(idle)" && name !== "(program)")
  .sort((a, b) => b[1] - a[1])
  .slice(0, top)
  .forEach(([name, ms]) => {
    console.log(ms.toFixed(0).padStart(9) + ((100 * ms) / busy).toFixed(1).padStart(6) + "%  " + name);
  });
