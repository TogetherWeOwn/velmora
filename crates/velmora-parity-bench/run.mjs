#!/usr/bin/env node
// Checks and times velmora_parity_bench.wasm under node (V8).
//
//   node run.mjs <bench.wasm> [--reps 15] [--check-only] [--expect-simd on|off]
//
// First the module's self-check: the bytes this build produces must be the
// ones the native build pins. A build that fails it is not timed and the
// script exits 1. Then, for each configured geometry, CPU milliseconds per
// MiB of extent plaintext for encoding all parity shards and for rebuilding
// 1..m lost data shards: the median of `reps` runs after one warm-up run.
// What is timed is elapsed time. The module is single threaded and does no
// I/O, so on an idle host that is its CPU time; on a busy host it also
// counts time the process was not running, and is an upper bound.
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const at = args.indexOf(name);
  return at < 0 ? fallback : args.splice(at, 2)[1];
};
const reps = Number(flag("--reps", "15"));
const expectSimd = flag("--expect-simd", null);
const checkOnly = args.includes("--check-only") && args.splice(args.indexOf("--check-only"), 1).length > 0;
const wasmPath = args[0];
if (!wasmPath || (expectSimd !== null && expectSimd !== "on" && expectSimd !== "off")) {
  console.error("usage: node run.mjs <bench.wasm> [--reps 15] [--check-only] [--expect-simd on|off]");
  process.exit(2);
}

const bytes = readFileSync(wasmPath);
const module = new WebAssembly.Module(bytes);
// The module is self-contained. Its imports are wasm-bindgen
// placeholders that the engine crate's dependencies leave in the module
// and that nothing here calls; each one throws if it ever is.
const imports = {};
for (const { module: m, name } of WebAssembly.Module.imports(module)) {
  (imports[m] ??= {})[name] = () => {
    throw new Error(`unexpected call to import ${m}.${name}`);
  };
}
const wasm = new WebAssembly.Instance(module, imports).exports;

const simd = wasm.simd128() === 1;
if (expectSimd !== null && simd !== (expectSimd === "on")) {
  console.error(`${wasmPath}: simd128 is ${simd ? "on" : "off"}, expected ${expectSimd}`);
  process.exit(1);
}
if (wasm.selfcheck() !== 1) {
  console.error(`${wasmPath}: self-check failed: this build's parity bytes differ from the pinned fingerprint`);
  process.exit(1);
}
console.log(`${wasmPath}: ${bytes.length} bytes, simd128 ${simd ? "on" : "off"}, self-check ok`);
if (checkOnly) process.exit(0);

const median = (xs) => [...xs].sort((a, b) => a - b)[xs.length >> 1];
const time = (run, want) => {
  // Every call must return the expected byte count: the warm-up and each
  // timed one. The result is compared outside the timed span.
  if (run() !== want) throw new Error("benchmark step failed");
  const times = [];
  for (let i = 0; i < reps; i++) {
    const t0 = performance.now();
    const got = run();
    times.push(performance.now() - t0);
    if (got !== want) throw new Error("benchmark step failed");
  }
  return median(times);
};

// (extent MiB, parity shards): the configured geometries.
const FIRST = 721120;
const NEXT = 721072;
console.log(`median of ${reps}; elapsed ms per MiB of extent plaintext (ms per call)`);
for (const [mib, m] of [[8, 2], [16, 3], [16, 4]]) {
  const k = wasm.setup(mib * 1048576, m);
  if (k === 0) throw new Error("setup failed");
  const label = `${mib} MiB (${k}+${m})`;
  const enc = time(() => wasm.bench_encode(), m * FIRST);
  console.log(`${label.padEnd(16)} encode ${m} rows`.padEnd(40) + `${(enc / mib).toFixed(3)}  (${enc.toFixed(2)})`);
  for (let t = 1; t <= m; t++) {
    const dec = time(() => wasm.bench_decode(t), FIRST + (t - 1) * NEXT);
    console.log(`${label.padEnd(16)} rebuild ${t} lost`.padEnd(40) + `${(dec / mib).toFixed(3)}  (${dec.toFixed(2)})`);
  }
}
