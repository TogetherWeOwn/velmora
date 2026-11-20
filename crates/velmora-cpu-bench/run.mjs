#!/usr/bin/env node
// Times the stages of velmora-cpu-bench.wasm under node (V8).
//
//   node run.mjs <bench.wasm> [--mib 16] [--reps 7] [--json out.json] [--unchecked]
//                [--expect-simd on|off] [--check-only]
//
// --expect-simd fails unless the module's simd128 state is the one named;
// --check-only stops after the self-check (no timing).
//
// Prints CPU milliseconds per MiB of object data for each stage: the
// median of `reps` runs after one warm-up run. The module is single
// threaded and does no I/O, so wall time is CPU time.
import { readFileSync, writeFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const at = args.indexOf(name);
  return at < 0 ? fallback : args.splice(at, 2)[1];
};
const mib = Number(flag("--mib", "16"));
const reps = Number(flag("--reps", "7"));
const jsonOut = flag("--json", null);
const expectSimd = flag("--expect-simd", null);
if (expectSimd !== null && expectSimd !== "on" && expectSimd !== "off") {
  console.error("--expect-simd takes on or off");
  process.exit(2);
}
const checkOnly = args.includes("--check-only") && args.splice(args.indexOf("--check-only"), 1).length > 0;
const unchecked = args.includes("--unchecked") && args.splice(args.indexOf("--unchecked"), 1).length > 0;
const wasmPath = args[0];
if (!wasmPath) {
  console.error("usage: node run.mjs <bench.wasm> [--mib 16] [--reps 7] [--json out.json] [--unchecked]");
  process.exit(2);
}

const bytes = readFileSync(wasmPath);
const module = new WebAssembly.Module(bytes);
// The module is self-contained. Any import is a function nothing here
// calls (the system RNG of the engine crate); it traps if it ever is.
const imports = {};
for (const { module: m, name } of WebAssembly.Module.imports(module)) {
  (imports[m] ??= {})[name] = () => {
    throw new Error(`unexpected call to import ${m}.${name}`);
  };
}
const wasm = new WebAssembly.Instance(module, imports).exports;

// Refuse to time a build whose outputs differ from the pinned ones.
// `--unchecked` times a module built from a tree older than the
// self-check (the "before" side of a comparison).
if (unchecked && !wasm.selfcheck) {
  console.error(`${wasmPath}: no self-check in this module; timing it unchecked`);
} else if (wasm.selfcheck() !== 1) {
  console.error(`${wasmPath}: self-check failed: this build's output bytes differ from the pinned fingerprint`);
  process.exit(1);
}
const simd = wasm.simd128?.() === 1;
if (expectSimd !== null && simd !== (expectSimd === "on")) {
  console.error(`${wasmPath}: simd128 is ${simd ? "on" : "off"}, expected ${expectSimd}`);
  process.exit(1);
}
if (checkOnly) {
  console.log(`${wasmPath}: ${bytes.length} bytes, simd128 ${simd ? "on" : "off"}, self-check ok`);
  process.exit(0);
}

const articles = wasm.setup(mib * 1048576);

// Socket chunk sizes for the stages that read from the transport: the
// size of the pieces the runtime hands over.
const CHUNKS = [4096, 65536];
const stages = [
  ["ingest", "seal + MD5 + 2x SHA-256 (seal_extent)", () => wasm.ingest()],
  ["post", "whole post stage", () => wasm.post(65536)],
  ["post.load_check", "SHA-256 of the loaded ciphertext", () => wasm.post_load_check()],
  ["post.payload_check", "SHA-256 of each article payload", () => wasm.post_payload_check()],
  ["post.render", "yEnc encode + CRC-32 + assemble", () => wasm.post_render()],
  ["post.send", "framing check + dot-stuffing + write", () => wasm.post_send(65536)],
  ...CHUNKS.flatMap((c) => [
    [`verify@${c}`, `whole verify, ${c}-byte socket chunks`, () => wasm.verify(c)],
    [`verify.read@${c}`, "BODY: socket hand-over + framing + unstuffing", () => wasm.verify_read(c)],
  ]),
  ["verify.check", "yEnc decode + CRC-32 + SHA-256", () => wasm.verify_check()],
  ...CHUNKS.map((c) => [`cold@${c}`, `whole cold read, ${c}-byte socket chunks`, () => wasm.cold(c)]),
  ["cold.open", "decrypt (open_range); also a read from the cache", () => wasm.cold_open()],
];

const median = (xs) => [...xs].sort((a, b) => a - b)[xs.length >> 1];
const results = {};
console.log(`${wasmPath}: ${bytes.length} bytes, simd128 ${simd ? "on" : "off"}, self-check ok; ${mib} MiB extent, ${articles} articles; median of ${reps}`);
console.log("stage".padEnd(22) + "ms/MiB".padStart(8) + "   what");
for (const [name, what, run] of stages) {
  run();
  const times = [];
  for (let i = 0; i < reps; i++) {
    const t0 = performance.now();
    run();
    times.push(performance.now() - t0);
  }
  const perMib = median(times) / mib;
  results[name] = Number(perMib.toFixed(3));
  console.log(name.padEnd(22) + perMib.toFixed(2).padStart(8) + "   " + what);
}
if (jsonOut) {
  writeFileSync(jsonOut, JSON.stringify({ wasm_bytes: bytes.length, simd128: simd, mib, articles, reps, ms_per_mib: results }, null, 2) + "\n");
}
