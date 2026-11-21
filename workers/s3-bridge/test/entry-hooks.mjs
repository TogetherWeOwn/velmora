// Module hooks for entry.test.mjs: `cloudflare:workers` and the generated
// Rust Worker (build/index.js) resolve to stubs, so entry.mjs is tested
// without a build and without the runtime.
const STUBS = {
  "cloudflare:workers": new URL("./stub-workers.mjs", import.meta.url).href,
  "./build/index.js": new URL("./stub-bridge.mjs", import.meta.url).href,
};

export async function resolve(specifier, context, next) {
  if (specifier in STUBS && (specifier !== "./build/index.js" || context.parentURL?.endsWith("/entry.mjs"))) {
    return { url: STUBS[specifier], shortCircuit: true };
  }
  return next(specifier, context);
}
