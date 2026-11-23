// Run after building the Worker: node tools/test_queue_metrics.mjs (Node 24).
// Load the actual Wasm/JS queue export with local binding doubles. No I/O to
// Cloudflare or any provider is possible: the sockets stub always throws.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';

const hooks = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'cloudflare:workers') {
      return { url: 'data:text/javascript,export class WorkerEntrypoint { constructor(ctx,env){this.ctx=ctx;this.env=env} }', shortCircuit: true };
    }
    if (specifier === 'cloudflare:sockets') {
      return { url: 'data:text/javascript,export function connect(){throw Error("unexpected socket")}', shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.endsWith('/build/index_bg.wasm')) {
      const bytes = readFileSync(new URL(url)).toString('base64');
      return { format: 'module', source: `export default new WebAssembly.Module(Buffer.from('${bytes}', 'base64'))`, shortCircuit: true };
    }
    return nextLoad(url, context);
  },
});
globalThis.addEventListener = () => {};
const { default: Worker } = await import('../build/index.js');
hooks.deregister();

class D1Database {}
class R2Bucket {}
class WorkerQueue {
  async send() { throw Error('local queue is unavailable'); }
}
const env = {
  ENVIRONMENT: 'dev', S3_HOST: 'localhost', S3_REGION: 'auto',
  MAX_EXTENT_BYTES: '16777216', REQUIRED_BACKBONES: '1', SAFETY_MIN_AGE_SECS: '0',
  VERIFY_DELAY_SECS: '1', NEWSGROUPS: 'alt.binaries.test', VELMORA_KEK_ACTIVE: '1',
  INFLIGHT_BUDGET_BYTES: '50331648', GC_MODE: 'disposable', MAINTENANCE: 'off',
  SERVER_SIDE_COPY: 'on', VELMORA_KEK_1: Buffer.alloc(32).toString('base64'),
  ADMIN_TOKEN: 'synthetic-token-not-for-use'.repeat(2), PERMITS: 'd1',
  NNTP_PROVIDERS: JSON.stringify([{ id: 'p1', host: '127.0.0.1', port: 1, user: 'test', pass: 'test', tls: false, backbone: 'test', post: true, read: true, max_conns: 2 }]),
  CATALOG: new D1Database(), SAFETY: new R2Bucket(), CACHE: new R2Bucket(),
  POST_Q: new WorkerQueue(), VERIFY_Q: new WorkerQueue(),
  METRICS: { writeDataPoint() { assert.fail('early or invalid jobs must not emit points'); } },
};
const entry = new Worker({}, env);

async function settle(queue, expectedMetadataReads) {
  let reads = 0;
  const messages = [];
  const actions = [];
  const message = (body) => ({
    body,
    get id() { assert.fail('job observation must not read the message ID'); },
    ack() { actions.push('ack'); },
    retry({ delaySeconds }) { assert.ok(delaySeconds >= 1); actions.push('retry'); },
  });
  messages.push(message({ t: 'invalid' }));
  messages.push(message({ t: 'wake', v: 1, stage: 'post', extent: 'x_test', generation: 'g_test', at: Date.now() + 60_000 }));
  await entry.queue({ messages, get queue() { reads++; return queue(); } });
  assert.deepEqual(actions, ['ack', 'retry']);
  assert.equal(reads, expectedMetadataReads);
}

env.JOB_METRICS_SAMPLE = '1';
await settle(() => { throw Error('throwing queue metadata getter'); }, 1);
await settle(() => undefined, 1);
await settle(() => 42, 1);
await settle(() => 'velmora-post', 1);
env.JOB_METRICS_SAMPLE = 0;
await settle(() => 'velmora-post', 0);
env.JOB_METRICS_SAMPLE = undefined;
await settle(() => 'velmora-post', 0);
delete env.JOB_METRICS_SAMPLE;
await settle(() => 'velmora-post', 1);
console.log('queue metadata Wasm smoke test passed');
