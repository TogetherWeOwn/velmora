// Stand-in for the generated Rust Worker: records what it was handed.
// Like the real one it exports classes only; the record is a global.
import { WorkerEntrypoint } from "cloudflare:workers";

const calls = (globalThis.__entryCalls ??= []);

export default class extends WorkerEntrypoint {
  fetch(request) {
    calls.push({ event: "fetch", request, ctx: this.ctx, env: this.env });
    return "fetched";
  }
  queue(batch) {
    calls.push({ event: "queue", batch, ctx: this.ctx, env: this.env });
    return "queued";
  }
  scheduled(controller) {
    calls.push({ event: "scheduled", controller, ctx: this.ctx, env: this.env });
    return "scheduled";
  }
}

export class PermitGate {}
