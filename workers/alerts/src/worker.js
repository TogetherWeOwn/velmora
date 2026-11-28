import { WorkerEntrypoint } from "cloudflare:workers";
import { ingestMail } from "./index.js";

export { default } from "./index.js";

// Cloudflare invokes this named entrypoint only through a service binding.
// The public default handler always uses the bearer-protected host/CI path.
export class MailAlerts extends WorkerEntrypoint {
  fetch(request) {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/v1/alert") {
      return new Response("not found\n", { status: 404 });
    }
    return ingestMail(request, this.env, Date.now(), this.ctx);
  }
}
