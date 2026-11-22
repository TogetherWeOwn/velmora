// Entry module of the velmora-s3 Worker (wrangler.toml `main`).
//
// The Rust Worker that worker-build generates (build/index.js) is used as
// it is. This module adds what Rust cannot declare: a second, named
// entrypoint for the WebDAV gateway.
//
// - `default`: every request from the Internet, and the Worker's binding
//   to itself (SELF), comes in here. It deletes the entry marker header,
//   so no client can claim another entry point, and hands the request to
//   the Rust Worker unchanged otherwise. A request without the header
//   (every honest one) is passed on as the very same object, so nothing
//   the runtime attached to it (`request.cf`) is lost.
// - `DavEntry`: has no route, no custom domain and no workers.dev URL; it
//   is reached only through a service binding that names it
//   (`entrypoint = "DavEntry"`), which only the WebDAV gateway has. It
//   sets the marker to `webdav`.
// - `MgmtEntry`: the storage management plane (`/v1`), the same way: no
//   route, no custom domain, no workers.dev URL, reached only through a
//   service binding that names it, which only `kofra-api` has. It sets
//   the marker to `mgmt`; the Rust Worker then serves the request with
//   the management plane and never with the S3 handler.
//
// The Rust side (crates/velmora-bridge/src/entry.rs) admits app passwords
// only with the marker, and S3 keys only without it, and counts the
// marker only on a request that carries no header the edge adds.
//
// This module exports entrypoints and the Rust Worker's classes only: the
// runtime takes every export of the main module for an entrypoint (a
// constant here stops the Worker from starting).

import { WorkerEntrypoint } from "cloudflare:workers";
import Bridge from "./build/index.js";
import { marked, MGMT, WEBDAV } from "./entry-marker.mjs";

// Durable Object classes and the other named exports of the Rust Worker.
export * from "./build/index.js";

export default class extends WorkerEntrypoint {
  fetch(request) {
    return new Bridge(this.ctx, this.env).fetch(marked(request, null));
  }

  queue(batch) {
    return new Bridge(this.ctx, this.env).queue(batch);
  }

  scheduled(controller) {
    return new Bridge(this.ctx, this.env).scheduled(controller);
  }
}

export class DavEntry extends WorkerEntrypoint {
  fetch(request) {
    return new Bridge(this.ctx, this.env).fetch(marked(request, WEBDAV));
  }
}

export class MgmtEntry extends WorkerEntrypoint {
  fetch(request) {
    return new Bridge(this.ctx, this.env).fetch(marked(request, MGMT));
  }
}
