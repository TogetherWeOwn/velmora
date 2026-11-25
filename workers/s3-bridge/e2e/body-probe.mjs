// Local slice entrypoint only. Observe the same reader and allocation that
// the generated Worker uses; the shipped entrypoint never imports this file.
import Bridge from "../entry.mjs";
export * from "../entry.mjs";

export default class extends Bridge {
  async fetch(request) {
    const mode = request.headers.get("x-e2e-byob");
    if (!mode) return super.fetch(request);

    if (mode === "disconnect") {
      const kind = new URL(request.url).searchParams.has("uploadId") ? "part" : "object";
      tapReader(request.body, {
        read(view) {
          if (view.byteOffset > 0) console.log(`BYOB probe: ${kind} fill pending`);
        },
        cancel() {
          console.log(`BYOB probe: ${kind} reader cancelled`);
        },
      });
      const result = super.fetch(request);
      // Keep observing the upload after the HTTP client closes its socket.
      this.ctx.waitUntil(result.then(
        (response) => console.log(`BYOB probe: ${kind} finished HTTP ${response.status}`),
        () => console.log(`BYOB probe: ${kind} rejected`),
      ));
      return result;
    }

    // HTTP framing cannot carry more bytes than its Content-Length in the
    // same request. Construct a workerd byte stream to exercise that case
    // independently of HTTP framing, and the no-Content-Length Copy probe.
    const size = Number(request.headers.get("x-e2e-byob-size"));
    const payload = request.headers.get("x-e2e-byob-payload");
    const bytes = payload ? Uint8Array.from(atob(payload), (c) => c.charCodeAt(0)) : new Uint8Array(size);
    const body = new ReadableStream({
      type: "bytes",
      start(controller) {
        if (bytes.length) controller.enqueue(bytes);
        controller.close();
      },
    });
    const headers = new Headers(request.headers);
    const declared = request.headers.get("x-e2e-byob-length");
    if (declared === null) headers.delete("content-length");
    else headers.set("content-length", declared);
    const probe = new Request(request.url, { method: request.method, headers, body });

    const NativeBuffer = globalThis.ArrayBuffer;
    const allocations = [];
    let firstRead;
    tapReader(probe.body, {
      read(view) {
        firstRead ??= { allocations: allocations.slice(), cap: view.byteLength };
      },
    });
    globalThis.ArrayBuffer = new Proxy(NativeBuffer, {
      construct(target, args) {
        const buffer = Reflect.construct(target, args);
        allocations.push(buffer.byteLength);
        return buffer;
      },
    });
    try {
      const response = await super.fetch(probe);
      const report = { allocations, firstRead: firstRead ?? null };
      const output = new Response(response.body, response);
      output.headers.set("x-e2e-byob-observed", JSON.stringify(report));
      return output;
    } finally {
      globalThis.ArrayBuffer = NativeBuffer;
    }
  }
}

function tapReader(stream, hooks) {
  const getReader = stream.getReader;
  stream.getReader = function (options) {
    const reader = getReader.call(this, options);
    if (options?.mode !== "byob") return reader;
    const read = reader.read;
    const cancel = reader.cancel;
    reader.read = function (view) {
      hooks.read?.(view);
      return read.call(this, view);
    };
    reader.cancel = function () {
      const result = cancel.call(this);
      hooks.cancel?.();
      return result;
    };
    return reader;
  };
}
