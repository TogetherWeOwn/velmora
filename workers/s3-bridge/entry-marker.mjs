// The entry marker of entry.mjs, in a module of its own: the runtime
// takes every export of the main module for an entrypoint, so the main
// module exports handlers and classes only.

// Must equal velmora_bridge::entry::ENTRY_HEADER, WEBDAV and MGMT.
export const ENTRY_HEADER = "x-velmora-entry";
export const WEBDAV = "webdav";
export const MGMT = "mgmt";

/** The request with the marker removed, or set to `value`. */
export function marked(request, value) {
  if (value === null && !request.headers.has(ENTRY_HEADER)) {
    return request;
  }
  const headers = new Headers(request.headers);
  headers.delete(ENTRY_HEADER);
  if (value !== null) {
    headers.set(ENTRY_HEADER, value);
  }
  return new Request(request, { headers });
}
