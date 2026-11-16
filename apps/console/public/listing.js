// Paging of one folder listing, kept free of the DOM so it can be tested.
//
// `listing` holds { folders, files, next, used }: the rows shown so far,
// the continuation token of the next page (null when there is none), and
// the tokens already sent for this folder.

export function emptyListing() {
  return { folders: [], files: [], next: null, used: new Set() };
}

/**
 * The token for a "Load more", or null when nothing may be requested: no
 * next page, or that token was sent already. A "Load more" never asks
 * for the first page again.
 */
export function takeMoreToken(listing) {
  const token = listing.next;
  if (!token || listing.used.has(token)) return null;
  listing.used.add(token);
  return token;
}

/** Adds one page; rows stay unique by key. A first page starts afresh. */
export function mergePage(listing, out, { more, prefix }) {
  if (!more) {
    listing.folders = [];
    listing.files = [];
    listing.used = new Set();
  }
  const folders = new Set(listing.folders);
  for (const p of out.folders) {
    if (!folders.has(p)) {
      folders.add(p);
      listing.folders.push(p);
    }
  }
  const keys = new Set(listing.files.map((f) => f.key));
  for (const f of out.files) {
    // The folder's own marker object is not listed as a file in it.
    if (f.key === prefix || keys.has(f.key)) continue;
    keys.add(f.key);
    listing.files.push(f);
  }
  listing.next = out.truncated && out.next ? out.next : null;
  // A token that was sent already would only repeat a page: no Load more.
  if (listing.next && listing.used.has(listing.next)) listing.next = null;
}

/** After a failed "Load more", its token may be tried again. */
export function releaseToken(listing, token) {
  listing.used.delete(token);
}
