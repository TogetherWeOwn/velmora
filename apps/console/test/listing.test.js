// Regression: "Load more" kept appending duplicates. After the last page
// the button stayed visible (a class's display beat `hidden`), and a click
// with no token fetched page 1 again and appended it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { emptyListing, mergePage, takeMoreToken } from "../public/listing.js";

const page = (n, last) => ({
  folders: [`d-${n}/`],
  files: [{ key: `f-${n}.txt` }],
  truncated: !last,
  next: last ? null : `t${n + 1}`,
});

test("three pages load once each; nothing can be loaded past the last", () => {
  const l = emptyListing();
  mergePage(l, page(0), { more: false, prefix: "" });
  for (let n = 1; n <= 2; n++) {
    const token = takeMoreToken(l);
    assert.equal(token, `t${n}`);
    mergePage(l, page(n, n === 2), { more: true, prefix: "" });
  }
  assert.equal(l.next, null);
  assert.equal(takeMoreToken(l), null); // never a tokenless request (= page 1 again)
  assert.deepEqual(l.files.map((f) => f.key), ["f-0.txt", "f-1.txt", "f-2.txt"]);
});

test("a token is handed out once (double click / click while in flight)", () => {
  const l = emptyListing();
  mergePage(l, page(0), { more: false, prefix: "" });
  assert.equal(takeMoreToken(l), "t1");
  assert.equal(takeMoreToken(l), null);
});

test("a page delivered twice adds no duplicate rows", () => {
  const l = emptyListing();
  mergePage(l, page(0), { more: false, prefix: "" });
  mergePage(l, page(0), { more: true, prefix: "" });
  mergePage(l, { ...page(1), files: [{ key: "f-0.txt" }, { key: "f-1.txt" }] }, { more: true, prefix: "" });
  assert.deepEqual(l.files.map((f) => f.key), ["f-0.txt", "f-1.txt"]);
  assert.deepEqual(l.folders, ["d-0/", "d-1/"]);
});

test("a first page starts afresh, including the used tokens", () => {
  const l = emptyListing();
  mergePage(l, page(0), { more: false, prefix: "" });
  takeMoreToken(l);
  mergePage(l, page(0), { more: false, prefix: "" });
  assert.equal(l.files.length, 1);
  assert.equal(takeMoreToken(l), "t1");
});

test("the folder's own marker is not a row", () => {
  const l = emptyListing();
  mergePage(l, { folders: [], files: [{ key: "a/" }, { key: "a/x" }], truncated: false }, { more: false, prefix: "a/" });
  assert.deepEqual(l.files.map((f) => f.key), ["a/x"]);
});

test("a truncated page without a token offers no Load more", () => {
  const l = emptyListing();
  mergePage(l, { folders: [], files: [], truncated: true, next: null }, { more: false, prefix: "" });
  assert.equal(takeMoreToken(l), null);
});

test("[hidden] always hides, whatever a class sets", () => {
  const css = readFileSync(new URL("../public/app.css", import.meta.url), "utf8");
  assert.match(css, /\[hidden\]\s*\{\s*display:\s*none\s*!important;?\s*\}/);
});
