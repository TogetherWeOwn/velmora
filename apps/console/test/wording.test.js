// What the console shows is worded for the person storing files: where
// the archive copy lives is not their concern and is not named.

import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { test } from "node:test";

const PUBLIC = new URL("../public/", import.meta.url);

test("the pages name no storage network", async () => {
  for (const name of await readdir(PUBLIC)) {
    const text = await readFile(new URL(name, PUBLIC), "utf8");
    assert.doesNotMatch(text, /usenet|nntp|newsgroup|newsreader/i, name);
    // Field names of the admin API are read; they are never shown as text.
    for (const quoted of text.match(/"[^"\n]*"/g) || []) {
      assert.doesNotMatch(quoted, /\b(providers?|backbones?)\b/i, `${name}: ${quoted}`);
    }
  }
});

test("a fully stored object is labelled without naming the archive", async () => {
  const app = await readFile(new URL("app.js", PUBLIC), "utf8");
  assert.match(app, /\["stored \(archived \+ cached\)", "good"\]/);
});
