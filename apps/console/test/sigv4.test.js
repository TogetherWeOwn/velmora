// SigV4 against the worked examples of the AWS S3 documentation
// ("Signature Calculations for the Authorization Header").

import { test } from "node:test";
import assert from "node:assert/strict";
import { EMPTY_SHA256, canonicalQuery, encodeKey, sha256Hex, sign } from "../src/sigv4.js";

const base = {
  host: "examplebucket.s3.amazonaws.com",
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  region: "us-east-1",
  now: Date.UTC(2013, 4, 24, 0, 0, 0),
};

test("GET object with Range", async () => {
  const s = await sign({ ...base, method: "GET", path: "/test.txt", headers: { range: "bytes=0-9" }, payloadHash: EMPTY_SHA256 });
  assert.equal(s.signature, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
  assert.match(s.headers.authorization, /SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,/);
  assert.equal(s.headers.authorization.startsWith("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"), true);
});

test("PUT object (key needs encoding, extra x-amz header)", async () => {
  const s = await sign({
    ...base,
    method: "PUT",
    path: "/" + encodeKey("test$file.text"),
    headers: { date: "Fri, 24 May 2013 00:00:00 GMT", "x-amz-storage-class": "REDUCED_REDUNDANCY" },
    payloadHash: await sha256Hex("Welcome to Amazon S3."),
  });
  assert.equal(s.signature, "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd");
});

test("GET bucket lifecycle (empty-valued sub-resource)", async () => {
  const s = await sign({ ...base, method: "GET", path: "/", query: [["lifecycle", ""]], payloadHash: EMPTY_SHA256 });
  assert.equal(s.signature, "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543");
});

test("GET bucket list (sorted query)", async () => {
  const s = await sign({
    ...base,
    method: "GET",
    path: "/",
    query: [["prefix", "J"], ["max-keys", "2"]],
    payloadHash: EMPTY_SHA256,
  });
  assert.equal(s.signature, "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7");
});

test("key and query encoding follow RFC 3986", () => {
  assert.equal(encodeKey("a b/c+d/ü/(x)*!'~._-"), "a%20b/c%2Bd/%C3%BC/%28x%29%2A%21%27~._-");
  assert.equal(canonicalQuery([["b", "2"], ["a", "x y"], ["a", "/"]]), "a=%2F&a=x%20y&b=2");
});
