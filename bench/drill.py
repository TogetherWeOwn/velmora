#!/usr/bin/env python3
"""drill.py: layer 2 of the benchmark, the client side. Times S3 calls
against a deployed Worker (or any S3 endpoint) and prints one JSON object
per measurement.

    drill.py <command> --base URL --bucket NAME [options]

Commands:
  mpu    --key K --size BYTES [--part BYTES] [--concurrency N]
         one multipart upload of random bytes; MiB/s from the first byte
         sent to the Complete answer. The bytes are written to a temporary
         file first (not timed), so at most N parts are in memory
  many   --prefix P --count N --size BYTES [--concurrency N]
         N PutObject calls of random bytes, N at a time; MiB/s over all
  get    --key K [--range START-END] [--sha256 HEX]
         TTFB (request sent to response headers), total, MiB/s over the
         total (request sent to last byte, as in every earlier run), SHA-256
         of the body (compared when --sha256 is given). A body shorter than
         its Content-Length is a broken connection and is tried again; the
         timings are then the last attempt's, so a line with retries > 0
         is not comparable (a cold read may have filled the cache)
  list   --prefix P [--max-keys N]
         latency of each page of ListObjectsV2 until the prefix ends
  evict  --key K          POST /_admin/evict/<bucket>/<key>?include_safety=1;
                          exit 3 when a safety copy was kept (safety_kept > 0):
                          a read after it would not come from Usenet only
  status --key K          GET /_admin/objects/<bucket>/<key>

Credentials: the [default] profile of AWS_SHARED_CREDENTIALS_FILE; the admin
bearer as a header line in the file named by VELMORA_ADMIN_HEADER_FILE
("Authorization: Bearer ..."). Neither is ever printed. Concurrency
defaults to 4, rclone's default (--transfers, --s3-upload-concurrency).
Standard library only.
"""
import argparse
import configparser
import datetime
import hashlib
import hmac
import http.client
import json
import os
import ssl
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

MIB = 1024 * 1024
REGION = os.environ.get("AWS_DEFAULT_REGION", "auto")


def creds():
    c = configparser.ConfigParser(interpolation=None)
    c.read(os.environ["AWS_SHARED_CREDENTIALS_FILE"])
    try:
        return c["default"]["aws_access_key_id"], c["default"]["aws_secret_access_key"]
    except KeyError:
        sys.exit("credentials file unreadable")


def sign(method, host, path, query, payload_sha, extra=None):
    akid, secret = creds()
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    q = sorted((urllib.parse.quote(k, safe="-_.~"), urllib.parse.quote(v, safe="-_.~")) for k, v in query)
    cq = "&".join(f"{k}={v}" for k, v in q)
    h = {"host": host, "x-amz-content-sha256": payload_sha, "x-amz-date": stamp}
    for k, v in (extra or {}).items():
        h[k.lower()] = v
    names = ";".join(sorted(h))
    canon = "\n".join([method, path, cq, "".join(f"{k}:{h[k].strip()}\n" for k in sorted(h)), names, payload_sha])
    scope = f"{day}/{REGION}/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canon.encode()).hexdigest()])
    key = ("AWS4" + secret).encode()
    for part in (day, REGION, "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    h["authorization"] = f"AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders={names}, Signature={sig}"
    return (path + ("?" + cq if cq else "")), h


class Client:
    """One keep-alive connection per thread."""

    def __init__(self, base, bucket):
        u = urllib.parse.urlsplit(base)
        self.https = u.scheme == "https"
        self.host = u.netloc
        self.bucket = bucket
        self.local = threading.local()
        self.lock = threading.Lock()
        self.retries = 0
        self.errors = {}

    def conn(self, fresh=False):
        c = getattr(self.local, "c", None)
        if c is None or fresh:
            if c is not None:
                c.close()
            c = (http.client.HTTPSConnection(self.host, timeout=900, context=ssl.create_default_context())
                 if self.https else http.client.HTTPConnection(self.host, timeout=900))
            self.local.c = c
        return c

    def call(self, method, key, query=(), body=b"", extra=None, stream=None):
        """One S3 call. A 5xx, a 429 or a broken connection is tried again
        (4 tries in all, pauses of 1, 2 and 4 s), as SDK clients do; every
        retry is counted in `self.retries` and the statuses in `self.errors`."""
        path = "/" + self.bucket + ("/" + urllib.parse.quote(key, safe="/-_.~") if key else "")
        sha = hashlib.sha256(body).hexdigest()
        for attempt in range(4):
            if attempt:
                with self.lock:
                    self.retries += 1
                time.sleep(2 ** (attempt - 1))
            target, headers = sign(method, self.host, path, list(query), sha, extra)
            if body or method == "PUT":
                headers["content-length"] = str(len(body))
            c = self.conn(fresh=attempt > 0)
            try:
                t0 = time.monotonic()
                c.request(method, target, body=body or None, headers=headers)
                r = c.getresponse()
                ttfb = time.monotonic() - t0
                if r.status >= 500 or r.status == 429:
                    r.read()
                    with self.lock:
                        self.errors[str(r.status)] = self.errors.get(str(r.status), 0) + 1
                    if attempt < 3:
                        continue
                if stream and r.status < 300:
                    n = stream(r)
                    data = b""
                else:
                    data = r.read()
                    n = len(data)
                return r.status, r.getheader("etag"), data, ttfb, time.monotonic() - t0, n
            except (http.client.HTTPException, ConnectionError, ssl.SSLError, TimeoutError) as e:
                with self.lock:
                    self.errors[type(e).__name__] = self.errors.get(type(e).__name__, 0) + 1
                if attempt == 3:
                    raise


def admin(base, method, path):
    """One admin call; a broken connection or a 5xx is tried again (4 tries, 2/4/8 s apart)."""
    line = open(os.environ["VELMORA_ADMIN_HEADER_FILE"]).read().strip()
    name, value = line.split(": ", 1)
    u = urllib.parse.urlsplit(base)
    for attempt in range(4):
        if attempt:
            time.sleep(2 ** attempt)
        c = (http.client.HTTPSConnection(u.netloc, timeout=900) if u.scheme == "https"
             else http.client.HTTPConnection(u.netloc, timeout=900))
        t0 = time.monotonic()
        try:
            c.request(method, "/_admin" + path, headers={name: value, "user-agent": "velmora-bench"})
            r = c.getresponse()
            body = r.read()
        except (http.client.HTTPException, ConnectionError, ssl.SSLError, TimeoutError):
            if attempt == 3:
                raise
            continue
        if r.status < 500 or attempt == 3:
            return r.status, body, time.monotonic() - t0


CLIENT = None


def emit(**kv):
    if CLIENT is not None:
        kv["retries"], kv["errors"] = CLIENT.retries, dict(CLIENT.errors)
    kv.setdefault("at", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    print(json.dumps(kv), flush=True)


def cmd_mpu(a, cl):
    nparts = -(-a.size // a.part)
    whole = hashlib.sha256()
    # The object goes to a temporary file first, one part at a time, so a
    # large upload holds at most `concurrency` parts in memory. It is
    # written before the upload is created: a full disk leaves no upload
    # open. Each part is read back (page cache) before its timer starts.
    spool = tempfile.TemporaryFile()
    for i in range(nparts):
        p = os.urandom(min(a.part, a.size - i * a.part))
        whole.update(p)
        spool.write(p)
    spool.flush()
    fd = spool.fileno()

    def part(i):
        want, off, out = min(a.part, a.size - i * a.part), i * a.part, bytearray()
        while len(out) < want:
            chunk = os.pread(fd, want - len(out), off + len(out))
            if not chunk:
                raise RuntimeError(f"part {i + 1}: the spool file ended at {off + len(out)}")
            out += chunk
        return bytes(out)

    st, _, data, _, _, _ = cl.call("POST", a.key, [("uploads", "")])
    if st != 200:
        sys.exit(f"CreateMultipartUpload: {st} {data[:300]!r}")
    upload = data.split(b"<UploadId>")[1].split(b"</UploadId>")[0].decode()
    etags = [None] * nparts
    lat = [0.0] * nparts

    def up(i):
        body = part(i)
        t = time.monotonic()
        s, etag, d, _, _, _ = cl.call("PUT", a.key, [("partNumber", str(i + 1)), ("uploadId", upload)], body)
        if s != 200:
            raise RuntimeError(f"UploadPart {i + 1}: {s} {d[:300]!r}")
        etags[i], lat[i] = etag, time.monotonic() - t

    t0 = time.monotonic()
    with ThreadPoolExecutor(a.concurrency) as ex:
        list(ex.map(up, range(nparts)))
    t_parts = time.monotonic() - t0
    spool.close()
    xml = "<CompleteMultipartUpload>" + "".join(
        f"<Part><PartNumber>{i + 1}</PartNumber><ETag>{e}</ETag></Part>" for i, e in enumerate(etags)) + "</CompleteMultipartUpload>"
    tc = time.monotonic()
    s, _, d, _, _, _ = cl.call("POST", a.key, [("uploadId", upload)], xml.encode(), {"content-type": "application/xml"})
    if s != 200 or b"<Error>" in d:
        sys.exit(f"CompleteMultipartUpload: {s} {d[:300]!r}")
    total = time.monotonic() - t0
    lat.sort()
    emit(metric="ingest_mpu", key=a.key, bytes=a.size, parts=nparts, part_bytes=a.part, concurrency=a.concurrency,
         seconds=round(total, 3), mib_s=round(a.size / MIB / total, 2), parts_seconds=round(t_parts, 3),
         complete_seconds=round(time.monotonic() - tc, 3), part_p50_s=round(lat[len(lat) // 2], 3),
         part_max_s=round(lat[-1], 3), sha256=whole.hexdigest())


def cmd_many(a, cl):
    lat = []
    lock = threading.Lock()

    def put(i):
        body = os.urandom(a.size)
        t = time.monotonic()
        s, _, d, _, _, _ = cl.call("PUT", f"{a.prefix}{i:05d}", body=body)
        if s != 200:
            raise RuntimeError(f"PutObject {i}: {s} {d[:300]!r}")
        with lock:
            lat.append(time.monotonic() - t)

    t0 = time.monotonic()
    with ThreadPoolExecutor(a.concurrency) as ex:
        list(ex.map(put, range(a.count)))
    total = time.monotonic() - t0
    lat.sort()
    emit(metric="ingest_many", prefix=a.prefix, count=a.count, bytes_each=a.size, concurrency=a.concurrency,
         seconds=round(total, 3), mib_s=round(a.count * a.size / MIB / total, 2), objects_s=round(a.count / total, 2),
         put_p50_s=round(lat[len(lat) // 2], 3), put_p95_s=round(lat[int(len(lat) * 0.95)], 3))


def cmd_get(a, cl):
    extra = {}
    if a.range:
        s, e = a.range.split("-")
        extra["range"] = f"bytes={s}-{e}"
    h = hashlib.sha256()

    def drain(r):
        # http.client returns EOF, not an error, when the connection ends
        # before Content-Length: count the bytes and raise, so the call is
        # tried again from the start (with a fresh hash).
        nonlocal h
        h = hashlib.sha256()
        want = r.getheader("content-length")
        n = 0
        while True:
            chunk = r.read(MIB)
            if not chunk:
                break
            h.update(chunk)
            n += len(chunk)
        if want is not None and n != int(want):
            raise http.client.IncompleteRead(b"", int(want) - n)
        return n

    st, _, _, ttfb, total, n = cl.call("GET", a.key, extra=extra, stream=drain)
    ok = st in (200, 206) and (not a.sha256 or a.sha256 == h.hexdigest())
    emit(metric="get", key=a.key, range=a.range, status=st, bytes=n, ttfb_s=round(ttfb, 3), seconds=round(total, 3),
         mib_s=round(n / MIB / total, 2) if total else None, sha256=h.hexdigest(), match=ok if a.sha256 else None)
    if not ok:
        sys.exit(2)


def cmd_list(a, cl):
    token, pages, keys, lat = None, 0, 0, []
    while True:
        q = [("list-type", "2"), ("prefix", a.prefix), ("max-keys", str(a.max_keys))]
        if token:
            q.append(("continuation-token", token))
        st, _, d, ttfb, total, _ = cl.call("GET", "", q)
        if st != 200:
            sys.exit(f"ListObjectsV2: {st} {d[:300]!r}")
        pages += 1
        keys += d.count(b"<Key>")
        lat.append(total)
        if b"<IsTruncated>true</IsTruncated>" not in d:
            break
        token = d.split(b"<NextContinuationToken>")[1].split(b"</NextContinuationToken>")[0].decode()
    emit(metric="list", prefix=a.prefix, pages=pages, keys=keys, page_seconds=[round(x, 3) for x in lat],
         seconds=round(sum(lat), 3))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["mpu", "many", "get", "list", "evict", "status"])
    p.add_argument("--base", required=True)
    p.add_argument("--bucket", required=True)
    p.add_argument("--key")
    p.add_argument("--prefix", default="")
    p.add_argument("--size", type=int)
    p.add_argument("--part", type=int, default=16 * MIB)
    p.add_argument("--count", type=int)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--range")
    p.add_argument("--sha256")
    p.add_argument("--max-keys", type=int, default=1000)
    a = p.parse_args()
    global CLIENT
    u = urllib.parse.urlsplit(a.base)
    if u.scheme != "https" and u.hostname not in ("localhost", "127.0.0.1", "::1"):
        sys.exit("--base: https only (the admin bearer and S3 signatures are sent with each call); http only for localhost")
    cl = CLIENT = Client(a.base, a.bucket)
    if a.command == "mpu":
        cmd_mpu(a, cl)
    elif a.command == "many":
        cmd_many(a, cl)
    elif a.command == "get":
        cmd_get(a, cl)
    elif a.command == "list":
        cmd_list(a, cl)
    elif a.command == "evict":
        st, body, t = admin(a.base, "POST", f"/evict/{a.bucket}/{urllib.parse.quote(a.key, safe='/')}?include_safety=1")
        answer = json.loads(body) if st == 200 else body[:200].decode("utf-8", "replace")
        emit(metric="evict", key=a.key, status=st, seconds=round(t, 3), answer=answer)
        if st != 200:
            sys.exit(2)
        kept = answer.get("safety_kept") if isinstance(answer, dict) else None
        if not isinstance(kept, int):
            sys.exit(2)
        if kept > 0:
            sys.exit(3)
    else:
        st, body, t = admin(a.base, "GET", f"/objects/{a.bucket}/{urllib.parse.quote(a.key, safe='/')}")
        print(body.decode("utf-8", "replace"))
        if st != 200:
            sys.exit(2)


if __name__ == "__main__":
    main()
