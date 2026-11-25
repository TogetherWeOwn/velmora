"""Signed local workerd body probes. Reads credentials from the slice's file."""

from base64 import b64encode
import configparser
from contextlib import closing
import datetime
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import ssl
import sys
import time
from urllib.parse import quote, urlencode, urlsplit
from xml.etree import ElementTree
import zlib


def wait_for(log, marker):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if marker in log.read_text(errors="replace"):
            return
        time.sleep(0.05)
    raise AssertionError(f"workerd did not log {marker!r}")


def main():
    base, bucket, log_path = sys.argv[1:]
    url = urlsplit(base)
    if url.hostname not in {"127.0.0.1", "localhost"}:
        raise AssertionError("body probes require local workerd")
    log = Path(log_path)

    try:
        creds = configparser.ConfigParser(interpolation=None)
        creds.read(os.environ["AWS_SHARED_CREDENTIALS_FILE"])
        access = creds["default"]["aws_access_key_id"]
        secret = creds["default"]["aws_secret_access_key"]
    except Exception:
        sys.exit("credentials file unreadable")

    def send(method, key, headers=None, *, signed=True, query=()):
        path = f"/{bucket}/{key}"
        query_string = urlencode(sorted(query), quote_via=quote)
        headers = dict(headers or {})
        canonical_headers = {"host": url.netloc}
        if signed:
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            payload = headers.get("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            canonical_headers.update(
                (k, v) for k, v in headers.items() if k.startswith("x-amz-") or k == "content-encoding"
            )
            canonical_headers.update({"x-amz-date": stamp, "x-amz-content-sha256": payload})
            names = ";".join(sorted(canonical_headers))
            fields = "".join(f"{k}:{canonical_headers[k]}\n" for k in sorted(canonical_headers))
            canonical = f"{method}\n{path}\n{query_string}\n{fields}\n{names}\n{payload}"
            region = os.environ["AWS_DEFAULT_REGION"]
            scope = f"{stamp[:8]}/{region}/s3/aws4_request"
            signing_key = ("AWS4" + secret).encode()
            for part in scope.split("/"):
                signing_key = hmac.digest(signing_key, part.encode(), "sha256")
            digest = hashlib.sha256(canonical.encode()).hexdigest()
            signature = hmac.digest(
                signing_key, f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{digest}".encode(), "sha256"
            ).hex()
            headers["authorization"] = (
                f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={names}, Signature={signature}"
            )
        headers.update(canonical_headers)
        if url.scheme == "https":
            context = ssl.create_default_context(cafile=os.environ["AWS_CA_BUNDLE"])
            conn = http.client.HTTPSConnection(url.netloc, context=context, timeout=20)
        else:
            conn = http.client.HTTPConnection(url.netloc, timeout=20)
        target = f"{path}?{query_string}" if query_string else path
        conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
        for name, value in headers.items():
            conn.putheader(name, value)
        conn.endheaders()
        return closing(conn)

    def probe(name, declared, size, *, signed, extra_headers=None):
        headers = {"x-e2e-byob": "synthetic", "x-e2e-byob-size": str(size), "content-length": "0"}
        headers.update(extra_headers or {})
        if declared is not None:
            headers["x-e2e-byob-length"] = str(declared)
        elif not extra_headers:
            headers["x-amz-copy-source"] = f"/{bucket}/w/byob-cap-1"
        with send("PUT", name, headers, signed=signed) as conn:
            response = conn.getresponse()
            report = response.getheader("x-e2e-byob-observed")
            return response.status, response.read(), json.loads(report) if report else None

    for declared, cap in [(0, 1), (1, 1), (32768, 32768), (65536, 65536), (65537, 65536), (None, 4096)]:
        size = declared or 0
        status, _, report = probe(f"w/byob-denied-{declared}", declared, size, signed=False)
        assert status == 403 and report == {"allocations": [], "firstRead": None}, (
            f"declared {declared}: wanted 403 with no allocations before polling, got {status} {report}"
        )
        status, _, report = probe(f"w/byob-cap-{declared}", declared, size, signed=True)
        expected = {"allocations": [cap], "cap": cap}
        assert status == 200 and report and report["firstRead"] == expected, (
            f"declared {declared}: wanted 200 and first read {expected}, got {status} {report}"
        )
        assert report["allocations"] == [cap], f"declared {declared}: allocated again: {report}"

    crc32 = b64encode(zlib.crc32(b"x").to_bytes(4, "big"))
    framed = b"1\r\nx\r\n0\r\nx-amz-checksum-crc32:" + crc32 + b"\r\n\r\n"
    framing = {
        "content-encoding": "aws-chunked",
        "x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        "x-amz-decoded-content-length": "1",
        "x-amz-trailer": "x-amz-checksum-crc32",
        "x-e2e-byob-payload": b64encode(framed).decode("ascii"),
    }
    # Valid framing cannot pad one decoded byte to 64 KiB. Check that an
    # overstated encoded length uses the same cap and still fails, then
    # check that exact and absent encoded lengths verify normally.
    for declared in (65536, len(framed), None):
        key = f"w/byob-aws-chunked-{declared}"
        status, body, report = probe(key, declared, 0, signed=True, extra_headers=framing)
        assert report == {"firstRead": {"allocations": [1], "cap": 1}, "allocations": [1]}, (
            f"aws-chunked encoded={declared}, decoded=1: wanted one 1-byte buffer; got {status} {report}"
        )
        if declared == 65536:
            assert status == 400 and b"<Code>IncompleteBody</Code>" in body, (
                f"aws-chunked encoded length mismatch: wanted 400 IncompleteBody, got HTTP {status}"
            )
        else:
            assert status == 200, f"valid aws-chunked upload: wanted 200, got {status}"
            with send("GET", key) as conn:
                response = conn.getresponse()
                assert (response.status, response.read()) == (200, b"x"), "aws-chunked readback mismatch"
    print("BYOB probe: aws-chunked used a 1-byte buffer; exact body verified, overstated length rejected")

    status, body, _ = probe("w/byob-surplus", 1, 2, signed=True)
    assert status == 400 and b"<Code>EntityTooLarge</Code>" in body, (
        f"wanted 400 EntityTooLarge for a surplus byte, got HTTP {status}"
    )
    print("BYOB probe: allocation and surplus checks passed")

    def disconnect(key, kind, query=()):
        headers = {"x-e2e-byob": "disconnect", "content-length": "1048576"}
        with send("PUT", key, headers, query=query) as conn:
            conn.send(bytes(4096))
            wait_for(log, f"BYOB probe: {kind} fill pending")
        wait_for(log, f"BYOB probe: {kind} reader cancelled")
        wait_for(log, f"BYOB probe: {kind} finished HTTP 400")

    disconnect("w/byob-disconnect", "object")
    for key in ("w/byob-surplus", "w/byob-disconnect"):
        with send("HEAD", key) as conn:
            response = conn.getresponse()
            assert response.status == 404, f"{key}: wanted 404, got {response.status}"
    print("BYOB probe: disconnected PutObject mid-fill; reader cancelled, no object published")

    key = "w/byob-disconnect-part"
    with send("POST", key, {"content-length": "0"}, query=[("uploads", "")]) as conn:
        response = conn.getresponse()
        assert response.status == 200, f"CreateMultipartUpload: wanted 200, got {response.status}"
        upload_id = ElementTree.fromstring(response.read()).findtext("{*}UploadId")
        assert upload_id, "CreateMultipartUpload: missing upload ID"
    query = [("uploadId", upload_id)]
    disconnect(key, "part", [*query, ("partNumber", "1")])
    with send("GET", key, query=query) as conn:
        response = conn.getresponse()
        assert response.status == 200, f"ListParts: wanted 200, got {response.status}"
        assert ElementTree.fromstring(response.read()).find("{*}Part") is None, "ListParts: found an incomplete part"
    with send("DELETE", key, query=query) as conn:
        response = conn.getresponse()
        assert response.status == 204, f"AbortMultipartUpload: wanted 204, got {response.status}"
    print("BYOB probe: disconnected UploadPart mid-fill; reader cancelled, no part published")


if __name__ == "__main__":
    main()
