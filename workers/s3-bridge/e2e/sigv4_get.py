"""SigV4 GET with a signed Accept-Encoding (what rclone sends by default).

aws-cli never signs Accept-Encoding, so slice.sh uses this for the one case.
Usage: sigv4_get.py <base-url> <bucket/key> <signed-ae> <sent-ae> <out-file>
Credentials: the [default] profile of AWS_SHARED_CREDENTIALS_FILE, read here
and never printed. TLS trust: AWS_CA_BUNDLE when set. Prints only
"<status> <error code or ->"; the body goes to <out-file>.
Standard library only.
"""

import configparser
import datetime
import hashlib
import hmac
import http.client
import os
import ssl
import sys
import urllib.parse


def main():
    base, path, signed_ae, sent_ae, out = sys.argv[1:6]
    # No interpolation (a `%` in a secret is literal), and no exception text:
    # a parse error could quote part of the file, and slice.sh prints stderr.
    try:
        creds = configparser.ConfigParser(interpolation=None)
        creds.read(os.environ["AWS_SHARED_CREDENTIALS_FILE"])
        akid = creds["default"]["aws_access_key_id"]
        secret = creds["default"]["aws_secret_access_key"]
    except Exception:
        sys.exit("credentials file unreadable")
    region = os.environ.get("AWS_DEFAULT_REGION", "auto")
    url = urllib.parse.urlsplit(base)
    host = url.netloc
    raw_path = "/" + urllib.parse.quote(path, safe="/-_.~")

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    day = stamp[:8]
    payload = hashlib.sha256(b"").hexdigest()
    signed = {
        "accept-encoding": signed_ae,
        "host": host,
        "x-amz-content-sha256": payload,
        "x-amz-date": stamp,
    }
    names = sorted(signed)
    canonical = "\n".join(
        ["GET", raw_path, "", "".join(f"{n}:{signed[n]}\n" for n in names), ";".join(names), payload]
    )
    scope = f"{day}/{region}/s3/aws4_request"
    to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()]
    )
    key = ("AWS4" + secret).encode()
    for part in (day, region, "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()

    if url.scheme == "https":
        ctx = ssl.create_default_context(cafile=os.environ.get("AWS_CA_BUNDLE") or None)
        conn = http.client.HTTPSConnection(host, context=ctx, timeout=120)
    else:
        conn = http.client.HTTPConnection(host, timeout=120)
    conn.putrequest("GET", raw_path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("host", host)
    conn.putheader("accept-encoding", sent_ae)
    conn.putheader("x-amz-content-sha256", payload)
    conn.putheader("x-amz-date", stamp)
    conn.putheader(
        "authorization",
        f"AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders={';'.join(names)}, Signature={signature}",
    )
    conn.endheaders()
    resp = conn.getresponse()
    body = resp.read()
    with open(out, "wb") as f:
        f.write(body)
    code = "-"
    if b"<Code>" in body:
        code = body.split(b"<Code>", 1)[1].split(b"</Code>", 1)[0].decode("ascii", "replace")
    print(f"{resp.status} {code}")


main()
