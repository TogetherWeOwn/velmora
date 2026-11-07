#!/usr/bin/env python3
"""`age` crate (rage) oracle vectors for velmora's STREAM layer (format decision §4).

The payloads are sealed by rage itself, through pyrage (its Python binding),
not by velmora. The `age` crate cannot be a Cargo dev-dependency: every
release from 0.11 on pulls an unmaintained crate (`basic-toml`, through
`i18n-embed-fl`), and 0.12 also pulls `crypto-bigint` 0.5 (RUSTSEC-2026-0387),
so cargo-deny and OSV refuse it. Regenerate with:

    pip install --only-binary=:all: --no-deps pyrage==1.4.0
    python3 -I gen_age_vectors.py > vectors.txt

pyrage 1.4.0 embeds `age` 0.12.1 / `age-core` 0.12.0 (its Cargo.lock). Each
record holds the file key, recovered from the scrypt stanza with pyca
`cryptography` (a fixed synthetic passphrase, nothing secret), rage's
nonce `N`, and the SHA-256 of rage's payload `N ‖ chunks`; payloads up to
FULL_MAX bytes also carry the whole age file. Before writing a record this
script checks that rage decrypts its own file and that an independent STREAM
decoder (pyca ChaCha20-Poly1305) opens the payload under the recovered key.
"""

import base64
import hashlib
import struct

import pyrage
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CHUNK = 65536
TAG = 16
# The same lengths as `AGE_ORACLE_LENGTHS` consumers expect: empty, short,
# one byte under/at/over 64 KiB, two full chunks, and ragged tails.
LENGTHS = [0, 1, 65535, 65536, 65537, 131072, 131073, 200003]
PASSPHRASE = "velmora-age-oracle"
FULL_MAX = 100


def plaintext(n):
    # Matches `oracle_plaintext` in src/media.rs.
    return bytes(((i * 31) ^ (i >> 9)) & 0xFF for i in range(n))


def b64(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


def split_header(age_file):
    """Returns (header lines before the MAC line, payload offset)."""
    mac = age_file.index(b"\n--- ") + 1
    end = age_file.index(b"\n", mac) + 1
    return age_file[:mac].decode().split("\n"), end


def scrypt_file_key(lines):
    """age v1 scrypt recipient: unwrap the 16-byte file key."""
    stanza = next(i for i, l in enumerate(lines) if l.startswith("-> scrypt "))
    _, _, salt, log_n = lines[stanza].split(" ")
    body = b64(lines[stanza + 1])
    n = 1 << int(log_n)
    wrap_key = hashlib.scrypt(
        PASSPHRASE.encode(),
        salt=b"age-encryption.org/v1/scrypt" + b64(salt),
        n=n,
        r=8,
        p=1,
        # scrypt needs 128 * r * n bytes (1 GiB at rage's log N = 20).
        maxmem=128 * 8 * n + (1 << 24),
        dklen=32,
    )
    return ChaCha20Poly1305(wrap_key).decrypt(b"\x00" * 12, body, None)


def stream_open(file_key, payload):
    """age v1 STREAM decoder, written from the spec with pyca primitives."""
    nonce, body = payload[:16], payload[16:]
    key = HKDF(hashes.SHA256(), 32, salt=nonce, info=b"payload").derive(file_key)
    aead = ChaCha20Poly1305(key)
    out, index = b"", 0
    while True:
        chunk, body = body[: CHUNK + TAG], body[CHUNK + TAG :]
        last = not body
        out += aead.decrypt(struct.pack(">Q", index).rjust(11, b"\x00") + bytes([last]), chunk, None)
        if last:
            return out
        index += 1


def main():
    print("# rage (age 0.12.1 via pyrage 1.4.0) oracle vectors; see gen_age_vectors.py")
    for n in LENGTHS:
        pt = plaintext(n)
        age_file = pyrage.passphrase.encrypt(pt, PASSPHRASE)
        assert pyrage.passphrase.decrypt(age_file, PASSPHRASE) == pt
        lines, at = split_header(age_file)
        assert lines[0] == "age-encryption.org/v1"
        file_key = scrypt_file_key(lines)
        payload = age_file[at:]
        assert stream_open(file_key, payload) == pt
        print()
        print(f"len={n}")
        print(f"file_key={file_key.hex()}")
        print(f"nonce={payload[:16].hex()}")
        print(f"payload_len={len(payload)}")
        print(f"payload_sha256={hashlib.sha256(payload).hexdigest()}")
        if len(payload) <= FULL_MAX:
            print(f"age_file={age_file.hex()}")


if __name__ == "__main__":
    main()
