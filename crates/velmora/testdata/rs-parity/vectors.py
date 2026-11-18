#!/usr/bin/env python3
"""Independent model of the repair-parity code (src/rs.rs), used once to
produce the fixed vectors in tests/rs_parity.rs. Standard library only.

    python3 -I vectors.py

It shares no code with the engine: the field is built here from the
polynomial, and parity is computed from the definition

    parity[row][w] = XOR over i of  data[i][w] * 1 / ((0x8000 | row) ^ i)

over GF(2^16) (x^16 + x^12 + x^3 + x + 1), shards read as little-endian
16-bit words and zero-padded to the longest shard rounded up to even.
The tests fail if the engine's bytes differ from the ones printed here.
"""
import hashlib
import sys
from array import array

assert sys.byteorder == "little"

POLY = 0x1100B
ZERO_LOG = 2 * 65536  # log of 0: lands in the zero tail of EXP
EXP = [0] * (4 * 65536)
LOG = [ZERO_LOG] * 65536
b = 1
for l in range(65535):
    EXP[l] = EXP[l + 65535] = b
    LOG[b] = l
    b <<= 1
    if b & 0x10000:
        b ^= POLY


def inv(a):
    assert a != 0
    return EXP[(65535 - LOG[a]) % 65535]


M64 = (1 << 64) - 1


def stream(seed, length):
    """splitmix64, each output as 8 little-endian bytes, cut to `length`."""
    out = array("Q")
    state = seed & M64
    for _ in range((length + 7) // 8):
        state = (state + 0x9E3779B97F4A7C15) & M64
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
        out.append(z ^ (z >> 31))
    return out.tobytes()[:length]


def article_lens(plain):
    """Article payload lengths of an extent with `plain` plaintext bytes."""
    cipher = 48 + plain + 16 * ((plain + 65535) // 65536)
    lens, start = [], 0
    while start < cipher:
        full = 721120 if start == 0 else 721072
        n = min(full, cipher - start)
        lens.append(n)
        start += n
    return lens


def encode(data, rows):
    longest = max(len(d) for d in data)
    size = longest + (longest & 1)
    parity = []
    for row in rows:
        acc = 0
        for i, shard in enumerate(data):
            words = array("H")
            words.frombytes(shard + bytes(size - len(shard)))
            lc = LOG[inv((0x8000 | row) ^ i)]
            exp, log = EXP, LOG
            term = array("H", [exp[log[w] + lc] for w in words])
            acc ^= int.from_bytes(term.tobytes(), "little")
        parity.append(acc.to_bytes(size, "little"))
    return parity


def stripe(seed, lens):
    return [stream(seed + i, n) for i, n in enumerate(lens)]


print("// tiny vectors: (data shards, rows, parity shards), hex")
for name, data, rows in [
    ("one odd shard", [bytes.fromhex("010203")], [0]),
    ("three shards", [b"hello", bytes.fromhex("ffee00dd"), bytes.fromhex("8001")], [0, 1]),
    ("high row", [bytes.fromhex("0001"), bytes.fromhex("0100ffff")], [0x7FFF, 5]),
]:
    parity = encode(data, rows)
    print(f"// {name}")
    print("  data:  ", [d.hex() for d in data])
    print("  rows:  ", rows)
    print("  parity:", [p.hex() for p in parity])

print("// SHA-256 of each parity shard: (name, seed, plain bytes, rows)")
for name, seed, plain, rows in [
    ("one article, (1,1)", 1, 5, [0]),
    ("two articles, short odd last, (2,2)", 2, 720896 + 1, [0, 1]),
    ("8 articles, short last, (8,2)", 3, 5 * 1048576 + 17, [0, 1]),
    ("8 MiB, (12,2)", 4, 8 * 1048576, [0, 1]),
    ("16 MiB, (24,3) and (24,4)", 5, 16 * 1048576, [0, 1, 2, 3]),
    ("8 MiB, top-up rows", 4, 8 * 1048576, [2, 0x7FFF]),
]:
    lens = article_lens(plain)
    parity = encode(stripe(seed, lens), rows)
    print(f"// {name}: {len(lens)} articles, last {lens[-1]} B, shard {len(parity[0])} B")
    for row, p in zip(rows, parity):
        print(f'  ({seed}, {plain}, {row}, "{hashlib.sha256(p).hexdigest()}"),')
