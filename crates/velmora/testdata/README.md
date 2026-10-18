# Test vectors: provenance (verified 2026-10-18 against the committed files and consuming tests)

## `yenc_go_vectors.bin`

Credited provenance (not re-runnable in-repo): exported from the v1 Go worker
(`TogetherWeOwn/nntune`, `worker/internal/yenc`) by encoding then decoding each
case with the v1 code. The consuming test corroborates this source
(`tests/yenc_vectors.rs:1-10`). Single-part records carry `raw` input hex +
CRC32 + decoded length + the full article bytes; multipart records carry
`part`/`begin`/`end` + CRC32 + decoded length + the full article bytes with no
`raw` hex — the parser recovers multipart bytes from the article and treats the
CRC as the oracle (`tests/yenc_vectors.rs:94-119`). Counts are pinned by the
tests: 7 single-part cases (`tests/yenc_vectors.rs:140`) and 3 multipart cases
(`tests/yenc_vectors.rs:160`).

Cases in `testdata/yenc_go_vectors.bin`:

- empty (`single 0` with empty `raw=`, `decoded=0`), single byte (`single 1
  raw=00`, `decoded=1`), text (`single 2 raw=68656c6c6f20776f726c64` =
  "hello world", `decoded=11`);
- 9-byte edge selection (`single 3 raw=000a0d3dffd6e3e813`, `decoded=9`): raw
  bytes `00 0A 0D 3D FF D6 E3 E8 13`. This covers NUL/LF/CR/`=` raw values,
  `0xFF`, and `+42` escape preimages `D6`/`E3`/`13` (escape rule: `+42` values
  NUL, LF, CR, `=` are escaped; `src/yenc.rs:193-194`), plus near-miss `E8`. It
  is not exhaustive over every escapable value: `E0` (the `+42` preimage of LF)
  is absent;
- line-wrap run (`single 4`, 200x `0x41`, `decoded=200`) and escape run
  (`single 5`, 200x `0xD6`, `decoded=200`); the wrap width is `LINE_LENGTH =
  128` columns (`src/yenc.rs:23`);
- 4 KiB buffer (`single 6`, `decoded=4096`, CRC `7cd5ad22`): credited as a
  pseudorandom buffer by the exporter; verified here only for size (4096 raw
  bytes / 8192 hex chars) and CRC;
- 3-part multipart file: `multi part=1 begin=1 end=1000`, `part=2 begin=1001
  end=2000`, `part=3 begin=2001 end=3000`, each `decoded=1000`; the test
  reassembles 3000 bytes (`tests/yenc_vectors.rs:172-176`). Shape per part:
  `=ybegin part=N total=3 line=128 size=3000`, `=ypart begin=... end=...`,
  `=yend size=1000 part=N pcrc32=...` (framing rules pinned in
  `tests/yenc_vectors.rs:307-336`).

Provenance sketch (record of the throwaway v1 exporter, not committed to v1;
do not re-run in-repo to regenerate — multipart records use the `multi
part=...` shape noted above):

```go
// in worker/cmd/vecdump/main.go (throwaway, not committed to v1)
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"os"

	yenc "github.com/Rick7C2/nntune/worker/internal/yenc"
)
// ... encode each case with yenc.EncodeSegment, decode with yenc.DecodeTo,
// print "single %d raw=%s crc=%08x decoded=%d" + "article %d:\n%s" records.
```

The committed file intentionally contains non-UTF-8 bytes (raw encoded
bodies) — parse it as bytes, not text (`tests/yenc_vectors.rs:26-27`; byte
search helper `tests/yenc_vectors.rs:302-305`).

## `rclone_small_sealed.hex`

Credited provenance: the sealed (ciphertext) block of a 1000-byte rclone-crypt
file built with the v1 secretbox construction (80-byte derived key of `0x3c`,
header nonce `a0..b7`). Verified in-repo: `RCLONE_PLAIN` is 1000 bytes and
`RCLONE_DERIVED` is 80 bytes of `0x3c` (`tests/decrypt_vectors.rs:78-79`); the
nonce is `a0a1...b7` (`tests/decrypt_vectors.rs:88-90`); the committed hex is
2032 chars = 1016 bytes = 1000 plain + 16 tag bytes (`CIPHER_OVERHEAD = 16`,
`src/decrypt.rs:181-182`). The test rebuilds the `RCLONE\x00\x00` magic (8
bytes) + nonce (24 bytes) + sealed block and asserts `blob.len() == 32 +
plain.len() + 16` (`tests/decrypt_vectors.rs:93-97`; magic per
`src/decrypt.rs:186`, header size per `src/decrypt.rs:177-178`). Full read plus
ranged and tamper checks live in `tests/decrypt_vectors.rs:99-143`.
Multi-block behaviour is covered by `seal_block` round-trips building a
two-block file in `tests/decrypt_vectors.rs:151-204` (`seal_block` contract:
`sealed.len() == plaintext.len() + CIPHER_OVERHEAD`, `src/decrypt.rs:309-312`;
derived key length 80, `src/decrypt.rs:319-320`).
