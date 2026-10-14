# Test vectors: provenance

## `yenc_go_vectors.bin`

Exported from the v1 Go worker (`TogetherWeOwn/nntune`,
`worker/internal/yenc`) by encoding then decoding each case with the v1
code and recording `raw` input hex + CRC32 + decoded length + the full
article bytes. Cases: empty, single byte, text, every escapable byte value,
line-wrap and escape-across-boundary runs, a 4 KiB pseudorandom buffer, and
a 3-part multipart file (1000-byte parts).

Regenerate (from a checkout of v1):

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
bodies) — parse it as bytes, not text (see `tests/yenc_vectors.rs`).

## `rclone_small_sealed.hex`

The sealed (ciphertext) block of a 1000-byte rclone-crypt file built by
`x/crypto/nacl/secretbox` in v1's construction (header nonce
`a0..b7`, 80-byte derived key of `0x3c`). The test rebuilds
`magic + nonce + sealed` and decrypts it. Full-file vectors (100 KiB)
were used during development but are too large to commit; multi-block
behaviour is covered by `seal_block` round-trips in
`tests/decrypt_vectors.rs`.
