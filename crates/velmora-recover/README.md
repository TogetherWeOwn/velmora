# Standalone Usenet recovery

`velmora-recover` reads a sealed recovery kit without talking to the service, its database, or its cache. It is a native-only CLI, opt-in at build time. The deployed service does not link it.

```sh
cargo build --release --locked -p velmora-recover --features recovery-cli
```

Use a trusted copy of the tool and a separately held KEK. `--kek-file` accepts a 32-byte raw key or a 64-digit hex key (an optional final newline is permitted), or `-` for standard input. Set `--kek-version` if the key is not version 1. The key itself is never a command-line argument.

```sh
velmora-recover --kit ./kit --kek-file ./key verify-kit
velmora-recover --kit ./kit --kek-file ./key ls --bucket backup --prefix photos/
velmora-recover --kit ./kit --kek-file ./key get --bucket backup --key photos/example.png --providers ./providers.toml --out ./restored
velmora-recover --kit ./kit --kek-file ./key nzb --object backup/photos/example.png --out ./example.nzb
velmora-recover --kit ./kit --kek-file ./key decrypt --bucket backup --key photos/example.png --from-dir ./downloads --out ./restored
velmora-recover --kit ./kit --kek-file ./key check --sample 5 --providers ./providers.toml
```

`verify-kit` reads and checks the manifest, authenticated index and all record packs. Restore uses the authenticated index and does not require the record packs. An index can include live objects without a usable article plan; `ls` marks them `recoverable: false`, and attempts to restore them fail. Plan availability does not guarantee provider retention.

Keep provider credentials in a protected file, not in command arguments. Example provider configuration:

```toml
[[providers]]
host = "provider.example.invalid"
port = 563
tls = true
user = "replace-with-username"
pass = "replace-with-password"
max_conns = 1
```

The current CLI uses one simultaneous connection total and rotates providers after a failed or corrupt article. A plaintext provider configuration is accepted only without credentials. For a separately provisioned recovery relay, substitute `--transport relay --relay-url HTTPS_URL --relay-token-file FILE` for `--providers`. The CLI otherwise uses direct NNTP; it does not silently fall back between transport types.

An NZB exposes message-IDs and groups, not object keys or plaintext. Let the downloader keep the decoded ciphertext files (no unpacking is needed) and point `decrypt` at their directory. The tool matches those files by authenticated payload digest, not by directory order.

Restore into a directory you control, on one filesystem that supports hard links and file locks. A restore uses one writer lock and a private staging directory; do not edit recovered files, journal, or staging data while it runs. Re-run into the same output directory to resume. Previously written extents are re-hashed before reuse. Final files are published only after the ordered extents, total length and applicable whole-object MD5 have been verified. Without an independent whole-object checksum (for example a multipart object with no source MD5), the reported MD5 is `computed`, not `verified`.

Recovered files are normally placed at `<out>/<bucket>/<key>`. Keys that cannot be represented as safe paths (or conflict with a file already there) go under `<out>/_unmapped`, with original keys and paths in `INDEX.tsv`. The report escapes backslashes, tabs, NULs and newlines. No differing existing file is overwritten. If an unmapped destination already holds different data, use a fresh output directory.
