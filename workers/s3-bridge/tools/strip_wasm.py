#!/usr/bin/env python3
"""Drops the `name` and `producers` custom sections from the Worker wasm.

worker-build 0.8.7 runs wasm-opt with `--debuginfo`, which keeps the
`name` section (function names, about 600 KB). The Worker never reads
it: V8 uses it only to print function names in stack traces. This
script removes it after the build, so the wasm that the size budget
measures and the deploy uploads is the stripped one.

Only whole custom sections are removed; every other byte is copied
unchanged, in order. Function indices therefore stay the same, and
because these sections follow the code section, so do code offsets: a
trace frame `wasm-function[N]:0xOFF` from the stripped wasm resolves
against the unstripped copy that `--unstripped` keeps.

Usage:
  strip_wasm.py strip WASM [--unstripped COPY]
  strip_wasm.py check WASM

`strip` rewrites WASM in place (atomically). With `--unstripped`, the
input is first copied to COPY when it has a section to drop; a stale
COPY is removed when it has none. `check` fails if WASM still has a
section that `strip` drops. Standard library only.
"""

import os
import sys
import tempfile

MAGIC = b"\x00asm"
VERSION = b"\x01\x00\x00\x00"
DROPPED = frozenset({"name", "producers"})


class WasmError(ValueError):
    pass


def _leb_u32(data, pos, end):
    """Decodes an unsigned LEB128 u32 at `pos`; returns (value, next pos)."""
    result = 0
    for i in range(5):
        if pos >= end:
            raise WasmError("truncated LEB128")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << (7 * i)
        if byte < 0x80:
            if result > 0xFFFFFFFF:
                raise WasmError("LEB128 over u32")
            return result, pos
    raise WasmError("LEB128 longer than 5 bytes")


def sections(data):
    """Yields (start, end, id, custom name or None) for each section."""
    if data[:4] != MAGIC or data[4:8] != VERSION:
        raise WasmError("not a version-1 wasm module")
    pos = 8
    while pos < len(data):
        start = pos
        sid = data[pos]
        size, body = _leb_u32(data, pos + 1, len(data))
        end = body + size
        if end > len(data):
            raise WasmError(f"section at {start} runs past the end")
        name = None
        if sid == 0:
            nlen, npos = _leb_u32(data, body, end)
            if npos + nlen > end:
                raise WasmError(f"custom section name at {start} runs past the section")
            try:
                name = data[npos:npos + nlen].decode("utf-8")
            except UnicodeDecodeError as e:
                raise WasmError(f"custom section name at {start} is not UTF-8") from e
        yield start, end, sid, name
        pos = end


def strip(data):
    """Returns (stripped bytes, list of (name, section bytes) dropped)."""
    kept = [data[:8]]
    dropped = []
    for start, end, sid, name in sections(data):
        if sid == 0 and name in DROPPED:
            dropped.append((name, end - start))
        else:
            kept.append(data[start:end])
    return b"".join(kept), dropped


def _write_atomic(path, payload, mode):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".strip-", suffix=".wasm")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main(argv):
    args = argv[1:]
    if len(args) == 2 and args[0] == "check":
        with open(args[1], "rb") as f:
            data = f.read()
        found = sorted({n for _, _, sid, n in sections(data) if sid == 0 and n in DROPPED})
        if found:
            print(f"{args[1]}: still has {', '.join(found)}", file=sys.stderr)
            return 1
        print(f"{args[1]}: stripped ({len(data)} bytes)")
        return 0
    if len(args) in (2, 4) and args[0] == "strip" and (len(args) == 2 or args[2] == "--unstripped"):
        path = args[1]
        copy = args[3] if len(args) == 4 else None
        with open(path, "rb") as f:
            data = f.read()
            mode = os.stat(f.fileno()).st_mode & 0o777
        out, dropped = strip(data)
        if copy is not None:
            if dropped:
                os.makedirs(os.path.dirname(os.path.abspath(copy)), exist_ok=True)
                _write_atomic(copy, data, mode)
            elif os.path.exists(copy):
                os.unlink(copy)
        if dropped:
            _write_atomic(path, out, mode)
        detail = ", ".join(f"{n} {s}" for n, s in dropped) or "nothing to drop"
        print(f"{path}: {len(data)} -> {len(out)} bytes ({detail})")
        return 0
    print("usage: strip_wasm.py strip WASM [--unstripped COPY] | check WASM", file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (OSError, WasmError) as e:
        print(f"strip_wasm: {e}", file=sys.stderr)
        sys.exit(1)
