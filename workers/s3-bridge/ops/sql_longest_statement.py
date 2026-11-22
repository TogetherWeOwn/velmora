"""Report the largest statement in a D1 dump: UTF-8 bytes and start line."""

import sqlite3
import sys


def longest_statement(path, limit):
    buffer = bytearray()
    whitespace = b" \t\r\n\v\f"
    longest = (0, 1)
    # D1 starts each statement on its own line, but a quoted SQL value or
    # schema definition can span lines. Preserve the raw UTF-8 byte count,
    # and use SQLite's tokenizer to find the end without executing SQL.
    with open(path, "rb") as dump:
        read_limit = limit + 1
        for line_number, line in enumerate(iter(lambda: dump.readline(read_limit), b""), 1):
            whole_line = len(line) < read_limit or line.endswith(b"\n")
            if not buffer:
                if whole_line and not line.strip(whitespace):
                    continue
                start_line = line_number
            buffer.extend(line)
            # An unfinished statement can only become complete at a
            # semicolon or at the end of a block comment after one.
            complete = (whole_line and (b";" in line or b"*/" in line)
                        and sqlite3.complete_statement(buffer.decode("utf-8")))
            size = len(buffer)
            # Stop at the first over-limit statement. Reads and buffers
            # stay bounded even if no statement terminator ever arrives.
            if size > limit:
                return (size, start_line) if complete else (size, start_line, "+")
            if complete:
                if size > longest[0]:
                    longest = (size, start_line)
                buffer.clear()
    if buffer:
        raise SystemExit("the dump ends inside a statement")
    return longest


if __name__ == "__main__":
    try:
        print(*longest_statement(sys.argv[1], int(sys.argv[2])))
    except (OSError, ValueError):
        raise SystemExit("could not measure SQL statements in the dump") from None
