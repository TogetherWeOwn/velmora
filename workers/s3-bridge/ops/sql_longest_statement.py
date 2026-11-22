"""Report the largest statement in a D1 dump: UTF-8 bytes and start line."""

import sqlite3
import sys


def longest_statement(path):
    buffer = ""
    start_line = 1
    longest = (0, 1)
    # D1 starts each statement on its own line, but a quoted SQL value or
    # schema definition can span lines. Use SQLite's tokenizer to find the
    # end without executing SQL. Preserve newlines for the byte count.
    with open(path, encoding="utf-8", newline="") as dump:
        for line_number, line in enumerate(dump, 1):
            buffer += line
            if sqlite3.complete_statement(buffer):
                size = len(buffer.encode("utf-8"))
                if size > longest[0]:
                    longest = (size, start_line)
                buffer = ""
                start_line = line_number + 1
    if buffer.strip(" \t\r\n\v\f"):
        raise SystemExit("the dump ends inside a statement")
    return longest


if __name__ == "__main__":
    try:
        print(*longest_statement(sys.argv[1]))
    except (OSError, ValueError):
        raise SystemExit("could not measure SQL statements in the dump") from None
