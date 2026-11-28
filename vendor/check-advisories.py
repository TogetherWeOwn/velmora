"""Check the vendored crates against the RustSec advisory database.

A crate replaced through a path [patch.crates-io] has no registry source in
Cargo.lock, so cargo-deny and other lockfile scanners skip it. This reads the
advisory database cargo-deny fetched (or the one given) and fails if any
advisory that is not withdrawn affects a vendored crate's version.

Usage: python3 -I vendor/check-advisories.py [advisory-db-dir]
"""

import pathlib
import re
import sys
import tomllib

VENDORED = {"tokio-postgres": (0, 7, 18)}


class Unsupported(ValueError):
    """A requirement form this checker does not evaluate: fail closed."""


def parse_version(text):
    """`MAJOR[.MINOR[.PATCH]]` with no prerelease or build part."""
    match = re.fullmatch(r"\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?\s*", text)
    if not match:
        raise Unsupported(f"unsupported version {text!r}")
    major, minor, patch = match.groups()
    return (int(major), int(minor or 0), int(patch or 0)), minor is None, patch is None


def satisfies(version, requirement):
    """A comma-separated Cargo requirement; every comparator must hold.

    Partial versions follow Cargo: `>= 0.7` is `>= 0.7.0`, `< 0.7` is
    `< 0.7.0`, `> 0.7` is `>= 0.8.0`, `<= 0.7` is `< 0.8.0`, `= 0.7` is
    `>= 0.7.0, < 0.8.0`. Prerelease, wildcard and build forms are refused.
    """
    for comparator in requirement.split(","):
        match = re.fullmatch(r"\s*(>=|<=|>|<|=|\^|~)?\s*(\S+)\s*", comparator)
        if not match:
            raise Unsupported(f"unsupported comparator {comparator!r}")
        op, rest = match.group(1) or "^", match.group(2)
        bound, no_minor, no_patch = parse_version(rest)
        # The first version past a partial bound (`0.7` -> `0.8.0`).
        if no_minor:
            past = (bound[0] + 1, 0, 0)
        elif no_patch:
            past = (bound[0], bound[1] + 1, 0)
        else:
            past = (bound[0], bound[1], bound[2] + 1)
        if op == ">=":
            ok = version >= bound
        elif op == ">":
            ok = version >= past
        elif op == "<":
            ok = version < bound
        elif op == "<=":
            ok = version < past
        elif op == "=":
            ok = bound <= version < past
        elif op == "~":
            upper = (bound[0] + 1, 0, 0) if no_minor else (bound[0], bound[1] + 1, 0)
            ok = bound <= version < upper
        else:
            # Caret: the leftmost non-zero part given may not change.
            if bound[0] > 0 or no_minor:
                upper = (bound[0] + 1, 0, 0)
            elif bound[1] > 0 or no_patch:
                upper = (0, bound[1] + 1, 0)
            else:
                upper = (0, 0, bound[2] + 1)
            ok = bound <= version < upper
        if not ok:
            return False
    return True


def front_matter(path):
    text = path.read_text(encoding="utf-8")
    match = re.search(r"```toml\n(.*?)\n```", text, re.S)
    if not match:
        raise ValueError(f"no TOML front matter in {path}")
    return tomllib.loads(match.group(1))


def self_test():
    cases = [((0, 7, 18), ">= 0.7.10", True), ((0, 7, 9), ">= 0.7.10", False),
             ((0, 7, 18), "^0.7.5", True), ((0, 8, 0), "^0.7.5", False), ((0, 0, 3), "^0.0.3", True),
             ((0, 0, 4), "^0.0.3", False), ((0, 7, 18), "< 0.7.0", False), ((0, 6, 9), ">= 0.6, < 0.7", True),
             ((0, 7, 18), "~0.7", True), ((0, 7, 18), "= 0.7.18", True), ((1, 2, 0), "^1", True),
             ((0, 7, 18), "< 0.7", False), ((0, 6, 99), "< 0.7", True), ((0, 7, 18), "<= 0.7", True),
             ((0, 8, 0), "<= 0.7", False), ((0, 7, 18), "> 0.7", False), ((0, 8, 0), "> 0.7", True),
             ((0, 7, 18), "= 0.7", True), ((0, 8, 0), "= 0.7", False), ((0, 7, 18), ">= 0.7", True)]
    for version, req, want in cases:
        assert satisfies(version, req) is want, (version, req)
    for unsupported in [">= 0.7.18-alpha.1", "0.7.*", ">= 0.7.18+build", "*"]:
        try:
            satisfies((0, 7, 18), unsupported)
        except Unsupported:
            continue
        raise AssertionError(f"accepted {unsupported!r}")


def main():
    self_test()
    if len(sys.argv) > 1:
        dbs = [pathlib.Path(sys.argv[1])]
    else:
        dbs = sorted(pathlib.Path.home().glob(".cargo/advisory-dbs/*"))
    dbs = [db for db in dbs if (db / "crates").is_dir()]
    if not dbs:
        sys.exit("no RustSec advisory database found (run cargo-deny first, or pass its path)")
    affected = []
    checked = 0
    for db in dbs:
        for crate, version in VENDORED.items():
            for path in sorted((db / "crates" / crate).glob("*.md")):
                checked += 1
                advisory = front_matter(path)
                if advisory.get("advisory", {}).get("withdrawn"):
                    continue
                versions = advisory.get("versions", {})
                safe = versions.get("patched", []) + versions.get("unaffected", [])
                try:
                    cleared = any(satisfies(version, req) for req in safe)
                except Unsupported as error:
                    sys.exit(f"{path.name}: {error}; check it by hand")
                if not cleared:
                    affected.append(f"{advisory['advisory']['id']} affects {crate} {'.'.join(map(str, version))}")
    if affected:
        sys.exit("\n".join(affected))
    print(f"vendored crates: no advisory affects {', '.join(f'{c} {'.'.join(map(str, v))}' for c, v in VENDORED.items())} "
          f"({checked} advisories read from {len(dbs)} database(s))")


if __name__ == "__main__":
    main()
