#!/usr/bin/env python3
"""Fail if a documented test count disagrees with the real one.

WHY THIS EXISTS
Every "N tests" in the README and the technical report is a claim a reader can
check by cloning the repo and running pytest, which makes a stale one a
published inaccuracy rather than a cosmetic slip. Keeping them current by hand
does not work: over a single day of feature work these numbers were corrected
five times and still drifted, and the one that stayed wrong longest was a
shields.io badge, because the badge spells the number differently from the prose
("tests-110%20passing" versus "110 tests") and a search for one does not find
the other.

So the count is collected from pytest and compared against every documented
figure. This runs in CI, so the claim cannot rot without the build saying so.

USAGE
    python tools/check_test_count.py            # verify, exit 1 on mismatch
    python tools/check_test_count.py --fix      # rewrite the docs to match
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Each entry is a file and the patterns that carry a test count in it. The
#: count is group 1 of every pattern, so --fix can rewrite it in place.
DOCUMENTED = {
    "README.md": [
        # shields.io badge: tests-545%20passing
        r"tests-(\d+)%20passing",
        # its alt text, which drifts separately from the badge URL
        r'alt="(\d+) tests passing"',
        # prose in the quickstart
        r"#\s*(\d+) tests; in-memory DB",
    ],
    "docs/TECHNICAL_REPORT.md": [
        r"\*\*(\d+) automated tests\*\*",
    ],
}


def collect_count() -> int:
    """The number of tests pytest collects, from pytest itself."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--collect-only"],
        cwd=ROOT, capture_output=True, text=True,
    )
    match = re.search(r"(\d+) tests? collected", proc.stdout)
    if not match:
        sys.stderr.write(proc.stdout[-2000:] + proc.stderr[-2000:])
        raise SystemExit("could not read a collected-test count from pytest")
    return int(match.group(1))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fix", action="store_true",
                    help="rewrite the documented counts instead of failing")
    args = ap.parse_args()

    actual = collect_count()
    print(f"pytest collects {actual} tests")

    stale: list[str] = []
    for rel, patterns in DOCUMENTED.items():
        path = ROOT / rel
        if not path.exists():
            print(f"  SKIP {rel} (missing)")
            continue
        text = original = path.read_text(encoding="utf-8")
        for pattern in patterns:
            found = False
            for m in re.finditer(pattern, text):
                found = True
                claimed = int(m.group(1))
                if claimed == actual:
                    continue
                stale.append(f"{rel}: claims {claimed}, actual {actual} "
                             f"(pattern {pattern!r})")
                if args.fix:
                    # Replace only the captured number, keeping the surrounding
                    # text exactly as written.
                    start, end = m.span(1)
                    text = text[:start] + str(actual) + text[end:]
            if not found:
                stale.append(f"{rel}: no match for {pattern!r} -- the wording "
                             "changed, so this check stopped watching it")
        if args.fix and text != original:
            path.write_text(text, encoding="utf-8", newline="")
            print(f"  updated {rel}")

    if not stale:
        print("every documented test count matches")
        return 0

    if args.fix:
        # Re-read after rewriting so the summary reflects reality.
        print(f"\nfixed {len(stale)} issue(s); re-run without --fix to confirm")
        return 0

    print("\nSTALE TEST COUNTS:", file=sys.stderr)
    for item in stale:
        print(f"  {item}", file=sys.stderr)
    print("\nRun: python tools/check_test_count.py --fix", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
