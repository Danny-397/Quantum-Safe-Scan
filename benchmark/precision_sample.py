"""Precision on real code: a random sample of findings, labeled by hand.

``evaluate.py`` measures precision on a corpus written for this project, which
is the corpus the scanner was tuned on. This harness measures it where nobody
chose the code: it scans the same popular PyPI packages as ``realworld.py``,
pools every finding, draws a fixed-seed random sample, and writes each one with
its surrounding source so it can be labeled by reading the code.

    python benchmark/precision_sample.py            # scan, sample, write sample file
    python benchmark/precision_sample.py --score    # score the labels in precision_labels.json

Labels live in ``precision_labels.json`` keyed by finding id, each with a
one-line reason, so every judgement is auditable. A finding is a **true
positive** when the flagged line uses, configures or implements the named
algorithm in executable code: a call, an import of it, an identifier or
constant that selects it, or a table entry the code acts on. It is a **false
positive** when the name only appears in a comment, docstring, message or
other inert text, when the identifier merely resembles the algorithm's name,
when the algorithm on the line is not the one reported, or when the line turns
the algorithm off (``OP_NO_TLSv1``): a finding implies exposure.

Package versions are pinned in the sample file, so a rerun scans the same code.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import tempfile
import urllib.request
import warnings

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from realworld import DEFAULT_PACKAGES, _UA, _download, _extract  # noqa: E402
from quantumsafe.scanner import scan_path  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(BASE, "precision_sample.json")
LABELS = os.path.join(BASE, "precision_labels.json")
RESULTS = os.path.join(BASE, "RESULTS-precision.md")
SEED = 2026
# Context for the committed labels, which describe the scanner as it was when the
# sample was drawn; kept in the generated report so a rescore does not drop it.
NOTE = (
    "**Measured before the TLS rule fix.** Four of the seven false positives were TLS 1.0 "
    "findings on flags that turn old protocols *off* (`OP_NO_SSLv3`, `OP_NO_TLSv1`). The rule "
    "in `cli/scanner.py` now requires the protocol name to start its own token, and "
    "`tests/test_scanner.py` checks both that those flags stay silent and that real selections "
    "(`PROTOCOL_TLSv1`, `SSLv3_METHOD`, `TLSVersion.TLSv1`) still fire. The numbers here are "
    "left as measured rather than re-scored against the fixed scanner."
)
N = 100
CONTEXT = 3


def _sdist(pkg: str, version: str | None) -> tuple[str, str]:
    url = f"https://pypi.org/pypi/{pkg}/{version}/json" if version else f"https://pypi.org/pypi/{pkg}/json"
    with urllib.request.urlopen(urllib.request.Request(url, headers=_UA), timeout=30) as resp:
        meta = json.load(resp)
    for entry in meta.get("urls", []):
        if entry.get("packagetype") == "sdist":
            return meta["info"]["version"], entry["url"]
    raise RuntimeError(f"no sdist for {pkg}")


def collect(pins: dict[str, str]) -> tuple[list[dict], dict[str, str]]:
    pool, versions = [], {}
    for pkg in DEFAULT_PACKAGES:
        try:
            version, url = _sdist(pkg, pins.get(pkg))
        except Exception as exc:  # a package without an sdist is skipped, not fatal
            print(f"  skip {pkg}: {exc}", file=sys.stderr)
            continue
        versions[pkg] = version
        with tempfile.TemporaryDirectory(prefix="qsprec_") as tmp:
            _extract(_download(url), url, tmp)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                findings = scan_path(tmp)
            for f in findings:
                # The scanner may report paths relative to the scan root.
                full = f.file_path if os.path.isabs(f.file_path) else os.path.join(tmp, f.file_path)
                rel = os.path.relpath(full, tmp).replace(os.sep, "/")
                try:
                    with open(full, encoding="utf-8", errors="replace") as fh:
                        lines = fh.read().splitlines()
                except OSError:
                    lines = []
                lo, hi = max(f.line_number - 1 - CONTEXT, 0), f.line_number + CONTEXT
                pool.append({
                    "package": pkg, "file": rel, "line": f.line_number,
                    "algorithm": f.algorithm, "family": f.family, "risk": f.risk_level,
                    "context": [f"{i + 1:>5}{'>' if i + 1 == f.line_number else ' '} {lines[i]}"
                                for i in range(lo, min(hi, len(lines)))],
                })
        print(f"  {pkg} {version}: {len(findings)} findings", file=sys.stderr)
    return pool, versions


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return centre - half, centre + half


def score() -> int:
    sample = json.load(open(SAMPLE, encoding="utf-8"))
    labels = json.load(open(LABELS, encoding="utf-8"))
    rows = sample["sample"]
    missing = [r["id"] for r in rows if r["id"] not in labels]
    if missing:
        sys.exit(f"{len(missing)} findings unlabeled, e.g. {missing[:5]}")
    tp = [r for r in rows if labels[r["id"]]["label"] == "tp"]
    fp = [r for r in rows if labels[r["id"]]["label"] == "fp"]
    n = len(rows)
    lo, hi = wilson(len(tp), n)
    by_fam: dict[str, list[int]] = {}
    for r in rows:
        by_fam.setdefault(r["family"], [0, 0])
        by_fam[r["family"]][0 if labels[r["id"]]["label"] == "tp" else 1] += 1

    out = [
        "# Precision on real code (random sample, hand-labeled)",
        "",
        f"Generated by [`precision_sample.py`](precision_sample.py) from {sample['pool_size']:,} "
        f"findings in {len(sample['versions'])} PyPI packages (versions pinned in "
        f"[`precision_sample.json`](precision_sample.json)); seed {sample['seed']}, "
        f"{n} findings drawn uniformly. Every label and its reason is in "
        f"[`precision_labels.json`](precision_labels.json).",
        "",
        "| Findings sampled | True positives | False positives | Precision | 95% CI (Wilson) |",
        "|--:|--:|--:|--:|--:|",
        f"| {n} | {len(tp)} | {len(fp)} | **{len(tp) / n:.0%}** | {lo:.0%} to {hi:.0%} |",
        "",
        NOTE,
        "",
        "## By family",
        "",
        "| Family | TP | FP |",
        "|---|--:|--:|",
        *[f"| {fam} | {a} | {b} |" for fam, (a, b) in sorted(by_fam.items(), key=lambda kv: -sum(kv[1]))],
        "",
        "## Every false positive",
        "",
        *([f"- `{r['package']}` {r['file']}:{r['line']} ({r['algorithm']}): {labels[r['id']]['reason']}"
           for r in fp] or ["None."]),
        "",
        "## Definition used",
        "",
        "A finding is a true positive when the flagged line uses, configures or implements the "
        "named algorithm in executable code: a call, an import of it, an identifier or constant "
        "that selects it, or a table entry the code acts on. It is a false positive when the name "
        "appears only in inert text (comment, docstring, message), when an identifier merely "
        "resembles the name, when the line's algorithm is not the one reported, or when the line "
        "turns the algorithm off (a finding implies exposure). Labels were "
        "assigned by reading each finding's source context; this measures precision only, not "
        "recall, which the seeded benchmark covers.",
        "",
    ]
    with open(RESULTS, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))
    print(f"precision {len(tp)}/{n} = {len(tp) / n:.1%}  (95% CI {lo:.1%} to {hi:.1%}); wrote {RESULTS}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--score", action="store_true", help="score precision_labels.json")
    args = ap.parse_args(argv)
    if args.score:
        return score()
    pins = json.load(open(SAMPLE, encoding="utf-8"))["versions"] if os.path.exists(SAMPLE) else {}
    pool, versions = collect(pins)
    rng = random.Random(SEED)
    picked = rng.sample(range(len(pool)), min(N, len(pool)))
    sample = []
    for i in sorted(picked):
        row = dict(pool[i])
        row["id"] = f"{row['package']}:{row['file']}:{row['line']}:{row['family']}"
        sample.append(row)
    with open(SAMPLE, "w", encoding="utf-8") as fh:
        json.dump({"seed": SEED, "pool_size": len(pool), "versions": versions, "sample": sample}, fh, indent=1)
    print(f"pooled {len(pool)} findings; wrote {len(sample)} to {SAMPLE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
