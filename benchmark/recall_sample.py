"""Recall on real code: random files, every quantum-vulnerable usage labeled by hand.

``precision_sample.py`` checks a random sample of the scanner's *findings*, so it
can only say how many of them are wrong. It cannot see what the scanner never
reported. This harness measures the other half: it draws a fixed-seed random
sample of real source files that touch cryptography, every quantum-vulnerable
usage in each file is labeled by reading the whole file (without looking at
the scanner's output), and recall is the share of those usages the scanner
reports on the right line with the right family.

    python benchmark/recall_sample.py                      # draw the first sample (recall_sample.json)
    python benchmark/recall_sample.py --score              # score it against recall_labels.json
    python benchmark/recall_sample.py --holdout            # draw the held-out sample
    python benchmark/recall_sample.py --holdout --score    # score recall_holdout_labels.json

**Two samples.** The first sample (seed 2026) was labeled and scored blind, and
its misses then drove scanner fixes, so re-scoring it afterwards measures the
fixes, not the scanner. The held-out sample (seed 2027, 40 more files, none of
them in the first sample) was drawn and labeled after those fixes and before
the scanner was run on it: that is the number to quote for the current scanner.

**Population.** Python files in the same pinned PyPI packages as the precision
sample whose source imports a module that can do cryptography (hashlib, hmac,
ssl, cryptography, Crypto/Cryptodome, OpenSSL, nacl, ecdsa, rsa, paramiko,
jwt). A usage in a file with none of those imports, such as a bare "RS256"
string in a config module, is outside the population; the result is recall
*given* the file visibly does crypto.

**Unit.** One labeled usage is a (file, family) pair, the granularity of the
hand-labeled corpus in ``labels.json``: a migration inventory needs to know that
a file uses DSA, not to list every line that touches the key object. Each label
lists the lines that select, construct, import or implement that algorithm,
and the pair counts as detected when the scanner reports that family on one of
those lines (a finding on some other line, a comment say, earns nothing).

**What is labeled.** The families the scanner rates HIGH or MEDIUM: RSA, ECC
(any elliptic curve, including Ed25519/X25519/Ed448/X448), DSA, DH, MD5, SHA-1,
3DES, RC4 and TLS 1.0/1.1. The LOW families (SHA-256, AES-128, TLS 1.2) are not
quantum-broken and are left out. A line counts when executable code uses,
configures, selects or implements the algorithm, the same rule as the precision
labels; a line that only names it in a comment or message, or turns it off,
does not.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import sys
import tempfile
import warnings

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from precision_sample import _sdist  # noqa: E402
from realworld import _download, _extract  # noqa: E402
from quantumsafe.scanner import scan_path  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))
PINS = os.path.join(BASE, "precision_sample.json")
SETS = {
    "first": dict(seed=2026, sample="recall_sample.json", labels="recall_labels.json",
                  results="RESULTS-recall.md", title="first sample (seed 2026)",
                  preface=("**Read this first.** Scored blind with scanner 0.3.1, before any change, this sample "
                           "gave **19 / 28 = 68% recall (95% CI 49% to 82%)**. Its nine misses drove the recall fixes "
                           "listed in the CHANGELOG, so the table below re-scores the same files with the fixed "
                           "scanner and is optimistic by construction. The number for the current scanner is the "
                           "[held-out sample](RESULTS-recall-holdout.md).")),
    "holdout": dict(seed=2027, sample="recall_holdout_sample.json", labels="recall_holdout_labels.json",
                    results="RESULTS-recall-holdout.md", title="held-out sample (seed 2027)",
                    preface=("Drawn after the fixes prompted by the [first sample](RESULTS-recall.md), from files "
                             "not in it, and labeled before the scanner was run on any of them. This is the recall "
                             "figure to quote for the current scanner.")),
}
CACHE = os.environ.get("QSS_BENCH_CACHE", os.path.join(tempfile.gettempdir(), "qss-bench-cache"))
N = 40
FAMILIES = {"rsa", "ecc", "dsa", "dh", "md5", "sha1", "3des", "rc4", "tls_old"}
CRYPTO_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+(?:hashlib|hmac|ssl|cryptography|Crypto|Cryptodome|OpenSSL|nacl"
    r"|ecdsa|rsa|paramiko|jwt)\b", re.MULTILINE)


def _package_root(pkg: str, version: str) -> str:
    root = os.path.join(CACHE, f"{pkg}-{version}")
    if not os.path.isdir(root):
        _, url = _sdist(pkg, version)
        os.makedirs(root)
        _extract(_download(url), url, root)
    return root


def population(versions: dict[str, str]) -> list[dict]:
    files = []
    for pkg, version in sorted(versions.items()):
        root = _package_root(pkg, version)
        for dirpath, _, names in os.walk(root):
            for name in sorted(names):
                if not name.endswith(".py"):
                    continue
                path = os.path.join(dirpath, name)
                try:
                    src = open(path, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                if CRYPTO_IMPORT.search(src):
                    files.append({"package": pkg, "version": version,
                                  "path": os.path.relpath(path, root).replace(os.sep, "/"),
                                  "lines": src.count("\n") + 1})
    return files


def draw(which: str) -> None:
    cfg = SETS[which]
    out = os.path.join(BASE, cfg["sample"])
    versions = json.load(open(PINS, encoding="utf-8"))["versions"]
    pool = population(versions)
    pool_size = len(pool)
    prefix = "R"
    if which == "holdout":
        first = json.load(open(os.path.join(BASE, SETS["first"]["sample"]), encoding="utf-8"))["sample"]
        taken = {(f["package"], f["path"]) for f in first}
        pool = [f for f in pool if (f["package"], f["path"]) not in taken]
        prefix = "H"
    rng = random.Random(cfg["seed"])
    picked = sorted(rng.sample(pool, N), key=lambda f: (f["package"], f["path"]))
    for i, f in enumerate(picked, 1):
        f["id"] = f"{prefix}{i:02d}"
    json.dump({"seed": cfg["seed"], "pool_size": pool_size, "versions": versions, "sample": picked},
              open(out, "w", encoding="utf-8"), indent=2)
    print(f"population {pool_size} crypto-importing files; sampled {N} ({len(pool)} eligible) -> {out}")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return centre - half, centre + half


def score(which: str) -> int:
    cfg = SETS[which]
    sample = json.load(open(os.path.join(BASE, cfg["sample"]), encoding="utf-8"))
    labels = json.load(open(os.path.join(BASE, cfg["labels"]), encoding="utf-8"))
    hits, misses, total = 0, [], 0
    per_family: dict[str, list[int]] = {}
    for f in sample["sample"]:
        root = _package_root(f["package"], f["version"])
        path = os.path.join(root, f["path"])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            found = {(x.line_number, x.family) for x in scan_path(path)}
        found_lines: dict[str, set[int]] = {}
        for line, fam in found:
            found_lines.setdefault(fam, set()).add(line)
        for usage in labels[f["id"]]["usages"]:
            total += 1
            ok = bool(found_lines.get(usage["family"], set()) & set(usage["lines"]))
            hits += ok
            per_family.setdefault(usage["family"], [0, 0])
            per_family[usage["family"]][0] += ok
            per_family[usage["family"]][1] += 1
            if not ok:
                misses.append({**usage, "id": f["id"], "file": f"{f['package']}/{f['path']}"})
    lo, hi = wilson(hits, total)
    files_with = sum(1 for f in sample["sample"] if labels[f["id"]]["usages"])

    out = [
        f"# Recall on real code: {cfg['title']}",
        "",
        cfg["preface"],
        "",
        f"Generated by `python benchmark/recall_sample.py {'--holdout ' if which == 'holdout' else ''}--score`."
        " Method and labeling rules:",
        "the module docstring of [`recall_sample.py`](recall_sample.py); every label, with its",
        f"reason, is in [`{cfg['labels']}`]({cfg['labels']}).",
        "",
        f"Population: {sample['pool_size']:,} Python files that import a crypto-capable module, in "
        f"{len(sample['versions'])} pinned PyPI packages. Sample: {len(sample['sample'])} files "
        f"(seed {sample['seed']}), {files_with} of which contain at least one quantum-vulnerable usage.",
        "",
        "| Labeled (file, family) usages | Detected | Missed | Recall | 95% CI (Wilson) |",
        "|--:|--:|--:|--:|--:|",
        f"| {total} | {hits} | {total - hits} | **{hits / total:.0%}** | {lo:.0%} to {hi:.0%} |",
        "",
        "Usages are not independent (one file can hold several families), so the interval is a guide,",
        "not an exact bound.",
        "",
        "| Family | Detected / labeled |",
        "|---|--:|",
    ]
    out += [f"| {fam} | {k} / {n} |" for fam, (k, n) in sorted(per_family.items())]
    out += ["", "## Every miss", ""]
    out += [f"- `{m['file']}` lines {', '.join(map(str, m['lines']))} ({m['family']}): {m['why']}"
            for m in misses] or ["None."]
    if labels.get("_note"):
        out += ["", labels["_note"]]
    open(os.path.join(BASE, cfg["results"]), "w", encoding="utf-8").write("\n".join(out) + "\n")
    print("\n".join(line for line in out if line.startswith("| ") and "%" in line))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--holdout", action="store_true", help="use the held-out sample (seed 2027)")
    args = ap.parse_args(argv)
    which = "holdout" if args.holdout else "first"
    if args.score:
        return score(which)
    draw(which)
    return 0


if __name__ == "__main__":
    sys.exit(main())
