"""Real-world benchmark: scan the latest release of popular PyPI packages.

``evaluate.py`` measures **precision/recall** on a small *labeled* corpus. This
harness answers a different, complementary question: **what does QuantumSafe
actually find in real, widely-used production code?**

For each package it downloads the source distribution (sdist) straight from the
PyPI JSON API — no build step, no dependencies installed, nothing executed —
extracts it, runs the scanner, and aggregates the findings.

    python benchmark/realworld.py                 # default curated package set
    python benchmark/realworld.py --limit 10      # only the first N packages
    python benchmark/realworld.py flask paramiko  # explicit packages
    python benchmark/realworld.py --json out.json --md RESULTS-realworld.md

The Markdown summary is written to ``benchmark/RESULTS-realworld.md`` and the
raw data to ``benchmark/realworld.json`` so the numbers are reproducible, not
asserted. Because these are *unlabeled* real packages, findings are reported as
discoveries (with file/line provenance) rather than scored against ground truth;
QuantumSafe's precision on labeled decoys is documented separately in RESULTS.md.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tarfile
import tempfile
import urllib.request
import warnings
import zipfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from quantumsafe import reporter  # noqa: E402
from quantumsafe.scanner import scan_path  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))

# Curated set of widely-used packages spanning web, crypto, cloud, data and
# infra. Chosen for real-world relevance and download volume, with a deliberate
# lean toward code that touches transport security, signing, and hashing — the
# places legacy quantum-vulnerable primitives actually live.
DEFAULT_PACKAGES = [
    "requests", "urllib3", "flask", "werkzeug", "django", "aiohttp",
    "paramiko", "pyjwt", "oauthlib", "requests-oauthlib", "pyopenssl",
    "cryptography", "pycryptodome", "rsa", "ecdsa", "passlib", "bcrypt",
    "itsdangerous", "boto3", "botocore", "sqlalchemy", "redis", "pymongo",
    "elasticsearch", "celery", "tornado", "scrapy", "twisted", "pip",
    "setuptools", "docker", "kubernetes", "jinja2",
    "certifi", "httpx", "websockets", "pyyaml",
]

PYPI_JSON = "https://pypi.org/pypi/{pkg}/json"
_UA = {"User-Agent": "quantumsafe-benchmark/1.0 (+https://github.com/Danny-397/Quantum-Safe)"}


def _sdist_url(pkg: str) -> tuple[str, str]:
    """Return (version, sdist_download_url) for a package's latest release."""
    req = urllib.request.Request(PYPI_JSON.format(pkg=pkg), headers=_UA)
    with urllib.request.urlopen(req, timeout=30) as resp:
        meta = json.load(resp)
    version = meta["info"]["version"]
    for entry in meta.get("urls", []):
        if entry.get("packagetype") == "sdist":
            return version, entry["url"]
    raise RuntimeError(f"no sdist available for {pkg} {version}")


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def _extract(blob: bytes, url: str, dest: str) -> None:
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            zf.extractall(dest)  # noqa: S202 - trusted PyPI artifacts, benchmark-only
    else:  # .tar.gz / .tgz
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
            try:
                tf.extractall(dest, filter="data")  # 3.12+: reject unsafe members
            except TypeError:
                tf.extractall(dest)  # noqa: S202 - older Python; trusted PyPI artifact


def _count_py(root: str) -> int:
    n = 0
    for _, _, files in os.walk(root):
        n += sum(1 for f in files if f.endswith(".py"))
    return n


def scan_package(pkg: str, taint: bool = False) -> dict:
    """Download, extract and scan one package. Returns a summary dict."""
    version, url = _sdist_url(pkg)
    blob = _download(url)
    with tempfile.TemporaryDirectory(prefix="qsbench_") as tmp:
        _extract(blob, url, tmp)
        py_files = _count_py(tmp)
        # Some packages contain source with invalid escape sequences etc; the
        # scanner handles them fine, we just don't want the parse warnings.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            findings = scan_path(tmp, taint=taint)
        report = reporter.build_report(findings, pkg)

    # File paths in findings are temp-absolute; keep only the tail for display.
    fam_counts: dict[str, int] = {}
    examples: list[dict] = []
    for f in findings:
        fam_counts[f.family] = fam_counts.get(f.family, 0) + 1
    for f in sorted(findings, key=lambda x: (x.risk_level != "HIGH", x.family))[:5]:
        rel = f.file_path.replace(os.sep, "/")
        rel = rel[rel.find(pkg.replace("-", "_")):] if pkg.replace("-", "_") in rel else os.path.basename(rel)
        examples.append({"algorithm": f.algorithm, "risk": f.risk_level,
                         "file": rel, "line": f.line_number})

    s = report["summary"]
    return {
        "package": pkg,
        "version": version,
        "py_files": py_files,
        "risk_score": report["risk_score"],
        "total": len(findings),
        "high": s["high"], "medium": s["medium"], "low": s["low"],
        "families": dict(sorted(fam_counts.items(), key=lambda kv: -kv[1])),
        "examples": examples,
    }


def _aggregate(rows: list[dict]) -> dict:
    fam_totals: dict[str, int] = {}
    for r in rows:
        for fam, n in r["families"].items():
            fam_totals[fam] = fam_totals.get(fam, 0) + n
    return {
        "packages_scanned": len(rows),
        "packages_with_findings": sum(1 for r in rows if r["total"] > 0),
        "total_py_files": sum(r["py_files"] for r in rows),
        "total_findings": sum(r["total"] for r in rows),
        "total_high": sum(r["high"] for r in rows),
        "family_totals": dict(sorted(fam_totals.items(), key=lambda kv: -kv[1])),
    }


def _to_markdown(rows: list[dict], agg: dict, generated_at: str) -> str:
    rows_sorted = sorted(rows, key=lambda r: (-r["high"], -r["total"], r["package"]))
    fam_line = ", ".join(f"`{fam}` ×{n}" for fam, n in agg["family_totals"].items()) or "none"
    out = [
        "# Real-world benchmark",
        "",
        "Generated by [`realworld.py`](realworld.py) — it downloads the latest "
        "sdist of each package from the PyPI JSON API, extracts it, and runs the "
        "real scanner. Nothing is built or executed. Reproduce with:",
        "",
        "```bash",
        "python benchmark/realworld.py",
        "```",
        "",
        f"_Generated: {generated_at} · scanner reports file/line for every finding._",
        "",
        "> These are **real, widely-used packages**, not a labeled corpus, so the "
        "numbers below are *discoveries*, not precision/recall. Every finding is a "
        "concrete file:line an auditor can open. QuantumSafe's measured precision "
        "on adversarial decoys is in [RESULTS.md](RESULTS.md).",
        "",
        "## Summary",
        "",
        f"- **Packages scanned:** {agg['packages_scanned']}",
        f"- **Packages with findings:** {agg['packages_with_findings']}",
        f"- **Python files analyzed:** {agg['total_py_files']:,}",
        f"- **Total findings:** {agg['total_findings']:,} "
        f"({agg['total_high']:,} HIGH-risk)",
        f"- **By family:** {fam_line}",
        "",
        "## Per-package results",
        "",
        "| Package | Version | .py files | Score | HIGH | MED | LOW | Top families |",
        "|---|---|--:|--:|--:|--:|--:|---|",
    ]
    for r in rows_sorted:
        fams = ", ".join(f"{k} ×{v}" for k, v in list(r["families"].items())[:4]) or "—"
        out.append(
            f"| {r['package']} | {r['version']} | {r['py_files']:,} | "
            f"{r['risk_score']} | {r['high']} | {r['medium']} | {r['low']} | {fams} |"
        )
    # A few concrete examples for credibility.
    out += ["", "## Example findings (file:line)", ""]
    shown = 0
    for r in rows_sorted:
        if not r["examples"] or shown >= 12:
            continue
        for ex in r["examples"][:2]:
            out.append(f"- **{r['package']}** — `{ex['algorithm']}` "
                       f"({ex['risk']}) at `{ex['file']}:{ex['line']}`")
            shown += 1
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan popular PyPI packages with QuantumSafe.")
    ap.add_argument("packages", nargs="*", help="Explicit packages (default: curated set).")
    ap.add_argument("--limit", type=int, default=None, help="Only scan the first N packages.")
    ap.add_argument("--taint", action="store_true", help="Enable data-flow (taint) analysis.")
    ap.add_argument("--json", default=os.path.join(BASE, "realworld.json"),
                    help="Path for the machine-readable JSON report.")
    ap.add_argument("--md", default=os.path.join(BASE, "RESULTS-realworld.md"),
                    help="Path for the Markdown report.")
    args = ap.parse_args(argv)

    packages = args.packages or DEFAULT_PACKAGES
    if args.limit:
        packages = packages[: args.limit]

    rows: list[dict] = []
    for i, pkg in enumerate(packages, 1):
        print(f"[{i}/{len(packages)}] {pkg} ...", end=" ", flush=True)
        try:
            row = scan_package(pkg, taint=args.taint)
        except Exception as exc:  # network / archive / parse issues: skip, keep going
            print(f"skipped ({exc})")
            continue
        rows.append(row)
        print(f"{row['py_files']} .py files, {row['total']} findings "
              f"({row['high']} HIGH), score {row['risk_score']}")

    if not rows:
        print("No packages scanned successfully.", file=sys.stderr)
        return 1

    agg = _aggregate(rows)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    payload = {"generated_at": generated_at, "summary": agg, "packages": rows}
    with open(args.json, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    md = _to_markdown(rows, agg, generated_at)
    with open(args.md, "w", encoding="utf-8") as fh:
        fh.write(md)

    print("\n" + "=" * 60)
    print(f"{agg['packages_with_findings']}/{agg['packages_scanned']} packages had "
          f"findings · {agg['total_findings']} total ({agg['total_high']} HIGH) "
          f"across {agg['total_py_files']:,} .py files")
    print(f"Wrote {args.json} and {args.md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
