"""Generate benchmark visualizations from LIVE scanner data.

This script runs the real QuantumSafe scanner over the labeled corpus and over
size-scaled copies of it, then renders three charts. Nothing is hardcoded — the
numbers come from an actual scan, so the figures stay honest if the corpus or the
detector changes.

Charts produced (written next to this file):
    1. vulnerabilities_by_type.png   bar chart  — findings per crypto family
    2. severity_distribution.png     pie chart  — HIGH / MEDIUM / LOW
    3. scan_time_vs_size.png         line chart — scan time vs. number of files

Usage:
    pip install matplotlib        # optional; NOT a core/CI dependency
    python benchmark/graphs/generate_graphs.py

matplotlib is deliberately kept out of the project's core requirements; this is a
standalone reporting tool, so the main package stays dependency-light.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from collections import Counter

# Make the `quantumsafe` package importable when run from the repo root.
HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
ROOT = os.path.dirname(BENCH)
sys.path.insert(0, ROOT)

try:
    import matplotlib

    matplotlib.use("Agg")  # headless: write files, never open a window
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit(
        "matplotlib is required for the charts.\n"
        "Install it with:  pip install matplotlib"
    )

from quantumsafe.scanner import (  # noqa: E402
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    scan_path,
)

POSITIVE = os.path.join(BENCH, "positive")

# Consistent palette aligned with the dashboard's risk colors.
C_HIGH = "#ff5c7a"
C_MED = "#ffb347"
C_LOW = "#2fe6a8"
C_BAR = "#34d6ff"


def _scan_positive():
    """Run the real scanner over the known-vulnerable corpus."""
    return list(scan_path(POSITIVE))


def chart_by_type(findings) -> str:
    counts = Counter(f.family.upper() for f in findings)
    families = [fam for fam, _ in counts.most_common()]
    values = [counts[fam] for fam in families]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(families, values, color=C_BAR, edgecolor="#0b1020")
    ax.set_title("Detected vulnerabilities by cryptographic family", fontweight="bold")
    ax.set_ylabel("Findings")
    ax.set_xlabel("Crypto family")
    for i, v in enumerate(values):
        ax.text(i, v + 0.05, str(v), ha="center", va="bottom", fontsize=9)
    ax.margins(y=0.15)
    fig.tight_layout()
    out = os.path.join(HERE, "vulnerabilities_by_type.png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return out


def chart_severity(findings) -> str:
    sev = Counter(f.risk_level for f in findings)
    order = [(RISK_HIGH, C_HIGH), (RISK_MEDIUM, C_MED), (RISK_LOW, C_LOW)]
    labels, sizes, colors = [], [], []
    for level, color in order:
        n = sev.get(level, 0)
        if n:
            labels.append(f"{level} ({n})")
            sizes.append(n)
            colors.append(color)

    fig, ax = plt.subplots(figsize=(6, 6))
    ax.pie(sizes, labels=labels, colors=colors, autopct="%1.0f%%",
           startangle=90, wedgeprops={"edgecolor": "#0b1020"})
    ax.set_title("Finding severity distribution", fontweight="bold")
    ax.axis("equal")
    fig.tight_layout()
    out = os.path.join(HERE, "severity_distribution.png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return out


def chart_scan_time() -> str:
    """Time real scans over corpora of increasing file counts."""
    src_files = [
        os.path.join(POSITIVE, f)
        for f in os.listdir(POSITIVE)
        if os.path.isfile(os.path.join(POSITIVE, f))
    ]
    multipliers = [1, 4, 8, 16, 32, 64]
    sizes, times = [], []

    for m in multipliers:
        tmp = tempfile.mkdtemp(prefix="qs_bench_")
        try:
            count = 0
            for i in range(m):
                for path in src_files:
                    base = os.path.basename(path)
                    shutil.copyfile(path, os.path.join(tmp, f"{i}_{base}"))
                    count += 1
            t0 = time.perf_counter()
            scan_path(tmp)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            sizes.append(count)
            times.append(elapsed_ms)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(sizes, times, marker="o", color=C_BAR, linewidth=2)
    ax.set_title("Scan time vs. number of files", fontweight="bold")
    ax.set_xlabel("Files scanned")
    ax.set_ylabel("Scan time (ms)")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    out = os.path.join(HERE, "scan_time_vs_size.png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return out


def main() -> None:
    findings = _scan_positive()
    print(f"Scanned corpus: {len(findings)} findings")
    for fn in (chart_by_type(findings), chart_severity(findings), chart_scan_time()):
        print(f"  wrote {os.path.relpath(fn, ROOT)}")


if __name__ == "__main__":
    main()
