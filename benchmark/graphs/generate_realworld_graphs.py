"""Render charts from the real-world PyPI benchmark (`benchmark/realworld.py`).

Reads the committed ``benchmark/realworld.json`` (so it's fast and reproducible
from data, not a re-scan) and writes two figures next to this file:

    1. realworld_by_family.png    findings per crypto family, colored by risk tier
    2. realworld_top_packages.png the packages with the most HIGH-risk findings

Usage:
    pip install matplotlib        # standalone reporting tool, not a core dependency
    python benchmark/graphs/generate_realworld_graphs.py
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
ROOT = os.path.dirname(BENCH)
DATA = os.path.join(BENCH, "realworld.json")

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("matplotlib is required for the charts.\nInstall it with:  pip install matplotlib")

# Same palette as generate_graphs.py, aligned with the dashboard's risk colors.
C_HIGH = "#ff5c7a"
C_MED = "#ffb347"
C_LOW = "#2fe6a8"

# Each detection family's inherent risk tier, used to color the bars.
_TIER = {
    "rsa": C_HIGH, "ecc": C_HIGH, "dsa": C_HIGH, "dh": C_HIGH,
    "md5": C_HIGH, "sha1": C_HIGH,
    "3des": C_MED, "rc4": C_MED, "tls_old": C_MED,
    "sha256": C_LOW, "aes128": C_LOW, "tls12": C_LOW,
}


def _load() -> dict:
    if not os.path.exists(DATA):
        sys.exit(f"{DATA} not found — run `python benchmark/realworld.py` first.")
    with open(DATA, encoding="utf-8") as fh:
        return json.load(fh)


def chart_by_family(data: dict) -> str:
    fam_totals = data["summary"]["family_totals"]
    fams = list(fam_totals.keys())[::-1]  # ascending for horizontal bars
    vals = [fam_totals[f] for f in fams]
    colors = [_TIER.get(f, C_MED) for f in fams]

    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh(fams, vals, color=colors, edgecolor="#0b1020")
    n = data["summary"]["packages_scanned"]
    ax.set_title(f"Quantum-vulnerable crypto across {n} popular PyPI packages",
                 fontweight="bold")
    ax.set_xlabel("Findings (file:line occurrences)")
    for i, v in enumerate(vals):
        ax.text(v + max(vals) * 0.01, i, f"{v:,}", va="center", fontsize=9)
    ax.margins(x=0.12)
    # Legend for the risk tiers.
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in (C_HIGH, C_MED, C_LOW)]
    ax.legend(handles, ["HIGH (Shor-breakable)", "MEDIUM", "LOW (Grover-weakened)"],
              loc="lower right", frameon=False, fontsize=9)
    fig.tight_layout()
    out = os.path.join(HERE, "realworld_by_family.png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return out


def chart_top_packages(data: dict, top: int = 12) -> str:
    pkgs = [p for p in data["packages"] if p["high"] > 0]
    pkgs.sort(key=lambda p: p["high"], reverse=True)
    pkgs = pkgs[:top][::-1]
    names = [p["package"] for p in pkgs]
    highs = [p["high"] for p in pkgs]

    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh(names, highs, color=C_HIGH, edgecolor="#0b1020")
    ax.set_title(f"Packages with the most HIGH-risk findings (top {top})",
                 fontweight="bold")
    ax.set_xlabel("HIGH-risk findings")
    for i, v in enumerate(highs):
        ax.text(v + max(highs) * 0.01, i, f"{v:,}", va="center", fontsize=9)
    ax.margins(x=0.12)
    fig.tight_layout()
    out = os.path.join(HERE, "realworld_top_packages.png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return out


def main() -> None:
    data = _load()
    s = data["summary"]
    print(f"Loaded {s['packages_scanned']} packages, {s['total_findings']:,} findings")
    for fn in (chart_by_family(data), chart_top_packages(data)):
        print(f"  wrote {os.path.relpath(fn, ROOT)}")


if __name__ == "__main__":
    main()
