"""Output formatting: terminal table, JSON, and standalone HTML report.

``build_report`` produces the canonical report dict that every output format —
and the backend API — is built from, so the CLI and dashboard always agree.
"""

from __future__ import annotations

import datetime as _dt
import html
import json

from . import __version__
from .scanner import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Finding
from .scorer import band_message, calculate_score, count_by_severity, risk_band

_RISK_ORDER = {RISK_HIGH: 0, RISK_MEDIUM: 1, RISK_LOW: 2}
# Reachability ranking: reachable/unlabeled first, then test/example, then dead code.
_REACH_ORDER = {"reachable": 0, "": 0, "test/example": 1, "unreferenced": 2}
_RISK_COLOR = {RISK_HIGH: "red", RISK_MEDIUM: "yellow", RISK_LOW: "green"}
_BAND_COLOR = {"Low": "green", "Medium": "yellow", "High": "red", "Critical": "red"}


def build_report(
    findings: list[Finding],
    target: str,
    endpoint: dict | None = None,
    secrecy_years: float | None = None,
    crqc_years: float | None = None,
) -> dict:
    """Assemble the canonical report structure from real findings.

    ``secrecy_years`` opts in to the Mosca's-inequality assessment (see
    :mod:`horizon`): how long the migration takes measured against how long
    the data has to stay confidential. It is absent from the report unless
    asked for, because it needs an input only the caller knows.
    """
    score = calculate_score(findings)
    band = risk_band(score)
    counts = count_by_severity(findings)
    # Rank by risk, then by reachability (exploitable findings surface first when
    # reachability ranking was requested), then by location for stable output.
    ordered = sorted(
        findings,
        key=lambda f: (_RISK_ORDER.get(f.risk_level, 9),
                       _REACH_ORDER.get(f.reachability, 0),
                       f.file_path, f.line_number),
    )
    report = {
        "tool": "quantumsafe",
        "version": __version__,
        "target": target,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "risk_score": score,
        "risk_band": band,
        "risk_message": band_message(band),
        "summary": {
            "total_findings": len(findings),
            "high": counts[RISK_HIGH],
            "medium": counts[RISK_MEDIUM],
            "low": counts[RISK_LOW],
        },
        "findings": [f.to_dict() for f in ordered],
    }
    if endpoint:
        report["endpoint"] = endpoint
    if secrecy_years is not None:
        from .horizon import assess
        report["horizon"] = assess(findings, secrecy_years, crqc_years).to_dict()
    return report


# --------------------------------------------------------------------------- #
# Terminal
# --------------------------------------------------------------------------- #


def print_terminal(report: dict) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
    except ImportError:  # graceful fallback if rich is unavailable
        _print_plain(report)
        return

    console = Console()
    score = report["risk_score"]
    band = report["risk_band"]
    color = _BAND_COLOR.get(band, "white")

    console.print(
        Panel(
            f"[bold {color}]Quantum Risk Score: {score}/100  ({band})[/bold {color}]\n"
            f"{report['risk_message']}\n\n"
            f"Target: {report['target']}\n"
            f"[red]HIGH: {report['summary']['high']}[/red]   "
            f"[yellow]MEDIUM: {report['summary']['medium']}[/yellow]   "
            f"[green]LOW: {report['summary']['low']}[/green]   "
            f"Total: {report['summary']['total_findings']}",
            title="QuantumSafe Scan",
            border_style=color,
        )
    )

    _print_endpoint(console, report.get("endpoint"))

    if not report["findings"]:
        console.print("[green]No quantum-vulnerable cryptography detected.[/green]")
        return

    table = Table(show_lines=False, header_style="bold")
    table.add_column("File", style="cyan", no_wrap=False, max_width=40)
    table.add_column("Line", justify="right")
    table.add_column("Algorithm")
    table.add_column("Risk")
    table.add_column("Recommendation", max_width=44)

    for f in report["findings"]:
        rc = _RISK_COLOR.get(f["risk_level"], "white")
        table.add_row(
            _location(f),
            str(f["line_number"]),
            f["algorithm"],
            f"[{rc}]{f['risk_level']}[/{rc}]",
            f["recommendation"],
        )
    console.print(table)
    _print_horizon(console, report.get("horizon"))


def _sarif_location(f: dict) -> dict:
    """One SARIF location for a finding.

    A code finding is a file and a line. A live-endpoint finding is neither,
    and pretending otherwise produces output a SARIF consumer acts on wrongly:
    GitHub code scanning would try to annotate line 1 of a file literally named
    "github.com [leaf certificate]", which does not exist. The previous
    `max(1, line_number)` also invented a line number for findings whose line
    is genuinely 0.

    So endpoint findings get the real https URI as the artifact -- which is a
    valid URI, unlike a bare hostname with a bracketed suffix -- no region at
    all, and the certificate position as a logicalLocation.
    """
    if f.get("origin") != "endpoint":
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": f["file_path"]},
                "region": {"startLine": max(1, f["line_number"])},
            }
        }

    raw = f.get("file_path") or ""
    host, _, bracket = raw.partition(" [")
    location = {
        "physicalLocation": {"artifactLocation": {"uri": f"https://{host}"}},
    }
    if bracket:
        location["logicalLocations"] = [{
            "name": bracket.rstrip("]"),
            "kind": "member",
        }]
    return location


def print_diff(d: dict) -> None:
    """Render a diff between two scans (see :mod:`diff`)."""
    try:
        from rich.console import Console
    except ImportError:
        print(f"\nSince baseline: {d['summary']}")
        for f in d["new"]:
            print(f"  NEW   {f.get('file_path')}:{f.get('line_number')} "
                  f"{f.get('algorithm')}")
        return

    console = Console()
    counts = d["counts"]
    if d["regressed"]:
        verdict, colour = "REGRESSED", "red"
    elif d["improved"]:
        verdict, colour = "IMPROVED", "green"
    else:
        verdict, colour = "UNCHANGED", "cyan"

    console.print()
    console.print(f"[bold]Since baseline[/bold]  [{colour}]{verdict}[/{colour}]")
    if d["target"]["mismatch"]:
        console.print(f"  [yellow]Warning: baseline scanned "
                      f"{d['target']['before']!r} but this scan is "
                      f"{d['target']['after']!r}; the comparison may be "
                      f"meaningless.[/yellow]")
    console.print(f"  [green]{counts['fixed']} fixed[/green]   "
                  f"[red]{counts['new']} new[/red]   "
                  f"{counts['unchanged']} unchanged   "
                  f"score {d['risk_score']['before']} -> "
                  f"{d['risk_score']['after']} "
                  f"({d['risk_score']['delta']:+d})")

    for label, colour, items in (("NEW", "red", d["new"]),
                                 ("FIXED", "green", d["fixed"])):
        for f in items[:12]:
            loc = f.get("file_path", "?")
            line = f.get("line_number")
            where = f"{loc}:{line}" if line else loc
            console.print(f"  [{colour}]{label:<5}[/{colour}] {where}  "
                          f"{f.get('algorithm', '?')} [{f.get('risk_level', '?')}]")
        if len(items) > 12:
            console.print(f"  [dim]... and {len(items) - 12} more {label.lower()}[/dim]")

    console.print(f"  [dim]{d['caveat']}[/dim]")


def _print_endpoint(console, e: dict | None) -> None:
    """Render what the TLS handshake actually negotiated."""
    if not e:
        return
    pq = e.get("key_exchange_post_quantum")
    kex_color = "green" if pq else "red"
    label = "post-quantum hybrid" if pq else "classical"

    console.print()
    console.print(f"[bold]TLS handshake[/bold]  {e['host']}:{e['port']}  "
                  f"[dim]({', '.join(e.get('addresses', []))})[/dim]")
    console.print(f"  Key exchange   : [{kex_color}]{e['key_exchange']}[/{kex_color}] "
                  f"({label})")
    console.print(f"  Protocol       : {e.get('protocol') or 'unknown'}")
    console.print(f"  Cipher         : {e.get('cipher') or 'unknown'} "
                  f"({e.get('symmetric_bits')}-bit symmetric)")
    cert = e.get("certificate") or {}
    if cert:
        console.print(f"  Certificate    : {cert.get('subject') or '(see SAN)'} "
                      f"issued by {cert.get('issuer') or 'unknown'}, "
                      f"expires {cert.get('not_after') or 'unknown'}")
    console.print(f"  [dim]Key exchange read via {e.get('key_exchange_observed_via')}; "
                  "this is the group the server selects from what we offer, "
                  "not everything it could support.[/dim]")

    chain = e.get("chain") or []
    if chain:
        console.print()
        console.print("[bold]Certificate chain[/bold] "
                      "[dim](a chain is only as strong as its weakest "
                      "signature)[/dim]")
        for c in chain:
            if "error" in c:
                console.print(f"  {c['role']:<13} [yellow]unparseable: "
                              f"{c['error']}[/yellow]")
                continue
            key = c.get("key_algorithm", "?")
            if c.get("key_curve"):
                key += f" {c['key_curve']}"
            elif c.get("key_bits"):
                key += f"-{c['key_bits']}"
            safe = c.get("signature_post_quantum") or c.get("key_post_quantum")
            # A root is trusted via the client's trust store, not its own
            # self-signature, so it is shown without a risk colour.
            if c["role"] == "root":
                colour = "dim"
                note = ("  [dim](trust-store anchored; its own signature is "
                        "not a forgery risk)[/dim]")
            else:
                colour = "green" if safe else "red"
                note = ""
            console.print(f"  [{colour}]{c['role']:<13}[/{colour}] "
                          f"sig={c.get('signature', '?'):<22} key={key}{note}")


_HORIZON_COLOR = {
    "already_late": "red",
    "at_risk": "yellow",
    "on_track": "green",
    "no_verdict": "cyan",
}


def _print_horizon(console, h: dict | None) -> None:
    """Render the Mosca assessment, if one was requested."""
    if not h:
        return
    y = h["migration_years"]
    be = h["breakeven_year"]
    color = _HORIZON_COLOR.get(h["verdict"], "white")

    console.print()
    console.print("[bold]Migration horizon[/bold] (Mosca's inequality)")
    console.print(f"  Data must stay confidential (X) : {h['secrecy_years']:g} years")
    console.print(f"  Estimated migration (Y)         : {y['low']:g}-{y['high']:g} years")
    if h["crqc_years"] is not None:
        console.print(f"  Assumed quantum threat (Z)      : {h['crqc_years']:g} years")
    else:
        console.print("  Assumed quantum threat (Z)      : not supplied")
    # X + Y: the deadline, and the only figure here that needs no guess about Z.
    if be["low"] == be["high"]:
        console.print(f"  Break-even year                 : {be['low']}")
    else:
        console.print(f"  Break-even year                 : {be['low']}-{be['high']}")
    console.print(f"  [{color}]{h['verdict'].replace('_', ' ').upper()}[/{color}] "
                  f"{h['message']}")
    if h["asymmetric_families"]:
        console.print(f"  Design changes needed           : "
                      f"{', '.join(h['asymmetric_families'])}")
    console.print("  [dim]Estimate rests on stated assumptions; see "
                  "\"assumptions\" in the JSON report.[/dim]")


def _location(f: dict) -> str:
    """File location, annotated with the package name for dependency findings so
    a library's *capability* exposure is never mistaken for first-party usage."""
    if f.get("origin") == "dependency" and f.get("component"):
        scope = f.get("scope")
        tag = f"dep: {f['component']}" + (f", {scope}" if scope else "")
        return f"{f['file_path']} [{tag}]"
    reach = f.get("reachability")
    if reach in ("test/example", "unreferenced"):
        return f"{f['file_path']} [{reach}]"
    return f["file_path"]


def _print_plain(report: dict) -> None:
    print(f"QuantumSafe Scan — {report['target']}")
    print(f"Quantum Risk Score: {report['risk_score']}/100 ({report['risk_band']}) — {report['risk_message']}")
    print(f"HIGH={report['summary']['high']} MEDIUM={report['summary']['medium']} "
          f"LOW={report['summary']['low']} TOTAL={report['summary']['total_findings']}")
    print("-" * 80)
    for f in report["findings"]:
        print(f"{f['risk_level']:<6} {_location(f)}:{f['line_number']}  "
              f"{f['algorithm']} -> {f['recommendation']}")


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #


_CBOM_PRIMITIVE = {
    "rsa": "pke", "ecc": "signature", "dsa": "signature", "dh": "key-agree",
    "md5": "hash", "sha1": "hash", "sha256": "hash",
    "3des": "block-cipher", "rc4": "stream-cipher", "aes128": "block-cipher",
    "tls_old": "other", "tls12": "other",
}


def to_cbom(report: dict) -> str:
    """Render findings as a CycloneDX 1.6 Cryptography Bill of Materials (CBOM).

    Detected algorithms become ``cryptographic-asset`` components with their
    file/line occurrences as evidence. Quantum-vulnerable third-party packages
    (``origin == "dependency"``) additionally become ``library`` components
    carrying a package URL (purl), and a ``dependencies`` graph links each
    library to the crypto assets it provides — so the CBOM captures not just the
    algorithms a project names but the libraries that ship them, which is what
    post-quantum inventory (NIST IR 8547) actually asks for.
    """
    findings = report["findings"]

    # 1. Algorithm crypto-assets, grouped by algorithm across both origins.
    algo_groups: dict[str, dict] = {}
    for f in findings:
        g = algo_groups.setdefault(f["algorithm"], {"finding": f, "occ": []})
        g["occ"].append({"location": f["file_path"], "line": f["line_number"]})

    components: list[dict] = []
    algo_ref: dict[str, str] = {}
    for i, (algo, g) in enumerate(algo_groups.items()):
        f = g["finding"]
        ref = f"crypto-{i}"
        algo_ref[algo] = ref
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": algo,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": _CBOM_PRIMITIVE.get(f["family"], "other"),
                    "nistQuantumSecurityLevel": 0 if f["risk_level"] == RISK_HIGH else 1,
                },
            },
            "evidence": {"occurrences": g["occ"]},
            "properties": [
                {"name": "quantumsafe:risk", "value": f["risk_level"]},
                {"name": "quantumsafe:recommendation", "value": f["recommendation"]},
                {"name": "quantumsafe:nist", "value": f["nist_reference"]},
            ],
        })

    # 2. Dependency libraries, grouped by purl (falling back to name@version).
    lib_groups: dict[str, dict] = {}
    for f in findings:
        if f.get("origin") != "dependency":
            continue
        key = f.get("purl") or f"{f.get('component', '')}@{f.get('version', '')}"
        lib = lib_groups.setdefault(key, {
            "component": f.get("component", ""),
            "version": f.get("version", ""),
            "purl": f.get("purl", ""),
            "scope": f.get("scope", ""),
            "risk": f["risk_level"],
            "algos": set(),
            "occ": [],
        })
        lib["algos"].add(f["algorithm"])
        lib["occ"].append({"location": f["file_path"], "line": f["line_number"]})
        if _RISK_ORDER.get(f["risk_level"], 9) < _RISK_ORDER.get(lib["risk"], 9):
            lib["risk"] = f["risk_level"]

    dependencies: list[dict] = []
    for j, (_key, lib) in enumerate(lib_groups.items()):
        ref = f"lib-{j}"
        comp: dict = {
            "type": "library",
            "bom-ref": ref,
            "name": lib["component"],
            "evidence": {"occurrences": lib["occ"]},
            "properties": [
                {"name": "quantumsafe:origin", "value": "dependency"},
                {"name": "quantumsafe:scope", "value": lib["scope"] or "direct"},
                {"name": "quantumsafe:risk", "value": lib["risk"]},
                {"name": "quantumsafe:providesQuantumVulnerable",
                 "value": ", ".join(sorted(lib["algos"]))},
            ],
        }
        if lib["version"]:
            comp["version"] = lib["version"]
        if lib["purl"]:
            comp["purl"] = lib["purl"]
        components.append(comp)
        # Link the library to the crypto-asset components it provides.
        provides = sorted({algo_ref[a] for a in lib["algos"] if a in algo_ref})
        if provides:
            dependencies.append({"ref": ref, "provides": provides})

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": report.get("generated_at", ""),
            "tools": {"components": [{"type": "application", "name": "QuantumSafe",
                                      "version": report.get("version", "")}]},
            "component": {"type": "application", "name": report.get("target", "scan")},
            "properties": [{"name": "quantumsafe:riskScore",
                            "value": str(report.get("risk_score", 0))}],
        },
        "components": components,
    }
    if dependencies:
        cbom["dependencies"] = dependencies
    return json.dumps(cbom, indent=2)


def to_badge_svg(report: dict) -> str:
    """Render a shields-style SVG badge of the quantum risk score (embeddable)."""
    score = report["risk_score"]
    band = report["risk_band"]
    color = {"Low": "#00FF88", "Medium": "#FFB800", "High": "#FF4444", "Critical": "#FF4444"}.get(band, "#888")
    label = "quantum risk"
    value = f"{score}/100 {band}"
    # Approximate text widths (~6.5px/char + padding).
    lw = int(len(label) * 6.5) + 12
    vw = int(len(value) * 6.5) + 14
    total = lw + vw
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{label}: {value}">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <rect width="{total}" height="20" rx="3" fill="#1c1c26"/>
  <rect x="{lw}" width="{vw}" height="20" rx="3" fill="{color}"/>
  <rect x="{lw}" width="6" height="20" fill="{color}"/>
  <rect width="{total}" height="20" rx="3" fill="url(#s)"/>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="11">
    <text x="{lw/2}" y="14" fill="#E0E0E0">{label}</text>
    <text x="{lw + vw/2}" y="14" fill="#0A0A0F" font-weight="bold">{value}</text>
  </g>
</svg>'''


def to_sarif(report: dict) -> str:
    """Render findings as SARIF 2.1.0 — the format GitHub code scanning ingests.

    Uploading this (e.g. via github/codeql-action/upload-sarif) makes QuantumSafe
    findings appear in a repository's Security tab.
    """
    level_map = {RISK_HIGH: "error", RISK_MEDIUM: "warning", RISK_LOW: "note"}
    severity_map = {RISK_HIGH: "9.0", RISK_MEDIUM: "5.0", RISK_LOW: "3.0"}

    # One SARIF rule per detection family.
    rules: list[dict] = []
    seen: set[str] = set()
    for f in report["findings"]:
        if f["family"] in seen:
            continue
        seen.add(f["family"])
        fix = f.get("fix") or {}
        help_text = f"{f['why']} Recommended replacement: {f['recommendation']} ({f['nist_reference']})."
        if fix.get("action"):
            help_text += f" Fix: {fix['action']}"
            if fix.get("before") and fix.get("after"):
                help_text += f" (e.g. `{fix['before']}` → `{fix['after']}`)"
        rules.append({
            "id": f["family"],
            "name": f["algorithm"],
            "shortDescription": {"text": f["algorithm"]},
            "fullDescription": {"text": f["why"]},
            "helpUri": "https://csrc.nist.gov/projects/post-quantum-cryptography",
            "help": {"text": help_text},
            "defaultConfiguration": {"level": level_map.get(f["risk_level"], "warning")},
            "properties": {"security-severity": severity_map.get(f["risk_level"], "5.0")},
        })

    results = []
    for f in report["findings"]:
        results.append({
            "ruleId": f["family"],
            "level": level_map.get(f["risk_level"], "warning"),
            "message": {"text": f"{f['algorithm']}: {f['why']} Replace with {f['recommendation']}."},
            "locations": [_sarif_location(f)],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "QuantumSafe",
                "version": report.get("version", ""),
                "informationUri": "https://github.com/Danny-397/Quantum-Safe-Scan",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _fix_html(e, fix: dict | None) -> str:
    """Render the call-site fix (before/after + guidance) beneath a recommendation."""
    if not fix or not fix.get("action"):
        return ""
    tag = "drop-in fix" if fix.get("drop_in") else "migration"
    parts = [f'<div class="fix"><span class="fixtag">{tag}</span> {e(fix["action"])}']
    if fix.get("before") and fix.get("after"):
        parts.append(
            f'<div class="ba"><span class="minus mono">- {e(fix["before"])}</span>'
            f'<span class="plus mono">+ {e(fix["after"])}</span></div>'
        )
    if fix.get("library"):
        parts.append(f'<div class="muted">Library: {e(fix["library"])}</div>')
    parts.append("</div>")
    return "".join(parts)


def to_html(report: dict) -> str:
    e = html.escape
    band = report["risk_band"]
    band_hex = {"Low": "#00FF88", "Medium": "#FFB800", "High": "#FF4444", "Critical": "#FF4444"}
    risk_hex = {RISK_HIGH: "#FF4444", RISK_MEDIUM: "#FFB800", RISK_LOW: "#00FF88"}
    accent = band_hex.get(band, "#E0E0E0")

    rows = []
    for f in report["findings"]:
        rc = risk_hex.get(f["risk_level"], "#E0E0E0")
        rows.append(f"""
        <tr>
          <td class="mono">{e(_location(f))}</td>
          <td class="mono num">{f['line_number']}</td>
          <td>{e(f['algorithm'])}</td>
          <td><span class="badge" style="color:{rc};border-color:{rc}">{e(f['risk_level'])}</span></td>
          <td>{e(f['why'])}</td>
          <td>{e(f['recommendation'])}<br><span class="muted mono">{e(f['nist_reference'])} · Complexity: {e(f['complexity'])}</span>{_fix_html(e, f.get('fix'))}</td>
        </tr>""")
    rows_html = "".join(rows) or '<tr><td colspan="6" class="muted">No quantum-vulnerable cryptography detected.</td></tr>'

    s = report["summary"]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QuantumSafe Report — {e(report['target'])}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0A0A0F; color:#E0E0E0; font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; margin:0; padding:32px; }}
  .mono {{ font-family:"SFMono-Regular",ui-monospace,Consolas,Menlo,monospace; }}
  .num {{ text-align:right; }}
  .muted {{ color:#7a7a8c; font-size:12px; }}
  h1 {{ font-size:20px; margin:0 0 4px; }}
  .score {{ font-size:56px; font-weight:700; color:{accent}; font-family:"SFMono-Regular",ui-monospace,Consolas,monospace; }}
  .card {{ background:#12121a; border:1px solid #23232f; border-radius:10px; padding:24px; margin-bottom:24px; }}
  .pills span {{ display:inline-block; margin-right:16px; font-family:ui-monospace,monospace; }}
  .high {{ color:#FF4444; }} .medium {{ color:#FFB800; }} .low {{ color:#00FF88; }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #23232f; vertical-align:top; }}
  th {{ color:#9a9aae; font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.05em; }}
  .badge {{ border:1px solid; border-radius:4px; padding:2px 8px; font-size:12px; font-family:ui-monospace,monospace; }}
  .fix {{ margin-top:8px; padding:8px 10px; background:#0e0e16; border:1px solid #23232f; border-radius:6px; font-size:12px; }}
  .fixtag {{ display:inline-block; font-size:10px; text-transform:uppercase; letter-spacing:.05em; color:#9a9aae; border:1px solid #33334a; border-radius:3px; padding:0 5px; margin-right:6px; }}
  .ba {{ margin-top:6px; display:flex; flex-direction:column; gap:2px; }}
  .ba .minus {{ color:#FF7A7A; }} .ba .plus {{ color:#00FF88; }}
  .footer {{ color:#7a7a8c; font-size:12px; margin-top:24px; }}
</style>
</head>
<body>
  <div class="card">
    <h1>QuantumSafe Scan Report</h1>
    <div class="muted mono">Target: {e(report['target'])} · Generated {e(report['generated_at'])} · v{e(report['version'])}</div>
    <div class="score">{report['risk_score']}/100</div>
    <div style="color:{accent};font-weight:600;">{e(band)} risk — {e(report['risk_message'])}</div>
    <div class="pills" style="margin-top:16px;">
      <span class="high">HIGH: {s['high']}</span>
      <span class="medium">MEDIUM: {s['medium']}</span>
      <span class="low">LOW: {s['low']}</span>
      <span>TOTAL: {s['total_findings']}</span>
    </div>
  </div>
  <div class="card">
    <table>
      <thead>
        <tr><th>File</th><th>Line</th><th>Algorithm</th><th>Risk</th><th>Why</th><th>Recommendation</th></tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
  <div class="footer">
    Based on NIST Post-Quantum Cryptography Standards (FIPS 203, 204, 205).
    This report is for awareness and is not a substitute for a professional cryptographic audit.
  </div>
</body>
</html>"""
