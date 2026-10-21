"""Sweep the third-party origins a page actually loads from.

A site can negotiate a post-quantum hybrid on its own domain and still pull
scripts, fonts and analytics from a dozen other origins over classical key
exchange. Data sent to those origins is exposed the same way, and the page
author chose every one of them. So "is this site post-quantum ready?" is not a
question about one endpoint -- it is a question about the weakest origin the
page depends on.

WHAT IT DOES
Fetches the entry page, extracts the hosts its sub-resources reference, and
runs the same TLS scan (:mod:`tlsscan`) against each. No HTML parsing library:
``html.parser`` is in the standard library and the module keeps the package
dependency-free.

WHY EVERY ORIGIN IS RE-VALIDATED
The SSRF guard is not applied once to the entry URL and then trusted. A page
is attacker-controlled input as far as this tool is concerned -- anyone can
publish a page whose script tags point at ``169.254.169.254`` or an internal
hostname, and a sweep that followed them would be an SSRF with extra steps.
Every discovered host goes through :func:`tlsscan.parse_target` and
:func:`tlsscan.resolve_safely` before a socket is opened, and an origin that
fails is recorded as refused rather than silently dropped.

BOUNDS
The page read is capped, the origin count is capped, and each handshake has its
own timeout, so one hostile page cannot turn a scan into an unbounded crawl.
Only the entry page is fetched: sub-resources are *scanned*, never downloaded.
"""

from __future__ import annotations

import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .scanner import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Finding
from .tlsscan import (
    DEFAULT_TIMEOUT,
    GROUPS,
    UnsafeTarget,
    negotiated,
    parse_target,
    preferred_group,
    resolve_safely,
)

#: Most bytes read from the entry page. Sub-resource references live in the
#: markup, so a cap well under a megabyte is ample and bounds a hostile page.
MAX_PAGE_BYTES = 512 * 1024

#: Most distinct third-party origins scanned. Each costs a TLS handshake, and
#: the point is to characterise a page's exposure, not to enumerate the web.
MAX_ORIGINS = 12

#: Attributes that cause a browser to fetch from another origin.
_URL_ATTRS = ("src", "href", "data-src", "poster")

#: Tags whose href is a navigation link rather than a fetched sub-resource.
#: An <a> does not load anything until the user clicks it.
_SKIP_HREF_TAGS = frozenset({"a", "area", "base"})


class _ResourceURLs(HTMLParser):
    """Collect URLs the page causes the browser to fetch."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        for attr in _URL_ATTRS:
            if attr == "href" and tag in _SKIP_HREF_TAGS:
                continue
            value = values.get(attr)
            if value:
                self.urls.append(value)
        # srcset carries several candidate URLs with descriptors.
        srcset = values.get("srcset")
        if srcset:
            for part in srcset.split(","):
                candidate = part.strip().split(" ")[0]
                if candidate:
                    self.urls.append(candidate)


def fetch_page(host: str, ip: str, port: int = 443,
               timeout: float = DEFAULT_TIMEOUT) -> str:
    """GET ``/`` over TLS from a pinned address and return the body as text.

    The request is written by hand against a socket opened to ``ip`` with SNI
    set to ``host``, rather than handed to urllib, so the connection goes to
    the address the guard already approved instead of re-resolving the name.
    """
    ctx = ssl.create_default_context()
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: quantumsafe-scan (+https://quantumsafescan.com)\r\n"
        "Accept: text/html\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii", "ignore")

    chunks: list[bytes] = []
    total = 0
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            tls.sendall(request)
            while total < MAX_PAGE_BYTES:
                try:
                    chunk = tls.recv(16384)
                except (TimeoutError, socket.timeout, ssl.SSLError):
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)

    raw = b"".join(chunks)
    _, _, body = raw.partition(b"\r\n\r\n")
    return (body or raw).decode("utf-8", "replace")


def extract_origins(html: str, base_host: str, base_port: int = 443) -> list[str]:
    """Distinct third-party hosts the page's sub-resources point at.

    Protocol-relative (``//cdn.example``) and absolute URLs are resolved
    against the page; relative paths resolve to the page's own host and are
    therefore not third-party. The entry host itself is excluded.
    """
    parser = _ResourceURLs()
    try:
        parser.feed(html)
    except Exception:
        # A malformed page should yield whatever was parsed before the fault,
        # not abort the scan.
        pass

    base = f"https://{base_host}" + ("" if base_port == 443 else f":{base_port}")
    seen: list[str] = []
    for raw in parser.urls:
        raw = raw.strip()
        if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#", "blob:")):
            continue
        try:
            host = urlsplit(urljoin(base, raw)).hostname
        except ValueError:
            continue
        if not host:
            continue
        host = host.lower()
        if host == base_host.lower():
            continue
        if host not in seen:
            seen.append(host)
    return seen


def scan_origin(host: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """TLS-scan one origin. Never raises: the outcome is in the result."""
    try:
        parsed_host, port = parse_target(host)
        addrs = resolve_safely(parsed_host, port)
    except UnsafeTarget as exc:
        return {"host": host, "status": "refused", "detail": str(exc)}

    ip = addrs[0]
    try:
        group_id, how = preferred_group(parsed_host, ip, port, timeout)
        info = negotiated(parsed_host, ip, port, timeout)
    except (OSError, ConnectionError, ssl.SSLError) as exc:
        return {"host": host, "status": "unreachable",
                "detail": f"{type(exc).__name__}: {exc}"}

    name, is_pq = GROUPS.get(group_id, (None, False)) if group_id else (None, False)
    return {
        "host": parsed_host,
        "status": "scanned",
        "key_exchange": name or (f"0x{group_id:04x}" if group_id else f"unknown ({how})"),
        "post_quantum": bool(is_pq),
        "protocol": info.get("protocol"),
        "cipher": info.get("cipher"),
    }


def sweep(target: str, timeout: float = DEFAULT_TIMEOUT,
          max_origins: int = MAX_ORIGINS) -> tuple[list[Finding], dict]:
    """Scan the TLS of every third-party origin the page at ``target`` loads.

    Returns ``(findings, summary)``. One aggregate finding is produced rather
    than one per origin: a dozen separate HIGHs for other people's servers
    would swamp the findings a reader can actually act on, and the actionable
    fact is how many of a page's dependencies are not ready.
    """
    host, port = parse_target(target)
    addrs = resolve_safely(host, port)

    try:
        html = fetch_page(host, addrs[0], port, timeout)
    except (OSError, ConnectionError, ssl.SSLError) as exc:
        return [], {"host": host, "error": f"could not fetch the page: {exc}",
                    "origins": []}

    discovered = extract_origins(html, host, port)
    truncated = len(discovered) > max_origins
    results = [scan_origin(h, timeout) for h in discovered[:max_origins]]

    scanned = [r for r in results if r["status"] == "scanned"]
    classical = [r for r in scanned if not r["post_quantum"]]
    ready = [r for r in scanned if r["post_quantum"]]

    findings: list[Finding] = []
    if scanned:
        if classical:
            why = (
                f"{len(classical)} of {len(scanned)} third-party origins this page "
                f"loads from negotiate classical key exchange "
                f"({', '.join(r['host'] for r in classical[:6])}"
                f"{', …' if len(classical) > 6 else ''}). Data sent to those origins "
                "is exposed to harvest-now-decrypt-later even when this site's own "
                "key exchange is post-quantum. You chose these dependencies: drop "
                "the ones you do not need and raise it with the vendors you do."
            )
            # MEDIUM, not HIGH: the exposure is real but the server is not yours
            # to fix, so it is not the same call to action as your own endpoint.
            risk = RISK_MEDIUM if ready else RISK_HIGH
            findings.append(_make(host, "Third-party origins on classical key exchange",
                                  risk, why, "ecc"))
        else:
            findings.append(_make(
                host, "All third-party origins post-quantum", RISK_LOW,
                f"Every one of the {len(scanned)} third-party origins this page loads "
                "from negotiated a post-quantum hybrid key exchange. Nothing to "
                "migrate here.", "pqc_hybrid"))

    summary = {
        "host": host,
        "origins_found": len(discovered),
        "origins_scanned": len(scanned),
        "origins_post_quantum": len(ready),
        "origins_classical": len(classical),
        "truncated": truncated,
        "max_origins": max_origins,
        "origins": results,
    }
    return findings, summary


def _make(host: str, algorithm: str, risk: str, why: str, family: str) -> Finding:
    f = Finding(
        file_path=f"{host} [third-party origins]",
        line_number=0,
        algorithm=algorithm,
        risk_level=risk,
        why=why,
        family=family,
        confidence="high",
        origin="endpoint",
    )
    return f.enrich()
