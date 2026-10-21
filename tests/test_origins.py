"""Tests for the third-party origin sweep.

THE SECURITY PROPERTY. A page is attacker-controlled input. Anyone can publish
markup whose script tags point at 169.254.169.254 or an internal hostname, so a
sweep that followed what it found would be an SSRF with extra steps. The guard
is therefore applied to every *discovered* origin, not once to the entry URL and
then trusted. That is what most of these tests are about, and they all run
offline.

THE REPORTING CHOICE. One aggregate finding, not one per origin: a dozen
separate HIGHs for other people's servers would bury the findings a reader can
act on. And MEDIUM rather than HIGH when the page's own origin is fine, because
a third-party server is not the author's to fix -- the action is to drop the
dependency or press the vendor, which is a different call to action.
"""

import socket
import ssl
from unittest.mock import patch

import pytest

from quantumsafe.origins import (
    MAX_ORIGINS,
    MAX_PAGE_BYTES,
    extract_origins,
    scan_origin,
    sweep,
)
from quantumsafe.scanner import RISK_HIGH, RISK_LOW, RISK_MEDIUM


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #
def test_finds_hosts_across_the_attributes_a_browser_fetches():
    html = """
      <link rel="stylesheet" href="https://fonts.googleapis.com/css?x=1">
      <script src="https://cdn.example.com/a.js"></script>
      <img src="https://img.example.net/p.png" poster="https://v.example.org/t.jpg">
      <iframe src="https://embed.example.io/f"></iframe>
      <video data-src="https://media.example.co/v.mp4"></video>
    """
    got = extract_origins(html, "site.test")
    for host in ("fonts.googleapis.com", "cdn.example.com", "img.example.net",
                 "v.example.org", "embed.example.io", "media.example.co"):
        assert host in got


def test_protocol_relative_urls_resolve():
    html = '<script src="//cdn.example.com/a.js"></script>'
    assert extract_origins(html, "site.test") == ["cdn.example.com"]


def test_relative_paths_are_not_third_party():
    html = '<script src="/static/app.js"></script><img src="logo.png">'
    assert extract_origins(html, "site.test") == []


def test_the_entry_host_is_excluded_however_it_is_written():
    html = ('<script src="https://site.test/a.js"></script>'
            '<img src="https://SITE.TEST/b.png">')
    assert extract_origins(html, "site.test") == []


def test_anchor_hrefs_are_not_sub_resources():
    """An <a> fetches nothing until the user clicks it."""
    html = ('<a href="https://elsewhere.example/page">link</a>'
            '<base href="https://base.example/">')
    assert extract_origins(html, "site.test") == []


def test_srcset_candidates_are_all_collected():
    html = ('<img srcset="https://a.example/1.png 1x, https://b.example/2.png 2x">')
    got = extract_origins(html, "site.test")
    assert "a.example" in got and "b.example" in got


@pytest.mark.parametrize("url", [
    "data:image/png;base64,AAAA", "javascript:void(0)", "mailto:a@b.com",
    "#anchor", "blob:https://x/y",
])
def test_non_network_schemes_are_ignored(url):
    assert extract_origins(f'<img src="{url}">', "site.test") == []


def test_duplicate_origins_collapse_and_order_is_stable():
    html = ('<script src="https://cdn.example/a.js"></script>'
            '<script src="https://cdn.example/b.js"></script>'
            '<img src="https://img.example/c.png">')
    assert extract_origins(html, "site.test") == ["cdn.example", "img.example"]


def test_malformed_markup_still_yields_what_was_parsed():
    html = '<script src="https://cdn.example/a.js"><<<>>> <img src=';
    assert "cdn.example" in extract_origins(html, "site.test")


def test_empty_page_yields_nothing():
    assert extract_origins("", "site.test") == []


# --------------------------------------------------------------------------- #
# The guard applies to discovered origins
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("host", [
    "127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.1.1",
    "localhost", "100.64.0.1", "[::1]",
])
def test_a_discovered_private_origin_is_refused(host):
    """The whole point: following what a page names must not reach a private
    network or the cloud metadata endpoint."""
    r = scan_origin(host)
    assert r["status"] == "refused"
    assert r["detail"]


def test_a_discovered_origin_on_a_forbidden_port_is_refused():
    assert scan_origin("example.com:22")["status"] == "refused"


def test_a_sweep_refuses_private_origins_found_in_the_markup():
    """End to end: a hostile page cannot get a connection to an internal host.

    `parse_target` is left unpatched and `resolve_safely` only short-circuits
    the *entry* host, so the discovered origins go through the real guard --
    mocking it here would test the mock instead of the protection. The origins
    are IP literals so no DNS is needed.
    """
    html = ('<script src="https://169.254.169.254/latest/meta-data/"></script>'
            '<img src="https://127.0.0.1/x.png">'
            '<script src="https://10.0.0.5/y.js"></script>')

    from quantumsafe import origins as mod
    real_resolve = mod.resolve_safely

    def entry_only(host, port):
        if host == "site.test":
            return ["1.1.1.1"]
        return real_resolve(host, port)      # the genuine guard

    with patch("quantumsafe.origins.resolve_safely", side_effect=entry_only), \
         patch("quantumsafe.origins.fetch_page", return_value=html):
        findings, summary = sweep("site.test")

    assert summary["origins_found"] == 3
    assert summary["origins_scanned"] == 0, "nothing private may be scanned"
    assert {r["status"] for r in summary["origins"]} == {"refused"}
    assert findings == [], "no finding is claimed about hosts never contacted"


def test_an_unreachable_origin_is_recorded_not_raised():
    with patch("quantumsafe.origins.parse_target", return_value=("x.test", 443)), \
         patch("quantumsafe.origins.resolve_safely", return_value=["1.1.1.1"]), \
         patch("quantumsafe.origins.preferred_group",
               side_effect=socket.timeout("timed out")):
        r = scan_origin("x.test")
    assert r["status"] == "unreachable"
    assert "timeout" in r["detail"].lower() or "timed out" in r["detail"].lower()


def test_an_ssl_error_on_one_origin_does_not_abort_the_sweep():
    def flaky(host, ip, port, timeout):
        if host == "bad.example":
            raise ssl.SSLError("handshake failure")
        return 0x11EC, "HelloRetryRequest"

    html = ('<script src="https://bad.example/a.js"></script>'
            '<script src="https://good.example/b.js"></script>')
    with patch("quantumsafe.origins.parse_target",
               side_effect=lambda h: (h.split(":")[0], 443)), \
         patch("quantumsafe.origins.resolve_safely", return_value=["1.1.1.1"]), \
         patch("quantumsafe.origins.fetch_page", return_value=html), \
         patch("quantumsafe.origins.preferred_group", side_effect=flaky), \
         patch("quantumsafe.origins.negotiated",
               return_value={"protocol": "TLSv1.3", "cipher": "C", "symmetric_bits": 256}):
        _findings, summary = sweep("site.test")

    by_host = {r["host"]: r for r in summary["origins"]}
    assert by_host["bad.example"]["status"] == "unreachable"
    assert by_host["good.example"]["status"] == "scanned"


# --------------------------------------------------------------------------- #
# Bounds
# --------------------------------------------------------------------------- #
def test_the_origin_count_is_capped():
    """One hostile page must not turn a scan into an unbounded crawl."""
    html = "".join(f'<script src="https://h{i}.example/a.js"></script>'
                   for i in range(60))
    with patch("quantumsafe.origins.parse_target",
               side_effect=lambda h: (h.split(":")[0], 443)), \
         patch("quantumsafe.origins.resolve_safely", return_value=["1.1.1.1"]), \
         patch("quantumsafe.origins.fetch_page", return_value=html), \
         patch("quantumsafe.origins.preferred_group", return_value=(0x001D, "ServerHello")), \
         patch("quantumsafe.origins.negotiated",
               return_value={"protocol": "TLSv1.3", "cipher": "C", "symmetric_bits": 256}):
        _f, summary = sweep("site.test", max_origins=5)

    assert summary["origins_found"] == 60
    assert summary["origins_scanned"] == 5
    assert summary["truncated"] is True
    assert len(summary["origins"]) == 5


def test_bounds_are_sane_constants():
    assert 0 < MAX_ORIGINS <= 50
    assert 0 < MAX_PAGE_BYTES <= 4 * 1024 * 1024


def test_a_page_that_cannot_be_fetched_degrades_gracefully():
    with patch("quantumsafe.origins.parse_target", return_value=("site.test", 443)), \
         patch("quantumsafe.origins.resolve_safely", return_value=["1.1.1.1"]), \
         patch("quantumsafe.origins.fetch_page", side_effect=OSError("reset")):
        findings, summary = sweep("site.test")
    assert findings == []
    assert "could not fetch" in summary["error"]
    assert summary["origins"] == []


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def _sweep_with(groups):
    """Sweep a page whose origins negotiate the given groups, in order."""
    html = "".join(f'<script src="https://h{i}.example/a.js"></script>'
                   for i in range(len(groups)))
    seq = list(groups)
    with patch("quantumsafe.origins.parse_target",
               side_effect=lambda h: (h.split(":")[0], 443)), \
         patch("quantumsafe.origins.resolve_safely", return_value=["1.1.1.1"]), \
         patch("quantumsafe.origins.fetch_page", return_value=html), \
         patch("quantumsafe.origins.preferred_group",
               side_effect=[(g, "ServerHello") for g in seq]), \
         patch("quantumsafe.origins.negotiated",
               return_value={"protocol": "TLSv1.3", "cipher": "C", "symmetric_bits": 256}):
        return sweep("site.test")


def test_all_post_quantum_origins_produce_good_news():
    findings, summary = _sweep_with([0x11EC, 0x11EC, 0x11EB])
    assert summary["origins_classical"] == 0
    assert len(findings) == 1
    assert findings[0].risk_level == RISK_LOW
    assert findings[0].family == "pqc_hybrid"


def test_a_mixed_page_is_medium_because_the_servers_are_not_yours():
    findings, summary = _sweep_with([0x11EC, 0x001D, 0x001D])
    assert (summary["origins_post_quantum"], summary["origins_classical"]) == (1, 2)
    assert findings[0].risk_level == RISK_MEDIUM
    assert "You chose these dependencies" in findings[0].why


def test_every_origin_classical_is_high():
    findings, _ = _sweep_with([0x001D, 0x0017])
    assert findings[0].risk_level == RISK_HIGH


def test_one_aggregate_finding_not_one_per_origin():
    """Twelve HIGHs for other people's servers would bury the actionable ones."""
    findings, summary = _sweep_with([0x001D] * 10)
    assert summary["origins_scanned"] == 10
    assert len(findings) == 1


def test_the_finding_names_the_offending_origins():
    findings, _ = _sweep_with([0x001D, 0x001D])
    assert "h0.example" in findings[0].why


def test_no_origins_means_no_finding():
    """A page with no third-party dependencies has nothing to report."""
    findings, summary = _sweep_with([])
    assert findings == [] and summary["origins_scanned"] == 0


def test_findings_are_endpoint_origin_and_enriched():
    findings, _ = _sweep_with([0x001D])
    f = findings[0]
    assert f.origin == "endpoint"
    assert f.line_number == 0
    assert "third-party origins" in f.file_path
    assert f.recommendation
