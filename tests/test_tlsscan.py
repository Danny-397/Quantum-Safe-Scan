"""Tests for the live-endpoint TLS scanner.

Two things carry nearly all the weight here.

THE SSRF GUARD. This is the one feature that takes a URL from a stranger and
opens a connection from the server, which is textbook server-side request
forgery. On a cloud host the prize is the instance metadata endpoint
(169.254.169.254), which hands out credentials. For a *security* tool this
would be the worst possible bug to ship, so the guard is tested far harder
than the feature it guards, and every test here runs without network.

THE HANDSHAKE PARSER. It is hand-rolled byte work against a wire format, so
the ClientHello is checked structurally and the ServerHello/HelloRetryRequest
discrimination is pinned -- those two messages share handshake type 0x02 and
are distinguished only by the random, so getting it wrong silently mislabels
every result.
"""

import socket
import struct
from unittest.mock import patch

import pytest

from quantumsafe.tlsscan import (
    ALLOWED_PORTS,
    DEFAULT_TIMEOUT,
    GROUPS,
    UnsafeTarget,
    _HRR_RANDOM,
    _is_public,
    build_client_hello,
    parse_target,
    resolve_safely,
    scan_url,
)
from quantumsafe.scanner import RISK_HIGH, RISK_LOW

import ipaddress


# --------------------------------------------------------------------------- #
# Target parsing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expected", [
    ("example.com", ("example.com", 443)),
    ("https://example.com", ("example.com", 443)),
    ("https://example.com/", ("example.com", 443)),
    ("https://example.com/deep/path?q=1", ("example.com", 443)),
    ("https://example.com:443", ("example.com", 443)),
    ("https://example.com:8443", ("example.com", 8443)),
    ("example.com:8443", ("example.com", 8443)),
    ("  example.com  ", ("example.com", 443)),
    ("https://EXAMPLE.com", ("example.com", 443)),   # hostname is lowercased
])
def test_accepts_reasonable_targets(raw, expected):
    assert parse_target(raw) == expected


@pytest.mark.parametrize("raw", ["http://example.com", "ftp://example.com",
                                 "file:///etc/passwd", "gopher://example.com"])
def test_non_https_schemes_are_refused(raw):
    """Not silently rewritten to https: that would measure a different endpoint."""
    with pytest.raises(UnsafeTarget, match="Only https"):
        parse_target(raw)


@pytest.mark.parametrize("port", [22, 25, 3306, 5432, 6379, 8080, 80, 11211, 1])
def test_ports_outside_the_allowlist_are_refused(port):
    """A URL must not become a way to reach an arbitrary internal service."""
    with pytest.raises(UnsafeTarget, match="not allowed"):
        parse_target(f"https://example.com:{port}")


def test_allowlist_is_small_and_https_only():
    assert ALLOWED_PORTS == {443, 8443}


@pytest.mark.parametrize("raw", ["", "   ", None])
def test_empty_target_is_refused(raw):
    with pytest.raises(UnsafeTarget):
        parse_target(raw)


def test_scheme_only_target_is_refused():
    with pytest.raises(UnsafeTarget, match="hostname"):
        parse_target("https://")


# --------------------------------------------------------------------------- #
# Address classification -- the core of the SSRF guard
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("addr", [
    "127.0.0.1", "127.1.2.3",            # loopback
    "10.0.0.5", "172.16.0.1", "192.168.1.1",   # RFC 1918
    "169.254.169.254",                   # cloud instance metadata
    "169.254.0.1",                       # link-local generally
    "100.64.0.1", "100.127.255.255",     # carrier-grade NAT
    "0.0.0.0",                           # unspecified
    "224.0.0.1",                         # multicast
    "240.0.0.1",                         # reserved
    "::1",                               # IPv6 loopback
    "fe80::1",                           # IPv6 link-local
    "fc00::1", "fd00::1",                # IPv6 unique-local
    "::",                                # IPv6 unspecified
    "::ffff:169.254.169.254",            # IPv4-mapped metadata
    "::ffff:127.0.0.1",                  # IPv4-mapped loopback
    "::ffff:10.0.0.1",                   # IPv4-mapped private
])
def test_non_public_addresses_are_rejected(addr):
    assert _is_public(ipaddress.ip_address(addr)) is False


@pytest.mark.parametrize("addr", [
    "1.1.1.1", "8.8.8.8", "140.82.121.4", "99.83.190.102",
    "2606:4700::1111", "2001:4860:4860::8888",
])
def test_public_addresses_are_accepted(addr):
    assert _is_public(ipaddress.ip_address(addr)) is True


def test_ipv4_mapped_ipv6_is_judged_on_the_embedded_address():
    """::ffff:169.254.169.254 must not walk through the IPv6 branch.

    An IPv4-mapped address is not private by IPv6 rules, so without unwrapping
    it the metadata endpoint is reachable through an IPv6 literal.
    """
    mapped = ipaddress.ip_address("::ffff:169.254.169.254")
    assert mapped.ipv4_mapped is not None
    assert _is_public(mapped) is False


# --------------------------------------------------------------------------- #
# Resolution -- rejects on ANY private answer, and reports the addresses used
# --------------------------------------------------------------------------- #
def _addrinfo(*addrs):
    """Fake getaddrinfo results for the given addresses."""
    out = []
    for a in addrs:
        fam = socket.AF_INET6 if ":" in a else socket.AF_INET
        out.append((fam, socket.SOCK_STREAM, 6, "", (a, 443)))
    return out


def test_resolution_returns_public_addresses():
    with patch("quantumsafe.tlsscan.socket.getaddrinfo",
               return_value=_addrinfo("1.1.1.1", "1.0.0.1")):
        assert resolve_safely("example.com", 443) == ["1.1.1.1", "1.0.0.1"]


def test_any_private_answer_rejects_the_whole_target():
    """A hostname can resolve to several addresses on purpose.

    Accepting the public one and ignoring a private sibling would let an
    attacker get a connection to the private address on a later attempt.
    """
    with patch("quantumsafe.tlsscan.socket.getaddrinfo",
               return_value=_addrinfo("1.1.1.1", "169.254.169.254")):
        with pytest.raises(UnsafeTarget, match="non-public"):
            resolve_safely("sneaky.example", 443)


def test_duplicate_addresses_are_collapsed():
    with patch("quantumsafe.tlsscan.socket.getaddrinfo",
               return_value=_addrinfo("1.1.1.1", "1.1.1.1")):
        assert resolve_safely("example.com", 443) == ["1.1.1.1"]


def test_unresolvable_host_is_refused():
    with patch("quantumsafe.tlsscan.socket.getaddrinfo",
               side_effect=socket.gaierror(-2, "Name or service not known")):
        with pytest.raises(UnsafeTarget, match="Could not resolve"):
            resolve_safely("no-such-host.invalid", 443)


def test_empty_resolution_is_refused():
    with patch("quantumsafe.tlsscan.socket.getaddrinfo", return_value=[]):
        with pytest.raises(UnsafeTarget, match="did not resolve"):
            resolve_safely("example.com", 443)


def test_scan_connects_to_the_checked_address_not_the_hostname():
    """Closes the DNS-rebinding window.

    Resolving once and connecting to that address means a name cannot resolve
    public for the safety check and private for the connection that follows.
    """
    calls = {}

    def fake_negotiated(host, ip, port, timeout):
        calls["negotiated"] = (host, ip, port)
        return {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                "symmetric_bits": 256, "certificate": {}, "certificate_der": b""}

    def fake_group(host, ip, port, timeout):
        calls["group"] = (host, ip, port)
        return 0x11EC, "HelloRetryRequest"

    with patch("quantumsafe.tlsscan.socket.getaddrinfo",
               return_value=_addrinfo("1.1.1.1")), \
         patch("quantumsafe.tlsscan.negotiated", side_effect=fake_negotiated), \
         patch("quantumsafe.tlsscan.preferred_group", side_effect=fake_group):
        scan_url("example.com")

    # The resolved IP is passed positionally; the hostname is kept only for SNI.
    assert calls["negotiated"] == ("example.com", "1.1.1.1", 443)
    assert calls["group"] == ("example.com", "1.1.1.1", 443)


# --------------------------------------------------------------------------- #
# ClientHello construction
# --------------------------------------------------------------------------- #
def test_client_hello_is_a_well_formed_handshake_record():
    msg = build_client_hello("example.com")
    assert msg[0] == 0x16, "TLS handshake record type"
    assert msg[1:3] == b"\x03\x01", "record version is TLS 1.0 for compatibility"
    declared = struct.unpack("!H", msg[3:5])[0]
    assert declared == len(msg) - 5, "record length must match the body"
    assert msg[5] == 0x01, "ClientHello handshake type"
    hs_len = int.from_bytes(msg[6:9], "big")
    assert hs_len == len(msg) - 9, "handshake length must match the body"


def test_client_hello_offers_hybrids_but_shares_only_x25519():
    """The mismatch is what forces the server to name its preference."""
    msg = build_client_hello("example.com")
    # supported_groups (0x000a) must contain the hybrid.
    assert struct.pack("!H", 0x11EC) in msg
    # key_share (0x0033) carries exactly one entry, for X25519, 32 bytes.
    idx = msg.index(struct.pack("!HH", 0x0033, 2 + 2 + 2 + 32))
    body = msg[idx + 4:]
    assert struct.unpack("!H", body[0:2])[0] == 36, "key_share list length"
    assert struct.unpack("!H", body[2:4])[0] == 0x001D, "share group is X25519"
    assert struct.unpack("!H", body[4:6])[0] == 32, "X25519 share is 32 bytes"


def test_client_hello_includes_sni_for_the_requested_host():
    assert b"example.com" in build_client_hello("example.com")


def test_client_hello_handles_an_internationalised_host():
    """IDNA encoding, or a unicode host raises instead of scanning."""
    msg = build_client_hello("bücher.example")
    assert b"xn--bcher-kva.example" in msg


def test_client_hello_randoms_differ_between_calls():
    """A fixed random would make the probe fingerprintable and replayable."""
    assert build_client_hello("example.com") != build_client_hello("example.com")


# --------------------------------------------------------------------------- #
# HelloRetryRequest discrimination
# --------------------------------------------------------------------------- #
def test_hrr_random_is_the_rfc_value():
    """RFC 8446 4.1.3. Derived, not pasted: one wrong digit fails silently."""
    assert _HRR_RANDOM.hex() == (
        "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
    assert len(_HRR_RANDOM) == 32


# --------------------------------------------------------------------------- #
# Group table
# --------------------------------------------------------------------------- #
def test_hybrid_groups_are_flagged_post_quantum():
    for code in (0x11EC, 0x11EB, 0x11ED, 0x6399):
        name, is_pq = GROUPS[code]
        assert is_pq is True, f"{name} is a PQC hybrid"


def test_classical_groups_are_not_flagged_post_quantum():
    for code in (0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100):
        name, is_pq = GROUPS[code]
        assert is_pq is False, f"{name} is classical"


def test_every_offered_group_is_in_the_table():
    """Otherwise a server could select a group we cannot name."""
    from quantumsafe.tlsscan import _OFFER
    for code in _OFFER:
        assert code in GROUPS


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def _fake_scan(group, protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", bits=256):
    def fake_negotiated(host, ip, port, timeout):
        return {"protocol": protocol, "cipher": cipher, "symmetric_bits": bits,
                "certificate": {}, "certificate_der": b""}
    with patch("quantumsafe.tlsscan.socket.getaddrinfo",
               return_value=_addrinfo("1.1.1.1")), \
         patch("quantumsafe.tlsscan.negotiated", side_effect=fake_negotiated), \
         patch("quantumsafe.tlsscan.preferred_group",
               return_value=(group, "ServerHello")):
        return scan_url("example.com")


def test_classical_key_exchange_is_high_and_says_why_it_is_retroactive():
    findings, details = _fake_scan(0x001D)
    kex = [f for f in findings if "key exchange" in f.algorithm]
    assert len(kex) == 1
    assert kex[0].risk_level == RISK_HIGH
    assert kex[0].family == "ecc"
    assert "record the traffic" in kex[0].why and "retroactively" in kex[0].why
    assert details["key_exchange_post_quantum"] is False


def test_hybrid_key_exchange_is_low_and_needs_no_action():
    findings, details = _fake_scan(0x11EC)
    kex = [f for f in findings if "key exchange" in f.algorithm]
    assert kex[0].risk_level == RISK_LOW
    assert "No action needed" in kex[0].why
    assert details["key_exchange_post_quantum"] is True


def test_endpoint_findings_carry_the_host_and_no_line():
    findings, _ = _fake_scan(0x001D)
    for f in findings:
        assert f.origin == "endpoint"
        assert f.file_path == "example.com"
        assert f.line_number == 0
        assert f.confidence == "high", "observed on the wire, not inferred"


def test_findings_are_enriched_with_recommendations():
    findings, _ = _fake_scan(0x001D)
    kex = [f for f in findings if "key exchange" in f.algorithm][0]
    assert kex.recommendation and kex.nist_reference


def test_tls13_with_aes256_and_hybrid_produces_only_the_good_news():
    findings, _ = _fake_scan(0x11EC, bits=256)
    assert len(findings) == 1
    assert findings[0].risk_level == RISK_LOW


@pytest.mark.parametrize("proto,family", [
    ("TLSv1.2", "tls12"),
    ("TLSv1.1", "tls_old"),
    ("TLSv1", "tls_old"),
])
def test_old_protocols_are_reported(proto, family):
    findings, _ = _fake_scan(0x11EC, protocol=proto)
    fams = [f.family for f in findings]
    assert family in fams


def test_tls13_is_not_reported_as_a_finding():
    findings, _ = _fake_scan(0x11EC, protocol="TLSv1.3")
    assert not any(f.family in ("tls12", "tls_old") for f in findings)


def test_aes128_is_a_low_note_not_a_warning():
    """Grover halves the effective key length; 128-bit is not an emergency."""
    findings, _ = _fake_scan(0x11EC, cipher="TLS_AES_128_GCM_SHA256", bits=128)
    aes = [f for f in findings if f.family == "aes128"]
    assert len(aes) == 1
    assert aes[0].risk_level == RISK_LOW
    assert "64-bit security" in aes[0].why


def test_unparseable_group_does_not_invent_a_finding():
    """A server we could not read must not be reported as either safe or broken."""
    findings, details = _fake_scan(None)
    assert not any("key exchange" in f.algorithm for f in findings)
    assert details["key_exchange_post_quantum"] is False
    assert "unknown" in details["key_exchange"]


def test_details_report_the_addresses_actually_used():
    _, details = _fake_scan(0x11EC)
    assert details["addresses"] == ["1.1.1.1"]
    assert details["host"] == "example.com"
    assert details["port"] == 443


def test_default_timeout_is_bounded():
    assert 0 < DEFAULT_TIMEOUT <= 30


# --------------------------------------------------------------------------- #
# The HTTP endpoint
#
# The guard is tested above as pure logic; these check the API wires it up and
# refuses bad input with a sensible status rather than a 500.
# --------------------------------------------------------------------------- #
def test_endpoint_rejects_missing_url(client):
    res = client.post("/api/v1/scan-url", json={})
    assert res.status_code == 400
    assert "url" in res.get_json()["error"].lower()


@pytest.mark.parametrize("target", [
    "https://127.0.0.1", "https://169.254.169.254", "http://example.com",
    "https://example.com:22", "https://[::1]",
])
def test_endpoint_refuses_unsafe_targets_with_400(client, target):
    """An SSRF attempt is a client error with an explanation, not a 500."""
    res = client.post("/api/v1/scan-url", json={"url": target})
    assert res.status_code == 400
    assert res.get_json()["error"]


def test_endpoint_rejects_an_overlong_target(client):
    res = client.post("/api/v1/scan-url", json={"url": "a" * 300 + ".com"})
    assert res.status_code == 400


def test_endpoint_returns_a_report_on_success(client):
    def fake_scan(target, timeout=DEFAULT_TIMEOUT):
        from quantumsafe.tlsscan import _finding
        f = _finding("example.com", "X25519 key exchange", RISK_HIGH,
                     "classical", "ecc")
        return [f], {"host": "example.com", "port": 443,
                     "addresses": ["1.1.1.1"], "protocol": "TLSv1.3",
                     "cipher": "TLS_AES_256_GCM_SHA384", "symmetric_bits": 256,
                     "key_exchange": "X25519",
                     "key_exchange_post_quantum": False,
                     "key_exchange_observed_via": "ServerHello",
                     "certificate": {}}
    with patch("quantumsafe.tlsscan.scan_url", side_effect=fake_scan):
        res = client.post("/api/v1/scan-url", json={"url": "example.com"})
    assert res.status_code == 200
    report = res.get_json()["report"]
    assert report["endpoint"]["key_exchange"] == "X25519"
    assert report["summary"]["high"] == 1


def test_endpoint_turns_a_handshake_failure_into_502(client):
    """An unreachable host is an upstream problem, not a bad request."""
    with patch("quantumsafe.tlsscan.scan_url",
               side_effect=OSError("timed out")):
        res = client.post("/api/v1/scan-url", json={"url": "example.com"})
    assert res.status_code == 502
    assert "handshake" in res.get_json()["error"].lower()
