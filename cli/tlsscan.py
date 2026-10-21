"""Scan a live HTTPS endpoint for quantum-vulnerable cryptography.

A website's quantum exposure is not in its source code -- it is in the TLS
handshake. Two brief public-key operations carry essentially all of it:

* the **key exchange**, which Shor's algorithm breaks to recover the session
  key. This is the harvest-now-decrypt-later risk: traffic recorded today
  becomes readable once a quantum computer exists, so it is retroactive and
  cannot be fixed after the fact.
* the **certificate signature**, which Shor also breaks, but only to forge
  future certificates. Not retroactive, and certificates rotate every ~90 days
  anyway. (Chain analysis lives in :mod:`certchain`.)

Symmetric cryptography is not the problem: Grover's algorithm square-roots a
brute-force search, so AES-128 drops to ~2^64 work and AES-256 is comfortable.
That asymmetry is why this module reports on key exchange first.

WHY A HAND-BUILT CLIENTHELLO
In TLS 1.2 the cipher suite named the key exchange
(``ECDHE_RSA_WITH_AES_128_GCM_SHA256``). TLS 1.3 removed it: every modern site
reports only ``TLS_AES_128_GCM_SHA256``, which says nothing about key exchange.
The group lives in the ``key_share`` extension instead, and Python's ``ssl``
cannot report it -- ``SSLContext.set_groups`` and ``SSLObject.group_used``
need OpenSSL 3.5+ and Python 3.14, while ML-KEM groups need OpenSSL 3.5 at all.
On OpenSSL 3.0 the most important fact about the connection is invisible.

So :func:`preferred_group` speaks the handshake directly: offer the hybrid
groups in ``supported_groups`` but a ``key_share`` for X25519 only. A server
preferring a hybrid must then answer with a HelloRetryRequest naming it
(RFC 8446 4.1.3), and one that does not proceeds with a normal ServerHello.
Either way the server states its choice, and no ML-KEM implementation is
needed to ask the question.

WHAT IT MEASURES, PRECISELY
The result is the group the server *selects* from what we offer -- the same
answer a browser offering that set would get. It is not proof of what the
server could support if asked differently, and the findings are worded as
"negotiated", not "supports".

SCANNING SOMEONE ELSE'S SERVER
This performs exactly one TLS handshake, which is what any browser does on
every visit: passive, non-intrusive, and nothing like port scanning or
vulnerability probing. It stays that way deliberately.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import ssl
import struct
from urllib.parse import urlsplit

from .scanner import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Finding

#: Ports a public HTTPS endpoint is plausibly on. Restricted so a URL cannot
#: be used to reach an arbitrary internal service port.
ALLOWED_PORTS = frozenset({443, 8443})

DEFAULT_TIMEOUT = 10.0

#: TLS supported_groups values (RFC 8446 + draft-kwiatkowski-tls-ecdhe-mlkem).
#: ``True`` marks a post-quantum hybrid.
GROUPS: dict[int, tuple[str, bool]] = {
    0x11EC: ("X25519MLKEM768", True),
    0x11EB: ("SecP256r1MLKEM768", True),
    0x11ED: ("SecP384r1MLKEM1024", True),
    0x6399: ("X25519Kyber768Draft00", True),
    0x639A: ("SecP256r1Kyber768Draft00", True),
    0x001D: ("X25519", False),
    0x001E: ("X448", False),
    0x0017: ("secp256r1", False),
    0x0018: ("secp384r1", False),
    0x0019: ("secp521r1", False),
    0x0100: ("ffdhe2048", False),
    0x0101: ("ffdhe3072", False),
}

#: Offered in supported_groups, hybrids first so a server that supports one
#: has to say so. Order is our preference, which the server may override.
_OFFER = (0x11EC, 0x11EB, 0x11ED, 0x6399, 0x001D, 0x0017, 0x0018)

#: RFC 8446 4.1.3: a HelloRetryRequest is a ServerHello whose random is this
#: fixed value. Computed rather than pasted -- a 64-character hex literal is
#: easy to mistype by a single digit, and the comparison then fails silently.
_HRR_RANDOM = hashlib.sha256(b"HelloRetryRequest").digest()


class UnsafeTarget(ValueError):
    """The target is not a safe, public HTTPS endpoint to connect to."""


# --------------------------------------------------------------------------- #
# Target validation (SSRF)
# --------------------------------------------------------------------------- #
def parse_target(raw: str) -> tuple[str, int]:
    """Return ``(host, port)`` for a user-supplied target.

    Accepts ``example.com``, ``example.com:8443`` and full https URLs. Any
    other scheme is refused rather than coerced: a tool that silently rewrites
    ``http://`` to ``https://`` would report on an endpoint the caller did not
    ask about.
    """
    raw = (raw or "").strip()
    if not raw:
        raise UnsafeTarget("No target supplied.")
    if "://" not in raw:
        raw = "https://" + raw

    parts = urlsplit(raw)
    if parts.scheme != "https":
        raise UnsafeTarget(
            f"Only https targets are supported (got {parts.scheme!r}). TLS is "
            "the thing being measured."
        )
    host = parts.hostname
    if not host:
        raise UnsafeTarget("Could not find a hostname in that target.")
    port = parts.port or 443
    if port not in ALLOWED_PORTS:
        raise UnsafeTarget(
            f"Port {port} is not allowed; permitted ports are "
            f"{sorted(ALLOWED_PORTS)}."
        )
    return host, port


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for addresses it is safe to open a connection to.

    ``is_private`` alone is not enough: it misses carrier-grade NAT on some
    Python versions, and link-local is where cloud instance metadata lives
    (169.254.169.254 on AWS, GCP and Azure), which is the single most valuable
    target for an SSRF against a service like this one.
    """
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        return False
    # Carrier-grade NAT, explicitly, rather than trusting is_private to cover it.
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    if ip.version == 6:
        if ip.is_site_local:
            return False
        # An IPv4 address tunnelled through IPv6 must be judged on the
        # embedded address, or ::ffff:169.254.169.254 walks straight through.
        mapped = getattr(ip, "ipv4_mapped", None) or getattr(ip, "sixtofour", None)
        if mapped is not None and not _is_public(mapped):
            return False
    return True


def resolve_safely(host: str, port: int) -> list[str]:
    """Resolve ``host`` and return its addresses, or raise :class:`UnsafeTarget`.

    Every resolved address must be public. Rejecting on *any* private result
    matters because a hostname can deliberately resolve to several addresses,
    and because the caller then connects to one of these addresses directly --
    never re-resolving -- which closes the DNS-rebinding window between the
    check and the connection.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTarget(f"Could not resolve {host!r}: {exc.strerror or exc}") from exc

    addrs: list[str] = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise UnsafeTarget(f"Unparseable address for {host!r}: {addr!r}")
        if not _is_public(ip):
            raise UnsafeTarget(
                f"{host!r} resolves to the non-public address {addr}. Refusing "
                "to connect: this tool will not be used to reach private "
                "networks or cloud instance metadata."
            )
        if addr not in addrs:
            addrs.append(addr)

    if not addrs:
        raise UnsafeTarget(f"{host!r} did not resolve to any address.")
    return addrs


# --------------------------------------------------------------------------- #
# The handshake
# --------------------------------------------------------------------------- #
def _ext(typ: int, body: bytes) -> bytes:
    return struct.pack("!HH", typ, len(body)) + body


def build_client_hello(host: str) -> bytes:
    """A TLS 1.3 ClientHello offering hybrids, with a key_share for X25519.

    The mismatch is the point: a server preferring one of the hybrid groups
    cannot complete the handshake from an X25519 share, so it must reply with
    a HelloRetryRequest that names the group it wants.
    """
    name = host.encode("idna")
    sni = _ext(0x0000, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    groups = _ext(0x000A, struct.pack("!H", len(_OFFER) * 2)
                  + b"".join(struct.pack("!H", g) for g in _OFFER))
    versions = _ext(0x002B, bytes([2]) + struct.pack("!H", 0x0304))
    share = struct.pack("!HH", 0x001D, 32) + os.urandom(32)
    key_share = _ext(0x0033, struct.pack("!H", len(share)) + share)
    sig_algs = _ext(0x000D, struct.pack("!H", 8)
                    + struct.pack("!4H", 0x0403, 0x0804, 0x0401, 0x0503))
    exts = sni + groups + versions + key_share + sig_algs

    body = (struct.pack("!H", 0x0303)          # legacy_version
            + os.urandom(32)                    # random
            + bytes([32]) + os.urandom(32)      # legacy session_id
            + struct.pack("!H", 4)              # cipher_suites
            + struct.pack("!2H", 0x1301, 0x1302)
            + bytes([1, 0])                     # compression: null
            + struct.pack("!H", len(exts)) + exts)
    hs = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16]) + struct.pack("!H", 0x0301) + struct.pack("!H", len(hs)) + hs


def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed mid-handshake.")
        buf += chunk
    return buf


def preferred_group(host: str, ip: str, port: int = 443,
                    timeout: float = DEFAULT_TIMEOUT) -> tuple[int | None, str]:
    """Return ``(group_id, how)`` for the group the server selects.

    ``how`` is "HelloRetryRequest" when the server asked us to retry with its
    preferred group, or "ServerHello" when it accepted the X25519 share we
    sent. ``group_id`` is None when the server said something unparseable, and
    ``how`` then explains what arrived.
    """
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.sendall(build_client_hello(host))
        rtype = _read_exact(sock, 1)[0]
        _read_exact(sock, 2)                       # record version
        rlen = struct.unpack("!H", _read_exact(sock, 2))[0]
        payload = _read_exact(sock, rlen)

    if rtype == 0x15:
        return None, "TLS alert (server rejected the ClientHello)"
    if rtype != 0x16:
        return None, f"unexpected TLS record type 0x{rtype:02x}"
    if not payload or payload[0] != 0x02:
        return None, f"unexpected handshake type 0x{payload[0]:02x}" if payload else "empty"

    body = payload[4:]
    how = "HelloRetryRequest" if body[2:34] == _HRR_RANDOM else "ServerHello"

    p = 2 + 32                                      # legacy_version + random
    p += 1 + body[p]                                # legacy session_id
    p += 2 + 1                                      # cipher suite + compression
    ext_len = struct.unpack("!H", body[p:p + 2])[0]
    p += 2
    end = min(p + ext_len, len(body))
    while p + 4 <= end:
        etyp, elen = struct.unpack("!HH", body[p:p + 4])
        p += 4
        ebody = body[p:p + elen]
        p += elen
        if etyp == 0x0033 and len(ebody) >= 2:      # key_share
            return struct.unpack("!H", ebody[:2])[0], how
    return None, f"{how} carried no key_share extension"


def negotiated(host: str, ip: str, port: int = 443,
               timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Complete a normal handshake and report what was negotiated."""
    from .certchain import chain_der

    ctx = ssl.create_default_context()
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cipher, _cipher_proto, bits = tls.cipher()
            return {
                "protocol": tls.version(),
                "cipher": cipher,
                "symmetric_bits": bits,
                "certificate": tls.getpeercert(),
                "certificate_der": tls.getpeercert(binary_form=True),
                "chain_der": chain_der(tls),
            }


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def _finding(host: str, algorithm: str, risk: str, why: str, family: str,
             snippet: str = "") -> Finding:
    """Build an endpoint finding.

    ``file_path`` carries the host and ``line_number`` is 0: a live endpoint
    has no file or line. ``origin="endpoint"`` is the discriminator, following
    the existing "source" / "dependency" split.
    """
    f = Finding(
        file_path=host,
        line_number=0,
        algorithm=algorithm,
        risk_level=risk,
        why=why,
        family=family,
        snippet=snippet,
        confidence="high",      # observed on the wire, not inferred from text
        origin="endpoint",
    )
    return f.enrich()


_PROTOCOL_FAMILY = {
    "TLSv1.3": None,                      # nothing to report
    "TLSv1.2": ("tls12", RISK_LOW, "TLS 1.2 still relies on classical key exchange."),
    "TLSv1.1": ("tls_old", RISK_MEDIUM, "TLS 1.1 is deprecated and uses quantum-vulnerable key exchange."),
    "TLSv1": ("tls_old", RISK_MEDIUM, "TLS 1.0 is deprecated and uses quantum-vulnerable key exchange."),
}


def scan_url(target: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[list[Finding], dict]:
    """Scan one HTTPS endpoint. Returns ``(findings, details)``.

    Raises :class:`UnsafeTarget` if the target is not a public HTTPS endpoint.
    """
    host, port = parse_target(target)
    addrs = resolve_safely(host, port)
    ip = addrs[0]

    info = negotiated(host, ip, port, timeout)
    group_id, how = preferred_group(host, ip, port, timeout)

    findings: list[Finding] = []

    # 1. Key exchange -- the harvest-now-decrypt-later risk, so it leads.
    group_name, is_pq = GROUPS.get(group_id, (None, False)) if group_id else (None, False)
    if group_id is None:
        group_label = f"unknown ({how})"
    else:
        group_label = group_name or f"0x{group_id:04x}"

    if is_pq:
        findings.append(_finding(
            host, f"{group_label} key exchange", RISK_LOW,
            "Post-quantum hybrid key exchange negotiated: the session secret "
            "is protected by ML-KEM alongside the classical curve, so recorded "
            "traffic is not exposed by Shor's algorithm alone. No action needed.",
            "pqc_hybrid",
            snippet=f"key_share: {group_label} (via {how})",
        ))
    elif group_id is not None:
        findings.append(_finding(
            host, f"{group_label} key exchange", RISK_HIGH,
            "Classical key exchange negotiated. Shor's algorithm recovers the "
            "session secret, and because an adversary can record the traffic "
            "now and decrypt it later, data sent today is exposed "
            "retroactively. Offer a hybrid group such as X25519MLKEM768.",
            "ecc",
            snippet=f"key_share: {group_label} (via {how})",
        ))

    # 2. Protocol version.
    proto = info["protocol"] or ""
    entry = _PROTOCOL_FAMILY.get(proto)
    if entry:
        family, risk, why = entry
        findings.append(_finding(host, proto, risk, why, family,
                                 snippet=f"negotiated {proto}"))

    # 3. Symmetric cipher. Reported only when it is genuinely weak: AES-128
    #    under Grover is ~2^64 work, which is worth a LOW note, not a warning.
    if info["symmetric_bits"] and info["symmetric_bits"] < 256:
        findings.append(_finding(
            host, info["cipher"] or "symmetric cipher", RISK_LOW,
            f"{info['symmetric_bits']}-bit symmetric key. Grover's algorithm "
            "square-roots a brute-force search, so this retains roughly "
            f"{info['symmetric_bits'] // 2}-bit security against a quantum "
            "attacker. Acceptable today; AES-256 is the long-term choice.",
            "aes128",
            snippet=f"cipher: {info['cipher']}",
        ))

    # 4. The certificate chain -- every signature, not just the leaf's.
    from .certchain import analyse_chain
    chain_findings, chain = analyse_chain(host, info.get("chain_der") or [])
    findings.extend(chain_findings)

    details = {
        "host": host,
        "port": port,
        "addresses": addrs,
        "chain": chain,
        "protocol": proto,
        "cipher": info["cipher"],
        "symmetric_bits": info["symmetric_bits"],
        "key_exchange": group_label,
        "key_exchange_post_quantum": bool(is_pq),
        "key_exchange_observed_via": how,
        "certificate": _cert_summary(info["certificate"]),
    }
    return findings, details


def _cert_summary(cert: dict | None) -> dict:
    """The parts of a certificate stdlib ssl exposes without extra parsing."""
    if not cert:
        return {}
    def flat(field):
        return {k: v for tup in cert.get(field, ()) for k, v in tup}
    subject, issuer = flat("subject"), flat("issuer")
    return {
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
        "not_after": cert.get("notAfter", ""),
        "alt_names": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:8],
    }
