"""Certificate chain analysis: every signature in the chain, not just the leaf.

A chain is only as strong as its weakest signature. A leaf certificate can use
ECDSA P-256 while the intermediate that signs it uses RSA-2048, and an attacker
who can forge the intermediate's signature can mint a leaf for any name under
it. Checkers that look only at the server certificate miss this routinely.

WHY THERE IS A DER PARSER IN HERE
``ssl.getpeercert()`` returns subject, issuer, validity and SANs -- but not the
signature algorithm and not the public key, which are the only two fields that
matter for quantum exposure. Getting them normally means adding
``cryptography`` as a runtime dependency; this package deliberately has none
beyond ``rich``, and the rest of the repo implements its primitives from
scratch rather than calling a library. So the handful of fields needed are
walked out of the DER directly.

The parser is deliberately minimal: it reads tag-length-value structure and
OBJECT IDENTIFIERs, and it never evaluates, verifies or trusts anything. It is
not a substitute for certificate validation -- ``ssl`` has already done that by
the time the chain reaches us.

WHAT THE RISK ACTUALLY IS
Breaking a certificate signature lets an attacker forge *future* certificates.
That is bad, but unlike the key exchange it is not retroactive: traffic
recorded today is not decrypted by it, and certificates rotate every ~90 days,
so the CA ecosystem's own migration fixes most of it. The findings say so,
rather than implying the same urgency as a harvest-now-decrypt-later exposure.

A root's own signature is a special case: it is self-signed, and it is trusted
because it is in the client's trust store, not because of that signature. A
quantum attacker gains nothing by forging it, so roots are reported for
completeness and not counted as findings.
"""

from __future__ import annotations

import ssl

from .scanner import RISK_HIGH, RISK_LOW, Finding

# --------------------------------------------------------------------------- #
# Minimal DER reader
# --------------------------------------------------------------------------- #
_SEQUENCE = 0x30
_INTEGER = 0x02
_BIT_STRING = 0x03
_OID = 0x06
_CONTEXT_0 = 0xA0          # [0] EXPLICIT, the optional version field


class DERError(ValueError):
    """The certificate bytes were not structured as expected."""


def read_tlv(buf: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Read one tag-length-value triple. Returns ``(tag, value, next_offset)``.

    Supports DER's definite-length form only, which is all a certificate uses.
    """
    if offset + 2 > len(buf):
        raise DERError("truncated: no room for a tag and length")
    tag = buf[offset]
    first = buf[offset + 1]
    pos = offset + 2

    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0:
            raise DERError("indefinite lengths are not valid in DER")
        if n > 4:
            raise DERError(f"implausible length-of-length {n}")
        if pos + n > len(buf):
            raise DERError("truncated length field")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n

    if pos + length > len(buf):
        raise DERError("value runs past the end of the buffer")
    return tag, buf[pos:pos + length], pos + length


def children(value: bytes) -> list[tuple[int, bytes]]:
    """Every immediate child TLV of a constructed value."""
    out: list[tuple[int, bytes]] = []
    off = 0
    while off < len(value):
        tag, val, off = read_tlv(value, off)
        out.append((tag, val))
    return out


def decode_oid(value: bytes) -> str:
    """Decode an OBJECT IDENTIFIER's contents to dotted-decimal form."""
    if not value:
        raise DERError("empty OID")
    first = value[0]
    # The first two arcs are packed into one byte as 40*arc1 + arc2.
    arcs = [first // 40, first % 40] if first < 80 else [2, first - 80]
    acc = 0
    for byte in value[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(acc)
            acc = 0
    return ".".join(str(a) for a in arcs)


# --------------------------------------------------------------------------- #
# OID tables
#
# (label, family, post_quantum). family "" means the algorithm is not a
# quantum-vulnerable signature scheme and needs no finding.
# --------------------------------------------------------------------------- #
SIGNATURE_OIDS: dict[str, tuple[str, str, bool]] = {
    "1.2.840.113549.1.1.5":  ("SHA-1 with RSA", "rsa", False),
    "1.2.840.113549.1.1.11": ("SHA-256 with RSA", "rsa", False),
    "1.2.840.113549.1.1.12": ("SHA-384 with RSA", "rsa", False),
    "1.2.840.113549.1.1.13": ("SHA-512 with RSA", "rsa", False),
    "1.2.840.113549.1.1.10": ("RSASSA-PSS", "rsa", False),
    "1.2.840.10045.4.1":     ("ECDSA with SHA-1", "ecc", False),
    "1.2.840.10045.4.3.2":   ("ECDSA with SHA-256", "ecc", False),
    "1.2.840.10045.4.3.3":   ("ECDSA with SHA-384", "ecc", False),
    "1.2.840.10045.4.3.4":   ("ECDSA with SHA-512", "ecc", False),
    "1.2.840.10040.4.3":     ("DSA with SHA-1", "dsa", False),
    "2.16.840.1.101.3.4.3.2": ("DSA with SHA-256", "dsa", False),
    "1.3.101.112":           ("Ed25519", "ecc", False),
    "1.3.101.113":           ("Ed448", "ecc", False),
    # FIPS 204. No public CA issues these yet, so this is forward-looking --
    # but classifying a post-quantum signature as safe is correctness, not
    # speculation, and the alternative is reporting it as "unknown".
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", "pqc_signature", True),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", "pqc_signature", True),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", "pqc_signature", True),
}

PUBKEY_OIDS: dict[str, tuple[str, str, bool]] = {
    "1.2.840.113549.1.1.1": ("RSA", "rsa", False),
    "1.2.840.10045.2.1":    ("EC", "ecc", False),
    "1.2.840.10040.4.1":    ("DSA", "dsa", False),
    "1.3.101.112":          ("Ed25519", "ecc", False),
    "1.3.101.113":          ("Ed448", "ecc", False),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", "pqc_signature", True),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", "pqc_signature", True),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", "pqc_signature", True),
}

CURVE_OIDS: dict[str, tuple[str, int]] = {
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34":        ("P-384", 384),
    "1.3.132.0.35":        ("P-521", 521),
    "1.3.132.0.10":        ("secp256k1", 256),
    "1.3.132.0.33":        ("P-224", 224),
}


# --------------------------------------------------------------------------- #
# Certificate fields
# --------------------------------------------------------------------------- #
def parse_certificate(der: bytes) -> dict:
    """Extract the quantum-relevant fields from one DER certificate.

    Returns the signature algorithm OID and label, and the public key's
    algorithm and size. Unknown OIDs are reported as such rather than guessed.
    """
    tag, cert_value, _ = read_tlv(der)
    if tag != _SEQUENCE:
        raise DERError(f"a certificate must be a SEQUENCE, got tag 0x{tag:02x}")

    top = children(cert_value)
    if len(top) < 3:
        raise DERError("a certificate needs tbsCertificate, "
                       "signatureAlgorithm and signatureValue")
    tbs_value = top[0][1]
    sig_alg_value = top[1][1]

    sig_oid = _first_oid(sig_alg_value, "signatureAlgorithm")
    sig_label, sig_family, sig_pq = SIGNATURE_OIDS.get(
        sig_oid, (f"unknown ({sig_oid})", "", False))

    key = _public_key(tbs_value)
    return {
        "signature_oid": sig_oid,
        "signature": sig_label,
        "signature_family": sig_family,
        "signature_post_quantum": sig_pq,
        **key,
    }


def _first_oid(alg_identifier: bytes, what: str) -> str:
    """The algorithm OID of an AlgorithmIdentifier SEQUENCE's contents."""
    for tag, val in children(alg_identifier):
        if tag == _OID:
            return decode_oid(val)
    raise DERError(f"{what} contained no OBJECT IDENTIFIER")


def _public_key(tbs_value: bytes) -> dict:
    """Read subjectPublicKeyInfo out of a TBSCertificate.

    The field order is fixed, but ``version`` is an optional [0] EXPLICIT, so
    the walk skips it when present rather than relying on a fixed index.
    """
    kids = children(tbs_value)
    idx = 0
    if kids and kids[0][0] == _CONTEXT_0:
        idx = 1                                   # skip version
    # serialNumber, signature, issuer, validity, subject, then SPKI.
    idx += 5
    if idx >= len(kids):
        raise DERError("TBSCertificate ended before subjectPublicKeyInfo")
    spki_tag, spki_value = kids[idx]
    if spki_tag != _SEQUENCE:
        raise DERError("subjectPublicKeyInfo is not a SEQUENCE")

    spki = children(spki_value)
    if len(spki) < 2:
        raise DERError("subjectPublicKeyInfo needs an algorithm and a key")
    alg_value = spki[0][1]
    key_bits_value = spki[1][1]

    oid = _first_oid(alg_value, "subjectPublicKeyInfo algorithm")
    label, family, pq = PUBKEY_OIDS.get(oid, (f"unknown ({oid})", "", False))

    size = 0
    curve = ""
    if family == "rsa":
        size = _rsa_modulus_bits(key_bits_value)
    elif family == "ecc":
        for tag, val in children(alg_value):
            if tag == _OID:
                dotted = decode_oid(val)
                if dotted in CURVE_OIDS:
                    curve, size = CURVE_OIDS[dotted]
        if not curve and label in ("Ed25519", "Ed448"):
            curve, size = label, 255 if label == "Ed25519" else 448

    return {
        "key_oid": oid,
        "key_algorithm": label,
        "key_family": family,
        "key_post_quantum": pq,
        "key_bits": size,
        "key_curve": curve,
    }


def _rsa_modulus_bits(bit_string_value: bytes) -> int:
    """Bit length of an RSA modulus inside a subjectPublicKey BIT STRING.

    The BIT STRING's first content byte counts unused trailing bits; the rest
    is a DER RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER }.
    """
    if not bit_string_value:
        return 0
    inner = bit_string_value[1:]                  # drop the unused-bits count
    try:
        tag, seq_value, _ = read_tlv(inner)
        if tag != _SEQUENCE:
            return 0
        kids = children(seq_value)
        if not kids or kids[0][0] != _INTEGER:
            return 0
        modulus = kids[0][1].lstrip(b"\x00")      # DER sign byte
        return len(modulus) * 8
    except DERError:
        return 0


# --------------------------------------------------------------------------- #
# Chain retrieval
# --------------------------------------------------------------------------- #
def chain_der(tls_socket) -> list[bytes]:
    """Every certificate in the verified chain, as DER.

    ``SSLSocket.get_verified_chain`` is public from Python 3.13; on 3.12 the
    same method exists on the private ``_sslobj``. Both are tried, and the
    fallback is the leaf alone -- a chain of one is still worth reporting, and
    is better than failing the whole scan over an attribute.
    """
    getter = getattr(tls_socket, "get_verified_chain", None)
    if getter is None:
        sslobj = getattr(tls_socket, "_sslobj", None)
        getter = getattr(sslobj, "get_verified_chain", None) if sslobj else None

    if getter is not None:
        try:
            # public_bytes() yields PEM; PEM_cert_to_DER_cert is a public API,
            # which avoids depending on ssl._ssl.ENCODING_DER.
            return [ssl.PEM_cert_to_DER_cert(c.public_bytes()) for c in getter()]
        except Exception:
            pass

    leaf = tls_socket.getpeercert(binary_form=True)
    return [leaf] if leaf else []


def role_for(index: int, total: int) -> str:
    """Position in the chain, from the server outwards.

    Intermediates are numbered when there is more than one. Two intermediates
    signed with the same algorithm are otherwise indistinguishable in the
    findings table, and two identical-looking rows read as a duplicate rather
    than as two separate certificates.
    """
    if index == 0:
        return "leaf"
    if index == total - 1:
        return "root"
    # total - 2 non-leaf, non-root positions; number them only if there are 2+.
    return f"intermediate {index}" if total > 3 else "intermediate"


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def analyse_chain(host: str, ders: list[bytes]) -> tuple[list[Finding], list[dict]]:
    """Classify every certificate in the chain. Returns ``(findings, chain)``."""
    findings: list[Finding] = []
    chain: list[dict] = []
    total = len(ders)

    for i, der in enumerate(ders):
        role = role_for(i, total)
        try:
            parsed = parse_certificate(der)
        except DERError as exc:
            chain.append({"role": role, "error": str(exc)})
            continue

        entry = {"role": role, **parsed}
        chain.append(entry)

        # A root is trusted because it is in the client's trust store, not
        # because of its self-signature, so forging that signature buys an
        # attacker nothing. Reported above, but not a finding.
        if role.startswith("root"):
            continue

        findings.extend(_cert_findings(host, role, entry))

    return findings, chain


def _cert_findings(host: str, role: str, c: dict) -> list[Finding]:
    out: list[Finding] = []
    where = f"{host} [{role} certificate]"

    if c["signature_post_quantum"]:
        out.append(_make(
            where, f"{c['signature']} certificate signature", RISK_LOW,
            f"The {role} certificate is signed with {c['signature']}, a "
            "NIST post-quantum signature scheme. Nothing to migrate.",
            "pqc_signature"))
    elif c["signature_family"]:
        out.append(_make(
            where, f"{c['signature']} certificate signature", RISK_HIGH,
            f"The {role} certificate is signed with {c['signature']}, which "
            "Shor's algorithm breaks. This permits forging future "
            "certificates; unlike the key exchange it is not retroactive, and "
            "certificates rotate every ~90 days, so this largely follows the "
            "CA ecosystem's own migration. A chain is only as strong as its "
            "weakest signature.",
            c["signature_family"]))

    key_label = c["key_algorithm"]
    if c["key_bits"]:
        key_label += f"-{c['key_bits']}" if not c["key_curve"] else f" {c['key_curve']}"

    if c["key_post_quantum"]:
        out.append(_make(
            where, f"{key_label} certificate key", RISK_LOW,
            f"The {role} certificate's public key is {key_label}, a NIST "
            "post-quantum scheme. Nothing to migrate.",
            "pqc_signature"))
    elif c["key_family"]:
        out.append(_make(
            where, f"{key_label} certificate key", RISK_HIGH,
            f"The {role} certificate's public key is {key_label}. Shor's "
            "algorithm recovers the private key from it regardless of size, "
            "which allows impersonation. Not retroactive: it does not expose "
            "traffic already recorded.",
            c["key_family"]))
    return out


def _make(where: str, algorithm: str, risk: str, why: str, family: str) -> Finding:
    f = Finding(
        file_path=where,
        line_number=0,
        algorithm=algorithm,
        risk_level=risk,
        why=why,
        family=family,
        confidence="high",      # read out of the certificate, not inferred
        origin="endpoint",
    )
    return f.enrich()
