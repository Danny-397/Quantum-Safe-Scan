"""Tests for certificate chain analysis.

This module hand-parses DER because the two fields that matter for quantum
exposure -- the signature algorithm and the public key -- are the two that
``ssl.getpeercert()`` does not return, and the package has no cryptography
dependency. Hand-rolled binary parsing against a real wire format needs to be
tested on structure, not just on happy-path output, so the certificates here
are built byte by byte rather than captured: a fixture proves one certificate
parses, a builder proves the parser understands the format.

The weakest-link case is the one the feature exists for. Real example found
while building it: cloudflare.com's leaf is ECDSA P-256, but an intermediate
in its chain is signed SHA-256 with RSA. A checker that reads only the server
certificate reports "modern ECDSA" and misses the RSA signature above it.
"""

import pytest

from quantumsafe.certchain import (
    CURVE_OIDS,
    DERError,
    PUBKEY_OIDS,
    SIGNATURE_OIDS,
    analyse_chain,
    children,
    decode_oid,
    parse_certificate,
    read_tlv,
    role_for,
)
from quantumsafe.recommender import NO_ACTION_FAMILIES, RECOMMENDATIONS
from quantumsafe.scanner import RISK_HIGH, RISK_LOW

# --------------------------------------------------------------------------- #
# DER builders -- the inverse of the parser, so the tests state the format
# independently of the code under test.
# --------------------------------------------------------------------------- #
def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + der_len(len(value)) + value


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def integer(n: int) -> bytes:
    raw = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return tlv(0x02, raw)


def bitstring(payload: bytes) -> bytes:
    return tlv(0x03, b"\x00" + payload)


def encode_oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        if arc == 0:
            out.append(0)
            continue
        chunks = []
        while arc:
            chunks.insert(0, arc & 0x7F)
            arc >>= 7
        for c in chunks[:-1]:
            out.append(c | 0x80)
        out.append(chunks[-1])
    return tlv(0x06, bytes(out))


def alg_id(oid: str, *params: bytes) -> bytes:
    return seq(encode_oid(oid), *params)


RSA_OID = "1.2.840.113549.1.1.1"
EC_OID = "1.2.840.10045.2.1"
SHA256_RSA = "1.2.840.113549.1.1.11"
ECDSA_SHA256 = "1.2.840.10045.4.3.2"
MLDSA65 = "2.16.840.1.101.3.4.3.18"
P256 = "1.2.840.10045.3.1.7"


def rsa_spki(bits: int) -> bytes:
    modulus = (1 << (bits - 1)) | 1          # exactly `bits` bits
    return seq(alg_id(RSA_OID, tlv(0x05, b"")),
               bitstring(seq(integer(modulus), integer(65537))))


def ec_spki(curve_oid: str = P256) -> bytes:
    return seq(alg_id(EC_OID, encode_oid(curve_oid)), bitstring(b"\x04" + b"\x11" * 64))


def pq_spki() -> bytes:
    return seq(alg_id(MLDSA65), bitstring(b"\x22" * 32))


def make_cert(sig_oid: str = SHA256_RSA, spki: bytes | None = None,
              with_version: bool = True) -> bytes:
    """A certificate with just enough structure for the fields we read."""
    name = seq(seq(seq(encode_oid("2.5.4.3"), tlv(0x13, b"example.com"))))
    validity = seq(tlv(0x17, b"260101000000Z"), tlv(0x17, b"270101000000Z"))
    parts = []
    if with_version:
        parts.append(tlv(0xA0, integer(2)))
    parts += [integer(1234), alg_id(sig_oid), name, validity, name,
              spki if spki is not None else rsa_spki(2048)]
    tbs = seq(*parts)
    return seq(tbs, alg_id(sig_oid), bitstring(b"\x99" * 16))


# --------------------------------------------------------------------------- #
# TLV reader
# --------------------------------------------------------------------------- #
def test_reads_a_short_form_tlv():
    tag, value, nxt = read_tlv(tlv(0x02, b"\x01\x02"))
    assert (tag, value, nxt) == (0x02, b"\x01\x02", 4)


@pytest.mark.parametrize("size", [127, 128, 255, 256, 65535, 70000])
def test_reads_long_form_lengths(size):
    """Certificates routinely exceed 127 bytes, so long form is the normal case."""
    payload = b"x" * size
    tag, value, nxt = read_tlv(tlv(0x04, payload))
    assert tag == 0x04
    assert value == payload
    assert nxt == len(tlv(0x04, payload))


def test_rejects_indefinite_length():
    """Valid in BER, forbidden in DER. Accepting it would read past the value."""
    with pytest.raises(DERError, match="indefinite"):
        read_tlv(b"\x30\x80\x00\x00")


def test_rejects_implausible_length_of_length():
    with pytest.raises(DERError, match="length-of-length"):
        read_tlv(b"\x30\x88" + b"\xff" * 8)


@pytest.mark.parametrize("buf", [b"", b"\x30", b"\x30\x05\x01\x02"])
def test_rejects_truncated_input(buf):
    with pytest.raises(DERError):
        read_tlv(buf)


def test_children_walks_every_sibling():
    body = integer(1) + integer(2) + tlv(0x04, b"abc")
    kids = children(body)
    assert [t for t, _ in kids] == [0x02, 0x02, 0x04]
    assert kids[2][1] == b"abc"


def test_children_of_empty_value_is_empty():
    assert children(b"") == []


# --------------------------------------------------------------------------- #
# OID decoding
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("dotted", [
    "1.2.840.113549.1.1.11",      # sha256WithRSA
    "1.2.840.10045.4.3.2",        # ecdsa-with-SHA256
    "2.16.840.1.101.3.4.3.18",    # ML-DSA-65: first arc 2, needs the >=80 path
    "1.3.101.112",                # Ed25519
    "2.5.4.3",                    # commonName
    "1.2.840.10045.3.1.7",        # prime256v1
])
def test_oid_round_trips(dotted):
    _tag, value, _ = read_tlv(encode_oid(dotted))
    assert decode_oid(value) == dotted


def test_oid_first_two_arcs_are_packed_into_one_byte():
    _tag, value, _ = read_tlv(encode_oid("1.2.840.113549"))
    assert value[0] == 42, "1*40 + 2"
    assert decode_oid(value).startswith("1.2.")


def test_empty_oid_is_rejected():
    with pytest.raises(DERError, match="empty OID"):
        decode_oid(b"")


# --------------------------------------------------------------------------- #
# Certificate parsing
# --------------------------------------------------------------------------- #
def test_parses_signature_and_key():
    c = parse_certificate(make_cert(SHA256_RSA, rsa_spki(2048)))
    assert c["signature"] == "SHA-256 with RSA"
    assert c["signature_family"] == "rsa"
    assert c["key_algorithm"] == "RSA"
    assert c["key_bits"] == 2048
    assert c["key_family"] == "rsa"
    assert c["signature_post_quantum"] is False


@pytest.mark.parametrize("bits", [1024, 2048, 3072, 4096])
def test_reads_rsa_modulus_size(bits):
    c = parse_certificate(make_cert(SHA256_RSA, rsa_spki(bits)))
    assert c["key_bits"] == bits


def test_parses_an_ec_key_and_its_curve():
    c = parse_certificate(make_cert(ECDSA_SHA256, ec_spki(P256)))
    assert c["key_algorithm"] == "EC"
    assert c["key_curve"] == "P-256"
    assert c["key_bits"] == 256
    assert c["key_family"] == "ecc"


@pytest.mark.parametrize("oid,curve,bits", [
    (o, name, size) for o, (name, size) in CURVE_OIDS.items()
])
def test_every_known_curve_is_read(oid, curve, bits):
    c = parse_certificate(make_cert(ECDSA_SHA256, ec_spki(oid)))
    assert (c["key_curve"], c["key_bits"]) == (curve, bits)


def test_version_field_is_optional():
    """version is [0] EXPLICIT with a default, so a v1 cert omits it.

    Indexing subjectPublicKeyInfo by a fixed position would read the wrong
    field for such a certificate.
    """
    with_v = parse_certificate(make_cert(SHA256_RSA, rsa_spki(2048), with_version=True))
    without = parse_certificate(make_cert(SHA256_RSA, rsa_spki(2048), with_version=False))
    assert with_v["key_bits"] == without["key_bits"] == 2048
    assert with_v["key_algorithm"] == without["key_algorithm"] == "RSA"


def test_post_quantum_signature_is_recognised():
    c = parse_certificate(make_cert(MLDSA65, pq_spki()))
    assert c["signature"] == "ML-DSA-65"
    assert c["signature_post_quantum"] is True
    assert c["key_post_quantum"] is True


def test_unknown_algorithm_is_reported_not_guessed():
    c = parse_certificate(make_cert("1.2.3.4.5", rsa_spki(2048)))
    assert "unknown" in c["signature"]
    assert c["signature_family"] == "", "an unknown OID must not be classified"


def test_non_sequence_is_refused():
    with pytest.raises(DERError, match="SEQUENCE"):
        parse_certificate(tlv(0x02, b"\x01"))


def test_certificate_with_too_few_fields_is_refused():
    with pytest.raises(DERError, match="tbsCertificate"):
        parse_certificate(seq(integer(1)))


def test_truncated_tbs_is_refused():
    short_tbs = seq(integer(1), alg_id(SHA256_RSA))
    with pytest.raises(DERError, match="subjectPublicKeyInfo"):
        parse_certificate(seq(short_tbs, alg_id(SHA256_RSA), bitstring(b"\x00")))


# --------------------------------------------------------------------------- #
# Chain roles
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("index,total,expected", [
    (0, 1, "leaf"),
    (0, 4, "leaf"),
    (1, 3, "intermediate"),       # a lone intermediate needs no number
    (1, 4, "intermediate 1"),     # two of them must be distinguishable
    (2, 4, "intermediate 2"),
    (3, 4, "root"),
    (1, 2, "root"),
    (2, 3, "root"),
])
def test_role_for_position(index, total, expected):
    assert role_for(index, total) == expected


def test_multiple_intermediates_get_distinct_labels():
    """Two intermediates with the same algorithm are otherwise identical rows."""
    chain = [make_cert(ECDSA_SHA256, ec_spki()),
             make_cert(ECDSA_SHA256, ec_spki()),
             make_cert(ECDSA_SHA256, ec_spki()),
             make_cert(ECDSA_SHA256, ec_spki())]
    findings, parsed = analyse_chain("example.com", chain)
    roles = [c["role"] for c in parsed]
    assert roles == ["leaf", "intermediate 1", "intermediate 2", "root"]
    locations = {f.file_path for f in findings}
    assert len(locations) == 3, "each reported certificate needs its own label"


def test_a_numbered_root_is_still_excluded():
    """role.startswith("root") must not accidentally match an intermediate."""
    chain = [make_cert(ECDSA_SHA256, ec_spki()) for _ in range(4)]
    findings, _ = analyse_chain("example.com", chain)
    assert not any("root" in f.file_path for f in findings)


# --------------------------------------------------------------------------- #
# Chain analysis
# --------------------------------------------------------------------------- #
def test_the_weakest_link_is_found_above_the_leaf():
    """The case the feature exists for.

    A modern ECDSA leaf signed by an RSA intermediate: reading only the
    server certificate reports "ECDSA" and misses the RSA signature that an
    attacker could forge to mint a leaf for any name under it.
    """
    chain = [
        make_cert(ECDSA_SHA256, ec_spki()),     # leaf: all elliptic curve
        make_cert(SHA256_RSA, rsa_spki(2048)),  # intermediate: RSA
        make_cert(SHA256_RSA, rsa_spki(4096)),  # root
    ]
    findings, parsed = analyse_chain("example.com", chain)
    rsa = [f for f in findings if f.family == "rsa"]
    assert rsa, "the RSA intermediate must be reported"
    assert any("intermediate" in f.file_path for f in rsa)
    assert [c["role"] for c in parsed] == ["leaf", "intermediate", "root"]


def test_the_root_is_reported_but_not_a_finding():
    """A root is trusted by being in the trust store, not by its signature.

    Forging a root's self-signature buys an attacker nothing, so counting it
    would inflate every chain with an unactionable HIGH.
    """
    chain = [
        make_cert(ECDSA_SHA256, ec_spki()),
        make_cert(SHA256_RSA, rsa_spki(4096)),   # root, RSA-signed
    ]
    findings, parsed = analyse_chain("example.com", chain)
    assert parsed[-1]["role"] == "root"
    assert parsed[-1]["signature_family"] == "rsa", "still parsed and shown"
    assert not any("root" in f.file_path for f in findings)


def test_certificate_findings_say_the_risk_is_not_retroactive():
    """The distinction from key exchange is the point of the wording."""
    findings, _ = analyse_chain("example.com", [make_cert(SHA256_RSA, rsa_spki(2048))])
    sig = [f for f in findings if "signature" in f.algorithm][0]
    assert "not retroactive" in sig.why or "not be retroactive" in sig.why
    assert "forging future" in sig.why


def test_post_quantum_chain_produces_only_low_findings():
    findings, _ = analyse_chain("example.com", [make_cert(MLDSA65, pq_spki())])
    assert findings
    assert all(f.risk_level == RISK_LOW for f in findings)
    assert all(f.family == "pqc_signature" for f in findings)


def test_classical_chain_findings_are_high():
    findings, _ = analyse_chain("example.com", [make_cert(SHA256_RSA, rsa_spki(2048))])
    assert all(f.risk_level == RISK_HIGH for f in findings)


def test_findings_are_endpoint_origin_with_the_role_in_the_location():
    findings, _ = analyse_chain("example.com", [make_cert(SHA256_RSA, rsa_spki(2048))])
    for f in findings:
        assert f.origin == "endpoint"
        assert f.line_number == 0
        assert "example.com" in f.file_path and "leaf" in f.file_path
        assert f.recommendation, "findings must be enriched"


def test_an_unparseable_certificate_does_not_abort_the_chain():
    """One malformed certificate must not lose the rest of the chain."""
    chain = [make_cert(SHA256_RSA, rsa_spki(2048)), b"\x30\x05garbage",
             make_cert(ECDSA_SHA256, ec_spki())]
    findings, parsed = analyse_chain("example.com", chain)
    assert len(parsed) == 3
    assert "error" in parsed[1]
    assert findings, "the parseable certificates are still reported"


def test_empty_chain_is_handled():
    findings, parsed = analyse_chain("example.com", [])
    assert findings == [] and parsed == []


def test_a_single_certificate_chain_is_treated_as_a_leaf():
    """The fallback path when get_verified_chain is unavailable."""
    findings, parsed = analyse_chain("example.com", [make_cert(SHA256_RSA, rsa_spki(2048))])
    assert parsed[0]["role"] == "leaf"
    assert findings


# --------------------------------------------------------------------------- #
# Table consistency
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("oid,entry", sorted(SIGNATURE_OIDS.items()))
def test_signature_families_exist_in_the_recommender(oid, entry):
    """A family with no recommendation would degrade to generic advice."""
    _label, family, _pq = entry
    assert family in RECOMMENDATIONS, f"{oid} maps to unknown family {family!r}"


@pytest.mark.parametrize("oid,entry", sorted(PUBKEY_OIDS.items()))
def test_pubkey_families_exist_in_the_recommender(oid, entry):
    _label, family, _pq = entry
    assert family in RECOMMENDATIONS, f"{oid} maps to unknown family {family!r}"


def test_post_quantum_entries_are_all_no_action_families():
    for table in (SIGNATURE_OIDS, PUBKEY_OIDS):
        for oid, (label, family, pq) in table.items():
            if pq:
                assert family in NO_ACTION_FAMILIES, (
                    f"{label} is post-quantum but {family!r} would be charged "
                    "as migration work")


def test_no_classical_entry_is_marked_post_quantum():
    for table in (SIGNATURE_OIDS, PUBKEY_OIDS):
        for label, family, pq in table.values():
            if family in ("rsa", "ecc", "dsa"):
                assert pq is False, f"{label} is not post-quantum"
