"""Standards-conformance tests for the export formats.

Two claims made in the README are checked here against the actual specs, so
"SARIF/CBOM output" is a *verified* claim, not an assertion:

* SARIF 2.1.0 output is validated against the official OASIS JSON Schema
  (vendored at ``tests/schemas/sarif-2.1.0.json`` so the test runs offline).
  GitHub code scanning rejects malformed SARIF, so this really matters.
* CycloneDX 1.6 CBOM output is checked against the spec's required structure and
  the authoritative ``primitive`` enum. (The CycloneDX schema ``$ref``s external
  sub-schemas — jsf/spdx — so we assert the crypto-asset constraints directly
  rather than resolve those refs offline.)
"""

import json
import os

import pytest

from quantumsafe.reporter import build_report, to_cbom, to_sarif
from quantumsafe.scanner import scan_path

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCHEMA_DIR = os.path.join(_HERE, "schemas")
_CORPUS = os.path.join(_HERE, "..", "benchmark", "positive")

# CycloneDX 1.6 cryptoProperties.algorithmProperties.primitive enum (verbatim
# from schema/bom-1.6.schema.json).
_CDX_PRIMITIVES = {
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
    "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown",
}


@pytest.fixture(scope="module")
def report():
    findings = scan_path(_CORPUS)
    assert findings, "expected the positive corpus to produce findings"
    return build_report(findings, "benchmark/positive")


def test_sarif_validates_against_official_schema(report):
    jsonschema = pytest.importorskip("jsonschema")
    with open(os.path.join(_SCHEMA_DIR, "sarif-2.1.0.json"), encoding="utf-8") as fh:
        schema = json.load(fh)
    doc = json.loads(to_sarif(report))
    # Raises jsonschema.ValidationError if the output is non-conformant.
    jsonschema.validate(instance=doc, schema=schema)


def test_sarif_structure_is_internally_consistent(report):
    doc = json.loads(to_sarif(report))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "QuantumSafe"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids, "expected at least one rule"
    for res in run["results"]:
        assert res["ruleId"] in rule_ids, f"result references undeclared rule {res['ruleId']}"
        assert res["level"] in ("error", "warning", "note")
        region = res["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1


def test_cbom_conforms_to_cyclonedx_1_6(report):
    doc = json.loads(to_cbom(report))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert isinstance(doc["version"], int)
    assert doc["components"], "expected at least one cryptographic-asset component"

    seen_refs = set()
    crypto_assets = 0
    for c in doc["components"]:
        # A CBOM may mix cryptographic-asset (algorithms) and library
        # (dependencies) components; both must carry a unique bom-ref.
        assert c["type"] in ("cryptographic-asset", "library"), f"unexpected type {c['type']!r}"
        ref = c["bom-ref"]
        assert ref and ref not in seen_refs, f"duplicate/empty bom-ref {ref!r}"
        seen_refs.add(ref)

        occurrences = c["evidence"]["occurrences"]
        assert occurrences and all("location" in o for o in occurrences)

        if c["type"] != "cryptographic-asset":
            continue
        crypto_assets += 1
        cp = c["cryptoProperties"]
        assert cp["assetType"] == "algorithm"
        primitive = cp["algorithmProperties"]["primitive"]
        assert primitive in _CDX_PRIMITIVES, f"invalid primitive {primitive!r}"
        assert cp["algorithmProperties"]["nistQuantumSecurityLevel"] in range(0, 7)

    assert crypto_assets >= 1, "expected at least one cryptographic-asset component"


def test_cbom_metadata_is_well_formed(report):
    doc = json.loads(to_cbom(report))
    tools = doc["metadata"]["tools"]["components"]
    assert any(t["name"] == "QuantumSafe" for t in tools)


# --------------------------------------------------------------------------- #
# Endpoint findings in SARIF
#
# A live-endpoint finding is not a file and a line. Representing it as one
# produces output a consumer acts on wrongly: GitHub code scanning would try to
# annotate line 1 of a file literally named "github.com [leaf certificate]".
# Schema-valid is not the same as correct, so these check the semantics as well
# as the schema.
# --------------------------------------------------------------------------- #
def _endpoint_report():
    """A report shaped like a URL scan, built without touching the network."""
    from quantumsafe.certchain import analyse_chain
    from quantumsafe.tlsscan import _finding
    from quantumsafe.scanner import RISK_HIGH

    kex = _finding("example.com", "X25519 key exchange", RISK_HIGH,
                   "classical key exchange", "ecc")
    # Reuse the chain builder from the certchain tests for a realistic chain.
    from tests.test_certchain import ECDSA_SHA256, SHA256_RSA, ec_spki, make_cert, rsa_spki
    chain = [make_cert(ECDSA_SHA256, ec_spki()),
             make_cert(SHA256_RSA, rsa_spki(2048)),
             make_cert(SHA256_RSA, rsa_spki(4096))]
    chain_findings, parsed = analyse_chain("example.com", chain)
    endpoint = {"host": "example.com", "port": 443, "addresses": ["1.1.1.1"],
                "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                "symmetric_bits": 256, "key_exchange": "X25519",
                "key_exchange_post_quantum": False,
                "key_exchange_observed_via": "ServerHello",
                "certificate": {}, "chain": parsed}
    return build_report([kex] + chain_findings, "example.com", endpoint=endpoint)


def test_endpoint_sarif_validates_against_official_schema():
    import jsonschema
    with open(os.path.join(_SCHEMA_DIR, "sarif-2.1.0.json"), encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.validate(json.loads(to_sarif(_endpoint_report())), schema)


def test_endpoint_findings_use_a_real_uri():
    """A bare host with a bracketed suffix is not a URI."""
    sarif = json.loads(to_sarif(_endpoint_report()))
    for result in sarif["runs"][0]["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "https://example.com", uri
        assert "[" not in uri


def test_endpoint_findings_do_not_invent_a_line_number():
    """There is no line 1 of a TLS handshake."""
    sarif = json.loads(to_sarif(_endpoint_report()))
    for result in sarif["runs"][0]["results"]:
        assert "region" not in result["locations"][0]["physicalLocation"]


def test_certificate_position_survives_as_a_logical_location():
    """Dropping the region must not lose which certificate was meant."""
    sarif = json.loads(to_sarif(_endpoint_report()))
    names = {
        loc["name"]
        for result in sarif["runs"][0]["results"]
        for loc in result["locations"][0].get("logicalLocations", [])
    }
    assert "leaf certificate" in names
    assert any("intermediate" in n for n in names)


def test_code_findings_keep_their_file_and_line(report):
    """The endpoint branch must not change the normal path."""
    sarif = json.loads(to_sarif(report))
    for result in sarif["runs"][0]["results"]:
        phys = result["locations"][0]["physicalLocation"]
        assert not phys["artifactLocation"]["uri"].startswith("https://")
        assert phys["region"]["startLine"] >= 1
