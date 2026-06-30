"""Tests for the from-scratch post-quantum (LWE) key encapsulation.

Skipped when NumPy isn't installed (kept out of the core/CI requirements).
"""

import os
import sys

import pytest

np = pytest.importorskip("numpy")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pqc.lwe_kem import decapsulate, encapsulate, keygen  # noqa: E402


def test_lwe_kem_roundtrip_is_reliable():
    rng = np.random.default_rng(1)
    for _ in range(50):
        pk, sk = keygen(rng)
        ct, alice = encapsulate(pk, rng)
        assert decapsulate(sk, ct) == alice  # Bob recovers the same shared secret


def test_shared_secret_is_32_bytes():
    rng = np.random.default_rng(7)
    pk, sk = keygen(rng)
    _, secret = encapsulate(pk, rng)
    assert isinstance(secret, bytes) and len(secret) == 32


def test_independent_encapsulations_differ():
    rng = np.random.default_rng(2)
    pk, sk = keygen(rng)
    _, a = encapsulate(pk, rng)
    _, b = encapsulate(pk, rng)
    assert a != b


def test_benchmark_reports_sizes_and_timing():
    from pqc.benchmark import measure
    m = measure()
    assert m["pubkey_bytes"] > 0 and m["ciphertext_bytes"] > 0
    assert m["shared_secret_bytes"] == 32
    assert m["keygen_ms"] >= 0 and m["encap_ms"] >= 0
