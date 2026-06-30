"""Benchmark the lattice KEM and compare it to classical RSA key exchange.

Measures the from-scratch LWE KEM (key generation, encapsulation, decapsulation
latency, and the on-the-wire sizes), then places it beside the *standardized*
sizes for RSA-2048 and NIST ML-KEM-768 so the migration trade-off is concrete:
post-quantum keys/ciphertexts are larger, but resist Shor's algorithm.

Run:  python pqc/benchmark.py
"""

from __future__ import annotations

import os
import statistics
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqc.lwe_kem import DEFAULT, decapsulate, encapsulate, keygen  # noqa: E402


def _time(fn, trials: int = 30) -> float:
    samples = []
    for _ in range(trials):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)  # ms
    return statistics.median(samples)


def _bytes(arr: np.ndarray, q: int) -> int:
    """On-the-wire size assuming ceil(log2 q) bits per coefficient."""
    bits_per = (q - 1).bit_length()
    return (arr.size * bits_per + 7) // 8


def measure() -> dict:
    rng = np.random.default_rng(0)
    p = DEFAULT
    pk, sk = keygen(rng, p)
    ct, _ = encapsulate(pk, rng)

    A, b = pk
    pk_bytes = _bytes(A, p.q) + _bytes(b, p.q)
    ct_bytes = sum(_bytes(u, p.q) for u, v in ct) + len(ct) * ((p.q - 1).bit_length() + 7) // 8

    return {
        "params": f"n={p.n}, m={p.m}, q={p.q}",
        "keygen_ms": _time(lambda: keygen(rng, p)),
        "encap_ms": _time(lambda: encapsulate(pk, rng)),
        "decap_ms": _time(lambda: decapsulate(sk, ct, p)),
        "pubkey_bytes": pk_bytes,
        "ciphertext_bytes": ct_bytes,
        "shared_secret_bytes": 32,
    }


def demo() -> None:
    m = measure()
    print("Post-quantum migration benchmark")
    print("=" * 64)
    print(f"  This LWE KEM ({m['params']}), measured here:")
    print(f"    keygen {m['keygen_ms']:.1f} ms | encap {m['encap_ms']:.1f} ms | decap {m['decap_ms']:.1f} ms")
    print(f"    public key {m['pubkey_bytes']:,} B | ciphertext {m['ciphertext_bytes']:,} B | secret {m['shared_secret_bytes']} B")
    print()
    print("  Standardized sizes for context (bytes):")
    print("    scheme            public key   ciphertext   quantum-safe")
    print("    " + "-" * 56)
    print("    RSA-2048              ~270         256         NO  (Shor breaks it)")
    print("    ML-KEM-768 (Kyber)    1184        1088         YES")
    print()
    print("  Trade-off: post-quantum key exchange costs larger keys/ciphertexts")
    print("  for security that survives a quantum computer. That is the migration.")


if __name__ == "__main__":
    demo()
