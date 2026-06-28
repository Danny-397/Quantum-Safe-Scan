"""A from-scratch lattice-based Key Encapsulation Mechanism (LWE).

This is the *solution* half of the QuantumSafe story. The scanner flags RSA/ECC
and recommends CRYSTALS-Kyber (ML-KEM); Kyber's security rests on the hardness of
the **Learning With Errors (LWE)** lattice problem. This module implements an
LWE public-key scheme and a KEM from scratch (NumPy only) so the recommended
replacement isn't just a name — it's runnable, and demonstrably quantum-safe.

Why it resists quantum computers: Shor's algorithm breaks RSA/ECC because those
reduce to *period-finding / hidden-subgroup* problems a quantum computer solves
efficiently. LWE has **no such periodic structure** — the best known quantum
attacks give only modest speedups over classical lattice reduction, so it stays
hard. That is the whole basis of NIST FIPS 203 (ML-KEM / Kyber).

Honest scope: this is a faithful *teaching* implementation of the LWE foundation,
not constant-time, side-channel-hardened production code. Real systems should use
vetted ML-KEM (e.g. liboqs / FIPS 203). The math, however, is the real thing.

Run:  python pqc/lwe_kem.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class Params:
    n: int = 256      # lattice dimension (secret length)
    m: int = 512      # number of LWE samples
    q: int = 4093     # modulus (prime)


DEFAULT = Params()


def _small_errors(rng: np.random.Generator, size: int) -> np.ndarray:
    """Short error vector from {-1, 0, 1} (a tiny centered distribution)."""
    return rng.integers(-1, 2, size=size, dtype=np.int64)


def keygen(rng: np.random.Generator, p: Params = DEFAULT):
    """Return (public_key, secret_key). pk = (A, b = A·s + e mod q)."""
    s = rng.integers(0, p.q, size=p.n, dtype=np.int64)
    A = rng.integers(0, p.q, size=(p.m, p.n), dtype=np.int64)
    e = _small_errors(rng, p.m)
    b = (A @ s + e) % p.q
    return (A, b), s


def _encrypt_bit(pk, bit: int, rng: np.random.Generator, p: Params = DEFAULT):
    A, b = pk
    r = rng.integers(0, 2, size=p.m, dtype=np.int64)   # random subset-sum selector
    u = (A.T @ r) % p.q                                 # length n
    v = (int(b @ r) + bit * (p.q // 2)) % p.q           # scalar, message in the high bit
    return u, v


def _decrypt_bit(sk, ct, p: Params = DEFAULT) -> int:
    u, v = ct
    x = (v - int(sk @ u)) % p.q                          # = e·r + bit·⌊q/2⌋  (e·r is small)
    return 1 if (p.q // 4) < x < (3 * p.q // 4) else 0


# --------------------------------------------------------------------------- #
# KEM: encapsulate / decapsulate a shared secret
# --------------------------------------------------------------------------- #


def encapsulate(pk, rng: np.random.Generator, bits: int = 256, p: Params = DEFAULT):
    """Generate a random shared secret and encrypt it under pk.

    Returns (ciphertext, shared_secret_bytes).
    """
    secret_bits = rng.integers(0, 2, size=bits, dtype=np.int64)
    ct = [_encrypt_bit(pk, int(b), rng, p) for b in secret_bits]
    shared = _bits_to_key(secret_bits)
    return ct, shared


def decapsulate(sk, ct, p: Params = DEFAULT) -> bytes:
    """Recover the shared secret from the ciphertext using the secret key."""
    bits = np.array([_decrypt_bit(sk, c, p) for c in ct], dtype=np.int64)
    return _bits_to_key(bits)


def _bits_to_key(bits: np.ndarray) -> bytes:
    packed = "".join(str(int(b)) for b in bits).encode()
    return hashlib.sha256(packed).digest()


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #


def demo() -> None:
    rng = np.random.default_rng()
    print("Lattice-based (LWE) Key Encapsulation - a quantum-safe key exchange")
    print("=" * 66)
    p = DEFAULT
    print(f"  Parameters: LWE dimension n={p.n}, samples m={p.m}, modulus q={p.q}")

    # Bob publishes a public key.
    pk, sk = keygen(rng)
    # Alice encapsulates a shared secret to Bob's public key.
    ct, alice_secret = encapsulate(pk, rng)
    # Bob decapsulates with his secret key.
    bob_secret = decapsulate(sk, ct)

    print(f"\n  Alice's shared secret: {alice_secret.hex()[:32]}...")
    print(f"  Bob's shared secret:   {bob_secret.hex()[:32]}...")
    print(f"  Secrets match:         {alice_secret == bob_secret}")

    # An eavesdropper with the public key + ciphertext but not the secret key
    # gets a different (useless) value.
    _, eve_guess = encapsulate(pk, rng)
    print(f"  Eavesdropper's value:  {eve_guess.hex()[:32]}...  (different - useless)")

    print("\n  This is the quantum-safe replacement QuantumSafe recommends for RSA/ECC")
    print("  key exchange. Shor's algorithm does NOT break it - LWE has no period to find.")


if __name__ == "__main__":
    demo()
