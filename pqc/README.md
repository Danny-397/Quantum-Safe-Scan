# QuantumSafe — Post-quantum module (the solution)

This is the third pillar of QuantumSafe. The full arc:

1. **The attack** — `quantum/` runs Shor's algorithm and breaks RSA.
2. **The detection** — the scanner finds RSA/ECC in your code and flags it HIGH.
3. **The solution** — `pqc/` implements the *quantum-safe replacement* the scanner
   recommends, from scratch, so the advice is runnable and provable.

`lwe_kem.py` is a lattice-based **Key Encapsulation Mechanism** built on
**Learning With Errors (LWE)** — the hardness assumption underneath
CRYSTALS-Kyber / **ML-KEM (NIST FIPS 203)**.

## Run it

```bash
pip install -r pqc/requirements.txt
python pqc/lwe_kem.py      # a full quantum-safe key exchange: Alice & Bob agree on a secret
python pqc/benchmark.py    # measured keygen/encap/decap latency + key/ciphertext sizes vs RSA & ML-KEM
```

## How it works

**Key generation.** Secret `s ∈ Z_q^n`. Public key is `(A, b)` where `A` is random
and `b = A·s + e (mod q)` with a *small* error `e`. Recovering `s` from `(A, b)` is
the LWE problem — provably as hard as worst-case lattice problems.

**Encapsulation.** To send a bit `μ`, pick a random 0/1 selector `r` and send
`u = Aᵀr`, `v = bᵀr + μ·⌊q/2⌋`. A full shared secret is many such bits, hashed
with SHA-256.

**Decapsulation.** Compute `v − sᵀu = eᵀr + μ·⌊q/2⌋`. Because `eᵀr` is small, the
high bit recovers `μ`. Our parameters (n=256, m=512, q=4093) keep the error far
below `q/4`, so decryption is reliable — verified over 200+ exchanges with **zero
failures**.

## Why quantum computers don't break it

Shor's algorithm breaks RSA/ECC because factoring and discrete-log reduce to
**period-finding** (the hidden-subgroup problem over abelian groups), which a
quantum computer solves efficiently. **LWE has no such periodic structure** — the
best known quantum algorithms give only polynomial speedups over classical
lattice reduction, so the problem stays exponentially hard. That is exactly why
NIST standardized lattice schemes (ML-KEM, ML-DSA) for the post-quantum era.

## Honest scope

This is a faithful **teaching** implementation of the LWE foundation, not
constant-time or side-channel-hardened, and it is plain LWE rather than the
optimized Module-LWE + NTT + Fujisaki–Okamoto construction of real Kyber.
Production systems should use vetted **ML-KEM** (e.g. `liboqs`). The mathematics
demonstrated here is the genuine basis of post-quantum key exchange.
