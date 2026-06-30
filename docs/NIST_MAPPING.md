# NIST Post-Quantum Migration Mapping

This table is the human-readable form of the machine mapping in
[`cli/recommender.py`](../cli/recommender.py), which the CLI reporter and the
backend's Migration Plan endpoint both consume — so the guidance shown in the
terminal, the API, and the dashboard is always identical.

In 2024 NIST finalized its first post-quantum standards:

- **FIPS 203 — ML-KEM** (Module-Lattice Key-Encapsulation Mechanism), based on
  CRYSTALS-Kyber. For key establishment / encryption.
- **FIPS 204 — ML-DSA** (Module-Lattice Digital Signature Algorithm), based on
  CRYSTALS-Dilithium. For signatures.
- **FIPS 205 — SLH-DSA** (Stateless Hash-Based DSA), based on SPHINCS+. A
  conservative, hash-based signature alternative.

Supporting transition guidance: **NIST SP 800-52 Rev. 2** (TLS), **SP 800-131A
Rev. 2** (algorithm/key-length transitions), **FIPS 197** (AES), **FIPS 180-4**
(SHA-2), **FIPS 202** (SHA-3), and **NIST IR 8547** (PQC transition).

---

## Quantum-vulnerable → quantum-safe

| Family (detected) | Classical use | Quantum threat | NIST-aligned replacement | Standard | Complexity |
|-------------------|---------------|----------------|--------------------------|----------|------------|
| **RSA** | Key transport, signatures | Shor (broken, any size) | **ML-KEM** (key exchange) / **ML-DSA** (signatures) | FIPS 203 / 204 | High |
| **ECC** (ECDH/ECDSA) | Key agreement, signatures | Shor (broken) | **ML-KEM** (ECDH) / **ML-DSA** (ECDSA) | FIPS 203 / 204 | High |
| **DSA** | Signatures | Shor (broken) | **ML-DSA** (or **SLH-DSA**) | FIPS 204 / 205 | High |
| **Diffie-Hellman** | Key exchange | Shor (broken) | **ML-KEM** (optionally hybrid during transition) | FIPS 203 | High |
| **MD5** | Hashing/MAC | Already collision-broken; Grover weakens further | **SHA-3** (SHA3-256) or SHA-256 | FIPS 202 / 180-4 | Low |
| **SHA-1** | Hashing | Collision-broken (SHAttered); Grover weakens | **SHA-3** (SHA3-256) or SHA-256 | FIPS 202 / 180-4 | Low |
| **TLS 1.0 / 1.1** | Transport security | Deprecated; quantum-vulnerable key exchange | **TLS 1.3** (plan hybrid PQC KEX) | SP 800-52 Rev. 2 | Low |
| **3DES** | Symmetric encryption | Deprecated; Grover halves strength | **AES-256** | FIPS 197 / SP 800-131A | Low |
| **RC4** | Stream cipher | Insecure; prohibited in TLS | **AES-256-GCM** (AEAD) | FIPS 197 / SP 800-131A | Low |
| **SHA-256** | Hashing | Grover → ~128-bit preimage (still secure) | Keep; consider **SHA-384/512** or **SHA-3** for long-lived data | FIPS 180-4 / 202 | Low |
| **AES-128** | Symmetric encryption | Grover → ~64-bit (insufficient long-term) | **AES-256** | FIPS 197 | Low |
| **TLS 1.2** | Transport security | Acceptable; classical key exchange | **TLS 1.3** with hybrid PQC KEX | SP 800-52 Rev. 2 | Low |

When the scanner encounters an unmapped family it falls back to "review against
NIST PQC guidance" (NIST IR 8547).

---

## Why each mapping exists

- **RSA → ML-KEM / ML-DSA.** RSA security reduces to integer factorization, which
  Shor's algorithm solves in polynomial time at any key size. ML-KEM replaces RSA
  used for key transport; ML-DSA replaces RSA used for signatures — split because a
  KEM and a signature scheme are not interchangeable.
- **ECC → ML-KEM / ML-DSA.** Elliptic-curve security reduces to the discrete
  logarithm problem, also solved by Shor. ECDH key agreement maps to ML-KEM;
  ECDSA signatures map to ML-DSA.
- **DSA → ML-DSA / SLH-DSA.** DSA signatures rest on discrete logarithms (broken by
  Shor). ML-DSA is the lattice replacement; SLH-DSA (hash-based) is offered where a
  more conservative security assumption is preferred over performance.
- **Diffie-Hellman → ML-KEM.** Classic DH key exchange is a discrete-log problem
  Shor breaks. ML-KEM provides quantum-safe key establishment; a hybrid
  (classical + PQC) construction is recommended during transition so a flaw in
  either component alone is not fatal.
- **MD5 → SHA-3 / SHA-256.** MD5 already has practical collisions and is unfit for
  security use independent of quantum concerns; Grover further erodes preimage
  resistance. SHA-3 or SHA-256 restores a sound hash.
- **SHA-1 → SHA-3 / SHA-256.** SHA-1 has practical collisions (SHAttered) and is
  deprecated; replace with SHA-3 or SHA-256.
- **TLS 1.0/1.1 → TLS 1.3.** These versions are deprecated and negotiate
  quantum-vulnerable, classical key exchange. TLS 1.3 is the baseline; hybrid PQC
  key exchange is the next step.
- **3DES → AES-256.** 3DES is deprecated and its effective strength is halved by
  Grover. AES-256 is the modern, quantum-resistant symmetric choice.
- **RC4 → AES-256-GCM.** RC4 has known biases, is insecure, and is prohibited in
  TLS; AES-256 in an AEAD mode (GCM) provides confidentiality and integrity.
- **SHA-256 → keep / size up.** Grover reduces SHA-256 preimage resistance to
  ~128 bits, which remains secure today; for data that must survive decades,
  SHA-384/512 or SHA-3 adds margin.
- **AES-128 → AES-256.** Grover halves AES-128 to ~64-bit effective security,
  which is insufficient for long-lived secrets; AES-256 retains ~128 bits under
  Grover and stays infeasible to brute-force.
- **TLS 1.2 → TLS 1.3 (hybrid PQC).** TLS 1.2 is acceptable now but still relies
  on classical key exchange; migrate to TLS 1.3 and plan hybrid PQC key exchange.

---

## References

- NIST **FIPS 203** — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM).
- NIST **FIPS 204** — Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
- NIST **FIPS 205** — Stateless Hash-Based Digital Signature Algorithm (SLH-DSA).
- NIST **FIPS 197** — Advanced Encryption Standard (AES).
- NIST **FIPS 180-4** — Secure Hash Standard (SHA-2).
- NIST **FIPS 202** — SHA-3 Standard.
- NIST **SP 800-52 Rev. 2** — Guidelines for TLS Implementations.
- NIST **SP 800-131A Rev. 2** — Transitioning the Use of Cryptographic Algorithms
  and Key Lengths.
- NIST **IR 8547** — Transition to Post-Quantum Cryptography Standards.
