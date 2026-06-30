# Vulnerability-Class Mapping

QuantumSafe detects **usage of weak or quantum-vulnerable cryptographic
primitives**. That detection overlaps with well-known *classes* of cryptographic
vulnerability — both the quantum threat (Shor/Grover) and classical weaknesses
that already have a track record of real-world exploitation.

> **Scope note.** This document maps QuantumSafe's findings to *general
> vulnerability classes*, not to specific CVE identifiers. No CVE numbers are
> invented or claimed. Where a famous incident is named (e.g. SHAttered, ROCA), it
> is referenced as illustrative context for the *class*, not as something
> QuantumSafe attributes to your code. QuantumSafe flags that a weak primitive is
> *used*; it does not prove a specific, exploitable instance is present.

---

## How to read this

- **Detects** = the QuantumSafe family/severity that fires.
- **Vulnerability class** = the general weakness category (CWE-style).
- **What QuantumSafe actually tells you** = the concrete, honest signal — usage
  detection, not exploit confirmation.

---

## Quantum vulnerability classes

| Vulnerability class | Detected (family / severity) | What QuantumSafe actually tells you |
|---------------------|------------------------------|--------------------------------------|
| **Factorization-breakable public-key crypto** (RSA) | `rsa` / HIGH | RSA is in use; Shor breaks it at any key size — migrate to ML-KEM/ML-DSA. |
| **Discrete-log-breakable public-key crypto** (ECC, DSA, DH) | `ecc`, `dsa`, `dh` / HIGH | An elliptic-curve or finite-field discrete-log scheme is in use; Shor breaks it. |
| **Grover-weakened symmetric strength** | `aes128`, `3des` / LOW–MED | Symmetric key sizes whose effective strength is halved by Grover; size up. |
| **Grover-weakened hash strength** | `sha256` / LOW | Acceptable today; preimage resistance drops to ~128 bits — size up for long-lived data. |

These are the post-quantum classes that are the core purpose of the tool: they map
directly to the "harvest now, decrypt later" risk described in
[WHITEPAPER.md](WHITEPAPER.md).

---

## Classical cryptographic weakness classes

These are weaknesses that are dangerous **today**, independent of quantum
computers. QuantumSafe surfaces the underlying primitive; the named incidents are
context for *why the class matters*.

| Vulnerability class | Detected (family / severity) | Illustrative real-world context | What QuantumSafe actually tells you |
|---------------------|------------------------------|---------------------------------|--------------------------------------|
| **Hash collision attacks** | `md5`, `sha1` / HIGH | MD5 collisions (chosen-prefix); SHA-1 collision ("SHAttered") | A collision-broken hash is in use — unsafe for signatures, certificates, integrity. |
| **Broken stream cipher / biased keystream** | `rc4` / MEDIUM | RC4 keystream biases led to its prohibition in TLS | RC4 is in use; replace with AES-256-GCM. |
| **Deprecated block cipher / small effective block** | `3des` / MEDIUM | Birthday-bound attacks on 64-bit-block ciphers ("Sweet32") | 3DES is in use; deprecated and Grover-weakened — move to AES-256. |
| **Obsolete TLS protocol versions** | `tls_old` / MEDIUM | Downgrade/protocol attacks against TLS 1.0/1.1 (BEAST-era) | A deprecated TLS version is configured; upgrade to TLS 1.3. |
| **Weak RSA key sizes / RSA-padding pitfalls** | `rsa` (and sub-2048 sizing) / HIGH | Padding-oracle attacks (Bleichenbacher-style), weak-key generation (ROCA-style) | RSA is in use; flagged for quantum risk *and* as the locus where padding/keygen pitfalls live. |
| **Use of cryptographically broken primitive for security** | `md5`, `sha1`, `rc4` | Maps to CWE-327 (broken/risky crypto algorithm) | A primitive unfit for security purposes is present in the code. |

---

## What QuantumSafe does *not* do

To keep this mapping honest:

- It does **not** detect *specific* CVEs or confirm exploitability — only that a
  weak/vulnerable primitive is **used**.
- It does **not** verify padding modes, key-generation quality, IV/nonce reuse,
  certificate validity, or protocol negotiation at runtime.
- It does **not** trace cryptography invoked transitively through dependencies that
  are not present in the scanned source.
- A clean scan is therefore **not** a proof of cryptographic safety; it means no
  flagged *patterns* were found in the scanned first-party code.

For the precise detection mechanics and limits, see
[../benchmark/README.md](../benchmark/README.md) and
[../TECHNICAL_OVERVIEW.md](../TECHNICAL_OVERVIEW.md).

---

## References (vulnerability-class context, not attributed CVEs)

- CWE-327 — Use of a Broken or Risky Cryptographic Algorithm.
- CWE-326 — Inadequate Encryption Strength.
- CWE-328 — Use of Weak Hash.
- Stevens et al., "The first collision for full SHA-1" (SHAttered), 2017.
- AlFardan et al., "On the Security of RC4 in TLS," USENIX Security, 2013.
- NIST SP 800-131A Rev. 2 — algorithm/key-length transitions.
