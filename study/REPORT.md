# Empirical study: quantum-vulnerable cryptography in popular open source

*Generated 2026-07-02T00:12:13.259230+00:00 by `study/run_study.py` — reproducible.*

## Method

Each project was shallow-cloned and scanned with the QuantumSafe engine (the same code path as `quantumsafe scan --repo`). Findings are aggregated below. **Caveats (stated honestly):** this is static analysis over whole repositories *including test code and vendored files*; cryptography libraries naturally reference many algorithm names, so a high count is expected for them and does not imply they are insecure.

## Headline findings

- **8** popular projects scanned.
- **88%** contain at least one quantum-relevant cryptographic usage.
- **88%** contain at least one **HIGH-risk** (Shor-breakable: RSA/ECC/DSA/DH or MD5/SHA-1) usage.
- Average Quantum Risk Score: **61.4/100**.

![Risk by project](chart.svg)

## Per-project results

| Project | Score | Band | HIGH | MED | LOW | Top algorithms |
|---------|------:|------|-----:|----:|----:|----------------|
| urllib3/urllib3 | 100 | Critical | 7 | 38 | 2 | tls_old×38, md5×6, tls12×2, sha1×1 |
| paramiko/paramiko | 100 | Critical | 89 | 6 | 15 | ecc×46, sha1×18, sha256×15, rsa×15, md5×10 |
| encode/httpx | 93 | Critical | 6 | 0 | 3 | md5×3, sha1×3, sha256×3 |
| pallets/jinja | 75 | High | 5 | 0 | 0 | sha1×5 |
| pallets/click | 47 | Medium | 3 | 0 | 2 | sha1×2, sha256×2, md5×1 |
| psf/requests | 46 | Medium | 3 | 0 | 1 | sha1×2, md5×1, sha256×1 |
| pallets/flask | 30 | Low | 2 | 0 | 0 | sha1×2 |
| expressjs/express | 0 | Low | 0 | 0 | 0 | — |

## Most common quantum-vulnerable families

| Family | Occurrences |
|--------|------------:|
| ecc | 46 |
| tls_old | 38 |
| sha1 | 33 |
| md5 | 21 |
| sha256 | 21 |
| rsa | 15 |
| tls12 | 2 |

## Takeaway

Quantum-vulnerable cryptography is pervasive even in well-maintained, widely-depended-on projects — which is exactly why automated detection and a migration plan (what QuantumSafe provides) are useful as the post-quantum transition begins.
