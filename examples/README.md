# Example vulnerable code

These files intentionally use quantum-vulnerable cryptography so you can try
QuantumSafe immediately:

```bash
pip install -e ..      # from the repo root: pip install -e .
quantumsafe scan --path .
```

You should see a Critical risk score with HIGH findings (RSA, ECDSA, MD5, SHA-1),
MEDIUM (3DES, RC4, TLS 1.0) and LOW (SHA-256, AES-128).

Try the extras:

```bash
quantumsafe scan --path . --output report.sarif      # GitHub code-scanning format
quantumsafe scan --path . --exclude 'legacy/*'       # skip a folder
```

The `safe.py` file shows an inline suppression (`# quantumsafe: ignore`).
