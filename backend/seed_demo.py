"""Seed the database with a demo account and realistic scans.

This makes the live dashboard look populated so a visitor (or admissions
reviewer) can log in and immediately see real data — without signing up.

Run after the API is deployed/configured:
    cd backend && python seed_demo.py

Demo login:  demo@quantumsafe.dev  /  demodemo123
"""

from __future__ import annotations

import datetime as dt
import os
import tempfile

from app import create_app
from config import Config
from extensions import db
from models import User, generate_api_key, hash_password
from quantumsafe.reporter import build_report
from quantumsafe.scanner import scan_path
from scanner_service import persist_scan

DEMO_EMAIL = "demo@quantumsafe.dev"
DEMO_PASSWORD = "demodemo123"

# (repo label, files, days-ago) — varied risk profiles so the trend chart moves.
SCANS = [
    ("github.com/acme/payments-api", {
        "auth.py": "import hashlib\nfrom cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
                   "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
                   "e = ec.generate_private_key(None)\n"
                   "tok = hashlib.md5(secret).hexdigest()\n"
                   "sig = hashlib.sha1(data).digest()\n",
        "tls.js": "const ctx = tls.createSecureContext({ secureProtocol: 'TLSv1_method' });\n"
                  "const k = crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });\n",
    }, 38),
    ("github.com/acme/payments-api", {
        "auth.py": "import hashlib\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n"
                   "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
                   "tok = hashlib.md5(secret).hexdigest()\n",
        "hash.go": 'import "crypto/ecdsa"\n',
    }, 24),
    ("github.com/acme/internal-tools", {
        "legacy.java": 'Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");\n'
                       'Cipher r = Cipher.getInstance("RC4");\n'
                       'MessageDigest md = MessageDigest.getInstance("SHA-1");\n',
    }, 16),
    ("github.com/acme/internal-tools", {
        "config.py": "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)\n"
                     "cipher = 'AES-128-GCM'\n",
        "hash.py": "import hashlib\nh = hashlib.sha256(b'x').hexdigest()\n",
    }, 7),
    ("github.com/acme/website", {
        "util.py": "import hashlib\nh = hashlib.sha256(b'x').hexdigest()\n",
        "ok.py": "def add(a, b):\n    return a + b\n",
    }, 2),
]


def seed() -> None:
    app = create_app(Config)
    with app.app_context():
        # Reset any existing demo user (cascades to scans + findings).
        existing = User.query.filter_by(email=DEMO_EMAIL).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()

        full_key, key_hash, prefix = generate_api_key()
        user = User(
            email=DEMO_EMAIL,
            password_hash=hash_password(DEMO_PASSWORD),
            email_verified=True,
            api_key_hash=key_hash,
            api_key_prefix=prefix,
            terms_accepted_at=dt.datetime.now(dt.timezone.utc),
        )
        db.session.add(user)
        db.session.commit()

        now = dt.datetime.now(dt.timezone.utc)
        for label, files, days_ago in SCANS:
            with tempfile.TemporaryDirectory() as tmp:
                for name, content in files.items():
                    with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                        fh.write(content)
                report = build_report(scan_path(tmp), label)
            scan = persist_scan(user.id, report)
            scan.created_at = now - dt.timedelta(days=days_ago)
            db.session.commit()

        print(f"Seeded demo account: {DEMO_EMAIL} / {DEMO_PASSWORD}")
        print(f"  {len(SCANS)} scans created.")
        print(f"  Demo CLI API key (store if you want it): {full_key}")


if __name__ == "__main__":
    seed()
