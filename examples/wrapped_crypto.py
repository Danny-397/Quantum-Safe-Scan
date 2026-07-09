"""Crypto hidden behind wrapper functions — a demo for `scan --taint`.

A plain scan flags the *direct* primitive calls below (the `hashlib.md5` and
`rsa.generate_private_key` lines). But in real code the dangerous call sites are
usually the *wrappers* — `legacy_token()` and `issue_signing_key()` — and the
places that call them, where no crypto keyword appears at all.

Run both to see the difference:

    quantumsafe scan --path wrapped_crypto.py            # direct calls only
    quantumsafe scan --path wrapped_crypto.py --taint    # + the wrapper blast radius

With --taint, the interprocedural data-flow pass follows the call graph and also
flags `legacy_token()`, `issue_signing_key()`, and their call sites at the bottom.
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa


def _digest(data: bytes) -> str:
    # Direct MD5 usage — caught by any scan.
    return hashlib.md5(data).hexdigest()


def legacy_token(payload: bytes) -> str:
    # One hop away from MD5; no "md5" keyword on this line.
    return _digest(payload)


def issue_signing_key():
    # Direct RSA usage — caught by any scan.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_session(user_id: bytes):
    # Two hops from MD5, one hop from RSA — invisible to a keyword/AST scan,
    # but reachable, so --taint reports both here.
    token = legacy_token(user_id)
    key = issue_signing_key()
    return token, key


if __name__ == "__main__":
    build_session(b"user-42")
