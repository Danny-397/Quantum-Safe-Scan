"""Example service using quantum-vulnerable cryptography (for demo purposes)."""

import hashlib

from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa


def make_keys():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # HIGH: RSA
    ec_key = ec.generate_private_key(ec.SECP256R1())                          # HIGH: ECC
    dsa_key = dsa.generate_private_key(key_size=2048)                         # HIGH: DSA
    return rsa_key, ec_key, dsa_key


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()       # HIGH: MD5


def legacy_checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()      # HIGH: SHA-1


def content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()    # LOW: SHA-256 (acceptable)
