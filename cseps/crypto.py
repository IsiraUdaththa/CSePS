"""
Cryptographic utilities for CSePS.
- ECC key generation (SECP256R1)
- ECDH-based hybrid encryption (ECIES-like): ECDH shared secret → AES-GCM
- ECDSA digital signatures
- Shamir Secret Sharing (pure Python, no secretsharing library)
- Hash chaining (SHA-256)
"""

import os
import hashlib
import secrets
from typing import List, Tuple

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# ── Constants ────────────────────────────────────────────────
CURVE = SECP256R1()
_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order used as Shamir modulus (large prime > 2^256)

# We use a safe large prime for Shamir (not curve order; just a large prime)
# 521-bit Mersenne-like prime: 2^521 - 1  (actually prime)
_SHAMIR_PRIME = 2**521 - 1


# ── ECC Key Generation ───────────────────────────────────────
def generate_keypair() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    priv = generate_private_key(CURVE)
    return priv, priv.public_key()


def serialize_public_key(pub: EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(data: bytes) -> EllipticCurvePublicKey:
    return serialization.load_pem_public_key(data)


def serialize_private_key(priv: EllipticCurvePrivateKey) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def deserialize_private_key(data: bytes) -> EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(data, password=None)


def private_key_to_int(priv: EllipticCurvePrivateKey) -> int:
    raw = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Extract raw scalar
    return priv.private_numbers().private_value


def int_to_private_key(val: int) -> EllipticCurvePrivateKey:
    from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key

    return derive_private_key(val, CURVE)


# ── ECIES Hybrid Encryption ──────────────────────────────────
def ecies_encrypt(recipient_pub: EllipticCurvePublicKey, plaintext: bytes) -> dict:
    """
    Encrypt plaintext for recipient_pub.
    Returns dict with ephemeral_pub (PEM), nonce (hex), ciphertext (hex).
    """
    eph_priv, eph_pub = generate_keypair()
    shared_key = eph_priv.exchange(ECDH(), recipient_pub)
    sym_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"cseps-ecies"
    ).derive(shared_key)
    nonce = os.urandom(12)
    ct = AESGCM(sym_key).encrypt(nonce, plaintext, None)
    return {
        "ephemeral_pub": serialize_public_key(eph_pub).decode(),
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
    }


def ecies_decrypt(recipient_priv: EllipticCurvePrivateKey, payload: dict) -> bytes:
    eph_pub = deserialize_public_key(payload["ephemeral_pub"].encode())
    shared_key = recipient_priv.exchange(ECDH(), eph_pub)
    sym_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"cseps-ecies"
    ).derive(shared_key)
    nonce = bytes.fromhex(payload["nonce"])
    ct = bytes.fromhex(payload["ciphertext"])
    return AESGCM(sym_key).decrypt(nonce, ct, None)


# ── ECDSA Signatures ─────────────────────────────────────────
def sign(priv: EllipticCurvePrivateKey, data: bytes) -> bytes:
    return priv.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature(pub: EllipticCurvePublicKey, data: bytes, sig: bytes) -> bool:
    try:
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ── Shamir Secret Sharing (pure Python) ──────────────────────
def _mod_inverse(a: int, p: int) -> int:
    """Extended Euclidean for modular inverse."""
    g, x, _ = _ext_gcd(a % p, p)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % p


def _ext_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _ext_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _eval_poly(coeffs: List[int], x: int, p: int) -> int:
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % p
    return result


def shamir_split(secret: int, n: int, k: int) -> List[Tuple[int, int]]:
    """
    Split `secret` into n shares with threshold k.
    Returns list of (x, y) pairs.
    secret must be < _SHAMIR_PRIME.
    """
    assert k <= n, "Threshold must be <= n"
    assert secret < _SHAMIR_PRIME, "Secret too large"
    coeffs = [secret] + [secrets.randbelow(_SHAMIR_PRIME) for _ in range(k - 1)]
    shares = []
    for i in range(1, n + 1):
        shares.append((i, _eval_poly(coeffs, i, _SHAMIR_PRIME)))
    return shares


def shamir_reconstruct(shares: List[Tuple[int, int]]) -> int:
    """Lagrange interpolation over _SHAMIR_PRIME to reconstruct secret."""
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = yi
        den = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = (num * (-xj)) % _SHAMIR_PRIME
                den = (den * (xi - xj)) % _SHAMIR_PRIME
        secret = (secret + num * _mod_inverse(den, _SHAMIR_PRIME)) % _SHAMIR_PRIME
    return secret


# ── Hash Chain ───────────────────────────────────────────────
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_entry_hash(prev_hash: str, entry_data: bytes) -> str:
    combined = (prev_hash + sha256(entry_data)).encode()
    return sha256(combined)


def verify_chain_integrity(entries: List[dict]) -> Tuple[bool, str]:
    """
    Verify the full hash chain. Each entry must have 'hash' and 'prev_hash'.
    Returns (valid, reason).
    """
    if not entries:
        return True, "empty"
    genesis_ok = entries[0]["prev_hash"] == "0" * 64
    if not genesis_ok:
        return False, "Genesis prev_hash invalid"
    for i in range(1, len(entries)):
        if entries[i]["prev_hash"] != entries[i - 1]["hash"]:
            return False, f"Chain broken at index {i}"
    return True, "ok"
