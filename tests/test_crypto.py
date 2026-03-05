"""Unit tests for cseps/crypto.py"""

import pytest
import json
from cseps.crypto import (
    generate_keypair,
    serialize_public_key,
    deserialize_public_key,
    private_key_to_int,
    int_to_private_key,
    ecies_encrypt,
    ecies_decrypt,
    sign,
    verify_signature,
    shamir_split,
    shamir_reconstruct,
    compute_entry_hash,
    verify_chain_integrity,
)


class TestECCKeys:
    def test_generate_keypair(self):
        priv, pub = generate_keypair()
        assert priv is not None
        assert pub is not None

    def test_serialize_deserialize_public(self):
        _, pub = generate_keypair()
        pem = serialize_public_key(pub)
        pub2 = deserialize_public_key(pem)
        assert serialize_public_key(pub2) == pem

    def test_private_key_roundtrip(self):
        priv, _ = generate_keypair()
        val = private_key_to_int(priv)
        priv2 = int_to_private_key(val)
        assert private_key_to_int(priv2) == val


class TestECIES:
    def test_encrypt_decrypt(self):
        priv, pub = generate_keypair()
        msg = b"secret bid: 100000"
        payload = ecies_encrypt(pub, msg)
        assert "ephemeral_pub" in payload
        assert "nonce" in payload
        assert "ciphertext" in payload
        recovered = ecies_decrypt(priv, payload)
        assert recovered == msg

    def test_wrong_key_fails(self):
        _, pub = generate_keypair()
        priv2, _ = generate_keypair()
        payload = ecies_encrypt(pub, b"data")
        with pytest.raises(Exception):
            ecies_decrypt(priv2, payload)

    def test_tampered_ciphertext_fails(self):
        priv, pub = generate_keypair()
        payload = ecies_encrypt(pub, b"data")
        ct = bytearray(bytes.fromhex(payload["ciphertext"]))
        ct[0] ^= 0xFF
        payload["ciphertext"] = ct.hex()
        with pytest.raises(Exception):
            ecies_decrypt(priv, payload)


class TestSignatures:
    def test_sign_verify(self):
        priv, pub = generate_keypair()
        data = b"canonical bid payload"
        sig = sign(priv, data)
        assert verify_signature(pub, data, sig)

    def test_wrong_key_fails(self):
        priv, _ = generate_keypair()
        _, pub2 = generate_keypair()
        sig = sign(priv, b"data")
        assert not verify_signature(pub2, b"data", sig)

    def test_tampered_data_fails(self):
        priv, pub = generate_keypair()
        sig = sign(priv, b"data")
        assert not verify_signature(pub, b"other data", sig)


class TestShamir:
    def test_reconstruct_exact_threshold(self):
        secret = 123456789
        shares = shamir_split(secret, 5, 3)
        assert len(shares) == 5
        recovered = shamir_reconstruct(shares[:3])
        assert recovered == secret

    def test_reconstruct_all_shares(self):
        secret = 99999999999999
        shares = shamir_split(secret, 4, 4)
        assert shamir_reconstruct(shares) == secret

    def test_insufficient_shares_wrong(self):
        secret = 42
        shares = shamir_split(secret, 5, 3)
        # With only 2 shares (below threshold), result should NOT equal secret
        recovered = shamir_reconstruct(shares[:2])
        assert recovered != secret

    def test_different_subsets_same_result(self):
        secret = 2**100 + 77
        shares = shamir_split(secret, 5, 3)
        assert shamir_reconstruct([shares[0], shares[2], shares[4]]) == secret
        assert shamir_reconstruct([shares[1], shares[3], shares[4]]) == secret

    def test_large_secret(self):
        from cseps.crypto import _SHAMIR_PRIME

        secret = _SHAMIR_PRIME - 1
        shares = shamir_split(secret, 3, 2)
        assert shamir_reconstruct(shares[:2]) == secret


class TestHashChain:
    def test_compute_entry_hash(self):
        h = compute_entry_hash("0" * 64, b"first entry")
        assert len(h) == 64

    def test_chain_integrity_valid(self):
        entries = []
        prev = "0" * 64
        for i in range(5):
            data = f"entry {i}".encode()
            h = compute_entry_hash(prev, data)
            entries.append({"prev_hash": prev, "hash": h, "data": data.decode()})
            prev = h
        valid, reason = verify_chain_integrity(entries)
        assert valid, reason

    def test_chain_tampered(self):
        entries = []
        prev = "0" * 64
        for i in range(3):
            data = f"entry {i}".encode()
            h = compute_entry_hash(prev, data)
            entries.append({"prev_hash": prev, "hash": h})
            prev = h
        # Tamper middle entry hash
        entries[1]["hash"] = "a" * 64
        valid, _ = verify_chain_integrity(entries)
        assert not valid

    def test_empty_chain(self):
        valid, reason = verify_chain_integrity([])
        assert valid
