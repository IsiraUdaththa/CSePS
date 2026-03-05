"""Unit tests for Bidder."""

import json
import pytest
from cseps.bidder import Bidder
from cseps.crypto import (
    generate_keypair,
    deserialize_public_key,
    ecies_decrypt,
    verify_signature,
    serialize_public_key,
)


class TestBidder:
    def test_init(self):
        b = Bidder("bidder_A")
        assert b.bidder_id == "bidder_A"
        assert b.pub_pem

    def test_prepare_bid_structure(self):
        priv, pub = generate_keypair()
        pub_pem = serialize_public_key(pub).decode()
        b = Bidder("bidder_B")
        bid = b.prepare_bid("AUC1", pub_pem, 75000.0)
        assert bid["auction_id"] == "AUC1"
        assert bid["bidder_id"] == "bidder_B"
        assert "encrypted_bid" in bid
        assert "signature" in bid
        assert "nonce" in bid

    def test_bid_decryptable(self):
        priv, pub = generate_keypair()
        pub_pem = serialize_public_key(pub).decode()
        b = Bidder("bidder_C")
        bid = b.prepare_bid("AUC2", pub_pem, 50000.0)
        plaintext = ecies_decrypt(priv, bid["encrypted_bid"])
        bid_data = json.loads(plaintext)
        assert bid_data["amount"] == 50000.0

    def test_bid_signature_verifiable(self):
        priv, pub = generate_keypair()
        pub_pem = serialize_public_key(pub).decode()
        b = Bidder("bidder_D")
        bid = b.prepare_bid("AUC3", pub_pem, 20000.0)
        bidder_pub = deserialize_public_key(bid["bidder_public_key_pem"].encode())
        # Reconstruct canonical signed bytes using the same logic as bidder/server
        payload = json.dumps(
            {
                "auction_id": bid["auction_id"],
                "bidder_id": bid["bidder_id"],
                "encrypted_bid": {
                    "ciphertext": bid["encrypted_bid"]["ciphertext"],
                    "ephemeral_pub": bid["encrypted_bid"]["ephemeral_pub"],
                    "nonce": bid["encrypted_bid"]["nonce"],
                },
                "nonce": bid["nonce"],
                "timestamp_ms": bid["timestamp_ms"],
            },
            sort_keys=True,
        ).encode()
        sig = bytes.fromhex(bid["signature"])
        assert verify_signature(bidder_pub, payload, sig)

    def test_unique_nonces(self):
        priv, pub = generate_keypair()
        pub_pem = serialize_public_key(pub).decode()
        b = Bidder("bidder_E")
        bids = [b.prepare_bid("AUC4", pub_pem, float(i * 1000)) for i in range(10)]
        nonces = [bid["nonce"] for bid in bids]
        assert len(set(nonces)) == 10
