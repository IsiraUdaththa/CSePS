"""
Bidder simulation.
Each bidder:
  1. Has an ECC keypair (identity).
  2. Fetches auction public key.
  3. Encrypts bid with auction public key (ECIES).
  4. Signs the canonical bid payload.
  5. Submits to server.

Design note on signing:
  The signature covers the FULL encrypted payload bytes (ephemeral_pub +
  nonce + ciphertext) concatenated with auction_id, bidder_id, nonce and
  an integer timestamp.  Using integer ms timestamps avoids float JSON
  round-trip precision drift that would break signature verification.
"""

from __future__ import annotations
import json
import secrets
import time
from cseps.crypto import (
    generate_keypair,
    serialize_public_key,
    deserialize_public_key,
    ecies_encrypt,
    sign,
)


def _canonical_signed_bytes(
    auction_id: str,
    bidder_id: str,
    encrypted_bid: dict,
    nonce: str,
    timestamp_ms: int,
) -> bytes:
    """
    Deterministic bytes that both the bidder signs and the server verifies.
    We sign over the encrypted_bid dict (sorted keys) so the server can
    verify without decrypting first, and we use an integer ms timestamp
    to avoid float JSON serialisation drift.
    """
    payload = {
        "auction_id": auction_id,
        "bidder_id": bidder_id,
        "encrypted_bid": {
            "ciphertext": encrypted_bid["ciphertext"],
            "ephemeral_pub": encrypted_bid["ephemeral_pub"],
            "nonce": encrypted_bid["nonce"],
        },
        "nonce": nonce,
        "timestamp_ms": timestamp_ms,
    }
    return json.dumps(payload, sort_keys=True).encode()


class Bidder:
    def __init__(self, bidder_id: str):
        self.bidder_id = bidder_id
        self._priv, self.pub = generate_keypair()
        self.pub_pem = serialize_public_key(self.pub).decode()

    def prepare_bid(
        self,
        auction_id: str,
        auction_pub_key_pem: str,
        amount: float,
        extra: dict | None = None,
    ) -> dict:
        """
        Encrypt and sign a bid.
        Returns the BidSubmission payload dict.
        """
        auction_pub = deserialize_public_key(auction_pub_key_pem.encode())
        nonce = secrets.token_hex(16)
        timestamp_ms = int(time.time() * 1000)  # integer ms — no float drift

        bid_data = {"amount": amount, **(extra or {})}

        # Encrypt bid_data
        encrypted_bid = ecies_encrypt(
            auction_pub, json.dumps(bid_data, sort_keys=True).encode()
        )

        # Sign over the encrypted envelope (not plaintext) + metadata
        signed_bytes = _canonical_signed_bytes(
            auction_id, self.bidder_id, encrypted_bid, nonce, timestamp_ms
        )
        sig = sign(self._priv, signed_bytes)

        return {
            "auction_id": auction_id,
            "bidder_id": self.bidder_id,
            "encrypted_bid": encrypted_bid,
            "signature": sig.hex(),
            "bidder_public_key_pem": self.pub_pem,
            "timestamp": timestamp_ms / 1000.0,  # stored as float for display
            "timestamp_ms": timestamp_ms,  # authoritative integer for sig
            "nonce": nonce,
        }
