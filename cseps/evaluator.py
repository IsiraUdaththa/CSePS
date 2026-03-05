"""
Evaluator simulation.
Each evaluator:
  1. Has an ECC keypair.
  2. Receives their encrypted Shamir share from the server.
  3. Decrypts it with their private key.
  4. After the deadline, publishes their share (signed) to the server.
"""

from __future__ import annotations
import json
import time
from cseps.crypto import (
    generate_keypair,
    serialize_public_key,
    ecies_decrypt,
    sign,
)


class Evaluator:
    def __init__(self, evaluator_id: str):
        self.evaluator_id = evaluator_id
        self._priv, self.pub = generate_keypair()
        self.pub_pem = serialize_public_key(self.pub).decode()
        self._share: tuple | None = None  # (x, y_int)

    def to_info(self) -> dict:
        return {"evaluator_id": self.evaluator_id, "public_key_pem": self.pub_pem}

    def receive_encrypted_share(self, encrypted_payload: dict) -> None:
        """Decrypt the Shamir share encrypted by the server."""
        raw = ecies_decrypt(self._priv, encrypted_payload)
        share_dict = json.loads(raw)
        self._share = (share_dict["x"], int(share_dict["y"], 16))

    def publish_share(self) -> dict:
        """Sign and return the share for submission to server."""
        if self._share is None:
            raise RuntimeError("No share received yet")
        x, y = self._share
        y_hex = hex(y)
        share_bytes = f"{self.evaluator_id}:{x}:{y_hex}".encode()
        sig = sign(self._priv, share_bytes)
        return {
            "evaluator_id": self.evaluator_id,
            "share_x": x,
            "share_y": y_hex,
            "signature": sig.hex(),
        }
