"""Unit tests for Evaluator."""

import json
import pytest
from cseps.evaluator import Evaluator
from cseps.crypto import (
    generate_keypair,
    ecies_encrypt,
    verify_signature,
    deserialize_public_key,
)


class TestEvaluator:
    def test_init(self):
        ev = Evaluator("e1")
        assert ev.evaluator_id == "e1"
        assert ev.pub_pem

    def test_receive_and_publish_share(self):
        ev = Evaluator("e1")
        # Simulate server encrypting a share to evaluator
        share_payload = json.dumps({"x": 1, "y": hex(999999)}).encode()
        enc = ecies_encrypt(ev.pub, share_payload)
        ev.receive_encrypted_share(enc)
        published = ev.publish_share()
        assert published["share_x"] == 1
        assert published["share_y"] == hex(999999)

    def test_publish_without_share_raises(self):
        ev = Evaluator("e2")
        with pytest.raises(RuntimeError):
            ev.publish_share()

    def test_published_share_signature_valid(self):
        ev = Evaluator("e3")
        share_payload = json.dumps({"x": 2, "y": hex(42)}).encode()
        enc = ecies_encrypt(ev.pub, share_payload)
        ev.receive_encrypted_share(enc)
        published = ev.publish_share()
        from cseps.crypto import verify_signature

        ev_pub = deserialize_public_key(ev.pub_pem.encode())
        msg = f"{published['evaluator_id']}:{published['share_x']}:{published['share_y']}".encode()
        sig = bytes.fromhex(published["signature"])
        assert verify_signature(ev_pub, msg, sig)
