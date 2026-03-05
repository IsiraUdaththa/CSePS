"""Integration tests for the FastAPI server."""

import json
import time
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from cseps.server import (
    app,
    _auctions,
    _ledger_dbs,
    _collected_shares,
    _decrypted_ledgers,
    _encrypted_shares,
    _server_private_keys,
)
from cseps.evaluator import Evaluator
from cseps.bidder import Bidder
from cseps.authority import Authority


def _setup_fresh():
    _auctions.clear()
    _ledger_dbs.clear()
    _collected_shares.clear()
    _decrypted_ledgers.clear()
    _encrypted_shares.clear()
    _server_private_keys.clear()


@pytest.fixture
def evaluators():
    return [Evaluator(f"eval_{i}") for i in range(3)]


@pytest.fixture
def authority():
    return Authority()


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


class TestAuctionCreation:
    @pytest.mark.asyncio
    async def test_create_auction(self, client, evaluators, authority):
        _setup_fresh()
        req = authority.build_auction_request(
            "AUC001", "Test Procurement", evaluators, threshold=2, duration_seconds=60
        )
        resp = await client.post("/auction/create", json=req)
        assert resp.status_code == 200
        data = resp.json()
        assert data["auction_id"] == "AUC001"
        assert "public_key_pem" in data
        assert len(data["encrypted_shares"]) == 3

    @pytest.mark.asyncio
    async def test_duplicate_auction_rejected(self, client, evaluators, authority):
        _setup_fresh()
        req = authority.build_auction_request("AUC_DUP", "T", evaluators, 2, 60)
        await client.post("/auction/create", json=req)
        resp = await client.post("/auction/create", json=req)
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_get_auction(self, client, evaluators, authority):
        _setup_fresh()
        req = authority.build_auction_request("AUC002", "T2", evaluators, 2, 60)
        await client.post("/auction/create", json=req)
        resp = await client.get("/auction/AUC002")
        assert resp.status_code == 200
        assert resp.json()["open"] is True


class TestBidSubmission:
    @pytest.mark.asyncio
    async def test_submit_valid_bid(self, client, evaluators, authority):
        _setup_fresh()
        req = authority.build_auction_request("AUC003", "T3", evaluators, 2, 60)
        create_resp = await client.post("/auction/create", json=req)
        pub_key = create_resp.json()["public_key_pem"]

        bidder = Bidder("bidder_1")
        bid_payload = bidder.prepare_bid("AUC003", pub_key, 50000.0)
        resp = await client.post("/auction/AUC003/bid", content=json.dumps(bid_payload))
        assert resp.status_code == 200
        assert resp.json()["seq"] == 0

    @pytest.mark.asyncio
    async def test_oversized_bid_rejected(self, client, evaluators, authority):
        _setup_fresh()
        req = authority.build_auction_request("AUC004", "T4", evaluators, 2, 60)
        create_resp = await client.post("/auction/create", json=req)
        pub_key = create_resp.json()["public_key_pem"]
        bidder = Bidder("b2")
        bid = bidder.prepare_bid("AUC004", pub_key, 1.0)
        # Inflate ciphertext
        bid["encrypted_bid"]["ciphertext"] = "ff" * 5000
        resp = await client.post("/auction/AUC004/bid", content=json.dumps(bid))
        assert resp.status_code == 413

    @pytest.mark.asyncio
    async def test_bid_after_deadline_rejected(self, client, evaluators, authority):
        _setup_fresh()
        req = authority.build_auction_request(
            "AUC005", "T5", evaluators, 2, duration_seconds=-1
        )
        create_resp = await client.post("/auction/create", json=req)
        pub_key = create_resp.json()["public_key_pem"]
        bidder = Bidder("b3")
        bid = bidder.prepare_bid("AUC005", pub_key, 1000.0)
        resp = await client.post("/auction/AUC005/bid", content=json.dumps(bid))
        assert resp.status_code == 403


class TestDecryption:
    @pytest.mark.asyncio
    async def test_full_flow(self, client, evaluators, authority):
        _setup_fresh()
        req = authority.build_auction_request(
            "AUC_FULL", "Full Test", evaluators, 2, duration_seconds=-1
        )
        create_resp = await client.post("/auction/create", json=req)
        data = create_resp.json()
        pub_key = data["public_key_pem"]
        enc_shares = {
            s["evaluator_id"]: s["encrypted_payload"] for s in data["encrypted_shares"]
        }

        # Evaluators receive shares
        for ev in evaluators:
            ev.receive_encrypted_share(enc_shares[ev.evaluator_id])

        # Submit 2 shares (threshold=2)
        for ev in evaluators[:2]:
            share_payload = ev.publish_share()
            share_payload["auction_id"] = "AUC_FULL"
            resp = await client.post("/auction/AUC_FULL/share", json=share_payload)
            assert resp.status_code == 200

        # Decrypt
        resp = await client.post("/auction/AUC_FULL/decrypt")
        assert resp.status_code == 200
        result = resp.json()
        assert result["chain_valid"] is True

    @pytest.mark.asyncio
    async def test_insufficient_shares(self, client, evaluators, authority):
        _setup_fresh()
        req = authority.build_auction_request(
            "AUC_INSUF", "T", evaluators, 3, duration_seconds=-1
        )
        await client.post("/auction/create", json=req)
        resp = await client.post("/auction/AUC_INSUF/decrypt")
        assert resp.status_code == 400
