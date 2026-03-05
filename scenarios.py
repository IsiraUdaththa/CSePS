"""
CSePS Scenario Runner
=====================
Runs multiple scenarios against a live in-process server to demo the system.
"""

import asyncio
import json
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

BANNER = "=" * 60


def reset_server():
    _auctions.clear()
    _ledger_dbs.clear()
    _collected_shares.clear()
    _decrypted_ledgers.clear()
    _encrypted_shares.clear()
    _server_private_keys.clear()


async def run_scenario(title: str, fn):
    print(f"\n{BANNER}")
    print(f"SCENARIO: {title}")
    print(BANNER)
    reset_server()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        await fn(client)


# ─────────────────────────────────────────────────────────────
# Scenario 1: Happy Path – 3 evaluators, 3 bidders, 2-of-3 threshold
# ─────────────────────────────────────────────────────────────
async def scenario_happy_path(client: AsyncClient):
    authority = Authority()
    evaluators = [Evaluator(f"evaluator_{i}") for i in range(3)]
    bidders = [
        Bidder("TechCorp"),
        Bidder("BuildCo"),
        Bidder("InfraSys"),
    ]
    bid_amounts = [150_000, 120_000, 135_000]

    # 1. Create auction (open for 2 seconds)
    print("\n[AUTHORITY] Creating auction...")
    req = authority.build_auction_request(
        "HAPPY_001",
        "Road Construction Tender",
        evaluators,
        threshold=2,
        duration_seconds=2,
    )
    resp = await client.post("/auction/create", json=req)
    data = resp.json()
    pub_key = data["public_key_pem"]
    enc_shares = {
        s["evaluator_id"]: s["encrypted_payload"] for s in data["encrypted_shares"]
    }
    print(f"  Auction created. Public key (first 60 chars): {pub_key[:60]}...")

    # 2. Evaluators receive their encrypted shares
    print("\n[EVALUATORS] Receiving encrypted key shares...")
    for ev in evaluators:
        ev.receive_encrypted_share(enc_shares[ev.evaluator_id])
        print(f"  {ev.evaluator_id}: share received and decrypted ✓")

    # 3. Bidders submit bids
    print("\n[BIDDERS] Submitting encrypted bids...")
    for bidder, amount in zip(bidders, bid_amounts):
        bid = bidder.prepare_bid("HAPPY_001", pub_key, amount)
        resp = await client.post("/auction/HAPPY_001/bid", content=json.dumps(bid))
        print(
            f"  {bidder.bidder_id}: bid £{amount:,} submitted → seq={resp.json()['seq']} hash={resp.json()['hash'][:16]}..."
        )

    # Check public ledger
    resp = await client.get("/auction/HAPPY_001/ledger")
    print(f"\n[PUBLIC LEDGER] {resp.text.count(chr(10))+1} entries (all encrypted)")

    # 4. Wait for deadline
    print("\n[SYSTEM] Waiting for auction deadline...")
    await asyncio.sleep(2.5)

    # 5. Evaluators publish shares (only 2 needed)
    print("\n[EVALUATORS] Publishing key shares post-deadline...")
    for ev in evaluators[:2]:
        share = ev.publish_share()
        share["auction_id"] = "HAPPY_001"
        resp = await client.post("/auction/HAPPY_001/share", json=share)
        d = resp.json()
        print(
            f"  {ev.evaluator_id}: share published ({d['collected']}/{d['threshold']} collected)"
        )

    # 6. Decrypt
    print("\n[SERVER] Reconstructing private key and decrypting ledger...")
    resp = await client.post("/auction/HAPPY_001/decrypt")
    result = resp.json()
    print(f"  Chain integrity: {result['chain_valid']} ({result['chain_reason']})")
    print(f"  Bids decrypted: {len(result['bids'])}")
    for bid in result["bids"]:
        status = "✓ VALID" if bid["valid"] else f"✗ INVALID: {bid['invalid_reason']}"
        amount = bid["bid_data"]["amount"] if bid["bid_data"] else "N/A"
        print(
            f"    [{bid['seq']}] {bid['bidder_id']}: £{amount:,} | sig_ok={bid['signature_verified']} | {status}"
        )
    print(f"\n  🏆 WINNER: {result['winner']} with £{result['winning_amount']:,}")


# ─────────────────────────────────────────────────────────────
# Scenario 2: Malicious bidder – oversized payload
# ─────────────────────────────────────────────────────────────
async def scenario_malicious_oversized(client: AsyncClient):
    authority = Authority()
    evaluators = [Evaluator("e1"), Evaluator("e2"), Evaluator("e3")]
    req = authority.build_auction_request(
        "MAL_SIZE", "Supply Tender", evaluators, 2, 30
    )
    resp = await client.post("/auction/create", json=req)
    pub_key = resp.json()["public_key_pem"]

    print("\n[ATTACKER] Attempting to submit oversized bid payload...")
    attacker = Bidder("attacker")
    bid = attacker.prepare_bid("MAL_SIZE", pub_key, 1.0)
    bid["encrypted_bid"]["ciphertext"] = "ff" * 5000  # 5KB ciphertext
    resp = await client.post("/auction/MAL_SIZE/bid", content=json.dumps(bid))
    print(f"  Server response: {resp.status_code} → {resp.json()['detail']}")
    assert resp.status_code == 413, "Should reject oversized bid"
    print("  ✓ Malicious oversized bid correctly rejected")


# ─────────────────────────────────────────────────────────────
# Scenario 3: Bid after deadline rejected
# ─────────────────────────────────────────────────────────────
async def scenario_late_bid(client: AsyncClient):
    authority = Authority()
    evaluators = [Evaluator("e1"), Evaluator("e2")]
    req = authority.build_auction_request(
        "LATE_001", "IT Procurement", evaluators, 2, duration_seconds=-1
    )
    resp = await client.post("/auction/create", json=req)
    pub_key = resp.json()["public_key_pem"]

    print("\n[BIDDER] Attempting to submit bid after deadline...")
    late_bidder = Bidder("LateBidder")
    bid = late_bidder.prepare_bid("LATE_001", pub_key, 80_000)
    resp = await client.post("/auction/LATE_001/bid", content=json.dumps(bid))
    print(f"  Server response: {resp.status_code} → {resp.json()['detail']}")
    assert resp.status_code == 403
    print("  ✓ Late bid correctly rejected")


# ─────────────────────────────────────────────────────────────
# Scenario 4: Threshold not met – decryption blocked
# ─────────────────────────────────────────────────────────────
async def scenario_insufficient_threshold(client: AsyncClient):
    authority = Authority()
    evaluators = [Evaluator(f"ev{i}") for i in range(4)]
    req = authority.build_auction_request(
        "THRESH_001", "Security Contract", evaluators, 3, duration_seconds=-1
    )
    resp = await client.post("/auction/create", json=req)
    enc_shares = {
        s["evaluator_id"]: s["encrypted_payload"]
        for s in resp.json()["encrypted_shares"]
    }
    for ev in evaluators:
        ev.receive_encrypted_share(enc_shares[ev.evaluator_id])

    print("\n[EVALUATORS] Only 2 of 4 evaluators publish shares (threshold=3)...")
    for ev in evaluators[:2]:
        share = ev.publish_share()
        share["auction_id"] = "THRESH_001"
        await client.post("/auction/THRESH_001/share", json=share)

    resp = await client.post("/auction/THRESH_001/decrypt")
    print(f"  Decrypt attempt: {resp.status_code} → {resp.json()['detail']}")
    assert resp.status_code == 400
    print("  ✓ Correctly blocked: cannot decrypt without sufficient shares")

    # Now 3rd evaluator publishes
    print("\n[3rd EVALUATOR] Publishing missing share...")
    share = evaluators[2].publish_share()
    share["auction_id"] = "THRESH_001"
    await client.post("/auction/THRESH_001/share", json=share)
    resp = await client.post("/auction/THRESH_001/decrypt")
    print(f"  Decrypt attempt: {resp.status_code}")
    assert resp.status_code == 200
    print("  ✓ Decryption succeeded after threshold met")


# ─────────────────────────────────────────────────────────────
# Scenario 5: Invalid bid data (zero amount)
# ─────────────────────────────────────────────────────────────
async def scenario_invalid_bid_data(client: AsyncClient):
    authority = Authority()
    evaluators = [Evaluator("e1"), Evaluator("e2"), Evaluator("e3")]
    # Auction open for 2 seconds so bids can be submitted first
    req = authority.build_auction_request(
        "INVALID_BID", "Office Supplies", evaluators, 2, duration_seconds=2
    )
    resp = await client.post("/auction/create", json=req)
    data = resp.json()
    pub_key = data["public_key_pem"]
    enc_shares = {
        s["evaluator_id"]: s["encrypted_payload"] for s in data["encrypted_shares"]
    }
    for ev in evaluators:
        ev.receive_encrypted_share(enc_shares[ev.evaluator_id])

    print("\n[BIDDERS] Submitting mix of valid and invalid bids...")
    good_bidder = Bidder("GoodCorp")
    bad_bidder = Bidder("BadActor")

    # Good bid
    bid1 = good_bidder.prepare_bid("INVALID_BID", pub_key, 45_000)
    r1 = await client.post("/auction/INVALID_BID/bid", content=json.dumps(bid1))
    print(f"  GoodCorp: bid £45,000 submitted → seq={r1.json().get('seq', 'ERR')}")

    # Bad bid (amount = 0 — server accepts it blindly; marked invalid after decryption)
    bid2 = bad_bidder.prepare_bid("INVALID_BID", pub_key, 0)
    r2 = await client.post("/auction/INVALID_BID/bid", content=json.dumps(bid2))
    print(
        f"  BadActor: bid £0 submitted → seq={r2.json().get('seq', 'ERR')} (will be invalid post-decryption)"
    )

    # Wait for deadline
    print("\n[SYSTEM] Waiting for auction deadline...")
    await asyncio.sleep(2.5)

    # Publish shares and decrypt
    print("\n[EVALUATORS] Publishing key shares...")
    for ev in evaluators[:2]:
        share = ev.publish_share()
        share["auction_id"] = "INVALID_BID"
        r = await client.post("/auction/INVALID_BID/share", json=share)
        d = r.json()
        print(
            f"  {ev.evaluator_id}: share published ({d['collected']}/{d['threshold']} collected)"
        )

    resp = await client.post("/auction/INVALID_BID/decrypt")
    result = resp.json()
    print("\n[RESULTS]")
    for bid in result["bids"]:
        status = "✓ VALID" if bid["valid"] else f"✗ INVALID: {bid['invalid_reason']}"
        amount = bid["bid_data"]["amount"] if bid["bid_data"] else "N/A"
        print(
            f"  [{bid['seq']}] {bid['bidder_id']}: £{amount} | sig_ok={bid['signature_verified']} | {status}"
        )

    if result["winner"]:
        print(
            f"  🏆 Winner: {result['winner']} with £{result['winning_amount']:,} (invalid bids excluded)"
        )
    else:
        print("  ⚠ No valid winner found")

    assert result["winner"] == "GoodCorp", f"Expected GoodCorp, got {result['winner']}"
    print("  ✓ Invalid bid correctly excluded from winner selection")


# ─────────────────────────────────────────────────────────────
# Main runner
# ─────────────────────────────────────────────────────────────
async def main():
    print("\n" + "=" * 60)
    print("  CSePS - Cryptographically Secure e-Procurement Demo")
    print("=" * 60)

    await run_scenario("Happy Path (3 bidders, 2-of-3 threshold)", scenario_happy_path)
    await run_scenario(
        "Malicious Oversized Payload Attack", scenario_malicious_oversized
    )
    await run_scenario("Late Bid Submission Attack", scenario_late_bid)
    await run_scenario(
        "Insufficient Threshold (Partial Evaluator Collusion)",
        scenario_insufficient_threshold,
    )
    await run_scenario("Invalid Bid Data (Zero Amount)", scenario_invalid_bid_data)

    print(f"\n{BANNER}")
    print("All scenarios completed.")
    print(BANNER)


if __name__ == "__main__":
    asyncio.run(main())
