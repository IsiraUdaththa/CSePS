"""
CSePS FastAPI Server
====================
Endpoints:
  POST /auction/create          - Authority creates auction, server distributes keys
  GET  /auction/{id}            - Public auction info + public key
  GET  /auction/{id}/ledger     - Public encrypted ledger (JSONL)
  POST /auction/{id}/bid        - Submit encrypted bid
  POST /auction/{id}/share      - Evaluator submits their key share
  POST /auction/{id}/decrypt    - Trigger decryption (after threshold shares)
  GET  /auction/{id}/results    - Decrypted ledger (after decryption)
"""

from __future__ import annotations
import json, os, time, secrets
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

from cseps.crypto import (
    generate_keypair,
    serialize_public_key,
    deserialize_public_key,
    private_key_to_int,
    int_to_private_key,
    shamir_split,
    shamir_reconstruct,
    ecies_encrypt,
    ecies_decrypt,
    verify_signature,
    compute_entry_hash,
    verify_chain_integrity,
)
from cseps.models import (
    AuctionConfig,
    EvaluatorInfo,
    EncryptedShare,
    BidSubmission,
    LedgerEntry,
    ShareSubmission,
    DecryptedBid,
    DecryptedLedger,
)
from cseps.database import LedgerDB

app = FastAPI(title="CSePS Server", version="1.0")

# ── In-memory state (per auction) ────────────────────────────
_auctions: Dict[str, AuctionConfig] = {}
_encrypted_shares: Dict[str, List[EncryptedShare]] = (
    {}
)  # auction_id → shares for evaluators
_collected_shares: Dict[str, List[tuple]] = {}  # auction_id → [(x, y_int)]
_decrypted_ledgers: Dict[str, DecryptedLedger] = {}
_ledger_dbs: Dict[str, LedgerDB] = {}
_server_private_keys: Dict[str, object] = (
    {}
)  # auction_id → private key (in-memory, for demo)

# ── Config ───────────────────────────────────────────────────
MAX_ENCRYPTED_BID_BYTES = 4096  # prevent oversized payloads
MAX_BIDS_PER_AUCTION = 10_000
DATA_DIR = "cseps_data"
os.makedirs(DATA_DIR, exist_ok=True)


def _ledger(auction_id: str) -> LedgerDB:
    if auction_id not in _ledger_dbs:
        path = os.path.join(DATA_DIR, f"{auction_id}.jsonl")
        _ledger_dbs[auction_id] = LedgerDB(path)
    return _ledger_dbs[auction_id]


# ── Auction Creation ─────────────────────────────────────────
@app.post("/auction/create")
async def create_auction(config: dict):
    """
    Authority posts auction config including evaluator list.
    Server generates auction keypair, splits private key via Shamir,
    encrypts each share to the corresponding evaluator, publishes public key.
    """
    auction_id = config["auction_id"]
    if auction_id in _auctions:
        raise HTTPException(400, "Auction already exists")

    evaluators = [EvaluatorInfo(**e) for e in config["evaluators"]]
    threshold = config["threshold"]
    n = len(evaluators)

    if threshold > n:
        raise HTTPException(400, "Threshold > number of evaluators")

    # 1. Generate auction keypair
    priv, pub = generate_keypair()
    secret_int = private_key_to_int(priv)

    # 2. Shamir split
    shares = shamir_split(secret_int, n, threshold)  # [(x, y), ...]

    # 3. Encrypt each share to evaluator's public key
    enc_shares = []
    for i, ev in enumerate(evaluators):
        ev_pub = deserialize_public_key(ev.public_key_pem.encode())
        share_payload = json.dumps({"x": shares[i][0], "y": hex(shares[i][1])}).encode()
        encrypted = ecies_encrypt(ev_pub, share_payload)
        enc_shares.append(
            EncryptedShare(evaluator_id=ev.evaluator_id, encrypted_payload=encrypted)
        )

    # 4. Build and store auction config
    pub_pem = serialize_public_key(pub).decode()
    auction = AuctionConfig(
        auction_id=auction_id,
        title=config["title"],
        deadline=config["deadline"],
        threshold=threshold,
        evaluators=evaluators,
        server_public_key_pem=pub_pem,
    )
    _auctions[auction_id] = auction
    _encrypted_shares[auction_id] = enc_shares
    _collected_shares[auction_id] = []
    _server_private_keys[auction_id] = priv  # kept only for recovery demo

    return {
        "status": "created",
        "auction_id": auction_id,
        "public_key_pem": pub_pem,
        "encrypted_shares": [s.model_dump() for s in enc_shares],
    }


# ── Public Auction Info ───────────────────────────────────────
@app.get("/auction/{auction_id}")
async def get_auction(auction_id: str):
    _require_auction(auction_id)
    a = _auctions[auction_id]
    return {
        "auction_id": a.auction_id,
        "title": a.title,
        "deadline": a.deadline,
        "threshold": a.threshold,
        "n_evaluators": len(a.evaluators),
        "public_key_pem": a.server_public_key_pem,
        "bid_count": _ledger(auction_id).count(),
        "open": time.time() < a.deadline,
    }


# ── Public Ledger ─────────────────────────────────────────────
@app.get("/auction/{auction_id}/ledger", response_class=PlainTextResponse)
async def get_ledger(auction_id: str):
    """Returns the raw JSONL ledger (public, encrypted)."""
    _require_auction(auction_id)
    db = _ledger(auction_id)
    lines = []
    for entry in db.iter_entries():
        lines.append(entry.model_dump_json())
    return "\n".join(lines)


# ── Bid Submission ────────────────────────────────────────────
@app.post("/auction/{auction_id}/bid")
async def submit_bid(auction_id: str, request: Request):
    _require_auction(auction_id)
    auction = _auctions[auction_id]

    # Deadline check
    if time.time() > auction.deadline:
        raise HTTPException(403, "Auction deadline has passed")

    body = await request.body()

    # Size restriction (prevent abuse)
    if len(body) > MAX_ENCRYPTED_BID_BYTES * 2:
        raise HTTPException(
            413, f"Payload too large. Max {MAX_ENCRYPTED_BID_BYTES * 2} bytes"
        )

    bid = BidSubmission(**json.loads(body))

    if bid.auction_id != auction_id:
        raise HTTPException(400, "auction_id mismatch")

    # Size check on encrypted bid ciphertext
    ct_hex = bid.encrypted_bid.get("ciphertext", "")
    if len(bytes.fromhex(ct_hex)) > MAX_ENCRYPTED_BID_BYTES:
        raise HTTPException(
            413, f"Encrypted bid too large. Max {MAX_ENCRYPTED_BID_BYTES} bytes"
        )

    # Capacity check
    db = _ledger(auction_id)
    if db.count() >= MAX_BIDS_PER_AUCTION:
        raise HTTPException(429, "Auction bid capacity reached")

    # Basic nonce uniqueness (we can only check in-memory last; full check on disk would scan)
    # For demo we skip full scan; in production use a bloom filter / index

    # Build ledger entry
    entry_data = json.dumps(bid.model_dump(), sort_keys=True).encode()
    prev_hash = db.last_hash()
    entry_hash = compute_entry_hash(prev_hash, entry_data)
    seq = db.count()

    entry = LedgerEntry(
        seq=seq,
        auction_id=auction_id,
        bidder_id=bid.bidder_id,
        encrypted_bid=bid.encrypted_bid,
        signature=bid.signature,
        bidder_public_key_pem=bid.bidder_public_key_pem,
        timestamp=bid.timestamp,
        timestamp_ms=bid.timestamp_ms,
        nonce=bid.nonce,
        prev_hash=prev_hash,
        hash=entry_hash,
    )
    db.append(entry)

    return {"status": "recorded", "seq": seq, "hash": entry_hash}


# ── Share Submission ──────────────────────────────────────────
@app.post("/auction/{auction_id}/share")
async def submit_share(auction_id: str, submission: ShareSubmission):
    _require_auction(auction_id)
    auction = _auctions[auction_id]

    if time.time() < auction.deadline:
        raise HTTPException(403, "Auction still open. Shares accepted after deadline.")

    # Verify evaluator is registered
    ev_ids = {e.evaluator_id for e in auction.evaluators}
    if submission.evaluator_id not in ev_ids:
        raise HTTPException(403, "Unknown evaluator")

    # Verify signature from evaluator
    ev_pub_pem = next(
        e.public_key_pem
        for e in auction.evaluators
        if e.evaluator_id == submission.evaluator_id
    )
    ev_pub = deserialize_public_key(ev_pub_pem.encode())
    share_bytes = (
        f"{submission.evaluator_id}:{submission.share_x}:{submission.share_y}".encode()
    )
    sig = bytes.fromhex(submission.signature)
    if not verify_signature(ev_pub, share_bytes, sig):
        raise HTTPException(400, "Invalid evaluator signature on share")

    y_int = int(submission.share_y, 16)
    _collected_shares[auction_id].append((submission.share_x, y_int))

    return {
        "status": "share_recorded",
        "collected": len(_collected_shares[auction_id]),
        "threshold": auction.threshold,
    }


# ── Decrypt Ledger ────────────────────────────────────────────
@app.post("/auction/{auction_id}/decrypt")
async def decrypt_ledger(auction_id: str):
    _require_auction(auction_id)
    auction = _auctions[auction_id]

    if time.time() < auction.deadline:
        raise HTTPException(403, "Cannot decrypt before deadline")

    shares = _collected_shares[auction_id]
    if len(shares) < auction.threshold:
        raise HTTPException(400, f"Need {auction.threshold} shares, have {len(shares)}")

    # Reconstruct private key
    secret_int = shamir_reconstruct(shares[: auction.threshold])
    priv = int_to_private_key(secret_int)

    db = _ledger(auction_id)
    all_entries = db.all_entries()

    # Verify chain integrity first
    chain_valid, chain_reason = verify_chain_integrity(
        [e.model_dump() for e in all_entries]
    )

    decrypted_bids = []
    nonces_seen = set()

    for entry in all_entries:
        invalid_reason = None
        bid_data = None
        sig_verified = False

        try:
            # Decrypt
            plaintext = ecies_decrypt(priv, entry.encrypted_bid)
            bid_data = json.loads(plaintext)

            # Verify signature using the same canonical scheme as the bidder
            bidder_pub = deserialize_public_key(entry.bidder_public_key_pem.encode())
            signed_bytes = json.dumps(
                {
                    "auction_id": entry.auction_id,
                    "bidder_id": entry.bidder_id,
                    "encrypted_bid": {
                        "ciphertext": entry.encrypted_bid["ciphertext"],
                        "ephemeral_pub": entry.encrypted_bid["ephemeral_pub"],
                        "nonce": entry.encrypted_bid["nonce"],
                    },
                    "nonce": entry.nonce,
                    "timestamp_ms": entry.timestamp_ms,
                },
                sort_keys=True,
            ).encode()
            sig = bytes.fromhex(entry.signature)
            sig_verified = verify_signature(bidder_pub, signed_bytes, sig)
            if not sig_verified:
                invalid_reason = "Signature verification failed"

            # Nonce replay check
            if entry.nonce in nonces_seen:
                invalid_reason = (invalid_reason or "") + " Duplicate nonce (replay)"
            nonces_seen.add(entry.nonce)

            # Basic bid structure check
            if "amount" not in bid_data:
                invalid_reason = (invalid_reason or "") + " Missing 'amount' field"
            elif (
                not isinstance(bid_data["amount"], (int, float))
                or bid_data["amount"] <= 0
            ):
                invalid_reason = (invalid_reason or "") + " Invalid bid amount"

        except Exception as ex:
            invalid_reason = f"Decryption/parse error: {ex}"

        decrypted_bids.append(
            DecryptedBid(
                seq=entry.seq,
                bidder_id=entry.bidder_id,
                bid_data=bid_data,
                valid=invalid_reason is None,
                invalid_reason=invalid_reason,
                signature_verified=sig_verified,
                timestamp=entry.timestamp,
            )
        )

    # Determine winner (lowest valid bid for procurement)
    valid_bids = [b for b in decrypted_bids if b.valid]
    winner = None
    winning_amount = None
    if valid_bids:
        best = min(valid_bids, key=lambda b: b.bid_data["amount"])
        winner = best.bidder_id
        winning_amount = best.bid_data["amount"]

    result = DecryptedLedger(
        auction_id=auction_id,
        bids=decrypted_bids,
        chain_valid=chain_valid,
        chain_reason=chain_reason,
        winner=winner,
        winning_amount=winning_amount,
    )
    _decrypted_ledgers[auction_id] = result
    return result.model_dump()


# ── Results ───────────────────────────────────────────────────
@app.get("/auction/{auction_id}/results")
async def get_results(auction_id: str):
    _require_auction(auction_id)
    if auction_id not in _decrypted_ledgers:
        raise HTTPException(404, "Results not yet available. Decryption not triggered.")
    return _decrypted_ledgers[auction_id].model_dump()


# ── Helper ────────────────────────────────────────────────────
def _require_auction(auction_id: str):
    if auction_id not in _auctions:
        raise HTTPException(404, "Auction not found")
