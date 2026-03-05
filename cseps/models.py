"""Pydantic models for CSePS."""

from __future__ import annotations
from typing import Optional, List
from pydantic import BaseModel, Field
import time


class EvaluatorInfo(BaseModel):
    evaluator_id: str
    public_key_pem: str  # evaluator's ECC public key


class AuctionConfig(BaseModel):
    auction_id: str
    title: str
    deadline: float  # Unix timestamp
    threshold: int  # Shamir threshold k
    evaluators: List[EvaluatorInfo]
    server_public_key_pem: str  # auction encryption key (public)
    chain_genesis_hash: str = "0" * 64


class EncryptedShare(BaseModel):
    evaluator_id: str
    encrypted_payload: dict  # ECIES encrypted share


class BidSubmission(BaseModel):
    auction_id: str
    bidder_id: str  # pseudonym or real ID
    encrypted_bid: dict  # ECIES payload
    signature: str  # hex ECDSA over canonical bid bytes
    bidder_public_key_pem: str
    timestamp: float = Field(default_factory=time.time)
    timestamp_ms: int = 0  # authoritative integer ms timestamp for sig verification
    nonce: str  # random hex to prevent replay


class LedgerEntry(BaseModel):
    seq: int
    auction_id: str
    bidder_id: str
    encrypted_bid: dict
    signature: str
    bidder_public_key_pem: str
    timestamp: float
    timestamp_ms: int = 0
    nonce: str
    prev_hash: str
    hash: str


class ShareSubmission(BaseModel):
    auction_id: str
    evaluator_id: str
    share_x: int
    share_y: str  # hex string of large int
    signature: str  # hex ECDSA by evaluator


class DecryptedBid(BaseModel):
    seq: int
    bidder_id: str
    bid_data: Optional[dict]
    valid: bool
    invalid_reason: Optional[str] = None
    signature_verified: bool = False
    timestamp: float


class DecryptedLedger(BaseModel):
    auction_id: str
    bids: List[DecryptedBid]
    chain_valid: bool
    chain_reason: str
    winner: Optional[str] = None
    winning_amount: Optional[float] = None
