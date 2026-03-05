"""
Authority simulation.
The authority (government procurement office):
  1. Knows the evaluators.
  2. Calls server to create the auction.
  3. Distributes the encrypted shares back to evaluators.
  4. Monitors the process.
"""

from __future__ import annotations
import time
from typing import List


class Authority:
    def __init__(self, authority_id: str = "GOV_AUTHORITY"):
        self.authority_id = authority_id

    def build_auction_request(
        self,
        auction_id: str,
        title: str,
        evaluators: list,
        threshold: int,
        duration_seconds: float = 60.0,
    ) -> dict:
        return {
            "auction_id": auction_id,
            "title": title,
            "deadline": time.time() + duration_seconds,
            "threshold": threshold,
            "evaluators": [e.to_info() for e in evaluators],
        }
