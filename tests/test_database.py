"""Unit tests for cseps/database.py"""

import os
import pytest
import time
from cseps.database import LedgerDB
from cseps.models import LedgerEntry


def _make_entry(seq: int, prev_hash: str = "0" * 64) -> LedgerEntry:
    return LedgerEntry(
        seq=seq,
        auction_id="test",
        bidder_id=f"bidder_{seq}",
        encrypted_bid={"ephemeral_pub": "x", "nonce": "aa", "ciphertext": "bb"},
        signature="sig",
        bidder_public_key_pem="pem",
        timestamp=time.time(),
        nonce=f"nonce_{seq}",
        prev_hash=prev_hash,
        hash="a" * 64,
    )


@pytest.fixture
def tmp_db(tmp_path):
    path = str(tmp_path / "test.jsonl")
    db = LedgerDB(path)
    yield db
    if os.path.exists(path):
        os.remove(path)


class TestLedgerDB:
    def test_empty_db(self, tmp_db):
        assert tmp_db.count() == 0
        assert tmp_db.last_entry() is None
        assert tmp_db.last_hash() == "0" * 64

    def test_append_and_count(self, tmp_db):
        e = _make_entry(0)
        tmp_db.append(e)
        assert tmp_db.count() == 1

    def test_last_entry(self, tmp_db):
        e0 = _make_entry(0)
        e1 = _make_entry(1)
        tmp_db.append(e0)
        tmp_db.append(e1)
        assert tmp_db.last_entry().seq == 1

    def test_iter_entries(self, tmp_db):
        for i in range(5):
            tmp_db.append(_make_entry(i))
        entries = list(tmp_db.iter_entries())
        assert len(entries) == 5
        assert entries[2].seq == 2

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "persist.jsonl")
        db1 = LedgerDB(path)
        for i in range(3):
            db1.append(_make_entry(i))
        # Re-open
        db2 = LedgerDB(path)
        assert db2.count() == 3
        assert db2.last_entry().seq == 2

    def test_clear(self, tmp_db):
        tmp_db.append(_make_entry(0))
        tmp_db.clear()
        assert tmp_db.count() == 0
        assert tmp_db.last_entry() is None
