"""
JSONL-based ledger database abstraction.
Server keeps only the last entry in memory; everything else is on disk.
"""

from __future__ import annotations
import json
import os
from typing import Optional, List, Generator
from cseps.models import LedgerEntry


class LedgerDB:
    """
    Append-only JSONL ledger.
    In-memory: only the last entry (for hash chaining).
    On disk: every entry as a JSON line.
    """

    def __init__(self, path: str):
        self._path = path
        self._last: Optional[LedgerEntry] = None
        self._count: int = 0
        # Load last entry if file exists
        if os.path.exists(path):
            for entry in self._iter_raw():
                self._last = LedgerEntry(**entry)
                self._count += 1

    # ── Write ────────────────────────────────────────────────
    def append(self, entry: LedgerEntry) -> None:
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(entry.model_dump_json() + "\n")
        self._last = entry
        self._count += 1

    # ── Read ─────────────────────────────────────────────────
    def last_entry(self) -> Optional[LedgerEntry]:
        return self._last

    def last_hash(self) -> str:
        return self._last.hash if self._last else "0" * 64

    def count(self) -> int:
        return self._count

    def iter_entries(self) -> Generator[LedgerEntry, None, None]:
        for raw in self._iter_raw():
            yield LedgerEntry(**raw)

    def all_entries(self) -> List[LedgerEntry]:
        return list(self.iter_entries())

    # ── Internal ─────────────────────────────────────────────
    def _iter_raw(self) -> Generator[dict, None, None]:
        if not os.path.exists(self._path):
            return
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def clear(self) -> None:
        if os.path.exists(self._path):
            os.remove(self._path)
        self._last = None
        self._count = 0
