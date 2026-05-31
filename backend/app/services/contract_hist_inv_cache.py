"""
HIST-INV cache — persist RAG-derived invariants per call graph entry.

Cache key: sha256(contract_name + "::" + cg_entry_line)[:16]
Cache value: { rag_query, inv_text, rag_title, rag_score, timestamp }
Cache file: <contest_cache_dir>/hist_inv_cache.json

Invalidation: chỉ khi CG entry text thay đổi (source code thay đổi).
Cùng contest, khác run → reuse 100% nếu code không đổi.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional

CACHE_VERSION = 1  # bump khi thay đổi schema cache


class HistInvCache:
    def __init__(self, cache_path: str):
        self.path = Path(cache_path)
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if raw.get("version") == CACHE_VERSION:
                    return raw.get("entries", {})
            except Exception:
                pass
        return {}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"version": CACHE_VERSION, "entries": self._data},
                       indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @staticmethod
    def entry_key(contract_name: str, cg_entry: str) -> str:
        """Deterministic key — same source code → same key mọi lần."""
        return hashlib.sha256(
            f"{contract_name}::{cg_entry}".encode()
        ).hexdigest()[:16]

    def get(self, key: str) -> Optional[dict]:
        return self._data.get(key)

    def set(self, key: str, rag_query: str, inv_text: str,
            rag_title: str, rag_score: float, cg_entry: str) -> None:
        self._data[key] = {
            "rag_query": rag_query,
            "inv_text": inv_text,
            "rag_title": rag_title,
            "rag_score": rag_score,
            "cg_entry": cg_entry,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

    def __len__(self) -> int:
        return len(self._data)

    def __bool__(self) -> bool:
        return True  # always truthy — even empty cache is a valid cache object
