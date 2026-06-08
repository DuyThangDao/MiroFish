"""
HIST cache — persist RAG-derived annotation titles per function.
  File: hist_inv_cache.json
  Key: sha256(contract_name + "::" + fn_name)[:16]
  Value: { fn_name, rag_query, inv_text, rag_title, rag_score, cg_entry, timestamp }
  Invalidation: khi đổi OP/ST query logic hoặc RAG DB thay đổi.

HIST-INV stmts cache — persist synthesized invariant statements per function.
  File: hist_inv_stmts.json  (cùng thư mục với hist_inv_cache.json)
  Key: same sha256 key
  Value: { contract_name, fn_name, hist_inv, timestamp }
  Invalidation: khi đổi synthesis prompt. Có thể rebuild độc lập từ hist_inv_cache.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional

CACHE_VERSION = 2      # HIST cache version
STMTS_VERSION = 1      # HIST-INV stmts cache version


class HistInvCache:
    """HIST RAG-title cache — hist_inv_cache.json."""

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
    def entry_key(contract_name: str, fn_name: str) -> str:
        return hashlib.sha256(
            f"{contract_name}::{fn_name}".encode()
        ).hexdigest()[:16]

    def get(self, key: str) -> Optional[dict]:
        return self._data.get(key)

    def set(self, key: str, contract_name: str, fn_name: str, rag_query: str,
            inv_text: str, rag_title: str, rag_score: float, cg_entry: str) -> None:
        self._data[key] = {
            "contract_name": contract_name,
            "fn_name": fn_name,
            "rag_query": rag_query,
            "inv_text": inv_text,
            "rag_title": rag_title,
            "rag_score": rag_score,
            "cg_entry": cg_entry,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

    def delete_by_fn(self, fn_name: str) -> int:
        to_delete = [k for k, v in self._data.items()
                     if v.get("fn_name") == fn_name]
        for k in to_delete:
            del self._data[k]
        return len(to_delete)

    def delete_by_contract(self, contract_name: str) -> int:
        to_delete = [k for k, v in self._data.items()
                     if v.get("contract_name") == contract_name]
        for k in to_delete:
            del self._data[k]
        return len(to_delete)

    def __len__(self) -> int:
        return len(self._data)

    def __bool__(self) -> bool:
        return True


class HistInvStmtsCache:
    """
    HIST-INV synthesized statements cache — hist_inv_stmts.json.

    Tách riêng khỏi HistInvCache để:
    - Tái sử dụng HIST titles cũ khi chỉ cần rebuild stmts
    - Xóa stmts độc lập khi đổi synthesis prompt mà không mất HIST
    - Backfill từ hist_inv_cache.json hiện có mà không cần chạy lại KG build

    Same key generation as HistInvCache.entry_key().
    """

    def __init__(self, stmts_path: str):
        self.path = Path(stmts_path)
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if raw.get("version") == STMTS_VERSION:
                    return raw.get("entries", {})
            except Exception:
                pass
        return {}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"version": STMTS_VERSION, "entries": self._data},
                       indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @staticmethod
    def entry_key(contract_name: str, fn_name: str) -> str:
        """Same key as HistInvCache — entries correspond 1-to-1."""
        return hashlib.sha256(
            f"{contract_name}::{fn_name}".encode()
        ).hexdigest()[:16]

    @staticmethod
    def stmts_path_from_hist_cache_path(hist_cache_path: str) -> str:
        """Derive stmts file path từ hist_inv_cache.json path."""
        return str(Path(hist_cache_path).parent / "hist_inv_stmts.json")

    def get(self, key: str) -> Optional[str]:
        """Returns hist_inv string or None."""
        entry = self._data.get(key)
        return entry.get("hist_inv", "") if entry else None

    def set(self, key: str, contract_name: str, fn_name: str, hist_inv: str) -> None:
        self._data[key] = {
            "contract_name": contract_name,
            "fn_name": fn_name,
            "hist_inv": hist_inv,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

    def get_hist_inv_map(self) -> dict:
        """Returns dict: (contract_name, fn_name) -> hist_inv. Only non-empty entries."""
        result = {}
        for v in self._data.values():
            inv = v.get("hist_inv", "").strip()
            if inv:
                result[(v.get("contract_name", ""), v.get("fn_name", ""))] = inv
        return result

    def __len__(self) -> int:
        return len(self._data)

    def __bool__(self) -> bool:
        return True
