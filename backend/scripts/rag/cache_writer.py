"""
cache_writer.py — Atomic batch-write helper for rag_sections_cache.json.

Usage (in Claude's migration session):

    from scripts.rag.cache_writer import CacheWriter

    cw = CacheWriter()                  # loads existing cache or creates empty one

    # After processing a batch:
    cw.append_findings([
        {
            "slug": "h-01-...",
            "status": "done",           # done | done_no_code | failed
            "title": "...",
            "firm": "Sherlock",
            "protocol": "...",
            "impact": "HIGH",
            "source_link": "https://...",
            "content_source": "api_excerpt",
            "code_source": "code_block",   # or None
            "sections": {
                "vul":  "prose...",
                "code": "_VAR -= uint128(_VAR);",   # or None
                "op":   None,
                "inv":  None,
            },
        },
        ...
    ])

    # Record a failed GitHub fetch (skip on next resume):
    cw.add_fetch_error("some-slug", url="https://github.com/...", reason="404")

    # Save to disk (atomic write via temp file):
    cw.save()

    # Convenience — one call:
    cw.append_and_save(findings, fetch_errors={"slug": {"url":..., "reason":...}})
"""

import json
import os
import tempfile
from pathlib import Path

CACHE_PATH = Path(__file__).parent / "rag_sections_cache.json"
TOTAL_FINDINGS = 3366

_EMPTY_CACHE = {
    "_meta": {
        "version": "1.0",
        "total_findings": TOTAL_FINDINGS,
        "processed_count": 0,
        "last_processed_slug": None,
    },
    "fetch_errors": {},
    "findings": [],
}


class CacheWriter:
    def __init__(self, path: Path = CACHE_PATH):
        self.path = path
        self._cache = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
                # Ensure all top-level keys exist
                data.setdefault("_meta", dict(_EMPTY_CACHE["_meta"]))
                data.setdefault("fetch_errors", {})
                data.setdefault("findings", [])
                data["_meta"].setdefault("total_findings", TOTAL_FINDINGS)
                data["_meta"].setdefault("processed_count", len(data["findings"]))
                data["_meta"].setdefault("last_processed_slug", None)
                return data
            except (json.JSONDecodeError, KeyError):
                print(f"[CacheWriter] Warning: corrupt cache at {self.path}, starting fresh")
        return {k: (v.copy() if isinstance(v, dict) else v)
                for k, v in _EMPTY_CACHE.items()}

    # ── read helpers ─────────────────────────────────────────────────────────

    @property
    def done_slugs(self) -> set[str]:
        """All slugs already processed (done, done_no_code, or failed)."""
        return {f["slug"] for f in self._cache["findings"]}

    @property
    def failed_fetch_urls(self) -> set[str]:
        """URLs that previously failed GitHub fetch — do NOT retry."""
        return {v["url"] for v in self._cache["fetch_errors"].values()}

    def already_processed(self, slug: str) -> bool:
        return slug in self.done_slugs

    def fetch_failed(self, url: str) -> bool:
        return url in self.failed_fetch_urls

    @property
    def processed_count(self) -> int:
        return len(self._cache["findings"])

    def summary(self) -> str:
        total = self._cache["_meta"]["total_findings"]
        done  = self.processed_count
        errs  = len(self._cache["fetch_errors"])
        last  = self._cache["_meta"].get("last_processed_slug") or "—"
        return (f"Processed {done}/{total} | fetch_errors={errs} "
                f"| last={last}")

    # ── write helpers ─────────────────────────────────────────────────────────

    def append_findings(self, findings: list[dict]) -> None:
        """Append findings to in-memory cache (does NOT save to disk)."""
        if not findings:
            return
        self._cache["findings"].extend(findings)
        self._cache["_meta"]["processed_count"] = self.processed_count
        self._cache["_meta"]["last_processed_slug"] = findings[-1]["slug"]

    def add_fetch_error(self, slug: str, url: str, reason: str,
                        attempted_at: str = "2026-06-08") -> None:
        """Record a failed GitHub fetch (won't be retried on resume)."""
        self._cache["fetch_errors"][slug] = {
            "url": url,
            "reason": reason,
            "attempted_at": attempted_at,
        }

    def save(self) -> None:
        """Atomically write cache to disk (temp → rename)."""
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._cache, ensure_ascii=False, indent=2))
        os.replace(tmp, self.path)

    def append_and_save(
        self,
        findings: list[dict],
        fetch_errors: dict[str, dict] | None = None,
    ) -> None:
        """Convenience: append findings + optional errors, then save."""
        self.append_findings(findings)
        if fetch_errors:
            for slug, info in fetch_errors.items():
                self.add_fetch_error(
                    slug,
                    url=info.get("url", ""),
                    reason=info.get("reason", "unknown"),
                    attempted_at=info.get("attempted_at", "2026-06-08"),
                )
        self.save()
        print(f"[CacheWriter] Saved. {self.summary()}")


# ── CLI: quick status check ───────────────────────────────────────────────────
if __name__ == "__main__":
    cw = CacheWriter()
    print(cw.summary())
    from collections import Counter
    status_counts = Counter(f.get("status") for f in cw._cache["findings"])
    for k, v in status_counts.items():
        print(f"  {k}: {v}")
