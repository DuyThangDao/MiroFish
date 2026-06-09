#!/usr/bin/env python3
"""
process_sections_gemini.py — Automated RAG 4-section extraction via Vertex AI Gemini.

Reads work_queue.json, skips already-processed slugs from rag_sections_cache.json,
calls google/gemini-3-flash-preview via Vertex AI OpenAI-compatible endpoint with
2 workers in parallel, saves results incrementally.

Usage (from MiroFish/backend/ with venv activated):
    source .venv/bin/activate
    python scripts/rag/process_sections_gemini.py [--dry-run] [--workers 2] [--batch-size 15]

Environment read from ../.env:
    LLM_VERTEX_AI_KEY_FILE   — service account JSON, worker 1
    LLM2_VERTEX_AI_KEY_FILE  — service account JSON, worker 2 (optional)
    LLM_BASE_URL             — Vertex AI OpenAI-compatible endpoint
    LLM_MODEL_NAME           — model name (google/gemini-3-flash-preview)
    LLM_GLOBAL_RPM_LIMIT     — global RPM cap (default 18)
    LLM_SUBMIT_DELAY_S       — per-request sleep after acquiring RPM slot (default 8)
"""

import sys
import os
import json
import re
import time
import logging
import fcntl
import argparse
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_DIR = SCRIPT_DIR.parent.parent.parent  # MiroFish/


def _load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


_load_env(REPO_DIR / ".env")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(SCRIPT_DIR / "process_sections.log", mode="a"),
    ],
)
log = logging.getLogger("process_sections")

# ── Rate limiter (shared across threads via file lock) ────────────────────────
_RPM_FILE = "/tmp/mirofish_rag_rpm.json"
_RPM_LOCK = "/tmp/mirofish_rag_rpm.lock"
_RPM_LIMIT = int(os.environ.get("LLM_GLOBAL_RPM_LIMIT", "18"))
_SUBMIT_DELAY = float(os.environ.get("LLM_SUBMIT_DELAY_S", "8"))


def _acquire_rpm_slot() -> None:
    """Block until a slot opens in the 60-second RPM window. Thread-safe via flock."""
    if _RPM_LIMIT <= 0:
        return
    while True:
        wait_for = 0.0
        with open(_RPM_LOCK, "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                now = time.time()
                cutoff = now - 60.0
                try:
                    with open(_RPM_FILE) as f:
                        data = json.load(f)
                    ts = [t for t in data.get("ts", []) if t > cutoff]
                except (FileNotFoundError, ValueError):
                    ts = []
                if len(ts) < _RPM_LIMIT:
                    ts.append(now)
                    with open(_RPM_FILE, "w") as f:
                        json.dump({"ts": ts}, f)
                    return
                wait_for = ts[0] + 60.0 - now + 0.1
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)
        time.sleep(min(wait_for, 1.0))


# ── Vertex AI OpenAI-compatible client ────────────────────────────────────────
def _build_vertex_client(key_file: str, base_url: str):
    """OpenAI client with Vertex AI service-account auth (auto token refresh)."""
    import httpx
    from openai import OpenAI
    from google.oauth2 import service_account
    import google.auth.transport.requests

    creds = service_account.Credentials.from_service_account_file(
        key_file,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )

    class _Auth(httpx.Auth):
        def auth_flow(self, request):
            if not creds.valid:
                creds.refresh(google.auth.transport.requests.Request())
            request.headers["Authorization"] = f"Bearer {creds.token}"
            yield request

    return OpenAI(
        api_key="vertex-ai",
        base_url=base_url,
        http_client=httpx.Client(auth=_Auth(), timeout=120),
        max_retries=0,
    )


# ── LLM call with rate limiting and retry ─────────────────────────────────────
def _call_llm(client, model: str, prompt: str, max_tokens: int = 8192) -> str:
    """Call LLM. Returns raw string. Retries on 429 up to 5 times."""
    max_retries = 5
    base_delay = 15
    for attempt in range(max_retries):
        try:
            _acquire_rpm_slot()
            if _SUBMIT_DELAY > 0:
                time.sleep(_SUBMIT_DELAY)
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=max_tokens,
                extra_body={"google": {"thinking_config": {"thinking_level": "low"}}},
            )
            msg = resp.choices[0].message if resp.choices else None
            raw = (msg.content if msg else "") or ""
            # Debug: log raw length and finish_reason
            finish = resp.choices[0].finish_reason if resp.choices else "?"
            log.debug(f"[LLM] finish_reason={finish} raw_len={len(raw)} raw_preview={raw[:200]!r}")
            if not raw:
                log.warning(f"[LLM] Empty content from model. finish_reason={finish}. Message fields: {vars(msg) if msg else 'None'}")
            # Strip thinking blocks and markdown fences
            raw = re.sub(r"<think>[\s\S]*?</think>", "", raw).strip()
            raw = re.sub(r"^```(?:json)?\s*\n?", "", raw, flags=re.IGNORECASE)
            raw = re.sub(r"\n?```\s*$", "", raw)
            return raw.strip()
        except Exception as e:
            is_rate = (
                "429" in str(e)
                or "rate" in str(e).lower()
                or "quota" in str(e).lower()
                or "resource_exhausted" in str(e).lower()
            )
            if is_rate and attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                log.warning(
                    f"Rate limit (attempt {attempt+1}/{max_retries}), waiting {delay}s..."
                )
                time.sleep(delay)
            else:
                raise


# ── Solidity normalization ─────────────────────────────────────────────────────
_SOL_KEYWORDS = {
    "abstract", "address", "anonymous", "assembly", "bool", "break", "bytes",
    "bytes1", "bytes2", "bytes4", "bytes8", "bytes16", "bytes32", "calldata",
    "catch", "constant", "constructor", "continue", "contract", "delete", "do",
    "else", "emit", "enum", "ether", "event", "external", "fallback", "false",
    "final", "for", "from", "function", "gwei", "if", "immutable", "import",
    "indexed", "interface", "internal", "is", "library", "mapping", "memory",
    "modifier", "new", "override", "payable", "pragma", "private", "public",
    "pure", "receive", "return", "returns", "revert", "storage", "struct",
    "super", "this", "throw", "true", "try", "type", "uint", "uint8", "uint16",
    "uint32", "uint64", "uint96", "uint128", "uint160", "uint256", "unchecked",
    "using", "view", "virtual", "while", "int", "int8", "int16", "int32",
    "int64", "int128", "int256", "string", "tuple", "require", "assert",
    "keccak256", "sha256", "ripemd160", "ecrecover", "addmod", "mulmod",
    "selfdestruct", "transfer", "send", "call", "delegatecall", "staticcall",
    "block", "tx", "msg", "now", "gasleft", "blockhash", "abi", "encode",
    "decode", "encodePacked", "encodeWithSelector", "encodeWithSignature",
    "encodeCall", "wei", "finney", "szabo", "seconds", "minutes", "hours",
    "days", "weeks", "years", "fixed", "var",
}


def _normalize_sol(code: str) -> str:
    if not code:
        return code
    return re.sub(
        r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
        lambda m: m.group(0) if m.group(0) in _SOL_KEYWORDS else "_VAR",
        code,
    )


# ── Junk code detection ────────────────────────────────────────────────────────
def _is_junk(code: str) -> bool:
    """True if code is not real Solidity (git diff, JS test, CLI output, etc.)."""
    if not code or len(code.strip()) < 20:
        return True
    lines = code.strip().splitlines()
    # Git diff markers
    if any(ln.startswith(("@@ ", "+++ ", "--- ", "diff ")) for ln in lines[:5]):
        return True
    # JavaScript / TypeScript test patterns (3+ hits → junk)
    js_patterns = [
        "() => {", "describe(", "it(", "expect(", ".to.", "beforeEach",
        "afterEach", "console.log", "async function", "await ",
    ]
    if sum(1 for p in js_patterns if p in code) >= 3:
        return True
    # CLI / terminal output
    cli_patterns = ["✓", "✗", "[⠑]", "[⠒]", "$ ", "npm ", "yarn "]
    if sum(1 for p in cli_patterns if p in code) >= 2:
        return True
    # Rust syntax
    if "-> " in code and any(kw in code for kw in ("fn ", "let mut ", "impl ")):
        return True
    # Only imports / comments / NatSpec — no real code
    real_lines = [
        ln.strip()
        for ln in lines
        if ln.strip()
        and not ln.strip().startswith(("//", "*", "/*", "/**", "* ", "import", "pragma", "using"))
    ]
    if not real_lines:
        return True
    # Must have at least one Solidity keyword
    has_sol = any(
        re.search(
            r"\b(function|mapping|uint|address|require|emit|return|if|for|while|struct|event)\b",
            ln,
        )
        for ln in lines
    )
    return not has_sol


# ── Prompt template ────────────────────────────────────────────────────────────
_PROMPT_HEADER = """\
You are a smart contract security expert. For each finding, extract two sections.

1. **vul**: 2-5 sentence prose describing the vulnerability — what the bug is, why it's \
dangerous, which invariant is violated. Write in the style of an audit finding description. \
NO code in this field.

2. **code**: The most relevant Solidity code snippet showing the vulnerability.
  - ONLY real Solidity — reject git diffs, JS/TS tests, CLI output, Rust, Python.
  - Normalize: replace ALL user-defined identifiers (variable/function/contract/type names) \
with _VAR. Keep Solidity keywords, built-in types (uint256, address, mapping, etc.), \
and operators unchanged.
  - Example: "totalSupply -= burnAmount;" → "_VAR -= _VAR;"
  - If no valid Solidity code exists → output null (not a string).

Output ONLY valid JSON (no markdown):
{"findings": [{"slug": "...", "vul": "prose", "code": "normalized Solidity or null"}, ...]}

Findings:
"""


def _build_prompt(batch: list) -> str:
    items = []
    for f in batch:
        item: dict = {
            "slug": f["slug"],
            "title": f.get("title", ""),
            "impact": f.get("impact", ""),
            "excerpt": (f.get("text_excerpt") or "")[:800],
        }
        code_blocks = f.get("code_blocks") or []
        audit_snippet = f.get("audit_snippet")
        if code_blocks:
            item["code_blocks"] = code_blocks[:2]
        elif audit_snippet:
            item["audit_snippet"] = audit_snippet[:600]
        items.append(item)
    return _PROMPT_HEADER + json.dumps(items, ensure_ascii=False, indent=2)


# ── Single finding fallback ────────────────────────────────────────────────────
def _make_failed(f: dict) -> dict:
    return {
        "slug": f["slug"],
        "status": "failed",
        "title": f.get("title", ""),
        "firm": f.get("firm", ""),
        "protocol": f.get("protocol", ""),
        "impact": f.get("impact", ""),
        "source_link": f.get("source_link", ""),
        "content_source": f.get("content_source", ""),
        "code_source": f.get("code_source"),
        "sections": {"vul": None, "code": None, "op": None, "inv": None},
    }


def _make_result(f: dict, vul: str, raw_code) -> dict:
    code = None
    if raw_code and isinstance(raw_code, str) and not _is_junk(raw_code):
        code = _normalize_sol(raw_code.strip())
    return {
        "slug": f["slug"],
        "status": "done" if code else "done_no_code",
        "title": f.get("title", ""),
        "firm": f.get("firm", ""),
        "protocol": f.get("protocol", ""),
        "impact": f.get("impact", ""),
        "source_link": f.get("source_link", ""),
        "content_source": f.get("content_source", ""),
        "code_source": f.get("code_source"),
        "sections": {
            "vul": vul or f"[{f.get('impact','?')}] {f.get('title', f['slug'])}",
            "code": code,
            "op": None,
            "inv": None,
        },
    }


# ── Batch processor ───────────────────────────────────────────────────────────
def process_batch(
    client, model: str, batch: list, worker_id: int, batch_idx: int
) -> list:
    log.info(f"[W{worker_id}] batch#{batch_idx+1} ({len(batch)}): {batch[0]['slug'][:50]}…")
    prompt = _build_prompt(batch)
    try:
        raw = _call_llm(client, model, prompt)
        data = json.loads(raw)
        by_slug = {r["slug"]: r for r in data.get("findings", [])}
    except Exception as e:
        log.error(f"[W{worker_id}] batch#{batch_idx+1} failed: {e}")
        return [_make_failed(f) for f in batch]

    results = []
    for f in batch:
        r = by_slug.get(f["slug"])
        if not r:
            log.warning(f"[W{worker_id}] no result for {f['slug'][:50]}, marking failed")
            results.append(_make_failed(f))
            continue
        results.append(_make_result(f, (r.get("vul") or "").strip(), r.get("code")))

    n_done = sum(1 for r in results if r["status"] == "done")
    n_no_code = sum(1 for r in results if r["status"] == "done_no_code")
    n_fail = sum(1 for r in results if r["status"] == "failed")
    log.info(f"[W{worker_id}] batch#{batch_idx+1} → {n_done} done, {n_no_code} done_no_code, {n_fail} failed")
    return results


# ── Main ───────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Process RAG sections via Vertex AI Gemini"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show plan without calling LLM"
    )
    parser.add_argument(
        "--workers", type=int, default=2, help="Parallel workers (default 2)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=5, help="Findings per LLM call (default 5)"
    )
    parser.add_argument(
        "--save-every", type=int, default=4,
        help="Save cache after every N completed batches (default 4)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Process at most N findings then stop (default 0 = no limit)",
    )
    args = parser.parse_args()

    # Config
    base_url1 = os.environ.get("LLM_BASE_URL", "")
    base_url2 = os.environ.get("LLM2_BASE_URL", "") or base_url1
    model = os.environ.get("LLM_MODEL_NAME", "google/gemini-3-flash-preview")
    key1 = os.environ.get("LLM_VERTEX_AI_KEY_FILE", "")
    key2 = os.environ.get("LLM2_VERTEX_AI_KEY_FILE", "")

    if not base_url1:
        log.error("LLM_BASE_URL not set")
        sys.exit(1)
    if not key1:
        log.error("LLM_VERTEX_AI_KEY_FILE not set")
        sys.exit(1)

    log.info(f"model={model}, workers={args.workers}, batch_size={args.batch_size}")
    log.info(f"RPM limit={_RPM_LIMIT}, submit_delay={_SUBMIT_DELAY}s")
    log.info(f"endpoint1={base_url1}")
    log.info(f"endpoint2={base_url2}")

    # Load work queue
    wq_path = SCRIPT_DIR / "work_queue.json"
    if not wq_path.exists():
        log.error(f"work_queue.json not found: {wq_path}")
        sys.exit(1)
    all_findings = json.loads(wq_path.read_text())["findings"]
    log.info(f"work_queue: {len(all_findings)} total findings")

    # Load cache
    sys.path.insert(0, str(SCRIPT_DIR))
    from cache_writer import CacheWriter

    cw = CacheWriter()
    # Exclude "failed" entries so they get retried
    done_slugs = {f["slug"] for f in cw._cache["findings"] if f.get("status") != "failed"}
    failed_count = cw.processed_count - len(done_slugs)
    log.info(f"cache: {cw.processed_count}/{len(all_findings)} total | {len(done_slugs)} done | {failed_count} failed (will retry)")

    remaining = [f for f in all_findings if f["slug"] not in done_slugs]
    log.info(f"remaining: {len(remaining)} findings")
    if args.limit > 0:
        remaining = remaining[: args.limit]
        log.info(f"--limit {args.limit}: trimmed to {len(remaining)} findings")

    if not remaining:
        log.info("All findings already processed.")
        return

    batches = [remaining[i:i+args.batch_size] for i in range(0, len(remaining), args.batch_size)]

    if args.dry_run:
        est = len(batches) / _RPM_LIMIT
        log.info(f"DRY RUN: {len(remaining)} findings → {len(batches)} batches, {args.workers} workers")
        log.info(f"Rough estimate: ~{est:.0f} minutes at {_RPM_LIMIT} RPM")
        return

    # Build clients — each worker uses its own key file + endpoint
    worker_configs = [(key1, base_url1)]
    if args.workers >= 2:
        if key2 and os.path.exists(key2):
            worker_configs.append((key2, base_url2))
        else:
            log.warning("LLM2_VERTEX_AI_KEY_FILE not found; worker 2 shares worker 1 config")
            worker_configs.append((key1, base_url1))

    clients = []
    for i, (kf, url) in enumerate(worker_configs[: args.workers]):
        if not os.path.exists(kf):
            log.error(f"Key file not found: {kf}")
            sys.exit(1)
        log.info(f"Worker {i+1}: key={kf} endpoint={url}")
        clients.append(_build_vertex_client(kf, url))

    n_clients = len(clients)

    def _worker_fn(batch_idx: int, batch: list) -> tuple[int, list]:
        worker_id = (batch_idx % n_clients) + 1
        client = clients[batch_idx % n_clients]
        return batch_idx, process_batch(client, model, batch, worker_id, batch_idx)

    total_all = len(all_findings)
    total_done = len(done_slugs)
    pending: list = []
    batches_done = 0

    log.info(f"Launching {len(batches)} batches across {args.workers} workers…")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(_worker_fn, i, b): i for i, b in enumerate(batches)}
        for future in as_completed(futures):
            batch_idx = futures[future]
            try:
                _, results = future.result()
                pending.extend(results)
                total_done += len(results)
                batches_done += 1
                pct = total_done / total_all * 100
                log.info(f"[PROGRESS] {total_done}/{total_all} ({pct:.1f}%) — batch {batch_idx+1}/{len(batches)}")
                if batches_done % args.save_every == 0:
                    cw.append_and_save(pending[:])
                    pending.clear()
            except Exception as exc:
                log.error(f"Batch {batch_idx+1} raised: {exc}", exc_info=True)

    # Final flush
    if pending:
        cw.append_and_save(pending)

    log.info(f"COMPLETE. {cw.processed_count}/{total_all} processed.")
    log.info(cw.summary())


if __name__ == "__main__":
    main()
