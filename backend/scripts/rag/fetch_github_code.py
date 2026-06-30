#!/usr/bin/env python3
"""
fetch_github_code.py — Fetch raw Solidity code from GitHub for done_no_code findings.

For each finding with github_links, fetches the relevant code snippet,
stores raw_code (original) and code (normalized) in rag_sections_cache.json.

Usage (from backend/ with venv activated):
    source .venv/bin/activate
    python scripts/rag/fetch_github_code.py [--dry-run] [--limit N] [--delay 1.5]
"""

import sys
import os
import json
import re
import time
import logging
import argparse
from pathlib import Path

import httpx

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
CACHE_PATH = SCRIPT_DIR / "rag_sections_cache.json"
WQ_PATH    = SCRIPT_DIR / "work_queue.json"
TODAY      = "2026-06-09"

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(SCRIPT_DIR / "fetch_github.log", mode="a"),
    ],
)
log = logging.getLogger("fetch_github")

# ── Canonical normalization (same as process_sections_gemini.py) ──────────────
SOL_KW = {
    "abstract","anonymous","assembly","break","catch","constant","constructor",
    "continue","contract","delete","do","else","enum","event","external",
    "fallback","false","final","for","from","function","if","immutable",
    "import","indexed","interface","internal","is","library","mapping",
    "modifier","new","override","payable","pragma","private","public",
    "pure","receive","return","returns","revert","storage","struct",
    "super","this","throw","true","try","type","unchecked","using",
    "view","virtual","while","calldata","memory",
    "address","bool","bytes","string","tuple","int","uint",
    "bytes1","bytes2","bytes4","bytes8","bytes16","bytes32",
    "uint8","uint16","uint32","uint64","uint96","uint128","uint160","uint256",
    "int8","int16","int32","int64","int128","int256",
    "abi","block","tx","msg","now","gasleft","blockhash",
    "keccak256","sha256","ripemd160","ecrecover","addmod","mulmod","selfdestruct",
    "require","assert","emit",
    "transfer","send","call","delegatecall","staticcall",
    "encode","decode","encodePacked","encodeWithSelector","encodeWithSignature","encodeCall",
    "seconds","minutes","hours","days","weeks","years",
    "wei","gwei","ether","szabo","finney",
    "fixed","ufixed","var","byte",
}

def normalize_code(code: str) -> str:
    if not code:
        return code
    code = re.sub(r"(?m)^\s*\d+\s*:\s*", "", code)
    code = re.sub(r"//[^\n]*", "", code)
    code = re.sub(r"/\*[\s\S]*?\*/", "", code)
    code = re.sub(
        r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
        lambda m: m.group(0) if m.group(0) in SOL_KW else "_VAR",
        code,
    )
    code = re.sub(r"[\s]+", " ", code)
    return code.strip()

# ── GitHub URL parsing ─────────────────────────────────────────────────────────
def parse_github_url(url: str):
    """
    Parse a github.com blob URL.
    Returns (raw_url, start_line, end_line) or None.
    start_line/end_line are 1-based ints. end_line may be None (open-ended).
    """
    url = url.rstrip("-").strip()
    m = re.match(
        r"https://github\.com/([^/]+/[^/]+)/blob/([^/?#]+)/([^#]+)(?:#(.*))?$",
        url,
    )
    if not m:
        return None
    owner_repo, ref, path, anchor = m.groups()
    raw_url = f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{path}"

    start_line = end_line = None
    if anchor:
        rm = re.match(r"L(\d+)(?:-L(\d+))?", anchor)
        if rm:
            start_line = int(rm.group(1))
            end_line   = int(rm.group(2)) if rm.group(2) else None

    return raw_url, start_line, end_line


def url_score(url: str) -> int:
    """Priority: full range > single line > truncated (#L178-) > no line."""
    if re.search(r"#L\d+-L\d+", url):  return 4
    if re.search(r"#L\d+$", url):      return 3
    if re.search(r"#L\d+-$", url):     return 2   # truncated #L178-
    if "/blob/" in url:                 return 1   # whole file (blob_no_line)
    return 0


def extract_lines(content: str, start: int, end: int | None,
                  context_before: int = 10,
                  context_after: int  = 20,
                  max_lines: int      = 50) -> str:
    """
    Extract a window of lines from raw file content.
    start/end are 1-based.
    - Known range (start..end): add context on both sides.
    - Single line or truncated: take start-context_before .. start+max_lines.
    """
    lines = content.splitlines()
    total = len(lines)

    if end and end > start:
        # full range known
        lo = max(0, start - 1 - context_before)
        hi = min(total, end + context_after)
    else:
        # single line or open-ended
        lo = max(0, start - 1 - context_before)
        hi = min(total, start - 1 + max_lines)

    return "\n".join(lines[lo:hi])


# ── HTTP fetch with in-process file cache ──────────────────────────────────────
_FILE_CACHE: dict[str, str | None] = {}   # raw_url → content (None = failed)

def fetch_raw(client: httpx.Client, raw_url: str,
              retries: int = 2, delay: float = 1.5) -> str | None:
    if raw_url in _FILE_CACHE:
        return _FILE_CACHE[raw_url]

    content = None
    for attempt in range(retries + 1):
        try:
            resp = client.get(raw_url, timeout=20, follow_redirects=True)
            if resp.status_code == 200:
                content = resp.text
                break
            if resp.status_code in (404, 403, 451):
                log.warning(f"HTTP {resp.status_code} (permanent): {raw_url}")
                break
            log.warning(f"HTTP {resp.status_code} attempt {attempt + 1}: {raw_url}")
        except Exception as e:
            log.warning(f"Fetch error attempt {attempt + 1}: {e}")
        if attempt < retries:
            time.sleep(delay)

    _FILE_CACHE[raw_url] = content
    return content


# ── Junk detection on fetched Solidity ────────────────────────────────────────
def is_junk(code: str) -> bool:
    if not code or len(code.strip()) < 20:
        return True
    lines = code.strip().splitlines()
    if any(ln.startswith(("@@ ", "+++ ", "--- ", "diff ")) for ln in lines[:5]):
        return True
    js_hits = sum(1 for p in ("() => {", "describe(", "it(", "expect(", "beforeEach") if p in code)
    if js_hits >= 3:
        return True
    if "-> " in code and any(kw in code for kw in ("fn ", "let mut ", "impl ")):
        return True
    return not any(re.search(r"\b" + kw + r"\b", code) for kw in SOL_KW)


# ── Save helper ───────────────────────────────────────────────────────────────
def save(cache: dict, path: Path) -> None:
    tmp = str(path) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ── Main ───────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch GitHub code for done_no_code findings")
    parser.add_argument("--dry-run",    action="store_true")
    parser.add_argument("--limit",      type=int,   default=0,    help="Max findings to process")
    parser.add_argument("--delay",      type=float, default=1.5,  help="Seconds between HTTP requests")
    parser.add_argument("--save-every", type=int,   default=20,   help="Save after N findings")
    parser.add_argument("--max-urls",   type=int,   default=2,    help="Max URLs to fetch per finding")
    args = parser.parse_args()

    cache  = json.load(open(CACHE_PATH))
    wq_map = {f["slug"]: f for f in json.load(open(WQ_PATH))["findings"]}

    fetch_errors = cache.setdefault("fetch_errors", {})
    skip_urls    = {v["url"] for v in fetch_errors.values()}

    # Build index map for in-place updates
    idx_map = {f["slug"]: i for i, f in enumerate(cache["findings"])}

    # Collect targets: done_no_code + has github_links
    targets: list[tuple[dict, list[tuple[int, str]]]] = []
    for f in cache["findings"]:
        if f["status"] != "done_no_code":
            continue
        wq_f  = wq_map.get(f["slug"], {})
        links = wq_f.get("github_links", [])
        if not links:
            continue
        scored = sorted(
            [(url_score(u), u) for u in links
             if url_score(u) > 0 and u not in skip_urls],
            reverse=True,
        )
        if scored:
            targets.append((f, scored))

    log.info(f"Found {len(targets)} findings with fetchable github_links")
    if args.limit:
        targets = targets[: args.limit]
        log.info(f"Limited to {args.limit}")

    if args.dry_run:
        for f, scored in targets[:8]:
            log.info(f"  {f['slug'][:55]}")
            for sc, url in scored[:2]:
                log.info(f"    score={sc}  {url}")
        return

    n_done = n_fail = n_junk = pending = 0

    with httpx.Client(headers={"User-Agent": "AuditEngine-RAG/1.0"}) as client:
        for finding, scored in targets:
            slug     = finding["slug"]
            snippets = []      # raw text per URL fetched
            errors   = []

            for _, url in scored[: args.max_urls]:
                parsed = parse_github_url(url)
                if not parsed:
                    errors.append(url)
                    continue

                raw_url, start_line, end_line = parsed
                content = fetch_raw(client, raw_url, delay=args.delay)
                time.sleep(args.delay)

                if content is None:
                    errors.append(url)
                    fetch_errors[slug] = {
                        "url": url, "reason": "http_error", "attempted_at": TODAY,
                    }
                    log.warning(f"  fetch failed: {url}")
                    continue

                if start_line:
                    snippet = extract_lines(content, start_line, end_line)
                else:
                    # blob_no_line (score=1): take first 60 lines
                    snippet = "\n".join(content.splitlines()[:60])

                if snippet.strip():
                    snippets.append(snippet)

            # ── Evaluate result ───────────────────────────────────────────────
            if not snippets:
                n_fail += 1
                log.warning(f"[FAIL] {slug[:55]}")
                continue

            raw_code = "\n\n".join(snippets)
            normalized = normalize_code(raw_code)

            if is_junk(normalized):
                n_junk += 1
                log.info(f"[JUNK] {slug[:55]}")
                continue

            # ── Update cache entry ────────────────────────────────────────────
            entry = cache["findings"][idx_map[slug]]
            entry["status"]              = "done"
            entry["sections"]["raw_code"] = raw_code
            entry["sections"]["code"]     = normalized
            n_done  += 1
            pending += 1

            log.info(
                f"[OK] {slug[:50]}  "
                f"raw={len(raw_code)}c  norm={len(normalized)}c"
            )

            if pending >= args.save_every:
                save(cache, CACHE_PATH)
                pending = 0
                log.info(
                    f"[SAVE] done={n_done} fail={n_fail} junk={n_junk} "
                    f"file_cache={len(_FILE_CACHE)}"
                )

    save(cache, CACHE_PATH)
    log.info(
        f"COMPLETE. done={n_done}  fail={n_fail}  junk={n_junk}  "
        f"files_cached={len(_FILE_CACHE)}"
    )


if __name__ == "__main__":
    main()
