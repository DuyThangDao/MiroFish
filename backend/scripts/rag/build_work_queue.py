"""
Build work_queue.json — pre-classify all 3366 findings for RAG migration.

Output: backend/scripts/rag/work_queue.json
Each entry: slug, firm, content_source, source_link, title, impact, protocol,
            code_source, github_links, rel_paths, text_excerpt (first 1800 chars),
            code_blocks (list of extracted solidity blocks, normalized),
            audit_snippet (lines around //@audit or @> markers)

Self-contained: Claude can process any entry without reading parents.json.

Run once:
  cd backend && source .venv/bin/activate
  python scripts/rag/build_work_queue.py
"""

__import__('pysqlite3')
import sys
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import json, re
from pathlib import Path

import chromadb

REPO_ROOT  = Path(__file__).resolve().parents[3]
BACKEND    = REPO_ROOT / "backend"
PARENTS    = BACKEND / "data/rag_db/parents.json"
CHROMA_DIR = BACKEND / "data/rag_db/chroma"
OUT        = Path(__file__).parent / "work_queue.json"

EXCERPT_LEN  = 1800
MAX_CODE_LEN = 800   # max chars per extracted code block stored in queue

# ── classification regexes ───────────────────────────────────────────────────
GITHUB_SOL_RE  = re.compile(r'https://github\.com/[^\s)\]]+\.sol(?:#L[\d-]+)?')
REL_SOL_RE     = re.compile(r'(?<!\S)((?:[\w.-]+/)*[\w.-]+\.sol#L[\d-]+)')
CODE_BLOCK_RE  = re.compile(r'```(?:solidity|sol)?\s*([\s\S]+?)```')
AUDIT_LINE_RE  = re.compile(r'//\s*@audit|(?<!\w)@>')
LINENUM_RE     = re.compile(r'(?m)^\s*\d{2,4}\s*:\s+\S')

# Inline Solidity in prose: indented lines starting with a Solidity type + assignment/call
# e.g. "    uint128 newTotalWithdrawn = uint128(\n  MathUtils.mulDiv(...))"
# Excludes PoC test functions (function test...) to avoid indexing test scaffolding
_SOL_TYPE_PAT = r'(?:uint(?:\d+)?|int(?:\d+)?|address|bool|bytes(?:\d+)?|mapping)'
SOLIDITY_INLINE_RE = re.compile(
    rf'(?m)^ {{3,}}{_SOL_TYPE_PAT}\b[ \t]+(?!_VAR)\w+[ \t]*[=({{]'
)

SOLIDITY_KEYWORDS = {
    "uint8","uint16","uint32","uint64","uint96","uint128","uint160","uint256","uint",
    "int8","int16","int32","int64","int96","int128","int160","int256","int",
    "address","bool","bytes","string","bytes1","bytes4","bytes8","bytes16","bytes20","bytes32",
    "mapping","if","else","for","while","do","return","break","continue",
    "unchecked","assembly","revert","require","assert","try","catch","emit","delete","new",
    "public","private","internal","external","view","pure","payable","override","virtual",
    "memory","storage","calldata","indexed","true","false","this","super","type",
    "msg","block","tx","abi","uint","int",
}


def normalize_code(code: str) -> str:
    return re.sub(
        r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
        lambda m: m.group(0) if m.group(0) in SOLIDITY_KEYWORDS else "_VAR",
        code,
    )


def extract_code_blocks(text: str) -> list[str]:
    """Extract and normalize solidity code blocks. Skip trivial (<2 lines or <30 chars)."""
    blocks = []
    for m in CODE_BLOCK_RE.finditer(text):
        raw = m.group(1).strip()
        if raw.count('\n') < 1 or len(raw) < 30:
            continue
        normalized = normalize_code(raw)
        blocks.append(normalized[:MAX_CODE_LEN])
    return blocks


def extract_audit_snippet(text: str, context: int = 4) -> str | None:
    """Extract lines around //@audit or @> markers (±context lines)."""
    lines = text.split('\n')
    marked = [i for i, ln in enumerate(lines) if AUDIT_LINE_RE.search(ln)]
    if not marked:
        return None
    # Collect unique line ranges
    collected, seen = [], set()
    for idx in marked:
        lo, hi = max(0, idx - context), min(len(lines), idx + context + 1)
        for j in range(lo, hi):
            if j not in seen:
                seen.add(j)
                collected.append(lines[j])
    snippet = '\n'.join(collected).strip()
    return normalize_code(snippet)[:MAX_CODE_LEN] if snippet else None


def extract_linenum_snippet(text: str) -> str | None:
    """Extract contiguous inline line-numbered code blocks."""
    lines = text.split('\n')
    groups, current = [], []
    for ln in lines:
        if LINENUM_RE.match(ln):
            current.append(ln)
        else:
            if current:
                groups.append('\n'.join(current))
            current = []
    if current:
        groups.append('\n'.join(current))
    if not groups:
        return None
    snippet = '\n'.join(groups).strip()
    return normalize_code(snippet)[:MAX_CODE_LEN]


def extract_inline_sol_snippet(text: str, context: int = 3) -> str | None:
    """Extract indented inline Solidity statements (no fences, no line numbers).
    Grabs the matching line + context lines below it."""
    lines = text.split('\n')
    collected, seen = [], set()
    for i, ln in enumerate(lines):
        if SOLIDITY_INLINE_RE.match(ln):
            lo = i
            hi = min(len(lines), i + context + 1)
            for j in range(lo, hi):
                if j not in seen:
                    seen.add(j)
                    collected.append(lines[j])
    if not collected:
        return None
    return normalize_code('\n'.join(collected).strip())[:MAX_CODE_LEN]


def classify(text: str) -> tuple[str | None, list[str], list[str], list[str], str | None]:
    """Return (code_source, github_links, rel_paths, code_blocks, audit_snippet)."""
    github_links  = GITHUB_SOL_RE.findall(text)
    rel_paths     = REL_SOL_RE.findall(text)
    code_blocks   = []
    audit_snippet = None

    if CODE_BLOCK_RE.search(text):
        code_blocks = extract_code_blocks(text)
        return "code_block", github_links, rel_paths, code_blocks, None

    if github_links:
        return "github_url", github_links, rel_paths, [], None

    if AUDIT_LINE_RE.search(text):
        audit_snippet = extract_audit_snippet(text)
        return "audit_marker", github_links, rel_paths, [], audit_snippet

    if LINENUM_RE.search(text):
        audit_snippet = extract_linenum_snippet(text)
        return "inline_linenum", github_links, rel_paths, [], audit_snippet

    if SOLIDITY_INLINE_RE.search(text):
        audit_snippet = extract_inline_sol_snippet(text)
        return "inline_sol", github_links, rel_paths, [], audit_snippet

    if rel_paths:
        return "rel_path", github_links, rel_paths, [], None

    return None, github_links, rel_paths, [], None


def main() -> None:
    print("Loading parents.json …")
    parents: dict[str, str] = json.loads(PARENTS.read_text())

    print("Connecting to ChromaDB …")
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    col    = client.get_collection("solodit_findings")

    print("Fetching chunk_index=0 metadata for all findings …")
    # Fetch in pages to avoid memory issues
    all_metas: list[dict] = []
    batch = 500
    offset = 0
    while True:
        res = col.get(
            where={"chunk_index": {"$eq": 0}},
            include=["metadatas"],
            limit=batch,
            offset=offset,
        )
        if not res["metadatas"]:
            break
        all_metas.extend(res["metadatas"])
        offset += batch
        print(f"  fetched {len(all_metas)} …", end="\r")

    print(f"\nTotal findings: {len(all_metas)}")

    queue = []
    missing = 0
    for i, meta in enumerate(all_metas):
        slug = meta.get("slug", "")
        text = parents.get(slug, "")
        if not text:
            missing += 1

        code_source, github_links, rel_paths, code_blocks, audit_snippet = classify(text)

        queue.append({
            "idx":            i,
            "slug":           slug,
            "firm":           meta.get("firm_name", ""),
            "content_source": meta.get("content_source", ""),
            "source_link":    meta.get("source_link", ""),
            "title":          meta.get("title", ""),
            "impact":         meta.get("impact", ""),
            "protocol":       meta.get("protocol", ""),
            "code_source":    code_source,
            "github_links":   github_links,
            "rel_paths":      rel_paths,
            # Pre-extracted code (normalized). Claude can use directly, no parents.json needed.
            "code_blocks":    code_blocks,     # list[str] — for code_block findings
            "audit_snippet":  audit_snippet,   # str|null  — for audit_marker / inline_linenum
            "text_excerpt":   text[:EXCERPT_LEN],
        })

        if (i + 1) % 500 == 0:
            print(f"  classified {i+1}/{len(all_metas)} …")

    # Summary stats
    from collections import Counter
    counts = Counter(e["code_source"] for e in queue)
    print("\n── Code source distribution ──")
    for k, v in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {k or 'None (prose_only)':<20} {v:>5}  ({v/len(queue)*100:.1f}%)")
    print(f"\nMissing in parents.json: {missing}")

    output = {
        "_meta": {
            "total": len(queue),
            "excerpt_len": EXCERPT_LEN,
            "code_source_counts": {str(k): v for k, v in counts.items()},
            "note": "Self-contained for RAG migration. code_blocks/audit_snippet pre-extracted and normalized.",
        },
        "findings": queue,
    }

    OUT.write_text(json.dumps(output, ensure_ascii=False, indent=2))
    print(f"\nWritten: {OUT}  ({OUT.stat().st_size / 1024 / 1024:.1f} MB)")


if __name__ == "__main__":
    main()
