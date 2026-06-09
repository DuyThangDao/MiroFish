#!/usr/bin/env python3
"""
fill_raw_code_static.py — Điền raw_code cho các finding đã có sections.code
nhưng chưa có raw_code (code được extract tĩnh từ inline code blocks).

Strategy: với mỗi finding có code_source=code_block,
  1. Lấy tất cả ```solidity``` blocks từ parents.json
  2. Normalize từng block → so khớp với sections.code đã có
  3. Block nào match → đó là raw_code

Usage:
    python scripts/rag/fill_raw_code_static.py [--dry-run] [--limit N]
"""
import sys, os, json, re, argparse
from pathlib import Path

SCRIPT_DIR  = Path(__file__).parent.resolve()
BACKEND     = SCRIPT_DIR.parent.parent
CACHE_PATH  = SCRIPT_DIR / "rag_sections_cache.json"
PARENTS_PATH = BACKEND / "data/rag_db/parents.json"

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
    "require","assert","emit","transfer","send","call","delegatecall","staticcall",
    "encode","decode","encodePacked","encodeWithSelector","encodeWithSignature","encodeCall",
    "seconds","minutes","hours","days","weeks","years",
    "wei","gwei","ether","szabo","finney","fixed","ufixed","var","byte",
}

def normalize_code(code: str) -> str:
    if not code: return code
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


def is_solidity(block: str) -> bool:
    """Heuristic: block chứa Solidity keywords, không phải Go/Python/JS."""
    if any(kw in block for kw in ("func ", "let mut ", "def ", "require.Equal", "println!")):
        return False
    sol_hits = sum(1 for kw in ("function ", "contract ", "mapping(", "uint256", "address",
                                "require(", "emit ", "modifier ", "pragma solidity", "internal",
                                "external", "public ", "private ", "returns (", "=> ") if kw in block)
    return sol_hits >= 1


def extract_sol_blocks(text: str) -> list[str]:
    """Extract Solidity code blocks from markdown — fenced and unfenced."""
    # Fenced blocks (```solidity, ```sol, plain ```)
    fenced = re.findall(r"```(?:solidity|sol)?\s*\n([\s\S]*?)```", text, re.IGNORECASE)
    blocks = [b.strip() for b in fenced if b.strip() and is_solidity(b)]

    # If nothing found, try any fenced block
    if not blocks:
        all_fenced = re.findall(r"```[^\n]*\n([\s\S]*?)```", text)
        blocks = [b.strip() for b in all_fenced if b.strip() and is_solidity(b)]

    return blocks


def similarity(a: str, b: str) -> float:
    """Token overlap similarity between two normalized strings."""
    ta = set(a.split())
    tb = set(b.split())
    if not ta or not tb: return 0.0
    return len(ta & tb) / max(len(ta), len(tb))


def find_best_block(raw_blocks: list[str], target_norm: str) -> str | None:
    """Find the raw block whose normalized form best matches target_norm."""
    best_raw  = None
    best_score = 0.0
    for raw in raw_blocks:
        norm = normalize_code(raw)
        if not norm: continue
        score = similarity(norm, target_norm)
        if score > best_score:
            best_score = score
            best_raw   = raw
    # Only accept if similarity is high enough
    return best_raw if best_score >= 0.35 else None


def save(cache: dict, path: Path) -> None:
    tmp = str(path) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit",   type=int, default=0)
    args = parser.parse_args()

    print("Loading cache and parents.json...")
    cache   = json.load(open(CACHE_PATH))
    parents = json.load(open(PARENTS_PATH))

    targets = [
        f for f in cache["findings"]
        if f["status"] == "done"
        and f["sections"].get("code")
        and not f["sections"].get("raw_code")
        and f.get("code_source") == "code_block"
    ]
    print(f"Targets (code_block, no raw_code): {len(targets)}")
    if args.limit:
        targets = targets[:args.limit]
        print(f"Limited to {args.limit}")

    n_filled = n_miss = n_no_parent = 0
    idx_map = {f["slug"]: i for i, f in enumerate(cache["findings"])}

    for f in targets:
        slug = f["slug"]
        content = parents.get(slug)
        if not content:
            n_no_parent += 1
            continue

        text = content if isinstance(content, str) else content.get("content", "")
        raw_blocks = extract_sol_blocks(text)

        if not raw_blocks:
            n_miss += 1
            continue

        target_norm = f["sections"]["code"]
        best = find_best_block(raw_blocks, target_norm)

        if not best:
            n_miss += 1
            continue

        if args.dry_run:
            print(f"[DRY] {slug[:55]} → {len(best.splitlines())} lines raw")
            continue

        entry = cache["findings"][idx_map[slug]]
        entry["sections"]["raw_code"] = best
        n_filled += 1

    if not args.dry_run:
        save(cache, CACHE_PATH)

    print(f"\nDone. filled={n_filled}  miss={n_miss}  no_parent={n_no_parent}")

    # Summary
    raw_cnt = sum(1 for f in cache["findings"] if f["sections"].get("raw_code"))
    print(f"Cache has_raw_code: {raw_cnt}")


if __name__ == "__main__":
    main()
