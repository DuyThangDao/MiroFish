"""
Rebuild hist_inv_cache.json cho một contest, chỉ cho GT contracts.

Usage:
  python scripts/rebuild_hist_inv_cache.py \
    --contracts-dir /path/to/contracts \
    --gt-contracts ContractA ContractB ... \
    --cache-path /path/to/hist_inv_cache.json \
    [--score-threshold 0.65] [--top-k 6]

Không cần LLM — chỉ dùng embedding + ChromaDB (solodit_op).
Entries cũ vẫn được giữ (merge), chỉ overwrite nếu trùng key.
"""
import sys, os, re, json, argparse, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pysqlite3; sys.modules['sqlite3'] = pysqlite3

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))

from app.services.contract_hist_inv_cache import HistInvCache
from scripts.rag.rag_retriever import SolodirRetriever

# ─── CLI ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument('--contracts-dir', required=True)
parser.add_argument('--gt-contracts',  nargs='+', required=True)
parser.add_argument('--cache-path',    required=True)
parser.add_argument('--score-threshold', type=float, default=0.65)
parser.add_argument('--top-k',           type=int,   default=6)
args = parser.parse_args()

# ─── Load RAG retriever ───────────────────────────────────────────────────────
print("Loading RAG retriever (solodit_op)...", flush=True)
retriever = SolodirRetriever()
print("RAG retriever ready.", flush=True)

# ─── Load cache (merge mode) ──────────────────────────────────────────────────
cache = HistInvCache(args.cache_path)
print(f"Cache loaded: {len(cache)} existing entries", flush=True)

# ─── Solidity function extractor ─────────────────────────────────────────────
_FN_RE = re.compile(
    r'(?:^|\n)[ \t]*function\s+(\w+)\s*\(([^)]*)\)[^{;]*\{',
    re.MULTILINE,
)

def extract_functions(source: str) -> list[tuple[str, str]]:
    """Returns [(fn_name, body_excerpt)] — body_excerpt = first 300 chars."""
    results = []
    for m in _FN_RE.finditer(source):
        fn_name = m.group(1)
        start   = m.end()
        # Walk braces to find end of body
        depth, i = 1, start
        while i < len(source) and depth > 0:
            if source[i] == '{':   depth += 1
            elif source[i] == '}': depth -= 1
            i += 1
        body = source[start:i-1].strip()[:300]
        results.append((fn_name, body))
    return results

# ─── Find GT contract files ───────────────────────────────────────────────────
gt_set = set(args.gt_contracts)
sol_files: dict[str, str] = {}   # contract_name → source

for root, dirs, files in os.walk(args.contracts_dir):
    dirs[:] = [d for d in dirs if d not in {'node_modules', 'test', 'interfaces', 'mocks'}]
    for f in files:
        if not f.endswith('.sol'):
            continue
        contract_name = f[:-4]
        if contract_name not in gt_set:
            continue
        path = os.path.join(root, f)
        sol_files[contract_name] = open(path, errors='replace').read()

print(f"Found {len(sol_files)}/{len(gt_set)} GT contract files: {sorted(sol_files)}", flush=True)
missing = gt_set - set(sol_files)
if missing:
    print(f"WARNING: missing contracts: {missing}", flush=True)

# ─── Rebuild cache entries ────────────────────────────────────────────────────
total_new = total_skip = 0

for contract_name, source in sorted(sol_files.items()):
    fns = extract_functions(source)
    print(f"\n[{contract_name}] {len(fns)} functions", flush=True)

    for fn_name, body in fns:
        key = HistInvCache.entry_key(contract_name, fn_name)
        existing = cache.get(key)

        # Skip nếu đã có entry mới format (có slugs field)
        if existing and 'slugs' in existing:
            total_skip += 1
            continue

        # Query RAG
        query = f"{fn_name} {body[:200]}"
        try:
            results = retriever.query_op(query, n_results=args.top_k)
        except Exception as e:
            print(f"  [WARN] query_op failed for {fn_name}: {e}", flush=True)
            results = []

        # Filter by score threshold
        slugs = [r['slug'] for r in results if r.get('score', 0) >= args.score_threshold]
        best_score = max((r.get('score', 0) for r in results), default=0.0)

        # Build inv_text summary from slug titles
        inv_parts = [r.get('op_line', '') or r.get('slug', '') for r in results
                     if r.get('score', 0) >= args.score_threshold]
        inv_text = '\n'.join(inv_parts[:4])

        cache.set(
            key=key,
            contract_name=contract_name,
            fn_name=fn_name,
            rag_query=query[:200],
            inv_text=inv_text,
            rag_title='',
            rag_score=best_score,
            cg_entry='',
            slugs=slugs,
        )
        total_new += 1
        slug_str = f"{len(slugs)} slugs (best={best_score:.3f})"
        print(f"  {fn_name}: {slug_str}", flush=True)

    cache.save()
    print(f"  → saved checkpoint", flush=True)

print(f"\nDone. new={total_new}  skipped={total_skip}  total={len(cache)}", flush=True)
