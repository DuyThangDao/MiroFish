"""
Query RAG và build hist_inv_cache + hist_inv_stmts cho một danh sách functions cụ thể.
Dùng khi muốn test/rebuild cho GT functions mà không chạy full benchmark.

Usage:
  cd backend && source .venv/bin/activate
  python scripts/build_hist_for_fns.py \
      --contest 35 \
      --contest-dir /home/thangdd/repos/web3bugs/contracts/35
"""
import argparse, hashlib, json, os, re, sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

parser = argparse.ArgumentParser()
parser.add_argument("--contest",     default="35")
parser.add_argument("--contest-dir", default="/home/thangdd/repos/web3bugs/contracts/35")
args = parser.parse_args()

CACHE_DIR   = Path(f"../benchmark/web3bugs/agent-redesign/{args.contest}")
HIST_CACHE  = CACHE_DIR / "hist_inv_cache.json"
STMTS_CACHE = CACHE_DIR / "hist_inv_stmts.json"
CONTEST_DIR = Path(args.contest_dir)

# Functions cần build
TARGETS = [
    ("ConcentratedLiquidityPool",     "burn"),
    ("ConcentratedLiquidityPosition", "burn"),
    ("ConcentratedLiquidityPool",     "initialize"),
    ("ConcentratedLiquidityPool",     "rangeFeeGrowth"),
]

# ── 1. Load source files ───────────────────────────────────────────────────────
def extract_fn_body(sol_text: str, fn_name: str) -> str:
    # Try named function first, then fallback to constructor for "initialize"
    patterns = [re.compile(
        r'function\s+' + re.escape(fn_name) + r'\s*\([^)]*\)[^{]*\{', re.DOTALL
    )]
    if fn_name in ("initialize", "constructor"):
        patterns.append(re.compile(r'\bconstructor\s*\([^)]*\)[^{]*\{', re.DOTALL))

    for pattern in patterns:
        m = pattern.search(sol_text)
        if not m:
            continue
        start = m.start()
        depth, i = 0, start
        while i < len(sol_text):
            if sol_text[i] == '{':
                depth += 1
            elif sol_text[i] == '}':
                depth -= 1
                if depth == 0:
                    return sol_text[start:i+1]
            i += 1
        return sol_text[start:]
    return ""

sol_index: dict[str, str] = {}  # contract_name → sol_text
for sol_path in CONTEST_DIR.rglob("*.sol"):
    try:
        text = sol_path.read_text(errors='replace')
        for m in re.finditer(r'contract\s+(\w+)', text):
            name = m.group(1)
            if name not in sol_index:
                sol_index[name] = text
    except Exception:
        pass

print(f"Indexed {len(sol_index)} contracts from {CONTEST_DIR}")

# ── 2. Load services ───────────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv(Path("../.env"))

from app.services.contract_kg_builder import ContractKGBuilder
from app.services.contract_hist_inv_cache import HistInvCache, HistInvStmtsCache
from app.services.cyber_session_orchestrator import _get_rag_retriever

hist_cache  = HistInvCache(str(HIST_CACHE))
stmts_cache = HistInvStmtsCache(HistInvStmtsCache.stmts_path_from_hist_cache_path(str(HIST_CACHE)))

# LLM client
from app.utils.llm_client import LLMClient
client = LLMClient()

retriever = _get_rag_retriever()
SCORE_THRESHOLD = 0.65  # _SCORE_INJECT_THRESHOLD_INV

print(f"\nProcessing {len(TARGETS)} functions...\n")

for contract_name, fn_name in TARGETS:
    print(f"{'='*60}")
    print(f"[{contract_name}::{fn_name}]")

    # Find fn body
    sol_text = sol_index.get(contract_name, "")
    fn_body  = extract_fn_body(sol_text, fn_name) if sol_text else ""
    if not fn_body:
        print(f"  [WARN] fn_body not found — skipping")
        continue
    print(f"  fn_body: {len(fn_body)} chars")

    # Generate queries (dual-track)
    op_queries = ContractKGBuilder._generate_operation_queries(fn_name, fn_body, llm_client=client)
    st_queries = ContractKGBuilder._generate_structural_queries(fn_name, fn_body, llm_client=client)
    print(f"  OP queries ({len(op_queries)}): {op_queries[:2]}")
    print(f"  ST queries ({len(st_queries)}): {st_queries[:2]}")

    # Query RAG → collect annotations
    seen_ann: set = set()
    all_candidates = []

    def collect_track(queries, cap):
        result = []
        for q in queries:
            if len(result) >= cap:
                break
            if not q.strip():
                continue
            try:
                docs = retriever.query(q, n_results=3)
                for d in (docs or []):
                    all_candidates.append({
                        "query": q[:80],
                        "title": d['title'][:80],
                        "score": round(d['score'], 3),
                        "firm":  d.get('firm',''),
                        "passed": d['score'] >= SCORE_THRESHOLD,
                    })
                    if d['score'] < SCORE_THRESHOLD:
                        continue
                    ann = ContractKGBuilder._make_hist_annotation(d)
                    if ann not in seen_ann:
                        seen_ann.add(ann)
                        result.append(ann)
                        break
            except Exception as e:
                print(f"  [ERR] query failed: {e}")
        return result

    OP_CAP, ST_CAP = 6, 4
    op_anns = collect_track(op_queries, OP_CAP)
    st_anns = collect_track(st_queries, ST_CAP)
    inv_texts = op_anns + st_anns

    # Show top candidates
    print(f"  Top RAG hits:")
    for c in sorted(all_candidates, key=lambda x: -x['score'])[:6]:
        marker = "✅" if c['passed'] else "  "
        firm_tag = " [self-crafted]" if c['firm'] == 'self-crafted' else ""
        print(f"    {marker} {c['score']:.3f} | {c['title'][:60]}{firm_tag}")

    print(f"  Annotations: {len(inv_texts)} → {[a[:60] for a in inv_texts]}")

    # Save to hist_inv_cache
    cache_key   = hashlib.sha256(f"{contract_name}::{fn_name}".encode()).hexdigest()[:16]
    queries_all = op_queries + st_queries
    queries_str = "; ".join(queries_all[:5])
    best_score  = max((c['score'] for c in all_candidates), default=0.0)
    combined    = "\n".join(inv_texts)

    hist_cache.set(cache_key, contract_name, fn_name, queries_str, combined, "", best_score, "")
    print(f"  ✓ hist_inv_cache saved (key={cache_key})")

    # Generate hist_inv stmt
    if not inv_texts:
        print(f"  [SKIP] no inv_texts — skip stmt generation")
        continue

    inv_text_block = "\n".join(f"- {a}" for a in inv_texts)
    hist_inv = ContractKGBuilder._generate_hist_inv(
        fn_name=fn_name,
        fn_body=fn_body,
        inv_text=inv_text_block,
        llm_client=client,
    )
    print(f"  hist_inv: {hist_inv[:120]}")

    stmts_cache.set(cache_key, contract_name, fn_name, hist_inv)
    print(f"  ✓ hist_inv_stmts saved\n")

hist_cache.save()
stmts_cache.save()
print(f"\nSaved: {HIST_CACHE}")
print(f"Saved: {STMTS_CACHE}")
print(f"\n{'='*60}")
print("Done.")
