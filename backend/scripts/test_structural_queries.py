"""
Test: structural property queries vs operation queries cho HIST-INV.

Với mỗi target function:
1. Extract function body từ source
2. LLM generate operation queries (current approach)
3. LLM generate structural property queries (new approach)
4. Query RAG với cả hai
5. So sánh scores và relevance
"""
import os, sys, json, re, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scripts'))

import pysqlite3
sys.modules['sqlite3'] = pysqlite3

os.environ.setdefault(
    'GOOGLE_APPLICATION_CREDENTIALS',
    '/home/thangdd/repos/MiroFish/vertex-ai-2.json'
)

from scripts.rag.rag_retriever import SolodirRetriever
from app.utils.llm_client import LLMClient

# ── Target functions: contest 42 (missed bugs) + contest 35 (sample) ──────────
_C35 = "/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/pool/concentrated/ConcentratedLiquidityPool.sol"
_C42_VAULT   = "/home/thangdd/repos/web3bugs/contracts/42/projects/mochi-core/contracts/vault/MochiVault.sol"
_C42_PROFILE = "/home/thangdd/repos/web3bugs/contracts/42/projects/mochi-core/contracts/profile/MochiProfileV0.sol"
_C42_FEE     = "/home/thangdd/repos/web3bugs/contracts/42/projects/mochi-core/contracts/feePool/FeePoolV0.sol"

TARGETS = [
    # contest 42 — currently missed
    {
        "contest": 42, "h_id": "H-04", "contract": "MochiProfileV0", "fn": "registerAsset",
        "file": _C42_PROFILE,
        "expected": "registerAsset() can overwrite _assetClass value",
    },
    {
        "contest": 42, "h_id": "H-07", "contract": "MochiVault", "fn": "liquidate",
        "file": _C42_VAULT,
        "expected": "Liquidation will never work with non-zero discounts",
    },
    {
        "contest": 42, "h_id": "H-08", "contract": "MochiVault", "fn": "deposit",
        "file": _C42_VAULT,
        "expected": "Anyone can extend withdraw wait period by depositing zero collateral",
    },
    # contest 42 — currently found (baseline validation)
    {
        "contest": 42, "h_id": "H-12", "contract": "FeePoolV0", "fn": "distributeMochi",
        "file": _C42_FEE,
        "expected": "feePool is vulnerable to sandwich attack",
    },
    # contest 35 — sample
    {
        "contest": 35, "h_id": "H-01", "contract": "ConcentratedLiquidityPool", "fn": "burn",
        "file": _C35,
        "expected": "Unsafe cast in ConcentratedLiquidityPool.burn leads to attack",
    },
    {
        "contest": 35, "h_id": "H-09", "contract": "ConcentratedLiquidityPool", "fn": "rangeFeeGrowth",
        "file": _C35,
        "expected": "rangeFeeGrowth underflow causes pool to become permanently broken",
    },
    {
        "contest": 35, "h_id": "H-15", "contract": "ConcentratedLiquidityPool", "fn": "initialize",
        "file": _C35,
        "expected": "initialPrice not validated against sqrtPriceLimits",
    },
]

SCORE_THRESHOLD = 0.65

# ── Helpers ───────────────────────────────────────────────────────────────────

def extract_fn_body(filepath: str, fn_name: str) -> str:
    """Extract function body from Solidity file."""
    try:
        src = open(filepath).read()
    except Exception as e:
        return f"<file error: {e}>"

    # Find function declaration
    pattern = re.compile(
        r'function\s+' + re.escape(fn_name) + r'\s*\(',
        re.MULTILINE
    )
    m = pattern.search(src)
    if not m:
        return f"<function {fn_name} not found>"

    start = m.start()
    # Find matching brace
    depth = 0
    i = start
    while i < len(src):
        if src[i] == '{':
            depth += 1
        elif src[i] == '}':
            depth -= 1
            if depth == 0:
                return src[start:i+1]
        i += 1
    return src[start:start+3000]


LLM_DELAY = 4   # seconds between LLM calls to avoid 429
LLM_MAX_TOKENS = 8192  # thinking model cần nhiều tokens


def _llm_call(client, prompt: str) -> list[str]:
    """Call LLM, return non-empty lines. Retries once on empty."""
    for attempt in range(2):
        try:
            raw = client.chat(
                [{"role": "user", "content": prompt}],
                temperature=0, max_tokens=LLM_MAX_TOKENS
            ).strip()
            if raw:
                lines = [ln.strip().lstrip('0123456789.-) ').strip()
                         for ln in raw.split('\n') if ln.strip()]
                if lines:
                    return lines
            if attempt == 0:
                print(f"  [LLM empty, retrying after {LLM_DELAY}s...]")
                time.sleep(LLM_DELAY)
        except Exception as e:
            print(f"  [LLM error attempt {attempt}] {e}")
            time.sleep(LLM_DELAY)
    return []


def llm_operation_queries(fn_name: str, fn_body: str, client) -> list[str]:
    """Current approach: enumerate operations."""
    prompt = (
        "You are a Solidity code analyst.\n\n"
        f"Function: {fn_name}()\n"
        f"Body:\n{fn_body.strip()[:2000]}\n\n"
        "Generate search queries to find historical vulnerability findings "
        "related to this function.\n"
        "Each query must target a DIFFERENT operation or pattern in this function.\n"
        "List ALL distinct operations — do not merge or skip any.\n"
        "Focus on: type casts, arithmetic operations, state updates, unchecked blocks.\n"
        "Be specific about data types (uint128, int128, uint256) and operations.\n"
        "Do NOT describe business purpose. Do NOT add 'vulnerability' keyword.\n\n"
        "Format: one query per line, max 15 words each.\n"
        "Output ONLY the queries, nothing else."
    )
    time.sleep(LLM_DELAY)
    return _llm_call(client, prompt)


def llm_structural_queries(fn_name: str, fn_body: str, client) -> list[str]:
    """New approach: structural vulnerability properties."""
    prompt = (
        "You are a smart contract security auditor.\n\n"
        f"Function: {fn_name}()\n"
        f"Body:\n{fn_body.strip()[:2000]}\n\n"
        "Analyze this function for structural vulnerability properties.\n"
        "For each property you find, generate ONE search query describing the vulnerability pattern.\n\n"
        "Check for these structural properties:\n"
        "- State written to mapping/storage without reading/checking existing value first\n"
        "- State mutation that executes unconditionally regardless of input amount (zero, max)\n"
        "- Arithmetic where intermediate result can underflow/overflow given specific input range\n"
        "- Missing access control: state-changing function callable by anyone\n"
        "- External call made without slippage/deadline/minOutput protection\n"
        "- Token transfer followed by state update that may not match actual transfer amount\n"
        "- Loop or array access where index can exceed bounds\n\n"
        "For each property present: write a query describing WHAT GOES WRONG, "
        "using the language of audit report finding titles.\n"
        "Example: 'deposit zero tokens resets cooldown timer griefing'\n"
        "Example: 'swap without minimum output vulnerable to sandwich attack'\n"
        "Example: 'mapping value overwritten without checking prior existence'\n\n"
        "Format: one query per line, max 15 words each.\n"
        "Only output queries for properties you actually find in this code.\n"
        "Output ONLY the queries, nothing else."
    )
    time.sleep(LLM_DELAY)
    return _llm_call(client, prompt)


def query_rag(retriever, queries: list[str], n_results=3, delay=1.5) -> dict:
    """Run queries against RAG, return best hit per query."""
    best_score = 0.0
    best_title = ""
    all_results = []
    for q in queries[:12]:  # cap to avoid 429
        try:
            docs = retriever.query(q, n_results=n_results)
            for d in docs:
                all_results.append({"query": q, "score": d["score"], "title": d["title"]})
                if d["score"] > best_score:
                    best_score = d["score"]
                    best_title = d["title"]
            time.sleep(delay)
        except Exception as e:
            if "429" in str(e):
                print(f"  [429] waiting 8s...")
                time.sleep(8)
            else:
                print(f"  [RAG error] {e}")
    passed = [r for r in all_results if r["score"] >= SCORE_THRESHOLD]
    return {
        "best_score": best_score,
        "best_title": best_title,
        "passed": len(passed),
        "top_hits": sorted(all_results, key=lambda x: -x["score"])[:3],
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("Initializing LLM client and RAG retriever...")
    client = LLMClient()
    retriever = SolodirRetriever()
    print("Ready.\n")

    results = []
    for t in TARGETS:
        print(f"{'='*60}")
        print(f"{t['contest']}/{t['h_id']} — {t['contract']}.{t['fn']}")
        print(f"Expected bug: {t['expected']}")
        print()

        # Extract function body
        fn_body = extract_fn_body(t["file"], t["fn"])
        if fn_body.startswith("<"):
            print(f"  ERROR: {fn_body}")
            continue
        print(f"  Function body: {len(fn_body)} chars")

        # Generate operation queries
        print("  [1] Generating operation queries (current)...")
        op_queries = llm_operation_queries(t["fn"], fn_body, client)
        print(f"      → {len(op_queries)} queries: {op_queries[:3]}")

        # Generate structural queries
        print("  [2] Generating structural queries (new)...")
        struct_queries = llm_structural_queries(t["fn"], fn_body, client)
        print(f"      → {len(struct_queries)} queries: {struct_queries[:3]}")

        # RAG: operation queries
        print("  [3] RAG with operation queries...")
        op_rag = query_rag(retriever, op_queries)

        # RAG: structural queries
        print("  [4] RAG with structural queries...")
        struct_rag = query_rag(retriever, struct_queries)

        result = {
            "contest": t["contest"],
            "h_id": t["h_id"],
            "fn": t["fn"],
            "expected": t["expected"],
            "operation": {
                "queries": op_queries,
                "best_score": op_rag["best_score"],
                "best_title": op_rag["best_title"],
                "passed": op_rag["passed"],
                "top_hits": op_rag["top_hits"],
            },
            "structural": {
                "queries": struct_queries,
                "best_score": struct_rag["best_score"],
                "best_title": struct_rag["best_title"],
                "passed": struct_rag["passed"],
                "top_hits": struct_rag["top_hits"],
            },
        }
        results.append(result)

        # Print comparison
        op_mark = "✅" if op_rag["best_score"] >= SCORE_THRESHOLD else "❌"
        st_mark = "✅" if struct_rag["best_score"] >= SCORE_THRESHOLD else "❌"
        print()
        print(f"  OPERATION  {op_mark} best={op_rag['best_score']:.3f} passed={op_rag['passed']} | {op_rag['best_title'][:70]}")
        print(f"  STRUCTURAL {st_mark} best={struct_rag['best_score']:.3f} passed={struct_rag['passed']} | {struct_rag['best_title'][:70]}")
        print()

    # Save results
    out = "/tmp/structural_query_test_results.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to {out}")

    # Summary table
    print("\n" + "="*70)
    print("SUMMARY")
    print(f"{'Bug':<12} {'Operation':>24} {'Structural':>24}")
    print(f"{'':12} {'score':>8} {'pass':>6} {'score':>8} {'pass':>6}")
    print("-"*70)
    for r in results:
        op = r["operation"]
        st = r["structural"]
        op_mark = "✅" if op["best_score"] >= SCORE_THRESHOLD else "❌"
        st_mark = "✅" if st["best_score"] >= SCORE_THRESHOLD else "❌"
        win = "← NEW" if st["best_score"] > op["best_score"] else ""
        print(f"{r['contest']}/{r['h_id']:<8} {op_mark}{op['best_score']:>7.3f} {op['passed']:>6}   {st_mark}{st['best_score']:>7.3f} {st['passed']:>6}  {win}")


if __name__ == "__main__":
    main()
