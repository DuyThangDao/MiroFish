"""
Test HIST-INV v4: Multi-operation query + title injection + 2 workers

So sánh v3 (1 desc → 1 query → extract inv) vs v4 (enumerate ops → N queries → title trực tiếp)
cho các GT-relevant functions của contest 35.

Usage:
    cd /home/thangdd/repos/MiroFish/backend
    source .venv/bin/activate
    python3 scripts/test_hist_inv_v4.py
"""
import sys, os, json, re, time
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Config
from app.utils.llm_client import LLMClient
from app.services.contract_kg_builder import ContractKGBuilder
from app.services.cyber_session_orchestrator import _get_rag_retriever

# ── Build 2 LLM clients (1 per Vertex key) ────────────────────────────────
def _build_llm_clients():
    """Build 2 LLM clients for 2 workers. LLM2 = erudite-flag key."""
    key2 = getattr(Config, "LLM2_VERTEX_AI_KEY_FILE", None)
    url2 = getattr(Config, "LLM2_BASE_URL", None)
    rpm = int(os.getenv("HIST_INV_RPM_LIMIT", str(getattr(Config, "LLM2_GLOBAL_RPM_LIMIT", 18))))

    client2 = LLMClient(
        vertex_key_file=key2, base_url=url2,
        model=getattr(Config, "LLM_MODEL_NAME", None),
        rpm_slot_file="/tmp/mirofish_hist_inv_v4_1.json",
        rpm_limit=rpm,
    ) if key2 and url2 else None

    client1 = LLMClient(
        rpm_slot_file="/tmp/mirofish_hist_inv_v4_0.json",
        rpm_limit=max(rpm // 2, 5),
    )
    clients = [c for c in [client2, client1] if c is not None]
    print(f"[setup] {len(clients)} LLM client(s) available for 2 workers")
    return clients

# ── V4 prompt: enumerate ALL operations ────────────────────────────────────
def _generate_fn_queries_v4(fn_name: str, fn_body: str, llm_client) -> list:
    """V4: 1 LLM call → list of operation-specific RAG queries."""
    if not fn_body or not fn_body.strip():
        return [f"{fn_name} vulnerability"]

    prompt = (
        "You are a Solidity code analyst.\n\n"
        f"Function: {fn_name}()\n"
        f"Body:\n{fn_body.strip()}\n\n"
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
    try:
        raw = llm_client.chat(
            [{"role": "user", "content": prompt}],
            temperature=0, max_tokens=256,
        ).strip()
        queries = [q.strip() for q in raw.split('\n') if q.strip()]
        return queries if queries else [f"{fn_name} vulnerability"]
    except Exception as e:
        print(f"  [WARN] LLM enumerate failed: {e}")
        return [f"{fn_name} vulnerability"]

# ── RAG query → top titles ──────────────────────────────────────────────────
def _query_rag_titles(queries: list, retriever, threshold: float = 0.65) -> list:
    """Run N RAG queries, dedup by title, return top-6 by score."""
    seen: dict = {}
    for q in queries:
        if not q.strip():
            continue
        try:
            docs = retriever.query(q, n_results=3)
            for d in (docs or []):
                title = d['title']
                score = d['score']
                if score >= threshold:
                    if title not in seen or score > seen[title]['score']:
                        seen[title] = {'score': score, 'query': q}
        except Exception as e:
            print(f"  [WARN] RAG query failed: {e}")

    # Sort by score, cap at 6
    results = sorted(seen.items(), key=lambda x: -x[1]['score'])[:6]
    return [{'title': t, 'score': v['score'], 'query': v['query']} for t, v in results]

# ── Test cases: GT-relevant functions ──────────────────────────────────────
TEST_CASES = [
    # (h_id, contract, fn_name, note)
    ("H-01",        "ConcentratedLiquidityPool", "burn",                    "uint128→-int128 cast"),
    ("H-04/08/12",  "ConcentratedLiquidityPool", "mint",                    "overflow + boundary + secondsPerLiquidity"),
    ("H-05",        "ConcentratedLiquidityPool", "_getAmountsForLiquidity", "uint128 truncation"),
    ("H-09/14",     "ConcentratedLiquidityPool", "rangeFeeGrowth",          "underflow revert"),
    ("H-11",        "Ticks",                     "cross",                   "fee var swap"),
    ("H-10/13",     "ConcentratedLiquidityPool", "burn",                    "reserve not decremented"),
]

# ── Load source code for contest 35 ────────────────────────────────────────
def _load_source():
    # Lấy từ run-60 session_summary (đã flatten source)
    ss_path = "../benchmark/web3bugs/agent-redesign/35/run-60/session_summary.txt"
    if not os.path.exists(ss_path):
        print(f"[ERROR] session_summary not found: {ss_path}")
        sys.exit(1)
    return open(ss_path).read()

# ── Process 1 test case ────────────────────────────────────────────────────
def _process_case(case: tuple, llm_client, retriever, source: str) -> dict:
    h_id, contract, fn_name, note = case
    t0 = time.time()

    # Extract function body
    fn_body = ContractKGBuilder._extract_fn_body(source, fn_name)

    # V3: single description → single query
    v3_desc = ContractKGBuilder._describe_function_body(fn_name, fn_body, llm_client=llm_client)
    v3_query = (v3_desc + " vulnerability smart contract") if v3_desc else f"{fn_name} vulnerability"
    v3_rag = []
    try:
        docs = retriever.query(v3_query, n_results=3)
        v3_rag = [{'title': d['title'][:60], 'score': round(d['score'], 3)}
                  for d in (docs or []) if d['score'] >= 0.65]
    except Exception:
        pass

    # V4: enumerate operations → N queries → titles
    v4_queries = _generate_fn_queries_v4(fn_name, fn_body, llm_client)
    v4_results = _query_rag_titles(v4_queries, retriever, threshold=0.65)

    elapsed = round(time.time() - t0, 1)
    return {
        "h_id": h_id,
        "fn": fn_name,
        "note": note,
        "body_len": len(fn_body),
        "elapsed": elapsed,
        "v3": {
            "description": v3_desc[:80] if v3_desc else "(none)",
            "query": v3_query[:80],
            "results": v3_rag,
        },
        "v4": {
            "queries": v4_queries,
            "results": v4_results,
        },
    }

# ── Main ────────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("HIST-INV v4 TEST — Multi-operation query + title injection + 2 workers")
    print("=" * 70)

    clients = _build_llm_clients()
    retriever = _get_rag_retriever()
    source = _load_source()

    print(f"[setup] RAG retriever: {retriever.__class__.__name__}")
    print(f"[setup] Source loaded: {len(source):,} chars")
    print(f"[setup] Test cases: {len(TEST_CASES)}")
    print()

    # 2 workers — assign client round-robin
    def _run_case(args):
        idx, case = args
        client = clients[idx % len(clients)]
        return _process_case(case, client, retriever, source)

    results = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = {pool.submit(_run_case, (i, c)): i for i, c in enumerate(TEST_CASES)}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                print(f"[ERROR] case failed: {e}")

    # Sort by original order
    order = {c[2]+c[0]: i for i, c in enumerate(TEST_CASES)}
    results.sort(key=lambda r: order.get(r['fn']+r['h_id'], 99))

    # ── Print results ──────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    for r in results:
        print(f"\n{'─'*70}")
        print(f"[{r['h_id']}] {r['fn']}()  ({r['note']})  body={r['body_len']}c  {r['elapsed']}s")

        print(f"\n  V3 (1 query):")
        print(f"    desc:  {r['v3']['description']}")
        print(f"    query: {r['v3']['query']}")
        if r['v3']['results']:
            for res in r['v3']['results']:
                print(f"    ✦ {res['score']:.3f}  {res['title']}")
        else:
            print(f"    (no results above threshold)")

        print(f"\n  V4 ({len(r['v4']['queries'])} queries):")
        for i, q in enumerate(r['v4']['queries']):
            print(f"    Q{i+1}: {q}")
        if r['v4']['results']:
            for res in r['v4']['results']:
                print(f"    ✦ {res['score']:.3f}  {res['title'][:65]}")
                print(f"          ← query: {res['query'][:60]}")
        else:
            print(f"    (no results above threshold)")

        # Delta: titles unique to v4
        v3_titles = {x['title'][:60] for x in r['v3']['results']}
        v4_titles = {x['title'][:60] for x in r['v4']['results']}
        new_in_v4 = v4_titles - v3_titles
        if new_in_v4:
            print(f"\n  NEW titles found only in v4:")
            for t in new_in_v4:
                print(f"    + {t}")

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    total_v3 = sum(len(r['v3']['results']) for r in results)
    total_v4 = sum(len(r['v4']['results']) for r in results)
    total_queries = sum(len(r['v4']['queries']) for r in results)
    print(f"  Total RAG titles found — v3: {total_v3}  v4: {total_v4}")
    print(f"  Total v4 queries generated: {total_queries} for {len(results)} functions")
    print(f"  Avg queries/fn: {total_queries/len(results):.1f}")

    # Save raw results
    out = "../benchmark/web3bugs/agent-redesign/35/hist_inv_v4_test.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  Raw results saved to: {out}")

if __name__ == "__main__":
    main()
