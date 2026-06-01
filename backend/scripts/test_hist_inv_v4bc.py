"""
Test V4-B vs V4-C annotation quality trên GT-relevant functions của contest 35.

V4-B: enumerate ops → N RAG queries → top-1 → LLM extract invariant
V4-C: enumerate ops → N RAG queries → top-1 → title + impact field (0 LLM)

Usage:
    cd /home/thangdd/repos/MiroFish/backend
    source .venv/bin/activate
    python3 scripts/test_hist_inv_v4bc.py
"""
import sys, os, re, json, time
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Config
from app.utils.llm_client import LLMClient
from app.services.contract_kg_builder import ContractKGBuilder
from app.services.cyber_session_orchestrator import _get_rag_retriever

THRESHOLD = 0.65
TOP_K     = 3
TOP_N_OUT = 6   # cap injected annotations per function

# ── LLM clients ───────────────────────────────────────────────────────────────
def _build_clients():
    key2 = getattr(Config, "LLM2_VERTEX_AI_KEY_FILE", None)
    url2 = getattr(Config, "LLM2_BASE_URL", None)
    rpm  = int(getattr(Config, "LLM2_GLOBAL_RPM_LIMIT", 18))
    c2 = LLMClient(vertex_key_file=key2, base_url=url2,
                   model=getattr(Config, "LLM_MODEL_NAME", None),
                   rpm_slot_file="/tmp/mirofish_v4bc_1.json", rpm_limit=rpm
                   ) if key2 and url2 else None
    c1 = LLMClient(rpm_slot_file="/tmp/mirofish_v4bc_0.json",
                   rpm_limit=max(rpm // 2, 5))
    clients = [c for c in [c2, c1] if c is not None]
    print(f"[setup] {len(clients)} LLM client(s)")
    return clients

# ── Enumerate ALL operations (v4 core) ───────────────────────────────────────
def _enumerate_queries(fn_name: str, fn_body: str, client) -> list[str]:
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
        raw = client.chat([{"role": "user", "content": prompt}],
                          temperature=0, max_tokens=6144).strip()
        qs = [q.strip().lstrip("0123456789.-) ").strip()
              for q in raw.split("\n") if q.strip()]
        return qs if qs else [f"{fn_name} vulnerability"]
    except Exception as e:
        print(f"  [WARN] enumerate failed: {e}")
        return [f"{fn_name} vulnerability"]

# ── RAG: N queries → dedup → top-N_OUT ───────────────────────────────────────
def _rag_top(queries: list[str], retriever) -> list[dict]:
    seen: dict = {}
    for q in queries:
        if not q.strip():
            continue
        try:
            docs = retriever.query(q, n_results=TOP_K)
            for d in (docs or []):
                title = d["title"]
                score = d["score"]
                if score >= THRESHOLD:
                    if title not in seen or score > seen[title]["score"]:
                        seen[title] = {**d, "query": q}
        except Exception as e:
            print(f"  [WARN] RAG failed: {e}")
    return sorted(seen.values(), key=lambda x: -x["score"])[:TOP_N_OUT]

# ── V4-B: LLM extract from top-1 ─────────────────────────────────────────────
def _extract_top1(top_results: list[dict], client) -> str:
    if not top_results:
        return ""
    d = top_results[0]
    try:
        inv = ContractKGBuilder._extract_invariant_from_finding(
            d["title"], d.get("content", "")[:2000], llm_client=client
        )
        return inv.strip() if inv else ""
    except Exception as e:
        print(f"  [WARN] extract failed: {e}")
        return ""

# ── V4-C: title + impact (0 LLM) ─────────────────────────────────────────────
def _title_impact(top_results: list[dict]) -> list[str]:
    anns = []
    for d in top_results:
        title  = d["title"]
        impact = d.get("impact", "").strip().upper()
        ann = f"[{title}]"
        if impact and impact in ("HIGH", "MEDIUM", "CRITICAL"):
            ann += f" [{impact}]"
        anns.append(ann)
    return anns

# ── Source loading ─────────────────────────────────────────────────────────────
def _load_clp_source():
    ss = open("../benchmark/web3bugs/agent-redesign/35/run-60/session_summary.txt").read()
    markers = list(re.compile(r'^// ─── (.+?\.sol)(?:[^\n]*) ───', re.MULTILINE).finditer(ss))
    for i, mk in enumerate(markers):
        nm = mk.group(1)
        if ("ConcentratedLiquidityPool.sol" in nm
                and "Manager" not in nm
                and "Position" not in nm
                and "Helper" not in nm):
            end = markers[i+1].start() if i+1 < len(markers) else len(ss)
            return ss[mk.end():end]
    return ss  # fallback

def _extract_body_v4(source: str, fn_name: str) -> str:
    """v4 threshold=5000c (vs v3 1000c)."""
    fn_re = re.compile(rf'\bfunction\s+{re.escape(fn_name)}\s*\([^{{]*\{{', re.DOTALL)
    m = fn_re.search(source)
    if not m:
        return ""
    start = m.end(); depth = 1; pos = start
    while pos < len(source) and depth > 0:
        c = source[pos]
        if c == "{": depth += 1
        elif c == "}": depth -= 1
        pos += 1
    body = source[start:pos-1].strip()
    if len(body) <= 5000:
        return body
    return body[:400] + "\n...\n" + body[-800:]

# ── Test cases ─────────────────────────────────────────────────────────────────
TEST_CASES = [
    ("H-01",       "burn",                   "uint128→-int128 cast"),
    ("H-04/08/12", "mint",                   "overflow + boundary + secondsPerLiq"),
    ("H-05",       "_getAmountsForLiquidity","uint128 truncation"),
    ("H-09/14",    "rangeFeeGrowth",         "underflow revert"),
    ("H-10/13",    "burn",                   "reserve not decremented"),
]

# ── Process one case ───────────────────────────────────────────────────────────
def _process(case, client, retriever, source) -> dict:
    h_id, fn_name, note = case
    t0 = time.time()

    fn_body = _extract_body_v4(source, fn_name)

    # Enumerate
    t_enum = time.time()
    queries = _enumerate_queries(fn_name, fn_body, client)
    dt_enum = round(time.time() - t_enum, 1)

    # RAG
    t_rag = time.time()
    top = _rag_top(queries, retriever)
    dt_rag = round(time.time() - t_rag, 1)

    # V4-C: title + impact (0 LLM)
    ann_c = _title_impact(top)

    # V4-B: extract top-1 (1 LLM call)
    t_ext = time.time()
    inv_b = _extract_top1(top, client)
    dt_ext = round(time.time() - t_ext, 1)
    ann_b = [inv_b] if inv_b else (ann_c[:1] if ann_c else [])

    return {
        "h_id": h_id, "fn": fn_name, "note": note,
        "body_len": len(fn_body),
        "n_queries": len(queries), "dt_enum": dt_enum,
        "n_rag_hits": len(top),    "dt_rag": dt_rag,
        "dt_extract": dt_ext,
        "queries": queries,
        "top_results": [{"title": d["title"][:70], "score": round(d["score"],3),
                         "impact": d.get("impact",""), "query": d["query"][:55]}
                        for d in top],
        "ann_b": ann_b,
        "ann_c": ann_c,
        "total_s": round(time.time()-t0, 1),
    }

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("HIST-INV V4-B vs V4-C — annotation quality comparison")
    print("=" * 70)

    clients  = _build_clients()
    retriever = _get_rag_retriever()
    source   = _load_clp_source()
    print(f"[setup] CLP source: {len(source):,} chars")
    print(f"[setup] threshold={THRESHOLD}, top_k={TOP_K}, top_n_out={TOP_N_OUT}\n")

    def _run(args):
        idx, case = args
        return _process(case, clients[idx % len(clients)], retriever, source)

    results = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = {pool.submit(_run, (i, c)): i for i, c in enumerate(TEST_CASES)}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                print(f"[ERROR] {e}")

    results.sort(key=lambda r: next(
        (i for i, c in enumerate(TEST_CASES) if c[0] == r["h_id"] and c[1] == r["fn"]), 99))

    # ── Print ──────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    for r in results:
        print(f"\n{'─'*70}")
        print(f"[{r['h_id']}] {r['fn']}()  {r['note']}")
        print(f"  body={r['body_len']}c  queries={r['n_queries']}  "
              f"rag_hits={r['n_rag_hits']}  "
              f"time={r['total_s']}s (enum={r['dt_enum']}s rag={r['dt_rag']}s ext={r['dt_extract']}s)")

        if r["top_results"]:
            print(f"\n  RAG top results (threshold={THRESHOLD}):")
            for d in r["top_results"]:
                print(f"    ✦ {d['score']:.3f} [{d['impact']:<6}]  {d['title']}")
                print(f"          ← {d['query']}")

        print(f"\n  V4-B annotation (title=extract from top-1):")
        if r["ann_b"]:
            for a in r["ann_b"]:
                print(f"    ↳ HIST: {a}")
        else:
            print("    (none)")

        print(f"\n  V4-C annotation (title+impact, 0 LLM):")
        if r["ann_c"]:
            for a in r["ann_c"]:
                print(f"    ↳ HIST: {a}")
        else:
            print("    (none)")

    # ── Summary ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    total_queries = sum(r["n_queries"] for r in results)
    total_hits    = sum(r["n_rag_hits"] for r in results)
    total_s       = sum(r["total_s"] for r in results)
    print(f"  Functions tested  : {len(results)}")
    print(f"  Total queries gen : {total_queries}  (avg {total_queries/len(results):.1f}/fn)")
    print(f"  Total RAG hits    : {total_hits}  (avg {total_hits/len(results):.1f}/fn)")
    print(f"  Total wall-clock  : {total_s}s  (2 workers = ~{round(total_s/2)}s effective)")
    print(f"  V4-B extra LLM    : {len(results)} extract calls (1/fn)")
    print()

    print("  Annotation comparison:")
    print(f"  {'Function':<30} {'V4-B (extracted)':<50} {'V4-C (title+impact)'}")
    print(f"  {'-'*30} {'-'*50} {'-'*40}")
    for r in results:
        b = (r["ann_b"][0] if r["ann_b"] else "(none)")[:48]
        c = (r["ann_c"][0] if r["ann_c"] else "(none)")[:48]
        print(f"  {r['fn']+'()':30} {b:<50} {c}")

    # Save
    out = "../benchmark/web3bugs/agent-redesign/35/hist_inv_v4bc_test.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved: {out}")

if __name__ == "__main__":
    main()
