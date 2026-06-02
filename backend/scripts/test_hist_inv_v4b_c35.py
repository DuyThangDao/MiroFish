"""
Test HIST-INV v4b trên GT-relevant functions của contest 35.
So sánh v4 (uniform 0.65) vs v4b ([TECH]=0.65 / [LOGIC]=0.72).

Usage:
    cd /home/thangdd/repos/MiroFish/backend
    source .venv/bin/activate
    python3 scripts/test_hist_inv_v4b_c35.py
"""
import sys, os, re, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Config
from app.utils.llm_client import LLMClient
from app.services.contract_kg_builder import ContractKGBuilder
from app.services.cyber_session_orchestrator import _get_rag_retriever

TECH_THRESHOLD  = 0.65
LOGIC_THRESHOLD = 0.72
TOP_K = 3

def _build_client():
    key2 = getattr(Config, "LLM2_VERTEX_AI_KEY_FILE", None)
    url2 = getattr(Config, "LLM2_BASE_URL", None)
    rpm  = int(getattr(Config, "LLM2_GLOBAL_RPM_LIMIT", 18))
    if key2 and url2:
        return LLMClient(vertex_key_file=key2, base_url=url2,
                         model=getattr(Config, "LLM_MODEL_NAME", None),
                         rpm_slot_file="/tmp/mirofish_v4b_c35.json", rpm_limit=rpm)
    return LLMClient(rpm_slot_file="/tmp/mirofish_v4b_c35.json", rpm_limit=max(rpm//2, 5))

def _enumerate_v4b(fn_name: str, fn_body: str, client) -> list[str]:
    if not fn_body or not fn_body.strip():
        return [f"[TECH] {fn_name} vulnerability"]
    prompt = (
        "You are a Solidity code analyst.\n\n"
        f"Function: {fn_name}()\n"
        f"Body:\n{fn_body.strip()}\n\n"
        "Generate search queries to find historical vulnerability findings "
        "related to this function.\n"
        "Each query must target a DIFFERENT operation or pattern.\n"
        "List ALL distinct operations — do not merge or skip any.\n\n"
        "Categorize each query with a prefix:\n"
        "[TECH]: type casts, arithmetic operations, unchecked blocks, "
        "overflow/underflow, unsafe downcasting\n"
        "[LOGIC]: missing input validation (zero amounts, bounds, existence checks), "
        "access control (who can call, what they overwrite), "
        "state consistency (variables that should update together), "
        "unexpected side effects of sub-function calls\n\n"
        "Be specific: reference exact variable names and data types from the code.\n"
        "Do NOT describe business purpose. Do NOT add 'vulnerability' keyword.\n"
        "Format: [PREFIX] query text, one per line, max 15 words each.\n"
        "Output ONLY the queries, nothing else."
    )
    try:
        raw = client.chat([{"role": "user", "content": prompt}],
                          temperature=0, max_tokens=6144).strip()
        queries = []
        for line in raw.split('\n'):
            line = line.strip().lstrip('0123456789.-) ').strip()
            if line:
                queries.append(line)
        return queries if queries else [f"[TECH] {fn_name} vulnerability"]
    except Exception as e:
        print(f"  [WARN] {e}")
        return [f"[TECH] {fn_name} vulnerability"]

def _rag_adaptive(queries: list[str], retriever) -> dict:
    seen_v4, seen_v4b = set(), set()
    hits_v4, hits_v4b = [], []
    noise_blocked = 0
    all_cands = []

    for q in queries:
        q_stripped = q.strip()
        if q_stripped.startswith('[LOGIC]'):
            qtype = 'LOGIC'; threshold = LOGIC_THRESHOLD; q_clean = q_stripped[7:].strip()
        elif q_stripped.startswith('[TECH]'):
            qtype = 'TECH';  threshold = TECH_THRESHOLD;  q_clean = q_stripped[6:].strip()
        else:
            qtype = 'TECH';  threshold = TECH_THRESHOLD;  q_clean = q_stripped
        if not q_clean:
            continue
        try:
            docs = retriever.query(q_clean, n_results=TOP_K)
            for d in (docs or []):
                score = round(d['score'], 3)
                passed_v4  = score >= TECH_THRESHOLD
                passed_v4b = score >= threshold
                all_cands.append({'qtype': qtype, 'title': d['title'][:65],
                                  'score': score, 'passed_v4': passed_v4,
                                  'passed_v4b': passed_v4b, 'query': q_clean[:55]})
                if passed_v4 and not passed_v4b:
                    noise_blocked += 1

                # v4 hits (uniform 0.65)
                ann = f"[{d['title']}]"
                if passed_v4 and ann not in seen_v4:
                    seen_v4.add(ann); hits_v4.append({'title': d['title'][:65], 'score': score}); break

            for d in (docs or []):
                score = round(d['score'], 3)
                passed_v4b = score >= threshold
                ann = f"[{d['title']}]"
                if passed_v4b and ann not in seen_v4b:
                    seen_v4b.add(ann)
                    hits_v4b.append({'title': d['title'][:65], 'score': score,
                                     'qtype': qtype, 'query': q_clean[:55]})
                    break
        except Exception as e:
            print(f"  [WARN] RAG: {e}")

    return {'hits_v4': hits_v4, 'hits_v4b': hits_v4b,
            'noise_blocked': noise_blocked, 'all_cands': all_cands}

def _load_clp_source():
    ss = open("../benchmark/web3bugs/agent-redesign/35/run-61/session_summary.txt").read()
    markers = list(re.compile(r'^// ─── (.+?\.sol)(?:[^\n]*) ───', re.MULTILINE).finditer(ss))
    for i, mk in enumerate(markers):
        nm = mk.group(1)
        if ("ConcentratedLiquidityPool.sol" in nm
                and "Manager" not in nm and "Position" not in nm and "Helper" not in nm):
            end = markers[i+1].start() if i+1 < len(markers) else len(ss)
            return ss[mk.end():end]
    return ss

TEST_CASES = [
    ("H-01/10/13", "burn",                   "uint128→-int128 cast + reserve not decremented"),
    ("H-04/08/12", "mint",                   "overflow + boundary + secondsPerLiquidity"),
    ("H-05",       "_getAmountsForLiquidity","uint128 truncation"),
    ("H-09/14",    "rangeFeeGrowth",         "underflow revert"),
    ("H-11",       "cross",                  "feeGrowthGlobal swap"),
]

def main():
    print("=" * 70)
    print("HIST-INV v4b — contest 35 GT functions impact check")
    print(f"TECH={TECH_THRESHOLD}  LOGIC={LOGIC_THRESHOLD}")
    print("=" * 70)

    client   = _build_client()
    retriever = _get_rag_retriever()
    source   = _load_clp_source()
    print(f"[setup] CLP source: {len(source):,} chars\n")

    results = []
    for h_id, fn_name, note in TEST_CASES:
        print(f"{'─'*70}")
        print(f"[{h_id}] {fn_name}()  {note}")

        fn_body = ContractKGBuilder._extract_fn_body(source, fn_name)
        print(f"  body: {len(fn_body)} chars")

        t0 = time.time()
        queries = _enumerate_v4b(fn_name, fn_body, client)
        dt = round(time.time()-t0, 1)

        tech_qs  = [q for q in queries if q.startswith('[TECH]')]
        logic_qs = [q for q in queries if q.startswith('[LOGIC]')]
        other_qs = [q for q in queries if not q.startswith('[TECH]') and not q.startswith('[LOGIC]')]
        print(f"  Queries: {len(queries)} ({dt}s) — TECH={len(tech_qs)} LOGIC={len(logic_qs)} other={len(other_qs)}")

        rag = _rag_adaptive(queries, retriever)

        # Key: critical findings for each function
        critical = {
            'burn':                   ['Unsafe type-casting', 'partial transfers', 'storage updates'],
            'mint':                   ['Unsafe type-casting', 'overflow', 'second per liquidity'],
            '_getAmountsForLiquidity':['Unsafe type-casting'],
            'rangeFeeGrowth':         ['get_fee_growth_inside', 'underflow'],
            'cross':                  [],
        }
        crit_titles = critical.get(fn_name, [])

        print(f"\n  v4  hits ({len(rag['hits_v4'])}):  ", end="")
        v4_crit  = [h for h in rag['hits_v4']  if any(k.lower() in h['title'].lower() for k in crit_titles)]
        print(f"{len(v4_crit)} critical" if crit_titles else "N/A")
        for h in rag['hits_v4'][:4]:
            mark = "✅" if any(k.lower() in h['title'].lower() for k in crit_titles) else "  "
            print(f"    {mark} {h['score']:.3f}  {h['title']}")

        print(f"\n  v4b hits ({len(rag['hits_v4b'])}):  ", end="")
        v4b_crit = [h for h in rag['hits_v4b'] if any(k.lower() in h['title'].lower() for k in crit_titles)]
        print(f"{len(v4b_crit)} critical" if crit_titles else "N/A")
        for h in rag['hits_v4b'][:4]:
            mark = "✅" if any(k.lower() in h['title'].lower() for k in crit_titles) else "  "
            print(f"    {mark} {h['score']:.3f} [{h['qtype']}]  {h['title']}")

        if rag['noise_blocked']:
            print(f"\n  Noise blocked: {rag['noise_blocked']}")

        # Delta
        v4_set  = {h['title'] for h in rag['hits_v4']}
        v4b_set = {h['title'] for h in rag['hits_v4b']}
        lost    = v4_set - v4b_set
        gained  = v4b_set - v4_set
        if lost:
            print(f"  ⚠ Lost in v4b:   {list(lost)[:2]}")
        if gained:
            print(f"  ✦ Gained in v4b: {list(gained)[:2]}")

        results.append({
            'h_id': h_id, 'fn': fn_name,
            'n_tech': len(tech_qs), 'n_logic': len(logic_qs), 'n_other': len(other_qs),
            'v4_hits': len(rag['hits_v4']), 'v4b_hits': len(rag['hits_v4b']),
            'v4_crit': len(v4_crit), 'v4b_crit': len(v4b_crit),
            'noise_blocked': rag['noise_blocked'],
            'lost': list(lost), 'gained': list(gained),
        })
        print()

    print("=" * 70)
    print("SUMMARY — v4 vs v4b on contest 35")
    print("=" * 70)
    print(f"  {'Function':<25} {'TECH':<6} {'LOGIC':<7} {'v4 crit':<9} {'v4b crit':<10} {'Blocked':<8} {'Lost/Gained'}")
    print(f"  {'-'*25} {'-'*6} {'-'*7} {'-'*9} {'-'*10} {'-'*8} {'-'*15}")
    for r in results:
        delta = ""
        if r['lost']:   delta += f"-{len(r['lost'])}"
        if r['gained']: delta += f"+{len(r['gained'])}"
        print(f"  {r['fn']:<25} {r['n_tech']:<6} {r['n_logic']:<7} "
              f"{r['v4_crit']:<9} {r['v4b_crit']:<10} {r['noise_blocked']:<8} {delta or '='}")

    out = "../benchmark/web3bugs/agent-redesign/35/hist_inv_v4b_c35_test.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  Saved: {out}")

if __name__ == "__main__":
    main()
