"""
Test HIST-INV v4b: [TECH]/[LOGIC] prefix + adaptive threshold

Kiểm tra tính khả thi:
1. LLM có sinh ra [LOGIC] queries đúng cho logic bug functions không?
2. Với threshold 0.72, LOGIC queries có trả về findings hữu ích không?
3. So sánh noise v4 (0.65 uniform) vs v4b (0.65 TECH / 0.72 LOGIC)

Test functions: distributeMochi, registerAsset, deposit (contest 42 lost bugs)

Usage:
    cd /home/thangdd/repos/MiroFish/backend
    source .venv/bin/activate
    python3 scripts/test_hist_inv_v4b_prefix.py
"""
import sys, os, re, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Config
from app.utils.llm_client import LLMClient
from app.services.cyber_session_orchestrator import _get_rag_retriever

TECH_THRESHOLD  = 0.65
LOGIC_THRESHOLD = 0.72
TOP_K = 3

# ── LLM client ────────────────────────────────────────────────────────────────
def _build_client():
    key2 = getattr(Config, "LLM2_VERTEX_AI_KEY_FILE", None)
    url2 = getattr(Config, "LLM2_BASE_URL", None)
    rpm  = int(getattr(Config, "LLM2_GLOBAL_RPM_LIMIT", 18))
    if key2 and url2:
        return LLMClient(vertex_key_file=key2, base_url=url2,
                         model=getattr(Config, "LLM_MODEL_NAME", None),
                         rpm_slot_file="/tmp/mirofish_v4b_test.json",
                         rpm_limit=rpm)
    return LLMClient(rpm_slot_file="/tmp/mirofish_v4b_test.json",
                     rpm_limit=max(rpm // 2, 5))

# ── v4b prompt ────────────────────────────────────────────────────────────────
def _enumerate_queries_v4b(fn_name: str, fn_body: str, client) -> list[str]:
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
        print(f"  [WARN] enumerate failed: {e}")
        return [f"[TECH] {fn_name} vulnerability"]

# ── RAG với adaptive threshold ────────────────────────────────────────────────
def _rag_adaptive(queries: list[str], retriever) -> dict:
    """Return dict: tech_hits, logic_hits, all_candidates, noise_blocked"""
    tech_hits, logic_hits = [], []
    all_candidates = []
    seen_ann = set()
    noise_blocked = 0

    for q in queries:
        q_stripped = q.strip()
        if q_stripped.startswith('[LOGIC]'):
            qtype = 'LOGIC'
            threshold = LOGIC_THRESHOLD
            q_clean = q_stripped[7:].strip()
        elif q_stripped.startswith('[TECH]'):
            qtype = 'TECH'
            threshold = TECH_THRESHOLD
            q_clean = q_stripped[6:].strip()
        else:
            qtype = 'TECH'
            threshold = TECH_THRESHOLD
            q_clean = q_stripped

        if not q_clean:
            continue

        try:
            docs = retriever.query(q_clean, n_results=TOP_K)
            for d in (docs or []):
                score = round(d['score'], 3)
                passed_v4 = score >= TECH_THRESHOLD      # v4: uniform 0.65
                passed_v4b = score >= threshold           # v4b: adaptive
                all_candidates.append({
                    'qtype': qtype, 'query': q_clean[:60],
                    'title': d['title'][:65], 'score': score,
                    'passed_v4': passed_v4, 'passed_v4b': passed_v4b,
                })
                # Count noise blocked by higher threshold
                if passed_v4 and not passed_v4b:
                    noise_blocked += 1

                if not passed_v4b:
                    continue
                ann = f"[{d['title']}]"
                if ann not in seen_ann:
                    seen_ann.add(ann)
                    hit = {'title': d['title'][:65], 'score': score,
                           'query': q_clean[:55], 'impact': d.get('impact','')}
                    if qtype == 'LOGIC':
                        logic_hits.append(hit)
                    else:
                        tech_hits.append(hit)
                    break
        except Exception as e:
            print(f"  [WARN] RAG failed: {e}")

    return {
        'tech_hits': tech_hits,
        'logic_hits': logic_hits,
        'all_candidates': all_candidates,
        'noise_blocked': noise_blocked,
    }

# ── Load source ───────────────────────────────────────────────────────────────
def _load_source_42():
    ss_path = "../benchmark/web3bugs/agent-redesign/42/run-7/session_summary.txt"
    if not os.path.exists(ss_path):
        print(f"[ERROR] session_summary not found: {ss_path}")
        sys.exit(1)
    return open(ss_path).read()

def _extract_body(source: str, fn_name: str) -> str:
    fn_re = re.compile(rf'\bfunction\s+{re.escape(fn_name)}\s*\([^{{]*\{{', re.DOTALL)
    m = fn_re.search(source)
    if not m:
        return ""
    start = m.end(); depth = 1; pos = start
    while pos < len(source) and depth > 0:
        c = source[pos]
        if c == '{': depth += 1
        elif c == '}': depth -= 1
        pos += 1
    body = source[start:pos-1].strip()
    return body if len(body) <= 5000 else body[:400] + "\n...\n" + body[-800:]

# ── Test cases: contest 42 lost bugs ─────────────────────────────────────────
TEST_CASES = [
    ("H-02", "distributeMochi", "FeePoolV0",     "wrong state reset in _shareMochi"),
    ("H-04", "registerAsset",   "MochiProfileV0","missing existence check overwrite"),
    ("H-08", "deposit",         "MochiVault",    "zero-amount griefing timestamp reset"),
]

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("HIST-INV v4b TEST — [TECH]/[LOGIC] prefix + adaptive threshold")
    print(f"TECH threshold: {TECH_THRESHOLD}  |  LOGIC threshold: {LOGIC_THRESHOLD}")
    print("=" * 70)

    client   = _build_client()
    retriever = _get_rag_retriever()
    source   = _load_source_42()
    print(f"[setup] Source: {len(source):,} chars\n")

    results = []
    for h_id, fn_name, contract, note in TEST_CASES:
        print(f"{'─'*70}")
        print(f"[{h_id}] {fn_name}()  — {note}")

        fn_body = _extract_body(source, fn_name)
        print(f"  body: {len(fn_body)} chars")

        t0 = time.time()
        queries = _enumerate_queries_v4b(fn_name, fn_body, client)
        dt_enum = round(time.time() - t0, 1)

        tech_qs  = [q for q in queries if q.startswith('[TECH]')]
        logic_qs = [q for q in queries if q.startswith('[LOGIC]')]
        other_qs = [q for q in queries if not q.startswith('[TECH]') and not q.startswith('[LOGIC]')]

        print(f"\n  Queries ({len(queries)}, {dt_enum}s):")
        print(f"    [TECH]  ({len(tech_qs)}): {[q[6:].strip()[:50] for q in tech_qs[:3]]}")
        print(f"    [LOGIC] ({len(logic_qs)}): {[q[7:].strip()[:50] for q in logic_qs[:3]]}")
        if other_qs:
            print(f"    [no-prefix] ({len(other_qs)}): {[q[:50] for q in other_qs[:2]]}")

        t1 = time.time()
        rag = _rag_adaptive(queries, retriever)
        dt_rag = round(time.time() - t1, 1)

        print(f"\n  RAG results ({dt_rag}s) — noise blocked by higher LOGIC threshold: {rag['noise_blocked']}")

        print(f"\n  TECH hits (threshold={TECH_THRESHOLD}):")
        if rag['tech_hits']:
            for h in rag['tech_hits']:
                print(f"    ✦ {h['score']:.3f}  {h['title']}")
                print(f"          ← {h['query']}")
        else:
            print("    (none)")

        print(f"\n  LOGIC hits (threshold={LOGIC_THRESHOLD}):")
        if rag['logic_hits']:
            for h in rag['logic_hits']:
                print(f"    ✦ {h['score']:.3f}  {h['title']}")
                print(f"          ← {h['query']}")
        else:
            print(f"    (none — RAG không có findings đủ tốt cho logic queries)")

        # Show what v4 would have injected that v4b blocks
        blocked = [c for c in rag['all_candidates']
                   if c['passed_v4'] and not c['passed_v4b']]
        if blocked:
            print(f"\n  Noise blocked by v4b ({len(blocked)} findings):")
            for c in blocked[:4]:
                print(f"    ✗ {c['score']:.3f} [{c['qtype']}] {c['title']}")

        results.append({
            'h_id': h_id, 'fn': fn_name, 'note': note,
            'n_tech_queries': len(tech_qs),
            'n_logic_queries': len(logic_qs),
            'n_other_queries': len(other_qs),
            'tech_hits': len(rag['tech_hits']),
            'logic_hits': len(rag['logic_hits']),
            'noise_blocked': rag['noise_blocked'],
            'queries': queries,
        })
        print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    total_tech  = sum(r['n_tech_queries'] for r in results)
    total_logic = sum(r['n_logic_queries'] for r in results)
    total_other = sum(r['n_other_queries'] for r in results)
    total_blocked = sum(r['noise_blocked'] for r in results)
    print(f"  [TECH] queries:      {total_tech}")
    print(f"  [LOGIC] queries:     {total_logic}")
    print(f"  [no-prefix] queries: {total_other}  ← LLM không tuân format (sẽ treat as TECH)")
    print(f"  Noise blocked total: {total_blocked}")
    print()

    print(f"  {'Function':<20} {'TECH-Q':<8} {'LOGIC-Q':<9} {'TECH-hits':<11} {'LOGIC-hits':<12} {'Blocked'}")
    print(f"  {'-'*20} {'-'*8} {'-'*9} {'-'*11} {'-'*12} {'-'*7}")
    for r in results:
        print(f"  {r['fn']:<20} {r['n_tech_queries']:<8} {r['n_logic_queries']:<9} "
              f"{r['tech_hits']:<11} {r['logic_hits']:<12} {r['noise_blocked']}")

    out = "../benchmark/web3bugs/agent-redesign/42/hist_inv_v4b_test.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved: {out}")

if __name__ == "__main__":
    main()
