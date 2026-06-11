"""
Quick single-group simulation: math_cast + evm_hardener, T1+T2 HIST-INV.
Dùng để đo tốc độ + kết quả của 1 group trước khi integrate vào pipeline.
"""
import sys, os, re, time, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pysqlite3; sys.modules['sqlite3'] = pysqlite3

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))

KEY_FILE = os.getenv('LLM_VERTEX_AI_KEY_FILE', '')
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = KEY_FILE
BASE_URL = os.getenv('LLM_BASE_URL', '')
MODEL    = os.getenv('LLM_MODEL_NAME', 'google/gemini-3-flash-preview')

import google.auth.transport.requests
from google.oauth2 import service_account
from openai import OpenAI

creds = service_account.Credentials.from_service_account_file(
    KEY_FILE, scopes=['https://www.googleapis.com/auth/cloud-platform'])
creds.refresh(google.auth.transport.requests.Request())
llm = OpenAI(api_key=creds.token, base_url=BASE_URL)

from app.services.contract_oasis_env import build_round1_prompt
from app.services.contract_profile_generator import ContractExpertProfileGenerator as Gen
from app.services.cyber_session_orchestrator import _annotate_source_with_hist_inv
from app.services.contract_hist_inv_cache import HistInvCache

def _strip(t): return re.sub(r'<think>.*?</think>', '', t or '', flags=re.DOTALL).strip()

# ─── Sources ──────────────────────────────────────────────────────────────────
BASE = '/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/pool/concentrated'
SRC_POOL = open(f'{BASE}/ConcentratedLiquidityPool.sol').read()

# ─── HIST-INV setup ──────────────────────────────────────────────────────────
_CACHE_PATH = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/hist_inv_cache.json'
_RAG_CACHE  = '/home/thangdd/repos/MiroFish/backend/scripts/rag/rag_sections_cache.json'

hc = HistInvCache(_CACHE_PATH)
matched_slugs = hc.get_matched_slugs()
rag_cache = json.load(open(_RAG_CACHE))
inv_lookup = {
    f['slug']: (f.get('sections') or {}).get('inv') or []
    for f in rag_cache.get('findings', [])
}

def build_inv_map():
    inv_map = {}
    for (contract, fn), slugs in matched_slugs.items():
        inv_lines = []
        for slug in slugs[:2]:
            inv_lines.extend((inv_lookup.get(slug) or [])[:2])
        if inv_lines:
            inv_map[(contract, fn)] = "\n".join(inv_lines[:3])
    return inv_map

INV_MAP = build_inv_map()

# ─── Function extractor ───────────────────────────────────────────────────────
def extract_contract_header(source):
    lines = source.split('\n')
    result, brace_depth, in_contract, skip_fn = [], 0, False, False
    for line in lines:
        stripped = line.strip()
        opens, closes = line.count('{'), line.count('}')
        if not in_contract:
            result.append(line)
            if re.match(r'^(contract|abstract contract|library)\s+\w+', stripped):
                in_contract = True
                brace_depth += opens - closes
            continue
        if re.match(r'(function|modifier|constructor|receive|fallback)\s*[\w(]', stripped):
            skip_fn = True
        if skip_fn:
            brace_depth += opens - closes
            if brace_depth <= 1:
                skip_fn = False
                brace_depth = max(brace_depth, 1)
            continue
        result.append(line)
        brace_depth += opens - closes
    return '\n'.join(result)

def extract_functions(source, fn_names):
    lines = source.split('\n')
    result, i = [], 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'^([ \t]*)(function|constructor)\s+(\w+)\s*[\(\{]', line)
        if m and m.group(3) in fn_names:
            fn_lines = [line]
            depth = line.count('{') - line.count('}')
            i += 1
            while i < len(lines) and (depth > 0 or fn_lines[-1].strip() == ''):
                fn_lines.append(lines[i])
                depth += lines[i].count('{') - lines[i].count('}')
                i += 1
            result.extend(fn_lines)
            result.append('')
        else:
            i += 1
    return '\n'.join(result)

def build_group_source(contract_name, source, fn_names):
    header = extract_contract_header(source)
    fns    = extract_functions(source, fn_names)
    return (
        f"// ─── {contract_name}.sol ─────────────────────────────────────────────────\n"
        + header.rstrip() + "\n"
        + "    // ... (other functions omitted)\n"
        + fns + "\n}"
    )

# ─── Profiles ────────────────────────────────────────────────────────────────
gen = Gen()
profiles_map = {p.agent_id: p for p in gen.generate_tier1_profiles(SRC_POOL)}

# ─── LLM ─────────────────────────────────────────────────────────────────────
def llm_call(prompt):
    for attempt in range(4):
        try:
            resp = llm.chat.completions.create(
                model=MODEL, temperature=0.3, max_tokens=4000,
                messages=[{"role": "user", "content": prompt}],
                extra_body={"google": {"thinking_config": {"thinking_budget": 0}}}
            )
            return _strip(resp.choices[0].message.content)
        except Exception as e:
            if '429' in str(e) or 'rate' in str(e).lower():
                wait = 25 * (attempt + 1)
                print(f"  [rate limit, wait {wait}s]", flush=True)
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("LLM failed after retries")

def clean_inv(t1):
    lines = [l for l in t1.splitlines() if re.match(r'\s*INV-\d+:', l)]
    return '\n'.join(lines) or t1[:400]

def detect(response, fn_names):
    return {
        fn: bool(re.search(rf'FUNCTION:\s*{re.escape(fn)}\b', response, re.IGNORECASE))
        for fn in fn_names
    }

# ─── Sources cho các groups ──────────────────────────────────────────────────
SRC_TICKS   = open('/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/libraries/concentratedPool/Ticks.sol').read()
SRC_MANAGER = open(f'{BASE}/ConcentratedLiquidityPoolManager.sol').read()

# ─── Groups ───────────────────────────────────────────────────────────────────
GROUPS = [
    {
        "name":      "clmm_semantic",
        "agent_id":  "clmm_specialist",
        "gt_fns":    ["rangeFeeGrowth"],
        "contracts": [("ConcentratedLiquidityPool", SRC_POOL), ("Ticks", SRC_TICKS)],
        "fn_names":  ["rangeFeeGrowth", "cross", "initialize", "insert"],
    },
    {
        "name":      "access_reward",
        "agent_id":  "access_escalator",
        "gt_fns":    ["reclaimIncentive", "claimReward"],
        "contracts": [("ConcentratedLiquidityPoolManager", SRC_MANAGER)],
        "fn_names":  ["reclaimIncentive", "claimReward", "subscribe", "addIncentive"],
    },
]

OUT_DIR = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/sim_single_group'
os.makedirs(OUT_DIR, exist_ok=True)

def run_group(grp):
    profile = profiles_map[grp['agent_id']]

    # Build source (multi-contract support)
    parts = []
    for cname, src in grp['contracts']:
        gs = build_group_source(cname, src, grp['fn_names'])
        parts.append(gs)
    group_source = '\n\n'.join(parts)

    ann_source  = _annotate_source_with_hist_inv(group_source, INV_MAP)
    src_lines   = ann_source.count('\n') + 1

    print(f"\n{'='*70}")
    print(f"Group: [{grp['name']}]  agent={grp['agent_id']}")
    print(f"GT functions: {grp['gt_fns']}")
    print(f"Source: {src_lines} lines  |  Model: {MODEL}")

    # T1
    print("[T1] Extracting invariants...", flush=True)
    time.sleep(2)
    t0 = time.time()
    t1_prompt = build_round1_prompt(profile, ann_source, invariant_only=True)
    print(f"  Prompt tokens ≈ {len(t1_prompt)//4}", flush=True)
    t1_resp = llm_call(t1_prompt)
    t1_time = time.time() - t0
    t1_clean = clean_inv(t1_resp)
    print(f"  Done: {t1_time:.1f}s  |  {t1_clean.count('INV-')} invariants")

    # T2
    print("[T2] Finding violations...", flush=True)
    time.sleep(2)
    t2_start = time.time()
    t2_prompt = build_round1_prompt(profile, ann_source, injected_invariants=t1_clean)
    print(f"  Prompt tokens ≈ {len(t2_prompt)//4}", flush=True)
    t2_resp = llm_call(t2_prompt)
    t2_time = time.time() - t2_start
    total_time = t1_time + t2_time

    detected      = detect(t2_resp, grp['gt_fns'])
    finding_count = t2_resp.count('FUNCTION:')
    tp            = sum(detected.values())

    print(f"  Done: {t2_time:.1f}s  |  {finding_count} FINDING blocks")
    print(f"\nRESULTS  time={total_time:.1f}s  TP={tp}/{len(grp['gt_fns'])}")
    for fn, hit in detected.items():
        print(f"  {'✅' if hit else '❌'} {fn}")

    # Save
    out_path = os.path.join(OUT_DIR, f"{grp['name']}_result.txt")
    with open(out_path, 'w') as f:
        f.write(f"Group: {grp['name']} / {grp['agent_id']}\n")
        f.write(f"T1={t1_time:.1f}s  T2={t2_time:.1f}s  Total={total_time:.1f}s\n")
        f.write(f"Detected: {detected}\n\n")
        f.write(f"{'='*60}\n=== SOURCE ({src_lines} lines) ===\n{ann_source}\n\n")
        f.write(f"{'='*60}\n=== T1 ===\n{t1_resp}\n\n")
        f.write(f"{'='*60}\n=== T2 ===\n{t2_resp}\n")
    print(f"Output: {out_path}")

    return {"group": grp['name'], "agent": grp['agent_id'],
            "time": round(total_time, 1), "tp": tp,
            "total_gt": len(grp['gt_fns']), "detected": detected}

# ─── Run all groups ───────────────────────────────────────────────────────────
print('\n' + '='*70)
print("Running 2 groups: clmm_semantic + access_reward")
print('='*70)

results = []
for grp in GROUPS:
    results.append(run_group(grp))
    time.sleep(3)

# ─── Summary ──────────────────────────────────────────────────────────────────
print('\n' + '='*70)
print("SUMMARY")
print('='*70)
total_tp  = sum(r['tp'] for r in results)
total_gt  = sum(r['total_gt'] for r in results)
for r in results:
    det = '  '.join(f"{'✅' if v else '❌'} {k}" for k, v in r['detected'].items())
    print(f"  {r['group']:<18} {r['time']:>6.1f}s  TP={r['tp']}/{r['total_gt']}  {det}")
print(f"\n  Total: TP={total_tp}/{total_gt}")
