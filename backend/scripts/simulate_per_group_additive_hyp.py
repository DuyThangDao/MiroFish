"""
Per-Function-Group Simulation — Run 6: HIST-INV T1+T2 + Additive Hypothesis Section.

Khác với Run 4 (append gate "Before writing any FINDING"):
  - Section hypothesis được viết ADDITIVE, không dùng ordering gate
  - "After completing the above analysis, ALSO perform independent cross-check..."
  - Hai section chạy sequential, không tranh control flow

So sánh:
  Run 1 (hist_inv T1+T2)      : 4/5, ~58s, 6 calls
  Run 4 (hist_inv + hyp gate) : 2/5, 48.8s, 6 calls  ← conflict vì gate
  Run 5 (single_turn_hyp)     : 3/5,  35s, 3 calls
  Run 6 (hist_inv + additive) : ?/5,  ?s,  6 calls
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
SRC_POOL    = open(f'{BASE}/ConcentratedLiquidityPool.sol').read()
SRC_MANAGER = open(f'{BASE}/ConcentratedLiquidityPoolManager.sol').read()
SRC_TICKS   = open('/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/libraries/concentratedPool/Ticks.sol').read()

# ─── HIST-INV ────────────────────────────────────────────────────────────────

_CACHE_PATH = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/hist_inv_cache.json'
_RAG_CACHE  = '/home/thangdd/repos/MiroFish/backend/scripts/rag/rag_sections_cache.json'

hc = HistInvCache(_CACHE_PATH)
matched_slugs = hc.get_matched_slugs()
rag_cache = json.load(open(_RAG_CACHE))
inv_lookup = {
    f['slug']: (f.get('sections') or {}).get('inv') or []
    for f in rag_cache.get('findings', [])
}

def build_inv_map() -> dict:
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

def extract_contract_header(source: str) -> str:
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

def extract_functions(source: str, fn_names: list) -> str:
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

def build_group_source(contracts: list, fn_names: list) -> str:
    parts = []
    for contract_name, source in contracts:
        header = extract_contract_header(source)
        fns = extract_functions(source, fn_names)
        if fns.strip():
            parts.append(f"// ─── {contract_name}.sol ─────────────────────────────────────────────────")
            parts.append(header.rstrip())
            parts.append("    // ... (other functions omitted)")
            parts.append(fns)
            parts.append("}")
    return '\n'.join(parts)

# ─── Profiles ─────────────────────────────────────────────────────────────────

gen = Gen()
profiles_map = {p.agent_id: p for p in gen.generate_tier1_profiles(SRC_POOL)}

# ─── LLM ──────────────────────────────────────────────────────────────────────

def llm_call(prompt: str) -> str:
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
                print(f"    [rate {wait}s]", flush=True)
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("LLM failed")

def clean_inv(t1: str) -> str:
    lines = [l for l in t1.splitlines() if re.match(r'\s*INV-\d+:', l)]
    return '\n'.join(lines) or t1[:400]

def detect(response: str, fn_names: list) -> dict:
    return {
        fn: bool(re.search(rf'FUNCTION:\s*{re.escape(fn)}\b', response, re.IGNORECASE))
        for fn in fn_names
    }

# ─── Additive hypothesis block (không dùng gate) ─────────────────────────────
# Không nói "Before writing any FINDING" — chỉ nói "ALSO perform after"
# Hai section chạy sequential, không tranh control flow

ADDITIVE_HYP_BLOCK = (
    "\n\n=== ADDITIONAL INDEPENDENT CROSS-CHECK ===\n"
    "After completing all FINDING blocks above, ALSO perform the following independent pass:\n"
    "Re-read the source from scratch. For each function, reason purely from code evidence:\n"
    "  State the mechanism you suspect, cite the exact code observation.\n"
    "  Format: 'HYPOTHESIS: [mechanism] because [exact code line/pattern]'\n"
    "  Good: 'uint256 cast to uint128 in burn() — amount may exceed 2^128-1 if liquidity large'\n"
    "  Good: 'nearestTick read once in rangeFeeGrowth() — not updated if price crossed tick boundary'\n"
    "  Good: 'reclaimIncentive() validates rewardToken but not msg.sender == incentive.owner'\n"
    "If a hypothesis confirms a new vulnerability not already reported above, add a FINDING block.\n"
    "If already reported, skip (no duplicate).\n"
)

# ─── Groups ───────────────────────────────────────────────────────────────────

GROUPS = [
    {
        "name": "math_cast",
        "agent_id": "evm_hardener",
        "gt_fns": ["burn", "_getAmountsForLiquidity"],
        "contracts": [("ConcentratedLiquidityPool", SRC_POOL)],
        "fn_names": ["burn", "mint", "_getAmountsForLiquidity", "_updateSecondsPerLiquidity"],
    },
    {
        "name": "clmm_semantic",
        "agent_id": "clmm_specialist",
        "gt_fns": ["rangeFeeGrowth"],
        "contracts": [
            ("ConcentratedLiquidityPool", SRC_POOL),
            ("Ticks", SRC_TICKS),
        ],
        "fn_names": ["rangeFeeGrowth", "cross", "initialize", "insert"],
    },
    {
        "name": "access_reward",
        "agent_id": "access_escalator",
        "gt_fns": ["reclaimIncentive", "claimReward"],
        "contracts": [("ConcentratedLiquidityPoolManager", SRC_MANAGER)],
        "fn_names": ["reclaimIncentive", "claimReward", "subscribe", "addIncentive"],
    },
]

OUT_DIR = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/sim_per_group'
os.makedirs(OUT_DIR, exist_ok=True)

# ─── Main ─────────────────────────────────────────────────────────────────────

print('\n' + '='*75)
print('Run 6 — HIST-INV T1+T2 + Additive Hypothesis (no gate conflict)')
print('='*75)
print(f"{'Group':<16} {'Agent':<20} {'Lines':>6} {'Time':>7}  GT found")
print('─'*65)

summary = []

for grp in GROUPS:
    profile = profiles_map[grp['agent_id']]

    group_source = build_group_source(grp['contracts'], grp['fn_names'])
    ann_source   = _annotate_source_with_hist_inv(group_source, INV_MAP)
    src_lines    = ann_source.count('\n') + 1
    print(f"  [{grp['name']}] {src_lines} lines ...", flush=True)

    # Turn 1 — extract invariants only (same as Run 1)
    time.sleep(3)
    t0 = time.time()
    t1_prompt = build_round1_prompt(profile, ann_source, invariant_only=True)
    t1_resp = llm_call(t1_prompt)
    t1_clean = clean_inv(t1_resp)
    t1_time = time.time() - t0

    # Turn 2 — find violations (same T2 as Run 1) + ADDITIVE hypothesis section appended
    # Key: ADDITIVE_HYP_BLOCK says "ALSO after completing FINDINGs", không nói "before"
    time.sleep(3)
    t2_start = time.time()
    t2_prompt = build_round1_prompt(profile, ann_source, injected_invariants=t1_clean)
    t2_resp = llm_call(t2_prompt + ADDITIVE_HYP_BLOCK)
    t2_time = time.time() - t2_start
    total_time = time.time() - t0

    detected = detect(t2_resp, grp['gt_fns'])
    found_str = '  '.join(f"{'✅' if v else '❌'} {k}" for k, v in detected.items())
    print(f"  {grp['name']:<16} {grp['agent_id']:<20} {src_lines:>6} {total_time:>7.1f}s  {found_str}")

    out = os.path.join(OUT_DIR, f"{grp['name']}_additive_hyp.txt")
    with open(out, 'w') as f:
        f.write(f"Run 6 — HIST-INV T1+T2 + Additive Hypothesis\n")
        f.write(f"Group: {grp['name']}  Agent: {grp['agent_id']}\n")
        f.write(f"T1: {t1_time:.1f}s  T2: {t2_time:.1f}s  Total: {total_time:.1f}s\n")
        f.write(f"GT detected: {detected}\n\n")
        f.write(f"{'='*60}\n=== ANNOTATED SOURCE ({src_lines} lines) ===\n{ann_source}\n\n")
        f.write(f"{'='*60}\n=== TURN 1 (invariants) ===\n{t1_resp}\n\n")
        f.write(f"{'='*60}\n=== TURN 2 + ADDITIVE_HYP_BLOCK ===\n{t2_resp}\n")

    summary.append({
        "group": grp['name'],
        "agent": grp['agent_id'],
        "src_lines": src_lines,
        "latency_s": round(total_time, 1),
        "detected": detected,
    })
    time.sleep(3)

# ─── Summary ──────────────────────────────────────────────────────────────────

all_gt = [fn for grp in GROUPS for fn in grp['gt_fns']]
tp = sum(1 for r in summary for found in r['detected'].values() if found)
total_lat = sum(r['latency_s'] for r in summary)

print(f"\n{'='*75}")
print(f"Run 6 (additive_hyp): TP={tp}/{len(all_gt)}  time={total_lat:.1f}s  calls={len(GROUPS)*2}")
print()
print("Comparison:")
print(f"  {'Run 1 (hist_inv T1+T2)':<32} 4/5  ~58s   6 calls  ← baseline tốt nhất")
print(f"  {'Run 4 (hist_inv + hyp gate)':<32} 2/5  48.8s  6 calls  ← regression do gate conflict")
print(f"  {'Run 5 (single_turn_hyp)':<32} 3/5   35s  3 calls")
print(f"  {'Run 6 (hist_inv + additive hyp)':<32} {tp}/{len(all_gt)}  {total_lat:.1f}s  {len(GROUPS)*2} calls")
print()
for r in summary:
    det = '  '.join(f"{'✅' if v else '❌'}{k}" for k, v in r['detected'].items())
    print(f"    {r['group']:<16} {r['latency_s']:>6.1f}s  {r['src_lines']:>5} lines  {det}")

with open(os.path.join(OUT_DIR, 'summary_run6.json'), 'w') as f:
    json.dump(summary, f, indent=2)
print(f"\nOutputs: {OUT_DIR}/")
