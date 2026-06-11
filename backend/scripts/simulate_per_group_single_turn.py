"""
Per-Function-Group Simulation — Run 5: Single-turn hypothesis-first (no T1/T2 split).

Hypothesis-first như trong docs/good-techniques/hypothesis-first-rag.md:
  - Agent tự làm STEP 1 (list invariants) + STEP 2 (find violations) trong 1 call
  - Không có T1/T2 split
  - Cross-protocol few-shot examples để calibrate granularity
  - HIST-INV annotations vẫn inject (giống Run 1)
  - Không dùng RAG tool

So sánh với:
  Run 1 (hist_inv_t1t2)    : 4/5, ~58s, 6 calls
  Run 4 (hist_inv+hyp_norag): 2/5, 48.8s, 6 calls
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
    """Old pipeline mechanism: slugs[:2], lines[:2]/slug, total[:3]."""
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
    result = []
    brace_depth = 0
    in_contract = False
    skip_fn = False
    for line in lines:
        stripped = line.strip()
        opens = line.count('{')
        closes = line.count('}')
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
    result = []
    i = 0
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

def detect(response: str, fn_names: list) -> dict:
    return {
        fn: bool(re.search(rf'FUNCTION:\s*{re.escape(fn)}\b', response, re.IGNORECASE))
        for fn in fn_names
    }

# ─── Cross-protocol examples (để calibrate granularity STEP 1) ───────────────

CROSS_PROTO_HINT = (
    "\n=== FEW-SHOT EXAMPLES — invariant specificity required in STEP 1 ===\n"
    "Invariants must look like these (protocol-specific, cite exact mechanism):\n"
    "  ✓ 'cToken exchange rate read before accrueInterest() → stale rate used in mint()'\n"
    "  ✓ 'LP shares burned but pool.reserve0/reserve1 not updated atomically → imbalance'\n"
    "  ✓ 'governance timelock: proposer == executor → no delay enforced'\n"
    "  ✓ 'fee recipient removed from mapping before balance transferred → funds locked'\n"
    "  ✗ 'overflow possible' — must cite specific cast (e.g. uint256→uint128 in burn())\n"
    "  ✗ 'reentrancy' — must cite exact external call + state variable written after\n"
    "Apply this level of specificity to every invariant you list.\n"
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
print('Run 5 — Single-turn hypothesis-first (no T1/T2 split) + HIST-INV + cross-proto examples')
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

    # Single call: STEP 1 (inline) + STEP 2 — agent does both in one response
    time.sleep(3)
    t0 = time.time()
    prompt = build_round1_prompt(profile, ann_source, step2_hint=CROSS_PROTO_HINT)
    resp = llm_call(prompt)
    total_time = time.time() - t0

    detected = detect(resp, grp['gt_fns'])
    found_str = '  '.join(f"{'✅' if v else '❌'} {k}" for k, v in detected.items())
    print(f"  {grp['name']:<16} {grp['agent_id']:<20} {src_lines:>6} {total_time:>7.1f}s  {found_str}")

    out = os.path.join(OUT_DIR, f"{grp['name']}_single_turn_hyp.txt")
    with open(out, 'w') as f:
        f.write(f"Run 5 — Single-turn hypothesis-first\n")
        f.write(f"Group: {grp['name']}  Agent: {grp['agent_id']}  Time: {total_time:.1f}s\n")
        f.write(f"GT detected: {detected}\n\n")
        f.write(f"{'='*60}\n=== ANNOTATED SOURCE ({src_lines} lines) ===\n{ann_source}\n\n")
        f.write(f"{'='*60}\n=== SINGLE-TURN RESPONSE ===\n{resp}\n")

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
print(f"Run 5 (single_turn_hyp): TP={tp}/{len(all_gt)}  time={total_lat:.1f}s  calls={len(GROUPS)}")
print()
print("Comparison:")
print(f"  {'Run 1 (hist_inv_t1t2)':<30} 4/5  ~58s   6 calls")
print(f"  {'Run 2 (no_inv baseline)':<30} 2/5  ~17s   3 calls")
print(f"  {'Run 3 (hist_inv+rag)':<30} 2/5  ~58s   6 calls")
print(f"  {'Run 4 (hist_inv+hyp_norag)':<30} 2/5  48.8s  6 calls")
print(f"  {'Run 5 (single_turn_hyp)':<30} {tp}/{len(all_gt)}  {total_lat:.1f}s  {len(GROUPS)} calls")
print()
for r in summary:
    det = '  '.join(f"{'✅' if v else '❌'}{k}" for k, v in r['detected'].items())
    print(f"    {r['group']:<16} {r['latency_s']:>6.1f}s  {r['src_lines']:>5} lines  {det}")

with open(os.path.join(OUT_DIR, 'summary_run5.json'), 'w') as f:
    json.dump(summary, f, indent=2)
print(f"\nOutputs: {OUT_DIR}/")
