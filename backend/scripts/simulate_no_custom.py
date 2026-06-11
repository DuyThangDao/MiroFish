"""
Simulation: 3 groups × 3 agents — KHÔNG có custom_* slugs trong inv_map.
Mục đích: đo performance thực sự khi không có contest-specific hints.

Groups:
  math_cast     → 3 agents (math_precision, evm_exploiter, invariant_breaker)
                  GT: burn (H-01), _getAmountsForLiquidity (H-05)
  clmm_semantic → 3 agents (clmm_specialist, defi_analyst, logic_exploiter)
                  GT: rangeFeeGrowth (H-17)
  access_reward → 3 agents (access_escalator, appsec_researcher, state_machine_analyst)
                  GT: reclaimIncentive (H-03), claimReward (H-16)

OR-merge: TP nếu BẤT KỲ agent nào trong group tìm được.
"""
import sys, os, re, time, json, threading
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

# ─── HIST-INV setup — NO custom_* slugs ──────────────────────────────────────
_CACHE_PATH = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/hist_inv_cache.json'
_RAG_CACHE  = '/home/thangdd/repos/MiroFish/backend/scripts/rag/rag_sections_cache.json'

hc = HistInvCache(_CACHE_PATH)
matched_slugs = hc.get_matched_slugs()
rag_cache = json.load(open(_RAG_CACHE))
inv_lookup = {
    f['slug']: (f.get('sections') or {}).get('inv') or []
    for f in rag_cache.get('findings', [])
}

def build_inv_map_no_custom() -> dict:
    """Slug cap fix NHƯNG exclude toàn bộ custom_* slugs."""
    inv_map = {}
    for (contract, fn), slugs in matched_slugs.items():
        # Chỉ dùng non-custom slugs; cap 4
        filtered = [s for s in slugs if not s.startswith('custom_')]
        inv_lines = []
        for slug in filtered[:4]:
            inv_lines.extend((inv_lookup.get(slug) or [])[:2])
        if inv_lines:
            inv_map[(contract, fn)] = "\n".join(inv_lines[:4])
    return inv_map

INV_MAP = build_inv_map_no_custom()

# Verify: không có custom slug nào được inject
custom_injected = sum(
    1 for v in INV_MAP.values()
    if 'current tick must be updated' in v or 'uint128 maximum bounds' in v
)
print(f"[INV_MAP] {len(INV_MAP)} functions annotated | custom hints injected: {custom_injected}")

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

def build_group_source(contracts, fn_names):
    parts = []
    for cname, src in contracts:
        header = extract_contract_header(src)
        fns    = extract_functions(src, fn_names)
        if fns.strip():
            parts.append(f"// ─── {cname}.sol ─────────────────────────────────────────────────")
            parts.append(header.rstrip())
            parts.append("    // ... (other functions omitted)")
            parts.append(fns)
            parts.append("}")
    return '\n'.join(parts)

# ─── Profiles ─────────────────────────────────────────────────────────────────
gen = Gen()
profiles_map = {p.agent_id: p for p in gen.generate_tier1_profiles(SRC_POOL)}

# ─── Groups — 3 agents mỗi group, diverse lenses ─────────────────────────────
GROUPS = [
    {
        "name":      "math_cast",
        "gt_fns":    ["burn", "_getAmountsForLiquidity"],
        "contracts": [("ConcentratedLiquidityPool", SRC_POOL)],
        "fn_names":  ["burn", "mint", "_getAmountsForLiquidity", "_updateSecondsPerLiquidity"],
        "agents":    ["math_precision", "evm_exploiter", "invariant_breaker"],
    },
    {
        "name":      "clmm_semantic",
        "gt_fns":    ["rangeFeeGrowth"],
        "contracts": [("ConcentratedLiquidityPool", SRC_POOL), ("Ticks", SRC_TICKS)],
        "fn_names":  ["rangeFeeGrowth", "cross", "initialize", "insert"],
        "agents":    ["clmm_specialist", "defi_analyst", "logic_exploiter"],
    },
    {
        "name":      "access_reward",
        "gt_fns":    ["reclaimIncentive", "claimReward"],
        "contracts": [("ConcentratedLiquidityPoolManager", SRC_MANAGER)],
        "fn_names":  ["reclaimIncentive", "claimReward", "subscribe", "addIncentive"],
        "agents":    ["access_escalator", "appsec_researcher", "state_machine_analyst"],
    },
]

OUT_DIR = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/sim_no_custom'
os.makedirs(OUT_DIR, exist_ok=True)

# ─── LLM ──────────────────────────────────────────────────────────────────────
_LOCK = threading.Lock()

def llm_call(prompt):
    for attempt in range(5):
        try:
            resp = llm.chat.completions.create(
                model=MODEL, temperature=0.3, max_tokens=4000,
                messages=[{"role": "user", "content": prompt}],
                extra_body={"google": {"thinking_config": {"thinking_budget": 0}}}
            )
            return _strip(resp.choices[0].message.content)
        except Exception as e:
            if '429' in str(e) or 'rate' in str(e).lower():
                wait = 30 * (attempt + 1)
                with _LOCK:
                    print(f"    [rate {wait}s]", flush=True)
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

# ─── Run one agent on one group ───────────────────────────────────────────────
def run_agent(agent_id, group_source, ann_source, gt_fns, group_name, agent_idx):
    profile = profiles_map[agent_id]
    t0 = time.time()

    time.sleep(2 + agent_idx * 3)  # stagger

    # T1: extract invariants
    t1_prompt = build_round1_prompt(profile, ann_source, invariant_only=True)
    t1_resp   = llm_call(t1_prompt)
    t1_clean  = clean_inv(t1_resp)

    time.sleep(2)

    # T2: find violations
    t2_prompt = build_round1_prompt(profile, ann_source, injected_invariants=t1_clean)
    t2_resp   = llm_call(t2_prompt)

    total_time = time.time() - t0
    detected   = detect(t2_resp, gt_fns)
    tp         = sum(detected.values())

    with _LOCK:
        found_str = '  '.join(f"{'✅' if v else '❌'} {fn}" for fn, v in detected.items())
        print(f"    [{group_name}/{agent_id}] {total_time:.1f}s  {found_str}", flush=True)

    # Save agent output
    out_path = os.path.join(OUT_DIR, f"{group_name}_{agent_id}.txt")
    with open(out_path, 'w') as f:
        f.write(f"Group: {group_name}  Agent: {agent_id}\n")
        f.write(f"T1+T2  Total: {total_time:.1f}s\n")
        f.write(f"Detected: {detected}\n\n")
        f.write(f"{'='*60}\n=== ANNOTATED SOURCE ===\n{ann_source}\n\n")
        f.write(f"{'='*60}\n=== T1 ===\n{t1_resp}\n\n")
        f.write(f"{'='*60}\n=== T2 ===\n{t2_resp}\n")

    return {"agent": agent_id, "detected": detected, "time": round(total_time, 1)}

# ─── Run one group (3 agents sequential to avoid rate limits) ─────────────────
def run_group(grp):
    group_source = build_group_source(grp['contracts'], grp['fn_names'])
    ann_source   = _annotate_source_with_hist_inv(group_source, INV_MAP)
    src_lines    = ann_source.count('\n') + 1

    print(f"\n{'='*65}")
    print(f"Group: {grp['name']}  |  GT: {grp['gt_fns']}")
    print(f"Source: {src_lines} lines  |  Agents: {grp['agents']}")
    print(f"{'='*65}", flush=True)

    # Kiểm tra custom hints có bị inject không
    for fn in grp['gt_fns']:
        for cname, _ in grp['contracts']:
            hint = INV_MAP.get((cname, fn), '')
            tag = '[CUSTOM HINT PRESENT]' if 'current tick must be updated' in hint or 'uint128 maximum bounds' in hint else '[no custom]'
            print(f"  INV for {cname}.{fn}: {len(hint)} chars  {tag}", flush=True)

    agent_results = []
    for idx, agent_id in enumerate(grp['agents']):
        r = run_agent(agent_id, group_source, ann_source, grp['gt_fns'], grp['name'], idx)
        agent_results.append(r)
        if idx < len(grp['agents']) - 1:
            time.sleep(5)

    # OR-merge: TP nếu bất kỳ agent nào tìm được
    merged = {fn: any(r['detected'].get(fn, False) for r in agent_results) for fn in grp['gt_fns']}
    tp = sum(merged.values())

    print(f"\n  OR-merge: TP={tp}/{len(grp['gt_fns'])}", flush=True)
    for fn, found in merged.items():
        per_agent = [('✅' if r['detected'].get(fn) else '❌') for r in agent_results]
        print(f"    {'✅' if found else '❌'} {fn}  [{' '.join(per_agent)}]")

    return {
        "group": grp['name'],
        "gt_fns": grp['gt_fns'],
        "agents": grp['agents'],
        "merged": merged,
        "tp": tp,
        "agent_results": agent_results,
    }

# ─── Main ─────────────────────────────────────────────────────────────────────
print('\n' + '='*65)
print('Simulation: 3 groups × 3 agents — NO custom_* slugs')
print('Config: HIST-INV T1+T2, non-custom slugs only, cap=4')
print('='*65)

t_start = time.time()
group_outputs = []
for grp in GROUPS:
    r = run_group(grp)
    group_outputs.append(r)
    time.sleep(5)

# ─── Final summary ────────────────────────────────────────────────────────────
total_tp  = sum(r['tp'] for r in group_outputs)
total_gt  = sum(len(r['gt_fns']) for r in group_outputs)
wall_time = time.time() - t_start

print(f"\n{'='*65}")
print(f"FINAL SUMMARY — NO custom slugs")
print(f"{'='*65}")
for r in group_outputs:
    for fn, found in r['merged'].items():
        per = [('✅' if a['detected'].get(fn) else '❌') for a in r['agent_results']]
        print(f"  {'✅' if found else '❌'} {r['group']}.{fn}  [{' '.join(per)}]")
print(f"\n  TP={total_tp}/{total_gt}  wall_time={wall_time:.0f}s")

# Save JSON summary
summary_path = os.path.join(OUT_DIR, 'summary_no_custom.json')
json.dump({
    "config": "no_custom_slugs_3agents_T1T2",
    "total_tp": total_tp,
    "total_gt": total_gt,
    "wall_time": round(wall_time),
    "groups": [{
        "name": r['group'],
        "gt_fns": r['gt_fns'],
        "merged": r['merged'],
        "tp": r['tp'],
        "per_agent": r['agent_results'],
    } for r in group_outputs]
}, open(summary_path, 'w'), indent=2)
print(f"\nSummary saved: {summary_path}")
