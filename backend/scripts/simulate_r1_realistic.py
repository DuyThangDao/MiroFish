"""
Simulate 5 GT functions với 3 conditions (no_inv / old_inv / new_inv)
dùng EXACT pipeline: Turn1 (invariant_only) → Turn2 (full analysis)
Actual agent profiles, full contract source, không leak bug type.

3 conditions:
  no_inv  : source không có [HIST-INV]
  old_inv : source có [HIST-INV] từ old mechanism (slugs[:2], lines[:2], total[:3])
  new_inv : source có [HIST-INV] từ new mechanism (custom first, no slug cap, lines[:2], total[:6])

GT functions tested:
  H-01  evm_hardener     ConcentratedLiquidityPool.burn
  H-03  access_escalator ConcentratedLiquidityPoolManager.reclaimIncentive
  H-05  evm_hardener     ConcentratedLiquidityPool._getAmountsForLiquidity
  H-16  clmm_specialist  ConcentratedLiquidityPoolManager.claimReward
  H-17  clmm_specialist  ConcentratedLiquidityPool.rangeFeeGrowth
"""
import sys, os, re, time, json, textwrap
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
from app.services.contract_profile_generator import ContractExpertProfileGenerator as ContractProfileGenerator
from app.services.contract_hist_inv_cache import HistInvCache

def _strip(t): return re.sub(r'<think>.*?</think>', '', t or '', flags=re.DOTALL).strip()

# ─── Load actual agent profiles ───────────────────────────────────────────────

BASE_SOL = '/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/pool/concentrated'
SRC_POOL    = open(f'{BASE_SOL}/ConcentratedLiquidityPool.sol').read()
SRC_MANAGER = open(f'{BASE_SOL}/ConcentratedLiquidityPoolManager.sol').read()

gen = ContractProfileGenerator()
# Use SRC_POOL as representative source for profile generation
pool_profiles = {p.agent_id: p for p in gen.generate_tier1_profiles(SRC_POOL)}
mgr_profiles  = {p.agent_id: p for p in gen.generate_tier1_profiles(SRC_MANAGER)}

# ─── Build inv maps ───────────────────────────────────────────────────────────

_CACHE_PATH = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/hist_inv_cache.json'
_RAG_CACHE  = '/home/thangdd/repos/MiroFish/backend/scripts/rag/rag_sections_cache.json'

hc = HistInvCache(_CACHE_PATH)
matched = hc.get_matched_slugs()
rc = json.load(open(_RAG_CACHE))
inv_lookup = {
    f['slug']: (f.get('sections') or {}).get('inv') or []
    for f in rc.get('findings', [])
}

def build_old_inv(contract, fn) -> str:
    """Old mechanism: slugs[:2], lines[:2]/slug, total[:3]."""
    slugs = matched.get((contract, fn), [])
    inv_lines = []
    for slug in slugs[:2]:
        inv_lines.extend((inv_lookup.get(slug) or [])[:2])
    return '\n'.join(inv_lines[:3])

def build_new_inv(contract, fn) -> str:
    """New mechanism: custom slugs first, no slug cap, lines[:2]/slug, total[:6]."""
    slugs = matched.get((contract, fn), [])
    custom = [s for s in slugs if s.startswith('custom_')]
    others = [s for s in slugs if not s.startswith('custom_')]
    lines = []
    for s in custom + others:
        lines.extend((inv_lookup.get(s) or [])[:2])
    return '\n'.join(lines[:6])

def inject_inv(source: str, fn_name: str, inv: str) -> str:
    """Inject // [HIST-INV]: comment above function definition."""
    if not inv:
        return source
    lines = source.split('\n')
    result = []
    for line in lines:
        m = re.match(r'^([ \t]*)function\s+(\w+)\s*[\(\{]', line)
        if m and m.group(2) == fn_name:
            indent = m.group(1)
            wrapped = textwrap.wrap(
                inv, width=96,
                initial_indent=f'{indent}// [HIST-INV]: ',
                subsequent_indent=f'{indent}//             ',
            )
            result.extend(wrapped)
        result.append(line)
    return '\n'.join(result)

# ─── LLM call ─────────────────────────────────────────────────────────────────

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
                print(f"  [rate limit, wait {wait}s]", flush=True)
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("LLM failed after retries")

def clean_inv_block(t1: str) -> str:
    """Strip non-INV lines from Turn 1 output."""
    lines = [l for l in t1.splitlines() if re.match(r'\s*INV-\d+:', l)]
    return '\n'.join(lines)

def detect_fn(response: str, fn_name: str) -> bool:
    """Check if FINDING block mentions the target function."""
    # Match FUNCTION: <fn_name> (case-insensitive, may have spaces/parens)
    pattern = rf'FUNCTION:\s*{re.escape(fn_name)}\b'
    return bool(re.search(pattern, response, re.IGNORECASE))

# ─── Tasks ────────────────────────────────────────────────────────────────────

TASKS = [
    {
        "id": "H-01",
        "contract": "ConcentratedLiquidityPool",
        "fn": "burn",
        "source": SRC_POOL,
        "agent_id": "evm_hardener",
        "profiles": pool_profiles,
    },
    {
        "id": "H-03",
        "contract": "ConcentratedLiquidityPoolManager",
        "fn": "reclaimIncentive",
        "source": SRC_MANAGER,
        "agent_id": "access_escalator",
        "profiles": mgr_profiles,
    },
    {
        "id": "H-05",
        "contract": "ConcentratedLiquidityPool",
        "fn": "_getAmountsForLiquidity",
        "source": SRC_POOL,
        "agent_id": "evm_hardener",
        "profiles": pool_profiles,
    },
    {
        "id": "H-16",
        "contract": "ConcentratedLiquidityPoolManager",
        "fn": "claimReward",
        "source": SRC_MANAGER,
        "agent_id": "clmm_specialist",
        "profiles": mgr_profiles,
    },
    {
        "id": "H-17",
        "contract": "ConcentratedLiquidityPool",
        "fn": "rangeFeeGrowth",
        "source": SRC_POOL,
        "agent_id": "clmm_specialist",
        "profiles": pool_profiles,
    },
]

CONDITIONS = [
    ("no_inv",  lambda c, f: ""),
    ("old_inv", build_old_inv),
    ("new_inv", build_new_inv),
]

# ─── Output dir ───────────────────────────────────────────────────────────────

OUT_DIR = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/sim_r1_realistic'
os.makedirs(OUT_DIR, exist_ok=True)

# ─── Main ─────────────────────────────────────────────────────────────────────

print('\n' + '='*80)
print('R1 Realistic Simulation — Turn1 + Turn2, actual agent profiles, full source')
print('='*80)
print(f"{'GT':>5}  {'Agent':<20} {'Fn':<30} {'No-INV':>7} {'Old-INV':>8} {'New-INV':>8}")
print('─'*80)

summary = []

for task in TASKS:
    profile = task['profiles'].get(task['agent_id'])
    if not profile:
        print(f"  [{task['id']}] ERROR: profile {task['agent_id']} not found")
        continue

    row = {"id": task["id"], "agent": task["agent_id"], "fn": task["fn"]}

    for cond_name, inv_fn in CONDITIONS:
        print(f"  [{task['id']}] {cond_name} ...", flush=True)

        # Build annotated source
        inv_text = inv_fn(task['contract'], task['fn'])
        ann_source = inject_inv(task['source'], task['fn'], inv_text) if inv_text else task['source']

        # Turn 1 — invariant extraction (no leak of bug type)
        time.sleep(3)
        t1_prompt = build_round1_prompt(
            profile,
            ann_source,
            invariant_only=True,
        )
        t1_resp = llm_call(t1_prompt)
        t1_clean = clean_inv_block(t1_resp) or t1_resp[:600]

        # Turn 2 — full analysis with invariants from Turn 1
        time.sleep(3)
        t2_prompt = build_round1_prompt(
            profile,
            ann_source,
            injected_invariants=t1_clean,
        )
        t2_resp = llm_call(t2_prompt)

        found = detect_fn(t2_resp, task['fn'])
        row[cond_name] = found

        # Save output
        fn_out = os.path.join(OUT_DIR, f"{task['id']}_{cond_name}_{task['fn']}.txt")
        with open(fn_out, 'w') as f:
            f.write(f"GT: {task['id']} — {task['contract']}.{task['fn']}\n")
            f.write(f"Condition: {cond_name}  Agent: {task['agent_id']}\n")
            f.write(f"INV injected:\n{inv_text}\n\n")
            f.write(f"{'='*60}\n=== TURN 1 ===\n{t1_resp}\n\n")
            f.write(f"{'='*60}\n=== TURN 2 ===\n{t2_resp}\n")

        time.sleep(3)

    # Print row
    marks = {True: '✅', False: '❌'}
    no  = marks[row.get('no_inv',  False)]
    old = marks[row.get('old_inv', False)]
    new = marks[row.get('new_inv', False)]
    print(f"  {task['id']:>5}  {task['agent_id']:<20} {task['fn']:<30} {no:>7} {old:>8} {new:>8}")
    summary.append(row)

# ─── Summary ──────────────────────────────────────────────────────────────────
print(f"\n{'='*80}")
for cond_name, _ in CONDITIONS:
    tp = sum(1 for r in summary if r.get(cond_name))
    print(f"{cond_name:>10} TP = {tp}/{len(summary)}")

improved_old = [r['id'] for r in summary if r.get('old_inv') and not r.get('no_inv')]
improved_new = [r['id'] for r in summary if r.get('new_inv') and not r.get('no_inv')]
regressions_old = [r['id'] for r in summary if r.get('no_inv') and not r.get('old_inv')]
regressions_new = [r['id'] for r in summary if r.get('no_inv') and not r.get('new_inv')]
print(f"\nImproved by old_inv: {improved_old or 'none'}")
print(f"Improved by new_inv: {improved_new or 'none'}")
print(f"Regressed by old_inv: {regressions_old or 'none'}")
print(f"Regressed by new_inv: {regressions_new or 'none'}")

with open(os.path.join(OUT_DIR, 'summary.json'), 'w') as f:
    json.dump(summary, f, indent=2)
print(f"\nOutputs: {OUT_DIR}/")
