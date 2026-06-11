"""
Simulate 5 FN bugs của contest 35 với new inv logic:
  - custom slugs first, no slug cap, lines[:2]/slug, total[:6]
  - H-03, H-16: dùng ConcentratedLiquidityPoolManager source (scope fix)
  - H-17: inv mới có custom_35_h17 ở dòng đầu
  - H-01, H-05: inv mới so với cũ

2 conditions: no_inv | with_new_inv
"""
import sys, os, re, time, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pysqlite3; sys.modules['sqlite3'] = pysqlite3
from openai import OpenAI
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))

KEY_FILE = os.getenv('LLM_VERTEX_AI_KEY_FILE', '')
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = KEY_FILE
BASE_URL = os.getenv('LLM_BASE_URL', '')
MODEL    = os.getenv('LLM_MODEL_NAME', 'google/gemini-3-flash-preview')

import google.auth.transport.requests
from google.oauth2 import service_account
creds = service_account.Credentials.from_service_account_file(
    KEY_FILE, scopes=['https://www.googleapis.com/auth/cloud-platform'])
creds.refresh(google.auth.transport.requests.Request())
llm = OpenAI(api_key=creds.token, base_url=BASE_URL)

def _strip(t): return re.sub(r'<think>.*?</think>', '', t or '', flags=re.DOTALL).strip()

# ─── Build new inv_map ────────────────────────────────────────────────────────

from app.services.contract_hist_inv_cache import HistInvCache

_CACHE_PATH = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/hist_inv_cache.json'
_RAG_CACHE  = '/home/thangdd/repos/MiroFish/backend/scripts/rag/rag_sections_cache.json'

hc = HistInvCache(_CACHE_PATH)
matched = hc.get_matched_slugs()
rc = json.load(open(_RAG_CACHE))
inv_lookup = {
    f['slug']: (f.get('sections') or {}).get('inv') or []
    for f in rc.get('findings', [])
}

def build_new_inv(contract, fn) -> str:
    """New logic: custom slugs first, no slug cap, lines[:2]/slug, total[:6]."""
    slugs = matched.get((contract, fn), [])
    custom = [s for s in slugs if s.startswith('custom_')]
    others = [s for s in slugs if not s.startswith('custom_')]
    lines = []
    for s in custom + others:
        lines.extend((inv_lookup.get(s) or [])[:2])
    return '\n'.join(lines[:6])

# ─── Sources ──────────────────────────────────────────────────────────────────

BASE = '/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/pool/concentrated'
SRC_POOL    = open(f'{BASE}/ConcentratedLiquidityPool.sol').read()
SRC_MANAGER = open(f'{BASE}/ConcentratedLiquidityPoolManager.sol').read()

def inject_inv(source: str, fn_name: str, inv: str) -> str:
    """Inject // [HIST-INV]: comment above function definition."""
    import textwrap
    lines = source.split('\n')
    result = []
    for line in lines:
        m = re.match(r'^([ \t]*)function\s+(\w+)\s*[\(\{]', line)
        if m and m.group(2) == fn_name and inv:
            indent = m.group(1)
            wrapped = textwrap.wrap(
                inv, width=96,
                initial_indent=f'{indent}// [HIST-INV]: ',
                subsequent_indent=f'{indent}//             ',
            )
            result.extend(wrapped)
        result.append(line)
    return '\n'.join(result)

# ─── Tasks ────────────────────────────────────────────────────────────────────

OUTPUT_FMT = """
OUTPUT FORMAT:
  FINDING: <title>
  CONTRACT: <name>
  FUNCTION: <name>
  SEVERITY: high|medium|low
  EVIDENCE: CODE: <snippet> | MISSING: <what> AT: <fn()>
  ATTACK_PATH: ACTOR / CALL / STATE_CHANGE / OUTCOME
  DESCRIPTION: <why>
  PATCH: <fix>

Write NO FINDING if nothing found. Do not hallucinate.
"""

TASKS = [
    {
        "id": "H-01",
        "contract": "ConcentratedLiquidityPool",
        "fn": "burn",
        "source": SRC_POOL,
        "agent_system": (
            "You are a formal methods engineer. "
            "You look for unsafe narrowing casts (uint256→uint128, int256→int128) "
            "where an attacker can craft values that overflow the target type, "
            "causing the operation to produce incorrect results or allow fund theft."
        ),
        "lens": (
            "Is there any narrowing cast (uint256 → uint128) in this function where "
            "an attacker can craft a value exceeding the target type's max? "
            "Trace every cast: what are the bounds on the input value?"
        ),
        "step1": (
            'STEP 1 — LIST INVARIANTS:\n'
            '  ✓ "all uint256→uint128 casts must be bounds-checked before casting"\n'
            '  ✓ "liquidity subtracted in burn must not exceed current position liquidity"\n'
            '  ✗ Generic: "no overflow"'
        ),
        "keywords": [
            r"unsafe.*cast|cast.*unsafe|uint256.*uint128|uint128.*overflow",
            r"casting.*attack|cast.*exploit|liquidity.*cast",
        ],
    },
    {
        "id": "H-03",
        "contract": "ConcentratedLiquidityPoolManager",
        "fn": "reclaimIncentive",
        "source": SRC_MANAGER,
        "agent_system": (
            "You are a privilege escalation specialist. "
            "You look for missing access control on sensitive operations, "
            "unprotected admin functions, and caller-controlled parameters "
            "that allow unauthorized fund extraction."
        ),
        "lens": (
            "What is the path of least resistance to extract incentive funds "
            "without authorization? Which functions lack proper caller validation?"
        ),
        "step1": (
            'STEP 1 — LIST INVARIANTS:\n'
            '  ✓ "reclaimIncentive must only be callable by the incentive creator"\n'
            '  ✓ "incentive funds must not be transferable to arbitrary addresses"\n'
            '  ✗ Generic: "access control exists"'
        ),
        "keywords": [
            r"anyone.*call|permissionless|missing.*auth|no.*check.*creator",
            r"steal.*incentive|drain.*incentive|unauthorized.*reclaim",
            r"access.*control.*missing|caller.*not.*verified|no.*owner.*check",
        ],
    },
    {
        "id": "H-05",
        "contract": "ConcentratedLiquidityPool",
        "fn": "_getAmountsForLiquidity",
        "source": SRC_POOL,
        "agent_system": (
            "You are a quantitative analyst. "
            "You look for incorrect typecasting in AMM math — "
            "int → uint conversions, precision loss from premature casts, "
            "and sign-bit truncation errors."
        ),
        "lens": (
            "Is there any typecast in this function that loses bits or flips sign? "
            "Trace every conversion: int24 → uint, uint160 → uint128, etc."
        ),
        "step1": (
            'STEP 1 — LIST INVARIANTS:\n'
            '  ✓ "int24 tick values must not be cast to uint without sign check"\n'
            '  ✓ "amounts returned must be non-negative and representable in target type"\n'
            '  ✗ Generic: "no overflow"'
        ),
        "keywords": [
            r"typecast|type.*cast|incorrect.*cast|wrong.*cast",
            r"int.*uint.*sign|sign.*flip|negative.*uint",
            r"cast.*loss|precision.*cast|truncat",
        ],
    },
    {
        "id": "H-16",
        "contract": "ConcentratedLiquidityPoolManager",
        "fn": "claimReward",
        "source": SRC_MANAGER,
        "agent_system": (
            "You are a DeFi exploit developer. "
            "You look for JIT (just-in-time) liquidity attacks, flash loan exploits, "
            "and economic attacks on reward distribution mechanisms."
        ),
        "lens": (
            "Can an attacker add liquidity immediately before a reward claim "
            "and remove it after, capturing disproportionate rewards? "
            "Is secondsPerLiquidity snapshotted at the right time?"
        ),
        "step1": (
            'STEP 1 — LIST INVARIANTS:\n'
            '  ✓ "reward share must be proportional to time-weighted liquidity, not instantaneous"\n'
            '  ✓ "secondsPerLiquidity snapshot must prevent JIT liquidity gaming"\n'
            '  ✗ Generic: "no reentrancy"'
        ),
        "keywords": [
            r"JIT|just.in.time|flash.*liquidity|instantaneous.*liquidity",
            r"sandwich.*reward|frontrun.*claim|add.*remove.*same.*block",
            r"secondsPerLiquidity.*manipulat|reward.*gaming|atomic.*liquidity",
        ],
    },
    {
        "id": "H-17",
        "contract": "ConcentratedLiquidityPool",
        "fn": "rangeFeeGrowth",
        "source": SRC_POOL,
        "agent_system": (
            "You are a formal methods engineer. "
            "You look for stale cached state reads — storage variables that are "
            "only updated on specific events, causing incorrect results when "
            "the underlying value has changed but the cache has not."
        ),
        "lens": (
            "Is there any storage variable used as a reference point that may be "
            "stale relative to current on-chain state? "
            "Can the price move without updating the cached tick reference?"
        ),
        "step1": (
            'STEP 1 — LIST INVARIANTS:\n'
            '  ✓ "currentTick used for fee growth must reflect actual current price"\n'
            '  ✓ "nearestTick is only updated when a tick boundary is crossed, not on every price move"\n'
            '  ✗ Generic: "no overflow"'
        ),
        "keywords": [
            r"nearestTick.*stale|stale.*nearestTick",
            r"currentTick.*nearestTick|nearestTick.*not.*current",
            r"cached.*tick|tick.*cached|wrong.*reference.*tick",
            r"price.*moved.*tick|tick.*not.*reflect.*current",
        ],
    },
]

# ─── Agent runner ─────────────────────────────────────────────────────────────

def make_prompt(task: dict, with_inv: bool) -> str:
    inv = build_new_inv(task['contract'], task['fn'])
    source = task['source']
    if with_inv and inv:
        source = inject_inv(source, task['fn'], inv)
        inv_note = (
            "\n=== HISTORICAL PATTERN MATCH ===\n"
            "The [HIST-INV] comment injected above the target function was derived from "
            "a matched historical finding. Verify: does the code actually violate this invariant?\n"
        )
    else:
        inv_note = ""

    return f"""=== ROUND 1 — INDEPENDENT DISCOVERY ===
You are a security auditor.
{task['agent_system']}
{inv_note}
=== CONTRACT: {task['contract']} ===
```solidity
{source}
```

=== EPISTEMIC LENS ===
{task['lens']}

{task['step1']}

STEP 2 — FIND VIOLATIONS: For each invariant, check all execution paths.
{OUTPUT_FMT}"""

def llm_call(prompt: str) -> str:
    for attempt in range(3):
        try:
            resp = llm.chat.completions.create(
                model=MODEL, temperature=0.3, max_tokens=3000,
                messages=[{"role": "user", "content": prompt}],
                extra_body={"google": {"thinking_config": {"thinking_budget": 0}}}
            )
            return _strip(resp.choices[0].message.content)
        except Exception as e:
            if '429' in str(e) or 'rate' in str(e).lower():
                wait = 20*(attempt+1); print(f"  [rate {wait}s]"); time.sleep(wait)
            else: raise
    raise RuntimeError("LLM failed")

def detect(resp: str, keywords: list) -> bool:
    return "FINDING:" in resp and any(re.search(kw, resp, re.IGNORECASE) for kw in keywords)

# ─── Main ─────────────────────────────────────────────────────────────────────

OUT_DIR = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/sim_fn_inv_fix'
os.makedirs(OUT_DIR, exist_ok=True)

print('\n' + '='*75)
print('FN bugs simulation — no_inv vs with_new_inv')
print('='*75)
print(f"{'GT':>5} {'Contract':<35} {'Fn':<25} {'No-INV':>7} {'New-INV':>8}")
print('─'*75)

summary = []
for task in TASKS:
    results = {}
    for label, with_inv in [('no_inv', False), ('with_inv', True)]:
        print(f"  [{task['id']}] {label} ...", flush=True)
        time.sleep(4)
        try:
            resp = llm_call(make_prompt(task, with_inv))
        except Exception as e:
            resp = f"ERROR: {e}"
        found = detect(resp, task['keywords'])
        results[label] = {'found': found, 'resp': resp}
        fn_out = os.path.join(OUT_DIR, f"{task['id']}_{label}_{task['fn']}.txt")
        with open(fn_out, 'w') as f:
            inv_used = build_new_inv(task['contract'], task['fn']) if with_inv else ''
            f.write(f"GT: {task['id']} — {task['contract']}.{task['fn']}\n")
            f.write(f"Condition: {label}\nINV injected:\n{inv_used}\n\n{'='*60}\n{resp}")
        time.sleep(3)

    a, b = results['no_inv'], results['with_inv']
    ma = '✅' if a['found'] else '❌'
    mb = '✅' if b['found'] else '❌'
    print(f"  {task['id']:>5} {task['contract']:<35} {task['fn']:<25} {ma:>7} {mb:>8}")
    summary.append({'id': task['id'], 'no_inv': a['found'], 'with_inv': b['found']})

print(f"\n{'='*75}")
no_tp  = sum(1 for r in summary if r['no_inv'])
inv_tp = sum(1 for r in summary if r['with_inv'])
print(f"No-INV  TP = {no_tp}/5")
print(f"New-INV TP = {inv_tp}/5")
improved  = [r['id'] for r in summary if r['with_inv'] and not r['no_inv']]
regressed = [r['id'] for r in summary if r['no_inv'] and not r['with_inv']]
print(f"Improved:  {improved or 'none'}")
print(f"Regressed: {regressed or 'none'}")

with open(os.path.join(OUT_DIR, 'summary.json'), 'w') as f:
    json.dump(summary, f, indent=2)
print(f"\nOutputs: {OUT_DIR}/")
