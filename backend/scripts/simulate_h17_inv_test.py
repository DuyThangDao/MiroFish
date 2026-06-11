"""
Test H-17 (rangeFeeGrowth nearestTick wrong reference) — 2 conditions:
  1. no_inv: agent tự suy luận từ code
  2. with_inv: có // [HIST-INV] annotation từ custom_35_h17
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

SOURCE = open("/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/pool/concentrated/ConcentratedLiquidityPool.sol").read()

# Invariant từ custom_35_h17
H17_INV = (
    "int24 current tick must be updated to the latest price state before comparing against range boundary ticks\n"
    "uint256 global fee growth must be calculated using the most recent price tick prior to range subtraction\n"
    "int24 tick used for conditional branching must reflect the current price instead of a cached storage value"
)

SYSTEM = (
    "You are a formal methods engineer who reads smart contracts as finite state machines. "
    "You look for invalid state transitions, dead-end states, and states where safety invariants "
    "are permanently broken. Key patterns: stale state reads, cached values that diverge from "
    "current on-chain state, update ordering bugs."
)

OUTPUT_FMT = """
OUTPUT FORMAT:
  FINDING: <title>
  CONTRACT: <name>
  FUNCTION: <name>
  SEVERITY: high|medium|low
  EVIDENCE: CODE: <snippet> | MISSING: <what> AT: <fn()>
  ATTACK_PATH: ACTOR / CALL / STATE_CHANGE / OUTCOME
  DESCRIPTION: <why this is wrong>
  PATCH: <fix>

Write NO FINDING if nothing found. Do not hallucinate.
"""

STEP1 = """STEP 1 — LIST INVARIANTS (3-5, specific to this function):
  ✓ "currentTick used for fee growth calculation must reflect the actual current price"
  ✓ "feeGrowthBelow/Above must be computed relative to the actual pool price, not a cached tick"
  ✗ Generic: "no overflow", "access control"
"""

def make_prompt(with_inv: bool) -> str:
    if with_inv:
        hist_block = f"""
// [HIST-INV]: {H17_INV.replace(chr(10), chr(10) + '//             ')}
function rangeFeeGrowth(...) {{ ... }}

"""
        inv_note = (
            "\n=== HISTORICAL PATTERN MATCH ===\n"
            "The [HIST-INV] comment above rangeFeeGrowth was injected from a matched historical finding.\n"
            "Verify: does the code actually violate this invariant? Require exact code evidence.\n"
        )
    else:
        hist_block = ""
        inv_note = ""

    return f"""=== ROUND 1 — INDEPENDENT DISCOVERY ===
You are state_machine_analyst.
{SYSTEM}
{inv_note}
=== CONTRACT: ConcentratedLiquidityPool ===
```solidity
{hist_block}{SOURCE}
```

=== EPISTEMIC LENS ===
Can any storage variable be stale at the time it is read for critical conditional logic?
Is there any function that reads state without first ensuring it reflects current on-chain reality?
Can the price move without updating a cached tick, causing incorrect fee accounting?

{STEP1}
TRACK A — ADVERSARIAL: test price at tick boundary, price moves mid-range, repeated swaps.

STEP 2 — FIND VIOLATIONS: For each invariant, find if any execution path violates it.
{OUTPUT_FMT}"""

def llm_call(prompt: str) -> str:
    for attempt in range(3):
        try:
            resp = llm.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=3000,
                extra_body={"google": {"thinking_config": {"thinking_budget": 0}}}
            )
            return _strip(resp.choices[0].message.content)
        except Exception as e:
            if '429' in str(e) or 'rate' in str(e).lower():
                wait = 20*(attempt+1); print(f"  [rate {wait}s]"); time.sleep(wait)
            else: raise
    raise RuntimeError("LLM failed")

KEYWORDS = [
    r"nearestTick.*stale|stale.*nearestTick",
    r"currentTick.*nearestTick|nearestTick.*currentTick",
    r"cached.*tick|tick.*cached",
    r"nearestTick.*not.*current|not.*accurate",
    r"wrong.*reference.*tick|tick.*wrong.*reference",
    r"price.*moved.*without.*updating|tick.*not.*reflect",
]

def detect(resp: str) -> bool:
    return "FINDING:" in resp and any(re.search(kw, resp, re.IGNORECASE) for kw in KEYWORDS)

OUT_DIR = "/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/sim_h17_inv_test"
os.makedirs(OUT_DIR, exist_ok=True)

print("\n" + "="*70)
print("H-17: rangeFeeGrowth — nearestTick wrong reference")
print("="*70)
print(f"{'Condition':<12} {'Found':^6}  First FINDING snippet")
print("─"*60)

results = []
for label, with_inv in [("no_inv", False), ("with_inv", True)]:
    print(f"\n[{label}] running...", flush=True)
    time.sleep(4)
    prompt = make_prompt(with_inv)
    resp = llm_call(prompt)
    found = detect(resp)
    mark = "✅" if found else "❌"
    snippet = ""
    m = re.search(r'FINDING: (.{0,70})', resp)
    if m: snippet = m.group(1)
    print(f"  {label:<12} {mark}  {snippet[:60]}")

    with open(os.path.join(OUT_DIR, f"h17_{label}.txt"), 'w') as f:
        f.write(f"Condition: {label}\nFound: {found}\n\n{'='*60}\n{resp}")
    results.append({"label": label, "found": found, "snippet": snippet})
    time.sleep(3)

print("\n" + "="*70)
print("SUMMARY")
for r in results:
    print(f"  {r['label']:<12} {'✅' if r['found'] else '❌'}  {r['snippet'][:60]}")

with open(os.path.join(OUT_DIR, "summary.json"), 'w') as f:
    json.dump(results, f, indent=2)
print(f"\nOutputs: {OUT_DIR}/")
