"""
Simulate Per-Function-Group Orchestration trên contest 35.
3 groups, mỗi group: đúng agent + chỉ relevant functions (~300-500 dòng).
Đo: latency + detection rate cho 5 GT bugs.

Groups:
  math_cast     → evm_hardener     → burn, mint, _getAmountsForLiquidity, _updateSecondsPerLiquidity
  clmm_semantic → clmm_specialist  → rangeFeeGrowth, cross (Ticks), initialize
  access_reward → access_escalator → reclaimIncentive, claimReward, subscribe, addIncentive
"""
import sys, os, re, time, json, textwrap
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pysqlite3; sys.modules['sqlite3'] = pysqlite3
import chromadb
from chromadb import EmbeddingFunction, Documents, Embeddings

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))

KEY_FILE = os.getenv('LLM_VERTEX_AI_KEY_FILE', '')
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = KEY_FILE
BASE_URL = os.getenv('LLM_BASE_URL', '')
MODEL    = os.getenv('LLM_MODEL_NAME', 'google/gemini-3-flash-preview')

import google.auth.transport.requests
from google.oauth2 import service_account
from openai import OpenAI
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput

creds = service_account.Credentials.from_service_account_file(
    KEY_FILE, scopes=['https://www.googleapis.com/auth/cloud-platform'])
creds.refresh(google.auth.transport.requests.Request())
llm = OpenAI(api_key=creds.token, base_url=BASE_URL)

# ─── RAG setup ────────────────────────────────────────────────────────────────

class VertexEmbed(EmbeddingFunction):
    def __init__(self):
        self._model = TextEmbeddingModel.from_pretrained("text-embedding-004")
    def __call__(self, input: Documents) -> Embeddings:
        ins = [TextEmbeddingInput(t, "RETRIEVAL_QUERY") for t in input]
        return [e.values for e in self._model.get_embeddings(ins)]

_embed  = VertexEmbed()
_chroma = chromadb.PersistentClient(
    path=os.path.join(os.path.dirname(__file__), '../data/rag_db/chroma'))
_col    = _chroma.get_collection('solodit_findings', embedding_function=_embed)
print(f"[RAG] solodit_findings: {_col.count()} docs loaded")

RAG_TOOL = [{
    "type": "function",
    "function": {
        "name": "search_historical_findings",
        "description": (
            "Search historical smart contract audit findings. "
            "RULE: Each query must encode your specific hypothesis derived from code evidence. "
            "Format: '[mechanism you suspect] because [specific code observation]'. "
            "If you cannot articulate a specific hypothesis yet, continue reading code first."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string",
                          "description": "Your specific hypothesis + code evidence (max 20 words)."}
            },
            "required": ["query"]
        }
    }
}]

# Cross-protocol hypothesis-first examples (best config từ experiment)
RAG_BLOCK = (
    "\n=== MEMORY TOOL ===\n"
    "You have search_historical_findings(query) — thousands of real audit findings.\n"
    "RULE 1: Complete STEP 1 (list invariants) before any RAG call.\n"
    "RULE 2: Each query must encode your specific hypothesis derived from code evidence.\n"
    "  Format: '[mechanism you suspect] because [specific code observation]'\n"
    "  Good: 'cToken exchange rate read before accrueInterest called, stale rate used in mint'\n"
    "  Good: 'LP shares burned but pool reserves not updated atomically, imbalance possible'\n"
    "  Good: 'governance timelock bypassed when proposer is also executor, instant execution'\n"
    "  Good: 'fee recipient mapping deleted but balance not transferred first, funds locked'\n"
    "  Bad:  'vulnerability in transfer()'\n"
    "  Bad:  'reentrancy bug'\n"
    "RULE 3: If you cannot articulate a specific hypothesis yet, continue reading code first.\n"
    "Multiple calls encouraged — each targeting a different suspected invariant violation.\n"
)

# Hypothesis-first NO RAG: same cross-protocol examples nhưng không có tool
# Agent học reasoning style từ examples, không call RAG
HYP_NO_RAG_BLOCK = (
    "\n=== HYPOTHESIS-FIRST REASONING ===\n"
    "Before writing any FINDING, you MUST form a specific hypothesis:\n"
    "  Format: '[mechanism you suspect] because [specific code observation]'\n"
    "  Good: 'cast uint256→uint128 in burn may overflow because liquidity can exceed uint128 max'\n"
    "  Good: 'nearestTick stale because only updated on tick cross in swap(), not every price move'\n"
    "  Good: 'reclaimIncentive missing caller check because only rewardToken validated, not creator'\n"
    "  Good: 'JIT attack: add liquidity before secondsPerLiquidity snapshot, remove after'\n"
    "  Bad:  'overflow in burn()' — too vague, no code observation\n"
    "  Bad:  'reentrancy' — no code evidence cited\n"
    "For each hypothesis: trace the exact execution path to CONFIRM or DENY. "
    "Only write FINDING after confirming with exact code evidence.\n"
)

def search_rag(query: str) -> str:
    results = _col.query(query_texts=[query], n_results=8,
                         include=['documents', 'metadatas', 'distances'])
    docs, metas, dists = results['documents'][0], results['metadatas'][0], results['distances'][0]
    seen, out = set(), []
    for doc, meta, dist in zip(docs, metas, dists):
        slug = meta.get('slug', '')
        if slug in seen: continue
        seen.add(slug)
        score = round(1 - dist, 3)
        title = meta.get('title', '')
        out.append(f"[score={score}] {title}\nSLUG: {slug}\n{doc[:800]}\n")
        if len(out) >= 3: break
    return "\n---\n".join(out) if out else "No results."

from app.services.contract_oasis_env import build_round1_prompt
from app.services.contract_profile_generator import ContractExpertProfileGenerator as Gen
from app.services.cyber_session_orchestrator import _annotate_source_with_hist_inv
from app.services.contract_hist_inv_cache import HistInvCache

def _strip(t): return re.sub(r'<think>.*?</think>', '', t or '', flags=re.DOTALL).strip()

# ─── Source files ─────────────────────────────────────────────────────────────

BASE = '/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/pool/concentrated'
SRC_POOL    = open(f'{BASE}/ConcentratedLiquidityPool.sol').read()
SRC_MANAGER = open(f'{BASE}/ConcentratedLiquidityPoolManager.sol').read()
SRC_TICKS   = open('/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/libraries/concentratedPool/Ticks.sol').read()

# ─── Function extractor ───────────────────────────────────────────────────────

def extract_contract_header(source: str) -> str:
    """Extract pragma, imports, contract declaration, state vars, structs, events, errors."""
    lines = source.split('\n')
    result = []
    brace_depth = 0
    in_contract = False
    skip_fn = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Track brace depth
        opens = line.count('{')
        closes = line.count('}')

        if not in_contract:
            result.append(line)
            if re.match(r'^(contract|abstract contract|library)\s+\w+', stripped):
                in_contract = True
                brace_depth += opens - closes
            continue

        # Inside contract — skip function bodies, keep declarations
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
    """Extract full bodies of specified functions from source."""
    lines = source.split('\n')
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'^([ \t]*)(function|constructor)\s+(\w+)\s*[\(\{]', line)
        if m and (m.group(3) in fn_names or 'constructor' in fn_names and m.group(2) == 'constructor'):
            # Collect full function body
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
    """Build focused source: header of contracts + only specified functions.
    Section header format matches _annotate_source_with_hist_inv expectation:
      // ─── ContractName.sol ───
    """
    parts = []
    for contract_name, source in contracts:
        header = extract_contract_header(source)
        fns = extract_functions(source, fn_names)
        if fns.strip():
            # Must match pattern: r'^// ─── ([\w]+)\.sol'
            parts.append(f"// ─── {contract_name}.sol ─────────────────────────────────────────────────")
            parts.append(header.rstrip())
            parts.append("    // ... (other functions omitted)")
            parts.append(fns)
            parts.append("}")
    return '\n'.join(parts)

# ─── Build inv_map (old pipeline mechanism: slugs[:2], lines[:2], total[:3]) ──

_CACHE_PATH = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/hist_inv_cache.json'
_RAG_CACHE  = '/home/thangdd/repos/MiroFish/backend/scripts/rag/rag_sections_cache.json'

hc = HistInvCache(_CACHE_PATH)
matched_slugs = hc.get_matched_slugs()
rag_cache = json.load(open(_RAG_CACHE))
inv_lookup = {
    f['slug']: (f.get('sections') or {}).get('inv') or []
    for f in rag_cache.get('findings', [])
}

def build_inv_map_pipeline() -> dict:
    """Old pipeline mechanism: slugs[:2], lines[:2]/slug, total[:3]."""
    inv_map = {}
    for (contract, fn), slugs in matched_slugs.items():
        inv_lines = []
        for slug in slugs[:2]:
            inv_lines.extend((inv_lookup.get(slug) or [])[:2])
        if inv_lines:
            inv_map[(contract, fn)] = "\n".join(inv_lines[:3])
    return inv_map

INV_MAP = build_inv_map_pipeline()

# ─── Build profiles ───────────────────────────────────────────────────────────

gen = Gen()
profiles_map = {p.agent_id: p for p in gen.generate_tier1_profiles(SRC_POOL)}

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
                print(f"    [rate {wait}s]", flush=True)
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("LLM failed")

def run_turn2_with_rag(prompt: str) -> tuple:
    """Turn 2 với hypothesis-first RAG tool calling. Returns (text, rag_count)."""
    messages = [{"role": "user", "content": prompt + RAG_BLOCK}]
    all_text = ""
    rag_n = 0
    for _ in range(8):  # max turns
        for attempt in range(4):
            try:
                resp = llm.chat.completions.create(
                    model=MODEL, temperature=0.3, max_tokens=4000,
                    messages=messages, tools=RAG_TOOL,
                    extra_body={"google": {"thinking_config": {"thinking_budget": 0}}}
                )
                break
            except Exception as e:
                if '429' in str(e) or 'rate' in str(e).lower():
                    wait = 25 * (attempt + 1)
                    print(f"    [rate {wait}s]", flush=True)
                    time.sleep(wait)
                else:
                    raise
        msg = resp.choices[0].message
        text = _strip(msg.content)
        if text:
            all_text += text + "\n"
        messages.append({"role": "assistant", "content": msg.content,
                          "tool_calls": msg.tool_calls})
        if msg.tool_calls:
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments)
                q = args.get("query", "")
                print(f"      RAG[{rag_n+1}]: '{q[:80]}'", flush=True)
                result = search_rag(q)
                rag_n += 1
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
            time.sleep(4)
            continue
        break
    return all_text, rag_n

def clean_inv(t1: str) -> str:
    lines = [l for l in t1.splitlines() if re.match(r'\s*INV-\d+:', l)]
    return '\n'.join(lines) or t1[:400]

def detect(response: str, fn_names: list) -> dict:
    """Return {fn: True/False} for each target function."""
    results = {}
    for fn in fn_names:
        pattern = rf'FUNCTION:\s*{re.escape(fn)}\b'
        results[fn] = bool(re.search(pattern, response, re.IGNORECASE))
    return results

# ─── Groups ───────────────────────────────────────────────────────────────────

GROUPS = [
    {
        "name": "math_cast",
        "agent_id": "evm_hardener",
        "gt_fns": ["burn", "_getAmountsForLiquidity"],   # H-01, H-05
        "contracts": [
            ("ConcentratedLiquidityPool", SRC_POOL),
        ],
        "fn_names": ["burn", "mint", "_getAmountsForLiquidity", "_updateSecondsPerLiquidity"],
    },
    {
        "name": "clmm_semantic",
        "agent_id": "clmm_specialist",
        "gt_fns": ["rangeFeeGrowth"],                    # H-17
        "contracts": [
            ("ConcentratedLiquidityPool", SRC_POOL),
            ("Ticks", SRC_TICKS),
        ],
        "fn_names": ["rangeFeeGrowth", "cross", "initialize", "insert"],
    },
    {
        "name": "access_reward",
        "agent_id": "access_escalator",
        "gt_fns": ["reclaimIncentive", "claimReward"],   # H-03, H-16
        "contracts": [
            ("ConcentratedLiquidityPoolManager", SRC_MANAGER),
        ],
        "fn_names": ["reclaimIncentive", "claimReward", "subscribe", "addIncentive"],
    },
]

# ─── Output dir ───────────────────────────────────────────────────────────────

OUT_DIR = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/sim_per_group'
os.makedirs(OUT_DIR, exist_ok=True)

# ─── Main ─────────────────────────────────────────────────────────────────────

# Cross-protocol few-shot examples cho single-turn hypothesis-first
CROSS_PROTO_HINT = (
    "\n=== FEW-SHOT EXAMPLES — invariant specificity level required ===\n"
    "When listing invariants in STEP 1, aim for this granularity:\n"
    "  ✓ 'cToken exchange rate read before accrueInterest() called → stale rate in mint'\n"
    "  ✓ 'LP shares burned but pool.reserve0/reserve1 not updated atomically → imbalance'\n"
    "  ✓ 'governance timelock bypassed: proposer == executor → instant execution'\n"
    "  ✓ 'fee recipient deleted from mapping before balance transferred → funds locked'\n"
    "  ✗ 'overflow exists' — too vague, must cite specific variable + cast\n"
    "  ✗ 'reentrancy possible' — must cite exact external call + state written after\n"
)


def run_group_for_condition(grp: dict, condition: str) -> dict:
    """Run one group under a given condition. Returns result dict."""
    profile = profiles_map[grp['agent_id']]

    group_source = build_group_source(grp['contracts'], grp['fn_names'])
    ann_source   = _annotate_source_with_hist_inv(group_source, INV_MAP)
    src_lines    = ann_source.count('\n') + 1

    t0 = time.time()

    if condition == "hist_inv_t1t2":
        # Run 1 config: HIST-INV annotated source, T1 extract, T2 find
        time.sleep(3)
        t1_prompt = build_round1_prompt(profile, ann_source, invariant_only=True)
        t1_resp = llm_call(t1_prompt)
        t1_clean = clean_inv(t1_resp)
        time.sleep(3)
        t2_prompt = build_round1_prompt(profile, ann_source, injected_invariants=t1_clean)
        t2_resp = llm_call(t2_prompt)
        llm_calls = 2
        save_parts = [("TURN 1", t1_resp), ("TURN 2", t2_resp)]
        final_resp = t2_resp

    elif condition == "single_turn_hyp":
        # Single call: STEP 1 + STEP 2 inline — no T1/T2 split
        # Cross-protocol examples injected via step2_hint for granularity
        time.sleep(3)
        prompt = build_round1_prompt(
            profile, ann_source, step2_hint=CROSS_PROTO_HINT)
        t2_resp = llm_call(prompt)
        llm_calls = 1
        save_parts = [("SINGLE TURN (STEP1+STEP2 inline, cross-proto examples)", t2_resp)]
        final_resp = t2_resp

    else:
        raise ValueError(f"Unknown condition: {condition}")

    total_time = time.time() - t0
    detected = detect(final_resp, grp['gt_fns'])

    out = os.path.join(OUT_DIR, f"{grp['name']}_{condition}.txt")
    with open(out, 'w') as f:
        f.write(f"Group: {grp['name']}  Agent: {grp['agent_id']}  Condition: {condition}\n")
        f.write(f"Source lines: {src_lines}  Total: {total_time:.1f}s  LLM calls: {llm_calls}\n")
        f.write(f"GT detected: {detected}\n\n")
        f.write(f"{'='*60}\n=== ANNOTATED GROUP SOURCE ({src_lines} lines) ===\n{ann_source}\n\n")
        for label, text in save_parts:
            f.write(f"{'='*60}\n=== {label} ===\n{text}\n\n")

    return {
        "group": grp['name'],
        "agent": grp['agent_id'],
        "condition": condition,
        "src_lines": src_lines,
        "latency_s": round(total_time, 1),
        "llm_calls": llm_calls,
        "detected": detected,
    }


CONDITIONS_TO_RUN = ["hist_inv_t1t2"]

all_gt = [fn for grp in GROUPS for fn in grp['gt_fns']]

# Load previous Run 1 results if available for comparison
run1_summary_path = os.path.join(OUT_DIR, 'summary_run1.json')
prev_results = {}
if os.path.exists(run1_summary_path):
    for r in json.load(open(run1_summary_path)):
        for fn, found in r['detected'].items():
            prev_results[fn] = found

print('\n' + '='*75)
print('Per-Function-Group Simulation — contest 35')
print('='*75)

summary = []

for cond in CONDITIONS_TO_RUN:
    print(f"\n--- Condition: {cond} ---")
    print(f"{'Group':<16} {'Agent':<20} {'Lines':>6} {'Time':>7}  GT found")
    print('─'*65)
    cond_results = []
    for grp in GROUPS:
        print(f"  [{grp['name']}] running ...", flush=True)
        r = run_group_for_condition(grp, cond)
        found_str = '  '.join(f"{'✅' if v else '❌'} {k}" for k, v in r['detected'].items())
        print(f"  {r['group']:<16} {r['agent']:<20} {r['src_lines']:>6} {r['latency_s']:>7.1f}s  {found_str}")
        cond_results.append(r)
        time.sleep(3)

    tp = sum(1 for r in cond_results for found in r['detected'].values() if found)
    total_lat = sum(r['latency_s'] for r in cond_results)
    total_calls = sum(r['llm_calls'] for r in cond_results)
    print(f"\n  [{cond}] TP={tp}/{len(all_gt)}  time={total_lat:.1f}s  calls={total_calls}")
    summary.extend(cond_results)

# ─── Final comparison ─────────────────────────────────────────────────────────
print(f"\n{'='*75}")
print("CONDITION COMPARISON (from saved runs):")
print(f"{'Condition':<22} {'TP':>4}  {'Time':>7}  {'Calls':>6}")
print('─'*50)

# Print stored results header
stored = {
    "hist_inv_t1t2 (Run1)":     {"tp": 4, "time": "~58s", "calls": 6},
    "no_inv (Run2)":            {"tp": 2, "time": "~17s", "calls": 3},
    "hist_inv+rag (Run3)":      {"tp": 2, "time": "~58s", "calls": 6},
    "hist_inv+hyp_norag (Run4)":{"tp": 2, "time": "48.8s","calls": 6},
}
for name, v in stored.items():
    print(f"  {name:<22} {v['tp']:>4}  {v['time']:>7}  {v['calls']:>6}")

# New run
if summary:
    tp5 = sum(1 for r in summary for found in r['detected'].values() if found)
    t5  = sum(r['latency_s'] for r in summary)
    c5  = sum(r['llm_calls'] for r in summary)
    cond_name = CONDITIONS_TO_RUN[0]
    print(f"  {cond_name + ' (Run5)':<22} {tp5:>4}  {t5:>7.1f}s  {c5:>6}")
    print()
    for r in summary:
        det = '  '.join(f"{'✅' if v else '❌'}{k}" for k, v in r['detected'].items())
        print(f"    {r['group']:<16} {r['latency_s']:>6.1f}s  {det}")

with open(os.path.join(OUT_DIR, 'summary_run5.json'), 'w') as f:
    json.dump(summary, f, indent=2)
print(f"\nOutputs: {OUT_DIR}/")
