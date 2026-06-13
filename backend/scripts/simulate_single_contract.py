"""
Chạy simulation cho 1 contract cụ thể — cùng cơ chế simulate_e2e.py.

Usage:
  python scripts/simulate_single_contract.py <ContractName> [contest_id]

Examples:
  python scripts/simulate_single_contract.py ConcentratedLiquidityPool 35
  python scripts/simulate_single_contract.py Ticks 35
  python scripts/simulate_single_contract.py ConcentratedLiquidityPosition 35
"""
import sys, os, re, json, time, threading, argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

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

# ─── CoT TRACE block — injected into T2 for math_precision only ──────────────
_MATH_COT_BLOCK = """\
=== CAST & ARITHMETIC TRACE (REQUIRED) ===
For EVERY cast or arithmetic operation that could overflow/underflow, write a TRACE block BEFORE your FINDING:

TRACE [{function}]:
  OP: <exact operation, e.g. "int256(uint256(_liquidity))" or "balanceOf - reserve0">
  TYPE_CHAIN: <trace each step with the maximum possible value at each conversion>
    e.g., "_liquidity: uint128(max=2^128-1) → uint256(ok, same value) → int256(OVERFLOW if val > 2^255-1)"
  UNCHECKED: <yes / no — is this inside an `unchecked` block?>
  ATTACKER_CONTROL: <can an attacker choose this input value? how?>
  VERDICT: EXPLOITABLE | SAFE | UNCLEAR

Rules:
- Only write a FINDING for TRACE blocks where VERDICT=EXPLOITABLE.
- For signed/unsigned conversions (int256↔uint256): check if value can exceed target type's max.
- For unchecked subtractions: check if minuend can be smaller than subtrahend.
- Skip TRACE for literals and provably-bounded constants.
"""

# ─── Hypothesis-first block (injected into T2 for no_inv+hyp mode) ────────────
_HYP_BLOCK = """\
=== HYPOTHESIS-FIRST RULES ===
Before writing any FINDING, you MUST state a specific mechanism hypothesis with code evidence.

RULE: For each suspected invariant violation, explicitly write:
  HYPOTHESIS: [what breaks mechanically]
  CODE_EVIDENCE: [exact variable/line/pattern you observed]

Good hypothesis examples (cross-protocol):
  "cToken exchange rate read before accrueInterest called, stale rate used in mint"
  "LP shares burned but pool reserves not updated atomically, imbalance possible"
  "governance timelock bypassed when proposer is also executor, instant execution"
  "fee recipient mapping deleted but balance not transferred first, funds locked"
  "reward balance not reset before transfer, caller can drain repeatedly"
  "global debt accumulator not updated after individual borrow, principal desync"

Bad (do NOT write these):
  "vulnerability in transfer()" — names a function, no mechanism
  "reentrancy bug" — names a category, no specific code evidence
  "unsafe cast" — no specific location or impact chain

Only AFTER stating hypothesis + code evidence → write the FINDING block.
If you cannot articulate a specific mechanism yet, re-read the code first.
"""

# ─── CLI args ─────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument('contract', help='Contract name to simulate (e.g. ConcentratedLiquidityPool)')
parser.add_argument('contest_id', nargs='?', default='35', help='Contest ID (default: 35)')
parser.add_argument('--no-inv', action='store_true', help='Disable HIST-INV injection (pure self-reasoning)')
parser.add_argument('--merge-both', action='store_true', help='Run with_inv then no_inv sequentially, merge findings')
parser.add_argument('--workers', type=int, default=1, help='Parallel agents per chunk (default: 1)')
parser.add_argument('--hyp', action='store_true', help='Use hypothesis-first RAG for no_inv mode')
parser.add_argument('--contracts-dir', help='Override contracts directory path')
args = parser.parse_args()

TARGET_CONTRACT = args.contract
CONTEST_ID      = args.contest_id
NO_INV          = args.no_inv
MERGE_BOTH      = args.merge_both
WORKERS         = args.workers
HYP             = args.hyp

# ─── Paths ────────────────────────────────────────────────────────────────────
CONTRACTS_DIR = args.contracts_dir or f'/home/thangdd/repos/web3bugs/contracts/{CONTEST_ID}/trident/contracts'
SKIP_DIRS     = {'interfaces', 'test', 'workInProgress', 'flat', 'mocks'}
GT_CONTRACTS  = {
    'ConcentratedLiquidityPool',
    'ConcentratedLiquidityPoolManager',
    'ConcentratedLiquidityPosition',
    'Ticks',
}
if MERGE_BOTH:
    _inv_tag = 'merged_hyp' if HYP else 'merged'
elif NO_INV:
    _inv_tag = 'no_inv_hyp' if HYP else 'no_inv'
else:
    _inv_tag = 'with_inv'
OUT_DIR = f'/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/{CONTEST_ID}/sim_single_{TARGET_CONTRACT}_{_inv_tag}'
os.makedirs(OUT_DIR, exist_ok=True)

# ─── HIST-INV (no custom) ─────────────────────────────────────────────────────
_CACHE_PATH = f'/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/{CONTEST_ID}/hist_inv_cache.json'
_RAG_CACHE  = '/home/thangdd/repos/MiroFish/backend/scripts/rag/rag_sections_cache.json'

hc = HistInvCache(_CACHE_PATH)
matched_slugs = hc.get_matched_slugs()
rag_cache = json.load(open(_RAG_CACHE))
inv_lookup = {
    f['slug']: (f.get('sections') or {}).get('inv') or []
    for f in rag_cache.get('findings', [])
}

def build_inv_map_no_custom():
    inv_map = {}
    for (contract, fn), slugs in matched_slugs.items():
        filtered = [s for s in slugs if not s.startswith('custom_')]
        inv_lines = []
        for slug in filtered[:4]:
            inv_lines.extend((inv_lookup.get(slug) or [])[:2])
        if inv_lines:
            inv_map[(contract, fn)] = "\n".join(inv_lines[:4])
    return inv_map

INV_MAP = build_inv_map_no_custom()
print(f"[INV_MAP] {len(INV_MAP)} functions annotated (no custom slugs)")

# ─── Domain rules ─────────────────────────────────────────────────────────────
FN_NAME_RULES = [
    (r'\btick\b|range.?fee|fee.?growth|nearest.?tick|sqrt.?ratio|'
     r'seconds.?per|range.?seconds|get.?price.?and',               'clmm_semantic'),
    (r'\bburn\b|\bmint\b|\bswap\b|flash.?swap|'
     r'get.?amount|amount.?for|get.?amounts|'
     r'_update.?position|_update.?fees|_update.?seconds|'
     r'_get.?amounts|_compute.?liquidity|get.?reserves|'
     r'add.?liquidity|remove.?liquidity|liquidity.?delta',          'math_cast'),
    (r'\bclaim\b|reward|reclaim|subscribe|distribute|'
     r'add.?incentive|remove.?incentive|get.?reward|get.?incentive|'
     r'stake\b|unstake',                                            'access_reward'),
    (r'flash(?!swap)|oracle|twap|get.?price|update.?price|arbitrage', 'economic'),
    (r'initialize|callback|settle|\bsync\b|deploy.?pool|'
     r'create.?pool|create.?position',                              'state_ordering'),
]

def match_domain(fn_name: str) -> str:
    n = fn_name.lower()
    for pattern, domain in FN_NAME_RULES:
        if re.search(pattern, n, re.IGNORECASE):
            return domain
    return 'general'

# ─── Domain → agents ──────────────────────────────────────────────────────────
DOMAIN_AGENTS = {
    'clmm_semantic':  ['clmm_specialist',   'defi_analyst',        'logic_exploiter'],
    'math_cast':      ['math_precision',    'invariant_breaker',   'logic_exploiter'],
    'access_reward':  ['access_escalator',  'appsec_researcher',   'state_machine_analyst'],
    'economic':       ['defi_attacker',     'flash_loan_specialist','economic_attacker'],
    'state_ordering': ['state_machine_analyst', 'appsec_researcher', 'logic_exploiter'],
    'general':        ['defi_attacker',     'logic_exploiter',     'appsec_hardener'],
}

FN_RE = re.compile(r'^\s*function\s+(\w+)\s*\(', re.MULTILINE)

def extract_contract_header(source: str) -> str:
    lines = source.split('\n')
    result, depth, in_contract, skip_fn = [], 0, False, False
    for line in lines:
        stripped = line.strip()
        opens, closes = line.count('{'), line.count('}')
        if not in_contract:
            result.append(line)
            if re.match(r'^(contract|abstract contract|library)\s+\w+', stripped):
                in_contract = True
                depth += opens - closes
            continue
        if re.match(r'(function|modifier|constructor|receive|fallback)\s*[\w(]', stripped):
            skip_fn = True
        if skip_fn:
            depth += opens - closes
            if depth <= 1:
                skip_fn = False
                depth = max(depth, 1)
            continue
        result.append(line)
        depth += opens - closes
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
            while i < len(lines) and (depth > 0 or (fn_lines[-1].strip() == '')):
                fn_lines.append(lines[i])
                depth += lines[i].count('{') - lines[i].count('}')
                i += 1
            result.extend(fn_lines)
            result.append('')
        else:
            i += 1
    return '\n'.join(result)

def build_chunk_source(contract_name: str, source: str, fn_names: list,
                       aux_contracts: list = None) -> str:
    header = extract_contract_header(source)
    fns    = extract_functions(source, fn_names)
    parts  = [
        f"// ─── {contract_name}.sol ─────────────────────────────────────────────────",
        header.rstrip(),
        "    // ... (other functions omitted)",
        fns,
        "}",
    ]
    if aux_contracts:
        for aux_name, aux_src in aux_contracts:
            parts.append(f"\n// ─── {aux_name}.sol (auxiliary) ─────────────────────")
            parts.append(aux_src)
    return '\n'.join(parts)

def discover_contracts():
    contracts = {}
    for root, dirs, files in os.walk(CONTRACTS_DIR):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if fname.endswith('.sol'):
                cname = fname.replace('.sol', '')
                path  = os.path.join(root, fname)
                contracts[cname] = (path, open(path).read())
    return contracts

def build_chunks(contracts: dict, target: str) -> list:
    domain_contract_fns = defaultdict(list)
    for cname, (_, src) in contracts.items():
        if cname != target:
            continue
        for m in FN_RE.finditer(src):
            fn  = m.group(1)
            dom = match_domain(fn)
            domain_contract_fns[(dom, cname)].append(fn)

    chunks = []
    for (dom, cname), fns in sorted(domain_contract_fns.items()):
        _, src = contracts[cname]
        aux = []
        if dom == 'clmm_semantic' and cname == 'ConcentratedLiquidityPool':
            if 'Ticks' in contracts:
                aux = [('Ticks', contracts['Ticks'][1])]
        if dom == 'math_cast' and cname == 'ConcentratedLiquidityPosition':
            if 'ConcentratedLiquidityPool' in contracts:
                aux = [('ConcentratedLiquidityPool', contracts['ConcentratedLiquidityPool'][1])]
        if dom == 'general' and cname == 'ConcentratedLiquidityPosition':
            if 'ConcentratedLiquidityPool' in contracts:
                aux = [('ConcentratedLiquidityPool', contracts['ConcentratedLiquidityPool'][1])]
        if dom == 'general' and cname == 'Ticks':
            _, src_full = contracts[cname]
            chunks.append({'domain': dom, 'contract_name': cname,
                           'source': f"// ─── {cname}.sol ─────────────────────────────────────────────────\n{src_full}",
                           'fn_names': fns,
                           'agents': DOMAIN_AGENTS.get(dom, DOMAIN_AGENTS['general'])})
            continue

        chunk_source = build_chunk_source(cname, src, fns, aux)
        chunks.append({
            'domain':        dom,
            'contract_name': cname,
            'source':        chunk_source,
            'fn_names':      fns,
            'agents':        DOMAIN_AGENTS.get(dom, DOMAIN_AGENTS['general']),
        })
    return chunks

# ─── Profiles ─────────────────────────────────────────────────────────────────
# Use target contract source for profile generation; fall back to CLP for contest 35
_profile_src_path = os.path.join(CONTRACTS_DIR, 'pool/concentrated/ConcentratedLiquidityPool.sol')
if not os.path.exists(_profile_src_path):
    # Find any .sol file in CONTRACTS_DIR to use as profile seed
    _sol_files = [f for f in os.listdir(CONTRACTS_DIR) if f.endswith('.sol')]
    _profile_src_path = os.path.join(CONTRACTS_DIR, _sol_files[0]) if _sol_files else None
_clp_src = open(_profile_src_path).read() if _profile_src_path else ""
gen = Gen()
profiles_map = {p.agent_id: p for p in gen.generate_tier1_profiles(_clp_src)}

# ─── LLM ──────────────────────────────────────────────────────────────────────
_LOCK = threading.Lock()

def llm_call(prompt: str) -> str:
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
                with _LOCK: print(f"    [rate {wait}s]", flush=True)
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("LLM failed")

def clean_inv(t1: str) -> str:
    lines = [l for l in t1.splitlines() if re.match(r'\s*INV-\d+:', l)]
    return '\n'.join(lines) or t1[:400]

_FIELD_RE = re.compile(
    r'^(CONTRACT|FUNCTION|SEVERITY|CODE_ANCHOR|EVIDENCE|ATTACK_PATH|'
    r'ACTOR|CALL|STATE_CHANGE|OUTCOME|DESCRIPTION|PATCH):\s*',
    re.IGNORECASE | re.MULTILINE,
)

def parse_findings(text: str, default_contract: str) -> list:
    findings = []
    parts = re.split(r'\nFINDING:', '\n' + text)
    for part in parts[1:]:
        lines = part.strip().split('\n')
        title = lines[0].strip()
        fields = {'title': title, 'contract_name': default_contract,
                  'function_name': '', 'severity': 'medium',
                  'description': '', 'attack_path': '', 'code_anchor': ''}
        current_field = None
        buf = []
        for line in lines[1:]:
            m = _FIELD_RE.match(line)
            if m:
                if current_field and buf:
                    fields[current_field.lower()] = '\n'.join(buf).strip()
                current_field = m.group(1).upper()
                val = line[m.end():].strip()
                buf = [val] if val else []
            elif current_field:
                buf.append(line)
        if current_field and buf:
            fields[current_field.lower()] = '\n'.join(buf).strip()

        fn_raw = fields.get('function', '') or fields.get('function_name', '')
        fn_clean = re.sub(r'\s*[\(\[].*', '', fn_raw).strip().rstrip('()')

        finding = {
            'title':         fields.get('title', ''),
            'description':   fields.get('description', '') or fields.get('outcome', ''),
            'attack_path':   fields.get('attack_path', '') or fields.get('call', ''),
            'contract_name': fields.get('contract', '') or fields.get('contract_name', default_contract),
            'function_name': fn_clean,
            'severity':      fields.get('severity', 'medium'),
            'code_anchor':   fields.get('code_anchor', ''),
            'evidence':      fields.get('evidence', ''),
        }
        if finding['title']:
            findings.append(finding)
    return findings

def run_agent(agent_id: str, ann_source: str, chunk_label: str, agent_idx: int,
              mode_suffix: str = '', use_hyp: bool = False) -> tuple:
    profile = profiles_map.get(agent_id)
    if not profile:
        print(f"    [WARN] agent {agent_id} not found — skip", flush=True)
        return '', []

    t0 = time.time()
    # Smaller stagger for parallel mode to avoid rate-limit bursts
    stagger = agent_idx * 2 if WORKERS > 1 else 2 + agent_idx * 3
    time.sleep(stagger)

    t1_prompt = build_round1_prompt(profile, ann_source, invariant_only=True)
    t1_resp   = llm_call(t1_prompt)
    t1_clean  = clean_inv(t1_resp)
    time.sleep(2)
    if use_hyp:
        _hint = _HYP_BLOCK
    else:
        _hint = ""
    t2_prompt = build_round1_prompt(
        profile, ann_source,
        injected_invariants=t1_clean,
        step2_hint=_hint,
    )
    t2_resp   = llm_call(t2_prompt)

    total = time.time() - t0
    n_findings = t2_resp.count('FINDING:')
    with _LOCK:
        print(f"    [{chunk_label}/{agent_id}] {total:.1f}s  {n_findings} FINDINGs", flush=True)

    out = os.path.join(OUT_DIR, f"{chunk_label.replace('/', '_')}_{agent_id}{mode_suffix}.txt")
    with open(out, 'w') as f:
        f.write(f"Chunk: {chunk_label}  Agent: {agent_id}  Time: {total:.1f}s\n\n")
        f.write(f"{'='*60}\n=== T1 ===\n{t1_resp}\n\n")
        f.write(f"{'='*60}\n=== T2 ===\n{t2_resp}\n")

    return t2_resp, n_findings

def run_chunk(chunk: dict, no_inv_override: bool = None, mode_suffix: str = '') -> list:
    use_no_inv = no_inv_override if no_inv_override is not None else NO_INV
    label    = f"{chunk['domain']}/{chunk['contract_name']}"
    ann_src  = chunk['source'] if use_no_inv else _annotate_source_with_hist_inv(chunk['source'], INV_MAP)
    src_lines = ann_src.count('\n') + 1
    mode_str  = 'no_inv' if use_no_inv else 'with_inv'

    print(f"\n{'='*65}")
    print(f"Chunk: {label}  |  {len(chunk['fn_names'])} fns  |  {src_lines} lines  [{mode_str}]", flush=True)

    _use_hyp = HYP and use_no_inv  # hypothesis-first only for no_inv mode

    all_findings = []
    if WORKERS > 1:
        with ThreadPoolExecutor(max_workers=WORKERS) as exe:
            futs = {
                exe.submit(run_agent, agent_id, ann_src, label, idx, mode_suffix, _use_hyp): agent_id
                for idx, agent_id in enumerate(chunk['agents'])
            }
            for fut in as_completed(futs):
                t2_resp, _ = fut.result()
                all_findings.extend(parse_findings(t2_resp, chunk['contract_name']))
    else:
        for idx, agent_id in enumerate(chunk['agents']):
            t2_resp, _ = run_agent(agent_id, ann_src, label, idx, mode_suffix, _use_hyp)
            all_findings.extend(parse_findings(t2_resp, chunk['contract_name']))
            if idx < len(chunk['agents']) - 1:
                time.sleep(5)

    seen, deduped = set(), []
    for f in all_findings:
        key = (f['contract_name'].lower(), f['function_name'].lower(), f['title'][:40].lower())
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    print(f"  → {len(all_findings)} raw findings  |  {len(deduped)} after dedup", flush=True)
    return deduped

# ─── Main ─────────────────────────────────────────────────────────────────────
print('\n' + '='*65)
print(f'Single-Contract Simulation — {TARGET_CONTRACT} (contest {CONTEST_ID})')
inv_mode = ('DISABLED + hypothesis-first' if (NO_INV and HYP)
            else 'DISABLED (pure self-reasoning)' if NO_INV
            else 'no-custom slugs')
print(f'Grouper: FN_NAME_RULES | Agents: 3/chunk | HIST-INV: {inv_mode}')
print('='*65)

contracts = discover_contracts()
if TARGET_CONTRACT not in contracts:
    print(f"ERROR: contract '{TARGET_CONTRACT}' not found. Available:")
    for c in sorted(contracts): print(f"  {c}")
    sys.exit(1)

chunks = build_chunks(contracts, TARGET_CONTRACT)
print(f"\nChunks for {TARGET_CONTRACT} ({len(chunks)} total):")
for c in chunks:
    print(f"  [{c['domain']}] {c['fn_names']}")

t_start = time.time()
all_findings = []

if MERGE_BOTH:
    print('\n' + '─'*65)
    print(f'[MERGE-BOTH] Phase 1: with_inv  (workers={WORKERS})')
    print('─'*65)
    with_inv_findings = []
    for chunk in chunks:
        findings = run_chunk(chunk, no_inv_override=False, mode_suffix='_with_inv')
        with_inv_findings.extend(findings)
        time.sleep(5)

    print('\n' + '─'*65)
    print(f'[MERGE-BOTH] Phase 2: no_inv  (workers={WORKERS})')
    print('─'*65)
    no_inv_findings = []
    for chunk in chunks:
        findings = run_chunk(chunk, no_inv_override=True, mode_suffix='_no_inv')
        no_inv_findings.extend(findings)
        time.sleep(5)

    # Merge + dedup across both modes
    seen, merged = set(), []
    for f in with_inv_findings + no_inv_findings:
        key = (f['contract_name'].lower(), f['function_name'].lower(), f['title'][:40].lower())
        if key not in seen:
            seen.add(key)
            merged.append(f)
    all_findings = merged
    print(f"\n[MERGE-BOTH] with_inv={len(with_inv_findings)} + no_inv={len(no_inv_findings)} → merged={len(all_findings)}")
else:
    for chunk in chunks:
        findings = run_chunk(chunk)
        all_findings.extend(findings)
        time.sleep(5)

wall_time = time.time() - t_start

report = {
    "contest_id":      CONTEST_ID,
    "target_contract": TARGET_CONTRACT,
    "config":          f"single_contract_3agents_T1T2_{_inv_tag}_workers{WORKERS}",
    "total_findings":  len(all_findings),
    "wall_time_s":     round(wall_time),
    "findings":        all_findings,
}
report_path = os.path.join(OUT_DIR, f'audit_report_{CONTEST_ID}.json')
json.dump(report, open(report_path, 'w'), indent=2, ensure_ascii=False)

print(f"\n{'='*65}")
print(f"DONE — {len(all_findings)} total findings  |  {wall_time:.0f}s")
print(f"Report: {report_path}")
print(f"\nEval command:")
print(f"  cd backend/scripts/evaluate")
print(f"  python web3bugs_eval.py gt/gt_{CONTEST_ID}.json {report_path} --verbose")
