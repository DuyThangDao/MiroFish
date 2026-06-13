"""
End-to-end simulation: grouper thực → per-chunk simulation → audit_report.json → eval.

Flow:
  1. Chạy FN_NAME_RULES grouper trên toàn bộ contest source
  2. Với mỗi (domain × contract) chunk chứa GT contracts: build focused source
  3. Chạy 3 agents × T1+T2 HIST-INV (no custom slugs)
  4. Parse FINDING blocks → audit_report.json (eval format)
  5. In hướng dẫn chạy eval

Config: NO custom_* slugs, call graph prepended, T2 (standard) + T3 (independent CoT sweep) merged + global dedup (post all chunks).
"""
import sys, os, re, json, time, threading
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

def _make_client(key_file: str, base_url: str) -> OpenAI:
    c = service_account.Credentials.from_service_account_file(
        key_file, scopes=['https://www.googleapis.com/auth/cloud-platform'])
    c.refresh(google.auth.transport.requests.Request())
    return OpenAI(api_key=c.token, base_url=base_url)

KEY_FILE2  = os.getenv('LLM2_VERTEX_AI_KEY_FILE', '')
BASE_URL2  = os.getenv('LLM2_BASE_URL', BASE_URL)
KEY_FILE3  = os.getenv('LLM3_VERTEX_AI_KEY_FILE', '')
BASE_URL3  = os.getenv('LLM3_BASE_URL', BASE_URL)
llm = _make_client(KEY_FILE, BASE_URL)
_extra = []
if KEY_FILE2: _extra.append(_make_client(KEY_FILE2, BASE_URL2))
if KEY_FILE3: _extra.append(_make_client(KEY_FILE3, BASE_URL3))
llm_pool = [llm] + _extra
print(f"[setup] llm_pool = {len(llm_pool)} client(s)")

from app.services.contract_oasis_env import build_round1_prompt
from app.services.contract_profile_generator import ContractExpertProfileGenerator as Gen
from app.services.cyber_session_orchestrator import _annotate_source_with_hist_inv, CyberSessionOrchestrator
from app.services.contract_hist_inv_cache import HistInvCache

# Disable attack_path validation — e2e format không dùng ACTOR/CALL/STATE_CHANGE/OUTCOME
os.environ.setdefault("ATTACK_PATH_VALIDATION", "false")

def _strip(t): return re.sub(r'<think>.*?</think>', '', t or '', flags=re.DOTALL).strip()

# ─── CLI args ─────────────────────────────────────────────────────────────────
import argparse
_parser = argparse.ArgumentParser()
_parser.add_argument('--no-inv', action='store_true', help='Disable HIST-INV injection (pure self-reasoning)')
_parser.add_argument('--workers', type=int, default=1, help='Parallel agents per chunk (default: 1)')
_parser.add_argument('--out-dir', type=str, default='', help='Override output directory')
_args = _parser.parse_args()
NO_INV  = _args.no_inv
WORKERS = _args.workers

# ─── Paths ────────────────────────────────────────────────────────────────────
CONTRACTS_DIR = '/home/thangdd/repos/web3bugs/contracts/35/trident/contracts'
SKIP_DIRS     = {'interfaces', 'test', 'workInProgress', 'flat', 'mocks'}
GT_CONTRACTS  = {
    'ConcentratedLiquidityPool',
    'ConcentratedLiquidityPoolManager',
    'ConcentratedLiquidityPosition',
    'Ticks',
}
CONTEST_ID = '35'
_inv_tag = 'no_inv' if NO_INV else 'with_inv'
_default_out = f'/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/{CONTEST_ID}/sim_e2e_v9_{_inv_tag}_cg_cot_dedup2'
OUT_DIR = _args.out_dir if _args.out_dir else _default_out
os.makedirs(OUT_DIR, exist_ok=True)

# ─── Call graph (from cached kg_result.json run-74) ──────────────────────────
_KG_RESULT_PATH = '/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/35/run-74/kg_result.json'
_context_summary = json.load(open(_KG_RESULT_PATH)).get('context_summary', '')

def _get_call_graph_block(contract_names: list) -> str:
    """Extract CALL GRAPH lines for one or more contracts from context_summary."""
    parts = []
    for cname in contract_names:
        m = re.search(
            rf'\[{re.escape(cname)}\]\n((?:  [^\n]*\n?)*)',
            _context_summary,
        )
        if m:
            parts.append(f"[{cname}]\n{m.group(1).rstrip()}")
    if parts:
        return "CALL GRAPH:\n" + "\n\n".join(parts) + "\n"
    return ""

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

# ─── Domain → agents (3 diverse lenses each) ─────────────────────────────────
DOMAIN_AGENTS = {
    'clmm_semantic':  ['clmm_specialist',   'defi_analyst',        'logic_exploiter'],
    'math_cast':      ['math_precision',    'invariant_breaker',   'logic_exploiter'],
    'access_reward':  ['access_escalator',  'clmm_specialist',     'state_machine_analyst'],
    'economic':       ['defi_attacker',     'flash_loan_specialist','economic_attacker'],
    'state_ordering': ['state_machine_analyst', 'appsec_researcher', 'logic_exploiter'],
    'general':        ['defi_attacker',     'logic_exploiter',     'appsec_hardener'],
}

# ─── Function extractor ───────────────────────────────────────────────────────
FN_RE = re.compile(r'^\s*(?:function\s+(\w+)|constructor)\s*\(', re.MULTILINE)

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
        m = re.match(r'^([ \t]*)(function\s+(\w+)|constructor)\s*[\(\{]', line)
        fn_name = m.group(3) if m and m.group(3) else ('constructor' if m else None)
        if m and fn_name in fn_names:
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
    """Build focused source: header + chunk functions. Optionally append aux contracts."""
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

# ─── Discover all sol files ───────────────────────────────────────────────────
def discover_contracts():
    """Return {contract_name: (path, source)} for non-skip contracts."""
    contracts = {}
    for root, dirs, files in os.walk(CONTRACTS_DIR):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if fname.endswith('.sol'):
                cname = fname.replace('.sol', '')
                path  = os.path.join(root, fname)
                contracts[cname] = (path, open(path).read())
    return contracts

# ─── Group functions per (domain × contract) ──────────────────────────────────
def build_chunks(contracts: dict) -> list:
    """
    Returns list of chunk dicts:
    {domain, contract_name, source, fn_names, agents}
    Only includes chunks for GT_CONTRACTS.
    """
    domain_contract_fns = defaultdict(list)
    for cname, (_, src) in contracts.items():
        if cname not in GT_CONTRACTS:
            continue
        for m in FN_RE.finditer(src):
            fn   = m.group(1) or 'constructor'
            dom  = match_domain(fn)
            domain_contract_fns[(dom, cname)].append(fn)

    chunks = []
    for (dom, cname), fns in sorted(domain_contract_fns.items()):
        _, src = contracts[cname]
        # For clmm_semantic CLP: attach Ticks.sol as aux (cross-contract fee accounting)
        aux = []
        if dom == 'clmm_semantic' and cname == 'ConcentratedLiquidityPool':
            if 'Ticks' in contracts:
                aux = [('Ticks', contracts['Ticks'][1])]
        # For math_cast CLPosition: attach CLP as aux (calls into pool)
        if dom == 'math_cast' and cname == 'ConcentratedLiquidityPosition':
            if 'ConcentratedLiquidityPool' in contracts:
                aux = [('ConcentratedLiquidityPool', contracts['ConcentratedLiquidityPool'][1])]
        # For general CLPosition: attach CLP as aux (collect/burn cross-contract interaction)
        if dom == 'general' and cname == 'ConcentratedLiquidityPosition':
            if 'ConcentratedLiquidityPool' in contracts:
                aux = [('ConcentratedLiquidityPool', contracts['ConcentratedLiquidityPool'][1])]
        # For general Ticks: use full Ticks source (small file)
        if dom == 'general' and cname == 'Ticks':
            src_full = src
            chunks.append({'domain': dom, 'contract_name': cname,
                           'source': f"// ─── {cname}.sol ─────────────────────────────────────────────────\n{src_full}",
                           'fn_names': fns, 'aux_names': [],
                           'agents': DOMAIN_AGENTS.get(dom, DOMAIN_AGENTS['general'])})
            continue

        chunk_source = build_chunk_source(cname, src, fns, aux)
        chunks.append({
            'domain':         dom,
            'contract_name':  cname,
            'source':         chunk_source,
            'fn_names':       fns,
            'aux_names':      [(a_name, None) for a_name, _ in aux],
            'agents':         DOMAIN_AGENTS.get(dom, DOMAIN_AGENTS['general']),
        })
    return chunks

# ─── Profiles ─────────────────────────────────────────────────────────────────
_clp_src = open(os.path.join(
    CONTRACTS_DIR, 'pool/concentrated/ConcentratedLiquidityPool.sol')).read()
gen = Gen()
profiles_map = {p.agent_id: p for p in gen.generate_tier1_profiles(_clp_src)}

# ─── Orchestrator (for pipeline dedup) ───────────────────────────────────────
_orch = CyberSessionOrchestrator()

_MD_FENCE_RE   = re.compile(r'```[a-z]*\n?(.*?)```', re.DOTALL)
_FILENAME_RE   = re.compile(r'^\([^\)]+\.sol\)\s*', re.IGNORECASE)

def _clean_anchor(anchor: str) -> str:
    """Strip markdown fences and filename prefixes agents add in CoT output."""
    if not anchor:
        return anchor
    # Extract code inside ```solidity ... ``` if present
    m = _MD_FENCE_RE.search(anchor)
    if m:
        anchor = m.group(1).strip()
    # Strip leading (ContractName.sol) prefix
    anchor = _FILENAME_RE.sub('', anchor).strip()
    # Strip surrounding backticks from inline code
    anchor = anchor.strip('`').strip()
    return anchor

def dedup_pipeline(findings: list, full_source: str) -> list:
    """Apply main pipeline dedup using full GT source (not chunk-only source).

    Steps (mirror main pipeline):
      1. _dedup_pre_r2  — CODE_ANCHOR substring check against full source
      2. _static_anchor_dedup — exact anchor merge
      3. _llm_anchor_dedup   — LLM semantic merge
    """
    if not findings:
        return findings
    # Clean code_anchor before dedup — T3 CoT agents wrap in markdown fences/filename prefix
    for f in findings:
        f['code_anchor'] = _clean_anchor(f.get('code_anchor', ''))
    pool = {
        f"f_{i:04d}": {
            "contract_name":    f.get("contract_name", ""),
            "function_name":    f.get("function_name", ""),
            "title":            f.get("title", ""),
            "code_anchor":      f.get("code_anchor", ""),
            "evidence_snippets": [f["evidence"]] if f.get("evidence") else [],
            "attack_path":      f.get("attack_path", ""),
            "submitters":       [],
            "description":      f.get("description", ""),
        }
        for i, f in enumerate(findings)
    }
    n0 = len(pool)
    pool = _orch._dedup_pre_r2(pool, full_source)               # CODE_ANCHOR check (full source)
    pool = _orch._semi_static_anchor_dedup(pool, full_source)   # semi-static: LLM verifies before merge
    pool = _orch._llm_anchor_dedup(pool, full_source)           # semantic merge by function
    print(f"      [dedup] {n0} → pre_r2={len(pool)} → final={len(pool)}", flush=True)
    return list(pool.values())

# ─── LLM ──────────────────────────────────────────────────────────────────────
_LOCK = threading.Lock()

def llm_call(prompt: str, client=None) -> str:
    _client = client or llm
    for attempt in range(5):
        try:
            resp = _client.chat.completions.create(
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

# ─── T3: Chain-of-thought independent sweep ───────────────────────────────────
_T3_COT_BLOCK = """\
=== ROUND 1 — PHASE C: CHAIN-OF-THOUGHT VERIFICATION SWEEP ===
You are {agent_id} ({persona}).
{system_prompt}

CONTRACT UNDER REVIEW:
{source}

=== TASK ===
Perform an independent structured reasoning sweep over every function in the source.
Do NOT reference any prior findings — this is a fresh, independent scan.

For each function that contains a suspicious operation, write a TRACE block:

TRACE [{{function_name}}]:
  OP: <the specific operation being examined>
  CHAIN: <step-by-step: what values flow in → what computation → what state changes>
  INVARIANT: <what property should hold here?>
  VERDICT: BUG | SAFE | UNCLEAR

After completing ALL TRACE blocks, write FINDING blocks ONLY for functions where VERDICT=BUG.
Use the same FINDING format:

FINDING: <title>
CONTRACT: <name>
FUNCTION: <name>
SEVERITY: high | medium | low
DESCRIPTION: <detailed explanation>
CODE_ANCHOR: <copy the EXACT line verbatim from the source code above — no paraphrasing, no markdown fences, no filename prefix>
ATTACK_PATH: <how an attacker exploits this>

IMPORTANT — FUNCTION attribution rule:
If the vulnerable line is inside a PRIVATE or INTERNAL helper function that is called by the function you are tracing (e.g. `_getAmountsForLiquidity`, `_updateFees`, `_computeReward`), set FUNCTION to the PRIVATE HELPER's name — not the public caller. The FUNCTION field must name the function that contains the actual vulnerable line.
"""

# ─── FINDING parser ───────────────────────────────────────────────────────────
_FINDING_RE = re.compile(
    r'FINDING:\s*(.+?)\n'
    r'(?:.*?CONTRACT:\s*(\w+)\n)?'
    r'(?:.*?FUNCTION:\s*(\w+)\b.*?\n)?'
    r'(?:.*?SEVERITY:\s*(\w+)\n)?'
    r'(?:.*?DESCRIPTION:\s*([\s\S]*?))?'
    r'(?=FINDING:|ANALYZED:|$)',
    re.IGNORECASE | re.DOTALL,
)

_FIELD_RE = re.compile(
    r'^(CONTRACT|FUNCTION|SEVERITY|CODE_ANCHOR|EVIDENCE|ATTACK_PATH|'
    r'ACTOR|CALL|STATE_CHANGE|OUTCOME|DESCRIPTION|PATCH):\s*',
    re.IGNORECASE | re.MULTILINE,
)

def parse_findings(text: str, default_contract: str) -> list:
    """Parse FINDING blocks from T2 text into list of finding dicts."""
    findings = []
    # Split on FINDING: boundaries
    parts = re.split(r'\nFINDING:', '\n' + text)
    for part in parts[1:]:  # skip everything before first FINDING
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

        # Normalize field names for eval
        finding = {
            'title':         fields.get('title', ''),
            'description':   fields.get('description', '') or fields.get('outcome', ''),
            'attack_path':   fields.get('attack_path', '') or fields.get('call', ''),
            'contract_name': fields.get('contract', '') or fields.get('contract_name', default_contract),
            'function_name': fields.get('function', '') or fields.get('function_name', ''),
            'severity':      fields.get('severity', 'medium'),
            'code_anchor':   fields.get('code_anchor', ''),
            'evidence':      fields.get('evidence', ''),
        }
        if finding['title']:
            findings.append(finding)
    return findings

# ─── Run one agent on one chunk ────────────────────────────────────────────────
def run_agent(agent_id: str, ann_source: str, chunk_label: str, agent_idx: int,
              contract_name: str, client=None) -> tuple:
    """Returns (t2_findings, t3_findings)."""
    profile = profiles_map.get(agent_id)
    if not profile:
        print(f"    [WARN] agent {agent_id} not found — skip", flush=True)
        return [], []

    t0 = time.time()
    stagger = agent_idx * 2 if WORKERS > 1 else 2 + agent_idx * 3
    time.sleep(stagger)

    # T1: invariant extraction
    t1_prompt = build_round1_prompt(profile, ann_source, invariant_only=True)
    t1_resp   = llm_call(t1_prompt, client)
    t1_clean  = clean_inv(t1_resp)
    time.sleep(2)

    # T2: standard finding discovery
    t2_prompt = build_round1_prompt(profile, ann_source, injected_invariants=t1_clean)
    t2_resp   = llm_call(t2_prompt, client)
    t2_findings = parse_findings(t2_resp, contract_name)
    time.sleep(2)

    # T3: independent CoT sweep (fresh, no T2 findings injected)
    t3_prompt = _T3_COT_BLOCK.format(
        agent_id=agent_id,
        persona=profile.persona,
        system_prompt=profile.system_prompt,
        source=ann_source,
    )
    t3_resp     = llm_call(t3_prompt, client)
    t3_findings = parse_findings(t3_resp, contract_name)

    total = time.time() - t0
    n2, n3 = len(t2_findings), len(t3_findings)
    with _LOCK:
        print(f"    [{chunk_label}/{agent_id}] {total:.1f}s  T2={n2} T3={n3} FINDINGs", flush=True)

    # Save raw output
    out = os.path.join(OUT_DIR, f"{chunk_label.replace('/', '_')}_{agent_id}.txt")
    with open(out, 'w') as f:
        f.write(f"Chunk: {chunk_label}  Agent: {agent_id}  Time: {total:.1f}s\n\n")
        f.write(f"{'='*60}\n=== T1 ===\n{t1_resp}\n\n")
        f.write(f"{'='*60}\n=== T2 (standard) ===\n{t2_resp}\n\n")
        f.write(f"{'='*60}\n=== T3 (CoT sweep) ===\n{t3_resp}\n")

    return t2_findings, t3_findings

# ─── Run one chunk (3 agents) ─────────────────────────────────────────────────
def run_chunk(chunk: dict) -> list:
    label    = f"{chunk['domain']}/{chunk['contract_name']}"
    base_src  = chunk['source'] if NO_INV else _annotate_source_with_hist_inv(chunk['source'], INV_MAP)
    # Prepend call graph for this contract (+ aux contracts if present)
    cg_contracts = [chunk['contract_name']] + [a for a, _ in chunk.get('aux_names', [])]
    cg_block = _get_call_graph_block(cg_contracts)
    ann_src  = (cg_block + "\n" + base_src) if cg_block else base_src
    src_lines = ann_src.count('\n') + 1
    mode_str  = 'no_inv' if NO_INV else 'with_inv'

    print(f"\n{'='*65}")
    print(f"Chunk: {label}  |  {len(chunk['fn_names'])} fns  |  {src_lines} lines  [{mode_str}]", flush=True)

    all_findings = []
    cname = chunk['contract_name']
    if WORKERS > 1:
        with ThreadPoolExecutor(max_workers=WORKERS) as exe:
            futs = {
                exe.submit(run_agent, agent_id, ann_src, label, idx, cname,
                           llm_pool[idx % len(llm_pool)]): agent_id
                for idx, agent_id in enumerate(chunk['agents'])
            }
            for fut in as_completed(futs):
                t2_f, t3_f = fut.result()
                all_findings.extend(t2_f)
                all_findings.extend(t3_f)
    else:
        for idx, agent_id in enumerate(chunk['agents']):
            t2_f, t3_f = run_agent(agent_id, ann_src, label, idx, cname)
            all_findings.extend(t2_f)
            all_findings.extend(t3_f)
            if idx < len(chunk['agents']) - 1:
                time.sleep(5)

    print(f"  → {len(all_findings)} raw findings", flush=True)
    return all_findings

# ─── Main ─────────────────────────────────────────────────────────────────────
print('\n' + '='*65)
print(f'E2E Simulation — Contest {CONTEST_ID}')
inv_mode = 'DISABLED (pure self-reasoning)' if NO_INV else 'no-custom slugs'
print(f'Grouper: FN_NAME_RULES | Agents: 3/chunk | HIST-INV: {inv_mode} | T2+T3 (CoT)')
print('='*65)

contracts = discover_contracts()
print(f"Contracts discovered: {len(contracts)}")

# Full GT source for dedup CODE_ANCHOR check (covers cross-contract references)
FULL_GT_SOURCE = "\n\n".join(
    src for cname, (_, src) in contracts.items() if cname in GT_CONTRACTS
)

chunks = build_chunks(contracts)
print(f"\nChunks to simulate ({len(chunks)} total — GT contracts only):")
for c in chunks:
    print(f"  [{c['domain']}] {c['contract_name']}: {c['fn_names']}")

t_start = time.time()
all_raw = []
for chunk in chunks:
    all_raw.extend(run_chunk(chunk))
    time.sleep(5)

# Global dedup trên toàn bộ findings (cross-chunk duplicates được xử lý đúng)
print(f"\n{'='*65}")
print(f"Global dedup: {len(all_raw)} raw findings across all chunks")
all_deduped = dedup_pipeline(all_raw, FULL_GT_SOURCE)
print(f"Global dedup result: {len(all_raw)} → {len(all_deduped)}")

wall_time = time.time() - t_start

# ─── Save 2 reports ───────────────────────────────────────────────────────────
def _save_report(findings, tag, config_note):
    report = {
        "contest_id":     CONTEST_ID,
        "config":         config_note,
        "total_findings": len(findings),
        "wall_time_s":    round(wall_time),
        "findings":       findings,
    }
    path = os.path.join(OUT_DIR, f'audit_report_{CONTEST_ID}_{tag}.json')
    json.dump(report, open(path, 'w'), indent=2, ensure_ascii=False)
    return path

raw_path    = _save_report(all_raw,     "raw",    "T2+T3_merged_no_dedup")
dedup_path  = _save_report(all_deduped, "deduped","T2+T3_pipeline_dedup")

print(f"\n{'='*65}")
print(f"DONE — raw={len(all_raw)}  deduped={len(all_deduped)}  |  {wall_time:.0f}s")
print(f"Raw report:    {raw_path}")
print(f"Deduped report:{dedup_path}")
print(f"\nEval commands:")
print(f"  cd backend/scripts/evaluate")
print(f"  python web3bugs_eval.py gt/gt_{CONTEST_ID}.json {raw_path} --verbose")
print(f"  python web3bugs_eval.py gt/gt_{CONTEST_ID}.json {dedup_path} --verbose")
