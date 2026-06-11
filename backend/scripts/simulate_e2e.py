"""
End-to-end simulation: grouper thực → per-chunk simulation → audit_report.json → eval.

Flow:
  1. Chạy FN_NAME_RULES grouper trên toàn bộ contest source
  2. Với mỗi (domain × contract) chunk chứa GT contracts: build focused source
  3. Chạy 3 agents × T1+T2 HIST-INV (no custom slugs)
  4. Parse FINDING blocks → audit_report.json (eval format)
  5. In hướng dẫn chạy eval

Config: NO custom_* slugs, NO call graph — baseline generic performance.
"""
import sys, os, re, json, time, threading
from collections import defaultdict

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
OUT_DIR = f'/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/{CONTEST_ID}/sim_e2e_v3'
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

# ─── Domain → agents (3 diverse lenses each) ─────────────────────────────────
DOMAIN_AGENTS = {
    'clmm_semantic':  ['clmm_specialist',   'defi_analyst',        'logic_exploiter'],
    'math_cast':      ['math_precision',    'library_auditor',     'invariant_breaker'],
    'access_reward':  ['access_escalator',  'appsec_researcher',   'state_machine_analyst'],
    'economic':       ['defi_attacker',     'flash_loan_specialist','economic_attacker'],
    'state_ordering': ['state_machine_analyst', 'appsec_researcher', 'logic_exploiter'],
    'general':        ['defi_attacker',     'logic_exploiter',     'invariant_breaker'],
}

# ─── Function extractor ───────────────────────────────────────────────────────
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
            fn   = m.group(1)
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
                           'fn_names': fns,
                           'agents': DOMAIN_AGENTS.get(dom, DOMAIN_AGENTS['general'])})
            continue

        chunk_source = build_chunk_source(cname, src, fns, aux)
        chunks.append({
            'domain':         dom,
            'contract_name':  cname,
            'source':         chunk_source,
            'fn_names':       fns,
            'agents':         DOMAIN_AGENTS.get(dom, DOMAIN_AGENTS['general']),
        })
    return chunks

# ─── Profiles ─────────────────────────────────────────────────────────────────
_clp_src = open(os.path.join(
    CONTRACTS_DIR, 'pool/concentrated/ConcentratedLiquidityPool.sol')).read()
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
def run_agent(agent_id: str, ann_source: str, chunk_label: str, agent_idx: int) -> tuple:
    """Returns (t2_text, findings_list)."""
    profile = profiles_map.get(agent_id)
    if not profile:
        print(f"    [WARN] agent {agent_id} not found — skip", flush=True)
        return '', []

    t0 = time.time()
    time.sleep(2 + agent_idx * 3)

    t1_prompt = build_round1_prompt(profile, ann_source, invariant_only=True)
    t1_resp   = llm_call(t1_prompt)
    t1_clean  = clean_inv(t1_resp)
    time.sleep(2)
    t2_prompt = build_round1_prompt(profile, ann_source, injected_invariants=t1_clean)
    t2_resp   = llm_call(t2_prompt)

    total = time.time() - t0
    n_findings = t2_resp.count('FINDING:')
    with _LOCK:
        print(f"    [{chunk_label}/{agent_id}] {total:.1f}s  {n_findings} FINDINGs", flush=True)

    # Save raw output
    out = os.path.join(OUT_DIR, f"{chunk_label.replace('/', '_')}_{agent_id}.txt")
    with open(out, 'w') as f:
        f.write(f"Chunk: {chunk_label}  Agent: {agent_id}  Time: {total:.1f}s\n\n")
        f.write(f"{'='*60}\n=== T1 ===\n{t1_resp}\n\n")
        f.write(f"{'='*60}\n=== T2 ===\n{t2_resp}\n")

    return t2_resp, n_findings

# ─── Run one chunk (3 agents) ─────────────────────────────────────────────────
def run_chunk(chunk: dict) -> list:
    label    = f"{chunk['domain']}/{chunk['contract_name']}"
    ann_src  = _annotate_source_with_hist_inv(chunk['source'], INV_MAP)
    src_lines = ann_src.count('\n') + 1

    print(f"\n{'='*65}")
    print(f"Chunk: {label}  |  {len(chunk['fn_names'])} fns  |  {src_lines} lines", flush=True)

    all_findings = []
    for idx, agent_id in enumerate(chunk['agents']):
        t2_resp, _ = run_agent(agent_id, ann_src, label, idx)
        findings = parse_findings(t2_resp, chunk['contract_name'])
        all_findings.extend(findings)
        if idx < len(chunk['agents']) - 1:
            time.sleep(5)

    # Deduplicate by (contract, function, title) — keep first occurrence
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
print(f'E2E Simulation — Contest {CONTEST_ID}')
print('Grouper: FN_NAME_RULES | Agents: 3/chunk | HIST-INV: no-custom')
print('='*65)

contracts = discover_contracts()
print(f"Contracts discovered: {len(contracts)}")

chunks = build_chunks(contracts)
print(f"\nChunks to simulate ({len(chunks)} total — GT contracts only):")
for c in chunks:
    print(f"  [{c['domain']}] {c['contract_name']}: {c['fn_names']}")

t_start = time.time()
all_findings = []
for chunk in chunks:
    findings = run_chunk(chunk)
    all_findings.extend(findings)
    time.sleep(5)

wall_time = time.time() - t_start

# ─── Save audit_report.json ───────────────────────────────────────────────────
report = {
    "contest_id":  CONTEST_ID,
    "config":      "e2e_grouper_3agents_T1T2_no_custom_no_callgraph",
    "total_findings": len(all_findings),
    "wall_time_s": round(wall_time),
    "findings":    all_findings,
}
report_path = os.path.join(OUT_DIR, f'audit_report_{CONTEST_ID}.json')
json.dump(report, open(report_path, 'w'), indent=2, ensure_ascii=False)

print(f"\n{'='*65}")
print(f"DONE — {len(all_findings)} total findings  |  {wall_time:.0f}s")
print(f"Report: {report_path}")
print(f"\nEval command:")
print(f"  cd backend/scripts/evaluate")
print(f"  python web3bugs_eval.py gt/gt_{CONTEST_ID}.json {report_path} --verbose")
