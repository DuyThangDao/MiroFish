"""
End-to-end simulation: contest-agnostic — per-chunk simulation → audit_report.json → eval.

Usage:
  python scripts/simulate_e2e.py \
    --contest-id 35 \
    --contracts-dir /path/to/contracts \
    --gt-contracts ContractA ContractB ... \
    [--kg-result /path/to/kg_result.json] \
    [--primary-contract /path/to/Primary.sol] \
    [--cache-path /path/to/hist_inv_cache.json] \
    [--no-inv] [--workers N] [--out-dir /path]

Flow:
  1. Chạy FN_NAME_RULES grouper trên toàn bộ contest source
  2. Với mỗi (domain × contract) chunk chứa GT contracts: build focused source
  3. Chạy 3-4 agents × T1+T2 HIST-INV + T3 CoT sweep
  4. Parse FINDING blocks → audit_report.json (eval format)
  5. In hướng dẫn chạy eval
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

from openai import OpenAI
from app.utils.llm_client import _build_vertex_ai_http_client

def _make_client(key_file: str, base_url: str) -> OpenAI:
    """Dùng _build_vertex_ai_http_client — token tự refresh trước mỗi request."""
    http_client = _build_vertex_ai_http_client(key_file)
    return OpenAI(api_key="vertex-ai", base_url=base_url,
                  http_client=http_client, max_retries=0)

KEY_FILE2  = os.getenv('LLM2_VERTEX_AI_KEY_FILE', '')
BASE_URL2  = os.getenv('LLM2_BASE_URL', BASE_URL)
KEY_FILE3  = os.getenv('LLM3_VERTEX_AI_KEY_FILE', '')
BASE_URL3  = os.getenv('LLM3_BASE_URL', BASE_URL)
KEY_FILE4  = os.getenv('LLM4_VERTEX_AI_KEY_FILE', '')
BASE_URL4  = os.getenv('LLM4_BASE_URL', BASE_URL)
KEY_FILE5  = os.getenv('LLM5_VERTEX_AI_KEY_FILE', '')
BASE_URL5  = os.getenv('LLM5_BASE_URL', BASE_URL)
llm = _make_client(KEY_FILE, BASE_URL)
_extra = []
if KEY_FILE2: _extra.append(_make_client(KEY_FILE2, BASE_URL2))
if KEY_FILE3: _extra.append(_make_client(KEY_FILE3, BASE_URL3))
if KEY_FILE4: _extra.append(_make_client(KEY_FILE4, BASE_URL4))
if KEY_FILE5: _extra.append(_make_client(KEY_FILE5, BASE_URL5))
llm_pool = [llm] + _extra
_pool_idx = {id(c): i for i, c in enumerate(llm_pool)}  # client id → key index for logging
print(f"[setup] llm_pool = {len(llm_pool)} client(s)")

from app.services.contract_oasis_env import build_round1_prompt, build_t3_prompt
from app.services.contract_profile_generator import ContractExpertProfileGenerator as Gen
from app.services.cyber_session_orchestrator import _annotate_source_with_hist_inv, CyberSessionOrchestrator
from app.services.contract_hist_inv_cache import HistInvCache
from app.services.contract_kg_builder import ContractKGBuilder
from scripts.flatten_contest import flatten_contest_dir

# Disable attack_path validation — e2e format không dùng ACTOR/CALL/STATE_CHANGE/OUTCOME
os.environ.setdefault("ATTACK_PATH_VALIDATION", "false")

def _strip(t): return re.sub(r'<think>.*?</think>', '', t or '', flags=re.DOTALL).strip()

# ─── CLI args ─────────────────────────────────────────────────────────────────
import argparse
_parser = argparse.ArgumentParser(description='Contest-agnostic e2e simulation')
_parser.add_argument('--contest-id',        required=True,  help='Contest ID, e.g. 35, 42, 5')
_parser.add_argument('--contest-dir',       default='',     help='Full contest directory for KG build (e.g. web3bugs/contracts/42). If omitted, falls back to --contracts-dir.')
_parser.add_argument('--contracts-dir',     required=True,  help='Path to contracts root directory (for agent scanning)')
_parser.add_argument('--gt-contracts',      nargs='+', required=True, help='GT contract names (without .sol)')
_parser.add_argument('--kg-result',         default='',     help='Path to kg_result.json for call graph (optional)')
_parser.add_argument('--primary-contract',  default='',     help='Path to primary .sol for agent profile generation (optional; auto-detect if omitted)')
_parser.add_argument('--cache-path',        default='',     help='Override hist_inv_cache.json path')
_parser.add_argument('--no-inv',   action='store_true',     help='Disable HIST-INV injection (pure self-reasoning)')
_parser.add_argument('--workers',  type=int, default=1,     help='Global parallel workers across all chunks (default: 1)')
_parser.add_argument('--dedup',        action='store_true',  help='Run per-chunk dedup after all agents of a chunk complete')
_parser.add_argument('--out-dir',      default='',           help='Override output directory')
_parser.add_argument('--single-agent', default='',           help='If set, every chunk runs with exactly this one agent (ablation mode)')
_parser.add_argument('--rt',            action='store_true',  help='Enable red-team (RT) attacker agents (disabled by default)')
_parser.add_argument('--max-fns-per-chunk', type=int, default=0, help='Max functions per (domain×contract) chunk; 0=no limit (default: 0)')
_parser.add_argument('--full-aux',     action='store_true',  help='Include full aux contract source instead of only directly-called functions')
_args = _parser.parse_args()

CONTEST_ID    = _args.contest_id
CONTRACTS_DIR = _args.contracts_dir
CONTEST_DIR   = _args.contest_dir or _args.contracts_dir
GT_CONTRACTS  = set(_args.gt_contracts)
NO_INV        = _args.no_inv
WORKERS       = _args.workers
DEDUP_ENABLED = _args.dedup
SINGLE_AGENT  = _args.single_agent.strip() or None
NO_RT             = not _args.rt
MAX_FNS_PER_CHUNK = _args.max_fns_per_chunk  # 0 = no limit
FULL_AUX          = _args.full_aux
SKIP_DIRS     = {'interfaces', 'test', 'workInProgress', 'flat', 'mocks', 'mock', 'node_modules', 'artifacts'}

_inv_tag     = 'no_inv' if NO_INV else 'with_inv'
_BENCH_DIR   = os.path.join(os.path.dirname(__file__), '../../benchmark/web3bugs/agent-redesign', CONTEST_ID)
_default_out = os.path.join(_BENCH_DIR, f'sim_e2e_v10_{_inv_tag}_cg_cot_dedup2')
OUT_DIR      = _args.out_dir if _args.out_dir else _default_out
os.makedirs(OUT_DIR, exist_ok=True)

# ─── Call graph ───────────────────────────────────────────────────────────────
# Priority: --kg-result file → auto-saved kg_result_auto.json → full KG pipeline
_context_summary = ''
_KG_AUTO_PATH = os.path.join(_BENCH_DIR, 'kg_result_auto.json')

def _load_kg_from_file(path: str) -> str:
    return json.load(open(path)).get('context_summary', '')

def _build_kg_pipeline(contracts: dict) -> str:
    """Build KG using main pipeline flatten logic when --contest-dir is given,
    otherwise fall back to simple concat of --contracts-dir files.

    Result saved to kg_result_auto.json for reuse on subsequent runs.
    """
    if _args.contest_dir and os.path.isdir(_args.contest_dir):
        print(f"[kg] flattening full contest dir: {_args.contest_dir}", flush=True)
        result = flatten_contest_dir(_args.contest_dir, verbose=True, emit_manifest=True)
        source_code, manifest = result if isinstance(result, tuple) else (result, {})
        combined_source = manifest.get('in_scope_source') or source_code
        print(f"[kg] flatten done — {len(combined_source):,} chars (in_scope)", flush=True)
    else:
        parts = []
        for cname in sorted(contracts):
            _, src = contracts[cname]
            parts.append(f"// ─── {cname}.sol ────────────────────────────────────────────────────")
            parts.append(src)
        combined_source = "\n".join(parts)
        print(f"[kg] building KG from --contracts-dir: {len(contracts)} contracts, {len(combined_source):,} chars", flush=True)

    kg_builder = ContractKGBuilder()
    print(f"[kg] submitting to KG builder...", flush=True)
    task_id = kg_builder.build_from_source_async(
        source_code=combined_source,
        graph_name=f"Contest {CONTEST_ID} Audit",
        contract_name=CONTEST_ID,
    )

    deadline = time.monotonic() + 3600
    last_pct  = -1
    while time.monotonic() < deadline:
        task = kg_builder.task_manager.get_task(task_id)
        if not task:
            print("[kg] task disappeared — call graph disabled", flush=True)
            return ''
        pct = task.progress or 0
        if pct != last_pct:
            print(f"[kg] {pct}% — {task.message or ''}", flush=True)
            last_pct = pct
        if task.status.value == 'completed':
            result = task.result or {}
            ctx = result.get('context_summary', '')
            print(f"[kg] done — context_summary {len(ctx):,} chars", flush=True)
            # Save for reuse
            result['_source'] = 'kg_result_auto'
            json.dump(result, open(_KG_AUTO_PATH, 'w'), indent=2, ensure_ascii=False)
            print(f"[kg] saved → {_KG_AUTO_PATH}", flush=True)
            return ctx
        elif task.status.value in ('failed', 'error'):
            print(f"[kg] build failed: {task.error} — call graph disabled", flush=True)
            return ''
        time.sleep(5)

    print("[kg] timeout — call graph disabled", flush=True)
    return ''

if _args.kg_result and os.path.exists(_args.kg_result):
    _context_summary = _load_kg_from_file(_args.kg_result)
    print(f"[kg] loaded from --kg-result: {_args.kg_result}")
elif os.path.exists(_KG_AUTO_PATH):
    _context_summary = _load_kg_from_file(_KG_AUTO_PATH)
    print(f"[kg] loaded from auto-saved: {_KG_AUTO_PATH}")
# else: built after discover_contracts() below — need source files first

def _get_call_graph_block(contract_names: list) -> str:
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

# ─── HIST-INV ─────────────────────────────────────────────────────────────────
_CACHE_PATH = _args.cache_path if _args.cache_path else \
    os.path.join(_BENCH_DIR, 'hist_inv_cache.json')
_RAG_CACHE  = os.path.join(os.path.dirname(__file__), 'rag/rag_sections_cache.json')

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
    # LP position lifecycle (mint/burn) — arithmetic + economic + temporal perspectives needed
    (r'\bburn\b|\bmint\b|add.?liquidity|remove.?liquidity',         'liquidity_mutation'),
    (r'\bswap|flash.?swap|'
     r'get\w*amount|amount.?for|get.?amounts|'
     r'_update.?position|_update.?fees|_update.?seconds|'
     r'_get.?amounts|_compute.?liquidity|get.?reserves|'
     r'liquidity.?delta|'
     r'\bcalc',                                                      'math_cast'),
    (r'\bclaim\b|reward|reclaim|subscribe|distribute|'
     r'add.?incentive|remove.?incentive|get.?reward|get.?incentive|'
     r'stake\b|unstake|'
     r'deposit|harvest|withdraw',                                    'access_reward'),
    (r'flash(?!swap)|oracle|twap|get.?price|update.?price|arbitrage|'
     r'buyback|buy[A-Z]|sell[A-Z]|lock(?:crv|token|lp)|vecrvlock|'
     r'swap(?:exact|token|eth)|add.?liquidity.*uni',                'economic'),
    (r'initialize|\binit\b|callback|settle|\bsync\b|deploy.?pool|'
     r'create.?pool|create.?position',                              'state_ordering'),
    (r'\bchange[A-Z]\w*|\bset(?:impl|contract|owner|governance|minter|treasury|'
     r'engine|vault|nft|address|operator|role|controller)\b|'
     r'\bmigrate\b|\bupgrade\b|transferOwn|renounceOwn|'
     r'proposal|votes?|curate|\blist[A-Z]|lock.?unit|unlock.?unit|exclu', 'admin_gov'),
]

def match_domain(fn_name: str) -> str:
    n = fn_name.lower()
    for pattern, domain in FN_NAME_RULES:
        if re.search(pattern, n, re.IGNORECASE):
            return domain
    return 'general'

# ─── Domain → agents (persona-based, domain expertise not pattern-matching) ──
DOMAIN_AGENTS = {
    # CLMM tick/fee semantic functions — math-heavy + logic
    'clmm_semantic':  ['quant_analyst',        'invariant_mathematician', 'program_logician',      'state_analyst',
                       'boundary_analyst',     'data_provenance_analyst',
                       'arithmetic_exploiter'],
    # LP position lifecycle (mint/burn) — arithmetic + economic + temporal
    'liquidity_mutation': ['quant_analyst',        'numerical_analyst',      'invariant_mathematician', 'evm_safety_expert',
                           'token_flow_expert',    'accounting_auditor',     'boundary_analyst',
                           'data_provenance_analyst', 'overflow_safety_expert', 'entry_point_hardener',
                           'economic_exploiter',   'temporal_attack_specialist', 'defi_security_researcher',
                           'arithmetic_exploiter'],
    # Arithmetic/computation functions (swap/calc/amounts) — math + accounting
    'math_cast':      ['quant_analyst',        'numerical_analyst',      'invariant_mathematician', 'evm_safety_expert',
                       'token_flow_expert',    'accounting_auditor',     'boundary_analyst',
                       'data_provenance_analyst', 'resource_exhaustion_analyst',
                       'overflow_safety_expert', 'entry_point_hardener',
                       'arithmetic_exploiter'],
    # Reward/claim/deposit functions — asset accounting + economic
    'access_reward':  ['token_flow_expert',    'accounting_auditor',     'asset_security_expert',
                       'defi_security_researcher', 'economic_exploiter', 'temporal_attack_specialist',
                       'authorization_boundary_analyst', 'protocol_state_machine_auditor',
                       'flash_loan_attacker',  'trusted_insider'],
    # Oracle/economic/flash functions — economic + integration
    'economic':       ['defi_security_researcher', 'economic_exploiter', 'protocol_economist',    'oracle_security_expert',
                       'temporal_attack_specialist',
                       'flash_loan_attacker',  'timing_manipulator'],
    # Initialize/callback/create functions — state + integration
    'state_ordering': ['program_logician',     'state_analyst',          'execution_tracer',      'integration_auditor',
                       'entry_point_hardener', 'data_provenance_analyst', 'callback_specialist',
                       'state_hijacker'],
    # Admin/setter functions — access control + state
    'admin_gov':      ['threat_modeler',       'state_analyst',          'program_logician',
                       'entry_point_hardener', 'authorization_boundary_analyst', 'absent_guard_detector',
                       'protocol_state_machine_auditor',
                       'trusted_insider'],
    # Fallback — broad coverage across all domains
    'general':        ['program_logician',     'state_analyst',          'execution_tracer',
                       'quant_analyst',        'defi_security_researcher', 'token_flow_expert',
                       'integration_auditor',  'entry_point_hardener',  'authorization_boundary_analyst',
                       'absent_guard_detector', 'protocol_state_machine_auditor',
                       'state_hijacker',       'trusted_insider'],
}

# Agent IDs that produce 'RT' findings (adversarial attacker profiles)
_RED_TEAM_AGENT_IDS = {
    'arithmetic_exploiter', 'flash_loan_attacker', 'state_hijacker',
    'timing_manipulator',   'trusted_insider',
}

# ─── Modifier inline expansion ────────────────────────────────────────────────
def _extract_modifiers(source: str) -> dict:
    mods = {}
    for m in re.finditer(r'\bmodifier\s+(\w+)\s*(?:\([^)]*\))?\s*\{', source, re.MULTILINE):
        name = m.group(1)
        depth, i = 1, m.end()
        while i < len(source) and depth > 0:
            if source[i] == '{':
                depth += 1
            elif source[i] == '}':
                depth -= 1
            i += 1
        mods[name] = source[m.end():i - 1].strip()
    return mods


def _inject_modifier_comments(fn_source: str, modifiers: dict) -> str:
    if not modifiers:
        return fn_source
    lines = fn_source.split('\n')
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r'^\s*(?:function\s+\w+|constructor)\s*[\(\{]', line):
            sig, j = line, i + 1
            while j < len(lines) and '{' not in sig:
                sig += ' ' + lines[j].strip()
                j += 1
            used = [n for n in modifiers if re.search(r'\b' + re.escape(n) + r'\b', sig)]
            if used:
                indent = re.match(r'^(\s*)', line).group(1)
                for name in used:
                    body_lines = modifiers[name].replace('\n', ' ').split(';')
                    summary = '; '.join(bl.strip() for bl in body_lines if bl.strip())[:300]
                    out.append(f"{indent}// [MODIFIER {name}]: {summary}")
        out.append(line)
        i += 1
    return '\n'.join(out)


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

def _extract_called_fns(primary_src: str, aux_src: str) -> list:
    """Return function names defined in aux_src that are directly called in primary_src."""
    aux_fns = re.findall(r'\bfunction\s+(\w+)\s*[\(\{]', aux_src)
    return [fn for fn in aux_fns if re.search(rf'\b{re.escape(fn)}\s*\(', primary_src)]

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
                       aux_contracts: list = None, full_aux: bool = False) -> str:
    modifiers = _extract_modifiers(source)
    header = extract_contract_header(source)
    fns    = extract_functions(source, fn_names)
    fns    = _inject_modifier_comments(fns, modifiers)
    parts  = [
        f"// ─── {contract_name}.sol ─────────────────────────────────────────────────",
        header.rstrip(),
        "    // ... (other functions omitted)",
        fns,
        "}",
    ]
    if aux_contracts:
        for aux_name, aux_src in aux_contracts:
            if full_aux:
                parts.append(f"\n// ─── {aux_name}.sol (auxiliary — full source) ─────────")
                parts.append(aux_src)
            else:
                called = _extract_called_fns(fns, aux_src)
                aux_header = extract_contract_header(aux_src)
                parts.append(f"\n// ─── {aux_name}.sol (auxiliary — called fns: {called or 'none'}) ─────────")
                parts.append(aux_header.rstrip())
                if called:
                    parts.append("    // ... (other functions omitted)")
                    parts.append(extract_functions(aux_src, called))
                parts.append("}")
    return '\n'.join(parts)

# ─── Discover all sol files ───────────────────────────────────────────────────
def discover_contracts():
    contracts = {}
    for root, dirs, files in os.walk(CONTRACTS_DIR):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if fname.endswith('.sol'):
                cname = fname.replace('.sol', '')
                path  = os.path.join(root, fname)
                contracts[cname] = (path, open(path, errors='replace').read())

    # Fallback: find GT contracts missing from contracts_dir by searching contest_dir
    missing_gt = GT_CONTRACTS - set(contracts.keys())
    if missing_gt and CONTEST_DIR != CONTRACTS_DIR:
        for root, dirs, files in os.walk(CONTEST_DIR):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                cname = fname.replace('.sol', '')
                if cname in missing_gt and cname not in contracts:
                    path = os.path.join(root, fname)
                    contracts[cname] = (path, open(path, errors='replace').read())
                    print(f'[discover] GT contract outside contracts_dir: {cname} → {path}')

    return contracts

# ─── Auto-detect aux contracts via import analysis ────────────────────────────
_IMPORT_RE = re.compile(r'import\s+[^;]+;', re.MULTILINE)
_PATH_RE   = re.compile(r'["\']([^"\']+\.sol)["\']')

def build_aux_map(contracts: dict, gt: set) -> dict:
    """Return {cname: [dep_cname, ...]} for every GT contract.

    Resolves both direct imports (Ticks.sol → Ticks) and interface imports
    (IConcentratedLiquidityPool.sol → ConcentratedLiquidityPool via I-prefix strip).
    """
    result = {}
    for cname in gt:
        if cname not in contracts:
            continue
        _, src = contracts[cname]
        deps = []
        for m in _IMPORT_RE.finditer(src):
            for path_str in _PATH_RE.findall(m.group(0)):
                imported = os.path.basename(path_str).replace('.sol', '')
                # Direct match
                if imported in gt and imported != cname:
                    if imported not in deps:
                        deps.append(imported)
                # Interface heuristic: IName → Name
                elif imported.startswith('I') and imported[1:] in gt and imported[1:] != cname:
                    if imported[1:] not in deps:
                        deps.append(imported[1:])
        result[cname] = deps
    return result

# ─── Fix E: parent contract source injection ──────────────────────────────────
_INHERIT_RE = re.compile(
    r'(?:abstract\s+)?contract\s+\w+\s+is\s+([^{]+)\{'
)

def _find_parent_sources(cname: str, contracts: dict, exclude: set = None) -> list:
    """Return [(parent_name, parent_src)] for implementation parents in the same dir.

    Guards applied:
      - Same directory as target contract (no cross-dir parents)
      - Not inside an interfaces/ path component
      - Not a pure interface declaration
      - File < 200 lines (excludes large ERC721 base classes like TridentNFT)
      - Not already in GT_CONTRACTS or exclude set
    """
    if cname not in contracts:
        return []
    filepath, src = contracts[cname]
    contract_dir = os.path.normpath(os.path.dirname(filepath))
    exclude = (exclude or set()) | GT_CONTRACTS

    parent_names = []
    for m in _INHERIT_RE.finditer(src):
        for p in re.split(r'\s*,\s*', m.group(1).strip()):
            p = p.strip()
            if p and p not in parent_names:
                parent_names.append(p)

    result = []
    for pname in parent_names:
        if pname in exclude:
            continue
        if pname not in contracts:
            continue
        p_filepath, p_src = contracts[pname]
        # Must be in the same directory
        if os.path.normpath(os.path.dirname(p_filepath)) != contract_dir:
            continue
        # Skip if path contains an interfaces/ component
        if 'interfaces' in p_filepath.replace('\\', '/').split('/'):
            continue
        # Skip pure interface declarations
        if re.search(r'^\s*interface\s+\w+', p_src, re.MULTILINE):
            continue
        # Size guard: < 200 lines
        if p_src.count('\n') + 1 >= 200:
            continue
        result.append((pname, p_src))
    return result


# ─── Group functions per (domain × contract) ──────────────────────────────────
def build_chunks(contracts: dict, aux_map: dict) -> list:
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

        # Aux contracts from import analysis (cross-contract context)
        aux = [(dep, contracts[dep][1]) for dep in aux_map.get(cname, []) if dep in contracts]

        # Fix E: parent contracts in same dir (not interfaces, not GT, < 200 lines)
        aux_names_set = {name for name, _ in aux}
        parents = _find_parent_sources(cname, contracts, exclude=aux_names_set)
        if parents:
            print(f"[Fix E] {cname}: injecting parent source(s): {[p for p,_ in parents]}")

        all_aux = aux + parents

        # Split fns into sub-chunks of at most MAX_FNS_PER_CHUNK (0 = no limit)
        if MAX_FNS_PER_CHUNK > 0 and len(fns) > MAX_FNS_PER_CHUNK:
            fn_groups = [fns[i:i + MAX_FNS_PER_CHUNK] for i in range(0, len(fns), MAX_FNS_PER_CHUNK)]
        else:
            fn_groups = [fns]

        n_groups = len(fn_groups)
        for grp_idx, grp_fns in enumerate(fn_groups):
            sub_label = f" ({grp_idx+1}/{n_groups})" if n_groups > 1 else ""

            # Small contract with no cross-contract deps: include full source (only when single group)
            if not aux and len(src) < 30_000 and not aux_map.get(cname) and n_groups == 1:
                full_src = f"// ─── {cname}.sol ─────────────────────────────────────────────────\n{src}"
                for pname, psrc in parents:
                    full_src += f"\n\n// ─── {pname}.sol (parent) ─────────────────────────────────────────\n{psrc}"
                _agents = [SINGLE_AGENT] if SINGLE_AGENT else DOMAIN_AGENTS.get(dom, DOMAIN_AGENTS['general'])
                chunks.append({
                    'domain':        dom,
                    'contract_name': cname,
                    'source':        full_src,
                    'fn_names':      grp_fns,
                    'aux_names':     [(pname, None) for pname, _ in parents],
                    'agents':        _agents,
                    'sub_label':     sub_label,
                })
                continue

            # Function-extraction mode
            chunk_source = build_chunk_source(cname, src, grp_fns, all_aux or None, full_aux=FULL_AUX)
            _agents = [SINGLE_AGENT] if SINGLE_AGENT else DOMAIN_AGENTS.get(dom, DOMAIN_AGENTS['general'])
            chunks.append({
                'domain':        dom,
                'contract_name': cname,
                'source':        chunk_source,
                'fn_names':      grp_fns,
                'aux_names':     [(a_name, None) for a_name, _ in all_aux],
                'agents':        _agents,
                'sub_label':     sub_label,
            })

    return chunks

# ─── Profiles (auto-detect primary contract if not specified) ─────────────────
def _find_primary_src(contracts: dict) -> str:
    if _args.primary_contract and os.path.exists(_args.primary_contract):
        return open(_args.primary_contract, errors='replace').read()
    # Auto-detect: first GT contract found (alphabetical)
    for cname in sorted(GT_CONTRACTS):
        if cname in contracts:
            print(f"[profiles] auto-detected primary contract: {cname}")
            return contracts[cname][1]
    raise RuntimeError(f"No GT contract found in {CONTRACTS_DIR} from {GT_CONTRACTS}")

# ─── Orchestrator (for pipeline dedup) ───────────────────────────────────────
_orch = CyberSessionOrchestrator()

_MD_FENCE_RE   = re.compile(r'```[a-z]*\n?(.*?)```', re.DOTALL)
_FILENAME_RE   = re.compile(r'^\([^\)]+\.sol\)\s*', re.IGNORECASE)

def _clean_anchor(anchor: str) -> str:
    if not anchor:
        return anchor
    m = _MD_FENCE_RE.search(anchor)
    if m:
        anchor = m.group(1).strip()
    anchor = _FILENAME_RE.sub('', anchor).strip()
    anchor = anchor.strip('`').strip()
    return anchor

def dedup_pipeline(findings: list, full_source: str) -> list:
    if not findings:
        return findings
    for f in findings:
        f['code_anchor'] = _clean_anchor(f.get('code_anchor', ''))
    pool = {
        f"f_{i:04d}": {
            "contract_name":     f.get("contract_name", ""),
            "function_name":     f.get("function_name", ""),
            "title":             f.get("title", ""),
            "code_anchor":       f.get("code_anchor", ""),
            "evidence_snippets": [f["evidence"]] if f.get("evidence") else [],
            "attack_path":       f.get("attack_path", ""),
            "submitters":        [],
            "description":       f.get("description", ""),
            "agent_id":          f.get("agent_id", ""),
            "source":            f.get("source", ""),
        }
        for i, f in enumerate(findings)
    }
    n0 = len(pool)
    pool = _orch._dedup_pre_r2(pool, full_source)
    pool = _orch._semi_static_anchor_dedup(pool, full_source)
    pool = _orch._llm_anchor_dedup(pool, full_source)
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
            msg = resp.choices[0].message if resp.choices else None
            content = msg.content if msg is not None else None
            if content is None:
                wait = 30 * (attempt + 1)
                with _LOCK: print(f"    [empty response, retry {attempt+1}/5, wait {wait}s]", flush=True)
                time.sleep(wait)
                continue
            return _strip(content)
        except Exception as e:
            err_str = str(e).lower()
            is_rate   = '429' in str(e) or 'rate' in err_str
            is_conn   = any(k in err_str for k in ('connection', 'timeout', 'connect error', 'read error', 'network'))
            if is_rate or is_conn:
                wait = 15 * (attempt + 1) if is_conn else 30 * (attempt + 1)
                key_idx = _pool_idx.get(id(_client), '?')
                tag = 'conn' if is_conn else 'rate'
                with _LOCK: print(f"    [{tag} retry {attempt+1}/5, wait {wait}s key={key_idx}]", flush=True)
                time.sleep(wait)
            else:
                raise
    return ""

def clean_inv(t1: str) -> str:
    lines = [l for l in t1.splitlines() if re.match(r'\s*INV-\d+:', l)]
    return '\n'.join(lines) or t1[:400]

# ─── T3: Chain-of-thought independent sweep ───────────────────────────────────
# ─── Red-team attack flow (RT1 → RT2 → RT3) ─────────────────────────────────
# Thay thế T1→T2→T3 cho attacker agents: mindset là adversary, không phải defender.

_RT1_SURFACE_BLOCK = """\
=== ATTACK SURFACE INVENTORY ===
You are {agent_id} ({persona}).
{system_prompt}

{focus_directive}
CONTRACT UNDER REVIEW:
{source}

=== TASK ===
You are an attacker scanning for entry points — NOT an auditor looking for violations.
Do NOT ask "what should hold?" Ask "what can I control, and what breaks when I abuse it?"

For each TARGET function, enumerate attack surfaces:

SURFACE [{{function_name}}]:
  INPUT: <parameter or calldata you control as an external caller>
  WORST_CASE: <value you would choose to maximize harm — zero, max, your own address, etc.>
  ASSUMPTION_BROKEN: <what does the developer assume about this input that you can violate?>
  PRE_STATE: <any on-chain state you can manipulate BEFORE calling this function>
  CALLBACKS: <any external call inside this function you could intercept or replace>

Be exhaustive. A missed surface here means a missed exploit later.
If a function has no external-facing attack surface worth noting, write: SURFACE [function]: NONE
"""

_RT2_EXPLOIT_BLOCK = """\
=== EXPLOIT CONSTRUCTION ===
You are {agent_id} ({persona}).
{system_prompt}

{focus_directive}
CONTRACT UNDER REVIEW:
{source}

=== ATTACK SURFACES (from prior scan) ===
{rt1_surfaces}

=== TASK ===
For each attack surface above, determine whether it enables a real exploit.
Target outcomes: theft of tokens/ETH, permanent DoS, privilege escalation,
state corruption that benefits you at the expense of others.

Discard surfaces that lead nowhere. For surfaces that DO produce an exploit:

FINDING: <title>
CONTRACT: <name>
FUNCTION: <name>
SEVERITY: high | medium | low
DESCRIPTION: <what the developer assumed; what you do instead; the resulting harm>
CODE_ANCHOR: <copy the EXACT vulnerable line verbatim from the source — no paraphrasing>
ATTACK_PATH: <concrete sequence: caller → function(args) → intermediate state → final outcome>
"""

_RT3_BACKWARD_BLOCK = """\
=== ADVERSARIAL BACKWARD TRACE ===
You are {agent_id} ({persona}).
{system_prompt}

{focus_directive}
CONTRACT UNDER REVIEW:
{source}

=== TASK ===
Independent sweep — do NOT reference any prior findings. Fresh adversarial eyes only.

For each TARGET function: assume you already have a profitable outcome (drained tokens,
bypassed a check, permanent DoS). Work BACKWARD — what sequence of calls and inputs
would produce it?

ATTACK_TRACE [{{function_name}}]:
  GOAL: <profitable outcome you want>
  PRECONDITION: <state that must exist before your first call>
  SEQUENCE: <call 1 with inputs → result; call 2 with inputs → result; ...>
  OUTCOME: <what you gain>
  FEASIBILITY: EXPLOIT | PARTIAL | INFEASIBLE

After ALL ATTACK_TRACE blocks, write FINDING blocks ONLY for EXPLOIT traces:

FINDING: <title>
CONTRACT: <name>
FUNCTION: <name>
SEVERITY: high | medium | low
DESCRIPTION: <detailed explanation>
CODE_ANCHOR: <copy the EXACT vulnerable line verbatim from the source>
ATTACK_PATH: <how an attacker exploits this>

IMPORTANT — FUNCTION attribution rule:
If the vulnerable line is inside a private/internal helper called by the traced function,
set FUNCTION to the helper's name — not the public caller.
"""

_T3_COT_BLOCK = """\
=== ROUND 1 — PHASE C: CHAIN-OF-THOUGHT VERIFICATION SWEEP ===
You are {agent_id} ({persona}).
{system_prompt}

{focus_directive}
CONTRACT UNDER REVIEW:
{source}

=== TASK ===
Perform an independent structured reasoning sweep over the TARGET functions listed above.
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
_FIELD_RE = re.compile(
    r'^(CONTRACT|FUNCTION|SEVERITY|CODE_ANCHOR|EVIDENCE|ATTACK_PATH|'
    r'ACTOR|CALL|STATE_CHANGE|OUTCOME|DESCRIPTION|PATCH):\s*',
    re.IGNORECASE | re.MULTILINE,
)

def _filter_to_chunk_contract(findings: list, chunk_contract: str,
                               aux_contracts: list = None) -> list:
    """Drop findings whose contract_name is not the primary contract or an aux contract.
    Prevents agents from hallucinating findings about external contracts they only
    see referenced via interface calls (e.g. DAO() calls inside Router.sol).
    Aux contracts (explicitly included in source) are allowed.
    """
    allowed = {chunk_contract.lower()}
    for a in (aux_contracts or []):
        allowed.add(a.lower())
    out, dropped = [], 0
    for f in findings:
        cn = (f.get('contract_name') or '').strip()
        if not cn or cn.lower() in allowed:
            out.append(f)
        else:
            dropped += 1
    if dropped:
        import logging as _log
        _log.getLogger(__name__).info(
            f"[contract_filter] dropped {dropped} findings for non-chunk contracts "
            f"(allowed={sorted(allowed)})"
        )
    return out


def parse_findings(text: str, default_contract: str, source: str = 'T2') -> list:
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

        finding = {
            'title':         fields.get('title', ''),
            'description':   fields.get('description', '') or fields.get('outcome', ''),
            'attack_path':   fields.get('attack_path', '') or fields.get('call', ''),
            'contract_name': fields.get('contract', '') or fields.get('contract_name', default_contract),
            'function_name': fields.get('function', '') or fields.get('function_name', ''),
            'severity':      fields.get('severity', 'medium'),
            'code_anchor':   fields.get('code_anchor', ''),
            'evidence':      fields.get('evidence', ''),
            'source':        source,
        }
        if finding['title']:
            findings.append(finding)
    return findings

# ─── Run one agent on one chunk ────────────────────────────────────────────────
def run_agent(agent_id: str, ann_source: str, chunk_label: str, agent_idx: int,
              contract_name: str, profiles_map: dict, client=None,
              aux_contracts: list = None, fn_names: list = None) -> tuple:
    """Returns (t2_findings, t3_findings)."""
    out = os.path.join(OUT_DIR, f"{chunk_label.replace('/', '_')}_{agent_id}.txt")

    # Resume: nếu file đã có → parse lại, không gọi LLM
    if os.path.exists(out):
        text = open(out).read()
        if agent_id in _RED_TEAM_AGENT_IDS:
            r2_m = re.search(r'=== RT2 \(exploit\) ===\n(.*?)(?====)', text, re.DOTALL)
            r3_m = re.search(r'=== RT3 \(backward trace\) ===\n(.*?)$', text, re.DOTALL)
            t2_f = _filter_to_chunk_contract(parse_findings(r2_m.group(1) if r2_m else '', contract_name, source='RT'), contract_name, aux_contracts)
            t3_f = _filter_to_chunk_contract(parse_findings(r3_m.group(1) if r3_m else '', contract_name, source='T3'), contract_name, aux_contracts)
        else:
            t2_m = re.search(r'=== T2 \(standard\) ===\n(.*?)(?====)', text, re.DOTALL)
            t3_m = re.search(r'=== T3 \(CoT sweep\) ===\n(.*?)$',      text, re.DOTALL)
            t2_f = _filter_to_chunk_contract(parse_findings(t2_m.group(1) if t2_m else '', contract_name, source='T2'), contract_name, aux_contracts)
            t3_f = _filter_to_chunk_contract(parse_findings(t3_m.group(1) if t3_m else '', contract_name, source='T3'), contract_name, aux_contracts)
        with _LOCK:
            print(f"    [{chunk_label}/{agent_id}] RESUMED  T2={len(t2_f)} T3={len(t3_f)}", flush=True)
        return t2_f, t3_f

    profile = profiles_map.get(agent_id)
    if not profile:
        print(f"    [WARN] agent {agent_id} not found — skip", flush=True)
        return [], []

    t0 = time.time()
    stagger = agent_idx * 2 if WORKERS > 1 else 2 + agent_idx * 3
    time.sleep(stagger)

    # Build focus directive — tells agents which contract/functions are the target
    aux_list = ", ".join(aux_contracts) if aux_contracts else "none"
    fn_list  = ", ".join(fn_names) if fn_names else "all"
    focus_directive = (
        f"⚠️  CHUNK SCOPE — PRIMARY audit target: {contract_name}.sol\n"
        f"  TARGET FUNCTIONS : {fn_list}\n"
        f"  AUXILIARY (available for exploration after targets): {aux_list}\n"
        f"\n"
        f"  ANALYSIS PROTOCOL:\n"
        f"  1. Analyze all TARGET FUNCTIONS thoroughly first — spend as much time and\n"
        f"     reasoning depth as needed on each before moving on.\n"
        f"  2. After completing target function analysis, you may freely explore AUX\n"
        f"     contracts for related vulnerabilities.\n"
        f"  3. Attribute each finding to the contract where the bug actually lives."
    )

    if agent_id in _RED_TEAM_AGENT_IDS:
        # ── Attacker flow: RT1 (surface scan) → RT2 (exploit construction) → RT3 (backward trace) ──
        # Strip HIST-INV annotations — attackers scan for surfaces independently,
        # not guided by defender hints.
        _HIST_INV_RE = re.compile(r'[ \t]*//[ \t]*\[HIST-INV\][^\n]*\n?')
        rt_source = _HIST_INV_RE.sub('', ann_source)

        rt1_prompt = _RT1_SURFACE_BLOCK.format(
            agent_id=agent_id,
            persona=profile.persona,
            system_prompt=profile.system_prompt,
            focus_directive=focus_directive,
            source=rt_source,
        )
        rt1_resp = llm_call(rt1_prompt, client)
        time.sleep(2)

        rt2_prompt = _RT2_EXPLOIT_BLOCK.format(
            agent_id=agent_id,
            persona=profile.persona,
            system_prompt=profile.system_prompt,
            focus_directive=focus_directive,
            source=rt_source,
            rt1_surfaces=rt1_resp[:3000],
        )
        rt2_resp     = llm_call(rt2_prompt, client)
        rt2_findings = _filter_to_chunk_contract(parse_findings(rt2_resp, contract_name, source='RT'), contract_name, aux_contracts)
        time.sleep(2)

        rt3_prompt = _RT3_BACKWARD_BLOCK.format(
            agent_id=agent_id,
            persona=profile.persona,
            system_prompt=profile.system_prompt,
            focus_directive=focus_directive,
            source=rt_source,
        )
        rt3_resp     = llm_call(rt3_prompt, client)
        rt3_findings = _filter_to_chunk_contract(parse_findings(rt3_resp, contract_name, source='T3'), contract_name, aux_contracts)

        total = time.time() - t0
        with _LOCK:
            print(f"    [{chunk_label}/{agent_id}] {total:.1f}s  RT2={len(rt2_findings)} RT3={len(rt3_findings)} FINDINGs", flush=True)

        with open(out, 'w') as f:
            f.write(f"Chunk: {chunk_label}  Agent: {agent_id}  Time: {total:.1f}s\n\n")
            f.write(f"{'='*60}\n=== RT1 (attack surfaces) ===\n{rt1_resp}\n\n")
            f.write(f"{'='*60}\n=== RT2 (exploit) ===\n{rt2_resp}\n\n")
            f.write(f"{'='*60}\n=== RT3 (backward trace) ===\n{rt3_resp}\n")

        return rt2_findings, rt3_findings

    else:
        # ── Defender flow: T1 (invariants) → T2 (findings) → T3 (CoT sweep) ──
        t1_prompt = build_round1_prompt(profile, ann_source, focus_directive=focus_directive, invariant_only=True)
        t1_resp   = llm_call(t1_prompt, client)
        t1_clean  = clean_inv(t1_resp)
        time.sleep(2)

        t2_prompt = build_round1_prompt(profile, ann_source, focus_directive=focus_directive, injected_invariants=t1_clean)
        t2_resp   = llm_call(t2_prompt, client)
        t2_findings = _filter_to_chunk_contract(parse_findings(t2_resp, contract_name, source='T2'), contract_name, aux_contracts)
        time.sleep(2)

        t3_prompt = build_t3_prompt(profile, ann_source, focus_directive=focus_directive)
        t3_resp     = llm_call(t3_prompt, client)
        t3_findings = _filter_to_chunk_contract(parse_findings(t3_resp, contract_name, source='T3'), contract_name, aux_contracts)

        total = time.time() - t0
        with _LOCK:
            print(f"    [{chunk_label}/{agent_id}] {total:.1f}s  T2={len(t2_findings)} T3={len(t3_findings)} FINDINGs", flush=True)

        with open(out, 'w') as f:
            f.write(f"Chunk: {chunk_label}  Agent: {agent_id}  Time: {total:.1f}s\n\n")
            f.write(f"{'='*60}\n=== T1 ===\n{t1_resp}\n\n")
            f.write(f"{'='*60}\n=== T2 (standard) ===\n{t2_resp}\n\n")
            f.write(f"{'='*60}\n=== T3 (CoT sweep) ===\n{t3_resp}\n")

        return t2_findings, t3_findings

# ─── Per-chunk state (thread-safe) ────────────────────────────────────────────
class ChunkState:
    def __init__(self, label: str, cname: str, ann_src: str, agents: list, aux_names: list = None, fn_names: list = None):
        self.label      = label
        self.label_flat = label.replace('/', '_')
        self.cname      = cname
        self.ann_src    = ann_src
        self.agents     = agents
        self.aux_names  = aux_names or []  # list of aux contract names
        self.fn_names   = fn_names or []   # target functions for this chunk
        self.lock       = threading.Lock()
        self.findings   = []
        self.agents_done   = 0
        self.agents_total  = len(agents)
        self.t_start    = time.time()
        self.raw_path   = os.path.join(OUT_DIR, f"{self.label_flat}_chunk_raw.json")
        self.dedup_path = os.path.join(OUT_DIR, f"{self.label_flat}_chunk_dedup.json")

_TIMING_LOG = os.path.join(OUT_DIR, 'chunk_timings.jsonl')

def _log_chunk_timing(cs: ChunkState, elapsed_s: float):
    entry = {
        "chunk":        cs.label,
        "contract":     cs.cname,
        "agents":       cs.agents_total,
        "fns":          len(cs.fn_names),
        "elapsed_s":    round(elapsed_s, 1),
        "findings_raw": len(cs.findings),
    }
    with _LOCK:
        with open(_TIMING_LOG, 'a') as fh:
            fh.write(json.dumps(entry) + '\n')

def _save_chunk_raw(cs: ChunkState):
    elapsed = time.time() - cs.t_start
    data = {"chunk": cs.label, "findings_count": len(cs.findings), "findings": cs.findings}
    json.dump(data, open(cs.raw_path, 'w'), indent=2, ensure_ascii=False)
    _log_chunk_timing(cs, elapsed)
    with _LOCK:
        print(f"  [{cs.label}] → {len(cs.findings)} raw findings | {elapsed:.0f}s → {cs.raw_path}", flush=True)

def _run_chunk_dedup(cs: ChunkState):
    deduped = dedup_pipeline(list(cs.findings), FULL_GT_SOURCE)
    data = {"chunk": cs.label, "findings_count": len(deduped), "findings": deduped}
    json.dump(data, open(cs.dedup_path, 'w'), indent=2, ensure_ascii=False)
    with _LOCK:
        print(f"  [{cs.label}] dedup: {len(cs.findings)} → {len(deduped)} → {cs.dedup_path}", flush=True)

def _agent_task(cs: ChunkState, agent_id: str, agent_idx: int, profiles_map: dict, client) -> None:
    """Run one agent, append findings to chunk state, trigger dedup if last agent."""
    t2_f, t3_f = run_agent(agent_id, cs.ann_src, cs.label, agent_idx, cs.cname, profiles_map, client, aux_contracts=cs.aux_names, fn_names=cs.fn_names)
    for f in t2_f:
        f['agent_id'] = agent_id
    for f in t3_f:
        f['agent_id'] = agent_id
    with cs.lock:
        cs.findings.extend(t2_f)
        cs.findings.extend(t3_f)
        cs.agents_done += 1
        is_last = (cs.agents_done == cs.agents_total)
    if is_last:
        _save_chunk_raw(cs)
        if DEDUP_ENABLED:
            _global_executor.submit(_run_chunk_dedup, cs)

def _prepare_chunk_state(chunk: dict) -> ChunkState:
    sub_label = chunk.get('sub_label', '')
    label    = f"{chunk['domain']}/{chunk['contract_name']}{sub_label}"
    base_src = chunk['source'] if NO_INV else _annotate_source_with_hist_inv(chunk['source'], INV_MAP)
    cg_contracts = [chunk['contract_name']] + [a for a, _ in chunk.get('aux_names', [])]
    cg_block = _get_call_graph_block(cg_contracts)
    ann_src  = (cg_block + "\n" + base_src) if cg_block else base_src
    src_lines = ann_src.count('\n') + 1
    mode_str  = 'no_inv' if NO_INV else 'with_inv'
    with _LOCK:
        print(f"\n{'='*65}")
        print(f"Chunk queued: {label}  |  {len(chunk['fn_names'])} fns  |  {src_lines} lines  [{mode_str}]", flush=True)
    aux_names = [a for a, _ in chunk.get('aux_names', [])]
    return ChunkState(label, chunk['contract_name'], ann_src, chunk['agents'], aux_names, fn_names=chunk.get('fn_names', []))

# ─── Main ─────────────────────────────────────────────────────────────────────
print('\n' + '='*65)
print(f'E2E Simulation — Contest {CONTEST_ID}')
print(f'Contracts dir: {CONTRACTS_DIR}')
print(f'GT contracts: {sorted(GT_CONTRACTS)}')
inv_mode = 'DISABLED (pure self-reasoning)' if NO_INV else 'no-custom slugs'
print(f'Grouper: FN_NAME_RULES | Agents: 3-4/chunk | HIST-INV: {inv_mode} | T2+T3 (CoT)')
print('='*65)

contracts = discover_contracts()
print(f"Contracts discovered: {len(contracts)}")

# Build call graph via full KG pipeline if not already loaded
if not _context_summary:
    if _args.kg_result:
        print(f"[kg] --kg-result path not found: {_args.kg_result} — call graph disabled")
    else:
        _context_summary = _build_kg_pipeline(contracts)

# Build profiles from primary contract
_primary_src = _find_primary_src(contracts)
gen = Gen()
profiles_map = {p.agent_id: p for p in gen.generate_tier1_profiles(_primary_src)}

# Full GT source for dedup CODE_ANCHOR check
FULL_GT_SOURCE = "\n\n".join(src for cname, (_, src) in contracts.items() if cname in GT_CONTRACTS)

aux_map = build_aux_map(contracts, GT_CONTRACTS)
print(f"\nAux contracts (auto-detected):")
for cname, deps in sorted(aux_map.items()):
    if deps:
        print(f"  {cname} → {deps}")

chunks = build_chunks(contracts, aux_map)
print(f"\nChunks to simulate ({len(chunks)} total — GT contracts only):")
for c in chunks:
    aux_str = f" +aux={c['aux_names']}" if c['aux_names'] else ""
    sub_str = c.get('sub_label', '')
    print(f"  [{c['domain']}] {c['contract_name']}{sub_str}: {c['fn_names']}{aux_str}")

t_start = time.time()

# Prepare all chunk states (source annotation, print headers) before submitting tasks
chunk_states = [_prepare_chunk_state(c) for c in chunks]

# Recalculate agents_total excluding skipped RT agents so is_last triggers correctly
if NO_RT:
    for cs in chunk_states:
        cs.agents_total = sum(1 for a in cs.agents if a not in _RED_TEAM_AGENT_IDS)

# Global executor shared between agent tasks and dedup tasks
total_tasks = sum(cs.agents_total for cs in chunk_states)
print(f"\n[exec] {total_tasks} agent tasks across {len(chunk_states)} chunks | workers={WORKERS} | dedup={'on' if DEDUP_ENABLED else 'off'} | rt={'off' if NO_RT else 'on'}", flush=True)

_global_executor = ThreadPoolExecutor(max_workers=WORKERS)
agent_futures = {}
task_counter = 0
for cs in chunk_states:
    for idx, agent_id in enumerate(cs.agents):
        if NO_RT and agent_id in _RED_TEAM_AGENT_IDS:
            continue
        client = llm_pool[task_counter % len(llm_pool)]
        f = _global_executor.submit(_agent_task, cs, agent_id, idx, profiles_map, client)
        agent_futures[f] = f"{cs.label}/{agent_id}"
        task_counter += 1

for fut in as_completed(agent_futures):
    label = agent_futures[fut]
    try:
        fut.result()
    except Exception as e:
        with _LOCK:
            print(f"  [ERROR] {label}: {e}", flush=True)

# All agent tasks done — dedup tasks were submitted inside _agent_task before they returned,
# so shutdown(wait=True) safely waits for all dedup tasks too.
_global_executor.shutdown(wait=True)

all_raw = []
for cs in chunk_states:
    all_raw.extend(cs.findings)

wall_time = time.time() - t_start

# ─── Save reports ─────────────────────────────────────────────────────────────
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

raw_path = _save_report(all_raw, "raw", "T2+T3_merged_no_dedup")

print(f"\n{'='*65}")
print(f"DONE — raw={len(all_raw)}  |  {wall_time:.0f}s  |  workers={WORKERS}")
print(f"Global raw report: {raw_path}")
print(f"\nPer-chunk files:")
for cs in chunk_states:
    raw_exists  = '✓' if os.path.exists(cs.raw_path)   else '✗'
    dedup_exists = '✓' if os.path.exists(cs.dedup_path) else '-'
    print(f"  [{raw_exists}raw/{dedup_exists}dedup] {cs.label_flat}")
print(f"\nEval commands:")
print(f"  cd backend/scripts/evaluate")
print(f"  python web3bugs_eval.py gt/gt_{CONTEST_ID}.json {raw_path} --verbose")
