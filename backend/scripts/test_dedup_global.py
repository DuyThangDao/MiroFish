"""
2-point dedup pipeline trên kết quả sim_e2e có sẵn:
  Point 1: per-chunk dedup (3-layer)
  Point 2: global dedup sau khi merge tất cả chunks (3-layer)

Lưu:
  audit_report_5_dedup_perchunk.json  — sau Point 1
  audit_report_5_dedup_global.json    — sau Point 2 (dùng cho eval)

Usage:
  python scripts/test_dedup_global.py --contest 5
"""
import sys, os, json, re, time, argparse, threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pysqlite3; sys.modules['sqlite3'] = pysqlite3

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))
KEY_FILE = os.getenv('LLM_VERTEX_AI_KEY_FILE', '')
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = KEY_FILE
os.environ['ATTACK_PATH_VALIDATION'] = 'false'

from app.services.cyber_session_orchestrator import CyberSessionOrchestrator

# ─── Args ─────────────────────────────────────────────────────────────────────
p = argparse.ArgumentParser()
p.add_argument('--contest',      default='5')
p.add_argument('--bench-dir',    default='')
p.add_argument('--sim-dir',      default='', help='Explicit sim_e2e_* subdir name')
p.add_argument('--contracts-dir',default='')
p.add_argument('--workers', type=int, default=3, help='Parallel workers for per-chunk dedup')
p.add_argument('--test-contract', default='', help='Test contract-level dedup on 1 contract (e.g. DAO)')
p.add_argument('--skip-perchunk', action='store_true', help='Load existing perchunk result instead of re-running')
args = p.parse_args()

CONTEST   = args.contest
BENCH_DIR = args.bench_dir or f'/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/{CONTEST}'
CONTRACTS_DIR = args.contracts_dir or {
    '5':  '/home/thangdd/repos/web3bugs/contracts/5/vader-protocol/contracts',
    '35': '/home/thangdd/repos/web3bugs/contracts/35/contracts',
    '42': '/home/thangdd/repos/web3bugs/contracts/42/projects/mochi-core/contracts',
}.get(CONTEST, '')

# Detect sim_e2e dir
if args.sim_dir:
    SIM_DIR = os.path.join(BENCH_DIR, args.sim_dir)
else:
    import glob as _glob
    candidates = sorted(
        [d for d in _glob.glob(f'{BENCH_DIR}/sim_e2e_*') if os.path.isdir(d)],
        key=os.path.getmtime, reverse=True
    )
    SIM_DIR = next(
        (d for d in candidates
         if any(f.endswith('_chunk_raw.json') for f in os.listdir(d))),
        ''
    )
assert SIM_DIR and os.path.isdir(SIM_DIR), f"No sim_e2e dir found under {BENCH_DIR}"
print(f"Sim dir : {os.path.basename(SIM_DIR)}")

# ─── Build full GT source ──────────────────────────────────────────────────────
full_source = ''
if CONTRACTS_DIR and os.path.isdir(CONTRACTS_DIR):
    parts = []
    for root, dirs, files in os.walk(CONTRACTS_DIR):
        dirs[:] = [d for d in dirs if d not in {'interfaces','test','mocks','node_modules'}]
        for f in files:
            if f.endswith('.sol'):
                src = open(os.path.join(root, f), errors='replace').read()
                parts.append(f"// ─── {f} ───\n{src}")
    full_source = "\n\n".join(parts)
    print(f"Source  : {len(full_source):,} chars")

# ─── Helpers ──────────────────────────────────────────────────────────────────
_MD_FENCE = re.compile(r'```[a-z]*\n?(.*?)```', re.DOTALL)
_FNAME_RE = re.compile(r'^\([^\)]+\.sol\)\s*', re.IGNORECASE)
_SIG_RE   = re.compile(r'\s*\(.*$')   # strip fn signature "(address,uint)"

def clean_anchor(a):
    if not a: return a
    m = _MD_FENCE.search(a)
    if m: a = m.group(1).strip()
    a = _FNAME_RE.sub('', a).strip()
    return a.strip('`').strip()

def norm_fn(fn_name: str) -> str:
    """Normalize: lowercase + strip signature."""
    return _SIG_RE.sub('', fn_name or '').strip().lower()

def to_pool(findings: list, prefix: str = 'f') -> dict:
    """Convert flat finding list → pool dict for dedup pipeline."""
    pool = {}
    for i, f in enumerate(findings):
        pool[f"{prefix}_{i:05d}"] = {
            "contract_name":     f.get("contract_name", ""),
            "function_name":     f.get("function_name", ""),
            "title":             f.get("title", ""),
            "code_anchor":       clean_anchor(f.get("code_anchor", "")),
            "evidence_snippets": [f["evidence"]] if f.get("evidence") else [],
            "attack_path":       f.get("attack_path", ""),
            "submitters":        [],
            "description":       f.get("description", ""),
            "_source":           f.get("source", "?"),
            "_chunk":            f.get("_chunk", ""),
        }
    return pool

def from_pool(pool: dict) -> list:
    """Convert pool dict back to flat finding list."""
    result = []
    for item in pool.values():
        result.append({
            "title":         item.get("title", ""),
            "description":   item.get("description", ""),
            "attack_path":   item.get("attack_path", ""),
            "contract_name": item.get("contract_name", ""),
            "function_name": item.get("function_name", ""),
            "severity":      item.get("severity", "high"),
            "code_anchor":   item.get("code_anchor", ""),
            "evidence":      (item.get("evidence_snippets") or [""])[0],
            "source":        item.get("_source", "?"),
        })
    return result

orch = CyberSessionOrchestrator()

def run_3layer(pool: dict, source: str, label: str = '') -> dict:
    n0 = len(pool)
    pool = orch._dedup_pre_r2(pool, source)
    n1 = len(pool)
    pool = orch._semi_static_anchor_dedup(pool, source)
    n2 = len(pool)
    pool = orch._llm_anchor_dedup(pool, source)
    n3 = len(pool)
    tag = f"[{label}] " if label else ""
    print(f"  {tag}{n0} → pre_r2={n1} → semi_static={n2} → llm={n3}")
    return pool

# ─── Step 1: Load all chunk_raw.json ─────────────────────────────────────────
import glob
chunk_files = sorted(glob.glob(f'{SIM_DIR}/*_chunk_raw.json'))
print(f"\nChunks  : {len(chunk_files)} chunk_raw.json files")

all_chunks = {}
for jf in chunk_files:
    d    = json.load(open(jf))
    name = os.path.basename(jf).replace('_chunk_raw.json', '')
    chunk_label = d.get('chunk', name.replace('_', '/', 1))
    findings = d.get('findings', [])
    for f in findings:
        f['_chunk'] = chunk_label
    all_chunks[chunk_label] = findings

total_raw = sum(len(v) for v in all_chunks.values())
print(f"Total raw findings: {total_raw}")

# ─── Step 2: Per-chunk dedup (or load from existing file) ────────────────────
PC_PATH = os.path.join(SIM_DIR, f'audit_report_{CONTEST}_dedup_perchunk.json')

if args.skip_perchunk and os.path.exists(PC_PATH):
    print(f"\n[SKIP] Loading existing per-chunk result: {PC_PATH}")
    pc_data = json.load(open(PC_PATH))
    perchunk_findings = pc_data.get('findings', [])
    total_raw = sum(len(v) for v in all_chunks.values())
    print(f"  Loaded {len(perchunk_findings)} findings (raw was {total_raw})")
else:
    print(f"\n{'='*60}")
    print("POINT 1 — Per-chunk dedup (3-layer each chunk)")
    print('='*60)

    perchunk_findings_map = {}
    _print_lock = threading.Lock()
    t0 = time.time()

    WORKERS = args.workers

    def _dedup_one_chunk(chunk_label: str, findings: list, idx: int) -> tuple:
        if not findings:
            return chunk_label, []
        pool = to_pool(findings, prefix=f"c{idx:04d}")
        with _print_lock:
            print(f"\n  Chunk: {chunk_label} ({len(findings)} findings)")
        pool = run_3layer(pool, full_source, label=chunk_label)
        return chunk_label, from_pool(pool)

    chunk_items = [(label, fns, i) for i, (label, fns) in enumerate(sorted(all_chunks.items())) if fns]

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(_dedup_one_chunk, label, fns, idx): label
                   for label, fns, idx in chunk_items}
        for fut in as_completed(futures):
            chunk_label, deduped = fut.result()
            perchunk_findings_map[chunk_label] = deduped

    perchunk_findings = []
    for label, _, _ in chunk_items:
        perchunk_findings.extend(perchunk_findings_map.get(label, []))

    t1 = time.time()
    print(f"\nPer-chunk done: {total_raw} → {len(perchunk_findings)}  ({t1-t0:.0f}s)")

    raw_report = json.load(open(os.path.join(SIM_DIR, f'audit_report_{CONTEST}_raw.json')))
    pc_report = dict(raw_report)
    pc_report['total_findings'] = len(perchunk_findings)
    pc_report['findings'] = perchunk_findings
    pc_report['_dedup'] = 'perchunk'
    json.dump(pc_report, open(PC_PATH, 'w'), indent=2, ensure_ascii=False)
    print(f"Saved: {PC_PATH}")

raw_report = json.load(open(os.path.join(SIM_DIR, f'audit_report_{CONTEST}_raw.json')))

# ─── Step 3: Normalize fn names for contract-level grouping ──────────────────
for f in perchunk_findings:
    f['_fn_orig'] = f.get('function_name', '')
    f['function_name'] = norm_fn(f['function_name'])

# ─── Step 4: Per-contract dedup ───────────────────────────────────────────────
print(f"\n{'='*60}")
print("POINT 2 — Per-contract dedup (3-layer per contract)")
print('='*60)

# Group by contract_name
from collections import defaultdict as _dd2
contract_groups = _dd2(list)
for f in perchunk_findings:
    contract = f.get('contract_name', '').strip() or '_unknown'
    contract_groups[contract].append(f)

print(f"\n  {len(contract_groups)} unique contracts, {len(perchunk_findings)} findings total")
for c, fns in sorted(contract_groups.items(), key=lambda x: -len(x[1]))[:10]:
    print(f"    {c}: {len(fns)} findings")

# If --test-contract, only run on that one contract
test_contract = args.test_contract.strip()
if test_contract:
    if test_contract not in contract_groups:
        # Case-insensitive match
        matches = [c for c in contract_groups if c.lower() == test_contract.lower()]
        test_contract = matches[0] if matches else ''
    if not test_contract:
        print(f"\nERROR: contract '{args.test_contract}' not found. Available: {sorted(contract_groups)[:20]}")
        import sys; sys.exit(1)
    run_contracts = [test_contract]
    print(f"\n  [TEST MODE] Running only on contract: {test_contract}")
else:
    run_contracts = sorted(contract_groups.keys())

t2 = time.time()
percontract_findings_map = {}

for contract in run_contracts:
    findings = contract_groups[contract]
    print(f"\n  Contract: {contract} ({len(findings)} findings)")
    pool = to_pool(findings, prefix=f"ct_{contract[:8]}")
    pool = run_3layer(pool, full_source, label=f'contract/{contract}')
    percontract_findings_map[contract] = from_pool(pool)

t3 = time.time()

# Merge results
if test_contract:
    # Test mode: show contract result + keep non-tested contracts unchanged
    deduped_tested = percontract_findings_map[test_contract]
    other_findings = [f for f in perchunk_findings
                      if (f.get('contract_name', '').strip() or '_unknown') != test_contract]
    contract_findings = deduped_tested + other_findings
    print(f"\n[TEST] {test_contract}: {len(contract_groups[test_contract])} → {len(deduped_tested)}")
else:
    contract_findings = []
    for contract in run_contracts:
        contract_findings.extend(percontract_findings_map[contract])

print(f"\nPer-contract done: {len(perchunk_findings)} → {len(contract_findings)}  ({t3-t2:.0f}s)")

# Save per-contract result
suffix = f'_test_{test_contract.lower()}' if test_contract else ''
GL_PATH = os.path.join(SIM_DIR, f'audit_report_{CONTEST}_dedup_contract{suffix}.json')
gl_report = dict(raw_report)
gl_report['total_findings'] = len(contract_findings)
gl_report['findings'] = contract_findings
gl_report['_dedup'] = f'contract{suffix}'
json.dump(gl_report, open(GL_PATH, 'w'), indent=2, ensure_ascii=False)
print(f"Saved: {GL_PATH}")

# ─── Summary ──────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print("SUMMARY")
print('='*60)
print(f"  Raw          : {total_raw}")
print(f"  Per-chunk    : {len(perchunk_findings)}  (−{total_raw - len(perchunk_findings)}, {(total_raw-len(perchunk_findings))*100//total_raw}%)")
print(f"  Per-contract : {len(contract_findings)}  (−{total_raw - len(contract_findings)}, {(total_raw-len(contract_findings))*100//total_raw}%)")

print(f"\nEval commands:")
print(f"  cd backend/scripts/evaluate")
print(f"  python web3bugs_eval.py gt/gt_{CONTEST}.json {GL_PATH} --verbose")
