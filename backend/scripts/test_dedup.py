"""
Test 3-layer dedup pipeline trên 1 chunk cụ thể.

Usage:
  python scripts/test_dedup.py \
    --chunk access_reward/Utils \
    --contest 5

Mỗi layer in ra: count trước → sau, và danh sách finding bị drop/merge.
Cuối cùng kiểm tra TP nào còn sót lại.
"""
import sys, os, json, argparse, re, logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pysqlite3; sys.modules['sqlite3'] = pysqlite3

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))

KEY_FILE = os.getenv('LLM_VERTEX_AI_KEY_FILE', '')
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = KEY_FILE

from app.services.cyber_session_orchestrator import CyberSessionOrchestrator

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# ─── Args ─────────────────────────────────────────────────────────────────────
p = argparse.ArgumentParser()
p.add_argument('--chunk',   required=True, help='domain/ContractName, e.g. access_reward/Utils')
p.add_argument('--contest', default='5',   help='Contest ID')
p.add_argument('--bench-dir', default='',  help='Override benchmark dir')
p.add_argument('--contracts-dir', default='', help='Override contracts dir')
args = p.parse_args()

CONTEST = args.contest
BENCH_DIR = args.bench_dir or f'/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/{CONTEST}'
CHUNK_LABEL = args.chunk  # e.g. "access_reward/Utils"
CHUNK_FLAT  = CHUNK_LABEL.replace('/', '_')

# Detect most recent sim_e2e_* dir
SIM_DIR = ''
for d in sorted(os.listdir(BENCH_DIR), reverse=True):
    full = os.path.join(BENCH_DIR, d)
    if os.path.isdir(full) and d.startswith('sim_e2e_'):
        candidate = os.path.join(full, f'{CHUNK_FLAT}_chunk_raw.json')
        if os.path.exists(candidate):
            SIM_DIR = full
            break

if not SIM_DIR:
    print(f"ERROR: No sim_e2e_* dir with {CHUNK_FLAT}_chunk_raw.json under {BENCH_DIR}")
    sys.exit(1)

print(f"Using: {os.path.basename(SIM_DIR)}")

CHUNK_RAW_PATH = os.path.join(SIM_DIR, f'{CHUNK_FLAT}_chunk_raw.json')

# ─── GT facts for TP check (contest 5) ────────────────────────────────────────
GT_PATH = os.path.join(os.path.dirname(__file__), 'evaluate/gt', f'gt_{CONTEST}.json')
GT = json.load(open(GT_PATH)) if os.path.exists(GT_PATH) else []
GT_FUNCTIONS = {x.get('function_name', '').lower() for x in GT}  # for quick lookup

# ─── Load findings ────────────────────────────────────────────────────────────
raw = json.load(open(CHUNK_RAW_PATH))
findings_raw = raw.get('findings', [])
print(f"\nChunk: {CHUNK_LABEL}  |  raw findings: {len(findings_raw)}")
print(f"  T2: {sum(1 for f in findings_raw if f.get('source')=='T2')}  "
      f"T3: {sum(1 for f in findings_raw if f.get('source')=='T3')}")

# ─── Build full GT source ──────────────────────────────────────────────────────
CONTRACTS_DIR = args.contracts_dir
if not CONTRACTS_DIR:
    # Auto-detect for known contests
    mapping = {
        '5':  '/home/thangdd/repos/web3bugs/contracts/5/vader-protocol/contracts',
        '35': '/home/thangdd/repos/web3bugs/contracts/35/contracts',
        '42': '/home/thangdd/repos/web3bugs/contracts/42/projects/mochi-core/contracts',
    }
    CONTRACTS_DIR = mapping.get(CONTEST, '')

full_source = ''
if CONTRACTS_DIR and os.path.isdir(CONTRACTS_DIR):
    parts = []
    for root, dirs, files in os.walk(CONTRACTS_DIR):
        dirs[:] = [d for d in dirs if d not in {'interfaces', 'test', 'mocks', 'node_modules'}]
        for f in files:
            if f.endswith('.sol'):
                src = open(os.path.join(root, f), errors='replace').read()
                parts.append(f"// ─── {f} ───\n{src}")
    full_source = "\n\n".join(parts)
    print(f"Full source: {len(full_source):,} chars from {CONTRACTS_DIR}")
else:
    print("WARNING: No contracts dir — pre_r2 CODE_ANCHOR check disabled")

# ─── Convert findings to pool format ──────────────────────────────────────────
_MD_FENCE_RE = re.compile(r'```[a-z]*\n?(.*?)```', re.DOTALL)
_FILENAME_RE = re.compile(r'^\([^\)]+\.sol\)\s*', re.IGNORECASE)

def clean_anchor(anchor: str) -> str:
    if not anchor:
        return anchor
    m = _MD_FENCE_RE.search(anchor)
    if m:
        anchor = m.group(1).strip()
    anchor = _FILENAME_RE.sub('', anchor).strip()
    return anchor.strip('`').strip()

for f in findings_raw:
    f['code_anchor'] = clean_anchor(f.get('code_anchor', ''))

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
        "_source":           f.get("source", "?"),  # keep for tracking
    }
    for i, f in enumerate(findings_raw)
}

def _print_pool(label: str, pool: dict, prev_pool: dict = None):
    print(f"\n{'─'*60}")
    print(f"After {label}: {len(pool)} findings", end="")
    if prev_pool:
        dropped = set(prev_pool.keys()) - set(pool.keys())
        print(f"  (dropped {len(dropped)})", end="")
    print()
    if prev_pool:
        dropped = set(prev_pool.keys()) - set(pool.keys())
        for pid in sorted(dropped):
            item = prev_pool[pid]
            src = item.get('_source', '?')
            fn  = item.get('function_name', '')
            print(f"  DROP [{src}] {item['title'][:60]}  fn={fn}")
    for pid, item in sorted(pool.items()):
        src   = item.get('_source', '?')
        fn    = item.get('function_name', '')
        anchor = item.get('code_anchor', '')[:50]
        gt_mark = ' ★TP?' if fn.lower().rstrip('()').split('(')[0] in GT_FUNCTIONS else ''
        print(f"  [{src}] {item['title'][:55]:<55} fn={fn}{gt_mark}")

_print_pool("raw", pool)

# ─── Layer 1: _dedup_pre_r2 ───────────────────────────────────────────────────
orch = CyberSessionOrchestrator()
# Disable ATTACK_PATH_VALIDATION (sim_e2e uses free-form attack_path)
os.environ['ATTACK_PATH_VALIDATION'] = 'false'

pool1 = orch._dedup_pre_r2(pool, full_source)
_print_pool("Layer 1: pre_r2 (CODE_ANCHOR check)", pool1, pool)

# ─── Layer 2: _semi_static_anchor_dedup ───────────────────────────────────────
pool2 = orch._semi_static_anchor_dedup(pool1, full_source)
_print_pool("Layer 2: semi_static (same anchor → LLM merge?)", pool2, pool1)

# ─── Layer 3: _llm_anchor_dedup ───────────────────────────────────────────────
pool3 = orch._llm_anchor_dedup(pool2, full_source)
_print_pool("Layer 3: llm_anchor (per-function grouping)", pool3, pool2)

# ─── Summary ──────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"SUMMARY: {len(pool)} → {len(pool1)} → {len(pool2)} → {len(pool3)}")
print(f"  Layer 1 (pre_r2):   dropped {len(pool) - len(pool1)}")
print(f"  Layer 2 (semi_static): dropped {len(pool1) - len(pool2)}")
print(f"  Layer 3 (llm_anchor):  dropped {len(pool2) - len(pool3)}")
print(f"  Final: {len(pool3)} findings")

# TP check
print(f"\nTP candidates in final pool (fn in GT):")
for pid, item in sorted(pool3.items()):
    fn = item.get('function_name', '').lower().rstrip('()').split('(')[0]
    if fn in GT_FUNCTIONS:
        src = item.get('_source', '?')
        print(f"  [{src}] {item['title'][:65]}  fn={fn}")
