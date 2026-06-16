#!/usr/bin/env python3
"""
populate_hist_inv_cache.py — Build hist_inv_cache.json cho một contest.

Y nguyên luồng main pipeline:
  1. flatten_contest_dir(contest_dir) → combined source (với file section headers)
  2. parser.parse_from_source(combined_source) → entity (source_code = combined_source)
  3. ContractKGBuilder._build_call_graph_with_hist_inv(
         entity.source_code, [f.name for f in entity.functions],
         cache=hc, llm_clients=clients)
  4. hc.save()

File section headers trong combined_source khiến _build_call_graph_with_hist_inv
đi vào multi-section branch → contract_name được extract đúng → cache có đúng keys
→ _annotate_source_with_hist_inv lookup được.

Usage:
    cd /home/thangdd/repos/MiroFish/backend
    source .venv/bin/activate
    python scripts/populate_hist_inv_cache.py \
        --contest-id 104 \
        --contest-dir /home/thangdd/repos/web3bugs/contracts/104 \
        --contracts-dir /home/thangdd/repos/web3bugs/contracts/104/core-contracts/contracts \
        --gt-contracts CoreCollection CoreProxy RoyaltyVault Splitter \
        --workers 4
"""

import argparse
import os
import sys

# ─── Path setup ───────────────────────────────────────────────────────────────
_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_SCRIPT_DIR)
_BENCH_DIR   = os.path.join(_BACKEND_DIR, '..', 'benchmark', 'web3bugs', 'agent-redesign')
sys.path.insert(0, _BACKEND_DIR)

os.environ.setdefault('FLASK_ENV', 'development')

# ─── Args ─────────────────────────────────────────────────────────────────────
_p = argparse.ArgumentParser(description='Populate hist_inv_cache.json for a contest')
_p.add_argument('--contest-id',    required=True, help='Contest ID, e.g. 104')
_p.add_argument('--contest-dir',   required=True, help='Contest root dir (passed to flatten_contest_dir)')
_p.add_argument('--contracts-dir', required=True, help='Primary contracts dir (for logging only)')
_p.add_argument('--gt-contracts',  required=True, nargs='+', help='GT contract names (for logging only)')
_p.add_argument('--cache-path',    default='',    help='Override hist_inv_cache.json path')
_p.add_argument('--workers',       default='4',   help='Number of parallel HIST-INV workers (default: 4)')
args = _p.parse_args()

CONTEST_ID   = args.contest_id
CONTEST_DIR  = args.contest_dir
CACHE_PATH   = args.cache_path or os.path.normpath(
    os.path.join(_BENCH_DIR, CONTEST_ID, 'hist_inv_cache.json'))

# Set workers trước khi import ContractKGBuilder để env var có hiệu lực
os.environ['HIST_INV_WORKERS'] = args.workers

# ─── Imports ──────────────────────────────────────────────────────────────────
from scripts.flatten_contest import flatten_contest_dir
from app.services.contract_kg_builder import ContractKGBuilder
from app.services.contract_parser import ContractParser
from app.services.contract_hist_inv_cache import HistInvCache

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{'='*65}")
    print(f"populate_hist_inv_cache — Contest {CONTEST_ID}")
    print(f"Contest dir:  {CONTEST_DIR}")
    print(f"Cache path:   {CACHE_PATH}")
    print(f"{'='*65}\n")

    # 1. Flatten — y hệt main pipeline
    print(f"[flatten] flattening contest dir...")
    result = flatten_contest_dir(CONTEST_DIR, verbose=True, emit_manifest=True)
    combined_source, manifest = result if isinstance(result, tuple) else (result, {})
    combined_source = manifest.get('in_scope_source') or combined_source
    print(f"[flatten] done — {len(combined_source):,} chars")

    # 2. Parse — y hệt main pipeline (entity.source_code = combined_source)
    print(f"\n[parse] parsing combined source...")
    parser = ContractParser()
    entity = parser.parse_from_source(combined_source, contract_name=CONTEST_ID)
    fn_names = [f.name for f in entity.functions]
    print(f"[parse] entity={entity.contract_id} | functions={len(fn_names)}")

    # 3. Init cache + LLM clients
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    hc      = HistInvCache(CACHE_PATH)
    clients = ContractKGBuilder._build_hist_inv_clients()
    print(f"\nCache: {len(hc.get_matched_slugs())} existing entries with slugs")
    print(f"LLM clients: {len(clients)}")

    if not clients:
        print("[ERROR] No LLM clients — check LLM_VERTEX_AI_KEY_FILE in .env")
        sys.exit(1)

    # 4. Build HIST-INV — y hệt main pipeline
    print(f"\n[hist_inv] running RAG search for {len(fn_names)} functions...")
    ContractKGBuilder._build_call_graph_with_hist_inv(
        entity.source_code,
        fn_names,
        cache=hc,
        score_threshold=float(os.getenv("HIST_INV_SCORE_THRESHOLD", "0.65")),
        llm_clients=clients,
    )
    hc.save()

    # 5. Summary
    matched = hc.get_matched_slugs()
    from collections import Counter
    per_contract = Counter(c for c, _ in matched.keys())

    print(f"\n{'='*65}")
    print(f"DONE — {len(matched)} functions with slug matches")
    for cname, n in sorted(per_contract.items()):
        gt = " [GT]" if cname in set(args.gt_contracts) else ""
        print(f"  {cname}{gt}: {n} functions annotated")
    print(f"Cache saved: {CACHE_PATH}")


if __name__ == '__main__':
    main()
