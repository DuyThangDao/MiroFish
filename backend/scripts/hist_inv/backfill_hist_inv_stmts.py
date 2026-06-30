#!/usr/bin/env python3
"""
Backfill hist_inv_stmts.json từ hist_inv_cache.json hiện có.

Đọc từng entry trong hist_inv_cache.json:
  - Nếu có inv_text và chưa có trong stmts cache → load fn_body → generate hist_inv → save
  - Nếu đã có trong stmts cache → skip

Tận dụng HIST titles đã build, không cần chạy lại KG build.

Usage:
  cd backend
  source .venv/bin/activate

  # Cần --contest-dir để load fn_body từ .sol files
  python scripts/backfill_hist_inv_stmts.py --contest 35 \
      --contest-dir /home/thangdd/repos/web3bugs/contracts/35

  # Chỉ định cache path trực tiếp
  python scripts/backfill_hist_inv_stmts.py \
      --cache-path ../benchmark/web3bugs/agent-redesign/35/hist_inv_cache.json \
      --contest-dir /home/thangdd/repos/web3bugs/contracts/35
"""

import argparse
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

parser = argparse.ArgumentParser()
parser.add_argument("--contest", default="")
parser.add_argument("--cache-path", default="")
parser.add_argument("--contest-dir", default="",
    help="Root dir of contest source (e.g. /home/.../web3bugs/contracts/35)")
parser.add_argument("--force", action="store_true",
    help="Regenerate even if already in stmts cache")
args = parser.parse_args()

if args.cache_path:
    HIST_CACHE_PATH = args.cache_path
elif args.contest:
    HIST_CACHE_PATH = f"../benchmark/web3bugs/agent-redesign/{args.contest}/hist_inv_cache.json"
else:
    print("[ERROR] Provide --contest or --cache-path")
    sys.exit(1)

if not os.path.exists(HIST_CACHE_PATH):
    print(f"[ERROR] hist_inv_cache.json not found: {HIST_CACHE_PATH}")
    sys.exit(1)

CONTEST_DIR = args.contest_dir or (
    f"/home/thangdd/repos/web3bugs/contracts/{args.contest}" if args.contest else ""
)

# Build index: contract_name → [sol_path, ...]
sol_index: dict[str, list[str]] = {}
if CONTEST_DIR and os.path.isdir(CONTEST_DIR):
    for sol_path in Path(CONTEST_DIR).rglob("*.sol"):
        # Skip artifacts/node_modules
        parts = sol_path.parts
        if any(p in ("artifacts", "node_modules", "cache", "lib") for p in parts):
            continue
        stem = sol_path.stem  # ContractName without .sol
        sol_index.setdefault(stem, []).append(str(sol_path))
    print(f"[backfill] sol_index: {len(sol_index)} contracts from {CONTEST_DIR}")
else:
    print("[backfill] No --contest-dir → fn_body will be empty (lower quality stmts)")


def extract_fn_body(contract_name: str, fn_name: str) -> str:
    """Try to load fn_body from .sol files for contract_name."""
    candidates = sol_index.get(contract_name, [])
    for sol_path in candidates:
        try:
            src = open(sol_path, encoding="utf-8", errors="replace").read()
            m = re.search(rf'\bfunction\s+{re.escape(fn_name)}\s*\(', src)
            if not m:
                continue
            brace_pos = src.find("{", m.start())
            if brace_pos < 0:
                continue
            depth, i = 0, brace_pos
            while i < len(src):
                if src[i] == "{":
                    depth += 1
                elif src[i] == "}":
                    depth -= 1
                    if depth == 0:
                        return src[m.start():i + 1]
                i += 1
        except Exception:
            continue
    return ""


for line in open("../.env"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

from app.services.contract_hist_inv_cache import HistInvCache, HistInvStmtsCache
from app.services.contract_kg_builder import ContractKGBuilder
from app.utils.llm_client import LLMClient

hist_cache = HistInvCache(HIST_CACHE_PATH)
stmts_path = HistInvStmtsCache.stmts_path_from_hist_cache_path(HIST_CACHE_PATH)
stmts_cache = HistInvStmtsCache(stmts_path)

llm = LLMClient()
print(f"[backfill] model    : {llm.model}")
print(f"[backfill] hist     : {len(hist_cache)} entries → {HIST_CACHE_PATH}")
print(f"[backfill] stmts    : {len(stmts_cache)} existing → {stmts_path}")
print()

entries = list(hist_cache._data.items())
skip = 0
generated = 0
none_returned = 0
errors = 0

for i, (key, v) in enumerate(entries):
    contract_name = v.get("contract_name", "")
    fn_name = v.get("fn_name", "")
    inv_text = v.get("inv_text", "").strip()

    if not inv_text:
        skip += 1
        continue

    if not args.force and stmts_cache.get(key):
        skip += 1
        continue

    fn_body = extract_fn_body(contract_name, fn_name)
    body_label = f"{len(fn_body)}chars" if fn_body else "no_body"
    print(f"[{i+1}/{len(entries)}] {contract_name}::{fn_name} ({body_label}) ... ", end="", flush=True)

    try:
        hist_inv = ContractKGBuilder._generate_hist_inv(
            fn_name=fn_name,
            fn_body=fn_body,
            inv_text=inv_text,
            llm_client=llm,
        )
    except Exception as e:
        print(f"ERROR: {e}")
        errors += 1
        continue

    if hist_inv:
        stmts_cache.set(key, contract_name, fn_name, hist_inv)
        generated += 1
        print(f"OK — {hist_inv[:80]}{'...' if len(hist_inv) > 80 else ''}")
    else:
        none_returned += 1
        print("NONE")

    # Save incrementally every 10 entries
    if (generated + none_returned) % 10 == 0:
        stmts_cache.save()

stmts_cache.save()
print(f"\n[backfill] Done: generated={generated} | skipped={skip} | none={none_returned} | errors={errors}")
print(f"[backfill] stmts saved: {stmts_path} ({len(stmts_cache)} total entries)")
