#!/usr/bin/env python3
"""
Simulation: test HIST-INV inline annotation với 1 agent trên 1 target function.

Thay đổi so với v1:
- Inject TẤT CẢ inv_text entries (không generate hist_inv từ LLM)
  → test xem agent có scan được hết các HIST không
- Dùng .sol files trực tiếp thay vì session_summary.txt (~260KB)
  → context nhỏ hơn, Turn 2 không bị truncate
- max_tokens=65536 cho Turn 2 (như pipeline thực)

Usage:
  cd backend
  source .venv/bin/activate
  python scripts/sim_hist_inv_agent.py \
      --contest 35 \
      --contract ConcentratedLiquidityPosition \
      --fn collect \
      --agent defi_analyst \
      --run-dir ../benchmark/web3bugs/agent-redesign/35/run-71/35_20260607_014133
"""

import argparse
import json
import os
import re
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── args ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("--contest",  default="35")
parser.add_argument("--contract", default="ConcentratedLiquidityPosition")
parser.add_argument("--fn",       default="collect")
parser.add_argument("--agent",    default="defi_analyst")
parser.add_argument("--run-dir",
    default="../benchmark/web3bugs/agent-redesign/35/run-71/35_20260607_014133")
parser.add_argument("--hist-inv", default="",
    help="Override hist_inv statement (bypass LLM generation)")
args = parser.parse_args()

RUN_DIR      = args.run_dir
CONTRACT     = args.contract
FN_NAME      = args.fn
AGENT_ID     = args.agent
CACHE_PATH   = f"../benchmark/web3bugs/agent-redesign/{args.contest}/hist_inv_cache.json"
CONTRACTS_DIR = f"/home/thangdd/repos/web3bugs/contracts/{args.contest}/trident/contracts/pool/concentrated"

# Path để load fn_body (dùng ở Step 2b)
SOL_PATH = os.path.join(CONTRACTS_DIR, f"{args.contract}.sol")

# ── load env ──────────────────────────────────────────────────────────────────
for line in open("../.env"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

from app.utils.llm_client import LLMClient
from app.services.cyber_session_orchestrator import _get_rag_retriever, _build_invariant_rag_hints
from app.services.contract_oasis_env import build_round1_prompt

SEP = "=" * 70

# ── Step 1: load cache entry ───────────────────────────────────────────────────
print(f"\n{SEP}")
print(f"TARGET: {CONTRACT}::{FN_NAME}  |  AGENT: {AGENT_ID}")
print(SEP)

cache_raw = json.loads(open(CACHE_PATH).read())
entries = cache_raw.get("entries", {})
cache_entry = None
for v in entries.values():
    if v.get("contract_name") == CONTRACT and v.get("fn_name") == FN_NAME:
        cache_entry = v
        break

if not cache_entry:
    print(f"[ERROR] No cache entry for {CONTRACT}::{FN_NAME}")
    sys.exit(1)

inv_text = cache_entry.get("inv_text", "")
rag_score = cache_entry.get("rag_score", 0)
inv_lines_raw = [l.strip() for l in inv_text.strip().splitlines() if l.strip()]
print(f"\n[Cache] RAG score: {rag_score:.3f}")
print(f"[Cache] inv_text ({len(inv_lines_raw)} entries):")
for line in inv_lines_raw:
    print(f"  {line}")

# ── Step 2: load .sol files as focused context ─────────────────────────────────
print(f"\n{SEP}")
print("STEP 2: Load .sol files as focused source context")
print(SEP)

# Bao gồm primary contract + related contracts cho context đầy đủ
target_sol_files = [
    "ConcentratedLiquidityPosition.sol",
    "ConcentratedLiquidityPool.sol",
]
# Ticks library thường nằm ở thư mục khác
ticks_candidates = [
    f"/home/thangdd/repos/web3bugs/contracts/{args.contest}/trident/contracts/libraries/Ticks.sol",
    f"/home/thangdd/repos/web3bugs/contracts/{args.contest}/trident/contracts/pool/concentrated/Ticks.sol",
]

source_parts = []
total_chars = 0
for sol_name in target_sol_files:
    sol_path = os.path.join(CONTRACTS_DIR, sol_name)
    if os.path.exists(sol_path):
        src = open(sol_path).read()
        source_parts.append(f"// ===== {sol_name} =====\n{src}")
        total_chars += len(src)
        print(f"  [+] {sol_name}: {len(src):,} chars")
    else:
        print(f"  [-] {sol_name}: NOT FOUND at {sol_path}")

for tpath in ticks_candidates:
    if os.path.exists(tpath):
        src = open(tpath).read()
        source_parts.append(f"// ===== Ticks.sol =====\n{src}")
        total_chars += len(src)
        print(f"  [+] Ticks.sol: {len(src):,} chars")
        break

combined_source = "\n\n".join(source_parts)
print(f"\n[Source] Total: {len(combined_source):,} chars ({len(source_parts)} files)")

if not combined_source.strip():
    print("[ERROR] No source loaded")
    sys.exit(1)

# ── Step 2b: load fn_body và generate 1 real hist_inv via LLM ─────────────────
print(f"\n{SEP}")
print("STEP 2b: Load fn_body + generate real hist_inv via LLM")
print(SEP)

fn_body = ""
if os.path.exists(SOL_PATH):
    src = open(SOL_PATH).read()
    m = re.search(rf'\bfunction\s+{re.escape(FN_NAME)}\s*\(', src)
    if m:
        brace_pos = src.find("{", m.start())
        if brace_pos >= 0:
            depth, i = 0, brace_pos
            while i < len(src):
                if src[i] == "{": depth += 1
                elif src[i] == "}":
                    depth -= 1
                    if depth == 0:
                        fn_body = src[m.start():i+1]
                        break
                i += 1
    print(f"[fn_body] {len(fn_body):,} chars loaded" if fn_body else "[fn_body] NOT FOUND")
else:
    print(f"[fn_body] Sol file not found: {SOL_PATH}")

llm = LLMClient()
print(f"[LLM] model: {llm.model}")

hist_inv = args.hist_inv.strip()
if hist_inv:
    print(f"\n[hist_inv] Using override: {hist_inv}")
elif fn_body and inv_text.strip():
    gen_prompt = (
        f"You are a senior smart contract security auditor.\n\n"
        f"TASK: Synthesize ONE security invariant for the function below, "
        f"guided by the historical findings list.\n\n"
        f"Function: {FN_NAME}()\n"
        f"Code:\n```solidity\n{fn_body.strip()[:2500]}\n```\n\n"
        f"Historical HIGH findings from SIMILAR DeFi functions (same concept, any language/protocol):\n"
        f"{inv_text.strip()}\n\n"
        f"Pattern-matching rules — if the code has ANY of these patterns, write an invariant:\n"
        f"  P1. Subtraction of two uint256 fee/growth/accumulator values "
        f"(e.g. globalX - lastX) → MUST be unchecked (accumulators overflow by design)\n"
        f"  P2. Reward index or balance snapshot read then subtracted → check if wrapping is expected\n"
        f"  P3. msg.sender used to derive permissions but not validated → access control gap\n"
        f"  P4. State written without reading/checking prior value → accounting inconsistency\n\n"
        f"Output format: ONE invariant starting with \"{FN_NAME}() must ...\"\n"
        f"  - Reference actual variable names from the code\n"
        f"  - Max 2 sentences\n"
        f"  - DO NOT say 'based on historical findings' — just state the invariant\n"
        f"  - If NO pattern from P1-P4 is present in the code, output EXACTLY: NONE\n\n"
        f"Output ONLY the invariant text or NONE."
    )
    hist_inv = llm.chat(
        [{"role": "user", "content": gen_prompt}],
        temperature=0, max_tokens=4096, strip_think=True,
    ).strip()
    if hist_inv.upper() == "NONE" or not hist_inv:
        print("[WARN] LLM returned NONE for hist_inv generation")
        hist_inv = ""
    else:
        print(f"\n[hist_inv generated]:\n  {hist_inv}")
elif not args.hist_inv:
    print("[SKIP] No fn_body or inv_text — skipping hist_inv generation")

# ── Step 3: inject ALL inv_text entries above target function ──────────────────
print(f"\n{SEP}")
print(f"STEP 3: Inject ALL {len(inv_lines_raw)} HIST entries above function {FN_NAME}()")
print(SEP)

def build_hist_comment_block(hist_inv_stmt: str, inv_lines: list, indent: str = "") -> list:
    """
    Tạo comment block:
    - Nếu có hist_inv_stmt: inject 1 real invariant statement (primary cue)
    - Kèm theo raw HIST entries (supporting evidence)
    """
    result = []
    if hist_inv_stmt:
        prefix1 = f"{indent}// [HIST-INV]: "
        prefixN = f"{indent}//             "
        words = hist_inv_stmt.split()
        cur = prefix1
        for w in words:
            if len(cur) + len(w) + 1 > 100:
                result.append(cur.rstrip())
                cur = prefixN + w
            else:
                cur += ("" if cur.endswith(": ") else " ") + w
        result.append(cur.rstrip())
    else:
        result.append(f"{indent}// [HIST-INV] Historical vulnerability patterns found in similar functions:")
    for i, entry in enumerate(inv_lines, 1):
        prefix = f"{indent}//   [{i}] "
        wrapped = textwrap.wrap(entry, width=96, initial_indent=prefix,
                                subsequent_indent=f"{indent}//       ")
        result.extend(wrapped)
    return result

lines = combined_source.split("\n")
result_lines = []
fn_re = re.compile(rf"^([ \t]*)(?:function\s+{re.escape(FN_NAME)}\s*[\(\{{]|"
                   rf"function\s+{re.escape(FN_NAME)}\b)")
injected = 0

for line in lines:
    m = fn_re.match(line)
    if m and injected == 0:
        indent = m.group(1)
        comment_block = build_hist_comment_block(hist_inv, inv_lines_raw, indent)
        result_lines.extend(comment_block)
        injected += 1
        print(f"[inject] Found 'function {FN_NAME}' — injecting {len(inv_lines_raw)} entries")
    result_lines.append(line)

annotated_source = "\n".join(result_lines)

print(f"[inject] Source: {len(combined_source):,} → {len(annotated_source):,} chars "
      f"(+{len(annotated_source)-len(combined_source):,})")

if injected == 0:
    print(f"[WARN] 'function {FN_NAME}' NOT FOUND in source — no injection")
else:
    ctx_idx = annotated_source.find("[HIST-INV]")
    if ctx_idx >= 0:
        snippet_start = max(0, ctx_idx - 10)
        snippet = annotated_source[snippet_start:snippet_start+600]
        print(f"\n[verify] Injected block (first 600 chars):")
        for l in snippet.split("\n"):
            print(f"  {l}")

# ── Step 4: load agent profile ─────────────────────────────────────────────────
print(f"\n{SEP}")
print(f"STEP 4: Load agent profile '{AGENT_ID}'")
print(SEP)

profiles = json.loads(open(os.path.join(RUN_DIR, "profiles.json")).read())
profile_data = next((p for p in profiles if p["agent_id"] == AGENT_ID), None)
if not profile_data:
    print(f"[ERROR] Agent '{AGENT_ID}' not found. Available: {[p['agent_id'] for p in profiles]}")
    sys.exit(1)

class AgentProfile:
    def __init__(self, d):
        self.agent_id     = d["agent_id"]
        self.domain_group = d["domain_group"]
        self.persona      = d["persona"]
        self.system_prompt = d["system_prompt"]
        self.core_question = d.get("core_question", "")

profile = AgentProfile(profile_data)
print(f"[profile] {profile.agent_id} | {profile.domain_group} | {profile.persona}")

# ── Step 5: Turn 1 — INV extraction ───────────────────────────────────────────
print(f"\n{SEP}")
print("STEP 5: Turn 1 — Invariant Extraction")
print(SEP)

llm = LLMClient()
print(f"[LLM] model: {llm.model}")

turn1_prompt = build_round1_prompt(
    profile,
    annotated_source,
    invariant_only=True,
)

print(f"[Turn1 prompt] {len(turn1_prompt):,} chars")
print("[Turn1] Calling LLM...")

turn1_response = llm.chat(
    [{"role": "user", "content": turn1_prompt}],
    temperature=0.7,
    max_tokens=65536,
    strip_think=False,
).strip()

print(f"\n[Turn1 response] {len(turn1_response):,} chars")
print("\n── Extracted INVs ──")
inv_matches = re.findall(r'INV-\d+:.*', turn1_response)
for inv in inv_matches:
    print(f"  {inv[:120]}")

# Check coverage: berapa banyak HIST keywords muncul di INVs
print(f"\n── HIST Coverage Analysis ──")
print(f"HIST entries: {len(inv_lines_raw)}")
print(f"Agent INVs: {len(inv_matches)}")
hist_covered = 0
for i, hist_entry in enumerate(inv_lines_raw, 1):
    # Extract key terms from hist entry (skip bracket noise)
    clean = re.sub(r'\[.*?\]', '', hist_entry).lower()
    key_terms = [w for w in clean.split() if len(w) > 4
                 and w not in {"should","would","could","based","which","where","being"}][:5]
    found_in = [inv for inv in inv_matches
                if sum(1 for kw in key_terms if kw in inv.lower()) >= 2]
    marker = "✓" if found_in else "✗"
    print(f"  {marker} HIST[{i}]: {hist_entry[:70]}")
    if found_in:
        hist_covered += 1
        print(f"      → covered by: {found_in[0][:80]}")
print(f"\n  Coverage: {hist_covered}/{len(inv_lines_raw)} HIST entries reflected in agent INVs")

# Check if [HIST-INV] block is acknowledged in Turn 1
if "[HIST-INV]" in turn1_response or "HIST-INV" in turn1_response:
    print("\n  [+] Agent explicitly acknowledged [HIST-INV] block in Turn 1")
elif "historical" in turn1_response.lower():
    print("\n  [~] Agent mentioned 'historical' (indirect acknowledgement)")
else:
    print("\n  [-] Agent did NOT explicitly reference [HIST-INV] block")

# ── Step 6: RAG per INV ───────────────────────────────────────────────────────
print(f"\n{SEP}")
print("STEP 6: RAG per INV")
print(SEP)

rag_enabled = os.environ.get("RAG_ENABLED", "true").lower() == "true"
step2_hint = ""
if rag_enabled:
    target_contracts = [CONTRACT,
                        "ConcentratedLiquidityPool",
                        "ConcentratedLiquidityPoolManager", "Ticks"]
    hint_block, rag_calls = _build_invariant_rag_hints(
        turn1_response, profile.agent_id,
        target_contracts=target_contracts,
    )
    if hint_block:
        step2_hint = (
            "\nHISTORICAL VIOLATION PATTERNS from audit database:\n\n"
            f"{hint_block}\n\n"
            "For each INV where a historical pattern is shown above:\n"
            "  - BE SKEPTICAL: Assume the code is SAFE first. Do not force a match.\n"
            "  - Check if THIS contract's code has the EXACT SAME logical flaw.\n"
            "  - Only write a FINDING if you can extract the SPECIFIC CODE LINES proving it.\n"
            "  - If the historical exploit path is blocked or mitigated, EXPLICITLY state "
            "'Mitigated' and skip.\n"
            "For INVs without historical patterns: reason independently.\n"
        )
    print(f"[RAG] {rag_calls} calls → hint_block {len(hint_block):,} chars")
    if hint_block:
        print(f"[RAG hint preview]:\n{hint_block[:600]}...")

# ── Step 7: Turn 2 — Violation Analysis ───────────────────────────────────────
print(f"\n{SEP}")
print("STEP 7: Turn 2 — Violation Analysis")
print(SEP)

turn1_clean = re.sub(r"<think>[\s\S]*?</think>", "", turn1_response).strip()

turn2_prompt = build_round1_prompt(
    profile,
    annotated_source,
    injected_invariants=turn1_clean,
    step2_hint=step2_hint,
)

print(f"[Turn2 prompt] {len(turn2_prompt):,} chars")
print("[Turn2] Calling LLM...")

turn2_response = llm.chat(
    [{"role": "user", "content": turn2_prompt}],
    temperature=0.7,
    max_tokens=65536,
    strip_think=True,
).strip()

print(f"\n[Turn2 response] {len(turn2_response):,} chars")

# ── Step 8: Parse findings ─────────────────────────────────────────────────────
print(f"\n{SEP}")
print("STEP 8: Findings")
print(SEP)

finding_blocks = re.split(r"\nFINDING:", "\nFINDING:" + turn2_response)[1:]
print(f"Total findings: {len(finding_blocks)}\n")

GT_KEYWORDS = {
    "collect": ["fee", "feegrowth", "feegrowthinside", "double", "underflow", "overflow",
                "yield", "burn", "accumulat"],
}
gt_kws = GT_KEYWORDS.get(FN_NAME, [])

gt_hits = 0
for i, block in enumerate(finding_blocks, 1):
    title_m = re.search(r"^TITLE:\s*(.+)", block, re.MULTILINE)
    fn_m    = re.search(r"FUNCTION:\s*(.+)", block, re.MULTILINE)
    sev_m   = re.search(r"SEVERITY:\s*(.+)", block, re.MULTILINE)
    title   = title_m.group(1).strip() if title_m else "(no title)"
    fn      = fn_m.group(1).strip()   if fn_m    else "?"
    sev     = sev_m.group(1).strip()  if sev_m   else "?"

    relevant = any(kw in (title + fn).lower() for kw in gt_kws)
    is_collect = FN_NAME.lower() in fn.lower()
    if relevant:
        gt_hits += 1
    marker   = "  *** GT-RELEVANT ***" if relevant else ("  [target fn]" if is_collect else "")
    print(f"  [{i}] [{sev}] {title[:70]}{marker}")
    print(f"       fn: {fn}")
    if relevant or is_collect:
        print(f"       --- FULL FINDING ---")
        for fline in block.strip().split("\n")[:25]:
            print(f"       {fline}")

# ── Summary ────────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("SUMMARY")
print(SEP)
print(f"Agent          : {AGENT_ID}")
print(f"Target         : {CONTRACT}::{FN_NAME}")
print(f"Source size    : {len(annotated_source):,} chars")
print(f"Turn2 prompt   : {len(turn2_prompt):,} chars")
print(f"HIST entries   : {len(inv_lines_raw)}")
print(f"INVs extracted : {len(inv_matches)}")
print(f"HIST covered   : {hist_covered}/{len(inv_lines_raw)}")
print(f"Findings       : {len(finding_blocks)}")
print(f"GT-relevant    : {gt_hits}")
print(f"\n{'✓ PASS — agent found GT-relevant finding for collect()' if gt_hits > 0 else '✗ FAIL — agent missed GT bug in collect()'}")
