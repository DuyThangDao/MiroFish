"""
Cyber Session Orchestrator — Multi-Expert Panel (Direction B)

Điều phối 3-phase OASIS session:
  Phase A (rounds 1–3): Intra-group — domain experts thảo luận nội bộ
  Phase B (rounds 4–7): Cross-group — domain experts challenge nhau
  Phase C (rounds 8–10): Attacker — 5 attacker profiles phản biện

Mỗi round: gọi LLM cho từng agent active → parse findings → lưu trạng thái
Không dùng OASIS subprocess (tương thích với môi trường không có OASIS cài sẵn).
"""

import os
import re
import time
import uuid
import threading
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime

from ..config import Config
from ..models.task import TaskManager, TaskStatus
from ..models.cyber_models import (
    ExpertFinding, AttackerFinding, AttackerCorroboration, CyberSessionState
)
from ..utils.llm_client import LLMClient, LLMClientPool
from ..utils.logger import get_logger
from .cyber_expert_profile_generator import CyberAgentProfile, CyberExpertProfileGenerator
from .cyber_oasis_env import (
    CyberOasisConfig, CyberOasisEnvBuilder,
    AttackerAction, parse_expert_finding_from_text,
    parse_gap_declarations, build_gap_context_for_agent,
    get_phase_for_round, TOTAL_ROUNDS,
)
from ..models.cyber_models import GapDeclaration

# Contract audit mode imports (lazy to avoid circular imports)
def _get_contract_modules():
    from .contract_oasis_env import (
        ContractAuditEnvBuilder,
        ContractAttackerAction, parse_contract_finding_from_text,
        parse_contract_gap_declarations, build_gap_context_for_agent as contract_gap_context,
        build_published_registry as contract_published_registry,
        get_phase_for_round as contract_get_phase,
        extract_known_functions,
        # v2 parsers
        parse_all_contract_findings_from_text,
        build_round1_prompt, build_round2_prompt, build_round2_update_prompt,
        build_round3_prompt, build_round3_update_prompt,
        parse_round2_votes_from_text, parse_round2_update_votes_from_text,
        parse_round3_verdict_from_text, parse_round3_update_verdict_from_text,
    )
    return {
        "env_builder":          ContractAuditEnvBuilder,
        "attacker_action":      ContractAttackerAction,
        "parse_finding":        parse_contract_finding_from_text,
        "parse_gap":            parse_contract_gap_declarations,
        "gap_context":          contract_gap_context,
        "published_registry":   contract_published_registry,
        "get_phase":            contract_get_phase,
        "extract_funcs":        extract_known_functions,
        # v2
        "parse_all_findings":   parse_all_contract_findings_from_text,
        "r1_prompt":            build_round1_prompt,
        "r2_prompt":            build_round2_prompt,
        "r2_update_prompt":     build_round2_update_prompt,
        "r3_prompt":            build_round3_prompt,
        "r3_update_prompt":     build_round3_update_prompt,
        "parse_r2_votes":       parse_round2_votes_from_text,
        "parse_r2_upd":         parse_round2_update_votes_from_text,
        "parse_r3_verdict":     parse_round3_verdict_from_text,
        "parse_r3_upd":         parse_round3_update_verdict_from_text,
    }

logger = get_logger("mirofish.cyber_orchestrator")

# ── RAG singleton ─────────────────────────────────────────────────────────────
_rag_retriever = None
_rag_lock = threading.Lock()  # serialize ChromaDB access — concurrent Rust bindings cause crashes

def _get_rag_retriever():
    global _rag_retriever
    if _rag_retriever is None:
        with _rag_lock:
            if _rag_retriever is None:  # double-checked locking
                import sys
                __import__('pysqlite3')
                sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
                from scripts.rag.rag_retriever import SolodirRetriever
                _rag_retriever = SolodirRetriever()
    return _rag_retriever


import re as _re_rag

# Parse FINDING blocks: title on FINDING: line, then full block until next FINDING or end
_FINDING_BLOCK_RE = _re_rag.compile(
    r'^FINDING:\s*(.+?)\n(.*?)(?=\nFINDING:|\Z)',
    _re_rag.DOTALL | _re_rag.MULTILINE,
)
# Extract a single named field from a FINDING block
_FIELD_RE = _re_rag.compile(
    r'^([A-Z_]+):\s*(.+?)(?=\n[A-Z_]+:|\Z)',
    _re_rag.DOTALL | _re_rag.MULTILINE,
)
_SCORE_INJECT_THRESHOLD     = 0.68
_SCORE_SHOW_THRESHOLD       = 0.65
_SCORE_INJECT_THRESHOLD_INV = 0.65  # lowered: 0.70 was blocking ~60% of relevant patterns (range 0.576–0.737)
_MAX_RAG_INJECT_PER_AGENT   = 4     # raised: after FIX-1/2 loại noise, không còn distractor effect
_inv_cache: dict[str, tuple] = {}   # key → (score, hint_block); session-level semantic dedup
_inv_cache_lock = threading.Lock()

_MECHANICS_TURN1_PROMPT_TEMPLATE = """\
You are a code mechanics analyst for smart contract security.

PRIMARY TARGET CONTRACT: {primary_contract}

Task: Analyze functions from {primary_contract} ONLY. Describe MECHANICALLY what each
function physically does — focusing on arithmetic, type casts, comparisons, and state
variable updates. Do NOT describe protocol intent or what the code should do.
Do NOT analyze functions from other contracts (helper pools, libraries, etc.).

Prioritize functions that contain ANY of these high-risk mechanics:
1. Narrowing type casts: uint128 → int128, uint256 → uint128, int256 → int128
2. Arithmetic inside unchecked {{ }} blocks that could wrap/overflow
3. Comparisons using < vs <= at boundary values (tick boundaries, price limits)
4. State variables (reserves, accumulators) that are NOT updated after a token transfer
5. Update ordering: which state variable is updated BEFORE vs AFTER a key operation

Rules:
- Write 3–5 continuous sentences per function (NOT bullet points, NOT terse labels)
- For type casts: name the source and destination types and whether overflow is checked
- For arithmetic: state whether inside unchecked block, what happens on overflow/underflow
- For comparisons: state exactly whether < or <= is used and the impact on boundary values
- For state variables: name which are UPDATED and which are NOT UPDATED after key operations
- For ordering: describe what is updated before vs after the critical operation

Output format (EXACTLY — use plain function name, no contract prefix):
FUNC burn():
  <3–5 sentences describing mechanics of {primary_contract}.burn>

FUNC mint():
  <3–5 sentences describing mechanics of {primary_contract}.mint>

FUNC <next_function>():
  <3–5 sentences>

Output ONLY the FUNC blocks for {primary_contract} functions.
Do NOT write protocol intent, invariants, or findings.

CONTRACT SOURCE:
{source}
"""

# Turn 1.5: convert FUNC mechanics blocks → testable INV-Mx vulnerability hypotheses.
# These INV-Mx lines are fed into the standard Turn 2 prompt as `injected_invariants`,
# enabling the Q1/Q2/Q3 violation reasoning chain to work correctly on specific patterns.
_MECHANICS_TO_INV_PROMPT_TEMPLATE = """\
You are a vulnerability hypothesis extractor for smart contract auditing.

INPUT: Mechanical descriptions of smart contract functions (FUNC blocks).
TASK: Convert notable mechanics into testable vulnerability hypotheses (INV-Mx lines).

Target exactly these 5 pattern classes — skip everything else:
  PATTERN-A (sign-flip cast): A narrowing cast (uint128→int128, uint256→int128) where
    input can exceed destination type max — causing the negated value to flip sign
    (e.g., -int128(amount) becomes positive), adding liquidity instead of removing it.
  PATTERN-B (unchecked-missing underflow): A subtraction OUTSIDE any unchecked block that
    naturally underflows in correct usage — reverts under Solidity 0.8+ and permanently
    blocks callers (DoS).
  PATTERN-C (wrong boundary comparison): A strict < or > at a tick/price boundary that
    wrongly excludes the boundary value, causing incorrect active-liquidity accounting.
  PATTERN-D (missing reserve/state update): A reserve or unclaimed-reward variable that
    is NOT decremented/cleared after tokens are transferred out — inflating accounting state.
  PATTERN-E (wrong accumulator update order): An accumulator (secondsPerLiquidity,
    rewardPerShare, feeGrowth) reads its denominator (liquidity, totalShares) AFTER that
    denominator has already been modified in the same function — wrong value accumulated.

Output format — EXACTLY one line per hypothesis:
INV-M1: <fn>() — PATTERN-<X> — exact code: `<expression at fault>` — consequence: <what breaks>
INV-M2: <fn>() — PATTERN-<X> — exact code: `<expression at fault>` — consequence: <what breaks>

Rules:
- Output ONLY INV-Mx lines. No headers, no FUNC blocks, no explanations.
- Quote the EXACT code token or expression (cast, subtraction, comparison, variable name).
- Skip any function with no clear match to PATTERN-A … PATTERN-E.
- Maximum 8 INV lines total. Prefer quality over quantity.
- If the same pattern appears in multiple functions, write one INV per function.

EXAMPLE (copy this format exactly):
INPUT: withdraw(): Converts uint256 shares to int256 via narrowing cast. Negates result to reduce position.
OUTPUT:
INV-M1: withdraw() — PATTERN-A — exact code: `int256(shares)` — consequence: if shares > type(int256).max, cast overflows, sign flips positive, position increased instead of decreased

FUNC MECHANICS:
{turn1_mechanics}
"""


def _extract_field(block: str, field: str) -> str:
    m = _re_rag.search(
        rf'^{field}:\s*(.+?)(?=\n[A-Z_]+:|\Z)', block,
        _re_rag.DOTALL | _re_rag.MULTILINE,
    )
    return m.group(1).strip() if m else ""


def build_rag_query(title: str, description: str) -> str:
    text = f"{title}. {description}"
    text = _re_rag.sub(r'\b\w+\s*\([^)]*\)', '', text)               # strip fn signatures
    text = _re_rag.sub(r'\b[a-zA-Z_]+\.[a-zA-Z_]+\b', '', text)     # strip dotted refs
    text = _re_rag.sub(r'\b[A-Z][a-z]+[A-Z][a-zA-Z]*\b', '', text)  # strip CamelCase
    text = _re_rag.sub(
        r'\b(?:Trident|BentoBox|Sushi|Uniswap|Aave|Compound|Balancer)\b',
        '', text, flags=_re_rag.IGNORECASE,
    )
    return _re_rag.sub(r'\s+', ' ', text).strip()


def _build_rag_observations(response: str, agent_id: str) -> list:
    matches = list(_FINDING_BLOCK_RE.finditer(response))
    if not matches:
        return []
    retriever = _get_rag_retriever()
    observations = []
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        block = m.group(2)
        # Use ATTACK_PATH as primary description; fall back to EVIDENCE
        attack_path = _extract_field(block, "ATTACK_PATH")
        evidence = _extract_field(block, "EVIDENCE")
        description = attack_path or evidence
        if not description:
            continue
        query = build_rag_query(title, description)
        if not query:
            continue
        with _rag_lock:
            results = retriever.query(query, n_results=3)
        if not results:
            continue
        top_score = results[0]["score"]
        logger.info(
            f"[RAG] agent={agent_id} finding={i+1}/{len(matches)} "
            f"top_score={top_score:.3f} title='{title[:50]}'"
        )
        if top_score < _SCORE_INJECT_THRESHOLD:
            continue
        lines = [f"--- Historical context for FINDING: '{title}' ---"]
        for j, r in enumerate(results, 1):
            if r["score"] < _SCORE_SHOW_THRESHOLD:
                break
            preview = r["content"][:400].replace("\n", " ").strip()
            lines.append(
                f"[{j}] score={r['score']:.3f} | {r['title']}\n"
                f"    Protocol: {r['protocol']} | {preview}"
            )
        observations.append("\n".join(lines))
    return observations


def _normalize_inv_key(inv: str, target_contracts: list[str]) -> str:
    """Cache key cho INV semantic dedup.

    Dùng build_rag_query để strip fn sigs, CamelCase, dotted refs trước khi lấy 8 words đầu.
    Đảm bảo 2 INVs cùng concept (khác word order) map về cùng key.
    """
    inv_lower = inv.lower()
    matched_contract = next(
        (c for c in target_contracts if c.lower() in inv_lower), "unknown"
    )
    clean_meaning = build_rag_query("", inv).lower()
    words = clean_meaning.split()
    return f"{matched_contract.lower()}::{' '.join(words[:8])}"


def _extract_independent_targets(network_summary: str, primary: str) -> list[str]:
    # Parse multi-target contest header: "// TARGET N — ContractName (primary)"
    # Contest 42 (single target): no such header → returns []
    targets = _re_rag.findall(r'TARGET \d+\s*[-—–]\s*(\w+)\s*\(primary\)', network_summary)
    return [t for t in targets if t != primary]


def _extract_callee_coverage_block(network_summary: str) -> str:
    """Parse CALL GRAPH từ network_summary → INTERNAL FUNCTION TARGETS block.

    For per-contract CALL GRAPH format (với [ContractName] headers), preserves
    contract attribution in output. For flat format (single contract), uses
    existing behavior. External calls ([EXTERNAL:]) are stripped from callee lists.
    """
    if not network_summary:
        return ""
    # Capture CALL GRAPH block: only lines starting with space/[ (callee lines / section
    # headers) or blank lines. Stops at first non-CALL-GRAPH content (DATA-FLOW GRAPH, ===, etc.)
    cg_match = _re_rag.search(r'CALL GRAPH:\s*\n((?:[ \t\[].*\n|\n)*)', network_summary)
    if not cg_match:
        return ""

    cg_text = cg_match.group(1)
    callee_line_re = _re_rag.compile(
        r'^\s+([a-zA-Z0-9_]+)\(\)\s*→\s*calls:\s*([^\n]+)', _re_rag.MULTILINE
    )

    def _parse_entries(text: str) -> list[str]:
        entries = []
        for m in callee_line_re.finditer(text):
            caller = m.group(1)
            raw = _re_rag.sub(r'\s*\|\s*\[EXTERNAL:[^\]]+\]', '', m.group(2))
            raw = raw.replace('(leaf)', '')
            callees = [c.strip() for c in raw.split(',') if c.strip()]
            if callees:
                entries.append(f"  {caller}() → calls: {', '.join(callees)}")
        return entries

    # Detect per-contract format ([ContractName] headers)
    section_header_re = _re_rag.compile(r'^\[(\w+)\]$', _re_rag.MULTILINE)
    sections = list(section_header_re.finditer(cg_text))

    if sections:
        output_parts = ["=== INTERNAL FUNCTION TARGETS ==="]
        for i, sec in enumerate(sections):
            contract_name = sec.group(1)
            start = sec.end()
            end = sections[i + 1].start() if i + 1 < len(sections) else len(cg_text)
            entries = _parse_entries(cg_text[start:end])
            if entries:
                output_parts.append(f"[{contract_name}]")
                output_parts.extend(entries)
        return "\n".join(output_parts) if len(output_parts) > 1 else ""

    # Flat format (single contract): existing behavior
    entries = _parse_entries(cg_text)
    if not entries:
        return ""
    lines = ["=== INTERNAL FUNCTION TARGETS ==="]
    lines.extend(entries)
    return "\n".join(lines)


def _build_invariant_rag_hints(invariant_text: str, agent_id: str,
                                target_contracts: list[str] | None = None) -> tuple:
    """Returns (hint_block: str, num_matched: int) — query RAG per INV-N line."""
    inv_pattern = _re_rag.compile(r'INV-\d+:\s*(.+)', _re_rag.IGNORECASE)
    invariants = inv_pattern.findall(invariant_text)
    if not invariants:
        return "", 0
    retriever = _get_rag_retriever()
    candidates = []  # (top_score, hint_block_str) — collect all, sort later
    # Agents that write generic domain patterns (no contract names by design)
    _M1_BYPASS_AGENTS = {"clmm_specialist"}

    for i, inv in enumerate(invariants):
        # M1: positive filter — skip invariants không liên quan đến target contracts
        # Bypass for agents that intentionally write generic patterns (e.g. clmm_specialist)
        if target_contracts and agent_id not in _M1_BYPASS_AGENTS:
            inv_lower = inv.lower()
            if not any(c.lower() in inv_lower for c in target_contracts):
                logger.info(
                    f"[RAG] agent={agent_id} inv={i+1} → skip (not about primary target)"
                )
                continue
        # FIX-3: semantic dedup — reuse cache nếu cùng concept đã được query trong session này
        cache_key = _normalize_inv_key(inv, target_contracts or [])
        with _inv_cache_lock:
            if cache_key in _inv_cache:
                cached_score, cached_block = _inv_cache[cache_key]
                logger.info(
                    f"[RAG] agent={agent_id} inv={i+1} → reuse cache (key={cache_key[:50]})"
                )
                candidates.append((cached_score, cached_block))
                continue
        query = build_rag_query("", inv)
        if not query:
            continue
        with _rag_lock:
            results = retriever.query(query, n_results=3)
        top_score = results[0]["score"] if results else 0.0
        if not results or top_score < _SCORE_INJECT_THRESHOLD_INV:
            logger.info(
                f"[RAG] agent={agent_id} inv={i+1} score={top_score:.3f} → skip (below threshold)"
            )
            continue
        logger.info(
            f"[RAG] agent={agent_id} inv={i+1} score={top_score:.3f} inv='{inv[:60]}'"
        )
        block = [f"INV-{i+1} historical violations (score={top_score:.3f}):"]
        for j, r in enumerate(results, 1):
            if r["score"] < _SCORE_SHOW_THRESHOLD:
                break
            preview = r["content"][:350].replace("\n", " ").strip()
            block.append(f"  [{j}] {r['title']} | {preview}")
        with _inv_cache_lock:
            _inv_cache[cache_key] = (top_score, "\n".join(block))
        candidates.append((top_score, "\n".join(block)))
    # Inject top-N by score — giữ highest-confidence hints, bỏ borderline
    candidates.sort(key=lambda x: x[0], reverse=True)
    hints = [b for _, b in candidates[:_MAX_RAG_INJECT_PER_AGENT]]
    return "\n\n".join(hints), len(hints)


_FUNC_HEADER_SPLIT_RE = _re_rag.compile(
    r'(?:^|\n)[ \t]*(?:[#*`>-]+\s*)?FUNC\s+[\w.]+\([^)]*\)[ \t]*:[ \t]*(?:\n|$)',
    _re_rag.MULTILINE,
)

_FILE_SECTION_RE = _re_rag.compile(
    r'(// ─── .+?\.sol.*? ───)',
    _re_rag.MULTILINE,
)

_TARGET_DECL_RE = _re_rag.compile(
    r'// TARGET \d+\s*[-—–]\s*(\w+)',
    _re_rag.MULTILINE,
)


def _build_code_similarity_rag_hints(
    turn1_mechanics: str,
    agent_id: str,
    target_contracts: list[str] | None = None,
    primary_contract: str = "",
) -> tuple[str, int]:
    """
    RAG track cho code_similarity_auditor.
    Query dựa trên FUNC blocks từ Turn 1 mechanics analysis (không phải INV statements).
    """
    retriever = _get_rag_retriever()

    # Split on FUNC header lines — avoids the empty-line trap of findall + .+
    # Handles prefix variations (##, **, etc.) and params in signatures
    # [\w.]+ allows Contract.function() format as well as plain function() format
    parts = _FUNC_HEADER_SPLIT_RE.split(turn1_mechanics)
    # parts[0] = preamble before first FUNC header; parts[1:] = block contents
    func_blocks = [p.strip() for p in parts[1:] if p.strip() and len(p.strip()) > 40]

    # Fallback: no FUNC headers found — use paragraphs as queries
    if not func_blocks and len(turn1_mechanics) > 60:
        paras = [
            p.strip() for p in _re_rag.split(r'\n\s*\n', turn1_mechanics)
            if len(p.strip()) > 60
        ]
        func_blocks = paras[:3]

    # Filter to primary contract blocks if contract name is embedded in header text
    if primary_contract and func_blocks:
        pc_lower = primary_contract.lower()
        # Find blocks where the surrounding FUNC header (in original text) mentions primary
        # Build header list from original split positions
        header_matches = list(_FUNC_HEADER_SPLIT_RE.finditer(turn1_mechanics))
        if header_matches and len(header_matches) == len(func_blocks):
            primary_blocks = [
                b for h, b in zip(header_matches, func_blocks)
                if pc_lower in h.group(0).lower()
            ]
            if primary_blocks:
                func_blocks = primary_blocks
                logger.info(
                    f"[code_sim] Filtered to {len(func_blocks)} blocks for '{primary_contract}'"
                )

    logger.info(
        f"[code_sim] Turn1: {len(turn1_mechanics)} chars → {len(func_blocks)} blocks, "
        f"preview: {repr(turn1_mechanics[:150])}"
    )

    if not func_blocks:
        return "", 0

    hints: list[str] = []
    rag_calls = 0

    for block_text in func_blocks[:3]:  # cap: 3 functions tối đa
        text = block_text.strip()
        if len(text) < 40:
            continue
        query = build_rag_query("", text)
        if not query:
            continue

        cache_key = f"code_mech::{query[:64]}"
        with _inv_cache_lock:
            if cache_key in _inv_cache:
                cached_score, cached_block = _inv_cache[cache_key]
                if cached_score >= _SCORE_INJECT_THRESHOLD_INV and cached_block:
                    hints.append(cached_block)
                continue

        with _rag_lock:
            results = retriever.query(query, n_results=3)
        rag_calls += 1

        top_score = results[0]["score"] if results else 0.0
        if top_score < _SCORE_INJECT_THRESHOLD_INV:
            with _inv_cache_lock:
                _inv_cache[cache_key] = (top_score, "")
            continue

        block_lines = [f"Code pattern similarity (score={top_score:.3f}):"]
        added = 0
        for r in results:
            if r["score"] < _SCORE_INJECT_THRESHOLD_INV or added >= 2:
                break
            preview = r["content"][:350].replace("\n", " ").strip()
            block_lines.append(f"  [{added + 1}] {r['title']} | {preview}")
            added += 1

        if added > 0:
            hint_block = "\n".join(block_lines)
            hints.append(hint_block)
            with _inv_cache_lock:
                _inv_cache[cache_key] = (top_score, hint_block)

    return "\n\n".join(hints), rag_calls


_TARGET_LINE_RE = _re_rag.compile(
    r'^// TARGET \d+\s*[-—–]\s*\w+.*$\n?',
    _re_rag.MULTILINE,
)

# Matches the multi-target warning block produced by flatten_contest.py:
#   // ⚠️  THIS PROTOCOL HAS N INDEPENDENT AUDIT TARGETS.
#   // Analyze each target SEPARATELY. ...
#   // is shared via direct external calls.
#   //
# Stops before any "// TARGET N — ..." line (negative lookahead on "// TARGET \d").
_MULTI_TARGET_WARN_RE = _re_rag.compile(
    r'^// ⚠️\s+THIS PROTOCOL HAS \d+ INDEPENDENT AUDIT TARGETS\..*$\n'
    r'(?:^//(?! TARGET \d).+$\n|^//\s*$\n)*',
    _re_rag.MULTILINE,
)


def _rewrite_header_for_scope(header: str, primary_contract: str) -> str:
    """
    Thay thế multi-target warning block + tất cả dòng TARGET N trong header
    bằng scope declaration cho primary_contract.

    Nếu header không có TARGET declarations → trả về nguyên vẹn.
    """
    if not _TARGET_LINE_RE.search(header):
        return header
    scope_block = (
        f"// ⚠️  AUDIT SCOPE: {primary_contract} (primary)\n"
        f"// (Other targets in this contest are outside this agent's specialization scope)\n"
    )
    # Step 1: remove the multi-line warning block ("THIS PROTOCOL HAS N INDEPENDENT AUDIT TARGETS")
    rewritten = _MULTI_TARGET_WARN_RE.sub("", header)
    # Step 2: replace first TARGET line with scope declaration, remove the rest
    rewritten, n = _TARGET_LINE_RE.subn(scope_block, rewritten, count=1)
    if n > 0:
        rewritten = _TARGET_LINE_RE.sub("", rewritten)
    return rewritten


def _filter_source_to_primary(
    network_summary: str,
    primary_contract: str,
    exclude_peripheral_suffixes: bool = True,
) -> str:
    """
    Lọc network_summary để chỉ giữ lại source của primary contract
    và các math library dependencies. Loại bỏ các non-primary target contracts.

    Logic hoàn toàn generic — không hardcode tên contract:
    1. Đọc danh sách tất cả TARGETs từ header của network_summary
    2. Non-primary targets = tất cả TARGETs trừ primary_contract
    3. Exclude file sections có tên khớp với non-primary target
    4. Optionally exclude peripheral "Related contracts" theo suffix (Manager, Helper)
    5. Giữ lại tất cả sections còn lại (primary + math libs)
    6. Rewrite header để chỉ declare primary target (tránh hallucination)
    """
    _PERIPHERAL_SUFFIXES = ("manager", "helper")

    if not primary_contract:
        return network_summary

    header_block = network_summary[:2000]
    all_targets = _TARGET_DECL_RE.findall(header_block)
    non_primary_targets = [t for t in all_targets if t != primary_contract]

    if not all_targets:
        logger.warning(
            f"[code_sim] _filter_source_to_primary: no TARGET declarations found, "
            f"returning full source"
        )
        return network_summary

    parts = _FILE_SECTION_RE.split(network_summary)
    # Rewrite header block so model sees only 1 audit target (prevents hallucination)
    result = [_rewrite_header_for_scope(parts[0], primary_contract)]
    excluded_peripheral: list[str] = []

    for i in range(1, len(parts), 2):
        header  = parts[i]
        content = parts[i + 1] if i + 1 < len(parts) else ""

        # Only exclude peripheral "Related contracts" by suffix (Manager, Helper).
        # Co-primary TARGET contracts are kept in body for context.
        if exclude_peripheral_suffixes:
            fname_match = _re_rag.search(r'[\w]+\.sol', header)
            if fname_match:
                fname_stem = fname_match.group(0)[:-4]  # strip .sol
                if any(fname_stem.lower().endswith(sfx) for sfx in _PERIPHERAL_SUFFIXES):
                    excluded_peripheral.append(fname_stem)
                    continue

        result.append(header)
        result.append(content)

    filtered = "".join(result)
    logger.info(
        f"[code_sim] source filter: {len(network_summary)} → {len(filtered)} chars "
        f"| co-primary targets kept: {non_primary_targets}"
        f"| excluded peripheral: {excluded_peripheral}"
        f"| header rewritten for scope: {primary_contract}"
    )
    return filtered


# Agents in the standard flow that should receive filtered source (not full network_summary)
_FILTERED_SOURCE_AGENTS: set[str] = {"clmm_specialist"}

# Compiled regex for flexible INV-Mx line extraction (Fix C)
_INV_LINE_RE = re.compile(r'INV-M\d+\s*:.+')


def _build_phase_c_review_list(
    expert_findings: List[Dict[str, Any]],
    invariants: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    RC-3 Two-step Phase C: build per-(SWC, function) review list for attackers.

    RC-3a: No social proof — no confidence scores, no group counts.
           Header frames claims as UNVERIFIED, default stance is DISMISS.
    RC-3b: One entry per (SWC, function) pair — forces per-function evaluation,
           prevents one SWC-level dismiss/confirm from sweeping all related findings.
    Invariant section appended when invariants are provided.
    """
    if not expert_findings:
        return ""

    # Build deduplicated per-(swc, func) items, preserving claimed evidence
    seen: set = set()
    items: List[Dict[str, Any]] = []
    for f in expert_findings:
        swc = f.get("swc_id") or "SWC-???"
        funcs = f.get("affected_functions") or []
        evidence_list = f.get("evidence") or []
        evidence = evidence_list[0] if evidence_list else ""
        title = f.get("title", "Untitled")

        if funcs:
            for func in funcs[:2]:  # max 2 functions per finding
                key = (swc, func.lower().rstrip("()"))
                if key not in seen:
                    seen.add(key)
                    items.append({"swc": swc, "func": func, "title": title, "evidence": evidence})
        else:
            key = (swc, "")
            if key not in seen:
                seen.add(key)
                items.append({"swc": swc, "func": "", "title": title, "evidence": evidence})

    if not items:
        return ""

    items = items[:25]  # cap list to avoid context overflow

    # RC-3a: adversarial framing — no confidence/group signals
    lines = [
        f"=== UNVERIFIED CLAIMS — {len(items)} per-function claims require independent attacker verification ===",
        "DEFAULT STANCE: DISMISS — only CONFIRM if you independently trace the exploit through contract code above.",
        "",
    ]
    for i, item in enumerate(items, 1):
        func_str = f" in {item['func']}" if item["func"] else ""
        ev_str = f"\n  Claimed evidence: {item['evidence']}" if item["evidence"] else ""
        lines.append(
            f"[F{i}] {item['swc']}{func_str} — {item['title'][:70]}"
            + ev_str
        )

    lines += [
        "",
        "Required format — one block per claim, INCLUDE function name:",
        "  [ATTACKER_DISMISS SWC-101 transfer()]",
        "  Finding: <title>",
        "  Reason: <why this specific function is NOT vulnerable>",
        "  ---",
        "  [ATTACKER_CONFIRM SWC-114 approve()]",
        "  Finding: <title>",
        "  Path: <concrete step-by-step exploit through this function>",
        "",
    ]

    # Invariant attack objectives section
    if invariants:
        lines += [
            "=== INVARIANT ATTACK OBJECTIVES — Prove or disprove each invariant ===",
            "For each invariant you can VIOLATE, use [ATTACKER_EXPLOIT INV-xxx]:",
            "",
        ]
        for inv in invariants[:10]:
            funcs_str = ", ".join(inv.get("functions") or []) or "—"
            hint_str = f"\n  Hint: {inv['violation_hint']}" if inv.get("violation_hint") else ""
            lines.append(
                f"  [{inv['id']}] {inv.get('statement', '')}\n"
                f"    Try via: {funcs_str}{hint_str}"
            )
        lines += [
            "",
            "  [ATTACKER_EXPLOIT INV-001]",
            "  Path: <step-by-step exploit>",
            "  Impact: <what attacker gains>",
            "  Feasible: yes/no",
            "",
        ]

    return "\n".join(lines)


class _RateLimiter:
    """
    Sliding-window rate limiter — thread-safe.

    Two modes (mutually exclusive, global takes priority):
    - LLM_GLOBAL_RPM_LIMIT > 0 : cross-process file-based limiter shared across
      all parallel evaluate_phase5b.py processes. Enforces a single RPM cap for
      the entire machine, preventing 429 cascade when running --parallel N.
    - LLM_RPM_LIMIT > 0        : per-process in-memory limiter (original behaviour,
      used for single-process runs).
    """

    _SHARED_FILE = "/tmp/mirofish_global_rpm.json"
    _LOCK_FILE   = "/tmp/mirofish_global_rpm.lock"

    def __init__(self):
        import threading as _threading
        self._lock = _threading.Lock()
        self._timestamps: list = []
        self.rpm        = int(os.environ.get("LLM_RPM_LIMIT",        "0"))
        self.global_rpm = int(os.environ.get("LLM_GLOBAL_RPM_LIMIT", "0"))

    def acquire(self):
        import time as _time
        if self.global_rpm > 0:
            self._acquire_global(_time)
        elif self.rpm > 0:
            self._acquire_local(_time)

    # ------------------------------------------------------------------ #
    # Per-process in-memory limiter (original)                            #
    # ------------------------------------------------------------------ #
    def _acquire_local(self, _time):
        with self._lock:
            now = _time.monotonic()
            self._timestamps = [t for t in self._timestamps if now - t < 60.0]
            if len(self._timestamps) >= self.rpm:
                sleep_for = 60.0 - (now - self._timestamps[0]) + 0.1
                if sleep_for > 0:
                    logger.debug(f"[rate limiter] sleeping {sleep_for:.1f}s (RPM cap={self.rpm})")
                    _time.sleep(sleep_for)
            self._timestamps.append(_time.monotonic())

    # ------------------------------------------------------------------ #
    # Cross-process file-based limiter (global)                           #
    # ------------------------------------------------------------------ #
    def _acquire_global(self, _time):
        import fcntl
        import json as _json

        while True:
            wait_for = 0.0
            with open(self._LOCK_FILE, "w") as lf:
                fcntl.flock(lf, fcntl.LOCK_EX)
                try:
                    now = _time.time()
                    cutoff = now - 60.0
                    try:
                        with open(self._SHARED_FILE) as f:
                            data = _json.load(f)
                        ts = [t for t in data.get("ts", []) if t > cutoff]
                    except (FileNotFoundError, _json.JSONDecodeError):
                        ts = []

                    if len(ts) < self.global_rpm:
                        ts.append(now)
                        with open(self._SHARED_FILE, "w") as f:
                            _json.dump({"ts": ts}, f)
                        return  # slot acquired

                    wait_for = ts[0] + 60.0 - now + 0.1
                finally:
                    fcntl.flock(lf, fcntl.LOCK_UN)

            logger.debug(
                f"[global rate limiter] waiting {wait_for:.1f}s "
                f"(global RPM cap={self.global_rpm})"
            )
            _time.sleep(min(wait_for, 1.0))


_rate_limiter = _RateLimiter()


class CyberSessionOrchestrator:
    """
    Orchestrate toàn bộ 3-phase vulnerability analysis session.
    Dùng LLM trực tiếp thay vì OASIS subprocess (portable hơn).
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        boost_llm_client: Optional[LLMClient] = None,
    ):
        if llm_client is not None:
            self.llm = llm_client
        elif Config.LLM2_VERTEX_AI_KEY_FILE and Config.LLM2_BASE_URL:
            client1 = LLMClient(rpm_slot_file="/tmp/mirofish_rpm_0.json")
            client2 = LLMClient(
                vertex_key_file=Config.LLM2_VERTEX_AI_KEY_FILE,
                base_url=Config.LLM2_BASE_URL,
                model=Config.LLM_MODEL_NAME,
                rpm_slot_file="/tmp/mirofish_rpm_1.json",
                rpm_limit=Config.LLM2_GLOBAL_RPM_LIMIT,
            )
            self.llm = LLMClientPool([client1, client2])
            logger.info("LLMClientPool: 2 Vertex AI accounts active, pool_size=2")
        else:
            self.llm = LLMClient()
        # boost_llm dùng cho expensive operations (Phase C attacker reasoning)
        self.boost_llm = boost_llm_client or self._try_build_boost_client()
        self.env_builder = CyberOasisEnvBuilder()
        self.task_manager = TaskManager()

    def run_session_async(
        self,
        graph_id: str,
        network_summary: str,
        profiles: List[CyberAgentProfile],
        session_id: Optional[str] = None,
        mode: str = "network_security",
        invariants: Optional[List[Dict[str, Any]]] = None,
        manifest: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Khởi chạy session trong background thread.
        Returns task_id để frontend poll.

        Args:
            mode: "network_security" (default) | "contract_audit"
            invariants: protocol invariants from ContractInvariantExtractor (contract_audit only)
            manifest: ContractManifest from flatten_contest_dir (contract_audit only)
        """
        session_id = session_id or f"cyber_{uuid.uuid4().hex[:12]}"
        task_id = self.task_manager.create_task(
            task_type="cyber_analysis_session",
            metadata={
                "session_id": session_id,
                "graph_id": graph_id,
                "agent_count": len(profiles),
                "mode": mode,
            }
        )

        thread = threading.Thread(
            target=self._session_worker,
            args=(task_id, session_id, graph_id, network_summary, profiles, mode, invariants, manifest),
            daemon=True
        )
        thread.start()
        return task_id

    def build_network_context_from_zep(self, graph_id: str) -> str:
        """
        Query Zep KG → tóm tắt hạ tầng để inject vào agent prompts.
        Trả về text mô tả: hosts, zones, CVEs, security controls, critical assets.
        Dùng thay cho việc caller phải tự build network_summary.
        """
        try:
            from ..utils.zep_paging import fetch_all_nodes, fetch_all_edges
            from .graph_builder import GraphBuilderService

            zep = GraphBuilderService().client
            nodes = fetch_all_nodes(zep, graph_id)
            edges = fetch_all_edges(zep, graph_id)

            hosts, services, vulns, zones = [], [], [], []
            for node in nodes:
                labels = node.labels or []
                attrs = node.attributes or {}
                name = getattr(node, "name", "unknown")
                if "NetworkHost" in labels:
                    hosts.append({
                        "name": name,
                        "zone": attrs.get("zone", "unknown"),
                        "ip": attrs.get("ip_address", "?"),
                        "os": attrs.get("os_version", "?"),
                        "patch": attrs.get("patch_status", "?"),
                        "critical": attrs.get("is_critical", "false"),
                        "controls": attrs.get("controls", "none"),
                    })
                elif "NetworkService" in labels:
                    services.append(f"{name} (port {attrs.get('port','?')}, exposed={attrs.get('is_exposed','?')})")
                elif "Vulnerability" in labels:
                    vulns.append(f"{attrs.get('cve_id', name)} [{attrs.get('severity','?')}] patched={attrs.get('is_patched','?')}")
                elif "NetworkZone" in labels:
                    zones.append(f"{name} (trust={attrs.get('trust_level','?')})")

            lines = [f"Network topology summary (graph: {graph_id}):"]

            if zones:
                lines.append(f"\nNetwork Zones ({len(zones)}):")
                for z in zones:
                    lines.append(f"  - {z}")

            if hosts:
                lines.append(f"\nHosts ({len(hosts)}):")
                for h in hosts:
                    crit = " [CRITICAL]" if str(h["critical"]).lower() == "true" else ""
                    lines.append(
                        f"  - {h['name']}{crit} | Zone: {h['zone']} | IP: {h['ip']}"
                        f" | OS: {h['os']} | Patch: {h['patch']} | Controls: {h['controls']}"
                    )

            if services:
                lines.append(f"\nServices ({len(services)}):")
                for s in services[:15]:
                    lines.append(f"  - {s}")

            if vulns:
                lines.append(f"\nKnown Vulnerabilities ({len(vulns)}):")
                for v in vulns[:15]:
                    lines.append(f"  - {v}")

            # Edge summary
            edge_types: Dict[str, int] = {}
            for e in edges:
                rt = getattr(e, "relation_type", "unknown")
                edge_types[rt] = edge_types.get(rt, 0) + 1
            if edge_types:
                lines.append(f"\nRelationships: " + ", ".join(f"{k}×{v}" for k, v in edge_types.items()))

            return "\n".join(lines)

        except Exception as e:
            logger.warning(f"build_network_context_from_zep failed for {graph_id}: {e}")
            return f"Network graph ID: {graph_id}. (Context unavailable — Zep query failed: {e})"

    def build_contract_context_from_zep(self, graph_id: str) -> str:
        """
        Query Zep KG → tóm tắt contract entity để inject vào agent prompts.
        Dùng ContractKGBuilder.build_context_summary() nếu có, fallback về Zep raw query.
        """
        try:
            from .contract_kg_builder import ContractKGBuilder
            kg_builder = ContractKGBuilder(llm_client=self.llm)
            return kg_builder.build_context_summary(graph_id)
        except Exception as e:
            logger.warning(f"build_contract_context_from_zep failed for {graph_id}: {e}")
            return f"Contract graph ID: {graph_id}. (Context unavailable — KG query failed: {e})"

    # ─── Session state persistence ────────────────────────────────────────────

    @staticmethod
    def _session_dir(session_id: str) -> str:
        return os.path.join(Config.UPLOAD_FOLDER, "cyber_sessions", session_id)

    def _save_session_state(self, state: CyberSessionState):
        """Persist session state to JSON so GET endpoints can read it."""
        session_dir = self._session_dir(state.session_id)
        os.makedirs(session_dir, exist_ok=True)
        path = os.path.join(session_dir, "state.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(state), f, ensure_ascii=False, indent=2)

    @staticmethod
    def load_session_state(session_id: str) -> Optional[Dict[str, Any]]:
        """Load persisted session state. Returns None nếu không tìm thấy."""
        path = os.path.join(
            Config.UPLOAD_FOLDER, "cyber_sessions", session_id, "state.json"
        )
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _append_feed_post(self, session_id: str, post: Dict[str, Any]):
        """Append 1 feed post (agent response) vào feed.jsonl của session."""
        session_dir = self._session_dir(session_id)
        os.makedirs(session_dir, exist_ok=True)
        path = os.path.join(session_dir, "feed.jsonl")
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(post, ensure_ascii=False) + "\n")

    @staticmethod
    def load_feed(session_id: str) -> List[Dict[str, Any]]:
        """Load feed posts từ session."""
        path = os.path.join(
            Config.UPLOAD_FOLDER, "cyber_sessions", session_id, "feed.jsonl"
        )
        if not os.path.exists(path):
            return []
        posts = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        posts.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return posts

    # ─── Worker ───────────────────────────────────────────────────────────────

    def _session_worker(
        self,
        task_id: str,
        session_id: str,
        graph_id: str,
        network_summary: str,
        profiles: List[CyberAgentProfile],
        mode: str = "network_security",
        invariants: Optional[List[Dict[str, Any]]] = None,
        manifest: Optional[Dict[str, Any]] = None,
    ):
        try:
            self.task_manager.update_task(
                task_id, status=TaskStatus.PROCESSING,
                progress=5, message="Khởi tạo session..."
            )

            # Pick env_builder and phase function based on mode
            if mode == "contract_audit":
                cm = _get_contract_modules()
                env_builder = cm["env_builder"](manifest=manifest)
                get_phase = cm["get_phase"]
                config = env_builder.build_config(
                    session_id=session_id,
                    graph_id=graph_id,
                    contract_id=graph_id,
                    profiles=profiles,
                    contract_summary=network_summary,
                )
                # RC-1 (2nd layer): extract known function names once per session
                known_functions = cm["extract_funcs"](network_summary)
                logger.info(
                    f"  Contract known functions ({len(known_functions)}): "
                    f"{', '.join(sorted(known_functions)) or '(none extracted)'}"
                )
            else:
                env_builder = self.env_builder
                get_phase = get_phase_for_round
                config = env_builder.build_config(
                    session_id=session_id,
                    graph_id=graph_id,
                    profiles=profiles,
                    network_summary=network_summary,
                )
                known_functions = None

            session_state = CyberSessionState(
                session_id=session_id,
                graph_id=graph_id,
            )
            self._save_session_state(session_state)

            # v2 feature flag — 3-round architecture
            _audit_v = os.environ.get("AUDIT_PIPELINE_VERSION", "v1").lower()
            if mode == "contract_audit" and _audit_v == "v2":
                # Extract target contract names for RAG scope restriction
                _tc: list[str] = []
                if manifest:
                    _tc = [manifest.get("primary", "")] + manifest.get("secondary", [])
                    _tc = [c for c in _tc if c]
                self._run_contract_audit_v2(
                    task_id=task_id,
                    session_id=session_id,
                    graph_id=graph_id,
                    network_summary=network_summary,
                    profiles=profiles,
                    known_functions=known_functions,
                    session_state=session_state,
                    invariants=invariants,
                    target_contracts=_tc or None,
                )
                return

            # RC-3 Two-step Phase C: computed after round 7, injected into Phase C rounds
            phase_c_review_list = ""

            # v1: Chạy 10 rounds
            for round_num in range(1, TOTAL_ROUNDS + 1):
                phase = get_phase(round_num)
                progress = 5 + int((round_num - 1) / TOTAL_ROUNDS * 85)

                self.task_manager.update_task(
                    task_id,
                    progress=progress,
                    message=f"Phase {phase} — Round {round_num}/{TOTAL_ROUNDS}"
                )

                self._run_round(
                    round_num=round_num,
                    phase=phase,
                    profiles=profiles,
                    session_state=session_state,
                    network_summary=network_summary,
                    config=config,
                    mode=mode,
                    env_builder=env_builder,
                    known_functions=known_functions,
                    phase_c_review_list=phase_c_review_list,
                )

                session_state.current_round = round_num
                session_state.current_phase = phase
                self._save_session_state(session_state)

                # RC-3: after Phase B ends (round 7), build Phase C review list
                if round_num == 7 and mode == "contract_audit":
                    phase_c_review_list = _build_phase_c_review_list(
                        session_state.expert_findings,
                        invariants=invariants,
                    )
                    logger.info(
                        f"Phase C review list built: "
                        f"{len(phase_c_review_list.splitlines())} lines from "
                        f"{len(session_state.expert_findings)} expert findings"
                        + (f", {len(invariants)} invariants" if invariants else "")
                    )

                # Inter-round cooldown — let Vertex AI TPM window partially recover
                # before next burst. Reads LLM_ROUND_COOLDOWN_S (default 15s).
                if round_num < TOTAL_ROUNDS:
                    cooldown = float(os.environ.get("LLM_ROUND_COOLDOWN_S", "15"))
                    if cooldown > 0:
                        time.sleep(cooldown)

            session_state.current_phase = "done"

            # P8: Attacker gate — finalize confidence với net vote ratio sau Phase C
            if mode == "contract_audit":
                self._apply_attacker_gate(session_state)

            self._save_session_state(session_state)

            # Serialize findings cho result
            self.task_manager.complete_task(task_id, {
                "session_id": session_id,
                "graph_id": graph_id,
                "expert_findings": session_state.expert_findings,
                "attacker_findings": session_state.attacker_findings,
                "semantic_findings": session_state.semantic_findings,
                "total_findings": (
                    len(session_state.expert_findings) +
                    len(session_state.attacker_findings)
                ),
                "rounds_completed": TOTAL_ROUNDS,
            })

        except Exception as e:
            import traceback
            self.task_manager.fail_task(task_id, f"{e}\n{traceback.format_exc()}")

    # ─── Round execution ──────────────────────────────────────────────────────

    def _run_round(
        self,
        round_num: int,
        phase: str,
        profiles: List[CyberAgentProfile],
        session_state: CyberSessionState,
        network_summary: str,
        config: Any,
        mode: str = "network_security",
        env_builder=None,
        known_functions=None,
        phase_c_review_list: str = "",
    ):
        """
        Chạy 1 round: dispatcher cho two-stage (Phase A/B contract_audit) hoặc single-stage.

        Two-stage: Stage 1 (free-form analysis + CLAIMs) → Stage 2 (FINDINGs + CHALLENGE/VALIDATE).
        Single-stage: Phase C attackers và network_security mode dùng luồng cũ.
        """
        if env_builder is None:
            env_builder = self.env_builder

        active_profiles = env_builder.get_active_agents_for_phase(profiles, phase)
        prior_context = self._build_prior_context(session_state, mode=mode)
        pool_size = getattr(self.llm, "pool_size", 1)
        max_workers = max(int(os.environ.get("LLM_MAX_WORKERS", "1")), pool_size)

        two_stage = (
            os.environ.get("TWO_STAGE_ROUNDS", "true").lower() == "true"
            and mode == "contract_audit"
            and phase in ("A", "B")
        )

        if two_stage:
            logger.info(f"[Round {round_num}] Two-stage mode: Phase={phase}, {len(active_profiles)} agents")

            # Stage 1: free-form analysis + CLAIM declarations
            stage1_posts = self._run_stage1(
                round_num=round_num, phase=phase,
                active_profiles=active_profiles,
                session_state=session_state,
                prior_context=prior_context,
                network_summary=network_summary,
                mode=mode, env_builder=env_builder,
                known_functions=known_functions,
                max_workers=max_workers,
            )
            stage1_claims = self._parse_stage1_claims(stage1_posts)
            session_state.round_stage1_posts[round_num] = stage1_posts
            logger.info(
                f"[Round {round_num}] Stage 1 done: {len(stage1_posts)} posts, "
                f"{len(stage1_claims)} CLAIMs extracted"
            )

            # Inter-stage cooldown — let Vertex AI TPM window recover after Stage 1 burst
            inter_stage_cooldown = float(os.environ.get("LLM_INTER_STAGE_COOLDOWN_S", "30"))
            if inter_stage_cooldown > 0:
                logger.info(f"[Round {round_num}] Inter-stage cooldown {inter_stage_cooldown:.0f}s...")
                time.sleep(inter_stage_cooldown)

            # Stage 2: structured findings with shared feed + CHALLENGE/VALIDATE
            feed_context = self._build_feed_context(round_num, stage1_posts, stage1_claims=stage1_claims)
            stage2_prior = feed_context + "\n\n" + prior_context

            logger.info(f"[Round {round_num}] Stage 2 starting: {len(active_profiles)} agents")
            self._run_stage2(
                round_num=round_num, phase=phase,
                active_profiles=active_profiles,
                session_state=session_state,
                prior_context=stage2_prior,
                network_summary=network_summary,
                mode=mode, env_builder=env_builder,
                known_functions=known_functions,
                phase_c_review_list=phase_c_review_list,
                stage1_claims=stage1_claims,
                max_workers=max_workers,
            )
            return  # two-stage path complete

        # ── Single-stage path (Phase C, network_security, or TWO_STAGE_ROUNDS=false) ──
        self._run_single_stage(
            round_num=round_num, phase=phase,
            active_profiles=active_profiles,
            session_state=session_state,
            prior_context=prior_context,
            network_summary=network_summary,
            mode=mode, env_builder=env_builder,
            known_functions=known_functions,
            phase_c_review_list=phase_c_review_list,
            max_workers=max_workers,
        )

    def _run_single_stage(
        self,
        round_num: int,
        phase: str,
        active_profiles: List,
        session_state: CyberSessionState,
        prior_context: str,
        network_summary: str,
        mode: str,
        env_builder,
        known_functions,
        phase_c_review_list: str,
        max_workers: int,
    ):
        """
        Luồng single-stage gốc — dùng cho Phase C, network_security, và TWO_STAGE_ROUNDS=false.
        """
        def _call_one(profile):
            """Single agent call — thread-safe (no shared mutable state written here)."""
            import time as _time
            gap_context = ""
            if profile.tier == 1 and phase in ("A", "B"):
                if mode == "contract_audit":
                    cm = _get_contract_modules()
                    gap_context = cm["gap_context"](
                        pending_gaps=session_state.pending_gaps(),
                        agent_domain=profile.domain_group,
                    )
                else:
                    gap_context = build_gap_context_for_agent(
                        pending_gaps=session_state.pending_gaps(),
                        agent_domain_group=profile.domain_group,
                    )
            # RC-3: pass phase_c_review_list to Phase C instructions
            phase_instruction = env_builder.build_phase_instruction(
                phase, round_num,
                gap_context=gap_context,
                phase_c_review_list=phase_c_review_list if phase == "C" else "",
            )
            _rate_limiter.acquire()
            # RC1: attacker Phase C → keep raw text (think blocks intact) for tag rescue
            is_attacker_phase_c = (profile.tier == 2 and phase == "C")
            _t0 = _time.time()
            response = self._call_agent(
                profile=profile,
                phase=phase,
                round_num=round_num,
                phase_instruction=phase_instruction,
                prior_context=prior_context,
                network_summary=network_summary,
                mode=mode,
                strip_think=not is_attacker_phase_c,
            )
            _elapsed = _time.time() - _t0
            logger.info(
                f"[TIMING] Phase={phase} R{round_num} agent={profile.agent_id} "
                f"tier={profile.tier} latency={_elapsed:.1f}s"
            )
            return profile, gap_context, response

        if max_workers > 1:
            submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "1.0"))
            results = []
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {}
                for i, p in enumerate(active_profiles):
                    if i > 0 and submit_delay > 0:
                        import time as _t; _t.sleep(submit_delay)
                    futures[pool.submit(_call_one, p)] = p
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        logger.warning(f"Agent {futures[future].agent_id} round {round_num} error: {e}")
        else:
            submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "0.0"))
            results = []
            for i, profile in enumerate(active_profiles):
                if i > 0 and submit_delay > 0:
                    import time as _t; _t.sleep(submit_delay)
                try:
                    results.append(_call_one(profile))
                except Exception as e:
                    logger.warning(f"Agent {profile.agent_id} round {round_num} error: {e}")

        # Process findings sequentially (no LLM — safe, preserves GAP routing order)
        _think_re = re.compile(r'<think>[\s\S]*?</think>')
        for profile, gap_context, response in results:
            # RC1: attacker Phase C responses are raw (think blocks intact for tag rescue).
            is_attacker_phase_c = (profile.tier == 2 and phase == "C")
            feed_content = _think_re.sub('', response).strip() if is_attacker_phase_c else response
            self._append_feed_post(session_state.session_id, {
                "round_num": round_num,
                "phase": phase,
                "agent_id": profile.agent_id,
                "agent_display": profile.display_name,
                "tier": profile.tier,
                "domain_group": profile.domain_group,
                "persona": profile.persona,
                "content": feed_content,
                "timestamp": datetime.now().isoformat(),
                "gap_context_injected": bool(gap_context),
            })
            if profile.tier == 1:
                self._process_expert_response(
                    response, profile, round_num, session_state,
                    mode=mode, known_functions=known_functions,
                )
                if phase in ("A", "B"):
                    self._process_gap_declarations(response, profile, round_num, session_state, mode=mode)
            else:
                # Pass raw response (may contain think blocks) — parse_from_text uses last-tag logic
                self._process_attacker_response(
                    response, profile, round_num, session_state,
                    mode=mode, phase_c_review_list=phase_c_review_list,
                )

        if phase in ("A", "B"):
            self._mark_gaps_as_routed(session_state)

    def _run_stage1(
        self,
        round_num: int,
        phase: str,
        active_profiles: List,
        session_state: CyberSessionState,
        prior_context: str,
        network_summary: str,
        mode: str,
        env_builder,
        known_functions,
        max_workers: int,
    ) -> List[Dict[str, Any]]:
        """
        Stage 1: tất cả tier-1 agents viết free-form analysis song song.
        max_tokens=STAGE1_MAX_TOKENS (default 400) — ngắn hơn, không parse FINDING.
        Returns: list of stage1 post dicts (saved to feed.jsonl với stage=1).
        """
        def _call_stage1(profile):
            import time as _time
            gap_context = ""
            if mode == "contract_audit":
                cm = _get_contract_modules()
                gap_context = cm["gap_context"](
                    pending_gaps=session_state.pending_gaps(),
                    agent_domain=profile.domain_group,
                )
            phase_instruction = env_builder.build_phase_instruction(
                phase, round_num, gap_context=gap_context, stage=1,
            )
            _rate_limiter.acquire()
            t0 = _time.time()
            response = self._call_agent(
                profile=profile, phase=phase, round_num=round_num,
                phase_instruction=phase_instruction, prior_context=prior_context,
                network_summary=network_summary, mode=mode, strip_think=True,
                max_tokens=self._STAGE1_MAX_TOKENS,
            )
            logger.info(
                f"[TIMING] Phase={phase} R{round_num} S1 agent={profile.agent_id} "
                f"latency={_time.time()-t0:.1f}s"
            )
            return profile, response

        submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "1.0"))
        results = []
        if max_workers > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {}
                for i, p in enumerate(active_profiles):
                    if i > 0 and submit_delay > 0:
                        import time as _t; _t.sleep(submit_delay)
                    futures[pool.submit(_call_stage1, p)] = p
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        logger.warning(f"Stage1 {futures[future].agent_id} R{round_num}: {e}")
        else:
            for i, p in enumerate(active_profiles):
                if i > 0 and submit_delay > 0:
                    import time as _t; _t.sleep(submit_delay)
                try:
                    results.append(_call_stage1(p))
                except Exception as e:
                    logger.warning(f"Stage1 {p.agent_id} R{round_num}: {e}")

        stage1_posts = []
        for profile, response in results:
            post = {
                "round_num":    round_num,
                "phase":        phase,
                "stage":        1,
                "agent_id":     profile.agent_id,
                "agent_display": profile.display_name,
                "domain_group": profile.domain_group,
                "persona":      profile.persona,
                "content":      response.strip(),
                "timestamp":    datetime.now().isoformat(),
            }
            stage1_posts.append(post)
            self._append_feed_post(session_state.session_id, post)
        return stage1_posts

    def _run_stage2(
        self,
        round_num: int,
        phase: str,
        active_profiles: List,
        session_state: CyberSessionState,
        prior_context: str,
        network_summary: str,
        mode: str,
        env_builder,
        known_functions,
        phase_c_review_list: str,
        stage1_claims: List[Dict[str, Any]],
        max_workers: int,
    ):
        """
        Stage 2: structured findings (FINDING/SEMANTIC_FINDING) + CHALLENGE/VALIDATE.
        prior_context đã bao gồm feed_context từ Stage 1.
        Sau parse findings, gọi _parse_challenge_validate() với stage1_claims.
        """
        # P4: Designated skeptic — 1 offensive tier-1 agent per round
        import random as _random
        offensive_agents = [p for p in active_profiles if p.persona == "offensive" and p.tier == 1]
        skeptic_id = _random.choice(offensive_agents).agent_id if offensive_agents else None
        _SKEPTIC_INSTRUCTION = (
            "\n\n--- YOUR ROLE THIS ROUND: SKEPTIC ---"
            "\nYour PRIMARY task is to challenge at least 2 CLAIMs or findings you believe are "
            "incorrect or overstated. Write CHALLENGE_FINDING blocks FIRST, then any new FINDING "
            "the group missed. Do not validate claims you are not certain about."
        )

        def _call_stage2(profile):
            import time as _time
            gap_context = ""
            if mode == "contract_audit":
                cm = _get_contract_modules()
                gap_context = cm["gap_context"](
                    pending_gaps=session_state.pending_gaps(),
                    agent_domain=profile.domain_group,
                )
            phase_instruction = env_builder.build_phase_instruction(
                phase, round_num, gap_context=gap_context, stage=2,
            )
            if profile.agent_id == skeptic_id:
                phase_instruction += _SKEPTIC_INSTRUCTION
            _rate_limiter.acquire()
            t0 = _time.time()
            response = self._call_agent(
                profile=profile, phase=phase, round_num=round_num,
                phase_instruction=phase_instruction, prior_context=prior_context,
                network_summary=network_summary, mode=mode, strip_think=True, stage=2,
            )
            logger.info(
                f"[TIMING] Phase={phase} R{round_num} S2 agent={profile.agent_id}"
                + (" [SKEPTIC]" if profile.agent_id == skeptic_id else "")
                + f" latency={_time.time()-t0:.1f}s"
            )
            return profile, gap_context, response

        # Stage 2 có thể cần delay dài hơn Stage 1 nếu STAGE2_MAX_TOKENS lớn
        submit_delay = float(os.environ.get("LLM_STAGE2_SUBMIT_DELAY_S",
                                            os.environ.get("LLM_SUBMIT_DELAY_S", "1.0")))
        results = []
        if max_workers > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {}
                for i, p in enumerate(active_profiles):
                    if i > 0 and submit_delay > 0:
                        import time as _t; _t.sleep(submit_delay)
                    futures[pool.submit(_call_stage2, p)] = p
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        logger.warning(f"Stage2 {futures[future].agent_id} R{round_num}: {e}")
        else:
            for i, p in enumerate(active_profiles):
                if i > 0 and submit_delay > 0:
                    import time as _t; _t.sleep(submit_delay)
                try:
                    results.append(_call_stage2(p))
                except Exception as e:
                    logger.warning(f"Stage2 {p.agent_id} R{round_num}: {e}")

        for profile, gap_context, response in results:
            self._append_feed_post(session_state.session_id, {
                "round_num":   round_num,
                "phase":       phase,
                "stage":       2,
                "agent_id":    profile.agent_id,
                "agent_display": profile.display_name,
                "tier":        profile.tier,
                "domain_group": profile.domain_group,
                "persona":     profile.persona,
                "content":     response,
                "timestamp":   datetime.now().isoformat(),
                "gap_context_injected": bool(gap_context),
            })
            if profile.tier == 1:
                self._process_expert_response(
                    response, profile, round_num, session_state,
                    mode=mode, known_functions=known_functions,
                )
                if phase in ("A", "B"):
                    self._process_gap_declarations(response, profile, round_num, session_state, mode=mode)
                # CHALLENGE/VALIDATE parsing — updates confidence on claims and prior-round findings
                self._parse_challenge_validate(
                    text=response, profile=profile,
                    round_num=round_num, session_state=session_state,
                    stage1_claims=stage1_claims,
                )

        if phase in ("A", "B"):
            self._mark_gaps_as_routed(session_state)

    def _call_agent(
        self,
        profile: CyberAgentProfile,
        phase: str,
        round_num: int,
        phase_instruction: str,
        prior_context: str,
        network_summary: str,
        mode: str = "network_security",
        strip_think: bool = True,
        max_tokens: Optional[int] = None,
        stage: int = 0,
    ) -> str:
        """Gọi LLM cho 1 agent và trả về response text."""
        # Chọn LLM (boost cho attacker Phase C)
        llm = self.boost_llm if (profile.tier == 2 and phase == "C") else self.llm

        if mode == "contract_audit":
            specificity_hint = (
                "Be specific, reference actual functions, state variables, "
                "and code patterns from the contract."
            )
        else:
            specificity_hint = "Be specific, reference actual hosts and services from the infrastructure."

        is_attacker_phase_c = (profile.tier == 2 and phase == "C")
        if is_attacker_phase_c:
            user_content = (
                f"{phase_instruction}\n\n"
                f"=== DISCUSSION SO FAR ===\n{prior_context}\n\n"
                "⚠ FORMAT ENFORCEMENT — bắt buộc:\n"
                "Dòng ĐẦU TIÊN của response phải là tag [ATTACKER_XXX].\n"
                "KHÔNG được viết bất kỳ câu phân tích nào trước tag đầu tiên.\n"
                "Mỗi claim trong UNVERIFIED CLAIMS LIST trên phải có 1 block riêng.\n"
                "Bắt đầu response của bạn ngay bây giờ với [ATTACKER_CONFIRM/DISMISS/EXPLOIT]:"
            )
        else:
            user_content = (
                f"{phase_instruction}\n\n"
                f"=== DISCUSSION SO FAR ===\n{prior_context}\n\n"
                f"Provide your analysis for Round {round_num}. "
                f"{specificity_hint}"
            )

        messages = [
            {"role": "system", "content": profile.system_prompt},
            {"role": "user", "content": user_content},
        ]

        # Stage 2: token override via env var + optional thinking disable
        if stage == 2:
            stage2_max = int(os.environ.get("STAGE2_MAX_TOKENS", "0"))
            max_tok = stage2_max if stage2_max > 0 else (max_tokens if max_tokens is not None else 1500)
        else:
            max_tok = max_tokens if max_tokens is not None else (4096 if is_attacker_phase_c else 1500)

        extra_body = None
        if stage == 2 and os.environ.get("STAGE2_DISABLE_THINKING", "").lower() in ("1", "true", "yes"):
            extra_body = {"thinking_config": {"thinking_budget": 0}}

        return llm.chat(messages, temperature=0.7, max_tokens=max_tok, strip_think=strip_think,
                        extra_body=extra_body)

    # ─── Parsers ──────────────────────────────────────────────────────────────

    def _process_semantic_response(
        self,
        text: str,
        profile: CyberAgentProfile,
        round_num: int,
        session_state: CyberSessionState,
        known_functions=None,
        is_attacker_surfaced: bool = False,
    ):
        """DEPRECATED: S-track removed in NL migration. No-op."""
        pass

    def _process_expert_response(
        self,
        text: str,
        profile: CyberAgentProfile,
        round_num: int,
        session_state: CyberSessionState,
        mode: str = "network_security",
        known_functions=None,
    ):
        """Parse expert agent response → ExpertFinding / ContractFinding entries."""
        if mode == "contract_audit":
            cm = _get_contract_modules()
            finding_dict = cm["parse_finding"](text, profile, round_num, known_functions=known_functions)
            if not finding_dict:
                self._process_semantic_response(text, profile, round_num, session_state, known_functions)
                return
            session_state.expert_findings.append(finding_dict)
            logger.debug(
                f"ContractFinding [{finding_dict['finding_id']}] from {profile.agent_id}: "
                f"{finding_dict['title']} ({finding_dict['severity']})"
            )
            # Also check for semantic findings in the same post
            self._process_semantic_response(text, profile, round_num, session_state, known_functions)
            return

        finding_raw = parse_expert_finding_from_text(text, profile, round_num)
        if not finding_raw:
            return

        finding_id = f"ef_{uuid.uuid4().hex[:8]}"
        finding = ExpertFinding(
            finding_id=finding_id,
            author_group=finding_raw["author_group"],
            author_persona=finding_raw["author_persona"],
            title=finding_raw["title"],
            description=finding_raw["description"],
            affected_assets=finding_raw["affected_assets"],
            severity=finding_raw["severity"],
            confidence=self._initial_confidence_for_severity(finding_raw["severity"]),
            evidence=finding_raw["evidence"],
            recommendations=finding_raw["recommendations"],
            mitre_techniques=finding_raw.get("mitre_techniques", []),
            phase=finding_raw["phase"],
            round_number=round_num,
        )

        session_state.expert_findings.append(asdict(finding))
        logger.debug(
            f"Finding [{finding_id}] from {profile.agent_id}: "
            f"{finding.title} ({finding.severity})"
        )

    def _rescue_attacker_action(
        self,
        narrative_text: str,
        review_list: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Fix B: khi parse_from_text() trả None (agent viết narrative không có tag),
        gọi LLM call ngắn để extract quyết định CONFIRM/DISMISS từ text đó.
        Trả None nếu extract thất bại.
        """
        if len(narrative_text.strip()) < 80:
            return None
        try:
            claims_preview = review_list[:600] if review_list else "unknown claims"
            raw = self.llm.chat_json(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You extract structured security decisions from analyst text. "
                            "Return ONLY JSON, no prose."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            "An attacker analyst wrote the following response WITHOUT using required tags.\n"
                            "Extract their CONFIRM or DISMISS decisions for each claim.\n\n"
                            f"CLAIMS BEING REVIEWED:\n{claims_preview}\n\n"
                            f"ANALYST RESPONSE:\n{narrative_text[:2000]}\n\n"
                            'Return JSON: {"actions": [{"action": "ATTACKER_CONFIRM or ATTACKER_DISMISS", '
                            '"swc_id": "SWC-XXX", "func_name": "funcName()", "reason": "..."}]}'
                        ),
                    },
                ],
                temperature=0.1,
                max_tokens=512,
            )
            actions = raw.get("actions", [])
            if not actions:
                return None
            cm = _get_contract_modules()
            ContractAttackerAction = cm["attacker_action"]
            a = actions[0]
            action_type = a.get("action", "ATTACKER_DISMISS")
            if action_type not in ContractAttackerAction.ALL:
                return None
            logger.debug(f"Attacker rescue: extracted {action_type} swc={a.get('swc_id')} fn={a.get('func_name')}")
            return {
                "action_type":      action_type,
                "swc_id":           a.get("swc_id", ""),
                "func_name":        a.get("func_name", ""),
                "finding_ref":      "",
                "reason":           a.get("reason", ""),
                "path":             "",
                "confidence_delta": ContractAttackerAction.CONFIDENCE_DELTA.get(action_type, 0.0),
            }
        except Exception as e:
            logger.debug(f"Attacker action rescue failed: {e}")
            return None

    def _process_attacker_response(
        self,
        text: str,
        profile: CyberAgentProfile,
        round_num: int,
        session_state: CyberSessionState,
        mode: str = "network_security",
        phase_c_review_list: str = "",
    ):
        """Parse attacker agent response → AttackerFinding or AttackerCorroboration."""
        if mode == "contract_audit":
            cm = _get_contract_modules()
            ContractAttackerAction = cm["attacker_action"]
            action = ContractAttackerAction.parse_from_text(text)
            if not action:
                # Fix B: rescue pass — extract từ narrative nếu không có tag
                action = self._rescue_attacker_action(text, phase_c_review_list)
            if not action:
                # Still check for SEMANTIC_FINDING in attacker post
                self._process_semantic_response(
                    text, profile, round_num, session_state, is_attacker_surfaced=True
                )
                return
            action_type = action["action_type"]
            if action_type == ContractAttackerAction.EXPLOIT:
                # Invariant violation — feasible exploits become attacker findings
                inv_id = action.get("invariant_id", "INV-???")
                feasible = action.get("feasible", "yes").lower() == "yes"
                if feasible:
                    finding_id = f"af_{uuid.uuid4().hex[:8]}"
                    session_state.attacker_findings.append({
                        "finding_id":       finding_id,
                        "invariant_id":     inv_id,
                        "attacker_profile": profile.persona,
                        "title":            f"Invariant Violated: {inv_id}",
                        "description":      action.get("reason", ""),
                        "path_description": action.get("path", ""),
                        "severity":         "high",
                        "base_confidence":  0.70,
                        "source":           "invariant_exploit",
                    })
                    logger.debug(
                        f"Contract Attacker EXPLOIT [{finding_id}] {inv_id} "
                        f"by {profile.agent_id}"
                    )
            elif action_type == ContractAttackerAction.ADD_PATH:
                # Check if the ADD_PATH contains a SEMANTIC_FINDING instead of FINDING
                if "SEMANTIC_FINDING:" in text or "SEMANTIC_FINDING :" in text:
                    self._process_semantic_response(
                        text, profile, round_num, session_state, is_attacker_surfaced=True
                    )
                else:
                    finding_id = f"af_{uuid.uuid4().hex[:8]}"
                    session_state.attacker_findings.append({
                        "finding_id":       finding_id,
                        "attacker_profile": profile.persona,
                        "title":            action["finding_ref"] or f"Attack path by {profile.display_name}",
                        "description":      action["reason"],
                        "severity":         "high",
                        "base_confidence":  0.60,
                        "path_description": action["path"],
                    })
                    logger.debug(f"Contract Attacker NEW path [{finding_id}] by {profile.agent_id}")
            else:
                self._attach_corroboration(
                    action=action,
                    attacker_profile=profile.persona,
                    session_state=session_state,
                )
            return

        action = AttackerAction.parse_from_text(text)
        if not action:
            return

        action_type = action["action_type"]

        if action_type == AttackerAction.ADD_PATH:
            # Tạo finding mới do attacker đề xuất
            finding_id = f"af_{uuid.uuid4().hex[:8]}"
            af = AttackerFinding(
                finding_id=finding_id,
                attacker_profile=profile.persona,
                title=action["finding_ref"] or f"Attack path by {profile.display_name}",
                description=action["reason"],
                affected_assets=[],
                severity="high",
                base_confidence=0.60,
                path_description=action["path"],
            )
            session_state.attacker_findings.append(asdict(af))
            logger.debug(f"Attacker NEW finding [{finding_id}] by {profile.agent_id}")
        else:
            # Gắn corroboration vào finding đã có (match bằng title keyword)
            self._attach_corroboration(
                action=action,
                attacker_profile=profile.persona,
                session_state=session_state,
            )

    def _process_gap_declarations(
        self,
        text: str,
        profile: CyberAgentProfile,
        round_num: int,
        session_state: CyberSessionState,
        mode: str = "network_security",
    ):
        """
        Parse GAP declarations từ expert agent post và lưu vào session state.
        Gaps sẽ được route đến domain groups phù hợp trong round tiếp theo.
        """
        if mode == "contract_audit":
            cm = _get_contract_modules()
            gaps = cm["parse_gap"](
                text=text,
                author_domain=profile.domain_group,
                author_persona=profile.persona,
                round_num=round_num,
            )
        else:
            gaps = parse_gap_declarations(
                text=text,
                author_group=profile.domain_group,
                author_persona=profile.persona,
                round_num=round_num,
            )
        for gap in gaps:
            session_state.gap_registry.append(gap)
            logger.debug(
                f"GAP declared by {profile.agent_id} | area='{gap['analyzed']}' "
                f"→ routed to {gap['routed_to']}"
            )

    def _mark_gaps_as_routed(self, session_state: CyberSessionState):
        """
        Sau khi tất cả agents trong round đã được xử lý, đánh dấu các pending gaps
        là đã được inject (routed=True). Chúng sẽ không xuất hiện trong round tiếp theo.
        """
        for gap in session_state.gap_registry:
            if not gap.get("routed", False):
                gap["routed"] = True

    # ─── Two-Stage Round helpers ───────────────────────────────────────────────

    _STAGE1_FEED_CHARS_PER_POST = int(os.environ.get("STAGE1_FEED_CHARS_PER_POST", "300"))
    _STAGE1_MAX_TOKENS = int(os.environ.get("STAGE1_MAX_TOKENS", "400"))

    def _build_feed_context(
        self,
        round_num: int,
        stage1_posts: List[Dict[str, Any]],
        stage1_claims: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Build context từ Stage 1 posts của round hiện tại để inject vào Stage 2 prompt.

        DRY: Khối CLAIM dựng từ cùng list stage1_claims đã parse bởi _parse_stage1_claims().
        Không re-parse regex ở đây — một nguồn regex duy nhất.
        Khi implement: truyền [] thay None khi parse trả về list rỗng → hành vi nhất quán.
        """
        if not stage1_posts:
            return ""

        cap = self._STAGE1_FEED_CHARS_PER_POST

        # Khối 1: summary truncated — cho reasoning context
        lines = [f"=== STAGE 1 ANALYSIS — Round {round_num} ({len(stage1_posts)} experts) ==="]
        lines.append("(Summaries — truncated for token budget)\n")
        for post in stage1_posts:
            domain = post.get("domain_group", "?")
            persona = post.get("persona", "?")
            content = post.get("content", "").strip()
            if len(content) > cap:
                content = content[:cap] + "…"
            lines.append(f"[{domain}/{persona}]: {content}")
            lines.append("")

        # Khối 2: CLAIM lines — FULL text từ stage1_claims đã parse (không truncate)
        if stage1_claims:
            lines.append(
                f"=== STAGE 1 CLAIMS — Round {round_num} "
                f"(full, use exact title to VALIDATE/CHALLENGE) ==="
            )
            for c in stage1_claims:
                lines.append(
                    f"  [{c.get('author_domain', '?')}/{c.get('author_id', '?')}] "
                    f"CLAIM: {c['title']}"
                )
            lines.append("")

        return "\n".join(lines)

    def _parse_stage1_claims(
        self,
        stage1_posts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Extract CLAIM: tags từ Stage 1 posts.
        CLAIMs được dùng làm target cho CHALLENGE/VALIDATE trong Stage 2.
        Không phải expert_findings — không qua consensus engine.
        """
        _claim_re = re.compile(r'(?i)^CLAIM\s*:\s*(.+)$', re.MULTILINE)
        claims = []
        for post in stage1_posts:
            for m in _claim_re.finditer(post.get("content", "")):
                claims.append({
                    "title":        m.group(1).strip(),
                    "author_id":    post.get("agent_id", "?"),
                    "author_domain": post.get("domain_group", "?"),
                    "round_num":    post.get("round_num", 0),
                    "challenged_by": [],
                    "validated_by":  [],
                })
        return claims

    def _parse_challenge_validate(
        self,
        text: str,
        profile,
        round_num: int,
        session_state: CyberSessionState,
        stage1_claims: Optional[List[Dict[str, Any]]] = None,
    ):
        """
        Parse CHALLENGE_FINDING và VALIDATE_FINDING từ Stage 2 response.

        Target priority:
          1. Stage 1 CLAIMs (same round — giải quyết ordering trap)
          2. expert_findings từ round trước (đã commit)

        P1: Sau khi CLAIM match, fuzzy-link sang expert_finding cùng round (Jaccard ≥ 0.15).
        P6: Guard — bỏ qua VALIDATE nếu CLAIM là phủ định ("not vulnerable", v.v.).
        """
        _CHALLENGE_RE = re.compile(
            r'(?i)^CHALLENGE_FINDING\s*:\s*(.+?)$\s*^REASON\s*:\s*(.+?)(?=^[A-Z_]+\s*:|$)',
            re.MULTILINE | re.DOTALL,
        )
        _VALIDATE_RE = re.compile(
            r'(?i)^VALIDATE_FINDING\s*:\s*(.+?)$\s*^DOMAIN_EVIDENCE\s*:\s*(.+?)(?=^[A-Z_]+\s*:|$)',
            re.MULTILINE | re.DOTALL,
        )

        def _normalize(s: str) -> str:
            """Lowercase + strip trailing punctuation — tolerate minor LLM title abbreviation."""
            return re.sub(r'[.,!?;:]+$', '', s.lower().strip())

        def _jaccard(a: str, b: str) -> float:
            """Token-level Jaccard similarity between two normalized title strings."""
            ta, tb = set(a.split()), set(b.split())
            if not ta or not tb:
                return 0.0
            return len(ta & tb) / len(ta | tb)

        def _find_target(title_fragment: str):
            frag = _normalize(title_fragment)
            # Priority 1: Stage 1 CLAIMs (same round) — Jaccard ≥ 0.30
            if stage1_claims:
                best_c, best_j = None, 0.0
                for c in stage1_claims:
                    j = _jaccard(frag, _normalize(c["title"]))
                    if j > best_j:
                        best_j, best_c = j, c
                if best_j >= 0.30:
                    return ("claim", best_c)
            # Priority 2: expert_findings từ round cũ (đã commit) — Jaccard ≥ 0.30
            best_f, best_j = None, 0.0
            for f in session_state.expert_findings:
                if f.get("round_number", 0) < round_num:
                    j = _jaccard(frag, _normalize(f.get("title", "")))
                    if j > best_j:
                        best_j, best_f = j, f
            if best_j >= 0.30:
                return ("finding", best_f)
            return (None, None)

        def _claim_is_negative(claim: dict) -> bool:
            """P6: True nếu CLAIM phủ định vulnerability — không propagate VALIDATE."""
            text_n = _normalize(claim.get("title", "") + " " + claim.get("content", ""))
            _TITLE_NEG = ("not vulnerable", "no risk", "is safe", "is not exploitable",
                          "cannot be exploited", "miscategorized", "false positive",
                          "not a vulnerability", "no vulnerability")
            if any(s in text_n for s in _TITLE_NEG):
                return True
            # Kiểm tra mệnh đề "because <reason>" bắt đầu bằng negation
            idx = text_n.find(" because ")
            if idx != -1:
                reason = text_n[idx + 9:].strip()
                _REASON_NEG = ("it does not", "there is no ", "the guard", "already protected",
                               "not possible", "no way to", "impossible", "is prevented")
                if any(reason.startswith(s) for s in _REASON_NEG):
                    return True
            return False

        def _fuzzy_link_claim_to_finding(claim: dict):
            """P1: Tìm expert_finding cùng round có title overlap cao nhất với CLAIM."""
            claim_tokens = set(_normalize(claim.get("title", "")).split())
            if not claim_tokens:
                return None
            min_overlap = 3 if len(claim_tokens) < 8 else 2
            best_match, best_score = None, 0
            for f in session_state.expert_findings:
                if f.get("round_number") != round_num:
                    continue
                finding_tokens = set(_normalize(f.get("title", "")).split())
                overlap = len(claim_tokens & finding_tokens)
                if overlap > best_score:
                    best_score, best_match = overlap, f
            if best_match and best_score >= min_overlap:
                union = claim_tokens | set(_normalize(best_match.get("title", "")).split())
                jaccard = best_score / len(union) if union else 0
                if jaccard >= 0.15:
                    logger.debug(
                        f"P1 link CLAIM→finding '{best_match.get('title','')[:50]}' "
                        f"(overlap={best_score}, jaccard={jaccard:.2f})"
                    )
                    return best_match
            return None

        for m in _CHALLENGE_RE.finditer(text):
            title_fragment = m.group(1).strip()
            reason = m.group(2).strip()[:300]
            kind, target = _find_target(title_fragment)
            if target is None:
                continue
            entry = {
                "challenger": profile.agent_id,
                "domain":     profile.domain_group,
                "reason":     reason,
                "round":      round_num,
            }
            target.setdefault("challenged_by", []).append(entry)
            # Confidence penalty chỉ áp lên expert_findings (claims không có confidence)
            if kind == "finding" and profile.domain_group != target.get("author_domain"):
                target["confidence"] = max(0.1, target.get("confidence", 0.5) - 0.10)
            logger.debug(
                f"CHALLENGE [{profile.agent_id}] → {kind} '{title_fragment[:60]}'"
            )

        for m in _VALIDATE_RE.finditer(text):
            title_fragment = m.group(1).strip()
            evidence = m.group(2).strip()[:300]
            kind, target = _find_target(title_fragment)
            if target is None:
                continue

            # P6: skip nếu CLAIM là phủ định
            if kind == "claim" and _claim_is_negative(target):
                logger.debug(
                    f"VALIDATE [{profile.agent_id}] skipped — negative CLAIM '{title_fragment[:60]}'"
                )
                continue

            # P1: fuzzy-link CLAIM → expert_finding cùng round
            if kind == "claim":
                linked = _fuzzy_link_claim_to_finding(target)
                if linked is not None:
                    kind, target = "finding", linked

            entry = {
                "validator": profile.agent_id,
                "domain":    profile.domain_group,
                "evidence":  evidence,
                "round":     round_num,
            }
            target.setdefault("validated_by", []).append(entry)
            if kind == "finding" and profile.domain_group != target.get("author_domain"):
                target["cross_domain_validated"] = True
                target["confidence"] = min(0.95, target.get("confidence", 0.5) + 0.08)
            logger.debug(
                f"VALIDATE [{profile.agent_id}] → {kind} '{title_fragment[:60]}'"
            )

    def _apply_attacker_gate(self, session_state: CyberSessionState, n_attackers: int = 5):
        """
        P8: Post-Phase-C attacker gate — áp dụng 1 lần sau khi Phase C kết thúc.

        Dùng last_vote per attacker (dedup) để tính net ratio thay vì cộng dồn
        từng flat delta. Tránh bias khi cùng profile vote nhiều lần.

        net_ratio = (confirms - dismisses) / n_attackers ∈ [-1, 1]
          ≤ -0.4  → majority DISMISS → confidence × 0.70
          ≥  0.6  → strong CONFIRM  → confidence × 1.15
        """
        for finding in session_state.expert_findings:
            corrs = finding.get("attacker_corroborations", [])
            if not corrs:
                continue
            # Lấy vote cuối cùng của mỗi attacker profile
            last_vote: Dict[str, str] = {}
            for c in corrs:
                last_vote[c["profile_id"]] = c["action"]
            confirms  = sum(1 for a in last_vote.values() if "CONFIRM" in a)
            dismisses = sum(1 for a in last_vote.values() if "DISMISS" in a)
            net_ratio = (confirms - dismisses) / n_attackers
            if net_ratio <= -0.4:
                finding["confidence"] = max(0.10, finding["confidence"] * 0.70)
                logger.debug(
                    f"AttackerGate PENALIZE '{finding.get('title','')[:50]}' "
                    f"net={net_ratio:.2f} ({confirms}C/{dismisses}D)"
                )
            elif net_ratio >= 0.6:
                finding["confidence"] = min(0.95, finding["confidence"] * 1.15)
                logger.debug(
                    f"AttackerGate BOOST '{finding.get('title','')[:50]}' "
                    f"net={net_ratio:.2f} ({confirms}C/{dismisses}D)"
                )

    def _attach_corroboration(
        self,
        action: Dict[str, Any],
        attacker_profile: str,
        session_state: CyberSessionState,
    ):
        """
        Gắn attacker corroboration vào matching expert findings.

        RC-3b: per-function matching — [ATTACKER_DISMISS SWC-101 transfer()] only
               applies to findings where BOTH swc_id AND function match.
        RC-3c: normalize confidence delta by number of affected findings —
               prevents one SWC-level action from having N×weight.
        Legacy: title-keyword match (no SWC) — stops at first hit.
        """
        swc_id    = action.get("swc_id", "")
        func_name = action.get("func_name", "")   # RC-3b: e.g. "transfer()"
        finding_ref = (action.get("finding_ref") or "").lower()

        # Bridge: SINV-xxx / INV-xxx from invariant targets — match by function name
        # instead of SWC ID (structural invariants don't have a SWC equivalent)
        if swc_id.upper().startswith(("SINV-", "INV-")):
            fn_bare = func_name.lower().rstrip("()") if func_name else ""
            delta = action["confidence_delta"]
            for finding_dict in session_state.expert_findings:
                funcs = finding_dict.get("affected_functions", [])
                fn_match = fn_bare and any(
                    fn_bare in fn.lower().rstrip("()") for fn in funcs
                )
                if not fn_match:
                    continue
                corr = AttackerCorroboration(
                    profile_id=attacker_profile,
                    action=action["action_type"],
                    comment=action.get("reason", f"Invariant target {swc_id} confirmed"),
                    confidence_delta=delta,
                )
                if "attacker_corroborations" not in finding_dict:
                    finding_dict["attacker_corroborations"] = []
                finding_dict["attacker_corroborations"].append(asdict(corr))
                current = finding_dict.get("confidence", 0.5)
                finding_dict["confidence"] = max(0.0, min(1.0, current + delta))
            return

        # RC-3c: pre-count affected findings to normalize delta
        if swc_id:
            fn_bare = func_name.lower().rstrip("()") if func_name else ""
            n_affected = sum(
                1 for f in session_state.expert_findings
                if f.get("swc_id") == swc_id and (
                    not fn_bare or any(
                        fn_bare in fn.lower().rstrip("()")
                        for fn in f.get("affected_functions", [])
                    )
                )
            )
            delta = action["confidence_delta"] / max(n_affected, 1)
        else:
            delta = action["confidence_delta"]

        for finding_dict in session_state.expert_findings:
            swc_match = bool(swc_id and finding_dict.get("swc_id") == swc_id)
            title_match = bool(
                not swc_id and finding_ref
                and finding_ref in finding_dict.get("title", "").lower()
            )
            if not (swc_match or title_match):
                continue

            # RC-3b: with function qualifier, skip findings that don't include that function
            if swc_match and func_name:
                fn_bare = func_name.lower().rstrip("()")
                funcs = finding_dict.get("affected_functions", [])
                if not any(fn_bare in fn.lower().rstrip("()") for fn in funcs):
                    continue

            corr = AttackerCorroboration(
                profile_id=attacker_profile,
                action=action["action_type"],
                comment=action["reason"],
                confidence_delta=delta,
            )
            if "attacker_corroborations" not in finding_dict:
                finding_dict["attacker_corroborations"] = []
            finding_dict["attacker_corroborations"].append(asdict(corr))
            current = finding_dict.get("confidence", 0.5)
            finding_dict["confidence"] = max(0.0, min(1.0, current + delta))

            # Legacy title match: stop at first hit; SWC match: continue to cover all matching
            if title_match:
                return

    # ─── Context builder ──────────────────────────────────────────────────────

    def _build_prior_context(self, session_state: CyberSessionState, mode: str = "network_security") -> str:
        """
        Build text summary của các findings đã có để inject vào tiếp theo.
        Giới hạn độ dài để không overflow context window.

        Includes Published Registry (Solution A for Weakness #4):
        agents see unique titles already reported → instructed to CHALLENGE
        or EXPAND rather than re-report the same finding.

        Sliding window (CONTEXT_WINDOW_ROUNDS, default 3): only findings/gaps from the
        last N rounds are shown in detail, keeping prompt size stable across all rounds.
        """
        lines = []

        # Sliding window: cap detailed context to the last N rounds
        window = int(os.environ.get("CONTEXT_WINDOW_ROUNDS", "3"))
        current_round = session_state.current_round
        min_round = max(1, current_round - window + 1)

        if mode == "contract_audit":
            cm = _get_contract_modules()
            registry = cm["published_registry"](session_state.expert_findings, max_entries=10)
        else:
            from .cyber_oasis_env import build_published_registry
            registry = build_published_registry(session_state.expert_findings, max_entries=10)

        # Published Registry — shown first so agents read it before anything else
        if registry:
            lines.append(registry)
            lines.append("")  # blank line separator

        if session_state.expert_findings:
            windowed = [f for f in session_state.expert_findings if f.get("round_number", 0) >= min_round]
            recent = windowed[-6:]
            if recent:
                lines.append(f"=== RECENT FINDINGS (rounds {min_round}–{current_round}, last {len(recent)}) ===")
                for f in recent:
                    corr_count = len(f.get("attacker_corroborations", []))
                    if mode == "contract_audit":
                        author_key = "author_domain"
                        swc_info = f"[{f.get('swc_id', '?')}] " if f.get("swc_id") else ""
                    else:
                        author_key = "author_group"
                        swc_info = ""
                    lines.append(
                        f"[{f.get('severity','?').upper()}] {swc_info}{f.get('title','Untitled')} "
                        f"(by {f.get(author_key,'?')}/{f.get('author_persona','?')}, "
                        f"confidence: {f.get('confidence', 0.5):.2f}"
                        + (f", {corr_count} attacker reactions" if corr_count else "") + ")"
                    )

            # P5: Top-3 high-confidence findings with evidence — help agents build on prior reasoning
            top3 = sorted(windowed, key=lambda f: f.get("confidence", 0), reverse=True)[:3]
            if top3:
                lines.append(f"\n=== TOP-3 HIGH-CONFIDENCE FINDINGS (with evidence) ===")
                for f in top3:
                    lines.append(f"[{f.get('severity','?').upper()}] {f.get('title','?')}")
                    ev_list = f.get("evidence") or []
                    ev = ev_list[0] if ev_list else (f.get("evidence") if isinstance(f.get("evidence"), str) else "")
                    if ev:
                        lines.append(f"  Evidence: {str(ev)[:400]}")

        if session_state.attacker_findings:
            windowed_atk = [f for f in session_state.attacker_findings if f.get("round_number", 0) >= min_round]
            recent_atk = windowed_atk[-5:]
            if recent_atk:
                lines.append(f"\n=== ATTACKER FINDINGS (rounds {min_round}+, {len(recent_atk)}) ===")
                for f in recent_atk:
                    lines.append(
                        f"[ATTACKER:{f.get('attacker_profile','?')}] "
                        f"{f.get('title','Untitled')} (base confidence: {f.get('base_confidence', 0.6):.2f})"
                    )

        # Gap registry: sliding window — only recent gaps to focus agent attention
        all_gaps = session_state.gap_registry
        if all_gaps:
            windowed_gaps = [g for g in all_gaps if g.get("round_number", 0) >= min_round]
            recent_gaps = windowed_gaps[-8:]
            if recent_gaps:
                lines.append(f"\n=== DECLARED KNOWLEDGE GAPS (rounds {min_round}+, {len(recent_gaps)}) ===")
                lines.append("Areas experts could not verify — still open for investigation:")
                author_key = "author_domain" if mode == "contract_audit" else "author_group"
                for g in recent_gaps:
                    lines.append(
                        f"  [{g.get(author_key,'?')}] Area: {g.get('analyzed','?')} — "
                        f"{g.get('gap_text','')[:100]}"
                    )

        return "\n".join(lines) if lines else "No findings yet — be the first to identify vulnerabilities."

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _initial_confidence_for_severity(self, severity: str) -> float:
        """Initial confidence dựa trên severity từ expert agent."""
        return {"critical": 0.70, "high": 0.60, "medium": 0.50, "low": 0.40, "info": 0.30}.get(
            severity.lower(), 0.50
        )

    def _try_build_boost_client(self):
        """Thử dùng BOOST LLM config nếu có, fallback về primary LLM.

        Mode A — Claude trên Vertex AI:
          BOOST_VERTEX_CLAUDE_REGION set + BOOST_MODEL_NAME=claude-*
        Mode B — Gemini Pro trên Vertex AI (cùng endpoint, đổi model):
          BOOST_MODEL_NAME=google/... (không set BOOST_VERTEX_CLAUDE_REGION)
          → Dùng LLMClientPool 2 accounts nếu LLM2_* được set
        Mode C — Anthropic API key riêng:
          BOOST_API_KEY set
        """
        try:
            boost_key       = getattr(Config, "BOOST_API_KEY",              None)
            boost_url       = getattr(Config, "BOOST_BASE_URL",             None)
            boost_model     = getattr(Config, "BOOST_MODEL_NAME",           None)
            claude_region   = getattr(Config, "BOOST_VERTEX_CLAUDE_REGION", None)
            vertex_key_file = (getattr(Config, "BOOST_VERTEX_AI_KEY_FILE", None)
                               or getattr(Config, "LLM_VERTEX_AI_KEY_FILE", None))

            if claude_region and boost_model:
                # Mode A: Claude trên Vertex AI — single client (Claude không có multi-account pool)
                return LLMClient(
                    model=boost_model,
                    vertex_key_file=vertex_key_file,
                    anthropic_vertex_region=claude_region,
                )

            if boost_key:
                # Mode C: Anthropic / OpenAI external key — single client
                return LLMClient(api_key=boost_key, base_url=boost_url, model=boost_model)

            if boost_model and boost_model != Config.LLM_MODEL_NAME:
                # Mode B: Vertex AI, đổi model sang Pro
                # Dùng pool 2 accounts nếu LLM2_* được cấu hình
                client1 = LLMClient(
                    base_url=boost_url or Config.LLM_BASE_URL,
                    model=boost_model,
                    vertex_key_file=vertex_key_file,
                    rpm_slot_file="/tmp/mirofish_boost_rpm_0.json",
                )
                if Config.LLM2_VERTEX_AI_KEY_FILE and Config.LLM2_BASE_URL:
                    client2 = LLMClient(
                        base_url=Config.LLM2_BASE_URL,
                        model=boost_model,
                        vertex_key_file=Config.LLM2_VERTEX_AI_KEY_FILE,
                        rpm_limit=Config.LLM2_GLOBAL_RPM_LIMIT,
                        rpm_slot_file="/tmp/mirofish_boost_rpm_1.json",
                    )
                    pool = LLMClientPool([client1, client2])
                    logger.info(f"BoostLLM pool: 2 Vertex AI accounts, model={boost_model}")
                    return pool
                return client1
        except Exception:
            pass
        return self.llm

    # ─── v2 — 3-Round Contract Audit Flow ────────────────────────────────────

    # Thresholds (can be overridden via env vars)
    _R2_THRESHOLD        = float(os.environ.get("R2_SCORE_THRESHOLD",      "0.42"))
    _R3_ATTACKER_BASE    = float(os.environ.get("R3_ATTACKER_FACTOR_BASE", "0.5"))
    _R3_CONFIRMED        = float(os.environ.get("R3_CONFIRMED_THRESHOLD",  "0.35"))

    # Gemini 3 Flash Preview (thinking model) uses ~30K tokens for internal reasoning
    # before generating visible output. Any max_tokens below ~32K results in content=None.
    # thinkingConfig/thinkingBudget is silently ignored by this model's endpoint.
    _V2_R1_MAX_TOKENS  = int(os.environ.get("V2_R1_MAX_TOKENS",  "65536"))
    _V2_R2_MAX_TOKENS  = int(os.environ.get("V2_R2_MAX_TOKENS",  "32768"))
    _V2_R3_MAX_TOKENS  = int(os.environ.get("V2_R3_MAX_TOKENS",  "1500"))
    _EV_PRIORITY: dict = {"CODE:": 0, "MISSING:": 1, "SEQ:": 2, "INV:": 3, "DESIGN:": 4}

    def _call_agent_v2(
        self,
        prompt: str,
        use_boost: bool = False,
        max_tokens: int = 65536,
    ) -> str:
        """Simple LLM call for v2 rounds — prompt is fully pre-built."""
        llm = self.boost_llm if use_boost else self.llm
        messages = [{"role": "user", "content": prompt}]
        return llm.chat(messages, temperature=0.7, max_tokens=max_tokens, strip_think=True)

    def _run_contract_audit_v2(
        self,
        task_id: str,
        session_id: str,
        graph_id: str,
        network_summary: str,
        profiles: list,
        known_functions: Optional[set],
        session_state: "CyberSessionState",
        invariants: Optional[list] = None,
        target_contracts: list[str] | None = None,
    ):
        """
        v2 entry point — replaces 10-round Phase A/B/C with 3-round flow.
        Stores results in session_state and completes the task.
        """
        cm = _get_contract_modules()
        t1 = [p for p in profiles if p.tier == 1]
        t2 = [p for p in profiles if p.tier == 2]
        n  = len(t1)

        # ── Checkpoint resume (4-tier) ────────────────────────────────────────
        # Pipeline: R1 → gap-fill → dedup → micropass
        #
        # Tier A: post_dedup.json  → skip R1 + gap-fill + dedup + micropass
        # Tier B: pre_dedup.json   → skip R1 + gap-fill; re-run dedup + micropass
        # Tier C: r1_findings.json → skip R1; re-run gap-fill + dedup + micropass
        # Tier D: no checkpoint    → full R1 + gap-fill + dedup + micropass
        #
        # Backward compat: pre_gap_fill.json treated as Tier A alias.
        import json as _cjson

        def _ckpt_save(env_key: str, default_path: str, pool: dict, label: str):
            path = os.environ.get(env_key, default_path)
            try:
                with open(path, "w") as _cf:
                    _cjson.dump(list(pool.values()), _cf, indent=2, default=str)
                logger.info(f"[v2] checkpoint {label} saved: {path} ({len(pool)} findings)")
            except Exception as _ce:
                logger.warning(f"[v2] checkpoint {label} save failed: {_ce}")

        def _ckpt_load(path: str) -> dict:
            with open(path) as _cf:
                _raw = _cjson.load(_cf)
            return {v["pair_id"]: v for v in _raw}

        _ckpt_dir = os.environ.get("CHECKPOINT_DIR", "")

        def _ckpt_path(name: str) -> str:
            return os.path.join(_ckpt_dir, name) if _ckpt_dir else ""

        _post_dedup_f = _ckpt_path("post_dedup.json")
        _pre_gap_f    = _ckpt_path("pre_gap_fill.json")   # backward compat alias for Tier A
        _pre_dedup_f  = _ckpt_path("pre_dedup.json")
        _r1_f         = _ckpt_path("r1_findings.json")

        _tier_a = next((f for f in [_post_dedup_f, _pre_gap_f] if f and os.path.exists(f)), None)

        _run_gap_fill  = os.environ.get("GAP_FILL_ENABLED", "false").lower() == "true"
        _run_micropass = os.environ.get("ENABLE_ACCOUNTING_MICROPASS", "true").lower() == "true"

        if _tier_a:
            # ── Tier A: skip R1 + gap-fill + dedup + micropass ───────────────
            candidate_pool = _ckpt_load(_tier_a)
            n_r1 = len(candidate_pool)
            logger.info(
                f"[v2] CHECKPOINT-A — loaded {n_r1} findings from {_tier_a}, "
                f"skipping R1 + gap-fill + dedup + micropass"
            )

        elif _pre_dedup_f and os.path.exists(_pre_dedup_f):
            # ── Tier B: skip R1 + gap-fill; re-run dedup + micropass ─────────
            candidate_pool = _ckpt_load(_pre_dedup_f)
            n_r1 = len(candidate_pool)
            logger.info(
                f"[v2] CHECKPOINT-B — loaded {n_r1} findings from {_pre_dedup_f}, "
                f"re-running dedup + micropass"
            )
            logger.info(f"[v2] Anchor dedup: {n_r1} → static + LLM...")
            candidate_pool = self._run_anchor_dedup(candidate_pool, network_summary)
            n_r1 = len(candidate_pool)
            logger.info(f"[v2] After anchor dedup: {n_r1} canonical findings")

        elif _r1_f and os.path.exists(_r1_f):
            # ── Tier C: skip R1; re-run gap-fill + dedup + micropass ─────────
            candidate_pool = _ckpt_load(_r1_f)
            n_r1 = len(candidate_pool)
            logger.info(
                f"[v2] CHECKPOINT-C — loaded {n_r1} R1 findings from {_r1_f}, "
                f"re-running gap-fill + dedup + micropass"
            )
            if _run_gap_fill:
                logger.info(f"[v2] ════ GAP-FILL (from R1 ckpt) — pool={n_r1} ════")
                gap_findings = self._run_gap_fill_pass(
                    cm=cm, candidate_pool=candidate_pool,
                    known_functions=known_functions,
                    network_summary=network_summary,
                    target_contracts=target_contracts,
                )
                candidate_pool.update(gap_findings)
                logger.info(f"[v2] Gap-fill injected {len(gap_findings)} → pool={len(candidate_pool)}")
            _ckpt_save("PRE_DEDUP_OUT", "/tmp/pre_dedup.json", candidate_pool, "pre_dedup")
            logger.info(f"[v2] Anchor dedup: {len(candidate_pool)} → static + LLM...")
            candidate_pool = self._run_anchor_dedup(candidate_pool, network_summary)
            n_r1 = len(candidate_pool)
            logger.info(f"[v2] After anchor dedup: {n_r1} canonical findings")

        else:
            # ── Tier D: full run ──────────────────────────────────────────────
            if _ckpt_dir:
                logger.warning(
                    f"[v2] CHECKPOINT_DIR={_ckpt_dir} but no checkpoint files found — full run"
                )
            self.task_manager.update_task(
                task_id, progress=10,
                message=f"Round 1/3 — Independent Discovery ({n} tier-1 agents)"
            )
            candidate_pool = self._run_discovery_round(
                cm=cm, t1_profiles=t1,
                network_summary=network_summary,
                known_functions=known_functions,
                session_id=session_id,
                target_contracts=target_contracts,
            )
            n_r1 = len(candidate_pool)
            logger.info(f"[v2] Round 1 complete: {n_r1} raw findings")
            session_state.current_round = 1
            self._save_session_state(session_state)

            _ckpt_save("R1_FINDINGS_OUT", "/tmp/r1_findings.json", candidate_pool, "r1_findings")

            if _run_gap_fill:
                logger.info(
                    f"[v2] ════ GAP-FILL PASS — pool_before={n_r1} "
                    f"known_fns={len(known_functions or set())} ════"
                )
                gap_findings = self._run_gap_fill_pass(
                    cm=cm, candidate_pool=candidate_pool,
                    known_functions=known_functions,
                    network_summary=network_summary,
                    target_contracts=target_contracts,
                )
                candidate_pool.update(gap_findings)
                logger.info(
                    f"[v2] ════ GAP-FILL DONE — injected={len(gap_findings)} "
                    f"pool_after={len(candidate_pool)} ════"
                )
            else:
                logger.info("[v2] GAP_FILL_ENABLED=false — skipped")

            _ckpt_save("PRE_DEDUP_OUT", "/tmp/pre_dedup.json", candidate_pool, "pre_dedup")

            logger.info(f"[v2] Anchor dedup: {len(candidate_pool)} → static + LLM...")
            candidate_pool = self._run_anchor_dedup(candidate_pool, network_summary)
            n_r1 = len(candidate_pool)
            logger.info(f"[v2] After anchor dedup: {n_r1} canonical findings")

        # ── Accounting Invariant Micro-Pass (Tier B / C / D only) ────────────
        if _run_micropass and not _tier_a:
            micro_findings = self._run_accounting_micropass(network_summary)
            for f in micro_findings:
                anchor = f.get("code_anchor", "")
                if anchor and not any(
                    cf.get("code_anchor") == anchor for cf in candidate_pool.values()
                ):
                    pair_id = f"micro_{uuid.uuid4().hex[:8]}"
                    f["pair_id"] = pair_id
                    f.setdefault("submitters", ["accounting_micropass"])
                    candidate_pool[pair_id] = f
                    logger.info(f"  [micro] Added: {f.get('title', '')}")

        # ── Checkpoint: post-dedup + micropass (Tier B / C / D) ──────────────
        if not _tier_a:
            _ckpt_save("POST_DEDUP_OUT", "/tmp/post_dedup.json", candidate_pool, "post_dedup")

        # ── Early exit after anchor dedup (STOP_AFTER_DEDUP=true) ───────────
        if os.environ.get("STOP_AFTER_DEDUP", "").lower() in ("true", "1", "yes"):
            import json as _json
            out_path = os.environ.get("STOP_AFTER_DEDUP_OUT", "/tmp/dedup_findings.json")
            with open(out_path, "w") as _f:
                _json.dump(list(candidate_pool.values()), _f, indent=2, default=str)
            logger.info(
                f"[v2] STOP_AFTER_DEDUP=true — {n_r1} findings saved to {out_path}"
            )
            self._v2_complete_task(
                task_id, session_id, graph_id, session_state, {}, [], [], [],
            )
            return

        # ── Pre-R2 FP Check ───────────────────────────────────────────────────
        logger.info(f"[v2] Pre-R2 FP check: {n_r1} candidates → filtering...")
        candidate_pool = self._dedup_pre_r2(candidate_pool, network_summary)
        n_r1 = len(candidate_pool)
        logger.info(f"[v2] After FP check: {n_r1} candidates enter R2")

        # ── Early exit after R1 (STOP_AFTER_R1=true) ─────────────────────────
        if os.environ.get("STOP_AFTER_R1", "").lower() == "true":
            import json as _json
            out_path = os.environ.get("STOP_AFTER_R1_OUT", "/tmp/r1_findings.json")
            with open(out_path, "w") as _f:
                _json.dump(list(candidate_pool.values()), _f, indent=2, default=str)
            logger.info(
                f"[v2] STOP_AFTER_R1=true — {n_r1} R1 findings saved to {out_path}, "
                f"skipping R2 and R3"
            )
            self._v2_complete_task(
                task_id, session_id, graph_id, session_state, {}, [], [], [],
            )
            return

        if not candidate_pool:
            logger.warning("[v2] Round 1 produced 0 candidates — nothing to vote on")
            self._v2_complete_task(task_id, session_id, graph_id, session_state, {}, [], [], [])
            return

        # ── Round 2: Blind Voting ─────────────────────────────────────────────
        self.task_manager.update_task(
            task_id, progress=35,
            message=f"Round 2/3 — Blind Voting ({n_r1} pairs, {n} agents)"
        )
        accepted_findings, all_votes = self._run_voting_round(
            cm=cm,
            t1_profiles=t1,
            candidate_pool=candidate_pool,
            n_agents=n,
        )
        n_r2 = len(accepted_findings)
        logger.info(
            f"[v2] Round 2 complete: {n_r2}/{n_r1} pairs accepted "
            f"(threshold={self._R2_THRESHOLD:.2f})"
        )
        session_state.current_round = 2
        self._save_session_state(session_state)

        # ── Post-R2 Score Cap (R3 disabled) ──────────────────────────────────
        accepted_findings = self._dedup_pre_r3(accepted_findings)
        n_r2 = len(accepted_findings)
        logger.info(f"[v2] Post-R2 cap: {n_r2} findings (R3 disabled)")

        session_state.current_round = 2
        session_state.current_phase = "done"
        self._save_session_state(session_state)

        self._v2_complete_task(
            task_id, session_id, graph_id, session_state, all_votes,
            accepted_findings, [], [],
        )

    # Agent-id prefix → domain group (must match _get_author_group in consensus_engine)
    _AGENT_PREFIX_TO_DOMAIN: dict = {
        "apps": "appsec",
        "bloc": "blockchain",
        "cryp": "cryptography",
        "defi": "defi",
        "smar": "smart_contract_economics",
        "gove": "governance",
        "toke": "token_standards",
        "math": "defi_math",
    }

    @classmethod
    def _v2_findings_to_consensus_compat(
        cls, confirmed: list
    ) -> list:
        """
        Convert v2 confirmed findings (from candidate pool) into unified findings list.

        Each finding gets per-domain entries so consensus engine cross_score is meaningful.
        Returns a flat list of finding dicts (unified NL format, no L/S split).
        """
        findings_out: list = []

        for f in confirmed:
            pair_id       = f.get("pair_id", "")
            contract_name = f.get("contract_name", "")
            title         = f.get("title", "")
            fn_name       = f.get("function_name", "") or f.get("_fallback_fn", "")
            submitters    = f.get("submitters", [])
            evidence      = " | ".join(f.get("evidence_snippets", [])[:2])
            attacker_rate = f.get("attacker_rate", 0.0)

            _verdict_rank = {"CONFIRMED": 2, "PLAUSIBLE": 1}
            _best_verdict = max(
                (v for v in f.get("attacker_verdicts", {}).values()
                 if v.get("verdict") in _verdict_rank),
                key=lambda v: _verdict_rank[v["verdict"]],
                default=None,
            )
            if _best_verdict:
                attack_path = _best_verdict.get("attack_steps", "")
                patch_suggestion = _best_verdict.get("expected_outcome", "")
            else:
                attack_path = ""
                patch_suggestion = f"Validate and restrict access to {fn_name}" if fn_name else ""

            domains_seen: dict = {}
            for agent_id in submitters:
                prefix = agent_id.split("_")[0]
                domain = cls._AGENT_PREFIX_TO_DOMAIN.get(prefix, "unknown")
                if domain not in domains_seen:
                    domains_seen[domain] = agent_id
            if not domains_seen:
                domains_seen = {"blockchain": "v2_fallback"}

            for domain in domains_seen:
                findings_out.append({
                    "finding_id":    f"{pair_id}_{domain}",
                    "title":         title or f"Vulnerability in {fn_name}",
                    "description":   title,
                    "attack_path":   attack_path,
                    "contract_name": contract_name,
                    "function_name": fn_name,
                    "affected_functions": [fn_name] if fn_name else [],
                    "author_domain": domain,
                    "evidence":      evidence,
                    "severity":      "high",
                    "confidence":    attacker_rate,
                    "patch_suggestion": patch_suggestion,
                    "challenged_by": [],
                    "validated_by":  [],
                    "v2_pair_id":    pair_id,
                    "v2_attacker_rate": attacker_rate,
                })

        return findings_out

    def _v2_complete_task(
        self,
        task_id: str,
        session_id: str,
        graph_id: str,
        session_state: "CyberSessionState",
        all_votes: dict,
        confirmed_findings: list,
        borderline_findings: list,
        discarded_findings: list,
    ):
        """Complete the v2 task with structured result."""
        self.task_manager.complete_task(task_id, {
            "session_id":          session_id,
            "graph_id":            graph_id,
            # v2 instance-level results — consumed by build_v2_output in report agent
            "v2_confirmed":        confirmed_findings,
            "v2_borderline":       borderline_findings,
            "v2_discarded":        discarded_findings,
            "v2_votes":            all_votes,
            # legacy fields kept for logging/debugging (empty for v2)
            "expert_findings":     [],
            "attacker_findings":   session_state.attacker_findings,
            "semantic_findings":   [],
            "total_findings":      len(confirmed_findings),
            "rounds_completed":    3,
            "pipeline_version":    "v2",
        })

    # ── Dedup helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_evidence(text: str) -> str:
        """Normalize a short evidence snippet for dedup key / embedding."""
        import re as _re
        text = _re.sub(r'//.*', '', text)
        text = _re.sub(r'/\*.*?\*/', '', text, flags=_re.DOTALL)
        text = _re.sub(r'\s+', ' ', text).strip()
        text = text.rstrip(';').strip()
        return text[:100].lower()

    @staticmethod
    def _normalize_source(text: str) -> str:
        """Normalize full source code for substring FP check — no length limit."""
        import re as _re
        text = _re.sub(r'//.*', '', text)
        text = _re.sub(r'/\*.*?\*/', '', text, flags=_re.DOTALL)
        text = _re.sub(r'\s+', ' ', text).strip()
        return text.lower()

    @staticmethod
    def _validate_attack_path(attack_path: str) -> bool:
        """Return False if ATTACK_PATH lacks structured ACTOR/CALL/STATE_CHANGE/OUTCOME fields."""
        if not attack_path or len(attack_path.strip()) < 50:
            return False
        return sum([
            "ACTOR:" in attack_path,
            "CALL:" in attack_path,
            "STATE_CHANGE:" in attack_path,
            "OUTCOME:" in attack_path,
        ]) >= 3

    @staticmethod
    def _is_valid_reject(vote: dict) -> bool:
        """REJECT valid chỉ khi COUNTER_TYPE thuộc 4 loại hợp lệ và COUNTER ≥ 20 chars."""
        valid_types = {"PHANTOM", "ACCESS_BLOCKED", "NO_STATE_CHANGE", "NO_IMPACT"}
        counter_type = vote.get("counter_type", "").strip().upper()
        counter      = vote.get("counter", "").strip()
        return counter_type in valid_types and len(counter) >= 20

    @classmethod
    def _dedup_pre_r2(cls, candidate_pool: dict, source_code: str) -> dict:
        """
        Layer 1A: Drop findings whose CODE_ANCHOR is not found in source.
        Layer 1B: Drop findings with unstructured ATTACK_PATH (missing ACTOR/CALL/STATE_CHANGE/OUTCOME).
        """
        fp_check = os.environ.get("R3_CODE_FP_CHECK", "true").lower() != "false"
        ap_check = os.environ.get("ATTACK_PATH_VALIDATION", "true").lower() != "false"
        norm_source = cls._normalize_source(source_code)

        survivors: dict = {}
        for pid, item in candidate_pool.items():
            # Check 1: CODE_ANCHOR must exist in source (applies to all evidence types)
            anchor = item.get("code_anchor", "")
            if anchor and fp_check:
                norm_anchor = cls._normalize_evidence(anchor)
                if norm_anchor and norm_anchor not in norm_source:
                    logger.debug(f"[dedup pre-R2] drop invalid CODE_ANCHOR: '{anchor[:60]}'")
                    continue

            # Check 2: ATTACK_PATH must be structured (ACTOR/CALL/STATE_CHANGE/OUTCOME)
            if ap_check and not cls._validate_attack_path(item.get("attack_path", "")):
                logger.debug(
                    f"[dedup pre-R2] drop unstructured ATTACK_PATH: '{item.get('title', '')[:60]}'"
                )
                continue

            survivors[pid] = item

        logger.info(
            f"[dedup pre-R2] FP check + ATTACK_PATH validation: "
            f"{len(candidate_pool)} → {len(survivors)}"
        )
        return survivors

    @classmethod
    def _dedup_pre_r3(cls, accepted_findings: list) -> list:
        """
        Layer 2 (embedding) removed — replaced by Merger Agent.
        Layer 3: Global cap (top R3_MAX_FINDINGS by round2_score).
        """
        max_total = int(os.environ.get("R3_MAX_FINDINGS", "40"))

        sorted_findings = sorted(
            accepted_findings,
            key=lambda x: x.get("round2_score", 0),
            reverse=True,
        )
        final   = sorted_findings[:max_total]
        dropped = sorted_findings[max_total:]
        logger.info(
            f"[dedup pre-R3] global cap={max_total}: "
            f"{len(accepted_findings)} → {len(final)} kept, {len(dropped)} dropped"
        )

        if os.environ.get("STOP_AFTER_PRE_R3", "").lower() == "true" and dropped:
            import json as _json
            dropped_path = os.environ.get("STOP_AFTER_PRE_R3_OUT", "/tmp/pre_r3_findings.json")
            dropped_path = dropped_path.replace(".json", "_dropped.json")
            with open(dropped_path, "w") as _f:
                _json.dump(dropped, _f, indent=2, default=str)
            logger.info(f"[dedup pre-R3] Dropped findings → {dropped_path}")

        return final

    # ── Sequential Anchor Dedup (Bước 1 static + Bước 2 LLM) ─────────────────

    @classmethod
    def _pick_primary(cls, group: list) -> tuple:
        """Given list of (pid, item), return (pid, item) with best evidence priority."""
        def priority(pid_item):
            _, item = pid_item
            ev = (item.get("evidence_snippets") or [""])[0]
            for prefix, rank in cls._EV_PRIORITY.items():
                if ev.upper().startswith(prefix):
                    return rank
            return 99
        return min(group, key=priority)

    @classmethod
    def _static_anchor_dedup(cls, candidate_pool: dict) -> dict:
        """
        Bước 1: group by (contract, function, normalize(code_anchor)).
        Same anchor → same bug → merge. No LLM needed.
        """
        from collections import defaultdict as _dd
        anchor_groups: dict = _dd(list)
        no_anchor: list = []

        for pid, item in candidate_pool.items():
            anchor = cls._normalize_evidence(item.get("code_anchor", ""))
            if anchor:
                key = (
                    item.get("contract_name", "").lower().strip(),
                    item.get("function_name", "").lower().strip(),
                    anchor,
                )
                anchor_groups[key].append((pid, item))
            else:
                no_anchor.append((pid, item))

        merged_pool: dict = {}
        n_merged = 0

        for _key, group in anchor_groups.items():
            if len(group) == 1:
                pid, item = group[0]
                merged_pool[pid] = item
            else:
                primary_pid, primary = cls._pick_primary(group)
                merged = dict(primary)
                all_evidence = list(primary.get("evidence_snippets", []))
                all_submitters = list(primary.get("submitters", []))
                for pid, item in group:
                    if pid == primary_pid:
                        continue
                    for ev in (item.get("evidence_snippets") or []):
                        if ev not in all_evidence:
                            all_evidence.append(ev)
                    for s in (item.get("submitters") or []):
                        if s not in all_submitters:
                            all_submitters.append(s)
                    n_merged += 1
                merged["evidence_snippets"] = all_evidence
                merged["submitters"] = all_submitters
                merged_pool[primary_pid] = merged
                logger.debug(
                    f"[static_dedup] merged {len(group)} findings at "
                    f"({_key[0]}.{_key[1]}) anchor: {_key[2][:60]}"
                )

        for pid, item in no_anchor:
            merged_pool[pid] = item

        logger.info(
            f"[static_dedup] {len(candidate_pool)} → {len(merged_pool)} "
            f"({n_merged} findings merged by exact anchor)"
        )
        return merged_pool

    @staticmethod
    def _extract_function_body(source_code: str, fn_name: str) -> str:
        """Extract Solidity function body by brace counting. Returns up to 3000 chars."""
        import re as _re
        lines = source_code.split('\n')
        pattern = _re.compile(r'\bfunction\s+' + _re.escape(fn_name) + r'\s*\(')
        start_idx = None
        for i, line in enumerate(lines):
            if pattern.search(line):
                start_idx = i
                break
        if start_idx is None:
            return ""
        body_lines = []
        depth = 0
        for i in range(start_idx, min(start_idx + 300, len(lines))):
            line = lines[i]
            body_lines.append(line)
            depth += line.count('{') - line.count('}')
            if depth <= 0 and i > start_idx:
                break
        return '\n'.join(body_lines)[:3000]

    @classmethod
    def _apply_llm_merges(cls, group: list, merge_pairs: list) -> list:
        """Apply MERGE decisions via union-find. Returns list of (pid, item) after merging."""
        from collections import defaultdict as _dd
        n = len(group)
        parent = list(range(n))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[py] = px

        for i, j in merge_pairs:
            union(i, j)

        clusters: dict = _dd(list)
        for idx in range(n):
            clusters[find(idx)].append(idx)

        result = []
        for _root, indices in clusters.items():
            if len(indices) == 1:
                result.append(group[indices[0]])
            else:
                cluster_items = [group[i] for i in indices]
                primary_pid, primary = cls._pick_primary(cluster_items)
                merged = dict(primary)
                all_evidence = list(primary.get("evidence_snippets", []))
                all_submitters = list(primary.get("submitters", []))
                for pid, item in cluster_items:
                    if pid == primary_pid:
                        continue
                    for ev in (item.get("evidence_snippets") or []):
                        if ev not in all_evidence:
                            all_evidence.append(ev)
                    for s in (item.get("submitters") or []):
                        if s not in all_submitters:
                            all_submitters.append(s)
                merged["evidence_snippets"] = all_evidence
                merged["submitters"] = all_submitters
                result.append((primary_pid, merged))
        return result

    def _llm_anchor_dedup(self, candidate_pool: dict, source_code: str) -> dict:
        """
        Bước 2: LLM dedup for functions with ≥2 findings after static dedup.
        CODE groups by (contract, function) statically; LLM only receives pre-assembled
        groups and outputs MERGE/KEEP_SEPARATE — does not search or filter itself.
        ~11 LLM calls for contest 35, runs in parallel with LLM_DEDUP_WORKERS workers.
        """
        import re as _re, time as _time
        from collections import defaultdict as _dd
        from concurrent.futures import ThreadPoolExecutor

        func_groups: dict = _dd(list)
        for pid, item in candidate_pool.items():
            key = (
                item.get("contract_name", "").lower().strip(),
                item.get("function_name", "").lower().strip(),
            )
            func_groups[key].append((pid, item))

        single_groups = {k: v for k, v in func_groups.items() if len(v) <= 1}
        multi_groups  = {k: v for k, v in func_groups.items() if len(v) > 1}

        result_pool: dict = {}
        n_llm_calls = 0
        n_llm_merged = 0
        max_workers = int(os.environ.get("LLM_DEDUP_WORKERS", "2"))

        def _process_one_group(contract: str, fn: str, group: list) -> list:
            fn_body = self._extract_function_body(source_code, fn)
            parts = [
                f"  [{i+1}] anchor: {item.get('code_anchor', 'N/A')[:120]}\n"
                f"       evidence: {(item.get('evidence_snippets') or ['N/A'])[0][:120]}\n"
                f"       title: {item.get('title', '')[:80]}"
                for i, (pid, item) in enumerate(group)
            ]
            prompt = (
                "You are a deduplication agent for smart contract audit findings.\n\n"
                f"CONTRACT: {contract}  FUNCTION: {fn}\n"
            )
            if fn_body:
                prompt += f"\nFUNCTION SOURCE:\n{fn_body}\n"
            prompt += (
                f"\nFINDINGS (same function, different code anchors):\n"
                + "\n\n".join(parts)
                + "\n\n"
                "TASK: Identify pairs that describe the SAME underlying vulnerability.\n\n"
                "Rules:\n"
                "  - Only merge when CERTAIN they share the same root cause\n"
                "  - Different anchors usually mean different bugs — when in doubt: KEEP_SEPARATE\n"
                "  - KEEP_SEPARATE is always safer (duplicate > missed TP)\n\n"
                "Output one decision per line:\n"
                "  MERGE: [i] == [j]  | REASON: <one sentence>\n"
                "  KEEP_SEPARATE: [i] | REASON: <one sentence>"
            )
            merge_pairs: list = []
            try:
                t0 = _time.time()
                response = self._call_agent_v2(prompt, max_tokens=512)
                elapsed = _time.time() - t0
                logger.info(f"[llm_dedup] {contract}.{fn}: {elapsed:.1f}s, {len(group)} findings")
                for line in response.split('\n'):
                    m = _re.search(r'MERGE:\s*\[(\d+)\]\s*==\s*\[(\d+)\]', line)
                    if m:
                        i, j = int(m.group(1)) - 1, int(m.group(2)) - 1
                        if 0 <= i < len(group) and 0 <= j < len(group) and i != j:
                            merge_pairs.append((min(i, j), max(i, j)))
                merge_pairs = list(set(merge_pairs))
            except Exception as e:
                logger.warning(f"[llm_dedup] error for {contract}.{fn}: {e} — keeping separate")
            return self._apply_llm_merges(group, merge_pairs)

        # Single-item groups: no LLM needed, add directly
        for (_contract, _fn), group in single_groups.items():
            for pid, item in group:
                result_pool[pid] = item

        # Multi-item groups: parallel LLM calls via ThreadPoolExecutor
        # Each future handles exactly one (contract, function) group — no duplication possible
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {
                ex.submit(_process_one_group, contract, fn, group): (contract, fn, group)
                for (contract, fn), group in multi_groups.items()
            }
            for future, (contract, fn, group) in futures.items():
                try:
                    merged_group = future.result()
                    n_llm_merged += len(group) - len(merged_group)
                    for pid, item in merged_group:
                        result_pool[pid] = item
                except Exception as e:
                    logger.warning(f"[llm_dedup] collect error {contract}.{fn}: {e} — keeping all")
                    for pid, item in group:
                        result_pool[pid] = item
                n_llm_calls += 1

        logger.info(
            f"[llm_dedup] {n_llm_calls} LLM calls ({max_workers} workers), "
            f"{len(candidate_pool)} → {len(result_pool)} "
            f"({n_llm_merged} findings merged by LLM)"
        )
        return result_pool

    def _run_anchor_dedup(self, candidate_pool: dict, source_code: str) -> dict:
        """Sequential dedup entry point: Bước 1 (static) → Bước 2 (LLM)."""
        after_static = self._static_anchor_dedup(candidate_pool)
        after_llm = self._llm_anchor_dedup(after_static, source_code)
        return after_llm

    # ── Round 1 helper ────────────────────────────────────────────────────────

    def _run_discovery_round(
        self,
        cm: dict,
        t1_profiles: list,
        network_summary: str,
        known_functions: Optional[set],
        session_id: str,
        target_contracts: list[str] | None = None,
    ) -> dict:
        """
        Call all N tier-1 agents in parallel.
        Returns candidate_pool: Dict[pair_id → meta_dict]

        meta_dict keys:
          pair_id, contract_name, title, function_name,
          submitters (list[str]), evidence_snippets (list[str])

        Round 1 parsing uses known_functions=None (no function-list filter) because:
        - The KG summary typically only captures 3-5 functions, far fewer than
          the actual contract.  Applying the filter here would silently drop
          every finding that references a function not in that tiny list.
        - Function validation happens implicitly: the evidence gate still
          requires at least one Solidity-specific code marker or a named function
          that survived RC-1 token filtering.
        """
        # FIX-3: reset session-level dedup cache cho mỗi audit run mới
        global _inv_cache
        _inv_cache = {}
        max_workers = int(os.environ.get("LLM_MAX_WORKERS", "1"))
        submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "0"))

        # Dump dir for raw agent responses (debug)
        _debug_dir = os.environ.get("V2_DEBUG_DIR", "")

        # raw_pool: each finding gets its own entry (no clustering by location)
        raw_pool: dict = {}

        def _discover_one(profile) -> list:
            t0 = time.time()

            rag_enabled = os.environ.get("RAG_ENABLED", "true").lower() == "true"
            rag_calls = 0

            # Extract primary contract name once — used by both code_similarity_auditor and Fix B
            _pc_m = _re_rag.search(
                r'TARGET 1\s*[-—–]\s*(\w+)\s*\(primary\)', network_summary
            )
            primary_contract = _pc_m.group(1) if _pc_m else ""

            try:
                # ── code_similarity_auditor: mechanics track ──────────────────
                if profile.agent_id == "code_similarity_auditor":

                    primary_source = _filter_source_to_primary(
                        network_summary, primary_contract
                    )
                    turn1_prompt = (
                        _MECHANICS_TURN1_PROMPT_TEMPLATE
                        .replace("{primary_contract}", primary_contract or "the primary target contract")
                        .replace("{source}", primary_source)
                    )
                    turn1_response = self.llm.chat(
                        [{"role": "user", "content": turn1_prompt}],
                        temperature=0.7,
                        max_tokens=self._V2_R1_MAX_TOKENS,
                        strip_think=False,
                    )
                    turn1_mechanics = _re_rag.sub(
                        r'<think>[\s\S]*?</think>', '', turn1_response
                    ).strip()
                    logger.info(
                        f"[code_sim] Turn1 raw={len(turn1_response)}chars "
                        f"mechanics={len(turn1_mechanics)}chars primary={primary_contract}"
                    )

                    # ── Turn 1.5: convert FUNC mechanics → INV-Mx hypotheses ──
                    # FUNC blocks are mechanics descriptions, not checkable invariants.
                    # The standard Turn 2 prompt reasons over "invariants" via Q1/Q2/Q3.
                    # Feeding raw FUNC blocks into injected_invariants causes the model
                    # to ignore them. Converting to INV-Mx format fixes the mismatch.
                    turn15_prompt = _MECHANICS_TO_INV_PROMPT_TEMPLATE.replace(
                        "{turn1_mechanics}", turn1_mechanics
                    )
                    turn15_response = self.llm.chat(
                        [{"role": "user", "content": turn15_prompt}],
                        temperature=0.3,
                        max_tokens=4000,
                        strip_think=True,
                        extra_body={"google": {"thinking_config": {"thinking_budget": 0}}},
                    )
                    # Log first 300 chars of Turn1.5 response for debugging format issues
                    logger.info(
                        f"[code_sim] Turn1.5 raw ({len(turn15_response)}chars): "
                        f"{repr(turn15_response[:300])}"
                    )
                    # Extract only INV-Mx lines; fall back to raw mechanics if conversion fails
                    # Fix C: flexible search instead of startswith — handles bullet/bold/numbered formats
                    inv_lines = []
                    for ln in turn15_response.splitlines():
                        m = _INV_LINE_RE.search(ln)
                        if m:
                            inv_lines.append(m.group(0).strip())
                    if inv_lines:
                        turn15_invs = "\n".join(inv_lines)
                        logger.info(
                            f"[code_sim] Turn1.5: {len(inv_lines)} INV-Mx lines extracted"
                        )
                    else:
                        turn15_invs = turn1_mechanics  # fallback: keep raw mechanics
                        logger.info(
                            f"[code_sim] Turn1.5: no INV-Mx found, using raw mechanics fallback"
                        )

                    step2_hint = ""
                    if rag_enabled:
                        # RAG still uses raw mechanics (FUNC blocks) for semantic search
                        hint_block, rag_calls = _build_code_similarity_rag_hints(
                            turn1_mechanics, profile.agent_id,
                            target_contracts=target_contracts,
                            primary_contract=primary_contract,
                        )
                        if hint_block:
                            step2_hint = (
                                "\nSIMILAR CODE PATTERNS from audit database:\n\n"
                                f"{hint_block}\n\n"
                                "For each code pattern shown above:\n"
                                "  - BE SKEPTICAL: assume the contract is SAFE first.\n"
                                "  - Check if THIS contract's mechanics match the historical vulnerability.\n"
                                "  - Only write a FINDING if you can show the EXACT SAME structural flaw.\n"
                                "  - If the historical pattern does not apply here, skip it.\n"
                                "For functions without matching patterns: reason independently.\n"
                            )

                    turn2_prompt = cm["r1_prompt"](
                        profile, primary_source,          # filtered: primary + math libs only
                        injected_invariants=turn15_invs,   # INV-Mx lines, not raw FUNC blocks
                        step2_hint=step2_hint,
                    )
                    response = self.llm.chat(
                        [{"role": "user", "content": turn2_prompt}],
                        temperature=0.7,
                        max_tokens=self._V2_R1_MAX_TOKENS,
                        strip_think=True,
                    )
                    if not response.strip():
                        response = self.llm.chat(
                            [{"role": "user", "content": turn2_prompt}],
                            temperature=0.7,
                            max_tokens=self._V2_R1_MAX_TOKENS,
                            strip_think=True,
                        )

                    elapsed = time.time() - t0
                    logger.info(
                        f"[TIMING] Phase=v2 R1 agent={profile.agent_id} latency={elapsed:.1f}s "
                        f"rag_calls={rag_calls}"
                    )
                    if _debug_dir:
                        try:
                            import pathlib
                            pathlib.Path(_debug_dir).mkdir(parents=True, exist_ok=True)
                            with open(os.path.join(_debug_dir, f"r1_{profile.agent_id}_mech.txt"), "w") as fh:
                                fh.write(turn1_mechanics)
                            with open(os.path.join(_debug_dir, f"r1_{profile.agent_id}.txt"), "w") as fh:
                                fh.write(response)
                        except Exception:
                            pass

                    parsed = cm["parse_all_findings"](
                        response, profile, 1, known_functions=known_functions
                    )
                    parsed = parsed[:5]  # safeguard: max 5 findings
                    n_findings = len(parsed)
                    logger.info(
                        f"[v2 R1] agent={profile.agent_id}: "
                        f"raw_response={len(response)}chars "
                        f"parsed={n_findings}findings rag_calls={rag_calls}"
                    )
                    results = []
                    for f in parsed:
                        fns = f.get("affected_functions") or ["_nofunc"]
                        contract    = f.get("contract_name", "")
                        title       = f.get("title", "")
                        description = f.get("description", "") or ""
                        attack_path = f.get("attack_path", [])
                        ev          = (f.get("evidence") or [""])[0]
                        code_anchor = f.get("code_anchor", "")
                        for fn in fns:
                            results.append((contract, fn, title, description, attack_path, ev, code_anchor))
                    return results
                # ── end code_similarity_auditor branch ───────────────────────

                # Fix B: filter source for agents that should only see primary contract
                agent_source = (
                    _filter_source_to_primary(network_summary, primary_contract)
                    if profile.agent_id in _FILTERED_SOURCE_AGENTS
                    else network_summary
                )

                # Extract call chain from the full network_summary (not filtered).
                # The CALL GRAPH is appended after the last file section in the KG output
                # and is excluded when _filter_source_to_primary removes peripheral
                # file sections (e.g. TridentHelper.sol). There is only ONE CALL GRAPH
                # per network_summary, so no need to filter.
                call_chain_block = _extract_callee_coverage_block(network_summary)

                # Turn 1: agent extracts invariants only
                # max_tokens must match Turn 2 — Gemini thinking model needs >= ~32K
                # to generate any visible output (smaller values → content=None)
                turn1_prompt = cm["r1_prompt"](
                    profile, agent_source,
                    invariant_only=True,
                    call_chain_block=call_chain_block,
                )
                turn1_response = self.llm.chat(
                    [{"role": "user", "content": turn1_prompt}],
                    temperature=0.7,
                    max_tokens=self._V2_R1_MAX_TOKENS,
                    strip_think=False,  # keep think block — INV-N regex works on full content
                )
                if not turn1_response.strip():
                    logger.warning(
                        f"[v2 R1] agent={profile.agent_id} Turn 1 returned empty — "
                        f"falling back to single-turn mode"
                    )

                # System: query RAG per invariant, build hint block
                step2_hint = ""
                if rag_enabled:
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
                            "  - If the historical exploit path is blocked or mitigated, EXPLICITLY state 'Mitigated' and skip.\n"
                            "For INVs without historical patterns: reason independently.\n"
                        )

                # Strip think block before injecting into Turn 2 (clean display, save context)
                turn1_clean = _re_rag.sub(r'<think>[\s\S]*?</think>', '', turn1_response).strip()

                # Turn 2: full violation analysis — ALWAYS runs (Turn 1 only extracted invariants)
                turn2_prompt = cm["r1_prompt"](
                    profile, agent_source,
                    injected_invariants=turn1_clean,
                    step2_hint=step2_hint,
                    call_chain_block=call_chain_block,
                )
                response = self.llm.chat(
                    [{"role": "user", "content": turn2_prompt}],
                    temperature=0.7,
                    max_tokens=self._V2_R1_MAX_TOKENS,
                    strip_think=True,
                )

                # Retry once if thinking model exhausted token budget (content=None → empty)
                if not response.strip():
                    logger.warning(
                        f"[v2 R1] agent={profile.agent_id} Turn 2 empty — retrying once"
                    )
                    response = self.llm.chat(
                        [{"role": "user", "content": turn2_prompt}],
                        temperature=0.7,
                        max_tokens=self._V2_R1_MAX_TOKENS,
                        strip_think=True,
                    )

            except Exception as e:
                logger.warning(f"[v2 R1] agent={profile.agent_id} error: {e}")
                return []

            elapsed = time.time() - t0
            logger.info(
                f"[TIMING] Phase=v2 R1 agent={profile.agent_id} latency={elapsed:.1f}s "
                f"rag_calls={rag_calls}"
            )

            if _debug_dir:
                try:
                    import pathlib
                    pathlib.Path(_debug_dir).mkdir(parents=True, exist_ok=True)
                    with open(os.path.join(_debug_dir, f"r1_{profile.agent_id}_inv.txt"), "w") as fh:
                        fh.write(turn1_response)
                    with open(os.path.join(_debug_dir, f"r1_{profile.agent_id}.txt"), "w") as fh:
                        fh.write(response)
                    with open(os.path.join(_debug_dir, f"r1_{profile.agent_id}_prompt.txt"), "w") as fh:
                        fh.write(turn2_prompt)
                except Exception:
                    pass

            parsed = cm["parse_all_findings"](response, profile, 1, known_functions=known_functions)
            n_findings = len(parsed)
            logger.info(
                f"[v2 R1] agent={profile.agent_id}: "
                f"raw_response={len(response)}chars "
                f"parsed={n_findings}findings rag_calls={rag_calls}"
            )

            results = []
            for f in parsed:
                fns = f.get("affected_functions") or []
                if not fns:
                    logger.debug(
                        f"[v2 R1] {profile.agent_id}: finding '{f.get('title','')[:50]}' "
                        f"has no affected_functions — using placeholder"
                    )
                    fns = ["_nofunc"]
                contract    = f.get("contract_name", "")
                title       = f.get("title", "")
                description = f.get("description", "") or ""
                attack_path = f.get("attack_path", [])
                ev          = (f.get("evidence") or [""])[0]
                code_anchor = f.get("code_anchor", "")
                for fn in fns:
                    results.append((contract, fn, title, description, attack_path, ev, code_anchor))

            return results

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {}
            for profile in t1_profiles:
                if submit_delay > 0:
                    time.sleep(submit_delay)
                futures[ex.submit(_discover_one, profile)] = profile

            for future, profile in futures.items():
                try:
                    findings = future.result()
                    for contract, fn, title, description, attack_path, ev, code_anchor in findings:
                        # No clustering — each finding gets its own entry in the pool
                        pair_id = f"p_{uuid.uuid4().hex[:8]}"
                        raw_pool[pair_id] = {
                            "pair_id":           pair_id,
                            "contract_name":     contract,
                            "title":             title,
                            "description":       description,
                            "attack_path":       attack_path,
                            "function_name":     fn,
                            "submitters":        [profile.agent_id],
                            "evidence_snippets": [ev[:300]] if ev else [],
                            "code_anchor":       code_anchor,
                        }
                except Exception as e:
                    logger.warning(f"[v2 R1] result error {profile.agent_id}: {e}")

        # Already indexed by pair_id
        return raw_pool

    # ── Round 2 helper ────────────────────────────────────────────────────────

    def _run_voting_round(
        self,
        cm: dict,
        t1_profiles: list,
        candidate_pool: dict,
        n_agents: int,
    ) -> tuple:
        """
        Blind voting round. Returns (accepted_findings_list, all_votes_dict).
        score = (k + r) / n   where k=submitters, r=ACCEPT votes, n=total agents
        """
        max_workers = int(os.environ.get("LLM_MAX_WORKERS", "1"))
        submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "0"))

        all_pairs = list(candidate_pool.values())

        # votes[pair_id][agent_id] = "ACCEPT" | "REJECT"
        votes: dict = {p["pair_id"]: {} for p in all_pairs}
        # evidence_by_pair: pair_id → list of evidence snippets from voters
        evidence_by_pair: dict = {p["pair_id"]: [] for p in all_pairs}

        def _vote_one(profile) -> list:
            # Self-exclusion: skip pairs where this agent was a submitter
            agent_pairs = [
                p for p in all_pairs
                if profile.agent_id not in p["submitters"]
            ]
            if not agent_pairs:
                return []
            t0 = time.time()
            prompt = cm["r2_prompt"](profile, agent_pairs)
            try:
                response = self._call_agent_v2(prompt, max_tokens=self._V2_R2_MAX_TOKENS)
            except Exception as e:
                logger.warning(f"[v2 R2] agent={profile.agent_id} error: {e}")
                return []
            elapsed = time.time() - t0
            logger.info(f"[TIMING] Phase=v2 R2 agent={profile.agent_id} latency={elapsed:.1f}s")
            return cm["parse_r2_votes"](response, profile.agent_id)

        # Initial voting
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {}
            for profile in t1_profiles:
                if submit_delay > 0:
                    time.sleep(submit_delay)
                futures[ex.submit(_vote_one, profile)] = profile

            for future, profile in futures.items():
                try:
                    for vote in future.result():
                        pid = vote["pair_id"]
                        if pid in votes:
                            votes[pid][profile.agent_id] = vote
                            if vote.get("counter"):
                                evidence_by_pair[pid].append(vote["counter"][:250])
                except Exception as e:
                    logger.warning(f"[v2 R2 collect] {profile.agent_id}: {e}")

        # Evidence reveal — build revealed_evidence per agent
        def _build_revealed(profile) -> list:
            revealed = []
            agent_voted_pairs = [
                pid for pid, pair_votes in votes.items()
                if profile.agent_id in pair_votes
            ]
            for pid in agent_voted_pairs:
                meta = candidate_pool[pid]
                agent_v = votes[pid].get(profile.agent_id, "?")
                revealed.append({
                    "pair_id":       pid,
                    "contract_name": meta.get("contract_name", ""),
                    "title":         meta.get("title", ""),
                    "function_name": meta["function_name"],
                    "all_evidence":  evidence_by_pair.get(pid, []),
                    "agent_vote":    agent_v.get("vote", "?") if isinstance(agent_v, dict) else agent_v,
                })
            return revealed

        def _update_vote_one(profile) -> list:
            revealed = _build_revealed(profile)
            if not revealed:
                return []
            t0 = time.time()
            prompt = cm["r2_update_prompt"](profile, revealed)
            if not prompt:
                return []
            try:
                response = self._call_agent_v2(prompt, max_tokens=self._V2_R2_MAX_TOKENS)
            except Exception as e:
                logger.warning(f"[v2 R2u] agent={profile.agent_id} error: {e}")
                return []
            elapsed = time.time() - t0
            logger.info(f"[TIMING] Phase=v2 R2u agent={profile.agent_id} latency={elapsed:.1f}s")
            return cm["parse_r2_upd"](response, profile.agent_id)

        # Update phase
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {}
            for profile in t1_profiles:
                if submit_delay > 0:
                    time.sleep(submit_delay)
                futures[ex.submit(_update_vote_one, profile)] = profile

            for future, profile in futures.items():
                try:
                    for upd in future.result():
                        pid = upd["pair_id"]
                        if pid in votes:
                            votes[pid][profile.agent_id] = upd
                            if upd.get("new_evidence"):
                                evidence_by_pair[pid].append(upd["new_evidence"][:250])
                except Exception as e:
                    logger.warning(f"[v2 R2u collect] {profile.agent_id}: {e}")

        # Score and filter
        def _get_vote_val(v):
            if isinstance(v, dict):
                return v.get("vote") or v.get("updated_vote", "")
            return v

        r_min = int(os.environ.get("R2_R_MIN", "4"))
        accepted = []
        for pair_id, meta in candidate_pool.items():
            k = len(meta["submitters"])
            pair_votes   = votes.get(pair_id, {})
            accept       = sum(1 for v in pair_votes.values() if _get_vote_val(v) == "ACCEPT")
            valid_reject = sum(
                1 for v in pair_votes.values()
                if _get_vote_val(v) == "REJECT" and isinstance(v, dict) and self._is_valid_reject(v)
            )
            eligible = accept + valid_reject
            score    = (k + accept) / (k + eligible) if (k + eligible) > 0 else 0.0

            meta["round2_score"]    = score
            meta["accept_votes"]    = accept
            meta["valid_reject"]    = valid_reject
            meta["reject_votes"]    = sum(1 for v in pair_votes.values() if _get_vote_val(v) == "REJECT")

            if score >= self._R2_THRESHOLD and accept >= r_min:
                accepted.append(meta)
                logger.debug(f"[v2 R2] ACCEPTED pair_id={pair_id} score={score:.2f} "
                             f"accept={accept} valid_reject={valid_reject} "
                             f"({meta.get('contract_name','?')}.{meta['function_name']} '{meta.get('title','')[:40]}')")
            else:
                logger.debug(f"[v2 R2] REJECTED pair_id={pair_id} score={score:.2f} "
                             f"accept={accept} valid_reject={valid_reject} (r_min={r_min})")

        return accepted, votes

    # ── Round 3 helper ────────────────────────────────────────────────────────

    def _run_attacker_round(
        self,
        cm: dict,
        t2_profiles: list,
        accepted_findings: list,
        contract_source: str,
    ) -> tuple:
        """
        Attacker validation. Returns (confirmed, borderline, discarded).
        Weights: CONFIRMED=1.0, PLAUSIBLE=0.5, INVALID=0.0
        attacker_rate = weighted_sum / effective_M
        """
        max_workers = int(os.environ.get("LLM_MAX_WORKERS", "1"))
        submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "0"))
        M = len(t2_profiles)
        _weights = {"CONFIRMED": 1.0, "PLAUSIBLE": 0.5, "INVALID": 0.0}

        confirmed:  list = []
        borderline: list = []
        discarded:  list = []

        for finding in accepted_findings:
            pair_id = finding["pair_id"]
            verdicts: dict = {}  # attacker_id → verdict dict

            # Initial attacker pass
            def _atk_one(attacker, finding=finding) -> Optional[dict]:
                t0 = time.time()
                prompt = cm["r3_prompt"](attacker, finding, contract_source)
                try:
                    response = self._call_agent_v2(prompt, use_boost=True, max_tokens=self._V2_R3_MAX_TOKENS)
                except Exception as e:
                    logger.warning(f"[v2 R3] attacker={attacker.agent_id} error: {e}")
                    return None
                elapsed = time.time() - t0
                logger.info(f"[TIMING] Phase=v2 R3 agent={attacker.agent_id} latency={elapsed:.1f}s")
                return cm["parse_r3_verdict"](response, attacker.agent_id)

            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {}
                for attacker in t2_profiles:
                    if submit_delay > 0:
                        time.sleep(submit_delay)
                    futures[ex.submit(_atk_one, attacker)] = attacker
                for future, attacker in futures.items():
                    try:
                        v = future.result()
                        if v:
                            verdicts[attacker.agent_id] = v
                    except Exception as e:
                        logger.warning(f"[v2 R3 collect] {attacker.agent_id}: {e}")

            # Evidence reveal for INVALID verdicts (1 update pass)
            invalid_reasons = [
                {"attacker_id": aid, "reason": v.get("reason","")}
                for aid, v in verdicts.items()
                if v.get("verdict") == "INVALID"
            ]
            if invalid_reasons and len(invalid_reasons) < M:
                # Some non-INVALID verdicts exist — give INVALID attackers a chance to reconsider
                def _atk_update(attacker, finding=finding, invalid_reasons=invalid_reasons) -> Optional[dict]:
                    if verdicts.get(attacker.agent_id, {}).get("verdict") != "INVALID":
                        return None
                    t0 = time.time()
                    prompt = cm["r3_update_prompt"](attacker, finding, invalid_reasons)
                    try:
                        response = self._call_agent_v2(prompt, use_boost=True, max_tokens=self._V2_R3_MAX_TOKENS)
                    except Exception as e:
                        logger.warning(f"[v2 R3u] attacker={attacker.agent_id} error: {e}")
                        return None
                    elapsed = time.time() - t0
                    logger.info(f"[TIMING] Phase=v2 R3u agent={attacker.agent_id} latency={elapsed:.1f}s")
                    return cm["parse_r3_upd"](response, attacker.agent_id)

                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    upd_futures = {}
                    for attacker in t2_profiles:
                        if submit_delay > 0:
                            time.sleep(submit_delay)
                        upd_futures[ex.submit(_atk_update, attacker)] = attacker
                    for future, attacker in upd_futures.items():
                        try:
                            upd = future.result()
                            if upd and upd.get("updated_verdict") and upd["pair_id"] == pair_id:
                                verdicts[attacker.agent_id]["verdict"] = upd["updated_verdict"]
                        except Exception as e:
                            logger.warning(f"[v2 R3u collect] {attacker.agent_id}: {e}")

            # Score
            not_applicable = sum(1 for v in verdicts.values() if v.get("verdict") == "NOT_APPLICABLE")
            effective_M = M - not_applicable
            if effective_M < 1:
                effective_M = 1  # avoid div-by-zero

            weighted_sum = sum(
                _weights.get(v.get("verdict","INVALID"), 0.0)
                for v in verdicts.values()
                if v.get("verdict") != "NOT_APPLICABLE"
            )
            attacker_rate = weighted_sum / effective_M

            finding = dict(finding)  # copy to avoid mutating candidate_pool
            r2_score        = finding.get("round2_score", 0.0)
            attacker_factor = self._R3_ATTACKER_BASE + (1.0 - self._R3_ATTACKER_BASE) * attacker_rate
            confidence      = r2_score * attacker_factor

            finding["attacker_rate"]         = attacker_rate
            finding["effective_attackers"]   = effective_M
            finding["attacker_verdicts"]     = verdicts
            finding["not_applicable_count"]  = not_applicable
            finding["attacker_factor"]       = attacker_factor
            finding["confidence"]            = confidence
            finding["final_score"]           = confidence   # alias for backward compat

            logger.info(
                f"[v2 R3] pair_id={pair_id} attacker_rate={attacker_rate:.2f} "
                f"attacker_factor={attacker_factor:.2f} confidence={confidence:.3f} "
                f"effective_M={effective_M} r2_score={r2_score:.2f}"
            )

            if confidence >= self._R3_CONFIRMED:
                finding["v2_status"] = "confirmed"
                confirmed.append(finding)
            else:
                finding["v2_status"] = "discarded"
                discarded.append(finding)

        return confirmed, borderline, discarded

    # ── Accounting Invariant Micro-Pass ───────────────────────────────────────

    def _run_accounting_micropass(self, source: str) -> List[Dict]:
        from app.services.contract_dep_graph import (
            find_transfer_without_accounting,
            build_accounting_check_context,
        )
        from app.services.contract_oasis_env import build_accounting_verifier_prompt

        candidates = find_transfer_without_accounting(source)
        if not candidates:
            logger.info("[micro] No transfer-without-accounting candidates found")
            return []
        logger.info(f"[micro] {len(candidates)} candidate functions for accounting check")
        prompt = build_accounting_verifier_prompt(build_accounting_check_context(candidates))
        raw = self._simple_llm_call(prompt, max_tokens=4096)
        return self._parse_accounting_findings(raw)

    def _simple_llm_call(self, prompt: str, max_tokens: int = 4096) -> str:
        """Single LLM call using the orchestrator's existing LLM client."""
        try:
            return self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=max_tokens,
            )
        except Exception as e:
            logger.warning(f"[micro] LLM call failed: {e}")
            return ""

    def _parse_accounting_findings(self, raw: str) -> List[Dict]:
        """Parse FINDING blocks from accounting verifier output."""
        findings = []
        blocks = re.split(r'\n(?=FINDING\b)', raw)
        for block in blocks:
            if not block.strip().startswith("FINDING"):
                continue
            def _field(name: str) -> str:
                m = re.search(rf'^  {name}:\s*(.+)$', block, re.MULTILINE)
                return m.group(1).strip() if m else ""
            title = _field("TITLE")
            fn = _field("FUNCTION")
            contract = _field("CONTRACT")
            evidence = _field("EVIDENCE")
            if not (title and fn):
                continue
            attack_m = re.search(r'ATTACK_PATH:(.*?)(?=\n\n|\Z)', block, re.DOTALL)
            attack_text = attack_m.group(1).strip() if attack_m else ""
            findings.append({
                "title": title,
                "function_name": fn,
                "contract_name": contract,
                "description": f"{title}. {evidence}",
                "evidence_snippets": [evidence] if evidence else [],
                "attack_path": attack_text,
                "code_anchor": evidence,
                "severity": "HIGH",
            })
        return findings

    # ── Gap-Fill Pass ─────────────────────────────────────────────────────────

    def _run_gap_fill_pass(
        self,
        cm: dict,
        candidate_pool: dict,
        known_functions: set,
        network_summary: str,
        target_contracts: list | None = None,
    ) -> dict:
        """
        Post-R1 targeted re-analysis for primary-contract functions with zero findings.
        Uses a single meta-agent (gap_filler) with full 2-turn flow (INV + RAG + violation).
        Returns dict of new pair_id → finding to merge into candidate_pool.
        """
        from app.services.contract_profile_generator import ContractAgentProfile

        max_fns = int(os.environ.get("GAP_FILL_MAX_FUNCTIONS", "8"))

        # 1. Detect primary contract
        _pc_m = re.search(r'TARGET 1\s*[-—–]\s*(\w+)\s*\(primary\)', network_summary)
        primary_contract = _pc_m.group(1).lower() if _pc_m else ""
        logger.info(f"[gap-fill] primary_contract={primary_contract!r}")

        # 2. Extract function names from within the primary contract's own body only.
        # _filter_source_to_primary still contains base contracts/libs — parse only
        # the block starting at "contract <PrimaryName>" up to the next "contract".
        primary_source = _filter_source_to_primary(network_summary, primary_contract)
        _contract_start = re.search(
            rf'\bcontract\s+{re.escape(primary_contract)}\b',
            primary_source, re.IGNORECASE,
        )
        if _contract_start:
            _body = primary_source[_contract_start.start():]
            # Use line-anchored regex to skip "contract" in inline comments/strings
            _next_contract = re.search(
                r'^\s*(?:abstract\s+)?contract\s+\w+\b',
                _body[len(primary_contract) + 10:],
                re.MULTILINE,
            )
            _offset = len(primary_contract) + 10
            _contract_body = _body[:_next_contract.start() + _offset] \
                if _next_contract else _body
        else:
            _contract_body = primary_source
        primary_fns_in_source = {
            m.lower() for m in re.findall(r'\bfunction\s+(\w+)\s*\(', _contract_body)
        }
        logger.info(
            f"[gap-fill] primary_contract_fns={len(primary_fns_in_source)}: "
            f"{sorted(primary_fns_in_source)}"
        )

        # 3. Covered functions in primary contract (exclude _nofunc placeholder)
        covered = {
            v.get("function_name", "").lower().rstrip("()")
            for v in candidate_pool.values()
            if v.get("contract_name", "").lower() == primary_contract
            and v.get("function_name", "") not in ("_nofunc", "")
        }
        logger.info(f"[gap-fill] covered={sorted(covered)}")

        # 4. Uncovered = primary_source_fns - covered, skip pure view helpers, cap at max_fns
        # Sort: public/external functions first (no leading _), then internal helpers
        # Note: keep _get* (e.g. _getAmountsForLiquidity) — they can contain real bugs (H-05)
        skip_prefixes = ("_compute", "compute")
        _candidates = [
            fn for fn in primary_fns_in_source
            if fn not in covered and not fn.startswith(skip_prefixes)
        ]
        uncovered = (
            sorted(fn for fn in _candidates if not fn.startswith("_"))
            + sorted(fn for fn in _candidates if fn.startswith("_"))
        )[:max_fns]

        if not uncovered:
            logger.info("[gap-fill] No uncovered functions — skipping")
            return {}

        logger.info(f"[gap-fill] {len(uncovered)} uncovered function(s) → targeting: {uncovered}")

        # 4. Build gap_filler meta-agent profile (inline — not in CONTRACT_AGENT_MATRIX)
        # Synthesizes all 22 agent domains so gap-fill works for any contest type.
        gap_profile = ContractAgentProfile(
            user_id=99, agent_id="gap_filler", tier=1,
            domain_group="gap_coverage", persona="gap_filler",
            display_name="Gap Coverage Auditor",
            system_prompt=(
                "You are a Gap Coverage Auditor — a security specialist who analyzes smart "
                "contract functions that received zero findings from all other analysis passes. "
                "You synthesize every security domain and apply all lenses simultaneously:\n"
                "\n"
                "CODE SECURITY:\n"
                "(1) REENTRANCY: every external call is a re-entry vector — check CEI order, "
                "cross-function reentrancy via shared state, read-only reentrancy, and "
                "ERC721/ERC1155/ERC777 callback hooks that can re-enter before state is committed.\n"
                "(2) MISSING CONTROLS: for every state-changing function, verify all necessary "
                "access checks, bounds validation, and range constraints are enforced. "
                "Initializer parameters accepted without explicit [MIN, MAX] bounds and used in "
                "math ops are a permanent DoS risk.\n"
                "(3) PRIVILEGE ESCALATION: unprotected admin functions, missing initializer guards "
                "(initialize() callable twice), tx.origin authentication, single-step ownership "
                "transfer, and delegatecall to user-controlled addresses.\n"
                "(4) EVM INTERNALS: delegatecall context, storage slot collisions in proxies, "
                "block.timestamp manipulability, and selfdestruct edge cases.\n"
                "\n"
                "ARITHMETIC & MATH:\n"
                "(5) NARROWING CASTS: uint128→int128 sign flip, uint256→uint128 truncation, "
                "int24 overflow. For every cast smallerType(expr), verify expr fits the target "
                "type at maximum realistic input — do not assume the library enforces this.\n"
                "(6) PRECISION & ROUNDING: integer division truncation, fixed-point precision loss, "
                "decimal mismatches between tokens, share inflation via first-deposit (ERC4626).\n"
                "(7) LIBRARY INTERNALS: edge cases in TickMath, FullMath, BitMath, PRBMath and "
                "private/internal helpers — zero, max uint256, and boundary tick inputs. "
                "Subtraction expected to underflow needs an unchecked block.\n"
                "(8) MATHEMATICAL INVARIANTS: boundary inequalities (strict < vs non-strict <=) "
                "at every state-transition gate — test the exact threshold value.\n"
                "\n"
                "DEFI & ECONOMICS:\n"
                "(9) STATE ACCOUNTING: every token transfer or balance change must be mirrored by "
                "the corresponding internal reserve/accounting variable update.\n"
                "(10) ACCUMULATOR ORDER: time-weighted accumulators (fee-growth, reward-per-share, "
                "seconds-per-unit) must checkpoint BEFORE the denominator (liquidity, shares, supply) "
                "changes — whether in this function or a caller.\n"
                "(11) FEE DOUBLE-COLLECTION: fee growth snapshot timing must prevent collecting "
                "fees accrued before a position was opened.\n"
                "(12) CROSS-CALL STALENESS: READER functions (collect, claim, withdraw) that "
                "compute payouts from accumulators must receive up-to-date WRITER state — "
                "calling READER before WRITER updates the snapshot returns stale data.\n"
                "(13) FLASH LOAN / ORACLE: price oracle manipulation via spot DEX reserves, "
                "stale oracle exploitation, same-block state manipulation with $100M+ capital.\n"
                "(14) JIT ATTACKS: time-weighted accumulators (time/active_liquidity) allow a "
                "rational actor to add a large position for 1 block as sole LP, capture 100% "
                "of the increment, then exit — verify hold-time or vesting guards.\n"
                "(15) TOKEN QUIRKS: fee-on-transfer tokens (received < sent), rebase tokens "
                "(balance changes without Transfer events), ERC20 silent failure (returns false), "
                "ERC777 tokensReceived hooks, missing SafeERC20.\n"
                "(16) COMPOSABILITY: ERC721/1155/777 callbacks as reentrancy vectors, "
                "cross-protocol trust assumptions that break when external protocol fails or pauses.\n"
                "(17) GOVERNANCE EXTRACTION: unbounded privileged setters (fee, rate, ratio) that "
                "drain user funds, upgrade functions replaceable with malicious logic, pause functions "
                "that trap funds — even if owner-only, document extractable value.\n"
                "\n"
                "CLMM-SPECIFIC (Uniswap V3 / Trident style):\n"
                "(18) CLMM FEE GROWTH INIT: new tick fee tracker must use the pool's ACTUAL current "
                "state — not a cached or indirect value that could lag the real price.\n"
                "(19) CLMM TICK CROSS VARIABLE SWAP: in cross(), feeGrowthOutside0 must update from "
                "the token0 global and feeGrowthOutside1 from the token1 global — check 0/1 suffix swap.\n"
                "(20) CLMM TICK BOUNDARY: active range is priceLower <= currentPrice < priceUpper "
                "(inclusive lower, exclusive upper) — strict < on lower or non-strict <= on upper "
                "silently miscounts active liquidity.\n"
                "(21) RECIPIENT VALIDATION: user-controlled recipient address in mint/burn/collect "
                "can redirect token transfers to an attacker.\n"
                "(22) INITIALIZATION BOUNDS: every numeric parameter accepted by an initialize() or "
                "constructor (price, ratio, fee, rate, threshold) must be validated against explicit "
                "[MIN, MAX] bounds before use in math. An unchecked initialPrice passed to a sqrt/log "
                "or stored as a price reference allows the deployer or first caller to permanently "
                "brick the contract or set an exploitable state (e.g., price=0 causes div-by-zero, "
                "price > MAX_PRICE breaks tick math). Check: is there a require/revert guard bounding "
                "the value? Is the bound tight enough (e.g., >= MIN_SQRT_RATIO and <= MAX_SQRT_RATIO)?"
            ),
            bio="Synthesizes all 22 agent security domains for universal gap coverage.",
            swc_focus=["SWC-101", "SWC-107", "SWC-113", "SWC-114", "SWC-116", "SWC-130"],
            core_question=(
                "For the target function — answer each question:\n"
                "(a) Can any external call allow re-entry before state is fully committed?\n"
                "(b) Are ALL narrowing casts safe at the maximum realistic input value?\n"
                "(c) Are ALL token transfers paired with matching reserve/accounting updates?\n"
                "(d) Are ALL accumulators checkpointed BEFORE denominator (liquidity/supply) changes?\n"
                "(e) Does fee snapshot use CURRENT (not stale) fee growth at position open?\n"
                "(f) Do boundary conditionals use the correct strict/non-strict inequality?\n"
                "(g) Are ALL token recipient parameters validated or caller-restricted?\n"
                "(h) Are ALL initializer numeric parameters validated against explicit bounds?\n"
                "(i) Can a flash-loan-funded attacker manipulate price or state in a single tx?\n"
                "(j) [CLMM] Are tick fee trackers initialized with the pool's ACTUAL current state?\n"
                "(k) [CLMM] Are feeGrowthOutside0/1 assigned to the CORRECT token in cross()?\n"
                "(l) [CLMM] Does any time/liquidity accumulator lack JIT hold-time protection?"
            ),
        )

        rag_enabled = os.environ.get("RAG_ENABLED", "true").lower() == "true"
        pool_size = getattr(self.llm, "pool_size", 1)
        max_workers = max(int(os.environ.get("GAP_FILL_MAX_WORKERS", "1")), pool_size)
        submit_delay = float(os.environ.get("GAP_FILL_SUBMIT_DELAY_S", "1.0"))
        logger.info(
            f"[gap-fill] START max_fns={max_fns} rag_enabled={rag_enabled} "
            f"max_workers={max_workers} pool_size={pool_size} "
            f"candidate_pool={len(candidate_pool)} known_fns={len(known_functions or set())}"
        )

        def _gap_fill_one(fn_idx: int, fn_name: str) -> dict:
            logger.info(
                f"[gap-fill] ── fn {fn_idx}/{len(uncovered)}: {fn_name!r} ──────────────"
            )
            directive = (
                f"GAP-FILL MODE — MANDATORY FUNCTION FOCUS\n"
                f"The function `{fn_name}()` in {primary_contract} received ZERO findings "
                f"from all previous analysis passes.\n"
                f"You MUST analyze `{fn_name}()` exclusively and in depth.\n"
                f"Do NOT write findings for other functions in this response.\n"
                f"Assume the contract is SAFE by default — only report if you find a concrete "
                f"vulnerability with a specific, verifiable attack path.\n"
                f"If `{fn_name}()` appears secure, write nothing."
            )
            try:
                t0 = time.time()

                # Turn 1: extract invariants for fn_name only
                turn1_prompt = cm["r1_prompt"](
                    gap_profile, network_summary,
                    focus_directive=directive,
                    invariant_only=True,
                )
                logger.info(f"[gap-fill] fn={fn_name} Turn1 prompt={len(turn1_prompt)}chars → calling LLM...")
                turn1_response = self.llm.chat(
                    [{"role": "user", "content": turn1_prompt}],
                    temperature=0.5,
                    max_tokens=self._V2_R1_MAX_TOKENS,
                    strip_think=False,
                )
                t1_elapsed = time.time() - t0
                inv_lines = re.findall(r'INV-\d+[^\n]*', turn1_response, re.IGNORECASE)
                logger.info(
                    f"[gap-fill] fn={fn_name} Turn1 done: {len(turn1_response)}chars "
                    f"inv={len(inv_lines)} latency={t1_elapsed:.1f}s"
                )
                for inv in inv_lines:
                    logger.info(f"[gap-fill]   {inv[:120]}")

                # RAG: query per invariant extracted in Turn 1
                step2_hint = ""
                rag_calls = 0
                if rag_enabled and turn1_response.strip():
                    logger.info(f"[gap-fill] fn={fn_name} RAG querying {len(inv_lines)} invariants...")
                    hint_block, rag_calls = _build_invariant_rag_hints(
                        turn1_response, "gap_filler",
                        target_contracts=target_contracts,
                    )
                    logger.info(
                        f"[gap-fill] fn={fn_name} RAG done: calls={rag_calls} "
                        f"hint_chars={len(hint_block)}"
                    )
                    if hint_block:
                        step2_hint = (
                            "\nHISTORICAL VIOLATION PATTERNS from audit database:\n\n"
                            f"{hint_block}\n\n"
                            "For each INV where a historical pattern is shown above:\n"
                            "  - BE SKEPTICAL: Assume the code is SAFE first.\n"
                            "  - Only write a FINDING if you can extract SPECIFIC CODE LINES proving it.\n"
                            "  - If the exploit path is blocked or mitigated, state 'Mitigated' and skip.\n"
                            "For INVs without historical patterns: reason independently.\n"
                        )

                # Strip think block before Turn 2
                turn1_clean = _re_rag.sub(r'<think>[\s\S]*?</think>', '', turn1_response).strip()

                # Turn 2: full violation analysis
                turn2_prompt = cm["r1_prompt"](
                    gap_profile, network_summary,
                    focus_directive=directive,
                    injected_invariants=turn1_clean,
                    step2_hint=step2_hint,
                )
                logger.info(
                    f"[gap-fill] fn={fn_name} Turn2 prompt={len(turn2_prompt)}chars "
                    f"step2_hint={'yes' if step2_hint else 'no'} → calling LLM..."
                )
                response = self.llm.chat(
                    [{"role": "user", "content": turn2_prompt}],
                    temperature=0.5,
                    max_tokens=self._V2_R1_MAX_TOKENS,
                    strip_think=True,
                )

                elapsed = time.time() - t0
                parsed = cm["parse_all_findings"](
                    response, gap_profile, 1, known_functions=known_functions
                )
                logger.info(
                    f"[gap-fill] fn={fn_name} Turn2 done: {len(response)}chars "
                    f"parsed={len(parsed)} total_latency={elapsed:.1f}s rag_calls={rag_calls}"
                )

                fn_findings: dict = {}
                injected_this_fn = 0
                for f in parsed:
                    # Propagate the function being analyzed when LLM omits it
                    if not f.get("function_name"):
                        f["function_name"] = fn_name
                    if not f.get("contract_name"):
                        f["contract_name"] = primary_contract.title()
                    anchor = f.get("code_anchor", "")
                    title = f.get("title", "")
                    fn_reported = f.get("function_name", "")
                    contract_reported = f.get("contract_name", "")
                    logger.info(
                        f"[gap-fill]   parsed finding: title={title!r} "
                        f"fn={fn_reported!r} contract={contract_reported!r} "
                        f"anchor={anchor[:60]!r}"
                    )
                    if anchor:
                        # No dedup here — anchor_dedup runs after gap-fill and handles it
                        pair_id = f"gap_{uuid.uuid4().hex[:8]}"
                        f["pair_id"] = pair_id
                        f.setdefault("submitters", ["gap_filler"])
                        fn_findings[pair_id] = f
                        injected_this_fn += 1
                        logger.info(f"[gap-fill]   → QUEUED as {pair_id} (dedup will filter)")
                    else:
                        logger.info(f"[gap-fill]   → DROPPED (no code_anchor)")

                logger.info(
                    f"[gap-fill] fn={fn_name} summary: parsed={len(parsed)} "
                    f"injected={injected_this_fn}"
                )
                return fn_findings

            except Exception as e:
                logger.warning(f"[gap-fill] fn={fn_name} ERROR: {e}", exc_info=True)
                return {}

        new_findings: dict = {}
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {}
            for fn_idx, fn_name in enumerate(uncovered, 1):
                if fn_idx > 1 and submit_delay > 0:
                    time.sleep(submit_delay)
                futures[ex.submit(_gap_fill_one, fn_idx, fn_name)] = fn_name
            for future, fn_name in futures.items():
                try:
                    new_findings.update(future.result())
                except Exception as e:
                    logger.warning(f"[gap-fill] fn={fn_name} unhandled error: {e}")

        logger.info(
            f"[gap-fill] COMPLETE — {len(new_findings)} new finding(s) injected "
            f"from {len(uncovered)} function(s)"
        )
        return new_findings
