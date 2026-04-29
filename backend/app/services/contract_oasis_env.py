"""
Contract Audit OASIS Environment — Đề tài 10 (Smart Contract Audit).

Định nghĩa cấu hình OASIS cho Contract Audit Room.
Tương tự cyber_oasis_env.py — giữ nguyên 3-phase structure,
đổi action space, finding format, và GAP routing table cho smart contract domain.

Phase A (rounds 1–3):  Domain experts phân tích nội bộ group, attacker agents im lặng
Phase B (rounds 4–7):  Domain experts challenge nhau cross-group
Phase C (rounds 8–10): Attacker profiles xác nhận/bác bỏ/bổ sung attack paths
"""

import re
import uuid
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from .contract_profile_generator import ContractAgentProfile
from .semantic_taxonomy import SEMANTIC_CATEGORY_PIPE_STRING, normalize_semantic_category

logger = get_logger("mirofish.contract_oasis_env")


# ─── Action Types ─────────────────────────────────────────────────────────────

CONTRACT_AUDIT_ACTIONS = {
    # Phase A — Intra-domain
    "POST_FINDING":      "Report a vulnerability with SWC ID and evidence from contract code",
    "CHALLENGE_FINDING": "Challenge a finding with specific reasons from contract code",
    "VALIDATE_FINDING":  "Confirm a finding after independent code review",
    "ADD_EVIDENCE":      "Add evidence: function name, line range, or code snippet",
    "REFINE_SEVERITY":   "Adjust severity with justification from exploit complexity",

    # Phase B — Cross-domain
    "CROSS_VALIDATE":     "Cross-domain confirmation of a finding (higher consensus weight)",
    "CROSS_CHALLENGE":    "Cross-domain challenge to a finding",
    "ESCALATE_TO_DEFI":   "Request DeFi expert to evaluate flash loan or oracle exploit path",
    "REQUEST_GOVERNANCE": "Request Governance expert to review access control findings",
    "CONCLUDE":           "Conclude a finding after cross-domain debate",

    # Phase C — Attacker profiles
    "ATTACKER_CONFIRM":   "Confirm: this vulnerability is exploitable from my attacker profile",
    "ATTACKER_DISMISS":   "Dismiss: not actually exploitable, reason given",
    "ATTACKER_ADD_PATH":  "Add attack path that experts missed",
    "ATTACKER_ESCALATE":  "Escalate severity: easier to exploit than experts assessed",
    "ATTACKER_DOWNGRADE": "Downgrade severity: harder to exploit (hidden mitigation exists)",
    "SUGGEST_PATCH":      "Attacker proposes patch (knows vulnerability best)",
}

# ─── GAP Format Instruction ───────────────────────────────────────────────────

# Appended to Phase A and B prompts — agents MUST declare GAPs
GAP_FORMAT_INSTRUCTION = """
REQUIRED — end every post with one or more GAP declarations:
ANALYZED: <function name, state variable, or contract property analyzed>
GAP: <what you cannot verify from available information, OR "None — fully assessed">

Examples:
ANALYZED: withdraw()
GAP: Cannot determine exact call order without full source — CEI pattern unverifiable.
ANALYZED: price oracle
GAP: Cannot assess oracle freshness — no Chainlink config visible in contract.
ANALYZED: governance voting
GAP: None — fully assessed from source.
"""

# ─── Phase Definitions ────────────────────────────────────────────────────────

PHASE_CONFIG = {
    "A": {
        "name": "Intra-domain Analysis",
        "rounds": [1, 2, 3],
        "description": "Domain experts analyze the contract within their specialization",
        "attacker_active": False,
        # Two-stage: Stage 1 — free-form analysis + optional CLAIM declarations
        "stage1_instruction": (
            "STAGE 1 — CLAIM DECLARATIONS\n"
            "Write ONLY 3-5 CLAIM lines from YOUR DOMAIN perspective. No prose, no headers.\n\n"
            "Format (one per line, start immediately):\n"
            "  CLAIM: <function_name()> may be vulnerable because <specific one-line reason>\n\n"
            "Examples:\n"
            "  CLAIM: fulfill() may be vulnerable because state update happens after external call\n"
            "  CLAIM: cancel() may be vulnerable because reentrancy guard missing on ETH transfer path\n"
            "  CLAIM: getPriceFromAMM() may be vulnerable because spot price manipulable via flash loan\n\n"
            "⚠️ SWC TAGGING RULES — MANDATORY: assign SWC when you see these patterns:\n"
            "  SWC-101: ANY explicit cast (uint128(x), int24(y), uint160(z), uint256→int256)\n"
            "           ANY unchecked{} block — Solidity 0.8 DOES NOT protect explicit casts,\n"
            "           only arithmetic operators (+, -, *). Casts can silently truncate.\n"
            "  SWC-107: ANY external call BEFORE state update, including via callback/hook/onFlashLoan\n"
            "  SWC-124: ANY delegatecall, including ones hidden inside batch() or proxy patterns\n"
            "  SWC-128: ANY loop over array/mapping that can grow unbounded\n\n"
            "⚠️ REQUIRED COVERAGE — explicitly check for these patterns before writing CLAIMs:\n"
            "  - Unbounded arrays/loops (SWC-128): any array that grows without a cap, or loops over\n"
            "    user-controlled data that could exhaust block gas (DoS with Block Gas Limit)\n"
            "  - Unprotected state-modifying functions any caller can invoke to grief other users\n"
            "  - Explicit type casts (SWC-101): uint128(x), int24(y), unchecked{} blocks — tag SWC-101\n"
            "    even on Solidity 0.8 contracts (0.8 does NOT protect casts, only operators)\n"
            "Include a CLAIM about DoS patterns even if you find no clear issue — write 'no issue found' if clean.\n\n"
            "Start your response with CLAIM lines directly. No introduction text.\n"
            "CLAIMs will be shared with ALL experts in Stage 2 for validation or challenge.\n"
            + GAP_FORMAT_INSTRUCTION
        ),
        # Two-stage: Stage 2 — structured findings with full feed context
        "stage2_instruction": (
            "STAGE 2 — FINDINGS & DISCUSSION\n"
            "You have read all domain experts' Stage 1 analyses and CLAIM declarations above.\n\n"
            "MANDATORY (write at least one before adding new findings):\n"
            "  1. CHALLENGE a CLAIM or prior-round finding you disagree with:\n"
            "       CHALLENGE_FINDING: <exact CLAIM or finding title>\n"
            "       REASON: <specific counter-evidence from code>\n"
            "       FUNCTION: <function name>\n"
            "       EVIDENCE: <code quote>\n\n"
            "  2. VALIDATE a CLAIM or prior-round finding from YOUR domain's angle:\n"
            "       VALIDATE_FINDING: <exact CLAIM or finding title>\n"
            "       DOMAIN_EVIDENCE: <your evidence>\n"
            "       FUNCTION: <function name>\n"
            "       ADDITIONAL_IMPACT: <extra impact>\n\n"
            "OPTIONAL (only after addressing the above):\n"
            "  3. FINDING / SEMANTIC_FINDING: new vulnerabilities from YOUR domain\n\n"
            "⚠️ FUNCTION FIELD IS MANDATORY IN ALL FINDINGS:\n"
            "  If you mention a function name anywhere in your description or evidence,\n"
            "  you MUST include it in the FUNCTION: field. A finding without FUNCTION: is\n"
            "  demoted to a low-value hint and will NOT appear as a confirmed vulnerability.\n"
            "  Wrong:   FUNCTION: (empty)  DESCRIPTION: _mint uses unsafe cast...\n"
            "  Correct: FUNCTION: _mint()  DESCRIPTION: _mint uses unsafe cast...\n"
            "  If the same SWC appears in 3 functions, write 3 separate FINDINGs.\n\n"
            "Note: CHALLENGE/VALIDATE target Stage 1 CLAIMs and previous-round findings.\n"
            "New findings from THIS round's other experts will be challengeable next round.\n"
            + GAP_FORMAT_INSTRUCTION
        ),
        # Backward compat: single-stage (stage=0) path
        "instruction_addition": (
            "In this phase, analyze the contract from YOUR DOMAIN EXPERTISE perspective. "
            "Propose findings with specific SWC IDs, function names, and code evidence. "
            "Discuss and validate findings with peers in your domain.\n"
            + GAP_FORMAT_INSTRUCTION
        ),
    },
    "B": {
        "name": "Cross-domain Challenge",
        "rounds": [4, 5, 6, 7],
        "description": "Domain experts challenge and validate findings across specializations",
        "attacker_active": False,
        # Two-stage: Stage 1 — cross-domain free-form analysis
        "stage1_instruction": (
            "STAGE 1 — CLAIM DECLARATIONS (cross-domain)\n"
            "Write ONLY 3-5 CLAIM lines from YOUR DOMAIN perspective. No prose, no headers.\n"
            "Include prior-round findings you want to challenge or validate.\n\n"
            "Format (one per line, start immediately):\n"
            "  CLAIM: <function_name()> may be vulnerable because <specific one-line reason>\n\n"
            "Examples:\n"
            "  CLAIM: fulfill() may be vulnerable because cross-domain reentrancy via router callback\n"
            "  CLAIM: addLiquidity() may be vulnerable because missing slippage check interacts with price oracle\n\n"
            "⚠️ SWC TAGGING RULES — MANDATORY: assign SWC when you see these patterns:\n"
            "  SWC-101: ANY explicit cast (uint128(x), int24(y), uint160(z)) or unchecked{} block\n"
            "           Solidity 0.8 DOES NOT protect explicit casts — only arithmetic operators\n"
            "  SWC-107: ANY external call BEFORE state update, via callback/hook/onFlashLoan\n"
            "  SWC-124: ANY delegatecall (direct or via proxy/batch)\n"
            "  SWC-128: ANY loop over unbounded array/mapping\n\n"
            "Start your response with CLAIM lines directly. No introduction text.\n"
            + GAP_FORMAT_INSTRUCTION
        ),
        # Two-stage: Stage 2 — cross-domain challenge + validate
        "stage2_instruction": (
            "STAGE 2 — CROSS-DOMAIN FINDINGS & CHALLENGE\n"
            "You have read all domain experts' Stage 1 analyses and CLAIM declarations above.\n\n"
            "MANDATORY (write at least one before adding new findings):\n"
            "1. CHALLENGE a Stage 1 CLAIM or prior-round finding you disagree with:\n"
            "   CHALLENGE_FINDING: <exact CLAIM title or prior finding title>\n"
            "   REASON: <specific counter-evidence from code>\n"
            "   FUNCTION: <function name>\n"
            "   EVIDENCE: <code quote>\n\n"
            "2. VALIDATE a Stage 1 CLAIM or prior-round finding from YOUR domain's angle:\n"
            "   VALIDATE_FINDING: <exact CLAIM title or prior finding title>\n"
            "   DOMAIN_EVIDENCE: <your evidence>\n"
            "   FUNCTION: <function>\n"
            "   ADDITIONAL_IMPACT: <extra impact>\n\n"
            "OPTIONAL (only after addressing the above):\n"
            "3. Add NEW findings missed by all domains.\n"
            "4. Reclassify business-logic bugs (no SWC → use SEMANTIC_FINDING).\n\n"
            "Note: CLAIM titles come from the Stage 1 feed above — use exact wording to match.\n\n"
            "⚠️ FUNCTION FIELD IS MANDATORY IN ALL FINDINGS:\n"
            "  If you mention a function name anywhere in your description or evidence,\n"
            "  you MUST include it in the FUNCTION: field. A finding without FUNCTION: is\n"
            "  demoted to a low-value hint and will NOT appear as a confirmed vulnerability.\n"
            "  Wrong:   FUNCTION: (empty)  DESCRIPTION: _mint uses unsafe cast...\n"
            "  Correct: FUNCTION: _mint()  DESCRIPTION: _mint uses unsafe cast...\n"
            "  If the same SWC appears in 3 functions, write 3 separate FINDINGs.\n\n"
            + GAP_FORMAT_INSTRUCTION
        ),
        # Backward compat: single-stage (stage=0) path
        "instruction_addition": (
            "In this phase, READ findings from OTHER domain groups and challenge them. "
            "Ask: Is this finding accurate? Is the severity correct? "
            "Does this function actually exhibit the claimed vulnerability pattern? "
            "Add new findings if you notice another domain missed something important.\n"
            + GAP_FORMAT_INSTRUCTION
        ),
    },
    "C": {
        "name": "Attacker Challenge",
        "rounds": [8, 9, 10],
        "description": "Attacker profiles validate exploitability and propose attack paths",
        "attacker_active": True,
        "instruction_addition": (
            "ATTACKER PHASE — Your visible response MUST begin with [ATTACKER_XXX] declaration blocks.\n\n"
            "=== REQUIRED FORMAT (write these blocks as the FIRST lines of your response) ===\n\n"
            "  [ATTACKER_CONFIRM SWC-114 approve()]\n"
            "  Finding: approve() race condition\n"
            "  Path: 1) Alice calls approve(Bob,100) 2) Bob front-runs transferFrom — spends old+new allowance\n"
            "  ---\n"
            "  [ATTACKER_DISMISS SWC-101 transfer()]\n"
            "  Finding: Integer overflow in transfer\n"
            "  Reason: transfer() uses SafeMath.sub() — reverts on underflow, no overflow possible\n"
            "  ---\n"
            "  [ATTACKER_EXPLOIT INV-001]\n"
            "  Path: 1. Call addLiquidity(amount, assetId, victimRouter) from any address\n"
            "        2. No require(router == msg.sender) — any caller accepted\n"
            "        3. Call removeLiquidity() to drain victim router's funds\n"
            "  Impact: Full liquidity drain of any router\n"
            "  Feasible: yes\n"
            "  ---\n\n"
            "=== RULES ===\n"
            "• DEFAULT STANCE: DISMISS. Every claim is UNVERIFIED until you independently confirm it.\n"
            "• CONFIRM only with a concrete step-by-step exploit traceable through THIS contract's code.\n"
            "• DISMISS for: out-of-scope claims, SafeMath/require-protected ops, no traceable exploit.\n"
            "• Write one block per claim in the UNVERIFIED CLAIMS LIST above.\n"
            "• For INVARIANT ATTACK OBJECTIVES: use [ATTACKER_EXPLOIT INV-xxx] if you can violate the invariant.\n"
            "• Dismissing false positives is MORE valuable than confirming an obvious finding.\n"
            "Domain expert agents: respond only if an attacker directly challenges your specific finding.\n"
        ),
    },
}

TOTAL_ROUNDS = 10


# ─── GAP Routing Table ────────────────────────────────────────────────────────

# Maps keywords in GAP text → domain groups best positioned to investigate
CONTRACT_GAP_ROUTING_TABLE: Dict[str, List[str]] = {
    # Reentrancy / external calls → appsec + blockchain
    "reentran":           ["appsec", "blockchain"],
    "external call":      ["appsec", "blockchain"],
    "call before state":  ["appsec", "blockchain"],
    "cei pattern":        ["appsec", "blockchain"],
    "reentrancy guard":   ["appsec", "blockchain"],

    # Integer arithmetic → cryptography + appsec
    "overflow":           ["cryptography", "appsec"],
    "underflow":          ["cryptography", "appsec"],
    "arithmetic":         ["cryptography", "appsec"],
    "safemath":           ["cryptography", "appsec"],
    "integer":            ["cryptography", "appsec"],

    # Access control → governance + appsec
    "access control":     ["governance", "appsec"],
    "onlyowner":          ["governance", "appsec"],
    "modifier":           ["governance", "appsec"],
    "authorization":      ["governance", "appsec"],
    "privilege":          ["governance", "appsec"],

    # Oracle / DeFi → defi
    "oracle":             ["defi"],
    "price manipulat":    ["defi"],
    "twap":               ["defi"],
    "chainlink":          ["defi"],
    "spot price":         ["defi"],
    "flash loan":         ["defi", "governance"],
    "flashloan":          ["defi", "governance"],
    "slippage":           ["defi"],
    "amm":                ["defi"],

    # Governance / voting → governance + defi
    "governance":         ["governance", "defi"],
    "voting":             ["governance", "defi"],
    "proposal":           ["governance"],
    "timelock":           ["governance"],
    "quorum":             ["governance"],
    "snapshot":           ["governance"],

    # Randomness / signatures → cryptography
    "random":             ["cryptography"],
    "entropy":            ["cryptography"],
    "chainlink vrf":      ["cryptography"],
    "ecrecover":          ["cryptography"],
    "signature":          ["cryptography"],
    "nonce":              ["cryptography"],
    "replay":             ["cryptography"],

    # Proxy / upgradeable → blockchain
    "proxy":              ["blockchain"],
    "upgradeable":        ["blockchain"],
    "delegatecall":       ["blockchain"],
    "storage collision":  ["blockchain"],
    "implementation":     ["blockchain"],

    # Gas / DoS → appsec + blockchain
    "gas limit":          ["appsec", "blockchain"],
    "unbounded loop":     ["appsec", "blockchain"],
    "denial of service":  ["appsec", "blockchain"],
    "dos":                ["appsec", "blockchain"],

    # Economic / tokenomics → smart_contract_economics
    "bank run":           ["smart_contract_economics"],
    "liquidity":          ["smart_contract_economics", "defi"],
    "incentive":          ["smart_contract_economics"],
    "tokenomics":         ["smart_contract_economics"],
    "collateral ratio":   ["smart_contract_economics", "defi"],
    "reflexiv":           ["smart_contract_economics"],
    "inflation":          ["smart_contract_economics"],
    "emission":           ["smart_contract_economics"],
    "death spiral":       ["smart_contract_economics"],
    "insolvency":         ["smart_contract_economics", "defi"],
    "economic":           ["smart_contract_economics"],
    "reward calculation": ["smart_contract_economics"],
    "apy":                ["smart_contract_economics", "defi"],

    # Supply chain / dependency → supply_chain
    "openzeppelin":       ["supply_chain"],
    "dependency":         ["supply_chain"],
    "import":             ["supply_chain", "appsec"],
    "library":            ["supply_chain", "blockchain"],
    "initializ":          ["supply_chain", "blockchain"],
    "initialize()":       ["supply_chain", "blockchain"],
    "deployment":         ["supply_chain"],
    "upgrade":            ["supply_chain", "blockchain"],
    "storage layout":     ["supply_chain", "blockchain"],
    "constructor":        ["supply_chain", "blockchain"],
    "package":            ["supply_chain"],
    "npm":                ["supply_chain"],
    "ci/cd":              ["supply_chain"],
}


def route_contract_gap(gap_text: str) -> List[str]:
    """
    Determine which domain groups should investigate a contract GAP declaration.
    Returns list of domain groups. Falls back to all domain groups if no match.
    """
    gap_lower = gap_text.lower()
    matched: List[str] = []
    for keyword, groups in CONTRACT_GAP_ROUTING_TABLE.items():
        if keyword in gap_lower:
            for g in groups:
                if g not in matched:
                    matched.append(g)
    # Fallback: broadcast to all domain groups
    return matched or [
        "appsec", "blockchain", "cryptography", "defi",
        "governance", "smart_contract_economics", "supply_chain",
    ]


def parse_contract_gap_declarations(
    text: str,
    author_domain: str,
    author_persona: str,
    round_num: int,
) -> List[Dict[str, Any]]:
    """
    Parse ANALYZED + GAP declaration blocks from an agent post.
    Same logic as parse_gap_declarations() in cyber_oasis_env.py.

    Expected format (one or more per post):
      ANALYZED: <function or property>
      GAP: <what cannot be verified>

    Returns list of ContractGapDeclaration-compatible dicts.
    """
    gaps = []
    blocks = re.split(r'(?i)\bANALYZED\s*:', text)
    for block in blocks[1:]:
        lines = block.strip().splitlines()
        analyzed = lines[0].strip() if lines else "unknown"

        gap_text = ""
        collecting = False
        for line in lines[1:]:
            stripped = line.strip()
            if re.match(r'(?i)^GAP\s*:', stripped):
                gap_text = stripped.split(":", 1)[1].strip()
                collecting = True
            elif collecting:
                if stripped.startswith("e.g.") or (line.startswith("  ") and stripped):
                    gap_text += " " + stripped
                else:
                    break

        if not gap_text:
            continue
        gap_lower = gap_text.lower().strip(" .")
        if gap_lower in (
            "none", "none identified", "none — fully assessed", "none -- fully assessed",
            "none - fully assessed within domain scope", "n/a", "not applicable",
            "fully assessed", "none — fully assessed within domain scope",
        ):
            continue

        gaps.append({
            "gap_id":         f"cgap_{uuid.uuid4().hex[:8]}",
            "author_domain":  author_domain,
            "author_persona": author_persona,
            "analyzed":       analyzed,
            "gap_text":       gap_text,
            "round_number":   round_num,
            "routed":         False,
            "routed_to":      route_contract_gap(gap_text),
        })

    return gaps


def build_gap_context_for_agent(
    pending_gaps: List[Dict[str, Any]],
    agent_domain: str,
) -> str:
    """
    Filter pending GAP declarations relevant to this agent's domain
    and format as injection text for the next round's context.

    Returns empty string if no relevant gaps.
    """
    relevant = [
        g for g in pending_gaps
        if agent_domain in g.get("routed_to", [])
    ]
    if not relevant:
        return ""

    lines = [
        "=== UNRESOLVED GAPS — Previous rounds identified areas needing YOUR expertise ===",
        "These gaps were declared by other experts who could not fully assess these areas.",
        "Please investigate and generate a FINDING or state NO_FINDING for each:",
    ]
    for g in relevant:
        lines.append(
            f"\n  [GAP from {g['author_domain']}/{g['author_persona']}, Round {g['round_number']}]"
            f"\n  Area: {g['analyzed']}"
            f"\n  Why unresolved: {g['gap_text']}"
        )
    lines.append("")
    return "\n".join(lines)


def build_published_registry(
    contract_findings: List[Dict[str, Any]],
    max_entries: int = 20,
) -> str:
    """
    Published Finding Registry — inject into agent context to reduce duplicates.
    Same logic as build_published_registry() in cyber_oasis_env.py.

    Shows unique finding titles grouped by domain, capped at max_entries.
    Agents are instructed to CHALLENGE or ADD EVIDENCE instead of re-reporting.
    """
    if not contract_findings:
        return ""

    seen: set = set()
    unique: List[Dict[str, Any]] = []
    for f in contract_findings:
        key = f.get("title", "").lower().strip()
        if key and key not in seen:
            seen.add(key)
            unique.append(f)

    capped = unique[-max_entries:] if len(unique) > max_entries else unique

    lines = [
        f"=== PUBLISHED FINDINGS REGISTRY ({len(unique)} unique findings reported so far) ===",
        "Do NOT duplicate these. If you agree → CHALLENGE or ADD_EVIDENCE.",
        "If you have distinct new information → write a NEW FINDING with a different title.",
    ]
    for f in capped:
        domain = f.get("author_domain", "?")
        persona = f.get("author_persona", "?")
        swc = f.get("swc_id", "?")
        lines.append(
            f"  • [{f.get('severity','?').upper()}][{swc}] "
            f"{f.get('title','?')} — by {domain}/{persona}"
        )

    return "\n".join(lines)


def get_phase_for_round(round_num: int) -> str:
    """Return phase letter (A/B/C) for a given round number."""
    if round_num <= 3:
        return "A"
    elif round_num <= 7:
        return "B"
    else:
        return "C"


# ─── Attacker Action Parser ────────────────────────────────────────────────────

class ContractAttackerAction:
    """Action types for attacker profile agents in Phase C."""

    CONFIRM   = "ATTACKER_CONFIRM"
    DISMISS   = "ATTACKER_DISMISS"
    ADD_PATH  = "ATTACKER_ADD_PATH"
    ESCALATE  = "ATTACKER_ESCALATE"
    DOWNGRADE = "ATTACKER_DOWNGRADE"
    EXPLOIT   = "ATTACKER_EXPLOIT"    # invariant violation with concrete exploit path

    # Confidence deltas when parsing from post text
    CONFIDENCE_DELTA = {
        CONFIRM:   +0.15,
        DISMISS:   -0.20,
        ADD_PATH:   0.00,   # handled separately as new finding
        ESCALATE:  +0.10,
        DOWNGRADE: -0.10,
        EXPLOIT:   +0.25,   # strong signal — attacker found a concrete invariant violation
    }

    ALL = {CONFIRM, DISMISS, ADD_PATH, ESCALATE, DOWNGRADE, EXPLOIT}

    # RC-3b: match [ATTACKER_CONFIRM SWC-107 transfer()] — SWC + optional function qualifier
    # Also matches SINV-xxx / INV-xxx (invariant targets from structural scan)
    _SWC_ACTION_RE = re.compile(
        r'\[(ATTACKER_CONFIRM|ATTACKER_DISMISS|ATTACKER_ESCALATE|ATTACKER_DOWNGRADE)'
        r'\s+(SWC-\d{1,3}|DEFI-[A-Z][A-Z_]{2,}|SINV-\d{1,3}|INV-\d{1,3})'
        r'(?:\s+([a-zA-Z_][a-zA-Z0-9_]*\(\)))?\]'  # optional: funcName()
    )

    # Match [ATTACKER_EXPLOIT INV-001]
    _EXPLOIT_RE = re.compile(
        r'\[ATTACKER_EXPLOIT\s+(INV-\d{1,3})\]',
        re.IGNORECASE,
    )

    @staticmethod
    def parse_from_text(text: str) -> Optional[Dict[str, Any]]:
        """
        Parse attacker action from agent post.

        Formats (tried in order):
          [ATTACKER_CONFIRM SWC-107 withdraw()]  ← RC-3b per-function (new)
          [ATTACKER_CONFIRM SWC-107]             ← RC-3 SWC-only
          [ATTACKER_CONFIRM]                     ← legacy title match
        """
        def _extract_fields(txt: str):
            finding_ref = reason = path = exploit_path = ""
            for ln in txt.split("\n"):
                ln = ln.strip()
                if ln.lower().startswith("finding:"):
                    finding_ref = ln.split(":", 1)[1].strip()
                elif ln.lower().startswith("reason:"):
                    reason = ln.split(":", 1)[1].strip()
                elif ln.lower().startswith("path:"):
                    path = ln.split(":", 1)[1].strip()
                elif ln.lower().startswith("exploit:") or ln.lower().startswith("exploit path:"):
                    exploit_path = ln.split(":", 1)[1].strip()
            return finding_ref, reason, path or exploit_path

        # RC2: normalize markdown wrappers (bold/backtick) around ATTACKER tags
        # Handles: **ATTACKER_DISMISS**, **ATTACKER_DISMISS SWC-101**, **[ATTACKER_DISMISS SWC-101 func()]**
        _MD_WRAP_RE = re.compile(
            r'[`*]{1,2}\[?(ATTACKER_(?:CONFIRM|DISMISS|ESCALATE|DOWNGRADE|ADD_PATH|EXPLOIT)'
            r'(?:\s+(?:SWC-\d{1,3}|DEFI-[A-Z][A-Z_]+|INV-\d{1,3}))?'
            r'(?:\s+[a-zA-Z_]\w*\(\))?)\]?[`*]{1,2}'
        )
        text = _MD_WRAP_RE.sub(r'[\1]', text)

        # Check for ATTACKER_EXPLOIT INV-xxx first (invariant violation path)
        exploit_matches = list(ContractAttackerAction._EXPLOIT_RE.finditer(text))
        if exploit_matches:
            m = exploit_matches[-1]
            inv_id = m.group(1).upper()
            finding_ref, reason, path = _extract_fields(text[m.start():])
            # Parse feasibility
            feasible = "yes"
            for ln in text[m.start():].split("\n"):
                if ln.lower().startswith("feasible:"):
                    feasible = ln.split(":", 1)[1].strip().lower()
                    break
            # Parse impact
            impact = ""
            for ln in text[m.start():].split("\n"):
                if ln.lower().startswith("impact:"):
                    impact = ln.split(":", 1)[1].strip()
                    break
            return {
                "action_type":      ContractAttackerAction.EXPLOIT,
                "invariant_id":     inv_id,
                "swc_id":           "",
                "func_name":        "",
                "finding_ref":      finding_ref or f"Invariant violation: {inv_id}",
                "reason":           reason or impact,
                "path":             path,
                "feasible":         feasible,
                "confidence_delta": ContractAttackerAction.CONFIDENCE_DELTA[ContractAttackerAction.EXPLOIT],
            }

        # RC1: use LAST match (final decision, not think-block deliberation noise)
        all_matches = list(ContractAttackerAction._SWC_ACTION_RE.finditer(text))
        if all_matches:
            m = all_matches[-1]
            action_type = m.group(1)
            swc_id = m.group(2)
            func_name = m.group(3) or ""   # e.g. "transfer()" or ""
            # Extract fields from text at/after the last tag for accurate context
            finding_ref, reason, path = _extract_fields(text[m.start():])
            return {
                "action_type":      action_type,
                "swc_id":           swc_id,
                "func_name":        func_name,
                "finding_ref":      finding_ref,
                "reason":           reason,
                "path":             path,
                "confidence_delta": ContractAttackerAction.CONFIDENCE_DELTA.get(action_type, 0.0),
            }

        # Legacy format: [ATTACKER_CONFIRM] — title match, no SWC
        for action_type in ContractAttackerAction.ALL:
            if f"[{action_type}]" in text:
                finding_ref, reason, path = _extract_fields(text)
                return {
                    "action_type":      action_type,
                    "swc_id":           "",
                    "func_name":        "",
                    "finding_ref":      finding_ref,
                    "reason":           reason,
                    "path":             path,
                    "confidence_delta": ContractAttackerAction.CONFIDENCE_DELTA.get(action_type, 0.0),
                }
        return None


# ─── SWC Validation ──────────────────────────────────────────────────────────

# Known non-standard tags that map to a canonical SWC/DEFI ID
_SWC_REMAP: Dict[str, str] = {
    "ACCESS_CONTROL_MISCONFIGURATION": "SWC-105",
    "MISSING_ACCESS_CONTROL":          "SWC-105",
    "UNPROTECTED_FUNCTION":            "SWC-105",
    "FLASH_LOAN_PRICE_MANIPULATION":   "DEFI-FLASH_LOAN",
    "FLASH_LOAN_ATTACK":               "DEFI-FLASH_LOAN",
    "GOVERNANCE_FLASH_LOAN":           "DEFI-GOVERNANCE",
    "REENTRANCY_ATTACK":               "SWC-107",
    "INTEGER_OVERFLOW":                "SWC-101",
    "INTEGER_UNDERFLOW":               "SWC-101",
    "TIMESTAMP_DEPENDENCE":            "SWC-116",
    "TX_ORIGIN_AUTHENTICATION":        "SWC-115",
    "SIGNATURE_REPLAY":                "SWC-121",
    "DELEGATECALL_INJECTION":          "SWC-112",
}
# Accepted formats: SWC-N through SWC-NNN, DEFI-UPPERCASE_NAME
_VALID_SWC_RE = re.compile(r'^(SWC-\d{1,3}|DEFI-[A-Z][A-Z_]{2,})$')

# Protocol keyword boundary: any ALLCAPS_WORD: pattern signals a new protocol field.
# Used to stop multi-line field accumulation when Stage 2 keywords (VALIDATE_FINDING,
# CHALLENGE_FINDING, DOMAIN_EVIDENCE, etc.) appear in the same response stream.
# Note: this also matches prose tokens like NOTE:, TODO:, WARNING: — if such words
# appear legitimately inside description text they will truncate it early.  Monitor
# for false-positive truncation; add a whitelist prefix set here if needed.
_PROTOCOL_KW_RE = re.compile(r'^[A-Z][A-Z_]{2,}\s*:')


# ─── Function Field Parser ────────────────────────────────────────────────────

# Only match identifiers starting with a letter (not underscore) — filters param names like _spender
_SOLIDITY_FUNC_RE = re.compile(r'\b([a-zA-Z][a-zA-Z0-9_]{3,})\b')

# English prose words and Solidity keywords that are NOT function names
_FUNC_PROSE_BLACKLIST = frozenset({
    "function", "functions", "contract", "assumed", "potentially", "standard",
    "implied", "inferred", "general", "hypothetical", "specific", "similar",
    "administrative", "operations", "involving", "balances", "supply",
    "modifier", "returns", "internal", "external", "public", "private",
    "virtual", "override", "memory", "storage", "calldata", "payable",
    "view", "pure", "abstract", "address", "struct", "mapping", "event",
    "error", "using", "import", "pragma", "solidity", "library", "interface",
    "emit", "indexed", "constructor", "fallback", "receive", "assembly",
    "delegatecall", "selfdestruct", "suicide", "keccak", "ecrecover",
    "reentrancy", "overflow", "underflow", "vulnerability", "finding",
    "critical", "unprotected", "missing", "lack", "absence", "potential",
    "allows", "enables", "performs", "executes", "calls", "sends",
    "receives", "creates", "deploys", "updates", "reads", "writes", "checks",
    "requires", "asserts", "reverts", "emits", "certain", "certain",
    "token", "owner", "spender", "amount", "value", "balance", "total",
    "wallet", "account", "asset", "logic", "control", "access", "state",
    "type", "name", "role", "guard", "check", "none", "null", "true",
    "false", "this", "that", "with", "without", "from", "into", "through",
    "during", "before", "after", "while", "when", "where", "which", "what",
    "also", "then", "thus", "hence", "however", "therefore", "because",
    "since", "case", "note", "instance", "example", "detail", "provided",
    "context", "based", "determined", "determinable", "described", "mentioned",
    "referenced", "indicated", "applies", "applied", "given", "known",
    "unknown", "possible", "likely", "unlikely", "uncertain", "explicit",
    "implicit", "inferred", "derived", "includes", "containing", "related",
    "particularly", "especially", "specifically", "generally", "typically",
    "effectively", "directly", "indirectly", "currently", "potentially",
})


def _parse_function_field(raw: str) -> List[str]:
    """
    RC-1 fix: extract only valid Solidity function names from the FUNCTION field.

    Filters:
    - Tokens starting with underscore (parameter names: _spender, _value)
    - Tokens ending in a digit (type names: uint256, bytes32, int128)
    - Prose words and Solidity keywords (via blacklist)
    """
    tokens = _SOLIDITY_FUNC_RE.findall(raw)
    result = []
    for t in tokens:
        if (t[-1].isdigit()                # type name: uint256, bytes32, int128
                or t.lower() in _FUNC_PROSE_BLACKLIST):
            continue
        result.append(t + "()")
    return result


def extract_known_functions(context_summary: str) -> set:
    """
    Parse function names from a contract_summary string.
    Handles both formats emitted by build_context_summary():
      - PUBLIC/EXTERNAL FUNCTIONS:\\n  - funcName()...
      - DEFINED FUNCTIONS:\\n  funcA, funcB, funcC
    Returns lowercase set of bare function names (no parens).
    """
    funcs: set = set()
    # Format 1: "  - funcName()" lines under PUBLIC/EXTERNAL FUNCTIONS:
    for m in re.finditer(r'^\s+-\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', context_summary, re.MULTILINE):
        funcs.add(m.group(1).lower())
    # Format 2: "DEFINED FUNCTIONS:\n  funcA, funcB, ..." line
    m2 = re.search(r'DEFINED FUNCTIONS:\s*\n\s*([^\n]+)', context_summary)
    if m2:
        for token in m2.group(1).split(','):
            t = token.strip()
            if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]+$', t):
                funcs.add(t.lower())
    return funcs


# ─── Evidence Gate ────────────────────────────────────────────────────────────

# Solidity-specific markers — presence in evidence text indicates real code reference
_EVIDENCE_MARKERS = (
    "()", ".call", ".transfer", ".send", "require(", "assert(", "revert(",
    "mapping(", "msg.sender", "msg.value", "msg.data", "block.", "tx.origin",
    "tx.", "pragma", "function ", "modifier ", "emit ", "event ", "assembly",
    "delegatecall", "selfdestruct", "suicide(", "ecrecover(", "keccak",
    "+=", "-=", "*=", "++", "--", "<<", ">>",
    "^0.",       # compiler version: ^0.4.24, ^0.8.0
    "solidity ", # pragma solidity
)

def _has_specific_evidence(evidence: List[str], functions: List[str]) -> bool:
    """
    RC-2: Return True if finding has concrete code evidence.
    After RC-1 fix, `functions` only contains clean Solidity identifiers.
    """
    # A named function that survived RC-1 filter = concrete evidence
    if functions:
        return True
    if not evidence:
        return False
    combined = " ".join(evidence).lower()
    # RC-2: reject trivially short evidence like "The", "N/A", "a function"
    if len(combined.strip()) < 15:
        return False
    # Must contain at least one Solidity-specific syntax marker
    return any(marker.lower() in combined for marker in _EVIDENCE_MARKERS)


# ─── Contract Finding Parser ──────────────────────────────────────────────────

def parse_contract_finding_from_text(
    text: str,
    agent_profile: ContractAgentProfile,
    round_num: int,
    known_functions: Optional[set] = None,
) -> Optional[Dict[str, Any]]:
    """
    Parse ContractFinding from an agent post.

    Expected format:
      FINDING: <title>
      SWC: <SWC-107 or DEFI-FLASH_LOAN_PRICE_MANIPULATION>
      SEVERITY: <critical|high|medium|low>
      FUNCTION: <function_name()>
      EVIDENCE: <specific code pattern or KG fact>
      DESCRIPTION: <detailed explanation>
      PATCH: <remediation recommendation>

    Returns raw dict or None if no finding detected.
    """
    # Support both "FINDING:" (new format) and "[FINDING]" (legacy compatibility)
    has_finding = (
        re.search(r'(?i)^FINDING\s*:', text, re.MULTILINE)
        or "[FINDING]" in text
    )
    if not has_finding:
        return None

    lines = text.split("\n")
    title = ""
    swc_id = ""
    swc_name = ""
    severity = "medium"
    affected_functions = []
    evidence = []
    description = ""
    patch_suggestion = None
    phase = get_phase_for_round(round_num)

    # Track multi-line field accumulation
    current_field = None
    current_value = []

    def _flush_field():
        nonlocal description, patch_suggestion
        if current_field == "description" and current_value:
            description = " ".join(current_value)
        elif current_field == "patch" and current_value:
            patch_suggestion = " ".join(current_value)

    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()

        # New field detected → flush previous
        if re.match(r'(?i)^(FINDING|SWC|SEVERITY|FUNCTION|EVIDENCE|DESCRIPTION|PATCH)\s*:', stripped):
            _flush_field()
            current_field = None
            current_value = []

        if re.match(r'(?i)^FINDING\s*:', stripped) or stripped.startswith("[FINDING]"):
            title = re.sub(r'(?i)^FINDING\s*:', '', stripped).replace("[FINDING]", "").strip()
        elif lower.startswith("swc:"):
            raw = stripped.split(":", 1)[1].strip()
            # Extract first SWC-XXX or known tag
            m = re.search(r'(SWC-\d+|[A-Z][A-Z_]{4,})', raw)
            swc_id = m.group(1) if m else raw.split()[0] if raw else ""
            # RC-5: remap known aliases to canonical IDs
            swc_id = _SWC_REMAP.get(swc_id, swc_id)
            # Try to get SWC name from the rest
            if m and raw != m.group(1):
                after = raw[m.end():].strip(" -—:")
                swc_name = after.split(".")[0].strip() if after else ""
        elif lower.startswith("severity:"):
            sev_raw = stripped.split(":", 1)[1].strip().lower()
            if sev_raw in {"critical", "high", "medium", "low", "info"}:
                severity = sev_raw
        elif lower.startswith("function:"):
            func_raw = stripped.split(":", 1)[1].strip()
            # RC-1: extract only valid Solidity identifiers (not prose words)
            affected_functions = _parse_function_field(func_raw)
        elif lower.startswith("evidence:"):
            evidence_raw = stripped.split(":", 1)[1].strip()
            evidence = [evidence_raw] if evidence_raw else []
        elif lower.startswith("description:"):
            current_field = "description"
            current_value = [stripped.split(":", 1)[1].strip()]
        elif lower.startswith("patch:"):
            current_field = "patch"
            current_value = [stripped.split(":", 1)[1].strip()]
        elif current_field and stripped and not _PROTOCOL_KW_RE.match(stripped):
            current_value.append(stripped)

    _flush_field()

    if not title:
        return None

    # RC-5 — SWC validation: reject findings with unmappable non-standard SWC tags
    if swc_id and not _VALID_SWC_RE.match(swc_id):
        logger.debug(
            f"RC-5: invalid SWC tag '{swc_id}' → dropped '{title[:60]}' "
            f"from {agent_profile.agent_id}"
        )
        return None

    # RC-1 (2nd layer) — if contract function list is known, keep only existing functions
    if known_functions and affected_functions:
        validated_funcs = [
            f for f in affected_functions
            if f.rstrip("()").lower() in known_functions
        ]
        if validated_funcs:
            affected_functions = validated_funcs
        # If none match the known list, discard all (don't fall back to garbage)
        # but only if known_functions is substantial (>= 3 entries)
        elif len(known_functions) >= 3:
            affected_functions = []

    # Layer 2 — Evidence gate: drop findings with no concrete code reference
    if not _has_specific_evidence(evidence, affected_functions):
        logger.debug(
            f"Evidence gate: dropped '{title[:60]}' from {agent_profile.agent_id} "
            f"— no function name or Solidity code pattern in evidence"
        )
        return None

    return {
        "finding_id":          f"cf_{uuid.uuid4().hex[:8]}",
        "author_domain":       agent_profile.domain_group,
        "author_persona":      agent_profile.persona,
        "title":               title,
        "swc_id":              swc_id,
        "swc_name":            swc_name,
        "severity":            severity,
        "affected_functions":  affected_functions,
        "evidence":            evidence,
        "description":         description or title,
        "patch_suggestion":    patch_suggestion,
        "phase":               phase,
        "round_number":        round_num,
        "confidence":          _initial_confidence(severity, phase),
        "challenged_by":       [],
        "validated_by":        [],
        "cross_domain_validated": False,
        "is_exploitable":      None,
        "exploit_scenario":    None,
        "attacker_corroborations": [],
    }


def _initial_confidence(severity: str, phase: str) -> float:
    """
    Initial confidence score based on severity and phase.
    Phase A findings start lower — need cross-group validation to rise.
    """
    base = {
        "critical": 0.70,
        "high":     0.60,
        "medium":   0.50,
        "low":      0.40,
        "info":     0.30,
    }.get(severity, 0.50)

    # Phase B onwards: slightly higher starting confidence (cross-group exposure)
    if phase == "B":
        base += 0.05
    elif phase == "C":
        base += 0.08

    return min(base, 0.85)


# ─── Semantic Finding Parser (Web3Bugs S-category) ───────────────────────────

SEMANTIC_FINDING_FORMAT = f"""\
SEMANTIC_FINDING: <title>
CATEGORY: <{SEMANTIC_CATEGORY_PIPE_STRING}>
SEVERITY: <critical|high|medium|low>
FUNCTION: <affected_function()>
EVIDENCE: <specific code pattern or economic invariant violated>
ATTACK_PATH: <step-by-step scenario>
PATCH: <concrete remediation recommendation>"""

_SEMANTIC_ATTACK_PATH_RE = re.compile(
    r'(?i)^(STEP\s*\d+|→|\d+[\.\)]\s)', re.MULTILINE
)


def parse_semantic_finding_from_text(
    text: str,
    agent_profile: "ContractAgentProfile",
    round_num: int,
    known_functions: Optional[set] = None,
) -> Optional[Dict[str, Any]]:
    """
    Parse a SEMANTIC_FINDING block from an agent post.

    Expected format:
      SEMANTIC_FINDING: <title>
      CATEGORY: <category>
      SEVERITY: <critical|high|medium|low>
      FUNCTION: <affected_function()>
      EVIDENCE: <specific code pattern or economic invariant violated>
      ATTACK_PATH: <step-by-step scenario>

    Returns raw dict or None if no semantic finding detected.
    """
    if not re.search(r'(?i)^SEMANTIC_FINDING\s*:', text, re.MULTILINE):
        return None

    lines = text.split("\n")
    title = ""
    category = "other"
    severity = "medium"
    affected_functions: List[str] = []
    evidence = ""
    attack_path: List[str] = []
    patch_suggestion = None
    phase = get_phase_for_round(round_num)

    current_field = None
    current_value: List[str] = []

    def _flush():
        nonlocal evidence, attack_path, patch_suggestion
        if current_field == "evidence" and current_value:
            evidence = " ".join(current_value)
        elif current_field == "attack_path" and current_value:
            attack_path = [v for v in current_value if v.strip()]
        elif current_field == "patch" and current_value:
            patch_suggestion = " ".join(current_value)

    _FIELD_RE = re.compile(
        r'(?i)^(SEMANTIC_FINDING|CATEGORY|SEVERITY|FUNCTION|EVIDENCE|ATTACK_PATH|PATCH)\s*:',
        re.MULTILINE
    )

    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()

        if _FIELD_RE.match(stripped):
            _flush()
            current_field = None
            current_value = []

        if re.match(r'(?i)^SEMANTIC_FINDING\s*:', stripped):
            title = re.sub(r'(?i)^SEMANTIC_FINDING\s*:', '', stripped).strip()
        elif lower.startswith("category:"):
            cat_raw = stripped.split(":", 1)[1].strip()
            category = normalize_semantic_category(cat_raw)
        elif lower.startswith("severity:"):
            sev_raw = stripped.split(":", 1)[1].strip().lower()
            if sev_raw in {"critical", "high", "medium", "low", "info"}:
                severity = sev_raw
        elif lower.startswith("function:"):
            func_raw = stripped.split(":", 1)[1].strip()
            affected_functions = _parse_function_field(func_raw)
        elif lower.startswith("evidence:"):
            current_field = "evidence"
            current_value = [stripped.split(":", 1)[1].strip()]
        elif lower.startswith("attack_path:"):
            current_field = "attack_path"
            val = stripped.split(":", 1)[1].strip()
            current_value = [val] if val else []
        elif lower.startswith("patch:"):
            current_field = "patch"
            current_value = [stripped.split(":", 1)[1].strip()]
        elif current_field and stripped and not _PROTOCOL_KW_RE.match(stripped):
            current_value.append(stripped)

    _flush()

    if not title:
        return None

    # Validate known functions if provided
    if known_functions and affected_functions:
        validated = [f for f in affected_functions if f.rstrip("()").lower() in known_functions]
        if validated:
            affected_functions = validated
        elif len(known_functions) >= 3:
            affected_functions = []

    # Require at least some evidence text
    if not evidence or len(evidence.strip()) < 10:
        logger.debug(
            f"Semantic evidence gate: dropped '{title[:60]}' from {agent_profile.agent_id} "
            f"— evidence too short or missing"
        )
        return None

    return {
        "finding_id":          f"sf_{uuid.uuid4().hex[:8]}",
        "author_domain":       agent_profile.domain_group,
        "author_persona":      agent_profile.persona,
        "title":               title,
        "category":            category,
        "severity":            severity,
        "affected_functions":  affected_functions,
        "evidence":            evidence,
        "attack_path":         attack_path,
        "patch_suggestion":    patch_suggestion,
        "phase":               phase,
        "round_number":        round_num,
        "confidence":          _initial_confidence(severity, phase),
        "validated_by":        [],
        "challenged_by":       [],
        "is_exploitable":      None,
        "is_attacker_surfaced": False,
    }


# ─── OASIS Config Builder ─────────────────────────────────────────────────────

@dataclass
class ContractAuditOasisConfig:
    """
    Configuration cho OASIS Contract Audit Room session.
    Tương đương CyberOasisConfig — adapted for smart contract domain.
    """
    session_id:       str
    graph_id:         str
    contract_id:      str
    platform:         str = "reddit"                # reddit cho threaded discussion
    environment_name: str = "contract_audit_room"
    total_rounds:     int = TOTAL_ROUNDS
    agents:           List[Dict[str, Any]] = field(default_factory=list)
    initial_post:     str = ""
    phase_config:     Dict[str, Any] = field(default_factory=lambda: PHASE_CONFIG)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id":       self.session_id,
            "graph_id":         self.graph_id,
            "contract_id":      self.contract_id,
            "platform":         self.platform,
            "environment_name": self.environment_name,
            "total_rounds":     self.total_rounds,
            "agent_count":      len(self.agents),
            "phase_config":     self.phase_config,
            "has_initial_post": bool(self.initial_post),
        }


class ContractAuditEnvBuilder:
    """
    Xây dựng OASIS environment config cho Contract Audit Room.
    Tương đương CyberOasisEnvBuilder.
    """

    def __init__(self, manifest: Optional[Dict[str, Any]] = None):
        self.manifest = manifest

    def _build_focus_directive(self) -> str:
        """Inject focus directive when manifest identifies a primary contract."""
        if not self.manifest:
            return ""
        primary = self.manifest.get("primary")
        if not primary:
            return ""
        secondary     = [s for s in self.manifest.get("secondary", []) if s]
        out_of_scope  = self.manifest.get("out_scope_contracts", [])
        scope_method  = self.manifest.get("scope_method", "")

        sec_str = ", ".join(secondary) if secondary else "none"

        lines = [
            f"\n⚠️ AUDIT SCOPE — Tập trung đúng contract:",
            f"  IN-SCOPE PRIMARY  : {primary}",
            f"  IN-SCOPE SECONDARY: {sec_str}",
        ]

        if out_of_scope:
            oos_str = ", ".join(out_of_scope[:6]) + (" ..." if len(out_of_scope) > 6 else "")
            lines += [
                f"  OUT-OF-SCOPE (stub only): {oos_str}",
                f"  → Các contracts OUT-OF-SCOPE chỉ có function signatures, KHÔNG có body.",
                f"  → KHÔNG report findings cho OUT-OF-SCOPE contracts trừ khi chúng",
                f"    ảnh hưởng trực tiếp đến {primary}.",
            ]

        lines += [
            f"  ≥60% findings PHẢI về {primary} hoặc direct dependencies của nó.",
            f"  Infrastructure/utility bugs chỉ report khi exploitable từ {primary}.",
        ]

        return "\n".join(lines) + "\n"

    def build_config(
        self,
        session_id: str,
        graph_id: str,
        contract_id: str,
        profiles: List[ContractAgentProfile],
        contract_summary: str,
        platform: str = "reddit",
    ) -> ContractAuditOasisConfig:
        """
        Build full OASIS config from agent profiles.

        Args:
            session_id: unique session identifier
            graph_id: Zep KG graph ID
            contract_id: contract being audited
            profiles: 18 ContractAgentProfile instances
            contract_summary: ContractKGBuilder.build_context_summary() output
            platform: "reddit" (recommended for threaded audit discussion)
        """
        agents = [p.to_oasis_format() for p in profiles]
        initial_post = self._build_initial_post(contract_id, contract_summary, graph_id)

        return ContractAuditOasisConfig(
            session_id=session_id,
            graph_id=graph_id,
            contract_id=contract_id,
            platform=platform,
            agents=agents,
            initial_post=initial_post,
        )

    def get_active_agents_for_phase(
        self,
        profiles: List[ContractAgentProfile],
        phase: str,
    ) -> List[ContractAgentProfile]:
        """Phase A/B: Tier-1 experts only; Phase C: all agents (Tier-1 + Tier-2 attackers)."""
        phase_cfg = PHASE_CONFIG.get(phase, {})
        attacker_active = phase_cfg.get("attacker_active", False)
        return profiles if attacker_active else [p for p in profiles if p.tier == 1]

    def build_phase_instruction(
        self,
        phase: str,
        round_num: int,
        gap_context: str = "",
        phase_c_review_list: str = "",
        stage: int = 0,
    ) -> str:
        """
        Build system instruction injected at the start of each round.

        stage=0: single-stage mode (backward compat — uses instruction_addition)
        stage=1: two-stage Stage 1 — free-form analysis + CLAIM declarations
        stage=2: two-stage Stage 2 — FINDING/SEMANTIC_FINDING + CHALLENGE/VALIDATE
        """
        phase_cfg = PHASE_CONFIG.get(phase, {})
        if stage == 1:
            instruction_text = phase_cfg.get("stage1_instruction", phase_cfg.get("instruction_addition", ""))
        elif stage == 2:
            instruction_text = phase_cfg.get("stage2_instruction", phase_cfg.get("instruction_addition", ""))
        else:
            instruction_text = phase_cfg.get("instruction_addition", "")

        # S2a: prepend focus directive to Stage 1 instructions only
        if stage == 1:
            instruction_text = self._build_focus_directive() + instruction_text

        instruction = (
            f"=== Phase {phase}: {phase_cfg.get('name', '')} | Round {round_num}/{TOTAL_ROUNDS} ===\n"
            f"{instruction_text}"
        )
        # RC-3 Two-step Phase C: inject preliminary consensus findings for attackers to review
        if phase == "C" and phase_c_review_list:
            instruction = phase_c_review_list + "\n" + instruction
        if gap_context:
            instruction = gap_context + "\n" + instruction
        return instruction

    def _build_initial_post(
        self,
        contract_id: str,
        contract_summary: str,
        graph_id: str,
    ) -> str:
        """
        Seeding post that initializes the audit session.
        Presented to all agents as the first message they see.
        """
        return f"""# Contract Security Audit Session

## Contract Under Review: {contract_id}
## Knowledge Graph: {graph_id}

{contract_summary}

---

## Audit Instructions

This is a structured multi-expert security audit using the Delphi method.

**Phase A (Rounds 1–3)**: Each domain group analyzes the contract from their expertise.
Report findings using the FINDING format. Declare GAPs for areas you cannot assess.

**Phase B (Rounds 4–7)**: Challenge and validate findings from other domain groups.
Look for overestimated severity, missing context, or overlooked functions.

**Phase C (Rounds 8–10)**: Attacker profiles validate exploitability.
Domain experts: respond to attacker challenges.

**Finding format (ALL domain experts must use this):**
```
FINDING: <concise title>
SWC: <SWC-ID or DeFi pattern>
SEVERITY: <critical|high|medium|low>
FUNCTION: <affected_function_name()>
EVIDENCE: <specific code pattern or KG fact>
DESCRIPTION: <detailed explanation>
PATCH: <remediation>
ANALYZED: <what you reviewed>
GAP: <what you cannot verify>
```

**CRITICAL — SWC field MUST use the exact `SWC-NNN` format** (e.g. `SWC-107`, `SWC-105`, `SWC-113`).
Do NOT use descriptive names alone (e.g. do NOT write just "Reentrancy" or "Unprotected Ether Withdrawal").
Common IDs: SWC-100 (Default Visibility), SWC-101 (Integer Overflow/Underflow), SWC-104 (Unchecked Return Value),
SWC-105 (Unprotected Ether Withdrawal), SWC-106 (Unprotected SELFDESTRUCT), SWC-107 (Reentrancy),
SWC-112 (Delegatecall Untrusted Callee), SWC-113 (DoS / Unbounded Loop), SWC-114 (Front-Running / Tx Order Dependence),
SWC-115 (tx.origin Authorization), SWC-116 (Block Timestamp Manipulation), SWC-120 (Weak Randomness),
SWC-121 (Signature Replay). For DeFi-only patterns: `DEFI-<PATTERN>`.

**CRITICAL — EVIDENCE GATE: Only report a finding if you can provide concrete evidence from THIS contract.**
- FUNCTION must name a real function that exists in the contract (e.g. `withdraw()`, `changeOwner()`).
- EVIDENCE must quote a specific code pattern, variable name, or line from the contract source — NOT a generic description.
- If you cannot point to specific code in THIS contract → do NOT use FINDING format. Use GAP instead:
  `GAP: No evidence of <vulnerability> in this contract — <function> not present / pattern not found.`
- Hypothetical or "potential" findings without code evidence will be dismissed as false positives.

Start the audit. Report your first findings based on the contract context above.
"""
