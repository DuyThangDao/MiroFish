"""
Contract Audit OASIS Environment — Smart Contract Audit.

Defines the OASIS configuration for the Contract Audit Room.
Mirrors cyber_oasis_env.py — preserves the 3-phase structure,
adapts the action space, finding format, and GAP routing table for the smart contract domain.

Phase A (rounds 1–3):  Domain experts analyze within their group; attacker agents are silent
Phase B (rounds 4–7):  Domain experts challenge each other cross-domain
Phase C (rounds 8–10): Attacker profiles confirm/dismiss/add attack paths
"""

import re
import uuid
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from .contract_profile_generator import ContractAgentProfile
from .semantic_taxonomy import SEMANTIC_CATEGORY_PIPE_STRING, normalize_semantic_category

logger = get_logger("contract_oasis_env")

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
    Extract Solidity function names from a FUNCTION field that may contain full signatures.

    Handles: bare names, name(), name(params), "function name(params)", comma-separated lists.
    Splits on commas only at paren depth 0 so "fn(a, b)" is kept as one unit.
    """
    # Split on commas at paren depth 0 — keeps "claimReward(uint256, address)" as one segment
    segments: list = []
    depth, start = 0, 0
    for i, ch in enumerate(raw):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch == ',' and depth == 0:
            segments.append(raw[start:i])
            start = i + 1
    segments.append(raw[start:])

    result = []
    for segment in segments:
        # Drop parameter list entirely — "claimReward(uint256 pos, address rec)" → "claimReward"
        name = segment.split("(")[0].strip()
        # Drop leading keywords — "function mint" → "mint"
        tokens = name.split()
        name = tokens[-1] if tokens else ""
        # Accept only valid Solidity identifiers (includes underscore-prefixed internal fns)
        if re.fullmatch(r'[a-zA-Z_]\w*', name):
            result.append(name + "()")
    return list(dict.fromkeys(result))  # dedup, preserve order


def _validate_code_anchor(anchor: str) -> bool:
    """Return True if anchor looks like real code (not prose or N/A)."""
    anchor = anchor.strip()
    if not anchor or len(anchor) < 4:
        return False
    if anchor.lower().startswith(("the ", "this ", "n/a", "none", "not ", "no ")):
        return False
    if anchor.startswith(("//", "/*")):
        return False
    if anchor in ("{", "}", "else", "return", "else {", "} else {"):
        return False
    return bool(re.search(r'[a-zA-Z_]\w{2,}', anchor))


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
    # Format 3: raw Solidity source — "function funcName("
    for m in re.finditer(r'\bfunction\s+([a-zA-Z_]\w*)\s*\(', context_summary):
        funcs.add(m.group(1).lower())
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

_EVIDENCE_TYPE_PREFIXES = ("CODE:", "MISSING:", "SEQ:", "INV:", "DESIGN:")

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
    combined = " ".join(evidence)
    # Structured evidence prefix = always valid
    if any(combined.strip().startswith(p) for p in _EVIDENCE_TYPE_PREFIXES):
        return True
    combined_lower = combined.lower()
    # RC-2: reject trivially short evidence like "The", "N/A", "a function"
    if len(combined_lower.strip()) < 15:
        return False
    # Must contain at least one Solidity-specific syntax marker
    return any(marker.lower() in combined_lower for marker in _EVIDENCE_MARKERS)


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
      CONTRACT: <contract name>
      FUNCTION: <function_name()>
      SEVERITY: <critical|high|medium|low>
      EVIDENCE: <specific code pattern or KG fact>
      ATTACK_PATH: <step-by-step exploit scenario>
      DESCRIPTION: <detailed explanation>
      PATCH: <remediation recommendation>

    Returns raw dict or None if no finding detected.
    """
    has_finding = (
        re.search(r'(?i)^FINDING\s*:', text, re.MULTILINE)
        or "[FINDING]" in text
    )
    if not has_finding:
        return None

    lines = text.split("\n")
    title = ""
    contract_name = ""
    severity = "medium"
    affected_functions = []
    code_anchor = ""
    evidence = []
    description = ""
    attack_path = ""
    patch_suggestion = None
    phase = get_phase_for_round(round_num)

    current_field = None
    current_value = []

    def _flush_field():
        nonlocal description, attack_path, patch_suggestion
        if current_field == "description" and current_value:
            description = " ".join(current_value)
        elif current_field == "attack_path" and current_value:
            attack_path = " ".join(current_value)
        elif current_field == "patch" and current_value:
            patch_suggestion = " ".join(current_value)

    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()

        if re.match(r'(?i)^(FINDING|CONTRACT|SEVERITY|FUNCTION|CODE_ANCHOR|EVIDENCE|ATTACK_PATH|DESCRIPTION|PATCH)\s*:', stripped):
            _flush_field()
            current_field = None
            current_value = []

        if re.match(r'(?i)^FINDING\s*:', stripped) or stripped.startswith("[FINDING]"):
            title = re.sub(r'(?i)^FINDING\s*:', '', stripped).replace("[FINDING]", "").strip()
        elif lower.startswith("contract:"):
            contract_name = stripped.split(":", 1)[1].strip()
        elif lower.startswith("severity:"):
            sev_raw = stripped.split(":", 1)[1].strip().lower()
            if sev_raw in {"critical", "high", "medium", "low", "info"}:
                severity = sev_raw
        elif lower.startswith("function:"):
            func_raw = stripped.split(":", 1)[1].strip()
            affected_functions = _parse_function_field(func_raw)
        elif lower.startswith("code_anchor:"):
            raw_anchor = stripped.split(":", 1)[1].strip()[:150]
            code_anchor = raw_anchor if _validate_code_anchor(raw_anchor) else ""
        elif lower.startswith("evidence:"):
            evidence_raw = stripped.split(":", 1)[1].strip()
            evidence = [evidence_raw] if evidence_raw else []
        elif lower.startswith("attack_path:"):
            current_field = "attack_path"
            current_value = [stripped.split(":", 1)[1].strip()]
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

    # RC-1 (2nd layer) — if contract function list is known, keep only existing functions
    if known_functions and affected_functions:
        validated_funcs = [
            f for f in affected_functions
            if f.rstrip("()").lower() in known_functions
        ]
        if validated_funcs:
            affected_functions = validated_funcs
        elif len(known_functions) >= 3:
            affected_functions = []

    # Evidence gate: drop findings with no concrete code reference
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
        "contract_name":       contract_name,
        "severity":            severity,
        "affected_functions":  affected_functions,
        "code_anchor":         code_anchor,
        "evidence":            evidence,
        "description":         description or title,
        "attack_path":         attack_path,
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


# ─── Semantic Finding Parser (DEPRECATED — S-track removed in NL migration) ──

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


# ─── v2 Multi-finding Parser ─────────────────────────────────────────────────

def parse_all_contract_findings_from_text(
    text: str,
    agent_profile: "ContractAgentProfile",
    round_num: int,
    known_functions: Optional[set] = None,
) -> List[Dict[str, Any]]:
    """
    Parse ALL FINDING blocks from a single agent response.

    Unlike parse_contract_finding_from_text() which stops at the first block,
    this function extracts every FINDING block in the response.

    Returns list of finding dicts (unified NL format with contract_name, attack_path).
    """
    findings: List[Dict[str, Any]] = []

    segment_pattern = re.compile(
        r'(?=(?:^|\n)FINDING\s*:)',
        re.IGNORECASE,
    )
    segments = segment_pattern.split(text)

    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        if re.match(r'(?i)^FINDING\s*:', seg):
            result = parse_contract_finding_from_text(seg, agent_profile, round_num, known_functions)
            if result:
                findings.append(result)

    return findings


# ─── OASIS Config Builder ─────────────────────────────────────────────────────

class ContractAuditEnvBuilder:
    """
    Build OASIS environment config for the Contract Audit Room.
    Equivalent to CyberOasisEnvBuilder.
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
            f"\n⚠️ AUDIT SCOPE — Focus on the correct contracts:",
            f"  IN-SCOPE PRIMARY  : {primary}",
            f"  IN-SCOPE SECONDARY: {sec_str}",
        ]

        if out_of_scope:
            oos_str = ", ".join(out_of_scope[:6]) + (" ..." if len(out_of_scope) > 6 else "")
            lines += [
                f"  OUT-OF-SCOPE (stub only): {oos_str}",
                f"  → OUT-OF-SCOPE contracts have function signatures only — NO body.",
                f"  → Do NOT report findings for OUT-OF-SCOPE contracts unless they",
                f"    directly affect {primary}.",
            ]

        lines += [
            f"  Analyze ALL in-scope contracts thoroughly — PRIMARY and SECONDARY contracts",
            f"  are equally important. Report findings in any in-scope contract.",
            f"  Infrastructure/utility bugs may be skipped ONLY IF they cannot be exploited from any in-scope contract.",
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
    ) -> Dict[str, Any]:
        """
        Build OASIS config from agent profiles.

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

        return {
            "session_id":       session_id,
            "graph_id":         graph_id,
            "contract_id":      contract_id,
            "platform":         platform,
            "environment_name": "contract_audit_room",
            "agents":           agents,
            "initial_post":     initial_post,
        }

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


# ─── v2 Round Prompt Builders ─────────────────────────────────────────────────

_STEP1_BLOCK = """\
STEP 1 — LIST INVARIANTS:
  Read the full contract source and list 3–6 PROTOCOL-SPECIFIC invariants.
  Format: INV-1: <invariant statement>, INV-2: ..., ...

  Invariants MUST be strictly derived from the code, require() statements, or NatSpec.
  Do NOT invent business rules or assume features not explicitly present in the code.
  (Wrong example: "contract must have a pause() function" if no pause mechanism exists.)

  Invariants MUST be protocol-specific — NOT acceptable:
    ✗ Generic: "no reentrancy", "no overflow", "onlyOwner"
    ✓ Specific accounting: "after borrow(), global_debts must increase by exactly amount + fee"
    ✓ Specific state: "withdrawalDelay[id] may only be set when msg.sender == owner(id)"
    ✓ Specific flow: "distribute() must only decrease mochiShare, never reset treasuryShare"
    ✓ Specific math: "shares * pricePerShare / 1e18 must equal depositor's underlying assets"

  How to find good invariants:
  - Read NatSpec @notice/@dev — they often describe conditions that must hold
  - Read require() messages — each require is an invariant candidate
  - Look for state variables named "total", "global", "cumulative" — they usually must equal sum of sub-values
  - Look for functions named "distribute", "reward", "migrate", "sync" — they often have ordering invariants

  ACCESS CONTROL INV — mandatory scan:
  - For EVERY function that writes to a shared counter, mapping, or array (e.g., registers an asset,
    adds to a list, increments a global total): check if there is an explicit msg.sender restriction
    (onlyOwner, onlyDAO, require(msg.sender == ...), or a role modifier).
  - If a function modifies shared state with NO caller restriction → generate an INV:
    "INV-N: <FunctionName>() MUST require explicit caller authorization before modifying <state variable>."
  - Do NOT skip this even if the function has other checks (bounds, amount > 0) — those are NOT access control."""

_TRACK_E_BLOCK = (
    "TRACK E — UNINITIALIZED STATE VARIABLES:\n"
    "  For every state variable used in a security-critical check (time gate, block delay,\n"
    "  fee rate, reward accumulator, cooldown, cap), verify it is explicitly SET somewhere\n"
    "  in the contract (constructor, init(), or a dedicated setter).\n"
    "  A variable that is only READ but never WRITTEN defaults to 0 in Solidity —\n"
    "  this silently bypasses the check (e.g., a delay of 0 = no delay).\n"
    "  Any security variable that is never assigned = FINDING candidate.\n\n"
    "  TIME-DELTA PATTERN — check explicitly:\n"
    "  If the contract uses `block.timestamp - lastTime[user]` (or `block.number - lastBlock[user]`)\n"
    "  to compute rewards, interest, or cooldowns:\n"
    "    → Check if `lastTime[user]` is SET in the deposit/entry/join function.\n"
    "    → If NOT set on entry: a new depositor has lastTime[user] == 0, so the delta equals\n"
    "      the entire chain history — producing a massive, incorrect reward on first claim.\n"
    "    → This is a FINDING candidate: 'Uninitialized lastTime leads to inflated first reward.'\n\n"
)

_INDEPENDENT_TRACKS_BLOCK_BASE = (
    "\nINDEPENDENT REASONING TRACKS — run these regardless of HIST-INV annotations:\n\n"
    "TRACK A — ADVERSARIAL INPUTS:\n"
    "  For the 2-3 most complex functions: test numeric bounds (0, max_uint),\n"
    "  address(0), empty arrays, and cross-function call sequences.\n"
    "  Any input that corrupts state without reverting = FINDING candidate.\n\n"
)

_INDEPENDENT_TRACKS_BLOCK_SUFFIX = "TRACK B/C/D: applied per your domain expertise (see your system prompt).\n"

# Domains where TRACK E is relevant (initialization bugs, access/reward logic)
_TRACK_E_DOMAINS = {"general", "access_reward"}


def _build_independent_tracks_block(domain_group: str) -> str:
    """Build INDEPENDENT_TRACKS_BLOCK with TRACK E scoped to relevant domains only."""
    block = _INDEPENDENT_TRACKS_BLOCK_BASE
    if domain_group in _TRACK_E_DOMAINS:
        block += _TRACK_E_BLOCK
    block += _INDEPENDENT_TRACKS_BLOCK_SUFFIX
    return block

# domain_group → hist-inv domain tag (agents not in _AGENT_TO_HIST_TAG use this)
_DOMAIN_GROUP_TO_HIST_TAG: dict = {
    'math_numerics':         'arithmetic',
    'asset_accounting':      'reserve',
    'access_control_domain': 'access',
    'integration_domain':    'reentrancy',
    'economic_domain':       'general',
    'state_logic':           'general',
    'general':               'general',
    'red_team_attacker':     'general',
}

# Per-agent overrides (take precedence over domain_group)
_AGENT_TO_HIST_TAG: dict = {
    'boundary_analyst':          'boundary',
    'temporal_attack_specialist': 'temporal',
    'callback_specialist':       'reentrancy',
}


def _get_agent_hist_tag(agent_profile: "ContractAgentProfile") -> str:
    """Return the HIST-INV domain tag for a given agent profile."""
    agent_id = getattr(agent_profile, 'agent_id', '')
    if agent_id in _AGENT_TO_HIST_TAG:
        return _AGENT_TO_HIST_TAG[agent_id]
    domain_group = getattr(agent_profile, 'domain_group', 'general')
    return _DOMAIN_GROUP_TO_HIST_TAG.get(domain_group, 'general')


def _build_hist_inv_check_block(hist_tag: str) -> str:
    """Build the HIST-INV CHECK block, filtered to the agent's domain tag."""
    if hist_tag == 'general':
        tag_filter = "  Process ALL annotated functions.\n"
    else:
        tag_filter = (
            f"  Your domain tag is `{hist_tag}`. "
            f"Process ONLY annotations tagged `[HIST-INV|{hist_tag}]` or `[HIST-INV|general]`.\n"
            f"  Skip all other domain tags — do NOT output HIST-CHECK lines for them.\n"
        )
    return f"""\
HIST-INV CHECK — run this BEFORE writing any FINDING:
{tag_filter}
  Scan the source for `// [HIST-INV|<tag>]` comments (historical HIGH-severity pattern matches).
  For each annotated function in your domain, output one verdict line:
    HIST-CHECK [<FunctionName>]: MATCH | MITIGATED | UNCLEAR — <one sentence citing exact code>
  If no domain-relevant annotations exist → write: HIST-CHECK: none

  MATCH RULE — MANDATORY FINDING:
    If HIST-CHECK verdict is MATCH → you MUST write a FINDING block immediately after the verdict line.
    Do NOT continue to other checks without writing the FINDING first.
    A MATCH without a corresponding FINDING block = an incomplete audit.

  MITIGATED criteria — access control specifically:
    MITIGATED requires an explicit caller check: msg.sender == owner/role, onlyOwner, onlyDAO, etc.
    A bound/size check (e.g., array.length < N, amount > 0, index < limit) is NOT access control.
    If the only check is a bound check and there is no caller authorization → mark MATCH, not MITIGATED.
"""


_FOCUSED_STEP1_BLOCK = """\
STEP 1 — DOMAIN INVARIANTS:
  Based on your worldview above, list 2–3 invariants SPECIFIC to your domain.
  Read the code looking ONLY for patterns relevant to your worldview.

  Do NOT list invariants about overflow, reserve accounting, CEI, or access
  control unless they are the direct mechanism of your domain. Other specialists
  cover those — your value is finding what they miss.

  Format: INV-1: <domain-specific invariant>, INV-2: ...\
"""

_FOCUSED_OUTPUT_GATE = """\
=== OUTPUT GATE ===
You are a DOMAIN SPECIALIST. Write FINDING blocks ONLY for vulnerabilities
consistent with your worldview above. Bugs outside your domain are covered
by other specialists — ignore them completely.\
"""


def _format_cq_sequential(cq: str) -> str:
    """Split multi-part CQ '(1)...(2)...(3)...' into sequential [Q1]/[Q2]/[Q3] blocks."""
    if not cq:
        return ""
    parts = re.split(r'\s*\(\d+\)\s*', cq.strip())
    parts = [p.strip() for p in parts if p.strip()]
    if len(parts) <= 1:
        return cq.strip()
    return "\n\n".join(f"[Q{i}] {p}" for i, p in enumerate(parts, 1))


def build_round1_prompt(
    agent_profile: "ContractAgentProfile",
    context_summary: str,
    dep_graph_text: str = "",
    intent_summary: str = "",
    focus_directive: str = "",
    invariant_only: bool = False,
    injected_invariants: str = "",
    step2_hint: str = "",
    call_chain_block: str = "",
) -> str:
    """
    Round 1 — Independent Discovery.

    Rules:
    - No prior findings injected (blind discovery)
    - Unified FINDING format — no SWC: or CATEGORY: fields
    - Only FINDING format allowed — no CLAIM/VALIDATE/CHALLENGE/CONFIRM/DISMISS
    """
    dep_block = f"\n=== STATIC DATA-FLOW SUMMARY ===\n{dep_graph_text}\n" if dep_graph_text else ""
    intent_block = f"\n=== CONTRACT INTENT ===\n{intent_summary}\n" if intent_summary else ""
    chain_block = f"\n{call_chain_block}\n" if call_chain_block else ""
    focus_block = f"\n{focus_directive}\n" if focus_directive else ""
    _cq_raw = getattr(agent_profile, "core_question", "")

    if invariant_only:
        _cq_fmt = _format_cq_sequential(_cq_raw)
        cq_section = (
            f"=== YOUR EPISTEMIC LENS ===\n"
            f"Address each question fully and in sequence — complete each before moving to the next:\n\n"
            f"{_cq_fmt}\n\n"
        ) if _cq_fmt else ""
        step1_block = _FOCUSED_STEP1_BLOCK
        return f"""\
=== ROUND 1 — PHASE A: INVARIANT EXTRACTION ===
You are {agent_profile.agent_id} ({agent_profile.domain_group}/{agent_profile.persona}).
{agent_profile.system_prompt}
{focus_block}{intent_block}{dep_block}
=== CONTRACT UNDER REVIEW ===
{context_summary}
{chain_block}
{cq_section}=== TASK: INVARIANT EXTRACTION ONLY ===
{step1_block}

Output ONLY the numbered invariant list (INV-1, INV-2, ...). Do NOT write any FINDING block,
violation analysis, or commentary. Violation analysis will happen in a separate step.
"""

    if injected_invariants:
        # T2 path: use domain invariants from T1 as the scan basis
        scan_directives = (
            f"Your domain invariants from Phase A — scan for violations of THESE specifically:\n"
            f"{injected_invariants}"
        )
    elif _cq_raw:
        # Direct scan with CQ: each sub-question becomes a scan directive
        _cq_parts = re.split(r'\s*\(\d+\)\s*', _cq_raw.strip())
        _cq_parts = [p.strip() for p in _cq_parts if p.strip()]
        if len(_cq_parts) <= 1:
            scan_directives = (
                f"[Q1] {_cq_raw.strip()}\n"
                f"  → Scan the source for this specific pattern.\n"
                f"  → If a violation exists: write a FINDING block immediately."
            )
        else:
            scan_directives = "\n\n".join(
                f"[Q{i}] {q}\n"
                f"  → Scan the source for this specific pattern.\n"
                f"  → If a violation exists: write a FINDING block immediately."
                for i, q in enumerate(_cq_parts, 1)
            )
    else:
        # No CQ: worldview-driven scan
        scan_directives = (
            "Scan the source for vulnerabilities consistent with your worldview above.\n"
            "Apply your worldview directly to identify violations of the conditions\n"
            "your worldview states must hold.\n"
            "Focus on patterns your worldview specifically names — ignore patterns outside it."
        )

    hist_inv_block = _build_hist_inv_check_block(_get_agent_hist_tag(agent_profile))

    return f"""\
=== ROUND 1 — INDEPENDENT DISCOVERY ===
You are {agent_profile.agent_id} ({agent_profile.domain_group}/{agent_profile.persona}).
{agent_profile.system_prompt}

⚠ ROUND 1 FORMAT OVERRIDE — Use ONLY FINDING blocks.
  Do NOT write CLAIM, VALIDATE, CHALLENGE, CONFIRM, or DISMISS in this round.

{focus_block}{intent_block}{dep_block}
=== CONTRACT UNDER REVIEW ===
{context_summary}
{chain_block}
=== INSTRUCTIONS ===
Perform an independent security analysis. No other expert's findings are shared at this stage.

The contract source above includes ALL functions — public, external, internal, and private.
Analyze every function. Do not limit your analysis to only public/external functions.

COVERAGE RULE — if a vulnerability pattern appears in MULTIPLE functions, write one FINDING per function.
Do NOT collapse "function A and B" into a single FINDING. A missed function = a missed bug.

LOCATION RULE — before writing FUNCTION: or VIOLATED_AT: in any EVIDENCE block:
  (1) Confirm the exact function name as it appears in the contract source.
  (2) For UPDATE-ORDER bugs (accumulator must be computed BEFORE denominator changes):
      VIOLATED_AT must be the function that performs the INCORRECT UPDATE SEQUENCE
      (e.g., the function that changes liquidity/supply THEN computes the accumulator),
      NOT a downstream function that merely reads the stale result.
  (3) If you cannot find the exact function name in the source, do NOT guess — skip the FINDING.
  (4) PRIVATE/INTERNAL HELPER ATTRIBUTION — if the vulnerable line is inside a private or
      internal helper function called by the function you are analyzing
      (e.g. `_getAmountsForLiquidity`, `_updateFees`, `_computeReward`, `_settle`):
      set FUNCTION to the HELPER's name, NOT the public caller.
      Example: if mint() calls _getAmountsForLiquidity() and the bug is a typecast inside
      _getAmountsForLiquidity, write FUNCTION: _getAmountsForLiquidity — not FUNCTION: mint.

DOMAIN-FOCUSED SCAN — analyze ONLY what your worldview directs:

{scan_directives}

{hist_inv_block}

OUTPUT FORMAT — use ONLY the FINDING format below. No CLAIM, VALIDATE, CHALLENGE, CONFIRM, or DISMISS.

  FINDING: <concise title describing the vulnerability>
  CONTRACT: <exact contract name where the vulnerable function is defined>
  FUNCTION: <exact function name from contract>
  SEVERITY: <critical|high|medium|low>
  CODE_ANCHOR: <exact line from source — see rules below>
  EVIDENCE: <one-line structured evidence — choose ONE prefix below>
  ATTACK_PATH: <structured — ACTOR / CALL / STATE_CHANGE / OUTCOME, see rules below>
  DESCRIPTION: <why this is exploitable>
  PATCH: <concrete fix>

CONTRACT field is MANDATORY:
  - Write the exact contract name where the vulnerable function is defined.
  - Example: if burn() is in ConcentratedLiquidityPool.sol → CONTRACT: ConcentratedLiquidityPool
  - Do NOT write the file path or .sol extension — contract name only.
  - If the same vulnerability exists in multiple contracts, write a separate FINDING for each.

EVIDENCE field — MANDATORY. Choose ONE format:
  CODE: <exact snippet copied verbatim from source, max 120 chars>
  MISSING: <what should exist> AT: <Contract.function()>
  SEQ: <fn_a()> → <fn_b()> via <state_var> | ISSUE: <why this order is wrong>
  INV: <invariant statement> | VIOLATED_AT: <fn()> | COUNTEREXAMPLE: <condition>
  DESIGN: <mechanism abused> | EXPLOIT: <step-by-step attack> | NO_MITIGATION: <missing safeguard>

⚠ EVIDENCE GATE: every FINDING must include at least one of:
  - A real function name that exists in the contract source
  - A CODE:, MISSING:, SEQ:, INV:, or DESIGN: evidence line
  Findings without valid EVIDENCE will be dropped automatically.

CODE_ANCHOR field — MANDATORY. Copy verbatim from source. Do NOT paraphrase or write N/A.
This is the line that appears in the git diff when the bug is fixed:

  If EVIDENCE is CODE:    → the wrong line that will be changed/fixed
    e.g. totalShares += uint128(depositAmount);

  If EVIDENCE is MISSING: → the last existing line BEFORE where new code must be inserted
    e.g. uint256 shares = _convertToShares(assets);

  If EVIDENCE is SEQ:     → the line executing out of order that will be moved when fixed
    e.g. cumulativeIndex += elapsed * rewardRate;

  If EVIDENCE is INV:     → the computation line that produces the invariant-violating value
    e.g. price = reserve1 * PRECISION / reserve0;

  If EVIDENCE is DESIGN:  → the function declaration line of the exploit entry point
    e.g. function withdraw(uint256 shares, address recipient) external returns (uint256 assets) {{

Rules:
  1. Must be findable verbatim by grep in the flattened source (parser will verify)
  2. No comment lines (// or /* */), no standalone braces or keywords
  3. If bug spans multiple lines: take the FIRST line of the expression
  4. Max 150 characters

ATTACK_PATH rules — MANDATORY. All four subfields must be present:
  ACTOR: <who initiates — attacker / any caller / LP holder / contract owner>
  CALL: <exact function(s) from THIS contract, in sequence, e.g. burn() → transfer()>
  STATE_CHANGE: <which state variable becomes incorrect and how>
  OUTCOME: <measurable impact — X tokens drained / invariant Y broken / price wrong>

✓ Good:
  ACTOR: Any LP holder
  CALL: burn(liquidity) → internally credits amount0 + amount0fees to user
  STATE_CHANGE: reserve0 -= amount0fees only (amount0 subtraction missing)
  OUTCOME: reserve0 inflated → next mint() caller receives excess tokens

✗ Bad (will be dropped by parser):
  ATTACK_PATH: An attacker can exploit this vulnerability to drain funds from the contract.

{_FOCUSED_OUTPUT_GATE}

Write ALL findings you can identify within your domain. Do not stop at the first one.

⚠ OUTPUT COMMITMENT: Begin writing FINDING blocks immediately after completing your analysis.
Do NOT end your response without either FINDING blocks or the marker NO_FINDINGS_IN_DOMAIN.
If you genuinely find no vulnerability in your domain, output exactly one line: NO_FINDINGS_IN_DOMAIN
"""


def build_round2_prompt(
    agent_profile: "ContractAgentProfile",
    candidate_pairs: List[Dict[str, Any]],
) -> str:
    """
    Round 2 — Blind Voting.

    candidate_pairs: list of dicts, each has:
      - pair_id: str
      - contract_name: str
      - title: str
      - function_name: str
      - evidence_snippets: list[str]  (aggregated from Round 1 — shown for initial vote)

    Self-exclusion: pairs submitted by this agent are already removed by the orchestrator.
    """
    if not candidate_pairs:
        return (
            f"=== ROUND 2 — BLIND VOTING ===\n"
            f"Agent: {agent_profile.agent_id}\n\n"
            "No candidate pairs assigned to you in this round "
            "(all submitted pairs were your own). No action required.\n"
        )

    pair_lines: List[str] = []
    for idx, p in enumerate(candidate_pairs, start=1):
        contract = p.get("contract_name", "?")
        title_excerpt = p.get("title", "")[:60]
        fn = p.get("function_name", "?")
        label = f"FINDING [{contract}.{fn}] {title_excerpt}"
        snippets = p.get("evidence_snippets", [])
        snip_text = " | ".join(snippets[:2]) if snippets else "(no evidence provided)"
        pair_lines.append(
            f"  [{idx}] pair_id={p['pair_id']}  {label}\n"
            f"       evidence: {snip_text[:200]}"
        )

    pairs_block = "\n".join(pair_lines)

    return f"""\
=== ROUND 2 — BLIND VOTING ===
Agent: {agent_profile.agent_id} ({agent_profile.domain_group}/{agent_profile.persona})

You are a SECURITY ADVERSARY reviewing candidate findings from Round 1.
Your task: find a SPECIFIC reason to REJECT each finding.
If you CANNOT find a concrete counter-argument → you MUST ACCEPT.

The burden of proof is on REJECTION, not acceptance. When uncertain → ACCEPT.

=== CANDIDATE FINDINGS TO REVIEW ===
{pairs_block}

=== VOTING INSTRUCTIONS ===
For each finding above, write one vote block. Do NOT skip any finding.

Four valid REJECT types (COUNTER_TYPE):
  PHANTOM        — snippet or function does not exist at the claimed location in source
  ACCESS_BLOCKED — the call path requires a role/modifier the attacker cannot bypass (onlyOwner, etc.)
  NO_STATE_CHANGE — the operation is read-only / view; no state variable is mutated
  NO_IMPACT      — the described outcome is not reachable in the actual execution path

Vote format (one block per finding, in any order):
  VERDICT: ACCEPT | REJECT
  PAIR: <pair_id>
  COUNTER_TYPE: PHANTOM | ACCESS_BLOCKED | NO_STATE_CHANGE | NO_IMPACT  (REJECT only — omit if ACCEPT)
  COUNTER: <one specific code element — function name, modifier, state variable — minimum 20 chars>
           (if ACCEPT: write "No specific counter-argument found — <one sentence why>")

⚠ A vague REJECT without a valid COUNTER_TYPE ("I don't think it's valid", "Uncertain")
  will be treated as NEUTRAL and will NOT count toward rejection — it will actually
  help the finding PASS. Write a specific code reference or ACCEPT.

Example REJECT (valid):
  VERDICT: REJECT
  PAIR: pair_abc123
  COUNTER_TYPE: NO_STATE_CHANGE
  COUNTER: incentives[position.pool] is a read-only mapping access — no write to any
           storage variable exists in the call path, so funds cannot be drained.

Example ACCEPT:
  VERDICT: ACCEPT
  PAIR: pair_def456
  COUNTER: No specific counter-argument found — reserve0 subtraction in burn() does
           not account for amount0fees, confirming the inflated reserve path.

Rules:
  - You MUST write exactly one vote block per finding listed above.
  - COUNTER must reference actual code in THIS contract (modifier name, function name, variable).
  - Do NOT write FINDING blocks in this round — only VERDICT blocks.
  - Do NOT change votes based on other agents (votes are blind).

Write all vote blocks now.
"""


def build_round2_update_prompt(
    agent_profile: "ContractAgentProfile",
    revealed_evidence: List[Dict[str, Any]],
) -> str:
    """
    Round 2 — Evidence Reveal Update.

    revealed_evidence: list of dicts, each has:
      - pair_id: str
      - contract_name: str
      - title: str
      - function_name: str
      - all_evidence: list[str]  (aggregated from ALL voters, anonymized)
      - agent_vote: "ACCEPT" | "REJECT"  (this agent's initial vote)

    Agents may change their vote ONLY if new evidence reveals something they missed in the code.
    """
    if not revealed_evidence:
        return ""

    reveal_lines: List[str] = []
    for p in revealed_evidence:
        contract = p.get("contract_name", "?")
        title_excerpt = p.get("title", "")[:60]
        fn = p.get("function_name", "?")
        label = f"FINDING [{contract}.{fn}] {title_excerpt}"
        your_vote = p.get("agent_vote", "?")
        all_ev = p.get("all_evidence", [])
        ev_text = "\n       ".join(f"• {e[:180]}" for e in all_ev[:4])
        reveal_lines.append(
            f"  pair_id={p['pair_id']}  {label}  function={fn}  YOUR_VOTE={your_vote}\n"
            f"  Aggregated evidence from all reviewers:\n"
            f"       {ev_text}"
        )

    reveal_block = "\n\n".join(reveal_lines)

    return f"""\
=== ROUND 2 — EVIDENCE REVEAL (Update Phase) ===
Agent: {agent_profile.agent_id} ({agent_profile.domain_group}/{agent_profile.persona})

Below are aggregated evidence snippets collected from all reviewers (anonymized).
You may update your vote ONCE if the new evidence reveals code you had not seen.

=== REVEALED EVIDENCE ===
{reveal_block}

=== UPDATE INSTRUCTIONS ===
Write an UPDATE_VOTE block ONLY for pairs where you are changing your vote.
If you are keeping your original vote, write nothing for that pair.

CRITICAL — you may NOT change your vote solely because:
  - Many agents voted ACCEPT (bandwagon)
  - You feel uncertain
Only change if the revealed code snippet shows a concrete pattern you missed.

Update format:
  UPDATE_VOTE: ACCEPT | REJECT
  PAIR: <pair_id>
  NEW_EVIDENCE: <specific code path that changed your assessment>
  REASON: <what you missed previously>

If you are keeping ALL original votes, write:
  NO_CHANGES
"""


def build_round3_prompt(
    attacker_profile: "ContractAgentProfile",
    finding: Dict[str, Any],
    contract_source: str,
) -> str:
    """
    Round 3 — Blind Attacker Validation.

    finding: dict with keys:
      - pair_id: str
      - contract_name: str
      - title: str
      - function_name: str
      - round2_score: float

    contract_source: full flattened contract source.

    No other attacker's scenario is injected. No Round 2 evidence shown.
    """
    contract = finding.get("contract_name", "?")
    title_excerpt = finding.get("title", "")[:80]
    vuln_label = f"FINDING [{contract}] {title_excerpt}"

    fn = finding.get("function_name", "?")
    pair_id = finding.get("pair_id", "?")
    r2_score = finding.get("round2_score", 0.0)

    return f"""\
=== ROUND 3 — ATTACKER VALIDATION ===
Attacker: {attacker_profile.agent_id} ({attacker_profile.domain_group}/{attacker_profile.persona})
{attacker_profile.system_prompt}

=== TARGET FINDING ===
  pair_id      : {pair_id}
  {vuln_label}
  FUNCTION     : {fn}
  Round-2 score: {r2_score:.2f}  (0=no votes, 1=all voted ACCEPT)

=== CONTRACT SOURCE ===
{contract_source[:12000]}

=== YOUR TASK ===
Independently assess whether this vulnerability is exploitable from your attacker profile.
You have NOT seen other attackers' assessments. Approach this with adversarial creativity.

VERDICT OPTIONS:
  CONFIRMED     — you can construct a concrete, step-by-step exploit
  PLAUSIBLE     — the vulnerability exists but full exploit requires assumptions you cannot verify
  INVALID       — the vulnerability is NOT present or is protected by mitigations in the code
  NOT_APPLICABLE — this finding type is outside your attacker domain (use sparingly)

Be concise. Each ATTACK_STEPS item must be 1 sentence.

Response format:

If CONFIRMED or PLAUSIBLE:
  VERDICT: CONFIRMED | PLAUSIBLE
  ENTRY_POINT: <function or transaction sequence that starts the attack>
  PRE_CONDITION: <on-chain state required before the attack>
  ATTACK_STEPS: <numbered step-by-step sequence>
  EXPECTED_OUTCOME: <what the attacker gains / what invariant is broken>

If INVALID:
  VERDICT: INVALID
  ENTRY_POINT: <function you checked>
  REASON: <specific mitigation or code pattern that prevents the exploit>

If NOT_APPLICABLE:
  VERDICT: NOT_APPLICABLE
  REASON: <why this finding type is outside your domain>

⚠ RULES:
  - DEFAULT STANCE: INVALID. Do not confirm without a traceable exploit path.
  - CONFIRM only if you can trace the attack through THIS contract's actual code.
  - Do NOT use FINDING/SEMANTIC_FINDING/VOTE format in this round.
  - pair_id must appear exactly as shown above in your verdict.
  PAIR: {pair_id}
"""


def build_round3_update_prompt(
    attacker_profile: "ContractAgentProfile",
    finding: Dict[str, Any],
    invalid_attacker_scenarios: List[Dict[str, Any]],
) -> str:
    """
    Round 3 — Evidence Reveal Update for INVALID verdicts.

    invalid_attacker_scenarios: list of dicts from other attackers who returned INVALID,
    including their REASON. Used to see if any missed a mitigation bypass.
    This is only called for attackers who initially returned INVALID.
    """
    pair_id = finding.get("pair_id", "?")
    fn = finding.get("function_name", "?")

    reason_lines: List[str] = []
    for s in invalid_attacker_scenarios[:3]:
        reason_lines.append(f"  • {s.get('reason', '(no reason)')[:200]}")
    reasons_block = "\n".join(reason_lines) if reason_lines else "  (none)"

    return f"""\
=== ROUND 3 — EVIDENCE REVEAL (INVALID Update) ===
Attacker: {attacker_profile.agent_id}
pair_id : {pair_id}  function={fn}

Other attackers who also returned INVALID cited these reasons:
{reasons_block}

If you now believe your INVALID verdict was wrong after reading the above, you may update ONCE:

  UPDATE_VERDICT: PLAUSIBLE
  PAIR: {pair_id}
  NEW_FINDING: <specific code path or condition you had not considered>

If you are keeping your INVALID verdict, write:
  VERDICT_UNCHANGED
  PAIR: {pair_id}
"""


# ─── v2 Round Response Parsers ────────────────────────────────────────────────

def build_t3_prompt(
    agent_profile: "ContractAgentProfile",
    ann_source: str,
    focus_directive: str = "",
) -> str:
    """
    Phase C — Domain-Focused Chain-of-Thought Sweep.

    Replaces the generic _T3_COT_BLOCK with a worldview/CQ-driven CoT.
    Agent traces ONLY patterns relevant to its domain.
    """
    _cq_raw = getattr(agent_profile, "core_question", "")
    focus_block = f"\n{focus_directive}\n" if focus_directive else ""

    if _cq_raw:
        _cq_parts = re.split(r'\s*\(\d+\)\s*', _cq_raw.strip())
        _cq_parts = [p.strip() for p in _cq_parts if p.strip()]
        if len(_cq_parts) <= 1:
            trace_directives = (
                f"[Q1] {_cq_raw.strip()}\n"
                f"  → For each function: trace whether this specific condition can occur.\n"
                f"  → Write a TRACE block for every function where the answer is YES or UNCLEAR."
            )
        else:
            trace_directives = "\n\n".join(
                f"[Q{i}] {q}\n"
                f"  → For each function: trace whether this specific condition can occur.\n"
                f"  → Write a TRACE block for every function where the answer is YES or UNCLEAR."
                for i, q in enumerate(_cq_parts, 1)
            )
    else:
        trace_directives = (
            "For each function: trace whether it violates any condition stated in your worldview.\n"
            "Write a TRACE block for every function where you find a potential violation."
        )

    hist_inv_block = _build_hist_inv_check_block(_get_agent_hist_tag(agent_profile))

    return f"""\
=== ROUND 1 — PHASE C: DOMAIN-FOCUSED CoT SWEEP ===
You are {agent_profile.agent_id} ({agent_profile.domain_group}/{agent_profile.persona}).
{agent_profile.system_prompt}
{focus_block}
CONTRACT UNDER REVIEW:
{ann_source}

=== TASK ===
Perform a structured chain-of-thought reasoning sweep WITHIN YOUR DOMAIN ONLY.
Do NOT reference any prior findings — this is a fresh, independent scan.

{trace_directives}

For each suspicious operation, write a TRACE block:

TRACE [{{function_name}}]:
  OP: <the specific operation being examined>
  CHAIN: <step-by-step: what values flow in → what computation → what state changes>
  INVARIANT: <what property should hold here — based on your worldview>
  VERDICT: BUG | SAFE | UNCLEAR

After completing ALL TRACE blocks, write FINDING blocks ONLY for VERDICT=BUG
AND consistent with your domain.

FINDING: <title>
CONTRACT: <name>
FUNCTION: <name>
SEVERITY: high | medium | low
DESCRIPTION: <detailed explanation>
CODE_ANCHOR: <copy the EXACT line verbatim from the source code above — no paraphrasing>
ATTACK_PATH: <how an attacker exploits this>

IMPORTANT — FUNCTION attribution:
If the vulnerable line is inside a PRIVATE or INTERNAL helper called by the function
you are tracing (e.g. `_getAmountsForLiquidity`, `_updateFees`):
set FUNCTION to the PRIVATE HELPER's name — not the public caller.

{hist_inv_block}
{_FOCUSED_OUTPUT_GATE}
"""


def parse_round2_votes_from_text(
    text: str,
    agent_id: str,
) -> List[Dict[str, Any]]:
    """
    Parse all VERDICT blocks from a Round 2 adversarial response.

    Expected format (one block per finding):
      VERDICT: ACCEPT | REJECT
      PAIR: <pair_id>
      COUNTER_TYPE: PHANTOM | ACCESS_BLOCKED | NO_STATE_CHANGE | NO_IMPACT  (REJECT only)
      COUNTER: <text>

    Returns list of vote dicts.
    """
    results: List[Dict[str, Any]] = []
    blocks = re.split(r'(?im)^VERDICT\s*:', text)
    for block in blocks[1:]:
        lines = block.strip().splitlines()
        vote_val = lines[0].strip().upper() if lines else ""
        if vote_val not in ("ACCEPT", "REJECT"):
            continue

        pair_id = counter_type = counter = ""
        for ln in lines[1:]:
            stripped = ln.strip()
            lower = stripped.lower()
            if lower.startswith("pair:"):
                pair_id = stripped.split(":", 1)[1].strip()
            elif lower.startswith("counter_type:"):
                counter_type = stripped.split(":", 1)[1].strip().upper()
            elif lower.startswith("counter:"):
                counter = stripped.split(":", 1)[1].strip()

        if not pair_id:
            continue

        results.append({
            "agent_id":     agent_id,
            "pair_id":      pair_id,
            "vote":         vote_val,
            "counter_type": counter_type,
            "counter":      counter,
        })

    return results


def parse_round2_update_votes_from_text(
    text: str,
    agent_id: str,
) -> List[Dict[str, Any]]:
    """
    Parse UPDATE_VOTE blocks from a Round 2 update response.

    Format:
      UPDATE_VOTE: ACCEPT | REJECT
      PAIR: <pair_id>
      NEW_EVIDENCE: <text>
      REASON: <text>

    Returns list of update dicts (empty if NO_CHANGES).
    """
    if re.search(r'(?i)\bNO_CHANGES\b', text):
        return []

    results: List[Dict[str, Any]] = []
    blocks = re.split(r'(?im)^UPDATE_VOTE\s*:', text)
    for block in blocks[1:]:
        lines = block.strip().splitlines()
        vote_val = lines[0].strip().upper() if lines else ""
        if vote_val not in ("ACCEPT", "REJECT"):
            continue

        pair_id = new_evidence = reason = ""
        for ln in lines[1:]:
            stripped = ln.strip()
            lower = stripped.lower()
            if lower.startswith("pair:"):
                pair_id = stripped.split(":", 1)[1].strip()
            elif lower.startswith("new_evidence:"):
                new_evidence = stripped.split(":", 1)[1].strip()
            elif lower.startswith("reason:"):
                reason = stripped.split(":", 1)[1].strip()

        if not pair_id:
            continue

        results.append({
            "agent_id":     agent_id,
            "pair_id":      pair_id,
            "updated_vote": vote_val,
            "new_evidence": new_evidence,
            "reason":       reason,
        })

    return results


_VERDICT_VALUES = frozenset({"CONFIRMED", "PLAUSIBLE", "INVALID", "NOT_APPLICABLE"})


def parse_round3_verdict_from_text(
    text: str,
    attacker_id: str,
) -> Optional[Dict[str, Any]]:
    """
    Parse a Round 3 attacker verdict from response text.

    Accepted formats:
      VERDICT: CONFIRMED | PLAUSIBLE | INVALID | NOT_APPLICABLE
      PAIR: <pair_id>
      ENTRY_POINT: ...
      PRE_CONDITION: ...
      ATTACK_STEPS: ...
      EXPECTED_OUTCOME: ...
      REASON: ...  (for INVALID / NOT_APPLICABLE)

    Returns dict or None if no valid verdict found.
    """
    # Find the LAST VERDICT: line (ignores think-block noise)
    verdict_matches = list(re.finditer(r'(?im)^VERDICT\s*:\s*(\S+)', text))
    if not verdict_matches:
        return None

    m = verdict_matches[-1]
    verdict_raw = m.group(1).strip().upper().rstrip(".,;")
    if verdict_raw not in _VERDICT_VALUES:
        return None

    # Parse fields from the text after the matched VERDICT line
    tail = text[m.start():]

    pair_id = entry_point = pre_condition = reason = expected_outcome = ""
    attack_steps: List[str] = []
    current_field: Optional[str] = None
    current_value: List[str] = []

    _FIELD_RE_R3 = re.compile(
        r'(?i)^(VERDICT|PAIR|ENTRY_POINT|PRE_CONDITION|ATTACK_STEPS|EXPECTED_OUTCOME|REASON)\s*:',
    )

    def _flush_r3():
        nonlocal pair_id, entry_point, pre_condition, reason, expected_outcome, attack_steps
        if not current_field or not current_value:
            return
        val = " ".join(v for v in current_value if v)
        f = current_field
        if f == "pair":
            pair_id = val
        elif f == "entry_point":
            entry_point = val
        elif f == "pre_condition":
            pre_condition = val
        elif f == "reason":
            reason = val
        elif f == "expected_outcome":
            expected_outcome = val
        elif f == "attack_steps":
            attack_steps = [v for v in current_value if v]

    for line in tail.splitlines():
        stripped = line.strip()
        fm = _FIELD_RE_R3.match(stripped)
        if fm:
            _flush_r3()
            current_field = fm.group(1).lower().replace("_", "_")
            current_value = [stripped.split(":", 1)[1].strip()]
        elif current_field and stripped and not _PROTOCOL_KW_RE.match(stripped):
            current_value.append(stripped)

    _flush_r3()

    # Require pair_id for SWC/semantic findings
    if not pair_id:
        # Try to extract from anywhere in the text as fallback
        pair_match = re.search(r'(?i)PAIR\s*:\s*(\S+)', text)
        if pair_match:
            pair_id = pair_match.group(1).strip()

    return {
        "attacker_id":      attacker_id,
        "pair_id":          pair_id,
        "verdict":          verdict_raw,
        "entry_point":      entry_point,
        "pre_condition":    pre_condition,
        "attack_steps":     attack_steps,
        "expected_outcome": expected_outcome,
        "reason":           reason,
    }


def parse_round3_update_verdict_from_text(
    text: str,
    attacker_id: str,
) -> Optional[Dict[str, Any]]:
    """
    Parse Round 3 update verdict (INVALID → PLAUSIBLE change).

    Format:
      UPDATE_VERDICT: PLAUSIBLE
      PAIR: <pair_id>
      NEW_FINDING: <text>

    or:
      VERDICT_UNCHANGED
      PAIR: <pair_id>
    """
    if re.search(r'(?i)\bVERDICT_UNCHANGED\b', text):
        pair_match = re.search(r'(?i)PAIR\s*:\s*(\S+)', text)
        return {
            "attacker_id": attacker_id,
            "pair_id":     pair_match.group(1).strip() if pair_match else "",
            "updated_verdict": None,  # no change
            "new_finding": "",
        }

    m = re.search(r'(?im)^UPDATE_VERDICT\s*:\s*(\S+)', text)
    if not m:
        return None

    verdict_raw = m.group(1).strip().upper()
    if verdict_raw not in _VERDICT_VALUES:
        return None

    pair_id = new_finding = ""
    for ln in text[m.start():].splitlines()[1:]:
        stripped = ln.strip()
        lower = stripped.lower()
        if lower.startswith("pair:"):
            pair_id = stripped.split(":", 1)[1].strip()
        elif lower.startswith("new_finding:"):
            new_finding = stripped.split(":", 1)[1].strip()

    return {
        "attacker_id":      attacker_id,
        "pair_id":          pair_id,
        "updated_verdict":  verdict_raw,
        "new_finding":      new_finding,
    }


def build_accounting_verifier_prompt(fn_contexts: str) -> str:
    return (
        "=== ACCOUNTING INVARIANT VERIFICATION ===\n"
        "You are a specialized accounting invariant checker.\n\n"
        "Your ONLY task: for each function below, answer:\n"
        "  1. Does this function transfer tokens or ETH OUTWARD (to an external address)?\n"
        "  2. If YES: is there a storage variable that tracks how much the contract owes\n"
        "     (balance, unclaimed, rewardsUnclaimed, shares, debt, etc.)?\n"
        "  3. If YES to both: is that variable DECREMENTED after the transfer?\n\n"
        "If a function transfers tokens outward WITHOUT decrementing a corresponding\n"
        "internal accounting variable → write a FINDING.\n\n"
        "FINDING format:\n"
        "  TITLE: Missing accounting update in <function_name>\n"
        "  FUNCTION: <function_name>\n"
        "  CONTRACT: <contract_name>\n"
        "  SEVERITY: HIGH\n"
        "  EVIDENCE: MISSING: <variable> -= amount; AT: <function_name>()\n"
        "  ATTACK_PATH:\n"
        "    ACTOR: any authorized caller\n"
        "    CALL: <function_name>() repeatedly\n"
        "    STATE_CHANGE: <variable> never decremented\n"
        "    OUTCOME: caller drains contract by calling repeatedly\n\n"
        "Only write FINDING if you are certain. If uncertain, write NO_FINDING with reason.\n\n"
        "=== FUNCTIONS TO CHECK ===\n"
        f"{fn_contexts}"
    )
