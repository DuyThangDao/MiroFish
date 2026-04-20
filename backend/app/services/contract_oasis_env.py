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
            "In this phase, ATTACKER PROFILES are activated. "
            "Domain expert agents: respond if an attacker challenges or escalates your finding. "
            "Attacker agents: read ALL findings and validate or dismiss them from an attacker's perspective. "
            "Add attack paths that domain experts missed."
            # Note: GAP format NOT required for attacker agents — they use ATTACKER_* format
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

    # Confidence deltas when parsing from post text
    CONFIDENCE_DELTA = {
        CONFIRM:   +0.15,
        DISMISS:   -0.20,
        ADD_PATH:   0.00,   # handled separately as new finding
        ESCALATE:  +0.10,
        DOWNGRADE: -0.10,
    }

    ALL = {CONFIRM, DISMISS, ADD_PATH, ESCALATE, DOWNGRADE}

    @staticmethod
    def parse_from_text(text: str) -> Optional[Dict[str, Any]]:
        """
        Parse attacker action from agent post.

        Expected format:
          [ATTACKER_CONFIRM]
          Finding: <exact finding title>
          Reason: <why exploitable>
          Path: <attack steps>

        Returns dict or None if no action found.
        """
        for action_type in ContractAttackerAction.ALL:
            if f"[{action_type}]" in text:
                lines = text.split("\n")
                finding_ref = ""
                reason = ""
                path = ""
                exploit_path = ""
                for line in lines:
                    line = line.strip()
                    if line.lower().startswith("finding:"):
                        finding_ref = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("reason:"):
                        reason = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("path:"):
                        path = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("exploit:") or line.lower().startswith("exploit path:"):
                        exploit_path = line.split(":", 1)[1].strip()

                return {
                    "action_type":      action_type,
                    "finding_ref":      finding_ref,
                    "reason":           reason,
                    "path":             path or exploit_path,
                    "confidence_delta": ContractAttackerAction.CONFIDENCE_DELTA.get(action_type, 0.0),
                }
        return None


# ─── Contract Finding Parser ──────────────────────────────────────────────────

def parse_contract_finding_from_text(
    text: str,
    agent_profile: ContractAgentProfile,
    round_num: int,
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
            # Extract first SWC-XXX or DeFi pattern key
            m = re.search(r'(SWC-\d+|[A-Z_]{5,})', raw)
            swc_id = m.group(1) if m else raw.split()[0] if raw else ""
            # Try to get SWC name from the rest
            if m and raw != swc_id:
                after = raw[m.end():].strip(" -—:")
                swc_name = after.split(".")[0].strip() if after else ""
        elif lower.startswith("severity:"):
            sev_raw = stripped.split(":", 1)[1].strip().lower()
            if sev_raw in {"critical", "high", "medium", "low", "info"}:
                severity = sev_raw
        elif lower.startswith("function:"):
            func_raw = stripped.split(":", 1)[1].strip()
            affected_functions = [
                f.strip().rstrip("()").strip() + "()"
                for f in func_raw.replace(",", " ").split()
                if f.strip()
            ]
        elif lower.startswith("evidence:"):
            evidence_raw = stripped.split(":", 1)[1].strip()
            evidence = [evidence_raw] if evidence_raw else []
        elif lower.startswith("description:"):
            current_field = "description"
            current_value = [stripped.split(":", 1)[1].strip()]
        elif lower.startswith("patch:"):
            current_field = "patch"
            current_value = [stripped.split(":", 1)[1].strip()]
        elif current_field and line.startswith("  ") or (
            current_field and stripped and not re.match(
                r'(?i)^(ANALYZED|GAP|FINDING|SWC|SEVERITY|FUNCTION|EVIDENCE|DESCRIPTION|PATCH)\s*:',
                stripped
            )
        ):
            if stripped:
                current_value.append(stripped)

    _flush_field()

    if not title:
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
    ) -> str:
        """Build system instruction injected at the start of each round."""
        phase_cfg = PHASE_CONFIG.get(phase, {})
        instruction = (
            f"=== Phase {phase}: {phase_cfg.get('name', '')} | Round {round_num}/{TOTAL_ROUNDS} ===\n"
            f"{phase_cfg.get('instruction_addition', '')}"
        )
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

Start the audit. Report your first findings based on the contract context above.
"""
