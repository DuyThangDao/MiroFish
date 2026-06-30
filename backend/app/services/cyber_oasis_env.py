"""
Cyber OASIS Environment — Multi-Expert Panel (Direction B)

Defines the OASIS configuration for the Security Review Room.
3-phase session: A (intra-group) → B (cross-group) → C (attacker challenge)

Phase A (rounds 1–3):  Domain experts discuss within their group; attacker agents are silent
Phase B (rounds 4–7):  Domain experts challenge each other cross-group; attacker agents are silent
Phase C (rounds 8–10): Attacker profiles speak — confirm/dismiss/add/escalate findings
"""

import re
import uuid
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from .cyber_expert_profile_generator import CyberAgentProfile

logger = get_logger("mirofish.cyber_oasis_env")


# ─── GAP Output Format ────────────────────────────────────────────────────────

# Appended to Phase A and B instructions — agents must follow this format
GAP_FORMAT_INSTRUCTION = """
REQUIRED — end every post with one or more GAP declarations:
ANALYZED: <host name or control, e.g. FW-01 or SIEM>
GAP: <what you cannot verify and why, OR "None — fully assessed">

Example:
ANALYZED: SIEM
GAP: Cannot evaluate alerting rules — no SIEM deployed.
ANALYZED: FW-01
GAP: Cannot assess admin interface — no management access details provided.
"""

# ─── Phase definitions ────────────────────────────────────────────────────────

PHASE_CONFIG = {
    "A": {
        "name": "Intra-group Analysis",
        "rounds": [1, 2, 3],
        "description": "Domain experts discuss within their own group",
        "attacker_active": False,
        "instruction_addition": (
            "In this phase, discuss PRIMARILY with experts in your own domain. "
            "Focus on your domain expertise. "
            "Propose findings and validate them with peers in your group.\n"
            + GAP_FORMAT_INSTRUCTION
        ),
    },
    "B": {
        "name": "Cross-group Challenge",
        "rounds": [4, 5, 6, 7],
        "description": "Domain experts challenge each other's findings across groups",
        "attacker_active": False,
        "instruction_addition": (
            "In this phase, READ and CHALLENGE findings from other domain groups. "
            "Ask: is this finding accurate? Is the severity overestimated? "
            "Is there missing context from your perspective? "
            "Also add new findings if you notice another domain group has missed something.\n"
            + GAP_FORMAT_INSTRUCTION
        ),
    },
    "C": {
        "name": "Attacker Challenge",
        "rounds": [8, 9, 10],
        "description": "Attacker profiles read all findings and provide real-world challenge",
        "attacker_active": True,
        "instruction_addition": (
            "In this phase, ATTACKER PROFILES are activated. "
            "Domain expert agents: respond if an attacker challenges your finding. "
            "Attacker agents: read all findings and challenge them from an attacker's perspective."
            # Note: GAP format NOT required for attacker agents — they use ATTACKER_* action format
        ),
    },
}

TOTAL_ROUNDS = 10


# ─── GAP Routing Table ────────────────────────────────────────────────────────

# Maps keywords in GAP text → domain groups best positioned to investigate
GAP_ROUTING_TABLE: Dict[str, List[str]] = {
    "siem":           ["threat_intel", "risk"],
    "log":            ["threat_intel", "network_security"],
    "alert":          ["threat_intel", "network_security"],
    "mfa":            ["risk", "appsec"],
    "multi-factor":   ["risk", "appsec"],
    "dlp":            ["risk", "endpoint_security"],
    "data loss":      ["risk", "endpoint_security"],
    "waf":            ["appsec", "network_security"],
    "web application firewall": ["appsec"],
    "backup":         ["endpoint_security", "risk"],
    "fw-01":          ["network_security", "risk"],
    "pfsense":        ["network_security"],
    "firewall rule":  ["network_security"],
    "management access": ["network_security", "risk"],
    "mail-01":        ["network_security", "appsec"],
    "postfix":        ["network_security", "appsec"],
    "smtp":           ["network_security", "appsec"],
    "patch":          ["endpoint_security"],
    "privilege":      ["endpoint_security", "risk"],
    "admin":          ["endpoint_security", "risk"],
    "authentication": ["appsec", "risk"],
    "authorization":  ["appsec"],
    "compliance":     ["risk"],
    "regulation":     ["risk"],
    "network segment": ["network_security"],
    "vlan":           ["network_security"],
    "trust":          ["network_security", "risk"],
}


def route_gap(gap_text: str) -> List[str]:
    """
    Determine which domain groups should investigate a GAP declaration.
    Returns list of domain group names. Falls back to all groups if no keyword matches.
    """
    gap_lower = gap_text.lower()
    matched: List[str] = []
    for keyword, groups in GAP_ROUTING_TABLE.items():
        if keyword in gap_lower:
            for g in groups:
                if g not in matched:
                    matched.append(g)
    # If no keyword matched, broadcast to all groups
    return matched or ["network_security", "appsec", "endpoint_security", "threat_intel", "risk"]


def parse_gap_declarations(
    text: str,
    author_group: str,
    author_persona: str,
    round_num: int,
) -> List[Dict[str, Any]]:
    """
    Parse ANALYZED + GAP declaration blocks from an agent post.

    Expected format (one or more per post):
      ANALYZED: <host or control>
      GAP: <description>

    Returns list of GapDeclaration-compatible dicts.
    Skips declarations where gap_text is empty or explicitly "none".
    """
    gaps = []
    # Split on ANALYZED: to find each declaration block
    blocks = re.split(r'(?i)\bANALYZED\s*:', text)
    for block in blocks[1:]:  # skip text before first ANALYZED:
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
                # Continuation lines (indented or starts with e.g.)
                if stripped.startswith("e.g.") or (line.startswith("  ") and stripped):
                    gap_text += " " + stripped
                else:
                    break  # Next field or block

        # Skip trivial / null gaps
        if not gap_text:
            continue
        gap_lower = gap_text.lower().strip(" .")
        if gap_lower in ("none", "none identified", "none — fully assessed within domain scope",
                         "n/a", "not applicable", "fully assessed"):
            continue

        gaps.append({
            "gap_id":        f"gap_{uuid.uuid4().hex[:8]}",
            "author_group":  author_group,
            "author_persona": author_persona,
            "analyzed":      analyzed,
            "gap_text":      gap_text,
            "round_number":  round_num,
            "routed":        False,
            "routed_to":     route_gap(gap_text),
        })

    return gaps


def build_gap_context_for_agent(
    pending_gaps: List[Dict[str, Any]],
    agent_domain_group: str,
) -> str:
    """
    Filter pending GAP declarations relevant to this agent's domain group
    and format as injection text for the next round's prompt.

    Returns empty string if no relevant gaps.
    """
    relevant = [
        g for g in pending_gaps
        if agent_domain_group in g.get("routed_to", [])
    ]
    if not relevant:
        return ""

    lines = [
        "=== UNRESOLVED GAPS — Previous rounds identified areas needing YOUR domain expertise ===",
        "These gaps were declared by other experts who could not verify these areas.",
        "Please investigate and generate a [FINDING] or [NO_FINDING] for each:",
    ]
    for g in relevant:
        lines.append(
            f"\n  [GAP from {g['author_group']}/{g['author_persona']}, Round {g['round_number']}]"
            f"\n  Area: {g['analyzed']}"
            f"\n  Why unresolved: {g['gap_text']}"
        )
    lines.append("")
    return "\n".join(lines)


def build_published_registry(
    expert_findings: List[Dict[str, Any]],
    max_entries: int = 20,
) -> str:
    """
    Published Registry — inject into agent context so agents know what has
    already been reported and avoid duplicating.

    Shows unique finding titles grouped by domain, capped at max_entries to
    prevent context overflow. Agents are instructed to CHALLENGE or EXPAND
    existing findings rather than re-report them.

    Returns empty string if no findings yet (round 1).
    """
    if not expert_findings:
        return ""

    # Deduplicate by title (case-insensitive) keeping first occurrence
    seen: set = set()
    unique: List[Dict[str, Any]] = []
    for f in expert_findings:
        key = f.get("title", "").lower().strip()
        if key and key not in seen:
            seen.add(key)
            unique.append(f)

    # Cap to avoid context overflow — take most recent unique findings
    capped = unique[-max_entries:] if len(unique) > max_entries else unique

    lines = [
        f"=== PUBLISHED FINDINGS REGISTRY ({len(unique)} unique findings reported so far) ===",
        "Do NOT duplicate these. If you agree → CHALLENGE or add evidence.",
        "If you have new information → write a NEW [FINDING] with distinct title.",
    ]
    for f in capped:
        reporters = f"{f.get('author_group','?')}/{f.get('author_persona','?')}"
        lines.append(f"  • [{f.get('severity','?').upper()}] {f.get('title','?')} — by {reporters}")

    return "\n".join(lines)


def get_phase_for_round(round_num: int) -> str:
    """Return the phase letter (A/B/C) for a given round number."""
    if round_num <= 3:
        return "A"
    elif round_num <= 7:
        return "B"
    else:
        return "C"


# ─── Attacker Action Types ────────────────────────────────────────────────────

class AttackerAction:
    """Action types reserved for attacker profile agents in Phase C."""

    CONFIRM   = "ATTACKER_CONFIRM"    # Confirm finding → +0.15 confidence
    DISMISS   = "ATTACKER_DISMISS"    # Dismiss finding → -0.20 confidence
    ADD_PATH  = "ATTACKER_ADD_PATH"   # New finding → base confidence 0.60
    ESCALATE  = "ATTACKER_ESCALATE"   # Upgrade severity (requires ≥2 profiles to agree)
    DOWNGRADE = "ATTACKER_DOWNGRADE"  # Downgrade severity (requires ≥3 profiles to agree)

    # Confidence delta when parsing an action from OASIS post content
    CONFIDENCE_DELTA = {
        CONFIRM:   +0.15,
        DISMISS:   -0.20,
        ADD_PATH:   0.00,  # handled separately
        ESCALATE:  +0.10,
        DOWNGRADE: -0.10,
    }

    ALL = {CONFIRM, DISMISS, ADD_PATH, ESCALATE, DOWNGRADE}

    @staticmethod
    def parse_from_text(text: str) -> Optional[Dict[str, Any]]:
        """
        Parse an attacker action from OASIS post text.

        Expected format in text:
          [ATTACKER_CONFIRM]
          Finding: <title>
          Reason: <reason>
          Path: <optional attack path>

        Returns a dict with keys: action_type, finding_ref, reason, path.
        Returns None if parsing fails.
        """
        for action_type in AttackerAction.ALL:
            if f"[{action_type}]" in text:
                lines = text.split("\n")
                finding_ref = ""
                reason = ""
                path = ""
                for line in lines:
                    line = line.strip()
                    if line.lower().startswith("finding:"):
                        finding_ref = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("reason:"):
                        reason = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("path:"):
                        path = line.split(":", 1)[1].strip()
                return {
                    "action_type": action_type,
                    "finding_ref": finding_ref,
                    "reason": reason,
                    "path": path,
                    "confidence_delta": AttackerAction.CONFIDENCE_DELTA.get(action_type, 0.0),
                }
        return None


# ─── Expert Finding Parser ────────────────────────────────────────────────────

def parse_expert_finding_from_text(
    text: str,
    agent_profile: CyberAgentProfile,
    round_num: int,
) -> Optional[Dict[str, Any]]:
    """
    Parse an expert finding from OASIS post text.

    Expected format:
      [FINDING] Title
      Severity: critical|high|medium|low
      Affected: host/service
      Evidence: reason from infrastructure
      Detail: detailed description
      Recommendation: action

    Returns a raw dict, or None if no finding is present.
    """
    if "[FINDING]" not in text:
        return None

    lines = text.split("\n")
    title = ""
    severity = "medium"
    affected = []
    evidence = []
    detail = ""
    recommendation = []
    mitre_techniques = []
    phase = get_phase_for_round(round_num)

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[FINDING]"):
            title = stripped.replace("[FINDING]", "").strip()
        elif stripped.lower().startswith("severity:"):
            sev_raw = stripped.split(":", 1)[1].strip().lower()
            if sev_raw in {"critical", "high", "medium", "low", "info"}:
                severity = sev_raw
        elif stripped.lower().startswith("affected:"):
            affected_raw = stripped.split(":", 1)[1].strip()
            affected = [a.strip() for a in affected_raw.split(",") if a.strip()]
        elif stripped.lower().startswith("evidence:"):
            evidence_raw = stripped.split(":", 1)[1].strip()
            evidence = [evidence_raw] if evidence_raw else []
        elif stripped.lower().startswith("detail:"):
            detail = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("mitre:"):
            mitre_raw = stripped.split(":", 1)[1].strip()
            mitre_techniques = re.findall(r'T\d{4}(?:\.\d{3})?', mitre_raw)
        elif stripped.lower().startswith("recommendation:") or stripped.lower().startswith("recommend:"):
            rec_raw = stripped.split(":", 1)[1].strip()
            recommendation = [rec_raw] if rec_raw else []

    if not title:
        return None

    # Fallback: if no MITRE: field found, scan full finding text for inline T-numbers
    if not mitre_techniques:
        mitre_techniques = list(dict.fromkeys(re.findall(r'\bT\d{4}(?:\.\d{3})?\b', text)))

    return {
        "author_group": agent_profile.domain_group,
        "author_persona": agent_profile.persona,
        "title": title,
        "severity": severity,
        "affected_assets": affected,
        "evidence": evidence,
        "description": detail or title,
        "recommendations": recommendation,
        "mitre_techniques": mitre_techniques,
        "phase": phase,
        "round_number": round_num,
    }


# ─── OASIS Config Builder ─────────────────────────────────────────────────────

@dataclass
class CyberOasisConfig:
    """
    Configuration for an OASIS Security Review Room session.
    Equivalent to SimulationConfig from the original MiroFish.
    """
    session_id: str
    graph_id: str
    platform: str = "reddit"           # reddit for threaded discussion
    environment_name: str = "security_review_room"
    total_rounds: int = TOTAL_ROUNDS
    agents: List[Dict[str, Any]] = field(default_factory=list)
    initial_post: str = ""             # seeding post to start the discussion
    phase_config: Dict[str, Any] = field(default_factory=lambda: PHASE_CONFIG)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "graph_id": self.graph_id,
            "platform": self.platform,
            "environment_name": self.environment_name,
            "total_rounds": self.total_rounds,
            "agent_count": len(self.agents),
            "phase_config": self.phase_config,
            "has_initial_post": bool(self.initial_post),
        }


class CyberOasisEnvBuilder:
    """
    Build OASIS environment config for the Multi-Expert Panel.
    """

    def build_config(
        self,
        session_id: str,
        graph_id: str,
        profiles: List[CyberAgentProfile],
        network_summary: str,
        platform: str = "reddit",
    ) -> CyberOasisConfig:
        """
        Build a full OASIS config from agent profiles.

        Args:
            session_id: unique session identifier
            graph_id: Zep graph ID (injected into the initial post)
            profiles: list of 18 CyberAgentProfile instances
            network_summary: infrastructure description used as the seeding post
            platform: "reddit" (recommended) or "twitter"

        Returns:
            CyberOasisConfig ready to pass to the session orchestrator
        """
        agents = [p.to_oasis_format() for p in profiles]
        initial_post = self._build_initial_post(network_summary, graph_id)

        return CyberOasisConfig(
            session_id=session_id,
            graph_id=graph_id,
            platform=platform,
            agents=agents,
            initial_post=initial_post,
        )

    def get_active_agents_for_phase(
        self,
        profiles: List[CyberAgentProfile],
        phase: str,
    ) -> List[CyberAgentProfile]:
        """
        Return the list of agents allowed to speak in the given phase.

        Phase A, B: Tier 1 only (domain experts)
        Phase C:    all agents (Tier 1 + Tier 2 attacker profiles)
        """
        phase_cfg = PHASE_CONFIG.get(phase, {})
        attacker_active = phase_cfg.get("attacker_active", False)

        if attacker_active:
            return profiles  # All 18
        else:
            return [p for p in profiles if p.tier == 1]  # Only 13 Tier-1

    def get_intra_group_agents(
        self,
        profiles: List[CyberAgentProfile],
        domain_group: str,
    ) -> List[CyberAgentProfile]:
        """Return agents in the same domain group (used for Phase A focus)."""
        return [p for p in profiles if p.domain_group == domain_group]

    def build_phase_instruction(
        self,
        phase: str,
        round_num: int,
        gap_context: str = "",
        **kwargs,  # absorb contract_audit-specific params (phase_c_review_list)
    ) -> str:
        """
        Build system instruction injected at the start of each round.

        Args:
            phase: "A" | "B" | "C"
            round_num: current round number
            gap_context: formatted GAP declarations routed to this specific agent
                         (empty string = no relevant gaps for this agent)
        """
        phase_cfg = PHASE_CONFIG.get(phase, {})
        instruction = (
            f"=== Phase {phase}: {phase_cfg.get('name', '')} | Round {round_num}/{TOTAL_ROUNDS} ===\n"
            f"{phase_cfg.get('instruction_addition', '')}"
        )
        if gap_context:
            instruction = gap_context + "\n" + instruction
        return instruction

    # ─── Private ──────────────────────────────────────────────────────────────

    def _build_initial_post(self, network_summary: str, graph_id: str) -> str:
        """
        Initial seeding post to start the OASIS discussion.
        This is the first post that all agents will read.
        """
        return f"""SECURITY REVIEW SESSION — Please analyze the following infrastructure.

=== INFRASTRUCTURE SUMMARY ===
{network_summary}

Knowledge Graph: {graph_id}

=== SESSION STRUCTURE ===
Phase A (Rounds 1-3):  Intra-group analysis — discuss within your domain group
Phase B (Rounds 4-7):  Cross-group challenge — challenge findings from other groups
Phase C (Rounds 8-10): Attacker perspective — attacker profiles provide real-world validation

=== YOUR TASK ===
1. Identify vulnerabilities, misconfigurations, and attack paths
2. Support claims with specific evidence from the infrastructure
3. Prioritize findings by severity and exploitability
4. Provide actionable recommendations

=== FINDING FORMAT (Phases A and B) ===
[FINDING] Title
Severity: critical|high|medium|low
Affected: host/service name
Evidence: specific evidence from infrastructure
MITRE: T#### (at least one ATT&CK technique ID)
Detail: detailed explanation
Recommendation: concrete action

[NO_FINDING] <area analyzed> — <brief reason it appears secure or out of scope>

=== GAP DECLARATION FORMAT (mandatory in Phases A and B) ===
After every post, declare what you could NOT verify:

ANALYZED: <host name or control category>
GAP: <what you could not assess and why>

Example:
  ANALYZED: FW-01
  GAP: Cannot assess pfSense admin interface exposure — no information about management network access in the description.

  ANALYZED: SIEM
  GAP: Cannot evaluate detection coverage — no SIEM is deployed.

GAP declarations route unresolved areas to the domain group best positioned to investigate.
If fully assessed: write "GAP: None — fully assessed."

Start with your domain's perspective. Be specific — reference actual hosts, CVEs, and services."""
