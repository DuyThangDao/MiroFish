"""
Cyber OASIS Environment — Multi-Expert Panel (Direction B)

Định nghĩa cấu hình OASIS cho Security Review Room.
3-phase session: A (intra-group) → B (cross-group) → C (attacker challenge)

Phase A (rounds 1–3):  Domain experts thảo luận nội bộ group, attacker agents im lặng
Phase B (rounds 4–7):  Domain experts challenge nhau cross-group, attacker agents im lặng
Phase C (rounds 8–10): Attacker profiles phát biểu — confirm/dismiss/add/escalate findings
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from .cyber_expert_profile_generator import CyberAgentProfile

logger = get_logger("mirofish.cyber_oasis_env")


# ─── Phase definitions ────────────────────────────────────────────────────────

PHASE_CONFIG = {
    "A": {
        "name": "Intra-group Analysis",
        "rounds": [1, 2, 3],
        "description": "Domain experts thảo luận trong nội bộ group của mình",
        "attacker_active": False,
        "instruction_addition": (
            "Trong phase này, bạn thảo luận CHỦ YẾU với các chuyên gia cùng domain. "
            "Tập trung vào domain expertise của bạn. "
            "Đề xuất findings và validate với peer trong cùng nhóm."
        ),
    },
    "B": {
        "name": "Cross-group Challenge",
        "rounds": [4, 5, 6, 7],
        "description": "Domain experts challenge findings của nhau cross-group",
        "attacker_active": False,
        "instruction_addition": (
            "Trong phase này, bạn ĐỌC và CHALLENGE findings từ các domain group khác. "
            "Đặt câu hỏi: finding này có đúng không? Severity có bị overestimate không? "
            "Có missing context từ góc độ của bạn không? "
            "Cũng bổ sung finding mới nếu bạn thấy domain group khác bỏ sót."
        ),
    },
    "C": {
        "name": "Attacker Challenge",
        "rounds": [8, 9, 10],
        "description": "Attacker profiles đọc toàn bộ findings và phản biện",
        "attacker_active": True,
        "instruction_addition": (
            "Trong phase này, CÁC ATTACKER PROFILES được kích hoạt. "
            "Domain expert agents: hãy phản hồi nếu attacker challenge finding của bạn. "
            "Attacker agents: đọc toàn bộ findings và phản biện từ góc nhìn của kẻ tấn công."
        ),
    },
}

TOTAL_ROUNDS = 10


def get_phase_for_round(round_num: int) -> str:
    """Trả về phase letter (A/B/C) cho round number."""
    if round_num <= 3:
        return "A"
    elif round_num <= 7:
        return "B"
    else:
        return "C"


# ─── Attacker Action Types ────────────────────────────────────────────────────

class AttackerAction:
    """Các action type dành riêng cho attacker profile agents trong Phase C."""

    CONFIRM   = "ATTACKER_CONFIRM"    # Confirm finding → +0.15 confidence
    DISMISS   = "ATTACKER_DISMISS"    # Dismiss finding → -0.20 confidence
    ADD_PATH  = "ATTACKER_ADD_PATH"   # New finding → base confidence 0.60
    ESCALATE  = "ATTACKER_ESCALATE"   # Upgrade severity (cần ≥2 profiles đồng ý)
    DOWNGRADE = "ATTACKER_DOWNGRADE"  # Downgrade severity (cần ≥3 profiles đồng ý)

    # Confidence delta khi parse action từ OASIS post content
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
        Parse attacker action từ OASIS post text.

        Expected format in text:
          [ATTACKER_CONFIRM]
          Finding: <title>
          Reason: <reason>
          Path: <optional attack path>

        Returns dict với keys: action_type, finding_ref, reason, path
        Returns None nếu không parse được.
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
    Parse expert finding từ OASIS post text.

    Expected format:
      [FINDING] Title
      Severity: critical|high|medium|low
      Affected: host/service
      Evidence: reason from infrastructure
      Detail: detailed description
      Recommendation: action

    Returns raw dict hoặc None nếu không có finding.
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
        elif stripped.lower().startswith("recommendation:"):
            rec_raw = stripped.split(":", 1)[1].strip()
            recommendation = [rec_raw] if rec_raw else []

    if not title:
        return None

    return {
        "author_group": agent_profile.domain_group,
        "author_persona": agent_profile.persona,
        "title": title,
        "severity": severity,
        "affected_assets": affected,
        "evidence": evidence,
        "description": detail or title,
        "recommendations": recommendation,
        "phase": phase,
        "round_number": round_num,
    }


# ─── OASIS Config Builder ─────────────────────────────────────────────────────

@dataclass
class CyberOasisConfig:
    """
    Configuration cho OASIS Security Review Room session.
    Tương đương với SimulationConfig của MiroFish gốc.
    """
    session_id: str
    graph_id: str
    platform: str = "reddit"           # reddit cho threaded discussion
    environment_name: str = "security_review_room"
    total_rounds: int = TOTAL_ROUNDS
    agents: List[Dict[str, Any]] = field(default_factory=list)
    initial_post: str = ""             # seeding post để khởi động thảo luận
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
    Xây dựng OASIS environment config cho Multi-Expert Panel.
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
        Build full OASIS config từ agent profiles.

        Args:
            session_id: unique session identifier
            graph_id: Zep graph ID (inject vào initial post)
            profiles: danh sách 18 CyberAgentProfile
            network_summary: mô tả hạ tầng để làm seeding post
            platform: "reddit" (recommended) hoặc "twitter"

        Returns:
            CyberOasisConfig sẵn sàng để pass vào session orchestrator
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
        Trả về danh sách agent được phép nói trong phase này.

        Phase A, B: chỉ Tier 1 (domain experts)
        Phase C:    tất cả (Tier 1 + Tier 2 attacker profiles)
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
        """Trả về agents trong cùng domain group (dùng cho Phase A focus)."""
        return [p for p in profiles if p.domain_group == domain_group]

    def build_phase_instruction(self, phase: str, round_num: int) -> str:
        """System instruction inject vào đầu mỗi round."""
        phase_cfg = PHASE_CONFIG.get(phase, {})
        return (
            f"=== Phase {phase}: {phase_cfg.get('name', '')} | Round {round_num}/{TOTAL_ROUNDS} ===\n"
            f"{phase_cfg.get('instruction_addition', '')}"
        )

    # ─── Private ──────────────────────────────────────────────────────────────

    def _build_initial_post(self, network_summary: str, graph_id: str) -> str:
        """
        Initial seeding post để khởi động thảo luận trong OASIS.
        Đây là post đầu tiên mà tất cả agent sẽ đọc.
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

Use format:
[FINDING] Title
Severity: critical|high|medium|low
Affected: host/service name
Evidence: specific evidence from infrastructure
Detail: detailed explanation
Recommendation: concrete action

Start with your domain's perspective. Be specific — reference actual hosts, CVEs, and services."""
