"""
Security data models cho Multi-Expert Panel (Direction B)
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ZoneType(str, Enum):
    DMZ        = "DMZ"
    INTERNAL   = "Internal"
    DATABASE   = "Database"
    MANAGEMENT = "Management"
    CLOUD      = "Cloud"
    EXTERNAL   = "External"


class PatchStatus(str, Enum):
    PATCHED           = "patched"
    UNPATCHED         = "unpatched"
    PARTIALLY_PATCHED = "partially_patched"
    UNKNOWN           = "unknown"


@dataclass
class SecurityControls:
    """Công cụ bảo mật đang triển khai trên một host."""
    edr:  bool = False   # Endpoint Detection & Response
    siem: bool = False   # Security Information & Event Management
    av:   bool = False   # Antivirus
    ndr:  bool = False   # Network Detection & Response
    waf:  bool = False   # Web Application Firewall
    mfa:  bool = False   # Multi-Factor Authentication
    dlp:  bool = False   # Data Loss Prevention

    def active_tools(self) -> List[str]:
        return [k for k, v in asdict(self).items() if v]

    def coverage_score(self) -> float:
        """Tỉ lệ tool được bật (0.0 – 1.0)."""
        all_fields = list(asdict(self).values())
        return sum(all_fields) / len(all_fields) if all_fields else 0.0


@dataclass
class NetworkAsset:
    """Một host/asset trong hạ tầng mạng."""
    host_id:         str                  # "WEB-01"
    hostname:        str                  # "web-server-01"
    ip:              str                  # "10.0.1.10"
    zone:            str                  # ZoneType value
    os:              str                  # "Ubuntu 22.04"
    services:        List[str]            # ["Apache 2.4.49", "OpenSSH 8.9"]
    vulnerabilities: List[str]            # ["CVE-2021-41773"]
    patch_status:    str = PatchStatus.UNKNOWN.value
    is_critical:     bool = False         # DC, DB server, firewall...
    controls:        SecurityControls = field(default_factory=SecurityControls)
    notes:           str = ""

    def to_zep_text(self) -> str:
        """Chuyển thành text để lưu vào Zep episode."""
        lines = [
            f"Host: {self.hostname} ({self.host_id})",
            f"IP: {self.ip}, Zone: {self.zone}, OS: {self.os}",
            f"Services: {', '.join(self.services) if self.services else 'none'}",
            f"CVEs: {', '.join(self.vulnerabilities) if self.vulnerabilities else 'none'}",
            f"Patch status: {self.patch_status}",
            f"Critical asset: {self.is_critical}",
            f"Security controls active: {', '.join(self.controls.active_tools()) or 'none'}",
        ]
        if self.notes:
            lines.append(f"Notes: {self.notes}")
        return "\n".join(lines)


# ─── Expert Findings ──────────────────────────────────────────────────────────

@dataclass
class AttackerCorroboration:
    """Phản hồi của 1 attacker profile về 1 finding."""
    profile_id:  str    # "opportunistic" | "apt" | "insider_threat" | "ransomware" | "supply_chain"
    action:      str    # "ATTACKER_CONFIRM" | "ATTACKER_DISMISS" | "ATTACKER_ESCALATE" | "ATTACKER_DOWNGRADE"
    comment:     str
    confidence_delta: float  # +0.15 for CONFIRM, -0.20 for DISMISS


@dataclass
class ExpertFinding:
    """Finding từ 1 expert agent trong Phase A hoặc B."""
    finding_id:          str
    author_group:        str          # "network_security" | "appsec" | "endpoint_security" | "threat_intel" | "risk"
    author_persona:      str          # "offensive" | "defensive" | "auditor" | "apt_analyst" | ...
    title:               str
    description:         str
    affected_assets:     List[str]    # host_id list
    severity:            str          # SeverityLevel value
    confidence:          float        # 0.0 – 1.0, sẽ được update theo consensus
    evidence:            List[str]    # dẫn chứng cụ thể từ network state
    recommendations:     List[str]
    mitre_techniques:    List[str]    # ["T1190", "T1059.001"]
    phase:               str          # "A" | "B"  — intra-group hay cross-group
    round_number:        int          # round nào trong OASIS session
    challenged_by:       List[str] = field(default_factory=list)   # "group/persona" format
    validated_by:        List[str] = field(default_factory=list)   # "group/persona" format
    cross_group_validated: bool = False
    attacker_corroborations: List[AttackerCorroboration] = field(default_factory=list)


@dataclass
class AttackerFinding:
    """Finding MỚI do attacker profile tạo ra trong Phase C."""
    finding_id:       str
    attacker_profile: str    # "apt" | "ransomware" | ...
    title:            str
    description:      str
    affected_assets:  List[str]
    severity:         str
    base_confidence:  float = 0.60  # attacker-only finding luôn bắt đầu thấp hơn
    path_description: str = ""      # mô tả attack path cụ thể
    agreed_by:        List[str] = field(default_factory=list)  # attacker profiles nào đồng ý


# ─── Consensus Output ─────────────────────────────────────────────────────────

@dataclass
class ConsensusVulnerability:
    """
    Vulnerability sau khi qua 3-layer consensus engine.
    Đây là output cuối để đưa vào VulnReportAgent.
    """
    vuln_id:               str
    title:                 str
    description:           str
    affected_assets:       List[str]
    severity:              str

    # 3-layer scores
    intra_group_score:     float   # Layer 1: agreement trong nội bộ group (weight 0.30)
    cross_group_score:     float   # Layer 2: validation từ group khác (weight 0.45)
    attacker_score:        float   # Layer 3: corroboration từ attacker profiles (weight 0.25)
    confidence_score:      float   # Final = L1×0.30 + L2×0.45 + L3×0.25

    supporting_groups:     List[str]    # domain groups đồng ý
    supporting_attackers:  List[str]    # attacker profiles confirm
    dismissing_attackers:  List[str]    # attacker profiles dismiss

    recommendations:       List[str]
    mitre_techniques:      List[str]

    # Source findings
    source_finding_ids:    List[str]    # ExpertFinding IDs hợp nhất thành vuln này
    attacker_finding_ids:  List[str]    # AttackerFinding IDs liên quan

    # Metadata
    is_attacker_only:      bool = False  # True nếu chỉ attacker profiles tìm ra
    needs_review:          bool = False  # True nếu confidence thấp (0.35–0.50)


# ─── GAP Declaration (Delphi-inspired) ───────────────────────────────────────

@dataclass
class GapDeclaration:
    """
    Khai báo giới hạn tri thức từ 1 expert agent.

    Khi agent không thể verify một khía cạnh của hạ tầng (ví dụ: không có SIEM
    nên IR analyst không thể đánh giá alerting rules), agent khai báo GAP thay vì
    bỏ qua. Hệ thống dùng GAP declarations để route sang domain group phù hợp.

    Inspired by Delphi method: structured elicitation yêu cầu experts khai báo
    explicit cả giới hạn của mình, không chỉ những gì họ biết.
    """
    gap_id:         str
    author_group:   str     # domain group của agent khai báo
    author_persona: str
    analyzed:       str     # host/control được phân tích (e.g., "FW-01", "SIEM", "ALL")
    gap_text:       str     # mô tả cụ thể về điều không verify được
    round_number:   int
    routed:         bool = False   # đã inject vào round tiếp theo chưa
    routed_to:      List[str] = field(default_factory=list)  # domain groups được route tới


# ─── Session State ─────────────────────────────────────────────────────────────

@dataclass
class CyberSessionState:
    """
    Trạng thái của 1 phiên phân tích bảo mật.
    Lưu vào file JSON cùng pattern với Project/Task.
    """
    session_id:       str
    graph_id:         str           # Zep graph ID chứa network topology
    current_phase:    str = "idle"  # "idle" | "A" | "B" | "C" | "consensus" | "done"
    current_round:    int = 0
    total_rounds:     int = 10      # 3 (A) + 4 (B) + 3 (C)

    expert_findings:   List[Dict[str, Any]] = field(default_factory=list)   # ExpertFinding serialized
    attacker_findings: List[Dict[str, Any]] = field(default_factory=list)  # AttackerFinding serialized
    semantic_findings: List[Dict[str, Any]] = field(default_factory=list)  # SemanticFinding serialized
    consensus_vulns:   List[Dict[str, Any]] = field(default_factory=list)   # ConsensusVulnerability serialized
    gap_registry:      List[Dict[str, Any]] = field(default_factory=list)   # GapDeclaration serialized
    round_stage1_posts: Dict[int, List[Dict[str, Any]]] = field(default_factory=dict)  # Two-stage: Stage 1 posts per round

    agent_config:     Dict[str, Any] = field(default_factory=dict)   # từ CyberExpertProfileGenerator
    error:            Optional[str] = None

    def phase_label(self) -> str:
        labels = {"A": "Intra-group analysis", "B": "Cross-group challenge", "C": "Attacker challenge"}
        return labels.get(self.current_phase, self.current_phase)

    def pending_gaps(self) -> List[Dict[str, Any]]:
        """Trả về các GAP declarations chưa được route (chưa inject vào round tiếp theo)."""
        return [g for g in self.gap_registry if not g.get("routed", False)]
