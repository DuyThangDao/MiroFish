"""
Smart Contract data models cho Multi-Expert Contract Audit Panel (Đề tài 10).
Tương tự cyber_models.py nhưng thay NetworkAsset → ContractEntity, MITRE → SWC.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from enum import Enum


class SWCCategory(str, Enum):
    """Top-level SWC categories — dùng để assign domain expert."""
    REENTRANCY        = "reentrancy"
    ACCESS_CONTROL    = "access_control"
    ARITHMETIC        = "arithmetic"
    UNCHECKED_CALLS   = "unchecked_calls"
    DENIAL_OF_SERVICE = "denial_of_service"
    LOGIC_ERROR       = "logic_error"
    RANDOMNESS        = "randomness"
    FRONT_RUNNING     = "front_running"
    TIMESTAMP         = "timestamp"
    GOVERNANCE        = "governance"


class ContractType(str, Enum):
    ERC20        = "ERC20"
    ERC721       = "ERC721"
    DEFI_LENDING = "DeFi_Lending"
    DEFI_AMM     = "DeFi_AMM"
    GOVERNANCE   = "Governance"
    BRIDGE       = "Bridge"
    VAULT        = "Vault"
    CUSTOM       = "Custom"


class FunctionVisibility(str, Enum):
    PUBLIC   = "public"
    PRIVATE  = "private"
    INTERNAL = "internal"
    EXTERNAL = "external"


class AuditSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# ─── Contract Structure ────────────────────────────────────────────────────────

@dataclass
class ContractFunction:
    """Một function trong smart contract."""
    name:                        str
    visibility:                  str              # FunctionVisibility value
    modifiers:                   List[str]        # ["onlyOwner", "nonReentrant"]
    has_external_call:           bool             # True nếu gọi external contract/address
    state_updates:               List[str]        # state vars được modify trong function này
    external_call_before_state:  bool             # True = reentrancy risk pattern
    sends_ether:                 bool             # True nếu có .call{value} hoặc .transfer
    parameters:                  List[str]        # tên parameter
    return_types:                List[str]
    swc_candidates:              List[str]        # SWC IDs sơ bộ từ static scan
    source_lines:                Optional[str] = None  # "45-67"


@dataclass
class ContractStateVar:
    """State variable của smart contract."""
    name:        str          # "balances"
    var_type:    str          # "mapping(address => uint256)"
    visibility:  str          # FunctionVisibility value
    is_critical: bool         # True nếu là balance mapping, owner, admin role
    modified_by: List[str]    # functions nào modify var này (function names)


@dataclass
class ContractEntity:
    """
    Toàn bộ thông tin về 1 smart contract.
    Thay thế NetworkAsset trong Hướng B.
    """
    contract_id:            str                      # "TokenVault"
    source_code:            str                      # Full Solidity source
    compiler_version:       str                      # "0.8.19"
    contract_type:          str                      # ContractType value
    functions:              List[ContractFunction]
    state_vars:             List[ContractStateVar]
    external_dependencies:  List[str]                # contracts/interfaces import/call
    has_reentrancy_guard:   bool
    has_access_control:     bool                     # onlyOwner, Role-based
    has_pausable:           bool
    uses_oracle:            bool                     # True nếu dùng price oracle
    uses_flash_loan:        bool                     # True nếu implements flash loan
    is_upgradeable:         bool                     # Proxy pattern
    swc_candidates:         List[str]                # Preliminary static findings
    raw_text:               str = ""                 # Description thêm (nếu có)

    def to_zep_text(self) -> str:
        """Chuyển thành text để lưu vào Zep episode."""
        risky_funcs = [
            f.name for f in self.functions
            if f.external_call_before_state or f.sends_ether
        ]
        public_funcs = [
            f.name for f in self.functions
            if f.visibility in ("public", "external")
        ]
        critical_vars = [v.name for v in self.state_vars if v.is_critical]

        lines = [
            f"Contract: {self.contract_id}",
            f"Type: {self.contract_type}, Compiler: {self.compiler_version}",
            f"Functions (public/external): {', '.join(public_funcs) if public_funcs else 'none'}",
            f"Critical state vars: {', '.join(critical_vars) if critical_vars else 'none'}",
            f"External dependencies: {', '.join(self.external_dependencies) if self.external_dependencies else 'none'}",
            f"Security flags: reentrancy_guard={self.has_reentrancy_guard}, "
            f"access_control={self.has_access_control}, pausable={self.has_pausable}",
            f"DeFi flags: uses_oracle={self.uses_oracle}, uses_flash_loan={self.uses_flash_loan}, "
            f"upgradeable={self.is_upgradeable}",
            f"High-risk functions: {', '.join(risky_funcs) if risky_funcs else 'none'}",
            f"SWC preliminary candidates: {', '.join(self.swc_candidates) if self.swc_candidates else 'none'}",
        ]
        if self.raw_text:
            lines.append(f"Notes: {self.raw_text}")
        return "\n".join(lines)

    def risk_summary(self) -> Dict[str, Any]:
        """Tóm tắt risk signals để inject vào agent context."""
        reentrancy_funcs = [
            f.name for f in self.functions if f.external_call_before_state
        ]
        unprotected_funcs = [
            f.name for f in self.functions
            if f.visibility in ("public", "external") and not f.modifiers and f.sends_ether
        ]
        return {
            "reentrancy_risk_functions": reentrancy_funcs,
            "unprotected_ether_senders": unprotected_funcs,
            "missing_reentrancy_guard": not self.has_reentrancy_guard and bool(reentrancy_funcs),
            "missing_access_control": not self.has_access_control,
            "oracle_manipulation_risk": self.uses_oracle and not self.has_pausable,
            "flash_loan_risk": self.uses_flash_loan,
            "upgrade_risk": self.is_upgradeable,
            "swc_candidates": self.swc_candidates,
        }


# ─── Expert Findings ──────────────────────────────────────────────────────────

@dataclass
class AttackerCorroboration:
    """Phản hồi của 1 attacker profile về 1 contract finding."""
    profile_id:       str    # "flash_loan" | "reentrancy_bot" | "governance_attack" | "mev" | "supply_chain"
    action:           str    # "ATTACKER_CONFIRM" | "ATTACKER_DISMISS" | "ATTACKER_ESCALATE" | "ATTACKER_DOWNGRADE"
    comment:          str
    exploit_path:     str    # Mô tả cụ thể cách exploit
    confidence_delta: float  # +0.15 for CONFIRM, -0.20 for DISMISS


@dataclass
class ContractFinding:
    """
    Finding từ 1 expert agent trong Phase A hoặc B.
    Thay thế ExpertFinding trong Hướng B.
    """
    finding_id:           str
    author_domain:        str           # "appsec" | "blockchain" | "cryptography" | "defi" | "governance"
    author_persona:       str           # "offensive" | "defensive" | "auditor"
    title:                str
    description:          str
    affected_functions:   List[str]     # function names bị ảnh hưởng
    swc_id:               str           # "SWC-107"
    swc_name:             str           # "Reentrancy"
    severity:             str           # AuditSeverity value
    confidence:           float         # 0.0 – 1.0
    evidence:             List[str]     # trích dẫn từ contract code / KG facts
    phase:                str           # "A" | "B"
    round_number:         int

    # Attacker validation (Phase C)
    is_exploitable:       Optional[bool] = None   # None = unknown, True/False = validated
    exploit_scenario:     Optional[str]  = None
    patch_suggestion:     Optional[str]  = None

    # Cross-domain validation
    challenged_by:           List[str] = field(default_factory=list)
    validated_by:            List[str] = field(default_factory=list)
    cross_domain_validated:  bool = False

    attacker_corroborations: List[AttackerCorroboration] = field(default_factory=list)


@dataclass
class AttackerContractFinding:
    """Finding MỚI do attacker profile tạo ra trong Phase C."""
    finding_id:       str
    attacker_profile: str     # "flash_loan" | "reentrancy_bot" | ...
    title:            str
    description:      str
    affected_functions: List[str]
    swc_id:           str
    severity:         str
    base_confidence:  float = 0.60
    exploit_path:     str = ""         # Chi tiết attack steps
    agreed_by:        List[str] = field(default_factory=list)


# ─── Consensus Output ─────────────────────────────────────────────────────────

@dataclass
class ContractAuditResult:
    """
    Vulnerability sau khi qua 3-layer consensus engine.
    Output cuối để đưa vào ContractAuditReportAgent.
    Thay thế ConsensusVulnerability.
    """
    vuln_id:               str
    title:                 str
    description:           str
    affected_functions:    List[str]
    swc_id:                str          # "SWC-107"
    swc_name:              str          # "Reentrancy"
    severity:              str

    # 3-layer scores (mirror ConsensusVulnerability)
    intra_domain_agreement: float       # Layer 1: agreement trong domain (weight 0.30)
    cross_domain_agreement: float       # Layer 2: validation từ domain khác (weight 0.45)
    attacker_corroboration: float       # Layer 3: attacker profile corroboration (weight 0.25)
    confidence_score:       float       # Final = L1×0.30 + L2×0.45 + L3×0.25

    supporting_domains:    List[str]
    supporting_attackers:  List[str]
    dismissing_attackers:  List[str]

    # Exploitability (unique to contract audit — maps to C3 contribution)
    is_exploitable:        bool
    exploit_scenario:      Optional[str]

    # Remediation (maps to C4/C5 contributions)
    patch_suggestion:      str
    recommendations:       List[str]

    # SWC ↔ MITRE cross-reference (optional, for paper completeness)
    mitre_equivalent:      Optional[str] = None

    # Source findings
    source_finding_ids:    List[str] = field(default_factory=list)
    attacker_finding_ids:  List[str] = field(default_factory=list)

    # Metadata
    is_attacker_only:      bool = False
    needs_review:          bool = False


# ─── GAP Declaration (Delphi-inspired) — reused pattern from cyber_models ─────

@dataclass
class ContractGapDeclaration:
    """
    Khai báo giới hạn tri thức từ 1 expert agent trong contract audit.
    Cùng cơ chế Delphi GAP từ Hướng B, áp dụng cho contract domain.

    Ví dụ: DeFi agent khai báo GAP về cryptography của custom PRNG
    → routed sang cryptography domain group.
    """
    gap_id:         str
    author_domain:  str
    author_persona: str
    analyzed:       str     # function/state_var/contract property được phân tích
    gap_text:       str     # điều không verify được
    round_number:   int
    routed:         bool = False
    routed_to:      List[str] = field(default_factory=list)


# ─── Session State ─────────────────────────────────────────────────────────────

@dataclass
class ContractSessionState:
    """
    Trạng thái của 1 phiên audit smart contract.
    Tương tự CyberSessionState — persist dưới dạng JSON.
    """
    session_id:       str
    graph_id:         str           # Zep graph ID chứa contract KG
    contract_id:      str           # ContractEntity.contract_id
    current_phase:    str = "idle"  # "idle" | "A" | "B" | "C" | "consensus" | "done"
    current_round:    int = 0
    total_rounds:     int = 10

    contract_findings:   List[Dict[str, Any]] = field(default_factory=list)
    attacker_findings:   List[Dict[str, Any]] = field(default_factory=list)
    audit_results:       List[Dict[str, Any]] = field(default_factory=list)
    gap_registry:        List[Dict[str, Any]] = field(default_factory=list)

    # Published finding registry — inject vào agent context để giảm duplicates
    published_finding_titles: List[str] = field(default_factory=list)

    agent_config:     Dict[str, Any] = field(default_factory=dict)
    contract_summary: str = ""      # build_context_summary() từ ContractKGBuilder
    error:            Optional[str] = None

    def phase_label(self) -> str:
        labels = {
            "A": "Intra-domain analysis",
            "B": "Cross-domain challenge",
            "C": "Attacker simulation"
        }
        return labels.get(self.current_phase, self.current_phase)

    def pending_gaps(self) -> List[Dict[str, Any]]:
        return [g for g in self.gap_registry if not g.get("routed", False)]

    def high_confidence_results(self, threshold: float = 0.65) -> List[Dict[str, Any]]:
        return [r for r in self.audit_results if r.get("confidence_score", 0) >= threshold]
