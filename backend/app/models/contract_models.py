"""
Smart contract data models for the Multi-Expert Contract Audit Panel.
Mirrors cyber_models.py with NetworkAsset → ContractEntity and MITRE → SWC.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from enum import Enum


class SWCCategory(str, Enum):
    """Top-level SWC categories — used to assign domain expert."""
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
    """A function within a smart contract."""
    name:                        str
    visibility:                  str              # FunctionVisibility value
    modifiers:                   List[str]        # ["onlyOwner", "nonReentrant"]
    has_external_call:           bool             # True if calls external contract/address
    state_updates:               List[str]        # state vars modified by this function
    external_call_before_state:  bool             # True = reentrancy risk pattern
    sends_ether:                 bool             # True if contains .call{value} or .transfer
    parameters:                  List[str]        # parameter names
    return_types:                List[str]
    swc_candidates:              List[str]        # preliminary SWC IDs from static scan
    source_lines:                Optional[str] = None  # "45-67"


@dataclass
class ContractStateVar:
    """A state variable of a smart contract."""
    name:        str          # "balances"
    var_type:    str          # "mapping(address => uint256)"
    visibility:  str          # FunctionVisibility value
    is_critical: bool         # True if balance mapping, owner, or admin role
    modified_by: List[str]    # functions that modify this var


@dataclass
class ContractEntity:
    """Complete information for a single smart contract."""
    contract_id:            str                      # "TokenVault"
    source_code:            str                      # full Solidity source
    compiler_version:       str                      # "0.8.19"
    contract_type:          str                      # ContractType value
    functions:              List[ContractFunction]
    state_vars:             List[ContractStateVar]
    external_dependencies:  List[str]                # contracts/interfaces imported or called
    has_reentrancy_guard:   bool
    has_access_control:     bool                     # onlyOwner, role-based
    has_pausable:           bool
    uses_oracle:            bool                     # True if uses a price oracle
    uses_flash_loan:        bool                     # True if implements flash loan
    is_upgradeable:         bool                     # proxy pattern
    swc_candidates:         List[str]                # preliminary static findings
    raw_text:               str = ""                 # additional description (if any)

    def to_zep_text(self) -> str:
        """Serialize to text for storage in a Zep episode."""
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
        """Summarize risk signals for injection into agent context."""
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
    """Response from one attacker profile about a contract finding."""
    profile_id:       str    # "flash_loan" | "reentrancy_bot" | "governance_attack" | "mev" | "supply_chain"
    action:           str    # "ATTACKER_CONFIRM" | "ATTACKER_DISMISS" | "ATTACKER_ESCALATE" | "ATTACKER_DOWNGRADE"
    comment:          str
    exploit_path:     str    # specific exploit description
    confidence_delta: float  # +0.15 for CONFIRM, -0.20 for DISMISS


@dataclass
class ContractFinding:
    """Finding from one expert agent in Phase A or B."""
    finding_id:           str
    author_domain:        str           # "appsec" | "blockchain" | "cryptography" | "defi" | "governance"
    author_persona:       str           # "offensive" | "defensive" | "auditor"
    title:                str
    description:          str
    affected_functions:   List[str]     # affected function names
    severity:             str           # AuditSeverity value
    confidence:           float         # 0.0 – 1.0
    evidence:             List[str]     # citations from contract code / KG facts
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

    # NL migration fields
    contract_name:        str = ""
    attack_path:          Optional[str] = None


@dataclass
class AttackerContractFinding:
    """New finding generated by an attacker profile in Phase C."""
    finding_id:       str
    attacker_profile: str     # "flash_loan" | "reentrancy_bot" | ...
    title:            str
    description:      str
    affected_functions: List[str]
    swc_id:           str
    severity:         str
    base_confidence:  float = 0.60
    exploit_path:     str = ""         # detailed attack steps
    agreed_by:        List[str] = field(default_factory=list)


# ─── Semantic Finding (Web3Bugs S-category) ────────────────────────────────────

SEMANTIC_CATEGORIES = {
    "price_oracle":          "Price oracle manipulation / stale price",
    "flash_loan":            "Flash loan attack vector",
    "governance_attack":     "Governance takeover / vote manipulation",
    "incorrect_accounting":  "Incorrect balance / share / reward accounting",
    "state_machine_bug":     "Incorrect state transition or invariant violation",
    "incentive_misalignment":"Economic incentive misalignment or griefing",
    "reentrancy_logic":      "Logic-level reentrancy (no SWC-107 pattern)",
    "other":                 "Other semantic / business-logic vulnerability",
}


@dataclass
class SemanticFinding:
    """
    DEPRECATED: S-track removed in NL migration. Use ContractFinding with contract_name/attack_path.
    Kept for backwards compatibility — do not use in new code.
    """
    finding_id:          str
    author_domain:       str
    author_persona:      str
    title:               str
    category:            str    # key from SEMANTIC_CATEGORIES
    severity:            str
    affected_functions:  List[str]
    evidence:            str
    attack_path:         List[str]
    phase:               str
    round_number:        int
    confidence:          float = 0.55
    validated_by:        List[str] = field(default_factory=list)
    challenged_by:       List[str] = field(default_factory=list)
    is_exploitable:      Optional[bool] = None
    is_attacker_surfaced: bool = False


# ─── Consensus Output ─────────────────────────────────────────────────────────

@dataclass
class ContractAuditResult:
    """Vulnerability after passing through 3-layer consensus engine — final output for ContractAuditReportAgent."""
    vuln_id:               str
    title:                 str
    description:           str
    affected_functions:    List[str]
    swc_id:                str          # "SWC-107"
    swc_name:              str          # "Reentrancy"
    severity:              str

    # 3-layer scores (mirror ConsensusVulnerability)
    intra_domain_agreement: float       # Layer 1: intra-domain agreement (weight 0.30)
    cross_domain_agreement: float       # Layer 2: cross-domain validation (weight 0.45)
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
    Knowledge-limit declaration from one expert agent in contract audit.

    Inspired by the Delphi GAP mechanism from Direction B, applied to the contract domain.
    Example: DeFi agent declares a GAP about a custom PRNG's cryptography
    → routed to the cryptography domain group.
    """
    gap_id:         str
    author_domain:  str
    author_persona: str
    analyzed:       str     # function/state_var/contract property being analyzed
    gap_text:       str     # what could not be verified
    round_number:   int
    routed:         bool = False                        # whether already injected into the next round
    routed_to:      List[str] = field(default_factory=list)


# ─── Session State ─────────────────────────────────────────────────────────────

@dataclass
class ContractSessionState:
    """State of one smart contract audit session — persisted as JSON."""
    session_id:       str
    graph_id:         str           # Zep graph ID for the contract knowledge graph
    contract_id:      str           # ContractEntity.contract_id
    current_phase:    str = "idle"  # "idle" | "A" | "B" | "C" | "consensus" | "done"
    current_round:    int = 0
    total_rounds:     int = 10

    contract_findings:   List[Dict[str, Any]] = field(default_factory=list)
    attacker_findings:   List[Dict[str, Any]] = field(default_factory=list)
    semantic_findings:   List[Dict[str, Any]] = field(default_factory=list)   # SemanticFinding serialized
    audit_results:       List[Dict[str, Any]] = field(default_factory=list)
    gap_registry:        List[Dict[str, Any]] = field(default_factory=list)

    # Published finding registry — injected into agent context to reduce duplicates
    published_finding_titles: List[str] = field(default_factory=list)

    agent_config:     Dict[str, Any] = field(default_factory=dict)
    contract_summary: str = ""      # output of build_context_summary() from ContractKGBuilder
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
