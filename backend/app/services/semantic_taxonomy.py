"""
Canonical semantic categories for contract audit (MiroFish product taxonomy).

Used by:
  - SEMANTIC_FINDING parser (contract_oasis_env)
  - Semantic consensus voting (consensus_engine)
  - Web3Bugs evaluation (evaluate_web3bugs) — normalize + optional gap→S pool

Publish CANONICAL_SEMANTIC_CATEGORIES + ALIAS_TO_CANONICAL + SWC_TO_SEMANTIC
in paper appendix when reporting Web3Bugs metrics.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Optional

# ─── Canonical vocabulary (enum in prompts must be subset of this set) ───────

CANONICAL_SEMANTIC_CATEGORIES: FrozenSet[str] = frozenset({
    "access_control",
    "price_oracle",
    "flash_loan",
    "governance_attack",
    "incorrect_accounting",
    "state_machine_bug",
    "business_flow",
    "reentrancy_logic",
    "other",
})

# Agent-facing pipe list (stable string for prompts / SEMANTIC_FINDING_FORMAT)
SEMANTIC_CATEGORY_PIPE_STRING = "|".join(sorted(CANONICAL_SEMANTIC_CATEGORIES))

# ─── Alias / free-form → canonical (evaluation + parser normalization) ───────

ALIAS_TO_CANONICAL: Dict[str, str] = {
    # Economic griefing / missing restriction often aligns with Web3Bugs S2 (access / ID)
    "incentive_misalignment": "access_control",
    "misaligned_incentives": "access_control",
    "griefing": "access_control",
    "liquidity_manipulation": "access_control",
    "router_attack": "access_control",
    "privilege_escalation": "access_control",
    "authorization": "access_control",
    "auth_bypass": "access_control",
    # Oracle-ish strings
    "oracle": "price_oracle",
    "oracle_manipulation": "price_oracle",
    "defi_flash_loan": "flash_loan",
    "flashloan": "flash_loan",
    # State / cleanup
    "state_bug": "state_machine_bug",
    "state_transition": "state_machine_bug",
    "cleanup_failure": "state_machine_bug",
    "approval_bug": "state_machine_bug",
    # Ordering / MEV → business-flow bucket for S4-style
    "mev": "business_flow",
    "frontrun": "business_flow",
    "front_running": "business_flow",
}

# SWC → semantic bucket (Policy B + gap SWC path). Keep in sync with evaluate_web3bugs L/S story.
SWC_TO_SEMANTIC: Dict[str, str] = {
    "SWC-100": "access_control",
    "SWC-105": "access_control",
    "SWC-106": "access_control",
    "SWC-115": "access_control",
    "SWC-113": "access_control",
    "SWC-119": "price_oracle",
    "SWC-108": "governance_attack",
    "SWC-132": "incorrect_accounting",
    "SWC-114": "business_flow",
    "SWC-107": "reentrancy_logic",
}

# unvalidated_swc_gaps.swc_category (string) → canonical semantic bucket
GAP_SWC_CATEGORY_TO_SEMANTIC: Dict[str, str] = {
    "access_control": "access_control",
    "oracle": "price_oracle",
    "price_oracle": "price_oracle",
    "flash_loan": "flash_loan",
    "governance": "governance_attack",
    "delegatecall": "access_control",  # proxy misuse often access / trust boundary
    "front_running": "business_flow",
    "reentrancy": "reentrancy_logic",
    "incorrect_accounting": "incorrect_accounting",
    "state_machine": "state_machine_bug",
}

# Gaps are weak signals — require minimum corroborating raw findings for S-pool use.
GAP_MIN_SOURCE_COUNT_FOR_S: int = 2


def normalize_semantic_category(raw: Optional[str]) -> str:
    """
    Map agent/LLM category string to a canonical bucket.
    Unknown tokens → 'other' (never None — keeps JSON schema stable).
    """
    if raw is None:
        return "other"
    s = str(raw).strip().lower().replace(" ", "_").replace("-", "_")
    if not s:
        return "other"
    if s in CANONICAL_SEMANTIC_CATEGORIES:
        return s
    if s in ALIAS_TO_CANONICAL:
        return ALIAS_TO_CANONICAL[s]
    return "other"


def semantic_category_from_gap(
    swc_category: Optional[str],
    swc_id: Optional[str],
    source_count: int,
    *,
    min_source: int = GAP_MIN_SOURCE_COUNT_FOR_S,
) -> Optional[str]:
    """
    Derive a canonical semantic category from an unvalidated_swc_gap row.
    Returns None if signal is too weak or unmapped (excluded from S-pool).
    """
    if source_count < min_source:
        return None
    sid = (swc_id or "").strip().upper()
    if sid.startswith("SWC-") and sid in SWC_TO_SEMANTIC:
        return SWC_TO_SEMANTIC[sid]
    # Non-SWC ids (e.g. DEFI-FLASH_LOAN) — optional light mapping
    if sid == "DEFI-FLASH_LOAN":
        return "flash_loan"
    raw_cat = (swc_category or "").strip().lower().replace(" ", "_")
    if raw_cat in GAP_SWC_CATEGORY_TO_SEMANTIC:
        return GAP_SWC_CATEGORY_TO_SEMANTIC[raw_cat]
    return None


# Few-shot lines for Tier-1 / attacker prompts (keep short)
SEMANTIC_CATEGORY_FEW_SHOT = """
Few-shot CATEGORY examples (use EXACTLY one token from the CATEGORY line above):
- Missing onlyRouter on addLiquidity / anyone can drain router → access_control
- Approval not cleared after failed external call / inconsistent cleanup → state_machine_bug
- TWAP / spot manipulation / stale oracle → price_oracle
- Multi-step business flow broken without lock / atomicity → business_flow
- Rounding or balance equation wrong (x=a+b vs x=a-b) → incorrect_accounting
- Vote / timelock / proposal abuse → governance_attack
- Callback reentrancy at logic (not classic SWC-107 template) → reentrancy_logic
- Does not fit above but logic flaw → other
"""
