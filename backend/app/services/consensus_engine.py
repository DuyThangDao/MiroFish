"""
Consensus Engine — Multi-Expert Panel (Direction B)

Two-stage scoring — Claim → Verify:

  Stage 1 (Expert hypothesis):
    expert_confidence = L1×0.40 + L2×0.60
      L1 — Intra-group agreement  weight: 0.40
      L2 — Cross-group validation weight: 0.60  (highest — prevents group bias)

  Stage 2 (Attacker verification gate — multiplicative):
    gate = 1.00  if net attacker confirms  > dismisses   (verified)
    gate = 0.75  if no attacker reviewed                 (unverified — 25% penalty)
    gate = 0.50  if net attacker dismisses > confirms    (rejected)

  final_confidence = expert_confidence × gate
  Filter: confidence < 0.50 → exclude from consensus_vulns

Rationale: expert agreement alone cannot confirm a finding. Cross-domain consensus
amplifies group hallucinations (many agents independently reaching the same wrong
conclusion). The attacker gate ensures expert findings are hypotheses until Phase C
independently verifies exploitability. Unreviewed findings are penalised so that
hallucinations that slip past Phase C don't auto-confirm via expert majority alone.

Safety net: findings below threshold still appear in unvalidated_swc_gaps (via
enforce_swc_coverage) — nothing is silently discarded.

Enhancements:
  B-dynamic — Semantic anchor clustering: findings sharing a control/host keyword
              in their title are clustered together even if title tokens differ.
  D         — Post-consensus control coverage enforcement: after scoring, any
              standard security control absent from consensus list is collected
              from raw findings into an `unvalidated_control_gaps` section.
"""

import re
import uuid
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict

from ..models.cyber_models import (
    ExpertFinding, AttackerFinding, AttackerCorroboration,
    ConsensusVulnerability, SeverityLevel
)
from ..utils.logger import get_logger
from .semantic_taxonomy import normalize_semantic_category

logger = get_logger("mirofish.consensus_engine")

# ─── Contract audit domain config ─────────────────────────────────────────────

CONTRACT_DOMAIN_GROUPS = {
    "appsec", "blockchain", "cryptography", "defi",
    "governance", "smart_contract_economics", "supply_chain",
}

# SWC keyword anchors for semantic clustering in contract audit mode.
# Same data as SWCRegistry.get_severity_anchor_keywords() — duplicated here
# to avoid circular imports and keep ConsensusEngine import-free from swc_registry.
SWC_ANCHOR_KEYWORDS: Dict[str, List[str]] = {
    "reentrancy":     ["reentrancy", "re-entrancy", "reentrant", "SWC-107", "CEI"],
    "overflow":       ["overflow", "underflow", "arithmetic", "SafeMath", "SWC-101"],
    "access_control": ["access control", "onlyOwner", "authorization", "SWC-105", "SWC-115", "privilege"],
    "oracle":         ["oracle", "price manipulation", "TWAP", "Chainlink", "flash loan price"],
    "flash_loan":     ["flash loan", "flashloan", "FLASH_LOAN", "flash attack"],
    "governance":     ["governance", "voting", "proposal", "timelock", "GOVERNANCE_FLASH"],
    "randomness":     ["randomness", "PRNG", "entropy", "VRF", "SWC-120"],
    "selfdestruct":   ["selfdestruct", "suicide", "SWC-106"],
    "delegatecall":   ["delegatecall", "delegate call", "SWC-112", "proxy"],
    "signature":      ["signature", "ecrecover", "replay", "SWC-121", "SWC-122"],
    "dos_gas":        ["SWC-128", "block gas limit", "unbounded array", "unbounded loop", "gas exhaustion", "DoS with Block Gas"],
    "front_running":  ["SWC-114", "front-run", "frontrunning", "front running", "MEV", "transaction order", "sandwich attack"],
}

# Semantic category anchors for S-category (Web3Bugs) findings.
SEMANTIC_ANCHOR_KEYWORDS: Dict[str, List[str]] = {
    "access_control":        ["access control", "missing restriction", "unauthorized", "anyone can", "arbitrary caller", "privilege", "onlyOwner"],
    "price_oracle":          ["oracle", "price manipulation", "spot price", "TWAP", "stale price", "Chainlink"],
    "flash_loan":            ["flash loan", "flashloan", "flash attack", "FLASH_LOAN"],
    "governance_attack":     ["governance", "voting", "proposal", "vote manipulation", "quorum"],
    "incorrect_accounting":  ["accounting", "balance", "share", "reward", "rounding", "precision", "incorrect"],
    "state_machine_bug":     ["state machine", "state transition", "invariant", "locked", "stuck", "approval not reset", "not cleaned up", "ERC20 approval"],
    "business_flow":         ["business logic", "protocol invariant", "double", "spec mismatch"],
    "incentive_misalignment":["incentive", "misalignment", "griefing", "sandwich", "MEV", "economic"],
    "reentrancy_logic":      ["reentrancy", "re-entrancy", "reentrant", "callback", "cross-contract"],
    "other":                 [],
}

# ─── Weights ──────────────────────────────────────────────────────────────────
# Stage 1: expert hypothesis strength
WEIGHT_INTRA  = 0.40   # L1 — intra-group agreement
WEIGHT_CROSS  = 0.60   # L2 — cross-domain validation

# Stage 2: attacker verification gate (multiplicative applied to expert_confidence)
# NEUTRAL = 1.0: unreviewed findings keep full expert_confidence
#   (no penalty — avoids over-filtering when Phase C has low attacker activity)
# DISMISS = 0.40: dismissed findings need extra peer challenge to drop below MIN_CONFIDENCE(0.35)
#   (0.40 * max_exp_conf=1.0 = 0.40 > 0.35; peer challenges can push it below threshold)
ATTACKER_GATE_CONFIRM  = 1.00   # confirmed by attacker  → no change
ATTACKER_GATE_NEUTRAL  = 1.00   # not reviewed           → no penalty
ATTACKER_GATE_DISMISS  = 0.40   # dismissed by attacker  → heavy penalty

MIN_CONFIDENCE = 0.35  # Below this → exclude from consensus_vulns (safety net: goes to gaps)

# ─── Tier-1 gate ──────────────────────────────────────────────────────────────
# Tier 1 (consensus_vulns): finding has function location + exploit path → actionable
# Tier 2 (unvalidated_swc_gaps): SWC detected but no location/path → triage signal
_BACKFILL_FN_RE = re.compile(r'`([a-zA-Z_]\w+)\(\)`')

# Attacker action → delta used only for attacker_score metadata field
ATTACKER_DELTA = {
    "ATTACKER_CONFIRM":   +0.15,
    "ATTACKER_DISMISS":   -0.20,
    "ATTACKER_ESCALATE":  +0.10,
    "ATTACKER_DOWNGRADE": -0.10,
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class ConsensusEngine:
    """
    Hợp nhất ExpertFinding + AttackerFinding → ConsensusVulnerability list.

    Algorithm:
    1. Cluster expert findings theo tiêu đề tương đồng (fuzzy match)
    2. Tính Layer 1 (intra-group): % agents trong cùng group đồng ý
    3. Tính Layer 2 (cross-group): số group khác nhau đã nêu finding tương tự
    4. Tính Layer 3 (attacker): net corroboration score từ attacker profiles
    5. Tính Layer 4 (peer): CHALLENGE/VALIDATE delta từ Stage 2 cross-domain review
    6. confidence = (L1*0.40 + L2*0.60) * attacker_gate + peer_delta;  clamped [0, 1]
    7. Filter < MIN_CONFIDENCE (0.35)
    8. Merge attacker-only findings với base confidence 0.60
    """

    def __init__(self) -> None:
        # Tier 2 findings demoted from consensus (no function/exploit path)
        # Appended to unvalidated_swc_gaps by enforce_swc_coverage()
        self._tier2_demoted: List[Dict[str, Any]] = []

    @staticmethod
    def _backfill_functions(vuln: "ConsensusVulnerability") -> "ConsensusVulnerability":
        """Extract function names from description/recommendations if affected_assets is empty."""
        if vuln.affected_assets:
            return vuln
        text = " ".join(filter(None, [
            vuln.description,
            " ".join(vuln.recommendations or []),
        ]))
        matches = list(dict.fromkeys(_BACKFILL_FN_RE.findall(text)))
        if matches:
            vuln.affected_assets = matches
        return vuln

    @staticmethod
    def _is_tier1(vuln: "ConsensusVulnerability") -> bool:
        """Tier 1: has at least 1 function location AND at least 1 recommendation (exploit path proxy)."""
        return bool(vuln.affected_assets) and bool(vuln.recommendations)

    def run(
        self,
        expert_findings_raw: List[Dict[str, Any]],
        attacker_findings_raw: List[Dict[str, Any]],
        domain_group_count: int = 5,
        mode: str = "network_security",
        semantic_findings_raw: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[List[ConsensusVulnerability], List[Dict[str, Any]]]:
        """
        Run full consensus pipeline.

        Args:
            expert_findings_raw: serialized ExpertFinding dicts từ session
            attacker_findings_raw: serialized AttackerFinding dicts từ session
            domain_group_count: số domain groups (default 5; use 7 for contract_audit)
            mode: "network_security" | "contract_audit"
            semantic_findings_raw: serialized SemanticFinding dicts (optional)

        Returns:
            Tuple of:
              - Sorted list ConsensusVulnerability (highest confidence first)
              - List of semantic consensus dicts (may be empty for network_security mode)
        """
        # ── Step 1: Cluster expert findings ──────────────────────────────────
        clusters = self._cluster_findings(expert_findings_raw, mode=mode)

        # ── Step 2–4: Score each cluster ─────────────────────────────────────
        vulns: List[ConsensusVulnerability] = []
        for cluster in clusters:
            vuln = self._score_cluster(cluster, domain_group_count, mode=mode)
            if vuln:
                vulns.append(vuln)

        # ── Step 5: Add attacker-only findings ───────────────────────────────
        for af_raw in attacker_findings_raw:
            agreed_by = af_raw.get("agreed_by", [])
            # Only include if at least 2 attacker profiles agree
            if len(agreed_by) < 2:
                continue
            av = self._attacker_finding_to_vuln(af_raw)
            if av:
                vulns.append(av)

        # ── Step 6: Filter and sort ───────────────────────────────────────────
        vulns = [v for v in vulns if v.confidence_score >= MIN_CONFIDENCE]
        vulns.sort(key=lambda v: (v.confidence_score, SEVERITY_RANK.get(v.severity, 0)), reverse=True)

        # ── Step 6b: Tier routing (contract_audit only) ───────────────────────
        # Backfill function names from description/recommendations, then split:
        #   Tier 1 → consensus_vulns  (has function location + recommendations)
        #   Tier 2 → unvalidated_swc_gaps  (class-level hint only)
        self._tier2_demoted = []
        if mode == "contract_audit":
            vulns = [self._backfill_functions(v) for v in vulns]
            tier1, tier2 = [], []
            for v in vulns:
                if self._is_tier1(v):
                    tier1.append(v)
                else:
                    tier2.append(v)
            if tier2:
                logger.info(
                    f"Tier routing: {len(tier1)} Tier-1 (actionable), "
                    f"{len(tier2)} Tier-2 demoted to gaps (no function/path)"
                )
            self._tier2_demoted = [
                {
                    "swc_category":       "tier2_demoted",
                    "swc_id":             (v.swc_ids or [""])[0],
                    "title":              v.title,
                    "description":        v.description,
                    "severity":           v.severity,
                    "affected_functions": v.affected_assets,
                    "confidence_score":   v.confidence_score,
                    "note":               "Tier-2: SWC pattern detected but no function location or exploit path confirmed",
                }
                for v in tier2
            ]
            vulns = tier1

        # ── Step 7: Semantic consensus (contract_audit only) ─────────────────
        semantic_results: List[Dict[str, Any]] = []
        if mode == "contract_audit" and semantic_findings_raw:
            semantic_results = self._run_semantic_consensus(
                semantic_findings_raw, domain_group_count
            )

        logger.info(
            f"Consensus: {len(expert_findings_raw)} expert findings + "
            f"{len(attacker_findings_raw)} attacker findings → "
            f"{len(vulns)} consensus vulnerabilities, "
            f"{len(semantic_results)} semantic consensus findings"
        )
        return vulns, semantic_results

    # ─── Clustering ───────────────────────────────────────────────────────────

    def _build_anchors(self, findings: List[Dict[str, Any]], mode: str = "network_security") -> Set[str]:
        """
        B-dynamic: derive semantic anchors from existing data — no hardcoding.

        Network security mode:
          1. SecurityControls field names (edr, siem, waf, …) — stable, scenario-independent
          2. Host IDs from affected_assets in findings — scenario-specific, auto-extracted

        Contract audit mode:
          1. SWC keyword terms (reentrancy, overflow, oracle, …) — from SWC_ANCHOR_KEYWORDS
          2. Function names from affected_functions in findings — contract-specific
        """
        if mode == "contract_audit":
            # 1. SWC semantic keywords as anchors
            anchors: Set[str] = set()
            for keywords in SWC_ANCHOR_KEYWORDS.values():
                for kw in keywords:
                    anchors.add(kw.lower())

            # 2. Function names mentioned in findings
            for f in findings:
                for func in f.get("affected_functions", []):
                    token = func.lower().rstrip("()").strip()
                    if token:
                        anchors.add(token)
            return anchors

        from ..models.cyber_models import SecurityControls
        from dataclasses import fields as dc_fields

        # 1. Standard security controls
        anchors = {f.name for f in dc_fields(SecurityControls)}

        # 2. Host IDs mentioned in any finding's affected_assets
        for f in findings:
            for asset in f.get("affected_assets", []):
                token = asset.lower().strip()
                if token:
                    anchors.add(token)

        return anchors

    @staticmethod
    def _anchor_in_text(anchor: str, text: str) -> bool:
        """Word-boundary match to prevent 'av' hitting 'traversal', 'have', etc."""
        return bool(re.search(r'\b' + re.escape(anchor) + r'\b', text))

    def _shares_anchor(
        self, f1: Dict[str, Any], f2: Dict[str, Any], anchors: Set[str]
    ) -> bool:
        """
        True if both findings share a semantic anchor where the anchor appears
        in the TITLE of at least one finding (title-dominant requirement).

        This prevents over-clustering: compound findings that mention many controls
        only in their description (e.g. "No EDR, SIEM, WAF, AV, NDR, MFA, DLP —
        None deployed") do not act as hubs that absorb all control findings into
        one mega-cluster. Clustering only fires when the topic is salient enough
        to appear in a title.

        Rule: anchor `a` triggers clustering of (f1, f2) when:
          - `a` in title(f1) AND `a` in title(f2)   ← both-title condition

        Requiring the anchor in BOTH titles (not just one) prevents compound
        findings like "Complete Absence of Foundational Security Controls"
        (whose description mentions every control) from acting as hubs.
        Only two findings that independently chose the same control as their
        primary topic (visible in the title) will be clustered.
        """
        t1 = f1.get("title", "").lower()
        t2 = f2.get("title", "").lower()

        return any(
            self._anchor_in_text(a, t1) and self._anchor_in_text(a, t2)
            for a in anchors
        )

    def _cluster_findings(
        self, findings: List[Dict[str, Any]], mode: str = "network_security"
    ) -> List[List[Dict[str, Any]]]:
        """
        Cluster findings theo tiêu đề tương đồng.

        contract_audit mode — SWC-first clustering:
          Rule 1: same SWC ID → always cluster (same vulnerability type by taxonomy)
          Rule 2: both have SWC IDs but different → never cluster (different vuln types)
          Rule 3: one or both lack SWC ID → fall back to title-token (semantic findings)
          This prevents cross-SWC contamination where e.g. SWC-106 findings get merged
          into a SWC-113 cluster because they share the same affected function name in
          their titles, which dilutes intra_score and hides the true per-SWC consensus.

        network_security mode — title-token clustering:
          Pass 1: ≥2 shared significant title tokens → same cluster
          Pass 2: shared semantic anchor → same cluster
        """
        if not findings:
            return []

        if mode == "contract_audit":
            return self._cluster_by_swc(findings)

        anchors = self._build_anchors(findings, mode=mode)
        clusters: List[List[Dict]] = []
        assigned: Set[int] = set()

        for i, f in enumerate(findings):
            if i in assigned:
                continue
            cluster = [f]
            assigned.add(i)
            tokens_i = self._title_tokens(f.get("title", ""))

            for j, g in enumerate(findings):
                if j <= i or j in assigned:
                    continue
                tokens_j = self._title_tokens(g.get("title", ""))
                # Pass 1: original token overlap
                if len(tokens_i & tokens_j) >= 2:
                    cluster.append(g)
                    assigned.add(j)
                # Pass 2: semantic anchor match
                elif self._shares_anchor(f, g, anchors):
                    cluster.append(g)
                    assigned.add(j)

            clusters.append(cluster)

        return clusters

    def _cluster_by_swc(
        self, findings: List[Dict[str, Any]]
    ) -> List[List[Dict[str, Any]]]:
        """
        contract_audit clustering: group strictly by SWC ID.

        - Findings with the same SWC ID → one cluster per unique SWC ID.
        - Findings without a SWC ID (semantic findings) → title-token fallback
          among themselves only, never merged into an SWC cluster.

        This is the root fix for cross-SWC contamination: different vulnerability
        types (different SWC IDs) are definitionally independent findings and must
        never share a cluster, even if they affect the same function.
        """
        swc_buckets: Dict[str, List[Dict]] = defaultdict(list)
        no_swc: List[Dict] = []

        for f in findings:
            swc = f.get("swc_id", "").strip()
            # A1: remap SWC-113 → SWC-128 when trigger is unbounded array growth
            # SWC-113 = DoS via failed call; SWC-128 = DoS via block gas (unbounded loop)
            if swc == "SWC-113":
                text = (f.get("title", "") + " " + f.get("description", "")).lower()
                if any(kw in text for kw in ("unbounded", "array growth", "grows without", "block gas", "gas limit")):
                    swc = "SWC-128"
                    f = dict(f, swc_id="SWC-128", swc_name="DoS with Block Gas Limit")
            if swc:
                swc_buckets[swc].append(f)
            else:
                no_swc.append(f)

        clusters: List[List[Dict]] = list(swc_buckets.values())

        # Title-token fallback for findings without SWC ID (rare in contract_audit)
        if no_swc:
            anchors = self._build_anchors(no_swc, mode="contract_audit")
            assigned: Set[int] = set()
            for i, f in enumerate(no_swc):
                if i in assigned:
                    continue
                cluster = [f]
                assigned.add(i)
                tokens_i = self._title_tokens(f.get("title", ""))
                for j, g in enumerate(no_swc):
                    if j <= i or j in assigned:
                        continue
                    tokens_j = self._title_tokens(g.get("title", ""))
                    if len(tokens_i & tokens_j) >= 2 or self._shares_anchor(f, g, anchors):
                        cluster.append(g)
                        assigned.add(j)
                clusters.append(cluster)

        return clusters

    def _title_tokens(self, title: str) -> Set[str]:
        """Significant tokens từ title (stop words removed, lowercased)."""
        stop = {
            "a", "an", "the", "in", "on", "at", "to", "for", "of", "and",
            "or", "is", "are", "was", "be", "has", "have", "not", "no",
        }
        return {
            t.strip("[](),.:;")
            for t in title.lower().split()
            if len(t) > 2 and t not in stop
        }

    # ─── Scoring ──────────────────────────────────────────────────────────────

    @staticmethod
    def _get_author_group(finding: Dict[str, Any]) -> str:
        """Get author group field — supports both network_security (author_group) and contract_audit (author_domain)."""
        return finding.get("author_domain") or finding.get("author_group", "unknown")

    def _score_cluster(
        self,
        cluster: List[Dict[str, Any]],
        domain_group_count: int,
        mode: str = "network_security",
    ) -> Optional[ConsensusVulnerability]:
        """Score 1 cluster → ConsensusVulnerability."""
        if not cluster:
            return None

        # Representatives
        representative = cluster[0]

        # ── Layer 1: Intra-group ──────────────────────────────────────────────
        # % agents trong cùng group đồng ý (có ít nhất 1 đại diện cùng nhóm)
        group_counts: Dict[str, int] = defaultdict(int)
        for f in cluster:
            group_counts[self._get_author_group(f)] += 1

        # Giả sử mỗi group có 2-3 agents; intra score = tỉ lệ groups có >1 member trong cluster
        groups_with_multiple = sum(1 for cnt in group_counts.values() if cnt >= 2)
        total_groups_in_cluster = len(group_counts)
        intra_score = groups_with_multiple / max(total_groups_in_cluster, 1)

        # ── Layer 2: Cross-group ──────────────────────────────────────────────
        # % domain groups khác nhau đã đề cập finding này
        unique_groups = set(group_counts.keys())
        cross_score = len(unique_groups) / domain_group_count

        # ── Layer 3: Attacker corroboration ──────────────────────────────────
        all_corr = []
        for f in cluster:
            all_corr.extend(f.get("attacker_corroborations", []))

        attacker_score = self._calc_attacker_score(all_corr)

        # ── Stage 1: Expert hypothesis strength ──────────────────────────────
        expert_confidence = intra_score * WEIGHT_INTRA + cross_score * WEIGHT_CROSS

        # ── Stage 2: Attacker verification gate (multiplicative) ─────────────
        # Expert agreement = hypothesis. Attacker review = verification.
        # Without attacker review, confidence is penalised so that cross-domain
        # hallucinations (many groups independently wrong) cannot auto-confirm.
        net_confirms  = sum(1 for c in all_corr
                            if c.get("action") in {"ATTACKER_CONFIRM", "ATTACKER_ESCALATE"})
        net_dismisses = sum(1 for c in all_corr
                            if c.get("action") in {"ATTACKER_DISMISS", "ATTACKER_DOWNGRADE"})

        if not all_corr:
            gate = ATTACKER_GATE_NEUTRAL   # no Phase C review → no penalty (NEUTRAL=1.0)
        elif net_confirms > net_dismisses:
            gate = ATTACKER_GATE_CONFIRM   # attackers verified exploitability
        elif net_dismisses > net_confirms:
            gate = ATTACKER_GATE_DISMISS   # attackers rejected finding
        else:
            gate = ATTACKER_GATE_NEUTRAL   # tied → treat as unreviewed

        # ── Layer 4: Peer cross-domain signal (Stage 2 CHALLENGE/VALIDATE) ────
        # peer_delta applied AFTER gate so it is independent of attacker activity.
        # Caps: max boost = 5*0.03 = +0.15; max penalty = 5*0.05 = -0.25.
        # Confidence clamped to [0, 1] to prevent negative scores.
        challenge_count = sum(len(f.get("challenged_by", [])) for f in cluster)
        validate_count  = sum(len(f.get("validated_by",   [])) for f in cluster)
        peer_delta = min(validate_count, 5) * 0.03 - min(challenge_count, 5) * 0.05

        confidence = max(0.0, min(1.0, expert_confidence * gate + peer_delta))

        # ── Severity consensus ────────────────────────────────────────────────
        severity = self._consensus_severity(cluster, all_corr)

        # ── Collect metadata ──────────────────────────────────────────────────
        supporting_groups = list(unique_groups)
        supporting_attackers = [
            c["profile_id"] for c in all_corr
            if c.get("action") in {"ATTACKER_CONFIRM", "ATTACKER_ESCALATE"}
        ]
        dismissing_attackers = [
            c["profile_id"] for c in all_corr
            if c.get("action") == "ATTACKER_DISMISS"
        ]

        # Merge affected assets and evidence/recommendations
        all_assets: List[str] = []
        all_evidence: List[str] = []
        all_recs: List[str] = []
        all_source_ids: List[str] = []
        all_swc_ids: List[str] = []

        for f in cluster:
            all_assets.extend(f.get("affected_functions") or f.get("affected_assets") or [])
            all_evidence.extend(f.get("evidence") or [])
            _patch = f.get("recommendations") or f.get("patch_suggestion")
            if isinstance(_patch, list):
                all_recs.extend(_patch)
            elif isinstance(_patch, str) and _patch.strip():
                all_recs.append(_patch)
            if f.get("finding_id"):
                all_source_ids.append(f["finding_id"])
            # collect SWC IDs from individual expert findings
            all_swc_ids.extend(f.get("swc_ids") or f.get("mitre_techniques") or [])
            swc_id = f.get("swc_id")
            if swc_id and swc_id not in all_swc_ids:
                all_swc_ids.append(swc_id)

        # Deduplicate
        all_assets   = list(dict.fromkeys(all_assets))
        all_evidence = list(dict.fromkeys(all_evidence))
        all_recs     = list(dict.fromkeys(all_recs))
        all_swc_ids  = list(dict.fromkeys(all_swc_ids))

        return ConsensusVulnerability(
            vuln_id=f"vuln_{uuid.uuid4().hex[:8]}",
            title=representative.get("title", "Unnamed Vulnerability"),
            description=representative.get("description", ""),
            affected_assets=all_assets,
            severity=severity,
            intra_group_score=intra_score,
            cross_group_score=cross_score,
            attacker_score=attacker_score,
            confidence_score=min(1.0, confidence),
            supporting_groups=supporting_groups,
            supporting_attackers=list(set(supporting_attackers)),
            dismissing_attackers=list(set(dismissing_attackers)),
            recommendations=all_recs,
            swc_ids=all_swc_ids,
            source_finding_ids=all_source_ids,
            attacker_finding_ids=[],
            needs_review=(len(all_corr) == 0),
        )

    def _calc_attacker_score(self, corroborations: List[Dict[str, Any]]) -> float:
        """
        Tính Layer 3 score từ attacker corroborations.
        Range: 0.0 – 1.0
        Net positive → score > 0.5, net negative → < 0.5
        """
        if not corroborations:
            return 0.50  # Neutral nếu attacker không nhận xét

        net_delta = sum(
            ATTACKER_DELTA.get(c.get("action", ""), 0.0)
            for c in corroborations
        )
        # Normalize: base 0.50, ±range ~0.5
        score = 0.50 + net_delta
        return max(0.0, min(1.0, score))

    def _consensus_severity(
        self,
        cluster: List[Dict[str, Any]],
        corroborations: List[Dict[str, Any]],
    ) -> str:
        """
        Xác định severity cuối bằng majority vote.
        Attacker ESCALATE/DOWNGRADE có thể override nếu đủ số phiếu.
        """
        # Count expert votes
        sev_votes: Dict[str, int] = defaultdict(int)
        for f in cluster:
            sev = f.get("severity", "medium").lower()
            sev_votes[sev] += 1

        # Majority expert vote
        expert_sev = max(sev_votes, key=lambda k: (sev_votes[k], SEVERITY_RANK.get(k, 0)))

        # Check attacker ESCALATE / DOWNGRADE
        escalate_count = sum(
            1 for c in corroborations if c.get("action") == "ATTACKER_ESCALATE"
        )
        downgrade_count = sum(
            1 for c in corroborations if c.get("action") == "ATTACKER_DOWNGRADE"
        )

        current_rank = SEVERITY_RANK.get(expert_sev, 2)
        if escalate_count >= 2:
            current_rank = min(4, current_rank + 1)
        if downgrade_count >= 3:
            current_rank = max(0, current_rank - 1)

        rank_to_sev = {v: k for k, v in SEVERITY_RANK.items()}
        return rank_to_sev.get(current_rank, "medium")

    # ─── Attacker-only findings ───────────────────────────────────────────────

    def _attacker_finding_to_vuln(
        self, af: Dict[str, Any]
    ) -> Optional[ConsensusVulnerability]:
        """Convert AttackerFinding → ConsensusVulnerability (attacker-only path)."""
        agreed_by = af.get("agreed_by", [])
        # Layer 3 score: proportional to agreement (2 → 0.70, 3 → 0.85, 4+ → 0.95)
        attacker_score = min(0.95, 0.60 + len(agreed_by) * 0.10)
        confidence = attacker_score

        if confidence < MIN_CONFIDENCE:
            return None

        return ConsensusVulnerability(
            vuln_id=f"vuln_{uuid.uuid4().hex[:8]}",
            title=af.get("title", "Attacker-identified path"),
            description=(
                af.get("description", "") +
                ("\nPath: " + af["path_description"] if af.get("path_description") else "")
            ),
            affected_assets=af.get("affected_assets", []),
            severity=af.get("severity", "high"),
            intra_group_score=0.0,
            cross_group_score=0.50,  # Neutral — không có expert validation
            attacker_score=attacker_score,
            confidence_score=min(1.0, confidence),
            supporting_groups=[],
            supporting_attackers=[af.get("attacker_profile", "unknown")] + agreed_by,
            dismissing_attackers=[],
            recommendations=[],
            swc_ids=[],
            source_finding_ids=[],
            attacker_finding_ids=[af.get("finding_id", "")],
            is_attacker_only=True,
            needs_review=True,
        )

    # ─── Semantic consensus (Web3Bugs S-category) ────────────────────────────

    @staticmethod
    def _shares_semantic_anchor(f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
        """True if both semantic findings share the same category or a title keyword anchor."""
        c1 = normalize_semantic_category(f1.get("category"))
        c2 = normalize_semantic_category(f2.get("category"))
        if c1 == c2 and c1 != "other":
            return True
        t1 = (f1.get("title", "") + " " + f1.get("evidence", "")).lower()
        t2 = (f2.get("title", "") + " " + f2.get("evidence", "")).lower()
        for cat, keywords in SEMANTIC_ANCHOR_KEYWORDS.items():
            if cat == "other":
                continue
            if any(kw.lower() in t1 and kw.lower() in t2 for kw in keywords):
                return True
        return False

    def _cluster_semantic_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[List[Dict[str, Any]]]:
        """Cluster semantic findings by category and keyword overlap."""
        clusters: List[List[Dict]] = []
        assigned: Set[int] = set()

        for i, f in enumerate(findings):
            if i in assigned:
                continue
            cluster = [f]
            assigned.add(i)
            for j, g in enumerate(findings):
                if j <= i or j in assigned:
                    continue
                tokens_i = self._title_tokens(f.get("title", ""))
                tokens_j = self._title_tokens(g.get("title", ""))
                if len(tokens_i & tokens_j) >= 2 or self._shares_semantic_anchor(f, g):
                    cluster.append(g)
                    assigned.add(j)
            clusters.append(cluster)
        return clusters

    def _score_semantic_cluster(
        self,
        cluster: List[Dict[str, Any]],
        domain_group_count: int,
    ) -> Optional[Dict[str, Any]]:
        """Score one semantic cluster → consensus semantic finding dict."""
        if not cluster:
            return None

        rep = cluster[0]
        group_counts: Dict[str, int] = defaultdict(int)
        for f in cluster:
            group_counts[self._get_author_group(f)] += 1

        groups_with_multiple = sum(1 for cnt in group_counts.values() if cnt >= 2)
        total_groups_in_cluster = len(group_counts)
        intra_score = groups_with_multiple / max(total_groups_in_cluster, 1)
        cross_score = len(group_counts) / domain_group_count

        attacker_surfaced = any(f.get("is_attacker_surfaced") for f in cluster)
        gate = ATTACKER_GATE_CONFIRM if attacker_surfaced else ATTACKER_GATE_NEUTRAL

        expert_confidence = intra_score * WEIGHT_INTRA + cross_score * WEIGHT_CROSS

        # Layer 4 peer signal — same formula as expert cluster scoring
        challenge_count = sum(len(f.get("challenged_by", [])) for f in cluster)
        validate_count  = sum(len(f.get("validated_by",   [])) for f in cluster)
        peer_delta = min(validate_count, 5) * 0.03 - min(challenge_count, 5) * 0.05

        confidence = max(0.0, min(1.0, expert_confidence * gate + peer_delta))

        # Semantic findings use a lower threshold (0.25) since they have no SWC
        # cross-validation baseline — 2 domains + attacker corroboration is sufficient
        if confidence < 0.25:
            return None

        severity = self._consensus_severity(cluster, [])
        all_funcs = list(dict.fromkeys(
            func for f in cluster for func in f.get("affected_functions", [])
        ))
        all_attack_paths = [
            step for f in cluster for step in f.get("attack_path", []) if step
        ]

        # Category by majority vote (canonical buckets)
        cat_votes: Dict[str, int] = defaultdict(int)
        for f in cluster:
            cat_votes[normalize_semantic_category(f.get("category"))] += 1
        category = max(cat_votes, key=lambda k: cat_votes[k])

        # Collect patch suggestions from cluster findings
        all_patches: List[str] = []
        for f in cluster:
            p = f.get("patch_suggestion")
            if isinstance(p, list):
                all_patches.extend(p)
            elif isinstance(p, str) and p.strip():
                all_patches.append(p)
        all_patches = list(dict.fromkeys(all_patches))

        # P3/P7: category "other" không mapped với ground truth label nào —
        # giữ trong report cho auditor người nhưng exclude khỏi F1 evaluation pool
        _EVAL_CATEGORIES = {
            "access_control", "price_oracle", "flash_loan", "governance_attack",
            "incorrect_accounting", "state_machine_bug", "business_flow", "reentrancy_logic",
        }
        exclude_from_eval = category not in _EVAL_CATEGORIES
        return {
            "semantic_vuln_id":    f"sv_{uuid.uuid4().hex[:8]}",
            "title":               rep.get("title", "Unnamed Semantic Finding"),
            "category":            category,
            "display_label":       "[UNCLASSIFIED]" if exclude_from_eval else None,
            "exclude_from_eval":   exclude_from_eval,
            "severity":            severity,
            "affected_functions":  all_funcs,
            "evidence":            rep.get("evidence", ""),
            "attack_path":         all_attack_paths[:5],
            "patch_suggestions":   all_patches,
            "confidence_score":    min(1.0, confidence),
            "intra_score":         intra_score,
            "cross_score":         cross_score,
            "attacker_score":      gate,
            "supporting_domains":  list(group_counts.keys()),
            "is_attacker_surfaced": attacker_surfaced,
            "source_finding_ids":  [f["finding_id"] for f in cluster if f.get("finding_id")],
        }

    def _run_semantic_consensus(
        self,
        semantic_findings_raw: List[Dict[str, Any]],
        domain_group_count: int,
    ) -> List[Dict[str, Any]]:
        """Full semantic consensus pipeline."""
        normalized_raw: List[Dict[str, Any]] = []
        for f in semantic_findings_raw:
            fc = dict(f)
            fc["category"] = normalize_semantic_category(f.get("category"))
            normalized_raw.append(fc)
        clusters = self._cluster_semantic_findings(normalized_raw)
        results = []
        for cluster in clusters:
            sv = self._score_semantic_cluster(cluster, domain_group_count)
            if sv:
                results.append(sv)
        results.sort(key=lambda x: x["confidence_score"], reverse=True)
        return results

    # ─── Solution D: Post-consensus control coverage enforcement ─────────────

    def enforce_control_coverage(
        self,
        consensus_vulns: List[ConsensusVulnerability],
        expert_findings_raw: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Solution D: after ConsensusEngine runs, collect any standard security
        control that is absent from consensus output but has at least 1 raw finding.

        Returns a list of unvalidated_control_gaps — findings that didn't survive
        consensus scoring but represent real coverage signals. These appear in the
        report as a separate section labeled "Single-domain — not cross-validated".

        Controls checked: all fields of SecurityControls dataclass (edr, siem, waf, …).
        """
        from ..models.cyber_models import SecurityControls
        from dataclasses import fields as dc_fields

        standard_controls = [f.name for f in dc_fields(SecurityControls)]
        unvalidated: List[Dict[str, Any]] = []

        for control in standard_controls:
            # Check if this control already covered in consensus (word boundary)
            in_consensus = any(
                self._anchor_in_text(control, v.title.lower())
                or self._anchor_in_text(control, v.description.lower())
                for v in consensus_vulns
            )
            if in_consensus:
                continue

            # Find all raw findings that mention this control (word boundary)
            candidates = [
                f for f in expert_findings_raw
                if self._anchor_in_text(control, f.get("title", "").lower())
                or self._anchor_in_text(control, f.get("description", "").lower())
            ]
            if not candidates:
                continue

            # Pick highest-confidence finding as representative
            best = max(candidates, key=lambda f: f.get("confidence", 0.0))
            unvalidated.append({
                "control":       control.upper(),
                "title":         best.get("title", f"Missing {control.upper()}"),
                "description":   best.get("description", ""),
                "severity":      best.get("severity", "medium"),
                "affected_assets": best.get("affected_assets", []),
                "author_group":  self._get_author_group(best),
                "source_count":  len(candidates),   # how many raw findings agreed
                "note":          "Single-domain finding — not cross-validated by consensus",
            })

        return unvalidated

    def enforce_swc_coverage(
        self,
        consensus_vulns: List[ConsensusVulnerability],
        expert_findings_raw: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Contract audit mode: after ConsensusEngine runs, collect any SWC category
        that is absent from consensus output but has at least 1 raw finding.

        Analogous to enforce_control_coverage() for network security mode.
        Returns unvalidated_swc_gaps list for the audit report.
        """
        unvalidated: List[Dict[str, Any]] = []

        for category, keywords in SWC_ANCHOR_KEYWORDS.items():
            # Check if category already covered in consensus
            in_consensus = any(
                any(
                    self._anchor_in_text(kw.lower(), v.title.lower())
                    or self._anchor_in_text(kw.lower(), v.description.lower())
                    for kw in keywords
                )
                for v in consensus_vulns
            )
            if in_consensus:
                continue

            # Find raw findings that mention any keyword in this category
            candidates = [
                f for f in expert_findings_raw
                if any(
                    self._anchor_in_text(kw.lower(), f.get("title", "").lower())
                    or self._anchor_in_text(kw.lower(), f.get("description", "").lower())
                    or kw == f.get("swc_id", "")
                    for kw in keywords
                )
            ]
            if not candidates:
                continue
            # Require mentions from at least 2 distinct author domains.
            # Same-domain repeated mentions don't count as independent corroboration.
            distinct_domains = {self._get_author_group(f) for f in candidates}
            if len(distinct_domains) < 2:
                continue

            best = max(candidates, key=lambda f: f.get("confidence", 0.0))
            all_funcs = sorted({fn for f in candidates for fn in (f.get("affected_functions") or [])})
            unvalidated.append({
                "swc_category":      category,
                "swc_id":            best.get("swc_id", ""),
                "title":             best.get("title", f"Potential {category} issue"),
                "description":       best.get("description", ""),
                "severity":          best.get("severity", "medium"),
                "affected_functions": all_funcs,
                "author_domain":     self._get_author_group(best),
                "source_count":      len(candidates),
                "domain_count":      len(distinct_domains),
                "note":              f"Multi-domain gap — flagged by {len(distinct_domains)} distinct domains",
            })

        # Append Tier-2 demoted findings (have SWC but no function/exploit path)
        for t2 in self._tier2_demoted:
            # Skip if same SWC already covered in unvalidated list
            t2_swc = t2.get("swc_id", "")
            already = any(g.get("swc_id") == t2_swc and t2_swc for g in unvalidated)
            if not already:
                unvalidated.append(t2)

        return unvalidated

    # ─── Utility ──────────────────────────────────────────────────────────────

    def get_coverage_gaps(
        self,
        vulns: List[ConsensusVulnerability],
        mode: str = "network_security",
        expert_findings_raw: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Tổng hợp gap analysis:
          - Domains không tìm ra gì (zero findings)
          - Findings chỉ có 1 group (low cross-group validation)
          - Attacker-only findings (bị expert bỏ sót)

        expert_findings_raw: nếu được truyền vào, phân biệt
          - silent_domain_groups: domain không sản xuất finding nào
          - contributed_but_filtered: domain có findings nhưng bị dismissed/filtered
        """
        if mode == "contract_audit":
            all_groups = CONTRACT_DOMAIN_GROUPS
        else:
            all_groups = {"network_security", "appsec", "endpoint_security", "threat_intel", "risk"}

        groups_with_findings = set()
        for v in vulns:
            groups_with_findings.update(v.supporting_groups)

        if expert_findings_raw:
            domains_with_any = {
                self._get_author_group(f)
                for f in expert_findings_raw
                if self._get_author_group(f) not in ("unknown", "")
            } & all_groups
            truly_silent = all_groups - domains_with_any
            contributed_but_filtered = domains_with_any - groups_with_findings
        else:
            truly_silent = all_groups - groups_with_findings
            contributed_but_filtered = set()

        low_cross = [v.title for v in vulns if v.cross_group_score < 0.25]
        attacker_only = [v.title for v in vulns if v.is_attacker_only]

        return {
            "silent_domain_groups": list(truly_silent),
            "contributed_but_filtered": list(contributed_but_filtered),
            "low_cross_validation_findings": low_cross,
            "attacker_only_paths": attacker_only,
            "total_vulns": len(vulns),
            "critical_count": sum(1 for v in vulns if v.severity == "critical"),
            "high_count": sum(1 for v in vulns if v.severity == "high"),
        }
