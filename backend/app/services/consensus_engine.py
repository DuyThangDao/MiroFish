"""
Consensus Engine — Multi-Expert Panel (Direction B)

3-layer weighted consensus scoring:
  Layer 1 — Intra-group agreement   weight: 0.30
  Layer 2 — Cross-group validation  weight: 0.45  (highest — prevents group bias)
  Layer 3 — Attacker corroboration  weight: 0.25

Final confidence = L1×0.30 + L2×0.45 + L3×0.25
Filter: confidence < 0.35 → discard (likely false positive)
"""

import uuid
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict

from ..models.cyber_models import (
    ExpertFinding, AttackerFinding, AttackerCorroboration,
    ConsensusVulnerability, SeverityLevel
)
from ..utils.logger import get_logger

logger = get_logger("mirofish.consensus_engine")

# ─── Weights ──────────────────────────────────────────────────────────────────
WEIGHT_INTRA  = 0.30   # Layer 1
WEIGHT_CROSS  = 0.45   # Layer 2
WEIGHT_ATTACK = 0.25   # Layer 3

MIN_CONFIDENCE = 0.35  # Below this → discard as likely FP

# Attacker action → confidence delta (applied on top of layer scores)
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
    5. Final = weighted sum
    6. Filter < MIN_CONFIDENCE
    7. Merge attacker-only findings với base confidence 0.60
    """

    def run(
        self,
        expert_findings_raw: List[Dict[str, Any]],
        attacker_findings_raw: List[Dict[str, Any]],
        domain_group_count: int = 5,
    ) -> List[ConsensusVulnerability]:
        """
        Run full consensus pipeline.

        Args:
            expert_findings_raw: serialized ExpertFinding dicts từ session
            attacker_findings_raw: serialized AttackerFinding dicts từ session
            domain_group_count: số domain groups (default 5)

        Returns:
            Sorted list ConsensusVulnerability (highest confidence first)
        """
        # ── Step 1: Cluster expert findings ──────────────────────────────────
        clusters = self._cluster_findings(expert_findings_raw)

        # ── Step 2–4: Score each cluster ─────────────────────────────────────
        vulns: List[ConsensusVulnerability] = []
        for cluster in clusters:
            vuln = self._score_cluster(cluster, domain_group_count)
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

        logger.info(
            f"Consensus: {len(expert_findings_raw)} expert findings + "
            f"{len(attacker_findings_raw)} attacker findings → "
            f"{len(vulns)} consensus vulnerabilities"
        )
        return vulns

    # ─── Clustering ───────────────────────────────────────────────────────────

    def _cluster_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[List[Dict[str, Any]]]:
        """
        Cluster findings theo tiêu đề tương đồng.
        Simple approach: normalize title → shared keyword token matching.
        Findings chia sẻ ≥ 2 significant tokens → cùng cluster.
        """
        if not findings:
            return []

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
                overlap = tokens_i & tokens_j
                if len(overlap) >= 2:
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

    def _score_cluster(
        self,
        cluster: List[Dict[str, Any]],
        domain_group_count: int,
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
            group_counts[f.get("author_group", "unknown")] += 1

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

        # ── Final weighted score ──────────────────────────────────────────────
        confidence = (
            intra_score  * WEIGHT_INTRA
            + cross_score  * WEIGHT_CROSS
            + attacker_score * WEIGHT_ATTACK
        )

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
        all_mitre: List[str] = []

        for f in cluster:
            all_assets.extend(f.get("affected_assets", []))
            all_evidence.extend(f.get("evidence", []))
            all_recs.extend(f.get("recommendations", []))
            if f.get("finding_id"):
                all_source_ids.append(f["finding_id"])
            all_mitre.extend(f.get("mitre_techniques", []))

        # Deduplicate
        all_assets  = list(dict.fromkeys(all_assets))
        all_evidence= list(dict.fromkeys(all_evidence))
        all_recs    = list(dict.fromkeys(all_recs))
        all_mitre   = list(dict.fromkeys(all_mitre))

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
            mitre_techniques=all_mitre,
            source_finding_ids=all_source_ids,
            attacker_finding_ids=[],
            needs_review=(MIN_CONFIDENCE <= confidence < 0.50),
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
        confidence = attacker_score * WEIGHT_ATTACK + 0.50 * WEIGHT_CROSS + 0.0 * WEIGHT_INTRA

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
            mitre_techniques=[],
            source_finding_ids=[],
            attacker_finding_ids=[af.get("finding_id", "")],
            is_attacker_only=True,
            needs_review=True,
        )

    # ─── Utility ──────────────────────────────────────────────────────────────

    def get_coverage_gaps(
        self, vulns: List[ConsensusVulnerability]
    ) -> Dict[str, Any]:
        """
        Tổng hợp gap analysis:
          - Domains không tìm ra gì (zero findings)
          - Findings chỉ có 1 group (low cross-group validation)
          - Attacker-only findings (bị expert bỏ sót)
        """
        all_groups = {"network_security", "appsec", "endpoint_security", "threat_intel", "risk"}
        groups_with_findings = set()
        for v in vulns:
            groups_with_findings.update(v.supporting_groups)

        silent_groups = all_groups - groups_with_findings
        low_cross = [v.title for v in vulns if v.cross_group_score < 0.25]
        attacker_only = [v.title for v in vulns if v.is_attacker_only]

        return {
            "silent_domain_groups": list(silent_groups),
            "low_cross_validation_findings": low_cross,
            "attacker_only_paths": attacker_only,
            "total_vulns": len(vulns),
            "critical_count": sum(1 for v in vulns if v.severity == "critical"),
            "high_count": sum(1 for v in vulns if v.severity == "high"),
        }
