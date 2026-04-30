"""
Contract Audit Report Agent — Đề tài 10 (Smart Contract Audit).

ReACT pattern agent tổng hợp audit report từ:
  - ConsensusVulnerability list (output của ConsensusEngine với mode="contract_audit")
  - ContractFinding dicts từ session (expert + attacker)
  - Contract KG summary từ Zep
  - SWC Registry cho patch suggestions

Output: structured 6-section audit report với severity breakdown,
exploitability status (per attacker validation), và patch suggestions.

Pattern: Thought → ACTION: tool_name({args}) → OBSERVATION: ... → FINAL_ANSWER:
Tương tự VulnReportAgent — đổi domain context sang smart contract.
"""

import os
import json
import threading
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import asdict

from ..config import Config
from ..models.task import TaskManager, TaskStatus
from ..models.cyber_models import ConsensusVulnerability
from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger
from .consensus_engine import ConsensusEngine

logger = get_logger("mirofish.contract_audit_agent")


# ─── Tool specification ───────────────────────────────────────────────────────

TOOLS_SPEC = """You have access to the following tools:

[get_top_vulnerabilities]
  Description: Get top N vulnerabilities sorted by confidence score (3-layer consensus)
  Args: { "limit": <int, default 10> }

[get_critical_findings]
  Description: Get all findings with severity critical or high, with evidence and SWC IDs
  Args: {}

[get_exploitable_findings]
  Description: Get findings that were confirmed exploitable by attacker profiles (Phase C)
  Args: {}

[get_attacker_profile_breakdown]
  Description: Show which findings each attacker profile confirmed/dismissed/escalated
  Args: { "profile": <"reentrancy_exploiter"|"flash_loan_attacker"|"governance_attacker"|"access_control_exploiter"|"logic_exploiter"|"all"> }

[get_attacker_only_findings]
  Description: Get attack paths found ONLY by attacker profiles (expert agents missed them)
  Args: {}

[get_patch_suggestions]
  Description: Get patch recommendations for top vulnerabilities, grouped by SWC category
  Args: { "severity": <"critical"|"high"|"medium"|"all", default "all"> }

[get_swc_breakdown]
  Description: Group vulnerabilities by SWC ID with counts and severity distribution
  Args: {}

[get_defi_specific_risks]
  Description: Get DeFi-specific risks: flash loan, oracle manipulation, governance attacks
  Args: {}

[get_findings_by_domain]
  Description: Get all findings contributed by a specific domain group
  Args: { "domain": <"appsec"|"blockchain"|"cryptography"|"defi"|"governance"|"smart_contract_economics"|"supply_chain"> }

[get_coverage_gaps]
  Description: Show silent domain groups, low-validation findings, and unvalidated SWC categories
  Args: {}

[get_semantic_findings]
  Description: Get business-logic / semantic vulnerabilities (no SWC ID) — Web3Bugs S-category style
  Args: { "category": <"price_oracle"|"flash_loan"|"governance_attack"|"incorrect_accounting"|"state_machine_bug"|"incentive_misalignment"|"reentrancy_logic"|"other"|"all", default "all"> }

Use tools by writing: ACTION: tool_name({"arg": value})
Write final report using: FINAL_ANSWER: <report content>
"""

REPORT_STRUCTURE_SPEC = """Your report MUST include these 6 sections:

## 1. EXECUTIVE SUMMARY
   - Total: X critical, Y high, Z medium vulnerabilities
   - Overall risk level: Critical/High/Medium/Low
   - Top 3 issues requiring immediate action
   - Exploitability verdict (how many confirmed exploitable)

## 2. VULNERABILITY DETAILS
   For each vulnerability:
   - SWC ID + name | Affected function(s) | Severity | Confidence score (3-layer breakdown)
   - Evidence from code | Exploitability status (attacker validated?)
   - Patch suggestion with code example

## 3. ATTACKER PERSPECTIVE
   - Findings confirmed exploitable (ATTACKER_CONFIRM)
   - Findings dismissed as unexploitable (ATTACKER_DISMISS) — note as likely FP
   - New attack paths added by attackers (ATTACKER_ADD_PATH) that experts missed

## 4. EXPERT DISAGREEMENTS
   - Findings with cross-domain disagreement
   - Reason for disagreement (offensive vs defensive perspective)
   - Recommendation given disagreement

## 5. DEFI-SPECIFIC RISKS (if applicable)
   - Flash loan attack paths
   - Oracle manipulation surface
   - Governance attack vectors

## 5B. SEMANTIC / BUSINESS-LOGIC FINDINGS (if any — no SWC ID)
   Use get_semantic_findings tool to retrieve these.
   - Category | Affected function | Severity | Confidence
   - Evidence | Step-by-step attack path
   - Note: these vulnerabilities have no SWC ID — they represent protocol design flaws

## 6. REMEDIATION ROADMAP
   - Immediate (critical): fix before deployment
   - Short-term (high): fix within 2 weeks
   - Long-term (medium): fix within 1 month
   Include code-level patch example for critical and high severity issues.

Confidence labels:
  [CONFIRMED] = cross-domain + attacker validated
  [EXPERT ONLY] = domain experts agree, attacker not yet validated
  [ATTACKER SURFACED] = attacker ADD_PATH, experts missed
  [DISPUTED] = cross-domain disagreement present

Be specific — reference actual function names, SWC IDs, and code patterns."""


def _build_invariant_coverage(
    invariants: List[Dict[str, Any]],
    attacker_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Cross-reference extracted invariants against attacker findings to produce
    invariant_coverage[]: VIOLATED | HOLDS | UNVERIFIED for each invariant.
    """
    violated: Dict[str, Dict[str, Any]] = {}
    for af in attacker_findings:
        inv_id = af.get("invariant_id")
        if inv_id and af.get("source") == "invariant_exploit":
            violated[inv_id] = af

    coverage = []
    for inv in invariants:
        inv_id = inv["id"]
        if inv_id in violated:
            af = violated[inv_id]
            coverage.append({
                "id":          inv_id,
                "statement":   inv.get("statement", ""),
                "status":      "VIOLATED",
                "finding_ref": af.get("finding_id"),
                "attacker":    af.get("attacker_profile"),
            })
        else:
            # HOLDS if experts found no issues with the invariant's functions
            # UNVERIFIED by default — we cannot confirm absence of violation without exploit
            coverage.append({
                "id":        inv_id,
                "statement": inv.get("statement", ""),
                "status":    "UNVERIFIED",
            })
    return coverage


class ContractAuditReportAgent:
    """
    ReACT agent tổng hợp audit report từ contract session kết quả.
    Tương đương VulnReportAgent — adapted cho smart contract domain.
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or LLMClient()
        self.task_manager = TaskManager()
        self.max_iterations = 10

    def generate_report_async(
        self,
        session_id: str,
        expert_findings: List[Dict[str, Any]],
        attacker_findings: List[Dict[str, Any]],
        contract_summary: str,
        graph_id: Optional[str] = None,
        semantic_findings: Optional[List[Dict[str, Any]]] = None,
        invariants: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Generate audit report trong background thread.
        Returns task_id.
        """
        task_id = self.task_manager.create_task(
            task_type="contract_audit_report",
            metadata={"session_id": session_id, "graph_id": graph_id}
        )

        thread = threading.Thread(
            target=self._generate_worker,
            args=(task_id, session_id, expert_findings, attacker_findings,
                  contract_summary, graph_id, semantic_findings, invariants),
            daemon=True
        )
        thread.start()
        return task_id

    def generate_report_sync(
        self,
        session_id: str,
        expert_findings: List[Dict[str, Any]],
        attacker_findings: List[Dict[str, Any]],
        contract_summary: str,
        graph_id: Optional[str] = None,
        semantic_findings: Optional[List[Dict[str, Any]]] = None,
        invariants: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Synchronous version — trả về report dict trực tiếp."""
        engine = ConsensusEngine()
        consensus_vulns, semantic_results = engine.run(
            expert_findings, attacker_findings,
            domain_group_count=7, mode="contract_audit",
            semantic_findings_raw=semantic_findings or [],
        )
        unvalidated_swc_gaps = engine.enforce_swc_coverage(consensus_vulns, expert_findings)

        tool_context = _ContractToolContext(
            consensus_vulns=consensus_vulns,
            expert_findings=expert_findings,
            attacker_findings=attacker_findings,
            unvalidated_swc_gaps=unvalidated_swc_gaps,
            semantic_results=semantic_results,
        )

        report_text = self._run_react_loop(
            contract_summary=contract_summary,
            tool_context=tool_context,
        )

        coverage_gaps = engine.get_coverage_gaps(consensus_vulns, mode="contract_audit", expert_findings_raw=expert_findings)
        invariant_coverage = _build_invariant_coverage(invariants or [], attacker_findings)

        return {
            "session_id":          session_id,
            "graph_id":            graph_id,
            "generated_at":        datetime.now().isoformat(),
            "report":              report_text,
            "consensus_vulns":     [asdict(v) for v in consensus_vulns],
            "semantic_results":    semantic_results,
            "unvalidated_swc_gaps": unvalidated_swc_gaps,
            "coverage_gaps":       coverage_gaps,
            "invariant_coverage":  invariant_coverage,
            "stats": {
                "total_expert_findings":    len(expert_findings),
                "total_attacker_findings":  len(attacker_findings),
                "total_semantic_findings":  len(semantic_findings or []),
                "consensus_vulns":          len(consensus_vulns),
                "semantic_consensus":       len(semantic_results),
                "unvalidated_swc_gaps":     len(unvalidated_swc_gaps),
                "invariants_extracted":     len(invariants or []),
                "invariants_violated":      sum(
                    1 for ic in invariant_coverage if ic["status"] == "VIOLATED"
                ),
                "critical":  sum(1 for v in consensus_vulns if v.severity == "critical"),
                "high":      sum(1 for v in consensus_vulns if v.severity == "high"),
                "medium":    sum(1 for v in consensus_vulns if v.severity == "medium"),
                "exploitable_count": sum(
                    1 for ef in expert_findings
                    if ef.get("is_exploitable") is True
                ),
            }
        }

    # ─── Worker ───────────────────────────────────────────────────────────────

    def _generate_worker(
        self,
        task_id: str,
        session_id: str,
        expert_findings: List[Dict[str, Any]],
        attacker_findings: List[Dict[str, Any]],
        contract_summary: str,
        graph_id: Optional[str],
        semantic_findings: Optional[List[Dict[str, Any]]] = None,
        invariants: Optional[List[Dict[str, Any]]] = None,
    ):
        try:
            self.task_manager.update_task(
                task_id, status=TaskStatus.PROCESSING,
                progress=10, message="Running consensus engine..."
            )

            result = self.generate_report_sync(
                session_id=session_id,
                expert_findings=expert_findings,
                attacker_findings=attacker_findings,
                contract_summary=contract_summary,
                graph_id=graph_id,
                semantic_findings=semantic_findings,
                invariants=invariants,
            )

            self.task_manager.update_task(task_id, progress=90, message="Saving report...")
            self._save_report(session_id, result)
            self.task_manager.complete_task(task_id, result)

        except Exception as e:
            import traceback
            self.task_manager.fail_task(task_id, f"{e}\n{traceback.format_exc()}")

    # ─── ReACT loop ───────────────────────────────────────────────────────────

    def _run_react_loop(
        self,
        contract_summary: str,
        tool_context: "_ContractToolContext",
    ) -> str:
        """
        Two-phase report generation:
          Phase 1 — data collection: call all tools deterministically in Python.
            No LLM involved. Produces a compact, structured data packet.
          Phase 2 — report writing: single focused LLM call with clean context.
            Input = contract_summary + data packet (~3-4k tokens).
            Output budget = max_tokens - input ≈ 4-5k tokens → enough for full report.

        Replaces the old ReACT loop where tool calls + report writing shared one context
        window, causing the FINAL_ANSWER to be truncated by accumulated message history.
        """
        data_packet = self._collect_report_data(tool_context)
        return self._write_report_from_data(contract_summary, data_packet)

    def _collect_report_data(self, tool_context: "_ContractToolContext") -> str:
        """Call all audit tools in Python and assemble a compact data summary."""
        sections = [
            ("TOP VULNERABILITIES",       "get_top_vulnerabilities",       {"limit": 20}),
            ("EXPLOITABILITY ASSESSMENT", "get_exploitable_findings",       {}),
            ("PATCH SUGGESTIONS",         "get_patch_suggestions",          {"severity": "all"}),
            ("SEMANTIC / LOGIC FINDINGS", "get_semantic_findings",          {"category": "all"}),
            ("ATTACKER PROFILE SUMMARY",  "get_attacker_profile_breakdown", {"profile": "all"}),
            ("SWC BREAKDOWN",             "get_swc_breakdown",              {}),
            ("COVERAGE GAPS",             "get_coverage_gaps",              {}),
        ]
        parts = []
        for title, tool, args in sections:
            result = tool_context.execute(tool, args)
            parts.append(f"=== {title} ===\n{result}")
        return "\n\n".join(parts)

    def _write_report_from_data(self, contract_summary: str, data_packet: str) -> str:
        """Single focused LLM call: contract context + pre-collected data → full report."""
        system_prompt = (
            "You are a senior smart contract security auditor writing a complete audit report.\n"
            "All audit data has been pre-collected and is provided below — do NOT call any tools.\n"
            "Write the complete report in one response covering all 6 sections.\n\n"
            + REPORT_STRUCTURE_SPEC
        )
        user_content = (
            f"CONTRACT CONTEXT:\n{contract_summary}\n\n"
            f"AUDIT DATA:\n{data_packet}\n\n"
            "Write the complete 6-section audit report now. "
            "Cover every vulnerability in Section 2. Include Solidity patch examples for critical/high issues."
        )
        # 16384: gemini-2.5-flash uses extended thinking which consumes output token budget.
        # With 8192, thinking (~6k tokens) + report text (~2k) fills up leaving report truncated.
        # 16384 gives enough headroom for both thinking and a complete 6-section report.
        return self.llm.chat(
            [
                {"role": "system",  "content": system_prompt},
                {"role": "user",    "content": user_content},
            ],
            temperature=0.3,
            max_tokens=16384,
        )

    def _parse_and_execute_action(
        self, text: str, tool_context: "_ContractToolContext"
    ) -> Optional[str]:
        """Parse ACTION: tool_name({args}) → execute → return observation string."""
        import re
        match = re.search(r'ACTION:\s*(\w+)\s*\((\{.*?\}|\{\})\)', text, re.DOTALL)
        if not match:
            match = re.search(r'ACTION:\s*(\w+)\s*\(\)', text)
            if match:
                tool_name = match.group(1)
                args = {}
            else:
                return None
        else:
            tool_name = match.group(1)
            try:
                args = json.loads(match.group(2))
            except json.JSONDecodeError:
                args = {}

        return tool_context.execute(tool_name, args)

    # ─── Persistence ──────────────────────────────────────────────────────────

    def _save_report(self, session_id: str, report_data: Dict[str, Any]):
        """Save report to uploads/contract_reports/<session_id>/report.json"""
        report_dir = os.path.join(Config.UPLOAD_FOLDER, "contract_reports", session_id)
        os.makedirs(report_dir, exist_ok=True)
        path = os.path.join(report_dir, "report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        logger.info(f"Contract audit report saved: {path}")

    @staticmethod
    def load_report(session_id: str) -> Optional[Dict[str, Any]]:
        """Load persisted report. Returns None nếu không tìm thấy."""
        path = os.path.join(
            Config.UPLOAD_FOLDER, "contract_reports", session_id, "report.json"
        )
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


# ─── Tool Context ──────────────────────────────────────────────────────────────

class _ContractToolContext:
    """
    Executes tool calls for ContractAuditReportAgent.
    Holds consensus vulns + raw findings during report generation.
    """

    def __init__(
        self,
        consensus_vulns: List[ConsensusVulnerability],
        expert_findings: List[Dict[str, Any]],
        attacker_findings: List[Dict[str, Any]],
        unvalidated_swc_gaps: List[Dict[str, Any]] = None,
        semantic_results: List[Dict[str, Any]] = None,
    ):
        self.vulns = consensus_vulns
        self.expert_findings = expert_findings
        self.attacker_findings = attacker_findings
        self.unvalidated_swc_gaps = unvalidated_swc_gaps or []
        self.semantic_results = semantic_results or []

    def execute(self, tool_name: str, args: Dict[str, Any]) -> str:
        """Dispatch tool call → return string observation."""
        dispatch = {
            "get_top_vulnerabilities":        self._get_top_vulnerabilities,
            "get_critical_findings":          self._get_critical_findings,
            "get_exploitable_findings":       self._get_exploitable_findings,
            "get_attacker_profile_breakdown": self._get_attacker_profile_breakdown,
            "get_attacker_only_findings":     self._get_attacker_only_findings,
            "get_patch_suggestions":          self._get_patch_suggestions,
            "get_swc_breakdown":              self._get_swc_breakdown,
            "get_defi_specific_risks":        self._get_defi_specific_risks,
            "get_findings_by_domain":         self._get_findings_by_domain,
            "get_coverage_gaps":              self._get_coverage_gaps,
            "get_semantic_findings":          self._get_semantic_findings,
        }
        fn = dispatch.get(tool_name)
        if not fn:
            return f"Unknown tool: '{tool_name}'. Available: {list(dispatch.keys())}"
        try:
            return fn(args)
        except Exception as e:
            return f"Tool error ({tool_name}): {e}"

    def _get_top_vulnerabilities(self, args: Dict) -> str:
        limit = args.get("limit", 10)
        top = self.vulns[:limit]
        if not top:
            return "No consensus vulnerabilities found."
        lines = [f"Top {len(top)} vulnerabilities by confidence:"]
        for v in top:
            swc_ids = ", ".join(v.swc_ids) if v.swc_ids else "unmapped"
            lines.append(
                f"\n[{v.severity.upper()}] {v.title}"
                f"\n  Confidence: {v.confidence_score:.2f} "
                f"(intra:{v.intra_group_score:.2f} cross:{v.cross_group_score:.2f} attack:{v.attacker_score:.2f})"
                f"\n  SWC: {swc_ids}"
                f"\n  Affected: {', '.join(v.affected_assets[:3]) or 'unspecified'}"
                f"\n  Domains: {', '.join(v.supporting_groups)}"
                f"\n  Attacker confirmed: {', '.join(v.supporting_attackers) or 'none'}"
            )
        return "\n".join(lines)

    def _get_critical_findings(self, args: Dict) -> str:
        critical = [v for v in self.vulns if v.severity in {"critical", "high"}]
        if not critical:
            return "No critical or high severity vulnerabilities found."
        lines = [f"Critical/High findings ({len(critical)} total):"]
        for v in critical:
            swc = ", ".join(v.swc_ids) if v.swc_ids else "?"
            lines.append(
                f"\n[{v.severity.upper()}][{swc}] {v.title} — confidence {v.confidence_score:.2f}"
                f"\n  {v.description[:200]}"
                + (" ⚠ Needs review" if v.needs_review else "")
            )
        return "\n".join(lines)

    def _get_exploitable_findings(self, args: Dict) -> str:
        # Findings where attacker profiles confirmed exploitability
        exploitable_vulns = [v for v in self.vulns if v.supporting_attackers]
        exploitable_raw = [
            ef for ef in self.expert_findings
            if ef.get("is_exploitable") is True
        ]
        dismissed_vulns = [v for v in self.vulns if v.dismissing_attackers]

        if not exploitable_vulns and not exploitable_raw:
            return "No findings confirmed exploitable by attacker profiles yet (Phase C may not be complete)."

        lines = [f"Exploitability Assessment:"]
        lines.append(f"\nCONFIRMED EXPLOITABLE ({len(exploitable_vulns)} consensus vulns):")
        for v in exploitable_vulns:
            lines.append(
                f"  [CONFIRMED] [{v.severity.upper()}] {v.title}"
                f"\n    Confirmed by: {', '.join(v.supporting_attackers)}"
            )
        if dismissed_vulns:
            lines.append(f"\nDISMISSED AS UNEXPLOITABLE ({len(dismissed_vulns)} — potential FP):")
            for v in dismissed_vulns:
                lines.append(
                    f"  [DISMISSED] [{v.severity.upper()}] {v.title}"
                    f"\n    Dismissed by: {', '.join(v.dismissing_attackers)}"
                )
        return "\n".join(lines)

    def _get_attacker_profile_breakdown(self, args: Dict) -> str:
        profile_filter = args.get("profile", "all")
        all_profiles = [
            "reentrancy_exploiter", "flash_loan_attacker", "governance_attacker",
            "access_control_exploiter", "logic_exploiter"
        ]
        profiles = all_profiles if profile_filter == "all" else [
            p for p in all_profiles if p == profile_filter
        ]

        lines = ["Attacker profile breakdown:"]
        for profile in profiles:
            confirmed, dismissed, escalated, new_paths = [], [], [], []

            for v in self.vulns:
                if profile in v.supporting_attackers:
                    confirmed.append(v.title)
                if profile in v.dismissing_attackers:
                    dismissed.append(v.title)

            for ef in self.expert_findings:
                for c in ef.get("attacker_corroborations", []):
                    if c.get("profile_id") == profile and c.get("action") == "ATTACKER_ESCALATE":
                        escalated.append(ef.get("title", "?"))

            for af in self.attacker_findings:
                if af.get("attacker_profile") == profile:
                    new_paths.append(af.get("title", "?"))

            lines.append(f"\n[{profile.upper()}]")
            lines.append(f"  Confirmed: {', '.join(confirmed) or 'none'}")
            lines.append(f"  Dismissed: {', '.join(dismissed) or 'none'}")
            lines.append(f"  Escalated: {', '.join(escalated) or 'none'}")
            lines.append(f"  New paths: {', '.join(new_paths) or 'none'}")

        return "\n".join(lines)

    def _get_attacker_only_findings(self, args: Dict) -> str:
        only = [v for v in self.vulns if v.is_attacker_only]
        raw_new = [af for af in self.attacker_findings]
        if not only and not raw_new:
            return "No attacker-only findings — experts covered all paths."
        lines = ["Findings discovered only by attacker profiles (expert agents missed):"]
        for v in only:
            lines.append(
                f"\n[ATTACKER SURFACED][{v.severity.upper()}] {v.title}"
                f"\n  Found by: {', '.join(v.supporting_attackers)}"
                f"\n  {v.description[:200]}"
            )
        for af in raw_new[:5]:
            lines.append(
                f"\n[ADD_PATH] {af.get('title','?')} — by {af.get('attacker_profile','?')}"
                f"\n  {af.get('description','')[:150]}"
            )
        return "\n".join(lines)

    def _get_patch_suggestions(self, args: Dict) -> str:
        severity_filter = args.get("severity", "all")

        # Collect patch suggestions from expert findings
        patches = []
        for ef in self.expert_findings:
            sev = ef.get("severity", "medium")
            if severity_filter != "all" and sev != severity_filter:
                continue
            patch = ef.get("patch_suggestion")
            if patch:
                patches.append({
                    "title": ef.get("title", "?"),
                    "swc_id": ef.get("swc_id", "?"),
                    "severity": sev,
                    "affected_functions": ef.get("affected_functions", []),
                    "patch": patch,
                })

        # Also from consensus vulns recommendations
        for v in self.vulns:
            if severity_filter != "all" and v.severity != severity_filter:
                continue
            if v.recommendations:
                patches.append({
                    "title": v.title,
                    "swc_id": v.swc_ids[0] if v.swc_ids else "?",
                    "severity": v.severity,
                    "affected_functions": v.affected_assets,
                    "patch": "; ".join(v.recommendations[:2]),
                })

        if not patches:
            return f"No patch suggestions available{' for severity=' + severity_filter if severity_filter != 'all' else ''}."

        # Deduplicate by title
        seen = set()
        unique_patches = []
        for p in patches:
            key = p["title"].lower()
            if key not in seen:
                seen.add(key)
                unique_patches.append(p)

        lines = [f"Patch suggestions ({len(unique_patches)} unique, filter={severity_filter}):"]
        for p in unique_patches[:15]:
            func_str = ", ".join(p["affected_functions"][:3]) or "unspecified"
            lines.append(
                f"\n[{p['severity'].upper()}][{p['swc_id']}] {p['title']}"
                f"\n  Functions: {func_str}"
                f"\n  Patch: {p['patch'][:300]}"
            )
        return "\n".join(lines)

    def _get_swc_breakdown(self, args: Dict) -> str:
        swc_counts: Dict[str, Dict] = {}
        for ef in self.expert_findings:
            swc = ef.get("swc_id", "UNKNOWN")
            if swc not in swc_counts:
                swc_counts[swc] = {"count": 0, "severities": {}, "titles": []}
            swc_counts[swc]["count"] += 1
            sev = ef.get("severity", "medium")
            swc_counts[swc]["severities"][sev] = swc_counts[swc]["severities"].get(sev, 0) + 1
            title = ef.get("title", "")
            if title and title not in swc_counts[swc]["titles"]:
                swc_counts[swc]["titles"].append(title)

        if not swc_counts:
            return "No expert findings to analyze."

        lines = [f"SWC breakdown ({len(swc_counts)} distinct vulnerability types):"]
        for swc, data in sorted(swc_counts.items(), key=lambda x: -x[1]["count"]):
            sev_str = ", ".join(f"{s}:{n}" for s, n in data["severities"].items())
            lines.append(
                f"\n  {swc}: {data['count']} findings ({sev_str})"
                f"\n    Examples: {', '.join(data['titles'][:2])}"
            )
        return "\n".join(lines)

    def _get_defi_specific_risks(self, args: Dict) -> str:
        defi_patterns = [
            "FLASH_LOAN_PRICE_MANIPULATION", "GOVERNANCE_FLASH_LOAN",
            "SANDWICH_ATTACK", "PRICE_ORACLE_STALENESS",
            "REENTRANCY_IN_DEFI", "ACCESS_CONTROL_MISCONFIGURATION"
        ]
        defi_findings = [
            ef for ef in self.expert_findings
            if ef.get("swc_id", "") in defi_patterns
            or ef.get("author_domain") == "defi"
        ]

        defi_vulns = [
            v for v in self.vulns
            if any(m in defi_patterns for m in v.swc_ids)
            or "defi" in v.supporting_groups
        ]

        if not defi_findings and not defi_vulns:
            return "No DeFi-specific risks identified (contract may not use DeFi patterns)."

        lines = [f"DeFi-specific risks ({len(defi_findings)} raw findings, {len(defi_vulns)} consensus vulns):"]
        for ef in defi_findings[:8]:
            lines.append(
                f"\n[{ef.get('severity','?').upper()}][{ef.get('swc_id','DEFI')}] {ef.get('title','?')}"
                f"\n  Domain: {ef.get('author_domain','?')}/{ef.get('author_persona','?')}"
                f"\n  Evidence: {'; '.join(ef.get('evidence', ['none']))[:200]}"
            )
        return "\n".join(lines)

    def _get_findings_by_domain(self, args: Dict) -> str:
        domain = args.get("domain", "")
        findings = [
            ef for ef in self.expert_findings
            if ef.get("author_domain", "") == domain
        ]
        if not findings:
            return f"No findings from domain '{domain}'."
        lines = [f"Findings by {domain} ({len(findings)} total):"]
        for f in findings[:10]:
            swc = f.get("swc_id", "?")
            lines.append(
                f"\n[{f.get('severity','?').upper()}][{swc}] {f.get('title','?')} "
                f"(by {f.get('author_persona','?')}, phase {f.get('phase','?')}, "
                f"confidence {f.get('confidence', 0.5):.2f})"
            )
        return "\n".join(lines)

    def _get_coverage_gaps(self, args: Dict) -> str:
        engine = ConsensusEngine()
        gaps = engine.get_coverage_gaps(self.vulns, mode="contract_audit", expert_findings_raw=self.expert_findings)
        lines = [
            "Coverage gap analysis:",
            f"  Total consensus vulns: {gaps['total_vulns']}",
            f"  Critical: {gaps['critical_count']}",
            f"  High: {gaps['high_count']}",
            f"  Silent domain groups (0 findings produced): {', '.join(gaps['silent_domain_groups']) or 'none'}",
            f"  Contributed but filtered (findings dismissed/below threshold): {', '.join(gaps['contributed_but_filtered']) or 'none'}",
            f"  Low cross-validation findings: {len(gaps['low_cross_validation_findings'])}",
            f"  Attacker-only paths: {len(gaps['attacker_only_paths'])}",
        ]
        if gaps["low_cross_validation_findings"]:
            lines.append("  Low validation: " + "; ".join(gaps["low_cross_validation_findings"][:5]))
        if self.unvalidated_swc_gaps:
            lines.append(f"\nUnvalidated SWC gaps (single-domain findings not in consensus):")
            for g in self.unvalidated_swc_gaps:
                lines.append(
                    f"  [{g['severity'].upper()}][{g.get('swc_id','?')}] "
                    f"{g['swc_category']}: {g['title']}"
                    f" (mentioned in {g['source_count']} raw findings, by {g['author_domain']})"
                )
        return "\n".join(lines)

    def _get_semantic_findings(self, args: Dict) -> str:
        """Return semantic / business-logic findings (no SWC ID)."""
        cat_filter = args.get("category", "all")
        items = self.semantic_results
        if cat_filter != "all":
            items = [sv for sv in items if sv.get("category") == cat_filter]

        if not items:
            if cat_filter == "all":
                return "No semantic/business-logic findings detected in this audit."
            return f"No semantic findings for category '{cat_filter}'."

        lines = [f"Semantic findings ({len(items)} consensus results, filter={cat_filter}):"]
        for sv in items:
            funcs = ", ".join(sv.get("affected_functions", [])[:3]) or "unspecified"
            attack_path = sv.get("attack_path", [])
            path_preview = " → ".join(attack_path[:3]) if attack_path else "N/A"
            lines.append(
                f"\n[{sv['severity'].upper()}][{sv['category']}] {sv['title']}"
                f"\n  Confidence: {sv['confidence_score']:.3f}"
                f"\n  Functions: {funcs}"
                f"\n  Evidence: {sv.get('evidence', 'N/A')[:200]}"
                f"\n  Attack path: {path_preview}"
                f"\n  Supporting domains: {', '.join(sv.get('supporting_domains', []))}"
                + (" [ATTACKER SURFACED]" if sv.get("is_attacker_surfaced") else "")
            )
        return "\n".join(lines)
