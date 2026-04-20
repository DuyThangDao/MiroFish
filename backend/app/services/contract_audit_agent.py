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

Use tools by writing: ACTION: tool_name({"arg": value})
Write final report using: FINAL_ANSWER: <report content>
"""

REACT_SYSTEM_PROMPT = f"""You are ContractAuditReportAgent — a senior smart contract security auditor.
You synthesize results from a multi-expert audit panel into a comprehensive security report.
You use a ReACT reasoning pattern: observe the data, gather details with tools, then write the report.

{TOOLS_SPEC}

Your report MUST include these 6 sections:

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
            args=(task_id, session_id, expert_findings, attacker_findings, contract_summary, graph_id),
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
    ) -> Dict[str, Any]:
        """Synchronous version — trả về report dict trực tiếp."""
        engine = ConsensusEngine()
        consensus_vulns = engine.run(
            expert_findings, attacker_findings,
            domain_group_count=7, mode="contract_audit"
        )
        unvalidated_swc_gaps = engine.enforce_swc_coverage(consensus_vulns, expert_findings)

        tool_context = _ContractToolContext(
            consensus_vulns=consensus_vulns,
            expert_findings=expert_findings,
            attacker_findings=attacker_findings,
            unvalidated_swc_gaps=unvalidated_swc_gaps,
        )

        report_text = self._run_react_loop(
            contract_summary=contract_summary,
            tool_context=tool_context,
        )

        coverage_gaps = engine.get_coverage_gaps(consensus_vulns, mode="contract_audit")

        return {
            "session_id":          session_id,
            "graph_id":            graph_id,
            "generated_at":        datetime.now().isoformat(),
            "report":              report_text,
            "consensus_vulns":     [asdict(v) for v in consensus_vulns],
            "unvalidated_swc_gaps": unvalidated_swc_gaps,
            "coverage_gaps":       coverage_gaps,
            "stats": {
                "total_expert_findings":   len(expert_findings),
                "total_attacker_findings": len(attacker_findings),
                "consensus_vulns":         len(consensus_vulns),
                "unvalidated_swc_gaps":    len(unvalidated_swc_gaps),
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
        """ReACT loop: Thought → ACTION → OBSERVATION → ... → FINAL_ANSWER"""
        messages = [
            {"role": "system", "content": REACT_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Generate a comprehensive smart contract audit report for:\n\n"
                    f"{contract_summary}\n\n"
                    f"Use the available tools to gather findings data, then write the complete 6-section report. "
                    f"Start with THOUGHT: to plan your approach. "
                    f"Call at least 4 tools before writing FINAL_ANSWER."
                )
            }
        ]

        for iteration in range(self.max_iterations):
            response = self.llm.chat(messages, temperature=0.3, max_tokens=8192)
            messages.append({"role": "assistant", "content": response})

            # Check for FINAL_ANSWER
            if "FINAL_ANSWER:" in response:
                idx = response.index("FINAL_ANSWER:")
                return response[idx + len("FINAL_ANSWER:"):].strip()

            # Parse and execute tool call
            action_result = self._parse_and_execute_action(response, tool_context)
            if action_result:
                messages.append({
                    "role": "user",
                    "content": f"OBSERVATION:\n{action_result}\n\nContinue your analysis."
                })
            else:
                messages.append({
                    "role": "user",
                    "content": (
                        "No valid tool call found. Use ACTION: tool_name({args}) format, "
                        "or write FINAL_ANSWER: to output your audit report."
                    )
                })

        # Fallback: force final answer
        messages.append({
            "role": "user",
            "content": "Max iterations reached. Write FINAL_ANSWER: with your complete audit report now."
        })
        final = self.llm.chat(messages, temperature=0.3, max_tokens=8192)
        if "FINAL_ANSWER:" in final:
            return final[final.index("FINAL_ANSWER:") + len("FINAL_ANSWER:"):].strip()
        return final

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
    ):
        self.vulns = consensus_vulns
        self.expert_findings = expert_findings
        self.attacker_findings = attacker_findings
        self.unvalidated_swc_gaps = unvalidated_swc_gaps or []

    def execute(self, tool_name: str, args: Dict[str, Any]) -> str:
        """Dispatch tool call → return string observation."""
        dispatch = {
            "get_top_vulnerabilities":       self._get_top_vulnerabilities,
            "get_critical_findings":         self._get_critical_findings,
            "get_exploitable_findings":      self._get_exploitable_findings,
            "get_attacker_profile_breakdown": self._get_attacker_profile_breakdown,
            "get_attacker_only_findings":    self._get_attacker_only_findings,
            "get_patch_suggestions":         self._get_patch_suggestions,
            "get_swc_breakdown":             self._get_swc_breakdown,
            "get_defi_specific_risks":       self._get_defi_specific_risks,
            "get_findings_by_domain":        self._get_findings_by_domain,
            "get_coverage_gaps":             self._get_coverage_gaps,
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
            swc_ids = ", ".join(v.mitre_techniques) if v.mitre_techniques else "unmapped"
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
            swc = ", ".join(v.mitre_techniques) if v.mitre_techniques else "?"
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
                    "swc_id": v.mitre_techniques[0] if v.mitre_techniques else "?",
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
            if any(m in defi_patterns for m in v.mitre_techniques)
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
        gaps = engine.get_coverage_gaps(self.vulns, mode="contract_audit")
        lines = [
            "Coverage gap analysis:",
            f"  Total consensus vulns: {gaps['total_vulns']}",
            f"  Critical: {gaps['critical_count']}",
            f"  High: {gaps['high_count']}",
            f"  Silent domain groups: {', '.join(gaps['silent_domain_groups']) or 'none'}",
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
