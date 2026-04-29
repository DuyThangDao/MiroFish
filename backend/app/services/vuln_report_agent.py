"""
Vulnerability Report Agent — Multi-Expert Panel (Direction B)

ReACT pattern agent tổng hợp vulnerability report từ:
  - ConsensusVulnerability list (output của ConsensusEngine)
  - Expert findings từ session
  - Attacker profile breakdown
  - Network topology từ Zep KG

Output: structured vulnerability report với confidence score, MITRE mapping,
và attacker profile analysis.
"""

import os
import json
import uuid
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import asdict

from ..config import Config
from ..models.task import TaskManager, TaskStatus
from ..models.cyber_models import ConsensusVulnerability
from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger
from .consensus_engine import ConsensusEngine

logger = get_logger("mirofish.vuln_report_agent")


# ─── Tool definitions ─────────────────────────────────────────────────────────

TOOLS_SPEC = """You have access to the following tools:

[get_top_vulnerabilities]
  Description: Get top N vulnerabilities sorted by confidence score
  Args: { "limit": <int, default 10> }

[get_critical_findings]
  Description: Get all findings with severity critical or high
  Args: {}

[get_attacker_profile_breakdown]
  Description: For each attacker profile, show which findings they confirmed/dismissed/escalated
  Args: { "profile": <"opportunistic"|"apt"|"insider_threat"|"ransomware"|"supply_chain"|"all"> }

[get_attacker_only_findings]
  Description: Get findings that were discovered only by attacker profiles (expert agents missed them)
  Args: {}

[get_coverage_gaps]
  Description: Show which domain groups were silent and which findings lack cross-group validation
  Args: {}

[get_findings_by_group]
  Description: Get all findings contributed by a specific domain group
  Args: { "group": <"network_security"|"appsec"|"endpoint_security"|"threat_intel"|"risk"> }

[get_mitre_mapping]
  Description: Map vulnerabilities to MITRE ATT&CK techniques
  Args: {}

[get_confidence_distribution]
  Description: Show how findings are distributed across confidence tiers (high/medium/low)
  Args: {}

Use tools by writing: ACTION: tool_name({"arg": value})
Write your final report using: FINAL_ANSWER: <report content>
"""

REACT_SYSTEM_PROMPT = f"""You are VulnReportAgent — an expert security analyst who generates comprehensive vulnerability reports.
You use a ReACT reasoning pattern: observe the data, plan your analysis, use tools to gather details, then synthesize findings into a report.

{TOOLS_SPEC}

Report must include:
1. Executive Summary (non-technical, business risk focus)
2. Top Vulnerabilities by Priority (with confidence score and MITRE mapping)
3. Attacker Profile Analysis (what each attacker profile found)
4. Coverage Gap Analysis (what was potentially missed)
5. Recommendations (immediate, short-term, long-term)

Always cite confidence scores and which groups/attackers validated each finding.
Write in a professional security report style. Be specific — reference actual hosts, CVEs, and attack paths."""


class VulnReportAgent:
    """
    ReACT agent tổng hợp vulnerability report từ consensus results.
    Pattern: Thought → Action → Observation → ... → Final Answer
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or LLMClient()
        self.task_manager = TaskManager()
        self.max_iterations = 8

    def generate_report_async(
        self,
        session_id: str,
        expert_findings: List[Dict[str, Any]],
        attacker_findings: List[Dict[str, Any]],
        network_summary: str,
        graph_id: Optional[str] = None,
    ) -> str:
        """
        Generate vulnerability report trong background thread.
        Returns task_id.
        """
        task_id = self.task_manager.create_task(
            task_type="vuln_report_generation",
            metadata={"session_id": session_id, "graph_id": graph_id}
        )

        thread = threading.Thread(
            target=self._generate_worker,
            args=(task_id, session_id, expert_findings, attacker_findings, network_summary, graph_id),
            daemon=True
        )
        thread.start()
        return task_id

    def generate_report_sync(
        self,
        session_id: str,
        expert_findings: List[Dict[str, Any]],
        attacker_findings: List[Dict[str, Any]],
        network_summary: str,
        graph_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Synchronous version — trả về report dict trực tiếp."""
        engine = ConsensusEngine()
        consensus_vulns, _ = engine.run(expert_findings, attacker_findings)
        unvalidated_gaps = engine.enforce_control_coverage(consensus_vulns, expert_findings)

        tool_context = _ToolContext(
            consensus_vulns=consensus_vulns,
            expert_findings=expert_findings,
            attacker_findings=attacker_findings,
            unvalidated_control_gaps=unvalidated_gaps,
        )

        report_text = self._run_react_loop(
            network_summary=network_summary,
            tool_context=tool_context,
        )

        coverage_gaps = engine.get_coverage_gaps(consensus_vulns)

        return {
            "session_id": session_id,
            "graph_id": graph_id,
            "generated_at": datetime.now().isoformat(),
            "report": report_text,
            "consensus_vulnerabilities": [asdict(v) for v in consensus_vulns],
            "unvalidated_control_gaps": unvalidated_gaps,
            "coverage_gaps": coverage_gaps,
            "stats": {
                "total_expert_findings": len(expert_findings),
                "total_attacker_findings": len(attacker_findings),
                "consensus_vulns": len(consensus_vulns),
                "unvalidated_gaps": len(unvalidated_gaps),
                "critical": sum(1 for v in consensus_vulns if v.severity == "critical"),
                "high": sum(1 for v in consensus_vulns if v.severity == "high"),
            }
        }

    # ─── Worker ───────────────────────────────────────────────────────────────

    def _generate_worker(
        self,
        task_id: str,
        session_id: str,
        expert_findings: List[Dict[str, Any]],
        attacker_findings: List[Dict[str, Any]],
        network_summary: str,
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
                network_summary=network_summary,
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
        network_summary: str,
        tool_context: "_ToolContext",
    ) -> str:
        """
        ReACT loop: Thought → Action → Observation → ... → FINAL_ANSWER
        """
        messages = [
            {"role": "system", "content": REACT_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Generate a comprehensive vulnerability report for the following infrastructure:\n\n"
                    f"{network_summary}\n\n"
                    f"Use the available tools to gather findings data, then write the complete report. "
                    f"Start with THOUGHT: to plan your approach."
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
                # No valid action found — prompt to conclude
                messages.append({
                    "role": "user",
                    "content": (
                        "No valid tool call found. Please use ACTION: tool_name({args}) format, "
                        "or write FINAL_ANSWER: to output your report."
                    )
                })

        # Fallback: ask LLM to write final report directly
        messages.append({
            "role": "user",
            "content": "Max iterations reached. Write FINAL_ANSWER: with your complete vulnerability report now."
        })
        final = self.llm.chat(messages, temperature=0.3, max_tokens=8192)
        if "FINAL_ANSWER:" in final:
            return final[final.index("FINAL_ANSWER:") + len("FINAL_ANSWER:"):].strip()
        return final

    def _parse_and_execute_action(
        self, text: str, tool_context: "_ToolContext"
    ) -> Optional[str]:
        """Parse ACTION: tool_name({args}) → execute → return observation string."""
        import re
        # Match: ACTION: tool_name({"key": "value"})
        match = re.search(r'ACTION:\s*(\w+)\s*\((\{.*?\}|\{\})\)', text, re.DOTALL)
        if not match:
            # Try without args
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
        """Save report to uploads/cyber_reports/<session_id>/report.json"""
        report_dir = os.path.join(Config.UPLOAD_FOLDER, "cyber_reports", session_id)
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, "report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        logger.info(f"Report saved: {report_path}")


# ─── Tool Context ──────────────────────────────────────────────────────────────

class _ToolContext:
    """
    Executes tool calls for VulnReportAgent.
    Holds consensus_vulns + raw findings in memory during report generation.
    """

    def __init__(
        self,
        consensus_vulns: List[ConsensusVulnerability],
        expert_findings: List[Dict[str, Any]],
        attacker_findings: List[Dict[str, Any]],
        unvalidated_control_gaps: List[Dict[str, Any]] = None,
    ):
        self.vulns = consensus_vulns
        self.expert_findings = expert_findings
        self.attacker_findings = attacker_findings
        self.unvalidated_control_gaps = unvalidated_control_gaps or []

    def execute(self, tool_name: str, args: Dict[str, Any]) -> str:
        """Dispatch tool call → return string observation."""
        dispatch = {
            "get_top_vulnerabilities":        self._get_top_vulnerabilities,
            "get_critical_findings":           self._get_critical_findings,
            "get_attacker_profile_breakdown":  self._get_attacker_profile_breakdown,
            "get_attacker_only_findings":      self._get_attacker_only_findings,
            "get_coverage_gaps":               self._get_coverage_gaps,
            "get_findings_by_group":           self._get_findings_by_group,
            "get_mitre_mapping":               self._get_mitre_mapping,
            "get_confidence_distribution":     self._get_confidence_distribution,
        }
        fn = dispatch.get(tool_name)
        if not fn:
            return f"Unknown tool: {tool_name}. Available: {list(dispatch.keys())}"
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
            lines.append(
                f"\n[{v.severity.upper()}] {v.title}"
                f"\n  Confidence: {v.confidence_score:.2f} "
                f"(intra:{v.intra_group_score:.2f} cross:{v.cross_group_score:.2f} attack:{v.attacker_score:.2f})"
                f"\n  Affected: {', '.join(v.affected_assets[:3]) or 'unspecified'}"
                f"\n  Groups: {', '.join(v.supporting_groups)}"
                f"\n  Attackers confirm: {', '.join(v.supporting_attackers) or 'none'}"
                f"\n  SWC: {', '.join(v.swc_ids) or 'unmapped'}"
            )
        return "\n".join(lines)

    def _get_critical_findings(self, args: Dict) -> str:
        critical = [v for v in self.vulns if v.severity in {"critical", "high"}]
        if not critical:
            return "No critical or high severity vulnerabilities found."
        lines = [f"Critical/High findings ({len(critical)} total):"]
        for v in critical:
            lines.append(
                f"\n[{v.severity.upper()}] {v.title} — confidence {v.confidence_score:.2f}"
                f"\n  {v.description[:200]}"
                f"\n  Recommendation: {'; '.join(v.recommendations[:2]) or 'none'}"
                + (" ⚠ Needs review" if v.needs_review else "")
            )
        return "\n".join(lines)

    def _get_attacker_profile_breakdown(self, args: Dict) -> str:
        profile_filter = args.get("profile", "all")
        lines = ["Attacker profile breakdown:"]

        profiles = ["opportunistic", "apt", "insider_threat", "ransomware", "supply_chain"]
        if profile_filter != "all":
            profiles = [p for p in profiles if p == profile_filter]

        for profile in profiles:
            confirmed = []
            dismissed = []
            escalated = []
            new_paths  = []

            # From consensus vulns corroborations
            for v in self.vulns:
                if profile in v.supporting_attackers:
                    confirmed.append(v.title)
                if profile in v.dismissing_attackers:
                    dismissed.append(v.title)

            # From expert findings raw corroborations
            for ef in self.expert_findings:
                for c in ef.get("attacker_corroborations", []):
                    if c.get("profile_id") != profile:
                        continue
                    if c.get("action") == "ATTACKER_ESCALATE":
                        escalated.append(ef.get("title", "?"))

            # From attacker-only findings
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
        raw = [af for af in self.attacker_findings if af.get("agreed_by")]
        if not only and not raw:
            return "No attacker-only findings — experts covered all paths."
        lines = ["Findings discovered only by attacker profiles (expert agents missed):"]
        for v in only:
            lines.append(
                f"\n[{v.severity.upper()}] {v.title}"
                f"\n  Found by: {', '.join(v.supporting_attackers)}"
                f"\n  {v.description[:200]}"
            )
        return "\n".join(lines)

    def _get_coverage_gaps(self, args: Dict) -> str:
        engine = ConsensusEngine()
        gaps = engine.get_coverage_gaps(self.vulns)
        lines = [
            f"Coverage gap analysis:",
            f"  Total consensus vulns: {gaps['total_vulns']}",
            f"  Critical: {gaps['critical_count']}",
            f"  High: {gaps['high_count']}",
            f"  Silent domain groups: {', '.join(gaps['silent_domain_groups']) or 'none'}",
            f"  Low cross-validation findings: {len(gaps['low_cross_validation_findings'])}",
            f"  Attacker-only paths: {len(gaps['attacker_only_paths'])}",
        ]
        if gaps["low_cross_validation_findings"]:
            lines.append("  Low validation: " + "; ".join(gaps["low_cross_validation_findings"][:5]))
        if self.unvalidated_control_gaps:
            lines.append(f"\nUnvalidated control gaps (not in consensus — single-domain findings):")
            for g in self.unvalidated_control_gaps:
                lines.append(
                    f"  [{g['severity'].upper()}] {g['control']}: {g['title']}"
                    f" (mentioned in {g['source_count']} raw findings, by {g['author_group']})"
                )
        return "\n".join(lines)

    def _get_findings_by_group(self, args: Dict) -> str:
        group = args.get("group", "")
        group_findings = [
            ef for ef in self.expert_findings
            if ef.get("author_group", "") == group
        ]
        if not group_findings:
            return f"No findings from group '{group}'."
        lines = [f"Findings by {group} ({len(group_findings)} total):"]
        for f in group_findings[:10]:
            lines.append(
                f"\n[{f.get('severity','?').upper()}] {f.get('title','?')} "
                f"(by {f.get('author_persona','?')}, phase {f.get('phase','?')}, "
                f"confidence {f.get('confidence', 0.5):.2f})"
            )
        return "\n".join(lines)

    def _get_mitre_mapping(self, args: Dict) -> str:
        swc_index: Dict[str, List[str]] = {}
        for v in self.vulns:
            for swc in v.swc_ids:
                if swc not in swc_index:
                    swc_index[swc] = []
                swc_index[swc].append(v.title)
        if not swc_index:
            return "No SWC mappings found (agents did not include SWC IDs)."
        lines = ["SWC mapping:"]
        for swc, titles in sorted(swc_index.items()):
            lines.append(f"  {swc}: {', '.join(titles[:3])}")
        return "\n".join(lines)

    def _get_confidence_distribution(self, args: Dict) -> str:
        high   = [v for v in self.vulns if v.confidence_score >= 0.70]
        medium = [v for v in self.vulns if 0.50 <= v.confidence_score < 0.70]
        low    = [v for v in self.vulns if v.confidence_score < 0.50]
        return (
            f"Confidence distribution ({len(self.vulns)} total vulns):\n"
            f"  High confidence (≥0.70): {len(high)} vulns\n"
            f"  Medium confidence (0.50–0.70): {len(medium)} vulns\n"
            f"  Low confidence (<0.50, needs review): {len(low)} vulns\n"
            f"  Average confidence: {sum(v.confidence_score for v in self.vulns)/max(len(self.vulns),1):.2f}"
        )
