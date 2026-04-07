"""
Cyber Session Orchestrator — Multi-Expert Panel (Direction B)

Điều phối 3-phase OASIS session:
  Phase A (rounds 1–3): Intra-group — domain experts thảo luận nội bộ
  Phase B (rounds 4–7): Cross-group — domain experts challenge nhau
  Phase C (rounds 8–10): Attacker — 5 attacker profiles phản biện

Mỗi round: gọi LLM cho từng agent active → parse findings → lưu trạng thái
Không dùng OASIS subprocess (tương thích với môi trường không có OASIS cài sẵn).
"""

import os
import uuid
import threading
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime

from ..config import Config
from ..models.task import TaskManager, TaskStatus
from ..models.cyber_models import (
    ExpertFinding, AttackerFinding, AttackerCorroboration, CyberSessionState
)
from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger
from .cyber_expert_profile_generator import CyberAgentProfile, CyberExpertProfileGenerator
from .cyber_oasis_env import (
    CyberOasisConfig, CyberOasisEnvBuilder,
    AttackerAction, parse_expert_finding_from_text,
    parse_gap_declarations, build_gap_context_for_agent,
    get_phase_for_round, TOTAL_ROUNDS,
)
from ..models.cyber_models import GapDeclaration

logger = get_logger("mirofish.cyber_orchestrator")


class CyberSessionOrchestrator:
    """
    Orchestrate toàn bộ 3-phase vulnerability analysis session.
    Dùng LLM trực tiếp thay vì OASIS subprocess (portable hơn).
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        boost_llm_client: Optional[LLMClient] = None,
    ):
        self.llm = llm_client or LLMClient()
        # boost_llm dùng cho expensive operations (Phase C attacker reasoning)
        self.boost_llm = boost_llm_client or self._try_build_boost_client()
        self.env_builder = CyberOasisEnvBuilder()
        self.task_manager = TaskManager()

    def run_session_async(
        self,
        graph_id: str,
        network_summary: str,
        profiles: List[CyberAgentProfile],
        session_id: Optional[str] = None,
    ) -> str:
        """
        Khởi chạy session trong background thread.
        Returns task_id để frontend poll.
        """
        session_id = session_id or f"cyber_{uuid.uuid4().hex[:12]}"
        task_id = self.task_manager.create_task(
            task_type="cyber_analysis_session",
            metadata={
                "session_id": session_id,
                "graph_id": graph_id,
                "agent_count": len(profiles),
            }
        )

        thread = threading.Thread(
            target=self._session_worker,
            args=(task_id, session_id, graph_id, network_summary, profiles),
            daemon=True
        )
        thread.start()
        return task_id

    def build_network_context_from_zep(self, graph_id: str) -> str:
        """
        Query Zep KG → tóm tắt hạ tầng để inject vào agent prompts.
        Trả về text mô tả: hosts, zones, CVEs, security controls, critical assets.
        Dùng thay cho việc caller phải tự build network_summary.
        """
        try:
            from ..utils.zep_paging import fetch_all_nodes, fetch_all_edges
            from .graph_builder import GraphBuilderService

            zep = GraphBuilderService().client
            nodes = fetch_all_nodes(zep, graph_id)
            edges = fetch_all_edges(zep, graph_id)

            hosts, services, vulns, zones = [], [], [], []
            for node in nodes:
                labels = node.labels or []
                attrs = node.attributes or {}
                name = getattr(node, "name", "unknown")
                if "NetworkHost" in labels:
                    hosts.append({
                        "name": name,
                        "zone": attrs.get("zone", "unknown"),
                        "ip": attrs.get("ip_address", "?"),
                        "os": attrs.get("os_version", "?"),
                        "patch": attrs.get("patch_status", "?"),
                        "critical": attrs.get("is_critical", "false"),
                        "controls": attrs.get("controls", "none"),
                    })
                elif "NetworkService" in labels:
                    services.append(f"{name} (port {attrs.get('port','?')}, exposed={attrs.get('is_exposed','?')})")
                elif "Vulnerability" in labels:
                    vulns.append(f"{attrs.get('cve_id', name)} [{attrs.get('severity','?')}] patched={attrs.get('is_patched','?')}")
                elif "NetworkZone" in labels:
                    zones.append(f"{name} (trust={attrs.get('trust_level','?')})")

            lines = [f"Network topology summary (graph: {graph_id}):"]

            if zones:
                lines.append(f"\nNetwork Zones ({len(zones)}):")
                for z in zones:
                    lines.append(f"  - {z}")

            if hosts:
                lines.append(f"\nHosts ({len(hosts)}):")
                for h in hosts:
                    crit = " [CRITICAL]" if str(h["critical"]).lower() == "true" else ""
                    lines.append(
                        f"  - {h['name']}{crit} | Zone: {h['zone']} | IP: {h['ip']}"
                        f" | OS: {h['os']} | Patch: {h['patch']} | Controls: {h['controls']}"
                    )

            if services:
                lines.append(f"\nServices ({len(services)}):")
                for s in services[:15]:
                    lines.append(f"  - {s}")

            if vulns:
                lines.append(f"\nKnown Vulnerabilities ({len(vulns)}):")
                for v in vulns[:15]:
                    lines.append(f"  - {v}")

            # Edge summary
            edge_types: Dict[str, int] = {}
            for e in edges:
                rt = getattr(e, "relation_type", "unknown")
                edge_types[rt] = edge_types.get(rt, 0) + 1
            if edge_types:
                lines.append(f"\nRelationships: " + ", ".join(f"{k}×{v}" for k, v in edge_types.items()))

            return "\n".join(lines)

        except Exception as e:
            logger.warning(f"build_network_context_from_zep failed for {graph_id}: {e}")
            return f"Network graph ID: {graph_id}. (Context unavailable — Zep query failed: {e})"

    # ─── Session state persistence ────────────────────────────────────────────

    @staticmethod
    def _session_dir(session_id: str) -> str:
        return os.path.join(Config.UPLOAD_FOLDER, "cyber_sessions", session_id)

    def _save_session_state(self, state: CyberSessionState):
        """Persist session state to JSON so GET endpoints can read it."""
        session_dir = self._session_dir(state.session_id)
        os.makedirs(session_dir, exist_ok=True)
        path = os.path.join(session_dir, "state.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(state), f, ensure_ascii=False, indent=2)

    @staticmethod
    def load_session_state(session_id: str) -> Optional[Dict[str, Any]]:
        """Load persisted session state. Returns None nếu không tìm thấy."""
        path = os.path.join(
            Config.UPLOAD_FOLDER, "cyber_sessions", session_id, "state.json"
        )
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _append_feed_post(self, session_id: str, post: Dict[str, Any]):
        """Append 1 feed post (agent response) vào feed.jsonl của session."""
        session_dir = self._session_dir(session_id)
        os.makedirs(session_dir, exist_ok=True)
        path = os.path.join(session_dir, "feed.jsonl")
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(post, ensure_ascii=False) + "\n")

    @staticmethod
    def load_feed(session_id: str) -> List[Dict[str, Any]]:
        """Load feed posts từ session."""
        path = os.path.join(
            Config.UPLOAD_FOLDER, "cyber_sessions", session_id, "feed.jsonl"
        )
        if not os.path.exists(path):
            return []
        posts = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        posts.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return posts

    # ─── Worker ───────────────────────────────────────────────────────────────

    def _session_worker(
        self,
        task_id: str,
        session_id: str,
        graph_id: str,
        network_summary: str,
        profiles: List[CyberAgentProfile],
    ):
        try:
            self.task_manager.update_task(
                task_id, status=TaskStatus.PROCESSING,
                progress=5, message="Khởi tạo session..."
            )

            # Build OASIS config (metadata only — không chạy subprocess)
            config = self.env_builder.build_config(
                session_id=session_id,
                graph_id=graph_id,
                profiles=profiles,
                network_summary=network_summary,
            )

            session_state = CyberSessionState(
                session_id=session_id,
                graph_id=graph_id,
            )
            self._save_session_state(session_state)

            # Chạy 10 rounds
            for round_num in range(1, TOTAL_ROUNDS + 1):
                phase = get_phase_for_round(round_num)
                progress = 5 + int((round_num - 1) / TOTAL_ROUNDS * 85)

                self.task_manager.update_task(
                    task_id,
                    progress=progress,
                    message=f"Phase {phase} — Round {round_num}/{TOTAL_ROUNDS}"
                )

                self._run_round(
                    round_num=round_num,
                    phase=phase,
                    profiles=profiles,
                    session_state=session_state,
                    network_summary=network_summary,
                    config=config,
                )

                session_state.current_round = round_num
                session_state.current_phase = phase
                # Persist state sau mỗi round để GET endpoints có thể đọc realtime
                self._save_session_state(session_state)

            session_state.current_phase = "done"
            self._save_session_state(session_state)

            # Serialize findings cho result
            self.task_manager.complete_task(task_id, {
                "session_id": session_id,
                "graph_id": graph_id,
                "expert_findings": session_state.expert_findings,
                "attacker_findings": session_state.attacker_findings,
                "total_findings": (
                    len(session_state.expert_findings) +
                    len(session_state.attacker_findings)
                ),
                "rounds_completed": TOTAL_ROUNDS,
            })

        except Exception as e:
            import traceback
            self.task_manager.fail_task(task_id, f"{e}\n{traceback.format_exc()}")

    # ─── Round execution ──────────────────────────────────────────────────────

    def _run_round(
        self,
        round_num: int,
        phase: str,
        profiles: List[CyberAgentProfile],
        session_state: CyberSessionState,
        network_summary: str,
        config: CyberOasisConfig,
    ):
        """
        Chạy 1 round: gọi LLM cho từng active agent → parse findings + GAP declarations.

        GAP declarations từ round này sẽ được route và inject vào round tiếp theo,
        cho phép experts nhận diện điểm mù của nhau và lấp đầy coverage gaps.
        """
        active_profiles = self.env_builder.get_active_agents_for_phase(profiles, phase)
        prior_context = self._build_prior_context(session_state)

        for profile in active_profiles:
            try:
                # Build per-agent gap context: chỉ inject gaps routed đến domain group này
                gap_context = ""
                if profile.tier == 1 and phase in ("A", "B"):
                    gap_context = build_gap_context_for_agent(
                        pending_gaps=session_state.pending_gaps(),
                        agent_domain_group=profile.domain_group,
                    )

                phase_instruction = self.env_builder.build_phase_instruction(
                    phase, round_num, gap_context=gap_context
                )

                response = self._call_agent(
                    profile=profile,
                    phase=phase,
                    round_num=round_num,
                    phase_instruction=phase_instruction,
                    prior_context=prior_context,
                    network_summary=network_summary,
                )

                # Persist post to feed
                self._append_feed_post(session_state.session_id, {
                    "round_num": round_num,
                    "phase": phase,
                    "agent_id": profile.agent_id,
                    "agent_display": profile.display_name,
                    "tier": profile.tier,
                    "domain_group": profile.domain_group,
                    "persona": profile.persona,
                    "content": response,
                    "timestamp": datetime.now().isoformat(),
                    "gap_context_injected": bool(gap_context),
                })

                if profile.tier == 1:
                    self._process_expert_response(response, profile, round_num, session_state)
                    # Parse và register GAP declarations (Phases A và B only)
                    if phase in ("A", "B"):
                        self._process_gap_declarations(response, profile, round_num, session_state)
                else:
                    self._process_attacker_response(response, profile, round_num, session_state)

            except Exception as e:
                logger.warning(f"Agent {profile.agent_id} round {round_num} error: {e}")

        # After all agents in round complete: mark injected gaps as routed
        if phase in ("A", "B"):
            self._mark_gaps_as_routed(session_state)

    def _call_agent(
        self,
        profile: CyberAgentProfile,
        phase: str,
        round_num: int,
        phase_instruction: str,
        prior_context: str,
        network_summary: str,
    ) -> str:
        """Gọi LLM cho 1 agent và trả về response text."""
        # Chọn LLM (boost cho attacker Phase C)
        llm = self.boost_llm if (profile.tier == 2 and phase == "C") else self.llm

        messages = [
            {"role": "system", "content": profile.system_prompt},
            {
                "role": "user",
                "content": (
                    f"{phase_instruction}\n\n"
                    f"=== DISCUSSION SO FAR ===\n{prior_context}\n\n"
                    f"Provide your analysis for Round {round_num}. "
                    f"Be specific, reference actual hosts and services from the infrastructure."
                )
            }
        ]

        return llm.chat(messages, temperature=0.7, max_tokens=1500)

    # ─── Parsers ──────────────────────────────────────────────────────────────

    def _process_expert_response(
        self,
        text: str,
        profile: CyberAgentProfile,
        round_num: int,
        session_state: CyberSessionState,
    ):
        """Parse expert agent response → ExpertFinding entries."""
        finding_raw = parse_expert_finding_from_text(text, profile, round_num)
        if not finding_raw:
            return

        finding_id = f"ef_{uuid.uuid4().hex[:8]}"
        finding = ExpertFinding(
            finding_id=finding_id,
            author_group=finding_raw["author_group"],
            author_persona=finding_raw["author_persona"],
            title=finding_raw["title"],
            description=finding_raw["description"],
            affected_assets=finding_raw["affected_assets"],
            severity=finding_raw["severity"],
            confidence=self._initial_confidence_for_severity(finding_raw["severity"]),
            evidence=finding_raw["evidence"],
            recommendations=finding_raw["recommendations"],
            mitre_techniques=[],
            phase=finding_raw["phase"],
            round_number=round_num,
        )

        session_state.expert_findings.append(asdict(finding))
        logger.debug(
            f"Finding [{finding_id}] from {profile.agent_id}: "
            f"{finding.title} ({finding.severity})"
        )

    def _process_attacker_response(
        self,
        text: str,
        profile: CyberAgentProfile,
        round_num: int,
        session_state: CyberSessionState,
    ):
        """Parse attacker agent response → AttackerFinding or AttackerCorroboration."""
        action = AttackerAction.parse_from_text(text)
        if not action:
            return

        action_type = action["action_type"]

        if action_type == AttackerAction.ADD_PATH:
            # Tạo finding mới do attacker đề xuất
            finding_id = f"af_{uuid.uuid4().hex[:8]}"
            af = AttackerFinding(
                finding_id=finding_id,
                attacker_profile=profile.persona,
                title=action["finding_ref"] or f"Attack path by {profile.display_name}",
                description=action["reason"],
                affected_assets=[],
                severity="high",
                base_confidence=0.60,
                path_description=action["path"],
            )
            session_state.attacker_findings.append(asdict(af))
            logger.debug(f"Attacker NEW finding [{finding_id}] by {profile.agent_id}")
        else:
            # Gắn corroboration vào finding đã có (match bằng title keyword)
            self._attach_corroboration(
                action=action,
                attacker_profile=profile.persona,
                session_state=session_state,
            )

    def _process_gap_declarations(
        self,
        text: str,
        profile: CyberAgentProfile,
        round_num: int,
        session_state: CyberSessionState,
    ):
        """
        Parse GAP declarations từ expert agent post và lưu vào session state.
        Gaps sẽ được route đến domain groups phù hợp trong round tiếp theo.
        """
        gaps = parse_gap_declarations(
            text=text,
            author_group=profile.domain_group,
            author_persona=profile.persona,
            round_num=round_num,
        )
        for gap in gaps:
            session_state.gap_registry.append(gap)
            logger.debug(
                f"GAP declared by {profile.agent_id} | area='{gap['analyzed']}' "
                f"→ routed to {gap['routed_to']}"
            )

    def _mark_gaps_as_routed(self, session_state: CyberSessionState):
        """
        Sau khi tất cả agents trong round đã được xử lý, đánh dấu các pending gaps
        là đã được inject (routed=True). Chúng sẽ không xuất hiện trong round tiếp theo.
        """
        for gap in session_state.gap_registry:
            if not gap.get("routed", False):
                gap["routed"] = True

    def _attach_corroboration(
        self,
        action: Dict[str, Any],
        attacker_profile: str,
        session_state: CyberSessionState,
    ):
        """Tìm expert finding phù hợp và gắn corroboration."""
        finding_ref = action["finding_ref"].lower()
        for finding_dict in session_state.expert_findings:
            if finding_ref and finding_ref in finding_dict.get("title", "").lower():
                corr = AttackerCorroboration(
                    profile_id=attacker_profile,
                    action=action["action_type"],
                    comment=action["reason"],
                    confidence_delta=action["confidence_delta"],
                )
                if "attacker_corroborations" not in finding_dict:
                    finding_dict["attacker_corroborations"] = []
                finding_dict["attacker_corroborations"].append(asdict(corr))

                # Apply confidence delta
                current = finding_dict.get("confidence", 0.5)
                finding_dict["confidence"] = max(0.0, min(1.0, current + corr.confidence_delta))
                return

    # ─── Context builder ──────────────────────────────────────────────────────

    def _build_prior_context(self, session_state: CyberSessionState) -> str:
        """
        Build text summary của các findings đã có để inject vào tiếp theo.
        Giới hạn độ dài để không overflow context window.
        """
        lines = []

        if session_state.expert_findings:
            lines.append(f"=== EXPERT FINDINGS ({len(session_state.expert_findings)}) ===")
            # Chỉ show 10 findings gần nhất để giữ context ngắn
            recent = session_state.expert_findings[-10:]
            for f in recent:
                corr_count = len(f.get("attacker_corroborations", []))
                lines.append(
                    f"[{f.get('severity','?').upper()}] {f.get('title','Untitled')} "
                    f"(by {f.get('author_group','?')}/{f.get('author_persona','?')}, "
                    f"confidence: {f.get('confidence', 0.5):.2f}"
                    + (f", {corr_count} attacker reactions" if corr_count else "") + ")"
                )

        if session_state.attacker_findings:
            lines.append(f"\n=== ATTACKER FINDINGS ({len(session_state.attacker_findings)}) ===")
            for f in session_state.attacker_findings[-5:]:
                lines.append(
                    f"[ATTACKER:{f.get('attacker_profile','?')}] "
                    f"{f.get('title','Untitled')} (base confidence: {f.get('base_confidence', 0.6):.2f})"
                )

        # Show gap registry summary (all rounds) so agents understand coverage state
        all_gaps = session_state.gap_registry
        if all_gaps:
            lines.append(f"\n=== DECLARED KNOWLEDGE GAPS ({len(all_gaps)} total) ===")
            lines.append("Areas experts could not verify — still open for investigation:")
            for g in all_gaps[-8:]:  # show last 8 to avoid overflow
                lines.append(
                    f"  [{g.get('author_group','?')}] Area: {g.get('analyzed','?')} — "
                    f"{g.get('gap_text','')[:100]}"
                )

        return "\n".join(lines) if lines else "No findings yet — be the first to identify vulnerabilities."

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _initial_confidence_for_severity(self, severity: str) -> float:
        """Initial confidence dựa trên severity từ expert agent."""
        return {"critical": 0.70, "high": 0.60, "medium": 0.50, "low": 0.40, "info": 0.30}.get(
            severity.lower(), 0.50
        )

    def _try_build_boost_client(self) -> LLMClient:
        """Thử dùng BOOST LLM config nếu có, fallback về primary LLM."""
        try:
            boost_key = Config.BOOST_API_KEY if hasattr(Config, "BOOST_API_KEY") else None
            boost_url = Config.BOOST_BASE_URL if hasattr(Config, "BOOST_BASE_URL") else None
            boost_model = Config.BOOST_MODEL_NAME if hasattr(Config, "BOOST_MODEL_NAME") else None
            if boost_key:
                return LLMClient(api_key=boost_key, base_url=boost_url, model=boost_model)
        except Exception:
            pass
        return self.llm
