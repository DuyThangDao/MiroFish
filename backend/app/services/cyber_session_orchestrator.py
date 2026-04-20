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
import time
import uuid
import threading
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
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

# Contract audit mode imports (lazy to avoid circular imports)
def _get_contract_modules():
    from .contract_oasis_env import (
        ContractAuditEnvBuilder,
        ContractAttackerAction, parse_contract_finding_from_text,
        parse_contract_gap_declarations, build_gap_context_for_agent as contract_gap_context,
        build_published_registry as contract_published_registry,
        get_phase_for_round as contract_get_phase,
    )
    return {
        "env_builder":         ContractAuditEnvBuilder,
        "attacker_action":     ContractAttackerAction,
        "parse_finding":       parse_contract_finding_from_text,
        "parse_gap":           parse_contract_gap_declarations,
        "gap_context":         contract_gap_context,
        "published_registry":  contract_published_registry,
        "get_phase":           contract_get_phase,
    }

logger = get_logger("mirofish.cyber_orchestrator")


class _RateLimiter:
    """
    Sliding-window rate limiter — thread-safe.

    Two modes (mutually exclusive, global takes priority):
    - LLM_GLOBAL_RPM_LIMIT > 0 : cross-process file-based limiter shared across
      all parallel evaluate_phase5b.py processes. Enforces a single RPM cap for
      the entire machine, preventing 429 cascade when running --parallel N.
    - LLM_RPM_LIMIT > 0        : per-process in-memory limiter (original behaviour,
      used for single-process runs).
    """

    _SHARED_FILE = "/tmp/mirofish_global_rpm.json"
    _LOCK_FILE   = "/tmp/mirofish_global_rpm.lock"

    def __init__(self):
        import threading as _threading
        self._lock = _threading.Lock()
        self._timestamps: list = []
        self.rpm        = int(os.environ.get("LLM_RPM_LIMIT",        "0"))
        self.global_rpm = int(os.environ.get("LLM_GLOBAL_RPM_LIMIT", "0"))

    def acquire(self):
        import time as _time
        if self.global_rpm > 0:
            self._acquire_global(_time)
        elif self.rpm > 0:
            self._acquire_local(_time)

    # ------------------------------------------------------------------ #
    # Per-process in-memory limiter (original)                            #
    # ------------------------------------------------------------------ #
    def _acquire_local(self, _time):
        with self._lock:
            now = _time.monotonic()
            self._timestamps = [t for t in self._timestamps if now - t < 60.0]
            if len(self._timestamps) >= self.rpm:
                sleep_for = 60.0 - (now - self._timestamps[0]) + 0.1
                if sleep_for > 0:
                    logger.debug(f"[rate limiter] sleeping {sleep_for:.1f}s (RPM cap={self.rpm})")
                    _time.sleep(sleep_for)
            self._timestamps.append(_time.monotonic())

    # ------------------------------------------------------------------ #
    # Cross-process file-based limiter (global)                           #
    # ------------------------------------------------------------------ #
    def _acquire_global(self, _time):
        import fcntl
        import json as _json

        while True:
            wait_for = 0.0
            with open(self._LOCK_FILE, "w") as lf:
                fcntl.flock(lf, fcntl.LOCK_EX)
                try:
                    now = _time.time()
                    cutoff = now - 60.0
                    try:
                        with open(self._SHARED_FILE) as f:
                            data = _json.load(f)
                        ts = [t for t in data.get("ts", []) if t > cutoff]
                    except (FileNotFoundError, _json.JSONDecodeError):
                        ts = []

                    if len(ts) < self.global_rpm:
                        ts.append(now)
                        with open(self._SHARED_FILE, "w") as f:
                            _json.dump({"ts": ts}, f)
                        return  # slot acquired

                    wait_for = ts[0] + 60.0 - now + 0.1
                finally:
                    fcntl.flock(lf, fcntl.LOCK_UN)

            logger.debug(
                f"[global rate limiter] waiting {wait_for:.1f}s "
                f"(global RPM cap={self.global_rpm})"
            )
            _time.sleep(min(wait_for, 1.0))


_rate_limiter = _RateLimiter()


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
        mode: str = "network_security",
    ) -> str:
        """
        Khởi chạy session trong background thread.
        Returns task_id để frontend poll.

        Args:
            mode: "network_security" (default) | "contract_audit"
        """
        session_id = session_id or f"cyber_{uuid.uuid4().hex[:12]}"
        task_id = self.task_manager.create_task(
            task_type="cyber_analysis_session",
            metadata={
                "session_id": session_id,
                "graph_id": graph_id,
                "agent_count": len(profiles),
                "mode": mode,
            }
        )

        thread = threading.Thread(
            target=self._session_worker,
            args=(task_id, session_id, graph_id, network_summary, profiles, mode),
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

    def build_contract_context_from_zep(self, graph_id: str) -> str:
        """
        Query Zep KG → tóm tắt contract entity để inject vào agent prompts.
        Dùng ContractKGBuilder.build_context_summary() nếu có, fallback về Zep raw query.
        """
        try:
            from .contract_kg_builder import ContractKGBuilder
            kg_builder = ContractKGBuilder(llm_client=self.llm)
            return kg_builder.build_context_summary(graph_id)
        except Exception as e:
            logger.warning(f"build_contract_context_from_zep failed for {graph_id}: {e}")
            return f"Contract graph ID: {graph_id}. (Context unavailable — KG query failed: {e})"

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
        mode: str = "network_security",
    ):
        try:
            self.task_manager.update_task(
                task_id, status=TaskStatus.PROCESSING,
                progress=5, message="Khởi tạo session..."
            )

            # Pick env_builder and phase function based on mode
            if mode == "contract_audit":
                cm = _get_contract_modules()
                env_builder = cm["env_builder"]()
                get_phase = cm["get_phase"]
                config = env_builder.build_config(
                    session_id=session_id,
                    graph_id=graph_id,
                    contract_id=graph_id,
                    profiles=profiles,
                    contract_summary=network_summary,
                )
            else:
                env_builder = self.env_builder
                get_phase = get_phase_for_round
                config = env_builder.build_config(
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
                phase = get_phase(round_num)
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
                    mode=mode,
                    env_builder=env_builder,
                )

                session_state.current_round = round_num
                session_state.current_phase = phase
                self._save_session_state(session_state)

                # Inter-round cooldown — let Vertex AI TPM window partially recover
                # before next burst. Reads LLM_ROUND_COOLDOWN_S (default 15s).
                if round_num < TOTAL_ROUNDS:
                    cooldown = float(os.environ.get("LLM_ROUND_COOLDOWN_S", "15"))
                    if cooldown > 0:
                        time.sleep(cooldown)

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
        config: Any,
        mode: str = "network_security",
        env_builder=None,
    ):
        """
        Chạy 1 round: gọi LLM cho từng active agent → parse findings + GAP declarations.

        GAP declarations từ round này sẽ được route và inject vào round tiếp theo,
        cho phép experts nhận diện điểm mù của nhau và lấp đầy coverage gaps.
        """
        if env_builder is None:
            env_builder = self.env_builder

        active_profiles = env_builder.get_active_agents_for_phase(profiles, phase)
        prior_context = self._build_prior_context(session_state, mode=mode)
        max_workers = int(os.environ.get("LLM_MAX_WORKERS", "1"))

        def _call_one(profile):
            """Single agent call — thread-safe (no shared mutable state written here)."""
            gap_context = ""
            if profile.tier == 1 and phase in ("A", "B"):
                if mode == "contract_audit":
                    cm = _get_contract_modules()
                    gap_context = cm["gap_context"](
                        pending_gaps=session_state.pending_gaps(),
                        agent_domain=profile.domain_group,
                    )
                else:
                    gap_context = build_gap_context_for_agent(
                        pending_gaps=session_state.pending_gaps(),
                        agent_domain_group=profile.domain_group,
                    )
            phase_instruction = env_builder.build_phase_instruction(
                phase, round_num, gap_context=gap_context
            )
            _rate_limiter.acquire()
            response = self._call_agent(
                profile=profile,
                phase=phase,
                round_num=round_num,
                phase_instruction=phase_instruction,
                prior_context=prior_context,
                network_summary=network_summary,
                mode=mode,
            )
            return profile, gap_context, response

        if max_workers > 1:
            # Parallel LLM calls within the round; process findings sequentially after
            submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "1.0"))
            results = []
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {}
                for i, p in enumerate(active_profiles):
                    if i > 0 and submit_delay > 0:
                        import time as _t; _t.sleep(submit_delay)
                    futures[pool.submit(_call_one, p)] = p
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        logger.warning(f"Agent {futures[future].agent_id} round {round_num} error: {e}")
        else:
            results = []
            for profile in active_profiles:
                try:
                    results.append(_call_one(profile))
                except Exception as e:
                    logger.warning(f"Agent {profile.agent_id} round {round_num} error: {e}")

        # Process findings sequentially (no LLM — safe, preserves GAP routing order)
        for profile, gap_context, response in results:
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
                self._process_expert_response(response, profile, round_num, session_state, mode=mode)
                if phase in ("A", "B"):
                    self._process_gap_declarations(response, profile, round_num, session_state, mode=mode)
            else:
                self._process_attacker_response(response, profile, round_num, session_state, mode=mode)

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
        mode: str = "network_security",
    ) -> str:
        """Gọi LLM cho 1 agent và trả về response text."""
        # Chọn LLM (boost cho attacker Phase C)
        llm = self.boost_llm if (profile.tier == 2 and phase == "C") else self.llm

        if mode == "contract_audit":
            specificity_hint = (
                "Be specific, reference actual functions, state variables, "
                "and code patterns from the contract."
            )
        else:
            specificity_hint = "Be specific, reference actual hosts and services from the infrastructure."

        messages = [
            {"role": "system", "content": profile.system_prompt},
            {
                "role": "user",
                "content": (
                    f"{phase_instruction}\n\n"
                    f"=== DISCUSSION SO FAR ===\n{prior_context}\n\n"
                    f"Provide your analysis for Round {round_num}. "
                    f"{specificity_hint}"
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
        mode: str = "network_security",
    ):
        """Parse expert agent response → ExpertFinding / ContractFinding entries."""
        if mode == "contract_audit":
            cm = _get_contract_modules()
            finding_dict = cm["parse_finding"](text, profile, round_num)
            if not finding_dict:
                return
            session_state.expert_findings.append(finding_dict)
            logger.debug(
                f"ContractFinding [{finding_dict['finding_id']}] from {profile.agent_id}: "
                f"{finding_dict['title']} ({finding_dict['severity']})"
            )
            return

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
            mitre_techniques=finding_raw.get("mitre_techniques", []),
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
        mode: str = "network_security",
    ):
        """Parse attacker agent response → AttackerFinding or AttackerCorroboration."""
        if mode == "contract_audit":
            cm = _get_contract_modules()
            ContractAttackerAction = cm["attacker_action"]
            action = ContractAttackerAction.parse_from_text(text)
            if not action:
                return
            action_type = action["action_type"]
            if action_type == ContractAttackerAction.ADD_PATH:
                finding_id = f"af_{uuid.uuid4().hex[:8]}"
                session_state.attacker_findings.append({
                    "finding_id":       finding_id,
                    "attacker_profile": profile.persona,
                    "title":            action["finding_ref"] or f"Attack path by {profile.display_name}",
                    "description":      action["reason"],
                    "severity":         "high",
                    "base_confidence":  0.60,
                    "path_description": action["path"],
                })
                logger.debug(f"Contract Attacker NEW path [{finding_id}] by {profile.agent_id}")
            else:
                self._attach_corroboration(
                    action=action,
                    attacker_profile=profile.persona,
                    session_state=session_state,
                )
            return

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
        mode: str = "network_security",
    ):
        """
        Parse GAP declarations từ expert agent post và lưu vào session state.
        Gaps sẽ được route đến domain groups phù hợp trong round tiếp theo.
        """
        if mode == "contract_audit":
            cm = _get_contract_modules()
            gaps = cm["parse_gap"](
                text=text,
                author_domain=profile.domain_group,
                author_persona=profile.persona,
                round_num=round_num,
            )
        else:
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

    def _build_prior_context(self, session_state: CyberSessionState, mode: str = "network_security") -> str:
        """
        Build text summary của các findings đã có để inject vào tiếp theo.
        Giới hạn độ dài để không overflow context window.

        Includes Published Registry (Solution A for Weakness #4):
        agents see unique titles already reported → instructed to CHALLENGE
        or EXPAND rather than re-report the same finding.
        """
        lines = []

        if mode == "contract_audit":
            cm = _get_contract_modules()
            registry = cm["published_registry"](session_state.expert_findings, max_entries=20)
        else:
            from .cyber_oasis_env import build_published_registry
            registry = build_published_registry(session_state.expert_findings, max_entries=20)

        # Published Registry — shown first so agents read it before anything else
        if registry:
            lines.append(registry)
            lines.append("")  # blank line separator

        if session_state.expert_findings:
            lines.append(f"=== RECENT FINDINGS (last 6) ===")
            # Reduced from 10 to 6 — registry already covers all unique titles
            recent = session_state.expert_findings[-6:]
            for f in recent:
                corr_count = len(f.get("attacker_corroborations", []))
                if mode == "contract_audit":
                    author_key = "author_domain"
                    swc_info = f"[{f.get('swc_id', '?')}] " if f.get("swc_id") else ""
                else:
                    author_key = "author_group"
                    swc_info = ""
                lines.append(
                    f"[{f.get('severity','?').upper()}] {swc_info}{f.get('title','Untitled')} "
                    f"(by {f.get(author_key,'?')}/{f.get('author_persona','?')}, "
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
            author_key = "author_domain" if mode == "contract_audit" else "author_group"
            for g in all_gaps[-8:]:  # show last 8 to avoid overflow
                lines.append(
                    f"  [{g.get(author_key,'?')}] Area: {g.get('analyzed','?')} — "
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
