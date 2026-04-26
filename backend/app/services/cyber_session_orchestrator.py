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
import re
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
from ..utils.llm_client import LLMClient, LLMClientPool
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
        parse_semantic_finding_from_text,
        parse_contract_gap_declarations, build_gap_context_for_agent as contract_gap_context,
        build_published_registry as contract_published_registry,
        get_phase_for_round as contract_get_phase,
        extract_known_functions,
    )
    return {
        "env_builder":          ContractAuditEnvBuilder,
        "attacker_action":      ContractAttackerAction,
        "parse_finding":        parse_contract_finding_from_text,
        "parse_semantic":       parse_semantic_finding_from_text,
        "parse_gap":            parse_contract_gap_declarations,
        "gap_context":          contract_gap_context,
        "published_registry":   contract_published_registry,
        "get_phase":            contract_get_phase,
        "extract_funcs":        extract_known_functions,
    }

logger = get_logger("mirofish.cyber_orchestrator")


def _build_phase_c_review_list(
    expert_findings: List[Dict[str, Any]],
    invariants: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    RC-3 Two-step Phase C: build per-(SWC, function) review list for attackers.

    RC-3a: No social proof — no confidence scores, no group counts.
           Header frames claims as UNVERIFIED, default stance is DISMISS.
    RC-3b: One entry per (SWC, function) pair — forces per-function evaluation,
           prevents one SWC-level dismiss/confirm from sweeping all related findings.
    Invariant section appended when invariants are provided.
    """
    if not expert_findings:
        return ""

    # Build deduplicated per-(swc, func) items, preserving claimed evidence
    seen: set = set()
    items: List[Dict[str, Any]] = []
    for f in expert_findings:
        swc = f.get("swc_id") or "SWC-???"
        funcs = f.get("affected_functions") or []
        evidence_list = f.get("evidence") or []
        evidence = evidence_list[0] if evidence_list else ""
        title = f.get("title", "Untitled")

        if funcs:
            for func in funcs[:2]:  # max 2 functions per finding
                key = (swc, func.lower().rstrip("()"))
                if key not in seen:
                    seen.add(key)
                    items.append({"swc": swc, "func": func, "title": title, "evidence": evidence})
        else:
            key = (swc, "")
            if key not in seen:
                seen.add(key)
                items.append({"swc": swc, "func": "", "title": title, "evidence": evidence})

    if not items:
        return ""

    items = items[:25]  # cap list to avoid context overflow

    # RC-3a: adversarial framing — no confidence/group signals
    lines = [
        f"=== UNVERIFIED CLAIMS — {len(items)} per-function claims require independent attacker verification ===",
        "DEFAULT STANCE: DISMISS — only CONFIRM if you independently trace the exploit through contract code above.",
        "",
    ]
    for i, item in enumerate(items, 1):
        func_str = f" in {item['func']}" if item["func"] else ""
        ev_str = f"\n  Claimed evidence: {item['evidence']}" if item["evidence"] else ""
        lines.append(
            f"[F{i}] {item['swc']}{func_str} — {item['title'][:70]}"
            + ev_str
        )

    lines += [
        "",
        "Required format — one block per claim, INCLUDE function name:",
        "  [ATTACKER_DISMISS SWC-101 transfer()]",
        "  Finding: <title>",
        "  Reason: <why this specific function is NOT vulnerable>",
        "  ---",
        "  [ATTACKER_CONFIRM SWC-114 approve()]",
        "  Finding: <title>",
        "  Path: <concrete step-by-step exploit through this function>",
        "",
    ]

    # Invariant attack objectives section
    if invariants:
        lines += [
            "=== INVARIANT ATTACK OBJECTIVES — Prove or disprove each invariant ===",
            "For each invariant you can VIOLATE, use [ATTACKER_EXPLOIT INV-xxx]:",
            "",
        ]
        for inv in invariants[:10]:
            funcs_str = ", ".join(inv.get("functions") or []) or "—"
            hint_str = f"\n  Hint: {inv['violation_hint']}" if inv.get("violation_hint") else ""
            lines.append(
                f"  [{inv['id']}] {inv.get('statement', '')}\n"
                f"    Try via: {funcs_str}{hint_str}"
            )
        lines += [
            "",
            "  [ATTACKER_EXPLOIT INV-001]",
            "  Path: <step-by-step exploit>",
            "  Impact: <what attacker gains>",
            "  Feasible: yes/no",
            "",
        ]

    return "\n".join(lines)


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
        if llm_client is not None:
            self.llm = llm_client
        elif Config.LLM2_VERTEX_AI_KEY_FILE and Config.LLM2_BASE_URL:
            client1 = LLMClient(rpm_slot_file="/tmp/mirofish_rpm_0.json")
            client2 = LLMClient(
                vertex_key_file=Config.LLM2_VERTEX_AI_KEY_FILE,
                base_url=Config.LLM2_BASE_URL,
                model=Config.LLM_MODEL_NAME,
                rpm_slot_file="/tmp/mirofish_rpm_1.json",
                rpm_limit=Config.LLM2_GLOBAL_RPM_LIMIT,
            )
            self.llm = LLMClientPool([client1, client2])
            logger.info("LLMClientPool: 2 Vertex AI accounts active, pool_size=2")
        else:
            self.llm = LLMClient()
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
        invariants: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Khởi chạy session trong background thread.
        Returns task_id để frontend poll.

        Args:
            mode: "network_security" (default) | "contract_audit"
            invariants: protocol invariants from ContractInvariantExtractor (contract_audit only)
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
            args=(task_id, session_id, graph_id, network_summary, profiles, mode, invariants),
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
        invariants: Optional[List[Dict[str, Any]]] = None,
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
                # RC-1 (2nd layer): extract known function names once per session
                known_functions = cm["extract_funcs"](network_summary)
                logger.info(
                    f"  Contract known functions ({len(known_functions)}): "
                    f"{', '.join(sorted(known_functions)) or '(none extracted)'}"
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
                known_functions = None

            session_state = CyberSessionState(
                session_id=session_id,
                graph_id=graph_id,
            )
            self._save_session_state(session_state)

            # RC-3 Two-step Phase C: computed after round 7, injected into Phase C rounds
            phase_c_review_list = ""

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
                    known_functions=known_functions,
                    phase_c_review_list=phase_c_review_list,
                )

                session_state.current_round = round_num
                session_state.current_phase = phase
                self._save_session_state(session_state)

                # RC-3: after Phase B ends (round 7), build Phase C review list
                if round_num == 7 and mode == "contract_audit":
                    phase_c_review_list = _build_phase_c_review_list(
                        session_state.expert_findings,
                        invariants=invariants,
                    )
                    logger.info(
                        f"Phase C review list built: "
                        f"{len(phase_c_review_list.splitlines())} lines from "
                        f"{len(session_state.expert_findings)} expert findings"
                        + (f", {len(invariants)} invariants" if invariants else "")
                    )

                # Inter-round cooldown — let Vertex AI TPM window partially recover
                # before next burst. Reads LLM_ROUND_COOLDOWN_S (default 15s).
                if round_num < TOTAL_ROUNDS:
                    cooldown = float(os.environ.get("LLM_ROUND_COOLDOWN_S", "15"))
                    if cooldown > 0:
                        time.sleep(cooldown)

            session_state.current_phase = "done"

            # P8: Attacker gate — finalize confidence với net vote ratio sau Phase C
            if mode == "contract_audit":
                self._apply_attacker_gate(session_state)

            self._save_session_state(session_state)

            # Serialize findings cho result
            self.task_manager.complete_task(task_id, {
                "session_id": session_id,
                "graph_id": graph_id,
                "expert_findings": session_state.expert_findings,
                "attacker_findings": session_state.attacker_findings,
                "semantic_findings": session_state.semantic_findings,
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
        known_functions=None,
        phase_c_review_list: str = "",
    ):
        """
        Chạy 1 round: dispatcher cho two-stage (Phase A/B contract_audit) hoặc single-stage.

        Two-stage: Stage 1 (free-form analysis + CLAIMs) → Stage 2 (FINDINGs + CHALLENGE/VALIDATE).
        Single-stage: Phase C attackers và network_security mode dùng luồng cũ.
        """
        if env_builder is None:
            env_builder = self.env_builder

        active_profiles = env_builder.get_active_agents_for_phase(profiles, phase)
        prior_context = self._build_prior_context(session_state, mode=mode)
        pool_size = getattr(self.llm, "pool_size", 1)
        max_workers = max(int(os.environ.get("LLM_MAX_WORKERS", "1")), pool_size)

        two_stage = (
            os.environ.get("TWO_STAGE_ROUNDS", "true").lower() == "true"
            and mode == "contract_audit"
            and phase in ("A", "B")
        )

        if two_stage:
            logger.info(f"[Round {round_num}] Two-stage mode: Phase={phase}, {len(active_profiles)} agents")

            # Stage 1: free-form analysis + CLAIM declarations
            stage1_posts = self._run_stage1(
                round_num=round_num, phase=phase,
                active_profiles=active_profiles,
                session_state=session_state,
                prior_context=prior_context,
                network_summary=network_summary,
                mode=mode, env_builder=env_builder,
                known_functions=known_functions,
                max_workers=max_workers,
            )
            stage1_claims = self._parse_stage1_claims(stage1_posts)
            session_state.round_stage1_posts[round_num] = stage1_posts
            logger.info(
                f"[Round {round_num}] Stage 1 done: {len(stage1_posts)} posts, "
                f"{len(stage1_claims)} CLAIMs extracted"
            )

            # Inter-stage cooldown — let Vertex AI TPM window recover after Stage 1 burst
            inter_stage_cooldown = float(os.environ.get("LLM_INTER_STAGE_COOLDOWN_S", "30"))
            if inter_stage_cooldown > 0:
                logger.info(f"[Round {round_num}] Inter-stage cooldown {inter_stage_cooldown:.0f}s...")
                time.sleep(inter_stage_cooldown)

            # Stage 2: structured findings with shared feed + CHALLENGE/VALIDATE
            feed_context = self._build_feed_context(round_num, stage1_posts, stage1_claims=stage1_claims)
            stage2_prior = feed_context + "\n\n" + prior_context

            logger.info(f"[Round {round_num}] Stage 2 starting: {len(active_profiles)} agents")
            self._run_stage2(
                round_num=round_num, phase=phase,
                active_profiles=active_profiles,
                session_state=session_state,
                prior_context=stage2_prior,
                network_summary=network_summary,
                mode=mode, env_builder=env_builder,
                known_functions=known_functions,
                phase_c_review_list=phase_c_review_list,
                stage1_claims=stage1_claims,
                max_workers=max_workers,
            )
            return  # two-stage path complete

        # ── Single-stage path (Phase C, network_security, or TWO_STAGE_ROUNDS=false) ──
        self._run_single_stage(
            round_num=round_num, phase=phase,
            active_profiles=active_profiles,
            session_state=session_state,
            prior_context=prior_context,
            network_summary=network_summary,
            mode=mode, env_builder=env_builder,
            known_functions=known_functions,
            phase_c_review_list=phase_c_review_list,
            max_workers=max_workers,
        )

    def _run_single_stage(
        self,
        round_num: int,
        phase: str,
        active_profiles: List,
        session_state: CyberSessionState,
        prior_context: str,
        network_summary: str,
        mode: str,
        env_builder,
        known_functions,
        phase_c_review_list: str,
        max_workers: int,
    ):
        """
        Luồng single-stage gốc — dùng cho Phase C, network_security, và TWO_STAGE_ROUNDS=false.
        """
        def _call_one(profile):
            """Single agent call — thread-safe (no shared mutable state written here)."""
            import time as _time
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
            # RC-3: pass phase_c_review_list to Phase C instructions
            phase_instruction = env_builder.build_phase_instruction(
                phase, round_num,
                gap_context=gap_context,
                phase_c_review_list=phase_c_review_list if phase == "C" else "",
            )
            _rate_limiter.acquire()
            # RC1: attacker Phase C → keep raw text (think blocks intact) for tag rescue
            is_attacker_phase_c = (profile.tier == 2 and phase == "C")
            _t0 = _time.time()
            response = self._call_agent(
                profile=profile,
                phase=phase,
                round_num=round_num,
                phase_instruction=phase_instruction,
                prior_context=prior_context,
                network_summary=network_summary,
                mode=mode,
                strip_think=not is_attacker_phase_c,
            )
            _elapsed = _time.time() - _t0
            logger.info(
                f"[TIMING] Phase={phase} R{round_num} agent={profile.agent_id} "
                f"tier={profile.tier} latency={_elapsed:.1f}s"
            )
            return profile, gap_context, response

        if max_workers > 1:
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
            submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "0.0"))
            results = []
            for i, profile in enumerate(active_profiles):
                if i > 0 and submit_delay > 0:
                    import time as _t; _t.sleep(submit_delay)
                try:
                    results.append(_call_one(profile))
                except Exception as e:
                    logger.warning(f"Agent {profile.agent_id} round {round_num} error: {e}")

        # Process findings sequentially (no LLM — safe, preserves GAP routing order)
        _think_re = re.compile(r'<think>[\s\S]*?</think>')
        for profile, gap_context, response in results:
            # RC1: attacker Phase C responses are raw (think blocks intact for tag rescue).
            is_attacker_phase_c = (profile.tier == 2 and phase == "C")
            feed_content = _think_re.sub('', response).strip() if is_attacker_phase_c else response
            self._append_feed_post(session_state.session_id, {
                "round_num": round_num,
                "phase": phase,
                "agent_id": profile.agent_id,
                "agent_display": profile.display_name,
                "tier": profile.tier,
                "domain_group": profile.domain_group,
                "persona": profile.persona,
                "content": feed_content,
                "timestamp": datetime.now().isoformat(),
                "gap_context_injected": bool(gap_context),
            })
            if profile.tier == 1:
                self._process_expert_response(
                    response, profile, round_num, session_state,
                    mode=mode, known_functions=known_functions,
                )
                if phase in ("A", "B"):
                    self._process_gap_declarations(response, profile, round_num, session_state, mode=mode)
            else:
                # Pass raw response (may contain think blocks) — parse_from_text uses last-tag logic
                self._process_attacker_response(response, profile, round_num, session_state, mode=mode)

        if phase in ("A", "B"):
            self._mark_gaps_as_routed(session_state)

    def _run_stage1(
        self,
        round_num: int,
        phase: str,
        active_profiles: List,
        session_state: CyberSessionState,
        prior_context: str,
        network_summary: str,
        mode: str,
        env_builder,
        known_functions,
        max_workers: int,
    ) -> List[Dict[str, Any]]:
        """
        Stage 1: tất cả tier-1 agents viết free-form analysis song song.
        max_tokens=STAGE1_MAX_TOKENS (default 400) — ngắn hơn, không parse FINDING.
        Returns: list of stage1 post dicts (saved to feed.jsonl với stage=1).
        """
        def _call_stage1(profile):
            import time as _time
            gap_context = ""
            if mode == "contract_audit":
                cm = _get_contract_modules()
                gap_context = cm["gap_context"](
                    pending_gaps=session_state.pending_gaps(),
                    agent_domain=profile.domain_group,
                )
            phase_instruction = env_builder.build_phase_instruction(
                phase, round_num, gap_context=gap_context, stage=1,
            )
            _rate_limiter.acquire()
            t0 = _time.time()
            response = self._call_agent(
                profile=profile, phase=phase, round_num=round_num,
                phase_instruction=phase_instruction, prior_context=prior_context,
                network_summary=network_summary, mode=mode, strip_think=True,
                max_tokens=self._STAGE1_MAX_TOKENS,
            )
            logger.info(
                f"[TIMING] Phase={phase} R{round_num} S1 agent={profile.agent_id} "
                f"latency={_time.time()-t0:.1f}s"
            )
            return profile, response

        submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "1.0"))
        results = []
        if max_workers > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {}
                for i, p in enumerate(active_profiles):
                    if i > 0 and submit_delay > 0:
                        import time as _t; _t.sleep(submit_delay)
                    futures[pool.submit(_call_stage1, p)] = p
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        logger.warning(f"Stage1 {futures[future].agent_id} R{round_num}: {e}")
        else:
            for i, p in enumerate(active_profiles):
                if i > 0 and submit_delay > 0:
                    import time as _t; _t.sleep(submit_delay)
                try:
                    results.append(_call_stage1(p))
                except Exception as e:
                    logger.warning(f"Stage1 {p.agent_id} R{round_num}: {e}")

        stage1_posts = []
        for profile, response in results:
            post = {
                "round_num":    round_num,
                "phase":        phase,
                "stage":        1,
                "agent_id":     profile.agent_id,
                "agent_display": profile.display_name,
                "domain_group": profile.domain_group,
                "persona":      profile.persona,
                "content":      response.strip(),
                "timestamp":    datetime.now().isoformat(),
            }
            stage1_posts.append(post)
            self._append_feed_post(session_state.session_id, post)
        return stage1_posts

    def _run_stage2(
        self,
        round_num: int,
        phase: str,
        active_profiles: List,
        session_state: CyberSessionState,
        prior_context: str,
        network_summary: str,
        mode: str,
        env_builder,
        known_functions,
        phase_c_review_list: str,
        stage1_claims: List[Dict[str, Any]],
        max_workers: int,
    ):
        """
        Stage 2: structured findings (FINDING/SEMANTIC_FINDING) + CHALLENGE/VALIDATE.
        prior_context đã bao gồm feed_context từ Stage 1.
        Sau parse findings, gọi _parse_challenge_validate() với stage1_claims.
        """
        # P4: Designated skeptic — 1 offensive tier-1 agent per round
        import random as _random
        offensive_agents = [p for p in active_profiles if p.persona == "offensive" and p.tier == 1]
        skeptic_id = _random.choice(offensive_agents).agent_id if offensive_agents else None
        _SKEPTIC_INSTRUCTION = (
            "\n\n--- YOUR ROLE THIS ROUND: SKEPTIC ---"
            "\nYour PRIMARY task is to challenge at least 2 CLAIMs or findings you believe are "
            "incorrect or overstated. Write CHALLENGE_FINDING blocks FIRST, then any new FINDING "
            "the group missed. Do not validate claims you are not certain about."
        )

        def _call_stage2(profile):
            import time as _time
            gap_context = ""
            if mode == "contract_audit":
                cm = _get_contract_modules()
                gap_context = cm["gap_context"](
                    pending_gaps=session_state.pending_gaps(),
                    agent_domain=profile.domain_group,
                )
            phase_instruction = env_builder.build_phase_instruction(
                phase, round_num, gap_context=gap_context, stage=2,
            )
            if profile.agent_id == skeptic_id:
                phase_instruction += _SKEPTIC_INSTRUCTION
            _rate_limiter.acquire()
            t0 = _time.time()
            response = self._call_agent(
                profile=profile, phase=phase, round_num=round_num,
                phase_instruction=phase_instruction, prior_context=prior_context,
                network_summary=network_summary, mode=mode, strip_think=True, stage=2,
            )
            logger.info(
                f"[TIMING] Phase={phase} R{round_num} S2 agent={profile.agent_id}"
                + (" [SKEPTIC]" if profile.agent_id == skeptic_id else "")
                + f" latency={_time.time()-t0:.1f}s"
            )
            return profile, gap_context, response

        # Stage 2 có thể cần delay dài hơn Stage 1 nếu STAGE2_MAX_TOKENS lớn
        submit_delay = float(os.environ.get("LLM_STAGE2_SUBMIT_DELAY_S",
                                            os.environ.get("LLM_SUBMIT_DELAY_S", "1.0")))
        results = []
        if max_workers > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {}
                for i, p in enumerate(active_profiles):
                    if i > 0 and submit_delay > 0:
                        import time as _t; _t.sleep(submit_delay)
                    futures[pool.submit(_call_stage2, p)] = p
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        logger.warning(f"Stage2 {futures[future].agent_id} R{round_num}: {e}")
        else:
            for i, p in enumerate(active_profiles):
                if i > 0 and submit_delay > 0:
                    import time as _t; _t.sleep(submit_delay)
                try:
                    results.append(_call_stage2(p))
                except Exception as e:
                    logger.warning(f"Stage2 {p.agent_id} R{round_num}: {e}")

        for profile, gap_context, response in results:
            self._append_feed_post(session_state.session_id, {
                "round_num":   round_num,
                "phase":       phase,
                "stage":       2,
                "agent_id":    profile.agent_id,
                "agent_display": profile.display_name,
                "tier":        profile.tier,
                "domain_group": profile.domain_group,
                "persona":     profile.persona,
                "content":     response,
                "timestamp":   datetime.now().isoformat(),
                "gap_context_injected": bool(gap_context),
            })
            if profile.tier == 1:
                self._process_expert_response(
                    response, profile, round_num, session_state,
                    mode=mode, known_functions=known_functions,
                )
                if phase in ("A", "B"):
                    self._process_gap_declarations(response, profile, round_num, session_state, mode=mode)
                # CHALLENGE/VALIDATE parsing — updates confidence on claims and prior-round findings
                self._parse_challenge_validate(
                    text=response, profile=profile,
                    round_num=round_num, session_state=session_state,
                    stage1_claims=stage1_claims,
                )

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
        strip_think: bool = True,
        max_tokens: Optional[int] = None,
        stage: int = 0,
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

        # Stage 2: token override via env var + optional thinking disable
        is_attacker_phase_c = (profile.tier == 2 and phase == "C")
        if stage == 2:
            stage2_max = int(os.environ.get("STAGE2_MAX_TOKENS", "0"))
            max_tok = stage2_max if stage2_max > 0 else (max_tokens if max_tokens is not None else 1500)
        else:
            max_tok = max_tokens if max_tokens is not None else (4096 if is_attacker_phase_c else 1500)

        extra_body = None
        if stage == 2 and os.environ.get("STAGE2_DISABLE_THINKING", "").lower() in ("1", "true", "yes"):
            extra_body = {"thinking_config": {"thinking_budget": 0}}

        return llm.chat(messages, temperature=0.7, max_tokens=max_tok, strip_think=strip_think,
                        extra_body=extra_body)

    # ─── Parsers ──────────────────────────────────────────────────────────────

    def _process_semantic_response(
        self,
        text: str,
        profile: CyberAgentProfile,
        round_num: int,
        session_state: CyberSessionState,
        known_functions=None,
        is_attacker_surfaced: bool = False,
    ):
        """Parse SEMANTIC_FINDING block from agent post → appended to semantic_findings."""
        cm = _get_contract_modules()
        sf = cm["parse_semantic"](text, profile, round_num, known_functions=known_functions)
        if not sf:
            return
        sf["is_attacker_surfaced"] = is_attacker_surfaced
        session_state.semantic_findings.append(sf)
        logger.debug(
            f"SemanticFinding [{sf['finding_id']}] from {profile.agent_id}: "
            f"{sf['title']} ({sf['category']}, {sf['severity']})"
        )

    def _process_expert_response(
        self,
        text: str,
        profile: CyberAgentProfile,
        round_num: int,
        session_state: CyberSessionState,
        mode: str = "network_security",
        known_functions=None,
    ):
        """Parse expert agent response → ExpertFinding / ContractFinding entries."""
        if mode == "contract_audit":
            cm = _get_contract_modules()
            finding_dict = cm["parse_finding"](text, profile, round_num, known_functions=known_functions)
            if not finding_dict:
                self._process_semantic_response(text, profile, round_num, session_state, known_functions)
                return
            session_state.expert_findings.append(finding_dict)
            logger.debug(
                f"ContractFinding [{finding_dict['finding_id']}] from {profile.agent_id}: "
                f"{finding_dict['title']} ({finding_dict['severity']})"
            )
            # Also check for semantic findings in the same post
            self._process_semantic_response(text, profile, round_num, session_state, known_functions)
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
                # Still check for SEMANTIC_FINDING in attacker post
                self._process_semantic_response(
                    text, profile, round_num, session_state, is_attacker_surfaced=True
                )
                return
            action_type = action["action_type"]
            if action_type == ContractAttackerAction.EXPLOIT:
                # Invariant violation — feasible exploits become attacker findings
                inv_id = action.get("invariant_id", "INV-???")
                feasible = action.get("feasible", "yes").lower() == "yes"
                if feasible:
                    finding_id = f"af_{uuid.uuid4().hex[:8]}"
                    session_state.attacker_findings.append({
                        "finding_id":       finding_id,
                        "invariant_id":     inv_id,
                        "attacker_profile": profile.persona,
                        "title":            f"Invariant Violated: {inv_id}",
                        "description":      action.get("reason", ""),
                        "path_description": action.get("path", ""),
                        "severity":         "high",
                        "base_confidence":  0.70,
                        "source":           "invariant_exploit",
                    })
                    logger.debug(
                        f"Contract Attacker EXPLOIT [{finding_id}] {inv_id} "
                        f"by {profile.agent_id}"
                    )
            elif action_type == ContractAttackerAction.ADD_PATH:
                # Check if the ADD_PATH contains a SEMANTIC_FINDING instead of FINDING
                if "SEMANTIC_FINDING:" in text or "SEMANTIC_FINDING :" in text:
                    self._process_semantic_response(
                        text, profile, round_num, session_state, is_attacker_surfaced=True
                    )
                else:
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

    # ─── Two-Stage Round helpers ───────────────────────────────────────────────

    _STAGE1_FEED_CHARS_PER_POST = int(os.environ.get("STAGE1_FEED_CHARS_PER_POST", "300"))
    _STAGE1_MAX_TOKENS = int(os.environ.get("STAGE1_MAX_TOKENS", "400"))

    def _build_feed_context(
        self,
        round_num: int,
        stage1_posts: List[Dict[str, Any]],
        stage1_claims: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Build context từ Stage 1 posts của round hiện tại để inject vào Stage 2 prompt.

        DRY: Khối CLAIM dựng từ cùng list stage1_claims đã parse bởi _parse_stage1_claims().
        Không re-parse regex ở đây — một nguồn regex duy nhất.
        Khi implement: truyền [] thay None khi parse trả về list rỗng → hành vi nhất quán.
        """
        if not stage1_posts:
            return ""

        cap = self._STAGE1_FEED_CHARS_PER_POST

        # Khối 1: summary truncated — cho reasoning context
        lines = [f"=== STAGE 1 ANALYSIS — Round {round_num} ({len(stage1_posts)} experts) ==="]
        lines.append("(Summaries — truncated for token budget)\n")
        for post in stage1_posts:
            domain = post.get("domain_group", "?")
            persona = post.get("persona", "?")
            content = post.get("content", "").strip()
            if len(content) > cap:
                content = content[:cap] + "…"
            lines.append(f"[{domain}/{persona}]: {content}")
            lines.append("")

        # Khối 2: CLAIM lines — FULL text từ stage1_claims đã parse (không truncate)
        if stage1_claims:
            lines.append(
                f"=== STAGE 1 CLAIMS — Round {round_num} "
                f"(full, use exact title to VALIDATE/CHALLENGE) ==="
            )
            for c in stage1_claims:
                lines.append(
                    f"  [{c.get('author_domain', '?')}/{c.get('author_id', '?')}] "
                    f"CLAIM: {c['title']}"
                )
            lines.append("")

        return "\n".join(lines)

    def _parse_stage1_claims(
        self,
        stage1_posts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Extract CLAIM: tags từ Stage 1 posts.
        CLAIMs được dùng làm target cho CHALLENGE/VALIDATE trong Stage 2.
        Không phải expert_findings — không qua consensus engine.
        """
        _claim_re = re.compile(r'(?i)^CLAIM\s*:\s*(.+)$', re.MULTILINE)
        claims = []
        for post in stage1_posts:
            for m in _claim_re.finditer(post.get("content", "")):
                claims.append({
                    "title":        m.group(1).strip(),
                    "author_id":    post.get("agent_id", "?"),
                    "author_domain": post.get("domain_group", "?"),
                    "round_num":    post.get("round_num", 0),
                    "challenged_by": [],
                    "validated_by":  [],
                })
        return claims

    def _parse_challenge_validate(
        self,
        text: str,
        profile,
        round_num: int,
        session_state: CyberSessionState,
        stage1_claims: Optional[List[Dict[str, Any]]] = None,
    ):
        """
        Parse CHALLENGE_FINDING và VALIDATE_FINDING từ Stage 2 response.

        Target priority:
          1. Stage 1 CLAIMs (same round — giải quyết ordering trap)
          2. expert_findings từ round trước (đã commit)

        P1: Sau khi CLAIM match, fuzzy-link sang expert_finding cùng round (Jaccard ≥ 0.15).
        P6: Guard — bỏ qua VALIDATE nếu CLAIM là phủ định ("not vulnerable", v.v.).
        """
        _CHALLENGE_RE = re.compile(
            r'(?i)^CHALLENGE_FINDING\s*:\s*(.+?)$\s*^REASON\s*:\s*(.+?)(?=^[A-Z_]+\s*:|$)',
            re.MULTILINE | re.DOTALL,
        )
        _VALIDATE_RE = re.compile(
            r'(?i)^VALIDATE_FINDING\s*:\s*(.+?)$\s*^DOMAIN_EVIDENCE\s*:\s*(.+?)(?=^[A-Z_]+\s*:|$)',
            re.MULTILINE | re.DOTALL,
        )

        def _normalize(s: str) -> str:
            """Lowercase + strip trailing punctuation — tolerate minor LLM title abbreviation."""
            return re.sub(r'[.,!?;:]+$', '', s.lower().strip())

        def _find_target(title_fragment: str):
            frag = _normalize(title_fragment)
            # Priority 1: Stage 1 CLAIMs (same round)
            if stage1_claims:
                for c in stage1_claims:
                    if frag in _normalize(c["title"]):
                        return ("claim", c)
            # Priority 2: expert_findings từ round cũ (đã commit)
            for f in session_state.expert_findings:
                if f.get("round_number", 0) < round_num and frag in _normalize(f.get("title", "")):
                    return ("finding", f)
            return (None, None)

        def _claim_is_negative(claim: dict) -> bool:
            """P6: True nếu CLAIM phủ định vulnerability — không propagate VALIDATE."""
            text_n = _normalize(claim.get("title", "") + " " + claim.get("content", ""))
            _TITLE_NEG = ("not vulnerable", "no risk", "is safe", "is not exploitable",
                          "cannot be exploited", "miscategorized", "false positive",
                          "not a vulnerability", "no vulnerability")
            if any(s in text_n for s in _TITLE_NEG):
                return True
            # Kiểm tra mệnh đề "because <reason>" bắt đầu bằng negation
            idx = text_n.find(" because ")
            if idx != -1:
                reason = text_n[idx + 9:].strip()
                _REASON_NEG = ("it does not", "there is no ", "the guard", "already protected",
                               "not possible", "no way to", "impossible", "is prevented")
                if any(reason.startswith(s) for s in _REASON_NEG):
                    return True
            return False

        def _fuzzy_link_claim_to_finding(claim: dict):
            """P1: Tìm expert_finding cùng round có title overlap cao nhất với CLAIM."""
            claim_tokens = set(_normalize(claim.get("title", "")).split())
            if not claim_tokens:
                return None
            min_overlap = 3 if len(claim_tokens) < 8 else 2
            best_match, best_score = None, 0
            for f in session_state.expert_findings:
                if f.get("round_number") != round_num:
                    continue
                finding_tokens = set(_normalize(f.get("title", "")).split())
                overlap = len(claim_tokens & finding_tokens)
                if overlap > best_score:
                    best_score, best_match = overlap, f
            if best_match and best_score >= min_overlap:
                union = claim_tokens | set(_normalize(best_match.get("title", "")).split())
                jaccard = best_score / len(union) if union else 0
                if jaccard >= 0.15:
                    logger.debug(
                        f"P1 link CLAIM→finding '{best_match.get('title','')[:50]}' "
                        f"(overlap={best_score}, jaccard={jaccard:.2f})"
                    )
                    return best_match
            return None

        for m in _CHALLENGE_RE.finditer(text):
            title_fragment = m.group(1).strip()
            reason = m.group(2).strip()[:300]
            kind, target = _find_target(title_fragment)
            if target is None:
                continue
            entry = {
                "challenger": profile.agent_id,
                "domain":     profile.domain_group,
                "reason":     reason,
                "round":      round_num,
            }
            target.setdefault("challenged_by", []).append(entry)
            # Confidence penalty chỉ áp lên expert_findings (claims không có confidence)
            if kind == "finding" and profile.domain_group != target.get("author_domain"):
                target["confidence"] = max(0.1, target.get("confidence", 0.5) - 0.10)
            logger.debug(
                f"CHALLENGE [{profile.agent_id}] → {kind} '{title_fragment[:60]}'"
            )

        for m in _VALIDATE_RE.finditer(text):
            title_fragment = m.group(1).strip()
            evidence = m.group(2).strip()[:300]
            kind, target = _find_target(title_fragment)
            if target is None:
                continue

            # P6: skip nếu CLAIM là phủ định
            if kind == "claim" and _claim_is_negative(target):
                logger.debug(
                    f"VALIDATE [{profile.agent_id}] skipped — negative CLAIM '{title_fragment[:60]}'"
                )
                continue

            # P1: fuzzy-link CLAIM → expert_finding cùng round
            if kind == "claim":
                linked = _fuzzy_link_claim_to_finding(target)
                if linked is not None:
                    kind, target = "finding", linked

            entry = {
                "validator": profile.agent_id,
                "domain":    profile.domain_group,
                "evidence":  evidence,
                "round":     round_num,
            }
            target.setdefault("validated_by", []).append(entry)
            if kind == "finding" and profile.domain_group != target.get("author_domain"):
                target["cross_domain_validated"] = True
                target["confidence"] = min(0.95, target.get("confidence", 0.5) + 0.08)
            logger.debug(
                f"VALIDATE [{profile.agent_id}] → {kind} '{title_fragment[:60]}'"
            )

    def _apply_attacker_gate(self, session_state: CyberSessionState, n_attackers: int = 5):
        """
        P8: Post-Phase-C attacker gate — áp dụng 1 lần sau khi Phase C kết thúc.

        Dùng last_vote per attacker (dedup) để tính net ratio thay vì cộng dồn
        từng flat delta. Tránh bias khi cùng profile vote nhiều lần.

        net_ratio = (confirms - dismisses) / n_attackers ∈ [-1, 1]
          ≤ -0.4  → majority DISMISS → confidence × 0.70
          ≥  0.6  → strong CONFIRM  → confidence × 1.15
        """
        for finding in session_state.expert_findings:
            corrs = finding.get("attacker_corroborations", [])
            if not corrs:
                continue
            # Lấy vote cuối cùng của mỗi attacker profile
            last_vote: Dict[str, str] = {}
            for c in corrs:
                last_vote[c["profile_id"]] = c["action"]
            confirms  = sum(1 for a in last_vote.values() if "CONFIRM" in a)
            dismisses = sum(1 for a in last_vote.values() if "DISMISS" in a)
            net_ratio = (confirms - dismisses) / n_attackers
            if net_ratio <= -0.4:
                finding["confidence"] = max(0.10, finding["confidence"] * 0.70)
                logger.debug(
                    f"AttackerGate PENALIZE '{finding.get('title','')[:50]}' "
                    f"net={net_ratio:.2f} ({confirms}C/{dismisses}D)"
                )
            elif net_ratio >= 0.6:
                finding["confidence"] = min(0.95, finding["confidence"] * 1.15)
                logger.debug(
                    f"AttackerGate BOOST '{finding.get('title','')[:50]}' "
                    f"net={net_ratio:.2f} ({confirms}C/{dismisses}D)"
                )

    def _attach_corroboration(
        self,
        action: Dict[str, Any],
        attacker_profile: str,
        session_state: CyberSessionState,
    ):
        """
        Gắn attacker corroboration vào matching expert findings.

        RC-3b: per-function matching — [ATTACKER_DISMISS SWC-101 transfer()] only
               applies to findings where BOTH swc_id AND function match.
        RC-3c: normalize confidence delta by number of affected findings —
               prevents one SWC-level action from having N×weight.
        Legacy: title-keyword match (no SWC) — stops at first hit.
        """
        swc_id    = action.get("swc_id", "")
        func_name = action.get("func_name", "")   # RC-3b: e.g. "transfer()"
        finding_ref = (action.get("finding_ref") or "").lower()

        # Bridge: SINV-xxx / INV-xxx from invariant targets — match by function name
        # instead of SWC ID (structural invariants don't have a SWC equivalent)
        if swc_id.upper().startswith(("SINV-", "INV-")):
            fn_bare = func_name.lower().rstrip("()") if func_name else ""
            delta = action["confidence_delta"]
            for finding_dict in session_state.expert_findings:
                funcs = finding_dict.get("affected_functions", [])
                fn_match = fn_bare and any(
                    fn_bare in fn.lower().rstrip("()") for fn in funcs
                )
                if not fn_match:
                    continue
                corr = AttackerCorroboration(
                    profile_id=attacker_profile,
                    action=action["action_type"],
                    comment=action.get("reason", f"Invariant target {swc_id} confirmed"),
                    confidence_delta=delta,
                )
                if "attacker_corroborations" not in finding_dict:
                    finding_dict["attacker_corroborations"] = []
                finding_dict["attacker_corroborations"].append(asdict(corr))
                current = finding_dict.get("confidence", 0.5)
                finding_dict["confidence"] = max(0.0, min(1.0, current + delta))
            return

        # RC-3c: pre-count affected findings to normalize delta
        if swc_id:
            fn_bare = func_name.lower().rstrip("()") if func_name else ""
            n_affected = sum(
                1 for f in session_state.expert_findings
                if f.get("swc_id") == swc_id and (
                    not fn_bare or any(
                        fn_bare in fn.lower().rstrip("()")
                        for fn in f.get("affected_functions", [])
                    )
                )
            )
            delta = action["confidence_delta"] / max(n_affected, 1)
        else:
            delta = action["confidence_delta"]

        for finding_dict in session_state.expert_findings:
            swc_match = bool(swc_id and finding_dict.get("swc_id") == swc_id)
            title_match = bool(
                not swc_id and finding_ref
                and finding_ref in finding_dict.get("title", "").lower()
            )
            if not (swc_match or title_match):
                continue

            # RC-3b: with function qualifier, skip findings that don't include that function
            if swc_match and func_name:
                fn_bare = func_name.lower().rstrip("()")
                funcs = finding_dict.get("affected_functions", [])
                if not any(fn_bare in fn.lower().rstrip("()") for fn in funcs):
                    continue

            corr = AttackerCorroboration(
                profile_id=attacker_profile,
                action=action["action_type"],
                comment=action["reason"],
                confidence_delta=delta,
            )
            if "attacker_corroborations" not in finding_dict:
                finding_dict["attacker_corroborations"] = []
            finding_dict["attacker_corroborations"].append(asdict(corr))
            current = finding_dict.get("confidence", 0.5)
            finding_dict["confidence"] = max(0.0, min(1.0, current + delta))

            # Legacy title match: stop at first hit; SWC match: continue to cover all matching
            if title_match:
                return

    # ─── Context builder ──────────────────────────────────────────────────────

    def _build_prior_context(self, session_state: CyberSessionState, mode: str = "network_security") -> str:
        """
        Build text summary của các findings đã có để inject vào tiếp theo.
        Giới hạn độ dài để không overflow context window.

        Includes Published Registry (Solution A for Weakness #4):
        agents see unique titles already reported → instructed to CHALLENGE
        or EXPAND rather than re-report the same finding.

        Sliding window (CONTEXT_WINDOW_ROUNDS, default 3): only findings/gaps from the
        last N rounds are shown in detail, keeping prompt size stable across all rounds.
        """
        lines = []

        # Sliding window: cap detailed context to the last N rounds
        window = int(os.environ.get("CONTEXT_WINDOW_ROUNDS", "3"))
        current_round = session_state.current_round
        min_round = max(1, current_round - window + 1)

        if mode == "contract_audit":
            cm = _get_contract_modules()
            registry = cm["published_registry"](session_state.expert_findings, max_entries=10)
        else:
            from .cyber_oasis_env import build_published_registry
            registry = build_published_registry(session_state.expert_findings, max_entries=10)

        # Published Registry — shown first so agents read it before anything else
        if registry:
            lines.append(registry)
            lines.append("")  # blank line separator

        if session_state.expert_findings:
            windowed = [f for f in session_state.expert_findings if f.get("round_number", 0) >= min_round]
            recent = windowed[-6:]
            if recent:
                lines.append(f"=== RECENT FINDINGS (rounds {min_round}–{current_round}, last {len(recent)}) ===")
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

            # P5: Top-3 high-confidence findings with evidence — help agents build on prior reasoning
            top3 = sorted(windowed, key=lambda f: f.get("confidence", 0), reverse=True)[:3]
            if top3:
                lines.append(f"\n=== TOP-3 HIGH-CONFIDENCE FINDINGS (with evidence) ===")
                for f in top3:
                    lines.append(f"[{f.get('severity','?').upper()}] {f.get('title','?')}")
                    ev_list = f.get("evidence") or []
                    ev = ev_list[0] if ev_list else (f.get("evidence") if isinstance(f.get("evidence"), str) else "")
                    if ev:
                        lines.append(f"  Evidence: {str(ev)[:400]}")

        if session_state.attacker_findings:
            windowed_atk = [f for f in session_state.attacker_findings if f.get("round_number", 0) >= min_round]
            recent_atk = windowed_atk[-5:]
            if recent_atk:
                lines.append(f"\n=== ATTACKER FINDINGS (rounds {min_round}+, {len(recent_atk)}) ===")
                for f in recent_atk:
                    lines.append(
                        f"[ATTACKER:{f.get('attacker_profile','?')}] "
                        f"{f.get('title','Untitled')} (base confidence: {f.get('base_confidence', 0.6):.2f})"
                    )

        # Gap registry: sliding window — only recent gaps to focus agent attention
        all_gaps = session_state.gap_registry
        if all_gaps:
            windowed_gaps = [g for g in all_gaps if g.get("round_number", 0) >= min_round]
            recent_gaps = windowed_gaps[-8:]
            if recent_gaps:
                lines.append(f"\n=== DECLARED KNOWLEDGE GAPS (rounds {min_round}+, {len(recent_gaps)}) ===")
                lines.append("Areas experts could not verify — still open for investigation:")
                author_key = "author_domain" if mode == "contract_audit" else "author_group"
                for g in recent_gaps:
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

    def _try_build_boost_client(self):
        """Thử dùng BOOST LLM config nếu có, fallback về primary LLM.

        Mode A — Claude trên Vertex AI:
          BOOST_VERTEX_CLAUDE_REGION set + BOOST_MODEL_NAME=claude-*
        Mode B — Gemini Pro trên Vertex AI (cùng endpoint, đổi model):
          BOOST_MODEL_NAME=google/... (không set BOOST_VERTEX_CLAUDE_REGION)
          → Dùng LLMClientPool 2 accounts nếu LLM2_* được set
        Mode C — Anthropic API key riêng:
          BOOST_API_KEY set
        """
        try:
            boost_key       = getattr(Config, "BOOST_API_KEY",              None)
            boost_url       = getattr(Config, "BOOST_BASE_URL",             None)
            boost_model     = getattr(Config, "BOOST_MODEL_NAME",           None)
            claude_region   = getattr(Config, "BOOST_VERTEX_CLAUDE_REGION", None)
            vertex_key_file = getattr(Config, "LLM_VERTEX_AI_KEY_FILE",     None)

            if claude_region and boost_model:
                # Mode A: Claude trên Vertex AI — single client (Claude không có multi-account pool)
                return LLMClient(
                    model=boost_model,
                    vertex_key_file=vertex_key_file,
                    anthropic_vertex_region=claude_region,
                )

            if boost_key:
                # Mode C: Anthropic / OpenAI external key — single client
                return LLMClient(api_key=boost_key, base_url=boost_url, model=boost_model)

            if boost_model and boost_model != Config.LLM_MODEL_NAME:
                # Mode B: Vertex AI, đổi model sang Pro
                # Dùng pool 2 accounts nếu LLM2_* được cấu hình
                client1 = LLMClient(
                    base_url=boost_url or Config.LLM_BASE_URL,
                    model=boost_model,
                    vertex_key_file=vertex_key_file,
                    rpm_slot_file="/tmp/mirofish_boost_rpm_0.json",
                )
                if Config.LLM2_VERTEX_AI_KEY_FILE and Config.LLM2_BASE_URL:
                    client2 = LLMClient(
                        base_url=Config.LLM2_BASE_URL,
                        model=boost_model,
                        vertex_key_file=Config.LLM2_VERTEX_AI_KEY_FILE,
                        rpm_limit=Config.LLM2_GLOBAL_RPM_LIMIT,
                        rpm_slot_file="/tmp/mirofish_boost_rpm_1.json",
                    )
                    pool = LLMClientPool([client1, client2])
                    logger.info(f"BoostLLM pool: 2 Vertex AI accounts, model={boost_model}")
                    return pool
                return client1
        except Exception:
            pass
        return self.llm
