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
        Chạy 1 round: gọi LLM cho từng active agent → parse findings + GAP declarations.

        GAP declarations từ round này sẽ được route và inject vào round tiếp theo,
        cho phép experts nhận diện điểm mù của nhau và lấp đầy coverage gaps.
        """
        if env_builder is None:
            env_builder = self.env_builder

        active_profiles = env_builder.get_active_agents_for_phase(profiles, phase)
        prior_context = self._build_prior_context(session_state, mode=mode)
        pool_size = getattr(self.llm, "pool_size", 1)
        max_workers = max(int(os.environ.get("LLM_MAX_WORKERS", "1")), pool_size)

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
            # Strip think blocks for feed storage to keep UI content clean.
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
        strip_think: bool = True,
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

        # Phase C attacker agents use boost LLM (Pro) with extended thinking — needs more tokens
        is_attacker_phase_c = (profile.tier == 2 and phase == "C")
        max_tok = 4096 if is_attacker_phase_c else 1500
        return llm.chat(messages, temperature=0.7, max_tokens=max_tok, strip_think=strip_think)

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
