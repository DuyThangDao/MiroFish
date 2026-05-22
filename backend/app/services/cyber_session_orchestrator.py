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
        parse_contract_gap_declarations, build_gap_context_for_agent as contract_gap_context,
        build_published_registry as contract_published_registry,
        get_phase_for_round as contract_get_phase,
        extract_known_functions,
        # v2 parsers
        parse_all_contract_findings_from_text,
        build_round1_prompt, build_round2_prompt, build_round2_update_prompt,
        build_round3_prompt, build_round3_update_prompt,
        parse_round2_votes_from_text, parse_round2_update_votes_from_text,
        parse_round3_verdict_from_text, parse_round3_update_verdict_from_text,
    )
    return {
        "env_builder":          ContractAuditEnvBuilder,
        "attacker_action":      ContractAttackerAction,
        "parse_finding":        parse_contract_finding_from_text,
        "parse_gap":            parse_contract_gap_declarations,
        "gap_context":          contract_gap_context,
        "published_registry":   contract_published_registry,
        "get_phase":            contract_get_phase,
        "extract_funcs":        extract_known_functions,
        # v2
        "parse_all_findings":   parse_all_contract_findings_from_text,
        "r1_prompt":            build_round1_prompt,
        "r2_prompt":            build_round2_prompt,
        "r2_update_prompt":     build_round2_update_prompt,
        "r3_prompt":            build_round3_prompt,
        "r3_update_prompt":     build_round3_update_prompt,
        "parse_r2_votes":       parse_round2_votes_from_text,
        "parse_r2_upd":         parse_round2_update_votes_from_text,
        "parse_r3_verdict":     parse_round3_verdict_from_text,
        "parse_r3_upd":         parse_round3_update_verdict_from_text,
    }

logger = get_logger("mirofish.cyber_orchestrator")

# ── RAG singleton ─────────────────────────────────────────────────────────────
_rag_retriever = None
_rag_lock = threading.Lock()  # serialize ChromaDB access — concurrent Rust bindings cause crashes

def _get_rag_retriever():
    global _rag_retriever
    if _rag_retriever is None:
        with _rag_lock:
            if _rag_retriever is None:  # double-checked locking
                import sys
                __import__('pysqlite3')
                sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
                from scripts.rag.rag_retriever import SolodirRetriever
                _rag_retriever = SolodirRetriever()
    return _rag_retriever


import re as _re_rag

# Parse FINDING blocks: title on FINDING: line, then full block until next FINDING or end
_FINDING_BLOCK_RE = _re_rag.compile(
    r'^FINDING:\s*(.+?)\n(.*?)(?=\nFINDING:|\Z)',
    _re_rag.DOTALL | _re_rag.MULTILINE,
)
# Extract a single named field from a FINDING block
_FIELD_RE = _re_rag.compile(
    r'^([A-Z_]+):\s*(.+?)(?=\n[A-Z_]+:|\Z)',
    _re_rag.DOTALL | _re_rag.MULTILINE,
)
_SCORE_INJECT_THRESHOLD     = 0.68
_SCORE_SHOW_THRESHOLD       = 0.65
_SCORE_INJECT_THRESHOLD_INV = 0.65  # lowered: 0.70 was blocking ~60% of relevant patterns (range 0.576–0.737)
_MAX_RAG_INJECT_PER_AGENT   = 4     # raised: after FIX-1/2 loại noise, không còn distractor effect
_inv_cache: dict[str, tuple] = {}   # key → (score, hint_block); session-level semantic dedup
_inv_cache_lock = threading.Lock()


def _extract_field(block: str, field: str) -> str:
    m = _re_rag.search(
        rf'^{field}:\s*(.+?)(?=\n[A-Z_]+:|\Z)', block,
        _re_rag.DOTALL | _re_rag.MULTILINE,
    )
    return m.group(1).strip() if m else ""


def build_rag_query(title: str, description: str) -> str:
    text = f"{title}. {description}"
    text = _re_rag.sub(r'\b\w+\s*\([^)]*\)', '', text)               # strip fn signatures
    text = _re_rag.sub(r'\b[a-zA-Z_]+\.[a-zA-Z_]+\b', '', text)     # strip dotted refs
    text = _re_rag.sub(r'\b[A-Z][a-z]+[A-Z][a-zA-Z]*\b', '', text)  # strip CamelCase
    text = _re_rag.sub(
        r'\b(?:Trident|BentoBox|Sushi|Uniswap|Aave|Compound|Balancer)\b',
        '', text, flags=_re_rag.IGNORECASE,
    )
    return _re_rag.sub(r'\s+', ' ', text).strip()


def _build_rag_observations(response: str, agent_id: str) -> list:
    matches = list(_FINDING_BLOCK_RE.finditer(response))
    if not matches:
        return []
    retriever = _get_rag_retriever()
    observations = []
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        block = m.group(2)
        # Use ATTACK_PATH as primary description; fall back to EVIDENCE
        attack_path = _extract_field(block, "ATTACK_PATH")
        evidence = _extract_field(block, "EVIDENCE")
        description = attack_path or evidence
        if not description:
            continue
        query = build_rag_query(title, description)
        if not query:
            continue
        with _rag_lock:
            results = retriever.query(query, n_results=3)
        if not results:
            continue
        top_score = results[0]["score"]
        logger.info(
            f"[RAG] agent={agent_id} finding={i+1}/{len(matches)} "
            f"top_score={top_score:.3f} title='{title[:50]}'"
        )
        if top_score < _SCORE_INJECT_THRESHOLD:
            continue
        lines = [f"--- Historical context for FINDING: '{title}' ---"]
        for j, r in enumerate(results, 1):
            if r["score"] < _SCORE_SHOW_THRESHOLD:
                break
            preview = r["content"][:400].replace("\n", " ").strip()
            lines.append(
                f"[{j}] score={r['score']:.3f} | {r['title']}\n"
                f"    Protocol: {r['protocol']} | {preview}"
            )
        observations.append("\n".join(lines))
    return observations


def _normalize_inv_key(inv: str, target_contracts: list[str]) -> str:
    """Cache key cho INV semantic dedup.

    Dùng build_rag_query để strip fn sigs, CamelCase, dotted refs trước khi lấy 8 words đầu.
    Đảm bảo 2 INVs cùng concept (khác word order) map về cùng key.
    """
    inv_lower = inv.lower()
    matched_contract = next(
        (c for c in target_contracts if c.lower() in inv_lower), "unknown"
    )
    clean_meaning = build_rag_query("", inv).lower()
    words = clean_meaning.split()
    return f"{matched_contract.lower()}::{' '.join(words[:8])}"


def _extract_independent_targets(network_summary: str, primary: str) -> list[str]:
    # Parse multi-target contest header: "// TARGET N — ContractName (primary)"
    # Contest 42 (single target): no such header → returns []
    targets = _re_rag.findall(r'TARGET \d+\s*[-—–]\s*(\w+)\s*\(primary\)', network_summary)
    return [t for t in targets if t != primary]


def _build_invariant_rag_hints(invariant_text: str, agent_id: str) -> tuple:
    """Returns (hint_block: str, num_matched: int) — query RAG per INV-N line."""
    inv_pattern = _re_rag.compile(r'INV-\d+:\s*(.+)', _re_rag.IGNORECASE)
    invariants = inv_pattern.findall(invariant_text)
    if not invariants:
        return "", 0
    retriever = _get_rag_retriever()
    candidates = []  # (top_score, hint_block_str) — collect all, sort later
    for i, inv in enumerate(invariants):
        # FIX-3: semantic dedup — reuse cache nếu cùng concept đã được query trong session này
        cache_key = _normalize_inv_key(inv, [])
        with _inv_cache_lock:
            if cache_key in _inv_cache:
                cached_score, cached_block = _inv_cache[cache_key]
                logger.info(
                    f"[RAG] agent={agent_id} inv={i+1} → reuse cache (key={cache_key[:50]})"
                )
                candidates.append((cached_score, cached_block))
                continue
        query = build_rag_query("", inv)
        if not query:
            continue
        with _rag_lock:
            results = retriever.query(query, n_results=3)
        top_score = results[0]["score"] if results else 0.0
        if not results or top_score < _SCORE_INJECT_THRESHOLD_INV:
            logger.info(
                f"[RAG] agent={agent_id} inv={i+1} score={top_score:.3f} → skip (below threshold)"
            )
            continue
        logger.info(
            f"[RAG] agent={agent_id} inv={i+1} score={top_score:.3f} inv='{inv[:60]}'"
        )
        block = [f"INV-{i+1} historical violations (score={top_score:.3f}):"]
        for j, r in enumerate(results, 1):
            if r["score"] < _SCORE_SHOW_THRESHOLD:
                break
            preview = r["content"][:350].replace("\n", " ").strip()
            block.append(f"  [{j}] {r['title']} | {preview}")
        with _inv_cache_lock:
            _inv_cache[cache_key] = (top_score, "\n".join(block))
        candidates.append((top_score, "\n".join(block)))
    # Inject top-N by score — giữ highest-confidence hints, bỏ borderline
    candidates.sort(key=lambda x: x[0], reverse=True)
    hints = [b for _, b in candidates[:_MAX_RAG_INJECT_PER_AGENT]]
    return "\n\n".join(hints), len(hints)


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
        manifest: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Khởi chạy session trong background thread.
        Returns task_id để frontend poll.

        Args:
            mode: "network_security" (default) | "contract_audit"
            invariants: protocol invariants from ContractInvariantExtractor (contract_audit only)
            manifest: ContractManifest from flatten_contest_dir (contract_audit only)
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
            args=(task_id, session_id, graph_id, network_summary, profiles, mode, invariants, manifest),
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
        manifest: Optional[Dict[str, Any]] = None,
    ):
        try:
            self.task_manager.update_task(
                task_id, status=TaskStatus.PROCESSING,
                progress=5, message="Khởi tạo session..."
            )

            # Pick env_builder and phase function based on mode
            if mode == "contract_audit":
                cm = _get_contract_modules()
                env_builder = cm["env_builder"](manifest=manifest)
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

            # v2 feature flag — 3-round architecture
            _audit_v = os.environ.get("AUDIT_PIPELINE_VERSION", "v1").lower()
            if mode == "contract_audit" and _audit_v == "v2":
                # Extract target contract names for RAG scope restriction
                _tc: list[str] = []
                if manifest:
                    _tc = [manifest.get("primary", "")] + manifest.get("secondary", [])
                    _tc = [c for c in _tc if c]
                self._run_contract_audit_v2(
                    task_id=task_id,
                    session_id=session_id,
                    graph_id=graph_id,
                    network_summary=network_summary,
                    profiles=profiles,
                    known_functions=known_functions,
                    session_state=session_state,
                    invariants=invariants,
                    target_contracts=_tc or None,
                )
                return

            # RC-3 Two-step Phase C: computed after round 7, injected into Phase C rounds
            phase_c_review_list = ""

            # v1: Chạy 10 rounds
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
                self._process_attacker_response(
                    response, profile, round_num, session_state,
                    mode=mode, phase_c_review_list=phase_c_review_list,
                )

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

        is_attacker_phase_c = (profile.tier == 2 and phase == "C")
        if is_attacker_phase_c:
            user_content = (
                f"{phase_instruction}\n\n"
                f"=== DISCUSSION SO FAR ===\n{prior_context}\n\n"
                "⚠ FORMAT ENFORCEMENT — bắt buộc:\n"
                "Dòng ĐẦU TIÊN của response phải là tag [ATTACKER_XXX].\n"
                "KHÔNG được viết bất kỳ câu phân tích nào trước tag đầu tiên.\n"
                "Mỗi claim trong UNVERIFIED CLAIMS LIST trên phải có 1 block riêng.\n"
                "Bắt đầu response của bạn ngay bây giờ với [ATTACKER_CONFIRM/DISMISS/EXPLOIT]:"
            )
        else:
            user_content = (
                f"{phase_instruction}\n\n"
                f"=== DISCUSSION SO FAR ===\n{prior_context}\n\n"
                f"Provide your analysis for Round {round_num}. "
                f"{specificity_hint}"
            )

        messages = [
            {"role": "system", "content": profile.system_prompt},
            {"role": "user", "content": user_content},
        ]

        # Stage 2: token override via env var + optional thinking disable
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
        """DEPRECATED: S-track removed in NL migration. No-op."""
        pass

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

    def _rescue_attacker_action(
        self,
        narrative_text: str,
        review_list: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Fix B: khi parse_from_text() trả None (agent viết narrative không có tag),
        gọi LLM call ngắn để extract quyết định CONFIRM/DISMISS từ text đó.
        Trả None nếu extract thất bại.
        """
        if len(narrative_text.strip()) < 80:
            return None
        try:
            claims_preview = review_list[:600] if review_list else "unknown claims"
            raw = self.llm.chat_json(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You extract structured security decisions from analyst text. "
                            "Return ONLY JSON, no prose."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            "An attacker analyst wrote the following response WITHOUT using required tags.\n"
                            "Extract their CONFIRM or DISMISS decisions for each claim.\n\n"
                            f"CLAIMS BEING REVIEWED:\n{claims_preview}\n\n"
                            f"ANALYST RESPONSE:\n{narrative_text[:2000]}\n\n"
                            'Return JSON: {"actions": [{"action": "ATTACKER_CONFIRM or ATTACKER_DISMISS", '
                            '"swc_id": "SWC-XXX", "func_name": "funcName()", "reason": "..."}]}'
                        ),
                    },
                ],
                temperature=0.1,
                max_tokens=512,
            )
            actions = raw.get("actions", [])
            if not actions:
                return None
            cm = _get_contract_modules()
            ContractAttackerAction = cm["attacker_action"]
            a = actions[0]
            action_type = a.get("action", "ATTACKER_DISMISS")
            if action_type not in ContractAttackerAction.ALL:
                return None
            logger.debug(f"Attacker rescue: extracted {action_type} swc={a.get('swc_id')} fn={a.get('func_name')}")
            return {
                "action_type":      action_type,
                "swc_id":           a.get("swc_id", ""),
                "func_name":        a.get("func_name", ""),
                "finding_ref":      "",
                "reason":           a.get("reason", ""),
                "path":             "",
                "confidence_delta": ContractAttackerAction.CONFIDENCE_DELTA.get(action_type, 0.0),
            }
        except Exception as e:
            logger.debug(f"Attacker action rescue failed: {e}")
            return None

    def _process_attacker_response(
        self,
        text: str,
        profile: CyberAgentProfile,
        round_num: int,
        session_state: CyberSessionState,
        mode: str = "network_security",
        phase_c_review_list: str = "",
    ):
        """Parse attacker agent response → AttackerFinding or AttackerCorroboration."""
        if mode == "contract_audit":
            cm = _get_contract_modules()
            ContractAttackerAction = cm["attacker_action"]
            action = ContractAttackerAction.parse_from_text(text)
            if not action:
                # Fix B: rescue pass — extract từ narrative nếu không có tag
                action = self._rescue_attacker_action(text, phase_c_review_list)
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

        def _jaccard(a: str, b: str) -> float:
            """Token-level Jaccard similarity between two normalized title strings."""
            ta, tb = set(a.split()), set(b.split())
            if not ta or not tb:
                return 0.0
            return len(ta & tb) / len(ta | tb)

        def _find_target(title_fragment: str):
            frag = _normalize(title_fragment)
            # Priority 1: Stage 1 CLAIMs (same round) — Jaccard ≥ 0.30
            if stage1_claims:
                best_c, best_j = None, 0.0
                for c in stage1_claims:
                    j = _jaccard(frag, _normalize(c["title"]))
                    if j > best_j:
                        best_j, best_c = j, c
                if best_j >= 0.30:
                    return ("claim", best_c)
            # Priority 2: expert_findings từ round cũ (đã commit) — Jaccard ≥ 0.30
            best_f, best_j = None, 0.0
            for f in session_state.expert_findings:
                if f.get("round_number", 0) < round_num:
                    j = _jaccard(frag, _normalize(f.get("title", "")))
                    if j > best_j:
                        best_j, best_f = j, f
            if best_j >= 0.30:
                return ("finding", best_f)
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
            vertex_key_file = (getattr(Config, "BOOST_VERTEX_AI_KEY_FILE", None)
                               or getattr(Config, "LLM_VERTEX_AI_KEY_FILE", None))

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

    # ─── v2 — 3-Round Contract Audit Flow ────────────────────────────────────

    # Thresholds (can be overridden via env vars)
    _R2_THRESHOLD        = float(os.environ.get("R2_SCORE_THRESHOLD",      "0.42"))
    _R3_ATTACKER_BASE    = float(os.environ.get("R3_ATTACKER_FACTOR_BASE", "0.5"))
    _R3_CONFIRMED        = float(os.environ.get("R3_CONFIRMED_THRESHOLD",  "0.35"))

    # Gemini 3 Flash Preview (thinking model) uses ~30K tokens for internal reasoning
    # before generating visible output. Any max_tokens below ~32K results in content=None.
    # thinkingConfig/thinkingBudget is silently ignored by this model's endpoint.
    _V2_R1_MAX_TOKENS  = int(os.environ.get("V2_R1_MAX_TOKENS",  "65536"))
    _V2_R2_MAX_TOKENS  = int(os.environ.get("V2_R2_MAX_TOKENS",  "32768"))
    _V2_R3_MAX_TOKENS  = int(os.environ.get("V2_R3_MAX_TOKENS",  "1500"))
    _EV_PRIORITY: dict = {"CODE:": 0, "MISSING:": 1, "SEQ:": 2, "INV:": 3, "DESIGN:": 4}

    def _call_agent_v2(
        self,
        prompt: str,
        use_boost: bool = False,
        max_tokens: int = 65536,
    ) -> str:
        """Simple LLM call for v2 rounds — prompt is fully pre-built."""
        llm = self.boost_llm if use_boost else self.llm
        messages = [{"role": "user", "content": prompt}]
        return llm.chat(messages, temperature=0.7, max_tokens=max_tokens, strip_think=True)

    def _run_contract_audit_v2(
        self,
        task_id: str,
        session_id: str,
        graph_id: str,
        network_summary: str,
        profiles: list,
        known_functions: Optional[set],
        session_state: "CyberSessionState",
        invariants: Optional[list] = None,
        target_contracts: list[str] | None = None,
    ):
        """
        v2 entry point — replaces 10-round Phase A/B/C with 3-round flow.
        Stores results in session_state and completes the task.
        """
        cm = _get_contract_modules()
        t1 = [p for p in profiles if p.tier == 1]
        t2 = [p for p in profiles if p.tier == 2]
        n  = len(t1)

        # ── Round 1: Independent Discovery ───────────────────────────────────
        self.task_manager.update_task(
            task_id, progress=10,
            message=f"Round 1/3 — Independent Discovery ({n} tier-1 agents)"
        )
        candidate_pool = self._run_discovery_round(
            cm=cm,
            t1_profiles=t1,
            network_summary=network_summary,
            known_functions=known_functions,
            session_id=session_id,
            target_contracts=target_contracts,
        )
        n_r1 = len(candidate_pool)
        logger.info(f"[v2] Round 1 complete: {n_r1} unique (kind,fn) pairs discovered")
        session_state.current_round = 1
        self._save_session_state(session_state)

        # ── Sequential Anchor Dedup ───────────────────────────────────────────
        logger.info(f"[v2] Anchor dedup: {n_r1} raw → Bước 1 (static) + Bước 2 (LLM)...")
        candidate_pool = self._run_anchor_dedup(candidate_pool, network_summary)
        n_r1 = len(candidate_pool)
        logger.info(f"[v2] After anchor dedup: {n_r1} canonical findings")

        # ── Accounting Invariant Micro-Pass ───────────────────────────────────
        if os.environ.get("ENABLE_ACCOUNTING_MICROPASS", "true").lower() == "true":
            micro_findings = self._run_accounting_micropass(network_summary)
            for f in micro_findings:
                anchor = f.get("code_anchor", "")
                if anchor and not any(
                    cf.get("code_anchor") == anchor for cf in candidate_pool.values()
                ):
                    pair_id = f"micro_{uuid.uuid4().hex[:8]}"
                    f["pair_id"] = pair_id
                    f.setdefault("submitters", ["accounting_micropass"])
                    candidate_pool[pair_id] = f
                    logger.info(f"  [micro] Added: {f.get('title', '')}")

        # ── Early exit after anchor dedup (STOP_AFTER_DEDUP=true) ───────────
        if os.environ.get("STOP_AFTER_DEDUP", "").lower() in ("true", "1", "yes"):
            import json as _json
            out_path = os.environ.get("STOP_AFTER_DEDUP_OUT", "/tmp/dedup_findings.json")
            with open(out_path, "w") as _f:
                _json.dump(list(candidate_pool.values()), _f, indent=2, default=str)
            logger.info(
                f"[v2] STOP_AFTER_DEDUP=true — {n_r1} findings saved to {out_path}"
            )
            self._v2_complete_task(
                task_id, session_id, graph_id, session_state, {}, [], [], [],
            )
            return

        # ── Pre-R2 FP Check ───────────────────────────────────────────────────
        logger.info(f"[v2] Pre-R2 FP check: {n_r1} candidates → filtering...")
        candidate_pool = self._dedup_pre_r2(candidate_pool, network_summary)
        n_r1 = len(candidate_pool)
        logger.info(f"[v2] After FP check: {n_r1} candidates enter R2")

        # ── Early exit after R1 (STOP_AFTER_R1=true) ─────────────────────────
        if os.environ.get("STOP_AFTER_R1", "").lower() == "true":
            import json as _json
            out_path = os.environ.get("STOP_AFTER_R1_OUT", "/tmp/r1_findings.json")
            with open(out_path, "w") as _f:
                _json.dump(list(candidate_pool.values()), _f, indent=2, default=str)
            logger.info(
                f"[v2] STOP_AFTER_R1=true — {n_r1} R1 findings saved to {out_path}, "
                f"skipping R2 and R3"
            )
            self._v2_complete_task(
                task_id, session_id, graph_id, session_state, {}, [], [], [],
            )
            return

        if not candidate_pool:
            logger.warning("[v2] Round 1 produced 0 candidates — nothing to vote on")
            self._v2_complete_task(task_id, session_id, graph_id, session_state, {}, [], [], [])
            return

        # ── Round 2: Blind Voting ─────────────────────────────────────────────
        self.task_manager.update_task(
            task_id, progress=35,
            message=f"Round 2/3 — Blind Voting ({n_r1} pairs, {n} agents)"
        )
        accepted_findings, all_votes = self._run_voting_round(
            cm=cm,
            t1_profiles=t1,
            candidate_pool=candidate_pool,
            n_agents=n,
        )
        n_r2 = len(accepted_findings)
        logger.info(
            f"[v2] Round 2 complete: {n_r2}/{n_r1} pairs accepted "
            f"(threshold={self._R2_THRESHOLD:.2f})"
        )
        session_state.current_round = 2
        self._save_session_state(session_state)

        # ── Post-R2 Score Cap (R3 disabled) ──────────────────────────────────
        accepted_findings = self._dedup_pre_r3(accepted_findings)
        n_r2 = len(accepted_findings)
        logger.info(f"[v2] Post-R2 cap: {n_r2} findings (R3 disabled)")

        session_state.current_round = 2
        session_state.current_phase = "done"
        self._save_session_state(session_state)

        self._v2_complete_task(
            task_id, session_id, graph_id, session_state, all_votes,
            accepted_findings, [], [],
        )

    # Agent-id prefix → domain group (must match _get_author_group in consensus_engine)
    _AGENT_PREFIX_TO_DOMAIN: dict = {
        "apps": "appsec",
        "bloc": "blockchain",
        "cryp": "cryptography",
        "defi": "defi",
        "smar": "smart_contract_economics",
        "gove": "governance",
        "toke": "token_standards",
        "math": "defi_math",
    }

    @classmethod
    def _v2_findings_to_consensus_compat(
        cls, confirmed: list
    ) -> list:
        """
        Convert v2 confirmed findings (from candidate pool) into unified findings list.

        Each finding gets per-domain entries so consensus engine cross_score is meaningful.
        Returns a flat list of finding dicts (unified NL format, no L/S split).
        """
        findings_out: list = []

        for f in confirmed:
            pair_id       = f.get("pair_id", "")
            contract_name = f.get("contract_name", "")
            title         = f.get("title", "")
            fn_name       = f.get("function_name", "") or f.get("_fallback_fn", "")
            submitters    = f.get("submitters", [])
            evidence      = " | ".join(f.get("evidence_snippets", [])[:2])
            attacker_rate = f.get("attacker_rate", 0.0)

            _verdict_rank = {"CONFIRMED": 2, "PLAUSIBLE": 1}
            _best_verdict = max(
                (v for v in f.get("attacker_verdicts", {}).values()
                 if v.get("verdict") in _verdict_rank),
                key=lambda v: _verdict_rank[v["verdict"]],
                default=None,
            )
            if _best_verdict:
                attack_path = _best_verdict.get("attack_steps", "")
                patch_suggestion = _best_verdict.get("expected_outcome", "")
            else:
                attack_path = ""
                patch_suggestion = f"Validate and restrict access to {fn_name}" if fn_name else ""

            domains_seen: dict = {}
            for agent_id in submitters:
                prefix = agent_id.split("_")[0]
                domain = cls._AGENT_PREFIX_TO_DOMAIN.get(prefix, "unknown")
                if domain not in domains_seen:
                    domains_seen[domain] = agent_id
            if not domains_seen:
                domains_seen = {"blockchain": "v2_fallback"}

            for domain in domains_seen:
                findings_out.append({
                    "finding_id":    f"{pair_id}_{domain}",
                    "title":         title or f"Vulnerability in {fn_name}",
                    "description":   title,
                    "attack_path":   attack_path,
                    "contract_name": contract_name,
                    "function_name": fn_name,
                    "affected_functions": [fn_name] if fn_name else [],
                    "author_domain": domain,
                    "evidence":      evidence,
                    "severity":      "high",
                    "confidence":    attacker_rate,
                    "patch_suggestion": patch_suggestion,
                    "challenged_by": [],
                    "validated_by":  [],
                    "v2_pair_id":    pair_id,
                    "v2_attacker_rate": attacker_rate,
                })

        return findings_out

    def _v2_complete_task(
        self,
        task_id: str,
        session_id: str,
        graph_id: str,
        session_state: "CyberSessionState",
        all_votes: dict,
        confirmed_findings: list,
        borderline_findings: list,
        discarded_findings: list,
    ):
        """Complete the v2 task with structured result."""
        self.task_manager.complete_task(task_id, {
            "session_id":          session_id,
            "graph_id":            graph_id,
            # v2 instance-level results — consumed by build_v2_output in report agent
            "v2_confirmed":        confirmed_findings,
            "v2_borderline":       borderline_findings,
            "v2_discarded":        discarded_findings,
            "v2_votes":            all_votes,
            # legacy fields kept for logging/debugging (empty for v2)
            "expert_findings":     [],
            "attacker_findings":   session_state.attacker_findings,
            "semantic_findings":   [],
            "total_findings":      len(confirmed_findings),
            "rounds_completed":    3,
            "pipeline_version":    "v2",
        })

    # ── Dedup helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_evidence(text: str) -> str:
        """Normalize a short evidence snippet for dedup key / embedding."""
        import re as _re
        text = _re.sub(r'//.*', '', text)
        text = _re.sub(r'/\*.*?\*/', '', text, flags=_re.DOTALL)
        text = _re.sub(r'\s+', ' ', text).strip()
        text = text.rstrip(';').strip()
        return text[:100].lower()

    @staticmethod
    def _normalize_source(text: str) -> str:
        """Normalize full source code for substring FP check — no length limit."""
        import re as _re
        text = _re.sub(r'//.*', '', text)
        text = _re.sub(r'/\*.*?\*/', '', text, flags=_re.DOTALL)
        text = _re.sub(r'\s+', ' ', text).strip()
        return text.lower()

    @staticmethod
    def _validate_attack_path(attack_path: str) -> bool:
        """Return False if ATTACK_PATH lacks structured ACTOR/CALL/STATE_CHANGE/OUTCOME fields."""
        if not attack_path or len(attack_path.strip()) < 50:
            return False
        return sum([
            "ACTOR:" in attack_path,
            "CALL:" in attack_path,
            "STATE_CHANGE:" in attack_path,
            "OUTCOME:" in attack_path,
        ]) >= 3

    @staticmethod
    def _is_valid_reject(vote: dict) -> bool:
        """REJECT valid chỉ khi COUNTER_TYPE thuộc 4 loại hợp lệ và COUNTER ≥ 20 chars."""
        valid_types = {"PHANTOM", "ACCESS_BLOCKED", "NO_STATE_CHANGE", "NO_IMPACT"}
        counter_type = vote.get("counter_type", "").strip().upper()
        counter      = vote.get("counter", "").strip()
        return counter_type in valid_types and len(counter) >= 20

    @classmethod
    def _dedup_pre_r2(cls, candidate_pool: dict, source_code: str) -> dict:
        """
        Layer 1A: Drop findings whose CODE_ANCHOR is not found in source.
        Layer 1B: Drop findings with unstructured ATTACK_PATH (missing ACTOR/CALL/STATE_CHANGE/OUTCOME).
        """
        fp_check = os.environ.get("R3_CODE_FP_CHECK", "true").lower() != "false"
        ap_check = os.environ.get("ATTACK_PATH_VALIDATION", "true").lower() != "false"
        norm_source = cls._normalize_source(source_code)

        survivors: dict = {}
        for pid, item in candidate_pool.items():
            # Check 1: CODE_ANCHOR must exist in source (applies to all evidence types)
            anchor = item.get("code_anchor", "")
            if anchor and fp_check:
                norm_anchor = cls._normalize_evidence(anchor)
                if norm_anchor and norm_anchor not in norm_source:
                    logger.debug(f"[dedup pre-R2] drop invalid CODE_ANCHOR: '{anchor[:60]}'")
                    continue

            # Check 2: ATTACK_PATH must be structured (ACTOR/CALL/STATE_CHANGE/OUTCOME)
            if ap_check and not cls._validate_attack_path(item.get("attack_path", "")):
                logger.debug(
                    f"[dedup pre-R2] drop unstructured ATTACK_PATH: '{item.get('title', '')[:60]}'"
                )
                continue

            survivors[pid] = item

        logger.info(
            f"[dedup pre-R2] FP check + ATTACK_PATH validation: "
            f"{len(candidate_pool)} → {len(survivors)}"
        )
        return survivors

    @classmethod
    def _dedup_pre_r3(cls, accepted_findings: list) -> list:
        """
        Layer 2 (embedding) removed — replaced by Merger Agent.
        Layer 3: Global cap (top R3_MAX_FINDINGS by round2_score).
        """
        max_total = int(os.environ.get("R3_MAX_FINDINGS", "40"))

        sorted_findings = sorted(
            accepted_findings,
            key=lambda x: x.get("round2_score", 0),
            reverse=True,
        )
        final   = sorted_findings[:max_total]
        dropped = sorted_findings[max_total:]
        logger.info(
            f"[dedup pre-R3] global cap={max_total}: "
            f"{len(accepted_findings)} → {len(final)} kept, {len(dropped)} dropped"
        )

        if os.environ.get("STOP_AFTER_PRE_R3", "").lower() == "true" and dropped:
            import json as _json
            dropped_path = os.environ.get("STOP_AFTER_PRE_R3_OUT", "/tmp/pre_r3_findings.json")
            dropped_path = dropped_path.replace(".json", "_dropped.json")
            with open(dropped_path, "w") as _f:
                _json.dump(dropped, _f, indent=2, default=str)
            logger.info(f"[dedup pre-R3] Dropped findings → {dropped_path}")

        return final

    # ── Sequential Anchor Dedup (Bước 1 static + Bước 2 LLM) ─────────────────

    @classmethod
    def _pick_primary(cls, group: list) -> tuple:
        """Given list of (pid, item), return (pid, item) with best evidence priority."""
        def priority(pid_item):
            _, item = pid_item
            ev = (item.get("evidence_snippets") or [""])[0]
            for prefix, rank in cls._EV_PRIORITY.items():
                if ev.upper().startswith(prefix):
                    return rank
            return 99
        return min(group, key=priority)

    @classmethod
    def _static_anchor_dedup(cls, candidate_pool: dict) -> dict:
        """
        Bước 1: group by (contract, function, normalize(code_anchor)).
        Same anchor → same bug → merge. No LLM needed.
        """
        from collections import defaultdict as _dd
        anchor_groups: dict = _dd(list)
        no_anchor: list = []

        for pid, item in candidate_pool.items():
            anchor = cls._normalize_evidence(item.get("code_anchor", ""))
            if anchor:
                key = (
                    item.get("contract_name", "").lower().strip(),
                    item.get("function_name", "").lower().strip(),
                    anchor,
                )
                anchor_groups[key].append((pid, item))
            else:
                no_anchor.append((pid, item))

        merged_pool: dict = {}
        n_merged = 0

        for _key, group in anchor_groups.items():
            if len(group) == 1:
                pid, item = group[0]
                merged_pool[pid] = item
            else:
                primary_pid, primary = cls._pick_primary(group)
                merged = dict(primary)
                all_evidence = list(primary.get("evidence_snippets", []))
                all_submitters = list(primary.get("submitters", []))
                for pid, item in group:
                    if pid == primary_pid:
                        continue
                    for ev in (item.get("evidence_snippets") or []):
                        if ev not in all_evidence:
                            all_evidence.append(ev)
                    for s in (item.get("submitters") or []):
                        if s not in all_submitters:
                            all_submitters.append(s)
                    n_merged += 1
                merged["evidence_snippets"] = all_evidence
                merged["submitters"] = all_submitters
                merged_pool[primary_pid] = merged
                logger.debug(
                    f"[static_dedup] merged {len(group)} findings at "
                    f"({_key[0]}.{_key[1]}) anchor: {_key[2][:60]}"
                )

        for pid, item in no_anchor:
            merged_pool[pid] = item

        logger.info(
            f"[static_dedup] {len(candidate_pool)} → {len(merged_pool)} "
            f"({n_merged} findings merged by exact anchor)"
        )
        return merged_pool

    @staticmethod
    def _extract_function_body(source_code: str, fn_name: str) -> str:
        """Extract Solidity function body by brace counting. Returns up to 3000 chars."""
        import re as _re
        lines = source_code.split('\n')
        pattern = _re.compile(r'\bfunction\s+' + _re.escape(fn_name) + r'\s*\(')
        start_idx = None
        for i, line in enumerate(lines):
            if pattern.search(line):
                start_idx = i
                break
        if start_idx is None:
            return ""
        body_lines = []
        depth = 0
        for i in range(start_idx, min(start_idx + 300, len(lines))):
            line = lines[i]
            body_lines.append(line)
            depth += line.count('{') - line.count('}')
            if depth <= 0 and i > start_idx:
                break
        return '\n'.join(body_lines)[:3000]

    @classmethod
    def _apply_llm_merges(cls, group: list, merge_pairs: list) -> list:
        """Apply MERGE decisions via union-find. Returns list of (pid, item) after merging."""
        from collections import defaultdict as _dd
        n = len(group)
        parent = list(range(n))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[py] = px

        for i, j in merge_pairs:
            union(i, j)

        clusters: dict = _dd(list)
        for idx in range(n):
            clusters[find(idx)].append(idx)

        result = []
        for _root, indices in clusters.items():
            if len(indices) == 1:
                result.append(group[indices[0]])
            else:
                cluster_items = [group[i] for i in indices]
                primary_pid, primary = cls._pick_primary(cluster_items)
                merged = dict(primary)
                all_evidence = list(primary.get("evidence_snippets", []))
                all_submitters = list(primary.get("submitters", []))
                for pid, item in cluster_items:
                    if pid == primary_pid:
                        continue
                    for ev in (item.get("evidence_snippets") or []):
                        if ev not in all_evidence:
                            all_evidence.append(ev)
                    for s in (item.get("submitters") or []):
                        if s not in all_submitters:
                            all_submitters.append(s)
                merged["evidence_snippets"] = all_evidence
                merged["submitters"] = all_submitters
                result.append((primary_pid, merged))
        return result

    def _llm_anchor_dedup(self, candidate_pool: dict, source_code: str) -> dict:
        """
        Bước 2: LLM dedup for functions with ≥2 findings after static dedup.
        CODE groups by (contract, function) statically; LLM only receives pre-assembled
        groups and outputs MERGE/KEEP_SEPARATE — does not search or filter itself.
        ~11 LLM calls for contest 35, runs in parallel with LLM_DEDUP_WORKERS workers.
        """
        import re as _re, time as _time
        from collections import defaultdict as _dd
        from concurrent.futures import ThreadPoolExecutor

        func_groups: dict = _dd(list)
        for pid, item in candidate_pool.items():
            key = (
                item.get("contract_name", "").lower().strip(),
                item.get("function_name", "").lower().strip(),
            )
            func_groups[key].append((pid, item))

        single_groups = {k: v for k, v in func_groups.items() if len(v) <= 1}
        multi_groups  = {k: v for k, v in func_groups.items() if len(v) > 1}

        result_pool: dict = {}
        n_llm_calls = 0
        n_llm_merged = 0
        max_workers = int(os.environ.get("LLM_DEDUP_WORKERS", "2"))

        def _process_one_group(contract: str, fn: str, group: list) -> list:
            fn_body = self._extract_function_body(source_code, fn)
            parts = [
                f"  [{i+1}] anchor: {item.get('code_anchor', 'N/A')[:120]}\n"
                f"       evidence: {(item.get('evidence_snippets') or ['N/A'])[0][:120]}\n"
                f"       title: {item.get('title', '')[:80]}"
                for i, (pid, item) in enumerate(group)
            ]
            prompt = (
                "You are a deduplication agent for smart contract audit findings.\n\n"
                f"CONTRACT: {contract}  FUNCTION: {fn}\n"
            )
            if fn_body:
                prompt += f"\nFUNCTION SOURCE:\n{fn_body}\n"
            prompt += (
                f"\nFINDINGS (same function, different code anchors):\n"
                + "\n\n".join(parts)
                + "\n\n"
                "TASK: Identify pairs that describe the SAME underlying vulnerability.\n\n"
                "Rules:\n"
                "  - Only merge when CERTAIN they share the same root cause\n"
                "  - Different anchors usually mean different bugs — when in doubt: KEEP_SEPARATE\n"
                "  - KEEP_SEPARATE is always safer (duplicate > missed TP)\n\n"
                "Output one decision per line:\n"
                "  MERGE: [i] == [j]  | REASON: <one sentence>\n"
                "  KEEP_SEPARATE: [i] | REASON: <one sentence>"
            )
            merge_pairs: list = []
            try:
                t0 = _time.time()
                response = self._call_agent_v2(prompt, max_tokens=512)
                elapsed = _time.time() - t0
                logger.info(f"[llm_dedup] {contract}.{fn}: {elapsed:.1f}s, {len(group)} findings")
                for line in response.split('\n'):
                    m = _re.search(r'MERGE:\s*\[(\d+)\]\s*==\s*\[(\d+)\]', line)
                    if m:
                        i, j = int(m.group(1)) - 1, int(m.group(2)) - 1
                        if 0 <= i < len(group) and 0 <= j < len(group) and i != j:
                            merge_pairs.append((min(i, j), max(i, j)))
                merge_pairs = list(set(merge_pairs))
            except Exception as e:
                logger.warning(f"[llm_dedup] error for {contract}.{fn}: {e} — keeping separate")
            return self._apply_llm_merges(group, merge_pairs)

        # Single-item groups: no LLM needed, add directly
        for (_contract, _fn), group in single_groups.items():
            for pid, item in group:
                result_pool[pid] = item

        # Multi-item groups: parallel LLM calls via ThreadPoolExecutor
        # Each future handles exactly one (contract, function) group — no duplication possible
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {
                ex.submit(_process_one_group, contract, fn, group): (contract, fn, group)
                for (contract, fn), group in multi_groups.items()
            }
            for future, (contract, fn, group) in futures.items():
                try:
                    merged_group = future.result()
                    n_llm_merged += len(group) - len(merged_group)
                    for pid, item in merged_group:
                        result_pool[pid] = item
                except Exception as e:
                    logger.warning(f"[llm_dedup] collect error {contract}.{fn}: {e} — keeping all")
                    for pid, item in group:
                        result_pool[pid] = item
                n_llm_calls += 1

        logger.info(
            f"[llm_dedup] {n_llm_calls} LLM calls ({max_workers} workers), "
            f"{len(candidate_pool)} → {len(result_pool)} "
            f"({n_llm_merged} findings merged by LLM)"
        )
        return result_pool

    def _run_anchor_dedup(self, candidate_pool: dict, source_code: str) -> dict:
        """Sequential dedup entry point: Bước 1 (static) → Bước 2 (LLM)."""
        after_static = self._static_anchor_dedup(candidate_pool)
        after_llm = self._llm_anchor_dedup(after_static, source_code)
        return after_llm

    # ── Round 1 helper ────────────────────────────────────────────────────────

    def _run_discovery_round(
        self,
        cm: dict,
        t1_profiles: list,
        network_summary: str,
        known_functions: Optional[set],
        session_id: str,
        target_contracts: list[str] | None = None,
    ) -> dict:
        """
        Call all N tier-1 agents in parallel.
        Returns candidate_pool: Dict[pair_id → meta_dict]

        meta_dict keys:
          pair_id, contract_name, title, function_name,
          submitters (list[str]), evidence_snippets (list[str])

        Round 1 parsing uses known_functions=None (no function-list filter) because:
        - The KG summary typically only captures 3-5 functions, far fewer than
          the actual contract.  Applying the filter here would silently drop
          every finding that references a function not in that tiny list.
        - Function validation happens implicitly: the evidence gate still
          requires at least one Solidity-specific code marker or a named function
          that survived RC-1 token filtering.
        """
        # FIX-3: reset session-level dedup cache cho mỗi audit run mới
        global _inv_cache
        _inv_cache = {}
        max_workers = int(os.environ.get("LLM_MAX_WORKERS", "1"))
        submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "0"))

        # Dump dir for raw agent responses (debug)
        _debug_dir = os.environ.get("V2_DEBUG_DIR", "")

        # raw_pool: each finding gets its own entry (no clustering by location)
        raw_pool: dict = {}

        def _discover_one(profile) -> list:
            t0 = time.time()

            rag_enabled = os.environ.get("RAG_ENABLED", "true").lower() == "true"
            rag_calls = 0

            try:
                # Turn 1: agent extracts invariants only
                # max_tokens must match Turn 2 — Gemini thinking model needs >= ~32K
                # to generate any visible output (smaller values → content=None)
                turn1_prompt = cm["r1_prompt"](profile, network_summary, invariant_only=True)
                turn1_response = self.llm.chat(
                    [{"role": "user", "content": turn1_prompt}],
                    temperature=0.7,
                    max_tokens=self._V2_R1_MAX_TOKENS,
                    strip_think=False,  # keep think block — INV-N regex works on full content
                )
                if not turn1_response.strip():
                    logger.warning(
                        f"[v2 R1] agent={profile.agent_id} Turn 1 returned empty — "
                        f"falling back to single-turn mode"
                    )

                # System: query RAG per invariant, build hint block
                step2_hint = ""
                if rag_enabled:
                    hint_block, rag_calls = _build_invariant_rag_hints(
                        turn1_response, profile.agent_id,
                    )
                    if hint_block:
                        step2_hint = (
                            "\nHISTORICAL VIOLATION PATTERNS from audit database:\n\n"
                            f"{hint_block}\n\n"
                            "For each INV where a historical pattern is shown above:\n"
                            "  - BE SKEPTICAL: Assume the code is SAFE first. Do not force a match.\n"
                            "  - Check if THIS contract's code has the EXACT SAME logical flaw.\n"
                            "  - Only write a FINDING if you can extract the SPECIFIC CODE LINES proving it.\n"
                            "  - If the historical exploit path is blocked or mitigated, EXPLICITLY state 'Mitigated' and skip.\n"
                            "For INVs without historical patterns: reason independently.\n"
                        )

                # Strip think block before injecting into Turn 2 (clean display, save context)
                turn1_clean = _re_rag.sub(r'<think>[\s\S]*?</think>', '', turn1_response).strip()

                # Turn 2: full violation analysis — ALWAYS runs (Turn 1 only extracted invariants)
                turn2_prompt = cm["r1_prompt"](
                    profile, network_summary,
                    injected_invariants=turn1_clean,
                    step2_hint=step2_hint,
                )
                response = self.llm.chat(
                    [{"role": "user", "content": turn2_prompt}],
                    temperature=0.7,
                    max_tokens=self._V2_R1_MAX_TOKENS,
                    strip_think=True,
                )

                # Retry once if thinking model exhausted token budget (content=None → empty)
                if not response.strip():
                    logger.warning(
                        f"[v2 R1] agent={profile.agent_id} Turn 2 empty — retrying once"
                    )
                    response = self.llm.chat(
                        [{"role": "user", "content": turn2_prompt}],
                        temperature=0.7,
                        max_tokens=self._V2_R1_MAX_TOKENS,
                        strip_think=True,
                    )

            except Exception as e:
                logger.warning(f"[v2 R1] agent={profile.agent_id} error: {e}")
                return []

            elapsed = time.time() - t0
            logger.info(
                f"[TIMING] Phase=v2 R1 agent={profile.agent_id} latency={elapsed:.1f}s "
                f"rag_calls={rag_calls}"
            )

            if _debug_dir:
                try:
                    import pathlib
                    pathlib.Path(_debug_dir).mkdir(parents=True, exist_ok=True)
                    with open(os.path.join(_debug_dir, f"r1_{profile.agent_id}_inv.txt"), "w") as fh:
                        fh.write(turn1_response)
                    with open(os.path.join(_debug_dir, f"r1_{profile.agent_id}.txt"), "w") as fh:
                        fh.write(response)
                    with open(os.path.join(_debug_dir, f"r1_{profile.agent_id}_prompt.txt"), "w") as fh:
                        fh.write(turn2_prompt)
                except Exception:
                    pass

            parsed = cm["parse_all_findings"](response, profile, 1, known_functions=known_functions)
            n_findings = len(parsed)
            logger.info(
                f"[v2 R1] agent={profile.agent_id}: "
                f"raw_response={len(response)}chars "
                f"parsed={n_findings}findings rag_calls={rag_calls}"
            )

            results = []
            for f in parsed:
                fns = f.get("affected_functions") or []
                if not fns:
                    logger.debug(
                        f"[v2 R1] {profile.agent_id}: finding '{f.get('title','')[:50]}' "
                        f"has no affected_functions — using placeholder"
                    )
                    fns = ["_nofunc"]
                contract    = f.get("contract_name", "")
                title       = f.get("title", "")
                description = f.get("description", "") or ""
                attack_path = f.get("attack_path", [])
                ev          = (f.get("evidence") or [""])[0]
                code_anchor = f.get("code_anchor", "")
                for fn in fns:
                    results.append((contract, fn, title, description, attack_path, ev, code_anchor))

            return results

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {}
            for profile in t1_profiles:
                if submit_delay > 0:
                    time.sleep(submit_delay)
                futures[ex.submit(_discover_one, profile)] = profile

            for future, profile in futures.items():
                try:
                    findings = future.result()
                    for contract, fn, title, description, attack_path, ev, code_anchor in findings:
                        # No clustering — each finding gets its own entry in the pool
                        pair_id = f"p_{uuid.uuid4().hex[:8]}"
                        raw_pool[pair_id] = {
                            "pair_id":           pair_id,
                            "contract_name":     contract,
                            "title":             title,
                            "description":       description,
                            "attack_path":       attack_path,
                            "function_name":     fn,
                            "submitters":        [profile.agent_id],
                            "evidence_snippets": [ev[:300]] if ev else [],
                            "code_anchor":       code_anchor,
                        }
                except Exception as e:
                    logger.warning(f"[v2 R1] result error {profile.agent_id}: {e}")

        # Already indexed by pair_id
        return raw_pool

    # ── Round 2 helper ────────────────────────────────────────────────────────

    def _run_voting_round(
        self,
        cm: dict,
        t1_profiles: list,
        candidate_pool: dict,
        n_agents: int,
    ) -> tuple:
        """
        Blind voting round. Returns (accepted_findings_list, all_votes_dict).
        score = (k + r) / n   where k=submitters, r=ACCEPT votes, n=total agents
        """
        max_workers = int(os.environ.get("LLM_MAX_WORKERS", "1"))
        submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "0"))

        all_pairs = list(candidate_pool.values())

        # votes[pair_id][agent_id] = "ACCEPT" | "REJECT"
        votes: dict = {p["pair_id"]: {} for p in all_pairs}
        # evidence_by_pair: pair_id → list of evidence snippets from voters
        evidence_by_pair: dict = {p["pair_id"]: [] for p in all_pairs}

        def _vote_one(profile) -> list:
            # Self-exclusion: skip pairs where this agent was a submitter
            agent_pairs = [
                p for p in all_pairs
                if profile.agent_id not in p["submitters"]
            ]
            if not agent_pairs:
                return []
            t0 = time.time()
            prompt = cm["r2_prompt"](profile, agent_pairs)
            try:
                response = self._call_agent_v2(prompt, max_tokens=self._V2_R2_MAX_TOKENS)
            except Exception as e:
                logger.warning(f"[v2 R2] agent={profile.agent_id} error: {e}")
                return []
            elapsed = time.time() - t0
            logger.info(f"[TIMING] Phase=v2 R2 agent={profile.agent_id} latency={elapsed:.1f}s")
            return cm["parse_r2_votes"](response, profile.agent_id)

        # Initial voting
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {}
            for profile in t1_profiles:
                if submit_delay > 0:
                    time.sleep(submit_delay)
                futures[ex.submit(_vote_one, profile)] = profile

            for future, profile in futures.items():
                try:
                    for vote in future.result():
                        pid = vote["pair_id"]
                        if pid in votes:
                            votes[pid][profile.agent_id] = vote
                            if vote.get("counter"):
                                evidence_by_pair[pid].append(vote["counter"][:250])
                except Exception as e:
                    logger.warning(f"[v2 R2 collect] {profile.agent_id}: {e}")

        # Evidence reveal — build revealed_evidence per agent
        def _build_revealed(profile) -> list:
            revealed = []
            agent_voted_pairs = [
                pid for pid, pair_votes in votes.items()
                if profile.agent_id in pair_votes
            ]
            for pid in agent_voted_pairs:
                meta = candidate_pool[pid]
                agent_v = votes[pid].get(profile.agent_id, "?")
                revealed.append({
                    "pair_id":       pid,
                    "contract_name": meta.get("contract_name", ""),
                    "title":         meta.get("title", ""),
                    "function_name": meta["function_name"],
                    "all_evidence":  evidence_by_pair.get(pid, []),
                    "agent_vote":    agent_v.get("vote", "?") if isinstance(agent_v, dict) else agent_v,
                })
            return revealed

        def _update_vote_one(profile) -> list:
            revealed = _build_revealed(profile)
            if not revealed:
                return []
            t0 = time.time()
            prompt = cm["r2_update_prompt"](profile, revealed)
            if not prompt:
                return []
            try:
                response = self._call_agent_v2(prompt, max_tokens=self._V2_R2_MAX_TOKENS)
            except Exception as e:
                logger.warning(f"[v2 R2u] agent={profile.agent_id} error: {e}")
                return []
            elapsed = time.time() - t0
            logger.info(f"[TIMING] Phase=v2 R2u agent={profile.agent_id} latency={elapsed:.1f}s")
            return cm["parse_r2_upd"](response, profile.agent_id)

        # Update phase
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {}
            for profile in t1_profiles:
                if submit_delay > 0:
                    time.sleep(submit_delay)
                futures[ex.submit(_update_vote_one, profile)] = profile

            for future, profile in futures.items():
                try:
                    for upd in future.result():
                        pid = upd["pair_id"]
                        if pid in votes:
                            votes[pid][profile.agent_id] = upd
                            if upd.get("new_evidence"):
                                evidence_by_pair[pid].append(upd["new_evidence"][:250])
                except Exception as e:
                    logger.warning(f"[v2 R2u collect] {profile.agent_id}: {e}")

        # Score and filter
        def _get_vote_val(v):
            if isinstance(v, dict):
                return v.get("vote") or v.get("updated_vote", "")
            return v

        r_min = int(os.environ.get("R2_R_MIN", "4"))
        accepted = []
        for pair_id, meta in candidate_pool.items():
            k = len(meta["submitters"])
            pair_votes   = votes.get(pair_id, {})
            accept       = sum(1 for v in pair_votes.values() if _get_vote_val(v) == "ACCEPT")
            valid_reject = sum(
                1 for v in pair_votes.values()
                if _get_vote_val(v) == "REJECT" and isinstance(v, dict) and self._is_valid_reject(v)
            )
            eligible = accept + valid_reject
            score    = (k + accept) / (k + eligible) if (k + eligible) > 0 else 0.0

            meta["round2_score"]    = score
            meta["accept_votes"]    = accept
            meta["valid_reject"]    = valid_reject
            meta["reject_votes"]    = sum(1 for v in pair_votes.values() if _get_vote_val(v) == "REJECT")

            if score >= self._R2_THRESHOLD and accept >= r_min:
                accepted.append(meta)
                logger.debug(f"[v2 R2] ACCEPTED pair_id={pair_id} score={score:.2f} "
                             f"accept={accept} valid_reject={valid_reject} "
                             f"({meta.get('contract_name','?')}.{meta['function_name']} '{meta.get('title','')[:40]}')")
            else:
                logger.debug(f"[v2 R2] REJECTED pair_id={pair_id} score={score:.2f} "
                             f"accept={accept} valid_reject={valid_reject} (r_min={r_min})")

        return accepted, votes

    # ── Round 3 helper ────────────────────────────────────────────────────────

    def _run_attacker_round(
        self,
        cm: dict,
        t2_profiles: list,
        accepted_findings: list,
        contract_source: str,
    ) -> tuple:
        """
        Attacker validation. Returns (confirmed, borderline, discarded).
        Weights: CONFIRMED=1.0, PLAUSIBLE=0.5, INVALID=0.0
        attacker_rate = weighted_sum / effective_M
        """
        max_workers = int(os.environ.get("LLM_MAX_WORKERS", "1"))
        submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "0"))
        M = len(t2_profiles)
        _weights = {"CONFIRMED": 1.0, "PLAUSIBLE": 0.5, "INVALID": 0.0}

        confirmed:  list = []
        borderline: list = []
        discarded:  list = []

        for finding in accepted_findings:
            pair_id = finding["pair_id"]
            verdicts: dict = {}  # attacker_id → verdict dict

            # Initial attacker pass
            def _atk_one(attacker, finding=finding) -> Optional[dict]:
                t0 = time.time()
                prompt = cm["r3_prompt"](attacker, finding, contract_source)
                try:
                    response = self._call_agent_v2(prompt, use_boost=True, max_tokens=self._V2_R3_MAX_TOKENS)
                except Exception as e:
                    logger.warning(f"[v2 R3] attacker={attacker.agent_id} error: {e}")
                    return None
                elapsed = time.time() - t0
                logger.info(f"[TIMING] Phase=v2 R3 agent={attacker.agent_id} latency={elapsed:.1f}s")
                return cm["parse_r3_verdict"](response, attacker.agent_id)

            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {}
                for attacker in t2_profiles:
                    if submit_delay > 0:
                        time.sleep(submit_delay)
                    futures[ex.submit(_atk_one, attacker)] = attacker
                for future, attacker in futures.items():
                    try:
                        v = future.result()
                        if v:
                            verdicts[attacker.agent_id] = v
                    except Exception as e:
                        logger.warning(f"[v2 R3 collect] {attacker.agent_id}: {e}")

            # Evidence reveal for INVALID verdicts (1 update pass)
            invalid_reasons = [
                {"attacker_id": aid, "reason": v.get("reason","")}
                for aid, v in verdicts.items()
                if v.get("verdict") == "INVALID"
            ]
            if invalid_reasons and len(invalid_reasons) < M:
                # Some non-INVALID verdicts exist — give INVALID attackers a chance to reconsider
                def _atk_update(attacker, finding=finding, invalid_reasons=invalid_reasons) -> Optional[dict]:
                    if verdicts.get(attacker.agent_id, {}).get("verdict") != "INVALID":
                        return None
                    t0 = time.time()
                    prompt = cm["r3_update_prompt"](attacker, finding, invalid_reasons)
                    try:
                        response = self._call_agent_v2(prompt, use_boost=True, max_tokens=self._V2_R3_MAX_TOKENS)
                    except Exception as e:
                        logger.warning(f"[v2 R3u] attacker={attacker.agent_id} error: {e}")
                        return None
                    elapsed = time.time() - t0
                    logger.info(f"[TIMING] Phase=v2 R3u agent={attacker.agent_id} latency={elapsed:.1f}s")
                    return cm["parse_r3_upd"](response, attacker.agent_id)

                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    upd_futures = {}
                    for attacker in t2_profiles:
                        if submit_delay > 0:
                            time.sleep(submit_delay)
                        upd_futures[ex.submit(_atk_update, attacker)] = attacker
                    for future, attacker in upd_futures.items():
                        try:
                            upd = future.result()
                            if upd and upd.get("updated_verdict") and upd["pair_id"] == pair_id:
                                verdicts[attacker.agent_id]["verdict"] = upd["updated_verdict"]
                        except Exception as e:
                            logger.warning(f"[v2 R3u collect] {attacker.agent_id}: {e}")

            # Score
            not_applicable = sum(1 for v in verdicts.values() if v.get("verdict") == "NOT_APPLICABLE")
            effective_M = M - not_applicable
            if effective_M < 1:
                effective_M = 1  # avoid div-by-zero

            weighted_sum = sum(
                _weights.get(v.get("verdict","INVALID"), 0.0)
                for v in verdicts.values()
                if v.get("verdict") != "NOT_APPLICABLE"
            )
            attacker_rate = weighted_sum / effective_M

            finding = dict(finding)  # copy to avoid mutating candidate_pool
            r2_score        = finding.get("round2_score", 0.0)
            attacker_factor = self._R3_ATTACKER_BASE + (1.0 - self._R3_ATTACKER_BASE) * attacker_rate
            confidence      = r2_score * attacker_factor

            finding["attacker_rate"]         = attacker_rate
            finding["effective_attackers"]   = effective_M
            finding["attacker_verdicts"]     = verdicts
            finding["not_applicable_count"]  = not_applicable
            finding["attacker_factor"]       = attacker_factor
            finding["confidence"]            = confidence
            finding["final_score"]           = confidence   # alias for backward compat

            logger.info(
                f"[v2 R3] pair_id={pair_id} attacker_rate={attacker_rate:.2f} "
                f"attacker_factor={attacker_factor:.2f} confidence={confidence:.3f} "
                f"effective_M={effective_M} r2_score={r2_score:.2f}"
            )

            if confidence >= self._R3_CONFIRMED:
                finding["v2_status"] = "confirmed"
                confirmed.append(finding)
            else:
                finding["v2_status"] = "discarded"
                discarded.append(finding)

        return confirmed, borderline, discarded

    # ── Accounting Invariant Micro-Pass ───────────────────────────────────────

    def _run_accounting_micropass(self, source: str) -> List[Dict]:
        from app.services.contract_dep_graph import (
            find_transfer_without_accounting,
            build_accounting_check_context,
        )
        from app.services.contract_oasis_env import build_accounting_verifier_prompt

        candidates = find_transfer_without_accounting(source)
        if not candidates:
            logger.info("[micro] No transfer-without-accounting candidates found")
            return []
        logger.info(f"[micro] {len(candidates)} candidate functions for accounting check")
        prompt = build_accounting_verifier_prompt(build_accounting_check_context(candidates))
        raw = self._simple_llm_call(prompt, max_tokens=4096)
        return self._parse_accounting_findings(raw)

    def _simple_llm_call(self, prompt: str, max_tokens: int = 4096) -> str:
        """Single LLM call using the orchestrator's existing LLM client."""
        try:
            return self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=max_tokens,
            )
        except Exception as e:
            logger.warning(f"[micro] LLM call failed: {e}")
            return ""

    def _parse_accounting_findings(self, raw: str) -> List[Dict]:
        """Parse FINDING blocks from accounting verifier output."""
        findings = []
        blocks = re.split(r'\n(?=FINDING\b)', raw)
        for block in blocks:
            if not block.strip().startswith("FINDING"):
                continue
            def _field(name: str) -> str:
                m = re.search(rf'^  {name}:\s*(.+)$', block, re.MULTILINE)
                return m.group(1).strip() if m else ""
            title = _field("TITLE")
            fn = _field("FUNCTION")
            contract = _field("CONTRACT")
            evidence = _field("EVIDENCE")
            if not (title and fn):
                continue
            attack_m = re.search(r'ATTACK_PATH:(.*?)(?=\n\n|\Z)', block, re.DOTALL)
            attack_text = attack_m.group(1).strip() if attack_m else ""
            findings.append({
                "title": title,
                "function_name": fn,
                "contract_name": contract,
                "description": f"{title}. {evidence}",
                "evidence_snippets": [evidence] if evidence else [],
                "attack_path": attack_text,
                "code_anchor": evidence,
                "severity": "HIGH",
            })
        return findings
