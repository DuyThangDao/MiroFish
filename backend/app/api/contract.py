"""
Contract Audit API — Multi-Expert Panel for Smart Contracts (Đề tài 10)

Blueprint riêng, không thay đổi code cũ.
Endpoints cho toàn bộ workflow: parse → KG build → agent gen → session → report.
"""

import traceback
from collections import defaultdict
from flask import Blueprint, request, jsonify

from ..utils.logger import get_logger
from ..models.task import TaskManager, TaskStatus
from ..services.contract_kg_builder import ContractKGBuilder
from ..services.contract_profile_generator import (
    ContractExpertProfileGenerator, ContractAgentProfile,
    CONTRACT_AGENT_MATRIX, CONTRACT_ATTACKER_PROFILES,
)
from ..services.cyber_session_orchestrator import CyberSessionOrchestrator
from ..services.contract_audit_agent import ContractAuditReportAgent
from ..utils.llm_client import LLMClient

logger = get_logger("mirofish.api.contract")

contract_bp = Blueprint("contract", __name__)

# Singletons — khởi tạo 1 lần khi module load
_kg_builder: ContractKGBuilder = None
_task_manager: TaskManager = None
_profile_generator: ContractExpertProfileGenerator = None
_orchestrator: CyberSessionOrchestrator = None
_report_agent: ContractAuditReportAgent = None
_llm_client: LLMClient = None


def _get_kg_builder() -> ContractKGBuilder:
    global _kg_builder
    if _kg_builder is None:
        _kg_builder = ContractKGBuilder()
    return _kg_builder


def _get_task_manager() -> TaskManager:
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager


def _get_profile_generator() -> ContractExpertProfileGenerator:
    global _profile_generator
    if _profile_generator is None:
        _profile_generator = ContractExpertProfileGenerator()
    return _profile_generator


def _get_orchestrator() -> CyberSessionOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = CyberSessionOrchestrator()
    return _orchestrator


def _get_report_agent() -> ContractAuditReportAgent:
    global _report_agent
    if _report_agent is None:
        _report_agent = ContractAuditReportAgent()
    return _report_agent


def _get_llm_client() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


# ─── Agent system prompt reconstruction ───────────────────────────────────────

def _build_interview_system_prompt(agent_id: str) -> tuple[str, str, str]:
    """
    Reconstruct system prompt từ agent_id.
    Returns (system_prompt, domain, persona).

    agent_id format:
      Tier 1: "<domain>_<persona>"           e.g. "appsec_offensive"
      Tier 2: "attacker_<profile_key>"       e.g. "attacker_reentrancy_exploiter"
    """
    # ── Tier 2: Attacker profiles ─────────────────────────────────────────────
    if agent_id.startswith("attacker_"):
        profile_key = agent_id[len("attacker_"):]
        profile = CONTRACT_ATTACKER_PROFILES.get(profile_key, {})
        base_prompt = profile.get("prompt", f"You are {profile.get('name', agent_id)}.")
        system_prompt = (
            f"{base_prompt}\n\n"
            f"You are in an interview context. Answer honestly from your attacker perspective.\n"
            f"Be specific about what you would actually do to exploit vulnerabilities."
        )
        return system_prompt, "attacker", profile_key

    # ── Tier 1: Domain × Persona experts ─────────────────────────────────────
    # agent_id like "appsec_offensive", "smart_contract_economics_economist"
    # Try progressively shorter domain prefixes to find the match
    domain, persona = "", ""
    for d in CONTRACT_AGENT_MATRIX:
        sanitized_domain = d.replace(" ", "_")
        if agent_id.startswith(sanitized_domain + "_"):
            domain = d
            persona = agent_id[len(sanitized_domain) + 1:]
            break

    if not domain:
        # Fallback: split on last underscore
        parts = agent_id.rsplit("_", 1)
        domain = parts[0] if len(parts) == 2 else agent_id
        persona = parts[1] if len(parts) == 2 else "auditor"

    matrix_entry = CONTRACT_AGENT_MATRIX.get(domain, {})
    persona_prompts = matrix_entry.get("persona_prompts", {})
    base_prompt = persona_prompts.get(
        persona,
        f"You are a {domain} security expert with {persona} mindset."
    )
    swc_focus = matrix_entry.get("swc_focus", [])
    swc_hint = f"Your SWC focus areas: {', '.join(swc_focus)}." if swc_focus else ""

    system_prompt = (
        f"{base_prompt}\n\n"
        f"{swc_hint}\n\n"
        f"You are in an interview context. Answer from your domain expertise.\n"
        f"Reference specific functions, SWC IDs, and evidence from the audit session."
    ).strip()

    return system_prompt, domain, persona


def _build_interview_context(
    state: dict,
    agent_id: str,
    domain: str,
    max_feed_posts: int = 15,
) -> str:
    """
    Build context block injected trước question:
      - Contract overview (graph_id)
      - Agent's own findings trong session này
      - Cuối feed (recent discussion)
    """
    lines = []

    lines.append(f"=== Audit Session Context ===")
    lines.append(f"Session: {state.get('session_id', '?')}")
    lines.append(f"Graph/Contract: {state.get('graph_id', '?')}")
    lines.append(f"Phase completed: {state.get('current_phase', '?')} / Round {state.get('current_round', 0)}/10")
    lines.append("")

    # Agent's own findings
    is_attacker = agent_id.startswith("attacker_")
    if is_attacker:
        profile_key = agent_id[len("attacker_"):]
        my_findings = [
            f for f in state.get("attacker_findings", [])
            if f.get("attacker_profile") == profile_key
        ]
    else:
        my_findings = [
            f for f in state.get("expert_findings", [])
            if f.get("author_domain") == domain
        ]

    if my_findings:
        lines.append(f"=== Your findings in this session ({len(my_findings)}) ===")
        for f in my_findings[:8]:
            swc = f.get("swc_id", "?")
            sev = f.get("severity", "?")
            title = f.get("title", "?")
            funcs = ", ".join(f.get("affected_functions", [])[:2]) or "?"
            lines.append(f"  [{sev.upper()}][{swc}] {title} — function: {funcs}")
        lines.append("")

    # Recent feed (last N posts across all agents)
    feed_posts = CyberSessionOrchestrator.load_feed(state.get("session_id", ""))
    if feed_posts:
        recent = feed_posts[-max_feed_posts:]
        lines.append(f"=== Recent discussion (last {len(recent)} posts) ===")
        for post in recent:
            aid   = post.get("agent_id", "?")
            phase = post.get("phase", "?")
            rnd   = post.get("round_num", "?")
            content = post.get("content", "")[:300]
            lines.append(f"[Phase {phase}/Round {rnd}] {aid}:")
            lines.append(f"  {content}")
        lines.append("")

    return "\n".join(lines)


# ─── Phase 1: Contract Upload & KG Build ──────────────────────────────────────

@contract_bp.route("/upload", methods=["POST"])
def upload_contract():
    """
    Parse Solidity source và build Zep Knowledge Graph (background task).

    Body (JSON):
        source_code : str  — Solidity source code (required)
        graph_name  : str  — tên graph (default: "Smart Contract Audit")

    Returns:
        { task_id }

    Task result (khi complete) sẽ có:
        { graph_id, contract_id, contract_type, function_count,
          state_var_count, swc_candidates, context_summary }
    """
    try:
        data = request.get_json(silent=True) or {}
        source_code = data.get("source_code", "").strip()
        graph_name  = data.get("graph_name", "Smart Contract Audit")

        if not source_code:
            return jsonify({"success": False, "error": "Cần cung cấp 'source_code'"}), 400

        builder = _get_kg_builder()
        task_id = builder.build_from_source_async(
            source_code=source_code,
            graph_name=graph_name,
        )

        return jsonify({"success": True, "data": {"task_id": task_id}})

    except Exception as e:
        logger.error(f"upload_contract error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Task polling ─────────────────────────────────────────────────────────────

@contract_bp.route("/task/<task_id>", methods=["GET"])
def get_task(task_id: str):
    """
    Poll task status (upload, session, report, ...).

    Returns:
        { status, progress, message, result }
    """
    task = _get_task_manager().get_task(task_id)
    if not task:
        return jsonify({"success": False, "error": f"Task không tồn tại: {task_id}"}), 404
    return jsonify({"success": True, "data": task.to_dict()})


# ─── Contract summary ─────────────────────────────────────────────────────────

@contract_bp.route("/<graph_id>/summary", methods=["GET"])
def get_contract_summary(graph_id: str):
    """
    Lấy context summary của contract từ Zep KG.
    Dùng để lấy lại contract_summary khi không muốn lưu từ task result.

    Returns:
        { graph_id, summary }
    """
    try:
        orchestrator = _get_orchestrator()
        summary = orchestrator.build_contract_context_from_zep(graph_id)
        return jsonify({
            "success": True,
            "data": {"graph_id": graph_id, "summary": summary}
        })
    except Exception as e:
        logger.error(f"get_contract_summary error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Phase 2: Agent Profile Generation ───────────────────────────────────────

@contract_bp.route("/<graph_id>/agents/generate", methods=["POST"])
def generate_agents(graph_id: str):
    """
    Generate 17 + 5 = 22 agent profiles (Tier-1 domain experts + Tier-2 attackers).

    Body (JSON):
        contract_summary : str  — từ task result .context_summary (required)

    Returns:
        { tier1_count, tier2_count, total, oasis_profiles }
    """
    try:
        data = request.get_json(silent=True) or {}
        contract_summary = data.get("contract_summary", "").strip()

        if not contract_summary:
            return jsonify({"success": False, "error": "Cần 'contract_summary' từ task result"}), 400

        generator = _get_profile_generator()
        result = generator.generate_all_profiles(
            contract_summary=contract_summary,
            graph_id=graph_id or None,
        )

        return jsonify({
            "success": True,
            "data": {
                "tier1_count":    len(result["tier1"]),
                "tier2_count":    len(result["tier2"]),
                "total":          len(result["all"]),
                "oasis_profiles": result["oasis_profiles"],
            }
        })

    except Exception as e:
        logger.error(f"generate_agents error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Phase 3: Audit Session ───────────────────────────────────────────────────

@contract_bp.route("/session/start", methods=["POST"])
def start_session():
    """
    Khởi chạy 3-phase audit session (background).

    Phases:
      A (rounds 1-3):   Intra-domain analysis — 17 Tier-1 experts
      B (rounds 4-7):   Cross-domain debate — 17 Tier-1 experts
      C (rounds 8-10):  Attacker profiles validate exploitability — all 22 agents

    Body (JSON):
        graph_id         : str
        contract_summary : str   — từ task result .context_summary
        oasis_profiles   : list  — từ /agents/generate

    Returns:
        { task_id, session_id }
    """
    try:
        data = request.get_json(silent=True) or {}
        graph_id         = data.get("graph_id", "")
        contract_summary = data.get("contract_summary", "")
        oasis_profiles_raw = data.get("oasis_profiles", [])

        if not contract_summary:
            return jsonify({"success": False, "error": "Cần 'contract_summary'"}), 400
        if not oasis_profiles_raw:
            return jsonify({"success": False, "error": "Cần 'oasis_profiles' từ /agents/generate"}), 400

        # Rebuild ContractAgentProfile objects từ oasis_profiles dicts
        profiles = []
        for idx, p in enumerate(oasis_profiles_raw):
            profiles.append(ContractAgentProfile(
                user_id=p.get("user_id", idx),
                agent_id=p.get("username", f"agent_{idx}"),
                tier=p.get("_tier", 1),
                domain_group=p.get("_domain_group", "appsec"),
                persona=p.get("_persona", "auditor"),
                display_name=p.get("name", ""),
                system_prompt=p.get("persona", ""),
                bio=p.get("bio", ""),
                swc_focus=p.get("_swc_focus", []),
            ))

        orchestrator = _get_orchestrator()
        task_id = orchestrator.run_session_async(
            graph_id=graph_id,
            network_summary=contract_summary,   # reuse network_summary param
            profiles=profiles,
            mode="contract_audit",
        )

        # Extract session_id from task metadata
        task = _get_task_manager().get_task(task_id)
        session_id = task.metadata.get("session_id", task_id) if task else task_id

        return jsonify({
            "success": True,
            "data": {"task_id": task_id, "session_id": session_id}
        })

    except Exception as e:
        logger.error(f"start_session error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Review session GET endpoints ─────────────────────────────────────────────

@contract_bp.route("/review/<session_id>/status", methods=["GET"])
def get_review_status(session_id: str):
    """
    Realtime status của audit session.

    Returns:
        { status, current_phase, current_round, finding_count, attacker_finding_count }
    """
    try:
        state = CyberSessionOrchestrator.load_session_state(session_id)
        if not state:
            return jsonify({"success": False, "error": f"Session không tồn tại: {session_id}"}), 404

        return jsonify({
            "success": True,
            "data": {
                "session_id":            session_id,
                "graph_id":              state.get("graph_id"),
                "status":                state.get("current_phase", "idle"),
                "current_phase":         state.get("current_phase", "idle"),
                "current_round":         state.get("current_round", 0),
                "total_rounds":          state.get("total_rounds", 10),
                "finding_count":         len(state.get("expert_findings", [])),
                "attacker_finding_count": len(state.get("attacker_findings", [])),
                "error":                 state.get("error"),
            }
        })
    except Exception as e:
        logger.error(f"get_review_status error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


@contract_bp.route("/review/<session_id>/findings", methods=["GET"])
def get_review_findings(session_id: str):
    """
    Danh sách findings từ session (expert + attacker, realtime).

    Query params:
        phase    : "A" | "B" | "C" (optional)
        domain   : domain group filter (optional) — "appsec" | "blockchain" | ...
        severity : severity filter (optional)    — "critical" | "high" | "medium" | "low"
        swc_id   : SWC ID filter (optional)      — "SWC-107" etc.
        type     : "expert" | "attacker" | "all" (default: all)

    Returns:
        { findings[], domain_breakdown, swc_breakdown, cross_validated_count, attacker_count }
    """
    try:
        state = CyberSessionOrchestrator.load_session_state(session_id)
        if not state:
            return jsonify({"success": False, "error": f"Session không tồn tại: {session_id}"}), 404

        phase_filter    = request.args.get("phase", "").upper()
        domain_filter   = request.args.get("domain", "")
        severity_filter = request.args.get("severity", "").lower()
        swc_filter      = request.args.get("swc_id", "").upper()
        type_filter     = request.args.get("type", "all")

        expert_findings   = list(state.get("expert_findings", []))
        attacker_findings = list(state.get("attacker_findings", []))

        # Apply filters to expert findings
        if phase_filter:
            expert_findings = [f for f in expert_findings if f.get("phase") == phase_filter]
        if domain_filter:
            expert_findings = [f for f in expert_findings if f.get("author_domain") == domain_filter]
        if severity_filter:
            expert_findings = [f for f in expert_findings if f.get("severity") == severity_filter]
        if swc_filter:
            expert_findings = [f for f in expert_findings if f.get("swc_id", "").upper() == swc_filter]

        # Domain breakdown
        domain_counts: dict = defaultdict(int)
        for f in expert_findings:
            domain_counts[f.get("author_domain", "unknown")] += 1

        # SWC breakdown
        swc_counts: dict = defaultdict(int)
        for f in expert_findings:
            swc_id = f.get("swc_id", "UNKNOWN")
            if swc_id:
                swc_counts[swc_id] += 1

        cross_validated = sum(
            1 for f in expert_findings if f.get("cross_group_validated", False)
        )

        result_findings = []
        if type_filter in ("expert", "all"):
            result_findings.extend(expert_findings)
        if type_filter in ("attacker", "all"):
            result_findings.extend(attacker_findings)

        return jsonify({
            "success": True,
            "data": {
                "session_id":            session_id,
                "total_expert":          len(state.get("expert_findings", [])),
                "total_attacker":        len(state.get("attacker_findings", [])),
                "filtered_count":        len(result_findings),
                "cross_validated_count": cross_validated,
                "domain_breakdown":      dict(domain_counts),
                "swc_breakdown":         dict(swc_counts),
                "findings":              result_findings,
            }
        })
    except Exception as e:
        logger.error(f"get_review_findings error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


@contract_bp.route("/review/<session_id>/feed", methods=["GET"])
def get_review_feed(session_id: str):
    """
    Lịch sử các post trên OASIS feed của audit session.
    Mỗi post = 1 agent response trong 1 round.

    Query params:
        phase     : "A" | "B" | "C" filter (optional)
        round_num : int filter (optional)
        agent_id  : agent_id filter (optional)
        limit     : max posts trả về (default 100)
        offset    : skip đầu (default 0)

    Returns:
        { posts[], total, phase_breakdown }
    """
    try:
        posts = CyberSessionOrchestrator.load_feed(session_id)
        if posts is None:
            return jsonify({"success": False, "error": f"Session không tồn tại: {session_id}"}), 404

        phase_filter  = request.args.get("phase", "").upper()
        round_filter  = request.args.get("round_num", type=int)
        agent_filter  = request.args.get("agent_id", "")
        limit         = request.args.get("limit", 100, type=int)
        offset        = request.args.get("offset", 0, type=int)

        if phase_filter:
            posts = [p for p in posts if p.get("phase") == phase_filter]
        if round_filter is not None:
            posts = [p for p in posts if p.get("round_num") == round_filter]
        if agent_filter:
            posts = [p for p in posts if p.get("agent_id") == agent_filter]

        total = len(posts)
        posts_page = posts[offset: offset + limit]

        phase_counts: dict = defaultdict(int)
        for p in posts:
            phase_counts[p.get("phase", "?")] += 1

        return jsonify({
            "success": True,
            "data": {
                "session_id":      session_id,
                "total":           total,
                "offset":          offset,
                "limit":           limit,
                "phase_breakdown": dict(phase_counts),
                "posts":           posts_page,
            }
        })
    except Exception as e:
        logger.error(f"get_review_feed error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Phase 4: Audit Report ─────────────────────────────────────────────────────

@contract_bp.route("/report/generate", methods=["POST"])
def generate_report():
    """
    Generate audit report từ session kết quả (background).
    Chạy ConsensusEngine + ContractAuditReportAgent ReACT loop.

    Body (JSON):
        session_id        : str
        expert_findings   : list  — từ session task result
        attacker_findings : list  — từ session task result
        contract_summary  : str
        graph_id          : str (optional)

    Returns:
        { task_id }
    """
    try:
        data = request.get_json(silent=True) or {}
        session_id        = data.get("session_id", "")
        expert_findings   = data.get("expert_findings", [])
        attacker_findings = data.get("attacker_findings", [])
        semantic_findings = data.get("semantic_findings", [])
        contract_summary  = data.get("contract_summary", "")
        graph_id          = data.get("graph_id")

        if not session_id or not contract_summary:
            return jsonify({
                "success": False,
                "error": "Cần 'session_id' và 'contract_summary'"
            }), 400

        agent = _get_report_agent()
        task_id = agent.generate_report_async(
            session_id=session_id,
            expert_findings=expert_findings,
            attacker_findings=attacker_findings,
            contract_summary=contract_summary,
            graph_id=graph_id,
            semantic_findings=semantic_findings,
        )

        return jsonify({"success": True, "data": {"task_id": task_id}})

    except Exception as e:
        logger.error(f"generate_report error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


@contract_bp.route("/report/<session_id>", methods=["GET"])
def get_report(session_id: str):
    """
    Lấy audit report đã generated.

    Returns:
        { report, consensus_vulns[], unvalidated_swc_gaps[], coverage_gaps, stats }
    """
    report_data = ContractAuditReportAgent.load_report(session_id)
    if not report_data:
        return jsonify({
            "success": False,
            "error": (
                f"Report chưa tồn tại cho session '{session_id}'. "
                "Chạy POST /report/generate trước."
            )
        }), 404

    return jsonify({"success": True, "data": report_data})


# ─── Agent Interview ───────────────────────────────────────────────────────────

@contract_bp.route("/interview", methods=["POST"])
def interview_agent():
    """
    Hỏi đáp trực tiếp với 1 agent sau khi session kết thúc.
    Agent trả lời từ đúng góc nhìn domain/persona của mình,
    dựa trên context của session (findings + feed).

    Body (JSON):
        session_id : str  — session đã chạy xong
        agent_id   : str  — ví dụ "appsec_offensive", "attacker_reentrancy_exploiter"
        question   : str  — câu hỏi bất kỳ

    agent_id hợp lệ (Tier 1):
        appsec_offensive, appsec_defensive, appsec_auditor
        blockchain_offensive, blockchain_defensive, blockchain_auditor
        cryptography_offensive, cryptography_defensive
        defi_offensive, defi_defensive, defi_analyst
        governance_offensive, governance_defensive
        smart_contract_economics_economist, smart_contract_economics_protocol_designer
        supply_chain_dependency_auditor, supply_chain_build_analyst

    agent_id hợp lệ (Tier 2):
        attacker_reentrancy_exploiter, attacker_flash_loan_attacker,
        attacker_governance_attacker, attacker_access_control_exploiter,
        attacker_logic_exploiter

    Returns:
        { agent_id, domain, persona, answer, findings_count }
    """
    try:
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id", "").strip()
        agent_id   = data.get("agent_id", "").strip()
        question   = data.get("question", "").strip()

        if not session_id or not agent_id or not question:
            return jsonify({
                "success": False,
                "error": "Cần 'session_id', 'agent_id', và 'question'"
            }), 400

        # Load session state
        state = CyberSessionOrchestrator.load_session_state(session_id)
        if not state:
            return jsonify({
                "success": False,
                "error": f"Session không tồn tại: {session_id}"
            }), 404

        # Reconstruct agent identity + system prompt
        system_prompt, domain, persona = _build_interview_system_prompt(agent_id)

        # Build session context
        context = _build_interview_context(
            state=state,
            agent_id=agent_id,
            domain=domain,
        )

        # Call LLM as this agent
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    f"{context}\n"
                    f"=== Interview Question ===\n"
                    f"{question}\n\n"
                    f"Answer as {agent_id} — stay in character, be specific and technical."
                )
            }
        ]

        llm = _get_llm_client()
        answer = llm.chat(messages, temperature=0.4, max_tokens=2048)

        # Count this agent's findings
        is_attacker = agent_id.startswith("attacker_")
        if is_attacker:
            profile_key = agent_id[len("attacker_"):]
            findings_count = sum(
                1 for f in state.get("attacker_findings", [])
                if f.get("attacker_profile") == profile_key
            )
        else:
            findings_count = sum(
                1 for f in state.get("expert_findings", [])
                if f.get("author_domain") == domain
            )

        return jsonify({
            "success": True,
            "data": {
                "agent_id":       agent_id,
                "domain":         domain,
                "persona":        persona,
                "answer":         answer,
                "findings_count": findings_count,
                "session_phase":  state.get("current_phase", "?"),
            }
        })

    except Exception as e:
        logger.error(f"interview_agent error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500
