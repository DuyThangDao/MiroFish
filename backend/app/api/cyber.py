"""
Cyber Security API — Multi-Expert Panel (Direction B)

Blueprint riêng, không thay đổi code cũ.
Endpoints cho Phase 1: network topology build + query.
"""

import traceback
from flask import Blueprint, request, jsonify

from ..utils.logger import get_logger
from ..models.task import TaskManager, TaskStatus
from ..services.network_topology_builder import NetworkTopologyBuilder
from ..services.mitre_reference import MitreReference, TTP_CATALOG, TTP_BY_DOMAIN
from ..services.cyber_expert_profile_generator import CyberExpertProfileGenerator
from ..services.cyber_session_orchestrator import CyberSessionOrchestrator
from ..services.vuln_report_agent import VulnReportAgent

logger = get_logger("mirofish.api.cyber")

cyber_bp = Blueprint("cyber", __name__)

# Singletons — khởi tạo 1 lần khi module load
_topology_builder: NetworkTopologyBuilder = None
_mitre_ref: MitreReference = None
_task_manager: TaskManager = None
_profile_generator: CyberExpertProfileGenerator = None
_orchestrator: CyberSessionOrchestrator = None
_report_agent: VulnReportAgent = None


def _get_topology_builder() -> NetworkTopologyBuilder:
    global _topology_builder
    if _topology_builder is None:
        _topology_builder = NetworkTopologyBuilder()
    return _topology_builder


def _get_mitre_ref() -> MitreReference:
    global _mitre_ref
    if _mitre_ref is None:
        _mitre_ref = MitreReference()
    return _mitre_ref


def _get_task_manager() -> TaskManager:
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager


def _get_profile_generator() -> CyberExpertProfileGenerator:
    global _profile_generator
    if _profile_generator is None:
        _profile_generator = CyberExpertProfileGenerator()
    return _profile_generator


def _get_orchestrator() -> CyberSessionOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = CyberSessionOrchestrator()
    return _orchestrator


def _get_report_agent() -> VulnReportAgent:
    global _report_agent
    if _report_agent is None:
        _report_agent = VulnReportAgent()
    return _report_agent


# ─── Phase 1: Network Topology ────────────────────────────────────────────────

@cyber_bp.route("/setup", methods=["POST"])
def setup_network():
    """
    Build network knowledge graph từ text mô tả hoặc IaC files.

    Body (JSON):
        text        : str                   — text mô tả hạ tầng (required if no iac_files)
        iac_files   : {filename: content}   — IaC file contents (optional)
        graph_name  : str                   — tên graph (default: "Cyber Security Graph")

    Returns:
        { task_id, mode }
    """
    try:
        data = request.get_json(silent=True) or {}
        text = data.get("text", "").strip()
        iac_files = data.get("iac_files", {})
        graph_name = data.get("graph_name", "Cyber Security Graph")

        if not text and not iac_files:
            return jsonify({"success": False, "error": "Cần cung cấp 'text' hoặc 'iac_files'"}), 400

        builder = _get_topology_builder()

        if iac_files:
            task_id = builder.build_from_iac_async(
                iac_files=iac_files,
                extra_text=text,
                graph_name=graph_name
            )
            mode = "iac"
        else:
            task_id = builder.build_from_text_async(text=text, graph_name=graph_name)
            mode = "text"

        return jsonify({"success": True, "data": {"task_id": task_id, "mode": mode}})

    except Exception as e:
        logger.error(f"setup_network error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


@cyber_bp.route("/task/<task_id>", methods=["GET"])
def get_task(task_id: str):
    """Poll task status."""
    task = _get_task_manager().get_task(task_id)
    if not task:
        return jsonify({"success": False, "error": f"Task không tồn tại: {task_id}"}), 404
    return jsonify({"success": True, "data": task.to_dict()})


@cyber_bp.route("/graph/<graph_id>/assets", methods=["GET"])
def get_assets(graph_id: str):
    """
    Trả về danh sách NetworkHost node từ Zep graph.

    Query params:
        zone    : lọc theo zone (optional)
        critical: "true" lọc chỉ critical assets (optional)
    """
    try:
        from ..utils.zep_paging import fetch_all_nodes
        from ..services.graph_builder import GraphBuilderService

        zone_filter = request.args.get("zone", "").strip()
        critical_only = request.args.get("critical", "").lower() == "true"

        graph_svc = GraphBuilderService()
        nodes = fetch_all_nodes(graph_svc.client, graph_id)

        assets = []
        for node in nodes:
            if not hasattr(node, "labels") or "NetworkHost" not in (node.labels or []):
                continue
            attrs = node.attributes or {}
            zone = attrs.get("zone", "")
            is_critical = str(attrs.get("is_critical", "false")).lower() == "true"

            if zone_filter and zone.lower() != zone_filter.lower():
                continue
            if critical_only and not is_critical:
                continue

            assets.append({
                "host_id":     attrs.get("host_id", node.name),
                "hostname":    node.name,
                "zone":        zone,
                "ip":          attrs.get("ip_address", "unknown"),
                "os":          attrs.get("os_version", "unknown"),
                "patch_status": attrs.get("patch_status", "unknown"),
                "is_critical": is_critical,
                "controls":    attrs.get("controls", ""),
                "node_uuid":   str(node.uuid) if hasattr(node, "uuid") else None,
            })

        return jsonify({
            "success": True,
            "data": {"asset_count": len(assets), "assets": assets}
        })

    except Exception as e:
        logger.error(f"get_assets error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


@cyber_bp.route("/graph/<graph_id>/attack-surface", methods=["GET"])
def get_attack_surface(graph_id: str):
    """
    Trả về các host nằm trong attack surface (có vulnerability hoặc thiếu control).
    """
    try:
        builder = _get_topology_builder()
        surface = builder.get_attack_surface(graph_id)
        return jsonify({
            "success": True,
            "data": {
                "vulnerable_count": len(surface),
                "vulnerable_hosts": surface,
            }
        })
    except Exception as e:
        logger.error(f"get_attack_surface error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── TTP Library ──────────────────────────────────────────────────────────────

@cyber_bp.route("/ttp-library", methods=["GET"])
def list_ttps():
    """
    Liệt kê TTP library.

    Query params:
        domain  : lọc theo domain (network_security, appsec, endpoint_security, threat_intel, risk)
        tactic  : lọc theo tactic (case-insensitive)
    """
    domain_filter = request.args.get("domain", "").strip()
    tactic_filter = request.args.get("tactic", "").strip().lower()

    if domain_filter:
        ids = TTP_BY_DOMAIN.get(domain_filter, [])
        ttps = {tid: TTP_CATALOG[tid] for tid in ids if tid in TTP_CATALOG}
    else:
        ttps = TTP_CATALOG

    if tactic_filter:
        ttps = {k: v for k, v in ttps.items() if v.get("tactic", "").lower() == tactic_filter}

    result = [
        {
            "id": tid,
            "name": v["name"],
            "tactic": v["tactic"],
            "description": v["description"],
            "detection_tools": v.get("detection_tools", []),
        }
        for tid, v in ttps.items()
    ]

    return jsonify({"success": True, "data": {"count": len(result), "techniques": result}})


@cyber_bp.route("/ttp-library/<technique_id>", methods=["GET"])
def get_ttp(technique_id: str):
    """Trả về chi tiết 1 TTP kèm D3FEND-style detection notes."""
    ttp = TTP_CATALOG.get(technique_id)
    if not ttp:
        return jsonify({"success": False, "error": f"Technique không tồn tại: {technique_id}"}), 404

    mitre = _get_mitre_ref()
    detection_reqs = mitre.get_detection_requirements(technique_id)

    return jsonify({
        "success": True,
        "data": {
            "id": technique_id,
            **ttp,
            "required_detection_tools": detection_reqs,
        }
    })


@cyber_bp.route("/ttp-library/context", methods=["POST"])
def get_ttp_context():
    """
    Trả về TTP context text cho 1 domain × persona combination.
    Dùng để preview prompt sẽ được inject vào agent.

    Body: { domain, persona }
    """
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "")
    persona = data.get("persona", "")

    if not domain or not persona:
        return jsonify({"success": False, "error": "Cần 'domain' và 'persona'"}), 400

    mitre = _get_mitre_ref()
    context = mitre.get_ttp_context_for_agent(domain, persona)

    return jsonify({"success": True, "data": {"context": context}})


# ─── Phase 2: Agent Profiles ──────────────────────────────────────────────────

@cyber_bp.route("/agents/generate", methods=["POST"])
def generate_agents():
    """
    Generate 18 agent profiles (13 domain expert + 5 attacker).

    Body: { graph_id, network_summary }
    Returns: { tier1, tier2, oasis_profiles }
    """
    try:
        data = request.get_json(silent=True) or {}
        graph_id = data.get("graph_id", "")
        network_summary = data.get("network_summary", "")

        if not network_summary:
            return jsonify({"success": False, "error": "Cần 'network_summary'"}), 400

        generator = _get_profile_generator()
        result = generator.generate_all_profiles(
            network_summary=network_summary,
            graph_id=graph_id or None,
        )

        return jsonify({
            "success": True,
            "data": {
                "tier1_count": len(result["tier1"]),
                "tier2_count": len(result["tier2"]),
                "total": len(result["all"]),
                "oasis_profiles": result["oasis_profiles"],
            }
        })

    except Exception as e:
        logger.error(f"generate_agents error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Phase 3: Analysis Session ────────────────────────────────────────────────

@cyber_bp.route("/session/start", methods=["POST"])
def start_session():
    """
    Khởi chạy 3-phase analysis session (background).

    Body:
        graph_id        : str
        network_summary : str
        oasis_profiles  : list  — từ /agents/generate

    Returns: { task_id, session_id }
    """
    try:
        data = request.get_json(silent=True) or {}
        graph_id = data.get("graph_id", "")
        network_summary = data.get("network_summary", "")
        oasis_profiles_raw = data.get("oasis_profiles", [])

        if not network_summary:
            return jsonify({"success": False, "error": "Cần 'network_summary'"}), 400
        if not oasis_profiles_raw:
            return jsonify({"success": False, "error": "Cần 'oasis_profiles' từ /agents/generate"}), 400

        # Rebuild CyberAgentProfile objects từ oasis_profiles dict
        from ..services.cyber_expert_profile_generator import CyberAgentProfile
        profiles = []
        for p in oasis_profiles_raw:
            profiles.append(CyberAgentProfile(
                user_id=p.get("user_id", 0),
                agent_id=p.get("username", "unknown"),
                tier=p.get("_tier", 1),
                domain_group=p.get("_domain_group", "unknown"),
                persona=p.get("_persona", "unknown"),
                display_name=p.get("name", ""),
                system_prompt=p.get("persona", ""),
                bio=p.get("bio", ""),
                ttp_focus=p.get("_ttp_focus", []),
                tools_known=p.get("_tools_known", []),
            ))

        orchestrator = _get_orchestrator()
        task_id = orchestrator.run_session_async(
            graph_id=graph_id,
            network_summary=network_summary,
            profiles=profiles,
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


# ─── Phase 4: Vulnerability Report ───────────────────────────────────────────

@cyber_bp.route("/report/generate", methods=["POST"])
def generate_report():
    """
    Generate vulnerability report từ session kết quả (background).

    Body:
        session_id         : str
        expert_findings    : list  — từ session task result
        attacker_findings  : list  — từ session task result
        network_summary    : str
        graph_id           : str (optional)

    Returns: { task_id }
    """
    try:
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id", "")
        expert_findings = data.get("expert_findings", [])
        attacker_findings = data.get("attacker_findings", [])
        network_summary = data.get("network_summary", "")
        graph_id = data.get("graph_id")

        if not session_id or not network_summary:
            return jsonify({
                "success": False,
                "error": "Cần 'session_id' và 'network_summary'"
            }), 400

        agent = _get_report_agent()
        task_id = agent.generate_report_async(
            session_id=session_id,
            expert_findings=expert_findings,
            attacker_findings=attacker_findings,
            network_summary=network_summary,
            graph_id=graph_id,
        )

        return jsonify({"success": True, "data": {"task_id": task_id}})

    except Exception as e:
        logger.error(f"generate_report error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Review session GET endpoints ─────────────────────────────────────────────

@cyber_bp.route("/review/<session_id>/status", methods=["GET"])
def get_review_status(session_id: str):
    """
    Realtime status của 1 analysis session.
    Đọc từ persisted state.json — không cần task_id.

    Returns:
        { status, current_phase, current_round, finding_count, attacker_finding_count }
    """
    try:
        from ..services.cyber_session_orchestrator import CyberSessionOrchestrator
        state = CyberSessionOrchestrator.load_session_state(session_id)
        if not state:
            return jsonify({"success": False, "error": f"Session không tồn tại: {session_id}"}), 404

        return jsonify({
            "success": True,
            "data": {
                "session_id": session_id,
                "graph_id": state.get("graph_id"),
                "status": state.get("current_phase", "idle"),
                "current_phase": state.get("current_phase", "idle"),
                "current_round": state.get("current_round", 0),
                "total_rounds": state.get("total_rounds", 10),
                "finding_count": len(state.get("expert_findings", [])),
                "attacker_finding_count": len(state.get("attacker_findings", [])),
                "error": state.get("error"),
            }
        })
    except Exception as e:
        logger.error(f"get_review_status error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


@cyber_bp.route("/review/<session_id>/findings", methods=["GET"])
def get_review_findings(session_id: str):
    """
    Danh sách findings từ session (expert + attacker, realtime).

    Query params:
        phase       : "A" | "B" | "C" (optional filter)
        group       : domain group filter (optional)
        severity    : severity filter (optional)
        type        : "expert" | "attacker" | "all" (default: all)

    Returns:
        { findings[], group_breakdown, cross_validated_count, attacker_count }
    """
    try:
        from ..services.cyber_session_orchestrator import CyberSessionOrchestrator
        state = CyberSessionOrchestrator.load_session_state(session_id)
        if not state:
            return jsonify({"success": False, "error": f"Session không tồn tại: {session_id}"}), 404

        phase_filter    = request.args.get("phase", "").upper()
        group_filter    = request.args.get("group", "")
        severity_filter = request.args.get("severity", "").lower()
        type_filter     = request.args.get("type", "all")

        expert_findings   = state.get("expert_findings", [])
        attacker_findings = state.get("attacker_findings", [])

        # Apply filters to expert findings
        if phase_filter:
            expert_findings = [f for f in expert_findings if f.get("phase") == phase_filter]
        if group_filter:
            expert_findings = [f for f in expert_findings if f.get("author_group") == group_filter]
        if severity_filter:
            expert_findings = [f for f in expert_findings if f.get("severity") == severity_filter]

        # Group breakdown
        from collections import defaultdict
        group_counts: dict = defaultdict(int)
        for f in expert_findings:
            group_counts[f.get("author_group", "unknown")] += 1

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
                "session_id": session_id,
                "total_expert": len(state.get("expert_findings", [])),
                "total_attacker": len(state.get("attacker_findings", [])),
                "filtered_count": len(result_findings),
                "cross_validated_count": cross_validated,
                "group_breakdown": dict(group_counts),
                "findings": result_findings,
            }
        })
    except Exception as e:
        logger.error(f"get_review_findings error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


@cyber_bp.route("/review/<session_id>/feed", methods=["GET"])
def get_review_feed(session_id: str):
    """
    Lịch sử các post trên OASIS feed của session.
    Mỗi post = 1 agent response trong 1 round.

    Query params:
        phase       : "A" | "B" | "C" filter (optional)
        round_num   : int filter (optional)
        agent_id    : agent_id filter (optional)
        limit       : max posts trả về (default 100)
        offset      : skip đầu (default 0)

    Returns:
        { posts[], total, phase_breakdown }
    """
    try:
        from ..services.cyber_session_orchestrator import CyberSessionOrchestrator

        posts = CyberSessionOrchestrator.load_feed(session_id)
        if posts is None:
            return jsonify({"success": False, "error": f"Session không tồn tại: {session_id}"}), 404

        phase_filter    = request.args.get("phase", "").upper()
        round_filter    = request.args.get("round_num", type=int)
        agent_filter    = request.args.get("agent_id", "")
        limit           = request.args.get("limit", 100, type=int)
        offset          = request.args.get("offset", 0, type=int)

        if phase_filter:
            posts = [p for p in posts if p.get("phase") == phase_filter]
        if round_filter is not None:
            posts = [p for p in posts if p.get("round_num") == round_filter]
        if agent_filter:
            posts = [p for p in posts if p.get("agent_id") == agent_filter]

        total = len(posts)
        posts_page = posts[offset: offset + limit]

        # Phase breakdown counts
        from collections import defaultdict
        phase_counts: dict = defaultdict(int)
        for p in posts:
            phase_counts[p.get("phase", "?")] += 1

        return jsonify({
            "success": True,
            "data": {
                "session_id": session_id,
                "total": total,
                "offset": offset,
                "limit": limit,
                "phase_breakdown": dict(phase_counts),
                "posts": posts_page,
            }
        })
    except Exception as e:
        logger.error(f"get_review_feed error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


@cyber_bp.route("/network-context/<graph_id>", methods=["GET"])
def get_network_context(graph_id: str):
    """
    Query Zep KG → trả về network summary text.
    Dùng để lấy network_summary khi không muốn tự build tay.
    """
    try:
        orchestrator = _get_orchestrator()
        summary = orchestrator.build_network_context_from_zep(graph_id)
        return jsonify({"success": True, "data": {"graph_id": graph_id, "summary": summary}})
    except Exception as e:
        logger.error(f"get_network_context error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Report GET endpoint ──────────────────────────────────────────────────────

@cyber_bp.route("/report/<session_id>", methods=["GET"])
def get_report(session_id: str):
    """
    Lấy vulnerability report đã generated.

    Returns:
        { report, consensus_vulnerabilities[], coverage_gaps, stats }
    """
    import os, json as _json
    from ..config import Config as _Config

    report_path = os.path.join(
        _Config.UPLOAD_FOLDER, "cyber_reports", session_id, "report.json"
    )

    if not os.path.exists(report_path):
        return jsonify({
            "success": False,
            "error": f"Report chưa tồn tại cho session '{session_id}'. Chạy /report/generate trước."
        }), 404

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            report_data = _json.load(f)
        return jsonify({"success": True, "data": report_data})
    except Exception as e:
        logger.error(f"get_report error: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500
