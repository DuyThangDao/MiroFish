"""
Security Review Script — Multi-Expert Panel (Direction B)

Script chạy độc lập cho 18-agent vulnerability analysis session.
Không cần Flask server — có thể chạy trực tiếp từ CLI.

Sử dụng:
    python run_security_review.py --graph-id <id> --output ./results/
    python run_security_review.py --text "Mô tả hạ tầng..." --output ./results/
    python run_security_review.py --config /path/to/review_config.json

Ví dụ đầy đủ:
    python run_security_review.py \\
        --graph-id mirofish_abc123 \\
        --output ./results/review1/ \\
        --rounds 10 \\
        --scenario sme_no_tools
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Optional

# ─── Path setup ───────────────────────────────────────────────────────────────
_scripts_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir  = os.path.abspath(os.path.join(_scripts_dir, ".."))
_project_root = os.path.abspath(os.path.join(_backend_dir, ".."))

sys.path.insert(0, _scripts_dir)
sys.path.insert(0, _backend_dir)

# Load .env
from dotenv import load_dotenv
_env_file = os.path.join(_project_root, ".env")
if os.path.exists(_env_file):
    load_dotenv(_env_file)
else:
    _backend_env = os.path.join(_backend_dir, ".env")
    if os.path.exists(_backend_env):
        load_dotenv(_backend_env)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("security_review")


# ─── Built-in scenarios ───────────────────────────────────────────────────────
# 3 kịch bản trong Multi-Expert-Panel-Plan.md §5.2

SCENARIOS = {
    "sme_no_tools": {
        "name": "Kịch bản 1 — SME không có security tool",
        "description": (
            "Small enterprise with 5 hosts. No EDR, SIEM, or WAF deployed.\n"
            "Hosts:\n"
            "  - WEB-01: Apache 2.4.49, zone DMZ, Ubuntu 20.04, unpatched, CVE-2021-41773\n"
            "  - DB-01: MySQL 8.0, zone Database, Ubuntu 20.04, patched, is_critical=true\n"
            "  - FW-01: pfSense 2.5, zone Management, is_critical=true\n"
            "  - WIN-01: Windows Server 2019, zone Internal, unpatched, RDP exposed\n"
            "  - MAIL-01: Postfix 3.5, zone DMZ, Ubuntu 22.04\n"
            "Security controls: none (no EDR, SIEM, AV, NDR, WAF, MFA, DLP)\n"
            "Network: Direct internet exposure on DMZ hosts. No network segmentation between Internal and Database."
        ),
    },
    "mid_siem": {
        "name": "Kịch bản 2 — Doanh nghiệp vừa có SIEM",
        "description": (
            "Medium enterprise with 15 hosts. SIEM deployed, no EDR.\n"
            "Zones: DMZ (3 hosts), Internal (8 hosts), Database (2 hosts), Management (2 hosts)\n"
            "Hosts include: load balancer, 2 web servers (Nginx 1.18), "
            "3 app servers (Tomcat 9.0), 2 DB servers (PostgreSQL 13, is_critical=true), "
            "AD domain controller (Windows Server 2019, is_critical=true), "
            "file server (Windows Server 2016, SMB exposed internally), "
            "2 developer workstations (Windows 10, local admin enabled).\n"
            "Security controls: SIEM on all hosts, MFA on VPN only, no EDR, no WAF.\n"
            "CVEs: CVE-2021-26855 (Exchange-like) on mail server, "
            "CVE-2020-1472 (ZeroLogon) patched status unknown on DC.\n"
            "Network: Developers have direct access to Internal zone. "
            "No segmentation between Internal and Database."
        ),
    },
    "enterprise_full_stack": {
        "name": "Kịch bản 3 — Enterprise với full stack security",
        "description": (
            "Large enterprise with 30+ hosts across multiple zones.\n"
            "Security controls: SIEM + EDR (all endpoints) + WAF (DMZ) + NDR + MFA (all remote access).\n"
            "Architecture: DMZ (10 hosts: web, API gateway, CDN, WAF), "
            "Internal (12 hosts: app servers, collaboration, developer), "
            "Database (5 hosts, all critical, isolated subnet), "
            "Management (3 hosts: jump server, monitoring, backup).\n"
            "All systems patched within 30 days. No known unpatched CVEs.\n"
            "Policies: Zero-trust network access, least privilege enforced, "
            "DLP on all endpoints, API authentication via OAuth2+JWT.\n"
            "3rd party integrations: SaaS HR platform (Workday), "
            "cloud storage (AWS S3), external CI/CD pipeline (GitHub Actions).\n"
            "Known gaps: Legacy VPN still in use alongside ZTNA during migration. "
            "Backup server not monitored by SIEM. GitHub Actions token has broad repo permissions."
        ),
    },
}


# ─── Main logic ───────────────────────────────────────────────────────────────

def run_review(
    graph_id: Optional[str],
    network_text: Optional[str],
    scenario: Optional[str],
    output_dir: str,
    rounds: int = 10,
    verbose: bool = False,
):
    """Chạy full review session và lưu kết quả vào output_dir."""

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    os.makedirs(output_dir, exist_ok=True)

    # ── Build network context ─────────────────────────────────────────────────
    from app.services.cyber_session_orchestrator import CyberSessionOrchestrator
    from app.services.cyber_expert_profile_generator import CyberExpertProfileGenerator
    from app.services.consensus_engine import ConsensusEngine
    from app.services.vuln_report_agent import VulnReportAgent

    orchestrator = CyberSessionOrchestrator()
    profile_gen  = CyberExpertProfileGenerator()

    if scenario:
        sc = SCENARIOS.get(scenario)
        if not sc:
            logger.error(f"Scenario '{scenario}' không tồn tại. Chọn: {list(SCENARIOS.keys())}")
            sys.exit(1)
        logger.info(f"Sử dụng scenario: {sc['name']}")
        network_summary = sc["description"]
        graph_id = graph_id or f"scenario_{scenario}"

    elif graph_id:
        logger.info(f"Lấy network context từ Zep graph: {graph_id}")
        network_summary = orchestrator.build_network_context_from_zep(graph_id)
        logger.info(f"Network context ({len(network_summary)} chars)")

    elif network_text:
        network_summary = network_text
        graph_id = f"manual_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    else:
        logger.error("Phải cung cấp --graph-id, --text, hoặc --scenario")
        sys.exit(1)

    logger.info(f"\n{'='*60}")
    logger.info(f"SECURITY REVIEW SESSION — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    logger.info(f"{'='*60}")
    logger.info(f"Graph ID   : {graph_id}")
    logger.info(f"Output     : {output_dir}")
    logger.info(f"Rounds     : {rounds}")

    # ── Generate agent profiles ───────────────────────────────────────────────
    logger.info("\n[Step 1/4] Generating 18 agent profiles...")
    result = profile_gen.generate_all_profiles(
        network_summary=network_summary,
        graph_id=graph_id,
    )
    profiles = result["all"]
    logger.info(f"  Tier 1 (domain experts): {len(result['tier1'])} agents")
    logger.info(f"  Tier 2 (attacker profiles): {len(result['tier2'])} agents")

    # Save profiles
    profiles_path = os.path.join(output_dir, "agent_profiles.json")
    with open(profiles_path, "w", encoding="utf-8") as f:
        json.dump(result["oasis_profiles"], f, ensure_ascii=False, indent=2)
    logger.info(f"  Saved: {profiles_path}")

    # ── Run 3-phase session (synchronous in script mode) ─────────────────────
    logger.info("\n[Step 2/4] Running 3-phase analysis session...")
    logger.info("  Phase A (rounds 1-3):  Intra-group discussion")
    logger.info("  Phase B (rounds 4-7):  Cross-group challenge")
    logger.info("  Phase C (rounds 8-10): Attacker challenge")

    from app.services.cyber_oasis_env import (
        get_phase_for_round, CyberOasisEnvBuilder,
        parse_expert_finding_from_text, AttackerAction
    )
    from app.models.cyber_models import (
        CyberSessionState, ExpertFinding, AttackerFinding, AttackerCorroboration
    )
    from dataclasses import asdict
    import uuid

    env_builder = CyberOasisEnvBuilder()
    session_id  = f"script_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    config = env_builder.build_config(
        session_id=session_id,
        graph_id=graph_id,
        profiles=profiles,
        network_summary=network_summary,
    )

    session_state = CyberSessionState(session_id=session_id, graph_id=graph_id, total_rounds=rounds)
    feed_posts = []

    from app.utils.llm_client import LLMClient
    llm = LLMClient()

    for round_num in range(1, rounds + 1):
        phase = get_phase_for_round(round_num)
        active = env_builder.get_active_agents_for_phase(profiles, phase)
        phase_instr = env_builder.build_phase_instruction(phase, round_num)

        logger.info(f"  Round {round_num:2d}/{rounds} [Phase {phase}] — {len(active)} active agents")

        # Build prior context
        prior_ctx = orchestrator._build_prior_context(session_state)

        for profile in active:
            try:
                messages = [
                    {"role": "system", "content": profile.system_prompt},
                    {
                        "role": "user",
                        "content": (
                            f"{phase_instr}\n\n"
                            f"=== DISCUSSION SO FAR ===\n{prior_ctx}\n\n"
                            f"Provide your analysis for Round {round_num}."
                        )
                    }
                ]
                response = llm.chat(messages, temperature=0.7, max_tokens=1200)

                post = {
                    "round_num": round_num, "phase": phase,
                    "agent_id": profile.agent_id, "agent_display": profile.display_name,
                    "tier": profile.tier, "domain_group": profile.domain_group,
                    "persona": profile.persona, "content": response,
                    "timestamp": datetime.now().isoformat(),
                }
                feed_posts.append(post)

                if profile.tier == 1:
                    orchestrator._process_expert_response(response, profile, round_num, session_state)
                else:
                    orchestrator._process_attacker_response(response, profile, round_num, session_state)

            except Exception as e:
                logger.warning(f"    Agent {profile.agent_id}: {e}")

        session_state.current_round = round_num
        session_state.current_phase = phase

    session_state.current_phase = "done"

    # Save feed + session state
    feed_path = os.path.join(output_dir, "feed.jsonl")
    with open(feed_path, "w", encoding="utf-8") as f:
        for post in feed_posts:
            f.write(json.dumps(post, ensure_ascii=False) + "\n")

    state_path = os.path.join(output_dir, "session_state.json")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(asdict(session_state), f, ensure_ascii=False, indent=2)

    logger.info(f"\n  Expert findings   : {len(session_state.expert_findings)}")
    logger.info(f"  Attacker findings : {len(session_state.attacker_findings)}")
    logger.info(f"  Feed posts        : {len(feed_posts)}")

    # ── Run consensus engine ──────────────────────────────────────────────────
    logger.info("\n[Step 3/4] Running consensus engine (3-layer scoring)...")
    engine = ConsensusEngine()
    consensus_vulns = engine.run(
        session_state.expert_findings,
        session_state.attacker_findings,
    )
    gaps = engine.get_coverage_gaps(consensus_vulns)

    logger.info(f"  Consensus vulnerabilities: {len(consensus_vulns)}")
    logger.info(f"    Critical : {gaps['critical_count']}")
    logger.info(f"    High     : {gaps['high_count']}")
    logger.info(f"    Silent groups: {gaps['silent_domain_groups'] or 'none'}")

    # ── Generate report ───────────────────────────────────────────────────────
    logger.info("\n[Step 4/4] Generating vulnerability report (ReACT agent)...")
    report_agent = VulnReportAgent()
    report_result = report_agent.generate_report_sync(
        session_id=session_id,
        expert_findings=session_state.expert_findings,
        attacker_findings=session_state.attacker_findings,
        network_summary=network_summary,
        graph_id=graph_id,
    )

    # Save all outputs
    report_path = os.path.join(output_dir, "report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_result, f, ensure_ascii=False, indent=2)

    report_txt_path = os.path.join(output_dir, "report.md")
    with open(report_txt_path, "w", encoding="utf-8") as f:
        f.write(f"# Security Review Report\n\n")
        f.write(f"**Session**: {session_id}\n")
        f.write(f"**Graph**: {graph_id}\n")
        f.write(f"**Generated**: {report_result.get('generated_at', '')}\n\n")
        f.write("---\n\n")
        f.write(report_result.get("report", ""))

    logger.info(f"\n{'='*60}")
    logger.info("REVIEW COMPLETED")
    logger.info(f"{'='*60}")
    logger.info(f"  agent_profiles.json : {profiles_path}")
    logger.info(f"  feed.jsonl          : {feed_path}")
    logger.info(f"  session_state.json  : {state_path}")
    logger.info(f"  report.json         : {report_path}")
    logger.info(f"  report.md           : {report_txt_path}")

    return report_result


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Run Multi-Expert Panel security review (18 agents, 3 phases)"
    )

    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--graph-id",
        help="Zep graph ID chứa network topology (đã build qua /api/cyber/setup)"
    )
    source.add_argument(
        "--text",
        help="Text mô tả hạ tầng mạng trực tiếp"
    )
    source.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()),
        help="Dùng built-in scenario từ luận án §5.2"
    )
    parser.add_argument(
        "--config",
        help="Path tới JSON config file (override các arg khác)"
    )
    parser.add_argument(
        "--output",
        default=f"./results/review_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        help="Thư mục lưu kết quả (default: ./results/review_<timestamp>)"
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=10,
        help="Số rounds (default: 10; A=3, B=4, C=3)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Debug logging"
    )

    args = parser.parse_args()

    # Config file override
    if args.config:
        if not os.path.exists(args.config):
            logger.error(f"Config file không tồn tại: {args.config}")
            sys.exit(1)
        with open(args.config, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        run_review(
            graph_id=cfg.get("graph_id"),
            network_text=cfg.get("network_text"),
            scenario=cfg.get("scenario"),
            output_dir=cfg.get("output", args.output),
            rounds=cfg.get("rounds", args.rounds),
            verbose=args.verbose,
        )
    else:
        if not args.graph_id and not args.text and not args.scenario:
            parser.print_help()
            print("\nVí dụ:")
            print("  python run_security_review.py --scenario sme_no_tools --output ./results/scenario1/")
            print("  python run_security_review.py --graph-id mirofish_abc123 --output ./results/")
            sys.exit(1)

        run_review(
            graph_id=args.graph_id,
            network_text=args.text,
            scenario=args.scenario,
            output_dir=args.output,
            rounds=args.rounds,
            verbose=args.verbose,
        )


if __name__ == "__main__":
    main()
