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

Tạm dừng và tiếp tục:
    # Chạy lần đầu (hoặc Ctrl+C để dừng)
    python run_security_review.py --scenario sme_no_tools --output ./results/r1/

    # Tiếp tục từ checkpoint
    python run_security_review.py --output ./results/r1/ --resume
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
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

CHECKPOINT_FILE = "checkpoint.json"


# ─── Rate limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Simple sliding-window rate limiter.
    Sleeps as needed to stay under `rpm` requests per minute.
    Set rpm=0 to disable (unlimited — paid tier).
    """

    def __init__(self, rpm: int):
        self.rpm = rpm
        self._lock = None  # created lazily so it works with ThreadPoolExecutor
        self._timestamps: list = []

    def acquire(self):
        """Block until a request slot is available."""
        if self.rpm <= 0:
            return
        from threading import Lock
        if self._lock is None:
            self._lock = Lock()
        with self._lock:
            now = time.monotonic()
            window = 60.0
            # Remove timestamps older than 1 minute
            self._timestamps = [t for t in self._timestamps if now - t < window]
            if len(self._timestamps) >= self.rpm:
                # Wait until oldest timestamp falls outside the window
                sleep_for = window - (now - self._timestamps[0]) + 0.1
                if sleep_for > 0:
                    logger.debug(f"  [rate limiter] sleeping {sleep_for:.1f}s (RPM={self.rpm})")
                    time.sleep(sleep_for)
            self._timestamps.append(time.monotonic())


# ─── Checkpoint helpers ───────────────────────────────────────────────────────

def _checkpoint_path(output_dir: str) -> str:
    return os.path.join(output_dir, CHECKPOINT_FILE)


def save_checkpoint(output_dir: str, data: dict):
    """Ghi checkpoint sau mỗi round."""
    path = _checkpoint_path(output_dir)
    tmp  = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)  # atomic write
    logger.info(f"  [checkpoint] Round {data['round_completed']}/{data['rounds']} saved → {path}")


def load_checkpoint(output_dir: str) -> Optional[dict]:
    """Đọc checkpoint nếu tồn tại."""
    path = _checkpoint_path(output_dir)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _profiles_to_dicts(profiles: list) -> list:
    """Serialize CyberAgentProfile list → list of dicts."""
    return [asdict(p) for p in profiles]


def _profiles_from_dicts(dicts: list) -> list:
    """Deserialize list of dicts → CyberAgentProfile list."""
    from app.services.cyber_expert_profile_generator import CyberAgentProfile
    result = []
    for d in dicts:
        result.append(CyberAgentProfile(
            user_id=d["user_id"],
            agent_id=d["agent_id"],
            tier=d["tier"],
            domain_group=d["domain_group"],
            persona=d["persona"],
            display_name=d["display_name"],
            system_prompt=d["system_prompt"],
            bio=d["bio"],
            ttp_focus=d["ttp_focus"],
            tools_known=d["tools_known"],
            motivation=d.get("motivation"),
            skill_level=d.get("skill_level"),
        ))
    return result


def _session_state_from_dict(d: dict):
    """Reconstruct CyberSessionState từ dict (bỏ qua nested dataclass conversion)."""
    from app.models.cyber_models import CyberSessionState
    state = CyberSessionState(
        session_id=d["session_id"],
        graph_id=d["graph_id"],
        total_rounds=d["total_rounds"],
    )
    state.current_round = d.get("current_round", 0)
    state.current_phase = d.get("current_phase", "A")
    state.expert_findings   = d.get("expert_findings", [])
    state.attacker_findings = d.get("attacker_findings", [])
    return state


# ─── Graceful shutdown ────────────────────────────────────────────────────────

_shutdown_requested = False

def _handle_signal(sig, frame):
    global _shutdown_requested
    if not _shutdown_requested:
        logger.info("\n[PAUSE] Ctrl+C nhận được — sẽ dừng sau khi round hiện tại hoàn thành.")
        logger.info("        Dùng --resume để tiếp tục sau.")
        _shutdown_requested = True

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ─── Main logic ───────────────────────────────────────────────────────────────

def run_review(
    graph_id: Optional[str],
    network_text: Optional[str],
    scenario: Optional[str],
    output_dir: str,
    rounds: int = 10,
    verbose: bool = False,
    resume: bool = False,
):
    """Chạy (hoặc tiếp tục) full review session và lưu kết quả vào output_dir."""
    global _shutdown_requested

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    os.makedirs(output_dir, exist_ok=True)

    from app.services.cyber_session_orchestrator import CyberSessionOrchestrator
    from app.services.cyber_expert_profile_generator import CyberExpertProfileGenerator
    from app.services.consensus_engine import ConsensusEngine
    from app.services.vuln_report_agent import VulnReportAgent
    from app.services.cyber_oasis_env import (
        get_phase_for_round, CyberOasisEnvBuilder,
    )
    from app.models.cyber_models import CyberSessionState
    from app.utils.llm_client import LLMClient

    orchestrator = CyberSessionOrchestrator()

    # ── Resume hoặc fresh start ───────────────────────────────────────────────
    ckpt = load_checkpoint(output_dir) if resume else None

    if ckpt:
        round_start    = ckpt["round_completed"] + 1
        rounds         = ckpt["rounds"]
        session_id     = ckpt["session_id"]
        graph_id       = ckpt["graph_id"]
        network_summary = ckpt["network_summary"]
        profiles       = _profiles_from_dicts(ckpt["profiles"])
        session_state  = _session_state_from_dict(ckpt["session_state"])
        feed_posts     = ckpt["feed_posts"]

        logger.info(f"\n{'='*60}")
        logger.info(f"RESUMING SECURITY REVIEW SESSION")
        logger.info(f"{'='*60}")
        logger.info(f"Session    : {session_id}")
        logger.info(f"Graph ID   : {graph_id}")
        logger.info(f"Resuming from round {round_start}/{rounds}")
        logger.info(f"Findings so far: {len(session_state.expert_findings)} expert, "
                    f"{len(session_state.attacker_findings)} attacker")

    else:
        # Fresh start
        if resume and not ckpt:
            logger.warning(f"Không tìm thấy checkpoint trong {output_dir}. Bắt đầu từ đầu.")

        profile_gen = CyberExpertProfileGenerator()

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
            logger.error("Phải cung cấp --graph-id, --text, hoặc --scenario (hoặc --resume để tiếp tục)")
            sys.exit(1)

        logger.info(f"\n{'='*60}")
        logger.info(f"SECURITY REVIEW SESSION — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        logger.info(f"{'='*60}")
        logger.info(f"Graph ID   : {graph_id}")
        logger.info(f"Output     : {output_dir}")
        logger.info(f"Rounds     : {rounds}")

        # Generate agent profiles
        logger.info("\n[Step 1/4] Generating 18 agent profiles...")
        result = profile_gen.generate_all_profiles(
            network_summary=network_summary,
            graph_id=graph_id,
        )
        profiles = result["all"]
        logger.info(f"  Tier 1 (domain experts): {len(result['tier1'])} agents")
        logger.info(f"  Tier 2 (attacker profiles): {len(result['tier2'])} agents")

        profiles_path = os.path.join(output_dir, "agent_profiles.json")
        with open(profiles_path, "w", encoding="utf-8") as f:
            json.dump(result["oasis_profiles"], f, ensure_ascii=False, indent=2)
        logger.info(f"  Saved: {profiles_path}")

        session_id    = f"script_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session_state = CyberSessionState(session_id=session_id, graph_id=graph_id, total_rounds=rounds)
        feed_posts    = []
        round_start   = 1

    # ── Run rounds ────────────────────────────────────────────────────────────
    logger.info("\n[Step 2/4] Running 3-phase analysis session...")
    logger.info("  Phase A (rounds 1-3):  Intra-group discussion")
    logger.info("  Phase B (rounds 4-7):  Cross-group challenge")
    logger.info("  Phase C (rounds 8-10): Attacker challenge")

    env_builder = CyberOasisEnvBuilder()
    llm = LLMClient()

    max_workers = int(os.environ.get("LLM_MAX_WORKERS", "1"))
    rpm_limit   = int(os.environ.get("LLM_RPM_LIMIT", "14"))  # 14 = safe margin under 15 RPM free tier
    rate_limiter = RateLimiter(rpm_limit)

    if max_workers > 1:
        logger.info(f"  Concurrency : {max_workers} parallel agent calls (LLM_MAX_WORKERS={max_workers})")
    else:
        logger.info("  Concurrency : sequential (LLM_MAX_WORKERS=1)")
    if rpm_limit > 0:
        logger.info(f"  Rate limit  : {rpm_limit} RPM (LLM_RPM_LIMIT={rpm_limit})")
    else:
        logger.info("  Rate limit  : disabled (LLM_RPM_LIMIT=0)")

    def _call_agent(profile, phase_instr, prior_ctx, round_num, phase):
        """Single agent LLM call — safe to run in a thread. Retries on 429."""
        import re as _re
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
        max_attempts = 5
        for attempt in range(max_attempts):
            rate_limiter.acquire()
            try:
                response = llm.chat(messages, temperature=0.7, max_tokens=4096)
                post = {
                    "round_num": round_num, "phase": phase,
                    "agent_id": profile.agent_id, "agent_display": profile.display_name,
                    "tier": profile.tier, "domain_group": profile.domain_group,
                    "persona": profile.persona, "content": response,
                    "timestamp": datetime.now().isoformat(),
                }
                return profile, post, response
            except Exception as e:
                err_str = str(e)
                # Parse retryDelay from Gemini 429 response
                match = _re.search(r"retryDelay['\"]:\s*['\"](\d+)s", err_str)
                retry_after = int(match.group(1)) + 2 if match else 60
                if "429" in err_str and attempt < max_attempts - 1:
                    logger.info(
                        f"    [rate limit] {profile.agent_id}: 429 — sleeping {retry_after}s "
                        f"(attempt {attempt+1}/{max_attempts})"
                    )
                    time.sleep(retry_after)
                else:
                    raise

    for round_num in range(round_start, rounds + 1):
        if _shutdown_requested:
            logger.info(f"\n[PAUSE] Stopping before round {round_num}. Checkpoint saved.")
            break

        phase  = get_phase_for_round(round_num)
        active = env_builder.get_active_agents_for_phase(profiles, phase)

        logger.info(f"  Round {round_num:2d}/{rounds} [Phase {phase}] — {len(active)} active agents")

        prior_ctx = orchestrator._build_prior_context(session_state)

        def _make_instr(profile):
            """Per-agent phase instruction with gap context injected if relevant."""
            from app.services.cyber_oasis_env import build_gap_context_for_agent
            gap_ctx = ""
            if profile.tier == 1 and phase in ("A", "B"):
                gap_ctx = build_gap_context_for_agent(
                    session_state.pending_gaps(), profile.domain_group
                )
            return env_builder.build_phase_instruction(phase, round_num, gap_context=gap_ctx)

        if max_workers > 1:
            # Parallel: collect results then process in order
            round_results = []
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {
                    pool.submit(_call_agent, p, _make_instr(p), prior_ctx, round_num, phase): p
                    for p in active
                    if not _shutdown_requested
                }
                for future in as_completed(futures):
                    if _shutdown_requested:
                        break
                    try:
                        profile, post, response = future.result()
                        round_results.append((profile, post, response))
                        logger.debug(f"    ✓ {profile.agent_id}")
                    except Exception as e:
                        logger.warning(f"    Agent {futures[future].agent_id}: {e}")
            # Process findings sequentially (no LLM — safe)
            for profile, post, response in round_results:
                feed_posts.append(post)
                if profile.tier == 1:
                    orchestrator._process_expert_response(response, profile, round_num, session_state)
                    if phase in ("A", "B"):
                        orchestrator._process_gap_declarations(response, profile, round_num, session_state)
                else:
                    orchestrator._process_attacker_response(response, profile, round_num, session_state)
            if phase in ("A", "B"):
                orchestrator._mark_gaps_as_routed(session_state)
        else:
            # Sequential
            for profile in active:
                if _shutdown_requested:
                    break
                try:
                    profile, post, response = _call_agent(profile, _make_instr(profile), prior_ctx, round_num, phase)
                    feed_posts.append(post)
                    if profile.tier == 1:
                        orchestrator._process_expert_response(response, profile, round_num, session_state)
                        if phase in ("A", "B"):
                            orchestrator._process_gap_declarations(response, profile, round_num, session_state)
                    else:
                        orchestrator._process_attacker_response(response, profile, round_num, session_state)
                except Exception as e:
                    logger.warning(f"    Agent {profile.agent_id}: {e}")
            if phase in ("A", "B"):
                orchestrator._mark_gaps_as_routed(session_state)

        session_state.current_round = round_num
        session_state.current_phase = phase

        # ── Save checkpoint sau mỗi round ─────────────────────────────────────
        save_checkpoint(output_dir, {
            "session_id":      session_id,
            "graph_id":        graph_id,
            "network_summary": network_summary,
            "scenario":        scenario,
            "rounds":          rounds,
            "round_completed": round_num,
            "profiles":        _profiles_to_dicts(profiles),
            "session_state":   asdict(session_state),
            "feed_posts":      feed_posts,
            "saved_at":        datetime.now().isoformat(),
        })

    # Nếu bị interrupt, lưu feed và thoát sớm
    if _shutdown_requested:
        _save_feed(output_dir, feed_posts, session_state)
        logger.info(f"\nĐể tiếp tục: python scripts/run_security_review.py --output {output_dir} --resume")
        return None

    session_state.current_phase = "done"

    # ── Lưu feed + session state ──────────────────────────────────────────────
    _save_feed(output_dir, feed_posts, session_state)

    logger.info(f"\n  Expert findings   : {len(session_state.expert_findings)}")
    logger.info(f"  Attacker findings : {len(session_state.attacker_findings)}")
    logger.info(f"  Feed posts        : {len(feed_posts)}")

    # ── Consensus engine ──────────────────────────────────────────────────────
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
    logger.info(f"  agent_profiles.json : {os.path.join(output_dir, 'agent_profiles.json')}")
    logger.info(f"  feed.jsonl          : {os.path.join(output_dir, 'feed.jsonl')}")
    logger.info(f"  session_state.json  : {os.path.join(output_dir, 'session_state.json')}")
    logger.info(f"  report.json         : {report_path}")
    logger.info(f"  report.md           : {report_txt_path}")

    # Xoá checkpoint khi hoàn thành
    ckpt_path = _checkpoint_path(output_dir)
    if os.path.exists(ckpt_path):
        os.remove(ckpt_path)
        logger.info(f"  checkpoint.json     : removed (session completed)")

    return report_result


def _save_feed(output_dir: str, feed_posts: list, session_state):
    """Lưu feed.jsonl và session_state.json."""
    feed_path = os.path.join(output_dir, "feed.jsonl")
    with open(feed_path, "w", encoding="utf-8") as f:
        for post in feed_posts:
            f.write(json.dumps(post, ensure_ascii=False) + "\n")

    state_path = os.path.join(output_dir, "session_state.json")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(asdict(session_state), f, ensure_ascii=False, indent=2)


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
        "--resume",
        action="store_true",
        help="Tiếp tục từ checkpoint trong --output dir (bỏ qua --scenario/--text/--graph-id)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Debug logging"
    )

    args = parser.parse_args()

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
            resume=args.resume,
        )
    elif args.resume:
        # Resume chỉ cần --output
        run_review(
            graph_id=None,
            network_text=None,
            scenario=None,
            output_dir=args.output,
            rounds=args.rounds,
            verbose=args.verbose,
            resume=True,
        )
    else:
        if not args.graph_id and not args.text and not args.scenario:
            parser.print_help()
            print("\nVí dụ:")
            print("  python run_security_review.py --scenario sme_no_tools --output ./results/scenario1/")
            print("  python run_security_review.py --output ./results/scenario1/ --resume")
            sys.exit(1)

        run_review(
            graph_id=args.graph_id,
            network_text=args.text,
            scenario=args.scenario,
            output_dir=args.output,
            rounds=args.rounds,
            verbose=args.verbose,
            resume=False,
        )


if __name__ == "__main__":
    main()
