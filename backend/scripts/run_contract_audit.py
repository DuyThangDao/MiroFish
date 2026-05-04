"""
Contract Audit Script — Multi-Expert Panel for Smart Contracts (Đề tài 10)

End-to-end CLI: load .sol file → parse → build Zep KG → run audit session → generate report.
Không cần Flask server — chạy trực tiếp từ CLI.

Sử dụng:
    python run_contract_audit.py --sol /path/to/Contract.sol
    python run_contract_audit.py --sol /path/to/Contract.sol --output ./audit_results/
    python run_contract_audit.py --sol /path/to/Contract.sol --graph-name "DAO Hack Audit"

Ví dụ đầy đủ:
    python run_contract_audit.py \\
        --sol ./samples/dao_hack.sol \\
        --output ./audit_results/dao_hack/ \\
        --graph-name "DAO Hack Contract" \\
        --rounds 10

Chạy với built-in sample:
    python run_contract_audit.py --sample dao        # classic DAO hack contract
    python run_contract_audit.py --sample erc20      # vulnerable ERC20
    python run_contract_audit.py --sample defi_vault # DeFi vault with oracle risk
"""

import argparse
import json
import logging
import os
import sys
import csv
import re
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Set

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
logger = logging.getLogger("contract_audit")


# ─── Built-in sample contracts ────────────────────────────────────────────────

SAMPLE_CONTRACTS = {
    "dao": {
        "name": "Classic DAO Hack Contract",
        "description": "Vulnerable contract illustrating the 2016 DAO reentrancy hack pattern",
        "source": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract VulnerableDAO {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        // SWC-107: External call BEFORE state update
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= _amount;  // state updated AFTER call
    }

    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}
""",
    },
    "erc20": {
        "name": "Vulnerable ERC20 Token",
        "description": "ERC20 with missing access control on minting and tx.origin vulnerability",
        "source": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableToken {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    uint256 public totalSupply;
    address public owner;

    constructor() {
        owner = msg.sender;
        totalSupply = 1_000_000 * 10**18;
        balances[msg.sender] = totalSupply;
    }

    // SWC-115: tx.origin used for authentication
    function transfer(address to, uint256 amount) public returns (bool) {
        require(tx.origin == owner || balances[msg.sender] >= amount, "Not authorized");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }

    // SWC-105: Missing access control — anyone can mint
    function mint(address to, uint256 amount) public {
        totalSupply += amount;
        balances[to] += amount;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }
}
""",
    },
    "defi_vault": {
        "name": "DeFi Vault with Oracle Risk",
        "description": "Lending vault that uses a price oracle without circuit breaker — flash loan price manipulation risk",
        "source": """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

contract VulnerableVault {
    IPriceOracle public oracle;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;
    address public owner;

    constructor(address _oracle) {
        oracle = IPriceOracle(_oracle);
        owner = msg.sender;
    }

    // SWC-107 + PRICE_ORACLE_STALENESS: Uses spot price, no TWAP
    function borrow(address token, uint256 amount) public {
        uint256 price = oracle.getPrice(token);  // spot price — flash loan manipulable
        uint256 collateralValue = deposits[msg.sender] * price / 1e18;
        require(collateralValue >= amount * 150 / 100, "Insufficient collateral");
        borrows[msg.sender] += amount;
        // SWC-107: external call before borrows update (re-entrant borrow)
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function deposit() public payable {
        deposits[msg.sender] += msg.value;
    }

    // SWC-105: no access control on liquidation
    function liquidate(address user) public {
        require(borrows[user] > 0, "No debt");
        uint256 seized = deposits[user];
        deposits[user] = 0;
        borrows[user] = 0;
        (bool ok, ) = msg.sender.call{value: seized}("");
        require(ok);
    }
}
""",
    },
}


# ─── Poll helper ──────────────────────────────────────────────────────────────

def _poll_task(task_manager, task_id: str, label: str, timeout: int = 300) -> dict:
    """Poll task until complete or fail. Returns task result dict."""
    deadline = time.monotonic() + timeout
    last_progress = -1
    while time.monotonic() < deadline:
        task = task_manager.get_task(task_id)
        if not task:
            raise RuntimeError(f"Task {task_id} disappeared")

        progress = task.progress or 0
        if progress != last_progress:
            logger.info(f"  [{label}] {progress}% — {task.message or ''}")
            last_progress = progress

        if task.status.value == "completed":
            logger.info(f"  [{label}] ✅ Done")
            return task.result or {}
        elif task.status.value in ("failed", "error"):
            raise RuntimeError(f"Task failed: {task.error}")

        time.sleep(3)

    raise TimeoutError(f"Task {task_id} did not complete within {timeout}s")


# ─── Profiles helpers ─────────────────────────────────────────────────────────

def _profiles_to_dicts(profiles: list) -> list:
    return [asdict(p) for p in profiles]


def _profiles_from_dicts(dicts: list) -> list:
    from app.services.contract_profile_generator import ContractAgentProfile
    result = []
    for d in dicts:
        result.append(ContractAgentProfile(
            user_id=d["user_id"],
            agent_id=d["agent_id"],
            tier=d["tier"],
            domain_group=d["domain_group"],
            persona=d["persona"],
            display_name=d["display_name"],
            system_prompt=d["system_prompt"],
            bio=d["bio"],
            swc_focus=d.get("swc_focus", []),
            motivation=d.get("motivation"),
            skill_level=d.get("skill_level"),
        ))
    return result


# ─── Main audit pipeline ──────────────────────────────────────────────────────

def run_audit(
    source_code: str,
    contract_name: str,
    output_dir: str,
    graph_name: Optional[str] = None,
    verbose: bool = False,
    timeout_session: int = 1800,
    ground_truth: Optional[List[str]] = None,
    sol_path: Optional[str] = None,
    manifest: Optional[dict] = None,
    readme_text: Optional[str] = None,
):
    """
    Full pipeline:
      1. Parse Solidity → ContractEntity
      2. Build Zep KG
      3. Generate 22 agent profiles
      4. Run 10-round audit session (Phase A + B + C)
      5. Generate audit report
      6. Save everything to output_dir
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    os.makedirs(output_dir, exist_ok=True)
    graph_name = graph_name or f"{contract_name} Audit"

    logger.info("=" * 60)
    logger.info(f"Contract Audit — {contract_name}")
    logger.info(f"Output: {output_dir}")
    logger.info("=" * 60)

    from app.models.task import TaskManager
    from app.services.contract_kg_builder import ContractKGBuilder
    from app.services.contract_profile_generator import ContractExpertProfileGenerator
    from app.services.cyber_session_orchestrator import CyberSessionOrchestrator
    from app.services.contract_audit_agent import ContractAuditReportAgent
    from app.services.contract_invariant_extractor import ContractInvariantExtractor
    from app.services.contract_intent_extractor import ContractIntentExtractor
    from app.services.contract_dep_graph import ContractDepGraph

    task_manager        = TaskManager()
    kg_builder          = ContractKGBuilder()
    prof_gen            = ContractExpertProfileGenerator()
    orchestrator        = CyberSessionOrchestrator()
    report_agent        = ContractAuditReportAgent()
    # Use boost LLM for heavier pre-processing steps
    invariant_extractor = ContractInvariantExtractor(llm_client=orchestrator.boost_llm)
    intent_extractor    = ContractIntentExtractor(llm_client=orchestrator.boost_llm)
    dep_graph           = ContractDepGraph()

    from datetime import datetime as _dt
    _run_start = _dt.now()

    graph_id = None
    kg_task_id = None
    try:
        # ── Step 1 + 2: Parse + Build KG ──────────────────────────────────────
        # Use in_scope_source for KG if available (from flatten_contest_dir scope classification)
        # so out-of-scope stubs don't pollute function/event indexing.
        kg_source = (manifest or {}).get("in_scope_source") or source_code
        logger.info("\n[STEP 1/4] Parsing Solidity source + building Zep KG...")
        if kg_source is not source_code:
            logger.info(f"  KG: using in-scope-only source ({len(kg_source):,} chars vs {len(source_code):,} full)")
        kg_task_id = kg_builder.build_from_source_async(
            source_code=kg_source,
            graph_name=graph_name,
            contract_name=contract_name,
        )
        kg_result = _poll_task(task_manager, kg_task_id, "KG Build", timeout=1800)

        graph_id        = kg_result["graph_id"]
        contract_id     = kg_result["contract_id"]
        contract_summary = kg_result["context_summary"]

        logger.info(f"  graph_id     : {graph_id}")
        logger.info(f"  contract_id  : {contract_id}")
        logger.info(f"  contract_type: {kg_result.get('contract_type','?')}")
        logger.info(f"  functions    : {kg_result.get('function_count', 0)}")
        logger.info(f"  state_vars   : {kg_result.get('state_var_count', 0)}")
        logger.info(f"  SWC static   : {', '.join(kg_result.get('swc_candidates', [])) or 'none'}")

        _save_json(output_dir, "kg_result.json", kg_result)
        _save_text(output_dir, "contract_summary.txt", contract_summary)

        # ── Step 1.1: Extract protocol intent from NatSpec (S5) ──────────────
        # Runs after KG build so LLM receives KG-enriched contract_summary as context.
        # Note: KG builder may also parse NatSpec — ContractIntentExtractor checks
        # for "PROTOCOL INTENT" in summary before injecting to avoid duplication.
        logger.info("\n[STEP 1.1/4] Extracting protocol intent from NatSpec (S5)...")
        intent_result    = intent_extractor.extract(
            source_code=kg_source,
            context_summary=contract_summary,
            readme=readme_text,
        )
        contract_summary = intent_result["enriched_summary"]
        _save_json(output_dir, "intent.json", {"intent": intent_result["intent_statements"]})
        logger.info(f"  Intent statements: {len(intent_result['intent_statements'])}")

        # ── Step 1.3: Build static data-flow graph via Slither (1b) ──────────
        # Slither requires a file path. Uses sol_path (flat file or contest_dir).
        # Falls back gracefully if Slither not installed or compilation fails.
        logger.info("\n[STEP 1.3/4] Building data-flow dependency graph (Slither / 1b)...")
        slither_target = sol_path  # contest_dir takes priority if provided via --contest-dir
        # Use manifest primary contract name so Slither targets the right .sol file
        # (contest_name is the directory number e.g. "35", not the contract name)
        slither_contract_name = (
            manifest.get("primary", contract_name) if manifest else contract_name
        )
        if slither_target:
            logger.info(f"  Slither target contract: {slither_contract_name}")
            dep_summary = dep_graph.build_and_summarize(
                source_path=slither_target,
                contract_name=slither_contract_name,
            )
            if dep_summary:
                contract_summary += f"\n\n{dep_summary.text}"
                logger.info(
                    f"  Dep graph: {len(dep_summary.critical_vars)} critical vars, "
                    f"primary={dep_summary.primary_contract}"
                )
                _save_json(output_dir, "dep_graph.json", {
                    "primary_contract": dep_summary.primary_contract,
                    "critical_vars":    dep_summary.critical_vars,
                    "top_writers":      dep_summary.top_writers,
                    "top_readers":      dep_summary.top_readers,
                })
            else:
                logger.info("  Dep graph: skipped (Slither not available or compile error)")
        else:
            logger.info("  Dep graph: skipped (no sol_path — sample contract mode)")

        # ── Step 1.5: Extract protocol invariants (additive layer) ────────────
        logger.info("\n[STEP 1.5/4] Extracting protocol invariants...")
        inv_result       = invariant_extractor.extract(
            source_code=source_code,
            context_summary=contract_summary,
        )
        invariants        = inv_result["invariants"]
        contract_summary  = inv_result["enriched_summary"]
        _save_json(output_dir, "invariants.json", {"invariants": invariants})
        logger.info(f"  Invariants extracted: {len(invariants)}")

        # ── Step 3: Generate 22 agent profiles ────────────────────────────────
        logger.info("\n[STEP 2/4] Generating 22 agent profiles...")
        prof_result = prof_gen.generate_all_profiles(
            contract_summary=contract_summary,
            graph_id=graph_id,
        )
        profiles = prof_result["all"]
        logger.info(f"  Tier-1: {len(prof_result['tier1'])} experts | Tier-2: {len(prof_result['tier2'])} attackers")

        _save_json(output_dir, "profiles.json", _profiles_to_dicts(profiles))

        # ── Step 4: Run audit session ──────────────────────────────────────────
        _audit_v = os.environ.get("AUDIT_PIPELINE_VERSION", "v1").lower()
        if _audit_v == "v2":
            # v2: use enriched contract_summary (KG + dep graph + intent + invariants)
            # as base context — same approach as v1 to avoid hallucination from
            # overwhelming agents with 54K chars of raw source.
            # Append full bodies of the most complex functions (by callee count in
            # CALL GRAPH) so agents can cite real code evidence.
            from app.services.contract_dep_graph import (
                extract_function_bodies,
                pick_critical_functions_from_summary,
            )
            _raw_src = locals().get("kg_source") or source_code
            _critical_fns = pick_critical_functions_from_summary(contract_summary, top_n=6)
            _critical_block = extract_function_bodies(_raw_src, _critical_fns) if _critical_fns else ""
            _v2_session_summary = contract_summary + ("\n\n" + _critical_block if _critical_block else "")
            logger.info(
                f"\n[STEP 3/4] Running 3-round v2 audit (Round 1 discovery / 2 voting / 3 attacker)..."
                f"\n  context for agents: {len(_v2_session_summary)} chars "
                f"(enriched summary + {len(_critical_fns)} critical functions)"
            )
        else:
            _v2_session_summary = contract_summary
            logger.info("\n[STEP 3/4] Running 10-round audit session (Phase A → B → C)...")

        task_id = orchestrator.run_session_async(
            graph_id=graph_id,
            network_summary=_v2_session_summary,
            profiles=profiles,
            mode="contract_audit",
            invariants=invariants,
            manifest=manifest,
        )

        task = task_manager.get_task(task_id)
        session_id = task.metadata.get("session_id", task_id) if task else task_id
        logger.info(f"  session_id: {session_id}")

        session_result = _poll_task(task_manager, task_id, "Audit Session", timeout=timeout_session)

        expert_findings   = session_result.get("expert_findings", [])
        attacker_findings = session_result.get("attacker_findings", [])
        semantic_findings = session_result.get("semantic_findings", [])
        v2_confirmed      = session_result.get("v2_confirmed")   # None for v1 runs
        v2_borderline     = session_result.get("v2_borderline", [])
        v2_discarded      = session_result.get("v2_discarded", [])

        _r3_confirmed_threshold = float(os.environ.get("R3_CONFIRMED_THRESHOLD", "0.35"))
        _pv = session_result.get("pipeline_version", "v1")
        if v2_confirmed is not None:
            logger.info(f"  [v2] Confirmed   : {len(v2_confirmed)} (confidence ≥ {_r3_confirmed_threshold})")
            logger.info(f"  [v2] Discarded   : {len(v2_discarded)}")
        else:
            logger.info(f"  Expert findings  : {len(expert_findings)}")
            logger.info(f"  Attacker findings: {len(attacker_findings)}")
            logger.info(f"  Semantic findings: {len(semantic_findings)}")

        _save_json(output_dir, "session_result.json", session_result)

        # ── Step 5: Generate report ────────────────────────────────────────────
        logger.info(f"\n[STEP 4/4] Generating audit report ({_pv})...")
        task_id = report_agent.generate_report_async(
            session_id=session_id,
            expert_findings=expert_findings,
            attacker_findings=attacker_findings,
            contract_summary=contract_summary,
            graph_id=graph_id,
            semantic_findings=semantic_findings,
            invariants=invariants,
            v2_confirmed=v2_confirmed,
            v2_borderline=v2_borderline,
            v2_discarded=v2_discarded,
        )
        report_result = _poll_task(task_manager, task_id, "Report Gen", timeout=1800)

        # ── Step 5b: PoC Enrichment (scenario-driven, post-consensus) ───────────
        _poc_enabled = os.environ.get("POC_ENABLED", "false").lower() in ("1", "true", "yes")
        logger.info(f"\n[STEP 4b/4] PoC Enrichment Stage — {'running' if _poc_enabled else 'SKIPPED (POC_ENABLED=false)'}...")
        try:
            from app.services.poc_verification import PoCVerificationStage, PoCConfig
            poc_stage = PoCVerificationStage(
                llm_client=orchestrator.llm,
                config=PoCConfig(enabled=_poc_enabled),
            )
            # Only confirmed findings go to PoC; discarded have been excluded already
            _consensus_vulns  = report_result.get("consensus_vulns", [])
            _semantic_results = report_result.get("semantic_results", [])
            all_confirmed     = _consensus_vulns + _semantic_results

            enriched = poc_stage.run(
                confirmed_findings=all_confirmed,
                flat_source=source_code,
            )

            # Split back into consensus_vulns / semantic_results by original lengths
            n_c = len(_consensus_vulns)
            report_result["consensus_vulns"]  = enriched[:n_c]
            report_result["semantic_results"] = enriched[n_c:]

            _poc_verified = sum(1 for f in enriched if f.get("poc_verified"))
            logger.info(f"  PoC: {_poc_verified}/{len(enriched)} finding(s) poc_verified=True")
        except Exception as _poc_err:
            logger.warning(f"  PoC stage skipped (non-fatal): {_poc_err}")

        # Inject timing + eval metrics into stats before saving
        _duration = int((_dt.now() - _run_start).total_seconds())
        _stats_update = {
            "started_at": _run_start.isoformat(),
            "duration_seconds": _duration,
        }
        if ground_truth:
            _stats_update.update(_compute_eval_metrics(
                report_result.get("consensus_vulns", []),
                ground_truth,
                unvalidated_gaps=report_result.get("unvalidated_swc_gaps", []),
            ))
        report_result.setdefault("stats", {}).update(_stats_update)

        report_path = os.path.join(output_dir, "audit_report.json")
        _save_json(output_dir, "audit_report.json", report_result)

        # Save human-readable report text
        report_text = report_result.get("report", "")
        _save_text(output_dir, "audit_report.md", report_text)

        # ── Summary ───────────────────────────────────────────────────────────
        stats = report_result.get("stats", {})
        logger.info("\n" + "=" * 60)
        logger.info("AUDIT COMPLETE")
        logger.info("=" * 60)
        logger.info(f"  Critical vulnerabilities : {stats.get('critical', 0)}")
        logger.info(f"  High vulnerabilities     : {stats.get('high', 0)}")
        logger.info(f"  Medium vulnerabilities   : {stats.get('medium', 0)}")
        logger.info(f"  Consensus findings       : {stats.get('consensus_vulns', 0)}")
        logger.info(f"  Exploitable confirmed    : {stats.get('exploitable_count', 0)}")
        logger.info(f"  Unvalidated SWC gaps     : {stats.get('unvalidated_swc_gaps', 0)}")
        logger.info(f"  Duration                 : {_duration//60}m{_duration%60:02d}s")
        if ground_truth:
            em = _stats_update
            logger.info(f"  Ground truth             : {ground_truth}")
            logger.info(f"  TP={em.get('tp')} FP={em.get('fp')} FN={em.get('fn')}  "
                        f"P={em.get('precision'):.2f} R={em.get('recall'):.2f} F1={em.get('f1'):.2f}")
        logger.info(f"\n  Report saved to          : {os.path.join(output_dir, 'audit_report.md')}")
        logger.info(f"  JSON result              : {report_path}")

    finally:
        # ── Cleanup Zep graph regardless of success/failure/timeout ──────────
        _gid = graph_id or (kg_builder._partial_graph_ids.pop(kg_task_id, None) if kg_task_id else None)
        if _gid:
            try:
                from app.services.graph_builder import GraphBuilderService
                GraphBuilderService().delete_graph(_gid)
                logger.info(f"  Zep graph {_gid} deleted (quota cleanup)")
            except Exception as _de:
                logger.warning(f"  Failed to delete Zep graph {_gid}: {_de}")

    return report_result


# ─── File helpers ─────────────────────────────────────────────────────────────

def _save_json(output_dir: str, filename: str, data):
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    logger.debug(f"  Saved: {path}")


def _save_text(output_dir: str, filename: str, text: str):
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    logger.debug(f"  Saved: {path}")


# ─── Ground truth helpers ─────────────────────────────────────────────────────

# SmartBugs category → primary SWC (mirrors evaluate_phase5b.py)
_CATEGORY_TO_SWC = {
    "reentrancy":              "SWC-107",
    "access_control":          "SWC-105",
    "arithmetic":              "SWC-101",
    "denial_of_service":       "SWC-113",
    "front_running":           "SWC-114",
    "bad_randomness":          "SWC-120",
    "time_manipulation":       "SWC-116",
    "short_addresses":         "SWC-104",
    "unchecked_low_level_calls": "SWC-104",
    "other":                   None,
}

def _lookup_ground_truth(sol_path: str) -> List[str]:
    """
    Auto-detect expected SWC IDs from the dataset ground truth.

    Supports two formats (tried in order):
      1. web3bugs bugs.csv: walk up from sol_path looking for results/bugs.csv;
         extract contest_id from the path segment matching a numeric directory
         under "contracts/"; return SWC IDs for L* bugs of that contest.
      2. SmartBugs vulnerabilities.json: walk up looking for vulnerabilities.json
         and match the .sol filename.
    """
    # web3bugs L-label → SWC mapping (mirrors evaluate_web3bugs.py L_TO_SWC)
    _L_TO_SWC = {
        "L1": {"SWC-107"},
        "L2": {"SWC-101"},
        "L3": {"SWC-109"},
        "L4": {"SWC-128"},
        "L5": {"SWC-124"},
        "L6": {"SWC-107", "SWC-131"},
        "L7": {"SWC-101"},
        "L8": {"SWC-104"},
        "L9": {"SWC-109"},
        "LA": {"SWC-121", "SWC-122"},
        "LB": {"SWC-115"},
    }

    sol_abs = Path(sol_path).resolve()

    # ── Strategy 1: web3bugs bugs.csv ─────────────────────────────────────────
    # Detect contest_id from path (look for numeric dir under "contracts/")
    contest_id: Optional[int] = None
    parts = sol_abs.parts
    for i, part in enumerate(parts):
        if part == "contracts" and i + 1 < len(parts) and parts[i + 1].isdigit():
            contest_id = int(parts[i + 1])
            break
    # Also accept a numeric dir anywhere in the path as fallback
    if contest_id is None:
        for part in reversed(parts[:-1]):
            if part.isdigit():
                contest_id = int(part)
                break

    if contest_id is not None:
        # Walk up to find results/bugs.csv (may be sibling of "contracts/" dir)
        check = sol_abs.parent
        for _ in range(8):
            bugs_csv = check / "results" / "bugs.csv"
            if bugs_csv.exists():
                try:
                    swcs: Set[str] = set()
                    with open(bugs_csv, newline="", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            # CSV columns may have leading spaces; extra commas produce None key
                            norm = {
                                k.strip(): (v.strip() if v else "")
                                for k, v in row.items()
                                if k is not None
                            }
                            cid_str = norm.get("Contest ID", "")
                            label   = norm.get("Bug Label",  "")
                            if cid_str.isdigit() and int(cid_str) == contest_id:
                                mapped = _L_TO_SWC.get(label)
                                if mapped:
                                    swcs.update(mapped)
                    if swcs:
                        return sorted(swcs)
                except Exception:
                    pass
                break
            if check.parent == check:
                break
            check = check.parent

    # ── Strategy 2: SmartBugs vulnerabilities.json ────────────────────────────
    check_dir = str(sol_abs.parent)
    for _ in range(5):
        candidate = os.path.join(check_dir, "vulnerabilities.json")
        if os.path.exists(candidate):
            break
        check_dir = os.path.dirname(check_dir)
    else:
        return []
    try:
        with open(candidate, encoding="utf-8") as f:
            db = json.load(f)
    except Exception:
        return []
    sol_name = sol_abs.name
    for entry in db:
        if entry.get("name") == sol_name or entry.get("name") == sol_name.replace(".sol", ""):
            swcs_s: Set[str] = set()
            for v in entry.get("vulnerabilities", []):
                cat = v.get("category", "")
                swc = _CATEGORY_TO_SWC.get(cat)
                if swc:
                    swcs_s.add(swc)
            return sorted(swcs_s)
    return []


def _compute_eval_metrics(
    consensus_vulns: list,
    ground_truth: List[str],
    unvalidated_gaps: Optional[list] = None,
) -> dict:
    """Compute TP/FP/FN/Precision/Recall/F1 vs ground truth SWC list."""
    if not ground_truth:
        return {}
    detected: Set[str] = set()
    for v in consensus_vulns:
        for swc in v.get("swc_ids", []):
            detected.add(swc)
    for gap in (unvalidated_gaps or []):
        swc = gap.get("swc_id", "")
        if swc:
            detected.add(swc)
    expected = set(ground_truth)
    tp = len(detected & expected)
    fp = len(detected - expected)
    fn = len(expected - detected)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "ground_truth":  sorted(expected),
        "detected_swcs": sorted(detected),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
    }


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Run end-to-end smart contract audit (parse → KG → session → report)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--sol", metavar="FILE",
        help="Path to Solidity .sol file",
    )
    source_group.add_argument(
        "--sample", choices=list(SAMPLE_CONTRACTS.keys()),
        help="Use a built-in sample contract",
    )
    source_group.add_argument(
        "--contest-dir", metavar="DIR",
        help="Path to Web3Bugs contest directory — auto-flattens + computes ContractManifest",
    )

    parser.add_argument(
        "--output", "-o", default="./audit_output",
        help="Output directory (default: ./audit_output)",
    )
    parser.add_argument(
        "--graph-name", default=None,
        help="Custom graph name for Zep KG (default: '<contract> Audit')",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose debug logging",
    )
    parser.add_argument(
        "--timeout", type=int, default=21600,
        help="Session timeout in seconds (default: 21600)",
    )
    parser.add_argument(
        "--ground-truth", metavar="SWC[,SWC...]", default=None,
        help="Comma-separated expected SWC IDs for eval metrics (e.g. SWC-107,SWC-101). "
             "Auto-detected from SmartBugs vulnerabilities.json if omitted.",
    )

    args = parser.parse_args()

    # ── Load source ──────────────────────────────────────────────────────────
    sol_path    = None
    manifest    = None
    readme_text = None

    if args.contest_dir:
        import sys as _sys
        _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from flatten_contest import flatten_contest_dir
        contest_dir = os.path.abspath(args.contest_dir)
        if not os.path.isdir(contest_dir):
            logger.error(f"Contest dir không tồn tại: {contest_dir}")
            sys.exit(1)
        logger.info(f"Flattening contest dir: {contest_dir}")
        source_code, manifest = flatten_contest_dir(contest_dir, verbose=True, emit_manifest=True)
        contract_name = Path(contest_dir).name
        sol_path      = contest_dir  # pass dir as Slither target
        if not source_code.strip():
            logger.error("Flatten produced empty source — check contest directory")
            sys.exit(1)
        logger.info(f"  Manifest: primary={manifest.get('primary')}, secondary={manifest.get('secondary')}")
    elif args.sol:
        sol_path = os.path.abspath(args.sol)
        if not os.path.exists(sol_path):
            logger.error(f"File không tồn tại: {sol_path}")
            sys.exit(1)
        with open(sol_path, "r", encoding="utf-8") as f:
            source_code = f.read()
        contract_name = os.path.splitext(os.path.basename(sol_path))[0]
    else:
        sol_path = None
        sample = SAMPLE_CONTRACTS[args.sample]
        source_code   = sample["source"]
        contract_name = args.sample
        logger.info(f"Using sample contract: {sample['name']}")
        logger.info(f"Description: {sample['description']}")

    # ── Load README (for S5 intent extraction) ──────────────────────────────
    search_dir = args.contest_dir or (os.path.dirname(sol_path) if sol_path and os.path.isfile(sol_path) else None)
    if search_dir:
        for _rname in ["README.md", "readme.md", "README.txt"]:
            _rpath = os.path.join(search_dir, _rname)
            if os.path.exists(_rpath):
                try:
                    with open(_rpath, "r", encoding="utf-8", errors="replace") as _rf:
                        readme_text = _rf.read()[:5000]
                    logger.info(f"  README found: {_rname} ({len(readme_text)} chars)")
                except Exception:
                    pass
                break

    # ── Timestamped output dir ────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(args.output, f"{contract_name}_{ts}")

    # ── Resolve ground truth ─────────────────────────────────────────────────
    if args.ground_truth:
        ground_truth = [s.strip().upper() for s in args.ground_truth.split(",") if s.strip()]
    elif sol_path and os.path.isfile(sol_path):
        ground_truth = _lookup_ground_truth(sol_path)
        if ground_truth:
            logger.info(f"Auto-detected ground truth from SmartBugs: {ground_truth}")
    else:
        ground_truth = []

    # ── Run ──────────────────────────────────────────────────────────────────
    run_audit(
        source_code=source_code,
        contract_name=contract_name,
        output_dir=output_dir,
        graph_name=args.graph_name,
        verbose=args.verbose,
        timeout_session=args.timeout,
        ground_truth=ground_truth or None,
        sol_path=sol_path,
        manifest=manifest,
        readme_text=readme_text,
    )


if __name__ == "__main__":
    main()
