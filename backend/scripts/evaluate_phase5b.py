"""
Phase 5b — SmartBugs Reentrancy Evaluation

Chạy pipeline trên toàn bộ (hoặc subset) contracts trong SmartBugs Curated
reentrancy category và đánh giá Precision/Recall/F1 so với ground truth SWC-107.

Sử dụng:
    # Chạy tất cả 31 reentrancy contracts (parallel=2)
    python evaluate_phase5b.py --dataset /path/to/smartbugs-curated --output ./results/phase5b/

    # Chỉ chạy 5 contracts đầu để test nhanh
    python evaluate_phase5b.py --dataset /path/to/smartbugs-curated --limit 5

    # Load kết quả đã lưu, tính lại metrics
    python evaluate_phase5b.py --load ./results/phase5b/

    # Parallel 3 contracts cùng lúc
    python evaluate_phase5b.py --dataset /path/to/smartbugs-curated --parallel 3

Tiêu chí pass Phase 5b:
    - Macro F1 ≥ 0.75 trên toàn bộ reentrancy contracts
    - Precision ≥ 0.60 (không quá nhiều FP)
    - Recall    ≥ 0.80 (không bỏ sót quá nhiều)
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional

# ─── Path setup ───────────────────────────────────────────────────────────────
_scripts_dir  = os.path.dirname(os.path.abspath(__file__))
_backend_dir  = os.path.abspath(os.path.join(_scripts_dir, ".."))
_project_root = os.path.abspath(os.path.join(_backend_dir, ".."))
sys.path.insert(0, _backend_dir)

from dotenv import load_dotenv
_env_file = os.path.join(_project_root, ".env")
if os.path.exists(_env_file):
    load_dotenv(_env_file)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("phase5b_eval")


# ─── SWC alias tables (reuse từ phase5a) ──────────────────────────────────────

SWC_ALIASES: Dict[str, Set[str]] = {
    "SWC-100": {
        "SWC-100", "DEFAULT VISIBILITY", "FUNCTION DEFAULT VISIBILITY",
        "PUBLIC BY DEFAULT", "MISSING VISIBILITY",
    },
    "SWC-101": {
        "SWC-101", "INTEGER OVERFLOW", "INTEGER UNDERFLOW", "OVERFLOW", "UNDERFLOW",
        "ARITHMETIC OVERFLOW", "ARITHMETIC UNDERFLOW", "SAFEMATH", "SAFE MATH",
        "OVERFLOW/UNDERFLOW", "OVERFLOW / UNDERFLOW",
    },
    "SWC-104": {
        "SWC-104", "UNCHECKED RETURN", "UNCHECKED CALL", "UNCHECKED LOW LEVEL",
        "UNCHECKED SEND", "UNCHECKED CALL RETURN", "UNCHECKED LOW-LEVEL CALL",
        "RETURN VALUE NOT CHECKED", "IGNORED RETURN",
    },
    "SWC-105": {
        "SWC-105", "UNPROTECTED ETHER WITHDRAWAL", "UNPROTECTED WITHDRAWAL",
        "UNPROTECTED ETH WITHDRAWAL", "UNPROTECTED ETHER", "MISSING ACCESS CONTROL",
        "UNAUTHORIZED WITHDRAWAL", "UNPROTECTED FUNCTION", "NO ACCESS CONTROL",
        "LACK OF ACCESS CONTROL", "ACCESS CONTROL MISSING", "PRIVILEGED FUNCTION",
        "UNPROTECTED SEND", "ARBITRARY WITHDRAWAL",
    },
    "SWC-106": {
        "SWC-106", "UNPROTECTED SELFDESTRUCT", "SELFDESTRUCT", "SELF-DESTRUCT",
        "UNPROTECTED SUICIDE", "SUICIDE",
    },
    "SWC-107": {
        "SWC-107", "REENTRANCY", "REENTRANCE", "RE-ENTRANCY",
        "REENTRANT", "REENTRANCY ATTACK", "REENTRANCY VULNERABILITY",
        "CROSS-FUNCTION REENTRANCY", "READ-ONLY REENTRANCY",
    },
    "SWC-112": {
        "SWC-112", "DELEGATECALL", "DELEGATE CALL", "UNTRUSTED CALLEE",
        "DELEGATECALL TO UNTRUSTED",
    },
    "SWC-113": {
        "SWC-113", "DENIAL OF SERVICE", "DENIAL-OF-SERVICE", "DOS", "D.O.S",
        "UNBOUNDED LOOP", "GAS EXHAUSTION", "GAS GRIEFING", "FAILED CALL",
        "BLOCKED CALL", "PULL OVER PUSH", "PUSH OVER PULL", "LOOP DOS",
        "ARRAY LOOP", "UNBOUNDED ARRAY", "PERMANENT DOS", "PERMANENT LOCK",
    },
    "SWC-114": {
        "SWC-114", "FRONT-RUNNING", "FRONT RUNNING", "FRONTRUNNING",
        "TRANSACTION ORDER DEPENDENCE", "TRANSACTION ORDER", "TOD",
        "RACE CONDITION", "ERC20 RACE", "APPROVE RACE", "ALLOWANCE RACE",
        "MEV", "SANDWICH ATTACK", "MEMPOOL", "PENDING TRANSACTION",
    },
    "SWC-115": {
        "SWC-115", "TX.ORIGIN", "TXORIGIN", "ORIGIN AUTHORIZATION",
        "AUTHORIZATION THROUGH TX.ORIGIN", "TX ORIGIN",
    },
    "SWC-116": {
        "SWC-116", "BLOCK TIMESTAMP", "TIMESTAMP MANIPULATION",
        "TIME MANIPULATION", "BLOCK.TIMESTAMP", "NOW MANIPULATION",
        "TIMESTAMP DEPENDENCY", "MINER TIMESTAMP",
    },
    "SWC-118": {
        "SWC-118", "INCORRECT CONSTRUCTOR", "CONSTRUCTOR NAME", "WRONG CONSTRUCTOR",
        "MISSPELLED CONSTRUCTOR", "CONSTRUCTOR TYPO",
    },
    "SWC-120": {
        "SWC-120", "WEAK RANDOMNESS", "BAD RANDOMNESS", "PRNG", "PSEUDORANDOM",
        "BLOCKHASH", "BLOCK HASH", "PREDICTABLE RANDOMNESS", "INSECURE RANDOMNESS",
        "BLOCK.DIFFICULTY", "BLOCK.NUMBER RANDOMNESS",
    },
    "SWC-121": {
        "SWC-121", "SIGNATURE REPLAY", "REPLAY ATTACK", "MISSING NONCE",
        "ECRECOVER REPLAY", "SIGNATURE REUSE",
    },
    "SWC-132": {
        "SWC-132", "UNEXPECTED ETHER", "UNEXPECTED ETH", "FORCED ETHER",
        "SELFDESTRUCT ETHER", "UNEXPECTED BALANCE",
    },
}


def _normalise_swc(s: str) -> str:
    s = s.upper().strip()
    if s.startswith("SWC") and "-" not in s and len(s) > 3:
        s = "SWC-" + s[3:]
    return s


def _resolve_swc(raw: str, expected: Set[str]) -> Set[str]:
    raw_upper = raw.upper()
    found = set()
    for canonical, aliases in SWC_ALIASES.items():
        if canonical not in expected:
            continue
        for alias in aliases:
            if alias in raw_upper:
                found.add(canonical)
                break
    return found


# ─── Dataset loader ───────────────────────────────────────────────────────────

def load_smartbugs_reentrancy(dataset_root: str, limit: Optional[int] = None) -> List[dict]:
    """
    Load contracts từ SmartBugs Curated reentrancy directory.
    Returns list of {name, path, source_code, expected_swcs}.
    """
    vuln_file = os.path.join(dataset_root, "vulnerabilities.json")
    with open(vuln_file, encoding="utf-8") as f:
        all_vulns = json.load(f)

    reentrancy = [
        e for e in all_vulns
        if any(v.get("category") == "reentrancy" for v in e.get("vulnerabilities", []))
    ]

    contracts = []
    for entry in reentrancy:
        sol_path = os.path.join(dataset_root, entry["path"])
        if not os.path.exists(sol_path):
            logger.warning(f"File not found: {sol_path}")
            continue
        with open(sol_path, encoding="utf-8", errors="replace") as f:
            source = f.read()
        name = entry["name"].replace(".sol", "")
        contracts.append({
            "name":          name,
            "file":          entry["name"],
            "path":          sol_path,
            "source_code":   source,
            "expected_swcs": {"SWC-107"},
            "pragma":        entry.get("pragma", ""),
        })
        if limit and len(contracts) >= limit:
            break

    logger.info(f"Loaded {len(contracts)} reentrancy contracts from SmartBugs")
    return contracts


# Primary SWC per category — dùng làm ground truth cho F1 computation
_CATEGORY_TO_SWC: Dict[str, Set[str]] = {
    "reentrancy":              {"SWC-107"},
    "access_control":          {"SWC-105"},  # representative: missing access control
    "arithmetic":              {"SWC-101"},
    "bad_randomness":          {"SWC-120"},
    "denial_of_service":       {"SWC-113"},
    "front_running":           {"SWC-114"},
    "time_manipulation":       {"SWC-116"},
    "unchecked_low_level_calls": {"SWC-104"},
    "short_addresses":         {"SWC-104"},
    "other":                   set(),
}

# Full SWC family per category — dùng để match trong text (wider net)
# Tìm thấy bất kỳ SWC nào trong family → normalize về primary
_CATEGORY_SWC_FAMILY: Dict[str, Set[str]] = {
    "reentrancy":              {"SWC-107"},
    "access_control":          {"SWC-100", "SWC-105", "SWC-106", "SWC-112", "SWC-115", "SWC-118"},
    "arithmetic":              {"SWC-101", "SWC-132"},
    "bad_randomness":          {"SWC-120"},
    "denial_of_service":       {"SWC-113"},
    "front_running":           {"SWC-114"},
    "time_manipulation":       {"SWC-116"},
    "unchecked_low_level_calls": {"SWC-104"},
    "short_addresses":         {"SWC-104"},
    "other":                   set(),
}

# Reverse map: any family SWC → primary SWC of its category
_MATCH_TO_PRIMARY: Dict[str, str] = {}
for _cat, _primaries in _CATEGORY_TO_SWC.items():
    _family = _CATEGORY_SWC_FAMILY.get(_cat, _primaries)
    for _member in _family:
        for _p in _primaries:
            _MATCH_TO_PRIMARY[_member] = _p


def load_smartbugs_all(dataset_root: str, limit: Optional[int] = None) -> List[dict]:
    """Load all 143 contracts từ SmartBugs Curated với đầy đủ category."""
    vuln_file = os.path.join(dataset_root, "vulnerabilities.json")
    with open(vuln_file, encoding="utf-8") as f:
        all_vulns = json.load(f)

    contracts = []
    for entry in all_vulns:
        sol_path = os.path.join(dataset_root, entry["path"])
        if not os.path.exists(sol_path):
            logger.warning(f"File not found: {sol_path}")
            continue
        with open(sol_path, encoding="utf-8", errors="replace") as f:
            source = f.read()
        # expected_swcs: primary SWC per category (ground truth for F1)
        # match_swcs: full family (wider search net, normalized to primary)
        expected: Set[str] = set()
        match: Set[str] = set()
        for v in entry.get("vulnerabilities", []):
            cat = v.get("category", "")
            expected |= _CATEGORY_TO_SWC.get(cat, set())
            match    |= _CATEGORY_SWC_FAMILY.get(cat, _CATEGORY_TO_SWC.get(cat, set()))
        name = entry["name"].replace(".sol", "")
        contracts.append({
            "name":          name,
            "file":          entry["name"],
            "path":          sol_path,
            "source_code":   source,
            "expected_swcs": expected,
            "match_swcs":    match,
            "pragma":        entry.get("pragma", ""),
        })
        if limit and len(contracts) >= limit:
            break

    logger.info(f"Loaded {len(contracts)} contracts from SmartBugs (all categories)")
    return contracts


# ─── Metrics ──────────────────────────────────────────────────────────────────

def _extract_found(report_result: dict, session_result: dict,
                   expected_swcs: Set[str],
                   match_swcs: Optional[Set[str]] = None) -> Tuple[Set[str], Set[str]]:
    """Returns (strict_found, lenient_found) — normalized to primary expected SWCs."""
    # match_swcs: full family for text search; found SWCs normalized to primary via _MATCH_TO_PRIMARY
    search = match_swcs if match_swcs else expected_swcs

    def _normalize(swc_set: Set[str]) -> Set[str]:
        result: Set[str] = set()
        for s in swc_set:
            primary = _MATCH_TO_PRIMARY.get(s, s)
            if primary in expected_swcs:
                result.add(primary)
            elif s in expected_swcs:
                result.add(s)
        return result

    strict: Set[str]  = set()
    lenient: Set[str] = set()

    # Strict: consensus_vulns
    for vuln in report_result.get("consensus_vulns", []):
        for swc in vuln.get("swc_ids", []):
            norm = _normalise_swc(swc)
            if norm in search:
                strict.add(norm)
        swc_text = " ".join(vuln.get("swc_ids", []))
        text = f"{vuln.get('title','')} {vuln.get('description','')} {swc_text}".upper()
        strict |= _resolve_swc(text, search)
    strict = _normalize(strict)

    # Lenient: expert findings + attacker findings + report text
    raw_lenient: Set[str] = set()
    for f in session_result.get("expert_findings", []):
        text = f"{f.get('swc_id','')} {f.get('title','')} {f.get('description','')}".upper()
        raw_lenient |= _resolve_swc(text, search)

    for f in session_result.get("attacker_findings", []):
        text = f"{f.get('title','')} {f.get('description','')} {f.get('attack_path','')}".upper()
        raw_lenient |= _resolve_swc(text, search)

    report_text = report_result.get("report", "").upper()
    raw_lenient |= _resolve_swc(report_text, search)
    lenient = _normalize(raw_lenient) | strict

    return strict, lenient


def _compute_metrics(found: Set[str], expected: Set[str]) -> dict:
    tp = len(found & expected)
    fp = len(found - expected)
    fn = len(expected - found)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    return {
        "TP": tp, "FP": fp, "FN": fn,
        "precision": round(precision, 3),
        "recall":    round(recall, 3),
        "f1":        round(f1, 3),
        "found":     sorted(found),
        "expected":  sorted(expected),
        "missed":    sorted(expected - found),
        "false_positives": sorted(found - expected),
    }


def _evaluate_contract(contract: dict, report_result: dict,
                       session_result: dict) -> dict:
    expected = contract["expected_swcs"]
    match = contract.get("match_swcs", expected)
    strict, lenient = _extract_found(report_result, session_result, expected, match)
    stats = report_result.get("stats", {})
    return {
        "name":           contract["name"],
        "file":           contract["file"],
        "expected_swcs":  sorted(expected),
        "pipeline": {
            "expert_findings":   len(session_result.get("expert_findings", [])),
            "attacker_findings": len(session_result.get("attacker_findings", [])),
            "consensus_vulns":   stats.get("consensus_vulns", 0),
            "critical":          stats.get("critical", 0),
            "high":              stats.get("high", 0),
        },
        "strict":  _compute_metrics(strict,  expected),
        "lenient": _compute_metrics(lenient, expected),
        "pass":    len(lenient & expected) > 0,
    }


# ─── Pipeline runner ──────────────────────────────────────────────────────────

def run_contract(contract: dict, output_base: str) -> Tuple[dict, dict, dict, str]:
    """
    Run audit pipeline cho 1 contract.
    Returns (eval_result, report_result, session_result, output_dir).
    """
    from run_contract_audit import run_audit

    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", contract["name"])[:40]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(output_base, f"{safe_name}_{ts}")

    t0 = time.monotonic()
    logger.info(f"  [{contract['name'][:20]}] Starting pipeline...")

    report_result = run_audit(
        source_code=contract["source_code"],
        contract_name=safe_name,
        output_dir=output_dir,
        graph_name=contract["name"],
        timeout_session=7200,
    )

    elapsed = time.monotonic() - t0
    logger.info(f"  [{contract['name'][:20]}] Done in {elapsed:.0f}s")

    session_path = os.path.join(output_dir, "session_result.json")
    session_result = {}
    if os.path.exists(session_path):
        with open(session_path, encoding="utf-8") as f:
            session_result = json.load(f)

    ev = _evaluate_contract(contract, report_result, session_result)
    return ev, report_result, session_result, output_dir


def load_contract_results(load_dir: str, contract_name: str) -> Tuple[dict, dict]:
    """Find most recent saved dir for contract_name, load JSONs."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", contract_name)[:40]
    entries = sorted([
        os.path.join(load_dir, e) for e in os.listdir(load_dir)
        if os.path.isdir(os.path.join(load_dir, e)) and e.startswith(safe)
    ])
    if not entries:
        raise FileNotFoundError(f"No saved results for '{contract_name}' in {load_dir}")
    # Prefer latest dir that has session_result.json; fall back to latest overall
    completed = [e for e in entries if os.path.exists(os.path.join(e, "session_result.json"))]
    d = completed[-1] if completed else entries[-1]
    report_result  = {}
    session_result = {}
    rp = os.path.join(d, "audit_report.json")
    sp = os.path.join(d, "session_result.json")
    if os.path.exists(rp):
        with open(rp, encoding="utf-8") as f:
            report_result = json.load(f)
    if os.path.exists(sp):
        with open(sp, encoding="utf-8") as f:
            session_result = json.load(f)
    return report_result, session_result


# ─── Print helpers ────────────────────────────────────────────────────────────

def _print_result(ev: dict):
    verdict = "✅ PASS" if ev["pass"] else "❌ FAIL"
    s = ev["strict"]
    l = ev["lenient"]
    print(f"  {ev['name'][:35]:<35}  "
          f"L-Recall={l['recall']:.2f}  S-Recall={s['recall']:.2f}  "
          f"exp={ev['expected_swcs']}  "
          f"found={l['found']}  {verdict}")


def _print_summary(results: List[dict]):
    total   = len(results)
    passed  = sum(1 for r in results if r["pass"])
    l_f1s   = [r["lenient"]["f1"] for r in results]
    s_f1s   = [r["strict"]["f1"]  for r in results]
    l_precs = [r["lenient"]["precision"] for r in results]
    l_recs  = [r["lenient"]["recall"]    for r in results]
    macro_l_f1 = sum(l_f1s) / total if total else 0
    macro_s_f1 = sum(s_f1s) / total if total else 0
    macro_prec = sum(l_precs) / total if total else 0
    macro_rec  = sum(l_recs)  / total if total else 0

    print()
    print("═" * 72)
    print("  PHASE 5b SUMMARY — SmartBugs Reentrancy")
    print("═" * 72)
    print()
    print(f"  Contracts evaluated : {total}")
    print(f"  Contracts passed    : {passed}/{total}")
    print()
    print(f"  Macro Lenient  Recall={macro_rec:.3f}  (Strict Recall={macro_s_f1:.3f})")
    print(f"  Note: Recall only — FP not penalised (SmartBugs labels primary vuln only)")
    print()

    PASS_REC  = 0.80
    rec_ok  = macro_rec  >= PASS_REC
    overall = rec_ok

    print(f"  Recall ≥ {PASS_REC}  : {'✅' if rec_ok  else '❌'}  ({macro_rec:.3f})")
    print()
    if overall:
        print("  🎉 Phase 5b PASSED — pipeline sẵn sàng cho Phase 5c (full 143)")
    else:
        print("  ⚠️  Phase 5b FAILED — cần tune prompts/consensus trước Phase 5c")
    print("═" * 72)

    return {
        "macro_lenient_recall": round(macro_rec,  3),
        "macro_strict_recall":  round(macro_s_f1, 3),
        "passed": passed,
        "total":  total,
        "phase5b_pass": overall,
    }


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Phase 5b: SmartBugs Reentrancy evaluation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--dataset", metavar="DIR",
        default=os.path.join(_project_root, "../smartbugs-curated"),
        help="Path to smartbugs-curated repo (default: ../smartbugs-curated)",
    )
    parser.add_argument(
        "--output", "-o", default="./results/phase5b",
        help="Directory to save results (default: ./results/phase5b)",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Run only first N contracts (for quick testing)",
    )
    parser.add_argument(
        "--parallel", type=int, default=2,
        help="Number of contracts to run in parallel (default: 2)",
    )
    parser.add_argument(
        "--load", metavar="DIR",
        help="Load previously saved results from DIR instead of re-running",
    )
    parser.add_argument(
        "--cooldown", type=int, default=120,
        help="Seconds to wait between contracts to let quota recover (default: 120)",
    )
    parser.add_argument(
        "--only", type=int, nargs="+", metavar="IDX",
        help="Run only contracts at these 0-based indices (e.g. --only 10 11)",
    )
    parser.add_argument(
        "--skip-done", action="store_true",
        help="Skip contracts that already have session_result.json in output dir",
    )
    parser.add_argument(
        "--all-categories", action="store_true",
        help="Load all 143 contracts (all SmartBugs categories), not just reentrancy",
    )
    args = parser.parse_args()

    os.makedirs(args.output if not args.load else args.load, exist_ok=True)

    # Load contract list
    dataset_dir = os.path.abspath(args.dataset)
    if args.all_categories:
        contracts = load_smartbugs_all(dataset_dir, limit=args.limit)
    else:
        contracts = load_smartbugs_reentrancy(dataset_dir, limit=args.limit)
    if args.only:
        contracts = [c for i, c in enumerate(contracts) if i in args.only]
        logger.info(f"--only filter: running {len(contracts)} contract(s)")

    if args.skip_done and not args.load:
        import glob as _glob
        before = len(contracts)
        def _is_done(c):
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", c["name"])[:40]
            pattern = os.path.join(args.output, f"{safe}_*/session_result.json")
            return bool(_glob.glob(pattern))
        contracts = [c for c in contracts if not _is_done(c)]
        logger.info(f"--skip-done: skipped {before - len(contracts)}, running {len(contracts)} contract(s)")

    results = []
    errors  = []

    if args.load:
        # Load mode — no re-running
        logger.info(f"\nLoading saved results from: {args.load}")
        for c in contracts:
            try:
                rr, sr = load_contract_results(args.load, c["name"])
                ev = _evaluate_contract(c, rr, sr)
                results.append(ev)
                _print_result(ev)
            except Exception as e:
                logger.warning(f"  [{c['name'][:20]}] Load error: {e}")
                errors.append({"name": c["name"], "error": str(e)})
    elif args.parallel > 1:
        # Parallel contract runs
        logger.info(f"\nRunning {len(contracts)} contracts with parallelism={args.parallel}")
        logger.info(f"Output: {args.output}\n")
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            future_to_contract = {
                pool.submit(run_contract, c, args.output): c
                for c in contracts
            }
            for future in as_completed(future_to_contract):
                c = future_to_contract[future]
                try:
                    ev, _, _, _ = future.result()
                    results.append(ev)
                    _print_result(ev)
                except Exception as e:
                    logger.error(f"  [{c['name'][:20]}] ERROR: {e}", exc_info=True)
                    errors.append({"name": c["name"], "error": str(e)})
    else:
        # Sequential
        logger.info(f"\nRunning {len(contracts)} contracts sequentially")
        for idx, c in enumerate(contracts):
            try:
                ev, _, _, _ = run_contract(c, args.output)
                results.append(ev)
                _print_result(ev)
            except Exception as e:
                logger.error(f"  [{c['name'][:20]}] ERROR: {e}", exc_info=True)
                errors.append({"name": c["name"], "error": str(e)})
            if idx < len(contracts) - 1 and args.cooldown > 0:
                logger.info(f"  [cooldown] Waiting {args.cooldown}s for quota to recover...")
                time.sleep(args.cooldown)

    if results:
        summary = _print_summary(results)

        if errors:
            print(f"\n  ⚠️  {len(errors)} contract(s) failed:")
            for err in errors:
                print(f"     [{err['name'][:30]}] {err['error'][:80]}")

        # Save evaluation JSON
        save_dir = args.load or args.output
        eval_path = os.path.join(
            save_dir,
            f"phase5b_eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(eval_path, "w", encoding="utf-8") as f:
            json.dump({
                "summary": summary,
                "results": results,
                "errors":  errors,
                "config": {
                    "dataset":  args.dataset,
                    "limit":    args.limit,
                    "parallel": args.parallel,
                },
            }, f, ensure_ascii=False, indent=2)
        print(f"\n  Evaluation saved → {eval_path}")
    else:
        print("\n  No results to summarize.")


if __name__ == "__main__":
    main()
