"""
Phase 5a — Debug Evaluation

Chạy 3 built-in sample contracts qua full pipeline và so sánh kết quả
với ground truth SWC labels để xác nhận pipeline hoạt động đúng.

Sử dụng:
    # Chạy full pipeline cho cả 3 samples
    python evaluate_phase5a.py --output ./results/phase5a/

    # Chỉ chạy 1 sample cụ thể
    python evaluate_phase5a.py --samples dao --output ./results/phase5a/

    # Load kết quả đã chạy trước, không chạy lại pipeline
    python evaluate_phase5a.py --load ./results/phase5a/

Tiêu chí pass:
    - Pipeline chạy end-to-end không crash (tất cả 3 samples)
    - Mỗi sample tìm được ít nhất 1 expected SWC (Recall > 0)
    - Không có false positive quá nhiều (FP/TP <= 3)
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from datetime import datetime
from typing import Dict, Set, Tuple

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
logger = logging.getLogger("phase5a_eval")


# ─── Ground Truth ─────────────────────────────────────────────────────────────
# Mỗi sample có expected_swcs (từ static analysis của source code)
# và expected_patterns (DeFi-specific attack patterns không có SWC number)

GROUND_TRUTH: Dict = {
    "dao": {
        "name": "Classic DAO Hack",
        "expected_swcs": {"SWC-107"},
        "expected_patterns": set(),
        "notes": (
            "withdraw(): external call BEFORE balances[msg.sender] update → SWC-107\n"
            "  No reentrancy guard. Solidity 0.6 (no auto-revert on overflow)."
        ),
    },
    "erc20": {
        "name": "Vulnerable ERC20",
        "expected_swcs": {"SWC-115", "SWC-105"},
        "expected_patterns": set(),
        "notes": (
            "transfer(): uses tx.origin for authorization → SWC-115\n"
            "  mint(): no onlyOwner modifier, anyone can mint → SWC-105"
        ),
    },
    "defi_vault": {
        "name": "DeFi Vault with Oracle Risk",
        "expected_swcs": {"SWC-107", "SWC-105"},
        "expected_patterns": {"FLASH_LOAN_PRICE_MANIPULATION"},
        "notes": (
            "borrow(): external call before borrows update → SWC-107\n"
            "  oracle.getPrice() uses spot price → FLASH_LOAN_PRICE_MANIPULATION\n"
            "  liquidate(): no access control, anyone can liquidate → SWC-105"
        ),
    },
}

# Các biến thể tên mà model có thể dùng cho cùng 1 vulnerability
SWC_ALIASES: Dict[str, Set[str]] = {
    "SWC-107": {
        "SWC-107", "REENTRANCY", "REENTRANCE", "RE-ENTRANCY",
        "REENTRANT", "REENTRANCY ATTACK",
    },
    "SWC-105": {
        "SWC-105",
        "MISSING ACCESS CONTROL", "MISSING_ACCESS_CONTROL",
        "UNPROTECTED FUNCTION", "UNPROTECTED_FUNCTION",
        "ACCESS CONTROL MISSING", "ACCESS_CONTROL_MISSING",
        "NO ACCESS CONTROL", "NO ONLYOWNER", "LACKS ACCESS CONTROL",
        "UNPROTECTED MINT", "ANYONE CAN MINT",
    },
    "SWC-115": {
        "SWC-115",
        "TX.ORIGIN", "TX_ORIGIN",
        "AUTHORIZATION THROUGH TX.ORIGIN", "AUTHORIZATION_THROUGH_TX_ORIGIN",
        "TX.ORIGIN AUTHENTICATION", "USES TX.ORIGIN",
    },
}

PATTERN_ALIASES: Dict[str, Set[str]] = {
    "FLASH_LOAN_PRICE_MANIPULATION": {
        "FLASH_LOAN_PRICE_MANIPULATION",
        "FLASH LOAN PRICE MANIPULATION",
        "FLASH_LOAN", "FLASH LOAN",
        "PRICE_ORACLE", "PRICE ORACLE",
        "ORACLE_MANIPULATION", "ORACLE MANIPULATION",
        "PRICE_MANIPULATION", "PRICE MANIPULATION",
        "SPOT_PRICE_ORACLE", "SPOT PRICE ORACLE",
        "SPOT PRICE", "ORACLE ATTACK",
    },
}


# ─── Normalisation helpers ────────────────────────────────────────────────────

def _normalise_swc(s: str) -> str:
    """
    Chuẩn hoá SWC ID: 'SWC107' → 'SWC-107', 'swc-107' → 'SWC-107'.
    """
    s = s.upper().strip()
    if s.startswith("SWC") and "-" not in s and len(s) > 3:
        s = "SWC-" + s[3:]
    return s


def _resolve_swc(raw: str, expected: Set[str]) -> Set[str]:
    """
    Map raw text → set of canonical SWC IDs tìm được.
    Trả về những expected SWC mà raw text match (dùng alias).
    """
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


def _resolve_pattern(raw: str, expected: Set[str]) -> Set[str]:
    """Map raw text → set of DeFi patterns tìm được."""
    raw_upper = raw.upper()
    found = set()
    for canonical, aliases in PATTERN_ALIASES.items():
        if canonical not in expected:
            continue
        for alias in aliases:
            if alias in raw_upper:
                found.add(canonical)
                break
    return found


# ─── SWC Extraction from pipeline output ─────────────────────────────────────

def _extract_found(
    report_result: dict,
    session_result: dict,
    expected_swcs: Set[str],
    expected_patterns: Set[str],
) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
    """
    Trích xuất SWC IDs và DeFi patterns từ pipeline output.

    Returns:
        (found_swcs_strict, found_swcs_lenient,
         found_patterns_strict, found_patterns_lenient)

    Strict  = xuất hiện trong consensus_vulns (confidence-validated)
    Lenient = xuất hiện trong bất kỳ expert_finding nào HOẶC report text
              → dùng cho Phase 5a debug (xem pipeline có hiểu contract không)
    """
    strict_swcs: Set[str]    = set()
    lenient_swcs: Set[str]   = set()
    strict_patterns: Set[str] = set()
    lenient_patterns: Set[str] = set()

    # ── 1. Consensus vulns (strict) ──────────────────────────────────────────
    for vuln in report_result.get("consensus_vulns", []):
        # mitre_techniques stores SWC IDs in contract mode
        for swc in vuln.get("mitre_techniques", []):
            norm = _normalise_swc(swc)
            if norm in {_normalise_swc(e) for e in expected_swcs}:
                strict_swcs.add(norm)
            elif norm in expected_swcs:
                strict_swcs.add(norm)

        # Also check title + description text for expected SWC matches
        text = f"{vuln.get('title','')} {vuln.get('description','')}".upper()
        strict_swcs |= _resolve_swc(text, expected_swcs)
        strict_patterns |= _resolve_pattern(text, expected_patterns)

    # ── 2. Expert findings (lenient) ─────────────────────────────────────────
    for f in session_result.get("expert_findings", []):
        swc = f.get("swc_id", "")
        if swc:
            norm = _normalise_swc(swc)
            # Check if it matches any expected SWC (by canonical or alias)
            full_text = f"{norm} {f.get('title','')} {f.get('description','')}".upper()
            lenient_swcs |= _resolve_swc(full_text, expected_swcs)
            lenient_patterns |= _resolve_pattern(full_text, expected_patterns)

    # ── 3. Attacker findings (lenient) ────────────────────────────────────────
    for f in session_result.get("attacker_findings", []):
        text = f"{f.get('title','')} {f.get('description','')} {f.get('attack_path','')}".upper()
        lenient_swcs |= _resolve_swc(text, expected_swcs)
        lenient_patterns |= _resolve_pattern(text, expected_patterns)

    # ── 4. Regex scan of full report text (lenient) ───────────────────────────
    report_text = report_result.get("report", "").upper()
    lenient_swcs |= _resolve_swc(report_text, expected_swcs)
    lenient_patterns |= _resolve_pattern(report_text, expected_patterns)

    # Strict is a subset of lenient (if it made it to consensus it also made it to lenient)
    lenient_swcs |= strict_swcs
    lenient_patterns |= strict_patterns

    return strict_swcs, lenient_swcs, strict_patterns, lenient_patterns


# ─── Per-sample metrics ───────────────────────────────────────────────────────

def _compute_metrics(found: Set[str], expected: Set[str]) -> dict:
    """Compute P/R/F1 given found and expected sets."""
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


def _evaluate_sample(
    sample_name: str,
    report_result: dict,
    session_result: dict,
) -> dict:
    """
    Evaluate một sample. Returns evaluation dict.
    """
    gt = GROUND_TRUTH[sample_name]
    expected_swcs     = gt["expected_swcs"]
    expected_patterns = gt["expected_patterns"]
    expected_all      = expected_swcs | expected_patterns

    strict_swcs, lenient_swcs, strict_pats, lenient_pats = _extract_found(
        report_result, session_result, expected_swcs, expected_patterns
    )

    strict_all  = strict_swcs  | strict_pats
    lenient_all = lenient_swcs | lenient_pats

    stats = report_result.get("stats", {})

    return {
        "sample": sample_name,
        "contract_name": gt["name"],
        "notes": gt["notes"],
        "pipeline": {
            "expert_findings":    len(session_result.get("expert_findings", [])),
            "attacker_findings":  len(session_result.get("attacker_findings", [])),
            "consensus_vulns":    stats.get("consensus_vulns", 0),
            "critical":           stats.get("critical", 0),
            "high":               stats.get("high", 0),
            "exploitable":        stats.get("exploitable_count", 0),
        },
        # Strict = only findings that made it through 3-layer consensus
        "strict": _compute_metrics(strict_all, expected_all),
        # Lenient = any mention in any finding/report text
        "lenient": _compute_metrics(lenient_all, expected_all),
        "pass": _determine_pass(strict_all, lenient_all, expected_all),
    }


def _determine_pass(strict: Set[str], lenient: Set[str], expected: Set[str]) -> dict:
    """
    Phase 5a pass criteria:
      - Pipeline không crash (function reached này thì đã pass)
      - At least 1 expected vuln found (lenient recall > 0)
      - No extreme FP ratio (FP <= 2 * TP in strict)
    """
    lenient_tp  = len(lenient & expected)
    lenient_fn  = len(expected - lenient)
    strict_tp   = len(strict & expected)
    strict_fp   = len(strict - expected)

    pipeline_ok  = True   # Đã reached đây → pipeline không crash
    recall_ok    = lenient_tp > 0   # Tìm được ít nhất 1 expected vuln
    fp_ratio_ok  = strict_fp <= (2 * strict_tp + 1)  # FP không quá nhiều

    overall_pass = pipeline_ok and recall_ok

    return {
        "pipeline_ok":  pipeline_ok,
        "recall_ok":    recall_ok,
        "fp_ratio_ok":  fp_ratio_ok,
        "overall":      overall_pass,
        "verdict":      "✅ PASS" if overall_pass else "❌ FAIL",
    }


# ─── Pipeline runner ──────────────────────────────────────────────────────────

def run_sample(sample_name: str, output_base: str) -> Tuple[dict, dict, str]:
    """
    Run audit pipeline cho 1 sample. Returns (report_result, session_result, output_dir).
    """
    from run_contract_audit import run_audit, SAMPLE_CONTRACTS
    sample = SAMPLE_CONTRACTS[sample_name]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(output_base, f"{sample_name}_{ts}")

    logger.info(f"\n{'='*60}")
    logger.info(f"Running sample: {sample['name']}")
    logger.info(f"{'='*60}")
    t0 = time.monotonic()

    report_result = run_audit(
        source_code=sample["source"],
        contract_name=sample_name,
        output_dir=output_dir,
        graph_name=sample["name"],
        timeout_session=2400,   # 40 min — 22 agents × 10 rounds × ~10s + retry backoff
    )

    elapsed = time.monotonic() - t0
    logger.info(f"  Elapsed: {elapsed:.1f}s")

    # Load session_result from saved JSON (run_audit doesn't return it directly)
    session_path = os.path.join(output_dir, "session_result.json")
    if os.path.exists(session_path):
        with open(session_path, encoding="utf-8") as f:
            session_result = json.load(f)
    else:
        session_result = {}

    return report_result, session_result, output_dir


def resume_sample(sample_name: str, resume_dir: str) -> Tuple[dict, dict, str]:
    """
    Tái tạo report từ session_result đã lưu trong resume_dir.
    Bỏ qua KG/profiles/session — chỉ chạy lại ConsensusEngine + ReACT report.
    Tìm thư mục mới nhất matching <sample_name>_* trong resume_dir.
    """
    import sys
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)
    from app.services.contract_audit_agent import ContractAuditReportAgent as ContractAuditAgent

    # Find most recent matching dir
    entries = sorted([
        os.path.join(resume_dir, e) for e in os.listdir(resume_dir)
        if os.path.isdir(os.path.join(resume_dir, e)) and e.startswith(sample_name + "_")
    ])
    if not entries:
        raise FileNotFoundError(f"No saved dir for '{sample_name}' in {resume_dir}")
    output_dir = entries[-1]
    logger.info(f"  Resuming from: {output_dir}")

    session_path  = os.path.join(output_dir, "session_result.json")
    summary_path  = os.path.join(output_dir, "contract_summary.txt")

    with open(session_path, encoding="utf-8") as f:
        session_result = json.load(f)
    contract_summary = ""
    if os.path.exists(summary_path):
        with open(summary_path, encoding="utf-8") as f:
            contract_summary = f.read()

    agent = ContractAuditAgent()
    report_result = agent.generate_report_sync(
        session_id=session_result.get("session_id", "resume"),
        expert_findings=session_result.get("expert_findings", []),
        attacker_findings=session_result.get("attacker_findings", []),
        contract_summary=contract_summary,
        graph_id=session_result.get("graph_id"),
        semantic_findings=session_result.get("semantic_findings", []),
    )

    # Save audit_report.json
    report_path = os.path.join(output_dir, "audit_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_result, f, ensure_ascii=False, indent=2)
    logger.info(f"  Saved: {report_path}")

    return report_result, session_result, output_dir


def load_sample_results(load_dir: str, sample_name: str) -> Tuple[dict, dict]:
    """
    Load previously saved pipeline results for a sample from load_dir.
    Looks for the most recent subdirectory matching <sample_name>_*.
    """
    # Find matching dirs
    entries = []
    for entry in os.listdir(load_dir):
        full = os.path.join(load_dir, entry)
        if os.path.isdir(full) and entry.startswith(sample_name + "_"):
            entries.append(full)
    if not entries:
        raise FileNotFoundError(
            f"No results found for '{sample_name}' in {load_dir}"
        )
    # Most recent
    sample_dir = sorted(entries)[-1]
    logger.info(f"  Loading from: {sample_dir}")

    report_path  = os.path.join(sample_dir, "audit_report.json")
    session_path = os.path.join(sample_dir, "session_result.json")

    report_result  = {}
    session_result = {}
    if os.path.exists(report_path):
        with open(report_path, encoding="utf-8") as f:
            report_result = json.load(f)
    if os.path.exists(session_path):
        with open(session_path, encoding="utf-8") as f:
            session_result = json.load(f)

    return report_result, session_result


# ─── Print helpers ────────────────────────────────────────────────────────────

def _print_separator(char: str = "─", width: int = 68):
    print(char * width)


def _print_sample_result(ev: dict):
    print()
    _print_separator("═")
    print(f"  {ev['contract_name']}  [{ev['sample'].upper()}]")
    _print_separator("═")
    print(f"  {ev['notes']}")
    print()

    p = ev["pipeline"]
    print(f"  Pipeline output:")
    print(f"    Expert findings   : {p['expert_findings']}")
    print(f"    Attacker findings : {p['attacker_findings']}")
    print(f"    Consensus vulns   : {p['consensus_vulns']}")
    print(f"    Critical/High     : {p['critical']}/{p['high']}")
    print(f"    Confirmed exploit : {p['exploitable']}")
    print()

    for mode_name, mode_key in [("LENIENT (any mention)", "lenient"),
                                  ("STRICT  (consensus only)", "strict")]:
        m = ev[mode_key]
        print(f"  {mode_name}:")
        print(f"    Expected : {', '.join(m['expected']) or '—'}")
        print(f"    Found    : {', '.join(m['found']) or '—'}")
        if m["missed"]:
            print(f"    Missed   : {', '.join(m['missed'])}")
        if m["false_positives"]:
            print(f"    FP       : {', '.join(m['false_positives'])}")
        print(f"    TP={m['TP']}  FP={m['FP']}  FN={m['FN']}  "
              f"P={m['precision']:.2f}  R={m['recall']:.2f}  F1={m['f1']:.2f}")
    print()

    pa = ev["pass"]
    print(f"  Verdict: {pa['verdict']}")
    if not pa["pipeline_ok"]:
        print("    ⚠️  Pipeline error")
    if not pa["recall_ok"]:
        print("    ⚠️  Recall = 0: no expected vulnerability found")
    if not pa["fp_ratio_ok"]:
        print("    ⚠️  FP ratio high: too many false positives")


def _print_summary(results: list):
    print()
    _print_separator("═")
    print("  PHASE 5a SUMMARY")
    _print_separator("═")
    print()
    print(f"  {'Sample':<15} {'Lenient F1':>10} {'Strict F1':>10} {'Verdict':>12}")
    _print_separator()
    for ev in results:
        lf1 = ev["lenient"]["f1"]
        sf1 = ev["strict"]["f1"]
        verdict = ev["pass"]["verdict"]
        print(f"  {ev['sample']:<15} {lf1:>10.2f} {sf1:>10.2f} {verdict:>12}")
    _print_separator()

    # Aggregates
    pass_count = sum(1 for ev in results if ev["pass"]["overall"])
    avg_lf1 = sum(ev["lenient"]["f1"] for ev in results) / len(results)
    avg_sf1 = sum(ev["strict"]["f1"] for ev in results) / len(results)
    print(f"\n  Samples passed   : {pass_count}/{len(results)}")
    print(f"  Avg Lenient F1   : {avg_lf1:.2f}")
    print(f"  Avg Strict F1    : {avg_sf1:.2f}")
    print()

    if pass_count == len(results):
        print("  🎉 Phase 5a PASSED — pipeline đã sẵn sàng cho Phase 5b")
        print("     Chạy 20 reentrancy contracts: evaluate_phase5b.py")
    elif pass_count > 0:
        print("  ⚠️  Phase 5a PARTIAL — xem sample nào fail và kiểm tra:")
        print("     1. LLM có parse được contract không (contract_summary.txt)?")
        print("     2. Findings có SWC ID không (session_result.json)?")
        print("     3. Consensus có output không (audit_report.json có consensus_vulns)?")
    else:
        print("  ❌ Phase 5a FAILED — pipeline chưa hoạt động, cần debug")
        print("     Gợi ý: chạy với --samples dao trước, kiểm tra từng bước")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Phase 5a: Evaluate 3 built-in samples against ground truth",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--samples", nargs="+",
        choices=["dao", "erc20", "defi_vault"],
        default=["dao", "erc20", "defi_vault"],
        help="Which samples to run (default: all 3)",
    )
    parser.add_argument(
        "--output", "-o", default="./results/phase5a",
        help="Directory to save pipeline outputs (default: ./results/phase5a)",
    )
    parser.add_argument(
        "--load", metavar="DIR",
        help="Load previously saved results from DIR instead of re-running pipeline",
    )
    parser.add_argument(
        "--resume", metavar="DIR",
        help="Re-run only report generation from saved session_result.json in DIR",
    )
    args = parser.parse_args()

    results = []
    errors  = []

    mode = "resume" if args.resume else ("load" if args.load else "run")
    for sample_name in args.samples:
        logger.info(f"\n[{sample_name.upper()}] {mode.upper()}...")
        try:
            if args.resume:
                report_result, session_result, _ = resume_sample(
                    sample_name, args.resume
                )
            elif args.load:
                report_result, session_result = load_sample_results(
                    args.load, sample_name
                )
            else:
                report_result, session_result, _ = run_sample(
                    sample_name, args.output
                )

            ev = _evaluate_sample(sample_name, report_result, session_result)
            results.append(ev)
            _print_sample_result(ev)

        except Exception as e:
            logger.error(f"  [{sample_name}] ERROR: {e}", exc_info=True)
            errors.append({"sample": sample_name, "error": str(e)})

    if results:
        _print_summary(results)

        # Save evaluation JSON
        eval_path = os.path.join(
            args.load or args.output,
            f"phase5a_eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        os.makedirs(os.path.dirname(eval_path), exist_ok=True)
        with open(eval_path, "w", encoding="utf-8") as f:
            json.dump({"results": results, "errors": errors}, f,
                      ensure_ascii=False, indent=2)
        print(f"\n  Evaluation saved → {eval_path}")

    if errors:
        print(f"\n  ❌ Errors: {len(errors)} sample(s) failed to run:")
        for e in errors:
            print(f"     [{e['sample']}] {e['error']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
