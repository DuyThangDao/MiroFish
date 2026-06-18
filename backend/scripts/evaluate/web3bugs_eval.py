"""
Web3Bugs H-bug evaluation.

Usage:
    python web3bugs_eval.py gt/gt_35.json audit_report_35.json [--verbose]

GT JSON schema (one file per contest):
    [{h_id, title, description, function_name, contract_name}, ...]

Findings JSON: audit_report.json field "findings" (or "consensus_vulns" for compat)
    [{title, description, attack_path, contract_name, function_name, ...}, ...]
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from llm_judge import judge_match
from metrics import compute_metrics

_EVAL_WORKERS = 3


_KEYWORD_KEYWORDS = {
    "overflow", "underflow", "reentrancy", "re-entrancy",
    "access control", "onlyowner", "modifier", "unbounded loop",
    "gas limit", "flash loan", "oracle",
}


def _load_json(path: str) -> dict | list:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _get_findings(report: dict | list) -> List[dict]:
    if isinstance(report, list):
        return report
    return report.get("findings") or report.get("consensus_vulns") or []


def _tier2_candidates(findings: List[dict], gt_fn: str, gt_con: str) -> List[dict]:
    """
    Tier-2: findings that declared a different function but mention the GT function
    in their attack_path or description — i.e. the agent analyzed the right function
    but attributed the finding to a different entry point.
    """
    results = []
    for f in findings:
        fn = (f.get("function_name") or "").lower().rstrip("()")
        con = (f.get("contract_name") or "").lower()
        if fn == gt_fn and con == gt_con:
            continue  # already a Tier-1 candidate
        text = " ".join([
            f.get("attack_path") or "",
            f.get("description") or "",
        ]).lower()
        if gt_fn in text and gt_con in text:
            results.append(f)
    return results


def _evaluate_one_gt(
    gt: dict,
    findings: List[dict],
    verbose: bool,
    worker_id: int = 0,
) -> Tuple[Optional[dict], List[str]]:
    """Evaluate a single GT bug. Returns (match_detail_or_None, verbose_lines)."""
    h_id  = gt.get("h_id", "?")
    gt_fn = (gt.get("function_name") or "").lower().rstrip("()")
    gt_con = (gt.get("contract_name") or "").lower()
    lines: List[str] = []

    # ── Tier-1 ────────────────────────────────────────────────────────────────
    candidates = [
        f for f in findings
        if (f.get("function_name") or "").lower().rstrip("()") == gt_fn
        and (f.get("contract_name") or "").lower() == gt_con
    ]
    if verbose:
        lines.append(f"\n[H] {h_id}: {gt.get('title','')[:60]}")
        lines.append(f"    location: {gt_con}.{gt_fn}  →  {len(candidates)} T1 candidates")

    for pred in candidates:
        fid = pred.get("finding_id") or pred.get("title", "")[:30]
        time.sleep(3)
        is_match, reason = judge_match(gt, pred, worker_id=worker_id)
        if verbose:
            lines.append(f"    [T1] '{fid[:40]}': {'YES' if is_match else 'NO'} — {reason}")
        if is_match:
            return (
                {"h_id": h_id, "finding_id": fid, "tier": 1, "reason": reason},
                lines,
            )

    # ── Tier-2 ────────────────────────────────────────────────────────────────
    t2_cands = _tier2_candidates(findings, gt_fn, gt_con)
    if verbose and t2_cands:
        lines.append(f"    location: {gt_con}.{gt_fn}  →  {len(t2_cands)} T2 candidates")

    for pred in t2_cands:
        fid = pred.get("finding_id") or pred.get("title", "")[:30]
        time.sleep(3)
        is_match, reason = judge_match(gt, pred, worker_id=worker_id)
        if verbose:
            lines.append(f"    [T2] '{fid[:40]}': {'YES' if is_match else 'NO'} — {reason}")
        if is_match:
            return (
                {"h_id": h_id, "finding_id": fid, "tier": 2, "reason": reason},
                lines,
            )

    return None, lines


def run_eval(gt_path: str, findings_path: str, verbose: bool = False) -> dict:
    gt_bugs: List[dict] = _load_json(gt_path)
    report = _load_json(findings_path)
    findings: List[dict] = _get_findings(report)

    # results indexed by position so verbose output prints in GT order
    results: List[Tuple[Optional[dict], List[str]]] = [None] * len(gt_bugs)

    with ThreadPoolExecutor(max_workers=_EVAL_WORKERS) as pool:
        futures = {
            pool.submit(_evaluate_one_gt, gt, findings, verbose, i % _EVAL_WORKERS): i
            for i, gt in enumerate(gt_bugs)
        }
        for fut in as_completed(futures):
            i = futures[fut]
            results[i] = fut.result()

    matched_h_ids: Set[str] = set()
    matched_finding_ids: Set[str] = set()
    matched_t2_h_ids: Set[str] = set()
    match_details: List[dict] = []

    for detail, lines in results:
        if verbose:
            for line in lines:
                print(line)
        if detail:
            matched_h_ids.add(detail["h_id"])
            matched_finding_ids.add(detail["finding_id"])
            if detail["tier"] == 2:
                matched_t2_h_ids.add(detail["h_id"])
            match_details.append(detail)

    tp = len(matched_h_ids)
    tp_t1 = tp - len(matched_t2_h_ids)
    tp_t2 = len(matched_t2_h_ids)
    fn = len(gt_bugs) - tp
    fp = sum(
        1 for f in findings
        if (f.get("finding_id") or f.get("title", "")[:30]) not in matched_finding_ids
    )

    metrics = compute_metrics(tp, fp, fn)
    metrics["tp_t1"] = tp_t1
    metrics["tp_t2"] = tp_t2
    metrics["match_details"] = match_details

    return metrics


def main():
    parser = argparse.ArgumentParser(description="Web3Bugs H-bug evaluation")
    parser.add_argument("gt_path", help="GT JSON file (gt/gt_{contest}.json)")
    parser.add_argument("findings_path", help="audit_report.json")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    metrics = run_eval(args.gt_path, args.findings_path, verbose=args.verbose)

    print(f"\n=== Web3Bugs Evaluation ===")
    print(f"TP={metrics['tp']}  (T1={metrics['tp_t1']} T2={metrics['tp_t2']})  FP={metrics['fp']}  FN={metrics['fn']}")
    print(f"Precision={metrics['precision']:.3f}  Recall={metrics['recall']:.3f}  F1={metrics['f1']:.3f}")

    if args.verbose and metrics.get("match_details"):
        print("\nMatched H bugs:")
        for m in metrics["match_details"]:
            tier_tag = f"[T{m.get('tier',1)}]"
            print(f"  {m['h_id']} {tier_tag} ← finding '{m['finding_id'][:40]}'")


if __name__ == "__main__":
    sys.exit(main())
