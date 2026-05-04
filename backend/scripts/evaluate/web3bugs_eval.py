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
from pathlib import Path
from typing import Dict, List, Set

from llm_judge import judge_match
from metrics import compute_metrics


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


def run_eval(gt_path: str, findings_path: str, verbose: bool = False) -> dict:
    gt_bugs: List[dict] = _load_json(gt_path)
    report = _load_json(findings_path)
    findings: List[dict] = _get_findings(report)

    matched_h_ids: Set[str] = set()
    matched_finding_ids: Set[str] = set()

    match_details: List[dict] = []

    for gt in gt_bugs:
        h_id     = gt.get("h_id", "?")
        gt_fn    = (gt.get("function_name") or "").lower().rstrip("()")
        gt_con   = (gt.get("contract_name") or "").lower()

        candidates = [
            f for f in findings
            if (f.get("function_name") or "").lower().rstrip("()") == gt_fn
            and (f.get("contract_name") or "").lower() == gt_con
        ]

        if verbose:
            print(f"\n[H] {h_id}: {gt.get('title','')[:60]}")
            print(f"    location: {gt_con}.{gt_fn}  →  {len(candidates)} candidates")

        for pred in candidates:
            fid = pred.get("finding_id") or pred.get("title", "")[:30]
            is_match, reason = judge_match(gt, pred)
            if verbose:
                print(f"    candidate '{fid[:40]}': {'YES' if is_match else 'NO'} — {reason}")
            if is_match:
                matched_h_ids.add(h_id)
                matched_finding_ids.add(fid)
                match_details.append({
                    "h_id": h_id, "finding_id": fid, "reason": reason,
                })
                break  # one TP per H bug is enough

    tp = len(matched_h_ids)
    fn = len(gt_bugs) - tp
    fp = sum(
        1 for f in findings
        if (f.get("finding_id") or f.get("title", "")[:30]) not in matched_finding_ids
    )

    metrics = compute_metrics(tp, fp, fn)
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
    print(f"TP={metrics['tp']}  FP={metrics['fp']}  FN={metrics['fn']}")
    print(f"Precision={metrics['precision']:.3f}  Recall={metrics['recall']:.3f}  F1={metrics['f1']:.3f}")

    if args.verbose and metrics.get("match_details"):
        print("\nMatched H bugs:")
        for m in metrics["match_details"]:
            print(f"  {m['h_id']} ← finding '{m['finding_id'][:40]}'")


if __name__ == "__main__":
    sys.exit(main())
