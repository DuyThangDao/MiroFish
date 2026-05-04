"""
SmartBugs SWC-based evaluation.

Usage:
    python smartbugs_eval.py gt/gt_smartbugs.json audit_report.json [--verbose]

GT JSON schema:
    {contract_id: [SWC-101, SWC-107, ...], ...}
    (or [{contract_id: str, swc_ids: [str, ...]}, ...])

Findings JSON: audit_report.json field "findings"
    [{title, description, attack_path, contract_name, function_name, ...}, ...]
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from llm_judge import classify_swc
from metrics import compute_metrics


# Keyword pre-filter: maps SWC ID → list of keywords (any match → candidate)
_SWC_KEYWORDS: Dict[str, List[str]] = {
    "SWC-101": ["overflow", "underflow", "explicit cast", "uint128", "int24", "unchecked"],
    "SWC-107": ["reentrancy", "re-entrancy", "reentrant", "external call before"],
    "SWC-105": ["access control", "onlyowner", "missing modifier", "unprotected", "unauthorized"],
    "SWC-113": ["dos", "denial of service", "failed call", "revert loop"],
    "SWC-128": ["unbounded loop", "gas limit", "gas exhaustion", "loop over array"],
    "SWC-116": ["block.timestamp", "timestamp", "block time"],
    "SWC-115": ["tx.origin", "origin"],
    "SWC-120": ["randomness", "blockhash", "block.difficulty", "keccak256(abi"],
    "SWC-114": ["front.run", "transaction order", "race condition", "mempool"],
    "SWC-106": ["selfdestruct", "self-destruct"],
    "SWC-112": ["delegatecall", "delegate call"],
}


def _keyword_match(swc_id: str, predicted: dict) -> bool:
    keywords = _SWC_KEYWORDS.get(swc_id, [])
    text = (
        (predicted.get("title") or "") + " " +
        (predicted.get("description") or "") + " " +
        (predicted.get("attack_path") or "")
    ).lower()
    return any(kw in text for kw in keywords)


def _load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _normalize_gt(gt_raw) -> Dict[str, List[str]]:
    """Normalize GT to {contract_id: [SWC-XXX, ...]} dict."""
    if isinstance(gt_raw, dict):
        return {k: v if isinstance(v, list) else [v] for k, v in gt_raw.items()}
    # list of {contract_id, swc_ids}
    result = {}
    for item in gt_raw:
        cid = item.get("contract_id", "")
        swcs = item.get("swc_ids", [])
        result[cid] = swcs
    return result


def _get_findings(report) -> List[dict]:
    if isinstance(report, list):
        return report
    return report.get("findings") or report.get("consensus_vulns") or []


def run_eval(gt_path: str, findings_path: str, verbose: bool = False) -> dict:
    gt_raw  = _load_json(gt_path)
    gt: Dict[str, List[str]] = _normalize_gt(gt_raw)
    report  = _load_json(findings_path)
    findings: List[dict] = _get_findings(report)

    per_swc_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    total_tp = total_fp = total_fn = 0

    for contract_id, gt_swcs in gt.items():
        contract_findings = [
            f for f in findings
            if (f.get("contract_name") or "").lower() == contract_id.lower()
        ]

        # Track which GT SWCs got a TP
        detected_swcs: Set[str] = set()

        for swc_id in gt_swcs:
            hit = False
            for pred in contract_findings:
                # Keyword pre-filter first (cheap)
                if _keyword_match(swc_id, pred):
                    hit = True
                    if verbose:
                        print(f"  [{contract_id}] {swc_id}: keyword match '{pred.get('title','')[:50]}'")
                    break
                # LLM classifier as fallback
                is_match, reason = classify_swc(swc_id, pred)
                if is_match:
                    hit = True
                    if verbose:
                        print(f"  [{contract_id}] {swc_id}: LLM match '{pred.get('title','')[:50]}' — {reason}")
                    break

            if hit:
                detected_swcs.add(swc_id)
                per_swc_stats[swc_id]["tp"] += 1
                total_tp += 1
            else:
                per_swc_stats[swc_id]["fn"] += 1
                total_fn += 1
                if verbose:
                    print(f"  [{contract_id}] {swc_id}: MISSED (FN)")

        # FP: findings that don't map to any GT SWC in this contract
        for pred in contract_findings:
            maps_to_any = any(
                _keyword_match(swc_id, pred) or classify_swc(swc_id, pred)[0]
                for swc_id in gt_swcs
            )
            if not maps_to_any:
                total_fp += 1
                if verbose:
                    print(f"  [{contract_id}] FP: '{pred.get('title','')[:50]}'")

    overall = compute_metrics(total_tp, total_fp, total_fn)

    per_swc_results = {}
    for swc_id, s in per_swc_stats.items():
        per_swc_results[swc_id] = compute_metrics(s["tp"], s["fp"], s["fn"])

    overall["per_swc"] = per_swc_results
    return overall


def main():
    parser = argparse.ArgumentParser(description="SmartBugs SWC evaluation")
    parser.add_argument("gt_path", help="GT JSON file ({contract_id: [SWC-XXX, ...]})")
    parser.add_argument("findings_path", help="audit_report.json")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    metrics = run_eval(args.gt_path, args.findings_path, verbose=args.verbose)

    print(f"\n=== SmartBugs SWC Evaluation ===")
    print(f"TP={metrics['tp']}  FP={metrics['fp']}  FN={metrics['fn']}")
    print(f"Precision={metrics['precision']:.3f}  Recall={metrics['recall']:.3f}  F1={metrics['f1']:.3f}")

    if metrics.get("per_swc"):
        print("\nPer-SWC breakdown:")
        for swc_id, s in sorted(metrics["per_swc"].items()):
            if s["tp"] + s["fn"] > 0:
                print(f"  {swc_id}: TP={s['tp']} FN={s['fn']} Recall={s['recall']:.3f}")


if __name__ == "__main__":
    sys.exit(main())
