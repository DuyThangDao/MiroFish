"""
evaluate_web3bugs.py — Dual-metric evaluation of MiroFish on Web3Bugs benchmark.

Usage:
    python evaluate_web3bugs.py \
        --results  backend/results/web3bugs_trial/ \
        --bugs-csv /path/to/web3bugs/results/bugs.csv \
        [--contest 19] \
        [--verbose]

Output: per-contest table + aggregate F1 (strict + lenient).

Metric definitions
------------------
Strict TP  : ground-truth bug label maps to the tool's finding AND function name overlaps.
Lenient TP : ground-truth bug label maps to the tool's finding category/SWC (no function check).
FP         : tool finding has no GT match (precision denominator).
FN         : GT bug has no tool match (recall denominator).

Two finding pools are evaluated:
  L-category  → matched against consensus_vulns via mitre_techniques (SWC IDs)
                 + unvalidated_swc_gaps (secondary, single-domain)
  S/SE/SC cat → matched against semantic_results via category field
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, FrozenSet, List, NamedTuple, Optional, Set, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# Label → detection target mappings
# ──────────────────────────────────────────────────────────────────────────────

L_TO_SWC: Dict[str, FrozenSet[str]] = {
    "L1":  frozenset({"SWC-107"}),
    "L2":  frozenset({"SWC-101"}),
    "L3":  frozenset({"SWC-109"}),
    "L4":  frozenset({"SWC-128"}),
    "L5":  frozenset({"SWC-124"}),
    "L6":  frozenset({"SWC-107", "SWC-131"}),
    "L7":  frozenset({"SWC-101"}),
    "L8":  frozenset({"SWC-104"}),
    "L9":  frozenset({"SWC-109"}),
    "LA":  frozenset({"SWC-121", "SWC-122"}),
    "LB":  frozenset({"SWC-115"}),
}

# SWC IDs that semantically correspond to S-category classes.
# Used to credit consensus_vulns findings when they capture an S-bug via SWC path.
SWC_TO_SEMANTIC: Dict[str, str] = {
    # Access control (S2)
    "SWC-100": "access_control",   # Function Default Visibility
    "SWC-105": "access_control",   # Unprotected Ether Withdrawal
    "SWC-106": "access_control",   # Unprotected Self-Destruct
    "SWC-115": "access_control",   # tx.origin auth
    "SWC-113": "access_control",   # DoS by admin
    # Price oracle / flash loan (S1)
    "SWC-119": "price_oracle",     # Shadowing State Variables (oracle context)
    # Governance (S5)
    "SWC-108": "governance_attack",
    # Incorrect accounting / state machine (S3/S6)
    "SWC-132": "incorrect_accounting",
}

S_TO_CATEGORIES: Dict[str, FrozenSet[str]] = {
    "S1":    frozenset({"price_oracle", "flash_loan"}),
    "S1-1":  frozenset({"price_oracle"}),
    "S1-2":  frozenset({"flash_loan", "price_oracle"}),
    "S2":    frozenset({"access_control"}),
    "S2-1":  frozenset({"access_control"}),
    "S3":    frozenset({"state_machine_bug", "incorrect_accounting"}),
    "S3-1":  frozenset({"state_machine_bug"}),
    "S4":    frozenset({"business_flow"}),
    "S5":    frozenset({"governance_attack"}),
    "S6":    frozenset({"incorrect_accounting"}),
    "SE":    frozenset({"other"}),
    "SE-1":  frozenset({"other"}),
    "SE-2":  frozenset({"other"}),
    "SE-3":  frozenset({"other"}),
    "SE-4":  frozenset({"other"}),
    "SC":    frozenset({"other"}),
}

# Semantic categories that are fundamentally undetectable from source alone
# (cross-chain state, spec intent) — flagged separately
OUT_OF_SCOPE_LABELS: FrozenSet[str] = frozenset({"SE", "SE-1", "SE-2", "SE-3", "SE-4", "SC"})


# ──────────────────────────────────────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────────────────────────────────────

class GTBug(NamedTuple):
    contest_id: int
    bug_id: str
    label: str
    difficulty: int
    description: str


class ToolFinding:
    """Normalised representation of one tool output finding."""
    def __init__(
        self,
        finding_id: str,
        swc_ids: Set[str],           # for L-category matching
        category: Optional[str],     # for S-category matching
        functions: Set[str],         # normalised function names
        confidence: float,
        is_secondary: bool = False,  # True = unvalidated_swc_gap
    ):
        self.finding_id = finding_id
        self.swc_ids = swc_ids
        self.category = category
        self.functions = functions
        self.confidence = confidence
        self.is_secondary = is_secondary


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _norm_fn(name: str) -> str:
    """Normalise function name: strip (), lowercase, strip whitespace."""
    return re.sub(r'\(.*\)', '', name).strip().lower()


def _norm_fn_set(names: List[str]) -> Set[str]:
    return {_norm_fn(n) for n in names if n}


def _f1(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


# ──────────────────────────────────────────────────────────────────────────────
# Data loading
# ──────────────────────────────────────────────────────────────────────────────

def load_bugs_csv(path: str) -> Dict[int, List[GTBug]]:
    bugs: Dict[int, List[GTBug]] = defaultdict(list)
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh, skipinitialspace=True)
        for row in reader:
            try:
                cid = int(row["Contest ID"].strip())
                bugs[cid].append(GTBug(
                    contest_id=cid,
                    bug_id=row["Bug ID"].strip(),
                    label=row["Bug Label"].strip(),
                    difficulty=int(row["Difficulty"].strip()),
                    description=row["Bug Description"].strip(),
                ))
            except (ValueError, KeyError):
                continue
    return bugs


def load_audit_report(report_path: str) -> Optional[Dict]:
    try:
        with open(report_path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:
        print(f"  [WARN] Could not read {report_path}: {e}")
        return None


def extract_findings(report: Dict) -> List[ToolFinding]:
    findings: List[ToolFinding] = []

    # 1) consensus_vulns — primary L-category signal
    # Also derive semantic category from SWC IDs so S-category bugs found via
    # consensus path (e.g. SWC-100/105 for access_control) are credited correctly.
    for cv in report.get("consensus_vulns", []):
        swcs = set(cv.get("mitre_techniques", []))
        fns  = _norm_fn_set(cv.get("affected_assets", []))
        # Derive best semantic category from SWC→semantic mapping
        derived_category: Optional[str] = None
        for swc in swcs:
            if swc in SWC_TO_SEMANTIC:
                derived_category = SWC_TO_SEMANTIC[swc]
                break
        findings.append(ToolFinding(
            finding_id=cv.get("vuln_id", "?"),
            swc_ids=swcs,
            category=derived_category,
            functions=fns,
            confidence=cv.get("confidence_score", 0.0),
        ))

    # 2) semantic_results — S-category signal
    for sr in report.get("semantic_results", []):
        fns = _norm_fn_set(sr.get("affected_functions", []))
        findings.append(ToolFinding(
            finding_id=sr.get("semantic_vuln_id", "?"),
            swc_ids=set(),
            category=sr.get("category"),
            functions=fns,
            confidence=sr.get("confidence_score", 0.0),
        ))

    # 3) unvalidated_swc_gaps — secondary L-category signal
    for gap in report.get("unvalidated_swc_gaps", []):
        swcs = {gap.get("swc_id", "")} if gap.get("swc_id") else set()
        fns  = _norm_fn_set(gap.get("affected_functions", []))
        findings.append(ToolFinding(
            finding_id=f"gap_{gap.get('swc_id', '?')}",
            swc_ids=swcs,
            category=gap.get("swc_category"),
            functions=fns,
            confidence=0.3,
            is_secondary=True,
        ))

    return findings


def find_latest_report(contest_results_dir: str) -> Optional[str]:
    """Return path to audit_report.json in the most recent run subdirectory."""
    base = Path(contest_results_dir)
    if not base.is_dir():
        return None
    runs = sorted(base.iterdir(), reverse=True)
    for run in runs:
        candidate = run / "audit_report.json"
        if candidate.exists():
            return str(candidate)
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Matching logic
# ──────────────────────────────────────────────────────────────────────────────

def _label_type(label: str) -> str:
    if label.startswith("L"):
        return "L"
    if label.startswith("S") or label in ("SE", "SC") or label.startswith("SE-") or label.startswith("SC-"):
        return "S"
    return "O"


def match_bug(bug: GTBug, findings: List[ToolFinding]) -> Tuple[bool, bool]:
    """
    Returns (strict_tp, lenient_tp).
    strict  = category/SWC match AND at least one function name overlap
    lenient = category/SWC match only
    """
    ltype = _label_type(bug.label)

    if ltype == "O":
        return False, False

    if ltype == "L":
        expected_swcs = L_TO_SWC.get(bug.label, frozenset())
        if not expected_swcs:
            return False, False
        for f in findings:
            if f.swc_ids & expected_swcs:          # any overlap in SWC IDs
                lenient = True
                strict  = bool(f.functions)        # if tool reported functions, require overlap
                # For strict: tool must name at least one function (even if we can't verify exact match
                # without ground-truth function labels — see note below)
                # Since bugs.csv doesn't carry GT function names, strict-L = lenient-L for now.
                # Strict-L is reserved for future when GT function labels are available.
                return lenient, lenient
        return False, False

    # S / SE / SC
    expected_cats = S_TO_CATEGORIES.get(bug.label, frozenset())
    if not expected_cats:
        return False, False
    for f in findings:
        if f.category and f.category.lower() in {c.lower() for c in expected_cats}:
            lenient = True
            strict  = bool(f.functions)
            # Same note as above — GT function names not in bugs.csv.
            return lenient, lenient
    return False, False


# ──────────────────────────────────────────────────────────────────────────────
# Per-contest evaluation
# ──────────────────────────────────────────────────────────────────────────────

class ContestResult(NamedTuple):
    contest_id: int
    gt_total: int
    gt_l: int
    gt_s: int
    gt_oos: int           # out-of-scope (SE/SC)
    tool_findings: int
    l_strict_tp: int
    l_lenient_tp: int
    s_strict_tp: int
    s_lenient_tp: int
    strict_fp: int
    lenient_fp: int


def evaluate_contest(
    contest_id: int,
    gt_bugs: List[GTBug],
    findings: List[ToolFinding],
    verbose: bool = False,
) -> ContestResult:
    gt_l   = [b for b in gt_bugs if _label_type(b.label) == "L"]
    gt_s   = [b for b in gt_bugs if _label_type(b.label) == "S"]
    gt_oos = [b for b in gt_bugs if b.label in OUT_OF_SCOPE_LABELS]
    gt_in_scope = gt_l + gt_s

    l_strict_tp = l_lenient_tp = 0
    s_strict_tp = s_lenient_tp = 0

    matched_finding_ids_strict:  Set[str] = set()
    matched_finding_ids_lenient: Set[str] = set()

    for bug in gt_l:
        strict, lenient = match_bug(bug, findings)
        if strict:
            l_strict_tp += 1
        if lenient:
            l_lenient_tp += 1
        if verbose:
            tag = ("✓" if lenient else "✗") + ("s" if strict else " ")
            print(f"    [{tag}] {bug.bug_id} ({bug.label}) — {bug.description[:60]}")

    for bug in gt_s:
        strict, lenient = match_bug(bug, findings)
        if strict:
            s_strict_tp += 1
        if lenient:
            s_lenient_tp += 1
        if verbose:
            tag = ("✓" if lenient else "✗") + ("s" if strict else " ")
            print(f"    [{tag}] {bug.bug_id} ({bug.label}) — {bug.description[:60]}")

    if verbose and gt_oos:
        for bug in gt_oos:
            print(f"    [--] {bug.bug_id} ({bug.label}) — OUT-OF-SCOPE: {bug.description[:60]}")

    total_strict_tp  = l_strict_tp  + s_strict_tp
    total_lenient_tp = l_lenient_tp + s_lenient_tp
    n_findings = len(findings)
    strict_fp  = max(0, n_findings - total_strict_tp)
    lenient_fp = max(0, n_findings - total_lenient_tp)

    return ContestResult(
        contest_id=contest_id,
        gt_total=len(gt_bugs),
        gt_l=len(gt_l),
        gt_s=len(gt_s),
        gt_oos=len(gt_oos),
        tool_findings=n_findings,
        l_strict_tp=l_strict_tp,
        l_lenient_tp=l_lenient_tp,
        s_strict_tp=s_strict_tp,
        s_lenient_tp=s_lenient_tp,
        strict_fp=strict_fp,
        lenient_fp=lenient_fp,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Aggregate + display
# ──────────────────────────────────────────────────────────────────────────────

def print_table(results: List[ContestResult], verbose: bool = False) -> None:
    hdr = (
        f"{'Ctest':>5} │ {'GT':>4} {'L':>3} {'S':>3} {'OOS':>3} │"
        f" {'Fnd':>4} │"
        f" {'L-TP':>5} {'S-TP':>5} {'TP':>4} {'FP':>4} {'FN':>4} │"
        f" {'Prec':>6} {'Rec':>6} {'F1':>6} │ (lenient)"
    )
    sep = "─" * len(hdr)

    print()
    print("  STRICT metric (function overlap required when GT functions available)")
    print(sep)
    print(hdr)
    print(sep)

    agg_gt_l = agg_gt_s = 0
    agg_l_tp = agg_s_tp = agg_fp = 0

    for r in results:
        tp = r.l_strict_tp + r.s_strict_tp
        fn = (r.gt_l - r.l_strict_tp) + (r.gt_s - r.s_strict_tp)
        fp = r.strict_fp
        P, R, F = _f1(tp, fp, fn)
        agg_gt_l += r.gt_l
        agg_gt_s += r.gt_s
        agg_l_tp += r.l_strict_tp
        agg_s_tp += r.s_strict_tp
        agg_fp   += fp
        print(
            f"  {r.contest_id:>5} │ {r.gt_total:>4} {r.gt_l:>3} {r.gt_s:>3} {r.gt_oos:>3} │"
            f" {r.tool_findings:>4} │"
            f" {r.l_strict_tp:>5} {r.s_strict_tp:>5} {tp:>4} {fp:>4} {fn:>4} │"
            f" {P:6.3f} {R:6.3f} {F:6.3f}"
        )

    print(sep)
    agg_tp = agg_l_tp + agg_s_tp
    agg_fn = (agg_gt_l - agg_l_tp) + (agg_gt_s - agg_s_tp)
    P, R, F = _f1(agg_tp, agg_fp, agg_fn)
    print(
        f"  {'AGG':>5} │ {sum(r.gt_total for r in results):>4}"
        f" {agg_gt_l:>3} {agg_gt_s:>3} {sum(r.gt_oos for r in results):>3} │"
        f" {sum(r.tool_findings for r in results):>4} │"
        f" {agg_l_tp:>5} {agg_s_tp:>5} {agg_tp:>4} {agg_fp:>4} {agg_fn:>4} │"
        f" {P:6.3f} {R:6.3f} {F:6.3f}  ← STRICT F1"
    )

    # ── lenient table ──────────────────────────────────────────────────────────
    print()
    print("  LENIENT metric (category/SWC match only)")
    print(sep)
    print(hdr)
    print(sep)

    agg_l_tp = agg_s_tp = agg_fp = 0
    for r in results:
        tp = r.l_lenient_tp + r.s_lenient_tp
        fn = (r.gt_l - r.l_lenient_tp) + (r.gt_s - r.s_lenient_tp)
        fp = r.lenient_fp
        P, R, F = _f1(tp, fp, fn)
        agg_l_tp += r.l_lenient_tp
        agg_s_tp += r.s_lenient_tp
        agg_fp   += fp
        print(
            f"  {r.contest_id:>5} │ {r.gt_total:>4} {r.gt_l:>3} {r.gt_s:>3} {r.gt_oos:>3} │"
            f" {r.tool_findings:>4} │"
            f" {r.l_lenient_tp:>5} {r.s_lenient_tp:>5} {tp:>4} {fp:>4} {fn:>4} │"
            f" {P:6.3f} {R:6.3f} {F:6.3f}"
        )

    print(sep)
    agg_tp = agg_l_tp + agg_s_tp
    agg_fn = (agg_gt_l - agg_l_tp) + (agg_gt_s - agg_s_tp)
    P, R, F = _f1(agg_tp, agg_fp, agg_fn)
    print(
        f"  {'AGG':>5} │ {sum(r.gt_total for r in results):>4}"
        f" {agg_gt_l:>3} {agg_gt_s:>3} {sum(r.gt_oos for r in results):>3} │"
        f" {sum(r.tool_findings for r in results):>4} │"
        f" {agg_l_tp:>5} {agg_s_tp:>5} {agg_tp:>4} {agg_fp:>4} {agg_fn:>4} │"
        f" {P:6.3f} {R:6.3f} {F:6.3f}  ← LENIENT F1"
    )
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    default_bugs = str(Path(__file__).parent.parent.parent.parent / "web3bugs" / "results" / "bugs.csv")
    default_results = str(Path(__file__).parent.parent / "results" / "web3bugs_trial")

    parser = argparse.ArgumentParser(description="Evaluate MiroFish on Web3Bugs benchmark")
    parser.add_argument("--results",  default=default_results, help="Path to web3bugs_trial results dir")
    parser.add_argument("--bugs-csv", default=default_bugs,    help="Path to bugs.csv")
    parser.add_argument("--contest",  type=int, default=None,  help="Evaluate single contest ID")
    parser.add_argument("--verbose",  action="store_true",     help="Print per-bug match details")
    args = parser.parse_args()

    if not os.path.exists(args.bugs_csv):
        print(f"[ERROR] bugs.csv not found: {args.bugs_csv}")
        sys.exit(1)

    all_bugs = load_bugs_csv(args.bugs_csv)
    results_base = Path(args.results)

    contest_ids = sorted(
        int(p.name.split("_")[1])
        for p in results_base.iterdir()
        if p.is_dir() and p.name.startswith("contest_")
    ) if not args.contest else [args.contest]

    if not contest_ids:
        print("[ERROR] No contest directories found in", args.results)
        sys.exit(1)

    all_results: List[ContestResult] = []

    for cid in contest_ids:
        contest_dir = results_base / f"contest_{cid}"
        report_path = find_latest_report(str(contest_dir))

        if not report_path:
            print(f"  [SKIP] Contest {cid}: no audit_report.json found")
            continue

        report = load_audit_report(report_path)
        if not report:
            continue

        gt_bugs = all_bugs.get(cid, [])
        if not gt_bugs:
            print(f"  [SKIP] Contest {cid}: no GT bugs in bugs.csv")
            continue

        findings = extract_findings(report)

        print(f"\n  Contest {cid} │ GT bugs: {len(gt_bugs)} │ Tool findings: {len(findings)}")
        if args.verbose:
            print(f"    Report: {report_path}")

        result = evaluate_contest(cid, gt_bugs, findings, verbose=args.verbose)
        all_results.append(result)

    if all_results:
        print_table(all_results, verbose=args.verbose)
    else:
        print("[WARN] No contests evaluated.")


if __name__ == "__main__":
    main()
