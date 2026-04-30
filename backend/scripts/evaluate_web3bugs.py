"""
evaluate_web3bugs.py — Two-track evaluation per docs/web3bugs-evaluation-protocol.md

Track L  : L* bugs → matched via SWC IDs in consensus_vulns / unvalidated_swc_gaps
Track S  : S1–S6 bugs → matched via category in semantic_results (Policy A default)
Out-of-scope: SE*, SC, O* — excluded from G_L and G_S denominators

Policy A (default): S-track uses only semantic_results.category
Policy B (--policy-b): S-track also allows SWC→category fallback from consensus_vulns
                       — report as secondary/sensitivity analysis when used
Policy Gap (--policy-gap): S-track also allows unvalidated_swc_gaps when
                           semantic_category_from_gap() returns a bucket (source_count
                           ≥ threshold; see semantic_taxonomy.py) — sensitivity only

FP counting (§6 Cách 2 / script-style upper bound):
  FP_L = max(0, n_L_pool_findings − TP_L)   where L-pool = consensus_vulns + swc_gaps
  FP_S = max(0, n_S_pool_findings − TP_S)   where S-pool = semantic_results
                                             (+ consensus w/ SWC→semantic under Policy B)
                                             (+ gap rows w/ derived category under Policy Gap)

Usage:
    python3 evaluate_web3bugs.py \\
        --results  backend/results/web3bugs_trial/ \\
        --bugs-csv /path/to/web3bugs/results/bugs.csv \\
        [--contest 19] \\
        [--policy-b] \\
        [--policy-gap] \\
        [--verbose]
"""

import argparse
import csv
import importlib.util
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, FrozenSet, List, NamedTuple, Optional, Set, Tuple

_BACKEND_ROOT = Path(__file__).resolve().parent.parent
_TAXONOMY_PATH = _BACKEND_ROOT / "app" / "services" / "semantic_taxonomy.py"
_spec = importlib.util.spec_from_file_location("semantic_taxonomy", _TAXONOMY_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"Cannot load semantic taxonomy: {_TAXONOMY_PATH}")
_semantic_taxonomy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_semantic_taxonomy)
SWC_TO_SEMANTIC = _semantic_taxonomy.SWC_TO_SEMANTIC
normalize_semantic_category = _semantic_taxonomy.normalize_semantic_category
semantic_category_from_gap = _semantic_taxonomy.semantic_category_from_gap

# ──────────────────────────────────────────────────────────────────────────────
# Label → detection target mappings  (publish as appendix / Table X in paper)
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

# (contest_id, bug_id) → expected function names (lowercase, no parens — matches _norm_fn output).
# Empty = no function-level GT for that bug → _match_l_fn() falls back to SWC-only match (lenient).
GT_FUNCTIONS: Dict[Tuple[int, str], Set[str]] = {
    # Contest 35 — ConcentratedLiquidityPool (SushiSwap Trident)
    (35, "H-01"): {"burn"},                                    # unsafe cast in burn()
    (35, "H-04"): {"mint"},                                    # overflow in mint()
    (35, "H-05"): {"_getamountsforliquidity"},                 # typecasting in _getAmountsForLiquidity()
    (35, "H-09"): {"rangefeegrowth"},                          # uint256 subtraction underflow in rangeFeeGrowth()
    (35, "H-14"): {"rangefeegrowth", "rangesecondsinside"},    # unchecked math needed in both view fns
    (35, "H-15"): {"constructor"},                             # initialPrice not validated in constructor
}

# SWC_TO_SEMANTIC imported from app.services.semantic_taxonomy (single source).

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
}

# Excluded from G_L and G_S (both denominators) per §3
OUT_OF_SCOPE_LABELS: FrozenSet[str] = frozenset({
    "SE", "SE-1", "SE-2", "SE-3", "SE-4", "SC",
})


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
    """One normalised finding from the audit report."""
    def __init__(
        self,
        finding_id: str,
        swc_ids: Set[str],
        category: Optional[str],    # from semantic_results (Policy A) or derived (Policy B)
        functions: Set[str],
        confidence: float,
        source: str,                # "consensus" | "semantic" | "gap"
    ):
        self.finding_id = finding_id
        self.swc_ids = swc_ids
        self.category = category
        self.functions = functions
        self.confidence = confidence
        self.source = source


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _norm_fn(name: str) -> str:
    return re.sub(r'\(.*\)', '', name).strip().lower()


def _norm_fn_set(names: List[str]) -> Set[str]:
    return {_norm_fn(n) for n in names if n}


def _f1(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def _label_type(label: str) -> str:
    """Returns 'L', 'S', 'OOS', or 'O'."""
    if label.startswith("L"):
        return "L"
    if label in OUT_OF_SCOPE_LABELS or label.startswith("SE-") or label.startswith("SC-"):
        return "OOS"
    if label.startswith("S"):
        return "S"
    return "O"


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


def extract_findings(
    report: Dict,
    policy_b: bool = False,
    policy_gap: bool = False,
) -> List[ToolFinding]:
    """
    Build finding pool.

    Policy A (policy_b=False — default):
      - consensus_vulns → source="consensus", swc_ids set, category=None
        (NOT eligible for S-track matching; only L-track)
      - semantic_results → source="semantic", category from field
        (only eligible for S-track matching)
      - unvalidated_swc_gaps → source="gap", swc_ids set, category=None
        (only L-track unless policy_gap)

    Policy B (policy_b=True):
      - consensus_vulns also get derived category via SWC_TO_SEMANTIC
        → eligible for S-track matching as well as L-track

    Policy Gap (policy_gap=True):
      - gaps with strong corroboration get category via semantic_category_from_gap
        → eligible for S-track (sensitivity)
    """
    findings: List[ToolFinding] = []

    for cv in report.get("consensus_vulns", []):
        swcs = set(cv.get("swc_ids", []))
        fns  = _norm_fn_set(cv.get("affected_assets", []))
        derived: Optional[str] = None
        if policy_b:
            for swc in swcs:
                if swc in SWC_TO_SEMANTIC:
                    derived = normalize_semantic_category(SWC_TO_SEMANTIC[swc])
                    break
        findings.append(ToolFinding(
            finding_id=cv.get("vuln_id", "?"),
            swc_ids=swcs,
            category=derived,
            functions=fns,
            confidence=cv.get("confidence_score", 0.0),
            source="consensus",
        ))

    for sr in report.get("semantic_results", []):
        fns = _norm_fn_set(sr.get("affected_functions", []))
        findings.append(ToolFinding(
            finding_id=sr.get("semantic_vuln_id", "?"),
            swc_ids=set(),
            category=normalize_semantic_category(sr.get("category")),
            functions=fns,
            confidence=sr.get("confidence_score", 0.0),
            source="semantic",
        ))

    for gap in report.get("unvalidated_swc_gaps", []):
        swc_raw = (gap.get("swc_id") or "").strip()
        swcs = {swc_raw} if swc_raw else set()
        fns  = _norm_fn_set(gap.get("affected_functions", []))
        gap_cat: Optional[str] = None
        if policy_gap:
            gap_cat = semantic_category_from_gap(
                gap.get("swc_category"),
                gap.get("swc_id"),
                int(gap.get("source_count") or 0),
            )
        findings.append(ToolFinding(
            finding_id=f"gap_{gap.get('swc_category', '?')}_{swc_raw or 'noswc'}",
            swc_ids=swcs,
            category=gap_cat,
            functions=fns,
            confidence=0.3,
            source="gap",
        ))

    return findings


def find_latest_report(contest_results_dir: str) -> Optional[str]:
    """Return audit_report.json in the most recently modified run subdirectory."""
    base = Path(contest_results_dir)
    if not base.is_dir():
        return None
    # Sort by mtime descending — avoids alphabetical edge cases (e.g. 'w' > 'T')
    runs = sorted(base.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    for run in runs:
        candidate = run / "audit_report.json"
        if candidate.exists():
            return str(candidate)
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Matching logic
# ──────────────────────────────────────────────────────────────────────────────

def _match_l_fn(bug: GTBug, findings: List[ToolFinding]) -> bool:
    """
    L-track fn-level match (primary): Tier-1 consensus finding with SWC match.
    If GT_FUNCTIONS has function data for this bug, also requires function overlap.
    Falls back to SWC-only match when no GT function data available.
    Only Tier-1 findings (source='consensus') are eligible.
    """
    expected_swcs = L_TO_SWC.get(bug.label, frozenset())
    if not expected_swcs:
        return False
    expected_fns = GT_FUNCTIONS.get((bug.contest_id, bug.bug_id), set())
    for f in findings:
        if f.source != "consensus":
            continue
        if not (f.swc_ids & expected_swcs):
            continue
        if not expected_fns:
            return True  # no GT function data — lenient fallback
        if f.functions & expected_fns:
            return True
    return False


def _match_s(
    bug: GTBug,
    findings: List[ToolFinding],
    policy_b: bool,
    policy_gap: bool,
) -> bool:
    """
    S-track lenient match.
    Policy A: only semantic_results findings (source="semantic").
    Policy B: also consensus findings that have a derived category (source="consensus", category set).
    Policy Gap: also gap findings with derived category (source="gap", category set).
    All: finding.category must be in S_TO_CATEGORIES[label] (canonical buckets).
    """
    expected_cats = S_TO_CATEGORIES.get(bug.label, frozenset())
    if not expected_cats:
        # Fall back to parent label: "S6-4" → "S6", "S3-1" → "S3", etc.
        parent = bug.label.split("-")[0]
        expected_cats = S_TO_CATEGORIES.get(parent, frozenset())
    if not expected_cats:
        return False
    expected_lower = {c.lower() for c in expected_cats}
    for f in findings:
        eligible = (
            f.source == "semantic"
            or (policy_b and f.source == "consensus" and f.category is not None)
            or (policy_gap and f.source == "gap" and f.category is not None)
        )
        if eligible and f.category and f.category.lower() in expected_lower:
            return True
    return False


def _in_s_pool(f: ToolFinding, policy_b: bool, policy_gap: bool) -> bool:
    if f.source == "semantic":
        return True
    if policy_b and f.source == "consensus" and f.category is not None:
        return True
    if policy_gap and f.source == "gap" and f.category is not None:
        return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Per-contest evaluation
# ──────────────────────────────────────────────────────────────────────────────

class ContestResult(NamedTuple):
    contest_id: int
    # Ground truth counts
    gt_total: int
    gt_l: int       # |G_L| — L* bugs in scope
    gt_s: int       # |G_S| — S1–S6 bugs in scope
    gt_oos: int     # SE*/SC/O* — excluded from denominators
    # Finding pool sizes (denominator of precision)
    n_l_tier1_pool: int  # consensus-only findings (Tier-1 pool)
    n_s_pool: int        # semantic findings (+ Policy-B consensus findings)
    # Track L — fn-level (primary metric, Tier-1 consensus only)
    tp_l_fn: int
    fp_l_fn: int
    fn_l_fn: int
    # Track S
    tp_s: int
    fp_s: int
    fn_s: int


def evaluate_contest(
    contest_id: int,
    gt_bugs: List[GTBug],
    findings: List[ToolFinding],
    policy_b: bool = False,
    policy_gap: bool = False,
    verbose: bool = False,
) -> ContestResult:

    gt_l   = [b for b in gt_bugs if _label_type(b.label) == "L"]
    gt_s   = [b for b in gt_bugs if _label_type(b.label) == "S"]
    gt_oos = [b for b in gt_bugs if _label_type(b.label) in ("OOS", "O")]

    # Tier-1 = consensus-only findings (fn-level primary metric)
    l_tier1_pool = [f for f in findings if f.source == "consensus"]
    s_pool = [f for f in findings if _in_s_pool(f, policy_b, policy_gap)]

    tp_l_fn = sum(1 for b in gt_l if _match_l_fn(b, findings))
    tp_s    = sum(1 for b in gt_s if _match_s(b, findings, policy_b, policy_gap))

    fn_l_fn = len(gt_l) - tp_l_fn
    fn_s    = len(gt_s) - tp_s

    fp_l_fn = max(0, len(l_tier1_pool) - tp_l_fn)
    fp_s    = max(0, len(s_pool)       - tp_s)

    if verbose:
        pol = ("B" if policy_b else "A") + ("+gap" if policy_gap else "")
        print(f"    ── Track L fn-level (G_L={len(gt_l)}, Tier-1 pool={len(l_tier1_pool)}) ──")
        for b in gt_l:
            hit_fn = _match_l_fn(b, findings)
            print(f"      [{'✓' if hit_fn else '✗'}] {b.bug_id} ({b.label}) — {b.description[:70]}")
        print(f"    ── Track S (G_S={len(gt_s)}, S-pool={len(s_pool)}, Policy {pol}) ──")
        for b in gt_s:
            hit = _match_s(b, findings, policy_b, policy_gap)
            print(f"      [{'✓' if hit else '✗'}] {b.bug_id} ({b.label}) — {b.description[:70]}")
        if gt_oos:
            print(f"    ── Out-of-scope ({len(gt_oos)} bugs, excluded from denominators) ──")
            for b in gt_oos:
                print(f"      [--] {b.bug_id} ({b.label}) — {b.description[:70]}")

    return ContestResult(
        contest_id=contest_id,
        gt_total=len(gt_bugs),
        gt_l=len(gt_l),
        gt_s=len(gt_s),
        gt_oos=len(gt_oos),
        n_l_tier1_pool=len(l_tier1_pool),
        n_s_pool=len(s_pool),
        tp_l_fn=tp_l_fn, fp_l_fn=fp_l_fn, fn_l_fn=fn_l_fn,
        tp_s=tp_s, fp_s=fp_s, fn_s=fn_s,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Display
# ──────────────────────────────────────────────────────────────────────────────

def _row_l(r: ContestResult) -> str:
    P, R, F = _f1(r.tp_l_fn, r.fp_l_fn, r.fn_l_fn)
    has_gt_fn = any(True for (cid, _), fns in GT_FUNCTIONS.items() if cid == r.contest_id and fns)
    note = "" if has_gt_fn else " [lenient: no GT_fn data]"
    return (
        f"  {r.contest_id:>5} │ G_L={r.gt_l:>3} │"
        f" pool={r.n_l_tier1_pool:>3} TP={r.tp_l_fn:>3} FP={r.fp_l_fn:>3} FN={r.fn_l_fn:>3}"
        f" P={P:.3f} R={R:.3f} F1={F:.3f}{note}"
    )


def _row_s(r: ContestResult, policy_b: bool, policy_gap: bool) -> str:
    P, R, F = _f1(r.tp_s, r.fp_s, r.fn_s)
    tag = ("B" if policy_b else "A") + ("+gap" if policy_gap else "")
    return (
        f"  {r.contest_id:>5} │ G_S={r.gt_s:>3} pool={r.n_s_pool:>3} │"
        f" TP={r.tp_s:>3} FP={r.fp_s:>3} FN={r.fn_s:>3} │"
        f" P={P:.3f} R={R:.3f} F1={F:.3f}  (Policy {tag})"
    )


def print_table(
    results: List[ContestResult],
    policy_b: bool = False,
    policy_gap: bool = False,
) -> None:
    sep = "─" * 72

    # ── Track L ───────────────────────────────────────────────────────────────
    gt_fn_contests = {cid for (cid, _), fns in GT_FUNCTIONS.items() if fns}
    fn_note = (
        f"(strict: function match required for {len(gt_fn_contests)} contest(s))"
        if gt_fn_contests
        else "(lenient: SWC match only — GT_FUNCTIONS not populated)"
    )
    print()
    print(f"  ══ TRACK L  (L* bugs) — fn-level, Tier-1 consensus ══")
    print(f"     {fn_note}")
    print(sep)
    for r in results:
        print(_row_l(r))
    print(sep)

    # Aggregate L
    agg_gt_l         = sum(r.gt_l           for r in results)
    agg_tp_l_fn      = sum(r.tp_l_fn        for r in results)
    agg_fp_l_fn      = sum(r.fp_l_fn        for r in results)
    agg_fn_l_fn      = sum(r.fn_l_fn        for r in results)
    agg_pool_l_tier1 = sum(r.n_l_tier1_pool for r in results)
    Pf, Rf, Ff = _f1(agg_tp_l_fn, agg_fp_l_fn, agg_fn_l_fn)
    print(
        f"  {'AGG':>5} │ G_L={agg_gt_l:>3} │"
        f" pool={agg_pool_l_tier1:>3} TP={agg_tp_l_fn:>3} FP={agg_fp_l_fn:>3} FN={agg_fn_l_fn:>3}"
        f" P={Pf:.3f} R={Rf:.3f} F1={Ff:.3f}  ← F1_L_fn"
    )

    # ── Track S ───────────────────────────────────────────────────────────────
    base = "Policy B (SWC→semantic fallback)" if policy_b else "Policy A (semantic_results only; primary)"
    if policy_gap:
        policy_label = base + " + Gap (unvalidated_swc_gaps→S when mapped; sensitivity)"
    else:
        policy_label = base
    print()
    print(f"  ══ TRACK S  (S1–S6 bugs, category-match) — {policy_label} ══")
    print(sep)
    for r in results:
        print(_row_s(r, policy_b, policy_gap))
    print(sep)

    agg_gt_s   = sum(r.gt_s    for r in results)
    agg_tp_s   = sum(r.tp_s    for r in results)
    agg_fp_s   = sum(r.fp_s    for r in results)
    agg_fn_s   = sum(r.fn_s    for r in results)
    agg_pool_s = sum(r.n_s_pool for r in results)
    P, R, F = _f1(agg_tp_s, agg_fp_s, agg_fn_s)
    print(
        f"  {'AGG':>5} │ G_S={agg_gt_s:>3} pool={agg_pool_s:>3} │"
        f" TP={agg_tp_s:>3} FP={agg_fp_s:>3} FN={agg_fn_s:>3} │"
        f" P={P:.3f} R={R:.3f} F1={F:.3f}  ← F1_S (micro)"
    )

    # ── Combined (micro-average across both tracks) ────────────────────────────
    agg_gt_in   = agg_gt_l + agg_gt_s
    agg_tp_comb = agg_tp_l_fn + agg_tp_s
    agg_fp_comb = agg_fp_l_fn + agg_fp_s
    agg_fn_comb = agg_fn_l_fn + agg_fn_s
    P, R, F = _f1(agg_tp_comb, agg_fp_comb, agg_fn_comb)
    agg_oos = sum(r.gt_oos for r in results)
    print()
    print("  ══ COMBINED  (F1_L_fn + F1_S) ══")
    print(
        f"  GT_in-scope={agg_gt_in}  OOS_excluded={agg_oos} │"
        f" TP={agg_tp_comb} FP={agg_fp_comb} FN={agg_fn_comb} │"
        f" P={P:.3f} R={R:.3f} F1={F:.3f}"
    )
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    default_bugs    = str(Path(__file__).parent.parent.parent.parent / "web3bugs" / "results" / "bugs.csv")
    default_results = str(Path(__file__).parent.parent / "results" / "web3bugs_trial")

    parser = argparse.ArgumentParser(description="Evaluate MiroFish on Web3Bugs (two-track)")
    parser.add_argument("--results",  default=default_results, help="Path to web3bugs_trial results dir")
    parser.add_argument("--bugs-csv", default=default_bugs,    help="Path to bugs.csv")
    parser.add_argument("--contest",  type=int, default=None,  help="Evaluate single contest ID")
    parser.add_argument("--policy-b", action="store_true",
                        help="Enable Policy B: allow SWC→semantic fallback for S-track (sensitivity analysis)")
    parser.add_argument("--policy-gap", action="store_true",
                        help="Enable Policy Gap: allow unvalidated_swc_gaps into S-pool when category maps (sensitivity)")
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

        findings = extract_findings(report, policy_b=args.policy_b, policy_gap=args.policy_gap)
        gt_l_n = sum(1 for b in gt_bugs if _label_type(b.label) == "L")
        gt_s_n = sum(1 for b in gt_bugs if _label_type(b.label) == "S")
        gt_oos_n = sum(1 for b in gt_bugs if _label_type(b.label) in ("OOS", "O"))
        l_tier1_pool_n  = sum(1 for f in findings if f.source == "consensus")
        s_pool_n        = sum(1 for f in findings if _in_s_pool(f, args.policy_b, args.policy_gap))

        print(
            f"\n  Contest {cid} │ GT: total={len(gt_bugs)} L={gt_l_n} S={gt_s_n} OOS={gt_oos_n}"
            f" │ Findings: L-pool(T1)={l_tier1_pool_n} S-pool={s_pool_n}"
        )
        if args.verbose:
            print(f"    Report: {report_path}")

        result = evaluate_contest(
            cid, gt_bugs, findings,
            policy_b=args.policy_b, policy_gap=args.policy_gap, verbose=args.verbose,
        )
        all_results.append(result)

    if all_results:
        print_table(all_results, policy_b=args.policy_b, policy_gap=args.policy_gap)
    else:
        print("[WARN] No contests evaluated.")


if __name__ == "__main__":
    main()
