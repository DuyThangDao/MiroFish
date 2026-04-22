"""
Summarize SolidiFI evaluation results.

Usage:
    python summarize_solidifi.py [--results-dir ../results/solidifi_eval]
    python summarize_solidifi.py --csv  # also write summary.csv
"""
import argparse
import json
import os
import sys
from pathlib import Path


def load_results(results_dir: str) -> list[dict]:
    rows = []
    base = Path(results_dir)
    for report_path in sorted(base.rglob("audit_report.json")):
        try:
            with open(report_path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        stats = data.get("stats", {})
        # derive bug_type from parent-of-parent dir name
        # structure: solidifi_eval/<bug_type>/<contract_ts>/audit_report.json
        contract_dir = report_path.parent
        bug_type_dir = contract_dir.parent.name
        rows.append({
            "bug_type": bug_type_dir,
            "contract": contract_dir.name,
            "ground_truth": stats.get("ground_truth", []),
            "detected_swcs": stats.get("detected_swcs", []),
            "tp": stats.get("tp"),
            "fp": stats.get("fp"),
            "fn": stats.get("fn"),
            "precision": stats.get("precision"),
            "recall": stats.get("recall"),
            "f1": stats.get("f1"),
            "duration_s": stats.get("duration_seconds"),
            "critical": stats.get("critical", 0),
            "high": stats.get("high", 0),
        })
    return rows


def _safe(v, fmt=".3f"):
    if v is None:
        return "  N/A "
    return format(float(v), fmt)


def print_summary(rows: list[dict]):
    if not rows:
        print("No results found.")
        return

    # Per-type aggregation
    from collections import defaultdict
    by_type: dict[str, list] = defaultdict(list)
    for r in rows:
        by_type[r["bug_type"]].append(r)

    print("\n" + "=" * 80)
    print(f"SolidiFI Evaluation Summary — {len(rows)} contracts")
    print("=" * 80)
    header = f"{'Bug Type':<22} {'N':>3}  {'TP':>4} {'FP':>4} {'FN':>4}  {'P':>6} {'R':>6} {'F1':>6}  {'AvgDur':>7}"
    print(header)
    print("-" * 80)

    total_tp = total_fp = total_fn = 0
    total_dur = 0
    eval_count = 0

    for bug_type in ["Re_entrancy", "Overflow_Underflow", "Timestamp_Dependency",
                     "TOD", "tx_origin", "Unchecked_Send", "Unhandled_Exceptions"]:
        rs = by_type.get(bug_type, [])
        if not rs:
            continue
        n = len(rs)
        tp = sum(r["tp"] or 0 for r in rs)
        fp = sum(r["fp"] or 0 for r in rs)
        fn = sum(r["fn"] or 0 for r in rs)
        durs = [r["duration_s"] for r in rs if r["duration_s"] is not None]
        avg_dur = sum(durs) / len(durs) if durs else None
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        dur_s = f"{avg_dur/60:.1f}m" if avg_dur else "  N/A"
        print(f"{bug_type:<22} {n:>3}  {tp:>4} {fp:>4} {fn:>4}  {prec:>6.3f} {rec:>6.3f} {f1:>6.3f}  {dur_s:>7}")
        total_tp += tp; total_fp += fp; total_fn += fn
        if avg_dur:
            total_dur += sum(durs); eval_count += len(durs)

    print("-" * 80)
    p_all = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    r_all = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    f1_all = 2 * p_all * r_all / (p_all + r_all) if (p_all + r_all) > 0 else 0.0
    avg_dur_all = total_dur / eval_count if eval_count else None
    dur_s = f"{avg_dur_all/60:.1f}m" if avg_dur_all else "  N/A"
    print(f"{'TOTAL':<22} {len(rows):>3}  {total_tp:>4} {total_fp:>4} {total_fn:>4}  {p_all:>6.3f} {r_all:>6.3f} {f1_all:>6.3f}  {dur_s:>7}")
    print("=" * 80)

    # Contracts without eval metrics
    no_eval = [r for r in rows if r["tp"] is None]
    if no_eval:
        print(f"\n  {len(no_eval)} contracts without eval metrics (no ground truth or failed):")
        for r in no_eval[:10]:
            print(f"    {r['bug_type']}/{r['contract']}")
        if len(no_eval) > 10:
            print(f"    ... and {len(no_eval)-10} more")


def write_csv(rows: list[dict], path: str):
    import csv
    fields = ["bug_type", "contract", "ground_truth", "detected_swcs",
              "tp", "fp", "fn", "precision", "recall", "f1", "duration_s", "critical", "high"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            row = dict(r)
            row["ground_truth"] = "|".join(r.get("ground_truth") or [])
            row["detected_swcs"] = "|".join(r.get("detected_swcs") or [])
            w.writerow(row)
    print(f"\nCSV saved: {path}")


def main():
    parser = argparse.ArgumentParser(description="Summarize SolidiFI evaluation results")
    parser.add_argument("--results-dir", default=None,
                        help="Path to solidifi_eval results dir")
    parser.add_argument("--csv", action="store_true",
                        help="Also write summary.csv")
    args = parser.parse_args()

    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    default_results = os.path.join(scripts_dir, "..", "results", "solidifi_eval")
    results_dir = args.results_dir or default_results

    if not os.path.isdir(results_dir):
        print(f"Results directory not found: {results_dir}")
        sys.exit(1)

    rows = load_results(results_dir)
    print_summary(rows)

    if args.csv:
        csv_path = os.path.join(results_dir, "summary.csv")
        write_csv(rows, csv_path)


if __name__ == "__main__":
    main()
