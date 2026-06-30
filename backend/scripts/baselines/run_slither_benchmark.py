"""
Run Slither on all 9 benchmark contests and filter findings to GT contracts only.

Usage:
    cd /home/thangdd/repos/MiroFish/backend
    source .venv/bin/activate
    python scripts/run_slither_benchmark.py [--contest-id 5] [--all]

Output:
    benchmark/web3bugs/slither/<contest_id>/slither_findings_filtered.json
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
WEB3BUGS_ROOT = Path("/home/thangdd/repos/web3bugs/contracts")
OUT_ROOT = REPO_ROOT / "benchmark/web3bugs/slither"

# Per-contest Slither run config
# run_dirs: list of (directory_to_run_slither_from, label)
# gt_contracts: from benchmark_contests.json
CONTEST_CONFIG = {
    "5": {
        "name": "Vader Protocol",
        "run_dirs": [(WEB3BUGS_ROOT / "5", "root")],
        "gt_contracts": ["Pools", "Router", "USDV", "Utils", "Vader", "Vault", "Vether"],
        "needs_npm": False,  # node_modules already exists
    },
    "35": {
        "name": "Trident (Sushi)",
        "run_dirs": [(WEB3BUGS_ROOT / "35/trident", "trident")],
        "gt_contracts": ["ConcentratedLiquidityPool", "TridentRouter", "HybridPool",
                         "ConstantProductPool", "Ticks", "DyDxMath"],
        "needs_npm": False,
    },
    "42": {
        "name": "Mochi",
        "run_dirs": [(WEB3BUGS_ROOT / "42/projects/mochi-core", "mochi-core")],
        "gt_contracts": ["MochiVault", "MochiProfileV0", "ReferralFeePoolV0",
                         "FeePoolV0", "MochiEngine", "MochiTreasuryV0", "VestedRewardPool"],
        "needs_npm": False,
    },
    "104": {
        "name": "Joyn",
        "run_dirs": [
            (WEB3BUGS_ROOT / "104/core-contracts", "core-contracts"),
            (WEB3BUGS_ROOT / "104/royalty-vault", "royalty-vault"),
            (WEB3BUGS_ROOT / "104/splits", "splits"),
        ],
        "gt_contracts": ["ChestV1", "RoyaltyVault", "Splits"],
        "needs_npm": False,
    },
    "71": {
        "name": "Insure Protocol",
        "run_dirs": [(WEB3BUGS_ROOT / "71", "root")],
        "gt_contracts": ["Vault", "PoolTemplate", "IndexTemplate", "Factory"],
        "needs_npm": True,
    },
    "83": {
        "name": "Concur Finance",
        "run_dirs": [(WEB3BUGS_ROOT / "83", "root")],
        "gt_contracts": ["ConcurRewardPool", "MasterChef", "Shelter", "VoteProxy", "ConvexStakingWrapper"],
        "needs_npm": True,
    },
    "30": {
        "name": "yAxis",
        "run_dirs": [(WEB3BUGS_ROOT / "30", "root")],
        "gt_contracts": ["Controller", "LegacyController", "Manager", "MetaVault",
                         "NativeStrategyCurve3Crv", "StrategyControllerV2", "Vault"],
        "needs_npm": True,
    },
    "3": {
        "name": "MarginSwap",
        "run_dirs": [(WEB3BUGS_ROOT / "3", "root")],
        "gt_contracts": ["MarginRouter", "PriceAware", "BaseLending", "CrossMarginTrading",
                         "CrossMarginAccounts", "IncentiveDistribution", "Lending"],
        "needs_npm": False,
        "target": "contracts/",
        "extra_args": [
            "--solc-remaps",
            f"@openzeppelin={WEB3BUGS_ROOT}/3/node_modules/@openzeppelin @uniswap={WEB3BUGS_ROOT}/3/node_modules/@uniswap",
            "--compile-force-framework", "solc",
        ],
    },
    "61": {
        "name": "Sublime Finance",
        "run_dirs": [(WEB3BUGS_ROOT / "61", "root")],
        "gt_contracts": ["CreditLine", "SavingsAccountUtil", "YearnYield",
                         "AaveYield", "SavingsAccount", "PriceOracle", "NoYield"],
        "needs_npm": True,
    },
}


def check_npm(run_dir: Path) -> bool:
    return (run_dir / "node_modules").exists()


def run_slither(run_dir: Path, out_json: Path, extra_args: list = None, target: str = ".") -> bool:
    cmd = ["slither", target, "--json", str(out_json)]
    if extra_args:
        cmd.extend(extra_args)

    print(f"  Running: {' '.join(cmd)}")
    print(f"  CWD: {run_dir}")

    result = subprocess.run(
        cmd, cwd=str(run_dir),
        capture_output=True, text=True, timeout=300,
    )
    # Slither exits 0 (no findings), 1 (findings found), 255 (findings + warnings) — all OK
    # Only fail on truly fatal exits (segfault, etc.)
    if result.returncode not in (0, 1, 255):
        print(f"  ERROR: slither exited {result.returncode}")
        print(result.stderr[-500:] if result.stderr else "")
        return False
    if not out_json.exists():
        print(f"  ERROR: output file not created")
        print(result.stderr[-500:] if result.stderr else "")
        return False
    return True


def normalize_finding(det: dict, gt_contracts: list) -> list:
    """
    Expand a Slither detector result into per-element findings filtered to GT contracts.
    Returns list of normalized finding dicts.
    """
    gt_lower = [c.lower() for c in gt_contracts]
    results = []

    for element in det.get("elements", []):
        # Extract contract and function names
        contract_name = ""
        function_name = ""

        if element.get("type") == "function":
            type_fields = element.get("type_specific_fields", {})
            parent = type_fields.get("parent", {})
            contract_name = parent.get("name", "")
            function_name = element.get("name", "")
        elif element.get("type") == "contract":
            contract_name = element.get("name", "")
        elif element.get("type") in ("node", "variable"):
            type_fields = element.get("type_specific_fields", {})
            parent = type_fields.get("parent", {})
            if isinstance(parent, dict):
                if parent.get("type") == "function":
                    function_name = parent.get("name", "")
                    gp = parent.get("type_specific_fields", {}).get("parent", {})
                    contract_name = gp.get("name", "") if isinstance(gp, dict) else ""
                elif parent.get("type") == "contract":
                    contract_name = parent.get("name", "")

        if not contract_name:
            continue

        # Filter: only keep if contract matches a GT contract
        if contract_name.lower() not in gt_lower:
            continue

        src = element.get("source_mapping", {})
        results.append({
            "check": det.get("check", ""),
            "impact": det.get("impact", ""),
            "confidence": det.get("confidence", ""),
            "title": f"[{det.get('check','')}] {contract_name}.{function_name}",
            "description": det.get("description", "").strip(),
            "contract_name": contract_name,
            "function_name": function_name,
            "source_file": src.get("filename_relative", ""),
            "source_lines": src.get("lines", []),
        })

    return results


def process_contest(contest_id: str) -> dict:
    cfg = CONTEST_CONFIG[contest_id]
    print(f"\n{'='*60}")
    print(f"Contest {contest_id}: {cfg['name']}")
    print(f"{'='*60}")

    out_dir = OUT_ROOT / contest_id
    out_dir.mkdir(parents=True, exist_ok=True)

    all_findings = []

    for run_dir, label in cfg["run_dirs"]:
        print(f"\n  [dir={label}] {run_dir}")

        if not run_dir.exists():
            print(f"  SKIP: directory not found")
            continue

        if cfg.get("needs_npm") and not check_npm(run_dir):
            print(f"  WARNING: node_modules missing — run `npm install` in {run_dir} first")
            print(f"  Attempting anyway (may fail to compile)...")

        out_json = out_dir / f"slither_raw_{label}.json"
        extra = cfg.get("extra_args", [])
        target = cfg.get("target", ".")

        ok = run_slither(run_dir, out_json, extra, target=target)
        if not ok:
            print(f"  FAILED: skipping {label}")
            continue

        raw = json.load(open(out_json))
        if not raw.get("success") and not raw.get("results"):
            print(f"  WARN: slither reported failure but checking results anyway")

        detectors = (raw.get("results") or {}).get("detectors", [])
        print(f"  Raw detector hits: {len(detectors)}")

        for det in detectors:
            findings = normalize_finding(det, cfg["gt_contracts"])
            all_findings.extend(findings)

        print(f"  Filtered findings (GT contracts only): "
              f"{sum(1 for d in detectors for _ in normalize_finding(d, cfg['gt_contracts']))}")

    # Deduplicate by (check, contract, function, description)
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f["check"], f["contract_name"], f["function_name"], f["description"][:100])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    output = {
        "contest_id": contest_id,
        "name": cfg["name"],
        "gt_contracts": cfg["gt_contracts"],
        "total_findings": len(deduped),
        "findings": deduped,
    }

    out_file = out_dir / "slither_findings_filtered.json"
    json.dump(output, open(out_file, "w"), indent=2)
    print(f"\n  Saved {len(deduped)} findings → {out_file}")
    return output


def main():
    parser = argparse.ArgumentParser(description="Run Slither benchmark on web3bugs contests")
    parser.add_argument("--contest-id", help="Run single contest (e.g. 5)")
    parser.add_argument("--all", action="store_true", help="Run all 9 contests")
    args = parser.parse_args()

    if not args.contest_id and not args.all:
        parser.print_help()
        sys.exit(1)

    target_ids = list(CONTEST_CONFIG.keys()) if args.all else [args.contest_id]

    for cid in target_ids:
        if cid not in CONTEST_CONFIG:
            print(f"Unknown contest_id: {cid}. Available: {list(CONTEST_CONFIG.keys())}")
            continue
        result = process_contest(cid)
        print(f"\nContest {cid} done: {result['total_findings']} filtered findings")

    print("\nAll done.")


if __name__ == "__main__":
    main()
