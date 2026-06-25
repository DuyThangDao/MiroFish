"""
Run GPTScan on all 9 benchmark contests and filter findings to GT contracts only.

Usage:
    cd /home/thangdd/repos/MiroFish/backend
    source .venv/bin/activate
    python scripts/run_gptscan_benchmark.py --contest-id 5
    python scripts/run_gptscan_benchmark.py --all

Output:
    benchmark/web3bugs/gptscan/<contest_id>/gptscan_findings_filtered.json

Requirements:
    - LLM5_VERTEX_AI_KEY_FILE and LLM5_BASE_URL must be set in .env (MiroFish root)
    - GPTScan venv at GPTScan/.venv must be set up
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB3BUGS_ROOT = Path("/home/thangdd/repos/web3bugs/contracts")
GPTSCAN_SRC = REPO_ROOT / "GPTScan/src"
GPTSCAN_PYTHON = REPO_ROOT / "GPTScan/.venv/bin/python"
OUT_ROOT = REPO_ROOT / "benchmark/web3bugs/gptscan"
BENCHMARK_JSON = REPO_ROOT / "benchmark/benchmark_contests.json"

# Load .env from repo root
def load_env(env_path: Path) -> dict:
    env = {}
    if not env_path.exists():
        return env
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip()
    return env

ENV_VARS = load_env(REPO_ROOT / ".env")

# Load contest config from benchmark_contests.json (single source of truth)
def _load_contest_config() -> dict:
    data = json.loads(BENCHMARK_JSON.read_text())
    configs = {}
    for entry in data["contests"]:
        cid = str(entry["contest_id"])
        configs[cid] = {
            "name": entry.get("name", f"Contest {cid}"),
            "contracts_dir": Path(entry["contracts_dir"]),
            "gt_contracts": entry["gt_contracts"],
        }
    return configs

CONTEST_CONFIG = _load_contest_config()


def build_env(base_env: dict) -> dict:
    """Build subprocess env: inherit current env + LLM5 vertex vars from .env."""
    env = os.environ.copy()
    for key in ("LLM5_VERTEX_AI_KEY_FILE", "LLM5_BASE_URL"):
        if key in base_env:
            env[key] = base_env[key]
    return env


def extract_contract_name(file_path: str) -> str:
    """Extract contract name from file path: /abs/path/Vault.sol -> Vault"""
    return Path(file_path).stem


def normalize_findings(raw_json: dict, gt_contracts: list, contracts_dir: Path) -> list:
    """
    Filter GPTScan results to GT contracts only and normalize format.

    Each result entry:
      {
        "code": "rule-name",
        "title": "...",
        "contract_name": "Vault",
        "function_a_file": "/abs/path/Vault.sol",
        "function_a_start": 42,
        "function_a_end": 58,
        "function_b_file": null or "/abs/path/...",
        "function_b_start": null or N,
        "function_b_end": null or N,
        "description": "...",
      }
    """
    gt_lower = {c.lower() for c in gt_contracts}
    results = []

    for item in raw_json.get("results", []):
        affected = item.get("affectedFiles", [])
        if not affected:
            continue

        file_a = affected[0].get("filePath", "")
        contract_a = extract_contract_name(file_a)

        # Filter: primary contract must be in GT contracts
        if contract_a.lower() not in gt_lower:
            continue

        entry = {
            "code": item.get("code", ""),
            "title": item.get("title", ""),
            "description": item.get("description", ""),
            "contract_name": contract_a,
            "function_a_file": file_a,
            "function_a_start": affected[0].get("range", {}).get("start", {}).get("line"),
            "function_a_end": affected[0].get("range", {}).get("end", {}).get("line"),
            "function_b_file": None,
            "function_b_start": None,
            "function_b_end": None,
            "function_b_contract": None,
        }

        if len(affected) > 1:
            file_b = affected[1].get("filePath", "")
            entry["function_b_file"] = file_b
            entry["function_b_contract"] = extract_contract_name(file_b)
            entry["function_b_start"] = affected[1].get("range", {}).get("start", {}).get("line")
            entry["function_b_end"] = affected[1].get("range", {}).get("end", {}).get("line")

        results.append(entry)

    return results


def run_gptscan(contracts_dir: Path, out_json: Path, env: dict, log_file: Path = None) -> bool:
    """Run GPTScan as subprocess from GPTScan/src directory."""
    cmd = [
        str(GPTSCAN_PYTHON), "main.py",
        "-s", str(contracts_dir),
        "-o", str(out_json),
        "-k", "dummy",   # ignored; Vertex AI uses env var auth
    ]
    print(f"  Running: {' '.join(cmd)}")
    print(f"  CWD: {GPTSCAN_SRC}")
    print(f"  VERTEX_KEY: {env.get('LLM5_VERTEX_AI_KEY_FILE', '(not set)')}")
    if log_file:
        print(f"  Console log: {log_file}")

    # Stream output to log file (Rich console output is visible in real-time)
    fout = open(log_file, "w") if log_file else subprocess.DEVNULL
    try:
        result = subprocess.run(
            cmd,
            cwd=str(GPTSCAN_SRC),
            env=env,
            stdout=fout,
            stderr=fout,
            timeout=7200,  # 2h max per contest
        )
    finally:
        if log_file:
            fout.close()

    if result.returncode != 0:
        print(f"  ERROR: GPTScan exited {result.returncode}")
        return False

    if not out_json.exists():
        print(f"  ERROR: output file not created")
        return False

    return True


def process_contest(contest_id: str) -> dict:
    cfg = CONTEST_CONFIG[contest_id]
    print(f"\n{'='*60}")
    print(f"Contest {contest_id}: {cfg['name']}")
    print(f"{'='*60}")

    contracts_dir = cfg["contracts_dir"]
    if not contracts_dir.exists():
        print(f"  ERROR: contracts_dir not found: {contracts_dir}")
        return {"contest_id": contest_id, "error": "contracts_dir not found"}

    out_dir = OUT_ROOT / contest_id
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_json_path = out_dir / "gptscan_raw.json"
    log_path = out_dir / "gptscan_console.log"
    env = build_env(ENV_VARS)

    ok = run_gptscan(contracts_dir, raw_json_path, env, log_file=log_path)
    if not ok:
        return {"contest_id": contest_id, "error": "gptscan failed"}

    raw = json.load(open(raw_json_path))
    total_raw = len(raw.get("results", []))
    print(f"  Raw findings: {total_raw}")

    filtered = normalize_findings(raw, cfg["gt_contracts"], contracts_dir)
    print(f"  Filtered findings (GT contracts only): {len(filtered)}")

    # Count by rule
    by_rule = {}
    for f in filtered:
        by_rule[f["code"]] = by_rule.get(f["code"], 0) + 1

    output = {
        "contest_id": contest_id,
        "name": cfg["name"],
        "gt_contracts": cfg["gt_contracts"],
        "total_raw": total_raw,
        "total_findings": len(filtered),
        "by_rule": by_rule,
        "findings": filtered,
    }

    out_file = out_dir / "gptscan_findings_filtered.json"
    json.dump(output, open(out_file, "w"), indent=2)
    print(f"  Saved {len(filtered)} findings → {out_file}")
    return output


def main():
    parser = argparse.ArgumentParser(description="Run GPTScan benchmark on web3bugs contests")
    parser.add_argument("--contest-id", help="Run single contest (e.g. 5)")
    parser.add_argument("--all", action="store_true", help="Run all 9 contests")
    args = parser.parse_args()

    if not args.contest_id and not args.all:
        parser.print_help()
        sys.exit(1)

    if not GPTSCAN_PYTHON.exists():
        print(f"ERROR: GPTScan venv python not found at {GPTSCAN_PYTHON}")
        sys.exit(1)

    missing_keys = [k for k in ("LLM5_VERTEX_AI_KEY_FILE", "LLM5_BASE_URL") if k not in ENV_VARS]
    if missing_keys:
        print(f"ERROR: missing env vars in .env: {missing_keys}")
        sys.exit(1)

    target_ids = list(CONTEST_CONFIG.keys()) if args.all else [args.contest_id]

    for cid in target_ids:
        if cid not in CONTEST_CONFIG:
            print(f"Unknown contest_id: {cid}. Available: {list(CONTEST_CONFIG.keys())}")
            continue
        result = process_contest(cid)
        total = result.get("total_findings", "ERROR")
        print(f"\nContest {cid} done: {total} filtered findings")

    print("\nAll done.")


if __name__ == "__main__":
    main()
