"""
Run LLMSmartAudit (SmartContractTA config) on web3bugs benchmark contests.

For each GT contract in a contest:
  1. Locate the .sol file under contracts_dir
  2. Run LLMSmartAudit with SmartContractTA (40 targeted detectors)
  3. Parse WareHouse log → extract structured findings
  4. Save to benchmark/web3bugs/llmsmartaudit-ta/<contest_id>/

Usage:
    cd /home/thangdd/repos/MiroFish/backend
    source .venv/bin/activate
    python scripts/run_llmsmartaudit_benchmark.py --contest-id 104
    python scripts/run_llmsmartaudit_benchmark.py --all --workers 4

Output:
    benchmark/web3bugs/llmsmartaudit-ta/<id>/findings_<Contract>.json   (per-contract)
    benchmark/web3bugs/llmsmartaudit-ta/<id>/findings_all.json          (aggregated)

Requirements:
    LLM1_VERTEX_AI_KEY_FILE + LLM1_BASE_URL (through LLM4) in .env
    Workers run in parallel, each contract on a different key (round-robin LLM1-4).
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB3BUGS_ROOT = Path("/home/thangdd/repos/web3bugs/contracts")
LLMSA_ROOT = REPO_ROOT / "LLMSmartAudit"
WAREHOUSE_DIR = LLMSA_ROOT / "WareHouse"
LLMSA_PYTHON = REPO_ROOT / "backend/.venv/bin/python"
OUT_ROOT = REPO_ROOT / "benchmark/web3bugs/llmsmartaudit-ta"
BENCHMARK_JSON = REPO_ROOT / "benchmark/benchmark_contests.json"


# ── Load .env ─────────────────────────────────────────────────────────────────
def load_env(path: Path) -> dict:
    env = {}
    if not path.exists():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip()
    return env

ENV_VARS = load_env(REPO_ROOT / ".env")

# ── Round-robin Vertex AI key pool (LLM1–LLM4) ────────────────────────────────
_KEY_SLOTS = [
    ("LLM_VERTEX_AI_KEY_FILE",  "LLM_BASE_URL"),
    ("LLM2_VERTEX_AI_KEY_FILE", "LLM2_BASE_URL"),
    ("LLM3_VERTEX_AI_KEY_FILE", "LLM3_BASE_URL"),
    ("LLM4_VERTEX_AI_KEY_FILE", "LLM4_BASE_URL"),
]

VERTEX_KEYS: list[tuple[str, str]] = []
for kf_var, bu_var in _KEY_SLOTS:
    kf = ENV_VARS.get(kf_var)
    bu = ENV_VARS.get(bu_var) or ENV_VARS.get("LLM_BASE_URL")
    if kf and bu:
        VERTEX_KEYS.append((kf, bu))

# ── Contest config (from benchmark_contests.json) ─────────────────────────────
def load_contest_configs() -> dict:
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

CONTEST_CONFIG = load_contest_configs()


# ── Build subprocess env for a specific key slot ──────────────────────────────
def build_env(key_file: str, base_url: str) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(LLMSA_ROOT)
    # model_backend reads VERTEX_AI_KEY_FILE and VERTEX_BASE_URL
    env["VERTEX_AI_KEY_FILE"] = key_file
    env["VERTEX_BASE_URL"] = base_url
    return env


# ── Find .sol file for a contract name ────────────────────────────────────────
def find_sol_file(contract_name: str, contracts_dir: Path) -> Path | None:
    """Search recursively for <ContractName>.sol under contracts_dir."""
    matches = list(contracts_dir.rglob(f"{contract_name}.sol"))
    if not matches:
        return None
    # Prefer shortest path (closest to root = least nested)
    return sorted(matches, key=lambda p: len(p.parts))[0]


# ── Parse WareHouse log for findings ──────────────────────────────────────────
# SmartContractTA format in log:
#   VULNERABILITY NAME
#   '''
#   DESCRIPTION
#   '''
#   ...
#   <INFO> XXX Identified.
#
# or: <INFO> NO XXX.
#
# We extract all vulnerability blocks (triple-single-quote delimited) from logs
# where an <INFO> Identified. line follows within the same agent turn.

_VULN_BLOCK_RE = re.compile(
    r"([A-Z][A-Z 0-9_\-/()]+)\s*\n\s*'''\s*\n(.*?)\n\s*'''",
    re.DOTALL,
)

_INFO_FOUND_RE = re.compile(
    r"<INFO>\s*(.+?(?:Identified|Found|Detected|Vulnerability|Vulnerable)[^<\n]*)",
    re.IGNORECASE,
)

_INFO_NONE_RE = re.compile(
    r"<INFO>\s*No\s+\w",
    re.IGNORECASE,
)

# Phase name from log header: "execute SimplePhase:[XxxDetector]"
_PHASE_RE = re.compile(r"execute SimplePhase:\[(\w+)\]")


def parse_log(log_path: Path, contract_name: str) -> list[dict]:
    """Parse SmartContractTA WareHouse log → list of finding dicts."""
    if not log_path.exists():
        return []

    text = log_path.read_text(encoding="utf-8", errors="replace")

    # Split into phase segments by the "execute SimplePhase" markers
    segments = []
    phase_positions = [(m.start(), m.group(1)) for m in _PHASE_RE.finditer(text)]

    for i, (pos, phase_name) in enumerate(phase_positions):
        end = phase_positions[i + 1][0] if i + 1 < len(phase_positions) else len(text)
        segments.append((phase_name, text[pos:end]))

    findings = []
    for phase_name, segment in segments:
        # Skip if no "Identified" in this segment
        if not _INFO_FOUND_RE.search(segment):
            continue

        # Extract all vulnerability blocks
        for m in _VULN_BLOCK_RE.finditer(segment):
            vuln_name = m.group(1).strip()
            description = m.group(2).strip()

            # Try to extract function name from description
            fn_match = re.search(
                r"`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", description
            )
            function_name = fn_match.group(1) if fn_match else None

            findings.append({
                "contract_name": contract_name,
                "detector_phase": phase_name,
                "vulnerability_name": vuln_name,
                "function_name": function_name,
                "description": description[:600],  # truncate for JSON
            })

    return findings


# ── Run LLMSmartAudit for one contract ────────────────────────────────────────
def run_one_contract(
    contract_name: str,
    sol_file: Path,
    run_name: str,
    key_file: str,
    base_url: str,
    log_path: Path,
) -> tuple[bool, Path | None]:
    """
    Run LLMSmartAudit on a single .sol file.
    Returns (success, warehouse_log_path).
    """
    env = build_env(key_file, base_url)
    cmd = [
        str(LLMSA_PYTHON),
        str(LLMSA_ROOT / "run.py"),
        "--config", "SmartContractTA",
        "--org", "Benchmark",
        "--model", "GEMINI_FLASH_PREVIEW",
        "--task-file", str(sol_file),
        "--name", run_name,
    ]
    key_label = Path(key_file).stem
    print(f"  [start] {contract_name} (key={key_label})")

    fout = open(log_path, "w")
    try:
        result = subprocess.run(
            cmd,
            cwd=str(LLMSA_ROOT),
            env=env,
            stdout=fout,
            stderr=fout,
            timeout=3600,  # 1h per contract
        )
    except subprocess.TimeoutExpired:
        fout.close()
        print(f"    TIMEOUT after 3600s")
        return False, None
    finally:
        fout.close()

    if result.returncode != 0:
        print(f"    ERROR: exit code {result.returncode}")
        return False, None

    # Find WareHouse log: either directly in WareHouse/ or inside a subdirectory
    # LLMSmartAudit creates WareHouse/<run_name>_Benchmark_<ts>/<run_name>_Benchmark_<ts>.log
    logs = sorted(WAREHOUSE_DIR.rglob(f"{run_name}_Benchmark_*.log"), key=lambda p: p.stat().st_mtime)
    if not logs:
        print(f"    ERROR: No WareHouse log found for {run_name}")
        return False, None

    return True, logs[-1]


# ── Process one contract (worker function) ─────────────────────────────────────
def _process_one(contest_id: str, contract_name: str, contracts_dir: Path,
                 out_dir: Path, key_file: str, base_url: str) -> dict:
    sol_file = find_sol_file(contract_name, contracts_dir)
    if not sol_file:
        print(f"  [skip] {contract_name}: .sol not found under {contracts_dir}")
        return {"contract_name": contract_name, "status": "sol_not_found", "findings": []}

    run_name = f"c{contest_id}_{contract_name}"
    console_log = out_dir / f"console_{contract_name}.log"
    warehouse_log = out_dir / f"warehouse_{contract_name}.log"

    t0 = time.time()
    ok, wh_log = run_one_contract(contract_name, sol_file, run_name, key_file, base_url, console_log)
    elapsed = time.time() - t0

    if not ok:
        print(f"  [fail] {contract_name} in {elapsed:.0f}s")
        return {"contract_name": contract_name, "status": "run_failed", "findings": []}

    if wh_log and wh_log.exists():
        warehouse_log.write_bytes(wh_log.read_bytes())

    findings = parse_log(wh_log, contract_name) if wh_log else []
    print(f"  [done] {contract_name}: {len(findings)} findings in {elapsed:.0f}s (key={Path(key_file).stem})")

    per_contract = {
        "contest_id": contest_id,
        "contract_name": contract_name,
        "sol_file": str(sol_file),
        "warehouse_log": str(wh_log) if wh_log else None,
        "elapsed_s": round(elapsed),
        "total_findings": len(findings),
        "findings": findings,
    }
    (out_dir / f"findings_{contract_name}.json").write_text(
        json.dumps(per_contract, indent=2, ensure_ascii=False)
    )
    return {"contract_name": contract_name, "status": "ok",
            "findings_count": len(findings), "findings": findings}


# ── Process one contest ────────────────────────────────────────────────────────
def process_contest(contest_id: str, workers: int = 4) -> dict:
    cfg = CONTEST_CONFIG[contest_id]
    n_keys = len(VERTEX_KEYS)
    actual_workers = min(workers, len(cfg["gt_contracts"]), n_keys)
    print(f"\n{'='*60}")
    print(f"Contest {contest_id}: {cfg['name']}")
    print(f"GT contracts: {cfg['gt_contracts']}")
    print(f"Workers: {actual_workers}  Keys: {n_keys}")
    print(f"{'='*60}")

    contracts_dir = cfg["contracts_dir"]
    if not contracts_dir.exists():
        print(f"  ERROR: contracts_dir not found: {contracts_dir}")
        return {"contest_id": contest_id, "error": "contracts_dir not found"}

    out_dir = OUT_ROOT / contest_id
    out_dir.mkdir(parents=True, exist_ok=True)

    all_findings = []
    contract_results = []

    with ThreadPoolExecutor(max_workers=actual_workers) as ex:
        futures = {}
        for i, contract_name in enumerate(cfg["gt_contracts"]):
            key_file, base_url = VERTEX_KEYS[i % n_keys]
            fut = ex.submit(_process_one, contest_id, contract_name,
                            contracts_dir, out_dir, key_file, base_url)
            futures[fut] = contract_name

        for fut in as_completed(futures):
            result = fut.result()
            all_findings.extend(result.get("findings", []))
            contract_results.append({k: v for k, v in result.items() if k != "findings"})

    # Aggregate
    by_phase = {}
    for f in all_findings:
        p = f["detector_phase"]
        by_phase[p] = by_phase.get(p, 0) + 1

    summary = {
        "contest_id": contest_id,
        "name": cfg["name"],
        "gt_contracts": cfg["gt_contracts"],
        "contracts": contract_results,
        "total_findings": len(all_findings),
        "by_phase": by_phase,
        "findings": all_findings,
    }
    (out_dir / "findings_all.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False)
    )
    print(f"\n  Saved {len(all_findings)} total findings → {out_dir}/findings_all.json")
    return summary


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Run LLMSmartAudit benchmark on web3bugs contests"
    )
    parser.add_argument("--contest-id", help="Single contest (e.g. 104)")
    parser.add_argument("--all", action="store_true", help="All contests")
    parser.add_argument("--workers", type=int, default=4, help="Parallel workers (default 4)")
    args = parser.parse_args()

    if not args.contest_id and not args.all:
        parser.print_help()
        sys.exit(1)

    if not LLMSA_PYTHON.exists():
        print(f"ERROR: venv python not found at {LLMSA_PYTHON}")
        sys.exit(1)

    if not VERTEX_KEYS:
        print("ERROR: no Vertex AI keys found in .env (need LLM_VERTEX_AI_KEY_FILE or LLM2..LLM4)")
        sys.exit(1)

    print(f"Loaded {len(VERTEX_KEYS)} Vertex AI keys: {[Path(k).stem for k, _ in VERTEX_KEYS]}")

    target_ids = list(CONTEST_CONFIG.keys()) if args.all else [args.contest_id]

    for cid in target_ids:
        if cid not in CONTEST_CONFIG:
            print(f"Unknown contest_id: {cid}. Available: {sorted(CONTEST_CONFIG)}")
            continue
        result = process_contest(cid, workers=args.workers)
        print(f"\nContest {cid} done: {result.get('total_findings', 'ERROR')} findings total")

    print("\nAll done.")


if __name__ == "__main__":
    main()
