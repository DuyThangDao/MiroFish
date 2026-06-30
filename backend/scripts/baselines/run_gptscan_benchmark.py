"""
Run GPTScan on web3bugs benchmark contests with parallel workers.
Each worker uses a different Vertex AI key (round-robin LLM1–LLM4).

Output: benchmark/web3bugs/gptscan/<contest_id>/
  findings_<Contract>.json   per-contract result
  findings_all.json          aggregated

Usage:
    cd /home/thangdd/repos/MiroFish/backend
    source .venv/bin/activate
    python scripts/run_gptscan_benchmark.py --contest-id 35
    python scripts/run_gptscan_benchmark.py --all --workers 4
"""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT      = Path(__file__).resolve().parents[2]
GPTSCAN_ROOT   = REPO_ROOT / "GPTScan/src"
VENV_PYTHON    = REPO_ROOT / "backend/.venv/bin/python"
BENCHMARK_JSON = REPO_ROOT / "benchmark/benchmark_contests.json"
OUT_ROOT       = REPO_ROOT / "benchmark/web3bugs/gptscan"


# ── Load .env ─────────────────────────────────────────────────────────────────
def _load_env(path: Path) -> dict:
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

_ENV = _load_env(REPO_ROOT / ".env")

# Round-robin across LLM1–LLM4 keys
# LLM1 uses LLM_VERTEX_AI_KEY_FILE / LLM_BASE_URL
# LLM2–4 use LLM{N}_VERTEX_AI_KEY_FILE / LLM{N}_BASE_URL
_KEY_SLOTS = [
    ("LLM_VERTEX_AI_KEY_FILE",  "LLM_BASE_URL"),
    ("LLM2_VERTEX_AI_KEY_FILE", "LLM2_BASE_URL"),
    ("LLM3_VERTEX_AI_KEY_FILE", "LLM3_BASE_URL"),
    ("LLM4_VERTEX_AI_KEY_FILE", "LLM4_BASE_URL"),
]

VERTEX_KEYS: list = []
for kf_var, bu_var in _KEY_SLOTS:
    kf = _ENV.get(kf_var)
    bu = _ENV.get(bu_var) or _ENV.get("LLM_BASE_URL")
    if kf and bu:
        VERTEX_KEYS.append((kf, bu))


# ── Per-file runner ────────────────────────────────────────────────────────────
def _run_one(contract_name: str, sol_file: Path, out_dir: Path, key_file: str, base_url: str) -> dict:
    output_file = out_dir / f"findings_{contract_name}.json"
    log_file    = out_dir / f"{contract_name}.log"

    with tempfile.TemporaryDirectory(prefix=f"gptscan_{contract_name}_") as tmpdir:
        shutil.copy(sol_file, tmpdir)

        env = os.environ.copy()
        env["PYTHONPATH"]         = str(GPTSCAN_ROOT)
        env["VERTEX_AI_KEY_FILE"] = key_file
        env["VERTEX_BASE_URL"]    = base_url

        cmd = [
            str(VENV_PYTHON), str(GPTSCAN_ROOT / "main.py"),
            "-s", tmpdir,
            "-o", str(output_file),
        ]

        try:
            with open(log_file, "w") as lf:
                result = subprocess.run(
                    cmd, env=env, stdout=lf, stderr=subprocess.STDOUT,
                    cwd=str(GPTSCAN_ROOT), timeout=900,
                )
            if output_file.exists():
                data = json.loads(output_file.read_text())
                n = len(data.get("results", []))
                print(f"  [done] {contract_name}: {n} findings (key={Path(key_file).stem})")
                return {"contract": contract_name, "status": "ok", "findings": data.get("results", []), "raw": data}
            else:
                print(f"  [warn] {contract_name}: no output (rc={result.returncode})")
                return {"contract": contract_name, "status": "no_output", "findings": []}
        except subprocess.TimeoutExpired:
            print(f"  [timeout] {contract_name}")
            return {"contract": contract_name, "status": "timeout", "findings": []}
        except Exception as e:
            print(f"  [error] {contract_name}: {e}")
            return {"contract": contract_name, "status": "error", "error": str(e), "findings": []}


# ── Contest runner ─────────────────────────────────────────────────────────────
def process_contest(contest_id: str, workers: int = 4) -> list:
    contests = json.loads(BENCHMARK_JSON.read_text())["contests"]
    entry = next((x for x in contests if str(x["contest_id"]) == contest_id), None)
    if not entry:
        raise ValueError(f"Contest {contest_id} not found in benchmark_contests.json")

    contracts_dir = Path(entry["contracts_dir"])
    gt_contracts  = entry["gt_contracts"]
    out_dir = OUT_ROOT / contest_id
    out_dir.mkdir(parents=True, exist_ok=True)

    contest_root = Path("/home/thangdd/repos/web3bugs/contracts") / contest_id
    sol_files = []
    for name in gt_contracts:
        sol = contracts_dir / f"{name}.sol"
        if not sol.exists():
            # Fallback: recursive search in contest root
            hits = list(contest_root.rglob(f"{name}.sol"))
            # Prefer non-artifacts paths
            hits = [h for h in hits if "artifact" not in str(h)] or hits
            sol = hits[0] if hits else None
        if sol and sol.exists():
            sol_files.append((name, sol))
        else:
            print(f"  [skip] {name}.sol not found")

    if not sol_files:
        raise ValueError(f"No GT .sol files found for contest {contest_id}")

    n_keys = len(VERTEX_KEYS)
    actual_workers = min(workers, len(sol_files))
    print(f"\nContest {contest_id} ({entry.get('name', '')}): {len(sol_files)} GT files, {actual_workers} workers, {n_keys} keys")

    all_results = []
    with ThreadPoolExecutor(max_workers=actual_workers) as ex:
        futures = {}
        for i, (name, sol_file) in enumerate(sol_files):
            key_file, base_url = VERTEX_KEYS[i % n_keys]
            fut = ex.submit(_run_one, name, sol_file, out_dir, key_file, base_url)
            futures[fut] = name

        for fut in as_completed(futures):
            all_results.append(fut.result())

    all_findings = []
    for r in all_results:
        for f in r.get("findings", []):
            f["_contract_source"] = r["contract"]
            all_findings.append(f)

    agg = {
        "contest_id": contest_id,
        "total_findings": len(all_findings),
        "per_contract": all_results,
        "findings": all_findings,
    }
    agg_file = out_dir / "findings_all.json"
    agg_file.write_text(json.dumps(agg, indent=2))
    print(f"  → {len(all_findings)} total findings → {agg_file}")
    return all_results


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run GPTScan benchmark on web3bugs contests")
    parser.add_argument("--contest-id", help="Single contest ID")
    parser.add_argument("--all", action="store_true", help="Run all contests")
    parser.add_argument("--workers", type=int, default=4, help="Parallel workers (default: 4)")
    args = parser.parse_args()

    if not VERTEX_KEYS:
        print("ERROR: No Vertex AI keys in .env (need LLM_VERTEX_AI_KEY_FILE + LLM_BASE_URL)")
        raise SystemExit(1)

    print(f"Loaded {len(VERTEX_KEYS)} Vertex AI keys: {[Path(k).stem for k, _ in VERTEX_KEYS]}")

    if args.all:
        contests = json.loads(BENCHMARK_JSON.read_text())["contests"]
        for entry in contests:
            process_contest(str(entry["contest_id"]), args.workers)
    elif args.contest_id:
        process_contest(args.contest_id, args.workers)
    else:
        parser.print_help()
