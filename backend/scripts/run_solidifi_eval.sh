#!/bin/bash
# SolidiFI-benchmark evaluation runner
# Usage: bash run_solidifi_eval.sh [N_PER_TYPE]
#   N_PER_TYPE: contracts per bug type (default 10 → 70 total)
#
# Env override: SOLIDIFI_DIR=/path/to/SolidiFI-benchmark
# Log: /tmp/solidifi_runner.log  |  Per-contract: /tmp/solidifi_<type>_<name>.log

BACKEND_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SOLIDIFI_DIR="${SOLIDIFI_DIR:-/home/thangdd/repos/SolidiFI-benchmark}"
OUTPUT_DIR="$BACKEND_DIR/results/solidifi_eval"
RUNNER_LOG="/tmp/solidifi_runner.log"
TIMEOUT=7200
N_PER_TYPE="${1:-10}"

# Bug type dir name → SWC ID
declare -A TYPE_TO_SWC=(
    ["Re-entrancy"]="SWC-107"
    ["Overflow-Underflow"]="SWC-101"
    ["Timestamp-Dependency"]="SWC-116"
    ["TOD"]="SWC-114"
    ["tx.origin"]="SWC-115"
    ["Unchecked-Send"]="SWC-104"
    ["Unhandled-Exceptions"]="SWC-104"
)

cd "$BACKEND_DIR" || exit 1
source .venv/bin/activate

mkdir -p "$OUTPUT_DIR"

done_count=0
fail_count=0
type_count=${#TYPE_TO_SWC[@]}
total=$(( type_count * N_PER_TYPE ))

echo "[$(date '+%H:%M:%S')] SolidiFI runner started — $total contracts (${N_PER_TYPE}/type × ${type_count} types)" | tee "$RUNNER_LOG"
echo "[$(date '+%H:%M:%S')] Output: $OUTPUT_DIR" | tee -a "$RUNNER_LOG"

for bug_type in "Re-entrancy" "Overflow-Underflow" "Timestamp-Dependency" "TOD" "tx.origin" "Unchecked-Send" "Unhandled-Exceptions"; do
    swc_id="${TYPE_TO_SWC[$bug_type]}"
    type_dir="$SOLIDIFI_DIR/buggy_contracts/$bug_type"
    safe_type="${bug_type//[^a-zA-Z0-9]/_}"

    if [ ! -d "$type_dir" ]; then
        echo "[$(date '+%H:%M:%S')] SKIP $bug_type — directory not found: $type_dir" | tee -a "$RUNNER_LOG"
        continue
    fi

    count=0
    while IFS= read -r sol_path && [ "$count" -lt "$N_PER_TYPE" ]; do
        [ -f "$sol_path" ] || continue
        count=$((count + 1))
        done_count=$((done_count + 1))

        contract_name=$(basename "$sol_path" .sol)
        contract_log="/tmp/solidifi_${safe_type}_${contract_name}.log"

        echo "[$(date '+%H:%M:%S')] [$done_count/$total] START ${bug_type}/${contract_name} (gt=${swc_id})" | tee -a "$RUNNER_LOG"

        python scripts/run_contract_audit.py \
            --sol "$sol_path" \
            --output "$OUTPUT_DIR/$safe_type" \
            --ground-truth "$swc_id" \
            --timeout "$TIMEOUT" \
            > "$contract_log" 2>&1

        exit_code=$?
        if [ $exit_code -eq 0 ]; then
            echo "[$(date '+%H:%M:%S')] [$done_count/$total] DONE  ${bug_type}/${contract_name}" | tee -a "$RUNNER_LOG"
        else
            fail_count=$((fail_count + 1))
            echo "[$(date '+%H:%M:%S')] [$done_count/$total] FAIL  ${bug_type}/${contract_name} (exit=$exit_code)" | tee -a "$RUNNER_LOG"
        fi
    done < <(ls -v "$type_dir"/buggy_*.sol 2>/dev/null)
done

echo "" | tee -a "$RUNNER_LOG"
echo "[$(date '+%H:%M:%S')] SolidiFI runner finished — done=$done_count fail=$fail_count" | tee -a "$RUNNER_LOG"
