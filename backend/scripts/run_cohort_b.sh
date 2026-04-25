#!/bin/bash
# Run remaining 63 Cohort B contracts sequentially
# Usage: bash run_cohort_b.sh
# Log: /tmp/cohort_b_runner.log  |  Per-contract logs: /tmp/cohort_b_<name>.log

BACKEND_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="$BACKEND_DIR/results/phase5c"
CONTRACT_LIST="/tmp/remaining_contracts.txt"
RUNNER_LOG="/tmp/cohort_b_runner.log"
TIMEOUT=7200

cd "$BACKEND_DIR" || exit 1
source .venv/bin/activate

total=$(wc -l < "$CONTRACT_LIST")
done_count=0
fail_count=0

echo "[$(date '+%H:%M:%S')] Cohort B runner started — $total contracts" | tee "$RUNNER_LOG"

while IFS= read -r sol_path; do
    contract_name=$(basename "$sol_path" .sol)
    contract_log="/tmp/cohort_b_${contract_name:0:40}.log"
    done_count=$((done_count + 1))

    echo "[$(date '+%H:%M:%S')] [$done_count/$total] START $contract_name" | tee -a "$RUNNER_LOG"

    python scripts/run_contract_audit.py \
        --sol "$sol_path" \
        --output "$OUTPUT_DIR" \
        --timeout "$TIMEOUT" \
        > "$contract_log" 2>&1

    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        echo "[$(date '+%H:%M:%S')] [$done_count/$total] DONE  $contract_name" | tee -a "$RUNNER_LOG"
    else
        fail_count=$((fail_count + 1))
        echo "[$(date '+%H:%M:%S')] [$done_count/$total] FAIL  $contract_name (exit=$exit_code)" | tee -a "$RUNNER_LOG"
    fi
done < "$CONTRACT_LIST"

echo "[$(date '+%H:%M:%S')] Cohort B runner finished — $total done, $fail_count failed" | tee -a "$RUNNER_LOG"
