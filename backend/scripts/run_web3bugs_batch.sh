#!/bin/bash
# Run contract audit for multiple web3bugs contests sequentially
# Usage: bash run_web3bugs_batch.sh <contest_id> [<contest_id> ...] [--dry-run]
# Example: bash run_web3bugs_batch.sh 35 19 28
#
# Stops on the first contest that fails.
# Each contest logs to /tmp/web3bugs_<id>.log
# A batch summary is written to /tmp/web3bugs_batch.log

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BATCH_LOG="/tmp/web3bugs_batch.log"

# --- Parse arguments ---
CONTEST_IDS=()
DRY_RUN_FLAG=""

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN_FLAG="--dry-run"
            ;;
        -*)
            echo "Unknown option: $arg" >&2
            echo "Usage: $0 <contest_id> [<contest_id> ...] [--dry-run]" >&2
            exit 1
            ;;
        *)
            CONTEST_IDS+=("$arg")
            ;;
    esac
done

if [ ${#CONTEST_IDS[@]} -eq 0 ]; then
    echo "Error: at least one contest_id is required." >&2
    echo "Usage: $0 <contest_id> [<contest_id> ...] [--dry-run]" >&2
    exit 1
fi

TOTAL=${#CONTEST_IDS[@]}
DONE_COUNT=0
FAIL_COUNT=0

echo "[$(date '+%H:%M:%S')] web3bugs batch started — ${TOTAL} contest(s): ${CONTEST_IDS[*]}" | tee "$BATCH_LOG"
[ -n "$DRY_RUN_FLAG" ] && echo "[$(date '+%H:%M:%S')] DRY-RUN mode active" | tee -a "$BATCH_LOG"

for CONTEST_ID in "${CONTEST_IDS[@]}"; do
    DONE_COUNT=$((DONE_COUNT + 1))
    echo "" | tee -a "$BATCH_LOG"
    echo "[$(date '+%H:%M:%S')] [${DONE_COUNT}/${TOTAL}] START contest ${CONTEST_ID}" | tee -a "$BATCH_LOG"

    set +e
    bash "$SCRIPT_DIR/run_web3bugs_contest.sh" "$CONTEST_ID" $DRY_RUN_FLAG
    EXIT_CODE=$?
    set -e

    if [ $EXIT_CODE -eq 0 ]; then
        echo "[$(date '+%H:%M:%S')] [${DONE_COUNT}/${TOTAL}] DONE  contest ${CONTEST_ID}" | tee -a "$BATCH_LOG"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "[$(date '+%H:%M:%S')] [${DONE_COUNT}/${TOTAL}] FAIL  contest ${CONTEST_ID} (exit=${EXIT_CODE}) — stopping batch." | tee -a "$BATCH_LOG"
        echo "" | tee -a "$BATCH_LOG"
        echo "[$(date '+%H:%M:%S')] Batch ABORTED after ${DONE_COUNT}/${TOTAL} contest(s), ${FAIL_COUNT} failure(s)." | tee -a "$BATCH_LOG"
        exit $EXIT_CODE
    fi
done

echo "" | tee -a "$BATCH_LOG"
echo "[$(date '+%H:%M:%S')] Batch FINISHED — ${TOTAL}/${TOTAL} contest(s) completed successfully." | tee -a "$BATCH_LOG"
