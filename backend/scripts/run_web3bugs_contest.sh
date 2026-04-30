#!/bin/bash
# Run contract audit for a single web3bugs contest using --contest-dir
# Usage: bash run_web3bugs_contest.sh <contest_id> [--dry-run]
# Log: /tmp/web3bugs_<id>.log
#
# Automatically locates the contest directory at:
#   ~/repos/web3bugs/contracts/<id>/
# and writes results to:
#   backend/results/web3bugs_trial/contest_<id>/

set -euo pipefail

BACKEND_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TIMEOUT=7200

# --- Parse arguments ---
CONTEST_ID=""
DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=1
            ;;
        -*)
            echo "Unknown option: $arg" >&2
            echo "Usage: $0 <contest_id> [--dry-run]" >&2
            exit 1
            ;;
        *)
            if [ -z "$CONTEST_ID" ]; then
                CONTEST_ID="$arg"
            else
                echo "Unexpected argument: $arg" >&2
                echo "Usage: $0 <contest_id> [--dry-run]" >&2
                exit 1
            fi
            ;;
    esac
done

if [ -z "$CONTEST_ID" ]; then
    echo "Error: contest_id is required." >&2
    echo "Usage: $0 <contest_id> [--dry-run]" >&2
    exit 1
fi

# --- Locate contest directory ---
CONTEST_DIR=""
CANDIDATES=(
    "$HOME/repos/web3bugs/contracts/${CONTEST_ID}"
    "/home/thangdd/repos/web3bugs/contracts/${CONTEST_ID}"
)

for candidate in "${CANDIDATES[@]}"; do
    if [ -d "$candidate" ]; then
        CONTEST_DIR="$candidate"
        break
    fi
done

if [ -z "$CONTEST_DIR" ]; then
    echo "Error: Contest directory not found. Tried:" >&2
    for candidate in "${CANDIDATES[@]}"; do
        echo "  $candidate" >&2
    done
    exit 1
fi

# --- Paths ---
OUTPUT_DIR="$BACKEND_DIR/results/web3bugs_trial/contest_${CONTEST_ID}"
LOG_FILE="/tmp/web3bugs_${CONTEST_ID}.log"

echo "[$(date '+%H:%M:%S')] Contest ${CONTEST_ID} — contest dir: $CONTEST_DIR"
echo "[$(date '+%H:%M:%S')] Output dir : $OUTPUT_DIR"
echo "[$(date '+%H:%M:%S')] Log file   : $LOG_FILE"

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[$(date '+%H:%M:%S')] DRY-RUN mode — would run:"
    echo "  python scripts/run_contract_audit.py \\"
    echo "    --contest-dir \"$CONTEST_DIR\" \\"
    echo "    --output     \"$OUTPUT_DIR\" \\"
    echo "    --timeout    $TIMEOUT"
    exit 0
fi

# --- Create output directory ---
mkdir -p "$OUTPUT_DIR"

# --- Activate venv and run audit ---
cd "$BACKEND_DIR" || exit 1
source .venv/bin/activate

echo "[$(date '+%H:%M:%S')] Starting audit for contest ${CONTEST_ID} ..." | tee "$LOG_FILE"

python scripts/run_contract_audit.py \
    --contest-dir "$CONTEST_DIR" \
    --output      "$OUTPUT_DIR" \
    --timeout     "$TIMEOUT" \
    >> "$LOG_FILE" 2>&1

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "[$(date '+%H:%M:%S')] Contest ${CONTEST_ID} DONE (exit=0)" | tee -a "$LOG_FILE"
else
    echo "[$(date '+%H:%M:%S')] Contest ${CONTEST_ID} FAILED (exit=${EXIT_CODE})" | tee -a "$LOG_FILE"
fi

exit $EXIT_CODE
