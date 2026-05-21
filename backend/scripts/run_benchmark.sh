#!/bin/bash
# Usage: bash run_benchmark.sh <contest-dir> <run-dir>
# Example: bash run_benchmark.sh /path/to/web3bugs/42 ../benchmark/web3bugs/agent-redesign/42/run-2
#
# Flags đặt cứng: STOP_AFTER_DEDUP=true, RAG_ENABLED=true
# Sau khi xong: dedup_findings.json, audit_report_dedup.json, run.log tự động copy vào run-dir

set -e

CONTEST_DIR="$1"
RUN_DIR="$2"

if [[ -z "$CONTEST_DIR" || -z "$RUN_DIR" ]]; then
    echo "Usage: $0 <contest-dir> <run-dir>"
    exit 1
fi

CONTEST_ID=$(basename "$CONTEST_DIR")
LOG="/tmp/benchmark_${CONTEST_ID}_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "$RUN_DIR"

echo "Contest : $CONTEST_DIR"
echo "Run dir : $RUN_DIR"
echo "Log     : $LOG"
echo ""

cd "$(dirname "$0")/.."
source .venv/bin/activate

export STOP_AFTER_DEDUP=true
export RAG_ENABLED=true
export AUDIT_LOG_FILE="$LOG"

python scripts/run_contract_audit.py \
    --contest-dir "$CONTEST_DIR" \
    --output      "$RUN_DIR" \
    --timeout     21600 \
    --verbose \
    2>&1 | tee "$LOG"

# Flatten timestamped subdir into RUN_DIR
SUBDIR=$(find "$RUN_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
if [[ -n "$SUBDIR" ]]; then
    mv "$SUBDIR"/* "$RUN_DIR"/
    rmdir "$SUBDIR"
fi

echo ""
echo "Done. Output: $RUN_DIR"
