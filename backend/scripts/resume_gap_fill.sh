#!/bin/bash
# Resume from a previous run's checkpoint.
#
# Usage:
#   bash scripts/resume_gap_fill.sh <contest-dir> <prev-run-dir> <new-run-dir>
#
# Checkpoint tiers (auto-detected, best available wins):
#   Tier A — post_dedup.json   : skip R1 + gap-fill + dedup + micropass          (~0 min)
#   Tier B — pre_dedup.json    : skip R1 + gap-fill → re-run dedup + micropass   (~5 min)
#   Tier C — r1_findings.json  : skip R1 → re-run gap-fill + dedup + micropass   (~20-25 min)
#   Tier D — no checkpoint     : full run                                          (~55 min)
#
# Backward compat: pre_gap_fill.json treated as Tier A alias.
# All tiers require: session_summary.txt + kg_result.json + profiles.json

set -e

CONTEST_DIR="$1"
PREV_RUN_DIR="$2"
NEW_RUN_DIR="$3"

if [[ -z "$CONTEST_DIR" || -z "$PREV_RUN_DIR" || -z "$NEW_RUN_DIR" ]]; then
    echo "Usage: $0 <contest-dir> <prev-run-dir> <new-run-dir>"
    echo ""
    echo "Example:"
    echo "  $0 /path/to/web3bugs/35 ../benchmark/.../35/run-45 ../benchmark/.../35/run-46"
    exit 1
fi

# Validate base files always required
for f in session_summary.txt kg_result.json profiles.json; do
    if [[ ! -f "$PREV_RUN_DIR/$f" ]]; then
        echo "ERROR: $PREV_RUN_DIR/$f not found (required for all checkpoint tiers)"
        exit 1
    fi
done

# Detect checkpoint tier (best available wins)
if [[ -f "$PREV_RUN_DIR/post_dedup.json" || -f "$PREV_RUN_DIR/pre_gap_fill.json" ]]; then
    TIER="A"
    TIER_DESC="skip R1 + gap-fill + dedup + micropass (~0 min, report only)"
elif [[ -f "$PREV_RUN_DIR/pre_dedup.json" ]]; then
    TIER="B"
    TIER_DESC="skip R1 + gap-fill → re-run dedup + micropass (~5 min)"
elif [[ -f "$PREV_RUN_DIR/r1_findings.json" ]]; then
    TIER="C"
    TIER_DESC="skip R1 → re-run gap-fill + dedup + micropass (~20-25 min)"
else
    TIER="D"
    TIER_DESC="no checkpoint — full run (~55 min, only KG/profiles skipped)"
    echo "WARNING: No checkpoint files found in $PREV_RUN_DIR"
    echo "         Will run full pipeline."
fi

LOG="/tmp/resume_gapfill_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$NEW_RUN_DIR"

echo "Contest   : $CONTEST_DIR"
echo "Checkpoint: $PREV_RUN_DIR"
echo "New run   : $NEW_RUN_DIR"
echo "Tier      : $TIER — $TIER_DESC"
echo "Log       : $LOG"
echo ""

cd "$(dirname "$0")/.."
source .venv/bin/activate

export CHECKPOINT_DIR="$PREV_RUN_DIR"
export STOP_AFTER_DEDUP=true
export RAG_ENABLED=true
export AUDIT_LOG_FILE="$LOG"

python scripts/run_contract_audit.py \
    --contest-dir "$CONTEST_DIR" \
    --output      "$NEW_RUN_DIR" \
    --timeout     3600 \
    --verbose \
    2>&1 | tee "$LOG"

# Flatten timestamped subdir into NEW_RUN_DIR
SUBDIR=$(find "$NEW_RUN_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
if [[ -n "$SUBDIR" ]]; then
    mv "$SUBDIR"/* "$NEW_RUN_DIR"/
    rmdir "$SUBDIR"
fi

echo ""
echo "Done. Output : $NEW_RUN_DIR"
echo "Log          : $LOG"
