#!/bin/bash
WATCH_PID=492532
LOG=/tmp/phase5c_v2.log

echo "[watcher] Waiting for PID $WATCH_PID to finish..."
while kill -0 $WATCH_PID 2>/dev/null; do
    sleep 20
done

echo "[watcher] PID $WATCH_PID done at $(date '+%H:%M:%S'). Starting Phase 5c (all 143)..."
cd /home/thangdd/repos/MiroFish/backend && source .venv/bin/activate

nohup python3 scripts/evaluate_phase5b.py \
    --dataset /home/thangdd/repos/smartbugs-curated \
    --output ./results/phase5b \
    --all-categories \
    --parallel 3 \
    --cooldown 30 \
    --skip-done \
    > $LOG 2>&1 &

echo "[watcher] Phase 5c started PID: $! | Log: $LOG"
