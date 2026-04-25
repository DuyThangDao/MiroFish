#!/bin/bash
# Watch for v8 (PID $1) to finish, then restart with parallel=1 + skip-done

WATCH_PID=${1:-3369101}
LOG=/tmp/phase5b_v9.log

echo "[watcher] Waiting for PID $WATCH_PID to finish..."
while kill -0 $WATCH_PID 2>/dev/null; do
    sleep 30
done

echo "[watcher] PID $WATCH_PID finished at $(date '+%H:%M:%S'). Starting parallel=1 run..."

cd /home/thangdd/repos/MiroFish/backend && source .venv/bin/activate

nohup python3 scripts/evaluate_phase5b.py \
    --dataset /home/thangdd/repos/smartbugs-curated \
    --output ./results/phase5b \
    --only 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 \
    --parallel 1 \
    --cooldown 30 \
    --skip-done \
    > $LOG 2>&1 &

echo "[watcher] Started v9 PID: $! | Log: $LOG"
