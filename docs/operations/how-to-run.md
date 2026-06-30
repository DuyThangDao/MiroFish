# Hướng Dẫn Chạy Audit Pipeline

Entry point duy nhất: `backend/main.py`

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate
```

---

## Giai đoạn 1 — Đăng ký contest (một lần)

Thêm entry vào `benchmark/benchmark_contests.json`:

```json
{
  "contest_id": "35",
  "name": "Trident Concentrated Liquidity",
  "contracts_dir": "/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/pool/concentrated",
  "gt_file": "backend/scripts/evaluate/gt/gt_35.json",
  "gt_contracts": ["ConcentratedLiquidityPool", "ConcentratedLiquidityPoolManager", "ConcentratedLiquidityPosition", "Ticks"]
}
```

Tra cứu contest đã có:
```bash
python3 -c "
import json
contests = json.load(open('benchmark/benchmark_contests.json'))['contests']
entry = next(x for x in contests if x['contest_id'] == '<id>')
print(entry)
"
```

---

## Giai đoạn 1b — Build RAG sections cache (một lần toàn dự án, nếu chưa có)

RAG cache dùng cho HIST-INV synthesis — cần có trước khi chạy `populate_hist_inv_cache.py`.

**Trạng thái hiện tại:** `processed_count = 3366 / 3366` — đã hoàn tất, không cần chạy lại.

Nếu cần rebuild (ví dụ: máy mới, file bị mất):

```bash
# Kiểm tra trạng thái
python3 -c "
import json
m = json.load(open('backend/data/rag_db/rag_sections_cache.json'))['_meta']
print(m['processed_count'], '/', m['total_findings'])
"

# Nếu chưa đầy đủ — chạy migration (Claude tự xử lý per-batch, không phải script tự động)
# Xem: docs/simulate-e2e-pipeline.md → mục RAG Migration
```

Cache lưu tại: `backend/data/rag_db/rag_sections_cache.json` (không commit, trong `.gitignore`).

---

## Giai đoạn 2 — Build HIST-INV cache (một lần per contest)

HIST-INV cache lưu kết quả LLM synthesis cho từng function — reuse được giữa các runs.

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

python scripts/hist_inv/populate_hist_inv_cache.py \
  --contest-id <id> \
  --contest-dir /home/thangdd/repos/web3bugs/contracts/<id> \
  --contracts-dir <contracts_dir từ benchmark_contests.json>
```

Cache lưu tại: `benchmark/web3bugs/agent-redesign/<id>/hist_inv_cache.json`

**Lưu ý cache:**
- Không xóa cache trừ khi thay đổi prompt HIST-INV hoặc user yêu cầu rõ ràng
- Cache có thể có 180+ entries — xóa toàn bộ tốn nhiều thời gian rebuild
- Xóa selective nếu chỉ cần rebuild một số function:

```python
import json
cache = json.load(open('benchmark/web3bugs/agent-redesign/<id>/hist_inv_cache.json'))
target_fns = {'borrow', 'liquidate'}
cache['entries'] = {k: v for k, v in cache.get('entries', {}).items()
                    if v.get('fn_name', '') not in target_fns}
json.dump(cache, open('benchmark/web3bugs/agent-redesign/<id>/hist_inv_cache.json', 'w'), indent=2)
```

---

## Giai đoạn 3 — Chạy audit

```bash
cd /home/thangdd/repos/MiroFish/backend
LOG=/tmp/sim_e2e_<id>_<label>_$(date +%Y%m%d_%H%M%S).log

nohup bash -c '
source .venv/bin/activate
exec python main.py \
  --contest-id <id> \
  --contest-dir /home/thangdd/repos/web3bugs/contracts/<id> \
  --contracts-dir <contracts_dir từ benchmark_contests.json> \
  --gt-contracts <gt_contracts từ benchmark_contests.json> \
  --workers 5 \
  --out-dir ../benchmark/web3bugs/agent-redesign/<id>/<label>
' > "$LOG" 2>&1 &
echo "PID=$!  LOG=$LOG"
```

**Theo dõi:**
```bash
tail -f "$LOG"
grep "→ .* raw findings" "$LOG" | wc -l   # chunks xong / tổng chunks
```

**Flags thường dùng:**

| Flag | Mặc định | Tác dụng |
|------|----------|---------|
| `--workers N` | 1 | Parallel workers |
| `--dedup` | off | Per-chunk dedup sau khi agents chạy xong |
| `--no-inv` | off | Tắt HIST-INV injection (pure self-reasoning) |
| `--swc` | off | Inject SWC knowledge base vào agent prompts |
| `--rt` | off | Bật red-team attacker agents |
| `--out-dir PATH` | auto | Override output directory |
| `--kg-file PATH` | auto | Dùng KG đã build sẵn thay vì build mới |

**Ví dụ — Contest 35:**
```bash
nohup bash -c '
source .venv/bin/activate
exec python main.py \
  --contest-id 35 \
  --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
  --contracts-dir /home/thangdd/repos/web3bugs/contracts/35/trident/contracts/pool/concentrated \
  --gt-contracts ConcentratedLiquidityPool ConcentratedLiquidityPoolManager ConcentratedLiquidityPosition Ticks \
  --workers 5 \
  --out-dir ../benchmark/web3bugs/agent-redesign/35/sim_e2e_run1
' > /tmp/sim_35.log 2>&1 &
```

**Ví dụ — Contest 5 (Vader Protocol):**
```bash
nohup bash -c '
source .venv/bin/activate
exec python main.py \
  --contest-id 5 \
  --contest-dir /home/thangdd/repos/web3bugs/contracts/5 \
  --contracts-dir /home/thangdd/repos/web3bugs/contracts/5/vader-protocol/contracts \
  --gt-contracts DAO Pools Router USDV Utils Vader Vault Vether \
  --workers 5 \
  --out-dir ../benchmark/web3bugs/agent-redesign/5/sim_e2e_run1
' > /tmp/sim_5.log 2>&1 &
```

---

## Dedup (tuỳ chọn, sau khi audit xong)

Dedup gom các findings trùng root cause về 1 representative per group. Chạy offline sau khi có `audit_report_*_raw.json`.

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

python scripts/dedup/dedup_report.py \
  --input  ../benchmark/web3bugs/agent-redesign/<id>/<label>/audit_report_<id>_raw.json \
  --output ../benchmark/web3bugs/agent-redesign/<id>/<label>/audit_report_dedup.json \
  --workers 3 \
  --batch-size 20
```

**Flags:**

| Flag | Mặc định | Tác dụng |
|------|----------|---------|
| `--workers N` | 3 | Parallel threads cho group clustering |
| `--batch-size N` | 20 | Số findings tối đa mỗi LLM call trong 1 group |
| `--skip-cross` | off | Bỏ qua Pattern C/D cross-group dedup |

**Kiểm tra kết quả:**
```bash
python3 -c "
import json
d = json.load(open('benchmark/web3bugs/agent-redesign/<id>/<label>/audit_report_dedup.json'))
m = d['_dedup_meta']
print(f\"raw={m['raw_count']}  dedup={m['dedup_count']}  reduced={round((1-m['dedup_count']/m['raw_count'])*100,1)}%\")
"
```

**Lưu ý:** Dedup dùng framing "merge-only" — chỉ merge khi chắc chắn 100% cùng bug. Mặc định giữ tất cả để không mất TP.

---

## Eval sau khi xong

```bash
cd /home/thangdd/repos/MiroFish/backend/scripts/evaluate

python web3bugs_eval.py \
  gt/gt_<id>.json \
  ../../benchmark/web3bugs/agent-redesign/<id>/<label>/audit_report_<id>_raw.json \
  --verbose | tee ../../benchmark/web3bugs/agent-redesign/<id>/<label>/eval_result.txt
```

Kết quả lưu vào `eval_result.txt` trong run dir.
