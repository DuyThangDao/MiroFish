# Fix: Selective Multi-Root BFS — Size Cap Workaround

## Vấn đề hiện tại

Multi-root BFS hiện tại (Phase 1) BFS từ **tất cả** implementation contracts và lấy union. Với contest 35 (Trident AMM, 105 `.sol` files), union này pull in gần như toàn bộ codebase (~302KB) → vượt size cap 200KB → fallback về single-root → Manager/Position vẫn là stubs.

Kết quả: 5 bugs luôn FN (H-02, H-03, H-06, H-07, H-16) vì `ConcentratedLiquidityPoolManager` và `ConcentratedLiquidityPosition` nằm ngoài scope.

---

## Root Cause

BFS từ tất cả impl contracts không selective — nó kéo theo cả OZ libraries, utility contracts, và các contracts không liên quan đến primary. Trong contest 35:

- Primary = `ConcentratedLiquidityPool` → import tree đã cover pool logic
- Manager → import tree **cũng** pull in OZ, math libraries → overlap lớn với pool tree
- Position → tương tự

Union của tất cả trees ≈ toàn bộ codebase → size cap triggered.

---

## Giải pháp: Selective Secondary Roots

Thay vì BFS từ tất cả impl contracts, chỉ thêm các contracts **không được reach từ primary** làm secondary roots:

```python
# Bước 1: BFS từ primary (như cũ)
primary_key = manifest.get("primary_key")
primary_reachable = _get_reachable_set(primary_key, graph) if primary_key else set()

# Bước 2: Tìm impl contracts nằm ngoài primary reachable
unreached_impls = [
    k for k in order
    if k not in primary_reachable
    and not _is_interface_only(sources.get(k, ""))
    and not _is_mock_or_test(k)
]

# Bước 3: BFS từ từng unreached impl, nhưng chỉ lấy phần
# KHÔNG overlap với primary reachable (tức là contracts mới thực sự)
reachable = set(primary_reachable)
for root_key in unreached_impls:
    if root_key in graph:
        sub_reachable = _get_reachable_set(root_key, graph)
        # Chỉ add contracts mới — không re-add OZ/utility đã có
        new_contracts = sub_reachable - primary_reachable
        reachable |= new_contracts
        reachable.add(root_key)  # luôn add bản thân root

# Bước 4: Size check — nếu vượt cap, drop dần unreached_impls ít quan trọng nhất
total_chars = sum(len(sources.get(k, "")) for k in reachable)
if total_chars > SIZE_CAP:
    # Fallback: chỉ giữ primary + những impl nào không thêm quá nhiều chars
    reachable = set(primary_reachable)
    for root_key in unreached_impls:
        added = {root_key} | (_get_reachable_set(root_key, graph) - primary_reachable)
        added_chars = sum(len(sources.get(k, "")) for k in added)
        if total_chars + added_chars <= SIZE_CAP:
            reachable |= added
            total_chars += added_chars
```

---

## Tại sao approach này tốt hơn

| | Full union (hiện tại) | Selective secondary |
|---|---|---|
| Contest 35 | 302KB → fallback | ~80–90KB (Pool tree + Manager + Position thêm ~20KB) |
| Contest 104 | 98 files in-scope | Tương tự |
| Contest 100 | All in-scope | Tương tự |
| OZ libraries | Đều được pull in nhiều lần | Pull in 1 lần qua primary tree |

---

## Coverage dự kiến cho contest 35

Sau fix:
- `ConcentratedLiquidityPoolManager` → in-scope → H-02, H-03, H-16 có thể detect
- `ConcentratedLiquidityPosition` → in-scope → H-06, H-07 có thể detect
- Tổng context tăng từ 63KB → ~85–95KB → model xử lý được
- Max possible TP: 17 (tất cả bugs in-scope) thay vì 12

---

## Files cần thay đổi

| File | Thay đổi |
|------|---------|
| `backend/scripts/flatten_contest.py` | Sửa Tier 1 trong `_classify_files()` — thay full union bằng selective secondary roots |

---

## Thứ tự triển khai

Phase 1 (đã làm): Multi-root BFS full union — fix contest 104, 100  
**Phase 1b (này):** Selective secondary roots — fix contest 35 mà không break 104/100  

Phase 1b không ảnh hưởng 104/100 vì:
- Contest 104: primary = `CoreCollection`, Splitter/RoyaltyVault nằm ngoài primary tree → vẫn được add làm secondary roots
- Contest 100: tất cả files đã in-scope → không thay đổi

---

## Verification

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

# Expect: scope_method = "multi_root_bfs_selective", > 14 files in-scope
LOG=/tmp/web3bugs_35_selective_$(date +%Y%m%d_%H%M%S).log
DEDUP=/tmp/dedup_35_selective_$(date +%Y%m%d_%H%M%S).json
STOP_AFTER_DEDUP=true STOP_AFTER_DEDUP_OUT=$DEDUP \
nohup bash -c 'source /home/thangdd/repos/MiroFish/backend/.venv/bin/activate && exec python scripts/run_contract_audit.py \
  --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
  --output ./results/web3bugs_trial/contest_35_selective --timeout 7200 --verbose' >> "$LOG" 2>&1 &

# Evaluate
python scripts/evaluate/web3bugs_eval.py scripts/evaluate/gt/gt_35.json $DEDUP --verbose
# Target: TP >= 13 (H-02/03/06/07/16 thêm vào scope)
```
