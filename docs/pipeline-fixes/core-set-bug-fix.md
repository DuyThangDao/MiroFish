# Bug Fix: primary_keys[1+] Dropped from Tier 1 after STEP 0 Re-flatten

## Tóm tắt

Pipeline multi-primary được implement đúng ở tầng scoring (`_compute_manifest()` trả về 4 primaries) nhưng **bị vô hiệu hóa hoàn toàn** ở tầng flatten do một bug 1 dòng: chỉ `primary_keys[0]` được đưa vào Tier 1, các primaries còn lại bị drop khỏi flattened source.

---

## Triệu chứng

Contest 42 sau khi implement multi-primary (Phase 1+2+3):
- `manifest["primary_names"]` = `['MochiVault', 'DutchAuctionLiquidator', 'MochiTreasuryV0', 'FeePoolV0']` ✅
- ToC header hiển thị đúng 4 targets ✅  
- Slither dep graph chạy cho cả 4 primaries ✅
- **48 findings — 0 finding nào về FeePoolV0, MochiTreasuryV0** ❌
- Recall = 23% (3/13 H bugs)

---

## Root Cause

### Luồng thực thi sau khi fix Phase 1+2+3

```
Initial flatten → manifest: primary_names = [MochiVault, DutchAuction, Treasury, FeePool]
         │
         ▼
STEP 0: Slither caller analysis cho 4 primaries
→ callers found: {DutchAuctionLiquidator, MinterV0, MochiProfileV0}  (callers của MochiVault)
→ FeePoolV0, Treasury, VestedRewardPool: 0 callers
         │
         ▼
STEP 0: Re-flatten với extra_scope_contracts = {DutchAuction, MinterV0, MochiProfileV0}
→ _classify_files() → skeletonized_slither mode
→ BUG: chỉ primary_key (singular) được add vào core_set
```

### Code bị lỗi (`flatten_contest.py`, hàm `_classify_files()`)

```python
# TRƯỚC FIX — chỉ primary_keys[0] vào Tier 1
core_set: Set[str] = set()
primary_key = manifest.get("primary_key")   # = MochiVault (primary_keys[0])
if primary_key:
    core_set.add(primary_key)               # chỉ MochiVault được add

# extra_scope_contracts = {DutchAuctionLiquidator, MinterV0, MochiProfileV0} cũng được add
# → core_set = {MochiVault, DutchAuction, MinterV0, MochiProfileV0}
#
# FeePoolV0 KHÔNG có trong core_set
# FeePoolV0 KHÔNG trong reachable set của MochiVault (không có import path)
# → FeePoolV0 rơi vào tier3_set → bị DROP khỏi flattened source
```

### Kết quả thực tế trong flattened source

```python
# Verify bằng code:
source, _ = flatten_contest_dir(
    contest_dir,
    extra_scope_contracts={"DutchAuctionLiquidator", "MinterV0", "MochiProfileV0"}
)
"contract FeePoolV0" in source  # → False
```

**FeePoolV0 hoàn toàn vắng mặt trong source code mà agents đọc.** Agents không có cơ hội tìm bug trong FeePoolV0 — không phải vì attention dilution, mà vì contract đó không tồn tại trong prompt.

---

## Fix

**File**: `backend/scripts/flatten_contest.py` — hàm `_classify_files()`, mode `skeletonized_slither`

```python
# SAU FIX — tất cả primary_keys vào Tier 1
core_set: Set[str] = set()
for pk in (manifest.get("primary_keys") or [manifest.get("primary_key")]):
    if pk:
        core_set.add(pk)
```

Thay đổi: 3 dòng → 3 dòng. Không thay đổi API, không thay đổi behavior với single-primary protocol (primary_keys chỉ có 1 phần tử, behavior giống hệt trước).

---

## Kết quả sau fix

```python
source, _ = flatten_contest_dir(
    contest_dir,
    extra_scope_contracts={"DutchAuctionLiquidator", "MinterV0", "MochiProfileV0"}
)

"contract MochiVault"      in source  # → True  (FULL SOURCE)
"contract FeePoolV0"       in source  # → True  (FULL SOURCE) ← fix
"contract MochiTreasuryV0" in source  # → True  (FULL SOURCE) ← fix
```

Source size sau fix: **32KB** (giảm từ ~200KB của conservative mode) vì:
- Tier 1 (full source): 4 primaries + 3 Slither callers = 7 contracts
- Tier 2 (skeleton stubs): các deps được import bởi Tier 1
- Tier 3 (dropped): tất cả còn lại

---

## Tại sao bị nhầm là "attention dilution"

Ban đầu giả thuyết là agents "đọc nhưng không chú ý" FeePoolV0 do context quá dài (Lost in the Middle). Giả thuyết này sai vì:

1. FeePoolV0 **không có trong source** → agents không thể đọc dù có muốn
2. Nếu là attention dilution, sẽ có ít findings về FeePoolV0 — thực tế là **0 findings hoàn toàn**
3. Source size sau fix chỉ 32KB — không đủ dài để gây attention dilution

Điều này cũng có nghĩa: **Phase 4 (Full Map-Reduce) không cần thiết để giải bài toán contest 42**. Bug fix này đã đặt FeePoolV0 vào full source với context window nhỏ (32KB). Phase 4 vẫn hữu ích cho protocol thực sự lớn (>150KB sau fix) nhưng không phải blocker hiện tại.

---

## Lessons Learned

**Luôn verify flattened source trước khi blame LLM.** Khi agents không tìm được bug ở contract X, câu hỏi đầu tiên phải là: *"Contract X có thực sự trong source code không?"* — không phải *"Agents có đủ attention không?"*

```bash
# Verification command:
python3 -c "
from scripts.flatten_contest import flatten_contest_dir
src, _ = flatten_contest_dir('/path/to/contest', emit_manifest=True,
                              extra_scope_contracts={'CallerA', 'CallerB'})
for name in ['ContractX', 'ContractY', 'ContractZ']:
    status = 'FOUND' if f'contract {name}' in src else 'MISSING'
    print(f'{name}: {status}')
"
```
