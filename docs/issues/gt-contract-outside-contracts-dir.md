# Issue: GT Contract Source Not Discovered When Outside contracts_dir

## Tóm tắt

Khi một GT contract (được khai báo qua `--gt-contracts`) có file `.sol` nằm ngoài `contracts_dir`, source của nó **không được inject vào agent prompt**. Contract đó được nhận diện trong aux dependency map nhưng bị filter ra tại bước build chunk source.

Hệ quả: bugs trong contract đó không thể được tìm thấy vì agents không có source để đọc.

---

## Cơ chế hiện tại

```
contracts_dir (os.walk)
  └── ConcentratedLiquidityPool.sol      ← discovered ✓
  └── ConcentratedLiquidityPoolManager.sol  ← discovered ✓
  └── ConcentratedLiquidityPosition.sol  ← discovered ✓
  └── Factory.sol                        ← discovered (non-GT, filtered)
  └── Helper.sol                         ← discovered (non-GT, filtered)

libraries/concentratedPool/
  └── Ticks.sol                          ← NOT discovered ✗
```

**Pipeline:**

1. `discover_contracts()` dùng `os.walk(CONTRACTS_DIR)` → chỉ tìm trong thư mục chỉ định
2. `build_aux_map()` phân tích import: `CLP.sol` import `Ticks.sol` → thêm Ticks vào aux deps của CLP
3. `build_chunks()` filter: `aux = [...if dep in contracts]` → Ticks bị loại vì không có trong `contracts` dict
4. Kết quả: **Ticks source = None** trong toàn bộ agent prompts

Log hiển thị misleading:
```
Aux contracts (auto-detected):
  ConcentratedLiquidityPool → ['Ticks']   ← Ticks được detect nhưng source bị drop
```

---

## Ví dụ thực tế: Contest 35 — Ticks.cross (H-11)

| Field | Value |
|-------|-------|
| Contest | 35 (Trident CLMM) |
| GT contract | `Ticks` |
| Bug | H-11: `Ticks.cross()` khi `zeroForOne=true` update `feeGrowthOutside0` với `feeGrowthGlobal0` thay vì `feeGrowthGlobal1` |
| contracts_dir | `.../contracts/35/trident/contracts/pool/concentrated/` |
| Ticks.sol location | `.../contracts/35/trident/contracts/libraries/concentratedPool/Ticks.sol` |
| Kết quả | H-11 miss trong **tất cả** các run (focus_r1, focus_r2, fixgeneric_r5) |

H-11 là bug **không thể tìm được** với pipeline hiện tại vì agents chỉ thấy call site `Ticks.cross(...)` trong CLP.swap, không thấy implementation.

---

## Phạm vi ảnh hưởng

Vấn đề xảy ra khi:
- User khai báo GT contract X
- X.sol nằm trong subdir khác với `contracts_dir` (thường là `libraries/`, `utils/`, `base/`)
- X được import bởi contracts trong `contracts_dir`

**Không ảnh hưởng** đến:
- Non-GT contracts (Factory, Helper) — đã bị filter đúng theo thiết kế
- GT contracts nằm trong `contracts_dir`

---

## Fix đề xuất

### Option A (Minimal): Mở rộng discovery scope cho GT contracts

Sau khi `discover_contracts()` chạy xong, check xem GT contract nào chưa được discover. Với mỗi GT contract còn thiếu, tìm trong toàn bộ `contest_dir`:

```python
def discover_contracts(contest_dir: str = None) -> dict:
    contracts = {}
    # Walk contracts_dir như hiện tại
    for root, dirs, files in os.walk(CONTRACTS_DIR):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if fname.endswith('.sol'):
                cname = fname.replace('.sol', '')
                contracts[cname] = (os.path.join(root, fname),
                                    open(os.path.join(root, fname), errors='replace').read())

    # Fallback: tìm GT contracts còn thiếu trong contest_dir
    if contest_dir:
        missing_gt = GT_CONTRACTS - set(contracts.keys())
        for root, dirs, files in os.walk(contest_dir):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                cname = fname.replace('.sol', '')
                if cname in missing_gt and cname not in contracts:
                    path = os.path.join(root, fname)
                    contracts[cname] = (path, open(path, errors='replace').read())
                    print(f"[discover] Found GT contract outside contracts_dir: {cname} at {path}")

    return contracts
```

**Ưu điểm**: Minimal change, backward compatible, chỉ mở rộng cho GT contracts còn thiếu.

### Option B (Robust): Log warning khi GT contract không được discover

Thêm warning sau `discover_contracts()`:

```python
missing = GT_CONTRACTS - set(contracts.keys())
if missing:
    print(f"[WARN] GT contracts not found in contracts_dir: {missing}")
    print(f"       Their bugs cannot be detected. Consider widening contracts_dir.")
```

Option B dùng làm safeguard, Option A là fix thực sự.

---

## Trạng thái

- [x] Issue xác nhận (contest 35, H-11 miss trong tất cả runs)
- [ ] Fix chưa implement
- [ ] Cần verify: có contest nào khác bị ảnh hưởng không (scan `benchmark_contests.json` xem GT contracts có nằm trong subdirs không)
