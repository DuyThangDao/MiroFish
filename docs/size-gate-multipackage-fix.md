# Size Gate: Multi-Package Contest Scope Bug

## Vấn đề

Size gate hiện tại chỉ include contracts **trong cùng sub-project với primary contract**, bỏ qua các packages khác dù chúng thuộc cùng contest scope.

### Root cause

```python
# flatten_contest.py — _classify_files()
_project_prefix = "/".join(_pk_parts[:_ci])  # e.g. ".../104/core-contracts"
_scoped_impl_keys = [
    k for k in all_impl_keys
    if not _project_prefix or k.startswith(_project_prefix)  # ← filter theo subdir
]
```

Với contest 104:
- Primary: `core-contracts/contracts/CoreCollection.sol` → prefix = `core-contracts/`
- Size gate: chỉ include `core-contracts/**` (34K chars)
- `splits/` (Splitter) và `royalty-vault/` (RoyaltyVault) bị **loại hoàn toàn**

### Hậu quả (contest 104)

| Run | Scope method | Contracts | TP | F1 |
|-----|-------------|-----------|----|----|
| run-2 (v4c) | skeletonized_slither | CoreCollection + Splitter + RoyaltyVault + ... | 7 | 0.350 |
| run-3 (v5) | full_audit_size_gate | CoreCollection only | 3 | 0.194 |

4 H bugs hoàn toàn không thể tìm (H-02, H-03, H-05, H-09) vì `Splitter` và `RoyaltyVault` không có trong scope.

---

## Tại sao prefix filter được thêm vào

Ban đầu thiết kế cho contest có monorepo cấu trúc kiểu:
```
contest/
  projects/mochi-core/contracts/   ← primary
  projects/mochi-usm/contracts/    ← unrelated
  projects/mochi-token/contracts/  ← unrelated
```

Mục tiêu: tránh audit các sub-projects không liên quan. Nhưng với contest dạng multi-package flat:
```
contest/
  core-contracts/   ← primary
  splits/           ← IN SCOPE (thuộc contest)
  royalty-vault/    ← IN SCOPE (thuộc contest)
```

Prefix filter sai — tất cả packages đều liên quan.

---

## Fix: Bỏ prefix filter

```python
# Trước
_scoped_impl_keys = [
    k for k in all_impl_keys
    if not _project_prefix or k.startswith(_project_prefix)
]

# Sau
_scoped_impl_keys = all_impl_keys  # đo tổng tất cả impl contracts
```

**200KB limit là safety net thật sự:**
- Contest nhỏ (< 200KB tổng) → full audit tất cả packages ✅
- Contest lớn (> 200KB) → fall through sang Slither BFS như cũ ✅

### Tại sao an toàn

1. **Contest 42 không bị ảnh hưởng**: tất cả .sol files đã nằm trong `mochi-core/` → `all_impl_keys` giống `_scoped_impl_keys` cũ
2. **Monorepo lớn tự xử lý**: nếu tổng nhiều packages > 200KB → size gate không trigger → Slither BFS như trước
3. **Recall ưu tiên hơn precision**: thêm scope = thêm TP, FP tăng nhẹ nhưng R2 xử lý

---

## File cần thay đổi

`backend/scripts/flatten_contest.py` — hàm `_classify_files()`, khoảng line 460–470.

Thay:
```python
_scoped_impl_keys = [
    k for k in all_impl_keys
    if not _project_prefix or k.startswith(_project_prefix)
]
```

Thành:
```python
_scoped_impl_keys = all_impl_keys
```

Và update print message:
```python
f"[flatten] Size gate: {_total_impl_chars:,} chars ≤ {_FULL_AUDIT_LIMIT:,} "
f"— full audit ({len(_scoped_impl_keys)} impl contracts)"
```

---

## Verification

```bash
cd /home/thangdd/repos/MiroFish/backend && source .venv/bin/activate

# Contest 104: phải include Splitter + RoyaltyVault
python3 - <<'EOF'
import sys; sys.path.insert(0, 'scripts')
from flatten_contest import flatten_contest_dir
result, manifest = flatten_contest_dir(
    "/home/thangdd/repos/web3bugs/contracts/104",
    emit_manifest=True, verbose=True
)
method = manifest.get("scope_method")
print(f"scope_method = {method}")
# Verify Splitter và RoyaltyVault trong scope
assert any("Splitter" in k or "splitter" in k.lower() for k in manifest.get("in_scope_keys", [])), \
    "FAIL: Splitter not in scope"
print("✅ Splitter in scope")
assert any("RoyaltyVault" in k or "royaltyvault" in k.lower() for k in manifest.get("in_scope_keys", [])), \
    "FAIL: RoyaltyVault not in scope"
print("✅ RoyaltyVault in scope")
EOF

# Contest 42: không bị ảnh hưởng
python3 - <<'EOF'
import sys; sys.path.insert(0, 'scripts')
from flatten_contest import flatten_contest_dir
result, manifest = flatten_contest_dir(
    "/home/thangdd/repos/web3bugs/contracts/42",
    emit_manifest=True, verbose=True
)
method = manifest.get("scope_method")
assert method == "full_audit_size_gate", f"FAIL: {method}"
print(f"✅ contest 42 method = {method} (unchanged)")
EOF

# Chạy lại run-4 contest 104 sau fix và so sánh với run-2 baseline
```

**Dấu hiệu thành công:**
- Contest 104: `full_audit_size_gate`, Splitter + RoyaltyVault có trong scope
- Contest 42: `full_audit_size_gate`, 16 contracts như cũ
- run-4 eval: TP ≥ 6 (recover phần lớn TP của run-2)
