# Size Gate — Full Audit cho Contest Nhỏ

## Bối cảnh

### Vấn đề hiện tại

Pipeline hiện tại chọn scope bằng **Slither BFS từ primary contract**:

1. Scoring → chọn top 4 primaries (MochiVault, FeePoolV0, ...)
2. Slither tìm callers của primaries → merge thành `core_set`
3. BFS import graph từ `core_set` → 6 contracts vào session_summary

Kết quả contest 42: **4/13 H bugs** nằm trong contracts không được chọn vào scope
(`ReferralFeePoolV0`, `VestedRewardPool`, `MochiEngine`) → trần lý thuyết chỉ **9/13 = 69.2%**.

Nguyên nhân: các "parallel contracts" (emission, referral, registry) không call
đến primary contract và không được primary contract import → BFS không reach được.

### Tại sao không dùng cơ chế hiện tại cho tất cả

Với contest lớn (contest 35: 294KB impl source, 50 file .sol), include tất cả
contracts sẽ gây context bloat → agent bị distract, chất lượng phân tích giảm.
Cơ chế primary-BFS hợp lý cho trường hợp này.

---

## Giải pháp: Size Gate

### Logic

```
if total_impl_chars <= FULL_AUDIT_CHAR_LIMIT:
    → include tất cả impl contracts (non-mock, non-interface)
    → method = "full_audit_size_gate"
else:
    → dùng cơ chế hiện tại (scoring + Slither BFS)
```

### Threshold

| Contest | Impl chars | Quyết định |
|---------|-----------|-----------|
| Contest 42 | 131KB | ✅ Full audit |
| Contest 35 | 294KB | ❌ Primary BFS |

Default: **`FULL_AUDIT_CHAR_LIMIT = 200_000`** (200KB)
Configurable qua env var: `FULL_AUDIT_CHAR_LIMIT`

Với threshold 200KB:
- Contest 42: 131KB < 200KB → full audit → trần lý thuyết tăng từ 69.2% → 100%
- Contest 35: 294KB > 200KB → giữ nguyên cơ chế hiện tại

---

## Triển khai

### File duy nhất: `backend/scripts/flatten_contest.py`

#### Thay đổi trong `_classify_scope()` (trước block `if all_impl_keys:`)

**Vị trí chèn:** Sau khi `all_impl_keys` được build, trước `if all_impl_keys: if extra_scope_contracts:`.

```python
# ── Size gate: full audit for small contests ──────────────────────────────
_FULL_AUDIT_LIMIT = int(os.getenv("FULL_AUDIT_CHAR_LIMIT", "200000"))
_total_impl_chars = sum(len(sources.get(k, "")) for k in all_impl_keys)
if _total_impl_chars <= _FULL_AUDIT_LIMIT:
    _all_impl_set = set(all_impl_keys)
    print(
        f"[flatten] Size gate: {_total_impl_chars:,} chars ≤ {_FULL_AUDIT_LIMIT:,} "
        f"— full audit ({len(all_impl_keys)} impl contracts)"
    )
    return {
        "in_scope":  all_impl_keys,
        "skeleton":  [],
        "out_scope": [k for k in order if k not in _all_impl_set],
        "method":    "full_audit_size_gate",
    }
# ── End size gate ─────────────────────────────────────────────────────────
```

#### Không thay đổi gì khác

`all_impl_keys` đã được filter đúng tại chỗ build:
```python
all_impl_keys = [
    k for k in order
    if not _is_interface_only(sources.get(k, ""))
    and not _is_mock_or_test(k)
]
```
→ Tự động loại mock, test, interface. Không cần thêm filter.

---

## Kỳ vọng

### Contest 42 (131KB → full audit)

Contracts thêm vào scope:
- `ReferralFeePoolV0.sol` → H-03, H-06 có thể được tìm
- `VestedRewardPool.sol` → H-13 có thể được tìm
- `MochiEngine.sol` → H-10 có thể được tìm

Trần lý thuyết: **9/13 → 13/13** (từ 69.2% lên 100%)

| Metric | Hiện tại (run-8) | Kỳ vọng sau size gate |
|--------|-----------------|----------------------|
| Trần lý thuyết | 9/13 | 13/13 |
| TP hiện tại | 8 | ≥ 8 (không regression) |
| TP tối đa có thể | 9 | 13 |

### Contest 35 (294KB → không đổi)

Không thay đổi gì — size gate không kích hoạt.

---

## Giới hạn đã biết

| Issue | Mức độ | Ghi chú |
|-------|--------|---------|
| Thêm contracts vào scope có thể tăng FP | Trung bình | Các contracts nhỏ có nhiều functions → agent sinh thêm findings |
| 200KB threshold cần tune | Thấp | Configurable qua env var — điều chỉnh dựa trên benchmark thêm |
| Không fix được large contests | Chấp nhận | Contest 35 vẫn dùng BFS — đây là tradeoff có chủ đích |

---

## Verification

```bash
cd /home/thangdd/repos/MiroFish/backend && source .venv/bin/activate

# Smoke test: contest 42 phải dùng full_audit_size_gate
python3 - <<'EOF'
import sys; sys.path.insert(0, '.')
sys.path.insert(0, 'scripts')
from flatten_contest import flatten_contest_dir

result, manifest = flatten_contest_dir(
    "/home/thangdd/repos/web3bugs/contracts/42",
    emit_manifest=True, verbose=True
)
method = manifest.get("scope_method")
assert method == "full_audit_size_gate", f"FAIL: got {method}"
print(f"✅ scope_method = {method}")
print(f"   in_scope contracts: {len(manifest.get('in_scope_keys', []))}")
EOF

# Smoke test: contest 35 phải dùng skeletonized_slither (không đổi)
python3 - <<'EOF'
import sys; sys.path.insert(0, '.')
sys.path.insert(0, 'scripts')
from flatten_contest import flatten_contest_dir

result, manifest = flatten_contest_dir(
    "/home/thangdd/repos/web3bugs/contracts/35",
    emit_manifest=True, verbose=True
)
method = manifest.get("scope_method")
assert method != "full_audit_size_gate", f"FAIL: 35 triggered size gate"
print(f"✅ contest 35 scope_method = {method} (unchanged)")
EOF

# Chạy run-9 contest 42 với size gate
rm -f /home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/42/hist_inv_cache.json
nohup bash scripts/run_benchmark.sh \
  /home/thangdd/repos/web3bugs/contracts/42 \
  ../benchmark/web3bugs/agent-redesign/42/run-9 \
  > /tmp/benchmark_42_run9.log 2>&1 &

# Eval
python3 scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_42.json \
  /home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/42/run-9/audit_report_dedup.json \
  --verbose | tee /home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/42/run-9/eval_result.txt
```

**Dấu hiệu thành công:**
- Session summary run-9 có sections cho `ReferralFeePoolV0`, `VestedRewardPool`, `MochiEngine`
- `scope_method = "full_audit_size_gate"` trong manifest/log
- TP ≥ 8 (không regression), kỳ vọng ≥ 9

---

## Kỳ vọng dài hạn

Threshold 200KB phù hợp với Web3Bugs contest benchmark. Với audit thực tế (private
audit), codebase lớn hơn — threshold cần tune hoặc làm configurable per-project.
Bước tiếp theo sau khi verify: benchmark thêm contest 35 để confirm không regression.
