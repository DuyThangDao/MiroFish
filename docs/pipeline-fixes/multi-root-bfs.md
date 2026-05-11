# Fix: Multi-Root BFS Scope Selection

## Vấn đề hiện tại

Pipeline chọn **1 primary contract** làm gốc BFS để xác định scope. Contracts nằm ngoài import tree của primary bị **stub hóa** (chỉ giữ function signatures, body bị thay bằng `{ ... }`). Agents không thể tìm bugs trong stub contracts.

### Hai trường hợp thực tế bị ảnh hưởng

**Contest 100 (prePO):**
- Primary được chọn: `PrePOMarket` (LOC lớn + tên match `_CORE_NAME_RE`)
- Import tree của PrePOMarket: chỉ interfaces + OpenZeppelin
- `Collateral`, `SingleStrategyController` → **stubs** → TP=0

**Contest 104 (MiroPad):**
- Primary: `CoreCollection`
- Import tree: `ERC721Payable`, `ERC721Claimable`, `IRoyaltyVault` (interface only)
- `Splitter`, `RoyaltyVault`, `CoreProxy` ở 3 subdirs khác → **stubs** → miss H-02, H-03, H-05, H-06, H-09

---

## Giải pháp: Multi-Root BFS

Thay vì BFS từ 1 primary, chạy BFS từ **tất cả implementation contracts** (không phải interface, không phải mock/test), merge kết quả thành 1 in-scope set duy nhất.

### Logic thay đổi

**File:** `backend/scripts/flatten_contest.py`  
**Function:** `_classify_files()` — Tier 1 logic (lines ~375–395)

**Hiện tại:**
```python
# Tier 1: BFS từ 1 primary
primary_key = manifest.get("primary_key")
if primary_key and primary_key in graph:
    reachable = _get_reachable_set(primary_key, graph)
    # + Slither callers
```

**Sau fix:**
```python
# Tier 1: Multi-root BFS — BFS từ tất cả implementation contracts
all_impl_keys = [
    k for k in order
    if not _is_interface_only(sources.get(k, ""))
    and not _is_mock_or_test(k)       # helper mới
]
reachable: Set[str] = set()
for root_key in all_impl_keys:
    if root_key in graph:
        reachable |= _get_reachable_set(root_key, graph)
# + Slither callers (giữ nguyên)
if extra_scope_contracts:
    ...
```

### Helper cần thêm

```python
def _is_mock_or_test(key: str) -> bool:
    """True nếu file là mock, test, hoặc script — không cần phân tích."""
    p = Path(key).parts
    name = Path(key).stem.lower()
    return (
        any(part.lower() in ("test", "tests", "mock", "mocks", "scripts", "deploy")
            for part in p)
        or name.startswith(("mock", "test", "fixture", "deploy"))
    )
```

---

## Tác động dự kiến

### Context size

| Contest | Hiện tại | Sau fix | Tăng |
|---------|----------|---------|------|
| 35 | ~100KB | ~100KB | ~0% (import tree đã đủ) |
| 100 | 26KB | ~60KB | +130% (vẫn < contest 35) |
| 104 | ~40KB | ~80KB | +100% (vẫn < contest 35) |
| 123 (60 files) | ~80KB | ~120KB | +50% |

OZ contracts và dependencies đã được stub → union of import trees không tăng nhiều.

### Recall dự kiến

| Contest | Hiện tại | Sau fix | Bugs mới có thể tìm |
|---------|----------|---------|---------------------|
| 100 | 0% | ~50–70%? | H-01, H-02, H-03 (tất cả trong scope) |
| 104 | 33% | ~50–60%? | H-02, H-03, H-05, H-09 (Splitter/RoyaltyVault vào scope) |

H-06 (storage collision CoreProxy) vẫn khó — pattern phức tạp, không liên quan đến scope.

---

## Giới hạn còn lại sau fix

1. **Cross-subdir Slither dep graph vẫn sai** (contest 104) — multi-root BFS fix scope nhưng không fix call graph. Agents có source code đầy đủ nhưng thiếu thông tin "function A gọi function B".

2. **Critical function selection vẫn dùng primary** — `pick_critical_functions_from_summary()` vẫn ưu tiên functions của primary contract. Cần cập nhật thêm để đưa functions từ tất cả contracts vào pool.

3. **Không giải quyết được contests có 50+ contracts** — context quá lớn, có thể vượt ngưỡng token tối ưu (~100KB). Cần thêm filter: nếu tổng in-scope > threshold, fallback về single-root + secondary contracts.

---

## Implementation checklist

- [ ] Thêm `_is_mock_or_test(key)` vào `flatten_contest.py`
- [ ] Sửa `_classify_files()` Tier 1: multi-root BFS
- [ ] Giữ nguyên Tier 2 (README hints) và Tier 3 (conservative)
- [ ] Thêm size cap: nếu `sum(len(sources[k]) for k in reachable) > 200_000` → fallback single-root
- [ ] Cập nhật manifest `scope_method` thành `"multi_root_bfs"` để track
- [ ] Re-run contest 100 và 104 để verify

---

## Files thay đổi

| File | Thay đổi |
|------|---------|
| `backend/scripts/flatten_contest.py` | Sửa `_classify_files()` + thêm `_is_mock_or_test()` |
