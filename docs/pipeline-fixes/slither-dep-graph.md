# Fix: Slither Dep Graph — Tổng quát

## Vai trò của dep graph

Dep graph (Slither) và scope selection (BFS) giải quyết 2 vấn đề **khác nhau**:

| | Scope Selection (BFS) | Dep Graph (Slither) |
|---|---|---|
| **Câu hỏi** | Agents đọc source code contract nào? | Trong code đó, agents tập trung vào đâu? |
| **Output** | Danh sách files in-scope / out-scope | Call graph, critical functions, state variable R/W |
| **Ảnh hưởng khi sai** | Agents mù với contract có bug | Agents thấy code nhưng thiếu định hướng |
| **Fix** | Multi-root BFS | Tài liệu này |

---

## Bug 1 — Contest 104: Wrong compilation directory

### Root cause

**File:** `backend/app/services/contract_dep_graph.py`, line 183

```python
_hardhat_cfg = next(path.rglob("hardhat.config.*"), None)
```

`rglob` trả về files theo filesystem inode order (không phải alphabetical). Với contest 104 có 3 subdirs, nó chọn `splits/hardhat.config.ts` trước trong khi `CoreCollection` nằm trong `core-contracts/`. Slither compile từ `splits/` → `CoreCollection` not found.

### Fix

Thay vì lấy config đầu tiên tìm được, tìm config nào mà subdir của nó chứa file `.sol` define `contract_name`:

```python
def _find_hardhat_cfg_for_contract(
    path: Path, contract_name: str
) -> Optional[Path]:
    """
    Tìm hardhat.config trong subdir chứa định nghĩa contract_name.
    Fallback về config đầu tiên tìm được nếu không match.
    """
    import re
    contract_pattern = re.compile(
        rf'\bcontract\s+{re.escape(contract_name)}\b'
    )
    for cfg in path.rglob("hardhat.config.*"):
        # Grep tất cả .sol trong subdir của config này
        for sol_file in cfg.parent.rglob("*.sol"):
            try:
                content = sol_file.read_text(errors="replace")
                if contract_pattern.search(content):
                    return cfg
            except OSError:
                continue
    # Fallback: config đầu tiên
    return next(path.rglob("hardhat.config.*"), None)
```

Thay thế trong `_resolve_slither_target()`:
```python
# Cũ:
_hardhat_cfg = next(path.rglob("hardhat.config.*"), None)

# Mới:
_hardhat_cfg = _find_hardhat_cfg_for_contract(path, contract_name)
```

### Coverage

- ✓ Contest 104: chọn đúng `core-contracts/` vì có `CoreCollection.sol`
- ✓ Mọi multi-subdir contest khác (43/102 contests)
- ✓ Single-subdir contests không bị ảnh hưởng (vẫn tìm được config duy nhất)
- ✗ Cross-subdir dependencies (Splitter/RoyaltyVault ở subdir khác) vẫn thiếu trong Slither compile — nhưng scope đã được fix bởi multi-root BFS

---

## Bug 2 — Contest 100: Wrong primary contract selection

### Root cause

**File:** `backend/scripts/flatten_contest.py`, function `_compute_manifest()` (line ~460)

Scoring heuristic: `score = LOC × name_multiplier + in_degree × 200`

- `PrePOMarket` chứa "Market" → `_CORE_NAME_RE` match → ×1.5 boost
- `PrePOMarket` có nhiều LOC hơn `Collateral`
- Kết quả: `PrePOMarket` thắng dù không phải contract quan trọng nhất

Primary sai → Slither query "ai gọi PrePOMarket?" → 0 callers → forward BFS → Collateral không vào scope (trước khi multi-root BFS fix).

### Fix

Thêm **mutable function count** vào scoring — contracts có nhiều state-writing functions có nhiều khả năng chứa bugs hơn:

```python
# Thêm vào vòng lặp scoring trong _compute_manifest():
import re

# Đếm non-view/non-pure functions có body
mutable_fn_count = len(re.findall(
    r'\bfunction\b[^;{]*\{',   # có body (kết thúc bằng {)
    stripped
)) - len(re.findall(
    r'\bfunction\b[^;{]*\b(?:view|pure)\b[^;{]*\{',
    stripped
))
score += max(0, mutable_fn_count) * 120

# Penalty cho contracts tên có "Market", "Factory", "Registry"
# nếu chúng chủ yếu là orchestration, không phải core logic
if re.search(r'Factory|Registry|Router', cname, re.IGNORECASE):
    score *= 0.7
```

### Tại sao không chỉ thêm "Collateral" vào `_CORE_NAME_RE`?

Quá cụ thể — chỉ fix contest 100. Mutable function count là signal tổng quát hơn: contract có nhiều state mutations thường là "core logic", bất kể tên gọi.

### Coverage

- ✓ Contest 100: `Collateral` (nhiều mutable functions) sẽ score cao hơn `PrePOMarket`
- ✓ Các contests tương tự có main logic contract tên không match CORE pattern
- ✗ Vẫn là heuristic — không đảm bảo 100% cho mọi trường hợp

---

## Bug 3 — Structural: Primary-only Slither query

### Root cause

Hiện tại Slither chỉ được query một lần với 1 contract: "ai gọi `primary`?". Với contest 100, câu trả lời là 0 (không ai gọi PrePOMarket). Nhưng câu hỏi đúng phải là: "trong project này có bao nhiêu implementation contracts và chúng gọi nhau như thế nào?"

### Fix (medium effort)

Sau khi có scope từ multi-root BFS, chạy Slither một lần trên toàn bộ project và build **full project call graph**:

```python
def build_full_project_dep_graph(
    source_path: str,
    in_scope_contracts: List[str]
) -> DepGraphSummary:
    """
    Thay vì query callers của 1 primary, build call graph
    cho tất cả in_scope_contracts.
    """
    sl = Slither(source_path)
    all_edges = {}
    for contract in sl.contracts:
        if contract.name in in_scope_contracts:
            for fn in contract.functions:
                callees = [c.name for c in fn.internal_calls + fn.external_calls_as_expressions]
                all_edges[f"{contract.name}.{fn.name}"] = callees
    return DepGraphSummary(
        primary_contract=in_scope_contracts[0],
        call_graph=all_edges,
        ...
    )
```

---

## Thứ tự triển khai đề xuất

```
Phase 1 — Scope fix (impact cao, effort thấp):
  └── Multi-root BFS (flatten_contest.py)
      → Fix contest 100 và 104 hoàn toàn về scope
      → Không cần Slither chạy đúng

Phase 2 — Slither fix (impact trung bình, effort thấp):
  ├── Bug 1: _find_hardhat_cfg_for_contract (contract_dep_graph.py)
  │   → Contest 104 compile đúng subdir → dep graph có CoreCollection
  └── Bug 2: Mutable function count scoring (flatten_contest.py)
      → Contest 100 chọn đúng primary → Slither query đúng

Phase 3 — Full project dep graph (impact cao, effort cao):
  └── build_full_project_dep_graph
      → Dep graph chính xác cho toàn bộ project
      → Phụ thuộc Phase 1 + 2 hoàn thành trước
```

---

## Files thay đổi

| File | Phase | Thay đổi |
|------|-------|---------|
| `backend/scripts/flatten_contest.py` | 1, 2 | Multi-root BFS + mutable fn scoring |
| `backend/app/services/contract_dep_graph.py` | 2, 3 | `_find_hardhat_cfg_for_contract` + full project graph |
