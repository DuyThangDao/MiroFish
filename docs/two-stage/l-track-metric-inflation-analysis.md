# L-track Metric Inflation: Phân tích, Nguyên nhân và Giải pháp

> Phát hiện trong quá trình đánh giá RC fixes — Contest 35 (Sushi Trident), 2026-04-27

---

## 1. Vấn đề

### 1.1 Hiện tượng quan sát được

Sau khi áp dụng G-RC-1 (SWC tagging rules), L-track F1 cho contest 35 tăng từ **0.000 lên 0.857** — một cải thiện trông rất ấn tượng. Tuy nhiên khi kiểm tra report thực tế, tool chỉ produce **1 generic hint** về SWC-101:

> *"While Solidity 0.8.x introduced built-in overflow protection for arithmetic, it does not revert on explicit type casting... Use OpenZeppelin SafeCast."*

Không có function cụ thể nào được chỉ ra (`affected_assets: []`). Không có exploit path. Không có patch cụ thể.

### 1.2 Kết quả đối chiếu chi tiết

**6 GT bugs (tất cả L7 — SWC-101):**

| Bug | Hàm cụ thể | Tool có tìm ra không? |
|---|---|---|
| H-01 | `burn()` — unsafe downcast uint256→int128 | ❌ |
| H-04 | `mint()` — overflow trong liquidity calc | ❌ |
| H-05 | `_getAmountsForLiquidity()` — truncation | ❌ |
| H-09 | `rangeFeeGrowth` — underflow | ❌ |
| H-14 | `rangeFeeGrowth`, `secondsPerLiquidity` — cần unchecked | ❌ |
| H-15 | `initialPrice` — không validate range | ❌ |

**Điều tool thực sự có:** 1 finding với `SWC-101`, `functions=[]`, xuất hiện như một gợi ý "Long-term Remediation" trong report.

### 1.3 So sánh với finding có vị trí cụ thể

Cùng run, tool produce các finding khác **có đầy đủ context**:

| Finding | SWC | Functions được chỉ ra | Có exploit path? |
|---|---|---|---|
| Cross-Function Reentrancy | SWC-107 | `flashSwap()`, `swap()`, `mint()`, `burn()` (7 hàm) | ✅ |
| DoS with Failed Call | SWC-128 | `initialize()`, `transferMultiple()` | ✅ |
| Missing Initializer | SWC-112 | `initialize()`, `init()`, `batch()` | ✅ |
| **Silent Truncation** | **SWC-101** | **`[]` — trống** | ❌ |

→ Tool **có khả năng** produce actionable findings, nhưng với SWC-101 thì không làm được.

---

## 2. Nguyên nhân phỏng đoán

### 2.1 Cơ chế lenient matching của eval framework

```python
def _match_l(bug, findings):
    expected_swcs = L_TO_SWC.get(bug.label)  # L7 → {SWC-101}
    for f in findings:
        if f.source in ("consensus", "gap") and f.swc_ids & expected_swcs:
            return True  # ← bất kỳ 1 finding có SWC-101 = tất cả L7 bugs "found"
```

Thiết kế này đo **"tool có biết vulnerability class tồn tại không?"** — không đo **"tool có chỉ ra đúng location không?"**. Hệ quả: 1 generic hint → 6 TP, recall = 1.0.

### 2.2 Tại sao SWC-101 không có function location?

**Nguyên nhân chính — flattened multi-contract source:**

Contest 35 được flatten thành 1 file 248K chars từ 35 files. Các L7 bugs nằm rải rác trong `ConcentratedLiquidityPool.sol` — một contract chuyên biệt về AMM V3 tick math. Khi agents xử lý file phẳng khổng lồ:

- Agents detect được *pattern* "explicit cast tồn tại" (đủ để tag SWC-101) nhưng không trace được *context* để xác định function cụ thể
- Attention dilution: 248K chars → agents focus vào các pattern dễ nhận hơn (reentrancy, access control) thay vì đào sâu vào từng cast operation
- Manifest heuristic lỗi (`primary=so`): focus directive không trỏ đúng vào `ConcentratedLiquidityPool` — agents không biết đây là contract cần audit sâu

**Nguyên nhân phụ — SWC-101 trên Solidity 0.8.x khó nhận ra:**

Agents được training để biết "0.8 = safe overflow". G-RC-1 đã sửa nhận thức này ở mức *class detection* (giúp SWC-101 xuất hiện trong consensus) nhưng chưa đủ để agents *localize* từng instance:
- Explicit cast như `int256(uint256(x))` trông vô hại
- Pattern `toUint128()`, `toInt128()` dễ bị bỏ qua khi đọc lướt
- Trong concentrated liquidity math, các cast ẩn trong công thức dày đặc

**Nguyên nhân phụ — Confidence thấp (0.49):**

Consensus engine có thể đã merge nhiều signals yếu thành 1 finding mà không có đủ evidence để attach function names. Finding có confidence 0.49 (gần threshold loại bỏ) — chỉ vừa đủ vào report, không đủ data để localize.

### 2.3 Vấn đề với cách tool "tìm" SWC-101

Tool hiện tại detect SWC-101 theo hướng **top-down pattern matching**:
1. Agent đọc code, nhận ra có explicit cast
2. Tag SWC-101 vào finding
3. Consensus merge → 1 generic finding

Thay vì **bottom-up instance enumeration**:
1. Tìm tất cả `uint256 → uint128`, `int256 → int128` operations
2. Kiểm tra từng cái có thể overflow không
3. Mỗi instance = 1 finding độc lập

Cách hiện tại là "đọc lướt và ghi nhớ pattern" — không phải "enumerate và verify từng instance".

---

## 3. Ảnh hưởng đến đánh giá

### 3.1 Mức độ phóng đại

| Metric | Eval framework | Thực tế audit |
|---|---|---|
| L-track TP | 6 | ~0–1 |
| L-track F1 | **0.857** | **~0.0–0.15** |
| Combined F1 | 0.538 | ~0.15–0.20 |

### 3.2 Loại metric nào phù hợp hơn?

| Metric | Đo cái gì | Phù hợp cho |
|---|---|---|
| **Class-level recall** (hiện tại) | Tool có biết vulnerability class tồn tại không? | Triage / screening tool |
| **Function-level recall** | Tool có chỉ đúng function không? | Audit assistant |
| **Instance-level recall** | Tool có tìm từng bug riêng lẻ không? | Automated bug finder |

MiroFish định vị là **audit assistant** — function-level recall mới là metric phù hợp.

---

## 4. Giải pháp đề xuất

### 4.1 Cải thiện eval framework: thêm function-level metric

Thêm `F1_L_fn` — chỉ tính TP khi finding có function overlap với GT bug:

```python
# Cần map GT bug → expected function names
GT_FUNCTION_MAP = {
    ("35", "H-01"): {"burn"},
    ("35", "H-04"): {"mint"},
    ("35", "H-05"): {"_getAmountsForLiquidity"},
    # ...
}

def _match_l_strict(bug, findings):
    expected_swcs = L_TO_SWC.get(bug.label)
    expected_fns  = GT_FUNCTION_MAP.get((str(bug.contest_id), bug.bug_id), set())
    for f in findings:
        if f.source in ("consensus", "gap") and f.swc_ids & expected_swcs:
            if not expected_fns:          # GT không có function info → fall back lenient
                return True
            if f.functions & expected_fns: # function overlap required
                return True
    return False
```

Report song song cả 2 metrics để có full picture:
```
L F1 (class-level):    0.857  ← khả năng detect pattern
L F1 (fn-level):       0.xxx  ← khả năng localize bug
```

### 4.2 Cải thiện tool: localize SWC-101 instances

**Giải pháp ngắn hạn — Prompt engineering:**

Thêm instruction vào `stage1_instruction`:
```
For SWC-101 findings, you MUST enumerate each explicit cast operation separately:
- List each function containing uint256→uint128, int256→int128 (or similar) casts
- For each: state whether overflow/underflow is possible given the value range
- Do NOT merge all cast issues into one generic finding
```

**Giải pháp dài hạn — Static analysis pre-pass:**

Trước khi chạy LLM agents, dùng regex/AST scan để enumerate tất cả explicit cast operations:
```python
CAST_PATTERN = re.compile(
    r'(?:uint(?:8|16|32|64|128|160)|int(?:8|16|32|64|128))\s*\(\s*\w+\s*\)',
)
# Map each match → function name → inject vào context
```

Kết quả inject vào `contract_summary` như một section riêng:
```
EXPLICIT CAST OPERATIONS (potential SWC-101):
  burn(): int256(liquidityDelta) at line 234
  mint(): uint128(amount) at line 189
  _getAmountsForLiquidity(): uint128(amount0) at line 312
```

Agents nhận context này sẽ có đủ thông tin để produce function-level findings.

### 4.3 Fix manifest heuristic

Manifest lỗi (`primary=so`) làm focus directive trỏ sai contract → agents không audit sâu vào `ConcentratedLiquidityPool`. Cần fix `_compute_manifest()` để handle trường hợp contest có nhiều file nhỏ, đặc biệt khi primary contract nằm trong subdirectory sâu.

### 4.4 Nhận thức khi báo cáo kết quả

Trong các báo cáo đánh giá, luôn kèm theo disclaimer:

> *"L-track F1 sử dụng class-level lenient matching — 1 finding với đúng SWC ID đủ để match tất cả GT bugs cùng class. Metric này đo khả năng nhận diện vulnerability pattern, không đo khả năng localize từng bug instance. Function-level F1 (stricter) sẽ thấp hơn đáng kể."*

---

## 5. Tóm tắt

| Điểm | Nội dung |
|---|---|
| **Vấn đề** | L F1 = 0.857 nhưng tool chỉ có 1 generic hint, không actionable |
| **Root cause chính** | Eval framework lenient: 1 SWC match = N TP nếu tất cả GT bugs cùng class |
| **Root cause phụ** | Tool không localize được do attention dilution + manifest sai + SWC-101 khó trace trong flattened file |
| **Giải pháp eval** | Thêm function-level F1 metric chạy song song |
| **Giải pháp tool** | Static cast enumeration pre-pass + prompt yêu cầu enumerate từng instance |
| **Ưu tiên** | Fix eval metric trước (độ chính xác đánh giá) → rồi mới cải thiện tool |
