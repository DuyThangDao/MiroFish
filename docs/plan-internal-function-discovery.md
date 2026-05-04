# Plan: Internal Function Discovery (Track L Blind Spot Fix)

## Vấn đề

Track L F1=0.000 trên contest 35. Root cause: contract profile chỉ gắn "Static SWC
candidates" cho public/external functions. Internal functions như `burn()`,
`_getAmountsForLiquidity()`, `rangeFeeGrowth()` không được hint → agents không
investigate → miss toàn bộ L-track bugs.

Code gây vấn đề — `contract_kg_builder.py:440`:
```python
public_funcs = [f for f in entity.functions if f.visibility in ("public", "external")]
# Chỉ public/external mới vào profile → internal functions bị blind spot
```

Slither đã phân tích internal functions và populate `f.swc_candidates` cho chúng,
nhưng data này không bao giờ được inject vào agent prompt.

---

## Hướng A — Expose internal SWC candidates (ít thay đổi, ưu tiên trước)

### Nguyên lý

Thêm section `INTERNAL FUNCTIONS WITH SWC RISK` vào contract profile, liệt kê
các internal functions mà Slither đã flag có SWC candidates. Agents có thêm
target để investigate trong R1, không thay đổi pipeline còn lại.

### Thay đổi cần làm

**File:** `backend/app/services/contract_kg_builder.py`

**Vị trí:** hàm `build_context_summary()`, sau section `PUBLIC/EXTERNAL FUNCTIONS`

```python
# Thêm sau block public_funcs
internal_swc_funcs = [
    f for f in entity.functions
    if f.visibility in ("private", "internal")
    and f.swc_candidates
]
if internal_swc_funcs:
    lines.append("INTERNAL FUNCTIONS WITH SWC RISK:")
    for f in internal_swc_funcs:
        lines.append(f"  - {f.name}()")
        lines.append(f"    Static SWC candidates: {', '.join(f.swc_candidates)}")
    lines.append("")
```

Ngoài ra, mở rộng `CRITICAL FUNCTIONS — full source` để bao gồm internal
functions có SWC-101 candidates (hiện chỉ inject top-7 theo caller count):

```python
# Trong _build_critical_functions_section() hoặc tương đương:
swc101_internal = [
    f.name for f in entity.functions
    if f.visibility in ("private", "internal")
    and "SWC-101" in (f.swc_candidates or [])
]
# Inject full source cho các hàm này, ưu tiên trước caller-count ranking
```

### Checklist

- [ ] Thêm `INTERNAL FUNCTIONS WITH SWC RISK` section vào `build_context_summary()`
- [ ] Verify Slither có đang populate `swc_candidates` cho internal functions
      (nếu không → cần bổ sung logic scan unsafe cast pattern trong `_analyze_function()`)
- [ ] Extend `CRITICAL FUNCTIONS — full source` để bao gồm SWC-101 internal functions
- [ ] Chạy lại contest 35, check xem `burn()`, `_getAmountsForLiquidity()`,
      `rangeFeeGrowth()` có xuất hiện trong R1 discoveries không
- [ ] So sánh Track L F1 trước/sau

### Rủi ro

- Nếu Slither không phát hiện unsafe cast trong internal functions (chỉ detect
  ở public), thì section này sẽ trống → không có cải thiện → chuyển Hướng B
- Context dài hơn một chút nhưng không đáng kể (chỉ thêm vài dòng per function)

---

## Hướng B — Full source injection cho R1 (fallback nếu A không hiệu quả)

### Nguyên lý

Chuẩn theo SmartLLM / Broad Analysis strategy: inject toàn bộ source code của
contract vào R1 agent prompt, bỏ filter visibility. Agents tự scan tất cả
functions thay vì chỉ nhìn vào profile summary.

Đây là approach đạt recall=100% trong SmartLLM (precision 62.5%).

### Thay đổi cần làm

**File:** `backend/app/services/contract_kg_builder.py`

Trong `build_context_summary()`, thêm section `FULL CONTRACT SOURCE` ở cuối
(hoặc thay thế phần `FUNCTION IMPLEMENTATIONS` hiện tại):

```python
if entity.source_code and len(entity.source_code) < 15_000:
    # Contract nhỏ: inject toàn bộ
    lines.append("=== FULL CONTRACT SOURCE ===")
    lines.append(entity.source_code)
elif entity.source_code:
    # Contract lớn: inject tất cả internal functions
    internal_sources = ContractKGBuilder._extract_function_snippets(
        entity.source_code,
        [f.name for f in entity.functions if f.visibility in ("private", "internal")]
    )
    if internal_sources:
        lines.append("INTERNAL FUNCTION IMPLEMENTATIONS (full source):")
        for fname, src in internal_sources.items():
            lines.append(f"\n// --- function {fname} ---")
            lines.append(src)
```

**File:** `backend/app/services/cyber_session_orchestrator.py`

Thêm instruction vào R1 prompt của agents:

```
IMPORTANT: The contract source above includes internal/private functions.
You MUST check ALL functions (public, external, internal, private) for vulnerabilities.
Do not limit your analysis to only public/external functions.
```

### Checklist

- [ ] Thêm `FULL CONTRACT SOURCE` hoặc `INTERNAL FUNCTION IMPLEMENTATIONS` vào profile
- [ ] Thêm instruction yêu cầu agents check ALL functions vào R1 prompt
- [ ] Giới hạn source injection: contracts > 15k chars chỉ inject internal functions
      (tránh vượt context limit)
- [ ] Đo latency: kỳ vọng tăng 20-40% do context dài hơn
- [ ] Chạy lại contest 35, verify `burn()` và `_getAmountsForLiquidity()` được discover
- [ ] Chạy thêm 2-3 contests khác để đo precision impact (kỳ vọng FP tăng)

### Tradeoff so với Hướng A

| Tiêu chí | Hướng A | Hướng B |
|----------|---------|---------|
| Recall cải thiện | Phụ thuộc Slither coverage | Cao (SmartLLM: 100%) |
| Precision impact | Nhỏ | FP có thể tăng |
| Latency | Không đổi | +20-40% |
| Thay đổi code | 15-20 dòng | 30-50 dòng + prompt |
| Rủi ro | Slither có thể miss | Context overflow với contract lớn |

---

## Thứ tự triển khai

1. Verify Slither có detect SWC-101 trong `burn()` cho contest 35 không
   (nếu có → Hướng A đủ; nếu không → skip thẳng Hướng B)
2. Triển khai Hướng A
3. Chạy contest 35, đo Track L F1
4. Nếu Track L F1 < 0.3 sau Hướng A → triển khai Hướng B
5. Benchmark trên ≥3 contests để đo precision impact

## Không thay đổi

- R2, R3, confidence formula, threshold
- Cách evaluator tính F1 (đây là vấn đề riêng — xem vấn đề S-track inflation)
- Output schema của consensus_engine
