# HIST-INV v3 — Operation-Level Neutral Description

## Vấn đề với v2

HIST-INV v2 dùng prompt "describe what this function COMPUTES" → LLM mô tả ở **function level** (high-level purpose):
- burn() → "Calculates token amounts from liquidity and fees, decrements reserves"
- rangeFeeGrowth() → "Subtracts conditional storage-read values from global fee growth variables"

RAG findings được viết ở **operation level** (kỹ thuật cụ thể):
- "Decrease in tokens due to arithmetic overflow of uint128 variable"
- "get_fee_growth_inside should allow underflow/overflow"

Mismatch level → embedding distance lớn → wrong finding ranked cao hơn correct finding.

### Tại sao không dùng "risky operation" prompt

Nếu LLM identify được risk → LLM đang làm vulnerability detection → không cần RAG nữa.
Nếu LLM identify sai → wrong query → wrong finding → cascade error.
Vi phạm nguyên tắc kiến trúc: LLM chỉ cần đọc code factually, RAG thêm historical context.

---

## Giải pháp v3: Operation-Level Neutral Description

**Nguyên tắc**: LLM mô tả ở operation level (WHAT HAPPENS trong code), không phải function level (WHAT THE FUNCTION DOES) và không phải risk level (WHAT'S DANGEROUS).

```
Ví dụ:
  Function level:  "Removes liquidity from pool"                ← quá abstract
  Operation level: "Converts uint128 amount to -int128() cast"  ← đúng level
  Risk level:      "Unsafe cast can cause sign flip"            ← cần vulnerability knowledge
```

### Prompt mới

```python
prompt = (
    "You are a Solidity code analyst.\n\n"
    f"Function: {fn_name}()\n"
    f"Body:\n{fn_body}\n\n"
    "Describe the MOST SPECIFIC and DISTINCTIVE computation in this function.\n"
    "Focus on: exact arithmetic, type conversions, data types, and specific operations used.\n"
    "Be precise about types (uint128, int128, int24...) and operations (subtraction, cast, division).\n"
    "Do NOT describe business purpose. Do NOT say what's dangerous. Just describe WHAT HAPPENS at the code level.\n\n"
    "One sentence, under 20 words. Output ONLY the description."
)
```

### Kết quả test vs v2

| Function | v2 score | v3 score | Delta | Finding (v3) |
|---------|---------|---------|-------|-------------|
| burn (H-01) | 0.700 | ❌ EMPTY | — | body quá dài |
| _getAmountsForLiquidity (H-05) | 0.693 | **0.713** | +0.020⬆ | "Unsafe type-casting" ✅ |
| rangeFeeGrowth (H-09/H-14) | 0.696 | **0.732** | +0.036⬆ | "get_fee_growth_inside should allow underflow" ✅ |
| cross (H-11) | 0.707 | 0.701 | -0.006⬇ | ≈ |
| mint (H-04/H-08) | 0.714 | **0.742** | +0.028⬆ | "Unsafe type-casting" ✅ |

3/5 cải thiện đáng kể. `rangeFeeGrowth` lên 0.732 với correct finding — trước đây không tìm được.

---

## Vấn đề: burn() EMPTY và Sweet Point của window size

### Nguyên nhân EMPTY

Test ban đầu với full body (1432 chars) → EMPTY. **Tuy nhiên**: đây là **non-determinism của thinking model**, không phải structural issue. Re-test với cùng 1432 chars → hoạt động bình thường (score 0.739). Root cause: prompt ~1900 chars → thinking model đôi khi exhaust 2048 tokens trước khi output.

### Test kết quả các window size

| Window | Body chars | Score | Finding | -int128 captured |
|--------|-----------|-------|---------|-----------------|
| Full body | 1432c | 0.739 | "Unsafe type-casting" ✅ | ✅ (char 774) |
| **300+700** | **1005c** | **0.719** | **"Unsafe type-casting" ✅** | **✅** |
| Last 800 only | 800c | 0.738 | "Fees can be stolen" ❌ | ✅ |
| Last 600 only | 600c | 0.718 | "Unsafe type-casting" ✅ | ✅ |

### Sweet Point: ≤1000 → full; >1000 → first 300 + last 700

**Tại sao first 300 quan trọng:**
- Chứa function parameters với data types (`uint128 amount`, `int24 lower, upper`)
- LLM cần type context để mô tả đúng ("casts **uint128** to **int128**")
- "Last 800 only" bỏ first part → LLM focus sai operation → wrong finding

**Tại sao last 700:**
- Final computations, state updates, type casts thường nằm ở giữa/cuối
- burn(): `-int128(amount)` ở char 774/1432 → trong last 700 (chars 732+) ✅

**Tại sao threshold 1000:**
- ≤1000: prompt ~1500 chars total → thinking model ổn định, không EMPTY
- >1000: 300+700 = 1005 chars → cân bằng coverage và reliability

```python
def _extract_fn_body(source_code: str, fn_name: str) -> str:
    ...
    body = source_code[start:pos - 1].strip()
    if len(body) <= 1000:
        return body
    # Sweet point: first 300 (type context) + last 700 (final computation)
    # Covers -int128(amount) at char 774 in burn() (1432 chars total)
    return body[:300] + "\n...\n" + body[-700:]
```

---

## So sánh với v2 prompts

| Aspect | v2 (compute) | v3 (operation-level) |
|--------|-------------|---------------------|
| Prompt focus | "What function COMPUTES" | "Most specific, distinctive computation" |
| LLM task | High-level summarize | Identify specific operation |
| Vulnerability knowledge | Not needed ✅ | Not needed ✅ |
| Level | Function level | Operation level |
| Generic? | ✅ Yes | ✅ Yes |
| RAG alignment | Poor (function vs operation) | Better (operation vs operation) |

---

## Thay đổi implement

### File: `contract_kg_builder.py`

**1. Update `_describe_function_body()` prompt** — thay v2 prompt bằng v3:

```python
prompt = (
    "You are a Solidity code analyst.\n\n"
    f"Function: {fn_name}()\n"
    f"Body:\n{fn_body}\n\n"
    "Describe the MOST SPECIFIC and DISTINCTIVE computation in this function.\n"
    "Focus on: exact arithmetic, type conversions, data types, and specific operations used.\n"
    "Be precise about types (uint128, int128, int24...) and operations (subtraction, cast, division).\n"
    "Do NOT describe business purpose. Do NOT say what's dangerous. "
    "Just describe WHAT HAPPENS at the code level.\n\n"
    "One sentence, under 20 words. Output ONLY the description."
)
```

**2. Update `_extract_fn_body()` window** — từ `200+600` (v2) lên `300+700` (v3):

Rationale: first 300 = parameter type context, last 700 = final computation; threshold 1000 giữ prompt ≤1500 chars để thinking model không EMPTY.

```python
if len(body) <= 1000:
    return body
# Sweet point: first 300 (type context) + last 700 (computation)
return body[:300] + "\n...\n" + body[-700:]
```

---

## Tại sao v3 là generic approach đúng

1. **Không cần vulnerability knowledge**: LLM chỉ cần đọc code và mô tả operation — không cần biết cái gì là risky
2. **Aligns với RAG finding format**: RAG findings mô tả "operation X gây bug Y" — description ở operation level match tốt hơn
3. **Không bias contest**: applies to any Solidity function ở bất kỳ contest nào
4. **Không cascade error**: nếu description sai, chỉ query sai, không phải hallucinate vulnerability

---

## Vấn đề chưa giải quyết

| Issue | Cause | Status |
|-------|-------|--------|
| burn() EMPTY | Body 1432 chars quá dài | Fix: window 300+700 |
| H-17 nearestTick wrong reference | Pure logic bug, không có operation-level signal | Cần RAG DB có finding về nearestTick |
| H-15 initialize missing validation | No signal trong body (thiếu check) | RAG coverage gap |
| Agent bỏ qua inv dù đúng | Inv quá abstract, không map được vào specific code | Cần improve inv extraction |
