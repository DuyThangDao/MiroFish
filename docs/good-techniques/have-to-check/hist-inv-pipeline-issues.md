# HIST-INV Pipeline Issues

## Tổng quan

HIST-INV là cơ chế inject historical vulnerability invariants vào source code dưới dạng `// [HIST-INV]:` comments trước mỗi function definition. Mục tiêu: giúp HIST-INV Verifier (agent `code_similarity_auditor`) nhận ra các bug đã từng xuất hiện trong protocol tương tự.

Pipeline gồm 4 bước:

```
RAG retrieval (OP query)
    ↓
hist_inv_cache.json  (contract, fn) → slugs
    ↓
_build_inv_map_from_slugs()  slugs → sections.inv → inv_text
    ↓
_annotate_source_with_hist_inv()  inject // [HIST-INV] vào source
    ↓
HIST-INV Verifier  Turn1 (flag) → Turn2 (confirm)
```

Thực nghiệm contest 35 (run-74): **confirmed=0** dù có invariants đúng được retrieve. Hai nguyên nhân root cause:

---

## Vấn đề 1 — Slug cap cắt bỏ invariant đúng

### Mô tả

`_build_inv_map_from_slugs()` trong `run_contract_audit.py` chỉ lấy **top-2 slugs** cho mỗi function:

```python
def _build_inv_map_from_slugs(hist_cache, inv_lookup: dict) -> dict:
    inv_map = {}
    for (contract, fn), slugs in hist_cache.get_matched_slugs().items():
        inv_lines = []
        for slug in slugs[:2]:          # ← chỉ lấy 2 slug đầu
            lines = inv_lookup.get(slug) or []
            inv_lines.extend(lines[:2])
        if inv_lines:
            inv_map[(contract, fn)] = "\n".join(inv_lines[:3])
    return inv_map
```

RAG trả về 6 slugs theo thứ tự score, nhưng slug có invariant đúng nhất có thể xếp thứ 3 trở đi → bị drop trước khi inject.

### Ví dụ thực tế — H-17 (contest 35)

GT bug: `ConcentratedLiquidityPool.rangeFeeGrowth` dùng `nearestTick` (cached storage) thay vì current price tick → stale tick reference → sai fee growth calculation.

Slugs được retrieve cho `rangeFeeGrowth` (theo thứ tự):
```
1. h-04-underflow-could-happened...     → INV: "fee growth subtraction must be unchecked"
2. h-04-positions-owed-fees...          → INV: "fee growth subtraction must be unchecked"
3. custom_35_h17_rangefeegrowth_...     → INV: "int24 current tick must be updated to the
                                                 latest price state before comparing against
                                                 range boundary ticks"   ← ĐÚNG INVARIANT
4. leverage-not-available...
5. h-03-missing-lowerupper-check...
6. incorrect-fee-growth-initialisation...
```

Slug thứ 3 (`custom_35_h17`) có invariant trực tiếp mô tả H-17, nhưng bị cắt bởi `slugs[:2]`.

**Kết quả inject thực tế** (chỉ từ slug 1+2, đều nói về unchecked):
```solidity
// [HIST-INV]: uint256 fee growth subtraction operations must be performed within an
//             unchecked block to permit 256-bit wrapping
//             uint256 fee growth delta calculations must occur inside an unchecked block
function rangeFeeGrowth(...) {
```

**Invariant bị bỏ qua** (từ custom_35_h17):
```
int24 current tick must be updated to the latest price state before comparing
against range boundary ticks
```

### Tác động

- H-17 không được inject hint đúng → HIST-INV Verifier không flag → confirmed=0
- Agent no_inv tự tìm được nearestTick stale nhưng attribute về `swap()` (sai function) → không match GT
- Agent with_inv (inject đúng custom_35_h17) → attribute đúng `rangeFeeGrowth` → match GT

### Fix đề xuất

Tăng slug cap từ 2 lên 3-4, ưu tiên custom slugs:

```python
# Ưu tiên custom slugs lên đầu
custom = [s for s in slugs if s.startswith("custom_")]
others = [s for s in slugs if not s.startswith("custom_")]
ordered_slugs = (custom + others)[:4]   # tăng cap lên 4

for slug in ordered_slugs:
    lines = inv_lookup.get(slug) or []
    inv_lines.extend(lines[:2])
if inv_lines:
    inv_map[(contract, fn)] = "\n".join(inv_lines[:4])
```

---

## Vấn đề 2 — Source code secondary contracts không được HIST-INV Verifier đọc

### Mô tả

HIST-INV Verifier chỉ nhận source của **primary contract**, bỏ qua toàn bộ secondary contracts. Có 3 tầng cắt:

**Tầng 1** — `_filter_source_to_primary()` trong Turn1:
```python
# cyber_session_orchestrator.py
primary_source = _filter_source_to_primary(network_summary, primary_contract)
turn1_prompt = _HIST_INV_VERIFIER_TURN1_PROMPT.replace("{source}", primary_source)
```
`network_summary` chứa tất cả contracts, nhưng chỉ primary contract được truyền vào Turn1.

**Tầng 2** — Hard truncate `[:3000]` trong Turn2:
```python
turn2_prompt = (
    _HIST_INV_VERIFIER_BATCH_PROMPT
    .replace("{batch_items}", batch_items)
    .replace("{source}", primary_source[:3000])  # ← chỉ 3000 ký tự đầu
)
```
Ngay cả trong primary contract, Turn2 chỉ nhận ~60-70 dòng đầu. Functions ở cuối file không bao giờ được verify.

**Tầng 3** — Annotation inject nhưng verifier không đọc được:
`[HIST-INV]` comments được inject vào tất cả contracts (bao gồm secondary), nhưng verifier chỉ đọc primary → annotations ở secondary vô nghĩa.

### Ví dụ thực tế — Contest 35

**GT bugs trong secondary contracts (out of scope hoàn toàn):**

| GT Bug | Contract | Function | Vấn đề |
|--------|---------|---------|--------|
| H-03 | ConcentratedLiquidityPoolManager | reclaimIncentive | Verifier không nhận source này |
| H-16 | ConcentratedLiquidityPoolManager | claimReward | Verifier không nhận source này |

**GT bug trong primary contract nhưng bị truncate (Turn2):**

`ConcentratedLiquidityPool.sol` (~700 dòng). `rangeFeeGrowth` ở dòng 601:
- Turn1 nhận full primary source → có thể thấy annotation ở dòng 601 ✅
- Turn2 nhận `primary_source[:3000]` ≈ dòng 1-60 → **rangeFeeGrowth không vào được Turn2** ❌

```
primary_source[:3000] ≈ lines 1–65:
  contract header, storage variables, constructor, initialize()
  ...và hết 3000 ký tự.

rangeFeeGrowth() ở dòng 601 → không bao giờ được Turn2 verify.
```

### Tác động trên contest 35

| Trường hợp | Số bugs | Nguyên nhân |
|-----------|---------|------------|
| Out of scope (secondary contracts) | 2 (H-03, H-16) | `_filter_source_to_primary` |
| In scope nhưng bị Turn2 truncate | ≥1 (H-17) | `[:3000]` |
| In scope + custom slug bị drop | 2 (H-01, H-15) | `slugs[:2]` + custom slug ở vị trí sai |

Tổng: **confirmed=0** dù retrieval quality tốt cho 5/17 GT functions.

### Fix đề xuất

**Fix tầng 1** — Truyền full network_summary vào Turn1, không filter:

```python
# Thay vì filter, truyền toàn bộ source có [HIST-INV]
turn1_prompt = _HIST_INV_VERIFIER_TURN1_PROMPT.replace("{source}", network_summary)
```

Nếu network_summary quá lớn, chỉ filter theo contracts có [HIST-INV] annotations:

```python
annotated_contracts = _filter_contracts_with_hist_inv(network_summary)
turn1_prompt = _HIST_INV_VERIFIER_TURN1_PROMPT.replace("{source}", annotated_contracts)
```

**Fix tầng 2** — Turn2 không cần full source; chỉ cần function body của function cần verify:

```python
# Thay vì primary_source[:3000], extract chính xác function body
fn_source = _extract_fn_body_from_source(network_summary, fn_name)
turn2_prompt = (
    _HIST_INV_VERIFIER_BATCH_PROMPT
    .replace("{batch_items}", batch_items)
    .replace("{source}", fn_source)   # chính xác function body, không truncate
)
```

---

## Summary

| Issue | Root cause | Affected bugs | Fix |
|-------|-----------|--------------|-----|
| Slug cap | `slugs[:2]` bỏ slug có inv đúng | H-17 (và các bug có custom slug xếp 3+) | Tăng cap lên 4, ưu tiên custom slugs |
| Source truncation | `_filter_source_to_primary` + `[:3000]` | H-03, H-16 (out of scope), H-17 (truncated) | Turn1 dùng full annotated source; Turn2 dùng function body thay vì `[:3000]` |

Nếu fix cả 2: expected **+3 confirmed findings** (H-03, H-16, H-17) cho contest 35.
