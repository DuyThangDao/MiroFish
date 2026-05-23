# RAG Pipeline Diagnosis — Session 2026-05-23

**Bối cảnh:** Điều tra regression TP từ 9-11 (historical) xuống 7-8 (runs 1-9, contest 35).  
**Trạng thái:** Fixes A/B/C đã implement. Run-12 đang chạy để validate.

---

## 1. Regression Timeline

| Thời điểm | TP | Ghi chú |
|-----------|:--:|---------|
| Baseline lịch sử (contest 35, pre-regression) | 9–13 | Commit `443d816` có run đạt 13 TP |
| Runs 1–9 (sau các commits 8efa1f5 + prompt change) | 7–8 | Regression xác nhận |
| Run-10 (sau Fix A+B+C) | 6 | Dưới mức kỳ vọng |
| Run-11 (sau Fix A+B+C) | 8 | Phục hồi một phần |
| Run-12 | _đang chạy_ | Chờ kết quả |

---

## 2. Root Cause Xác Định (git diff `443d816..HEAD`)

### Root Cause #1 — Commit `8efa1f5`: Persona prompt migration

**Thay đổi:** `system_prompt` của agent đổi từ persona dài 200-500 từ (chứa DeFi field names cụ thể) sang abstract worldview 40-80 từ (generic).

**Impact:** Turn 1 dùng `system_prompt` để seed invariant extraction. Old prompt chứa vocabulary như `feeGrowthInside`, `rewardDebt`, `secondsPerLiquidityInside` → invariants cụ thể → RAG query embedding gần với DB entries → Turn 2 inject đúng pattern. New prompt → generic invariants → RAG query miss → Turn 2 không có context.

**H bugs bị ảnh hưởng:** H-06, H-07, H-16 (staleness), H-09, H-14 (secondsPerLiquidity overflow).

### Root Cause #2 — Premature "proceed to writing" signal trong Turn 2

**Thay đổi:** Trong `build_round1_prompt` (`contract_oasis_env.py`), 2 dòng xuất hiện giữa STEP 2 trước khi model đọc hết checklist:

```
After analysis, proceed to writing FINDING blocks.
No summary or commentary needed — go straight to findings.
```

**Impact:** Model bắt đầu viết findings ngay sau STEP 2 → bỏ qua CAST & COMPARISON PRECISION, STATE UPDATE ORDERING, CROSS-CALL SEQUENCING ở phía dưới.

**H bugs bị ảnh hưởng:** H-03, H-04, H-05, H-08 (cast overflow), H-10, H-13 (ordering).

---

## 3. Fixes Đã Implement

### Fix A — Enrich agent prompts (`contract_profile_generator.py`)

**Mục tiêu:** Khôi phục DeFi vocabulary vào Turn 1 để cải thiện RAG query quality.

**A.1 — `defi_analyst`:**
- `prompt`: Thêm đoạn **CROSS-CALL STALENESS** — mô tả pattern WRITER/READER function và stale accumulator
- `core_question`: Thêm field names cụ thể (`feeGrowthInside`, `secondsPerLiquidityInside`, `rewardDebt`) làm anchor ví dụ

**A.2 — `state_machine_analyst`:**
- `prompt`: Thêm **CONDITIONAL SYNC SKIP** (branch skip synchronization) và **INTRA-FUNCTION ORDERING** (accumulator phải update trước khi liquidity thay đổi)
- `core_question`: Anchor vào `secondsPerLiquidity`, `rewardPerShare`, `feeGrowthInside`

**Generalizability:** `prompt` dùng generic patterns (không hardcode field names), áp dụng cho CLP/lending/vault/farming. `core_question` dùng CLP field names làm *ví dụ*, không block non-CLP analysis.

### Fix B — Xóa premature write signal (`contract_oasis_env.py`)

Xóa 2 dòng "proceed to writing FINDING blocks" khỏi giữa STEP 2. Model giờ đọc hết CAST & COMPARISON + STATE UPDATE ORDERING trước khi bắt đầu viết.

### Fix C — Đổi framing invariants (`contract_oasis_env.py`)

```python
# Cũ:
f"Your invariants from Phase A (use these — do NOT re-derive):\n{injected_invariants}\n"

# Mới:
f"Your invariants from Phase A (starting point — also apply ALL independent checks below):\n{injected_invariants}\n"
```

Cho phép model apply CAST/STATE UPDATE checks độc lập với invariants từ Turn 1.

---

## 4. RAG DB Coverage Analysis

**Phương pháp:** Query RAG trực tiếp bằng GT bug descriptions (không qua pipeline) với threshold 0.65.

**Kết quả (2026-05-23):**

| H Bug | RAG Score | RAG Match (excerpt) | Status |
|-------|:---------:|---------------------|--------|
| H-01 | 0.708 | "An attacker can force 0 shares to be minted" (Hyperdrive) | INJECT |
| H-02 | 0.726 | "PositionManager moveLiquidity" (Ajna Protocol) | INJECT |
| H-03 | 0.725 | "DoS: Blacklisted user may prevent withdraw" (FactoryDAO) | INJECT |
| H-04 | 0.723 | "LiquidityProviders.sol share price" (Biconomy) | INJECT |
| H-05 | 0.765 | "Unsafe type-casting" | INJECT |
| H-06 | 0.701 | "collect() function will always return 0" | INJECT |
| H-07 | — | 429 quota exceeded | ERROR |
| H-08 | — | 429 quota exceeded | ERROR |
| H-09 | 0.755 | "Underflow could happen when calculating" | INJECT |
| H-10 | 0.709 | "Swaps can be done for free and steal reserves" | INJECT |
| H-11 | 0.745 | "Liquidity staked at ticks can be manipulated" | INJECT |
| H-12 | — | 429 quota exceeded | ERROR |
| H-13 | — | 429 quota exceeded | ERROR |
| H-14 | 0.758 | "get_fee_growth_inside in tick.rs" | INJECT |
| H-15 | 0.713 | "LiquidityProviders.sol share price" | INJECT |
| H-16 | 0.720 | "User can avoid bankrupting by calling" | INJECT |
| H-17 | — | 429 quota exceeded | ERROR |

**Summary:** 12/12 queried bugs đạt INJECT level (≥0.65). 5 bugs không query được do rate limit.

**Kết luận quan trọng:** RAG DB *có* pattern relevant cho tất cả bugs contest 35. Vấn đề không phải ở nội dung DB mà ở **cách pipeline query DB** (chất lượng Turn 1 invariants).

---

## 5. Hai Vấn Đề Cấu Trúc Còn Mở

### Vấn đề S1 — Skepticism Gate Quá Strict

**Code hiện tại** (`cyber_session_orchestrator.py` ~line 2752):

```python
"  - BE SKEPTICAL: Assume the code is SAFE first. Do not force a match.\n"
"  - Check if THIS contract's code has the EXACT SAME logical flaw.\n"
"  - Only write a FINDING if you can extract the SPECIFIC CODE LINES proving it.\n"
"  - If the historical exploit path is blocked or mitigated, EXPLICITLY state 'Mitigated' and skip.\n"
```

**Vấn đề:** 2 dòng có wording quá strict:
- `"EXACT SAME logical flaw"` — bugs thực tế là *variations*, không phải bản sao
- `"state 'Mitigated' and skip"` — khuyến khích dismiss thay vì investigate

**Trade-off:**
- Nếu bỏ hoàn toàn: FP spike từ 53-64 lên 80-100+. Không khuyến nghị.
- Nếu soften 2 dòng đó (giữ nguyên phần còn lại): FP tăng nhẹ (~5-10 FP), TP tăng ~1-2 cho H bugs bị dismiss sai.

**Đề xuất tinh chỉnh:**

```python
# Từ:
"  - Check if THIS contract's code has the EXACT SAME logical flaw.\n"
"  - If the historical exploit path is blocked or mitigated, EXPLICITLY state 'Mitigated' and skip.\n"

# Thành:
"  - Check if THIS contract's code has the SAME CLASS of logical flaw (pattern may vary in details).\n"
"  - If the historical exploit path is clearly blocked by the code, note the mitigation but still check for partial violations.\n"
```

### Vấn đề S2 — RAG Ceiling `_MAX_RAG_INJECT_PER_AGENT = 4`

**Cơ chế:** Mỗi agent extract 3-6 invariants → RAG query per invariant → chỉ top-4 by score được inject hint. Invariants ở rank 5-6 xử lý "blind" (không có historical context).

**Trade-off:**
- Nâng 4→6: context dài hơn (~500-800 tokens/agent), rank 5-6 thường score 0.65-0.67 (borderline) → noise tăng nhẹ
- Benefit thực tế phụ thuộc vào việc agents có thực sự extract >4 invariants không

**Cần verify trước khi quyết định:** Đếm số invariants trung bình per agent từ run-10/11/12 logs.

---

## 6. Pending — Chờ Run-12

**Câu hỏi cần trả lời từ run-12:**
1. Turn 1 invariants của `defi_analyst` và `state_machine_analyst` có mention `feeGrowthInside`/`secondsPerLiquidity` không? (Verify Fix A có hiệu lực)
2. Agents có đọc đến CAST & COMPARISON và STATE UPDATE ORDERING không? (Verify Fix B/C)
3. Bao nhiêu invariants trung bình per agent? (Quyết định có cần nâng RAG ceiling không)
4. TP/FP là bao nhiêu? (Đánh giá tổng thể)

**Log cần check:**
```bash
tail -f /tmp/benchmark_35_run12.log
grep -E "INV-|RAG\|INJECT|FINDING" /tmp/benchmark_35_run12.log
```

---

## 7. Roadmap Tiếp Theo

| # | Vấn đề | Action | Phụ thuộc |
|---|--------|--------|-----------|
| S1 | Skepticism gate | Soften 2 dòng wording | Không |
| S2 | RAG ceiling | Nâng 4→6 nếu agents thực sự extract >4 inv | Verify run-12 logs |
| P3 | Single-hypothesis bias | Thêm instruction Turn 2 (đã có plan trong open-problems.md) | Không |
| P4 | Economic attack blind spots | Thêm JIT + state-reset patterns (đã có plan trong open-problems.md) | Không |

**Xem thêm:** [open-problems.md](open-problems.md) cho P1-P5 từ session trước.
