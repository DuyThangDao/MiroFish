# Đánh giá Gemini 3.x — Contest 19 & Contest 3

> Ngày: 2026-04-26 | Cấu hình: gemini-3-flash-preview (main) + gemini-3.1-pro-preview (boost)  
> Tất cả run dùng cùng bộ 7 fixes (Fix-B2, Fix-H2, Fix-CV1, Fix-CV3, Fix-CV4, P-L1, Fix-H2/P-L5)

---

## 1. L-track: Tìm được tất cả vulnerabilities chưa?

**Đáp: Có — với Gemini 3.x, L-track đạt Recall = 1.0 (tìm được 100% L-bugs in-scope).**

Contest 19 chỉ có **1 L-track bug** (H-02: SWC-128 DoS via unbounded `activeTransactionBlocks` loop):

| Run | H-02 tìm được? | L TP | L FP | L FN | L F1 |
|-----|---------------|------|------|------|------|
| Baseline gemini-2.5 `_200440` | ✗ | 0 | 8 | 1 | 0.000 |
| gemini-2.5 + 7 fixes `_051405` | ✗ | 0 | 4 | 1 | 0.000 |
| **gemini-3.x `_110326`** | **✓** | **1** | 9 | 0 | **0.182** |

**Nhận xét:**
- Gemini 3.x là lần **đầu tiên** H-02 xuất hiện trong `consensus_vulns` với tag SWC-128 chính xác
- Recall = 1.0 nhưng Precision = 0.10 (F1=0.182) do còn 9 FP trong L-pool
- Nguyên nhân H-02 được tìm: kết hợp P-L1 (DoS checklist trong stage1_instruction) + sức mạnh reasoning của thinking model
- **G_L=1** — contest 19 chỉ có 1 L-track GT nên FN=0 đã là tối ưu; cải thiện F1 cần giảm FP

---

## 2. So sánh thời gian chạy

### Số liệu thực đo

| Run | Model (main/boost) | Duration | Expert findings | Semantic findings |
|-----|--------------------|----------|-----------------|-------------------|
| `_200440` (gemini-2.5 + fixes) | gemini-2.5-flash / gemini-2.5-pro | **3h 00m** (10 778s) | 19 | 27 |
| `_051405` (gemini-2.5 + fixes, best) | gemini-2.5-flash / gemini-2.5-pro | **3h 05m** (11 113s) | 21 | 29 |
| **`_110326` (Gemini 3.x)** | gemini-3-flash-preview / gemini-3.1-pro-preview | **1h 16m** (4 548s) | **44** | **60** |

### Phân tích

- **Gemini 3.x nhanh hơn ~2.4×** so với gemini-2.5
- Latency trung bình per-agent (Phase B/C): ~15–19s với Gemini 3.x vs ước tính 25–35s với gemini-2.5
- Gemini 3.x sinh ra **2× nhiều findings hơn** (44 expert vs 21) trong thời gian ngắn hơn:
  - Throughput findings/giờ: gemini-2.5 ≈ 7/h → gemini-3.x ≈ **35/h** (5× throughput)
- Phase C (attacker tier-2) dùng gemini-3.1-pro-preview: latency 28–65s/agent do thinking tokens (~94–120 tokens reasoning), nhưng tổng thời gian vẫn ngắn hơn do Phase A+B nhanh hơn nhiều

---

## 3. Tại sao Gemini 3.x sinh ra nhiều FP hơn?

### Bảng so sánh

| Metric | gemini-2.5+fixes `_051405` | Gemini 3.x `_110326` | Thay đổi |
|--------|---------------------------|----------------------|---------|
| Expert findings (raw) | 21 | 44 | +110% |
| Semantic findings (raw) | 29 | 60 | +107% |
| consensus_vulns | 2 | 7 | +250% |
| semantic_results | 5 | 10 | +100% |
| L-pool (eval) | 4 | 10 | +150% |
| S-pool (eval) | 5 | 10 | +100% |
| **L FP** | 4 | **9** | +125% |
| **S FP** | 3 | **8** | +167% |

### Lý giải — 4 nguyên nhân

**a) "Ít hallucination" ≠ "ít FP trong security audit"**

Hallucination trong LLM đề cập đến việc model **bịa đặt thông tin không tồn tại** (function ảo, bug không có cơ sở). Tuy nhiên, 9 L-track FP của Gemini 3.x **không phải là hallucination** — chúng là các pattern bảo mật có thật trong code:

| FP finding | SWC | Có thật trong code? |
|-----------|-----|---------------------|
| Signature Malleability in ECDSA | SWC-117 | ✓ Pattern có thật |
| Denial of Service via Gas Griefing | SWC-134 | ✓ Pattern có thật |
| Build-time Dependency Injection | SWC-102 | ✓ Có thật (unpinned deps) |
| DoS via Loop Revert (non-existent) | SWC-113 | ✓ Pattern có thật |
| Forced Ether Injection | SWC-132 | ✓ Pattern có thật |

→ **Contest chỉ award H-02 cho SWC-128**; các pattern trên là FP theo GT label nhưng KHÔNG phải lỗi của model.

**b) Thinking model → reasoning sâu hơn → nhiều findings hơn**

`gemini-3-flash-preview` là **thinking model** (không giống gemini-2.5-flash là non-thinking). Khi agent "suy nghĩ" về attack surface, nó tự nhiên phát hiện nhiều potential issues hơn. Đây là đặc tính thiết kế:

> Model tốt hơn = **bao phủ rộng hơn**, không phải ít findings hơn

Với bài toán audit có GT chỉ có 3 bugs in-scope, bao phủ rộng hơn tất yếu sinh ra nhiều FP hơn.

**c) P-L1 DoS checklist khuếch đại SWC-tagging**

Fix P-L1 thêm explicit checklist vào stage1_instruction:
```
⚠️ REQUIRED COVERAGE: SWC-128 (unbounded arrays)...
```
→ Agents tìm được SWC-128 (H-02 ✓), nhưng cũng bắt gặp SWC-113, SWC-134 liên quan DoS theo "hướng dẫn" → tạo thêm L-tagged FP.

**d) Volume effect thuần túy**

Nhiều findings raw hơn → xác suất FP tuyệt đối cao hơn, dù precision rate có thể tương đồng:
- gemini-2.5: 21 expert findings → 4 L-pool entries → precision = 1/4 = 25%  
- gemini-3.x: 44 expert findings → 10 L-pool entries → precision = 1/10 = 10%

Precision giảm từ 25% → 10% cho thấy gemini-3.x có **recall cao hơn nhưng noise cao hơn** — trade-off điển hình của reasoning models trong security auditing.

---

## 4. Tổng kết & Hướng tiếp theo

### Scorecard cuối cùng

| | Baseline gemini-2.5 | Best gemini-2.5+fixes | **Gemini 3.x+fixes** |
|-|--------------------|-----------------------|----------------------|
| **L-track F1** | 0.000 | 0.000 | **0.182** ↑ |
| **S-track F1** | 0.667 | 0.571 | 0.333 ↓ |
| **Combined F1** | 0.267 | **0.333** | 0.261 ↓ |
| H-02 tìm được | ✗ | ✗ | **✓** |
| Duration | ~3h | ~3h | **~76 min** |
| Expert findings | 19–21 | 19–21 | 44 |

### Đánh giá

- **Gemini 3.x mang lại L-track breakthrough**: H-02 lần đầu được detect → L F1: 0 → 0.182
- **S-track regression**: Thinking model tạo nhiều semantic findings hơn, làm S-pool tăng gấp đôi với cùng số TP
- **Tốc độ**: Nhanh hơn 2.4× — lợi thế lớn cho iteration
- **Net kết quả**: Combined F1 giảm nhẹ (0.333 → 0.261) do S-track FP lấn át L-track gain

### Hướng cải thiện tiếp theo

| Hướng | Mục tiêu | Cơ chế |
|-------|---------|--------|
| **Tăng MIN_CONFIDENCE cho semantic** | Giảm S-track FP | Lọc semantic_results theo confidence ngưỡng cao hơn |
| **Cap semantic pool size** | Giảm S FP | Chỉ giữ top-K semantic findings theo confidence |
| **Precision-recall tradeoff analysis** | Hiểu rõ noise pattern | Chạy thêm contests để có sample size lớn hơn |
| **Separate L/S model config** | Dùng 3.x cho L, 2.5 cho S | Khó về architecture nhưng có thể improve cả hai |

---

## 5. Kết quả Contest 3 — Marginswap (Dexes, 2021)

> Run: `contest3_flat_20260424_172941_20260426_132808` | Duration: 67m27s | 0 error 429

**Ground truth:** G_L=3 (H-01/L1, H-09/L4, H-11/L4) | G_S=4 (H-03/S1-1, H-04/S6-2, H-05/S6-4, H-07/S3-1) | OOS=3

### Kết quả eval

| Track | TP | FP | FN | Pool | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|-----|
| **L-track** (G_L=3) | 2 | 7 | 1 | 9 | 0.222 | 0.667 | **0.333** |
| **S-track** (G_S=4) | 2 | 5 | 2 | 7 | 0.286 | 0.500 | **0.364** |
| **Combined** | 4 | 12 | 3 | 16 | 0.250 | 0.571 | **0.348** |

### Chi tiết bugs

| Bug | Track | Tìm được? | Ghi chú |
|-----|-------|----------|--------|
| H-01 | L1 (Reentrancy) | ✗ | Classic reentrancy — miss |
| H-09 | L4 (Uninit state) | ✓ | `lastUpdatedDay` not initialized |
| H-11 | L4 (DoS gas) | ✓ | `withdrawReward` gas exhaustion |
| H-03 | S1-1 (Price oracle) | ✓ | Price feed manipulation |
| H-04 | S6-2 (Logic) | ✗ | Inconsistent `applyInterest` — logic bug phức tạp |
| H-05 | S6-4 (Logic) | ✗ | Wrong liquidation logic — logic bug phức tạp |
| H-07 | S3-1 (State) | ✓ | `holdsToken` never set |

### Nhận xét

- **L-track**: Miss H-01 (reentrancy L1) — đây là loại bug thường bị bỏ qua nếu pattern không đủ rõ ràng trong flat file
- **S-track**: Miss H-04/H-05 — cả hai là logic bugs kinh doanh phức tạp (incorrect accounting, liquidation math), khó detect bằng pattern matching
- **Contest 3 LOC lớn hơn** (134K chars vs ~80K) nhưng chạy nhanh hơn contest 19 (67 vs 76 phút)

---

## 6. Tổng hợp 2 Contests — Gemini 3.x

| Contest | GL | GS | L TP | L FP | L FN | L F1 | S TP | S FP | S FN | S F1 | Combined F1 | Duration |
|---------|----|----|------|------|------|------|------|------|------|------|-------------|----------|
| **C19** (Connext) | 1 | 2 | 1 | 9 | 0 | 0.182 | 2 | 8 | 0 | 0.333 | 0.261 | 76 min |
| **C03** (Marginswap) | 3 | 4 | 2 | 7 | 1 | 0.333 | 2 | 5 | 2 | 0.364 | 0.348 | 67 min |
| **Aggregated** | 4 | 6 | 3 | 16 | 1 | **0.273** | 4 | 13 | 2 | **0.348** | **0.311** | — |

**Quan sát từ 2 contests:**
- L-track Recall = 3/4 = **75%** — miss 1 reentrancy (H-01)
- S-track Recall = 4/6 = **67%** — miss logic bugs phức tạp (S6-x)
- FP trung bình: L=8/run, S=6.5/run — khá cao, cần giảm để tăng precision
- Tốc độ ổn định: **67–76 phút/contest**, không có 429

---

## 7. Kết quả Contest 35 — Sushi Trident Phase 2 (Dexes/AMM, 2022)

> Run: `contest35_flat_20260426_144308_20260426_160932` | Duration: 68m42s | 0 error 429  
> Flat file: 248,342 chars (lớn nhất trong 3 contests)

**Ground truth:** G_L=6 (tất cả L7) | G_S=5 (S3-1, S6-1, S6-3, S6-4×2) | OOS=6

### Kết quả eval

| Track | TP | FP | FN | Pool | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|-----|
| **L-track** (G_L=6) | 0 | 10 | 6 | 10 | 0.000 | 0.000 | **0.000** |
| **S-track** (G_S=5) | 1 | 7 | 4 | 8 | 0.125 | 0.200 | **0.154** |
| **Combined** | 1 | 17 | 10 | 18 | 0.056 | 0.091 | **0.069** |

### Chi tiết bugs

| Bug | Track | Tìm được? | Ghi chú |
|-----|-------|----------|--------|
| H-01 | L7 | ✗ | Unsafe cast trong `burn()` — overflow math |
| H-04 | L7 | ✗ | Overflow trong `mint()` |
| H-05 | L7 | ✗ | Incorrect typecast trong `_getAmountsForLiquidity` |
| H-09 | L7 | ✗ | `rangeFeeGrowth` underflow |
| H-14 | L7 | ✗ | Math bug `rangeFeeGrowth` & `secondsPerLiquidity` |
| H-15 | L7 | ✗ | `initialPrice` không check giới hạn |
| H-03 | S3-1 | ✓ | Incentives bị steal (CLPM) |
| H-08 | S6-4 | ✗ | Wrong inequality add/remove liquidity |
| H-10 | S6-3 | ✗ | `burn()` sai logic |
| H-11 | S6-4 | ✗ | Sai `feeGrowthGlobal` accounting |
| H-12 | S6-1 | ✗ | `secondsPerLiquidity` không update đúng |

### Phân tích — Tại sao F1 rất thấp?

**L7 là loại bug đặc biệt khó:**
- Tất cả 6 L-bugs đều thuộc L7 (arithmetic overflow/underflow trong concentrated liquidity math)
- Đây là các lỗi toán học cực kỳ tinh vi trong Uniswap v3-style AMM: integer overflow khi cast, fixed-point precision loss, underflow trong fee accounting
- Không có SWC nào bao phủ chính xác L7 → L-pool không match được GT
- Ngay cả auditor chuyên nghiệp cũng phải hiểu sâu về Uniswap v3 math mới tìm được

**S6-x logic bugs phức tạp:**
- H-08/H-10/H-11/H-12 đều là protocol-level logic bugs đòi hỏi hiểu rõ concentrated liquidity mechanics
- Loại bug này khác hoàn toàn với S1 (price oracle) hay S3 (state) mà tool detect tốt hơn

**Kết luận:** Contest 35 là **hard case** — tool hiện tại không phù hợp cho AMM math bugs chuyên biệt.

---

## 8. Tổng hợp 3 Contests — Gemini 3.x

| Contest | Domain | GL | GS | L TP | L FP | L FN | L F1 | S TP | S FP | S FN | S F1 | Comb F1 | Duration |
|---------|--------|----|----|------|------|------|------|------|------|------|------|---------|----------|
| **C19** Connext | Bridge | 1 | 2 | 1 | 9 | 0 | 0.182 | 2 | 8 | 0 | 0.333 | 0.261 | 76 min |
| **C03** Marginswap | Dexes | 3 | 4 | 2 | 7 | 1 | 0.333 | 2 | 5 | 2 | 0.364 | 0.348 | 67 min |
| **C35** Sushi Trident | AMM | 6 | 5 | 0 | 10 | 6 | 0.000 | 1 | 7 | 4 | 0.154 | 0.069 | 69 min |
| **Aggregated** | — | **10** | **11** | **3** | 26 | 7 | **0.176** | **5** | 20 | 6 | **0.294** | **0.235** | — |

### Insights từ 3 contests

| Observation | Chi tiết |
|------------|---------|
| **Tool mạnh nhất ở Bridge/Lending** | C19/C03 Combined F1 = 0.261–0.348; C35 = 0.069 |
| **L7 (AMM math) = điểm mù lớn** | 0/6 L7 bugs detected — cần specialized reasoning |
| **S3/S1 tốt, S6 yếu** | TP: H-03(S3)✓, H-07(S3)✓, H-03(S1)✓ vs H-04/05/08/10/11/12(S6) ✗ |
| **L-track recall theo contest type** | C19: 1/1=100%, C03: 2/3=67%, C35: 0/6=0% |
| **FP cao và ổn định** | ~7–10 L-FP/run bất kể contract size — cần giảm ngưỡng |
| **Tốc độ rất ổn định** | 67–76 min/contest dù size khác nhau (80K–248K chars) |
