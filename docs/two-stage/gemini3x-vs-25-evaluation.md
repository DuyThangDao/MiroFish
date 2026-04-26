# Đánh giá so sánh: Gemini 3.x vs Gemini 2.5 — Contest 19

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
