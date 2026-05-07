# Issue 5 (Revised): Đề Xuất Bỏ R3

> Tài liệu này trình bày lý do bỏ hoàn toàn R3 Attacker Validation
> và thay thế bằng việc tăng cường R2.

---

## 1. Vấn Đề Với R3 Hiện Tại

### 1.1 Chi Phí Không Tương Xứng

```
5 attackers × N findings = 5N calls
Contest 35 (N=45): 225 calls → ~30–60 phút wall time
Contest lớn (N=100): 500 calls → có thể bị kill vì timeout/rate limit
```

### 1.2 Không Thể Filter Đúng

R3 được thiết kế để filter FP, nhưng bất kỳ thiết kế nào cũng có trade-off không giải quyết được:

| R3 aggressive | R3 conservative |
|---|---|
| Filter nhiều FP hơn | Filter ít FP hơn |
| Risk filter nhầm TP cao | Risk filter nhầm TP thấp |

Không có điểm cân bằng tốt vì đây là single/few agent decision trên data mà R2 đã xử lý.

**Bugs dễ bị filter nhầm thành FP:**
- Invariant bugs phức tạp (H-09, H-17 type) — cần domain knowledge sâu
- Missing check bugs (H-15 type) — "cái không có" khó nhận ra hơn "cái sai"
- Cross-function bugs (H-06 type) — nhìn 1 function không thấy full picture

### 1.3 Echo Chamber Risk

R3 judge không có thông tin mới hơn R1/R2. Nếu 19 R2 experts đã đồng ý finding là valid,
1 judge sau đó rất khó sửa được — và còn có nguy cơ chỉ là echo chamber.

---

## 2. Tại Sao R2 Đã Đủ

### 2.1 R2 Toàn Diện Hơn R3

| | R2 | R3 (hiện tại) |
|---|---|---|
| Số agents | 19 | 5 (hoặc 1 nếu universal) |
| Domain diversity | 8 domains × 2–3 personas | Chỉ attacker perspective |
| Cross-validation | Thực sự chéo — appsec challenge defi, crypto challenge blockchain | Không |
| Consensus | Đa số đồng ý mới pass | 1 agent quyết định |

### 2.2 R2 Đã Là Adversarial

R2 voting với diverse personas thực chất đã là adversarial:
- `blockchain/offensive` challenge `appsec/auditor`
- `defi_math/offensive` challenge `smart_contract_economics/economist`
- `cryptography/offensive` challenge `defi/analyst`

Finding phải qua được scrutiny của 19 perspectives khác nhau để pass R2 — đây là
adversarial check toàn diện hơn bất kỳ thiết kế R3 nào với 1–5 agents.

### 2.3 Root Cause Noise Nằm Ở R2, Không Phải R3

Nếu R2 accept 100% findings (Issue 3), vấn đề là **R2 threshold quá thấp** (0.35),
không phải thiếu R3. Fix R2 → noise bị chặn đúng chỗ, bởi mechanism đúng.

---

## 3. Đề Xuất

### 3.1 Bỏ Hoàn Toàn R3

Pipeline mới:

```
R1 (19 agents — Independent Discovery)
    ↓
Static + LLM Anchor Dedup
    ↓
FP Check (CODE: snippet verification)
    ↓
R2 (19 agents — Blind Voting + Filter)
    ↓
Output
```

Số calls giảm: loại bỏ hoàn toàn 5N–225+ calls của R3.

### 3.2 Điều Kiện Tiên Quyết

**Bỏ R3 chỉ hợp lý khi Issue 3 được fix trước:**

```bash
# R2_SCORE_THRESHOLD: 0.35 → 0.55 (hoặc cao hơn)
# Cần k+r ≥ 13/22 agents đồng ý thay vì 8/22
```

Nếu R2 vẫn accept 100% mà bỏ R3 → không có gì lọc noise → quality giảm.

### 3.3 Scoring Sau Khi Bỏ R3

Thay `confidence = r2_score × attacker_factor` bằng `final_score = r2_score` trực tiếp.

Output report chia theo R2 score:
```
High confidence  (r2_score ≥ 0.70) → Critical/High severity
Medium confidence(r2_score 0.55–0.70) → Medium severity
Low confidence   (r2_score 0.40–0.55) → Low / Informational
```

---

## 4. Rủi Ro & Mitigation

### 4.1 Thiếu Adversarial Signal

**Rủi ro:** Không có agent nào đặt câu hỏi "finding này thực sự exploit được không?"

**Mitigation:** R2 prompt có thể được tăng cường thêm directive yêu cầu agents
challenge severity và exploitability khi vote — không chỉ đồng ý/không đồng ý.

### 4.2 Precision Giảm Nếu R2 Threshold Chưa Fix

**Rủi ro:** Thiếu R3 + R2 threshold thấp → FP rate tăng trong output.

**Mitigation:** Fix Issue 3 trước. Thứ tự triển khai:
```
1. Fix R2 threshold (Issue 3) — P0
2. Bỏ R3
3. Benchmark precision/recall trên contest 35
4. Điều chỉnh R2 threshold dựa trên kết quả
```

---

## 5. Tương Lai

Nếu sau khi bỏ R3 và fix R2, recall/precision vẫn chưa đủ:
- Xem xét thêm 1 lightweight enrichment agent (không phải filter) để annotate findings
  với attack surface info — giúp auditor con người đọc report dễ hơn
- Không discard bất kỳ finding nào qua enrichment agent này

---

## 6. Thứ Tự Ưu Tiên Triển Khai

| Bước | Action | Issue |
|---|---|---|
| 1 | Fix R2 threshold 0.35 → 0.55 | Issue 3 |
| 2 | Bỏ R3 khỏi v2 pipeline | Issue 5 (tài liệu này) |
| 3 | Benchmark contest 35 với pipeline mới | — |
| 4 | Điều chỉnh threshold theo kết quả | — |
