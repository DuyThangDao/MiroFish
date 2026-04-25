# Sliding Window Context — Thiết kế & Triển khai

**Implemented:** 2026-04-24
**File:** `backend/app/services/cyber_session_orchestrator.py` — `_build_prior_context()`
**Env var:** `CONTEXT_WINDOW_ROUNDS` (default: `3`)

---

## 1. Vấn đề cần giải quyết

Trong mỗi round, mỗi agent nhận một prompt gồm:

```
system_prompt + phase_instruction + flat_file + prior_context
```

`prior_context` được build từ toàn bộ findings tích lũy từ đầu session. Không có giới hạn theo round, context phình dần theo thời gian:

| Round | prior_context ước tính | Tổng tokens/request |
|-------|------------------------|---------------------|
| R1 | ~200 tokens | ~10K |
| R3 | ~800 tokens | ~11K |
| R6 | ~2.5K tokens | ~12K |
| R9 | ~5K tokens | ~15K |

Với flat file 38K chars (~9.5K tokens), tổng prompt ở Phase C (round 8-10) có thể đạt **14-20K tokens/request**, vượt TPM quota của Vertex AI → gây 429 với pattern queue timeout 622s.

---

## 2. Giải pháp: Sliding Window

Thay vì pass toàn bộ findings history, chỉ pass findings từ **N round gần nhất**.

### Cơ chế

```python
window = int(os.environ.get("CONTEXT_WINDOW_ROUNDS", "3"))
current_round = session_state.current_round
min_round = max(1, current_round - window + 1)
```

Ví dụ với `window=3`, đang ở Round 9:
- `min_round = max(1, 9 - 3 + 1) = 7`
- Chỉ include findings từ Round 7, 8, 9

### Những gì được filter theo window

| Thành phần | Trước | Sau (window=3) |
|-----------|-------|----------------|
| Expert findings | tất cả (last 6 by count) | last 6 trong window rounds |
| Attacker findings | last 5 | last 5 trong window rounds |
| Gap registry | last 8 | last 8 trong window rounds |
| Published Registry | max 20 entries | **max 10 entries** (giảm cố định) |

### Những gì KHÔNG filter

Published Registry vẫn show tất cả unique findings (đã giảm từ 20 → 10 entries), đảm bảo agent biết những gì đã được report để không lặp lại.

---

## 3. Token impact ước tính

| Round | Không có sliding window | Có sliding window (N=3) |
|-------|------------------------|------------------------|
| R1-R3 | ~10-11K | ~10-11K (không đổi) |
| R4-R6 | ~11-13K | ~11K (ổn định) |
| R7-R9 | ~13-15K | ~11K (ổn định) |
| R10 | ~15-20K | ~11K (ổn định) |

Ở Phase C, sliding window giữ prompt size ổn định thay vì tăng tuyến tính.

---

## 4. Trade-off

### Lợi ích
- Prompt size ổn định qua mọi round → giảm TPM pressure ở Phase C
- Agent tập trung vào context gần nhất, liên quan hơn
- Dễ scale lên nhiều rounds hơn nếu cần

### Rủi ro
- Agent ở Round 9 không thấy findings từ Round 1-6 **trong detail**
- Findings quan trọng từ round sớm vẫn xuất hiện qua **Published Registry** (title only, không có full evidence)
- Gaps declared ở round sớm và chưa được giải quyết sẽ không được nhắc lại

### Mitigation
Published Registry (max 10 entries, tất cả unique titles) đảm bảo agent biết **danh sách những gì đã report**, dù không có full evidence. Agent được instruct: "CHALLENGE or EXPAND rather than re-report".

---

## 5. Cấu hình

```bash
# .env hoặc environment variable
CONTEXT_WINDOW_ROUNDS=3   # default, recommended
CONTEXT_WINDOW_ROUNDS=5   # nếu muốn context rộng hơn (chấp nhận token cao hơn)
CONTEXT_WINDOW_ROUNDS=2   # nếu flat file rất lớn (>100K chars)
```

### Khuyến nghị theo kích thước flat file

| Flat file size | CONTEXT_WINDOW_ROUNDS |
|---------------|----------------------|
| < 20K chars | 5 (window rộng) |
| 20-50K chars | 3 (default) |
| 50-100K chars | 2 |
| > 100K chars | 2, cân nhắc thêm domain slicing |

---

## 6. Kết quả thực tế

**Contest 19 run (2026-04-24):**
- Sliding window được áp dụng từ đầu
- 429 vẫn xảy ra từ R2 (bloc_auditor 624.8s) và R3 (3 outliers đồng thời)
- **Kết luận:** Sliding window không đủ để ngăn 429 với flat file 38K chars vì 429 xảy ra ngay từ round đầu khi context còn nhỏ → root cause là **tổng token/request quá lớn do flat file**, không phải do context tích lũy

**Nguyên nhân 429 thực sự:** Flat file ~9.5K tokens/request đã gần sát TPM limit ngay từ R1. Sliding window chỉ có ý nghĩa khi `prior_context` là phần lớn của prompt. Với flat file 38K chars, flat file chiếm ~85% token budget → sliding window chỉ ảnh hưởng ~15% còn lại.

---

## 7. Hướng cải tiến tiếp theo

1. **Gemini API direct** (thay Vertex AI) — TPM quota cao hơn, không bị regional throttle
2. **Domain-based code slicing** — mỗi agent nhận subset của flat file liên quan domain → giảm 50-70% tokens/request
3. **Tăng `CONTEXT_WINDOW_ROUNDS`** chỉ có ý nghĩa sau khi giải quyết vấn đề flat file token
