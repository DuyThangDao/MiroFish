# Plan: Confidence Formula Redesign — R2 + R3 Combined Score

## Vấn đề hiện tại

### Công thức hiện tại

```python
# Tính nhưng không dùng để quyết định:
final_score = round2_score × 0.4 + attacker_rate × 0.6

# Decision thực tế (hard gate trên attacker_rate):
if attacker_rate == 0.0:               → DISCARD
elif attacker_rate < 0.40:             → borderline
else:                                  → CONFIRMED
```

**Vấn đề cốt lõi**: `round2_score` được tính nhưng không tham gia vào decision.
R3 là hard gate — finding với `r2_score=0.85` (13/19 experts đồng ý) nhưng `attacker_rate=0`
bị DISCARD hoàn toàn. R2 signal bị bỏ qua.

### Khi nào attacker_rate=0 nhưng bug vẫn real?

- Bug là **logic/semantic error** khó viết exploit (ví dụ: rounding accumulation qua nhiều txn)
- Attacker agents có **blind spot** về bug class này (tất cả 5 attackers không quen pattern)
- Bug cần **oracle state đặc biệt** mà attacker không biết cách setup
- Bug là **griefing/DOS** không có financial gain rõ ràng → attacker không write CONFIRMED

Những trường hợp này phổ biến trong Web3Bugs contest, đặc biệt ở S-track.

---

## Công thức mới

### Formula

```
attacker_factor = 0.5 + 0.5 × attacker_rate        # range: [0.5, 1.0]
confidence      = round2_score × attacker_factor
```

### Ý nghĩa của attacker_factor

| attacker_rate | attacker_factor | Diễn giải |
|--------------|----------------|-----------|
| 0.00 | 0.50 | R2 vẫn đóng góp 50% — không bị xóa |
| 0.25 | 0.63 | 1-2 attackers PLAUSIBLE — bonus nhỏ |
| 0.50 | 0.75 | 2-3 attackers confirm — bonus đáng kể |
| 0.75 | 0.88 | 3-4 attackers confirm — near full |
| 1.00 | 1.00 | Tất cả attackers CONFIRMED — R2 tính full |

**Không có trường hợp nào confidence bị về 0 chỉ vì R3 fail**, trừ khi r2_score bản thân thấp.

### Decision thresholds

| confidence | Status | Ghi chú |
|-----------|--------|---------|
| ≥ 0.35 | **CONFIRMED** | Vào output |
| 0.20 – 0.35 | **BORDERLINE** | Vào output với confidence thấp |
| < 0.20 | **DISCARD** | Bỏ |

> **Lưu ý**: Borderline findings vẫn vào output (với confidence_score thấp).
> Auditor thấy và tự đánh giá. Tool không quyết định thay họ với signal yếu.

### So sánh kết quả

| r2_score | attacker_rate | Công thức cũ | Công thức mới |
|----------|--------------|-------------|--------------|
| **0.85** | **0.00** | **DISCARD** ❌ | 0.85×0.50=**0.425 → CONFIRMED** ✓ |
| **0.70** | **0.00** | **DISCARD** ❌ | 0.70×0.50=**0.350 → CONFIRMED** ✓ |
| **0.60** | **0.00** | **DISCARD** ❌ | 0.60×0.50=**0.300 → BORDERLINE** ✓ |
| 0.40 | 0.00 | DISCARD | 0.40×0.50=**0.200 → BORDERLINE** |
| 0.35 | 0.00 | DISCARD | 0.35×0.50=**0.175 → DISCARD** ✓ |
| 0.85 | 0.50 | CONFIRMED | 0.85×0.75=**0.638 → CONFIRMED** ✓ |
| 0.40 | 1.00 | CONFIRMED | 0.40×1.00=**0.400 → CONFIRMED** ✓ |
| 0.35 | 1.00 | CONFIRMED | 0.35×1.00=**0.350 → CONFIRMED** |
| 0.30 | 0.75 | BORDERLINE | 0.30×0.875=**0.263 → BORDERLINE** |
| 0.30 | 0.25 | BORDERLINE | 0.30×0.625=**0.188 → DISCARD** |

### Tại sao threshold CONFIRMED = 0.35?

Với `attacker_factor_min = 0.5`:
- r2_score = 0.70 (13-14/19 agents đồng ý) + không có attacker → confidence = 0.35 → CONFIRMED
- Đây là ngưỡng hợp lý: nếu đại đa số domain experts đồng ý, finding đáng được report
- r2_score = 0.60 + không có attacker → confidence = 0.30 → BORDERLINE (cần thêm attention)

### Giá trị confidence trong output

`confidence_score` trong `audit_report.json` sẽ phản ánh đúng công thức mới:

```json
{
  "confidence_score": 0.425,
  "v2_round2_score": 0.85,
  "v2_attacker_rate": 0.00,
  "v2_attacker_factor": 0.50
}
```

Auditor đọc được: "R2 rất cao (0.85) nhưng không có attacker scenario — medium confidence tổng."

---

## Env vars có thể tune

```bash
# Thresholds (có thể override qua .env)
R3_ATTACKER_FACTOR_BASE=0.5      # floor khi attacker_rate=0
R3_CONFIRMED_THRESHOLD=0.35      # confidence >= này → CONFIRMED
R3_BORDERLINE_THRESHOLD=0.20     # confidence >= này → BORDERLINE, else DISCARD
```

---

## Files cần thay đổi

### 1. `backend/app/services/cyber_session_orchestrator.py`

```python
# Thêm env vars
_R3_ATTACKER_BASE      = float(os.environ.get("R3_ATTACKER_FACTOR_BASE", "0.5"))
_R3_CONFIRMED          = float(os.environ.get("R3_CONFIRMED_THRESHOLD", "0.35"))
_R3_BORDERLINE         = float(os.environ.get("R3_BORDERLINE_THRESHOLD", "0.20"))

# Thay công thức (trong _run_attacker_round):
attacker_factor = _R3_ATTACKER_BASE + (1.0 - _R3_ATTACKER_BASE) * attacker_rate
confidence      = round2_score * attacker_factor

finding["attacker_factor"]   = attacker_factor
finding["confidence"]        = confidence       # dùng cho decision
finding["final_score"]       = confidence       # giữ tên final_score để tương thích

# Thay decision:
if confidence >= _R3_CONFIRMED:
    finding["v2_status"] = "confirmed"
    confirmed.append(finding)
elif confidence >= _R3_BORDERLINE:
    finding["v2_status"] = "borderline"
    borderline.append(finding)
else:
    finding["v2_status"] = "discarded"
    discarded.append(finding)
```

### 2. `backend/app/services/consensus_engine.py`

`build_v2_output()` — dùng `confidence` từ finding thay vì recompute:

```python
# Cũ: conf = round(r2_score * att_rate, 4)
# Mới: lấy trực tiếp từ finding (đã tính trong orchestrator)
conf = round(f.get("confidence", f.get("final_score", 0.0)), 4)
```

Thêm field vào output:
```python
"v2_attacker_factor": f.get("attacker_factor", 0.5),
```

### 3. `backend/scripts/run_contract_audit.py`

Cập nhật log output:
```python
logger.info(f"  [v2] Confirmed   : {len(v2_confirmed)} "
            f"(confidence ≥ {_R3_CONFIRMED})")
```

### 4. `backend/scripts/evaluate_web3bugs.py`

Không thay đổi — evaluator đọc `confidence_score` trực tiếp từ finding, không quan tâm
cách nó được tính.

---

## Checklist kiểm tra sau khi implement

- [ ] Finding r2=0.85, att=0 → CONFIRMED (trước đây DISCARD)
- [ ] Finding r2=0.35, att=0 → DISCARD (vẫn đúng)
- [ ] Finding r2=0.40, att=1.0 → CONFIRMED (vẫn đúng)
- [ ] `confidence_score` trong audit_report.json phản ánh công thức mới
- [ ] `v2_attacker_factor` có trong output để traceable
- [ ] Evaluate F1 trên contest 35 sau khi fix — so sánh với baseline
