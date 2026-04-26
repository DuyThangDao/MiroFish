# Chất lượng báo cáo & tín hiệu — Contest 19 (run mới nhất)

**Mục đích:** Tài liệu hóa đánh giá chất lượng audit report (tín hiệu tích cực, rủi ro, giới hạn), phục vụ hậu nghiệm sau run `contest19_flat_20260424_091722_20260425_200440/`.

**Ngày tham chiếu:** 2026-04-26 (cập nhật sau kiểm tra thực tế)
**Session:** `cyber_68e0c0037e3d` (theo `session_result.json` trong thư mục run trên)
**Báo cáo:** `backend/results/web3bugs_trial/contest_19/contest19_flat_20260424_091722_20260425_200440/audit_report.json`

**Ground truth in-scope (contest 19):** H-01 (access_control), H-02 (L-track, SWC-128), H-05 (state_machine_bug)

---

## 1. Tín hiệu tích cực ✅

| Tín hiệu | Xác nhận thực tế |
|---------|-----------------|
| H-01 direction: `prepare()` thiếu kiểm tra `msg.sender` | ✓ `access_control` finding "Front-running fund theft via `prepare()` due to missing `msg.sender` validation" — đúng hướng |
| H-05 direction: ERC20 approval không reset sau `fulfill()` fail | ✓ `state_machine_bug` "ERC20 Approval Not Revoked on `fulfill()` Execution Failure" — đúng bug |
| `exclude_from_eval=True` + nhãn `[UNCLASSIFIED]` cho `category=other` | ✓ Hoạt động đúng: 2 findings kinh tế/thiết kế bị exclude khỏi F1 pool nhưng vẫn giữ trong report |
| Report tự công khai exploitability = 0 | ✓ Report ghi rõ "No findings confirmed exploitable by attacker profiles yet" — không misleading |

---

## 2. Vấn đề phát hiện sau kiểm tra thực tế

### 2.1 Protocol Bleed — Structured Field Corruption

**Mức độ thực tế: NGHIÊM TRỌNG hơn mô tả ban đầu**

Kiểm tra `session_result.json` (nguồn gốc): **8/19 expert findings (42%)** có `VALIDATE_FINDING:` text bị nhúng trực tiếp vào trường `description`:

```
Findings bị bleed:
  Missing `address(0)` Check for `ecrecover` Result
  Floating Pragma Allows Compiler Version Mismatch
  OpenZeppelin Dependency Version Unspecified        ← nặng nhất
  OpenZeppelin `ECDSA` Library Version Unknown
  Lack of upgrade authorization mechanism
  General Lack of Access Control for Critical Operations
  Hardcoded Gas Stipend in `transfer()`
  `ecrecover` result not explicitly checked for `address(0)`
```

**Ví dụ bleed nghiêm trọng nhất** (finding `OpenZeppelin Dependency Version Unspecified`):

```
description = "...impossible to confirm if the contract is protected against past
vulnerabilities. VALIDATE_FINDING: `cancel()` may be vulnerable because it
performs an external asset transfer via `transferAsset()` and is not explicitly
protected by a reentrancy guard. DOMAIN_EVIDENCE: From a dependency audit
perspective, the `ReentrancyGuard` dependency is present..."
```

Một Stage 2 response hoàn chỉnh của agent khác (bao gồm cả `VALIDATE_FINDING:` + `DOMAIN_EVIDENCE:`) bị nối vào `description` của finding thay vì được parse và xử lý riêng.

**Root cause:** Parser `_process_semantic_response()` và `_process_expert_response()` extract `DESCRIPTION:` field bằng cách lấy text từ sau keyword `DESCRIPTION:` đến keyword tiếp theo. Nếu agent viết FINDING và VALIDATE_FINDING trong cùng một response stream, và VALIDATE_FINDING xuất hiện trước keyword kết thúc được parser expect, toàn bộ phần còn lại bị hút vào `description`.

**Hậu quả:**
- `description` field trong `audit_report.json` chứa nội dung protocol → báo cáo markdown vẫn sạch (được render riêng) nhưng JSON raw bị corrupt
- 8/19 findings bị nhiễm → bất kỳ downstream processing nào đọc `description` (vector search, LLM summarization, export) đều bị ảnh hưởng

**Đề xuất Fix-B1 — Strip protocol keywords khi parse description (P0, đơn giản):**

```python
_PROTOCOL_STRIP_RE = re.compile(
    r'(?i)\n?(VALIDATE_FINDING|CHALLENGE_FINDING|DOMAIN_EVIDENCE|'
    r'ADDITIONAL_IMPACT|GAP:|CLAIM:|STAGE\s*[12])\s*:.*$',
    re.MULTILINE | re.DOTALL
)

def _sanitize_description(text: str) -> str:
    """Strip protocol markers that leaked into description field."""
    return _PROTOCOL_STRIP_RE.sub('', text).strip()
```

Áp dụng trong `_process_expert_response()` và `_process_semantic_response()` ngay sau khi extract `description`.

**Đề xuất Fix-B2 — Truncate description tại keyword ranh giới (P0, alternative):**

Thay vì regex, đơn giản hơn: khi extract `DESCRIPTION:` block, dừng tại bất kỳ dòng nào bắt đầu bằng `[A-Z_]+:` ở đầu dòng (tức là keyword protocol tiếp theo):

```python
def _extract_until_next_keyword(text: str, start_keyword: str) -> str:
    """Extract field value, stopping at the next protocol keyword."""
    _KEYWORD_LINE = re.compile(r'^[A-Z_]{3,}\s*:', re.MULTILINE)
    match = re.search(rf'(?i)^{start_keyword}\s*:(.*)', text, re.MULTILINE | re.DOTALL)
    if not match:
        return ""
    content = match.group(1)
    # Stop at next keyword
    next_kw = _KEYWORD_LINE.search(content, 1)
    return content[:next_kw.start()].strip() if next_kw else content.strip()
```

---

### 2.2 H-track: Nhiễu cao, mất trọng tâm L-track

**Xác nhận: Đúng hoàn toàn**

3 consensus_vulns trong run này:

| Finding | SWC | Confidence | Thực tế |
|---------|-----|-----------|---------|
| Lack of `address(0)` check for ecrecover | SWC-122 | 0.49 | FP |
| ERC20 `approve()` race condition in `fulfill()` | SWC-114 | 0.49 | FP |
| OpenZeppelin Dependency Version Unspecified | SWC-102 | 0.37 | FP + bị bleed |

SWC-128 (`activeTransactionBlocks` DoS — H-02) vắng mặt hoàn toàn → L-track F1 = 0.000.

**Root cause phân tích tại:** `docs/l-track-miss-analysis.md`

**Đề xuất Fix-H1 — DoS coverage checklist trong Stage 1 prompt (P1):**

```python
# Trong stage1_instruction Phase A:
"⚠️ REQUIRED COVERAGE: Explicitly check for:\n"
"  - Unbounded arrays/loops (SWC-128, SWC-113): any array that grows without bound\n"
"  - Unprotected state-modifying functions any caller can abuse for griefing\n"
"Include a CLAIM about DoS patterns even if you find no issue.\n"
```

**Đề xuất Fix-H2 — SWC gap confidence gate min_source=2 (P0):**

Chỉ tạo `unvalidated_swc_gap` khi ≥2 agents độc lập mention cùng SWC category. Giảm FP từ 8 xuống ước tính 3–4.

```python
# Trong _collect_swc_gaps() của consensus_engine.py:
if len(source_findings) < 2:   # thêm điều kiện này
    continue
```

---

### 2.3 Cross-validation không có tác dụng thực tế

**Xác nhận: Đúng — và nghiêm trọng hơn mô tả ban đầu**

Dữ liệu từ run (19 findings, 10 rounds):

```
Findings bị challenge:          1 / 19  (5%)
Findings có validate:           5 / 19  (26%)
Findings cross_domain_validated: 0 / 19  (0%)
```

`ConsensusEngine` hoàn toàn bỏ qua `challenged_by` và `validated_by` — tính lại confidence từ đầu chỉ bằng intra/cross-group score. Attacker gate = 1.0× khi không có review → không có natural penalty.

**Root cause và giải pháp chi tiết tại:** `docs/fp-high-root-cause-analysis.md`

**Đề xuất Fix-CV1 — Đưa peer signal vào ConsensusEngine (P0):**

```python
# Trong _score_cluster():
challenge_count = sum(len(f.get("challenged_by", [])) for f in cluster)
validate_count  = sum(len(f.get("validated_by",   [])) for f in cluster)
peer_delta = min(validate_count, 5) * 0.03 - min(challenge_count, 5) * 0.05
confidence = max(0.0, min(1.0, (expert_confidence + peer_delta) * gate))
```

**Đề xuất Fix-CV2 — Hạ ATTACKER_GATE_NEUTRAL = 0.75 (P1):**

Findings không được attacker review nên bị giảm 25% confidence thay vì giữ nguyên.

**Đề xuất Fix-CV3 — Đảo thứ tự prompt Stage 2 (P1, zero-code):**

```
Priority 1 (bắt buộc ≥1): CHALLENGE_FINDING hoặc VALIDATE_FINDING
Priority 2 (nếu còn có): FINDING / SEMANTIC_FINDING mới
```

---

### 2.4 Attacker Phase C không tạo ra findings

**Xác nhận: Đúng — nhưng report minh bạch đúng mức**

`total_attacker_findings: 0`, `exploitable_count: 0`. Report ghi rõ *"No findings confirmed exploitable by attacker profiles yet"* → không misleading.

**Root cause / làm rõ:** `total_attacker_findings: 0` nghĩa là **không** có path mới chỉ từ attacker — **khác** với `attacker_corroborations` trên `expert_findings`. Trong `session_result.json` của run này, **5/19** expert findings có mảng `attacker_corroborations` không rỗng; phần còn lại không nhận review Phase C. Vấn đề “exploitability = 0” vẫn đúng: **không** có cách diễn đạt “confirmed exploitable” đầy đủ ở tầm báo cáo, dù một số finding có bản ghi `ATTACKER_*` trong session.

**Đề xuất Fix-A1 — Log attacker corroboration rate (P2):**

```python
logger.info(
    f"Phase C done: {n_confirms} CONFIRM, {n_dismisses} DISMISS, "
    f"{n_unreviewed}/{total} findings unreviewed by attackers"
)
```

Giúp detect sớm khi Phase C không hoạt động mà không cần đọc toàn bộ log.

---

## 3. Tổng hợp vấn đề và đề xuất

| # | Vấn đề | Mức độ | Fix | Priority |
|---|--------|--------|-----|----------|
| B1 | Protocol bleed vào `description` (8/19 findings) | 🔴 Nghiêm trọng | Fix-B1: strip regex sau extract | P0 |
| CV1 | ConsensusEngine bỏ qua challenge/validate signal | 🔴 Nghiêm trọng | Fix-CV1: Layer 4 peer signal | P0 |
| H2 | FP cao — SWC gap không cần min_source | 🟠 Cao | Fix-H2: min_source_count=2 | P0 |
| CV3 | Prompt Stage 2 tạo FINDING trước CHALLENGE | 🟠 Cao | Fix-CV3: đảo thứ tự prompt | P1 |
| CV2 | ATTACKER_GATE_NEUTRAL = 1.0 | 🟠 Cao | Fix-CV2: hạ xuống 0.75 | P1 |
| H1 | Không có DoS coverage trong Stage 1 | 🟡 Trung bình | Fix-H1: checklist instruction | P1 |
| A1 | Attacker Phase C không có observability | 🟡 Trung bình | Fix-A1: log corroboration rate | P2 |

---

## 4. Độ tin cậy của đánh giá này

Tài liệu này dựa trên kiểm tra trực tiếp `session_result.json` và `audit_report.json` từ run cụ thể. **Không kết luận "mô hình xấu vĩnh viễn"** từ 1 run — SWC-128 đã được tìm thấy trong 6/7 run trước đó. Đây là đánh giá về chất lượng output và điểm yếu kiến trúc, không phải về capability của LLM backbone.

Số P/R/F1 chính thức lấy từ `evaluate_web3bugs.py`, không từ tài liệu này.
