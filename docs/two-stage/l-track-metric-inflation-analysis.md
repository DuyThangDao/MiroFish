# L-track Metric Inflation: Phân tích, Quyết định và Giải pháp

> Vấn đề phát lộ khi đối chiếu F1 L-track (class-level) với mức localize thực tế — có thể lặp lại trên bất kỳ contest nào có nhiều GT cùng nhãn L / cùng SWC.

---

## 1. Vấn đề

### 1.1 Hiện tượng

Eval L-track tính TP theo cơ chế **giao lớp**: một finding đúng SWC tương ứng nhãn L có thể match tất cả bug GT cùng lớp trong cùng contest. Khi nhiều bug GT cùng nhãn L, **một** finding generic đúng class kéo **nhiều** TP cùng lúc — F1_class cao dù tool chỉ có một hint không gắn function/exploit path nào.

Hệ quả: metric nói "đã nhận ra pattern lớp lỗi" nhưng không đo "đã trỏ đúng vị trí và có bằng chứng exploit" — hai câu hỏi hoàn toàn khác nhau về giá trị thực tế.

### 1.2 Phân tầng ý nghĩa

| Tầng | Câu hỏi | Giá trị thực tế |
|---|---|---|
| **Class** | Tool có nhận ra lớp lỗi (SWC) tồn tại không? | Triage — auditor biết phải tìm pattern gì |
| **Function** | Tool có trỏ đúng function mà GT kỳ vọng không? | Audit assistant — có chỗ cụ thể để kiểm tra |
| **Exploit path** | Tool có dựng được attack sequence không? | Actionable — có thể confirm và fix ngay |

**Quyết định về metric:**

Class-level F1 sẽ được **bỏ** sau khi fix structured output compliance được deploy ổn định. Lý do:

- Sau fix, finding có SWC → hầu hết cũng có function → class và fn-level đo gần như cùng thứ
- Sự khác biệt còn lại (finding có SWC nhưng không có function sau fix) chính là Tier 2 — đã được report riêng trong output, không cần thêm metric
- Giữ hai metric tạo overhead tracking mà không thêm insight mới

**Ngoại lệ — giai đoạn chuyển tiếp:** Giữ class-level song song trong **1–2 lần chạy đầu tiên sau khi deploy fix** để làm diagnostic: nếu `F1_L_class` và `F1_L_fn` vẫn cách xa nhau sau fix → backfill chưa đủ, cần điều tra thêm. Sau khi hai metric hội tụ, bỏ class-level.

**Metric dài hạn duy nhất: `F1_L_fn`** — đo finding có SWC đúng + function đúng + exploit path.

---

## 2. Nguyên nhân gốc

### 2.1 Eval: class-level match + GT nhiều mục cùng lớp

Một finding trong L-pool có đúng SWC → match toàn bộ bug GT cùng lớp. Không phụ thuộc tên dự án — chỉ cần GT có nhiều mục trùng lớp là xảy ra.

### 2.2 Tool: agents biết vị trí nhưng không điền đúng field — đây là root cause thực sự

Kiểm tra raw session output (contest 35) cho thấy điều ngược lại với giả định ban đầu:

**Agents BIẾT function cụ thể — nhưng ghi vào free-text thay vì `affected_functions` field:**

```json
// Finding cf_e5494d6c — SWC-101
{
  "affected_functions": [],                          // ← TRỐNG
  "description": "In this contract, _mint and _burn use these casts...",  // ← BIẾT RÕ
  "evidence": ["to128() → (leaf) (implied in context of _mint and _burn)"] // ← BIẾT RÕ
}

// Finding cf_685ae9f5 — SWC-101
{
  "affected_functions": [],                          // ← TRỐNG
  "description": "the pools rely on to128 for internal accounting (e.g., in _transfer and _updateReserves)"  // ← BIẾT RÕ
}
```

Agents đã nhận diện được `to128()`, `to64()`, `_mint`, `_burn`, `_transfer`, `_updateReserves` — thông tin nằm trong `description` và `evidence`. Consensus engine chỉ đọc `affected_functions` (structured field) và không parse free-text → function location bị mất hoàn toàn khi merge.

**Root cause thực sự:** Structured output compliance — thông tin có trong reasoning của agent nhưng không được ghi vào đúng schema field. Đây là vấn đề **prompt + output format**, không phải vấn đề capability.

Hệ quả: fix đơn giản hơn nhiều so với giả định ban đầu — không cần thay đổi cách agents "tìm" bug, chỉ cần enforce điền đúng field.

### 2.3 Consensus engine không recover từ free-text

Ngay cả khi agent biết function, nếu `affected_functions: []` thì merged finding cũng trống. Không có bước nào trong pipeline hiện tại extract function names từ `description`/`evidence` text để backfill vào structured output.

### 2.4 File lớn + attention dilution (yếu tố phụ)

Flat multi-contract file (248K chars) làm tăng xác suất agents viết tắt trong free-text thay vì điền đầy đủ structured fields. Manifest sai (focus directive trỏ nhầm) làm trầm trọng thêm nhưng không phải root cause chính.

---

## 3. Kiến trúc 2-tier output (giải pháp cốt lõi)

Hai mong muốn — giữ class-level signal VÀ yêu cầu exploit path cho finding actionable — không xung đột nếu output được phân thành 2 tier rõ ràng:

```
┌─────────────────────────────────────────────────────┐
│  TIER 1 — consensus_vulns                           │
│  Điều kiện: SWC đúng + function cụ thể + exploit   │
│  path ít nhất 2 bước + impact rõ                    │
│  → Actionable: auditor có thể confirm và fix ngay   │
├─────────────────────────────────────────────────────┤
│  TIER 2 — unvalidated_swc_gaps                      │
│  Điều kiện: SWC đúng, nhưng thiếu function hoặc    │
│  thiếu exploit path                                 │
│  → Triage signal: auditor biết phải tìm gì,        │
│    chưa biết chính xác ở đâu                        │
└─────────────────────────────────────────────────────┘
```

**Eval mapping:**
- `F1_L_fn` — **metric chính**, chỉ dùng Tier 1 (finding có function + exploit path)
- `F1_L_class` — **diagnostic tạm thời**, dùng cả 2 tier, chỉ dùng trong giai đoạn chuyển tiếp để verify fix hiệu quả → bỏ sau khi hai metric hội tụ

---

## 4. Giải pháp triển khai

### 4.1 Fix root cause: enforce `affected_functions` trong agent output (Stage 1 + Stage 2)

Vì agents đã biết function nhưng không điền vào field, fix ưu tiên cao nhất là **prompt enforcement** — buộc agents populate `affected_functions` bất cứ khi nào họ đề cập function trong reasoning.

**Thêm vào Stage 1 instruction (expert agents):**

```
CRITICAL OUTPUT RULE — affected_functions field:
If you mention any function name (e.g., _mint, to128, withdraw) anywhere in your
description or evidence, you MUST also list it in the "affected_functions" array.
Do NOT leave affected_functions empty if you can identify the vulnerable function.
Wrong:  { "affected_functions": [], "description": "_mint uses unsafe cast..." }
Correct: { "affected_functions": ["_mint"], "description": "_mint uses unsafe cast..." }
```

**Thêm vào Stage 2 instruction (attacker/validator agents):**

```
When validating a finding, check: does it have affected_functions populated?
If the description mentions a function but affected_functions is empty, ADD the
function name to affected_functions before escalating. This is required for Tier 1.

To escalate a finding to Tier 1 (consensus_vulns), ALL 3 must be present:
  1. affected_functions: at least 1 exact function name
  2. Attack path: step-by-step sequence (minimum 2 steps)
  3. Impact: concrete outcome (funds lost / state corrupted / DoS)

Findings without all 3 → Tier 2 (triage signal, still reported).
Do NOT merge multiple function-level issues of the same SWC into one generic finding.
```

### 4.2 Consensus engine: backfill từ free-text + gate Tier 1

Thêm 2 bước trong consensus engine trước khi route finding:

**Bước 1 — Backfill `affected_functions` từ free-text** (safety net khi prompt không đủ):

```python
import re

_FN_PATTERN = re.compile(r'`([a-zA-Z_]\w+\(\))`')

def _backfill_functions(finding: dict) -> dict:
    """Extract function names từ description/evidence nếu affected_functions rỗng."""
    if finding.get("affected_functions"):
        return finding  # đã có, không cần
    text = " ".join([
        finding.get("description", ""),
        " ".join(finding.get("evidence", [])),
    ])
    extracted = _FN_PATTERN.findall(text)
    if extracted:
        finding["affected_functions"] = list(dict.fromkeys(extracted))  # dedup, preserve order
    return finding
```

**Bước 2 — Gate vào Tier 1:**

```python
def _has_exploit_path(finding: dict) -> bool:
    return (
        bool(finding.get("affected_functions"))   # có function name (sau backfill)
        and bool(finding.get("exploit_steps"))    # có attack sequence
        and finding.get("confidence_score", 0) >= 0.45
    )

# Trong consensus engine, sau khi merge:
finding = _backfill_functions(finding)
if _has_exploit_path(finding):
    consensus_vulns.append(finding)       # Tier 1 — actionable
else:
    unvalidated_swc_gaps.append(finding)  # Tier 2 — triage, vẫn report
```

### 4.3 Thêm F1_L_fn vào eval pipeline (metric chính dài hạn)

```python
def _match_l_fn(bug: GTBug, findings: List[ToolFinding]) -> bool:
    """Primary metric: SWC đúng class VÀ function overlap VÀ finding ở Tier 1."""
    expected_swcs = L_TO_SWC.get(bug.label, frozenset())
    expected_fns  = gt_functions.get((bug.contest_id, bug.bug_id), set())
    if not expected_swcs:
        return False
    for f in findings:
        if f.source != "consensus":           # chỉ Tier 1
            continue
        if not (f.swc_ids & expected_swcs):
            continue
        if not expected_fns:                  # GT không có function data → fallback lenient
            return True
        if f.functions & expected_fns:        # function overlap
            return True
    return False
```

Output eval trong giai đoạn chuyển tiếp (cả 2 dòng để verify fix):
```
F1_L_fn    (primary):    0.xxx  ← SWC đúng + function đúng + exploit path [METRIC CHÍNH]
F1_L_class (diagnostic): 0.857  ← chỉ cần SWC đúng [bỏ sau khi hai metric hội tụ]
```

Khi `|F1_L_class - F1_L_fn| < 0.05` ổn định qua 2–3 contest → bỏ `F1_L_class` khỏi output.

### 4.4 Cập nhật report format — phân biệt 2 tier rõ trong output

Trong `audit_report.md`, Tier 2 findings phải được hiển thị khác biệt:

```markdown
## CONFIRMED VULNERABILITIES (Tier 1 — Actionable)
[HIGH] SWC-107: Cross-Function Reentrancy | flashSwap() | Exploit: ...

---

## SUSPECTED PATTERNS (Tier 2 — Triage Signal)
> Các pattern dưới đây được nhận diện ở lớp lỗi nhưng chưa có exploit path
> cụ thể. Auditor nên kiểm tra thủ công các function liên quan.

[MEDIUM] SWC-101: Possible unsafe explicit casting — check all uint256→uint128
conversions. Confidence: 0.49. No specific function confirmed.
```

---

## 5. Tác động dự kiến

| Metric | Hiện tại | Sau fix |
|---|---|---|
| consensus_vulns count | Mix có/không path | Chỉ có path → ít hơn, chất hơn |
| unvalidated_swc_gaps | Ít | Hấp thụ hints → nhiều hơn |
| F1_L_class | Không đổi (cả 2 tier count) | Giữ nguyên |
| F1_L_fn | Không đo | Có thể đo, phản ánh thực tế |
| Report value | Hint lẫn với findings | Tier 1 = actionable, Tier 2 = triage |
| FP trong consensus | Cao (hint vào tier 1) | Giảm (hint bị route sang tier 2) |

---

## 6. Thứ tự triển khai

| Bước | Nội dung | Ghi chú |
|---|---|---|
| **1** | Enforce `affected_functions` trong Stage 1 + Stage 2 prompt | Fix root cause — không đổi kiến trúc |
| **2** | Thêm `_backfill_functions()` + `_has_exploit_path()` gate vào consensus engine | Safety net + route 2 tier |
| **3** | Cập nhật report format — phân biệt Tier 1 / Tier 2 | Output rõ ràng cho auditor |
| **4** | Thêm F1_L_fn vào eval pipeline | Đo hiệu quả fix |
| **5** | Củng cố manifest/focus (G-RC-2) | Giảm attention dilution → tăng chất Tier 1 |

Bước 1+2+3 là một cụm triển khai cùng lúc. Bước 4 độc lập. Bước 5 dài hạn.

---

## 7. Nguyên tắc an toàn khi triển khai

| Nguyên tắc | Chi tiết |
|---|---|
| **Class-level là tạm thời** | In song song trong giai đoạn chuyển tiếp để verify fix, sau đó bỏ |
| **Fallback khi GT thiếu function data** | Nếu `gt_functions[bug_id]` rỗng: không buộc strict, giữ hành vi cũ cho bug đó |
| **Tier 2 không bị xóa** | Hint vào Tier 2 vẫn xuất hiện trong report — không suppress, chỉ đánh dấu khác |
| **Manifest có điều kiện** | Chỉ inject focus directive khi `confidence(manifest) >= ngưỡng` hoặc user override |
| **Prompt có trần finding** | Tối đa N findings riêng cùng lớp SWC mỗi round — tránh flood consensus |
| **A/B trước khi bật global** | Test prompt mới trên 1–2 contest trước khi deploy toàn bộ |

---

## 8. Tóm tắt

| Mục | Quyết định |
|---|---|
| **Metric dài hạn** | `F1_L_fn` duy nhất — SWC đúng + function đúng + exploit path (Tier 1 only) |
| **Class-level F1** | Bỏ sau khi fix ổn định; giữ tạm làm diagnostic trong giai đoạn chuyển tiếp |
| **Điều kiện bỏ class-level** | `\|F1_L_class − F1_L_fn\| < 0.05` ổn định qua 2–3 contest |
| **Tier 1 (consensus_vulns)** | Bắt buộc: function + exploit path + impact → actionable |
| **Tier 2 (unvalidated_swc_gaps)** | Hint không có path — vẫn report như triage signal, không tính vào metric chính |
| **Xung đột 2 mong muốn?** | Không — Tier 1 = actionable, Tier 2 = triage, mỗi tier phục vụ một mục đích |
| **Root cause thực sự** | Agents biết function nhưng không điền `affected_functions` — structured output compliance, không phải capability |
| **Fix ưu tiên cao nhất** | Prompt enforcement Stage 1+2 + `_backfill_functions()` safety net trong consensus engine |
