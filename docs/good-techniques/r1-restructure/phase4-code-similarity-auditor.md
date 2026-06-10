# Phase 4 — Redesign `code_similarity_auditor`

## Mục tiêu

`code_similarity_auditor` hiện phụ thuộc hoàn toàn vào `_build_code_similarity_rag_hints`
(đã bị remove ở Phase 2). Cần quyết định: loại bỏ hay redesign với task mới.

## Prerequisites

- [x] Phase 2 + Phase 3 hoàn thành và benchmark ổn

---

## Phân tích hiện trạng

**Hiện tại `code_similarity_auditor` làm gì:**
1. Turn 1: sinh FUNC mechanics blocks (mô tả từng function làm gì)
2. System: `_build_code_similarity_rag_hints` query `solodit_findings` bằng FUNC blocks
3. Turn 2: nhận "SIMILAR CODE PATTERNS" → viết finding dựa trên historical matches

**Sau Phase 2:** Step 2 bị remove → agent nhận Turn 2 không có hint → chỉ còn FUNC mechanics analysis mà không có direction để viết finding.

---

## Option A — Loại bỏ hoàn toàn

**Khi nào chọn**: Phase 3 benchmark cho thấy F1 ≥ Phase 2 sau khi thêm 4 tracks, không có gap rõ ràng.

**Thực hiện:**
- Xóa `code_similarity_auditor` khỏi `AGENT_MATRIX` trong `contract_profile_generator.py`
- Xóa `_CODE_SIMILARITY_SYSTEM_PROMPT`
- Xóa `_build_code_similarity_rag_hints` (nếu chưa xóa ở Phase 2)

---

## Option B — Redesign: HIST-INV Verifier

Đổi task của agent thành: **so sánh trực tiếp HIST-INV annotations với actual code mechanics**.

**Task mới:**
```
Turn 1: Đọc toàn bộ source code + tất cả [HIST-INV] annotations
        → Với mỗi [HIST-INV] annotation, mô tả:
          a) Annotation nói điều gì cần kiểm tra (inv)
          b) Code thực tế trong function đó làm gì (mechanics)
          c) Preliminary judgment: có match không?

Turn 2: Với mỗi annotation mà Turn 1 flagged là "potentially matches":
        → Verify chi tiết: exact code path nào vi phạm inv?
        → Nếu confirmed: viết FINDING với code evidence
        → Nếu không confirmed: explicit "Mitigated" + lý do
```

**Lý do tốt hơn current design:**
- Không cần RAG query runtime
- HIST-INV annotations đã có inv cụ thể từ Phase 1 → agent có gì để verify
- Agent làm đúng vai trò: verifier, không phải pattern searcher

**System prompt mới:**
```python
_CODE_SIMILARITY_SYSTEM_PROMPT_V2 = (
    "You are a precise code verifier specializing in historical vulnerability pattern matching. "
    "You are given source code annotated with [HIST-INV] comments — each comment contains "
    "an operation pattern (op:) and a safety invariant (inv:) derived from past audit findings. "
    "Your job is NOT to find new bugs. Your job is to systematically verify: "
    "does THIS contract's code violate each annotated invariant? "
    "You require exact code evidence. If you cannot point to a specific line that violates "
    "the invariant, you must conclude 'Mitigated'. "
    "Precision over recall — one confirmed FINDING is worth more than five speculative ones."
)
```

---

## Option C — Merge vào `logic_exploiter`

Absorb mechanics analysis capability vào `logic_exploiter` (already in `deep_analysis` group).
`logic_exploiter` nên có thêm Track C (state consistency) + mechanics comparison as part of core_question.

**Khi nào chọn**: muốn giảm tổng số agents (từ 20+ xuống ~18).

---

## Khuyến nghị

**Chọn Option B** — HIST-INV Verifier.

Lý do: agent có specialized role (verifier) rõ ràng, không overlap với 20 agents còn lại
vốn đang làm independent reasoning. Verifier + reasoners = complementary coverage.
Khác gap-fill (speculative, high FP): verifier bị ràng buộc chặt — phải cite exact code line,
không có evidence → "Mitigated". FP thấp hơn nhiều.

---

## Option B — Chi tiết triển khai

### Flow mới (3 bước, không có RAG)

```
Turn 1:  Đọc toàn bộ source + tất cả [HIST-INV] annotations
         → Với mỗi annotation: mô tả inv cần check + code mechanics thực tế
         → Preliminary: "match" / "mitigated" / "unclear"

[Filter] Loại các annotation đã được agents khác verify (xem cơ chế bên dưới)

Turn 2:  Batch verify: mỗi call kiểm tra 5 annotation còn lại
         → Nếu confirmed: FINDING + exact code line evidence
         → Nếu không: "Mitigated: <lý do>"
```

Không có RAG. Không có Turn 1.5 (mechanics → INV-Mx conversion). Giảm từ 3 LLM calls
xuống 2 + N/5 batch calls (N = số annotation chưa verified).

---

### Cơ chế 1: Tracked Annotations — tránh re-verify

**Vấn đề**: 22 R1 agents đều đọc source có `// [HIST-INV]:` — mỗi agent khi viết FINDING
đã implicitly verify annotation đó. Verifier không nên kiểm tra lại những inv đã có finding.

**Giải pháp**: sau khi R1 hoàn thành, orchestrator build `_verified_annotations` set trước
khi chạy verifier:

```python
# Sau khi collect tất cả R1 findings
_verified_annotations: set[str] = set()
for finding in candidate_pool.values():
    # Dùng affected_functions + contract_name (structured fields) thay vì code_anchor (free-text evidence)
    fns = finding.get("affected_functions") or []
    contract_f = finding.get("contract_name", "")
    for (inv_contract, inv_fn), inv_text in inv_map.items():
        if inv_fn in fns and inv_contract == contract_f:
            _verified_annotations.add(f"{inv_contract}::{inv_fn}")

# Early exit: nếu không còn annotation nào unverified → skip agent hoàn toàn
unverified = [
    (contract, fn, inv_text)
    for (contract, fn), inv_text in inv_map.items()
    if f"{contract}::{fn}" not in _verified_annotations
]
if not unverified:
    return []   # tiết kiệm toàn bộ Turn 1 + Turn 2
```

Verifier chỉ nhận `unverified` list → không waste tokens re-check annotations đã có finding.

**Lưu ý**: dùng `affected_functions` + `contract_name` thay vì `code_anchor` vì `code_anchor` = evidence free-text (EVIDENCE: field từ LLM), không đảm bảo chứa tên function/contract. `affected_functions` là structured field được parse riêng từ FUNCTION: line → đáng tin hơn.

**Fallback**: nếu không có cơ chế tracking (Phase 4 chạy độc lập), verifier check tất cả
annotations nhưng prompt có instruction: *"Skip any annotation for which a FINDING already
exists in the provided candidate list."*

---

### Cơ chế 2: Batch Verify — tránh phình LLM calls

**Vấn đề**: nếu có 20 unverified annotations, 20 lần gọi LLM là không chấp nhận được.

**Giải pháp**: gom 5 annotations vào 1 Turn 2 call. Format prompt:

```
You are verifying HIST-INV annotations against source code.

For each annotation below, check if the source code actually violates the invariant.
Require EXACT code evidence (line content). If no exact violation found → "Mitigated".

--- ANNOTATION BATCH (5 items) ---

[1] Contract: ConcentratedLiquidityPool | Function: burn
    INV: uint256 value must fit within uint128 bounds before any narrowing cast
    Code (lines 45-62):
    <relevant code snippet>

[2] Contract: Vault | Function: deposit
    INV: token balance must be verified after transfer, not assumed equal to amount
    Code (lines 112-128):
    <relevant code snippet>

... (up to 5)

--- OUTPUT FORMAT (repeat for each item) ---
[1] CONFIRMED | burn() line 52: `uint128(amount)` casts uint256 without bounds check
[1] MITIGATED | checked via `if (amount > type(uint128).max) revert()`
```

Max 5 per batch → N annotations = ceil(N/5) LLM calls.
Nếu N ≤ 5: tất cả trong 1 Turn 2 call.

---

### System prompt mới

```python
_CODE_SIMILARITY_SYSTEM_PROMPT_V2 = (
    "You are a precise HIST-INV Verifier. "
    "You are given source code annotated with [HIST-INV] comments — each derived from "
    "historical audit findings for similar code patterns. "
    "Your ONLY job: for each unverified annotation, determine if THIS contract's code "
    "violates the stated invariant. "
    "Rules: "
    "(1) Require exact code evidence — cite the specific line that violates the invariant. "
    "(2) If no exact violation exists, output MITIGATED with the reason. "
    "(3) Do NOT generate findings for functions without [HIST-INV] annotations. "
    "(4) Precision over recall — one confirmed FINDING beats five speculative ones."
)
```

---

### Số LLM calls sau redesign

| Scenario | Calls |
|----------|-------|
| 0 unverified annotations | 1 (Turn 1 only, no Turn 2) |
| ≤ 5 unverified | 2 (Turn 1 + 1 batch Turn 2) |
| 10 unverified | 3 (Turn 1 + 2 batch Turn 2) |
| 20 unverified | 5 (Turn 1 + 4 batch Turn 2) |

So với hiện tại: 3 fixed calls + N RAG queries → sau redesign: 1 + ceil(N/5) calls, N thường < 10 sau R1 đã verify.

---

## Checklist

- [ ] Chờ Phase 3 benchmark kết quả
- [ ] Implement tracked annotations trong orchestrator (sau R1, trước verifier)
- [ ] Viết `_CODE_SIMILARITY_SYSTEM_PROMPT_V2`
- [ ] Cập nhật Turn 1 prompt: đọc source + list annotations + preliminary judgment
- [ ] Cập nhật Turn 2: batch verify (5 per call), output CONFIRMED/MITIGATED format
- [ ] Xóa Turn 1.5 (mechanics → INV-Mx conversion) — không cần nữa
- [ ] Xóa `_build_code_similarity_rag_hints` call
- [ ] Benchmark contest 42 sau redesign
