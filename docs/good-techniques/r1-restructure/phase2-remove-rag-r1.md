# Phase 2 — Remove RAG from R1

## Mục tiêu

Loại bỏ 3 RAG hooks hiện tại trong R1 (circular/duplicate/dead code).
Sau đó benchmark để xác nhận recall không drop trước khi sang Phase 3.

## Prerequisites

- [x] Phase 1 hoàn thành — HIST-INV build dùng `solodit_op` + inv annotations
- [x] Baseline F1 đã có (từ Phase 1 benchmark)

---

## Step 2.1 — Disable `_build_invariant_rag_hints` ở Turn 2

**File**: `backend/app/services/cyber_session_orchestrator.py`

Tìm đoạn sau (line ~3475):
```python
# System: query RAG per invariant, build hint block
step2_hint = ""
if rag_enabled:
    hint_block, rag_calls = _build_invariant_rag_hints(
        turn1_response, profile.agent_id,
        target_contracts=target_contracts,
    )
    if hint_block:
        step2_hint = (
            "\nHISTORICAL VIOLATION PATTERNS from audit database:\n\n"
            ...
        )
```

**Thay bằng:**
```python
# [Phase 2] INV → RAG removed: circular reasoning + semantic mismatch.
# HIST-INV build (solodit_op) đã inject knowledge vào source annotations trước R1.
step2_hint = ""
# ⚠️ Cũng xóa rag_calls={rag_calls} khỏi logger ngay bên dưới (biến không còn tồn tại)
```

---

## Step 2.2 — Disable `_build_invariant_rag_hints` ở gap-fill *(SKIP — gap-fill đã disabled)*

**GAP_FILL_ENABLED=false** là default và không có run nào đang enable — step này không cần thiết.
Nếu sau này enable lại gap-fill thì mới cần xử lý.

Code không cần thay đổi. Nếu gap-fill được enable lại sau này, áp dụng cùng pattern với Step 2.1.

---

## Step 2.3 — Disable `_build_code_similarity_rag_hints`

**File**: `backend/app/services/cyber_session_orchestrator.py`

Tìm đoạn sau (line ~3362):
```python
if rag_enabled:
    hint_block, rag_calls = _build_code_similarity_rag_hints(
        turn1_mechanics, profile.agent_id,
        target_contracts=target_contracts,
        primary_contract=primary_contract,
    )
    if hint_block:
        step2_hint = (
            "\nSIMILAR CODE PATTERNS from audit database:\n\n"
            ...
        )
```

**Thay bằng:**
```python
# [Phase 2] code_similarity RAG removed: duplicate với HIST-INV build.
step2_hint = ""
# ⚠️ Cũng xóa rag_calls={rag_calls} khỏi logger ngay bên dưới (biến không còn tồn tại)
```

**Lưu ý**: Step 2.3 là stepping stone — `code_similarity_auditor` sẽ được redesign toàn bộ ở Phase 4
(Option B: HIST-INV Verifier). Sau Phase 4, block code này sẽ bị thay thế hoàn toàn.

---

## Step 2.4 — Xóa dead code `_build_rag_observations`

**File**: `backend/app/services/cyber_session_orchestrator.py`

Xóa toàn bộ function `_build_rag_observations` (line ~223, ~40 lines).
Không được gọi ở đâu → safe to delete.

---

## Step 2.5 — Benchmark

```bash
bash scripts/run_benchmark.sh \
  /home/thangdd/repos/web3bugs/contracts/42 \
  ../benchmark/web3bugs/agent-redesign/42/run-phase2

python3 scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_42.json \
  ../benchmark/web3bugs/agent-redesign/42/run-phase2/*/audit_report_dedup.json \
  --verbose | tee ../benchmark/web3bugs/agent-redesign/42/run-phase2/eval_result.txt
```

---

## Tiêu chí quyết định

| Kết quả | Hành động |
|---|---|
| F1 ≥ Phase 1 baseline | ✅ Tiếp tục Phase 3 |
| F1 drop ≤ 2 points | ⚠️ Tiếp tục Phase 3, note để theo dõi |
| F1 drop > 2 points | ❌ Rollback → xem xét Evidence-Enrichment RAG (xem Section 6 trong plan tổng) |

---

## Checklist

- [ ] Disable `_build_invariant_rag_hints` ở Turn 2 + xóa `rag_calls=` khỏi logger (Step 2.1)
- [x] ~~Disable `_build_invariant_rag_hints` ở gap-fill~~ — SKIP, gap-fill disabled (Step 2.2)
- [ ] Disable `_build_code_similarity_rag_hints` + xóa `rag_calls=` khỏi logger (Step 2.3)
- [ ] Xóa `_build_rag_observations` (Step 2.4)
- [ ] Chạy benchmark contest 42
- [ ] So sánh F1 với Phase 1 baseline → quyết định tiếp tục hay rollback
