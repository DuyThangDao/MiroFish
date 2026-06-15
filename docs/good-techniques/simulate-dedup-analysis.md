# Simulate E2E — Dedup Pipeline Analysis

## Trạng thái hiện tại

Toàn bộ dedup bị comment trong `backend/scripts/simulate_e2e.py` (lines 696–699, 717).
Pipeline hiện tại: `run_chunk() × N → all_raw → save raw JSON (no dedup)`

Kết quả: FP rất cao (ví dụ contest 5 run cũ: 557 raw findings, TP=12, FP=545).

---

## Test thực tế trên chunk `admin_gov/DAO` (24 raw findings)

### Kết quả pipeline đầy đủ

| Bước | Input | Output | Removed | Cơ chế |
|------|-------|--------|---------|--------|
| `_dedup_pre_r2` (static) | 24 | 9 | **-15** | Drop anchor không tồn tại trong source + ATTACK_PATH không structured |
| `_semi_static_anchor_dedup` (semi) | 9 | 8 | **-1** | Group exact anchor → LLM verify, merge 1 group |
| `_llm_anchor_dedup` (LLM) | 8 | 8 | **-0** | 2 LLM calls, không merge thêm |
| **TOTAL** | **24** | **8** | **-16** | **66% reduction** |

### Phân tích drop của `_dedup_pre_r2`

Phần lớn 15 findings bị drop là từ **T3** vì:
1. Thiếu structured `ATTACK_PATH` (phải có ACTOR/CALL/STATE_CHANGE/OUTCOME) — T3 prompt không yêu cầu
2. `CODE_ANCHOR` paraphrase / tổng hợp nhiều dòng — T3 prompt chỉ có "copy EXACT line", thiếu rules 1-4

Findings bị drop **không phải vì reasoning kém** mà vì **format output sai**.

---

## Vấn đề: Drop anchor có thể mất TP

`_dedup_pre_r2` drop finding nếu anchor không tồn tại verbatim trong source.
Các trường hợp anchor bị "sai" hợp lệ:
- `MISSING:` evidence type — anchor là dòng trước chỗ insert, LLM thường viết pseudo-code thay vì dòng thật
- Multi-line expression — LLM gộp 2-3 dòng thành 1
- Whitespace/formatting khác nhau dù cùng nghĩa

---

## Fix đề xuất: Tightening T3 prompt format

**Không sợ mất TP** vì T3's unique value là TRACE reasoning approach, không phải loose format.

Cần thêm vào `_T3_COT_BLOCK` trong `simulate_e2e.py`:

```
CODE_ANCHOR rules — MANDATORY:
  1. Must be findable verbatim by grep in the source above
  2. No comment lines (// or /* */), no standalone braces
  3. If bug spans multiple lines: take the FIRST line of the expression
  4. Max 150 characters

ATTACK_PATH — MANDATORY (all 4 subfields):
  ACTOR: <who initiates>
  CALL: <exact function(s) in sequence>
  STATE_CHANGE: <which state variable becomes incorrect>
  OUTCOME: <measurable impact>
```

**Expected effect:** giảm số findings bị drop ở `_dedup_pre_r2`, giữ được TP từ T3.

---

## Các phương pháp dedup static thuần (không LLM)

1. **Exact match** — same (contract, function, anchor) → precision 100%, recall thấp
2. **Normalized anchor similarity** — `SequenceMatcher` ≥ 0.65 → ~46% reduction (lower bound)
3. **Token-set Jaccard** — tốt hơn khi từ đảo thứ tự
4. **Substring containment** — anchor A ⊂ anchor B → giữ cái dài hơn
5. **Function-level + title ngram** — same (contract, function) + title Jaccard ≥ 0.5
6. **Keyword fingerprint** — extract keywords, hash thành set, đo overlap

Kết hợp thực tế:
```
duplicate nếu: same (contract, function)
  AND (anchor_sim ≥ 0.65 OR title_jaccard ≥ 0.5 OR anchor_contains)
```
LLM dedup chỉ xử lý cặp trong vùng threshold trung bình (0.4–0.65), giảm API calls.

---

## Relaxed anchor check (alternative)

Thay vì drop khi `anchor not in source`, dùng fuzzy match:
```python
# Thay vì: if norm_anchor not in norm_source → drop
# Dùng:    if max_line_similarity(norm_anchor, norm_source) < 0.85 → drop
```
Giữ được TP hơn, đặc biệt với MISSING evidence type.

---

## Kế hoạch test

- [ ] Fix T3 prompt: thêm CODE_ANCHOR rules 1-4 + ATTACK_PATH subfields
- [ ] Re-enable `dedup_pipeline()` sau T3 fix, test trên contest 5
- [ ] So sánh TP/FP trước và sau dedup để calibrate threshold
- [ ] Cân nhắc relaxed anchor check thay vì hard drop
