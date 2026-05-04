# Plan: R2u Anti-Groupthink & Evidence Quality Guard

## Vấn đề

Phase Evidence Reveal (R2u) hiện tại có nguy cơ **groupthink / anchoring bias**:

- Pool evidence được reveal tự nhiên skewed về phía majority vote trong R2
- Agent đang REJECT borderline đọc nhiều ACCEPT reasoning → flip sang ACCEPT theo hiệu ứng bầy đàn
- Kết quả: FP tăng, không phải vì evidence tốt hơn mà vì áp lực xã hội

Ngoài ra có rủi ro phụ **evidence fabrication**: agent cite code snippet trông hợp lý nhưng không khớp với contract thật, agent khác bị thuyết phục mà không verify.

---

## Mục tiêu

1. Giữ nguyên lợi ích của R2u (recover TP bị bỏ sót)
2. Giảm groupthink: agent không flip vote chỉ vì majority nghĩ vậy
3. Giảm evidence fabrication: buộc agent verify evidence với contract source

---

## Thiết kế cải thiện

### A. Prompt hardening (ưu tiên cao, ít code nhất)

Thêm vào `r2_update_prompt` một đoạn **skepticism instruction**:

```
CRITICAL: You are an independent auditor, not a follower.
- ONLY change your vote if you find supporting evidence in the CONTRACT SOURCE CODE provided above.
- Do NOT change your vote simply because other agents disagree with you.
- If revealed evidence cites a code snippet, verify it exists verbatim in the contract source before accepting it.
- Changing REJECT → ACCEPT requires you to quote a specific vulnerable line from the source.
- Changing ACCEPT → REJECT requires you to identify a specific mitigation that was missed.
```

### B. Evidence grounding score (ưu tiên trung bình)

Sau khi collect R2u updates, chạy một bước **evidence grounding check**:

- Với mỗi evidence snippet được reveal, fuzzy-match nó với contract source
- Nếu evidence không có grounding (< 60% match), đánh dấu `unverified`
- Trong prompt R2u, evidence `unverified` được gắn nhãn `[UNVERIFIED — agent cannot confirm this exists in source]`
- Agent được khuyến khích bỏ qua unverified evidence khi ra quyết định

Implementation: dùng `difflib.SequenceMatcher` hoặc simple substring check trên `flat_source`.

### C. Vote delta monitoring (ưu tiên thấp, diagnostic)

Sau R2u, log thống kê:

```
[R2u] Vote delta: +N ACCEPT, -M REJECT (net change)
[R2u] Pair p_xxx: REJECT→ACCEPT (triggered by: <evidence_snippet_preview>)
```

Cho phép detect pattern: nếu delta luôn dương (ACCEPT tăng không bao giờ giảm), đó là dấu hiệu groupthink.

---

## Checklist triển khai

### Phase 1 — Prompt hardening (không cần thay đổi data flow)
- [ ] Thêm skepticism instruction vào `r2_update_prompt` trong `cyber_session_orchestrator.py`
- [ ] Test: chạy lại contest 35, so sánh R2u delta trước/sau

### Phase 2 — Evidence grounding
- [ ] Implement `_ground_evidence(evidence_text, flat_source) -> float` (trả về 0.0–1.0)
- [ ] Trong `_build_revealed()`, gắn tag `[UNVERIFIED]` cho evidence có score < 0.6
- [ ] Update prompt để agent nhận biết `[UNVERIFIED]` tag
- [ ] Test: inject một evidence giả vào R2 pool, verify agent không flip vote

### Phase 3 — Vote delta monitoring
- [ ] Sau `_update_vote_one()`, log original vs updated vote
- [ ] Aggregate stats cuối R2u: n_flipped_accept, n_flipped_reject
- [ ] Alert nếu n_flipped_accept > 2× n_flipped_reject (groupthink signal)

---

## Không thay đổi

- Cơ chế R2u cơ bản (vẫn collect evidence → reveal → allow one update)
- round2_score formula: `(k + r) / n_agents`
- Threshold R2 = 0.35

---

## Đánh giá thành công

So sánh trước/sau trên tập benchmark:
- Precision không giảm sau khi thêm skepticism instruction
- Recall không giảm (TP vẫn được recover)
- Vote delta: n_flipped_reject tăng lên (filter FP tốt hơn)
