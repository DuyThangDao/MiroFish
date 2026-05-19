# RAG Injection Cap — Options A & B

## Vấn đề

Contest 42 (Lending/MochiVault) bị regression F1 0.302 → 0.246 (-18%) sau khi thêm Spearbit.  
Root cause: avg 2–5 RAG injections/agent → "distractor effect" — agent bị dẫn dắt bởi DeFi patterns
từ RAG, miss H-07 (liquidation underflow) và H-05, H-11, H-15, H-17.

Contest 35 (AMM/ConcentratedLiquidityPool) không bị ảnh hưởng (avg ~0.9 inj/agent, TP=13).

Ngưỡng hiện tại: `_SCORE_INJECT_THRESHOLD_INV = 0.70` (không giới hạn số injections/agent).

---

## Option A — Thêm cap top-2, giữ nguyên threshold 0.70

### Thay đổi

Trong `_build_invariant_rag_hints` (`cyber_session_orchestrator.py`):

```python
_MAX_RAG_INJECT_PER_AGENT = 2   # thêm constant sau _SCORE_INJECT_THRESHOLD_INV
```

Thay logic build `hints` list: thay vì append theo thứ tự INV-1, INV-2, ...,
collect tất cả candidates pass threshold rồi sort by score desc, take top-2:

```python
candidates = []  # list of (score, hint_block_str)
for i, inv in enumerate(invariants):
    query = build_rag_query("", inv)
    if not query:
        continue
    results = retriever.query(query, n_results=3)
    top_score = results[0]["score"] if results else 0.0
    if not results or top_score < _SCORE_INJECT_THRESHOLD_INV:
        logger.info(f"[RAG] agent={agent_id} inv={i+1} score={top_score:.3f} → skip")
        continue
    logger.info(f"[RAG] agent={agent_id} inv={i+1} score={top_score:.3f} inv='{inv[:60]}'")
    block = [f"INV-{i+1} historical violations (score={top_score:.3f}):"]
    for j, r in enumerate(results, 1):
        if r["score"] < _SCORE_SHOW_THRESHOLD:
            break
        preview = r["content"][:350].replace("\n", " ").strip()
        block.append(f"  [{j}] {r['title']} | {preview}")
    candidates.append((top_score, "\n".join(block)))

# Sort by score desc, take top-2
candidates.sort(key=lambda x: x[0], reverse=True)
hints = [b for _, b in candidates[:_MAX_RAG_INJECT_PER_AGENT]]
return "\n\n".join(hints), len(hints)
```

### Trade-off

| | Trước | Sau Option A |
|---|---|---|
| Contest 35 (AMM) | TP=13, F1=0.329 | Dự kiến giữ nguyên (avg 0.9 inj → hầu hết agents không bị cap) |
| Contest 42 (Lending) | TP=11, F1=0.246 | Dự kiến recover về ~0.29–0.31 |
| Rủi ro bỏ sót | Thấp | Bug thực sự trong RAG → score cao → vẫn lọt top-2 |

### Lý do không lo bỏ sót

- 19 agents chạy độc lập, mỗi agent derive 3–6 INVs riêng → một bug có nhiều cơ hội được hint
- Nếu bug score hạng 3-4 ở một agent → match yếu → khả năng cao là noise
- Agent vẫn chạy Turn 2 đầy đủ ngay cả khi không có hint nào

---

## Option B — Thêm cap top-2 + tăng threshold 0.70 → 0.73

### Thay đổi

Tất cả thay đổi của Option A, cộng thêm:

```python
_SCORE_INJECT_THRESHOLD_INV = 0.73   # tăng từ 0.70 lên 0.73
```

### Tác dụng

- Loại bỏ thêm các hints "borderline" (score 0.70–0.72)
- Chỉ inject khi RAG rất confident về relevance
- Giảm tổng số injections across toàn bộ contest

### Trade-off

| | Option A | Option B |
|---|---|---|
| Threshold | 0.70 (giữ nguyên) | 0.73 (+0.03) |
| Cap | top-2 | top-2 |
| Coverage | Rộng hơn, dễ trigger | Hẹp hơn, ít false positives |
| Risk | Score 0.70–0.72 vẫn có thể noise | Có thể miss hint score 0.70–0.72 có ích |
| Phù hợp | Tất cả contest types | Contest với nhiều DeFi invariants (lending, vault) |

### Khi nào dùng B thay A

- Sau khi A đã verify ổn trên contest 42 và 35
- Nếu FP vẫn còn cao (>40) sau Option A
- Contest protocol phức tạp (nhiều invariants, nhiều agents → nhiều query hits)

---

## Thứ tự triển khai

1. **Implement Option A** — đơn giản, ít rủi ro nhất
2. **Re-run contest 42** với Option A → so sánh F1 vs baseline 0.302
3. **Re-run contest 35** với Option A → verify không regression
4. Nếu vẫn còn vấn đề → thử **Option B**

---

## File cần sửa

| File | Thay đổi |
|------|----------|
| `backend/app/services/cyber_session_orchestrator.py` | Thêm `_MAX_RAG_INJECT_PER_AGENT = 2`, rewrite collect logic trong `_build_invariant_rag_hints` |

Không cần sửa `contract_oasis_env.py` hay bất kỳ file nào khác.
