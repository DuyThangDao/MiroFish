# Phase 1 — Embed solodit_op + Update HIST-INV Build

## Mục tiêu

Thay `solodit_findings` (blob) bằng `solodit_op` (per-operation docs) trong HIST-INV build.
Khi query match → lookup `sections.inv` từ cache → inject invariant vào source annotation.

## Về `solodit_findings` (RAG cũ)

Giữ nguyên, không xóa, không dùng đến nữa sau Phase 1 + Phase 2. Nếu cần dùng lại thì tính sau.

---

## Prerequisites

- [x] `fill_op_llm.py` hoàn thành — `rag_sections_cache.json` có `sections.op` cho 3366 findings
- [x] `fill_inv_llm.py` hoàn thành — `rag_sections_cache.json` có `sections.inv` cho 3366 findings

---

## Step 1.1 — Viết script embed `solodit_op`

**File mới**: `backend/scripts/rag/embed_solodit_op.py`

Mỗi op line trong `sections.op` → 1 ChromaDB document riêng biệt.

**Schema ChromaDB document:**
```python
{
    "id":       f"{slug}::op::{i}",   # unique per op line
    "document": op_line,               # "cast uint256 to uint128 in reserve balance update"
    "metadata": {
        "slug":   slug,
        "impact": finding["impact"],   # "HIGH" / "MEDIUM" / ...
        "firm":   finding["firm"],
    }
}
```

**Embedding model**: `text-embedding-004` (Vertex AI), task_type=`RETRIEVAL_DOCUMENT`
**Batch size**: 40 documents, truncate mỗi doc tại 1200 chars
**Collection name**: `solodit_op`

**Logic:**
```python
# Nếu collection đã tồn tại và count == expected → skip (idempotent)
existing = collection.count()
if existing >= total_expected:
    log("solodit_op already built, skip")
    return

# Embed theo batch
for batch in chunks(all_docs, size=40):
    texts = [d["document"][:1200] for d in batch]
    embeddings = embed_batch(texts, task_type="RETRIEVAL_DOCUMENT")
    collection.add(
        ids=[d["id"] for d in batch],
        embeddings=embeddings,
        documents=[d["document"] for d in batch],
        metadatas=[d["metadata"] for d in batch],
    )
```

**Tổng docs**: 17280 op lines → ~432 batches

---

## Step 1.2 — Cập nhật `rag_retriever.py`

**File**: `backend/scripts/rag/rag_retriever.py`

Thêm support query `solodit_op` collection. Query trả về slug + score để caller có thể lookup `sections.inv`.

```python
def query_op(self, query_text: str, n_results: int = 5) -> list[dict]:
    """
    Query solodit_op collection.
    Returns: [{"slug": ..., "op_line": ..., "score": ..., "impact": ...}]
    """
    collection = self._get_collection("solodit_op")
    embedding = self._embed([query_text], task_type="RETRIEVAL_QUERY")[0]
    results = collection.query(
        query_embeddings=[embedding],
        n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )
    out = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        out.append({
            "slug":    meta["slug"],
            "op_line": doc,
            "score":   round(1 - dist, 4),   # cosine similarity
            "impact":  meta.get("impact", ""),
        })
    return out
```

---

## Step 1.3 — Bỏ call graph title injection, chỉ giữ source injection

Hiện tại có 2 nơi inject HIST-INV:

| Nơi inject | Nội dung | File |
|---|---|---|
| Call graph node (`↳ HIST:`) | `[Title] [IMPACT]` | `contract_kg_builder.py` |
| Source code (`// [HIST-INV]:`) | Synthesized invariant | `cyber_session_orchestrator.py` |

Chỉ giữ **source code injection** — agents đọc source, không đọc call graph titles.

**Bỏ call graph injection** (`contract_kg_builder.py`):
```python
# TRƯỚC: gán title vào call graph
result.append(f"    ↳ HIST: {inv}")   # ← xóa dòng này

# SAU: call graph giữ nguyên, không có ↳ HIST line
```

**Bỏ `_generate_hist_inv`** (LLM call synthesize inv từ titles → không cần nữa vì `sections.inv` pre-built):
```python
# TRƯỚC
hist_inv = ContractKGBuilder._generate_hist_inv(fn_name, fn_body, inv_text=combined, llm_client=client)
if hist_inv:
    stmts_cache.set(cache_key, contract_name, fn_name, hist_inv)

# SAU: xóa đoạn trên — inv lấy trực tiếp từ sections.inv qua slug lookup
```

Lợi ích: tiết kiệm N LLM calls/run (N = số functions có RAG match).

---

## Step 1.4 — Cập nhật source injection (`cyber_session_orchestrator.py`)

`_annotate_source_with_hist_inv` hiện dùng `inv_map` từ `HistInvStmtsCache` (LLM-synthesized).
Sau Phase 1: `inv_map` được build trực tiếp từ `sections.inv` lookup theo slug — không cần LLM.

**Thay đổi cách build `inv_map`** (trong orchestrator, trước khi gọi `_annotate_source_with_hist_inv`):

```python
# TRƯỚC: inv_map từ HistInvStmtsCache (LLM synthesized)
inv_map = stmts_cache.get_hist_inv_map()

# SAU: inv_map từ slug lookup trong rag_sections_cache.json
inv_map = _build_inv_map_from_slugs(hist_inv_cache, inv_lookup)
```

**Format annotation trong source giữ nguyên** — chỉ thay nội dung:
```
// [HIST-INV]: uint256 value must fit within uint128 bounds before any narrowing cast
//             storage write must follow bounds verification in unchecked block
```

**`_build_inv_map_from_slugs`** (hàm mới trong orchestrator):
```python
def _build_inv_map_from_slugs(hist_inv_cache, inv_lookup: dict) -> dict:
    """Build inv_map: (contract_name, fn_name) → inv string từ pre-built sections.inv."""
    inv_map = {}
    for (contract, fn), slugs in hist_inv_cache.get_matched_slugs().items():
        inv_lines = []
        for slug in slugs[:2]:           # max 2 findings per function
            lines = inv_lookup.get(slug) or []
            inv_lines.extend(lines[:2])  # max 2 inv per finding
        if inv_lines:
            inv_map[(contract, fn)] = "\n".join(inv_lines[:3])  # max 3 total
    return inv_map
```

**`inv_lookup`** load 1 lần khi orchestrator khởi động:
```python
# _inv_lookup: {slug → list[str]} từ rag_sections_cache.json
_inv_lookup = {f["slug"]: f["sections"].get("inv") or []
               for f in json.load(open(CACHE_PATH))["findings"]}
```

---

## Step 1.5 — Cập nhật `contract_kg_builder.py` — query solodit_op

**Thay đổi RAG query trong `_process_entry`:**

```python
# TRƯỚC: query solodit_findings (blob)
docs = retriever.query(q, n_results=3)

# SAU: query solodit_op (per-op docs) — trả về slug để caller lookup inv
docs = retriever.query_op(q, n_results=3)
```

Cache vẫn lưu slugs matched per function để orchestrator dùng khi build inv_map:
```python
# Lưu thêm slugs vào cache entry
cache.set(cache_key, contract_name, fn_name,
          queries_str, combined="", slugs=[d["slug"] for d in matched_docs], ...)
```

---

## Step 1.6 — Benchmark

Chạy 1 contest với `solodit_op` + inv annotations, so sánh với baseline `solodit_findings`.

```bash
# Run với solodit_op
bash scripts/run_benchmark.sh \
  /home/thangdd/repos/web3bugs/contracts/42 \
  ../benchmark/web3bugs/agent-redesign/42/run-phase1

# Eval
python3 scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_42.json \
  ../benchmark/web3bugs/agent-redesign/42/run-phase1/*/audit_report_dedup.json \
  --verbose | tee ../benchmark/web3bugs/agent-redesign/42/run-phase1/eval_result.txt
```

**Dấu hiệu thành công:**
- HIST-INV annotations trên source có dạng `[HIST-INV] op: ... inv: ...` thay vì chỉ title
- F1 không drop so với baseline (run-10 của contest 42)
- Cosine scores cao hơn (per-op embedding khớp tốt hơn blob)

---

## Checklist

- [ ] `embed_solodit_op.py` — viết và chạy (Step 1.1)
- [ ] `rag_retriever.py` — thêm `query_op()` (Step 1.2)
- [ ] `contract_kg_builder.py` — bỏ call graph title injection + `_generate_hist_inv` (Step 1.3)
- [ ] `contract_kg_builder.py` — switch sang `query_op`, lưu slugs vào cache (Step 1.5)
- [ ] `cyber_session_orchestrator.py` — thêm `_build_inv_map_from_slugs`, load `_inv_lookup` (Step 1.4)
- [ ] Chạy benchmark contest 42
- [ ] Xác nhận F1 ≥ baseline trước khi sang Phase 2
