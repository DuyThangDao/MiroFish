# Plan: Build `solodit_unified` ChromaDB Collection

## Mục tiêu

Thay thế `solodit_findings` (raw report blob, avg 4911 chars, thường bị truncate) bằng `solodit_unified` — collection mới với structured documents (vul + inv + op), avg 1213 chars, không truncate, signal/noise tốt hơn cho agent retrieval.

**Motivation từ simulation (contest 42):**
- `solodit_findings` gây regression ở 3/13 bugs (H-06, H-10, H-11): agent bị distracted bởi noisy retrieved docs
- Structured sections loại bỏ boilerplate report → embedding vector tập trung vào semantic vulnerability pattern

---

## Data có sẵn

| Nguồn | Path | Số lượng |
|-------|------|----------|
| `rag_sections_cache.json` | `backend/scripts/rag/rag_sections_cache.json` | 3366 findings |
| `parents.json` | `backend/data/rag_db/parents.json` | 3366 (full text, source of truth) |
| ChromaDB hiện tại | `backend/data/rag_db/chroma/` | `solodit_findings` (8396 chunked docs) |

**Status breakdown:** `done`=3077, `done_no_code`=289 — tất cả đều có đủ vul+inv+op.

**Metadata có sẵn per finding:** `slug`, `title`, `firm`, `protocol`, `impact`, `source_link`, `content_source`, `code_source`

**Combined vul+inv+op length:** avg=1213, median=1218, p90=1383, max=1651 — KHÔNG cần truncate.

---

## Document Format

### Template cho mỗi document (text được embed)

```
[VULNERABILITY]
{vul}

[INVARIANT]
{inv}

[OPERATIONS]
{op}
```

**Không đưa vào:**
- `sections.code` (normalized `_VAR` identifiers — agent không đọc hiểu được, dùng cho code-track riêng)
- Full report text (đây là solodit_unified, không phải solodit_findings)
- Title/slug trong text (đã có trong metadata, không cần trong embedding text)

### Metadata per document

```python
{
    "slug":           "h-01-...",
    "title":          "...",
    "firm":           "Code4rena" | "Sherlock" | ...,
    "protocol":       "...",
    "impact":         "HIGH",  # all HIGH
    "source_link":    "https://...",
    "content_source": "api_excerpt" | ...,
}
```

### Display format khi agent nhận kết quả

```
--- FINDING (score=0.823) ---
SLUG: h-01-...
TITLE: Missing ownership check allows draining vault
FIRM: Sherlock | PROTOCOL: SomeProtocol

VULNERABILITY:
{vul}

INVARIANT:
{inv}

OPERATIONS:
{op}
```

---

## Bước thực hiện

### Phase 1: Viết embed script

**File:** `backend/scripts/rag/embed_solodit_unified.py`

**Cấu trúc:**

```python
# 1. Load rag_sections_cache.json
# 2. Build documents list (text + metadata)
# 3. Batch embed bằng Vertex AI text-embedding-004 (DOCUMENT task type)
# 4. Write vào ChromaDB collection "solodit_unified"
# 5. Checkpoint sau mỗi batch (resume-safe)
```

**Chi tiết:**

```python
BATCH_SIZE = 250      # Vertex AI API limit per request
CHROMA_BATCH = 500    # ChromaDB add batch size
TASK_TYPE = "RETRIEVAL_DOCUMENT"  # cho embed, khác với RETRIEVAL_QUERY khi query
```

**Checkpoint strategy:**
- Lưu `embed_checkpoint.json` cạnh script sau mỗi batch
- Key: `last_processed_slug`, value: slug cuối cùng đã embed
- Resume: skip tất cả slugs trước checkpoint

**Lưu ý section type:**
```python
def to_str(v):
    """Handle sections stored as list or string."""
    if isinstance(v, list): return ' '.join(str(x) for x in v)
    return v or ''
```
Một số sections trong cache lưu dạng list thay vì string.

**Vertex AI embedding:**
```python
# DOCUMENT task type khi build collection
inputs = [TextEmbeddingInput(text, "RETRIEVAL_DOCUMENT") for text in batch]
# QUERY task type khi agent query
inputs = [TextEmbeddingInput(query, "RETRIEVAL_QUERY")]
```
Quan trọng: DOCUMENT vs QUERY phải khớp với cách solodit_findings đã dùng.

### Phase 2: Chạy embed script

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

# Chạy foreground (có progress bar)
python scripts/rag/embed_solodit_unified.py

# Hoặc background
nohup python scripts/rag/embed_solodit_unified.py \
  > /tmp/embed_unified.log 2>&1 &
tail -f /tmp/embed_unified.log
```

**Ước tính thời gian:**
- 3366 docs / 250 per batch = ~14 Vertex AI calls
- ~2-5 phút total (chủ yếu I/O)

**Verify sau khi xong:**
```python
col = chroma_client.get_collection("solodit_unified")
print(col.count())  # should be 3366
```

### Phase 3: Thêm `search_audit_memory` tool vào R1 pipeline

**File cần sửa:** `backend/app/services/contract_oasis_env.py`

**Tool definition mới:**
```python
{
    "type": "function",
    "function": {
        "name": "search_audit_memory",
        "description": (
            "Search historical smart contract audit findings. "
            "Each result contains: vulnerability description, violated invariant, "
            "and mechanical operations involved. "
            "Use to recall similar past vulnerabilities while reasoning about a pattern. "
            "Call multiple times with different query angles as analysis deepens."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Describe the suspicious pattern, mechanism, or invariant violation you suspect."
                },
                "n_results": {"type": "integer", "default": 3}
            },
            "required": ["query"]
        }
    }
}
```

**Tool handler:**
```python
def search_audit_memory(query: str, n_results: int = 3) -> str:
    col = chroma_client.get_collection("solodit_unified", embedding_function=VertexQueryEmbed())
    results = col.query(query_texts=[query], n_results=n_results * 2, ...)
    # dedup by slug, format structured output
    # return top n_results
```

**Tích hợp vào R1 round:**
- Thêm tool vào danh sách tools trong `build_round1_prompt()` hoặc `_discover_one()`
- Cho phép agent gọi trong multi-turn loop (max 3-5 RAG calls per agent)
- Tool call format đã có sẵn trong pipeline (xem `simulate_r1_real.py` làm reference)

### Phase 4: A/B test `solodit_unified` vs `solodit_findings`

Chạy lại `simulate_r1_real.py` với collection = `solodit_unified` thay vì `solodit_findings`.

**Mục tiêu:**
- No-regression: H-02, H-03, H-06, H-10, H-11, H-12 (currently found by no_rag) không bị drop
- Improvement: các bugs bị regression (H-06, H-10, H-11) phải được recover
- Stretch: H-04, H-07, H-08 (hiện tại 0/0) có cải thiện không

**Metric target:**
- With-RAG TP ≥ 8/13 (vs 7/13 hiện tại với solodit_findings)
- RAG regression ≤ 1 (vs 3/13 hiện tại)

---

## File cần tạo/sửa

| File | Action | Nội dung |
|------|--------|---------|
| `backend/scripts/rag/embed_solodit_unified.py` | Tạo mới | Embed script |
| `backend/scripts/simulate_r1_real.py` | Sửa | Đổi collection name sang `solodit_unified` |
| `backend/app/services/contract_oasis_env.py` | Sửa (Phase 3) | Thêm `search_audit_memory` tool |

---

## Checklist

- [ ] Viết `embed_solodit_unified.py` với checkpoint/resume support
- [ ] Test embed với 10 docs trước khi chạy full
- [ ] Chạy full embed (3366 docs)
- [ ] Verify count = 3366 trong ChromaDB
- [ ] Verify một query thủ công trả về đúng structure
- [ ] Sửa `simulate_r1_real.py` để dùng `solodit_unified`
- [ ] Chạy lại simulation và so sánh TP với baseline (7/13)
- [ ] Nếu kết quả tốt hơn → integrate vào R1 pipeline (`contract_oasis_env.py`)

---

## Quyết định thiết kế đã confirm

| Câu hỏi | Quyết định | Lý do |
|---------|-----------|-------|
| Đưa code normalize vào không? | Không | Agent không đọc `_VAR` identifiers; code track dùng `solodit_code` riêng |
| Dùng full report hay structured sections? | Structured sections | Full report avg 4911 chars, thường truncate; sections avg 1213 chars, không truncate |
| Giữ `solodit_findings` không? | Có, giữ nguyên | HIST-INV layer 1 (pre-computed OP queries) vẫn dùng `solodit_op`; không xóa `solodit_findings` |
| RETRIEVAL_DOCUMENT vs RETRIEVAL_QUERY? | DOCUMENT khi embed, QUERY khi search | Phải match với cách collection build |
| Bao nhiêu results trả về cho agent? | 3 (dedup by slug) | Nhiều hơn → noise tăng; ít hơn → miss |

---

## Notes

- `solodit_unified` là Layer 2 trong 2-layer RAG architecture (xem `rag-4section-architecture.md`)
- Layer 1 (`solodit_op` + pre-computed HIST-INV) vẫn chạy độc lập song song
- Hai layer không xung đột: Layer 1 inject trước R1, Layer 2 agent tự query trong R1
