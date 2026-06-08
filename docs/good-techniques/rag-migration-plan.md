# RAG Migration Plan: Blob → 4-Section Architecture

## Tổng quan

Migrate `solodit_findings` (blob text) thành 4 collections riêng biệt theo kiến trúc đã thiết kế trong [rag-4section-architecture.md](rag-4section-architecture.md).

**Phạm vi**: 3366 findings từ 7 firms.
**Không phá vỡ**: `solodit_findings` giữ nguyên — migration additive, không xóa cũ.
**Thứ tự ưu tiên**: Vul (Phase 1) → Code (Phase 2) → Op/Inv (Phase 3, sau).

---

## Số liệu thực tế

### Coverage cho `solodit_vul` (Phase 1)

| Firm | content_source | Total | Vul text có sẵn |
|------|---------------|-------|-----------------|
| Code4rena | api_excerpt | 554 | 554 (100%) |
| Code4rena | scraped | 582 | 582 (100%) |
| Sherlock | api_excerpt | 912 | 912 (100%) |
| OpenZeppelin | api_excerpt | 405 | 405 (100%) |
| Cyfrin | api_excerpt | 205 | 205 (100%) |
| Spearbit | api_excerpt | 342 | 342 (100%) |
| MixBytes | api_excerpt | 362 | 362 (100%) |
| self-crafted | self-crafted | 4 | 4 (100%) |
| **Total** | | **3366** | **3366 (100%)** |

### Coverage cho `solodit_code` (Phase 2)

Phân loại theo cách code vulnerable được lưu trữ:

| Category | Count | % | Có thể index? |
|----------|-------|---|---------------|
| ` ```solidity``` ` block inline | 1706 | 50% | ✅ trực tiếp |
| GitHub URL permalink (`.sol#L`) | 1116 | 33% | ⚠️ cần fetch |
| `prose_only` (không có code/link) | 306 | 9% | ❌ skip |
| Relative path (`File.sol#L123`) | 155 | 4% | ❌ skip (thiếu repo URL) |
| Inline marker (`//@audit`, `@>`) | 49 | 1% | ✅ extract + detokenize |
| Inline line numbers (`374 :`) | 34 | 1% | ✅ extract + detokenize |

**Phân bố GitHub-URL-only theo firm:**

| Firm | github_url_only | % trong firm |
|------|----------------|-------------|
| OpenZeppelin | 348/405 | 86% |
| MixBytes | 215/362 | 59% |
| C4 scraped | 270/582 | 46% |
| Sherlock | 208/912 | 23% |
| C4 api | 66/554 | 12% |
| Cyfrin | 9/205 | 4% |
| Spearbit | 0/342 | 0% |

**Nếu chỉ dùng inline code** (`code_block` + markers): ~1789 entries (53%)
**Nếu thêm GitHub fetch**: tối đa ~2905 entries (86%)

---

## Phase 1 — `solodit_vul` (Vul Description)

### Mục tiêu
Tách phần **vulnerability description** (prose mô tả lỗi) ra khỏi blob, loại bỏ PoC/judge comments/mitigation. ST queries sẽ match chính xác hơn vào phần semantic này.

### Script: `backend/scripts/rag/build_vul_collection.py`

**Input**: `data/rag_db/parents.json` + metadata từ `solodit_findings`
**Output**: ChromaDB collection `solodit_vul`
**Embedding**: Vertex AI `text-embedding-004`, task_type `RETRIEVAL_DOCUMENT`
**Document ID**: `vul_{slug}`

#### Extraction logic theo firm

```
scraped (C4):
  → Lấy text từ sau header đến trước "Proof of Concept|PoC|Tools Used|Recommended Mitigation"
  → Nếu không có marker: lấy 800 chars đầu

api_excerpt (Sherlock, C4 api):
  → Lấy: ## Summary + ## Root Cause + ## Vulnerability Detail (bỏ ## PoC, ## Impact, ## Mitigation)

Cyfrin:
  → Lấy: **Description:** section đến trước **Impact:**

Spearbit:
  → Lấy: ## Description section

MixBytes:
  → Lấy: ##### Description section, hoặc prose đầu đến trước "## Impact"

OpenZeppelin:
  → Lấy: toàn bộ prose (không có PoC, không cần filter)

self-crafted:
  → Lấy: prose description (sau Title/Impact/Protocol header)
```

#### Xử lý rate limit
- Batch 50 requests, sleep 5s giữa mỗi batch
- Retry 3 lần với exponential backoff khi 429
- Progress checkpoint: lưu `vul_progress.json` sau mỗi 200 entries → resume được

#### Output format mỗi document
```python
{
  "id": "vul_{slug}",
  "document": "<extracted vul description text>",
  "metadata": {
    "parent_slug": slug,
    "title": "...",
    "impact": "HIGH|MEDIUM|LOW",
    "firm": "Sherlock",
    "protocol": "...",
    "source_link": "https://...",
    "content_source": "api_excerpt",
    "section": "vul",
    "char_count": 850,
  }
}
```

#### Validation check (chạy sau khi build xong)
```bash
python3 scripts/rag/test_vul_retrieval.py \
  --queries "stale cached tick results in incorrect fee growth distribution" \
            "reserve accounting ignores principal tokens" \
  --collection solodit_vul
# Kỳ vọng: H-17 self-crafted score > 0.75, tăng so với blob (0.762 hiện tại)
```

---

## Phase 2 — `solodit_code` (Code Description)

### Mục tiêu
Index **normalized vulnerable code** để CODE track có thể tìm pattern tương tự dù variable names khác nhau.

### Script: `backend/scripts/rag/build_code_collection.py`

**Input**: `data/rag_db/parents.json` + metadata
**Output**: ChromaDB collection `solodit_code`
**Embedding**: Vertex AI `text-embedding-004`, task_type `RETRIEVAL_DOCUMENT` (symmetric)
**Document ID**: `code_{slug}_{block_idx}`

#### Extraction logic

```
Ưu tiên 1 — self-crafted: dòng có @> marker
  → extract dòng @> → normalize → index

Ưu tiên 2 — api_excerpt có ```solidity``` blocks:
  → extract tất cả code blocks
  → bỏ blocks < 2 dòng hoặc < 30 chars
  → normalize từng block
  → index mỗi block là 1 document riêng (id: code_{slug}_{i})

Ưu tiên 3 — scraped có //@audit hoặc @> marker:
  → extract dòng có marker ± 3 dòng context
  → detokenize (remove spaces giữa tokens: "amount . sub" → "amount.sub")
  → normalize → index

Ưu tiên 4 — scraped có inline line numbers ("374 : \t code"):
  → extract block liên tục có line numbers
  → detokenize → normalize → index
```

#### Fetch code từ GitHub URL (gộp vào Phase 2, không tách riêng)

1116 entries có GitHub permalink nhưng không có inline code. Dùng `WebFetch` để đọc trực tiếp GitHub blob URL — tool parse HTML và extract code đúng vùng `#L42-L58` chỉ định.

```
https://github.com/org/repo/blob/abc123/src/Foo.sol#L42-L58
  → WebFetch(url, "extract Solidity code at lines 42-58 with surrounding context")
  → code snippet (10-20 dòng)
  → normalize_code()
  → sections.code
```

**Không cần GITHUB_TOKEN** — WebFetch đọc được public repo trực tiếp.

**Relative path entries (133 entries, toàn bộ C4 scraped):**
Path dạng `contracts/SmartAccount.sol#L218` thiếu domain. Reconstruct bằng `source_link`:
```
source_link: https://code4rena.com/reports/2022-09-biconomy
→ repo:       https://github.com/code-423n4/2022-09-biconomy
→ full URL:   https://github.com/code-423n4/2022-09-biconomy/blob/main/contracts/SmartAccount.sol#L218
```
Branch mặc định thử `main` → fallback `master` nếu 404.

**Fallback nếu fetch thất bại** (repo xóa / private / branch sai): `sections.code = null`, log vào `fetch_errors.json`.

**Coverage sau khi gộp fetch:**
- Inline code_block + markers: ~1789 entries (53%)
- + GitHub fetch thành công: ~+1116 entries
- Tổng tối đa: ~2905 entries (**86%**)

#### Normalize function
```python
SOLIDITY_KEYWORDS = {
    "uint8","uint16","uint32","uint64","uint96","uint128","uint160","uint256","uint",
    "int8","int16","int32","int64","int96","int128","int160","int256","int",
    "address","bool","bytes","string","bytes32","bytes20","bytes16","bytes8","bytes4",
    "mapping","if","else","for","while","do","return","break","continue",
    "unchecked","assembly","revert","require","assert","emit","delete","new",
    "public","private","internal","external","view","pure","payable","override","virtual",
    "memory","storage","calldata","true","false","this","super","msg","block","tx","abi",
}

def normalize_code(code: str) -> str:
    return re.sub(
        r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
        lambda m: m.group(0) if m.group(0) in SOLIDITY_KEYWORDS else "_VAR",
        code
    )
```

#### Số entries dự kiến
- Phase 2 (inline): ~1789 findings → trung bình 2-3 blocks/finding → ~3500-5000 code documents
- Phase 2b (GitHub fetch): thêm ~1116 findings nếu fetch thành công

#### Validation check
```bash
python3 scripts/rag/test_code_retrieval.py \
  --fn-body "path/to/ConcentratedLiquidityPool.sol" \
  --fn-name "burn" \
  --collection solodit_code
# Kỳ vọng: self-crafted H-01 (uint128 cast pattern) score > 0.80
```

---

## Phase 3 — `solodit_op` + `solodit_inv` (LLM-generated)

**Sau Phase 1+2 validated** — không làm ngay.

### `solodit_op`
- Input: code block từ Phase 2 (hoặc fn_body)
- LLM prompt: "Describe the mechanical operations in this code: casts, arithmetic, storage writes, external calls"
- ~1700 LLM calls × ~300 tokens = ~500K tokens
- Embedding: RETRIEVAL_DOCUMENT (asymmetric, OP queries dùng RETRIEVAL_QUERY)

### `solodit_inv`
- Input: vul description từ Phase 1
- LLM prompt: "Convert to invariant: 'function X must ensure Y before Z'"
- ~3366 LLM calls × ~200 tokens = ~670K tokens

---

## Thay đổi `ContractKGBuilder`

File: `backend/app/services/contract_kg_builder.py`

### Thêm retriever mới khi init RAG

```python
# Hiện tại (1 retriever):
self._rag_retriever = RAGRetriever(collection_name="solodit_findings", ...)

# Sau migration (3 retrievers):
self._retriever_blob = RAGRetriever(collection_name="solodit_findings", ...)   # OP track (tạm)
self._retriever_vul  = RAGRetriever(collection_name="solodit_vul",      ...)   # ST track
self._retriever_code = RAGRetriever(collection_name="solodit_code",      ...)   # CODE track
```

### Đổi routing trong annotation collection

```python
# Hiện tại:
op_anns = _collect_track(op_queries, OP_CAP, retriever=self._rag_retriever)
st_anns = _collect_track(st_queries, ST_CAP, retriever=self._rag_retriever)

# Sau Phase 1:
op_anns = _collect_track(op_queries, OP_CAP, retriever=self._retriever_blob)  # unchanged
st_anns = _collect_track(st_queries, ST_CAP, retriever=self._retriever_vul)   # → vul collection

# Sau Phase 2 (thêm):
code_anns = _collect_code_track(fn_body, CODE_CAP, retriever=self._retriever_code)
inv_texts = op_anns + st_anns + code_anns
```

### `_collect_code_track` (hàm mới)

```python
CODE_CAP = 3
CODE_WINDOW = 5       # dòng per sliding window
CODE_THRESHOLD = 0.80 # cao hơn OP/ST vì normalized code rất specific

def _collect_code_track(fn_body, cap, retriever_code):
    lines = [l for l in fn_body.split('\n') if l.strip()]
    seen, result = set(), []
    for i in range(len(lines) - CODE_WINDOW + 1):
        if len(result) >= cap:
            break
        chunk = normalize_code('\n'.join(lines[i:i+CODE_WINDOW]))
        docs = retriever_code.query(chunk, n_results=2,
                                    task_type="RETRIEVAL_DOCUMENT")  # symmetric
        for d in (docs or []):
            if d['score'] < CODE_THRESHOLD:
                continue
            ann = ContractKGBuilder._make_hist_annotation(d)
            if ann not in seen:
                seen.add(ann)
                result.append(ann)
                break
    return result
```

---

## Thứ tự chạy

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

# Phase 1 — ~1-2 giờ (3366 entries × embedding call, rate limited)
python3 scripts/rag/build_vul_collection.py

# Validate Phase 1
python3 scripts/rag/test_vul_retrieval.py

# Phase 2 — ~2-3 giờ (~5000 code documents × embedding call)
python3 scripts/rag/build_code_collection.py

# Validate Phase 2
python3 scripts/rag/test_code_retrieval.py

# Update ContractKGBuilder (chỉnh code)
# Clear hist_inv_cache contest đang benchmark
rm -f ../benchmark/web3bugs/agent-redesign/35/hist_inv_cache.json

# Chạy lại build_hist_for_fns.py để verify ST/CODE track
python3 scripts/build_hist_for_fns.py ...

# Nếu kết quả tốt → chạy benchmark run mới
bash scripts/run_benchmark.sh ...
```

---

## Rủi ro và fallback

| Rủi ro | Xác suất | Xử lý |
|--------|----------|-------|
| Vertex AI 429 | Cao | Checkpoint mỗi 200 entries, resume từ điểm dừng |
| Regex extract sai firm | Trung bình | Validate trên 6 sample files trước khi chạy full |
| ST score không cải thiện sau Phase 1 | Thấp | Blob `solodit_findings` vẫn giữ → rollback dễ |
| CODE track FP cao (threshold 0.80 quá thấp) | Trung bình | Tăng lên 0.85, hoặc require window ≥ 4 dòng |
| GitHub fetch thất bại (repo xóa / private) | Trung bình | Log lỗi vào fetch_errors.json, sections.code = null |
| Relative path reconstruct sai branch | Trung bình | Thử main → master → skip nếu cả 2 fail |
| `solodit_vul` chiếm thêm disk | Thấp | ~3366 embeddings × 768 dims × 4 bytes ≈ 10MB |

---

## Done criteria

- [ ] `solodit_vul`: 3366 entries indexed, ST query "stale tick fee distribution" → self-crafted H-17 score > 0.75
- [ ] `solodit_code`: ~2905 entries indexed (inline + GitHub fetch), CODE query trên `burn()` body → self-crafted H-01 cast pattern score > 0.80, fetch error rate < 20%
- [ ] ContractKGBuilder routing updated, unit test pass
- [ ] `build_hist_for_fns.py` trên 4 GT functions: ST annotations vẫn correct (không regress)
- [ ] Benchmark run-N F1 ≥ run hiện tại
