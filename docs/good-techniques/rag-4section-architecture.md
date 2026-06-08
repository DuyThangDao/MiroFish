# RAG 4-Section Architecture

## Vấn đề hiện tại

RAG DB hiện tại lưu mỗi finding dưới dạng **1 blob text** — title + full text scrape/api — không có cấu trúc nội bộ. Khi query, tất cả 3 track (OP, ST, CODE) đều tìm kiếm trong cùng 1 không gian embedding.

Hệ quả:
- **OP queries** (mô tả "code đang làm gì") không match được với NL vul description → score < 0.65 thường xuyên
- **ST queries** (mô tả "lỗi là gì") match tốt hơn, nhưng chỉ match phần title/summary
- **CODE queries** (normalized code) không có collection riêng → không tồn tại trong kiến trúc hiện tại

---

## Kiến trúc 4-Section

Mỗi finding được tách thành 4 sections, mỗi section được embed và index **riêng biệt**. Query của từng track chỉ tìm trong section tương ứng.

```
Finding (parent)
├── Section 1: Operation Description  ← OP queries match vào đây
├── Section 2: Code Description       ← CODE queries match vào đây
├── Section 3: Vul Description        ← ST queries match vào đây
└── Section 4: Inv Description        ← future: invariant synthesis
```

### Section 1 — Operation Description

**Nội dung**: Mô tả cơ học các operations trong hàm bị lỗi — cast, arithmetic, storage write, external call, decode.

**Format mẫu**:
```
Operations: abi.decode bytes calldata to address uint24 uint160;
store sqrtPriceX96 to price slot without bounds check;
call TickMath.getTickAtSqrtRatio with stored price
```

**Nguồn**: Không có sẵn trong bất kỳ firm nào → **LLM generate** từ code snippet (Section 2) hoặc từ vul description (Section 3).

**Embedding**: `RETRIEVAL_DOCUMENT` (asymmetric — query dùng `RETRIEVAL_QUERY`)

---

### Section 2 — Code Description

**Nội dung**: Đoạn code vulnerable đã normalize (user-defined identifiers → `_VAR`, giữ Solidity types/keywords).

**Format mẫu**:
```solidity
_VAR -= uint128(_VAR);   // vulnerable line
_VAR -= uint128(_VAR);
```

**Nguồn**:

| Firm | Có sẵn? | Cách lấy |
|------|---------|---------|
| C4 scraped | ⚠️ partial | Code inline nhưng tokenized (HTML scrape). Dùng được nếu có `//@audit` hoặc `❌` marker |
| C4 api / Sherlock / Cyfrin | ✅ | Code block ` ```solidity``` ` — extract trực tiếp |
| OpenZeppelin | ❌ | Chỉ có GitHub link — cần fetch |
| Spearbit / MixBytes | ❌ | Không có code |
| self-crafted | ✅ | Code block với `@>` annotation |

**Embedding**: `RETRIEVAL_DOCUMENT` symmetric (code-to-code matching — cả query và document đều là code)

**Normalize function**:
```python
SOLIDITY_KEYWORDS = {
    "uint8","uint16","uint32","uint64","uint96","uint128","uint160","uint256","uint",
    "int8","int16","int32","int64","int96","int128","int160","int256","int",
    "address","bool","bytes","string","bytes1","bytes4","bytes8","bytes16","bytes20","bytes32",
    "mapping","if","else","for","while","do","return","break","continue",
    "unchecked","assembly","revert","require","assert","try","catch","emit","delete","new",
    "public","private","internal","external","view","pure","payable","override","virtual",
    "memory","storage","calldata","indexed","true","false","this","super","type",
    "msg","block","tx","abi",
}

def normalize_code(code: str) -> str:
    return re.sub(
        r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
        lambda m: m.group(0) if m.group(0) in SOLIDITY_KEYWORDS else "_VAR",
        code
    )
```

---

### Section 3 — Vul Description

**Nội dung**: Mô tả lỗ hổng theo ngôn ngữ audit finding — "X causes Y", "missing Z allows W". Đây là phần semantic nhất.

**Format mẫu**:
```
Missing sqrtPrice bounds check in pool initialization allows deployer
to store an invalid price, causing all subsequent swap/mint/burn calls
to revert permanently via TickMath underflow.
```

**Nguồn**:

| Firm | Có sẵn? | Cách lấy |
|------|---------|---------|
| C4 scraped | ✅ | Prose trước PoC section |
| C4 api / Sherlock | ✅ | `## Summary` + `## Root Cause` sections |
| Cyfrin | ✅ | `**Description:**` section |
| OpenZeppelin | ✅ | Toàn bộ prose (không có code inline) |
| Spearbit | ✅ | `## Description` section |
| MixBytes | ✅ | Prose đầu finding |

**Tất cả firm đều có sẵn** — đây là section khả thi nhất để migrate ngay.

**Embedding**: `RETRIEVAL_DOCUMENT` (asymmetric — ST queries dùng `RETRIEVAL_QUERY`)

---

### Section 4 — Inv Description

**Nội dung**: Invariant/property dạng "function X must ensure Y before Z" — dùng để synthesis invariant trong HIST-INV pipeline.

**Format mẫu**:
```
initialize() must validate sqrtPriceX96 >= MIN_SQRT_RATIO and
sqrtPriceX96 < MAX_SQRT_RATIO before storing to price slot.
```

**Nguồn**: **Không có sẵn** trong bất kỳ nguồn nào → LLM generate từ Section 3.

**Embedding**: `RETRIEVAL_DOCUMENT`

---

## ChromaDB Collections

```
ChromaDB
├── solodit_op          ← Section 1, RETRIEVAL_DOCUMENT (asymmetric)
├── solodit_code        ← Section 2, RETRIEVAL_DOCUMENT (symmetric)
├── solodit_vul         ← Section 3, RETRIEVAL_DOCUMENT (asymmetric)  ← hiện tại gần nhất
└── solodit_inv         ← Section 4, RETRIEVAL_DOCUMENT (asymmetric)
```

Collection hiện tại `solodit_findings` là blob — tương đương gần nhất với `solodit_vul` nhưng bị pha tạp bởi PoC, mitigation, judge comments.

**Metadata chung** cho mỗi document trong 4 collections:
```json
{
  "parent_slug": "h-01-order-double-linked-list-...",
  "title": "[H-01] Order double-linked list is broken...",
  "impact": "HIGH",
  "firm": "Code4rena",
  "protocol": "GTE",
  "source_link": "https://code4rena.com/reports/2025-07-gte-spot-clob-and-router",
  "section": "vul"
}
```

---

## Query Routing

| Track | Query vào collection | Embedding type | Threshold |
|-------|---------------------|----------------|-----------|
| OP    | `solodit_op`        | RETRIEVAL_QUERY | 0.65 |
| CODE  | `solodit_code`      | RETRIEVAL_DOCUMENT (symmetric) | 0.80 |
| ST    | `solodit_vul`       | RETRIEVAL_QUERY | 0.65 |
| —     | `solodit_inv`       | RETRIEVAL_QUERY | 0.65 |

---

## Feasibility — Số lượng entries có thể populate

Tổng DB: ~2800 findings (Code4rena 1136 + Sherlock 912 + OZ 405 + MixBytes 362 + Spearbit 342 + Cyfrin 205)

| Section | Số entries có thể extract tự động | Ghi chú |
|---------|----------------------------------|---------|
| Vul Description | ~2800 (100%) | Tất cả firm đều có prose |
| Code Description | ~900–1200 (32–43%) | C4 api + Sherlock + Cyfrin có ` ```solidity``` ` blocks. C4 scraped có 1 subset nhỏ |
| Operation Description | 0% auto | Cần LLM generate — tốn cost |
| Inv Description | 0% auto | Cần LLM generate — tốn cost |

---

## Migration Plan

### Phase 1 — Vul Description (không cần LLM, không tốn cost)

Tách Section 3 từ `parents.json` bằng regex theo firm:

```python
def extract_vul_description(full_text: str, firm: str) -> str:
    if firm in ("Code4rena",) and "content_source" == "scraped":
        # Lấy prose trước "Proof of Concept" hoặc "PoC"
        m = re.search(r'\n\s*(?:Proof of Concept|PoC)\s*\n', full_text, re.IGNORECASE)
        return full_text[:m.start()].strip() if m else full_text

    elif firm in ("Sherlock", "Code4rena"):  # api_excerpt
        # Lấy ## Summary + ## Root Cause
        parts = []
        for section in ("## Summary", "## Root Cause", "## Vulnerability Detail"):
            m = re.search(rf'{re.escape(section)}\s*\n([\s\S]+?)(?=\n## |\Z)', full_text)
            if m:
                parts.append(m.group(1).strip())
        return "\n\n".join(parts)

    elif firm == "Cyfrin":
        m = re.search(r'\*\*Description:\*\*([\s\S]+?)(?=\n\*\*Impact|\Z)', full_text)
        return m.group(1).strip() if m else full_text

    elif firm == "Spearbit":
        m = re.search(r'## Description\s*\n([\s\S]+?)(?=\n## |\Z)', full_text)
        return m.group(1).strip() if m else full_text

    else:
        # Fallback: đoạn prose đầu tiên
        return full_text[:1500]
```

### Phase 2 — Code Description (không cần LLM, chỉ regex)

Extract code blocks từ entries có ` ```solidity``` `:

```python
def extract_code_blocks(full_text: str) -> list[str]:
    return re.findall(r'```(?:solidity)?\s*([\s\S]+?)```', full_text)
```

Với C4 scraped: extract dòng có `//@audit` hoặc `❌` ± 3 dòng context.

Normalize mỗi block bằng `normalize_code()` trước khi upsert vào `solodit_code`.

### Phase 3 — Operation + Inv Description (cần LLM)

Chỉ làm sau khi Phase 1 + 2 hoàn thành và validated.

Batch LLM call qua toàn bộ findings có Code Description (Phase 2 output):
```
Input: code snippet từ Section 2
Output OP: "operations: abi.decode ...; store ... without check; ..."
Output INV: "function X must ensure Y before Z"
```

Cost estimate: ~900 findings × 2 LLM calls × ~500 tokens = ~900K tokens.

---

## Tái sử dụng với pipeline hiện tại

Trong `ContractKGBuilder._collect_track()`, chỉ cần đổi collection target:

```python
# Hiện tại:
op_anns  = _collect_track(op_queries,  OP_CAP,  retriever=retriever_blob)
st_anns  = _collect_track(st_queries,  ST_CAP,  retriever=retriever_blob)

# Sau khi migrate:
op_anns  = _collect_track(op_queries,  OP_CAP,  retriever=retriever_op)
st_anns  = _collect_track(st_queries,  ST_CAP,  retriever=retriever_vul)
code_anns = _collect_code_track(fn_body, CODE_CAP, retriever=retriever_code)
```

`_make_hist_annotation()` không đổi — vẫn dùng `title` + `impact` từ metadata.

---

## Ưu tiên triển khai

1. **Làm ngay (không tốn LLM)**: Phase 1 — build `solodit_vul` từ extracted vul description. Kỳ vọng ST track cải thiện vì query không còn bị nhiễu bởi PoC/judge comments.
2. **Làm tiếp**: Phase 2 — build `solodit_code` từ entries có code blocks. Unlock CODE track.
3. **Sau cùng**: Phase 3 — LLM generate OP + INV descriptions. Cost cao, chỉ làm khi Phase 1+2 đã validate tốt.
