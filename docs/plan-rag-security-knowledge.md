# RAG Security Knowledge Base — Design Plan

## Vấn đề hiện tại

Pipeline hiện tại dùng Zep KG để **RAG code** (store/retrieve snippets từ contract source).
Với DeFi contracts (thường 10–50k tokens), code đã fit hoàn toàn vào context window của model
hiện đại (128k–1M+ tokens) → không cần RAG code nữa.

Thay vào đó, bottleneck thực sự là **thiếu domain knowledge** — agents có thể thấy code nhưng
không biết pattern attack nào tương tự đã được khai thác trong quá khứ.

**Ví dụ**: Agent thấy `feeGrowthGlobal - feeGrowthBelow - feeGrowthAbove` nhưng không biết đây
là intentional underflow của Uniswap V3 fee growth mechanism → sẽ report sai hoặc bỏ qua.
Nếu có RAG retrieve Uniswap V3 audit report → agent biết ngay đây là pattern cần unchecked block.

---

## Kiến trúc đề xuất

```
Audit Pipeline (R1)
│
├── Full contract source (100%, no truncation)  ← đã implement
│
└── RAG Query: "similar vulnerabilities to [function pattern]"
            │
            ▼
    ┌──────────────────────┐
    │  Vector DB           │
    │  Security Knowledge  │
    └──────────────────────┘
            │
    Returns: top-3 relevant past findings
    → Injected vào R1 prompt của agent
```

---

## Nguồn dữ liệu

### Tier 1 — Có sẵn, free, high quality

| Nguồn | Nội dung | Format |
|-------|----------|--------|
| SWC Registry | 36 weakness classes với description, examples, remediation | JSON/MD |
| Web3Bugs dataset | ~300 audit reports từ Code4rena/Sherlock, đã có H/M labels | MD files |
| 4naly3er | Static analysis rules với description | Python |
| Ethereum Security | ethereum.org/security, known attack patterns | Web |

### Tier 2 — Cần thu thập

| Nguồn | Nội dung | Note |
|-------|----------|------|
| Trail of Bits Audit Reports | ~150 public audits, rất chi tiết | PDF/HTML scrape |
| Consensys Diligence | ~100 public audits | PDF |
| OpenZeppelin Audits | ~50 audits | PDF |
| DeFiHackLabs POC | ~400 real exploits với PoC code | GitHub |
| Solodit.xyz | Aggregated findings từ nhiều audit firms | Web scrape |

### Tier 3 — Optional

- Immunefi bug reports (public disclosures)
- Etherscan verified contract comments
- Academic papers (SoK: Blockchain papers)

---

## Schema một entry trong Vector DB

```json
{
  "id": "web3bugs_35_H01",
  "source": "web3bugs",
  "contest_id": "35",
  "h_id": "H-01",
  "title": "Unsafe cast in ConcentratedLiquidityPool.burn leads to attack",
  "vulnerability_type": "unsafe_cast",
  "swc_id": "SWC-101",
  "contract_pattern": "concentrated_liquidity_amm",
  "affected_function": "burn",
  "code_pattern": "int128(amount) cast from uint128 without overflow check",
  "description": "The burn function performs an unsafe cast of amount (uint128) to -int128(amount)...",
  "exploit_scenario": "When amount = 2^128 - 1, this is interpreted as -1 as a signed integer...",
  "remediation": "Use SafeCast library or explicitly check amount <= type(int128).max before casting",
  "embedding": [...]  // vector của title + description + code_pattern
}
```

---

## Query Strategy

### Khi nào query?

Agent nhận full source → trước khi gọi LLM, extract **function signatures + state variable names**
từ source → dùng làm query key để retrieve relevant past vulnerabilities.

### Query types

**1. Pattern-based query** (automatic, trước R1 call):
```python
# Extract patterns từ source
patterns = extract_patterns(source_code)
# patterns = ["unchecked arithmetic", "sqrt price cast", "fee growth subtraction", ...]

# Query cho mỗi pattern
for pattern in patterns:
    results = vector_db.query(pattern, top_k=3)
    context += format_results(results)
```

**2. Function-name query** (per-agent):
```python
# Mỗi agent được assign 1 nhóm functions để focus
# Query: "past vulnerabilities in [function_name] of AMM contracts"
results = vector_db.query(f"vulnerability in {fn_name} AMM", top_k=2)
```

**3. Protocol-type query** (once per session):
```python
# Detect protocol type từ source (AMM, Lending, Bridge, ...)
protocol_type = detect_protocol(source_code)  # "concentrated_liquidity_amm"
results = vector_db.query(f"known attacks on {protocol_type}", top_k=5)
```

---

## Format inject vào R1 prompt

Thêm section sau phần `=== CONTRACT SOURCE ===`:

```
=== RELEVANT PAST VULNERABILITIES (RAG) ===
The following vulnerabilities were found in similar contracts. Use as detection hints:

[1] Unsafe Cast in AMM burn() — SWC-101
    Pattern: uint128 amount cast to -int128(amount) without overflow check
    Impact: Attacker mints LP tokens for free by triggering integer wraparound
    Reference: Web3Bugs #35 H-01

[2] Uniswap V3 Fee Growth Underflow — requires unchecked block
    Pattern: feeGrowthGlobal - feeGrowthOutside calculations can legitimately underflow
    Impact: Revert in valid scenarios → pool permanently broken
    Reference: Uniswap V3 whitepaper §6.3

[3] Reserve Accounting in burn() — wrong field updated
    Pattern: reserve -= feeAmount instead of reserve -= totalAmount
    Impact: Reserve inflation → all subsequent mints/swaps fail
    Reference: Web3Bugs #35 H-10
```

---

## Implementation Roadmap

### Phase 1 — MVP (1-2 ngày)

1. **Build SWC Registry DB**: 36 entries, mỗi entry = title + description + code examples
   - File: `backend/data/swc_registry.json` (đã có SWC data trong `swc_registry.py`)
   - Embed với `text-embedding-004` (Vertex AI) hoặc `all-MiniLM-L6-v2` (local)
   - Store: ChromaDB hoặc FAISS (local, không cần server)

2. **Build Web3Bugs findings DB**: Parse từ `../web3bugs/reports/*.md`
   - ~300 H/M findings, mỗi finding = title + description + function_name
   - Embed và store

3. **Query interface**: `SecurityKnowledgeRAG.query(text, top_k=3) -> List[FindingHint]`

4. **Inject vào R1 prompt**: `build_round1_prompt()` call RAG với contract type + function names

### Phase 2 — Expand (1 tuần)

- Add Trail of Bits / Consensys audit reports
- Add DeFiHackLabs PoC descriptions
- Improve query với function-level context
- Add caching để tránh duplicate queries trong 1 session

### Phase 3 — Advanced (optional)

- Fine-tune embedding model trên security domain
- Cross-reference: nếu RAG hint match → tăng confidence score của finding
- Auto-update: khi có contest mới, auto-add findings vào DB

---

## Tech Stack đề xuất

```
Embedding model : text-embedding-004 (Vertex AI, miễn phí với quota) 
                  hoặc all-MiniLM-L6-v2 (local, 80MB, không cần API)
Vector store    : ChromaDB (local, persist to disk, zero-config)
                  hoặc FAISS (nhanh hơn, không persist natively)
Query top_k     : 3-5 results per query
Chunk size      : 1 finding = 1 chunk (không split nhỏ hơn)
```

ChromaDB được khuyến nghị vì:
- Persist to disk tự động
- Python native, zero-config
- Support metadata filtering (filter theo `swc_id`, `protocol_type`)
- Đã có sẵn trong Python ecosystem

---

## Trade-off cần chú ý

| Vấn đề | Giải pháp |
|--------|-----------|
| RAG inject quá nhiều → noise trong prompt | Limit top_k=3, chỉ inject khi similarity > 0.7 |
| Embedding cost | Dùng local model (MiniLM) cho build-time, chỉ dùng Vertex cho query-time |
| False positive RAG hints | Agent vẫn phải verify trong actual source — RAG chỉ là hint, không phải verdict |
| Stale data | Thêm `last_updated` metadata, re-index khi có contest mới |
| Duplicate hints | Deduplicate bằng `swc_id` + `function_name` trước khi inject |
