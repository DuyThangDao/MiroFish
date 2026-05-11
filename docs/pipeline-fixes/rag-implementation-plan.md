# Plan: RAG Implementation cho Smart Contract Audit Pipeline

## Tổng quan

Xây dựng vector database chứa lịch sử vulnerability write-ups, cho phép mỗi R1 agent truy vấn
các patterns liên quan đến domain của mình trước khi phân tích contract.

**Mục tiêu:** Tăng recall trên các protocol-specific bugs mà pattern matching bỏ sót,
đặc biệt với DeFi protocols phức tạp (lending, AMM, governance).

---

## Kiến trúc tổng thể

```
Data Sources                  Processing                   Storage
─────────────────             ─────────────────────        ──────────────────
DeFiHackLabs/src/test/   →    defi_hack_labs extractor →   ChromaDB
(Solodit — Phase 2)      →    solodit extractor        →   backend/data/rag_db/
                              chunk + embed + tag      →

                              Query Layer (per-agent)
                              rag_retriever.py
                                  ↓
                         build_round1_prompt()
```

### Tại sao ChromaDB

- Python-native, không cần server riêng — chạy embedded trong process
- Persistent storage ra disk → build 1 lần, dùng mãi
- Hỗ trợ metadata filtering — lọc theo domain_tag, protocol_type, severity
- Dùng sentence-transformers local (zero-cost) hoặc Vertex AI embedding API

---

## Nguồn dữ liệu

**Tại sao không dùng web3bugs làm RAG:**
- Web3bugs là evaluation dataset → dùng làm RAG tạo data leakage, kết quả benchmark không clean
- Descriptions trong web3bugs được viết gắn với codebase cụ thể ("trong hàm X của contract Y") — không generalizable thành attack patterns dùng được cho protocols khác

### Nguồn 1 — DeFiHackLabs (ưu tiên cao)

**Vị trí:** `DeFiHackLabs/src/test/YYYY-MM/*.sol` — 689 exploit PoC files.

**Format (comment block đầu file):**
```solidity
// @KeyInfo - Total Lost : ~$130K
// Attacker : 0x...
// Vuln Contract : 0x...
// Attack Tx : https://...

// @Analysis
// https://...article_url...
```

**Giá trị:** On-chain exploits thực tế — attack patterns rất cụ thể, protocol name trong filename.

**Extract được:**
- `protocol_name` — từ filename (e.g., `BarleyFinance_exp.sol`)
- `total_lost` — từ `@KeyInfo` comment
- `analysis_urls` — từ `@Analysis` section
- `attack_pattern` — từ test function logic + comments
- `contract_type` — infer từ interfaces được import (IUniswapV3Router → AMM, ILendingPool → lending, v.v.)

### Nguồn 2 — Solodit (Phase 2)

Solodit aggregates audit findings từ Code4rena, Sherlock, Immunefi — đây là nguồn lý tưởng
vì chứa write-ups được viết theo format generalizable (không tied vào 1 codebase cụ thể).

**Cách lấy data:**
- Solodit cung cấp public feed tại `solodit.xyz` — có thể scrape hoặc dùng export nếu có
- Lọc theo severity H/M, exclude các contests đang trong eval set
- Format: title + description + tags (protocol_type, vuln_class đã được Solodit label sẵn)

**Defer sang Phase 2** — sau khi DeFiHackLabs source đã hoạt động ổn định.

---

## Schema Vector Database

```python
# Collection: "vulnerability_patterns"
# Mỗi document = 1 vulnerability finding

Document:
  id:       str   # "defi_hack_labs_BarleyFinance_2024-01"
  content:  str   # text được embed — xem format bên dưới

  metadata:
    source:           "defi_hack_labs" | "solodit"
    protocol_type:    str   # "AMM" | "lending" | "NFT" | "governance" | "staking" | "bridge" | "token"
    domain_tags:      str   # comma-separated: "defi_math,defi" (ChromaDB metadata là flat)
    severity:         "exploit"   # DeFiHackLabs; Solodit sẽ có "H" | "M"
    vuln_class:       str   # "integer_overflow" | "reentrancy" | "access_control" | "price_manipulation" | ...
    year:             int   # năm incident
    protocol_name:    str   # "BarleyFinance", "Euler Finance", ...
```

**Content format (text được embed):**

```
[PROTOCOL] {protocol_name}
[TOTAL LOST] {total_lost}
[ATTACK PATTERN] {inferred_pattern}
[CONTRACT TYPE] {contract_type}
```

---

## Mapping: Agent Domain → Query Tags

Mỗi agent domain được map sang bộ keyword để query RAG.

```python
DOMAIN_QUERY_MAP = {
    # R1 agents
    "appsec":                   "reentrancy access control unguarded external call initialization",
    "blockchain":               "cross-chain bridge oracle manipulation consensus",
    "cryptography":             "signature replay ECDSA hash collision permit front-run",
    "defi":                     "flash loan price manipulation sandwich MEV arbitrage",
    "smart_contract_economics": "tokenomics inflation deflation fee distribution reward",
    "defi_math":                "arithmetic overflow precision loss rounding truncation cast",
    "token_standard":           "ERC20 ERC721 ERC4626 transfer return value safeTransfer",
    "governance":               "proposal replay timelock bypass quorum manipulation vote",

    # R3 attacker agents
    "reentrancy_exploiter":     "reentrancy cross-function reentrancy read-only reentrancy",
    "flash_loan_attacker":      "flash loan oracle price manipulation single-block attack",
    "governance_attacker":      "governance attack vote bribe flash loan governance",
    "access_control_exploiter": "access control privilege escalation missing modifier",
    "logic_exploiter":          "logic error state corruption business rule invariant violation",
}
```

---

## Cấu trúc Files

```
backend/
  data/
    rag_db/              ← ChromaDB persistent storage (gitignore)

  scripts/
    rag/
      __init__.py
      build_rag_db.py    ← CLI script: build/rebuild toàn bộ DB
      extractors/
        __init__.py
        defi_hack_labs.py ← Parse DeFiHackLabs/src/test/**/*.sol
        solodit.py        ← (Phase 2) Solodit scraper/parser

  app/
    services/
      rag_retriever.py   ← Per-agent query interface, dùng trong pipeline
```

---

## Chi tiết từng module

### Module 1: `defi_hack_labs.py` — Extractor

**Nguyên tắc quan trọng: KHÔNG embed raw .sol code.**
Truncate cơ học (`doc[:400]`) trên file .sol chỉ trả về SPDX license + imports — vô nghĩa với RAG.
Attack pattern nằm trong test function body (thường cách header 200-400 dòng).

**Approach đúng: 2-phase extraction**

Phase A — Parse tĩnh (không cần LLM):
```python
def extract_exploits(hack_labs_dir: str) -> List[dict]:
    # 1. protocol_name từ filename (BarleyFinance_exp.sol → "BarleyFinance")
    # 2. year từ parent dir (2024-01)
    # 3. @KeyInfo block: total_lost, attacker address
    # 4. @Analysis block: article URLs (lưu làm reference)
    # 5. imports: IUniswapV3Router → protocol_type = "AMM"
    # 6. Tách test function body (từ "function testExploit" đến cuối)
    # → Trả về: metadata + raw_test_body (chưa embed)
```

Phase B — LLM summarization (chạy song song, dùng model rẻ):
```python
SUMMARIZE_PROMPT = """
Read this Solidity Foundry exploit test. Focus ONLY on the core attack logic inside
the main exploit function (usually named testExploit or test_Exploit).
IGNORE: setUp(), environment config, vm.createSelectiveFork(), deal() calls,
vm.label(), and any test infrastructure code.

Summarize the attack technique in 3 bullet points:
1. Root Cause: [the underlying vulnerability in the victim contract]
2. Attack Steps: [sequence of external calls the attacker makes, with key function names]
3. Impact: [what the attacker gains — amounts if visible]
Max 500 characters total.

{test_exploit_body}
"""

# test_exploit_body = chỉ phần body của hàm testExploit/test_Exploit
# (tách ra từ Phase A bằng regex tìm function testExploit)
# Dùng gemini-2.5-flash-preview (model R1 hiện tại qua Vertex AI)
# Reuse LLMClient infrastructure — không cần thêm dependency hay API key mới
# Build 1 lần, kết quả persist trong ChromaDB mãi mãi
```

**Content cuối cùng được embed:**
```
[PROTOCOL] BarleyFinance
[CONTRACT TYPE] lending
[TOTAL LOST] ~$130K
[ROOT CAUSE] Flash loan manipulation of bond/debond price oracle
[ATTACK STEPS] 1. Flash loan USDC → 2. bond() inflates wBARL price → 3. debond() drains pool
[IMPACT] Attacker drains ~$130K via price manipulation
```

**Interface → protocol_type mapping:**
```python
INTERFACE_TYPE_MAP = {
    ("IUniswapV2", "IUniswapV3", "ICurve", "IBalancer"): "AMM",
    ("ILendingPool", "IVault", "IBorrowable", "IComptroller"): "lending",
    ("IERC721", "IERC1155", "IMarketplace"): "NFT",
    ("IBridge", "IRelay"): "bridge",
    ("IStaking", "IEpoch"): "staking",
}
```

### Module 2: `build_rag_db.py` — Build Script

```python
# CLI: python scripts/rag/build_rag_db.py [--reset]

def build(hack_labs_dir, db_path, embedding_model):
    client = chromadb.PersistentClient(path=db_path)
    collection = client.get_or_create_collection(
        name="vulnerability_patterns",
        embedding_function=embedding_fn,   # OpenAI or local
    )

    # Phase 1: DeFiHackLabs
    exploits = defi_hack_labs_extractor.extract_exploits(hack_labs_dir)
    collection.upsert(
        ids=[e["id"] for e in exploits],
        documents=[e["content"] for e in exploits],
        metadatas=[e["metadata"] for e in exploits],
    )

    # Phase 2 (future): Solodit
    # solodit_extractor.extract(...) — khi implement

    print(f"DB built: {collection.count()} documents")
```

**Embedding function:**
```python
# Option A (default): sentence-transformers/all-MiniLM-L6-v2
#   - Local model, ~80MB, zero-cost, không cần thêm API call
#   - Đủ tốt cho keyword-heavy queries (domain terms + protocol type)
#   - Không phụ thuộc vào Vertex AI quota

# Option B: Vertex AI text-embedding API (textembedding-gecko)
#   - Accuracy cao hơn nhưng tốn quota Vertex AI
#   - Chỉ dùng nếu Option A cho kết quả retrieve không đủ tốt sau evaluation
```

### Module 3: `rag_retriever.py` — Query Interface

**Phân tách quyền Write/Read:**
- `build_rag_db.py` là **process duy nhất** được phép ghi (upsert) vào ChromaDB
- `RAGRetriever` chỉ có read methods — không expose add/upsert/delete
- ChromaDB PersistentClient dùng SQLite WAL: concurrent reads an toàn, lock chỉ xảy ra khi concurrent writes
- Constraint thực tế: không chạy `build_rag_db.py` khi audit pipeline đang chạy (hai operations này không bao giờ cần chạy đồng thời)

```python
class RAGRetriever:
    def __init__(self, db_path: str, embedding_fn):
        self._client = chromadb.PersistentClient(db_path)
        self.collection = self._client.get_collection("vulnerability_patterns")
        self._cache: dict[str, list[str]] = {}
        # RAGRetriever là read-only — không expose bất kỳ write method nào

    def get_context_for_agent(
        self,
        domain_group: str,
        contract_type: str,    # "AMM" | "lending" | ... từ STEP 1.5 contract_type field
        top_k: int = 3,
    ) -> str:
        """
        Query RAG với domain-specific terms + contract_type.
        Return formatted block để inject vào R1 prompt.
        """
        cache_key = f"{domain_group}:{contract_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        query_terms = DOMAIN_QUERY_MAP.get(domain_group, "")
        query = f"{query_terms} in {contract_type} smart contract"

        # Tier 1: query với where filter (protocol_type khớp)
        results = self.collection.query(
            query_texts=[query],
            n_results=top_k,
            where={"protocol_type": contract_type},
            include=["documents", "metadatas"],
        )

        # Tier 2: fallback nếu Tier 1 trả về rỗng
        if not results["documents"] or len(results["documents"][0]) == 0:
            results = self.collection.query(
                query_texts=[query],
                n_results=top_k,
                include=["documents", "metadatas"],
            )

        # Format output — không cần truncate vì content đã là LLM summary (~500 chars)
        excerpts = []
        for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
            excerpts.append(
                f"[{meta['source'].upper()} — {meta['protocol_name']}]\n"
                f"Vuln class: {meta['vuln_class']} | Type: {meta['protocol_type']}\n"
                f"{doc}\n"
            )

        block = (
            f"\n=== RELEVANT HISTORICAL PATTERNS (for {domain_group}) ===\n"
            + "\n---\n".join(excerpts)
            + "\n"
        )
        self._cache[cache_key] = block
        return block
```

**Caching:** Các agents cùng domain_group + contract_type dùng chung 1 query result → giảm ChromaDB calls.

**Where filter edge case:** Nếu `contract_type` không match bất kỳ document nào → fallback query không có where filter.

---

## Tích hợp vào Pipeline

### Thứ tự Prompt trong `build_round1_prompt()`

Khi có cả RAG và self-generated invariants, thứ tự các block trong prompt phải tạo một flow logic hoàn chỉnh:

```
1. [CONTRACT SOURCE CODE]         ← agent đọc code trước
2. [PERSONA DIRECTIVE]            ← xác định góc nhìn chuyên môn
3. [RELEVANT HISTORICAL PATTERNS] ← RAG: "các protocol tương tự đã bị tấn công thế này"
4. [PROTOCOL INVARIANT ANALYSIS]  ← agent tự list invariants (đã có RAG context làm nền)
5. [VULNERABILITY SEARCH]         ← dùng cả RAG + invariants để tìm violations
```

RAG đứng **trước** invariant listing — agent generate invariants với "tiền lệ" trong đầu,
thay vì generate trong chân không rồi mới thấy RAG context. Tránh được việc agent lười
chỉ copy-paste patterns từ RAG mà không tự suy luận.

### Điểm chèn: `run_contract_audit.py` — Round 1 loop

```python
# Khởi tạo 1 lần trước R1 loop
rag = RAGRetriever(db_path="data/rag_db", embedding_fn=...) if RAG_ENABLED else None

# Trong R1 loop, khi build prompt cho mỗi agent:
rag_block = ""
if rag:
    rag_block = rag.get_context_for_agent(
        domain_group=agent_profile.domain_group,
        contract_type=manifest.get("contract_type", ""),
    )

prompt = build_round1_prompt(
    agent_profile=agent_profile,
    context_summary=context_summary,
    dep_graph_text=dep_graph_text,
    intent_summary=intent_summary,
    rag_block=rag_block,   # inject riêng để build_round1_prompt đặt đúng vị trí
)
```

**Vị trí inject trong `build_round1_prompt()`:**
RAG block nằm sau `=== CONTRACT UNDER REVIEW ===` và trước `=== INSTRUCTIONS ===`
(nơi có PROTOCOL INVARIANT ANALYSIS block).

**Tắt RAG:** Env var `RAG_ENABLED=false` (default false cho đến khi verify).

**contract_type:** STEP 1.5 (ContractInvariantExtractor) đã infer contract_type — dùng lại.

---

## Thứ tự triển khai

### Phase RAG-1 — Build Data Pipeline (không ảnh hưởng runtime)

1. Cài dependency: `uv add chromadb sentence-transformers`
2. Implement `extractors/defi_hack_labs.py`:
   - Parser cho @KeyInfo comments
   - Interface → protocol_type mapping
   - Infer attack_pattern từ imports + test function structure
   - Unit test: chạy trên 10 files → expect 10 documents với đúng metadata
3. Implement `build_rag_db.py`:
   - ChromaDB setup + upsert
   - CLI: `python scripts/rag/build_rag_db.py --reset`
   - Verify: `python -c "import chromadb; c=chromadb.PersistentClient('data/rag_db'); print(c.get_collection('vulnerability_patterns').count())"`

**Target sau Phase RAG-1:**
- ~689 documents từ DeFiHackLabs on-chain exploits

### Phase RAG-2 — Query Layer + Integration

5. Implement `rag_retriever.py` với DOMAIN_QUERY_MAP
6. Add `RAG_ENABLED` env var check trong `run_contract_audit.py`
7. Tích hợp vào R1 loop (inject rag_block vào prompt)
8. Smoke test: log rag_block của 1 agent → verify relevant content

### Phase RAG-3 — Evaluation

9. Chạy contest 42 với `RAG_ENABLED=true`
10. So sánh:
    - TP: có tăng không (target: H-01/H-02/H-05/H-07 với pattern từ lending write-ups)
    - FP: không tăng đáng kể (RAG không nên tạo thêm false positives)
    - Diversity check: Jaccard similarity giữa findings của agents khác domain
      - Nếu > 0.5 → RAG đang override personas → giảm top_k hoặc tăng where filter

---

## Rủi ro và mitigation

**Rủi ro 1 — LLM summarization cost khi build DB:**
689 files × ~2000 tokens input + ~150 tokens output ≈ 1.5M tokens tổng.
gemini-2.5-flash-preview qua Vertex AI — reuse LLMClient hiện tại, không cần API key mới.
Chi phí tùy theo Vertex AI quota, ước tính tương đương ~$1-2 cho 689 files.
Build 1 lần duy nhất, kết quả persist trong ChromaDB mãi mãi → chấp nhận được.
Embedding: sentence-transformers local (zero-cost, không tốn Vertex AI quota).

**Rủi ro 2 — Protocol type mismatch (where filter quá strict): ĐÃ GIẢI QUYẾT**
Two-tier fallback đã implement trong `rag_retriever.py`:
Tier 1 query với `where={"protocol_type": contract_type}`,
Tier 2 fallback không có where filter nếu Tier 1 trả rỗng.

**Rủi ro 3 — Data leakage khi thêm Solodit (Phase 2):**
Solodit cũng chứa Code4rena findings — nếu vô tình include các contests trong eval set → leakage.
Mitigation: Khi build Solodit source, blacklist contest IDs đang dùng để benchmark (35, 42, 104, ...).
DeFiHackLabs (Phase 1) không có vấn đề này vì là on-chain exploits, không phải audit contest findings.

**Rủi ro 4 — Token cost tăng (top_k=3 excerpts × 400 chars ≈ 1200 chars/agent):**
Với 22 agents: 22 × 1200 = ~26K chars thêm vào input.
Chấp nhận được — nhỏ hơn source code context (197KB cho contest 35).

---

## Verification Checklist

```bash
# 1. Build DB
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate
python scripts/rag/build_rag_db.py --reset
# Expect: "DB built: ~689 documents"

# 2. Smoke test query
python -c "
from app.services.rag_retriever import RAGRetriever
r = RAGRetriever('data/rag_db', ...)
print(r.get_context_for_agent('defi_math', 'AMM'))
"
# Expect: 3 relevant AMM arithmetic vulnerability excerpts

# 3. Run contest 42 với RAG
RAG_ENABLED=true LOG=/tmp/web3bugs_42_rag_$(date +%Y%m%d_%H%M%S).log
# ... (xem CLAUDE.md cho full command)

# 4. Evaluate
python scripts/evaluate/web3bugs_eval.py scripts/evaluate/gt/gt_42.json $DEDUP --verbose
# Target: TP >= 7 (từ 5), FP không tăng quá 20%
```
