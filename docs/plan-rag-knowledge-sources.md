# RAG Knowledge Sources — Implementation Plan

## Mục tiêu

Build vector DB chứa kiến thức bảo mật **tổng quát, chuẩn hóa, có thể kiểm nghiệm** —
không phụ thuộc vào incident cụ thể. Ưu tiên sources có:
- Format có cấu trúc rõ ràng (dễ parse → embed)
- Peer-reviewed / được cộng đồng validate
- Coverage rộng (pattern chung, không thiên về 1 protocol)

---

## Tier 1 — SWC Registry + Not So Smart Contracts

### 1a. SWC Registry (Smart Contract Weakness Classification)

**URL:** https://swcregistry.io | https://github.com/SmartContractSecurity/SWC-registry

**Nội dung:** 36 weakness classes — mỗi class có:
- ID chuẩn (SWC-101 → SWC-136)
- Title + Description (tại sao vulnerable)
- Relationships (CWE mapping)
- Code examples: `test_cases/` — vulnerable + fixed Solidity files
- Remediation

**Số lượng:** 36 entries chính + ~80 code examples

**Format đầu vào:** JSON + Markdown + `.sol` files trong GitHub repo

**Parse strategy:**
```python
# Clone repo, đọc từng entry
for swc_dir in Path("SWC-registry").glob("SWC-*"):
    meta = yaml.load(swc_dir / "README.md")   # title, description, relationships
    examples = list(swc_dir.glob("**/*.sol"))  # vulnerable/fixed code
    # Tạo 1 entry per SWC: title + description + vulnerable_pattern + remediation
```

**Vector DB entry:**
```json
{
  "id": "SWC-101",
  "source": "swc_registry",
  "title": "Integer Overflow and Underflow",
  "description": "...",
  "vulnerable_pattern": "uint128 x = type(uint128).max; int128 y = int128(x); // = -1",
  "remediation": "Use SafeCast or check bounds before casting",
  "severity": "high",
  "tags": ["arithmetic", "cast", "solidity-0.8"]
}
```

**Bugs cover được (contest 35):** H-01 (SWC-101 unsafe cast)

---

### 1b. Not So Smart Contracts — Trail of Bits

**URL:** https://github.com/crytic/not-so-smart-contracts

**Nội dung:** ~15 vulnerability categories với:
- Description + root cause analysis
- Vulnerable code (`bad.sol`) + fixed code (`good.sol` hoặc `fixed.sol`)
- Real-world references (links đến actual exploits)
- Không phụ thuộc vào incident cụ thể — mô tả pattern

**Số lượng:** ~15 categories × 2-4 examples = ~40-60 entries

**Categories quan trọng:**
```
integer_overflow/         ← H-01 (unsafe cast)
reentrancy/               ← general
wrong_constructor_name/
unprotected_ether/
access_control/
bad_randomness/
forced_ether_reception/
denial_of_service/
race_condition/
unchecked_external_call/
```

**Parse strategy:**
```python
for category_dir in Path("not-so-smart-contracts").iterdir():
    readme = (category_dir / "README.md").read_text()
    bad_sol = (category_dir / "bad.sol").read_text() if exists else ""
    # Entry = category name + description + vulnerable pattern
```

**Vector DB entry:**
```json
{
  "id": "nssc_integer_overflow",
  "source": "not_so_smart_contracts",
  "title": "Integer Overflow / Unsafe Cast",
  "description": "Solidity 0.8 introduces checked arithmetic for operators (+,-,*) but NOT for explicit type casts. int128(uint128_max) silently wraps to -1.",
  "vulnerable_pattern": "position.liquidity -= int128(amount); // overflows when amount > int128.max",
  "remediation": "Use SafeCast.toInt128() or require(amount <= uint128(type(int128).max))",
  "tags": ["arithmetic", "cast", "solidity-0.8", "silent-overflow"]
}
```

**Tại sao quan trọng:** Đây là nguồn duy nhất document rõ **explicit cast không revert trong Solidity 0.8** — knowledge cần thiết để detect H-01.

---

## Tier 2 — ConsenSys Best Practices + Solidity Docs

### 2a. ConsenSys Smart Contract Best Practices

**URL:** https://github.com/ConsenSys/smart-contract-best-practices |
https://consensys.github.io/smart-contract-best-practices/

**Nội dung:** Comprehensive guide — 2 phần chính cho RAG:
- **Known Attacks** (~15 attack patterns): reentrancy, front-running, DoS, oracle manipulation, ...
- **Solidity Recommendations** (~30 items): integer math, visibility, events, ...

**Số lượng:** ~45 entries sau parse

**Format:** Markdown với heading structure rõ ràng

**Parse strategy:**
```python
# Scrape / clone mkdocs site
# Split theo H2/H3 heading — mỗi section là 1 entry
sections = split_by_heading(content, level=2)
for section in sections:
    if section.has_code_example():
        entries.append(build_entry(section))
```

**Vector DB entry:**
```json
{
  "id": "consensys_tx_order_dependence",
  "source": "consensys_best_practices",
  "title": "Transaction Ordering Dependence (TOD) / Front Running",
  "description": "The order of transactions in a block can be exploited...",
  "attack_scenario": "Attacker observes pending tx in mempool and submits higher gas tx to execute first",
  "remediation": "Use commit-reveal scheme or submarine sends",
  "tags": ["front-running", "mempool", "ordering"]
}
```

---

### 2b. Ethereum Yellow Paper — Relevant Sections

**URL:** https://ethereum.github.io/yellowpaper/paper.pdf

**Nội dung:** Chỉ lấy các sections liên quan đến security:
- Section 9: Transaction Execution (gas, out-of-gas behavior)
- Section 11: Block Finalization
- Appendix H: Virtual Machine (opcode semantics)

**Số lượng:** ~10 entries (chỉ những phần agent có thể lẫn lộn)

**Ưu tiên thấp hơn** 2a vì ít actionable hơn cho audit context.

---

## Tier 3 — Public Audit Reports

### 3a. Trail of Bits Public Audits

**URL:** https://github.com/trailofbits/publications/tree/master/reviews

**Nội dung:** ~150 public audit reports — mỗi report có:
- Executive Summary
- Finding list: Severity + Title + Description + Impact + Recommendation
- Appendix: tool output

**Số lượng:** ~150 reports × trung bình 10 H/M findings = ~1500 findings

**Parse strategy — lấy riêng từng finding:**
```python
# PDF hoặc Markdown (ToB đang chuyển dần sang MD)
findings = extract_findings(report)  # regex: "Finding N", "Severity:", "Description:"
for f in findings:
    if f.severity in ("High", "Medium"):
        entries.append({
            "title": f.title,
            "protocol_type": detect_protocol(report.name),  # AMM, Lending, Bridge
            "description": f.description,
            "impact": f.impact,
            "recommendation": f.recommendation,
        })
```

**Vector DB entry:**
```json
{
  "id": "tob_uniswapv3_finding_3",
  "source": "trail_of_bits",
  "protocol": "uniswap_v3",
  "protocol_type": "concentrated_liquidity_amm",
  "title": "Fee growth initialized with nearestTick instead of pool tick",
  "severity": "high",
  "description": "When initializing feeGrowthOutside for a new tick, the code compares against nearestTick instead of the current pool tick. This makes the Case 1/Case 2 distinction ambiguous...",
  "impact": "Fee accounting incorrect for positions at boundary ticks",
  "recommendation": "Use pool.tick (current price tick) as reference point, not nearestTick",
  "tags": ["fee-growth", "tick", "concentrated-liquidity", "initialization"]
}
```

**Tại sao quan trọng:** Đây là nguồn duy nhất có thể give hint cho H-17 (nearestTick bug).

---

### 3b. Spearbit Public Audits

**URL:** https://github.com/spearbit/portfolio

**Nội dung:** ~50 audits, tập trung DeFi protocols (AMM, lending, bridge)
Chất lượng rất cao — detailed root cause analysis

**Số lượng:** ~50 reports × 8 H/M findings = ~400 findings

---

### 3c. ChainSecurity Public Audits

**URL:** https://chainsecurity.com/security-audits/ (public reports page)

**Nội dung:** ~40 public audits, nhiều Uniswap-compatible protocols

---

## Vector DB Schema — Unified

Mỗi entry trong vector DB có cấu trúc:

```json
{
  "id": "unique_id",
  "source": "swc_registry | not_so_smart_contracts | consensys | trail_of_bits | spearbit",
  "tier": 1,
  "title": "Concise vulnerability name",
  "protocol_type": "amm | lending | bridge | general",
  "vulnerability_class": "arithmetic | access_control | reentrancy | logic | oracle | ...",
  "swc_id": "SWC-101",
  "description": "Why this is vulnerable + root cause",
  "vulnerable_pattern": "Short code snippet showing the vulnerable pattern",
  "attack_scenario": "Step-by-step how an attacker exploits this",
  "remediation": "Concrete fix",
  "tags": ["solidity-0.8", "cast", "uint128", "amm"],
  "embedding": [...]
}
```

**Embedding field:** `title + description + vulnerable_pattern` concatenated

---

## Build Order & Effort Estimate

| Bước | Nguồn | Entries | Effort | Priority |
|------|--------|---------|--------|----------|
| 1 | SWC Registry | 36 | 2h (JSON sẵn) | Ngay |
| 2 | Not So Smart Contracts | ~50 | 3h (parse MD + sol) | Ngay |
| 3 | ConsenSys Best Practices | ~45 | 4h (parse MD) | Ngay |
| 4 | Trail of Bits audits | ~1500 | 2 ngày (PDF parse) | Sau |
| 5 | Spearbit portfolio | ~400 | 1 ngày | Sau |

Bước 1-3: **~130 entries**, build trong 1 ngày, cover pattern chung.
Bước 4-5: **~1900 entries thêm**, cover protocol-specific bugs như H-17.

---

## Query Strategy khi inject vào R1

```python
# Trước R1 call, query với 3 dimensions:

# 1. Function name + contract type
results_fn = rag.query(f"vulnerability in {fn_name} concentrated_liquidity_amm", top_k=3)

# 2. Code pattern (extract từ source)
for pattern in ["int128 cast", "strict inequality", "fee growth subtraction"]:
    results_pat = rag.query(pattern, top_k=2)

# 3. Protocol-level invariant
results_proto = rag.query(f"known attacks on {protocol_type}", top_k=3)

# Deduplicate và inject top-5 vào prompt
```

**Threshold:** chỉ inject khi similarity > 0.65 — tránh noise khi không có relevant knowledge.

---

## Tech Stack

```
Embedding model : all-MiniLM-L6-v2 (local, 80MB, no API cost)
                  hoặc text-embedding-004 (Vertex AI) cho chất lượng tốt hơn
Vector store    : ChromaDB (persist to disk, zero-config, Python native)
Index path      : backend/data/rag_security_kb/
Collection name : security_knowledge
```
