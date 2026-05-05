# Evidence Types & Dedup Strategy

## 1. Evidence Types

Mỗi finding bắt buộc phải khai báo loại evidence theo một trong 5 types dưới đây.
Agent chọn type phù hợp nhất với bản chất bug.

---

### Type 1: CODE_LINE

Bug nằm ở **một đoạn code đang tồn tại** trong source — code sai, toán tử sai, biến sai, cast sai.

```
CODE: <snippet trích nguyên văn từ source, tối đa 120 ký tự>
```

**Ví dụ thực tế (contest 35):**
```
CODE: reserve0 -= uint128(amount0fees);
CODE: position.liquidity -= int128(amount);
CODE: if (priceLower < currentPrice && currentPrice < priceUpper)
CODE: incentives[pool][positionId]
CODE: ticks[nearestTick].feeGrowthOutside0 = feeGrowthGlobal0;
```

**Bugs cover:** H-01, H-02, H-03, H-05, H-08, H-10, H-11, H-13, H-17

**FP check tự động:** Tìm `snippet` trong flattened source → nếu không tồn tại → drop finding.

**Dedup key:** `(contract, function, normalize(snippet))`

---

### Type 2: MISSING

Bug là **sự vắng mặt** của một đoạn code cần có — missing check, missing state update, missing unchecked block.

```
MISSING: <mô tả code cần có>
AT: <Contract.function()>
```

**Ví dụ thực tế:**
```
MISSING: require(initialPrice >= MIN_SQRT_RATIO && initialPrice <= MAX_SQRT_RATIO)
AT: ConcentratedLiquidityPool.initialize()

MISSING: rewardsUnclaimed -= claimed_amount
AT: ConcentratedLiquidityPoolManager.reclaimIncentive()

MISSING: unchecked { } around feeGrowthGlobal0 - feeGrowthBelow - feeGrowthAbove
AT: ConcentratedLiquidityPool.rangeFeeGrowth()
```

**Bugs cover:** H-03 (missing state update), H-14 (missing unchecked), H-15 (missing validation)

**FP check tự động:** Tìm pattern tương tự trong source → nếu tồn tại → nghi ngờ FP.
*(Partial — heuristic, không 100% reliable)*

**Dedup key:** `(contract, function, normalize(MISSING_text))`

---

### Type 3: SEQUENCE

Bug nằm ở **thứ tự thực thi** giữa hai operations — từng operation riêng lẻ đúng, nhưng kết hợp tạo ra lỗi. Thường xảy ra cross-function hoặc cross-transaction.

```
SEQ: <Contract_A.fn_a()> modifies <state_var>
THEN: <Contract_B.fn_b()> reads <state_var> incorrectly
ISSUE: <mô tả tại sao thứ tự này sai>
```

**Ví dụ thực tế:**
```
SEQ: ConcentratedLiquidityPool.mint() changes liquidity
THEN: secondsPerLiquidity += diff / liquidity  (dùng liquidity mới, phải dùng liquidity cũ)
ISSUE: secondsPerLiquidity phải được update trước khi thay đổi liquidity

SEQ: ConcentratedLiquidityPosition.collect() reads và mark fees as collected (local)
THEN: ConcentratedLiquidityPool.burn() thu phí lần 2 từ pool
ISSUE: double-collect cùng fees
```

**Bugs cover:** H-06 (double yield), H-12 (secondsPerLiquidity ordering)

**FP check tự động:** Không khả thi — cần trace cross-function data flow.

**Dedup key:** `(contract, function, normalize(SEQ_text + THEN_text))`

---

### Type 4: INVARIANT

Bug là **vi phạm bất biến toán học hoặc kế toán** — không có dòng code nào sai cụ thể, mà toàn bộ một tính toán cho kết quả không thỏa bất biến của protocol.

```
INV: <invariant statement — điều phải luôn đúng>
VIOLATED_AT: <Contract.function()>
COUNTEREXAMPLE: <điều kiện cụ thể khiến invariant bị phá vỡ>
```

**Ví dụ thực tế:**
```
INV: after burn(), reserve0 == token0.balanceOf(pool)
VIOLATED_AT: ConcentratedLiquidityPool.burn()
COUNTEREXAMPLE: amount0 transferred out but only amount0fees subtracted from reserve0

INV: feeGrowthInside = feeGrowthGlobal - feeGrowthBelow - feeGrowthAbove >= 0 (Solidity 0.8 assumption)
VIOLATED_AT: ConcentratedLiquidityPool.rangeFeeGrowth()
COUNTEREXAMPLE: Uniswap V3 tick crossing allows feeGrowthBelow + feeGrowthAbove > feeGrowthGlobal
```

**Bugs cover:** H-09, H-10 (accounting invariant), H-17 (fee initialization invariant)

**FP check tự động:** Không khả thi — cần symbolic reasoning hoặc LLM judge.

**Dedup key:** `(contract, function, normalize(INV_text))`

---

### Type 5: DESIGN

Bug là **cơ chế kinh tế/incentive không an toàn** — không có dòng code nào sai, nhưng thiết kế tạo ra kịch bản có thể bị khai thác lợi nhuận.

```
DESIGN: <mô tả cơ chế bị khai thác>
EXPLOIT: <kịch bản tấn công step-by-step>
NO_MITIGATION: <mitigations đang thiếu>
AT: <Contract.function()>
```

**Ví dụ thực tế:**
```
DESIGN: claimReward() phân phối reward tỷ lệ secondsPerLiquidity, không có lockup
EXPLOIT: Mint tight-range position tại current price → claim reward → burn → repeat
NO_MITIGATION: không có minimum hold time, không có anti-JIT check
AT: ConcentratedLiquidityPoolManager.claimReward()
```

**Bugs cover:** H-16 (JIT liquidity attack)

**FP check tự động:** Không khả thi.

**Dedup key:** `(contract, function, normalize(DESIGN_text[:80]))`

---

## 2. Summary Matrix

| Type | Tần suất | Dedup reliable? | FP auto-check? | Key dùng để dedup |
|------|----------|----------------|----------------|-------------------|
| CODE_LINE | ~55% | Rất cao | Có (exact match) | normalize(snippet) |
| MISSING | ~20% | Cao | Partial | normalize(what + AT) |
| SEQUENCE | ~10% | Trung bình | Không | normalize(SEQ + THEN) |
| INVARIANT | ~10% | Trung bình | Không | normalize(INV text) |
| DESIGN | ~5% | Thấp | Không | normalize(DESIGN[:80]) |

---

## 3. Dedup Strategy

### 3.1 Tổng quan: 2 lần dedup

Dedup xảy ra ở **2 thời điểm** trong pipeline, mỗi lần phục vụ mục đích khác nhau:

```
R1 findings (~150)
    │
    ▼
[Pre-R2 Dedup] ← Layer 1: CODE_LINE exact match + CODE_LINE FP check
    │               Mục tiêu: shrink R2 input, giảm prompt size
    │               Rank signal: evidence quality + severity
    ▼
R2 voting (~60-70 candidates)
    │
    ▼
[Pre-R3 Dedup] ← Layer 2: NL evidence embedding similarity
    │            ← Layer 3: per-function cap (dùng R2_score để rank)
    │            ← Layer 4: global cap
    │               Mục tiêu: loại remaining dups trước attacker validation
    │               Rank signal: R2_score
    ▼
R3 attacker validation (~30-40 canonical findings)
```

**Lý do 2 lần:**
- Pre-R2: xử lý CODE_LINE exact dups — không cần R2_score vì dups hiển nhiên
- Pre-R3: xử lý NL dups và per-function overflow — cần R2_score để biết giữ cái nào tốt nhất

---

### 3.2 Normalization

Áp dụng cho tất cả types trước khi tính key hoặc embed:

```python
import re

def normalize_evidence(text: str) -> str:
    text = re.sub(r'//.*', '', text)          # bỏ comments
    text = re.sub(r'/\*.*?\*/', '', text)     # bỏ block comments
    text = re.sub(r'\s+', ' ', text).strip()  # collapse whitespace
    text = text.rstrip(';').strip()           # bỏ trailing semicolon
    return text[:100].lower()                 # lowercase, giới hạn độ dài
```

---

### 3.3 Pre-R2 Dedup (sau R1, trước R2)

Chỉ xử lý **CODE_LINE** — loại duy nhất có thể dedup chính xác bằng text matching.

**Bước A — FP check (drop hallucinated findings):**

```python
def verify_code_evidence(snippet: str, source_code: str) -> bool:
    norm_snippet = normalize_evidence(snippet)
    norm_source  = normalize_evidence(source_code)
    return norm_snippet in norm_source
```

CODE_LINE findings mà snippet không tìm thấy trong source → drop ngay.
*(MISSING/SEQUENCE/INVARIANT/DESIGN: không apply — những types này không cần snippet có trong source)*

**Bước B — Exact match dedup:**

```python
def build_exact_key(finding: dict) -> str:
    ev = finding.get("evidence", "")
    contract = finding.get("contract_name", "").strip()
    function = finding.get("function_name", "").strip()
    return f"{contract}::{function}::{normalize_evidence(ev)}"
```

Cùng key → giữ 1 representative, rank theo:
1. Evidence length (dài hơn = chi tiết hơn)
2. Severity (critical > high > medium)
3. Description length

**Kết quả dự kiến (contest 35):**
```
~150 R1 findings
→ Drop ~10 CODE_LINE FP (snippet không tồn tại trong source)
→ Merge ~60 CODE_LINE exact dups (H-10 ×5, H-02 ×8, H-09 ×4, ...)
→ ~65-75 candidates vào R2
```

---

### 3.4 Pre-R3 Dedup (sau R2, trước R3)

Xử lý **NL evidence types** (MISSING, SEQUENCE, INVARIANT, DESIGN) và overflow per-function.

#### Layer 2 — Embedding similarity cho NL evidence

Dùng embedding model local (all-MiniLM-L6-v2, 80MB, đã có trong RAG stack) để tính cosine similarity giữa evidence texts. **Không thêm LLM call nào.**

```python
from sentence_transformers import SentenceTransformer
import numpy as np

_embed_model = SentenceTransformer("all-MiniLM-L6-v2")

def embed_evidence(text: str) -> np.ndarray:
    return _embed_model.encode(normalize_evidence(text), normalize_embeddings=True)

def cosine_sim(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b))  # đã normalize → dot product = cosine
```

**Threshold:**
```
similarity > 0.92  → merge tự động (very confident — cùng phrasing, khác wording nhỏ)
0.80 – 0.92       → giữ cả hai (conservative — có thể là bug khác nhau)
< 0.80            → giữ cả hai (clearly different)
```

**Lý do không dùng LLM agent để dedup NL:**
- LLM pairwise: O(n²) calls → ~11,000 calls cho 150 findings, phủ nhận mục tiêu giảm cost
- LLM cluster: ~150 calls thêm, inconsistent, risk over-merge (không có cơ chế conservative)
- Embedding: < 1 giây cho toàn bộ 150 findings, threshold tunable, zero LLM cost

**Ví dụ:**
```
"MISSING: require(initialPrice >= MIN_SQRT_RATIO)"
"MISSING: no validation of sqrtPrice range in initialize()"
→ cosine ~0.87 → giữ cả hai (conservative)

"MISSING: require(initialPrice >= MIN_SQRT_RATIO)"
"MISSING: require(initialPrice >= MIN_SQRT_RATIO && <= MAX_SQRT_RATIO)"
→ cosine ~0.95 → merge, giữ cái có R2_score cao hơn
```

#### Layer 3 — Per-function cap

```
Cùng (contract, function) mà count > MAX_PER_FUNCTION (default=3):
→ sort by R2_score desc, giữ top 3
→ Log danh sách bị drop
```

#### Layer 4 — Global cap

```
Tổng findings sau Layer 2+3 > R3_MAX_FINDINGS (default=40):
→ sort by R2_score desc, lấy top 40
```

---

### 3.5 Ví dụ end-to-end (contest 35)

```
R1: ~150 findings

── Pre-R2 Dedup ──────────────────────────────────────
Layer 1A (CODE_LINE FP check):   150 → ~140  (-10 hallucinated snippets)
Layer 1B (CODE_LINE exact dedup): 140 → ~70   (-70 exact dups: H-10×5, H-02×8, ...)

R2: ~70 candidates (prompt nhỏ hơn ~50% so với hiện tại)

── Pre-R3 Dedup ──────────────────────────────────────
Giả sử R2 accept 55/70 (threshold=0.35, tỉ lệ tương tự)

Layer 2 (embedding similarity ≥ 0.92): 55 → ~45  (-10 NL near-dups)
Layer 3 (per-function cap=3):          45 → ~35   (-10 overflow per function)
Layer 4 (global cap=40):               35 → 35    (dưới cap, không cắt thêm)

R3: ~35 canonical findings
    35 × 5 attackers = 175 calls (~15-25 phút thay vì 6+ giờ)
```

---

## 4. Implementation Notes

### Evidence là bắt buộc

Parser drop finding nếu:
- EVIDENCE field trống hoặc quá ngắn (< 10 ký tự)
- TYPE không thuộc 5 types trên
- CODE_LINE mà snippet không tìm thấy trong source (FP check)

### Agent prompt addition

Thêm vào R1 prompt:

```
EVIDENCE field — MANDATORY. Choose ONE format:
  CODE: <exact snippet from source, max 120 chars>
  MISSING: <what should exist> AT: <Contract.function()>
  SEQ: <fn_a> → <fn_b> via <state_var> | ISSUE: <why wrong>
  INV: <invariant> | VIOLATED_AT: <fn> | COUNTEREXAMPLE: <condition>
  DESIGN: <mechanism> | EXPLOIT: <scenario> | NO_MITIGATION: <what's missing>

Findings without a valid EVIDENCE field will be dropped automatically.
```

### Config params (env vars)

| Var | Default | Mô tả |
|-----|---------|-------|
| `DEDUP_EMBED_THRESHOLD` | `0.92` | Cosine similarity threshold để merge NL evidence |
| `R3_MAX_PER_FUNCTION` | `3` | Max findings per (contract, function) sau Layer 3 |
| `R3_MAX_FINDINGS` | `40` | Hard cap trước R3 |
| `R3_EVIDENCE_REQUIRED` | `true` | Drop findings thiếu evidence |
| `R3_CODE_FP_CHECK` | `true` | Verify CODE_LINE snippet tồn tại trong source |

### Dependency

Embedding dedup dùng `sentence-transformers` (đã có trong RAG stack):
```
all-MiniLM-L6-v2 — 80MB, local, no API cost
Inference time: ~50ms cho 150 findings trên CPU
```
