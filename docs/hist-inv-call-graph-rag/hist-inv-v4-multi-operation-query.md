# HIST-INV v4 — Multi-Operation Query + Title Injection

## Bối cảnh: Tại sao v3 không đủ

### Vấn đề 1: Single-operation coverage

v3 dùng prompt *"describe MOST SPECIFIC and DISTINCTIVE computation"* → LLM chọn **1 operation** mà nó thấy nổi bật nhất → chỉ query RAG 1 lần → miss tất cả operations khác trong cùng function.

Ví dụ `burn()` trong ConcentratedLiquidityPool:
```
Operation A: uint128 amount → -int128() cast   → H-01 ✅ (được query)
Operation B: reserve không decremented          → H-10, H-13 ❌ (bị miss ở HIST level)
Operation C: unchecked fee subtraction          → potential bugs ❌ (bị miss)
```

H-10, H-13 vẫn được detect vì agent tự tìm — nhưng đây là **variance**, không phải thiết kế. Ta có data chứa vulns trong RAG mà không exploit hết được.

### Vấn đề 2: Noise từ wrong-protocol findings

run-60 inject **349 HIST annotations** (so với 117 của run-59) vì toàn bộ inv_texts của tất cả passed candidates được inject. Kết quả:

- `_computeLiquidityFromAdjustedBalances` (HybridPool, Newton's method) nhận inv về *"Liquidation validation logic"* (score 0.740) — từ lending protocol hoàn toàn khác
- Agent đọc CALL GRAPH thấy "liquidation" → sinh 10 FP về HybridPool (**0 GT bugs**)
- FP tăng từ 54 (run-59) → 71 (run-60)

Root cause: query quá generic → embedding match cross-protocol → wrong findings pass threshold.

### Tại sao threshold không giải quyết được

Score của đúng và sai findings đều nằm trong range 0.65–0.73:

| Function (GT) | Scores passed |
|---------------|--------------|
| mint (H-04/08/12) | 0.719, 0.707, 0.708 — tất cả < 0.72 |
| subscribe (H-02) | 0.691, 0.683 — tất cả < 0.72 |
| rangeFeeGrowth (H-09/14) | 0.730, 0.706, 0.695 |
| wrong-protocol (HybridPool) | **0.740** — cao hơn GT scores |

Threshold 0.72 giữ lại 11% candidates → cắt hầu hết GT findings. Score không phải discriminator tốt.

---

## Giải pháp v4

### Thay đổi 1: 1 LLM call → N queries (multi-operation)

Thay vì mô tả 1 operation, LLM output thẳng 2–3 RAG queries, mỗi query nhắm vào 1 operation khác nhau trong function:

**Prompt v4:**
```python
prompt = (
    "You are a Solidity code analyst.\n\n"
    f"Function: {fn_name}()\n"
    f"Body:\n{fn_body.strip()}\n\n"
    "Generate search queries to find historical vulnerability findings "
    "related to this function.\n"
    "Each query must target a DIFFERENT operation or pattern in this function.\n"
    "List ALL distinct operations — do not merge or skip any.\n"
    "Focus on: type casts, arithmetic operations, state updates, unchecked blocks.\n"
    "Be specific about data types (uint128, int128, uint256) and operations.\n"
    "Do NOT describe business purpose. Do NOT add 'vulnerability' keyword.\n\n"
    "Format: one query per line, max 15 words each.\n"
    "Output ONLY the queries, nothing else."
)
```

**Ví dụ output cho burn():**
```
uint128 amount cast to negative int128 for signed liquidity delta
reserve0 reserve1 not decremented after removing liquidity position
unchecked subtraction of uint128 fee amounts from uint128 reserves
```

→ N queries (N = số operations LLM detect) → N RAG lookups tuần tự → coverage đầy đủ với **cùng số LLM calls**.

**Tại sao không cap số queries:**
- Cap cứng tái tạo vấn đề: function 5 operations → miss 2 operations
- LLM tự quyết định dựa trên nội dung function — simple function ra 1-2, complex ra 4-5

**Concurrency model: 2 workers = 2 Vertex AI keys**

HIST-INV chạy với `ThreadPoolExecutor(max_workers=2)`, tương tự R1 agents. Mỗi worker dùng 1 Vertex AI key riêng. Đây là giới hạn cứng từ quota API, không phải tuỳ chọn:

```
Worker 1 (key A): function_1 → enumerate → query_1a → query_1b → query_1c
Worker 2 (key B): function_2 → enumerate → query_2a → query_2b
                  (chạy song song với Worker 1)
```

Trong mỗi worker, N RAG queries của 1 function chạy **tuần tự** (không parallel thêm). Với N=3–4 queries/fn và RAG ~2s/query:

- v3 (1 worker): 164 entries × 18s = ~49 phút
- v4 (2 workers): 82 pairs × (6s enumerate + 4×2s RAG) = **~19 phút**

**Không cap output — inject tất cả unique titles từ per-query top-1:**
- Mỗi query đóng góp tối đa 1 title (dedup by title)
- Avg ~5 annotations/fn trong thực tế (50% queries pass threshold)
- Titles ngắn (3–5 chữ) không overwhelm agent như v3 invariant sentences

### Thay đổi 2: Bỏ extraction LLM — dùng title + content snippet

Hiện tại mỗi candidate passed → 1 LLM call để extract invariant từ full finding text:
```
Finding: "[H-06] get_fee_growth_inside should allow underflow/overflow..."
→ LLM extract → "Fee growth calculations must permit unchecked arithmetic..."
```

v4: dùng **title + 80 chars đầu của description** từ content đã có sẵn trong RAG result — không cần LLM call.

```
↳ HIST: [Unsafe type-casting] — various uint128/int128 casts without bounds check   ← v4
↳ HIST: Numerical type conversions must include validation...                        ← v3 extracted
```

**Đã test 3 cách annotation (V4-A/B/C) — kết quả trong section "Test V4-B vs V4-C" bên dưới.**

Kết luận: dùng **V4-C: title + impact field**.

```python
# V4-C: 0 LLM calls — dùng title + impact từ RAG result
def _make_hist_annotation(rag_result: dict) -> str:
    title  = rag_result['title']
    impact = rag_result.get('impact', '').strip().upper()
    ann = f"[{title}]"
    if impact in ('HIGH', 'MEDIUM', 'CRITICAL'):
        ann += f" [{impact}]"
    return ann
# → "↳ HIST: [Unsafe type-casting] [HIGH]"
# → "↳ HIST: [[H-06] get_fee_growth_inside should allow underflow/overflow] [HIGH]"
```

**Tác động**: Bỏ N×LLM calls per entry (N = số candidates passed, avg 2.72):
- v3: 472 LLM calls tổng (97 describe + 29 query_llm + **346 extract**)
- v4: 165 LLM calls tổng (165 enumerate, 0 extract)
- **KG Build time: ~56 phút → ~24 phút** (với 2 workers)

### Thay đổi 3: Nâng threshold truncation từ 1000c → 5000c

`_extract_fn_body()` hiện tại truncate bất kỳ body nào > 1000c thành first 300 + last 700. Với v4 enumerate-ALL-operations, đây là vấn đề nghiêm trọng.

**Ví dụ cụ thể — mint() (3268c):**

| Region | Chars | Nội dung | Status |
|--------|-------|----------|--------|
| First 300 | 0–300 | parameter decoding, getSqrtRatioAtTick | ✅ giữ |
| DROPPED | 300–2568 | getLiquidityForAmounts, **secondsPerLiquidity update** (char 1529), _updatePosition | ❌ bỏ |
| Last 700 | 2568–3268 | balance checks, reserve updates, emit Mint | ✅ giữ |

`secondsPerLiquidity` (H-12) nằm hoàn toàn trong vùng bị drop → LLM không thấy operation này → không sinh query → H-12 miss hoàn toàn ở HIST level.

**Fix**: nâng threshold lên 5000c:
```python
if len(body) <= 5000:
    return body
# Chỉ truncate khi body cực dài (>5000c) — rất hiếm trong Solidity thực tế
return body[:400] + "\n...\n" + body[-800:]
```

**Tần suất bị ảnh hưởng**: ~1–2% functions về số lượng, nhưng các hàm bị truncate thường là hàm "core" (mint, burn, swap) — chứa nhiều bugs nhất → impact không cân xứng với tỷ lệ.

**Chi phí**: Input tokens rẻ — full mint() body 3268c ≈ 820 input tokens, không đáng kể so với max_tokens=6144 output budget. Bottleneck là output tokens, không phải input.

### Wrong-protocol noise vẫn còn — nhưng không amplify

Test V4-C trên burn() cho thấy top RAG hit vẫn là wrong-protocol (UniswapV4Wrapper, score 0.682). v4 queries cụ thể hơn v3 nhưng không loại bỏ hoàn toàn cross-protocol matching.

Tuy nhiên với cơ chế **per-query top-1 + V4-C title injection**:
- Wrong-protocol findings vào list titles nhưng không được extract thành invariant (không amplify)
- Agent nhìn thấy `[Fees can be stolen from UniswapV4Wrapper]` trong list → agent đủ thông minh để nhận ra đây không phải context của mình
- Cùng lúc đó `[Unsafe type-casting] [HIGH]` cũng có mặt trong list → đúng signal vẫn đến được agent

Nếu sau benchmark vẫn thấy FP tăng từ wrong-protocol titles → xem xét thêm `protocol` field filter (loại bỏ findings từ protocols không liên quan). Không over-engineer trước khi có data.

---

## Pipeline v4 so với v3

```
v3 (1 worker, sequential):
  fn_body
    → [LLM: describe 1 operation]             ← 1 LLM call / ~6s
    → 1 RAG query                             ← ~2s
    → candidates (N passed)
    → [LLM: extract invariant × N]            ← N × 6s
    → inject all inv_texts
  Total/entry: ~18–30s  |  164 entries: ~49 phút

v4 (2 workers, 2 Vertex keys):
  Worker 1 (key A) và Worker 2 (key B) chạy song song, mỗi worker xử lý 1 function:
    fn_body
      → [LLM: enumerate ALL operations]       ← 1 LLM call / ~6s
      → N RAG queries (tuần tự, N = số ops)   ← N × 2s
      → dedup + threshold filter
      → inject top-6 RAG titles               ← 0 LLM calls
  Total/entry: ~6 + N×2s  |  82 pairs × 14s: ~19 phút
```

---

## Kết quả test thực tế (contest 35, 2 workers)

### max_tokens cần thiết cho enumerate prompt

Thinking model (gemini-3-flash-preview) cần token budget lớn hơn nhiều khi enumerate nhiều operations:

| max_tokens | burn() (1005c) | mint() (3369c full / 1005c trunc) | rangeFeeGrowth() |
|-----------|---------------|----------------------------------|-----------------|
| 256 | EMPTY | EMPTY | EMPTY |
| 1024 | EMPTY | EMPTY | EMPTY |
| 4096 | 9 queries ✅ | **EMPTY** ❌ | 10 queries ✅ |
| **6144** | 9 queries ✅ | **14 queries ✅** | 10 queries ✅ |

**Root cause mint() EMPTY với max_tokens=4096**: mint() là function phức tạp nhất (3268c full body). Thinking model dùng hết token budget (~4096) cho reasoning, không còn output tokens. Với max_tokens=6144, thinking vẫn có đủ budget và output được 18 queries.

→ **Cần dùng max_tokens=6144** cho enumerate prompt.

### Về thinking mode

Giữ **thinking ON**. Kết quả test cho thấy thinking model tạo queries rất cụ thể:

```
burn() → 9 queries:
  - cast uint128 to int128 negation _updatePosition
  - unchecked subtraction uint128 downcast reserve0 amount0fees
  - Ticks.remove ticks lower upper amount nearestTick
  ...

rangeFeeGrowth() → 10 queries:
  - uint256 wrapping subtraction in tick fee growth logic      → RAG 0.711 [get_fee_growth_inside should allow underflow] ✅
  - uint256 subtraction of lower.feeGrowthOutside0 from _feeGrowthGlobal0
  ...
```

Non-thinking mode sẽ output generic ("burn vulnerability") thay vì operation-specific — mất đi toàn bộ giá trị của v4.

### Kết quả RAG so sánh v3 vs v4

| Function (GT) | v3 best hit | v4 best hit | Delta |
|---------------|------------|------------|-------|
| burn (H-01) | ❌ 0.652 (wrong fn body) | **0.703** "Unsafe type-casting" ✅ | +0.051 |
| _getAmountsForLiquidity (H-05) | 0.724 ✅ | 0.694 ✅ | -0.030 (still correct finding) |
| rangeFeeGrowth (H-09/14) | 0.707 ✅ | **0.711** "get_fee_growth_inside underflow" ✅ | +0.004 |

**burn() cải thiện đáng kể**: v3 lấy sai source (ConstantProductPool.burn thay vì CLP.burn) → kLast query → score thấp. v4 với contract-aware source extraction tìm đúng operation.

---

## So sánh v3 vs v4

| Metric | v3 | v4 |
|--------|----|----|
| LLM calls/entry | 3–5 | **1** |
| max_tokens cho LLM | 1024 | **6144** |
| RAG queries/fn | 1 | **N (= số operations, avg 8–10)** |
| Operation coverage | 1/fn | **tất cả distinct operations** |
| Truncation threshold | 1000c (300+700) | **5000c (full body cho hầu hết fns)** |
| Vùng bị bỏ (mint) | chars 300–2568 (70%) | **không bỏ** |
| Workers | 1 | **2 (2 Vertex AI keys)** |
| KG Build time | ~54 phút | **~25 phút** (est. với 2 workers) |
| HIST annotations/session | ~350 (verbose) | **~400–600** (short titles, ~5/fn × 128 fns) |
| Injection content | Extracted invariant (LLM) | **title + impact field (no LLM)** |
| Wrong-protocol filter | Không | **Tự nhiên giảm** |

---

## Thay đổi cần implement

### File: `contract_kg_builder.py`

**1. Đổi `_describe_function_body()` → `_generate_fn_queries()`**

Thay vì return 1 description string, return list of 2–3 query strings.

```python
def _generate_fn_queries(self, fn_name: str, fn_body: str) -> list[str]:
    """Enumerate ALL distinct operations → one RAG query per operation."""
    prompt = ...  # prompt v4 ở trên
    raw = self._call_hist_inv_llm(prompt, max_tokens=6144)  # thinking model cần 6144
    if not raw or not raw.strip():
        return [f"{fn_name} vulnerability"]  # fallback nếu EMPTY
    # Strip numbering nếu LLM output "1. query" format
    queries = []
    for line in raw.strip().split('\n'):
        line = line.strip().lstrip('0123456789.-) ').strip()
        if line:
            queries.append(line)
    return queries  # no cap — LLM decides based on function complexity
```

**2. Đổi `_extract_invariant_from_finding()` → bỏ, dùng V4-C: title + impact**

```python
# v3: gọi LLM để extract invariant (1 LLM call/doc, avg 2.72 calls/entry)
# v4: title + impact từ RAG result (0 LLM calls)
def _make_hist_annotation(rag_result: dict) -> str:
    title  = rag_result['title']
    impact = rag_result.get('impact', '').strip().upper()
    ann = f"[{title}]"
    if impact in ('HIGH', 'MEDIUM', 'CRITICAL'):
        ann += f" [{impact}]"
    return ann
# → "↳ HIST: [Unsafe type-casting] [HIGH]"
# → "↳ HIST: [[H-06] get_fee_growth_inside should allow underflow/overflow] [HIGH]"
```

**Tại sao không dùng V4-B (top-1 extract)**: test cho thấy khi top-1 RAG hit là wrong-protocol finding, V4-B extract ra invariant hoàn toàn sai và inject vào call graph như sự thật — amplification of noise. V4-C an toàn hơn vì list titles để agent tự lọc.

**Tại sao không dùng title-only (V4-A)**: `impact` field có sẵn trong RAG result, 0 extra cost, thêm severity signal cho agent ưu tiên điều tra.

**3. Update `_build_call_graph_with_hist_inv()`**

⚠️ **Logic quan trọng: per-query top-1, không phải global sort by score**

Score-based global top-6 có lỗi: nếu 1 query noisy trả về 3 findings score 0.74–0.73, chúng chiếm 3/6 slots và đẩy findings đúng (score 0.68–0.70) của các operations khác ra ngoài.

Fix: lấy **top-1 per query theo thứ tự query** (= thứ tự operations trong function body), dedup by title, **không cap số lượng output**.

```python
queries = self._generate_fn_queries(fn_name, fn_body)

# Per-query top-1 → maintain query order (= operation order) → dedup by title
# Không cap — mỗi operation được đại diện đầy đủ
seen_ann: set = set()
ordered_ann: list = []
for q in queries:
    if not q.strip():
        continue
    results = self.retriever.query(q, n_results=3)
    for d in (results or []):
        if d['score'] < 0.65:
            continue
        ann = _make_hist_annotation(d)   # "[title] [HIGH]"
        if ann not in seen_ann:
            seen_ann.add(ann)
            ordered_ann.append(ann)
        break  # top-1 unique per query — move to next query

inv_lines = ordered_ann  # full list — no cap
```

**Tại sao không cần cap**:
- Cap 6 đến từ lo ngại "agent bị overwhelm" với v3 verbose invariants (câu 25 chữ). Với v4 titles `[Unsafe type-casting] [HIGH]` chỉ 3–5 chữ — token cost thấp hơn 10×.
- Per-query top-1 tự nhiên bounded: avg 10 queries/fn, ~50% pass threshold 0.65 → avg ~5 annotations thực tế. Hiếm khi có function nào sinh ra 15+ unique annotations đều pass.
- Không sort by score: score không phải discriminator tốt (range 0.65–0.74 cho cả đúng lẫn sai). Query order = operation order trong function body = natural relevance ordering.

**4. Nâng truncation threshold `_extract_fn_body()`**

```python
# v3 (current):
if len(body) <= 1000:
    return body
return body[:300] + "\n...\n" + body[-700:]

# v4:
if len(body) <= 5000:
    return body
return body[:400] + "\n...\n" + body[-800:]
```

Không cần contract-aware extraction cho v4 — threshold 5000c đủ cover mọi hàm bình thường trong Solidity. Chỉ những hàm > 5000c mới truncate, và những hàm đó cực hiếm.

**5. Cache schema update**

Thêm field `queries: list[str]` thay cho `rag_query: str` (single).

---

## Kết quả kỳ vọng

- **Coverage**: burn() sẽ có inv cho cả cast AND reserve-not-decremented AND fee subtraction → H-01, H-10, H-13 đều có HIST support
- **Noise**: Giảm vì queries cụ thể hơn + không còn extraction step amplify wrong findings
- **Speed**: Nhanh hơn v3 (~19 phút với 2 workers thay vì 1)
- **F1**: Kỳ vọng cải thiện so với cả run-59 (F1=0.268) và run-60 (F1=0.204)

---

---

## Test V4-B vs V4-C — annotation quality (contest 35)

### Chi phí thực tế (từ hist_inv_detail.json)

| Method | LLM calls | RAG calls | Wall-clock (est.) |
|--------|-----------|-----------|-------------------|
| V3 current (1 worker) | **472** (97 describe + 29 query_llm + 346 extract) | 256 | ~56 min |
| V4-A title only (2 workers) | 165 | 768 | ~24 min |
| V4-B enumerate + top-1 extract (2 workers) | 293 | 768 | ~29 min |
| **V4-C enumerate + title+impact (2 workers)** | **165** | **768** | **~24 min** |

346 extraction calls = 73% tổng LLM calls của v3 — đây là chi phí cần loại bỏ.

### Kết quả annotation so sánh

| Function (GT) | V4-B (extracted from top-1) | V4-C (title+impact) | Winner |
|--------------|----------------------------|---------------------|--------|
| `burn()` H-01 | ❌ *"Partial unwrapping of fractionalized positions must distribute accrued fees..."* — wrong protocol (UniswapV4Wrapper) | ✅ list gồm `[Unsafe type-casting] [HIGH]` + `[H-06] fee growth underflow] [HIGH]` | **V4-C** |
| `mint()` H-04/08/12 | ❌ *"All internal state changes must be finalized before executing external calls..."* — reentrancy invariant, sai hoàn toàn | ❌ `[H-07] reentrancy attack during mint()]` — cũng sai | Tie (cả hai miss) |
| `_getAmountsForLiquidity()` H-05 | ❌ *"Liquidation rewards must be calculated to ensure liquidators are economically incentivized..."* — lending protocol invariant | ✅ `[Unsafe type-casting] [HIGH]` ở vị trí 2 | **V4-C** |
| `rangeFeeGrowth()` H-09/14 | ✅ *"Fee growth calculations must utilize wrapping arithmetic..."* | ✅ `[H-06] get_fee_growth_inside should allow underflow/overflow] [HIGH]` | Tie (cả hai tốt) |
| `burn()` H-10/13 | ❌ same wrong-protocol invariant như H-01 | ✅ `[Unsafe type-casting] [HIGH]` trong list | **V4-C** |

### Root cause V4-B tệ hơn V4-C

V4-B lấy top-1 RAG hit → gọi LLM extract invariant → inject 1 câu cụ thể. Khi top-1 là wrong-protocol finding (e.g., UniswapV4Wrapper), LLM extract ra invariant hoàn toàn sai và inject vào call graph như thể đó là sự thật → **amplification of noise**.

V4-C inject list titles → agent thấy cả noise lẫn signal đúng (`[Unsafe type-casting]`) và tự lọc — **graceful degradation**.

### Kết luận

**V4-C thắng**: -65% LLM calls so với v3, -2.3× wall-clock, an toàn hơn V4-B khi top RAG hit sai protocol.

## Vấn đề chưa giải quyết

| Issue | Nguyên nhân | Status |
|-------|------------|--------|
| H-15 initialize missing validation | Bug là thiếu code, không có operation để query | Ngoài scope HIST-INV |
| H-17 nearestTick logic error | Pure logic error, RAG không có finding tương tự | Ngoài scope HIST-INV |
| H-11 cross() HIST empty | `cross() → (leaf)` — không có source body | Cấu trúc tất yếu |
| H-12 secondsPerLiquidity ordering | **Ordering bug** — RAG không có finding về "update order invariants"; HIST có thể inject `[H-17] Second per liquidity inside could overflow` (0.691) nhưng đây là overflow finding, không phải ordering finding | RAG gap, ngoài scope HIST-INV |

### Tại sao threshold fix KHÔNG giải quyết H-12

Test với full body (3268c, threshold=5000c):
- LLM generate **18 queries** — nhưng không có query nào target `secondsPerLiquidity` ordering
- Lý do: LLM enumerate explicit code operations (type casts, arithmetic, external calls); **ordering/timing** giữa 2 operations là implicit invariant, không phải explicit operation → LLM không enumerate được
- Direct RAG queries về secondsPerLiquidity ordering: score 0.63–0.68 — không có finding nào trong RAG database về "update order" invariants
- HIST tốt nhất có thể làm: inject `[H-17] Second per liquidity inside could overflow uint256` (0.691, từ query về unchecked liquidity addition) → agent nhận được hint về `secondsPerLiquidity` patterns nhưng đây là overflow finding, không phải ordering

**Threshold fix vẫn có giá trị**: Các operations khác trong vùng 300–2568 chars (hiện bị drop) — như `_updatePosition`, `getLiquidityForAmounts`, balance checks — sẽ được enumerate và query RAG. H-12 là edge case vì bản chất của bug là ordering, không phải computation.
