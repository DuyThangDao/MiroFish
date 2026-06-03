# HIST-INV v5: Dual-Track Structural + Operation Queries

## Bối cảnh

### Vấn đề của v4 (operation queries)

v4 generate queries bằng cách liệt kê các **mechanical operations** trong function body:

```
"getLiquidity external call return value manipulation"
"uint256 liq assignment from external function call"
"_register internal function call state update"
```

Vấn đề: RAG DB index theo ngôn ngữ của audit findings — mô tả **what goes wrong**, không phải **what code does**. Mismatch ngôn ngữ → retrieve sai hoặc retrieve bugs không liên quan.

### Root cause phân tích từ benchmark

Full test trên **29 H bugs** (contest 42: 13 bugs, contest 35: 16 bugs, 1 error):

**Tổng kết:**

| Metric | Kết quả |
|--------|---------|
| Score winner | **STRUCT thắng 24/29**, OP thắng 4/29, TIE 1 |
| Both pass (≥0.65) | 25 bugs |
| Chỉ STRUCT pass, OP fail | **+3 bugs** (35/H-04, 35/H-08, 35/H-12) |
| Chỉ OP pass, STRUCT fail | -1 bug (42/H-07 — ST trả về 0 queries) |
| Neither pass | **0** |

**Chi tiết contest 42:**

| H Bug | OP score | ST score | ST query được generate |
|-------|----------|----------|----------------------|
| H-04 registerAsset | ✅ 0.663 | ✅ 0.665 | "Missing check for existing registration allows overwriting asset state" |
| H-07 liquidate | ✅ 0.664 | ❌ 0.000 | *(ST trả về empty — function body quá phức tạp)* |
| H-08 deposit | ✅ 0.686 | ✅ 0.716 | "Overwriting lastDeposit without checking existing value" |
| H-09 veCRVlock | ✅ 0.672 | ✅ 0.717 | "Missing access control allows unauthorized users to trigger" |
| H-10 changeNFT | ✅ 0.652 | ✅ 0.659 | "Missing check for existing value allows redundant state" |
| H-13 vest | ✅ 0.721 | ✅ 0.753 | "Missing access control allows anyone to vest unmanaged" |

**Chi tiết contest 35 — ST-only gains (OP failed hoàn toàn):**

| H Bug | OP score | ST score | ST top hit |
|-------|----------|----------|------------|
| H-04 mint | ❌ 0.000 | ✅ 0.748 | "Unsafe type-casting" |
| H-08 mint | ❌ 0.000 | ✅ 0.748 | "Unsafe type-casting" |
| H-12 mint | ❌ 0.000 | ✅ 0.748 | "Unsafe type-casting" |

Ba bugs trên đều trong cùng một function `mint` của `ConcentratedLiquidityPool`. OP thất bại vì function body quá dài → LLM trả về empty. ST vẫn generate được queries ("Unsafe casting of liquidity to int128 causes incorrect position updates") → retrieve được relevant findings.

**Pattern rõ ràng:**
- Operation queries: fail khi function body dài (LLM empty), produce noise cao (H-07: 18 passed hits)
- Structural queries: tốt hơn cho absence bugs và edge cases, precision cao, fail ở 1/29 case (H-07)
- **Dual-track bắt buộc** vì H-07 chỉ OP mới cover được

### Tại sao structural queries hoạt động tốt hơn

Operation queries mô tả **mechanics**:
```
"uint256 subtraction mapping state update"
```

Structural queries mô tả **vulnerability pattern** — cùng ngôn ngữ với audit DB:
```
"zero amount deposit resets lastDeposit timer griefing"
"swap without minimum output vulnerable to sandwich attack"
```

RAG DB chứa audit finding titles như:
- "H-2: Users can deposit 0 ether to any round"
- "feePool is vulnerable to sandwich attack"

→ Structural queries match trực tiếp.

### Tại sao giữ cả hai track

**Không thể dùng structural alone:**
- Structural là bug hypothesis queries → circular dependency: nếu LLM đã biết bug, cần gì RAG?
- Với code phức tạp hoặc subtle bugs, LLM không tự nhận ra → structural queries sai → RAG retrieve sai

**Operation queries vẫn có value:**
- Khi LLM không nhận ra bug nhưng code có pattern tương tự historical bugs → operation queries bridge được gap
- Ví dụ: `uint256 to int256 cast` → RAG tìm được unsafe cast findings từ contests khác
- Không circular vì LLM chỉ describe mechanics, RAG provide historical validation

**Combine = coverage rộng + precision cao:**
```
Operation  → tốt cho code-visible bugs (arithmetic pattern, reentrancy order)
Structural → tốt cho absence/edge-case bugs (missing check, zero-value griefing)
Merge + dedup → không tăng FP vì RAG score threshold vẫn là gate
```

---

## Thiết kế v5

### Dual-track architecture

```
fn_body
  ├── Track 1: Operation queries (v4c, giữ nguyên)
  │     "enumerate ALL distinct operations — arithmetic, casts, state updates"
  │     → LLM generate 10-15 operation queries
  │
  └── Track 2: Structural queries (mới)
        "check structural vulnerability properties — what goes WRONG"
        → LLM generate 3-8 vulnerability pattern queries

  → Merge queries (dedup exact string)
  → RAG: top-1 per query, score threshold 0.65
  → Dedup annotations by exact text
  → Inject vào call graph — cùng format ↳ HIST: [title] [IMPACT]
```

**Annotation format không thay đổi** — cả hai tracks dùng chung prefix `↳ HIST:`:

```
  deposit() [EXTERNAL: cheapTransferFrom]
    ↳ HIST: [Increase in token amount due to arithmetic overflow] [HIGH]   ← từ OP
    ↳ HIST: [H-2: Users can deposit 0 ether to any round] [HIGH]           ← từ ST
```

Agent không biết nguồn gốc của mỗi hint — tự judge cái nào relevant với code đang xét. RAG score threshold (0.65) là gate duy nhất kiểm soát chất lượng. Nếu benchmark cho thấy FP tăng bất thường do noise từ hai tracks, sẽ xem xét tách prefix `↳ HIST-OP:` / `↳ HIST-ST:` trong phase sau.

### Structural query prompt

```python
STRUCTURAL_PROMPT = """\
You are a smart contract security auditor.

Function: {fn_name}()
Body:
{fn_body}

Analyze this function for structural vulnerability properties.
For each property present, write ONE search query describing what goes wrong —
using the language of audit report finding titles.

Check ONLY for properties actually visible in this code:
- State written to mapping/storage WITHOUT reading/checking existing value first
- State mutation that executes unconditionally regardless of input amount (zero, max)
- Arithmetic where intermediate result can underflow/overflow for specific input range
- External call without slippage/deadline/minOutput protection
- Missing access control: state-changing function callable by anyone
- Token balance assumption that breaks with fee-on-transfer tokens
- Array/index access that can exceed bounds

Format: one query per line, max 15 words each.
Use phrasing like audit finding titles: "X causes Y", "missing Z allows W".
If NO structural vulnerability properties are found, output EXACTLY the word NONE and nothing else.
Output ONLY queries or NONE.
"""
```

**Lý do thêm `NONE` bail-out:** LLM có xu hướng không muốn output rỗng — thay vào đó sẽ bịa ra một rủi ro viễn vông để "chiều lòng" prompt. `NONE` cho LLM lối thoát danh dự rõ ràng, giảm thiểu hallucinated queries cho safe functions.

```python
def _generate_structural_queries(fn_name, fn_body, llm_client) -> list:
    raw = llm_client.chat([{"role": "user", "content": STRUCTURAL_PROMPT.format(...)}],
                          temperature=0, max_tokens=1024).strip()
    if not raw or raw.upper() == "NONE":
        return []
    return [ln.strip() for ln in raw.split('\n') if ln.strip()]
```

### Cap per track

Hiện tại production code không có cap (`inv_texts = ordered_ann  # full list, no cap`).
Với dual-track, không cap sẽ gây bloat — ví dụ `burn()` (contest 35): OP 18 queries + ST 5 queries → có thể 14+ annotations trong 1 call graph entry.

**Giới hạn per function:**
- **OP track: tối đa 6 annotations**
- **ST track: tối đa 4 annotations**
- **Tổng tối đa: 10 annotations per function**

Lý do tách cap thay vì cap tổng: nếu dùng cap tổng với OP xử lý trước, ST gần như bị đẩy ra với functions nhiều OP queries. Cap riêng đảm bảo ST luôn có slot dù OP đã fill.

### Merge và dedup logic

```python
_OP_CAP = 6   # max HIST annotations từ operation track
_ST_CAP = 4   # max HIST annotations từ structural track

op_queries = _generate_operation_queries(fn_name, fn_body, llm_client)
st_queries = _generate_structural_queries(fn_name, fn_body, llm_client)

def _collect_annotations(queries: list, cap: int, seen_ann: set) -> list:
    """RAG query với cap, dedup by exact annotation text."""
    result = []
    for q in queries:
        if len(result) >= cap:
            break
        if not q.strip():
            continue
        docs = retriever.query(q, n_results=3)
        for d in (docs or []):
            if d['score'] < threshold:
                continue
            ann = _make_hist_annotation(d)  # "[title] [IMPACT]" — không đổi
            if ann not in seen_ann:
                seen_ann.add(ann)
                result.append(ann)
                break  # unique hit — next query
    return result

seen_ann: set = set()
op_anns = _collect_annotations(op_queries, _OP_CAP, seen_ann)
st_anns = _collect_annotations(st_queries, _ST_CAP, seen_ann)  # shared seen_ann: không trùng với OP
inv_texts = op_anns + st_anns  # tổng ≤ 10
```

**`seen_ann` shared giữa hai tracks** — nếu ST tìm được cùng finding với OP, annotation đó bị skip → không bao giờ duplicate trong call graph.

Kết quả inject vào call graph: cùng format `↳ HIST:` cho cả hai tracks. Không cần thay đổi downstream logic hay agent prompts.

### Thay đổi trong `_generate_fn_queries()` → tách thành 2 functions

```python
def _generate_operation_queries(fn_name, fn_body, llm_client) -> list:
    """V4c: enumerate operations (giữ nguyên logic hiện tại)."""
    ...  # không thay đổi

def _generate_structural_queries(fn_name, fn_body, llm_client) -> list:
    """V5: structural vulnerability property queries."""
    ...  # mới

def _generate_fn_queries(fn_name, fn_body, llm_client) -> list:
    """V5: merge cả hai tracks."""
    op = _generate_operation_queries(fn_name, fn_body, llm_client)
    st = _generate_structural_queries(fn_name, fn_body, llm_client)
    seen = set()
    merged = []
    for q in op + st:
        if q and q not in seen:
            seen.add(q)
            merged.append(q)
    return merged
```

### Cache compatibility

Cache key hiện tại: `(contract_name, cg_entry_stripped)` — không đổi. Nhưng queries bên trong cache thay đổi (nhiều hơn do 2 tracks). Cần **clear hist_inv_cache** khi upgrade lên v5.

---

## Kỳ vọng

### Cải thiện per H bug (contest 42)

| H Bug | v4c hiện tại | v5 dual-track | Lý do |
|-------|-------------|--------------|-------|
| H-04 registerAsset | OP 0.663 (sai finding) | OP 0.663 + ST 0.665 (đúng pattern) | ST "Missing check for existing registration" → đúng direction |
| H-07 liquidate | OP 0.664 (noisy) | OP 0.664 (ST empty) | Không đổi — OP giữ signal |
| H-08 deposit | OP 0.686 (sai: arithmetic) | ST 0.716 "Overwriting lastDeposit" | **Cải thiện rõ** — hint đúng pattern |
| H-09 veCRVlock | OP 0.672 | ST 0.717 | Marginal better |
| H-10 changeNFT | OP 0.652 (barely) | ST 0.659 | Marginal better |
| H-13 vest | OP 0.721 | ST 0.753 | Better, đã TP |

### Contest level — TP estimate

**Contest 42** (baseline run-8: TP=8/13, FP=28, F1=0.327):

Bugs hiện đang miss: H-04, H-06, H-07, H-08, H-09, H-10

- **H-08**: ST hint "Overwriting lastDeposit without checking existing value" → thay thế hint sai (arithmetic overflow). Agent có direction đúng hơn → **+1 TP khả năng cao**
- **H-04**: ST hint "Missing check for existing registration" → đúng direction nhưng vẫn retrieve permission bug khác → **+0.5 TP** (không chắc)
- **H-07**: Không đổi (ST empty) → vẫn miss
- **H-09, H-10**: Marginal improvement, không đủ để recover từ 0 finding

**Ước tính contest 42: +1 TP** (TP=9, F1 ≈ 0.360)

---

**Contest 35** (chưa có baseline benchmark):

Cải thiện quan trọng nhất:
- **H-04, H-08, H-12** (cùng `mint` function): từ **0 HIST hints** → **ST 0.748** với "Unsafe type-casting" + "Unsafe casting of liquidity to int128 causes incorrect position updates"
  - H-04 (overflow in mint): "Unsafe casting" hint trực tiếp liên quan → **+1 TP khả năng cao**
  - H-08 (wrong inequality in mint): hint về casting ít liên quan → **+0 đến +0.5 TP**
  - H-12 (update ordering in mint): hint về casting không liên quan → **+0 TP**
- Toàn bộ 16 bugs còn lại: ST score cao hơn OP → hints chất lượng hơn → marginal improvement

**Ước tính contest 35: +1 đến +2 TP** so với nếu chạy với v4c

### Lưu ý về estimate

HIST hints là 1 trong nhiều signals (source code, KG invariants, SWC patterns). Improvement trong HIST không guarantee improvement TP vì:
1. Agent vẫn phải reason đúng từ hint → có thể miss dù hint đúng (H-06 case: HIST 0.756 nhưng vẫn sai mechanism)
2. FP: thêm hints có thể tăng confidence cho sai findings → tăng FP nhẹ
3. Variance từ `contract_invariant_extractor.py` (temp=0.2) vẫn là major source of variance

---

## Rủi ro và biện pháp khắc phục

### Risk 1: LLM hallucinate structural queries cho safe functions ✅ Đã xử lý

**Vấn đề:** LLM không muốn output rỗng → bịa ra rủi ro viễn vông → query rác → RAG trả về finding không liên quan → noise trong call graph.

**Giải pháp:** `NONE` bail-out trong prompt + check `if raw.upper() == "NONE": return []`. LLM có lối thoát rõ ràng thay vì bắt buộc phải output gì đó.

---

### Risk 2: Confirmation Bias — rủi ro FP tăng ⚠️ Còn tồn tại, cần monitor

**Vấn đề:** ST queries mang tính assertive (mô tả bug hypothesis), khác OP queries chỉ describe mechanics. Flow nguy hiểm:

```
LLM đoán sai bug → ST query match từ khóa với historical finding
→ RAG trả về finding thuyết phục (score ≥ 0.65)
→ Agent đọc, bị "xác nhận" bug tồn tại → FP finding
```

OP queries ít bị ảnh hưởng hơn vì chúng neutral — agent tự judge relevance. ST queries assertive → agent ít có lý do để nghi ngờ.

**Biện pháp hiện tại (chưa triệt để):**
- RAG score threshold 0.65 loại phần lớn false matches
- ST cap=4 giới hạn tối đa 4 annotations từ ST per function
- `NONE` bail-out giảm hallucinated queries cho safe functions

**Phát hiện sau benchmark:** Nếu FP tăng rõ ràng sau v5, nguyên nhân chính là Risk 2. Giải pháp khi đó: tách prefix `↳ HIST-ST:` để agent nhận biết nguồn và không bị xác nhận thiên kiến; hoặc tăng ST score threshold lên 0.68-0.70.

---

### Risk 3: Hạ threshold cho H-04 ❌ Không nên làm

H-04 có ST score 0.629, gần nhưng dưới threshold 0.65. Có thể nảy sinh ý định hạ threshold ST xuống 0.62 để capture H-04.

**Không nên:** Khoảng cách 0.65 → 0.62 trong vector embedding space là lớn — sẽ mở cửa cho nhiều findings rác tràn vào toàn bộ pipeline. Thà miss H-04 ở HIST layer và để agent tự tìm qua code analysis + KG invariants. Không đánh đổi độ chính xác toàn hệ thống cho 1 bug.

---

## Giới hạn đã biết

| Issue | Mức độ | Ghi chú |
|-------|--------|---------|
| Confirmation Bias (Risk 2) | **Cao** | ST queries assertive → FP risk. Monitor sau benchmark; tách prefix nếu FP tăng |
| LLM calls tăng x2 | Trung bình | 2 LLM calls/function; cached sau run đầu → chỉ ảnh hưởng KG build lần đầu |
| H-04 vẫn dưới threshold | Trung bình | Score 0.629 < 0.65 — chấp nhận, không hạ threshold |
| Cache cần clear khi upgrade | Thấp | 1 lần per contest |

---

## Implementation plan

### Phase 1: Tách functions (không breaking)
- Extract `_generate_operation_queries()` từ `_generate_fn_queries()` hiện tại
- Thêm `_generate_structural_queries()` mới
- `_generate_fn_queries()` merge output của cả hai

### Phase 2: Test on contest 42
- Clear hist_inv_cache cho contest 42
- Chạy KG build, kiểm tra annotations trong call graph
- So sánh annotations với v4c: H-08 và H-12 phải có structural annotation mới

### Phase 3: Run benchmark
- Run-11 contest 42 với v5
- Eval, so sánh với run-8 (v4c baseline: TP=8, FP=28, F1=0.327)
- Nếu TP tăng mà FP không tăng → confirm và apply cho contest 35

### Phase 4: Monitor FP sau benchmark
- So sánh FP run-11 vs run-8 baseline (FP=28)
- Nếu FP tăng ≥ 5 → xem xét tách prefix `↳ HIST-ST:` hoặc tăng ST threshold lên 0.68
- Không hạ threshold xuống dưới 0.65

---

## Files thay đổi

| File | Thay đổi |
|------|---------|
| `backend/app/services/contract_kg_builder.py` | Tách `_generate_fn_queries()` thành 3 functions; thêm structural prompt |
| `benchmark/web3bugs/agent-redesign/42/hist_inv_cache.json` | Clear khi upgrade |

Không thay đổi RAG retriever, scoring logic, call graph format, hay downstream pipeline.

---

## Verification

```bash
# Smoke test: kiểm tra annotations có cả hai loại
cd /home/thangdd/repos/MiroFish/backend && source .venv/bin/activate

# Chạy KG build riêng cho MochiVault.deposit
python3 - <<'EOF'
import os, sys
sys.path.insert(0, '.')
for line in open('/home/thangdd/repos/MiroFish/.env'):
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, _, v = line.partition('=')
        os.environ[k.strip()] = v.strip().split('  #')[0].strip()

from app.services.contract_kg_builder import ContractKGBuilder
from app.utils.llm_client import LLMClient

src = open('/home/thangdd/repos/web3bugs/contracts/42/projects/mochi-core/contracts/vault/MochiVault.sol').read()
client = LLMClient()
queries = ContractKGBuilder._generate_fn_queries('deposit', src, llm_client=client)
print(f'Total queries: {len(queries)}')
for q in queries:
    print(f'  {q}')
EOF

# Kiểm tra structural queries xuất hiện (phải có "zero" hoặc "griefing" keyword)
# Chạy run-11 contest 42
rm -f /home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/42/hist_inv_cache.json
nohup bash scripts/run_benchmark.sh \
  /home/thangdd/repos/web3bugs/contracts/42 \
  ../benchmark/web3bugs/agent-redesign/42/run-11 \
  > /tmp/benchmark_42_run11.log 2>&1 &
```

**Dấu hiệu thành công:**
- `_generate_fn_queries('deposit', ...)` trả về ≥ 1 query chứa "zero" hoặc "griefing"
- Call graph annotations cho `deposit` có `↳ HIST:` liên quan đến zero-deposit/timer pattern
- run-11 eval: TP ≥ 9 (H-08 được tìm thấy), FP ≤ 30
