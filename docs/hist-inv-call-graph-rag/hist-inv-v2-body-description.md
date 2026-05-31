# Plan: HIST-INV v2 — Function Body Description Query

## Bối cảnh

HIST-INV v1 dùng `fn_name + ext_markers` làm RAG query. Vấn đề: tên hàm quá generic (`_mintFee`, `_getAmountOut`) → RAG match sai finding → invariant sai hoặc rỗng. Coverage chỉ 22/164 entries (13%).

**Nguyên nhân gốc**: Query signal yếu. Tên hàm không mang semantic của những gì hàm *thực sự tính toán*.

**Mục tiêu**: Thay query signal = function body description (LLM đọc source code, mô tả bằng NL) → RAG match đúng vulnerability class dù tên hàm generic.

---

## Tại sao pre-scan thay vì để R1 agents tự làm

HIST-INV chạy **1 lần duy nhất trong KG build**, trước R1, với kết quả được cache. Đây là thiết kế có chủ ý:

| Vấn đề nếu để R1 agents tự làm | Giải pháp pre-scan |
|-------------------------------|-------------------|
| 22 agents × describe + query + extract = chi phí nhân 22x, không cache được | 1 lần × cache ≈ 0 chi phí từ run 2 trở đi |
| R1 agents mix task: tìm vuln + mô tả code + query RAG = mất focus | Single responsibility: KG build = mô tả, R1 = tìm violations |
| Findings từ RAG trả về dạng HINT → agents bị bias, tăng FP | Pre-scan output là INVARIANT (nguyên tắc phải đúng), không phải hint → agents check independently |
| Mỗi agent có context window riêng, describe code → khác nhau giữa agents | 1 description nhất quán, tất cả agents nhận cùng invariant |

**Mô tả code dễ hơn tìm vulnerability**: LLM describe body chỉ cần reading comprehension ("hàm này tính gì?"), không cần reason về edge cases hay attacker scenarios. Task đơn giản hơn → output chính xác hơn, ít fail hơn.

---

## Thiết kế v2

```
CG entry: _getAmountsForLiquidity() → (leaf)

Bước 1 — LLM describe body (NEW):
  Input: source code của function _getAmountsForLiquidity
  Output: "Converts uint256 results from getDy/getDx to uint128 via explicit cast"

Bước 2 — RAG query (cải thiện):
  query = description + " vulnerability"
  → "Converts uint256 results from getDy/getDx to uint128 via explicit cast vulnerability"
  → RAG score: 0.75+ (vs 0.68 với tên hàm)

Bước 3 — Extract invariant (giữ nguyên):
  LLM extracts: "Explicit type casts from uint256 to uint128 must check for overflow before truncation"

Bước 4 — Annotate CALL GRAPH:
  _getAmountsForLiquidity() → (leaf)
    ↳ HIST: Explicit type casts from uint256 to uint128 must check for overflow before truncation
```

---

## Thay đổi so với v1

| Bước | v1 (current) | v2 |
|------|-------------|-----|
| **Entries có `[EXTERNAL:]`** | LLM semantic question (1 call) + extract | **Giữ nguyên** — ext_markers đã là signal tốt |
| **Leaf entries, tên generic** | Direct query (0 LLM) + extract | **LLM describe body (1 call)** + extract |
| Coverage arithmetic/logic | ❌ blind (tên hàm quá generic) | ✅ LLM đọc code, thấy uint128 cast, subtraction pattern |
| Scale | Tự động (tên hàm) | Tự động (LLM đọc bất kỳ body) |

**Entries với ext_markers không cần describe**: `_buyMochi() → [EXTERNAL: swapExactTokensForTokens]` — ext_markers "swapExactTokensForTokens" đã là signal đủ mạnh cho RAG. Chỉ leaf entries mới cần describe vì không có external signal nào.

---

## Scope — Hàm nào cần describe?

Không describe tất cả 164 entries. Chỉ describe khi:

```python
NEEDS_DESCRIPTION = (
    # Có external calls → query từ ext_markers vẫn dùng được
    not ext_markers
    # Không phải trivial getter
    and fn_name.lower() not in _TRIVIAL_EXACT
    # Tên hàm không đủ specific (underscore prefix hoặc camelCase generic)
    and (fn_name.startswith('_') or fn_name[0].islower())
)
```

Ước tính: ~40-60% entries là leaf functions với tên generic cần description. Entries có `[EXTERNAL:]` vẫn dùng ext_markers làm signal chính.

---

## Implementation

### File: `backend/app/services/contract_kg_builder.py`

**Thêm method `_describe_function_body()`**

```python
@staticmethod
def _describe_function_body(fn_name: str, fn_body: str,
                            llm_client: Optional[Any] = None) -> str:
    """
    LLM đọc function body source code và mô tả ngắn gọn những gì hàm tính toán.
    Focus vào operations có thể gây vulnerability, không phải high-level intent.
    Cached → chỉ gọi LLM lần đầu.
    """
    if not fn_body or not fn_body.strip():
        return ""
    if not llm_client:
        return ""

    # Giới hạn body để tránh prompt quá dài
    body_excerpt = fn_body[:800].strip()

    prompt = (
        "You are a smart contract security expert.\n\n"
        f"Describe in ONE concise sentence (under 20 words) what this Solidity function COMPUTES.\n"
        "Focus on: arithmetic operations, type casts, storage reads/writes, external dependencies.\n"
        "Do NOT describe the business purpose. Describe the COMPUTATION.\n\n"
        f"Function: {fn_name}()\n"
        f"Body:\n{body_excerpt}\n\n"
        "Output ONLY the description sentence. No explanation.\n\n"
        "Examples:\n"
        "- 'Converts uint256 getDy/getDx results to uint128 via explicit cast'\n"
        "- 'Subtracts feeGrowthGlobal minus feeGrowthAbove minus feeGrowthBelow for range'\n"
        "- 'Negates uint128 amount via -int128 cast for signed liquidity delta'\n"
        "- 'Multiplies two uint256 values and divides by 2^96 without overflow check'\n"
    )
    try:
        result = llm_client.chat(
            [{"role": "user", "content": prompt}],
            temperature=0, max_tokens=512,
        ).strip().strip('"\'')
        return result if result else ""
    except Exception:
        return ""
```

**Update `_generate_rag_query()` để nhận description**

```python
@staticmethod
def _generate_rag_query(fn_name: str, ext_markers: set, contract_name: str,
                        fn_description: str = "",
                        llm_client: Optional[Any] = None) -> str:
    """
    Build RAG query. Priority:
    1. fn_description (body description) — strongest signal for logic/arithmetic bugs
    2. ext_markers — strong signal for external call bugs
    3. fn_name — fallback
    """
    if fn_description:
        # Dùng description làm query trực tiếp
        return fn_description + " vulnerability smart contract"

    if not llm_client:
        return ContractKGBuilder._build_direct_query(fn_name, ext_markers)

    # ext_markers → LLM semantic question (v1 behavior)
    ext_context = ", ".join(sorted(ext_markers)) if ext_markers else "none"
    prompt = (...)  # same as v1
    try:
        result = llm_client.chat(...).strip()
        return result if result else ContractKGBuilder._build_direct_query(fn_name, ext_markers)
    except Exception:
        return ContractKGBuilder._build_direct_query(fn_name, ext_markers)
```

**Update `_process_entry()` để extract function body và generate description**

```python
def _process_entry(entry: str, contract_name: str) -> tuple[str, list]:
    fn_match = re.match(r'\s+(\w+)\(\)', entry)
    if not fn_match:
        return entry, []
    fn_name = fn_match.group(1)

    ext_match = re.search(r'\[EXTERNAL:\s*([^\]]+)\]', entry)
    ext_markers = {m.strip() for m in ext_match.group(1).split(',')} if ext_match else set()

    if fn_name.lower() in _TRIVIAL_EXACT and not ext_markers:
        return entry, []

    # Cache lookup (unchanged)
    cache_key = _Cache.entry_key(contract_name, entry.strip()) if cache else None
    if cache and cache_key:
        cached = cache.get(cache_key)
        if cached is not None:
            raw = cached.get("inv_text", "")
            return entry, [i for i in raw.split("\n") if i.strip()] if raw else []

    if not retriever:
        return entry, []

    # NEW: Generate function body description for leaf functions without ext_markers
    fn_description = ""
    if not ext_markers and not fn_name.lower() in _TRIVIAL_EXACT:
        # Extract function body from source_code (cần pass source_code vào)
        fn_body = ContractKGBuilder._extract_fn_body(source_code, fn_name)
        if fn_body:
            fn_description = ContractKGBuilder._describe_function_body(
                fn_name, fn_body, llm_client=llm_client
            )

    # Query generation với description hoặc ext_markers
    llm_query = ContractKGBuilder._generate_rag_query(
        fn_name, ext_markers, contract_name,
        fn_description=fn_description,
        llm_client=llm_client,
    )
    direct_query = ContractKGBuilder._build_direct_query(fn_name, ext_markers)

    # Dual RAG query (unchanged)
    ...
```

**Thêm `_extract_fn_body()` static method**

```python
@staticmethod
def _extract_fn_body(source_code: str, fn_name: str) -> str:
    """
    Extract source code của 1 function từ flattened source.
    Dùng brace counting từ vị trí 'function fn_name('.
    Returns body (không bao gồm signature), max 800 chars.
    """
    fn_re = re.compile(
        rf'\bfunction\s+{re.escape(fn_name)}\s*\([^{{]*\{{',
        re.DOTALL
    )
    m = fn_re.search(source_code)
    if not m:
        return ""

    # Count braces để tìm end của function
    start = m.end()
    depth = 1
    pos = start
    while pos < len(source_code) and depth > 0:
        c = source_code[pos]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
        pos += 1

    body = source_code[start:pos-1].strip()
    return body[:800]  # Limit để tránh prompt quá dài
```

---

## source_code propagation

`_process_entry` hiện là closure bên trong `_build_call_graph_with_hist_inv` — nó có access đến `source_code` từ closure variable. Không cần thay đổi signature của `_process_entry`.

Trong `_enrich(contract_name, entries)`:
- Multi-contract: `section` = source của contract đó
- Single contract: `source_code` = toàn bộ source

Cần pass `section` vào `_describe_function_body` thay vì toàn bộ `source_code` để tránh match sai function trùng tên.

```python
def _enrich(contract_name: str, entries: List[str], section_source: str = "") -> List[str]:
    ...
    def _process_entry(entry, contract_name):
        ...
        fn_body = ContractKGBuilder._extract_fn_body(section_source or source_code, fn_name)
```

---

## Cache schema (không đổi)

Cache `hist_inv_cache.json` không cần thay đổi schema:
```json
{
  "rag_query": "Converts uint256 getDy results to uint128 via explicit cast vulnerability",
  "inv_text": "Explicit type casts from uint256 to uint128 must check for overflow",
  "rag_title": "...",
  "rag_score": 0.76,
  "cg_entry": "  _getAmountsForLiquidity() → (leaf)"
}
```

`rag_query` sẽ là description-based query thay vì name-based — vẫn dùng được cho cache invalidation.

---

## LLM call budget

| Entry type | v1 (current) | v2 |
|-----------|-------------|-----|
| Has `[EXTERNAL:]` (~40 entries) | 1 LLM (semantic question) + 1 LLM (extract if ≥0.68) | 1 LLM (semantic question, unchanged) + 1 LLM (extract if ≥0.68) |
| Leaf, generic name (~80 entries) | 0 LLM (direct query) + 1 LLM (extract if ≥0.68) | **1 LLM (describe body)** + 1 LLM (extract if ≥0.68) |
| Leaf, trivial getter (~44 entries) | 0 | 0 |

**Contest 35 ước tính (~164 entries, ~80 leaf generic, ~86 above threshold)**:
- v1: 40 (semantic question) + 61 (extract, 25% success) = **101 LLM calls** — nhưng 64/86 fail do rate limit
- v2: 40 (semantic question) + 80 (describe body) + ? extract = **120+ LLM calls** — nhưng describe tạo query tốt hơn → ít entries fail extraction hơn

**Quan trọng**: v2 thêm 80 describe calls nhưng giảm waste (ít entries score dưới threshold vì query chính xác hơn). Trade-off: thêm calls nhưng chất lượng cao hơn nhiều.

### LLM client policy

HIST-INV **chỉ dùng LLM2 (erudite-flag)**, không dùng LLM1 (hopeful-frame):
- LLM1 đã được dùng bởi R1 agents → dùng thêm HIST-INV sẽ double load, gây 429
- `_build_hist_inv_llm_pool()` trong `contract_kg_builder.py` return single `LLMClient` với `LLM2_VERTEX_AI_KEY_FILE`
- Slot file riêng: `/tmp/mirofish_hist_inv_1.json` (không conflict với R1's `mirofish_rpm_0/1.json`)

---

## Các files thay đổi

| File | Thay đổi |
|------|----------|
| `contract_kg_builder.py` | Thêm `_describe_function_body()`, `_extract_fn_body()`, update `_generate_rag_query()`, update `_process_entry()` closure, update `_enrich()` pass section_source |
| `contract_hist_inv_cache.py` | Không đổi |
| `run_contract_audit.py` | Không đổi |

---

## Verification

```bash
cd /home/thangdd/repos/MiroFish/backend && source .venv/bin/activate

# Test _describe_function_body với 3 key functions của contest 35
python3 - <<'EOF'
import sys; sys.path.insert(0, '.')
from app.services.contract_kg_builder import ContractKGBuilder
from app.utils.llm_client import LLMClient
from app.config import Config

key2 = getattr(Config, 'LLM2_VERTEX_AI_KEY_FILE', None)
client = LLMClient(vertex_key_file=key2, base_url=getattr(Config,'LLM2_BASE_URL',None),
    model=getattr(Config,'LLM_MODEL_NAME',None),
    rpm_slot_file='/tmp/mirofish_hist_inv_1.json', rpm_limit=18)

test_bodies = {
    "_getAmountsForLiquidity": """
        amount0Actual = uint128(DyDxMath.getDy(liquidity, priceLower, priceUpper, false));
        amount1Actual = uint128(DyDxMath.getDx(liquidity, priceLower, priceUpper, false));
    """,
    "rangeFeeGrowth": """
        feeGrowthInside0 = feeGrowthGlobal0 - feeGrowthBelow0 - feeGrowthAbove0;
        feeGrowthInside1 = feeGrowthGlobal1 - feeGrowthBelow1 - feeGrowthAbove1;
    """,
    "burn_CLP": """
        (uint256 amount0, uint256 amount1) = _getAmountsForLiquidity(...);
        _updatePosition(owner, lower, upper, -int128(amount));  // ← unsafe cast
    """,
}

from app.services.cyber_session_orchestrator import _get_rag_retriever
retriever = _get_rag_retriever()

for fn_name, body in test_bodies.items():
    desc = ContractKGBuilder._describe_function_body(fn_name, body, llm_client=client)
    if desc:
        query = desc + " vulnerability smart contract"
        docs = retriever.query(query, n_results=1)
        score = docs[0]['score'] if docs else 0
        title = docs[0]['title'][:60] if docs else ""
        print(f"\n[{fn_name}]")
        print(f"  DESC: {desc}")
        print(f"  RAG: {score:.3f} | {title}")
    else:
        print(f"\n[{fn_name}] FAILED to describe")
EOF

# Expected:
# _getAmountsForLiquidity: desc về uint128 cast → score > 0.75
# rangeFeeGrowth: desc về subtraction accumulators → score > 0.75
# burn_CLP: desc về -int128 cast → score > 0.72
```

**Dấu hiệu thành công**:
- Descriptions capture đúng operations (uint128 cast, subtraction, int128 negation)
- RAG scores tăng so với v1 (mục tiêu > 0.72 cho key functions)
- Không rate limit (erudite-flag, cached)
- Coverage tăng từ 22 → 40+ entries với inv_text

---

## Rủi ro

| Rủi ro | Xử lý |
|--------|-------|
| LLM describe trả "" | Skip entry, fallback về direct query (fn_name + "vulnerability") |
| Description quá generic ("performs arithmetic") | Prompt example-driven + focus vào type casts, specific operations |
| `_extract_fn_body` không tìm được function | Fallback về direct query |
| Trùng tên function trong multi-contract | Dùng `section_source` (source của contract section) thay vì full source |
| Quota LLM erudite-flag (describe ~80 + extract ~40 = ~120 calls) | Cached contest-level sau lần đầu; erudite-flag riêng không conflict R1 |
| LLM extraction vẫn fail (64/86 trong v1) | v2 giải quyết gián tiếp: describe → query tốt hơn → fewer borderline entries → fewer extraction calls trên entries sai |
