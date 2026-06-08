# HIST-INV Inline Annotation — Implementation Plan

## Mục tiêu

Thay vì inject HIST titles vào call graph (ambient context, agent dễ bỏ qua),
embed real invariant trực tiếp vào source code **ngay trên function definition**.

Agent đọc code → thấy invariant đúng tại function đó → không thể gán sang function
khác, không thể bỏ sót.

---

## Nguyên tắc thiết kế

- **Inject toàn bộ cache** — không filter theo score hay contract type. Cache đã chứa
  các entries đạt quality threshold khi build. Vuls có thể ở bất kỳ contract nào trong scope.
- **1 INV per function** — LLM synthesize từ toàn bộ `inv_text` (tất cả HIST entries của
  function đó) + `fn_body` → 1 invariant statement súc tích nhất.
- **Phân tán tự nhiên** — 164 comments trải đều trong source (không wall of text), agent
  chỉ thấy INV khi đọc đến đúng function.
- **Không filter** — contest nhỏ (5, 42: scan full source) hay lớn (35) đều inject như nhau.

---

## Kết quả mong đợi trong source code

```solidity
// [HIST-INV]: collect() must allow feeGrowthInside subtraction to wrap/underflow —
//             fee growth accumulators overflow by design; Solidity 0.8 checked
//             arithmetic will revert, permanently DoS-ing fee collection.
function collect(uint256 tokenId, address recipient, bool unwrapBento) external {
    ...
}

// [HIST-INV]: _getAmountsForLiquidity() must not silently truncate — the uint128
//             cast of DyDxMath.getDx/getDy may overflow if token amount > 2^128-1,
//             causing callers to receive more tokens than the pool actually owns.
function _getAmountsForLiquidity(
    uint160 priceLower,
    ...
) internal pure returns (uint256 amount0, uint256 amount1) {
    ...
}
```

---

## Thay đổi cần thiết

### File 1: `contract_hist_inv_cache.py`

**Thêm field `hist_inv` vào `set()`:**

```python
def set(self, key: str, contract_name: str, fn_name: str, rag_query: str,
        inv_text: str, rag_title: str, rag_score: float, cg_entry: str,
        hist_inv: str = "") -> None:
    self._data[key] = {
        "contract_name": contract_name,
        "fn_name": fn_name,
        "rag_query": rag_query,
        "inv_text": inv_text,       # giữ nguyên: title-based (dùng cho call graph hiện tại)
        "rag_title": rag_title,
        "rag_score": rag_score,
        "cg_entry": cg_entry,
        "hist_inv": hist_inv,       # NEW: real invariant statement
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
```

**Thêm method `get_hist_inv_map()`:**

```python
def get_hist_inv_map(self) -> dict[tuple[str, str], str]:
    """
    Trả về dict: (contract_name, fn_name) -> hist_inv string.
    Chỉ bao gồm entries có hist_inv non-empty.
    """
    result = {}
    for v in self._data.values():
        inv = v.get("hist_inv", "").strip()
        if inv:
            key = (v.get("contract_name", ""), v.get("fn_name", ""))
            result[key] = inv
    return result
```

---

### File 2: `contract_kg_builder.py`

**Thêm method `_generate_hist_inv()`** — sau `_make_hist_annotation`:

```python
@staticmethod
def _generate_hist_inv(fn_name: str, fn_body: str,
                        inv_text: str,
                        llm_client=None) -> str:
    """
    Từ fn_body + toàn bộ inv_text (tất cả HIST titles của function) →
    synthesize 1 real invariant statement cho function này.

    inv_text: chuỗi multi-line chứa tất cả "[Title] [IMPACT]" entries.
    Trả về empty string nếu fail.
    """
    if not fn_body or not fn_body.strip() or not inv_text.strip() or not llm_client:
        return ""

    prompt = (
        f"You are a smart contract security auditor.\n\n"
        f"Function: {fn_name}()\n"
        f"Code:\n{fn_body.strip()[:2000]}\n\n"
        f"The following vulnerability patterns were found in similar functions "
        f"across other audited protocols:\n"
        f"{inv_text.strip()}\n\n"
        f"Based on the code above and these historical patterns, write ONE invariant "
        f"that must hold for {fn_name}() in this contract.\n\n"
        f"Rules:\n"
        f"- Start with \"{fn_name}() must ...\"\n"
        f"- Be specific to THIS function's actual variable names and operations\n"
        f"- Describe the condition that MUST hold, not what goes wrong\n"
        f"- Maximum 2 sentences\n"
        f"- Do NOT copy titles verbatim — derive from the code\n"
        f"- If NO historical pattern is applicable to this code, output EXACTLY: NONE\n\n"
        f"Output ONLY the invariant statement or NONE."
    )
    try:
        raw = llm_client.chat(
            [{"role": "user", "content": prompt}],
            temperature=0, max_tokens=256,
        ).strip()
        if not raw or raw.upper() == "NONE":
            return ""
        if "must" in raw.lower() or fn_name.lower() in raw.lower():
            return raw
        return ""
    except Exception:
        return ""
```

**Cập nhật call site** — sau khi build `inv_texts` (combined annotation), gọi thêm:

```python
# Sau khi đã có combined (inv_text) từ RAG hits:
hist_inv = ""
if combined.strip():
    hist_inv = ContractKGBuilder._generate_hist_inv(
        fn_name=fn_name,
        fn_body=fn_body,
        inv_text=combined,
        llm_client=client,
    )

cache.set(cache_key, contract_name, fn_name, queries_str, combined,
          best_title, best_score, entry.strip(), hist_inv=hist_inv)
```

**Chi phí:** 1 LLM call thêm per function **có inv_text non-empty** trong KG build.
One-time cost — cache reuse giữa các runs.

---

### File 3: `cyber_session_orchestrator.py`

**Thêm hàm `_annotate_source_with_hist_inv()`:**

```python
import re as _re_inline

def _annotate_source_with_hist_inv(source: str,
                                    inv_map: dict[tuple[str, str], str],
                                    contract_name: str) -> str:
    """
    Inject `// [HIST-INV]: ...` comment ngay trước `function fn_name(` trong source.
    Dùng simple line-by-line search — không parse full signature, tránh lỗi multiline.

    inv_map: (contract_name, fn_name) -> invariant string (từ cache.get_hist_inv_map())
    """
    lines = source.split('\n')
    result = []
    fn_pattern = _re_inline.compile(r'^([ \t]*)function\s+(\w+)\s*[\(\{]')

    for line in lines:
        m = fn_pattern.match(line)
        if m:
            indent = m.group(1)
            fn_name = m.group(2)
            inv = inv_map.get((contract_name, fn_name), "")
            if inv:
                # Wrap comment ở 100 chars
                prefix1 = f"{indent}// [HIST-INV]: "
                prefixN = f"{indent}//             "
                words = inv.split()
                comment_lines, cur = [], prefix1
                for w in words:
                    if len(cur) + len(w) + 1 > 100:
                        comment_lines.append(cur.rstrip())
                        cur = prefixN + w
                    else:
                        cur += ("" if cur == prefix1 else " ") + w
                comment_lines.append(cur.rstrip())
                result.extend(comment_lines)
        result.append(line)

    return '\n'.join(result)
```

**Gọi annotation** — tìm chỗ format source code trước khi build agent prompt (network_summary),
thêm bước annotate cho từng contract:

```python
# Load hist_inv_map từ cache (đã có sẵn trong session)
inv_map = hist_cache.get_hist_inv_map() if hist_cache else {}

# Annotate từng contract source trước khi ghép thành network_summary
if inv_map:
    for contract_name in contract_sources:
        contract_sources[contract_name] = _annotate_source_with_hist_inv(
            source=contract_sources[contract_name],
            inv_map=inv_map,
            contract_name=contract_name,
        )
```

---

### File 4: `contract_oasis_env.py`

**Cập nhật `_STEP1_BLOCK`** — thêm hướng dẫn về `[HIST-INV]`:

```python
_STEP1_BLOCK = """\
STEP 1 — LIST INVARIANTS:
  Read the full contract source and list 3–6 PROTOCOL-SPECIFIC invariants.
  Format: INV-1: <invariant statement>, INV-2: ..., ...

  ⚠ PRIORITY — Functions marked with // [HIST-INV]: in the source have been flagged
  by historical audit analysis as similar to past vulnerabilities. For EACH such
  function: include its [HIST-INV] as one of your INV-N entries (restate in your
  own words if needed), then check whether this contract's implementation violates it.

  Invariants MUST be strictly derived from the code, require() statements, or NatSpec.
  ...  (phần còn lại giữ nguyên)
"""
```

---

## Thứ tự thực hiện

1. `contract_hist_inv_cache.py` — thêm `hist_inv` field + `get_hist_inv_map()`
2. `contract_kg_builder.py` — thêm `_generate_hist_inv()` + gọi sau build `inv_texts`
3. Clear cache và build lại: kill sau STEP 2/4, verify entries có `hist_inv` non-empty
4. `cyber_session_orchestrator.py` — thêm `_annotate_source_with_hist_inv()` + gọi trước build prompt
5. `contract_oasis_env.py` — cập nhật `_STEP1_BLOCK`
6. Chạy run-72, eval, so sánh TP/FP với run-71

---

## Trade-offs

| | Trước (run-71) | Sau (run-72) |
|---|---|---|
| HIST location | Call graph cuối prompt | Inline ngay trên function |
| HIST format | Title only | Real invariant statement |
| Scope | Tất cả contracts (noise) | Tất cả — nhưng phân tán tự nhiên |
| Filter | Score threshold | Không filter thêm (cache đã filter) |
| KG build cost | 2 LLM calls/fn | 3 LLM calls/fn (one-time per contest) |
| Agent run cost | Không thêm | Không thêm |
| Agent association | Ambient → dễ sai fn | Pinned inline → đúng fn |
| Cache rebuild | Không cần | Cần 1 lần |
