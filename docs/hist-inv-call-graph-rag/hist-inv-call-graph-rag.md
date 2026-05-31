# Plan: HIST-INV — Call Graph + RAG Invariant Extraction

## Bối cảnh

Hiện tại pipeline có các nguồn invariant:
1. **SINV** — structural invariants từ static scan (access control)
2. **TINV** — domain template invariants hardcoded (5 domains, 7 invariants, detect sai ~50%)
3. **INV** — LLM extract từ source code trong KG build
4. **Agent INV** — mỗi agent tự extract trong Phase A của R1

Vấn đề: agents chỉ extract invariants từ code đang đọc → không biết vulnerability patterns từ lịch sử audit → miss bugs như slippage (H-12), proxy collision (H-06), fee growth underflow (H-09).

**Mục tiêu**: Thêm nguồn thứ 5 — **HIST-INV** — invariants được extract từ RAG findings, annotated trực tiếp vào CALL GRAPH tại function liên quan. Có cache để tránh re-query khi code không thay đổi.

---

## Thiết kế tổng quan

```
KG Build (sau khi CALL GRAPH được build):
  Với mỗi CG entry:
    1. LLM generate RAG query từ (fn_name + ext_markers + contract_name)
    2. Direct fallback query: fn_name + ext_markers làm raw text
    3. Dual query RAG, lấy max score
    4. Nếu score ≥ SCORE_THRESHOLD: LLM extract abstract invariant từ finding
    5. Cache: hash(contract_name + cg_entry) → { query, inv_text, rag_title, score }
    6. Annotate CG entry: thêm "↳ HIST: ..." inline

Agent R1:
  context_summary (chứa annotated CALL GRAPH) → agent đọc function
  → thấy HIST annotation ngay tại chỗ → check invariant đó
  → không cần cross-reference với section riêng biệt
```

**Không có static map** — LLM tự generate query phù hợp với ngữ cảnh của từng function. Scale tự động, không cần maintain tay.

---

## Format output của annotated CALL GRAPH

```
[FeePoolV0]
  distributeMochi() → calls: _buyMochi, _shareMochi
  _buyMochi() → [EXTERNAL: swapExactTokensForTokens, approve, usdm, mochi]
    ↳ HIST: DEX swap calls must specify non-trivial amountOutMin to prevent sandwich attacks
  _shareMochi() → [EXTERNAL: balanceOf, mochi, transfer, vMochi]

[MochiTreasuryV0]
  veCRVlock() → calls: _buyCRV, _lockCRV, updateFee
  _buyCRV() → [EXTERNAL: swapExactTokensForTokens, approve]
    ↳ HIST: DEX swap calls must specify non-trivial amountOutMin to prevent sandwich attacks

[ConcentratedLiquidityPool]
  rangeFeeGrowth() → (leaf)
    ↳ HIST: Fee growth calculations in concentrated liquidity must use unchecked arithmetic to allow intentional wrap-around
  _getAmountsForLiquidity() → (leaf)
    ↳ HIST: Explicit type casts from uint256 to uint128 must check for overflow before truncation
```

---

## Files cần thay đổi / tạo mới

### File 1 (mới): `backend/app/services/contract_hist_inv_cache.py`

Cache manager cho HIST-INV. Persist to disk, keyed by hash của CG entry.

```python
"""
HIST-INV cache — persist RAG-derived invariants per call graph entry.

Cache key: sha256(contract_name + "::" + cg_entry_line)[:16]
Cache value: { rag_query, inv_text, rag_title, rag_score, timestamp }
Cache file: <contest_cache_dir>/hist_inv_cache.json

Invalidation: chỉ khi CG entry text thay đổi (source code thay đổi).
Cùng contest, khác run → reuse 100% nếu code không đổi.
"""

import hashlib, json, time
from pathlib import Path
from typing import Optional

CACHE_VERSION = 1  # bump khi thay đổi schema cache

class HistInvCache:
    def __init__(self, cache_path: str):
        self.path = Path(cache_path)
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text())
                if raw.get("version") == CACHE_VERSION:
                    return raw.get("entries", {})
            except Exception:
                pass
        return {}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({
            "version": CACHE_VERSION,
            "entries": self._data,
        }, indent=2, ensure_ascii=False))

    @staticmethod
    def entry_key(contract_name: str, cg_entry: str) -> str:
        """Deterministic key — same source code → same key mọi lần."""
        return hashlib.sha256(f"{contract_name}::{cg_entry}".encode()).hexdigest()[:16]

    def get(self, key: str) -> Optional[dict]:
        return self._data.get(key)

    def set(self, key: str, rag_query: str, inv_text: str,
            rag_title: str, rag_score: float, cg_entry: str):
        self._data[key] = {
            "rag_query": rag_query,
            "inv_text": inv_text,
            "rag_title": rag_title,
            "rag_score": rag_score,
            "cg_entry": cg_entry,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
```

---

### File 2: `backend/app/services/contract_kg_builder.py`

Thêm 3 method:

**2A — LLM generate RAG query (thay thế static maps)**

```python
@staticmethod
def _generate_rag_query(fn_name: str, ext_markers: set, contract_name: str) -> str:
    """
    Dùng LLM để generate optimal RAG query cho 1 CG entry.
    Không dùng static map — LLM tự suy luận vulnerability pattern từ context.
    Kết quả được cache → chỉ gọi LLM lần đầu.
    """
    from app.services.llm_client import call_llm_simple  # map sang client thực tế

    ext_context = ", ".join(sorted(ext_markers)) if ext_markers else "none"
    # Infer contract type for context without leaking specific name into query
    prompt = f"""You are a smart contract security expert generating a RAG search query.

Context (for understanding only — do NOT copy contract name into query):
- Contract type context: {contract_name}
- Function: {fn_name}()
- External calls made: {ext_context}

Generate ONE short question (under 15 words) asking about historical vulnerabilities
for this type of function. Write a natural semantic question, not a keyword list.

Rules:
- Use contract type (e.g., vault, AMM, lending) NOT the specific contract name
- Frame as a question — embedding models match questions to finding titles well
- Focus on what could go wrong

Output ONLY the question string. No explanation.

Examples:
- Function: _buyMochi, external: swapExactTokensForTokens
  → "What vulnerabilities occur when swapExactTokensForTokens is called without slippage protection?"
- Function: rangeFeeGrowth, external: none
  → "What are common bugs in Uniswap V3 fee growth accounting functions?"
- Function: constructor, external: delegatecall
  → "What storage collision issues arise in proxy contracts using delegatecall?"
"""
    try:
        return call_llm_simple(prompt, max_tokens=40, temperature=0).strip()
    except Exception:
        # Fallback: dùng fn_name + ext_markers trực tiếp
        parts = [fn_name] + list(ext_markers)[:3]
        return " ".join(parts) + " vulnerability smart contract"
```

**2B — Extract invariant từ RAG finding**

```python
@staticmethod
def _extract_invariant_from_finding(title: str, content: str) -> str:
    """
    Dùng LLM để extract 1 abstract invariant từ finding.
    Output: 1 câu ngắn, protocol-agnostic, mô tả property PHẢI đúng.
    """
    from app.services.llm_client import call_llm_simple

    prompt = f"""Extract ONE security invariant from this audit finding.

Finding: {title}
Detail: {content[:1500]}

Requirements:
- State what SHOULD be true (not the violation)
- Protocol-agnostic: no specific contract/token names
- Max 25 words, 1 sentence
- Focus on the security property

Output ONLY the invariant sentence.
Example: "DEX swap calls must specify a non-trivial minimum output amount to prevent sandwich attacks."
"""
    try:
        return call_llm_simple(prompt, max_tokens=60, temperature=0).strip().strip('"\'')
    except Exception:
        return ""
```

**2C — `_build_call_graph_with_hist_inv()` — main method**

```python
@staticmethod
def _build_call_graph_with_hist_inv(
    source_code: str,
    known_functions: list,
    cache: "HistInvCache | None" = None,
    score_threshold: float = 0.68,  # configurable, không hardcode trong logic
) -> str:
    """
    Build CALL GRAPH với HIST-INV annotations.

    Flow per entry:
      1. LLM generate query (cached)
      2. Direct fallback query: fn_name + ext_markers raw
      3. Dual query RAG, max score
      4. score ≥ score_threshold → LLM extract invariant (cached)
      5. Annotate entry với "↳ HIST: ..."

    Filter: skip chỉ khi fn_name là trivial exact getter VÀ không có external calls.
    Có ext_markers → luôn process bất kể tên ngắn (buy/add/swap đều quan trọng).
    Không dùng length-based filter — mint/burn/swap đều ≤4 chars nhưng critical.
    """
    from app.services.cyber_session_orchestrator import _get_rag_retriever
    from app.services.contract_hist_inv_cache import HistInvCache as _Cache

    file_section_re = re.compile(r'^// ─── (.+?\.sol)(?:[^\n]*) ───', re.MULTILINE)
    markers = list(file_section_re.finditer(source_code))
    retriever = _get_rag_retriever() if cache is not None else None

    def _enrich_entries(contract_name: str, entries: list[str]) -> list[str]:
        result = []
        for entry in entries:
            result.append(entry)

            fn_match = re.match(r'\s+(\w+)\(\)', entry)
            if not fn_match:
                continue
            fn_name = fn_match.group(1)

            # Extract ext_markers trước để dùng trong filter
            ext_match = re.search(r'\[EXTERNAL:\s*([^\]]+)\]', entry)
            ext_markers = set()
            if ext_match:
                ext_markers = {m.strip() for m in ext_match.group(1).split(',')}

            # Skip chỉ khi: trivial exact getter VÀ không có external calls
            # Có ext_markers → luôn process (buy/add/swap ngắn nhưng critical)
            _TRIVIAL_EXACT = frozenset({'get', 'set', 'is', 'has'})
            if fn_name.lower() in _TRIVIAL_EXACT and not ext_markers:
                continue

            # Cache lookup
            cache_key = _Cache.entry_key(contract_name, entry.strip()) if cache else None
            if cache and cache_key:
                cached = cache.get(cache_key)
                if cached and cached.get("inv_text"):
                    result.append(f"    ↳ HIST: {cached['inv_text']}")
                    continue
                elif cached and not cached.get("inv_text"):
                    continue  # đã query trước, score thấp → skip

            if not retriever:
                continue

            # LLM generate query (+ fallback)
            llm_query = ContractKGBuilder._generate_rag_query(
                fn_name, ext_markers, contract_name
            )
            direct_query = " ".join([fn_name] + list(ext_markers)[:3]) + " vulnerability"

            # Dual query, lấy max
            best_score, best_doc = 0.0, None
            for q in [llm_query, direct_query]:
                docs = retriever.query(q, n_results=1)
                if docs and docs[0]['score'] > best_score:
                    best_score = docs[0]['score']
                    best_doc = docs[0]

            # Cache miss kết quả (kể cả score thấp để không retry)
            if cache and cache_key:
                if best_score < score_threshold or not best_doc:
                    cache.set(cache_key, llm_query, "", "", best_score, entry.strip())
                    continue

            if best_score < score_threshold or not best_doc:
                continue

            inv_text = ContractKGBuilder._extract_invariant_from_finding(
                best_doc['title'],
                best_doc.get('content', '')[:2000],
            )
            if not inv_text:
                continue

            result.append(f"    ↳ HIST: {inv_text}")

            if cache and cache_key:
                cache.set(cache_key, llm_query, inv_text,
                          best_doc['title'], best_score, entry.strip())
        return result

    # Multi-contract (flattened source)
    if len(markers) >= 2:
        parts = []
        for i, marker in enumerate(markers):
            contract_name = marker.group(1).rsplit('/', 1)[-1].replace('.sol', '')
            start = marker.end()
            end = markers[i + 1].start() if i + 1 < len(markers) else len(source_code)
            section = source_code[start:end]
            local_fns = list(set(re.findall(r'\bfunction\s+([a-zA-Z_]\w*)\s*\(', section)))
            raw_entries = ContractKGBuilder._build_call_graph_entries(section, local_fns)
            enriched = _enrich_entries(contract_name, raw_entries)
            if enriched:
                parts.append(f"[{contract_name}]\n" + "\n".join(enriched))
        return ("CALL GRAPH:\n" + "\n\n".join(parts) + "\n") if parts else ""

    # Single contract
    raw_entries = ContractKGBuilder._build_call_graph_entries(source_code, known_functions)
    enriched = _enrich_entries("", raw_entries)
    return ("CALL GRAPH:\n" + "\n".join(enriched) + "\n") if enriched else ""
```

---

### File 3: Integration vào KG build pipeline

Tìm nơi `_build_call_graph_summary()` được gọi trong `build_context_summary()`, thay bằng `_build_call_graph_with_hist_inv()`.

```python
# Cũ:
call_graph = ContractKGBuilder._build_call_graph_summary(source, known_fns)

# Mới:
from app.services.contract_hist_inv_cache import HistInvCache
cache = HistInvCache(f"{contest_cache_dir}/hist_inv_cache.json")
call_graph = ContractKGBuilder._build_call_graph_with_hist_inv(
    source, known_fns, cache=cache,
    score_threshold=float(os.getenv("HIST_INV_SCORE_THRESHOLD", "0.68")),
)
cache.save()
```

`contest_cache_dir` lấy từ session/run context — cùng folder với `hist_inv_cache.json` per contest.

---

## Cache

**Location**: `benchmark/web3bugs/agent-redesign/<contest_id>/hist_inv_cache.json`
- Contest-level (không phải run-level) — tất cả runs cùng contest dùng chung
- Invalidation tự động: thay đổi source code → CG entry hash khác → cache miss → re-query

**Luồng incremental**:
```
Run N (lần đầu):
  build CG → 50 entries → process 30 entries (fn_name > 4 chars)
  → LLM generate 30 queries (30 LLM calls)
  → RAG query 30 entries → 10 entries score ≥ 0.68
  → LLM extract 10 HIST-INVs (10 LLM calls)
  → cache: 30 entries saved (20 với inv_text="", 10 với inv_text đầy đủ)
  → annotate CG: 10 "↳ HIST:" lines

Run N+1 (code không đổi):
  build CG → 50 entries (identical hash)
  → 30/30 cache hits → 0 LLM calls, 0 RAG queries
  → annotate CG từ cache: 10 "↳ HIST:" lines (instant)

Run N+2 (1 function thay đổi):
  build CG → 1 entry hash mới → 1 cache miss
  → 1 LLM query call + 1 RAG query + 1 LLM extract call
  → 29 cache hits
```

---

## Bảng tóm tắt

| File | Loại | Thay đổi |
|------|------|----------|
| `contract_hist_inv_cache.py` | Mới | Cache manager |
| `contract_kg_builder.py` | Sửa | Thêm `_generate_rag_query()`, `_extract_invariant_from_finding()`, `_build_call_graph_with_hist_inv()` |
| Nơi gọi KG build | Sửa | Swap `_build_call_graph_summary()` → `_build_call_graph_with_hist_inv()` |

---

## Các điểm cần chú ý khi implement

### 1. `call_llm_simple` — cần map sang client thực tế
Hàm này chưa tồn tại. Cần tìm LLM client hiện có trong codebase và wrap lại. Dùng model nhỏ/nhanh (Haiku) vì prompt ngắn, cần nhiều calls.

### 2. `score_threshold = 0.68`
Không hardcode trong logic — truyền qua param với default. Có thể override qua env var `HIST_INV_SCORE_THRESHOLD`. Giá trị 0.68 dựa trên `_SCORE_INJECT_THRESHOLD` đang dùng trong orchestrator — nên giữ nhất quán.

### 3. Filter trivial getter — không dùng length
Rule: skip chỉ khi `fn_name in {'get','set','is','has'}` AND `not ext_markers`.
Lý do: `mint`, `burn`, `swap`, `buy`, `add` đều ≤4 chars nhưng critical — length filter sẽ miss hết.
Có ext_markers → luôn process bất kể tên ngắn thế nào.

### 4. Cache "miss kết quả thấp"
Khi score < threshold, vẫn lưu vào cache với `inv_text=""` để không retry RAG lần sau cho cùng entry. Tránh lãng phí LLM calls trên entries không có RAG coverage.

### 5. `protocol_type` đã bị loại bỏ
Không còn cần detect domain và truyền protocol_type. LLM tự suy từ contract_name + fn_name + ext_markers. Đơn giản hơn, không cần `_detect_domain()`.

---

## Verification

```bash
cd /home/thangdd/repos/MiroFish/backend

# Smoke test
python3 - <<'EOF'
import sys; sys.path.insert(0, '.')
from app.services.contract_kg_builder import ContractKGBuilder
from app.services.contract_hist_inv_cache import HistInvCache
import re

src = open('../benchmark/web3bugs/agent-redesign/42/run-6/contract_summary.txt').read()
m = re.search(r'=== CONTRACT SOURCE ===\n(.*)', src, re.DOTALL)
source = m.group(1) if m else src

cache = HistInvCache('/tmp/test_hist_inv_cache.json')
result = ContractKGBuilder._build_call_graph_with_hist_inv(source, [], cache=cache)
print(result[:3000])
assert '↳ HIST:' in result, "No HIST annotations!"
cache.save()
print(f"Cache: {len(cache._data)} entries")

# Lần 2 — phải instant (0 LLM calls)
result2 = ContractKGBuilder._build_call_graph_with_hist_inv(source, [], cache=cache)
assert result == result2, "Cache not working!"
print("✅ Cache reuse verified")
EOF

# Benchmark contest 42 run-7
nohup bash scripts/run_benchmark.sh \
  /home/thangdd/repos/web3bugs/contracts/42 \
  ../benchmark/web3bugs/agent-redesign/42/run-7 \
  > /tmp/benchmark_42_run7.log 2>&1 &
```

**Dấu hiệu thành công**:
- CALL GRAPH có `↳ HIST:` tại `_buyMochi`, `_buyCRV`, `rangeFeeGrowth`, `_getAmountsForLiquidity`, `burn`
- Cache tạo sau lần đầu, lần 2 instant
- Contest 42 run-7: H-09 (veCRVlock sandwich) lên T1
- Contest 35: H-01, H-05, H-17 được tìm thấy
- FP không tăng đáng kể
