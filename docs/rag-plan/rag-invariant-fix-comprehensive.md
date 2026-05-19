# Giải Pháp Toàn Diện: RAG Invariant Variance

**Date:** 2026-05-19  
**Dựa trên:** 5 runs contest 35 (TP range 7–13), phân tích log chi tiết từng run  
**Tài liệu phân tích gốc:** `rag-variance-fix.md`, `rag-cap2-evaluation-report.md`

---

## 1. Tóm tắt vấn đề

Hệ thống RAG Phase 5 inject historical findings vào Turn 2 dựa trên invariants từ Turn 1.
Qua 5 runs cùng contest 35, TP dao động **7–13** với cùng codebase — instability quá cao để
đánh giá hoặc publish kết quả.

**Ba root cause xác định qua log:**

| # | Root Cause | Bằng chứng |
|---|-----------|-----------|
| RC-1 | Turn 1 generate invariants về wrong protocols (HybridPool, ConstantProductPool) | 67–85% injections là noise qua 5 runs |
| RC-2 | Khi agents generate đúng CLP INVs, nhiều agent focus cùng 1 aspect → duplicate hints | Run 5: 2/3 CLP hints là `rewardsUnclaimed` x2 |
| RC-3 | Cap=2 conflict: sau khi noise bị loại bỏ, cap cắt đi CLP hints hữu ích | `toke_offensive` run 5: CLP `MAX_TICK_LIQUIDITY` (0.704) bị cap cắt vì 2 noise INVs score cao hơn |

**Hậu quả dây chuyền:**

```
RC-1: Wrong INVs generated
  → RAG query sai target → hint vô dụng → agent miss bugs
    → TP thấp

RC-2: Duplicate INVs pass threshold
  → Cùng 1 hint inject vào 2 agents → coverage breadth không tăng
    → Variance cao dù injection count tương tự

RC-3: Cap=2 với threshold 0.70
  → Khi 2 noise INVs score cao hơn 1 CLP INV → CLP INV bị cắt
    → Chỉ xảy ra khi RC-1 còn tồn tại, hết tác dụng sau khi fix RC-1
```

---

## 2. Kiến trúc giải pháp

### Pipeline trước khi fix

```
Turn 1 (LLM, temp=0.7)
  generate INV-1..6
  ← stochastic: 1-2 CLP-specific, 4-5 HybridPool/IndexPool noise

  ↓ all INVs → RAG query
  67-85% queries → sai target → noise hints injected
  cap=2 → đôi khi cắt CLP hint đúng vì noise score cao hơn

Turn 2 (LLM)
  receives 2 hints, mostly noise → TP=7-13 (variance cao)
```

### Pipeline sau khi fix

```
Turn 1 (LLM, temp=0.7)
  prompt: "SCOPE: only ConcentratedLiquidityPool, ..."   ← FIX-2
  generate INV-1..6 (mostly CLP-specific)

  ↓ INVs pass contract-name filter                        ← FIX-1
  loại bỏ noise còn sót (LLM prompt adherence không 100%)

  ↓ INVs pass semantic dedup (session-level cache)        ← FIX-3
  loại bỏ duplicate: nếu same (contract, concept) đã query → reuse cached hint

  ↓ unique CLP-specific INVs → RAG query
  ~0% noise, ~10-15 unique CLP hints per session

  inject top-4 per agent (cap raised từ 2→4)              ← CAP-ADJUST
  no distractor effect vì tất cả hints CLP-relevant

Turn 2 (LLM)
  receives 3-4 diverse, relevant CLP hints → coverage rộng, variance thấp
```

### Tác động ước tính

| Metric | Hiện tại | Sau fix |
|--------|----------|---------|
| Noise ratio | 67–85% | < 10% (chỉ còn escaped hints) |
| CLP hints/run | 3–5 | 10–15 (unique, diverse) |
| Duplicate hints | 0–2/run | 0 (dedup loại hết) |
| TP range (contest 35) | 7–13 (±3) | Mục tiêu: 11–14 (±1–2) |
| F1 range | 0.165–0.329 | Mục tiêu: 0.28–0.35 stable |

---

## 3. Chi tiết từng fix

### FIX-1: Contract-Name Filter (safety net)

**Vị trí:** `_build_invariant_rag_hints()` trong `cyber_session_orchestrator.py`  
**Khi nào chạy:** Sau Turn 1, trước khi query RAG  
**Logic:** Skip mọi INV không đề cập tên contract đang audit

```python
# Trong loop invariants, thêm trước query = build_rag_query(...)
if target_contracts:
    inv_lower = inv.lower()
    if not any(c.lower() in inv_lower for c in target_contracts):
        logger.info(f"[RAG] agent={agent_id} inv={i+1} → skip (off-target contract)")
        continue
```

**Lưu ý:** `target_contracts` = `[manifest["primary"]] + manifest["secondary"]`.
Với contest 35: `["ConcentratedLiquidityPool", "ConcentratedLiquidityPoolManager", "Ticks", ...]`

---

### FIX-2: Turn 1 Scope Restriction (root fix)

**Vị trí:** `build_round1_prompt()` trong `contract_oasis_env.py`, nhánh `invariant_only=True`  
**Khi nào chạy:** Turn 1 prompt generation  
**Logic:** Inject scope restriction block vào prompt, buộc LLM chỉ viết INVs về target contracts

```python
if target_contracts:
    contract_list = ", ".join(f"`{c}`" for c in target_contracts)
    scope_restriction = (
        f"\n⚠ INVARIANT SCOPE: Generate invariants ONLY about these contracts: "
        f"{contract_list}.\n"
        f"  Do NOT write invariants about protocols from your training data "
        f"(HybridPool, ConstantProductPool, Uniswap, Aave, Compound, etc.) "
        f"unless they are explicitly imported in the code above.\n"
    )
```

**Tại sao đây là root fix:** Giải quyết RC-1 tại nguồn. Nếu Turn 1 generate đúng INVs,
Fix-1 và Fix-3 gần như không cần làm gì.

---

### FIX-3: INV Semantic Deduplication (diversity maximizer)

**Vị trí:** `_build_invariant_rag_hints()` trong `cyber_session_orchestrator.py`  
**Khi nào chạy:** Sau Fix-1, trước khi query RAG  
**Logic:** Session-level cache lưu `(normalized_key → hint_block)`. Nếu same key đã query
trong session này → reuse cached hint, không query lại.

**Key normalization:** Dùng `build_rag_query` có sẵn để clean INV trước khi lấy key — đảm
bảo hai INVs cùng concept (dù khác word order hoặc dài/ngắn) sẽ map về cùng key:

```python
# Module-level session cache (reset mỗi audit session)
_inv_cache: dict[str, tuple] = {}   # key → (score, hint_block)
_inv_cache_lock = threading.Lock()

def _normalize_inv_key(inv: str, target_contracts: list[str]) -> str:
    """Tạo cache key từ INV.

    Dùng build_rag_query để strip backticks, CamelCase contract names, fn signatures,
    dấu câu — trước khi lấy 8 words đầu làm discriminator. Tốt hơn raw split vì:
    - "reserve0 must decrease after burn()" == "must decrease reserve0 balance" → same key
    - Không bị dominated bởi contract name (bị strip bởi CamelCase regex)
    """
    inv_lower = inv.lower()
    matched_contract = next(
        (c for c in target_contracts if c.lower() in inv_lower), "unknown"
    )
    # clean_meaning loại bỏ fn signatures, dotted refs, CamelCase, protocol names
    clean_meaning = build_rag_query("", inv).lower()
    words = clean_meaning.split()
    return f"{matched_contract.lower()}::{' '.join(words[:8])}"
```

**Thread-safety note:** `candidates` là biến local trong mỗi lần gọi `_build_invariant_rag_hints`
— mỗi agent call hàm này độc lập, không share. Race condition chỉ tồn tại ở `_inv_cache`
(shared dict) và đã được bảo vệ bởi `_inv_cache_lock` bao quanh toàn bộ Read+Write block.

**Flow trong `_build_invariant_rag_hints`:**
```python
cache_key = _normalize_inv_key(inv, target_contracts or [])
with _inv_cache_lock:
    if cache_key in _inv_cache:
        # Duplicate INV — reuse cached result, không query lại
        cached_score, cached_block = _inv_cache[cache_key]
        logger.info(f"[RAG] agent={agent_id} inv={i+1} → reuse cache (key={cache_key[:50]})")
        candidates.append((cached_score, cached_block))
        continue

# Query RAG như bình thường
results = retriever.query(query, n_results=3)
# ... build hint block ...
with _inv_cache_lock:
    _inv_cache[cache_key] = (top_score, "\n".join(block))
candidates.append((top_score, "\n".join(block)))
```

**Cache reset:** Mỗi audit session bắt đầu → `_inv_cache.clear()` trong `_run_discovery_round`.

---

### CAP-ADJUST: Raise _MAX_RAG_INJECT_PER_AGENT từ 2 → 4

**Lý do:** Cap=2 được đặt để tránh distractor effect khi nhiều noise INVs pass threshold.
Sau Fix-1 + Fix-2, mọi INVs đều CLP-relevant → không còn distractor effect → cap=2 chỉ
cắt đi coverage breadth.

```python
# cyber_session_orchestrator.py, line 112
_MAX_RAG_INJECT_PER_AGENT = 4   # raised từ 2 — sau Fix-1/2 không còn distractor effect
```

**Tại sao 4 và không phải unbounded:** Giữ giới hạn để tránh context overflow trong Turn 2
(mỗi hint ~400 chars, 4 hints ≈ 1600 chars overhead). 4 là balance giữa coverage và context size.

---

## 4. Thứ tự implement và dependency

```
FIX-2 (prompt restriction)
  ↓ độc lập
FIX-1 (contract filter)        ← cần target_contracts, implement cùng lúc với FIX-2
  ↓ cần FIX-1 hoạt động trước
FIX-3 (dedup cache)            ← cần sau FIX-1 để chỉ cache CLP-specific hits
  ↓ cần tất cả 3 fixes trước
CAP-ADJUST (raise to 4)        ← chỉ raise sau khi noise đã loại bỏ
```

**Đề xuất:** Implement FIX-1 + FIX-2 + CAP-ADJUST cùng 1 commit (nhỏ, ít risk).
FIX-3 trong commit riêng (phức tạp hơn do shared state across threads).

---

## 5. Files cần sửa

### `backend/app/services/contract_oasis_env.py`

| Thay đổi | Dòng hiện tại | Mô tả |
|----------|--------------|-------|
| FIX-2 | `build_round1_prompt()` line 1396 | Thêm `target_contracts` param + scope restriction block |

### `backend/app/services/cyber_session_orchestrator.py`

| Thay đổi | Dòng hiện tại | Mô tả |
|----------|--------------|-------|
| CAP-ADJUST | line 112 | `_MAX_RAG_INJECT_PER_AGENT = 2` → `4` |
| FIX-3 globals | sau line 112 | Thêm `_inv_cache`, `_inv_cache_lock` |
| FIX-1 + FIX-3 | `_build_invariant_rag_hints()` line 177 | Thêm `target_contracts` param, filter + dedup logic |
| FIX-3 reset | `_run_discovery_round()` line 2633 | `_inv_cache.clear()` ở đầu mỗi session |
| Propagate param | `_run_discovery_round()` line 2633 | Thêm `target_contracts` param |
| Propagate param | `_run_contract_audit_v2()` line 2033 | Extract `target_contracts` từ manifest, pass xuống |
| Propagate param | `_discover_one()` line 2666 | Pass `target_contracts` vào `cm["r1_prompt"]()` và `_build_invariant_rag_hints()` |

---

## 6. Verification plan

### Smoke test sau implement

```bash
cd /home/thangdd/repos/MiroFish/backend && source .venv/bin/activate
python -c "
import os; os.environ.setdefault('RAG_ENABLED','true')
from dotenv import load_dotenv; load_dotenv('../.env')
from app.services.cyber_session_orchestrator import _build_invariant_rag_hints, _inv_cache

inv = '''INV-1: In HybridPool, the StableSwap invariant D must hold.
INV-2: In ConcentratedLiquidityPool, reserve0 must decrease after burn().
INV-3: In HybridPool, token balances normalized by decimals.
INV-4: In ConcentratedLiquidityPool, reserve0 must decrease after burn().
INV-5: In ConcentratedLiquidityPoolManager, rewardsUnclaimed must decrease.'''

target = ['ConcentratedLiquidityPool', 'ConcentratedLiquidityPoolManager']
block, n = _build_invariant_rag_hints(inv, 'test', target_contracts=target)
print(f'Injected: {n} hints')
print(f'Cache size: {len(_inv_cache)} entries')
print(block[:300])
# Kỳ vọng: n=2 (INV-2 + INV-5, INV-4 bị dedup với INV-2)
# HybridPool INVs (1, 3) bị filter bởi Fix-1
"
```

**Kỳ vọng:**
- INV-1 và INV-3: bị Fix-1 filter (HybridPool)
- INV-2: pass, query RAG, cache với key `concentratedliquiditypool::in concentratedliquiditypool reserve0 must`
- INV-4: bị Fix-3 dedup (same key với INV-2) → reuse cached result, không query lại
- INV-5: pass (CLPManager rewardsUnclaimed)
- Total injected: 2 (cap=4, nhưng chỉ có 2 unique CLP INVs)

### Full run verification (contest 35)

```bash
LOG=/tmp/rag_fix123_35_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
  cd /home/thangdd/repos/MiroFish/backend
  source .venv/bin/activate
  AUDIT_PIPELINE_VERSION=v2 STOP_AFTER_DEDUP=true RAG_ENABLED=true \
  exec python -u scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
    --output ./results/fix123_test/contest_35 \
    --verbose
' >> "$LOG" 2>&1 &
echo "PID=$!  LOG=$LOG"

# Sau khi xong — kiểm tra tỷ lệ CLP-specific vs noise:
grep "\[RAG\]" "$LOG" | grep -v skip | grep -iv "ConcentratedLiquidity\|nearestTick\|feeGrowth\|secondsPerLiq" | wc -l
# Kỳ vọng: < 3 (so với 8-17 hiện tại)

# Eval
python scripts/evaluate/web3bugs_eval.py scripts/evaluate/gt/gt_35.json /tmp/dedup_findings.json
# Kỳ vọng: TP ≥ 11 stable, F1 ≥ 0.28
```

### Pass criteria để confirm fix có tác dụng

| Metric | Trước fix (5 runs avg) | Mục tiêu sau fix |
|--------|----------------------|-----------------|
| Noise ratio | 67–85% | < 15% |
| CLP-specific hits/run | 3–5 | ≥ 8 |
| Duplicate hits/run | 0–2 | 0 |
| TP range (3 runs) | 7–13 (±3) | 10–14 (±2) |
| F1 mean | ~0.22 (cap=2 avg) | ≥ 0.28 |

---

## 7. Vấn đề còn lại sau fix (không giải quyết được)

| Vấn đề | Lý do không fix trong scope này |
|--------|--------------------------------|
| Hard misses: H-05, H-11, H-15, H-17 (0/5 runs) | RAG DB không có tương tự; cần thêm data hoặc reasoning cải tiến |
| FP cao (~50-60/run) | Vấn đề riêng của consensus gate, không liên quan RAG invariant |
| ~20% variance inherent | Model stochasticity trong Turn 2 reasoning — không addressable |
| Prompt adherence < 100% | LLM có thể vẫn "trôi" sang HybridPool → Fix-1 là safety net cho trường hợp này |
