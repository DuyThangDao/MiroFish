# Phase 5 — Invariant-driven RAG

## Bối cảnh & Bài học từ Phase 3–4

### Kết quả các phase trước

| Phase | Kiến trúc | TP | FP | F1 |
|---|---|---|---|---|
| Baseline (no RAG) | Single-turn | 5 | 55 | 0.130 |
| Phase 3 (ReACT) | Agent tự query mid-analysis | 9 | 42 | 0.265 |
| Phase 4 (Post-process) | System query sau FINDING | 7 | 59 | 0.169 |

### Tại sao Phase 3–4 không giải quyết được vấn đề gốc rễ

**Phase 3** tăng F1 do side-effect (agents phân tích kỹ hơn vì phải viết DRAFT_FINDING), không phải do RAG content có ích. Queries quá protocol-specific ("Trident IndexPool _pow") → embedding không match.

**Phase 4** giải quyết query quality nhưng phát hiện ra vấn đề cấu trúc sâu hơn: RAG được inject **sau khi** agent đã quyết định có bug gì. Kết quả:

- RAG chỉ có thể enrich findings đã đúng rồi → không tăng TP
- Turn 2 khuyến khích agents viết thêm findings mới từ historical patterns → FP tăng từ 42 → 59
- Precision giảm từ 0.176 → 0.106

### Root cause cốt lõi

```
RAG-as-enricher:  agent quyết định → RAG confirm/decorate  (bounded by agent's discovery)
RAG-as-discoverer: RAG gợi ý pattern → agent verify in contract  (unbounded by prior analysis)
```

F1 chỉ tăng khi RAG giúp agent **tìm ra bug mới** — không phải khi nó làm description đẹp hơn.

---

## Giải pháp: Invariant-driven RAG

### Ý tưởng cốt lõi

Prompt hiện tại đã có STEP 1 (list invariants) và STEP 2 (find violations). Điểm inject RAG tự nhiên nhất nằm **giữa hai bước này**:

```
FLOW CŨ (single-turn):
  agent đọc contract
  → STEP 1: viết invariants           ← contract-specific, chính xác
  → STEP 2: tìm violations            ← blind, không biết cần tìm pattern gì

FLOW MỚI (invariant-driven, 2-turn):
  TURN 1: agent viết CHỈ invariants
  → SYSTEM: parse invariants → query RAG cho từng invariant
  → SYSTEM: build "violation hint" từ historical findings có score cao
  TURN 2: agent nhận invariants + RAG hints → tìm violations có guided context
```

**Tại sao invariants là query source tốt hơn:**

| Source | Ví dụ query | Vấn đề |
|---|---|---|
| Phase 3: agent query | "Trident IndexPool _pow" | Protocol-specific, noisy |
| Phase 4: FINDING title+desc | "Principal reserves not updated" | Chỉ có sau khi tìm thấy rồi |
| **Phase 5: invariant** | **"reserve must equal sum of token balances"** | **Generic, technical, không protocol-specific** |

Invariants được agent viết ra từ code thực — không chứa tên protocol, chỉ chứa accounting logic. Đây chính xác là loại query embedding model hoạt động tốt nhất.

---

## Thiết kế kỹ thuật

### 1. Turn 1 — Agent viết invariants (lightweight)

Prompt turn 1 chỉ yêu cầu STEP 1:

```
=== ROUND 1 — PHASE A: INVARIANT EXTRACTION ===
[contract source]

STEP 1 — LIST INVARIANTS:
  Liệt kê 3–6 protocol-specific invariants từ code.
  Format: INV-N: <invariant statement>

  Chỉ viết invariants. Không phân tích violations.
```

Response turn 1 rất ngắn (~200–400 tokens):
```
INV-1: After burn(), reserve0 and reserve1 must decrease by the principal amounts transferred out.
INV-2: claimReward() must read incentives using incentiveId, not positionId.
INV-3: secondsPerLiquidity must be updated before any change to global liquidity.
INV-4: The exponent function _pow(a, n) must return a^n for all valid inputs.
```

### 2. System — Parse + Query RAG

```python
def _build_invariant_rag_hints(invariant_text: str, agent_id: str) -> str:
    """Parse invariant lines, query RAG for each, build hint block."""
    inv_pattern = re.compile(r'INV-\d+:\s*(.+)', re.IGNORECASE)
    invariants = inv_pattern.findall(invariant_text)
    if not invariants:
        return ""

    retriever = _get_rag_retriever()
    hints = []

    for i, inv in enumerate(invariants):
        query = build_rag_query("", inv)  # reuse existing cleaner
        if not query:
            continue

        results = retriever.query(query, n_results=3)
        if not results or results[0]["score"] < _SCORE_INJECT_THRESHOLD_INV:
            # Không inject nếu score thấp — agent tự suy luận
            logger.info(
                f"[RAG] agent={agent_id} inv={i+1} score={results[0]['score'] if results else 0:.3f} "
                f"→ skip (below threshold)"
            )
            continue

        top = results[0]
        logger.info(
            f"[RAG] agent={agent_id} inv={i+1} score={top['score']:.3f} "
            f"inv='{inv[:60]}'"
        )

        block = [f"INV-{i+1} historical violations (score={top['score']:.3f}):"]
        for j, r in enumerate(results, 1):
            if r["score"] < _SCORE_SHOW_THRESHOLD:
                break
            preview = r["content"][:350].replace("\n", " ").strip()
            block.append(f"  [{j}] {r['title']} | {preview}")
        hints.append("\n".join(block))

    return "\n\n".join(hints)
```

**Threshold cho Phase 5:** `_SCORE_INJECT_THRESHOLD_INV = 0.75`

Cao hơn Phase 4 (0.68) vì:
- Invariant queries generic hơn → dễ match sai hơn
- Thà không inject hơn inject misleading
- Chỉ inject khi historical finding thực sự liên quan mạnh

### 3. Turn 2 — Agent tìm violations có guided context

```python
hint_block = _build_invariant_rag_hints(turn1_response, profile.agent_id)

if hint_block:
    step2_hint = (
        "\nHISTORICAL VIOLATION PATTERNS from audit database:\n\n"
        f"{hint_block}\n\n"
        "For each INV where a historical pattern is shown above:\n"
        "  - BE SKEPTICAL: Assume the code is SAFE first. Do not force a match.\n"
        "  - Check if THIS contract's code has the EXACT SAME logical flaw.\n"
        "  - Only write a FINDING if you can extract the SPECIFIC CODE LINES proving it.\n"
        "  - If the historical exploit path is blocked or mitigated, EXPLICITLY state 'Mitigated' and skip.\n"
        "For INVs without historical patterns: reason independently.\n"
    )
else:
    step2_hint = ""  # Không có RAG match → agent tự do hoàn toàn

turn2_prompt = f"""\
{original_contract_source}

Your invariants from Phase A:
{turn1_response}
{step2_hint}
STEP 2 — FIND VIOLATIONS:
[... giữ nguyên STEP 2 instruction hiện tại ...]
"""
```

**Điểm quan trọng:** Turn 2 **luôn luôn chạy** vì Turn 1 chỉ extract invariants, chưa phân tích violations. Khi `hint_block` rỗng (không có RAG match đủ tốt), `step2_hint = ""` → Turn 2 tương đương single-turn cũ — agent tự suy luận không bị ảnh hưởng.

### 4. Fallback graceful

```
score < 0.75 → không inject hint cho INV đó → agent tự suy luận (không bị anchoring)
score ≥ 0.75 → inject hint → agent được guided với Devil's Advocate skepticism
hint_block rỗng hoàn toàn → step2_hint = "" → turn 2 = single-turn equivalent

CRITICAL: Turn 2 luôn chạy bất kể hint_block có rỗng hay không.
          Turn 1 chỉ extract invariants, không phân tích violations.
          Bỏ qua Turn 2 = không có output nào.
```

---

## Phân tích rủi ro

### Rủi ro 1: Anchoring bias khi RAG hint sai hướng

**Vấn đề:** Agent nhận hint về overflow → check overflow → "không thấy" → bỏ qua bug thực (underflow wrapping).

**Mitigation:** Threshold cao (0.75) + prompt rõ ràng "For INVs WITHOUT historical patterns: reason independently" → agent không bị anchored vào hints, chỉ dùng như gợi ý thêm.

**Residual risk:** Trung bình. Giảm bằng cách giữ "reason independently" instruction luôn active.

### Rủi ro 2: Invariants sai hoặc quá generic

**Vấn đề:** Agent viết "no reentrancy" thay vì protocol-specific invariant → query RAG với generic term → match kém → không inject (safe fallback).

**Mitigation:** STEP 1 prompt đã có rule chống generic invariants. Nếu agent vẫn viết generic → score thấp → không inject → no harm.

**Residual risk:** Thấp. Worst case là không có RAG benefit, không phải regression.

### Rủi ro 3: DB coverage không đủ đa dạng

**Vấn đề:** H-07 (ConcentratedLiquidityPosition.burn yield theft) — pattern đặc thù, có thể không có trong DB.

**Mitigation:** Với invariant "burn() phải reset accumulated fees về 0", nếu không có match → agent tự suy luận như cũ. RAG không giúp nhưng cũng không cản.

**Residual risk:** Thấp với fallback mechanism.

### Rủi ro 4: Latency tăng (2 turns bắt buộc)

**Vấn đề:** Turn 1 thêm ~30–60s/agent cho tất cả 19 agents.

**Mitigation:** Turn 1 rất ngắn (chỉ invariants, ~300 tokens response) → latency thấp. RAG queries ~100ms × N invariants. Turn 2 có thể ngắn hơn turn 1+2 của Phase 4 vì không cần "CRITICAL REQUIREMENT" force-reproduce.

**Residual risk:** Thấp — tổng latency tương đương Phase 4.

---

## So sánh kiến trúc

| Khía cạnh | Phase 4 (Post-process) | Phase 5 (Invariant-driven) |
|---|---|---|
| RAG trigger timing | Sau khi agent viết FINDING | Giữa STEP 1 và STEP 2 |
| Query source | FINDING title + description | Invariant statement |
| Query quality | Cao (full description) | Cao (generic, no protocol names) |
| Khả năng discover bug mới | ✗ (bounded by turn 1 findings) | ✓ (guided search before analysis) |
| Rủi ro FP inflation | Cao (turn 2 thêm findings mới) | Thấp (agent verify, không enrich) |
| Rủi ro anchoring | Thấp | Trung bình (mitigated by threshold) |
| Fallback khi RAG kém | Agent reproduce turn 1 | Agent tự suy luận (= single-turn) |
| Prompt length | Ngắn (agent không thấy RAG) | Trung bình (+hint block) |

---

## Test Plan

### Bước 1: Unit test invariant parsing + query

```python
from app.services.cyber_session_orchestrator import _build_invariant_rag_hints

inv_text = """
INV-1: After burn(), reserve0 must decrease by the principal amount transferred out.
INV-2: claimReward() must use incentiveId as mapping key, not positionId.
INV-3: _pow(a, n) must return a^n for all n >= 0.
"""

hints = _build_invariant_rag_hints(inv_text, "test_agent")
print(hints)
# Verify: INV-1 match "reserve desync on burn" (score >= 0.75)
# Verify: INV-2 match "incorrect mapping key in reward" (score >= 0.75)
# Verify: INV-3 score < 0.75 → không inject (novel pattern)

# Thêm: test với invariant chứa protocol names (dễ xảy ra nếu agent leak tên protocol vào invariant)
inv_text_noisy = """
INV-1: In Trident ConcentratedLiquidityPool, after burn(), secondsPerLiquidityOutside must be updated.
INV-2: reserve must equal sum of token balances.
"""
hints_noisy = _build_invariant_rag_hints(inv_text_noisy, "test_noisy")
# Verify: build_rag_query đã strip "Trident", "ConcentratedLiquidityPool" khỏi INV-1 query
# Verify: INV-1 query sau clean = "after burn secondsPerLiquidity must be updated" → match tốt hơn
# Verify: INV-2 match "reserve accounting flaw" (generic enough)
```

### Bước 2: Integration test contest 35

```bash
cd /home/thangdd/repos/MiroFish/backend
LOG=/tmp/rag_phase5_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
  source .venv/bin/activate
  V2_DEBUG_DIR=/tmp/r1_debug_p5 AUDIT_PIPELINE_VERSION=v2 STOP_AFTER_DEDUP=true RAG_ENABLED=true \
  exec python -u scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
    --output ./results/rag_phase5_test/contest_35 \
    --verbose
' >> "$LOG" 2>&1 &
echo "PID=$!  LOG=$LOG"
```

**Verify trong log:**
```bash
# RAG được gọi từ invariants (trước STEP 2)
grep "\[RAG\].*inv=" "$LOG"

# Chỉ score >= 0.75 được inject
grep "\[RAG\].*score=0\.[89]\|score=0\.7[5-9]" "$LOG"

# Agents không có RAG match vẫn chạy bình thường
grep "TIMING.*rag_calls=0" "$LOG"
```

### Bước 3: Evaluate F1

```bash
python scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_35.json \
  /tmp/dedup_findings.json --verbose
```

**Pass criteria:**
- F1 ≥ 0.28 (vượt Phase 3: 0.265)
- FP ≤ 45 (không tệ hơn Phase 3: 42)
- Không regression: TP ≥ 9

---

## Câu hỏi mở

**RAG DB có đủ invariant-level coverage không?**
DB hiện tại (~1000 findings từ Solodit) tốt cho DeFi AMM patterns (fee, reserve, swap). Yếu hơn với governance, bridge, novel patterns. Với contest 35 (AMM-heavy), coverage dự kiến tốt.

**Có nên combine với single-turn fallback không?**
Không nên skip Turn 2 dù `hint_block == ""`. Turn 1 chỉ extract invariants, Turn 2 là bước phân tích violations duy nhất — bỏ Turn 2 = không có output. Trường hợp duy nhất có thể skip 2-turn hoàn toàn là nếu `len(invariants) == 0` sau Turn 1, tức agent không extract được gì (rare edge case). Tiết kiệm latency không đáng kể vì Turn 1 rất ngắn (~300 tokens).
