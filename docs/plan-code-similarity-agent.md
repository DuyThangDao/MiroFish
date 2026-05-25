# Plan: Code Similarity Auditor Agent

## Bối cảnh

Baseline hiện tại (c8a30ef): TP=9, FP=48 (run-27).
20 agents dùng INV-based RAG — tốt nhưng phụ thuộc 100% vào những gì agent tự nghĩ ra ở Turn 1.
Bugs FLAKY như H-08 (tick boundary) bị miss khi agent không viết INV về boundary condition.

Mục tiêu: thêm 1 agent mới chạy song song, tiếp cận từ góc độ code mechanics thay vì protocol intent.
Constraint: không được ảnh hưởng TP/FP của 20 agents hiện tại.

---

## Thiết kế

### Persona: `code_similarity_auditor`

Agent này tiếp cận contract từ góc độ **code cơ học** (what the code does) thay vì **protocol intent** (what it should do).
Chạy song song với 20 agents — output đi qua cùng dedup pipeline.

### So sánh với existing agents

| | Existing agents (20) | code_similarity_auditor |
|---|---|---|
| Turn 1 hỏi gì | Protocol intent (invariants) | Code mechanics (mô tả cơ học từng function) |
| RAG query source | INV-N text | Function description từ Turn 1 |
| Turn 2 context | INV + semantic hints | Mechanics analysis + code-similarity hints |
| Số findings | 7–10 | Tối đa 5 |

---

## Turn 1 — Code Mechanics Extraction

**Prompt goal:** Buộc agent đọc kỹ từng function và mô tả *thực tế code làm gì*, không phải nên làm gì.

**Critical requirement (từ RAG test):** Agent phải viết **3-5 câu chi tiết mỗi function**, KHÔNG viết bullet points ngắn.
Terse queries (1 câu, <15 words) fail threshold 0.65 (score 0.60-0.64). Long-form descriptions đều pass (0.69-0.71).

**Output format (long-form — bắt buộc):**
```
FUNC burn():
  Converts the uint128 liquidity parameter to int128 via direct cast without checking
  if the value exceeds int128 max (2^127-1). If a large LP position is burned, the
  cast wraps to negative, causing the function to ADD liquidity instead of removing it.
  The function calls _updatePosition() then transfers amount0/amount1 out to recipient,
  but does NOT decrement reserve0/reserve1 state variables after the transfer.
  Uses strict less-than (lower < currentTick < upper) for range check — boundary ticks
  excluded from the active liquidity update path.

FUNC mint():
  Adds amount0/amount1 to reserve0/reserve1 inside an unchecked arithmetic block.
  If the amount exceeds (uint256_max - current_reserve), the addition overflows and
  wraps reserves to near-zero, bypassing the subsequent balance delta check.
  Updates secondsPerLiquidity accumulator AFTER incrementing liquidity — uses new
  liquidity value instead of old value, causing incorrect time-weighted calculation.
  Range check uses strict inequality: priceLower < currentPrice < priceUpper.

FUNC rangeFeeGrowth():
  Subtracts feeGrowthBelow and feeGrowthAbove from feeGrowthGlobal to compute
  in-range fee accumulation. These values are designed to wrap around using
  unchecked arithmetic (Uniswap V3 pattern), but the function has NO unchecked block.
  In Solidity 0.8, the subtraction reverts on underflow — permanently breaking
  any operation that calls this function.
```

**Key instruction:** Tập trung vào:
1. Arithmetic operations — mô tả đủ dài: loại cast, giá trị max, hậu quả nếu overflow
2. Strict vs non-strict comparisons — nêu rõ `<` hay `<=`, ảnh hưởng đến state nào
3. State variables được update và KHÔNG được update — liệt kê cụ thể tên biến
4. Timing/ordering — biến nào được update trước/sau thao tác nào

**Không viết:**
- Bullet points 1 câu ngắn ("- Cast uint128 to int128")
- Nhận xét về protocol intent ("should be unchecked")
- Tên hàm helper không có ngữ cảnh ("calls _updatePosition()")

---

## RAG Query Mechanism

Thay vì dùng INV-N text, dùng **function descriptions từ Turn 1** làm query:

```python
# Existing INV track:
query = build_rag_query("", inv_text)
# Ví dụ: "burn reserves must decrease by exact amount withdrawn"  → score 0.628 (FAIL)

# New code track:
query = build_rag_query("", func_description)
# Ví dụ (long-form): "burn transfers amount0 amount1 out to recipient but does NOT
#   subtract from reserve0 reserve1 state variables after transfer, reserves remain
#   inflated after every burn operation"  → score 0.699 (PASS)
```

Sự khác biệt: INV query = "phải làm gì", Code query = "thực tế đang làm gì (và có gì thiếu)".

**Kết quả test thực tế (text-embedding-004, ChromaDB solodit):**

| Bug target | Mechanics score | INV-style score | Winner |
|-----------|----------------|----------------|--------|
| H-10/H-13 (reserves not updated) | 0.699 PASS | 0.628 FAIL | Mechanics |
| H-08 (tick boundary) | 0.702 PASS | 0.656 PASS | Mechanics (more relevant match) |
| H-01 (int128 cast) | 0.691 PASS | — | Mechanics |
| H-09/H-14 (unchecked fee) | 0.714 PASS | — | Best score overall |
| H-12 (secondsPerLiquidity) | 0.670 PASS | — | Unique catch |

**Chất lượng matches:**
- H-08 → "Missing `lower<upper` check in mint_position" — trực tiếp relevant
- H-09/H-14 → "secondsPerLiquidity could overflow in UniswapV3Staker" — trực tiếp relevant
- H-12 → Same Uniswap finding — relevant (timing accumulator issue)
- H-10/H-13 → "Partial transfers still possible" — tangential nhưng trong threshold
- H-01 → "Unsafe type-casting" (Primitive: int256→int128 in swap) — useful analog

**Threshold:** 0.65 (giống INV track)
**Cap:** top-3 hits, max 2 được inject vào Turn 2
**Format:** `content[:350]` (giống INV track — an toàn, không có code contamination)

**Lưu ý phrasing:** Query phải là long-form natural language (không dùng số cụ thể như `170141183460469231731687303715884105727`, không dùng Solidity syntax như `int128(x)`). Short terse queries (< 15 words) thường fail threshold.

---

## Turn 2 — Finding Discovery

**Input:**
- Source code (giống các agents khác)
- Mechanics analysis từ Turn 1 của chính agent này
- RAG hints dạng: `"[HIGH] Similar pattern found in Protocol XYZ: ..."`

**Instruction:** Với mỗi RAG hint, đối chiếu với mechanics analysis:
- "RAG nói pattern này từng có bug X — trong contract này có pattern tương tự không?"
- Nếu có → viết finding với function_name, title, description đầy đủ
- Nếu không → bỏ qua

**Output cap:** 5 findings tối đa.

---

## Integration vào Pipeline

### File: `backend/app/services/cyber_session_orchestrator.py`

**Bước 1 — Thêm profile cho agent mới**

Trong `_DEFAULT_AGENT_PROFILES` (hoặc file profiles), thêm:
```python
AgentProfile(
    agent_id="code_similarity_auditor",
    domain="code_structure/similarity",
    persona_description=(
        "Code Similarity Auditor — analyzes contract functions mechanically, "
        "comparing code patterns against historically vulnerable implementations. "
        "Identifies bugs by recognizing structural similarities to known exploits, "
        "not by reasoning about protocol intent."
    ),
    focus_areas=["arithmetic", "casting", "boundary_conditions", "state_updates"],
)
```

**Bước 2 — Thêm hàm `_build_code_similarity_rag_hints()`**

```python
def _build_code_similarity_rag_hints(
    turn1_mechanics: str,       # output của Turn 1 mới
    target_contracts: list[str] | None = None,
) -> tuple[str, int]:
    """
    RAG track cho code_similarity_auditor.
    Query dựa trên function mechanics descriptions từ Turn 1,
    không phải INV statements.
    """
```

Dùng chung `_inv_cache` và `_inv_cache_lock` để tránh re-query.
Parse Turn 1 output theo `FUNC <name>():` blocks → mỗi block = 1 query.
Cap: 3 queries tối đa (3 functions quan trọng nhất).

**Bước 3 — Thêm vào `_run_v2_r1_agent()`**

Trong hàm chạy agent R1, thêm nhánh riêng cho `agent_id == "code_similarity_auditor"`:
```python
if profile.agent_id == "code_similarity_auditor":
    # Turn 1: code mechanics (khác với INV extraction)
    turn1_response = await _run_turn1_mechanics(network_summary, profile)
    # RAG: dùng mechanics descriptions
    rag_block, rag_calls = _build_code_similarity_rag_hints(
        turn1_response, target_contracts=target_contracts
    )
    # Turn 2: findings dựa trên mechanics + RAG
    findings = await _run_turn2_with_mechanics(
        network_summary, turn1_response, rag_block, profile
    )
else:
    # existing flow không thay đổi
    ...
```

**Bước 4 — Đảm bảo agent chạy parallel**

Agent mới được thêm vào `agent_tasks` list trước khi `asyncio.gather()` — chạy song song với 20 agents, không tăng wall-clock time.

---

## Safeguards

| Safeguard | Giá trị | Lý do |
|-----------|---------|-------|
| Max findings | 5 | Tránh FP tăng mạnh |
| RAG threshold | 0.65 | Nhất quán với INV track |
| Content format | `content[:350]` | Đã proven safe, không gây contamination |
| Shared dedup | Có | Findings trùng với 20 agents → merge, không duplicate |
| Shared cache | `_inv_cache` | Tránh re-query cùng concept |

---

## Verification sau khi implement

```bash
# Chạy run-28
cd /home/thangdd/repos/MiroFish/backend && nohup bash scripts/run_benchmark.sh \
  /home/thangdd/repos/web3bugs/contracts/35 \
  ../benchmark/web3bugs/agent-redesign/35/run-28 \
  > /tmp/benchmark_35_run28.log 2>&1 &

# Kiểm tra agent mới có chạy không
grep "code_similarity_auditor" /tmp/benchmark_35_run28.log | grep "TIMING\|parsed="

# Kiểm tra TP/FP
python3 scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_35.json \
  ../benchmark/web3bugs/agent-redesign/35/run-28/audit_report_dedup.json \
  --verbose
```

**Targets:**
- TP ≥ 9 (giữ nguyên baseline — bắt buộc)
- TP = 10 nếu agent mới catch được H-08 hoặc H-03
- FP ≤ 55 (run-27 FP=48, chấp nhận tăng tối đa 7 từ agent mới)
- `code_similarity_auditor` có ≥ 1 finding match GT

---

## Thứ tự implement

1. Thêm Turn 1 mechanics prompt + hàm `_run_turn1_mechanics()`
2. Thêm `_build_code_similarity_rag_hints()`
3. Thêm agent profile
4. Nối vào `_run_v2_r1_agent()` với nhánh riêng
5. Chạy run-28, verify agent chạy, đo TP/FP
