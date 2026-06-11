# Per-Function-Group Orchestration

## Vấn đề hiện tại

22 agents mỗi agent đọc **toàn bộ** `contract_summary.txt` (3591 dòng, 150KB, 23 contracts).
Kết quả: agent bị overwhelmed → focus vào pattern nổi bật nhất (overflow/unchecked), miss semantic bugs.

Ví dụ contest 35:
- `clmm_specialist` có built-in knowledge về JIT + nearestTick stale
- Isolated (1 contract, 700 dòng): ✅ tìm H-16, H-17
- Full pipeline (3591 dòng): ❌ miss H-16, H-17 — bị kéo về overflow pattern

---

## Ý tưởng: Per-Function-Group

Thay vì mỗi agent đọc full source, **Orchestrator** đọc signatures + NatSpec để phân nhóm functions theo domain, sau đó tạo batched agents — mỗi agent chỉ đọc group của mình.

```
contract_summary.txt (3591 dòng)
        ↓
  Orchestrator
  (đọc signatures + NatSpec only, không full body)
        ↓
  ┌─────────────────────────────────────────────┐
  │ Group 1  │ Group 2  │ Group 3  │ ...        │
  │ math/cast│ clmm sem.│ access/  │            │
  │          │          │ reward   │            │
  └─────────────────────────────────────────────┘
        ↓           ↓           ↓
  evm_hardener  clmm_spec  access_esc
  inv_breaker              defi_attacker
  (300-500 dòng mỗi group)
```

---

## Thiết kế Orchestrator

### Input
Chỉ đọc **function signatures + NatSpec** của toàn bộ contracts — không full body.
Ví dụ:
```
// ConcentratedLiquidityPool
function burn(int24 lower, int24 upper, uint128 amount) external lock returns (...)
function mint(MintParams memory params) public lock returns (uint256 liquidityMinted)
function rangeFeeGrowth(int24 lowerTick, int24 upperTick) public view returns (...)
function swap(bytes calldata data) public lock returns (uint256 finalAmountOut)

// ConcentratedLiquidityPoolManager
function reclaimIncentive(IConcentratedLiquidityPool pool, uint256 incentiveId, ...) external
function claimReward(IConcentratedLiquidityPool pool, ...) external
```

### Task
Với mỗi function, orchestrator quyết định:
1. **Domain group** (math/cast / clmm-semantic / access-control / state-ordering / economic / ...)
2. **Agent(s)** phù hợp

### Output
JSON map: `function → {group, agents, contract}`

---

## Function Groups (ví dụ contest 35)

| Group | Functions | Agents | Source size |
|-------|-----------|--------|-------------|
| `math_cast` | burn, mint, _getAmountsForLiquidity, swap, _updateSecondsPerLiquidity | evm_hardener, invariant_breaker | ~400 dòng |
| `clmm_semantic` | rangeFeeGrowth, cross (Ticks), initialize, collect | clmm_specialist | ~350 dòng |
| `access_reward` | reclaimIncentive, claimReward, subscribe, addIncentive, getReward | access_escalator, defi_attacker | ~300 dòng |
| `state_ordering` | mint, burn, swap (ordering invariants) | state_machine_analyst, appsec_hardener | ~400 dòng |
| `economic` | swap, flash, claimReward | economic_attacker, flash_loan_specialist | ~400 dòng |

**Một function có thể xuất hiện ở nhiều groups** nếu nó có nhiều attack surface.

---

## Cost so sánh

| Approach | LLM calls (R1) | Source/call | Wall time (ước tính) |
|----------|---------------|-------------|----------------------|
| Current (22 agents, full source) | 22 × 2 = 44 | 3591 dòng | ~31 phút |
| Per-contract (4 primaries) | 22 × 4 × 2 = 176 | ~900 dòng | ~2.5 giờ |
| **Per-function-group** | **~8-10 × 2 = ~20** | **300-500 dòng** | **~15-20 phút (ước tính)** |

Per-function-group có thể **ít calls hơn current** (20 vs 44) vì:
- Không cần chạy tất cả 22 agents — chỉ chạy agents relevant cho từng group
- Mỗi group ~2-3 agents thay vì 22

---

## Ưu điểm

1. **Focus**: mỗi agent chỉ đọc ~300-500 dòng thay vì 3591 → không overwhelm
2. **Cost tương đương hoặc thấp hơn current**: ~20 calls vs 44
3. **Agent-function matching**: clmm_specialist chỉ đọc CLM functions → không bị distract bởi ConstantProductPool
4. **Orchestrator nhẹ**: chỉ đọc signatures, không full body → latency thấp

## Nhược điểm

1. **Cross-function bugs có thể bị miss**: bug đòi hỏi đọc cả `mint()` + `claimReward()` trong cùng 1 context
   - Mitigation: group `state_ordering` và `economic` include functions từ nhiều contracts
2. **Orchestrator classification errors**: nếu orchestrator xếp nhầm group → bug miss
   - Mitigation: orchestrator có thể xếp 1 function vào nhiều groups
3. **Implementation complexity**: cần viết orchestrator + group-based context builder

---

## Implementation Plan (khi triển khai)

### Bước 1 — Orchestrator prompt
```
Đọc function signatures và NatSpec.
Với mỗi function, output JSON:
{
  "function": "rangeFeeGrowth",
  "contract": "ConcentratedLiquidityPool",
  "domain": "clmm_semantic",
  "agents": ["clmm_specialist"],
  "reason": "Uses tick references for fee growth — potential stale state"
}
```

### Bước 2 — Group builder
- Group functions by `domain`
- Extract source code của chỉ các functions trong group (không full contract)
- Thêm context cần thiết: storage variables, struct definitions, events

### Bước 3 — Batched agents
- Chạy parallel các groups
- Mỗi agent nhận: group source + role-appropriate system prompt
- Thu thập findings → merge vào pipeline thông thường

---

## So sánh với ý tưởng khác

| | Per-function-group | Per-function (sub-agents) | Single full-persona agent |
|---|---|---|---|
| Focus | Tốt (300-500 dòng) | Rất tốt (50-200 dòng) | Kém (full source) |
| Cross-function bugs | Partially | Miss | OK |
| Cost | ≤ current | 2-3x đắt hơn | Rẻ nhất |
| Independence | Tốt | Tốt | Kém (blend personas) |
| Complexity | Moderate | Cao | Thấp |

**Per-function-group = sweet spot** giữa focus, cost, và cross-function coverage.

---

## Trạng thái

- [ ] Chưa implement
- [ ] Cần simulate: đo latency difference khi pass 300 dòng vs 3591 dòng
- [ ] Cần validate: orchestrator classification quality trên contest 35
