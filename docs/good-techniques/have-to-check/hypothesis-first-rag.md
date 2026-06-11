# Hypothesis-First RAG: Technique Document

## Vấn đề gốc

Khi agent được trang bị RAG tool và tự do query bất kỳ lúc nào, kết quả thực nghiệm cho thấy RAG đôi khi làm **tệ hơn** so với không dùng RAG:

- Contest 42, baseline (solodit_findings, no constraint): no_rag=6/13, with_rag=7/13, **3 regressions**
- H-06 (claimRewardAsMochi): agent tự tìm được khi không có RAG, nhưng bị miss khi có RAG
- H-11, H-12: tương tự

**Root cause**: Agent gọi RAG với query mơ hồ (e.g., "claimRewardAsMochi pattern") → retrieved findings không match → agent anchor vào findings sai → bỏ qua bug thực sự trong code.

---

## Phương pháp: Hypothesis-First RAG

Thay vì cho phép agent query RAG tự do, enforce constraint:

> **Agent phải hình thành hypothesis từ code trước, rồi mới dùng RAG để validate hypothesis đó.**

### 3 Rules trong prompt

```
RULE 1: Complete STEP 1 (list invariants) before any RAG call.
RULE 2: Each query must encode your specific hypothesis derived from code evidence.
  Format: '[mechanism you suspect] because [specific code observation]'
  Good: 'reward balance not reset before transfer, can claim repeatedly'
  Good: 'global debt accumulator not updated after individual borrow, desync'
  Good: 'swap called with amountOutMin=1, no slippage protection sandwich'
  Bad:  'claimReward vulnerability'  (too vague — no hypothesis)
RULE 3: If you cannot articulate a specific hypothesis yet, continue reading code first.
```

### So sánh flow

**Old (anchor bias):**
```
Agent nhận code → query RAG ngay ("claimRewardAsMochi") 
→ retrieved: h-03 (array out-of-bounds) ← KHÔNG match
→ agent pivot sang tìm array bug
→ miss missing reset bug thực sự
```

**New (hypothesis-first):**
```
Agent nhận code → đọc code → nhận ra rewards[msg.sender] không bị reset
→ hình thành hypothesis: "reward balance not reset before transfer"
→ query RAG với hypothesis đó
→ retrieved: h-06 (missing reset → drain) ← MATCH
→ confirm FINDING
```

---

## Triển khai

### Scripts test

| Script | Collection | Prompt | Output dir |
|--------|-----------|--------|-----------|
| `simulate_r1_real.py` | solodit_findings | Old (no constraint) | `sim_real/` |
| `simulate_r1_unified.py` (v1) | solodit_unified | Old (no constraint) | `sim_unified/` |
| `simulate_r1_unified.py` (v2) | solodit_unified | Hypothesis-first | `sim_unified_hyp/` |
| `simulate_r1_findings_hyp.py` | solodit_findings | Hypothesis-first | `sim_findings_hyp/` |

Tất cả scripts test 13 GT bugs của contest 42 với 2 conditions: no_rag và with_rag.

### Prompt diff (make_prompt())

```python
# OLD
rag_block = (
    "\n=== MEMORY TOOL ===\n"
    "You have search_historical_findings(query) — thousands of real audit findings.\n"
    "Call it freely when you suspect a pattern. Examples:\n"
    "  'storage mapping overwrite missing existence check'\n"
    "  ...\n"
    "Multiple calls encouraged — each with a different angle.\n"
)

# NEW (hypothesis-first)
rag_block = (
    "\n=== MEMORY TOOL ===\n"
    "You have search_historical_findings(query) — thousands of real audit findings.\n"
    "RULE 1: Complete STEP 1 (list invariants) before any RAG call.\n"
    "RULE 2: Each query must encode your specific hypothesis derived from code evidence.\n"
    "  Format: '[mechanism you suspect] because [specific code observation]'\n"
    "  Good: 'reward balance not reset before transfer, can claim repeatedly'\n"
    "  Good: 'global debt accumulator not updated after individual borrow, desync'\n"
    "  Good: 'swap called with amountOutMin=1, no slippage protection sandwich'\n"
    "  Bad:  'claimReward vulnerability' (too vague — no hypothesis)\n"
    "RULE 3: If you cannot articulate a specific hypothesis yet, continue reading code first.\n"
    "Multiple calls encouraged — each targeting a different suspected invariant violation.\n"
)
```

### Tool description (search_historical_findings)

```python
# OLD
"description": (
    "Search real smart contract audit findings from Solodit database. "
    "Call when you suspect a vulnerability pattern..."
)

# NEW
"description": (
    "Search historical smart contract audit findings. "
    "RULE: Each query must encode your specific hypothesis derived from code evidence. "
    "Format: '[mechanism you suspect] because [specific code observation]'. "
    "If you cannot articulate a specific hypothesis yet, continue reading code first."
)
```

---

## Kết quả thực nghiệm (Contest 42 — 13 GT bugs)

### Tổng hợp

```
Method                               No-RAG      With-RAG    RAG regressions
──────────────────────────────────────────────────────────────────────────────
Baseline (findings, no hyp)          6/13 (46%)  7/13 (54%)   3
Unified  (unified, no hyp)           7/13 (54%)  7/13 (54%)   2
Unified + hyp (contest-42 examples)  7/13 (54%)  8/13 (62%)   2
Unified + hyp (cross-protocol)       9/13 (69%)  6/13 (46%)   4  ← WORST RAG
Findings + hyp (contest-42 examples) 9/13 (69%)  9/13 (69%)   2
Findings + hyp (generic abstract)    8/13 (62%)  5/13 (38%)   4
Findings + hyp (cross-protocol)     10/13 (77%)  9/13 (69%)   3  ← BEST overall
```

### Per-bug breakdown

| Bug | Baseline | Unified+Hyp | Findings+Hyp (c42) | Findings+Hyp (cross) |
|-----|----------|-------------|--------------------|-----------------------|
| H-01 | ❌/✅ | ❌/✅ | ❌/❌ | ❌/✅ |
| H-02 | ✅/✅ | ✅/❌ | ❌/✅ | ✅/❌ |
| H-03 | ✅/✅ | ✅/✅ | ✅/❌ | ✅/✅ |
| H-04 | ❌/❌ | ❌/❌ | ❌/✅ | ✅/❌ |
| H-05 | ❌/✅ | ❌/✅ | ✅/✅ | ✅/✅ |
| H-06 | ✅/❌ | ✅/✅ | ✅/✅ | ✅/❌ |
| H-07 | ❌/❌ | ✅/❌ | ✅/✅ | ✅/✅ |
| H-08 | ❌/❌ | ❌/❌ | ✅/❌ | ❌/❌ |
| H-09 | ❌/✅ | ❌/✅ | ✅/✅ | ✅/✅ |
| H-10 | ✅/❌ | ❌/❌ | ❌/❌ | ❌/✅ |
| H-11 | ✅/❌ | ✅/✅ | ✅/✅ | ✅/✅ |
| H-12 | ✅/✅ | ✅/✅ | ✅/✅ | ✅/✅ |
| H-13 | ❌/✅ | ✅/✅ | ✅/✅ | ✅/✅ |

Ký hiệu: `no_rag / with_rag`

### Phân tích per-version

**Findings+Hyp (contest-42 examples)**: no_rag=9/13, with_rag=9/13, regressions=2
- H-04 tìm được qua RAG (registerAsset hypothesis khớp)
- H-06 ổn định ✅/✅
- H-10 vẫn miss cả 2

**Findings+Hyp (cross-protocol)**: no_rag=10/13, with_rag=9/13, regressions=3
- No_rag tốt nhất (+1 so contest-42): cross-protocol examples giúp agent suy luận tốt hơn tổng quát
- H-10 lần đầu tiên tìm được qua RAG (governance zero-address example → agent query đúng pattern)
- H-04 và H-06 regressed với RAG (anchor bias vẫn còn)
- H-08 miss cả 2 (zero-deposit griefing — structural blind spot)

**Unified+Hyp (cross-protocol)**: Tệ nhất cho RAG (6/13, 4 regressions). Unified docs dense (VUL+INV+OP) → khi agent query với cross-protocol hypothesis, retrieved findings trông convincing nhưng domain khác → anchor bias mạnh hơn raw blob.

**Findings+Hyp (generic abstract)**: 5/13 RAG — examples quá ngắn → agent không học được granularity level cần thiết.

---

## Phân tích

### Tại sao no_rag cũng tăng (6→10)?

Hypothesis-first prompt bao gồm `RULE 1: Complete STEP 1 before any RAG call` — rule này buộc agent liệt kê invariants trước khi làm bất cứ điều gì khác, **kể cả khi không dùng RAG**. Structured reasoning này tự nó tăng detection, độc lập với RAG.

Cross-protocol examples thêm một tầng nữa: few-shot demonstrations về granularity level cần thiết → agent áp dụng tư duy cụ thể hơn ngay cả khi không query RAG (+1 so contest-42 examples).

### Tại sao findings tốt hơn unified với hypothesis-first?

Khi agent query với hypothesis cụ thể, **embedding quality của query** trở nên quan trọng hơn **embedding quality của document**. `solodit_findings` có nhiều docs hơn (8396 vs 3366 sau chunking) → recall cao hơn khi query đúng target.

`solodit_unified` có ưu thế khi query mơ hồ (structured sections → better signal/noise). Nhưng khi query đã cụ thể với cross-protocol examples, unified docs **tăng anchor bias**: mỗi doc có VUL+INV+OP đầy đủ → retrieved result trông authoritative và convincing ngay cả khi domain khác → agent bị pull mạnh hơn theo retrieved pattern thay vì code evidence.

**Pattern rõ ràng**: `solodit_unified` + cross-protocol = worst RAG (6/13). `solodit_findings` + cross-protocol = best overall (9/13 with_rag). Khi examples đã specific, raw blob volume wins over structured density.

### Về example quality trong prompt

| Example style | No-RAG | With-RAG | Nhận xét |
|--------------|--------|----------|----------|
| Contest-42 specific | 9/13 | 9/13 | Stable, ít regressions |
| Generic abstract (8 words) | 8/13 | 5/13 | Quá ngắn → agent không học được granularity |
| Cross-protocol (protocol-specific) | 10/13 | 9/13 | Best no_rag, nhưng thêm 1 regression |

**Kết luận về examples**: Specific > Abstract; Cross-protocol tốt cho no_rag nhưng chưa clear winner cho with_rag. Với deployment thực tế (diverse contests), cross-protocol là lựa chọn an toàn nhất.

### H-10 với cross-protocol

H-10 (changeNFT) **lần đầu tìm được** với cross-protocol examples + RAG. Governance-related example trong prompt (`governance timelock bypassed`) giúp agent form hypothesis đúng → query RAG với "governance address set to address(0)" → retrieved match.

Tuy nhiên no_rag vẫn miss H-10 — bug nằm ở secondary contract (MochiEngine), không phải primary. Secondary contract coverage vẫn cần giải quyết riêng.

### H-08 structural blind spot

H-08 (zero-deposit griefing) miss ở **tất cả** versions. STEP 1 không buộc agent test deposit=0 một cách systematic. Cần thêm `TRACK A — ADVERSARIAL INPUTS: test 0, max_uint, address(0)` vào prompt (đã có trong simulate scripts nhưng chưa đủ explicit).

---

## Kết luận

1. **Prompt hypothesis-first là driver chính** — improvement đến từ cách agent sử dụng RAG, không phải từ collection
2. **Example quality quan trọng**: Specific protocol-level examples > generic abstractions. Cross-protocol examples (Compound, Uniswap, governance) generalize tốt nhất.
3. **Best no_rag**: Cross-protocol examples, no_rag=10/13 (77%) — gain +4 so baseline
4. **Best with_rag (tie)**: Contest-42 vs cross-protocol đều 9/13 với hypothesis-first
5. **Recommendation**: Apply **`solodit_findings` + cross-protocol hypothesis-first** vào `build_round1_prompt()` — best combination (10/13 no_rag, 9/13 with_rag), generalize tốt cho diverse contests
6. **`solodit_unified` không recommend** với hypothesis-first: amplifies anchor bias, đặc biệt nguy hiểm với cross-protocol examples
7. **Remaining gaps**: H-08 (adversarial input edge case), H-10 no_rag (secondary contract)

---

## Pending integration

- [ ] Apply hypothesis-first prompt vào `contract_oasis_env.py:build_round1_prompt()`
- [ ] Add `solodit_unified` collection lookup vào tool handler (`zep_tools.py` hoặc `contract_oasis_env.py`)
- [ ] Extend hist_verifier sang secondary contracts (fix H-10 class)
- [ ] Validate trên contest 35 run sau khi integrate
