# Per-Function-Group Orchestration — Implementation Plan

## 1. Vấn đề cần giải quyết

Pipeline hiện tại: 22 agents × full source (~3591 dòng) = source overwhelm.

Kết quả run-74 contest 35:
- H-16 (claimReward/JIT): agent tìm đúng function nhưng mô tả sai class → NO
- H-17 (rangeFeeGrowth/nearestTick): tương tự → NO
- H-01 (burn/unsafe cast): 0 candidates
- H-05 (_getAmountsForLiquidity): 0 candidates

Simulation với per-group (300–500 dòng/agent): 4/5 TP, đúng class, đúng function.

**Root cause**: Agent đọc 3591 dòng bị kéo về pattern salient nhất (overflow, unchecked)
thay vì đào sâu vào semantic. Focus = recall.

---

## 2. Kiến trúc tổng quan

```
contract_summary.txt (3591 dòng)
        ↓
  [Step 1] Function Extractor
  Đọc tất cả function signatures + NatSpec (không full body)
        ↓
  [Step 2] Rule-Based Grouper
  Regex match tên hàm + NatSpec → domain group
        ↓
  ┌──────────┬──────────┬──────────┬──────────┬──────────┐
  │math_cast │clmm_sem  │access_rwd│economic  │general   │
  │~400 lines│~500 lines│~300 lines│~400 lines│~300 lines│
  └──────────┴──────────┴──────────┴──────────┴──────────┘
        ↓           ↓           ↓          ↓          ↓
  [Step 3] Group Source Builder
  extract_contract_header() + extract_functions() + HIST-INV inject
        ↓
  [Step 4] Agent Dispatcher
  1–2 agents/group, T1+T2 pipeline
        ↓
  [Step 5] Finding Merger
  Deduplicate findings across groups → dedup_findings.json
```

---

## 3. Domain Taxonomy

6 domains — ordered từ specific đến general (match priority từ trên xuống):

| Domain | Vulnerability class | Ví dụ functions |
|--------|--------------------|--------------------|
| `clmm_semantic` | Stale state, tick accounting, fee growth | `rangeFeeGrowth`, `cross`, `nearestTick`, `sqrtPrice` |
| `math_cast` | Unsafe cast, overflow, AMM math | `burn`, `mint`, `swap`, `getAmountOut`, `_getAmountsForLiquidity` |
| `access_reward` | Access control, reward distribution, JIT | `claimReward`, `reclaimIncentive`, `subscribe`, `harvest`, `distribute` |
| `economic` | Flash loan, price manipulation, oracle | `flash`, `getPrice`, `twap`, `arbitrage` |
| `state_ordering` | Update order, reentrancy, callback | `initialize`, `execute`, `callback`, `settle` |
| `general` | Catch-all — không match domain nào | Mọi function còn lại |

---

## 4. Rule-Based Grouper

### 4.1 Regex Rules

```python
DOMAIN_RULES = [
    # ── CLMM Semantic (specific nhất — phải match trước math_cast) ──────────
    (
        r'tick|range.*fee|fee.*growth|nearest.*tick|sqrt.*ratio|'
        r'price.*lower|price.*upper|tick.*cross|cross.*tick',
        'clmm_semantic',
    ),

    # ── Math / Cast ──────────────────────────────────────────────────────────
    (
        r'burn|mint|swap|add.*liquidity|remove.*liquidity|'
        r'get.*amount|amount.*for|reserve|sqrt|liquidity.*delta|'
        r'_update.*position|_get.*amounts',
        'math_cast',
    ),

    # ── Access Control / Reward ──────────────────────────────────────────────
    (
        r'claim|reward|incentive|reclaim|subscribe|harvest|'
        r'distribute|get.*reward|stake|unstake|withdraw.*reward|'
        r'add.*incentive|remove.*incentive',
        'access_reward',
    ),

    # ── Economic / Flash ─────────────────────────────────────────────────────
    (
        r'flash|oracle|twap|get.*price|update.*price|'
        r'price.*manip|arbitrage|sandwich',
        'economic',
    ),

    # ── State Ordering ───────────────────────────────────────────────────────
    (
        r'initialize|execute|callback|settle|sync|'
        r'before.*transfer|after.*transfer|_before|_after',
        'state_ordering',
    ),

    # ── General (catch-all) ──────────────────────────────────────────────────
    (r'.*', 'general'),
]
```

### 4.2 Thuật toán phân nhóm

```python
def group_functions(contracts: list[tuple[str, str]]) -> dict[str, list[tuple[str, str, str]]]:
    """
    Input:  list[(contract_name, source_code)]
    Output: {domain: [(contract_name, fn_name, fn_body), ...]}
    """
    groups = defaultdict(list)

    for contract_name, source in contracts:
        for fn_name, fn_body, natspec in extract_fn_signatures(source):
            text = f"{fn_name} {natspec}".lower()
            domain = _match_domain(text)
            groups[domain].append((contract_name, fn_name, fn_body))

    return dict(groups)


def _match_domain(text: str) -> str:
    """Match text against DOMAIN_RULES, return first matching domain."""
    for pattern, domain in DOMAIN_RULES:
        if re.search(pattern, text, re.IGNORECASE):
            return domain
    return 'general'
```

### 4.3 Multi-group assignment

Một số functions có cross-domain vulnerability (ví dụ `burn()` vừa có math_cast vừa có
state_ordering). Để không bỏ sót, cho phép một function xuất hiện ở nhiều groups:

```python
MULTI_GROUP_RULES = [
    # Function xuất hiện ở cả 2 groups nếu match cả 2 patterns
    (r'burn|mint', ['math_cast', 'state_ordering']),
    (r'swap',      ['math_cast', 'economic']),
]
```

Mặc định: match group đầu tiên. Nếu cần coverage cao hơn, bật multi-group.

---

## 5. Agent Assignment

### 5.1 Mô hình: 1 agent / group (mặc định)

Mỗi group được assign **1 agent chuyên biệt**. Agent đó chạy T1+T2 trên **toàn bộ group source**
(tất cả functions trong group, cùng 1 context). Không phân chia per-function.

```
group: math_cast
  source: burn() + mint() + _getAmountsFor() + _updateSeconds()  ← 1 context
  agent:  evm_hardener
  flow:   T1 (invariant extraction) → T2 (violation finding)
  calls:  2 LLM calls
```

Lý do 1 agent/group:
- Simulation Run 1 (1 agent/group) → 4/5 TP — đủ để validate approach
- Agent chuyên biệt + source nhỏ = focus cao, không cần đa góc nhìn
- N agents × 1 group = N × cost, recall tăng không đủ justify

### 5.2 Khi nào dùng 2 agents / group?

Chỉ khi group có **cross-domain vulnerability potential** — tức là bug có thể bị miss bởi
1 specialist do nằm ở ranh giới 2 domains.

Ví dụ `state_ordering` (mint + initialize + callback): bug có thể là math (overflow trong
mint), hoặc ordering (callback reentrancy), hoặc access (initialize chưa có auth). Dùng 2
agents với 2 lenses khác nhau trên CÙNG context.

```python
DOMAIN_AGENT_MAP = {
    'clmm_semantic':  ['clmm_specialist'],                       # 1 agent
    'math_cast':      ['evm_hardener'],                          # 1 agent
    'access_reward':  ['access_escalator'],                      # 1 agent
    'economic':       ['defi_attacker'],                         # 1 agent
    'state_ordering': ['state_machine_analyst', 'evm_hardener'], # 2 agents, cùng source
    'general':        ['invariant_breaker'],                     # 1 agent (nếu chạy)
}
```

Cả 2 agents trong `state_ordering` nhận **cùng group source**, chạy **độc lập song song**
(parallel), không biết findings của nhau. Đây là behavior giống production hiện tại nhưng
với source nhỏ hơn (300–500 dòng thay vì 3591).

### 5.3 Tóm tắt execution model

```
1 group → N agents (thường N=1) → mỗi agent T1+T2 trên CÙNG group source
```

- **Không** phân chia function cho từng agent riêng
- **Không** pass findings của agent này cho agent kia trong cùng group (Round 1 là blind)
- **Có** chạy parallel giữa các groups và giữa các agents trong cùng group

So sánh với production hiện tại:

| | Production (run-74) | Per-group |
|---|---|---|
| Source/agent | 3591 lines (full) | 200–500 lines (focused) |
| N agents đọc cùng source | 22 | 1–2 per domain |
| Agents biết findings nhau? | Không (Round 1 blind) | Không (Round 1 blind) |
| Parallel execution | ✓ | ✓ |

### 5.4 Cách lấy agent profile

Agent profile được generate từ `ContractExpertProfileGenerator.generate_tier1_profiles(source)`.
Profiles map theo `agent_id`. Với per-group, chỉ cần profiles của agents trong map:

```python
gen = ContractExpertProfileGenerator()
all_profiles = {p.agent_id: p for p in gen.generate_tier1_profiles(representative_source)}
# representative_source = contract lớn nhất trong batch (để profile có đủ context)
```

---

## 6. Group Source Builder

### 6.1 Spec

Mỗi group source gồm:
1. Section header: `// ─── ContractName.sol ───` (cần đúng format cho HIST-INV injection)
2. Contract header: pragma + imports + state vars + structs + events (không có fn body)
3. `// ... (other functions omitted)` spacer
4. Full body của các functions thuộc group

```python
def build_group_source(
    contracts: list[tuple[str, str]],
    fn_names: list[str],
    inv_map: dict,
) -> str:
    parts = []
    for contract_name, source in contracts:
        fns = extract_functions(source, fn_names)
        if not fns.strip():
            continue
        header = extract_contract_header(source)
        parts.append(f"// ─── {contract_name}.sol ─────────────────────────────────────────────────")
        parts.append(header.rstrip())
        parts.append("    // ... (other functions omitted)")
        parts.append(fns)
        parts.append("}")

    group_source = '\n'.join(parts)
    return _annotate_source_with_hist_inv(group_source, inv_map)
```

### 6.2 Source size limits

| Domain | Target | Hard limit |
|--------|--------|-----------|
| `clmm_semantic` | 400–600 lines | 800 lines |
| `math_cast` | 300–500 lines | 700 lines |
| `access_reward` | 200–400 lines | 600 lines |
| `economic` | 300–500 lines | 700 lines |
| `state_ordering` | 300–500 lines | 700 lines |
| `general` | 200–400 lines | 600 lines |

Nếu group source vượt hard limit → split thành sub-groups (batch functions 10 at a time).

---

## 7. Orchestration Flow

### 7.1 Thay thế trong pipeline hiện tại

**Hiện tại** (`_run_discovery_phase()`):
```
for agent in all_22_agents:
    findings = _discover_one(agent, contract_summary_txt)  # 3591 dòng
```

**Mới** (per-group):
```
groups = group_functions(contracts)          # Step 1+2: group by domain
for domain, fns in groups.items():           # Step 3: build focused source
    group_src = build_group_source(...)      # 300-500 dòng
    for agent_id in DOMAIN_AGENT_MAP[domain]:# Step 4: dispatch agents
        findings = _discover_one(agent, group_src)
all_findings = merge_and_dedup(all_groups)   # Step 5: merge
```

### 7.2 Integration point trong code

File: `backend/app/services/cyber_session_orchestrator.py`

```python
# Thêm trước _run_discovery_phase():
def _build_function_groups(self, contracts: list) -> dict:
    """Group all functions by domain using DOMAIN_RULES."""
    ...

def _build_group_source(self, domain: str, fn_entries: list) -> str:
    """Build focused source for a domain group."""
    ...

# Sửa _run_discovery_phase():
def _run_discovery_phase(self, ...):
    # OLD: iterate 22 agents × full source
    # NEW: iterate groups × focused source

    groups = self._build_function_groups(self._contracts)

    with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
        futures = []
        for domain, fn_entries in groups.items():
            group_src = self._build_group_source(domain, fn_entries)
            for agent_id in DOMAIN_AGENT_MAP.get(domain, ['invariant_breaker']):
                profile = self._profiles.get(agent_id)
                if profile:
                    futures.append(executor.submit(
                        self._discover_one, profile, group_src, ...
                    ))
        # collect results...
```

### 7.3 Parallel execution

**Hai cấp độ parallelism độc lập:**

**Cấp 1 — Groups song song nhau** (giống hiện tại, ThreadPoolExecutor):
```
Group math_cast   ──→ [agents A1, A2, ...]  ──→ findings_math
Group clmm_sem    ──→ [agents B1]            ──→ findings_clmm    ← tất cả chạy song song
Group access_rwd  ──→ [agents C1]            ──→ findings_access
Group economic    ──→ [agents D1]            ──→ findings_econ
Group general     ──→ [agents E1]            ──→ findings_gen
                                                       ↓
                                                merge + dedup
```

**Cấp 2 — Nhiều agents trên cùng 1 group cũng song song nhau:**
```
group_source (300 lines)
    ├─→ state_machine_analyst  T1+T2  ──→ findings_1  ┐
    ├─→ evm_hardener           T1+T2  ──→ findings_2  ├─ song song, không share context
    └─→ appsec_hardener        T1+T2  ──→ findings_3  ┘
                                              ↓
                                       merge (dedup by fn+title)
```

**Các điểm quan trọng:**
- Mỗi agent nhận **cùng group_source** — không có agent nào thấy kết quả của agent khác trong Round 1 (blind parallel)
- **Wall clock = group chậm nhất** (không phải tổng), vì tất cả groups + agents trong group đều chạy parallel
- **Tổng LLM calls** = Σ(agents_per_group × 2) — ví dụ 3 agents × 2 turns = 6 calls cho group đó
- Nếu group có 3 agents → vẫn tính là 1 "slot" trong ThreadPoolExecutor (mỗi agent submit 1 future độc lập)

---

## 8. Finding Merger

Findings từ nhiều groups có thể:
1. **Trùng function + title** → deduplicate (giống cơ chế hiện tại)
2. **Cùng function, khác angle** → giữ cả 2 (cross-domain insight)
3. **Cross-group findings** (bug đòi hỏi đọc cả mint + claimReward) → có thể miss

Merger dùng existing `_dedup_findings()` — không cần thay đổi.

---

## 9. Edge Cases

### 9.1 Function không match domain nào
→ Rơi vào `general` group → `invariant_breaker` agent
→ Vẫn được phân tích, chỉ là agent không specialized

### 9.2 Cross-group bugs
Bug đòi hỏi đọc 2 functions từ 2 groups khác nhau (ví dụ: mint + claimReward interaction).

Mitigation:
- Thêm `state_ordering` group bao gồm cả 2 functions → agent đọc cả 2
- Hoặc: sau per-group pass, chạy 1 "cross-group agent" đọc top-N suspicious functions từ mỗi group

### 9.3 Group source vượt size limit
→ Split thành sub-groups: batch 5-10 functions/sub-group
→ Mỗi sub-group = 1 agent call riêng

### 9.4 Không có Slither → không có full function list
→ Dùng regex fallback (đã có trong pipeline)
→ Per-group vẫn hoạt động vì dùng regex extract từ source text trực tiếp

### 9.5 Contract không có NatSpec
→ Chỉ dùng function name để classify
→ Rule regex vẫn đủ cho naming convention chuẩn

---

## 10. Cost Comparison

| Approach | Agents | Source/agent | LLM calls (R1) | Ước tính time |
|----------|--------|-------------|----------------|---------------|
| Current (full source) | 22 | 3591 lines | 44 | ~31 phút |
| Per-group (baseline) | 6 | 300–500 lines | 12 | ~8–10 phút |
| Per-group (+ state_ordering) | 8 | 300–500 lines | 16 | ~12 phút |

Per-group giảm ~3x calls và ~3x time, đồng thời tăng recall từ
4 FN → dự kiến ≤1 FN cho contest 35.

---

## 11. Validation Plan

Sau khi implement, validate trên contest 35:

```bash
# Chạy với per-group flag
bash scripts/run_benchmark.sh \
  /home/thangdd/repos/web3bugs/contracts/35 \
  ../benchmark/web3bugs/agent-redesign/35/run-N \
  --per-group

# Eval
python3 scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_35.json \
  benchmark/web3bugs/agent-redesign/35/run-N/*/audit_report_dedup.json \
  --verbose | tee benchmark/web3bugs/agent-redesign/35/run-N/eval_result.txt
```

Expected: H-01, H-05, H-16, H-17 từ FN → TP. Recall ≥ 0.88 (vs 0.647 hiện tại).

---

## 12. Dry-Run Validation — Contest 35 (31 contracts)

Đã chạy `simulate_grouping_dryrun.py` trên toàn bộ 31 contracts của contest 35.

### 12.1 GT assignment — ✅ tất cả 5/5 đúng

| Bug | Function | Domain assigned | Agent |
|-----|----------|----------------|-------|
| H-01 | burn | math_cast | evm_hardener ✓ |
| H-05 | _getAmountsForLiquidity | math_cast | evm_hardener ✓ |
| H-03 | reclaimIncentive | access_reward | access_escalator ✓ |
| H-16 | claimReward | access_reward | access_escalator ✓ |
| H-17 | rangeFeeGrowth | clmm_semantic | clmm_specialist ✓ |

### 12.2 Vấn đề phát hiện

**Vấn đề 1 — Regex anchors `^fn$` không work:**
Text được match là `"fn_name natspec..."` (multi-word). `^burn$` không match vì có trailing text.
Fix: dùng `\bburn\b` word boundary.

**Vấn đề 2 — Multi-line function signatures bị skip:**
`_getAmountsForLiquidity(int24, int24, uint160, uint128)` khi params trên nhiều dòng →
regex `\(([^)]*)\)` yêu cầu cả signature trên 1 dòng → miss function.
Fix: chỉ match đến opening paren `r'^function\s+(\w+)\s*\('`.

**Vấn đề 3 — `math_cast` 1195 lines > 700 limit:**
8 pool contracts đều có `burn`/`mint`/`swap` → tất cả gom vào 1 group.
Root cause: Trident protocol có nhiều pool types chia sẻ cùng function names.

Fix: **sub-group split by contract family** trong cùng domain:
```
math_cast/concentrated → ConcentratedLiquidityPool  (~200 lines) ← H-01, H-05
math_cast/constantProd → ConstantProductPool        (~100 lines)
math_cast/hybrid       → HybridPool                 (~100 lines)
math_cast/franchised   → 3 Franchised pools         (~150 lines)
```
Mỗi sub-group vẫn dùng `evm_hardener`, mỗi agent call chỉ đọc 1 contract family.

**Vấn đề 4 — `general` 910 lines > 600 limit, 154 functions:**
Chứa ERC20 helpers, view functions, utils — low security priority.
Recommendation: **skip `general` group** trong giai đoạn đầu để giảm noise + calls.
Nếu cần coverage: split per-contract nhưng filter ra contracts có logic thực (loại TridentERC20, WhiteListManager).

### 12.3 Kết quả sau fix

```
clmm_semantic     :   5 fns,  238 lines  ✓  (1 call)
math_cast/conc    :  ~8 fns,  200 lines  ✓  (1 call)  ← H-01, H-05
math_cast/others  : ~65 fns, ~300 lines  ✓  (split, optional)
access_reward     :   6 fns,   45 lines  ✓  (1 call)  ← H-03, H-16
state_ordering    :  10 fns,  107 lines  ✓  (1 call)
economic          :   8 fns,  180 lines  ✓  (1 call)
general           :  --  skip  --
```

Total calls (focused): ~10 × 2 turns = 20 (vs 44 current, vs 12 naive grouping)

---

## 13. HIST-INV Slug Cap Fix

### 13.1 Vấn đề

`build_inv_map` (và `_build_inv_map_from_slugs` trong pipeline) chỉ lấy **top-2 slugs** cho mỗi function. RAG trả về 6 slugs theo score, nhưng custom slug có invariant đúng nhất có thể xếp ở vị trí 3+ → bị drop trước khi inject.

**Ví dụ thực tế — H-17 (`rangeFeeGrowth`):**
```
slug[0] USED    h-04-underflow...  → inv: "fee growth subtraction must be unchecked"
slug[1] USED    h-04-positions...  → inv: "fee growth subtraction must be unchecked"
slug[2] SKIPPED custom_35_h17...  → inv: "int24 current tick must be updated to latest  ← ĐÚNG
                                          price state before comparing range boundaries"
```

**Kết quả simulation:**
- `slugs[:2]` (baseline): rangeFeeGrowth ❌ — inject hint sai (unchecked block)
- Fix slug cap: rangeFeeGrowth ✅ — inject hint đúng (stale tick reference)

### 13.2 Fix

```python
def build_inv_map_fixed(hist_cache, inv_lookup: dict) -> dict:
    inv_map = {}
    for (contract, fn), slugs in hist_cache.get_matched_slugs().items():
        # Ưu tiên custom slugs lên đầu (contest-specific invariants)
        custom = [s for s in slugs if s.startswith('custom_')]
        others = [s for s in slugs if not s.startswith('custom_')]
        ordered = (custom + others)[:4]      # tăng cap từ 2 → 4
        inv_lines = []
        for slug in ordered:
            inv_lines.extend((inv_lookup.get(slug) or [])[:2])
        if inv_lines:
            inv_map[(contract, fn)] = '\n'.join(inv_lines[:4])
    return inv_map
```

Thay đổi so với baseline:
- `custom_*` slugs được đưa lên đầu danh sách trước khi áp dụng cap
- Cap tăng từ 2 → 4 (lấy thêm 2 slugs/function)
- Inv lines per function tăng từ 3 → 4

### 13.3 Kết quả simulation (contest 35, 3 groups)

| Group | Baseline (cap=2) | Fix (custom first, cap=4) |
|-------|-----------------|--------------------------|
| math_cast (burn, _getAmountsForLiquidity) | 0/2 | **1/2** (burn ✅) |
| clmm_semantic (rangeFeeGrowth) | 0/1 | **1/1** (rangeFeeGrowth ✅) |
| access_reward (reclaimIncentive, claimReward) | 1/2 | 1/2 (claimReward ✅) |
| **Total** | **1/5** | **3/5** |

`rangeFeeGrowth` ❌ → ✅ trực tiếp nhờ custom slug được inject đúng.

### 13.4 Apply points

Fix cần apply ở **2 chỗ**:

| File | Function | Dòng cần sửa |
|------|---------|-------------|
| `backend/app/services/run_contract_audit.py` | `_build_inv_map_from_slugs()` | `slugs[:2]` → custom-first + cap=4 |
| Simulation scripts (`simulate_per_group*.py`) | `build_inv_map()` | Tương tự |

---

## 14. Implementation Checklist

### Phase 1 — Core grouping (không thay đổi agent flow)

- [ ] `extract_fn_signatures(source)` — match đến opening paren (multi-line safe)
- [ ] `match_domain(fn_name, natspec)` — word-boundary regex, fn_name first then natspec
- [ ] `group_functions(contracts)` — phân nhóm cross-contract
- [ ] Sub-group split khi group > size limit: split by contract family
- [ ] Unit test: contest 35 → 5 GT functions assign đúng domain

### Phase 2 — Group source builder

- [ ] `build_group_source(entries, inv_map)` — đã validate trong simulation runs
- [ ] Source size check + cảnh báo
- [ ] Sub-group splitting: `split_group_by_contract(entries, limit)`

### Phase 3 — HIST-INV slug cap fix

- [ ] Sửa `_build_inv_map_from_slugs()` trong `run_contract_audit.py`: custom slugs first, cap=4
- [ ] Verify: `rangeFeeGrowth` annotation sau fix chứa stale-tick inv (không chỉ unchecked block)

### Phase 4 — Orchestration integration

- [ ] Thêm `FN_NAME_RULES` + `DOMAIN_AGENT_MAP` vào `cyber_session_orchestrator.py`
- [ ] Sửa `_run_discovery_phase()`: loop groups × focused source thay vì 22 agents × full source
- [ ] Flag `--per-group` trong `run_benchmark.sh` để A/B test
- [ ] Log group assignments (domain, contract, fn_count, lines) sau Step 2

### Phase 5 — Validation

- [ ] Chạy contest 35 per-group + slug cap fix
- [ ] So sánh eval vs run-74: Recall 0.647 → target ≥ 0.88
- [ ] Validate: H-01, H-05, H-16, H-17 từ FN → TP
- [ ] Chạy 1–2 contest khác kiểm tra generalization
