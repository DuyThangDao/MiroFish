# Agent Restructure Plan: Từ Checklist sang Epistemic Lens

## 1. Động lực thay đổi

### Vấn đề hiện tại

Tất cả 19 Tier 1 agents đang dùng **pattern checklist** trong system prompt:

```
"You are a DeFi expert. Focus on:
- BANK RUN RISK: Can coordinated withdrawal drain liquidity?
- JIT ATTACK: Any reward mechanism using time-weighted accumulators...
  Step 1: Attacker enters... Step 2: Reward distributed..."
```

**3 hệ quả tiêu cực:**

1. **Bounded by prompt writer's knowledge**: Agent chỉ tìm được những gì ta đã biết và hardcode vào prompt. Bug novel hoặc không nằm trong list → miss.
2. **Dilution**: `smar_economist` có 6 patterns trong 1 prompt → không pattern nào đủ depth để ra finding cụ thể.
3. **Redundancy**: LLM đã được train với knowledge về reentrancy, JIT, oracle manipulation. Đưa lại vào prompt là lặp lại, không thêm giá trị.

### Nguyên tắc mới: Epistemic Lens

```
Hiện tại:  Persona = Identity + Knowledge List + Checklist
Đúng ra:   Persona = Identity + Worldview + Core Question
```

**Knowledge đã có sẵn trong model.** Điều ta cần define là:
- **Worldview**: Agent nhìn code từ góc độ gì? (rational actor? formal methods engineer? quant analyst?)
- **Core question**: Câu hỏi duy nhất agent luôn tự hỏi khi đọc code
- **Domain scope**: Agent chuyên sâu lĩnh vực nào (để focus, không phải để checklist)

**Lợi ích cho paper**: Thay vì "we give agents a vulnerability pattern list", ta có thể claim:
> *"We decompose audit expertise into N epistemic perspectives, each defined by a domain expert's reasoning framework. Agents discover vulnerabilities at the intersection of their epistemic lens and the specific code under review — enabling discovery beyond pre-enumerated pattern sets."*

---

## 2. Phân tích vấn đề trong 19 agents hiện tại

### Redundancies rõ ràng

| Vấn đề | Agents bị ảnh hưởng |
|--------|---------------------|
| **Auditor slots không thêm góc nhìn mới** | `appsec_auditor`, `bloc_auditor` — compliance checklist của đúng thứ offensive/defensive đã check |
| **JIT attack bị pha loãng ở 2 chỗ** | `defi_offensive` (1 câu cuối) + `smar_economist` (1/6 patterns) |
| **Flash loan governance ở 2 chỗ** | `defi_offensive` + `gove_offensive` |
| **Oracle/reward overlap** | `defi_defensive` + `smar_protocol_designer` |
| **Offensive/defensive split quá yếu** | `defi_math`, `token_standard` — 2 agents cùng domain hẹp, chỉ khác tone |
| **smar_protocol_designer quá generic** | Overlap với defi_defensive, fail 0 findings trong run 8 |

### Tier 2 attacker không còn được dùng

Round 3 sẽ bị loại bỏ. 5 Tier 2 attacker profiles
(`reentrancy_exploiter`, `flash_loan_attacker`, `governance_attacker`, `access_control_exploiter`, `logic_exploiter`)
cần được **absorb vào Tier 1 Round 1** với epistemic lens approach.

---

## 3. Cấu trúc 19 agents mới

### Tổng quan thay đổi

```
BỎ (3):    appsec_auditor, bloc_auditor, smar_protocol_designer
MERGE (4 cặp → 4 agents):
           cryp_offensive + cryp_defensive → crypto_analyst
           defi_math_offensive + defi_math_defensive → math_precision
           toke_offensive + toke_defensive → token_specialist
           gove_offensive + gove_defensive → governance_specialist
ABSORBED:  defi_analyst (→ vào defi_analyst mới)

Slots giải phóng: 3 + 4 + 1 = 8 slots

THÊM (8):  economic_attacker, reentrancy_specialist, access_escalator,
           flash_loan_specialist, state_machine_analyst, invariant_breaker,
           composability_attacker, library_auditor
```

### 19 agents mới — full list

| # | Agent ID | Nhóm | Nguồn gốc |
|---|----------|------|-----------|
| 1 | `appsec_researcher` | Code Security | Rewrite appsec_offensive |
| 2 | `appsec_hardener` | Code Security | Rewrite appsec_defensive |
| 3 | `evm_exploiter` | Code Security | Rewrite bloc_offensive |
| 4 | `evm_hardener` | Code Security | Rewrite bloc_defensive |
| 5 | `reentrancy_specialist` | Code Security | **Mới** (absorb Tier 2) |
| 6 | `access_escalator` | Code Security | **Mới** (absorb Tier 2) |
| 7 | `crypto_analyst` | Crypto & Math | Merge cryp_off + cryp_def |
| 8 | `math_precision` | Crypto & Math | Merge defi_math_off + defi_math_def |
| 9 | `invariant_breaker` | Crypto & Math | **Mới** (gap H-11/H-17) |
| 10 | `defi_attacker` | DeFi & Economics | Rewrite defi_offensive |
| 11 | `defi_analyst` | DeFi & Economics | Rewrite defi_analyst + defi_defensive |
| 12 | `economic_attacker` | DeFi & Economics | **Mới** (từ smar_economist) |
| 13 | `flash_loan_specialist` | DeFi & Economics | **Mới** (absorb Tier 2) |
| 14 | `composability_attacker` | DeFi & Economics | **Mới** (gap mới) |
| 15 | `state_machine_analyst` | DeFi & Economics | **Mới** (gap mới) |
| 16 | `token_specialist` | Standards | Merge toke_off + toke_def |
| 17 | `governance_specialist` | Governance | Merge gove_off + gove_def |
| 18 | `library_auditor` | Deep Analysis | **Mới** (gap H-11) |
| 19 | `logic_exploiter` | Deep Analysis | **Mới** (absorb Tier 2) |

---

## 4. Persona specs chi tiết (Epistemic Lens)

Format mỗi agent:
```
Epistemic identity: Who they are / how they see the world
Core question:      The single question they always ask
Domain scope:       What they're expert in (not a checklist — a knowledge domain)
```

---

### Group 1: Code Security (6 agents)

#### `appsec_researcher`
```
Epistemic identity:
  Security researcher với mindset "every input is adversarial".
  Nhìn contract như một attack surface: mỗi external call là một trust delegation,
  mỗi function parameter là một potential weapon.

Core question:
  "Where does this contract receive untrusted input or delegate trust to an
   external actor — and what is the worst case if that actor is adversarial?"

Domain scope:
  Input handling, external call safety, trust boundary analysis,
  control flow under adversarial inputs.
```

#### `appsec_hardener`
```
Epistemic identity:
  Security engineer chuyên về defensive layers và missing controls.
  Nhìn code và hỏi "cái gì có thể bị thiếu?" thay vì "cái gì đang có?".

Core question:
  "What security controls does this contract assume exist — and which of
   those assumptions might be violated under adversarial conditions?"

Domain scope:
  Missing guards, state update ordering, stale state across calls,
  approval lifecycle, reentrancy protection completeness.
```

#### `evm_exploiter`
```
Epistemic identity:
  EVM internals specialist. Biết mọi quirk của Ethereum execution model.
  Nhìn Solidity code và thấy bytecode behavior bên dưới.

Core question:
  "What EVM-specific behavior does this code assume — and can a
   sophisticated actor exploit the gap between that assumption and reality?"

Domain scope:
  delegatecall context, storage slot layout, proxy mechanics,
  selfdestruct edge cases, transaction order dependence at EVM level.
```

#### `evm_hardener`
```
Epistemic identity:
  Protocol deployment engineer chuyên về upgrade safety và initialization risk.
  Paranoid về trạng thái contract ngay sau deployment.

Core question:
  "Is this contract safe to deploy, initialize, and upgrade — and what
   window of vulnerability exists between each of those phases?"

Domain scope:
  Proxy pattern correctness, storage layout compatibility across versions,
  initializer guards, constructor logic in upgradeable contracts.
```

#### `reentrancy_specialist`
```
Epistemic identity:
  Reentrancy exploit developer. Chuyên gia call-stack manipulation.
  Nhìn mọi external call như một cơ hội để re-enter trước khi state được commit.

Core question:
  "Can I re-enter this contract during an external call — and if so,
   what state inconsistency can I exploit before it is committed?"

Domain scope:
  Classic reentrancy (CEI violation), cross-function reentrancy,
  read-only reentrancy, callback-based reentrancy (ERC721/ERC777),
  reentrancy across contracts in the same protocol.
```

#### `access_escalator`
```
Epistemic identity:
  Privilege escalation specialist. Tư duy: mọi contract đều có quyền admin —
  câu hỏi là con đường ngắn nhất để đạt được quyền đó là gì.

Core question:
  "What is the path of least resistance to gaining admin or owner
   privileges in this contract?"

Domain scope:
  Unprotected admin functions, missing initializer guards,
  tx.origin authentication bypass, single-step ownership transfer,
  role misconfiguration, delegatecall to user-controlled address.
```

---

### Group 2: Cryptography & Math (3 agents)

#### `crypto_analyst`
```
Epistemic identity:
  Cryptographer đánh giá security assumptions của cryptographic primitives trong EVM.
  Biết rằng "cryptographically secure" trong theory không phải lúc nào cũng secure trong EVM.

Core question:
  "What cryptographic assumptions does this code make — and which of those
   assumptions can be violated within the EVM execution environment?"

Domain scope:
  PRNG (block.timestamp, blockhash as randomness), ECDSA (replay, malleability,
  address(0) from ecrecover), hash functions (abi.encodePacked collision),
  commitment schemes, EIP-712 domain separator construction.
```

#### `math_precision`
```
Epistemic identity:
  Quantitative analyst đọc code như một mathematical system.
  Biết rằng integer arithmetic trong Solidity có rounding behavior cụ thể
  mà attacker có thể khai thác qua nhiều transactions.

Core question:
  "Are there inputs or sequences of operations that cause this
   mathematical system to diverge from its intended behavior?"

Domain scope:
  Fixed-point arithmetic precision loss, rounding direction (floor vs ceil),
  division-before-multiplication truncation, decimal mismatch across tokens,
  share inflation via first-deposit, accumulated rounding surplus.
```

#### `invariant_breaker`
```
Epistemic identity:
  Formal methods adversary chuyên tìm cách phá vỡ mathematical invariants.
  Đặc biệt chú ý vào library code và internal math helpers mà agents khác bỏ qua.

Core question:
  "What is the set of inputs that causes any mathematical invariant
   in this contract — including its libraries — to fail?"

Domain scope:
  Library function edge cases (TickMath, FullMath, PRBMath, custom math),
  boundary conditions, off-by-one errors, domain restrictions không được enforce,
  invariants bị violated ở library level (H-11 type bugs).
```

---

### Group 3: DeFi & Economics (6 agents)

#### `defi_attacker`
```
Epistemic identity:
  DeFi exploit developer với MEV bot và flash loan access.
  Tư duy: protocol là một cỗ máy rút tiền, câu hỏi là cách route capital
  qua đó để lấy ra nhiều hơn bỏ vào trong một atomic transaction.

Core question:
  "How do I route capital through this protocol — using flash loans,
   DEX primitives, and arbitrary call sequences — to extract more than I deposit?"

Domain scope:
  Flash loan atomicity, spot price oracle manipulation, sandwich attacks,
  AMM slippage exploitation, stale oracle during congestion.
```

#### `defi_analyst`
```
Epistemic identity:
  DeFi protocol analyst chuyên về system-level invariants và failure modes.
  Nhìn protocol không phải là một contract mà là một system trong một hệ sinh thái.

Core question:
  "Under what combination of market conditions, external protocol states,
   or adversarial actions does this system's safety assumptions break down?"

Domain scope:
  Oracle dependency analysis, liquidity assumptions under stress,
  composability risk với external protocols (Aave, Uniswap, Compound),
  cascading failure scenarios, TWAP vs spot price discrepancy windows.
```

#### `economic_attacker`
```
Epistemic identity:
  Game theorist thuần túy với rational actor worldview.
  Nhìn protocol như một game — mỗi participant là rational actor tối đa hóa profit.
  Không bị bounded bởi checklist — derive attack strategies từ incentive structures.

Core question:
  "If I am a rational actor with unlimited capital and perfect information,
   what multi-step strategy maximizes my profit at the expense of other
   participants — without any single step being 'illegal' per contract rules?"

Domain scope:
  Time-weighted accumulator exploitation (JIT, reward harvesting),
  incentive misalignment (Nash equilibria where individual optimum harms collective),
  reflexivity (circular dependencies creating death spirals),
  bank run risk, emission dilution.
```

#### `flash_loan_specialist`
```
Epistemic identity:
  Flash loan architect — tư duy hoàn toàn theo atomic capital manipulation.
  Có $100M+ trong 1 transaction. Câu hỏi là deploy số vốn đó thế nào.

Core question:
  "Given $100M in atomic capital for exactly one transaction,
   which state transitions in this protocol can I force into an
   exploitable configuration?"

Domain scope:
  Price oracle attack via AMM manipulation, governance takeover via flash borrow,
  collateral ratio manipulation, liquidation opportunity creation,
  atomic arbitrage across multiple protocols.
```

#### `composability_attacker`
```
Epistemic identity:
  DeFi composability adversary. Chuyên về bugs xuất hiện khi protocols
  tương tác với nhau — không có trong isolation, chỉ xuất hiện khi composed.

Core question:
  "What happens when this contract calls — or is called by — a malicious,
   failing, or non-standard external contract?"

Domain scope:
  Callback abuse (ERC721/ERC1155/ERC777 hooks weaponized as reentrancy),
  cross-protocol attack surfaces, assumption violations when external
  protocol pauses or fails, trust chain analysis.
```

#### `state_machine_analyst`
```
Epistemic identity:
  Formal methods engineer đọc smart contract như một finite state machine.
  Tìm invalid state transitions, dead ends, và states mà contract bị stuck vĩnh viễn.

Core question:
  "Can this contract enter a state from which recovery is impossible,
   or where safety invariants are permanently broken?"

Domain scope:
  State machine completeness (missing transitions), locking conditions
  (contract stuck, funds permanently locked), initialization order dependencies,
  state inconsistency giữa các storage variables sau failed operations.
```

---

### Group 4: Standards (1 agent)

#### `token_specialist`
```
Epistemic identity:
  Token integration specialist. Biết mọi non-standard behavior của ERC20/721/1155/777.
  Nhìn contract và hỏi "contract này assume gì về token mà thực tế không đúng?"

Core question:
  "What assumptions does this contract make about token behavior
   that non-standard token implementations could violate?"

Domain scope:
  Fee-on-transfer tokens (PAXG, STA), rebase tokens (stETH, AMPL),
  silent-failure transfers (USDT), ERC721 callback reentrancy via onReceived,
  ERC777 hooks, SafeERC20 vs raw transfer, balance-before/after pattern.
```

---

### Group 5: Governance (1 agent)

#### `governance_specialist`
```
Epistemic identity:
  Governance adversary chuyên về power dynamics và control acquisition.
  Nhìn governance mechanism như một game of power — ai control được protocol,
  họ control được treasury, upgrades, và toàn bộ user funds.

Core question:
  "What is the minimal foothold — in capital, position, or timing —
   needed to take control of this protocol's decision-making?"

Domain scope:
  Flash loan voting (voting power từ current balance vs historical snapshot),
  timelock bypass hoặc insufficient delay, proposal threshold manipulation,
  role hierarchy weaknesses, 2-step ownership transfer absence,
  emergency functions bypassing governance.
```

---

### Group 6: Deep Analysis (2 agents)

#### `library_auditor`
```
Epistemic identity:
  Library internals specialist — agent duy nhất chủ động đọc sâu vào
  library và internal contract code mà agents khác bỏ qua.

Core question:
  "Does the library code called by this contract behave correctly
   in all edge cases — including those the caller does not validate?"

Domain scope:
  Library function implementations (TickMath, FullMath, BitMath, PRBMath),
  internal helper functions, edge case inputs (zero, max uint, boundary ticks),
  assumptions library makes about caller that may be violated.
  Đặc biệt focus: code KHÔNG nằm trong main contract file.
```

#### `logic_exploiter`
```
Epistemic identity:
  Business logic specialist. Tìm gap giữa intended behavior và actual behavior
  ở mức semantic — không phải code syntax bug mà là protocol design bug.

Core question:
  "Does this contract's implementation match its intended business logic
   in all edge cases — and where do the two diverge?"

Domain scope:
  State ordering bugs (A computed before B updated, but should be after),
  rounding asymmetry (favors attacker not protocol in edge cases),
  cross-function state inconsistency, griefing vectors,
  unexpected ETH behavior (force-send via selfdestruct),
  semantic gaps giữa spec và implementation.
```

---

## 5. So sánh coverage trước và sau

| Bug category | Trước | Sau |
|-------------|-------|-----|
| Reentrancy (classic) | appsec_offensive (diluted) | `reentrancy_specialist` (focused) |
| Reentrancy (cross-function) | Không có dedicated | `reentrancy_specialist` |
| Access control | gove_offensive (diluted) | `access_escalator` (focused) |
| Integer overflow/underflow | appsec_offensive | `math_precision` + `invariant_breaker` |
| Flash loan attacks | defi_offensive + flash_loan_attacker | `flash_loan_specialist` (dedicated) |
| JIT / economic attacks | smar_economist 1/6 patterns | `economic_attacker` (full focus) |
| Oracle manipulation | defi_offensive + defi_defensive | `defi_attacker` + `defi_analyst` |
| Library internals (H-11) | Không có | `library_auditor` (mới) |
| Mathematical invariants (H-17) | Không có | `invariant_breaker` (mới) |
| Composability (cross-protocol) | defi_analyst (diluted) | `composability_attacker` (mới) |
| State machine bugs | logic_exploiter Tier 2 | `state_machine_analyst` (Tier 1 mới) |
| Token non-standard behavior | toke_off + toke_def (2 agents) | `token_specialist` (1 agent, deeper) |
| Governance | gove_off + gove_def (2 agents) | `governance_specialist` (1 agent, deeper) |
| Cryptography | cryp_off + cryp_def (2 agents) | `crypto_analyst` (1 agent, deeper) |
| Business logic | logic_exploiter Tier 2 | `logic_exploiter` (Tier 1 mới) |

---

## 6. Implementation

### Cảnh báo: 3 nơi sẽ break nếu không sửa đồng bộ

#### Break point 1 — `contract.py:107` (`_build_interview_system_prompt`)

```python
# Hiện tại: reconstruct prompt bằng cách tìm domain prefix trong agent_id
for d in CONTRACT_AGENT_MATRIX:              # d = "appsec", "blockchain", ...
    if agent_id.startswith(sanitized_domain + "_"):  # "appsec_offensive" → tìm "appsec"
        ...
CONTRACT_AGENT_MATRIX.get(domain, {})        # lookup bằng "appsec"

# Sau khi đổi: CONTRACT_AGENT_MATRIX keys là "appsec_researcher", "evm_exploiter"...
# → startswith("appsec_researcher_") sẽ không bao giờ match "appsec_researcher"
# → CONTRACT_AGENT_MATRIX.get("appsec", {}) → {} (không tìm thấy)
```

**Fix**: Rewrite `_build_interview_system_prompt` để lookup trực tiếp:
```python
def _build_interview_system_prompt(agent_id: str) -> tuple[str, str, str]:
    spec = CONTRACT_AGENT_MATRIX.get(agent_id)
    if spec:
        domain = spec.get("domain_group", agent_id.split("_")[0])
        return spec["prompt"], domain, agent_id
    # fallback cho attacker_ prefix (nếu còn dùng)
    ...
```

#### Break point 2 — `consensus_engine.py:1166` (`supporting_domains` + `domain_group_count`)

```python
# Hiện tại:
ag.split("_")[0] for ag in f.get("submitters", [])
# "flash_loan_specialist".split("_")[0] → "flash"   ← SAI group
# "state_machine_analyst".split("_")[0] → "state"   ← SAI group

# Và domain_group_count=7 (hardcoded cho 8 domain groups cũ)
# Với 19 agents có thể có 16 unique prefixes → cross_score = 16/7 > 2 → vỡ formula
```

**Fix**: Thêm `domain_group` field explicit vào mỗi agent spec, dùng thay cho `split("_")[0]`:
```python
# contract_profile_generator.py — mỗi agent có:
"appsec_researcher": {
    "domain_group": "code_security",   # ← explicit, không derive từ agent_id
    ...
}
# Định nghĩa 6 groups: code_security, crypto_math, defi_economics,
#                       standards, governance, deep_analysis

# consensus_engine.py — đọc từ profile thay vì split:
ag_domain = submitter_profile.get("domain_group", ag.split("_")[0])
# Cập nhật domain_group_count = 6 cho contract audit
```

#### Break point 3 — `ContractAgentProfile.domain_group` field

```python
# ContractAgentProfile dataclass có field:
domain_group: str  # currently "appsec" | "blockchain" | ...

# Sau khi đổi: domain_group sẽ là nhóm mới:
# "code_security" | "crypto_math" | "defi_economics" | "standards" | "governance" | "deep_analysis"
# Cần update mọi nơi hardcode old domain_group strings
```

---

### Matrix structure mới

```python
CONTRACT_AGENT_MATRIX = {
    "appsec_researcher": {
        "display_name": "Application Security Researcher",
        "domain_group": "code_security",      # explicit group (1 trong 6)
        "swc_focus": ["SWC-107", "SWC-101"],  # giữ cho RAG routing
        "prompt": (                            # system_prompt (đặt ở đầu)
            "You are a security researcher with an adversarial mindset. ..."
        ),
        "core_question": (                     # đặt ở CUỐI prompt, trước output
            "Where does this contract receive untrusted input or delegate trust "
            "to an external actor — and what is the worst case if adversarial?"
        ),
    },
    ...
}
```

**6 domain groups** (thay cho 8 cũ — cập nhật `domain_group_count=6`):
```
code_security:    appsec_researcher, appsec_hardener, evm_exploiter,
                  evm_hardener, reentrancy_specialist, access_escalator
crypto_math:      crypto_analyst, math_precision, invariant_breaker
defi_economics:   defi_attacker, defi_analyst, economic_attacker,
                  flash_loan_specialist, composability_attacker, state_machine_analyst
standards:        token_specialist
governance:       governance_specialist
deep_analysis:    library_auditor, logic_exploiter
```

### `generate_profiles()` — rewrite flat loop

```python
# Cũ: nested loop domain → personas
for domain_key, domain_cfg in CONTRACT_AGENT_MATRIX.items():
    for persona in domain_cfg["personas"]:
        agent_id = f"{domain_key[:4]}_{persona}"
        ...

# Mới: flat loop — mỗi key là 1 agent
for agent_key, spec in CONTRACT_AGENT_MATRIX.items():
    system_prompt = self._build_epistemic_system_prompt(
        agent_key, spec["prompt"], spec["core_question"], spec["swc_focus"]
    )
    profiles.append(ContractAgentProfile(
        agent_id     = agent_key,
        tier         = 1,
        domain_group = spec["domain_group"],
        persona      = agent_key,          # no more separate persona field
        display_name = spec["display_name"],
        system_prompt= system_prompt,
        swc_focus    = spec.get("swc_focus", []),
    ))
```

### Prompt position của `core_question` — PHẢI inject ở CẢ 2 turns

Theo recency bias của LLM, `core_question` cần đặt **cuối prompt**, ngay trước output instruction.
**Quan trọng**: Turn 2 là LLM call độc lập — nếu chỉ inject ở Turn 1, agent sẽ "quên" worldview
khi bước vào violation analysis (Turn 2) và rơi lại generic analysis.

#### Turn 1 — `invariant_only` branch (line 1418):

```python
if invariant_only:
    return f"""\
=== ROUND 1 — PHASE A: INVARIANT EXTRACTION ===
You are {agent_profile.agent_id} — {agent_profile.display_name}.
{agent_profile.system_prompt}

=== CONTRACT UNDER REVIEW ===
{context_summary}

=== YOUR EPISTEMIC LENS ===
Before generating invariants, anchor your perspective with your core question:
{agent_profile.core_question}

=== TASK: INVARIANT EXTRACTION ONLY ===
{_STEP1_BLOCK}
"""
```

#### Turn 2 — default branch (line 1441), ngay trước `STEP 2 — FIND VIOLATIONS` (line 1466):

```python
# Hiện tại (line 1464–1466):
{step1_section}

{hint_section}STEP 2 — FIND VIOLATIONS:

# Sau khi sửa — inject core_question giữa step1_section và STEP 2:
{step1_section}

=== YOUR EPISTEMIC LENS ===
Re-anchor your perspective before analyzing violations:
{agent_profile.core_question}

{hint_section}STEP 2 — FIND VIOLATIONS:
```

Cần thêm `core_question: str = ""` vào `ContractAgentProfile` dataclass.

### Ảnh hưởng toán học khi đổi `domain_group_count` 7 → 6

`cross_score = len(unique_groups) / domain_group_count`
`expert_confidence = intra_score × 0.40 + cross_score × 0.60`

Ví dụ finding được 3 domains đồng thuận:
```
Trước: cross_score = 3/7 = 0.429 → confidence += 0.429 × 0.60 = 0.257
Sau:   cross_score = 3/6 = 0.500 → confidence += 0.500 × 0.60 = 0.300
Diff:  +0.043 trên mỗi finding có 3-domain support
```

**Tác động**: Threshold filter hiện tại `min_score = 0.35` (hardcoded tại `contract_audit_agent.py:305`).
Findings borderline (score 0.31–0.35 trước) có thể pass filter sau khi đổi → FP có thể tăng nhẹ.

**Khuyến nghị**: Nâng threshold lên `0.38` khi đổi sang domain_group_count=6 để compensate.
Verify bằng cách so sánh score distribution của run 8 (baseline) với run 9 (sau redesign).

**Vị trí cần sửa**: `contract_audit_agent.py:305`
```python
# Cũ:
engine.run_consensus(findings, domain_group_count=7, mode="contract_audit")
# Mới:
engine.run_consensus(findings, domain_group_count=6, mode="contract_audit", threshold=0.38)
```

### Files cần sửa (theo thứ tự)

| File | Thay đổi |
|------|---------|
| `contract_profile_generator.py` | Rewrite `CONTRACT_AGENT_MATRIX` (flat, 19 entries) + `generate_profiles()` (flat loop) + thêm `_build_epistemic_system_prompt()` |
| `contract_profile_generator.py` | Xóa `CONTRACT_ATTACKER_PROFILES` và Tier 2 generation |
| `contract_oasis_env.py` | Inject `core_question` ở cuối `invariant_only` prompt branch |
| `contract_oasis_env.py` | Update `ContractAgentProfile` dataclass: thêm `core_question` field |
| `contract.py:80–134` | Rewrite `_build_interview_system_prompt` dùng flat lookup |
| `consensus_engine.py` | `domain_group_count=6`, đọc `domain_group` từ profile thay vì `split("_")[0]` |
| `cyber_session_orchestrator.py` | Update `domain_group_count` call site nếu hardcoded |

---

## 7. Verification plan

### Smoke test

```bash
cd /home/thangdd/repos/MiroFish/backend && source .venv/bin/activate
python -c "
from app.services.contract_profile_generator import ContractExpertProfileGenerator
gen = ContractExpertProfileGenerator(None, None)
profiles = gen.generate_profiles()
tier1 = [p for p in profiles if p.tier == 1]
print(f'Tier 1 count: {len(tier1)}')
for p in tier1:
    print(f'  {p.agent_id}: {p.display_name}')
"
# Expected: 19 Tier 1 agents với agent_ids mới
```

### Full run contest 35

```bash
LOG=/tmp/agent_redesign_35_run9.log
nohup bash -c '
  source /home/thangdd/repos/MiroFish/backend/.venv/bin/activate
  AUDIT_PIPELINE_VERSION=v2 STOP_AFTER_DEDUP=true RAG_ENABLED=true \
  python -u scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
    --output /home/thangdd/repos/MiroFish/backend/results/agent_redesign/contest_35_run9 \
    --verbose
' > "$LOG" 2>&1 &
echo "PID=$! LOG=$LOG"
```

### Pass criteria

| Metric | Run 8 (baseline) | Target |
|--------|-----------------|--------|
| TP | 10 | ≥ 11 |
| FP | 52 | ≤ 45 |
| F1 | 0.253 | ≥ 0.280 |
| H-16 (JIT) | ❌ miss | ✅ (economic_attacker) |
| H-11 (Ticks lib) | ❌ miss | ✅ (library_auditor) |
| H-07 (CLPPosition) | ❌ miss | ✅ (logic_exploiter) |

---

## 8. Rủi ro và mitigation

| Rủi ro | Likelihood | Mitigation |
|--------|-----------|-----------|
| FP tăng do agents có freedom hơn | Trung bình | RAG blacklist vẫn active; dedup filter vẫn active |
| Một số SWC patterns bị miss vì không còn trong checklist | Thấp | `swc_focus` metadata vẫn giữ cho RAG routing — model biết SWC từ training |
| agent_id format thay đổi break downstream code | Thấp | Kiểm tra tất cả chỗ dùng `agent_id` trước khi deploy |
| FN tăng với common bugs (reentrancy, overflow) | Rất thấp | Dedicated specialist agents có depth hơn checklist diluted agents |
