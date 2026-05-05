# Specialized Agents — Implementation Plan

## Bối cảnh

R1 discovery hiện tại có bias nặng về CODE_LINE (~55%) và MISSING (~20%).
Các bug dạng SEQUENCE, INVARIANT, DESIGN bị bỏ sót hệ thống vì:

1. **Cấu trúc prompt hiện tại** — agent scan source tuyến tính → tự nhiên chú ý sai cú pháp/giá trị, không trace multi-step execution
2. **Thiếu context** — INVARIANT cần biết "điều gì phải đúng" trước khi check; SEQUENCE cần state variable map; DESIGN cần hiểu economic mechanism
3. **Cognitive bias** — khi CODE_LINE quá dễ tìm, agent không đầu tư effort vào SEQUENCE/INVARIANT/DESIGN

**Giải pháp:** Thêm 3 specialized agents vào R1, mỗi agent được thiết kế để tìm đúng 1 evidence type mà current agents bỏ sót, với input context phù hợp.

**Điều kiện tiên quyết:** Implement evidence-based dedup (xem `evidence-types-and-dedup.md`) TRƯỚC khi thêm agents, vì thêm agents mà không có dedup sẽ làm nặng R3.

---

## Agent 1: Invariant Verifier

### Mục tiêu
Tìm các hàm vi phạm **bất biến toán học/kế toán** của protocol.
Không scan code để tìm syntax lỗi — thay vào đó nhận invariants đã extract (Step 1.5) và verify từng hàm có maintain chúng không.

### Evidence type
`INVARIANT`

### Bugs expected to catch (contest 35)
- H-09: `rangeFeeGrowth` revert vì Solidity 0.8 không cho wrap-around
- H-10: `burn()` chỉ trừ fee khỏi reserve, không trừ full amount
- H-17: `nearestTick` làm sai invariant khởi tạo `feeGrowthOutside`

### Input context đặc biệt
```
Standard R1 inputs:
  - Contract source (full)
  - dep_graph

Thêm mới:
  - Protocol invariants từ Step 1.5 (invariants.json)
  - Format: numbered list, mỗi invariant gồm statement + affected functions
```

### Persona
```
Tên: invariant_verifier
Domain: formal_verification
Role: AUDITOR

System prompt:
You are a formal verification engineer. You think in terms of invariants —
properties that MUST hold before and after every state-changing function.

Your task is NOT to find syntax errors. Your task is:
1. For each invariant provided, check every function that touches the relevant
   state variables.
2. Find functions where the invariant is NOT maintained after execution.
3. Report as INVARIANT evidence type only.

Focus on:
- Accounting invariants: "after op X, balance Y must equal reserve Y"
- Arithmetic invariants: "subtraction A - B - C may wrap in Uniswap V3 design"
- State invariants: "variable X must be updated before variable Y changes"

You are BLIND to CODE_LINE bugs intentionally — leave syntax errors to other agents.
```

### Prompt structure
```
=== ROUND 1 — INVARIANT VERIFICATION PASS ===
You are invariant_verifier (formal_verification/auditor).
[system_prompt]

=== PROTOCOL INVARIANTS (extracted from NatSpec + design) ===
[invariants từ Step 1.5, numbered]

=== CONTRACT SOURCE ===
[full source]

=== INSTRUCTIONS ===
For each invariant listed above:
1. Identify all functions that read or write the relevant state variables.
2. Trace the execution path — does the invariant hold AFTER the function returns?
3. If violated: write 1 FINDING per (invariant, function) pair.

OUTPUT FORMAT — use ONLY FINDING with INVARIANT evidence:
  FINDING: <title>
  CONTRACT: <contract>
  FUNCTION: <function>
  SEVERITY: <critical|high|medium>
  EVIDENCE:
    INV: <invariant statement>
    VIOLATED_AT: <Contract.function()>
    COUNTEREXAMPLE: <specific condition that breaks it>
  ATTACK_PATH: <how attacker exploits the violation>
  DESCRIPTION: <root cause>
  PATCH: <fix>
```

### Expected output volume
3–8 findings per run (focused, không nhiễu)

---

## Agent 2: Ordering Analyst

### Mục tiêu
Tìm các bug do **thứ tự thực thi sai** giữa các operations — bao gồm:
- Cross-function state mutation order
- Read-before-update vs update-before-read
- Cross-contract callback sequences
- Transaction ordering dependencies

Không tìm code sai — tìm đúng code ở sai vị trí.

### Evidence type
`SEQUENCE`

### Bugs expected to catch (contest 35)
- H-06: `Position.collect()` mark fees collected → `Pool.burn()` re-collect same fees
- H-12: `secondsPerLiquidity` update AFTER liquidity change, phải là trước

### Input context đặc biệt
```
Standard R1 inputs:
  - Contract source (full)

Thêm mới:
  - dep_graph từ Step 1.3 (dep_graph.json) — state variable read/write map
  - Format: per-function list of state vars read và written
```

### Persona
```
Tên: ordering_analyst
Domain: concurrency_security
Role: AUDITOR

System prompt:
You are a concurrency and ordering security specialist. You think about
WHEN operations happen, not WHAT the operations are.

Your mental model for every function:
  Pre-state → [reads] → [computes] → [writes] → Post-state

Your task: find pairs of operations where the ORDER matters and is WRONG.

Focus on:
- State variable X is written in fn_a, then read incorrectly by fn_b
  (fn_b should have been called before fn_a, or vice versa)
- A value is computed using a variable AFTER it has changed, but the computation
  needed the value BEFORE the change
- Cross-contract callbacks that change state between two reads in the caller
- Two functions that together create a double-spend or double-credit
  because each individually looks correct

You are NOT looking for wrong values or wrong formulas.
You are looking for correct operations in wrong order.
```

### Prompt structure
```
=== ROUND 1 — ORDERING ANALYSIS PASS ===
You are ordering_analyst (concurrency_security/auditor).
[system_prompt]

=== STATE VARIABLE READ/WRITE MAP ===
[dep_graph: per-function state var reads/writes]

=== CONTRACT SOURCE ===
[full source]

=== INSTRUCTIONS ===
Step 1: For each state variable in the read/write map, list all functions
        that read it and all functions that write it.

Step 2: For each (writer, reader) pair:
        - Does the reader depend on the pre-write or post-write value?
        - If reader is called AFTER writer but needs pre-write value → bug
        - If two functions each partially update the same state → race condition

Step 3: For each function, check if it computes a value using a variable
        that it then modifies — is the order correct?

OUTPUT FORMAT — use ONLY FINDING with SEQUENCE evidence:
  FINDING: <title>
  CONTRACT: <contract>
  FUNCTION: <entry function where ordering fails>
  SEVERITY: <critical|high|medium>
  EVIDENCE:
    SEQ: <Contract_A.fn_a()> modifies <state_var>
    THEN: <Contract_B.fn_b()> reads <state_var> incorrectly
    ISSUE: <why this order is wrong>
  ATTACK_PATH: <exploit scenario>
  DESCRIPTION: <root cause>
  PATCH: <fix — swap order / add snapshot / add lock>
```

### Expected output volume
2–5 findings per run

---

## Agent 3: Economic Attacker

### Mục tiêu
Tìm các bug do **cơ chế kinh tế/incentive không an toàn** — không có dòng code nào sai, nhưng thiết kế reward/penalty/access structure tạo ra kịch bản profitable attack.

### Evidence type
`DESIGN`

### Bugs expected to catch (contest 35)
- H-16: JIT liquidity attack trên `claimReward()` — mint → claim → burn → repeat
- Các dạng front-running liên quan đến reward distribution
- Các cơ chế reward không có minimum lock period

### Input context đặc biệt
```
Standard R1 inputs:
  - Contract source (full)

Thêm mới:
  - Protocol intent từ Step 1.1 (intent.json) — mô tả mục đích thiết kế
  - Contest README (nếu có) — mô tả kinh tế protocol
```

### Persona
```
Tên: economic_attacker
Domain: mechanism_design
Role: OFFENSIVE

System prompt:
You are a mechanism design expert and DeFi economic attacker.
You think about protocols as economic games where rational actors
maximize profit given the rules.

Your attack framework:
  1. What does this protocol REWARD? (yield, fees, governance power)
  2. What CONTROLS access to the reward? (time, liquidity, votes)
  3. Can I acquire the control cheaply, claim the reward, then exit?
  4. Is there a minimum cost that makes this unprofitable? If not → attack.

Classic patterns you look for:
  - JIT (Just-In-Time): provide resource T before measurement, remove after
  - Sandwich: front-run + back-run around a state change
  - Governance capture: borrow votes for 1 block, pass proposal, repay
  - Fee skimming: exploit fee rounding in your favor repeatedly
  - Incentive misalignment: protocol intends X, rational actor does Y instead

You are NOT looking for code bugs. You are looking for economic exploits
where the code works exactly as written, but the design rewards bad behavior.
```

### Prompt structure
```
=== ROUND 1 — ECONOMIC ATTACK ANALYSIS ===
You are economic_attacker (mechanism_design/offensive).
[system_prompt]

=== PROTOCOL INTENT ===
[intent từ Step 1.1]

=== CONTRACT SOURCE ===
[full source — focus on reward distribution, access control, fee logic]

=== INSTRUCTIONS ===
For each reward/incentive mechanism in the contract:

1. Map the reward flow:
   WHO receives → WHAT triggers → HOW MUCH → WHEN measured

2. Ask: can a rational actor game the measurement timing?
   - Flash loan to temporarily satisfy condition?
   - Front-run the measurement transaction?
   - Provide capital just before measurement, remove after?

3. Ask: is there a penalty for the attack? What is the minimum cost?
   If profit > cost → report as DESIGN finding.

OUTPUT FORMAT — use ONLY FINDING with DESIGN evidence:
  FINDING: <title>
  CONTRACT: <contract>
  FUNCTION: <reward/claim function>
  SEVERITY: <critical|high|medium>
  EVIDENCE:
    DESIGN: <reward mechanism description>
    EXPLOIT: <step-by-step attack: acquire → claim → exit>
    NO_MITIGATION: <what safeguard is missing>
    AT: <Contract.function()>
  ATTACK_PATH: <concrete transaction sequence with profit calculation>
  DESCRIPTION: <why protocol design enables this>
  PATCH: <structural fix — lockup, commit-reveal, smoothing>
```

### Expected output volume
1–4 findings per run (DESIGN bugs hiếm nhưng critical khi có)

---

## Integration vào Pipeline

### Vị trí trong flow

```
Step 1.5: Extract invariants → invariants.json       ←── input cho Agent 1
Step 1.3: Build dep_graph   → dep_graph.json         ←── input cho Agent 2
Step 1.1: Extract intent    → intent.json            ←── input cho Agent 3
                ↓
Step 2: Generate profiles
  Current: 17-22 tier-1 agents
  New:     +3 specialized agents (invariant_verifier, ordering_analyst, economic_attacker)
                ↓
Round 1: All agents chạy độc lập
  - 17-22 standard agents → CODE_LINE + MISSING findings
  - Agent 1 (invariant_verifier) → INVARIANT findings
  - Agent 2 (ordering_analyst) → SEQUENCE findings
  - Agent 3 (economic_attacker) → DESIGN findings
                ↓
[Dedup step] — theo evidence-types-and-dedup.md
                ↓
Round 2: Blind voting (tất cả agents vote)
                ↓
Round 3: Attacker validation
```

### Profile generation

3 agents này là **static profiles** — không generate từ contest README, luôn có mặt trong mọi contract audit:

```python
SPECIALIZED_PROFILES = [
    ContractAgentProfile(
        agent_id="spec_invariant_verifier",
        domain_group="formal_verification",
        persona="auditor",
        tier=1,
        system_prompt=INVARIANT_VERIFIER_PROMPT,
        evidence_type_focus="INVARIANT",   # new field
    ),
    ContractAgentProfile(
        agent_id="spec_ordering_analyst",
        domain_group="concurrency_security",
        persona="auditor",
        tier=1,
        system_prompt=ORDERING_ANALYST_PROMPT,
        evidence_type_focus="SEQUENCE",
    ),
    ContractAgentProfile(
        agent_id="spec_economic_attacker",
        domain_group="mechanism_design",
        persona="offensive",
        tier=1,
        system_prompt=ECONOMIC_ATTACKER_PROMPT,
        evidence_type_focus="DESIGN",
    ),
]
```

### R1 dispatch modification

```python
def _run_discovery_round(...):
    for profile in t1_profiles:
        if getattr(profile, "evidence_type_focus", None) == "INVARIANT":
            prompt = build_invariant_verifier_prompt(profile, network_summary, invariants)
        elif getattr(profile, "evidence_type_focus", None) == "SEQUENCE":
            prompt = build_ordering_analyst_prompt(profile, network_summary, dep_graph)
        elif getattr(profile, "evidence_type_focus", None) == "DESIGN":
            prompt = build_economic_attacker_prompt(profile, network_summary, intent)
        else:
            prompt = build_round1_prompt(profile, network_summary, ...)
```

---

## Coverage Analysis

### Bugs bị miss trong contest 35 và specialized agent coverage

| Bug | Root cause bị miss | Agent cover |
|-----|--------------------|-------------|
| H-06 | collect→burn double yield (ordering) | Ordering Analyst ✓ |
| H-08 | strict < thay vì <= (subtle CODE_LINE) | Standard agents (nên detect được) |
| H-12 | secondsPerLiquidity update order | Ordering Analyst ✓ |
| H-15 | missing initialPrice validation | Standard agents (MISSING type) |
| H-16 | JIT liquidity attack | Economic Attacker ✓ |
| H-17 | nearestTick invariant violation | Invariant Verifier ✓ |

**H-01, H-05** (unsafe cast): Nên được standard agents detect — nếu vẫn miss, cần
điều chỉnh focus directive của arithmetic-specialist agents, không cần specialized agent mới.

---

## Trade-offs

| | Benefit | Cost |
|-|---------|------|
| +3 R1 calls | Thêm coverage cho 3 evidence types | +3 LLM calls (~3-5 phút, minimal) |
| Specialized context | Agent có thêm invariants/dep_graph/intent | Cần truyền đúng data vào prompt |
| Static profiles | Không phụ thuộc contest profile generation | Prompt cần maintain khi pipeline thay đổi |
| R3 overhead | Tìm thêm bugs thực sự | Cần dedup trước để không tăng R3 calls |

---

## Implementation Order

```
1. [Prerequisite] Implement evidence-based dedup
2. Add 3 static profiles vào profile generator
3. Add 3 prompt builders (build_invariant_verifier_prompt, ...)
4. Modify _run_discovery_round() để dispatch đúng prompt
5. Verify parser handle INVARIANT/SEQUENCE/DESIGN evidence format
6. Test trên contest 35, so sánh recall trước/sau
```
