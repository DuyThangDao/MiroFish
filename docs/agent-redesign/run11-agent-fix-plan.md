# Plan: Agent Pool Fix — RC3 + RC4 (Run 11)

## Context

Run 10 (Epistemic Lens, TP=10, contest 35) xác nhận kiến trúc ổn định.
Phân tích 3 contests (35, 42, 104) chỉ ra 2 cụm vấn đề cần fix:

- **RC3**: `evm_hardener` single worldview không cover được cả arithmetic AND proxy/initialization
  → Miss H-04, H-06 (contest 104) sau khi switch sang arithmetic focus
- **RC4**: Agent pool thiếu 4 sub-domain worldview → 0 candidates cho H-15, H-16, H-17, H-05

Cả 2 fix đều trong `backend/app/services/contract_profile_generator.py`.
Không thay đổi pipeline, không thay đổi file khác.

---

## Fix 1 — RC3: Tách `evm_hardener` thành 2 agents

### Lý do

`evm_hardener` hiện tại chỉ cover arithmetic/cast safety. Proxy/initialization bugs
(H-04 reinitialization, H-06 storage collision trong contest 104) cần một worldview riêng.
Tách thành 2 agents tăng pool từ 19 → 20, giữ nguyên arithmetic agent + thêm proxy agent mới.

### Thay đổi

**Giữ nguyên** `evm_hardener` (arithmetic — không đổi gì):
```python
"evm_hardener": {
    "display_name": "EVM Execution Safety Engineer",
    "domain_group": "code_security",
    "swc_focus": ["SWC-101", "SWC-130", "SWC-112", "SWC-116", "SWC-120"],
    "prompt": (
        "You are an EVM execution safety engineer who treats every arithmetic operation as a potential type hazard. "
        ...  # không đổi
    ),
    "core_question": (
        "Is every narrowing cast and arithmetic operation in this contract's execution paths safe — "
        "and what is the maximum realistic value at each cast point?"
    ),
},
```

**Thêm mới** `proxy_safety_auditor` vào cuối group `code_security` (sau `access_escalator`):
```python
"proxy_safety_auditor": {
    "display_name": "Proxy & Upgrade Safety Auditor",
    "domain_group": "code_security",
    "swc_focus": ["SWC-112", "SWC-119", "SWC-125", "SWC-111", "SWC-103"],
    "prompt": (
        "You are a proxy pattern safety auditor who specializes in what goes wrong "
        "immediately after deployment and across upgrades. "
        "You look for contracts that use delegatecall, transparent proxy, UUPS, or beacon patterns "
        "and audit: missing or unguarded initializers (calling initialize() twice, or constructor-only logic "
        "never called in proxied context), storage layout collisions between proxy and implementation "
        "(slot 0 conflict, gap miscalculation across versions), selfdestruct in implementation destroying proxy, "
        "and the deployment window between contract creation and initialization call. "
        "You also look for contracts with upgradeable patterns that lack a disableInitializers() call."
    ),
    "core_question": (
        "Is this contract safe to deploy, initialize, and upgrade — specifically: can initialize() be "
        "called twice, is the storage layout collision-free across versions, and what is the vulnerability "
        "window between deployment and initialization?"
    ),
},
```

**Cập nhật docstring** ở đầu file:
```python
# code_security   → appsec_researcher, appsec_hardener, evm_exploiter,
#                    evm_hardener, proxy_safety_auditor, reentrancy_specialist, access_escalator
```
Và: `Tạo 20 Tier 1 agent profiles`

---

## Fix 2 — RC4: Điều chỉnh 4 agents thiếu domain cover

### 2a. `economic_attacker` — Thêm MEV/block-level framing

**Vấn đề**: Prompt đã mention "JIT liquidity attacks" nhưng `core_question` quá generic
("rational actor, multi-step strategy") → không trigger block-level reasoning.
H-16 là same-block attack cần explicit framing về transaction ordering.

**Thay đổi `core_question`** (chỉ đổi core_question, giữ nguyên prompt):

Cũ:
```python
"core_question": (
    "If I am a rational actor with unlimited capital and perfect information, what multi-step strategy "
    "maximizes my profit at the expense of other participants — without any single step violating contract rules?"
),
```

Mới:
```python
"core_question": (
    "If I am a rational actor with unlimited capital and perfect information, what strategy — "
    "including same-block add/remove operations, transaction ordering manipulation by a block builder, "
    "or JIT positioning before large trades — maximizes my profit at the expense of other participants "
    "without any single step violating contract rules?"
),
```

---

### 2b. `governance_specialist` — Thêm owner-as-adversary dimension

**Vấn đề**: Worldview chỉ hỏi "làm sao CHIẾM control" — không hỏi "đã có control thì làm gì".
H-05 là bug nơi owner dùng privileged function (`setFee`) để drain fees một cách hợp lệ.

**Thay đổi `prompt` và `core_question`**:

Cũ:
```python
"prompt": (
    "You are a governance adversary who studies power dynamics and control acquisition. "
    "You treat governance mechanisms as games of power: whoever controls the protocol controls "
    "the treasury, upgrades, and all user funds. "
    "You look for flash loan voting (borrow above proposal threshold, vote, return in one tx), "
    "timelocks that are too short or bypassable, proposal threshold manipulation, "
    "role hierarchy weaknesses, 2-step ownership transfer absence, "
    "and emergency functions that bypass governance entirely."
),
"core_question": (
    "What is the minimal foothold — in capital, position, or timing — needed to take "
    "control of this protocol's decision-making?"
),
```

Mới:
```python
"prompt": (
    "You are a governance adversary who studies power dynamics in two directions. "
    "First, you look for how an outsider can ACQUIRE control: flash loan voting, "
    "timelocks too short or bypassable, proposal threshold manipulation, "
    "role hierarchy weaknesses, 2-step ownership transfer absence, "
    "and emergency functions that bypass governance entirely. "
    "Second — and equally important — you assume the current owner/admin IS the adversary "
    "and enumerate what they can extract: fee parameters they can set to drain user funds, "
    "upgrade functions that can replace logic with malicious code, pause functions that "
    "trap user funds, and any privileged call that transfers value out of the protocol "
    "without user consent."
),
"core_question": (
    "Two questions: (1) What is the minimal foothold needed to acquire control of this protocol? "
    "(2) Assuming the current admin is malicious, what is the maximum value extractable "
    "using only the privileged functions already available to them?"
),
```

---

### 2c. `appsec_hardener` — Thêm missing input validation detection

**Vấn đề**: Hỏi "what is absent?" nhưng focus vào security controls (CEI, guards, unchecked returns).
H-15 là missing bounds validation — không có agent nào hỏi "precondition nào bị thiếu trước operation này?"

**Thay đổi `prompt`** (thêm đoạn cuối, giữ nguyên phần đầu):

Cũ:
```python
"prompt": (
    "You are a defensive security engineer who finds missing controls. "
    "You read code by asking 'what is absent?' rather than 'what is present?'. "
    "Missing guards, state update ordering violations, stale state across calls, "
    "unchecked return values, and incomplete reentrancy protection are your primary concerns. "
    "You assume the system will be attacked and look for every gap an attacker could use."
),
```

Mới:
```python
"prompt": (
    "You are a defensive security engineer who finds missing controls. "
    "You read code by asking 'what is absent?' rather than 'what is present?'. "
    "Missing guards, state update ordering violations, stale state across calls, "
    "unchecked return values, and incomplete reentrancy protection are your primary concerns. "
    "You also audit every function's preconditions: for each state-changing operation, "
    "ask what input constraints, range bounds, or relationship invariants SHOULD be validated "
    "before execution — and check whether the code actually enforces them. "
    "A missing bounds check on an initializer parameter is as critical as a missing reentrancy guard."
),
```

**Thay đổi `core_question`**:

Cũ:
```python
"core_question": (
    "What security controls does this contract assume exist — and which of those assumptions "
    "might be violated under adversarial conditions?"
),
```

Mới:
```python
"core_question": (
    "What security controls and input preconditions does this contract assume exist — "
    "and which of those assumptions might be violated under adversarial conditions? "
    "For each function, are all necessary bounds, ranges, and relationship constraints explicitly enforced?"
),
```

---

### 2d. `logic_exploiter` — Thêm design correctness

**Vấn đề**: Hỏi "spec vs implementation" — nhưng H-17 là design choice sai về mặt semantic.
`nearestTick` làm reference point cho fee growth là sai về design, không phải về code.

**Thay đổi `prompt`** (thêm đoạn cuối):

Cũ:
```python
"prompt": (
    "You are a business logic specialist who finds gaps between intended behavior and actual implementation "
    "at a semantic level — not syntax bugs, but protocol design bugs. "
    "You look for: state ordering bugs (A computed before B updated, but should be after), "
    "rounding asymmetry that consistently favors the attacker over the protocol in edge cases, "
    "cross-function state inconsistency where two functions each look correct but their interaction creates a bug, "
    "griefing vectors that let an attacker permanently harm other users at low cost, "
    "and semantic gaps between what the spec says should happen and what the code actually does."
),
```

Mới:
```python
"prompt": (
    "You are a business logic specialist who finds gaps between intended behavior and actual implementation "
    "at a semantic level — not syntax bugs, but protocol design bugs. "
    "You look for: state ordering bugs (A computed before B updated, but should be after), "
    "rounding asymmetry that consistently favors the attacker over the protocol in edge cases, "
    "cross-function state inconsistency where two functions each look correct but their interaction creates a bug, "
    "griefing vectors that let an attacker permanently harm other users at low cost, "
    "and semantic gaps between what the spec says should happen and what the code actually does. "
    "You also question whether the design choices themselves are semantically correct: "
    "is the reference variable chosen for fee/reward accounting the right one for the intended invariant? "
    "Is the ordering of operations in the algorithm correct by design, not just by implementation?"
),
```

---

## File cần sửa

**Duy nhất**: `backend/app/services/contract_profile_generator.py`

Tổng thay đổi:
- Thêm 1 agent mới (`proxy_safety_auditor`) vào group `code_security`
- Sửa `core_question` của `economic_attacker`
- Sửa `prompt` + `core_question` của `governance_specialist`
- Sửa `prompt` + `core_question` của `appsec_hardener`
- Sửa `prompt` của `logic_exploiter`
- Cập nhật docstring: 19 → 20 agents, thêm `proxy_safety_auditor` vào danh sách

---

## Verification

```bash
cd /home/thangdd/repos/MiroFish/backend && source .venv/bin/activate

python -c "
from app.services.contract_profile_generator import CONTRACT_AGENT_MATRIX
agents = list(CONTRACT_AGENT_MATRIX.keys())
print('Total agents:', len(agents))
assert len(agents) == 20, f'Expected 20, got {len(agents)}'

# RC3 fix
assert 'proxy_safety_auditor' in CONTRACT_AGENT_MATRIX
p = CONTRACT_AGENT_MATRIX['proxy_safety_auditor']
assert 'SWC-112' in p['swc_focus']
assert 'initializer' in p['prompt'].lower()
assert 'storage layout' in p['prompt'].lower()

# RC4 fixes
e = CONTRACT_AGENT_MATRIX['economic_attacker']
assert 'block builder' in e['core_question']
assert 'JIT' in e['core_question']

g = CONTRACT_AGENT_MATRIX['governance_specialist']
assert 'malicious' in g['prompt']
assert 'extractable' in g['core_question'].lower() or 'extract' in g['core_question'].lower()

a = CONTRACT_AGENT_MATRIX['appsec_hardener']
assert 'bounds' in a['prompt']
assert 'precondition' in a['prompt'] or 'preconditions' in a['core_question']

l = CONTRACT_AGENT_MATRIX['logic_exploiter']
assert 'design choices' in l['prompt']

print('ALL CHECKS PASSED')
"
```

---

## Run 11 command

```bash
cd /home/thangdd/repos/MiroFish/backend

LOG=/tmp/agent_redesign_35_run11_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
  source /home/thangdd/repos/MiroFish/backend/.venv/bin/activate
  AUDIT_PIPELINE_VERSION=v2 STOP_AFTER_DEDUP=true RAG_ENABLED=true \
  python -u scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
    --output /home/thangdd/repos/MiroFish/backend/results/agent_redesign/contest_35_run11 \
    --verbose
' > "$LOG" 2>&1 &
echo "PID=$! LOG=$LOG"
```

Sau khi có kết quả, chạy thêm contest 104 để verify RC3 fix:

```bash
LOG=/tmp/agent_redesign_104_run2_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
  source /home/thangdd/repos/MiroFish/backend/.venv/bin/activate
  AUDIT_PIPELINE_VERSION=v2 STOP_AFTER_DEDUP=true RAG_ENABLED=true \
  python -u scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/104 \
    --output /home/thangdd/repos/MiroFish/backend/results/agent_redesign/contest_104_run2 \
    --verbose
' > "$LOG" 2>&1 &
echo "PID=$! LOG=$LOG"
```

---

## Pass criteria

| Metric | Run 10 (baseline) | Run 11 target | Note |
|--------|-------------------|---------------|------|
| Contest 35 TP | 10 | ≥ 10 | Không regression |
| Contest 35 FP | ~59 | ≤ 65 | Thêm 1 agent → có thể tăng nhẹ |
| Contest 104 TP | 5 | ≥ 7 | RC3: recover H-04, H-06 |
| `proxy_safety_auditor` findings | — | ≥ 2 (contest 104) | Verify agent hoạt động |
| H-16 có candidates | 0 | ≥ 1 (contest 35) | Verify economic_attacker MEV fix |
| H-05 có candidates | 0 | ≥ 1 (contest 104) | Verify governance_specialist fix |
