# Plan: Zero-Output Agent Fix — RC5 (Run 14)

## Context

Run 13 (contest 35, TP=8) xác nhận 4 agents trả về 0 findings mặc dù API call thành công (200 OK).
Điều tra log xác định **root cause không phải rate limit** mà là Gemini thinking model behavior:
model dùng hết token budget cho internal reasoning rồi trả về empty `content`.

Phân tích chi tiết từng agent:

| Agent | Latency | Root cause | Contest 35 expectation |
|-------|---------|-----------|------------------------|
| `proxy_safety_auditor` | 279.8s | Không có proxy pattern → model kết luận đúng "nothing to report" | 0 findings = Expected |
| `governance_specialist` | 331.5s | Minimal governance (chỉ `updateBarFee`) → model im lặng | 0 findings = Expected cho AMM |
| `defi_analyst` | 329.4s | Worldview lead với system-level (oracle, composability) không match AMM bugs | 0 findings = **Bug** |
| `logic_exploiter` | 338.2s | "Design choice correctness" framing academic → không có forcing function ra FINDING | 0 findings = **Bug** |

**Kết luận:** `proxy_safety_auditor` và `governance_specialist` cần verify trên contest 104 trước khi kết luận có vấn đề.
`defi_analyst` và `logic_exploiter` cần fix ngay — cả 2 đều miss bugs hiện diện trong codebase.

---

## Ghi chú về các góp ý mitigation (review round)

Sau khi draft plan lần đầu, có 3 góp ý mitigation để giảm FP mà không mất TP. Ghi lại quyết định áp dụng từng góp ý:

### Mitigation 1 — logic_exploiter: "Burden of Proof" (áp dụng một phần)

**Góp ý gốc:** Thêm "you MUST articulate a concrete, step-by-step worst-case scenario" làm điều kiện trước khi viết FINDING.

**Quyết định:** Áp dụng một phần — giữ burden-of-proof nhưng **đảo thứ tự obligation**.

**Lý do không áp dụng toàn bộ:** Nếu "articulate scenario" là điều kiện tiên quyết để viết FINDING, model có thể dùng "tôi không chứng minh được attack path cụ thể" làm escape hatch → về lại vấn đề gốc (0 output sau 300s). Đây là tension cốt lõi: forcing function và burden-of-proof mâu thuẫn nhau nếu proof là prerequisite.

**Cách áp dụng:** Viết FINDING TRƯỚC (obligatory), articulate scenario SAU (best-effort). Framing: "write the finding first, then articulate the worst-case scenario — even if speculative. Do not use inability to prove the full attack path as a reason to stay silent." Burden-of-proof hoạt động như quality signal cho consensus round, không phải như gate để viết finding.

---

### Mitigation 2 — defi_analyst: "Dependency Hunting" (áp dụng toàn bộ)

**Góp ý gốc:** Thay "SECONDARY — only when external dependencies are present" bằng "actively hunt for hidden external dependencies."

**Quyết định:** Áp dụng toàn bộ.

**Lý do:** Đây là improvement rõ ràng không có downside. Framing bị động ("only when present") cho phép model mặc định "self-contained → skip system-level", bỏ sót hidden dependencies (implicit price assumptions, arbitrary token interactions). Framing chủ động ("actively hunt") giữ nguyên priority order (accounting TRƯỚC) nhưng không tạo escape hatch cho system-level. Không add FP risk.

---

### Mitigation 3 — governance_specialist: "Impact Thresholding" (áp dụng với tweak)

**Góp ý gốc:** Thêm criteria "ONLY write a finding if the setter lacks bounds entirely, allows permanent fund locking, or enables direct theft without timelocks."

**Quyết định:** Áp dụng với 1 tweak: thay "lacks bounds entirely" bằng "lacks explicit upper bound enforcement in code."

**Lý do tweak:** "Lacks bounds entirely" quá strict — bỏ sót case bounds tồn tại nhưng loose (fee có thể set đến 50%). "Lacks explicit upper bound enforcement in code" đúng hơn về mặt audit — chỉ yêu cầu enforcement phải có trong code, không chấp nhận off-chain governance là lý do miễn trừ.

**Lý do giữ "without timelock or multisig":** Đây là criterion quan trọng nhất — phân biệt được intended centralization (có safeguard) với dangerous centralization (không có safeguard). Giúp tránh flag các protocol intentionally centralized trong khi vẫn catch H-05 type bugs.

---

## Fix 1 — `logic_exploiter`: Forcing directive + Burden of proof (output-first)

### Vấn đề

Prompt RC4 thêm câu "question whether design choices themselves are semantically correct" nhưng không có
**output obligation**. Model suy nghĩ "nearestTick có thể sai về design" (đúng với H-17), nhưng không
commit thành FINDING vì framing academic — không có câu nào nói "viết ra dù không chắc chắn".

Kết quả: 338s thinking, 0 chars output. H-08 và H-17 là exactly loại bugs logic_exploiter phải catch.

### Thay đổi

**Prompt** — thêm forcing directive + burden-of-proof output-first vào cuối:

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
    "Is the ordering of operations in the algorithm correct by design, not just by implementation? "
    "When you identify a suspicious design choice, write a FINDING first, then articulate "
    "the worst-case scenario — even if speculative. "
    "Do not use inability to prove the full attack path as a reason to stay silent."
),
```

**core_question** — từ yes/no question sang action-oriented:

Cũ:
```python
"core_question": (
    "Does this contract's implementation match its intended business logic in all edge cases — "
    "and where do the two diverge in a way that an attacker can exploit?"
),
```

Mới:
```python
"core_question": (
    "For each accumulator, reference variable, or operation ordering in this contract: "
    "is this the correct choice for the intended invariant? "
    "If the answer is 'possibly not', write a FINDING first, then articulate the worst-case scenario — "
    "do not use inability to prove the full attack path as a reason to stay silent."
),
```

### Trade-off

**Được:**
- Model không còn im lặng sau 300s thinking — phải output FINDING trước khi prove
- Burden-of-proof vẫn hoạt động như quality signal: findings không có scenario sẽ bị filter ở consensus round
- Tăng khả năng catch H-08 (boundary condition design), H-17 (nearestTick wrong reference)
- Forcing function áp dụng cho mọi contest — không chỉ contest 35

**Mất:**
- **FP tăng** — speculative findings không có attack path rõ ràng sẽ xuất hiện nhiều hơn
  Ước tính: +3 đến +8 FP (từ 0 → có output)
- Consensus round phải filter harder
- Nguy cơ "confirmation bias": model viết finding cho design choices đúng nhưng trông lạ

**Verdict:** Chấp nhận được. Burden-of-proof output-first giảm FP so với forcing directive thuần túy mà không tạo escape hatch.

---

## Fix 2 — `defi_analyst`: Accounting-first + Active dependency hunting

### Vấn đề

Prompt hiện tại lead với system-level concerns (oracle dependency, composability với Aave/Uniswap/Compound,
cascading failures). Với self-contained AMM (contest 35, 42 — không có external protocol dependency),
model spend toàn bộ 330s reasoning về "what if oracle fails?" / "what if Aave liquidity crisis?" — những
điều không tồn tại. Đến khi cần audit internal accounting, budget đã cạn.

Phần "reward/fee accounting" hiện đứng CUỐI prompt như một afterthought (`"You also audit..."`).
Nhưng đây chính xác là nơi AMM bugs ẩn: fee state inconsistency, reserve divergence, reward ordering.

### Thay đổi

**Prompt** — accounting TRƯỚC, system-level SAU với active dependency hunting (không bị động):

Cũ:
```python
"prompt": (
    "You are a DeFi protocol analyst who studies system-level invariants and failure modes. "
    "You treat the protocol not as a single contract but as a system within an ecosystem of external protocols. "
    "You look for oracle dependency under stress, liquidity assumptions that break under market conditions, "
    "composability risk with external protocols (Aave, Uniswap, Compound), "
    "and cascading failure scenarios. "
    "You also audit reward/fee accounting: do global and per-user states remain consistent "
    "across all combinations of mint, burn, swap, and collect operations?"
),
"core_question": (
    "Under what combination of market conditions, external protocol states, or adversarial actions "
    "does this system's safety assumptions break down?"
),
```

Mới:
```python
"prompt": (
    "You are a DeFi protocol analyst who audits in two layers. "
    "PRIMARY — internal accounting consistency: for every state variable tracking reserves, fees, "
    "or rewards, verify that it remains correct after every combination of mint, burn, swap, "
    "collect, and claim operations. Look for: fee state that grows but never decrements correctly, "
    "reserve values that diverge from actual balances after partial operations, "
    "reward accumulators updated in wrong order relative to liquidity changes, "
    "and per-user states that become inconsistent with global state across multiple calls. "
    "SECONDARY — system-level failure modes: actively hunt for hidden external dependencies "
    "(interfaces, arbitrary token interactions, implicit price assumptions). "
    "If found, evaluate oracle dependency under stress, liquidity assumptions that break under "
    "market conditions, composability risk with external protocols (Aave, Uniswap, Compound), "
    "and cascading failures."
),
"core_question": (
    "After every possible operation sequence (mint→burn, swap→collect, claim→claim, burn→claim): "
    "do all internal accounting invariants hold — reserves, fees, and reward states? "
    "If the contract has external dependencies, what external conditions break its safety assumptions?"
),
```

### Trade-off

**Được:**
- Model focus vào internal accounting ngay từ đầu thinking phase — đúng với AMM bug patterns
- "PRIMARY/SECONDARY" structure rõ ràng → model tự biết priority
- "Actively hunt" thay cho "only when present" → không bỏ sót hidden dependencies
- core_question liệt kê explicit operation sequences → trigger systematic coverage

**Mất:**
- **Overlap cao hơn** với `defi_attacker` và `economic_attacker` trên accounting bugs
  → FP tăng do nhiều agent report cùng bug, dedup phải merge nhiều hơn
- Với protocols có real external dependencies phức tạp (aggregator, multi-protocol vault),
  "SECONDARY" framing vẫn có thể khiến model underweight system-level so với baseline

**Verdict:** Chấp nhận được. Active dependency hunting giải quyết hidden dependency risk của fix ban đầu. Overlap với `defi_attacker` được chấp nhận — duplicate findings bị filter ở dedup round.

---

## Fix 3 — `governance_specialist`: Minimal-governance fallback + Impact threshold

### Vấn đề

Prompt hiện tại (RC4) presume có governance mechanism phức tạp: flash loan voting, timelocks, proposal
threshold. Với AMM chỉ có `updateBarFee()` (1 setter function), model kết luận đúng "không có governance
để tấn công" → im lặng 330s. Không có output.

Vấn đề: "owner-as-adversary" framing (mới thêm) cũng không rescue được vì model tự đặt bar quá cao —
chỉ report khi có "fee parameters they can set to drain user funds" theo nghĩa literal (drain all funds),
không report khi chỉ là "fee không có upper bound".

Trường hợp H-05 (contest 104): `setFee` không có bounds → owner có thể set fee = 100%. Đây chính xác là
loại bug governance_specialist phải catch nhưng đang miss.

### Thay đổi

**Prompt** — thêm minimal-governance fallback block với impact threshold rõ ràng:

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
    "without user consent. "
    "For contracts with minimal governance (only 1-2 privileged setter functions, no token voting): "
    "focus ALL attention on those setters. Write a FINDING only if the setter: "
    "(1) lacks explicit upper bound enforcement in code, "
    "(2) allows permanent fund locking, or "
    "(3) enables direct value extraction without timelock or multisig. "
    "The absence of complex governance means a single privileged call is the ONLY attack surface — "
    "audit it more thoroughly, not less."
),
```

`core_question` giữ nguyên — đã đủ rõ.

### Trade-off

**Được:**
- Model không còn im lặng với minimal-governance contracts
- Impact threshold (3 criteria) ngăn flag legitimate setters: model chỉ report khi thực sự nguy hiểm
- "Without timelock or multisig" phân biệt được intended centralization vs dangerous centralization
- Tăng khả năng catch H-05 (contest 104): `setFee` lacks explicit upper bound

**Mất:**
- **Overlap với `appsec_hardener`** trên "missing bounds check" — cùng 1 bug có thể bị report 2 agents
- Criteria "(1) lacks explicit upper bound" vẫn có thể miss case bounds tồn tại nhưng unreasonably loose
  (ví dụ: fee có thể set đến 99%, có upper bound trong code nhưng thực tế vô nghĩa)
- Model phải tự judge "explicit enforcement" — có thể sai với các pattern bound gián tiếp (revert trong logic, không phải require bound)

**Verdict:** Chấp nhận được. 3 criteria cụ thể là bước cải thiện lớn so với "audit more thoroughly" mơ hồ. Overlap với `appsec_hardener` chấp nhận được — dedup sẽ merge.

---

## Tóm tắt thay đổi và risk matrix

| Fix | Thay đổi so với draft gốc | TP expected | FP risk | Verdict |
|-----|--------------------------|-------------|---------|---------|
| RC5a: `logic_exploiter` | Burden-of-proof output-first (thay "must prove first") | +1~2 (H-08, H-17) | +3~6 | Thực hiện |
| RC5b: `defi_analyst` | Active dependency hunting (thay "only when present") | +1~3 | +2~5 | Thực hiện |
| RC5c: `governance_specialist` | 3-criteria threshold, "lacks explicit bound" (thay "lacks entirely") | +1 (H-05 c104) | +2~5 | Thực hiện |

**Tổng FP risk**: +7 đến +16 (giảm so với draft gốc +8 đến +20 nhờ mitigations)
**TP expected gain**: +2 đến +5 trên contest 35, +1 đến +2 trên contest 104

### Pass criteria Run 14

| Metric | Run 13 baseline | Run 14 target | Ghi chú |
|--------|-----------------|---------------|---------|
| Contest 35 TP | 8 | ≥ 8 | Không regression |
| Contest 35 FP | 57 | ≤ 73 | FP ceiling (thấp hơn draft gốc 75 nhờ mitigations) |
| `logic_exploiter` findings | 0 | ≥ 3 | Verify forcing directive hoạt động |
| `defi_analyst` findings | 0 | ≥ 3 | Verify accounting-first reorder |
| `governance_specialist` findings | 0 | ≥ 1 (contest 35) hoặc ≥ 2 (contest 104) | Verify fallback |
| H-08 có candidates | 0 | ≥ 1 | logic_exploiter target |
| H-17 có candidates | 0 | ≥ 1 | logic_exploiter target |

---

## Verification script

```bash
cd /home/thangdd/repos/MiroFish/backend && source .venv/bin/activate

python -c "
from app.services.contract_profile_generator import CONTRACT_AGENT_MATRIX

# RC5a: logic_exploiter forcing directive + burden-of-proof output-first
l = CONTRACT_AGENT_MATRIX['logic_exploiter']
assert 'stay silent' in l['prompt'], 'Missing forcing directive'
assert 'write a FINDING first' in l['prompt'], 'Missing output-first obligation'
assert 'possibly not' in l['core_question'], 'core_question not action-oriented'

# RC5b: defi_analyst accounting-first + active dependency hunting
d = CONTRACT_AGENT_MATRIX['defi_analyst']
assert d['prompt'].index('PRIMARY') < d['prompt'].index('SECONDARY'), 'PRIMARY must come before SECONDARY'
assert 'actively hunt' in d['prompt'], 'Missing active dependency hunting'
assert 'operation sequence' in d['core_question'], 'core_question missing operation sequence'

# RC5c: governance_specialist minimal fallback + impact threshold
g = CONTRACT_AGENT_MATRIX['governance_specialist']
assert 'minimal governance' in g['prompt'], 'Missing minimal-governance fallback'
assert 'lacks explicit upper bound' in g['prompt'], 'Missing impact threshold criterion 1'
assert 'timelock or multisig' in g['prompt'], 'Missing timelock/multisig criterion'

print('ALL RC5 CHECKS PASSED')
"
```

---

## Run 14 command

```bash
cd /home/thangdd/repos/MiroFish/backend

LOG=/tmp/agent_redesign_35_run14_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
  source /home/thangdd/repos/MiroFish/backend/.venv/bin/activate
  AUDIT_PIPELINE_VERSION=v2 STOP_AFTER_DEDUP=true RAG_ENABLED=true \
  python -u scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
    --output /home/thangdd/repos/MiroFish/backend/results/agent_redesign/contest_35_run14 \
    --verbose
' > "$LOG" 2>&1 &
echo "PID=$! LOG=$LOG"
```
