# Audit Pipeline v2 — 3-Round Architecture

## Vấn đề của kiến trúc hiện tại (10-round)

### 1. Parser bug: mỗi agent response chỉ parse được 1 FINDING
Prompt yêu cầu: `"If the same SWC appears in 3 functions, write 3 separate FINDINGs."` nhưng `parse_contract_finding_from_text()` trả về sau FINDING block đầu tiên. 2 finding sau bị drop im lặng.

### 2. Cluster-by-SWC gian lận confidence
Tất cả agents report SWC-101 → 1 cluster. `affected_assets` = union các `fns` non-empty từ các agent. Nhưng mỗi agent thường chỉ tìm được 1 function khác nhau → union tích lũy. Confidence cluster này đo "có bao nhiêu agent tìm SWC-101", **không** đo "function X có thực sự bị SWC-101 không". Kết quả: 10 agents tìm SWC-101 ở 10 functions khác nhau → cluster có confidence cao + 10 affected_assets, nhưng chỉ cần 1 function đúng là đã pass evaluator.

### 3. OASIS philosophy violation
Phase B (CHALLENGE/VALIDATE/CONFIRM/DISMISS) hoạt động ở title-string level, không phải (SWC, function) pair level. Agent nhìn thấy "Integer Overflow" và VALIDATE mà không biết đó là overflow ở function nào. Không có corroboration thực sự ở instance level.

### 4. Round dư thừa
10 rounds kế thừa từ OASIS timestep. Không có social network propagation mechanism → mỗi round là independent re-sampling, không phải genuine convergence. Phase C review list build một lần sau round 7, dùng cho 3 rounds C → không có new information.

### 5. Confidence metric level mismatch
Current confidence = class-level agreement (does codebase have SWC-101?).  
Evaluator requires = instance-level (is THIS function vulnerable to SWC-101?).

---

## Kiến trúc mới: 3 Rounds

```
Round 1: Independent Discovery  →  Pool[(SWC, function) pairs]
Round 2: Parallel Blind Voting  →  accepted_finding_list + round2_score
Round 3: Blind Attacker Validation  →  final_score, discard, or PoC fallback
```

---

## Agent Composition

### Tier 1 — Domain Experts

#### Benchmark evaluation configuration (N=15)

| Domain Group | Personas | Agents | Coverage |
|---|---|---|---|
| Application Security | offensive, defensive, auditor | 3 | Reentrancy, overflow, input validation |
| Blockchain Security | offensive, defensive, auditor | 3 | Cross-function reentrancy, delegatecall, upgradeable |
| Cryptography & Randomness | offensive, defensive | 2 | Weak randomness, signature malleability |
| DeFi Protocol Security | offensive, defensive, analyst | 3 | Flash loan, oracle manipulation, MEV |
| Smart Contract Economics | economist, protocol_designer | 2 | Tokenomics attack, economic invariants |
| Governance & Access Control | offensive, defensive | 2 | Privilege escalation, governance bypass |

#### Lý do loại bỏ Supply Chain & Dependency (2 agents)

Hai agents `dependency_auditor` và `build_analyst` bị loại khỏi benchmark evaluation vì các lý do sau:

**1. Out-of-scope với ground truth:** Web3Bugs dataset đánh giá on-chain vulnerabilities trong Solidity source code. Supply chain vulnerabilities (npm dependency confusion, malicious build artifact, compromised Hardhat plugin) không xuất hiện trong bất kỳ ground truth entry nào của dataset → 2 agents này không thể đóng góp TP, chỉ sinh FP.

**2. Tự bị filter bởi co-discovery mechanism:** Các findings từ supply chain không có overlap với domain khác (k=1 luôn vì không domain nào khác cover build pipeline). Với threshold Round 2, pair có k=1 cần ít nhất 5 explicit ACCEPT votes mới pass — khó xảy ra vì các domain experts không đủ kiến thức để evaluate supply chain findings. Tuy nhiên, 2 LLM calls vẫn bị tiêu tốn ở Round 1 mà không có giá trị.

**3. Tốn tài nguyên không tương xứng:** Với 15 rounds (10 round cũ, nay 3 round), mỗi agent tốn 1 call/round. 2 agents × 3 rounds = 6 calls lãng phí trên mỗi contract. Trên benchmark 100+ contracts, con số này có ý nghĩa.

**Trong production deployment thực tế:** Supply chain domain có giá trị thực với các project có monorepo Hardhat/Foundry, bridge contracts phụ thuộc vào external library, hoặc upgrade scripts tự động. Có thể plug-in lại tùy loại project mà không thay đổi kiến trúc core.

#### Đề xuất bổ sung agents để cải thiện kết quả

Thay 2 slot supply chain bằng **2 domain mới, tổng 4 agents (N=19)**. Co-discovery mechanism tự điều chỉnh: khi n tăng từ 15→19, denominator tăng theo → threshold tự nâng → FP không bùng nổ. Genuine bug từ 2 agents cùng domain co-discover → k=2 ngay → pass dễ; noise finding đơn lẻ → k=1 → càng khó pass hơn. Chi phí: +4 calls/round (+27%), chấp nhận được.

**Domain 1: DeFi Math & Precision Specialist (2 agents: `math_offensive`, `math_defensive`)**

`appsec` cover SWC-101 (integer overflow/underflow) nhưng precision loss là vấn đề khác — bị undercover hoàn toàn trong agent set hiện tại:
- Division order: `a / b * c` vs `a * c / b` → kết quả khác nhau do Solidity integer truncation
- Accumulated rounding error: nhiều small truncation tích lũy thành value drain có thể exploit
- Fixed-point arithmetic: `mulDiv`, `FullMath` sai scaling factor → giá trị sai hàng orders of magnitude
- Token decimal mismatch: 6-decimal USDC vs 18-decimal ETH trong cùng pool không được scale đúng

Mỗi persona có system prompt và góc nhìn riêng biệt:

| Persona | Agent ID | Góc nhìn | Focus chính |
|---------|----------|-----------|-------------|
| `offensive` | `math_offensive` | Attacker: tìm cách exploit precision error để drain value | Deposit/withdraw cycles khai thác rounding surplus, sandwich rounding direction, inflate share price qua first-deposit precision attack |
| `defensive` | `math_defensive` | Defender: kiểm tra invariants và rounding contract | Round-down khi tính output, round-up khi tính input được đảm bảo chưa; invariant `total_assets >= total_supply × price` có bị phá vỡ sau mỗi operation không |

**Domain 2: Token Standard Compliance Specialist (2 agents: `token_offensive`, `token_defensive`)**

Non-standard token behavior là nguồn gốc của nhiều integration bugs mà static analyzer không phát hiện được vì cần context protocol-level:
- Fee-on-transfer tokens (PAXG, STA): `transfer(amount)` → contract nhận ít hơn `amount` → accounting sai, LP pool bị drain
- Rebase tokens (stETH, AMPL): balance thay đổi externally ngoài contract → cached balance stale → sai position
- ERC20 `transfer()` return `false` thay vì revert (USDT legacy): contract không check return value → silent failure
- ERC721/ERC1155 `safeTransfer` callback qua `onERC721Received` → reentrancy path bị bỏ qua

Mỗi persona có system prompt và góc nhìn riêng biệt:

| Persona | Agent ID | Góc nhìn | Focus chính |
|---------|----------|-----------|-------------|
| `offensive` | `token_offensive` | Attacker: tìm assumptions về token behavior có thể vi phạm để exploit | Contract assume `balanceOf` tăng đúng `amount` sau transfer không? Có path nào gọi `transfer` mà không check return value? Callback nào có thể bị reentrancy? |
| `defensive` | `token_defensive` | Defender: kiểm tra contract có defensive guard với non-standard token không | `safeTransfer` (OpenZeppelin) được dùng thay vì raw `transfer`? Balance check before/after transfer? `onERC721Received` được implement đúng không? |

**Nguyên tắc chung về persona cho tất cả domains:**

Mỗi domain cần ít nhất 2 personas để cover cả 2 chiều phân tích:
- `offensive` (hoặc tương đương như `economist`, `dependency_auditor`): góc nhìn attacker — tìm path exploit
- `defensive` (hoặc tương đương như `protocol_designer`, `build_analyst`): góc nhìn defender — tìm missing control

Domain có thể thêm persona thứ 3 (`auditor` hoặc `analyst`) để cover comprehensive review khi bug class đủ phức tạp (ví dụ: `appsec`, `blockchain`, `defi` đều có 3 personas). Domain mới (`math`, `token`) bắt đầu với 2 personas vì bug class còn tương đối hẹp; có thể mở rộng sang persona `auditor` nếu cần coverage rộng hơn.

#### Tóm tắt composition

| Config | N tier-1 | Personas | LLM calls/contract | Mục tiêu |
|--------|----------|---------|-------------------|---------|
| Benchmark baseline | 15 | offensive/defensive/auditor/analyst × 6 domains | 45 | F1 trên Web3Bugs |
| **Benchmark + Math + Token** | **19** | **+math(off/def) +token(off/def)** | **57** | **Cải thiện recall precision + integration bugs** |
| Production full | 21+ | Thêm supply chain, cross-chain | 63+ | Real-world audit |

### Tier 2 — Attacker Agents (M=5)

| Agent | Chuyên môn | Blind spot |
|---|---|---|
| reentrancy_exploiter | ETH drain via recursive call | Read-only reentrancy, cross-function path phức tạp |
| flash_loan_attacker | Oracle manipulation, governance via temp capital | Contracts không dùng external price feed |
| governance_attacker | Privilege escalation, governance bypass | Non-governance contracts |
| access_control_exploiter | Permission escalation, role abuse | Flat permission model |
| logic_exploiter | Business logic bugs, semantic violations | Không có blind spot rõ ràng |

### Hai loại findings — đã tách từ kiến trúc hiện tại

Trong thực tế chỉ có **2 loại vulnerability** mà LLM-based audit phát hiện được:

**1. SWC findings** — mapped to SWC Registry (SWC-101 đến SWC-136):
- Identifier: `swc_id` (stable, standardized) → matchable với ground truth benchmark
- Đơn vị đánh giá: `(swc_id, function_name)`
- Evaluatable trực tiếp: F1, Precision, Recall đo được

**2. Semantic findings** — logic-level bugs không có SWC ID:
- Economic invariant violations, business flow bugs, protocol-specific logic errors
- **Đây là lợi thế cốt lõi của LLM** so với static analysis tools (Slither, Mythril): LLM hiểu business intent, không chỉ code pattern. Bỏ semantic track = thu hẹp tool về mức một static analyzer đắt hơn.
- Đơn vị: `(semantic_category, function_name, description)`
- Không tính vào F1 benchmark nhưng có giá trị thực trong production audit

**Kiến trúc hiện tại đã tách 2 track riêng biệt** — đây không phải cải tiến mới của v2 mà là thiết kế đã có:

```
Session output:
  session_result["expert_findings"]     → raw FINDING blocks    (SWC track)
  session_result["semantic_findings"]   → raw SEMANTIC_FINDING  (Semantic track)
                      ↓ consensus_engine.run()
  report_result["consensus_vulns"]      → SWC findings đã pass  (L-track)
  report_result["semantic_results"]     → Semantic findings đã pass (S-track)
  report_result["unvalidated_swc_gaps"] → SWC findings không pass
```

Cả hai key được lưu riêng trong `audit_report.json`. Title-matching problem của phiên bản cũ đã được giải quyết bằng cách force `swc_id` vào response format thay vì match theo free-text title.

**Điều v2 cần giữ nguyên:** Cấu trúc 2-track output này hoạt động đúng. Pool voting trong Round 1 và Round 2 vẫn là union của cả hai loại — voters đánh giá dựa trên code logic. Separation chỉ xảy ra ở output cuối, giống kiến trúc hiện tại.

---

## Context Strategy cho Round 1 — Structured Summary + Critical Functions

### Vấn đề khi pass full source code

Truyền toàn bộ Solidity source (~54K chars) trực tiếp cho agents gặp hai vấn đề:

1. **Hallucination**: "lost in the middle" — model tập trung vào đầu/cuối context, hallucinate code snippets ở giữa thay vì đọc thực sự.
2. **Thinking token overflow** (với thinking models như Gemini 3 Flash Preview): model dùng hết toàn bộ output token budget cho internal reasoning, không còn token để write findings (`content=None`).

### Giải pháp: Enriched Summary + Critical Function Bodies

```
Round 1 context = contract_summary (enriched)    ← ~5-10K chars
                + CRITICAL FUNCTIONS block        ← ~10-15K chars
                ≈ 15-20K chars total (vs 54K full source)
```

**`contract_summary` enriched** (giữ nguyên pipeline v1) bao gồm:
- KG context: function signatures, safety patterns, risk signals, SWC candidates
- CALL GRAPH: per-function call dependencies với `[EXTERNAL]` markers
- Protocol Intent: NatSpec-derived invariants
- Dep graph text: critical state vars, top writer functions (từ Slither)

**`CRITICAL FUNCTIONS block`** — được thêm mới cho v2:
- Parse `CALL GRAPH` section của `contract_summary` để rank functions theo số callees
- Boost functions có external calls (`[EXTERNAL]` tag) vì là reentrancy candidates
- Extract top-6 function bodies đầy đủ từ `kg_source` (in-scope Solidity source)
- Cap tại 20K chars để tránh overflow

```python
# contract_dep_graph.py
fns = pick_critical_functions_from_summary(contract_summary, top_n=6)
block = extract_function_bodies(kg_source, fns, max_chars=20000)
v2_context = contract_summary + "\n\n" + block
```

**Kết quả thực tế** (contest 35 — ConcentratedLiquidityPool):
- Trước: 54,498 chars → thinking model dùng hết token budget → 0 findings
- Sau: 17,950 chars → agents trả về 3-7 findings/agent trong 30-40s

**Lưu ý về thinking models (Gemini 3 Flash Preview):**
Với thinking models trên Vertex AI, `max_tokens` phải đủ lớn để cover cả thinking tokens + output tokens. Với context ~18K chars, setting `V2_R1_MAX_TOKENS=65536` (env var) đảm bảo model có đủ budget.

---

## Round 1 — Independent Discovery

### Mục tiêu
Tối đa hóa recall. Mỗi agent hoạt động độc lập, không có thông tin từ agent khác, để tránh anchoring bias.

### Cơ chế
- **Agents**: Tất cả N=19 tier-1 expert agents.
- **Input**: `contract_summary` enriched + critical function bodies (xem "Context Strategy" ở trên). Không có context từ round trước. Không có danh sách findings từ agent khác.
- **Output**: Mỗi agent trả về 2 list riêng biệt:
  - SWC findings: `(swc_id, function_name, evidence_snippet)`
  - Semantic findings: `(semantic_category, function_name, description, evidence_snippet)`
  - Mỗi (category, function) là một finding riêng biệt — agent phải list tất cả functions, không dừng ở function đầu tiên.
- **Parser**: `parse_all_contract_findings_from_text()` — trích xuất TẤT CẢ FINDING blocks, không dừng sớm.

### Aggregation sau Round 1
```
raw_swc_pairs:      Dict[(swc_id, fn_name),        List[agent_id]] = {}
raw_semantic_pairs: Dict[(sem_category, fn_name),  List[agent_id]] = {}

for agent_id, findings in all_round1_findings.items():
    for f in findings.swc_findings:
        raw_swc_pairs[(f.swc_id, f.function_name)].append(agent_id)
    for f in findings.semantic_findings:
        raw_semantic_pairs[(f.category, f.function_name)].append(agent_id)
```

- Deduplicate: cùng (category, function) từ nhiều agent → 1 pair, ghi nhận `submitters`.
- Kết quả: `candidate_pool = raw_swc_pairs ∪ raw_semantic_pairs`.

**Ví dụ:**
- Agent A tìm: `(SWC-101, collect())`, `(SWC-101, swap())`
- Agent D tìm: `(SWC-101, swap())`, `(SWC-101, collectProtocolFee())`
- Agent F tìm: `(SWC-101, swap())`
- → Candidates: `{(SWC-101, collect()): [A], (SWC-101, swap()): [A,D,F], (SWC-101, collectProtocolFee()): [D]}`

---

## Round 2 — Parallel Blind Voting

### Mục tiêu
Đo instance-level confidence: function X có thực sự bị SWC Y không? Tránh hallucination cascade.

### Cơ chế

**Self-exclusion rule:** Agent không vote cho finding mà chính nó đã submit trong Round 1.  
→ Tránh double-counting (agent không thể nâng score finding của chính mình).

**Blind voting:** Mỗi agent nhận danh sách pairs cần review (trừ pairs của bản thân) và vote **độc lập**:
- Không biết identity của submitter.
- Không biết số vote hiện tại.
- Không biết kết quả vote của agent khác.

**Vote format:**
```
VOTE: ACCEPT | REJECT
PAIR: (SWC_id, function_name)
EVIDENCE: <code snippet hoặc logic path chứng minh>
REASON: <giải thích ngắn gọn>
```

**Evidence reveal sau khi tất cả submit:**  
Sau khi TẤT CẢ agents đã nộp vote:
- Công bố tất cả `EVIDENCE` snippets (ẩn danh, không kèm agent_id, không kèm vote_count).
- Mỗi agent được phép cập nhật vote MỘT LẦN nếu evidence mới cho thấy code path mình bỏ sót.
- Không được thay đổi vì "nhiều người vote ACCEPT".

### Scoring formula

```
score(SWC, fn) = (k + r) / n

k = số agents đã submit pair này trong Round 1  (implicit ACCEPT = co-discovery)
r = số explicit ACCEPT votes từ agents KHÔNG submit pair này
n = tổng số expert agents
```

**Ý nghĩa:**
- `k/n`: tỉ lệ co-discovery — bao nhiêu experts độc lập tìm ra cùng (SWC, function).
- `r/n`: tỉ lệ corroboration — bao nhiêu experts không tìm ra nhưng xác nhận sau khi review code.
- Score đo CÙNG LÚC khả năng phát hiện và khả năng xác nhận ở instance level.

**Threshold:** `score >= threshold` (đề xuất 0.35–0.5) → pass vào `accepted_finding_list`.

**Ví dụ với n=17:**
- `(SWC-101, swap())`: k=3, r=8 → score = 11/17 = 0.647 → PASS
- `(SWC-101, collect())`: k=1, r=2 → score = 3/17 = 0.176 → REJECT (below threshold)
- `(SWC-101, collectProtocolFee())`: k=1, r=6 → score = 7/17 = 0.412 → PASS

**Trade-off threshold:**
| Threshold | Effect |
|-----------|--------|
| 0.3 | High recall, more FP |
| 0.5 | Balanced |
| 0.6 | High precision, may miss rare bugs |

---

## Round 3 — Blind Attacker Validation

### Mục tiêu
Verify exploitability. Chỉ findings có thể bị exploit thực sự mới pass. Tránh attacker cascade (không copy scenario của nhau).

### Cơ chế

**Attacker pool:** M=5 attacker agents, chuyên viết exploit scenarios.

**Blind exploit writing:** Mỗi attacker nhận:
- Finding: `(category, function_name, contract_source)`
- Không thấy scenario của attacker khác.
- Không thấy Round 2 evidence.

Mỗi attacker có 2 lựa chọn:

**Option A — Viết exploit scenario:**
```
VERDICT: CONFIRMED | PLAUSIBLE | INVALID
ENTRY_POINT: <function hoặc transaction sequence>
PRE_CONDITION: <state cần thiết trước khi exploit>
ATTACK_STEPS: <step-by-step>
EXPECTED_OUTCOME: <profit / state corruption / access gained>
```

**Option B — Declare out-of-scope:**
```
VERDICT: NOT_APPLICABLE
REASON: <lý do cụ thể tại sao finding này nằm ngoài phạm vi chuyên môn>
        Ví dụ: "Contract has no external price feed; flash loan attack vector does not apply."
```

`NOT_APPLICABLE` bị loại khỏi denominator. Attacker không có incentive để lạm dụng: nếu tất cả declare NOT_APPLICABLE → finding tự động vào PoC pipeline — PoC fail → DISCARD.

**Evidence reveal sau khi tất cả submit:**  
- Công bố TẤT CẢ exploit scenarios ẩn danh (ẩn identity, ẩn verdict count).
- Attacker có verdict INVALID được phép update MỘT LẦN nếu scenario khác chỉ ra code path cụ thể mình bỏ sót.
- Không update chỉ vì "scenario khác chi tiết hơn".

**Tiered validation:** LLM judge hoặc automated PoC runner đánh giá từng scenario:

| Verdict | Ý nghĩa | Weight |
|---------|---------|--------|
| `CONFIRMED` | Attack path hoàn chỉnh, executable, pre-condition achievable | 1.0 |
| `PLAUSIBLE` | Logic đúng nhưng thiếu detail cụ thể (missing exact pre-condition) | 0.5 |
| `INVALID` | Hallucinated function, impossible pre-condition, hoặc outcome không xảy ra | 0.0 |
| `NOT_APPLICABLE` | Out-of-scope domain — excluded từ tính toán | excluded |

Lý do dùng tiered thay vì binary: attacker với blind spot partial thường viết scenario có direction đúng nhưng thiếu chi tiết. Binary VALID/INVALID đánh đồng trường hợp này với hallucination hoàn toàn — sai về mức độ.

### Final scoring

```
effective_M = M - not_applicable_count

attacker_rate = Σ weight_i / effective_M
             = (CONFIRMED×1.0 + PLAUSIBLE×0.5 + INVALID×0.0) / effective_M

final_score = round2_score × attacker_rate
```

**Trường hợp đặc biệt:** Nếu `effective_M < 2` (quá ít attacker relevant) → finding tự động vào PoC pipeline bất kể attacker_rate.

**Decision:**

| Điều kiện | Decision |
|-----------|----------|
| `attacker_rate = 0` | **DISCARD** |
| `effective_M < 2` | **PoC pipeline** (không đủ coverage) |
| `0 < attacker_rate < 0.4` | **PoC pipeline** (borderline) |
| `attacker_rate >= 0.4` | **CONFIRMED** vulnerability |

**PoC fallback:**
- Chạy PoC pipeline (Foundry/Hardhat) với best PLAUSIBLE/CONFIRMED scenario.
- PoC pass → CONFIRMED.
- PoC fail → DISCARD.

### Final output

**SWC findings list:**
```json
{
  "type": "swc",
  "swc_id": "SWC-101",
  "function_name": "swap",
  "round2_score": 0.647,
  "attacker_rate": 0.6,
  "effective_attackers": 4,
  "final_score": 0.388,
  "status": "CONFIRMED",
  "exploit_scenarios": [...],
  "round2_evidence": [...]
}
```

**Semantic findings list:**
```json
{
  "type": "semantic",
  "semantic_category": "business_flow_violation",
  "function_name": "withdraw",
  "round2_score": 0.412,
  "attacker_rate": 0.5,
  "effective_attackers": 4,
  "final_score": 0.206,
  "status": "CONFIRMED",
  "description": "...",
  "exploit_scenarios": [...],
  "round2_evidence": [...]
}
```

---

## So sánh với kiến trúc 10-round hiện tại

| Tiêu chí | 10-round hiện tại | 3-round mới |
|----------|-------------------|-------------|
| Đơn vị finding | SWC cluster (class-level) | (SWC, function) pair (instance-level) |
| Confidence đo gì | Có bao nhiêu agent tìm SWC này | Function cụ thể được co-discover + vote |
| Round dư thừa | Phase C 3 rounds lặp review list cũ | Không có round dư thừa |
| CHALLENGE mechanism | Title-string level, không phải instance | Không có CHALLENGE; thay bằng structured vote |
| Evidence | Không verify evidence từng agent | Evidence reveal + one-time update |
| Parser | 1 FINDING per response | Tất cả FINDING blocks per response |
| Attacker | PoC chỉ chạy cho consensus vulns | Attacker round tích hợp với final_score |
| FP control | intra_score + confidence threshold | score = (k+r)/n + attacker_rate gate |

---

## Implementation plan

### Thay đổi bắt buộc

1. **Parser** (`contract_oasis_env.py`): Viết `parse_all_contract_findings_from_text()` — trích xuất list findings thay vì 1 finding.

2. **Prompt** (`contract_oasis_env.py`): Bỏ Phase A/B/C; thay bằng Round 1 prompt (independent, list all (SWC, function), no context).

3. **Orchestrator** (`cyber_session_orchestrator.py`): Thay 10-round loop bằng 3-round flow:
   - Round 1: `_run_discovery_round()` → `raw_pairs`
   - Round 2: `_run_voting_round(raw_pairs)` → `accepted_finding_list`
   - Round 3: `_run_attacker_round(accepted_finding_list)` → `confirmed_vulns`

4. **Scoring** (`consensus_engine.py`): Bỏ `_cluster_by_swc()`; thay bằng `_score_by_instance_pair()` với formula `(k+r)/n`.

5. **Attacker agent** (mới): `ContractAttackerAgent` nhận (SWC, function, source) và viết exploit scenario.

### Thay đổi tùy chọn

- Domain weighting: attacker domain experts có weight cao hơn trong `r` count.
- Adaptive threshold: threshold Round 2 thấp hơn cho rare bug categories (reentrancy < arithmetic).
- PoC integration: reuse existing `PoCVerificationEngine` cho borderline cases.

---

## Tại sao KHÔNG để agents tương tác trực tiếp trong Round 2

Nếu Agent A thấy Agent B vote ACCEPT với reasoning → anchoring bias:
- Agent C tin theo B không vì code evidence mà vì authority/confidence của B.
- Nếu B hallucinate và A,C follow → cascade hallucination → tất cả vote ACCEPT cho finding sai.

**Blind voting + evidence-only reveal** giải quyết:
- Không biết ai vote gì → không bị ảnh hưởng bởi authority.
- Chỉ thấy code evidence → update dựa trên code thực, không phải social influence.
- One-time update → không có spiral discussion.

---

## Lưu ý về self-exclusion và duplicate handling

**Self-exclusion:**
- Agent A submit `(SWC-101, swap())` → A không vote cho pair này trong Round 2.
- A có thể vote cho `(SWC-101, collect())` nếu A không submit pair đó.

**Duplicate từ Round 1:**
- Nếu A và D đều submit `(SWC-101, swap())` → 1 pair duy nhất, `submitters = [A, D]`.
- k=2 (cả A và D đều là co-discoverers).
- A và D đều KHÔNG vote cho pair này trong Round 2 (cả hai bị self-excluded).
- → Chỉ 15 agents còn lại vote.

**Công thức vẫn đúng:** `score = (k + r) / n = (2 + r) / 17`. Pair được cộng điểm từ co-discovery, phần còn lại từ voting pool nhỏ hơn. Không inflation nhân tạo.
