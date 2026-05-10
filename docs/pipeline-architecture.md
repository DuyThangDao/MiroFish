# Smart Contract Audit Pipeline — Architecture (v2)

> Tài liệu mô tả kiến trúc pipeline hiện tại (v2).
> Cập nhật lần cuối: 2026-05-08

---

## Design Principle

R2 adversarial framing được thiết kế dựa trên nguyên tắc *presumption of innocence* — gánh nặng
chứng minh thuộc về bên muốn loại bỏ finding, không phải bên muốn giữ lại. Khi agent không tìm
được lý do cụ thể để REJECT → finding được giữ lại. Thiết kế này ưu tiên tránh bỏ sót true
positive (false negative) hơn là tránh giữ lại false positive — đây là tradeoff phù hợp với bài
toán security audit, nơi chi phí của việc bỏ sót một lỗ hổng thật cao hơn chi phí của việc báo
cáo thêm một false alarm.

---

## Tổng Quan

Pipeline v2 là một hệ thống multi-agent swarm intelligence cho smart contract security audit.
Kiến trúc gồm **5 phase chính**, chạy tuần tự, mỗi phase có mục đích lọc và làm giàu tập findings.

```
[PREP]  STEP 0–2: Phân tích tĩnh + Build KG + Sinh agent profiles
   ↓
[R1]    Round 1: 19 agents độc lập phát hiện vulnerabilities
   ↓
[DEDUP] Anchor Dedup: Loại bỏ findings trùng lặp (static + LLM)
   ↓
[FP]    Pre-R2 FP Check: Lọc hallucination + ATTACK_PATH mờ
   ↓
[R2]    Round 2: 19 agents vote adversarial (REJECT phải có lý do cụ thể)
   ↓
[CAP]   Post-R2 Cap: Giới hạn số lượng output theo score
   ↓
[OUT]   Build output JSON + Evaluate
```

**Entry point:** `backend/scripts/run_contract_audit.py`
**Orchestrator:** `backend/app/services/cyber_session_orchestrator.py`
**Env:** `AUDIT_PIPELINE_VERSION=v2`

---

## Phase 0 — Preparation (STEP 0–2)

### STEP 0: Slither Static Analysis
**File:** `scripts/run_contract_audit.py` (~line 798), `app/services/contract_dep_graph.py`

Chạy Slither (Python API, không qua Docker) để xây dựng dependency graph: ai đọc/ghi state
variable nào, call graph giữa các function.

**Output:** `DepGraphSummary` — tập hàm quan trọng, critical state variables, caller/callee map.

**Tại sao:** Cung cấp `known_functions` để filter hallucinated function names ở R1 parser.
Không dùng Slither để detect bug mà chỉ để grounding agent context.

---

### STEP 1: Build Knowledge Graph
**File:** `scripts/run_contract_audit.py` (~line 304), `app/services/contract_kg_builder.py`

Parse source code → trích xuất ontology (entities, relationships) → lưu vào **Zep Cloud**
knowledge graph.

**Output:** `graph_id`, `contract_summary` (NL overview của contract).

**Tại sao:** Agents không đọc raw source code trực tiếp — họ query KG để lấy context có cấu
trúc. KG cũng lưu invariants và protocol intent để làm reference khi audit.

---

### STEP 1.1: Protocol Intent Extraction
**File:** `scripts/run_contract_audit.py` (~line 332), `app/services/contract_intent_extractor.py`
**Model:** BOOST LLM (`BOOST_MODEL_NAME`) — model nặng hơn primary để reasoning chính xác hơn.

Hai-layer approach:
- **Layer 1 (deterministic):** Regex scan NatSpec `@notice` / `@dev` comments — không cần LLM.
- **Layer 2 (LLM):** Infer intent từ function signatures + `require()` messages + contest README.
  Prompt chỉ gửi metadata (NatSpec + signatures), không gửi raw source (~55K chars) để tránh truncation.

Output là danh sách **protocol MUST statements** theo 5 loại: `ORDERING`, `BOUNDARY`, `ACCOUNTING`, `STATE`, `EFFECT`.

**Output file:** `intent.json` trong output dir.
**Fallback:** Nếu BOOST lỗi → bước này bị skip, `contract_summary` không có intent section. R1 agents vẫn chạy được nhưng thiếu context về design intent.

---

### STEP 1.3: Data-flow Dependency Graph
**File:** `scripts/run_contract_audit.py` (~line 345), `app/services/contract_dep_graph.py`
**Model:** Không dùng LLM — Slither static analysis.

Chạy Slither lần 2 (chi tiết hơn STEP 0) để xây dựng **data-flow dependency graph**: state variable nào được đọc/ghi bởi function nào, caller/callee relationships.

**Output:** `dep_graph.json` + `dep_graph_text` (text summary inject vào R1 prompt).
**Fallback:** Nếu Slither fail → dep graph bị skip, R1 agents thiếu data-flow context.

---

### STEP 1.5: Protocol Invariant Extraction
**File:** `scripts/run_contract_audit.py` (~line 376), `app/services/contract_invariant_extractor.py`
**Model:** BOOST LLM (`BOOST_MODEL_NAME`).

Hai-layer approach:
- **Layer 1 (structural):** Deterministic regex scan — ví dụ: tìm function ghi vào `mapping[addrParam]` mà không có `require(msg.sender == addrParam)`.
- **Layer 2 (LLM):** "Missing enforcement framing" — thay vì hỏi "contract đang enforce gì", hỏi "protocol MUỐN maintain invariant nào nhưng code KHÔNG enforce". Approach này hiệu quả hơn vì trực tiếp target lỗ hổng.

**Output file:** `invariants.json`. Inject vào `contract_summary` cùng với intent → R1 prompt.
**Fallback:** Nếu BOOST lỗi → chỉ có structural invariants (Layer 1), không có LLM-inferred invariants.

---

**Tóm tắt STEP 1.1 → 1.5 → R1:**

```
NatSpec + signatures + README
    │
    ├─[STEP 1.1 — BOOST]──→ intent_statements (ORDERING/BOUNDARY/ACCOUNTING/STATE/EFFECT)
    ├─[STEP 1.3 — Slither]─→ dep_graph_text (data-flow, caller/callee)
    └─[STEP 1.5 — BOOST]──→ invariants (structural + LLM-inferred missing enforcement)
                                    │
                          ┌─────────▼──────────────┐
                          │  contract_summary        │
                          │  = KG summary            │
                          │  + intent_statements     │
                          │  + dep_graph_text        │
                          │  + invariants            │
                          └─────────┬──────────────┘
                                    │
                          inject vào R1 prompt của 19 agents
```

---

### STEP 2: Generate Agent Profiles
**File:** `scripts/run_contract_audit.py` (~line 387), `app/services/contract_profile_generator.py`

Sinh ra hai tier agent profiles từ `CONTRACT_AGENT_MATRIX`:

| Tier | Số lượng | Vai trò |
|------|----------|---------|
| **Tier 1** | 19 agents | Discovery (R1) + Voting (R2) |
| **Tier 2** | 5 agents | Attacker validation (R3 — hiện disabled) |

**19 Tier-1 agents** được tổ chức theo 8 domain group, mỗi group 2–3 persona:

| Domain | Personas | Chuyên môn |
|--------|----------|------------|
| `appsec` | offensive, defensive, auditor | Reentrancy, access control, ERC compliance |
| `blockchain` | offensive, defensive, auditor | MEV, oracle manipulation, storage layout |
| `cryptography` | offensive, defensive | Hash collision, signature malleability |
| `defi` | offensive, defensive, analyst | AMM math, flash loan, price oracle |
| `governance` | offensive, defensive | Voting manipulation, timelock bypass |
| `smart_contract_economics` | offensive, defensive | Incentive misalignment, rounding |
| `defi_math` | offensive, defensive | Precision loss, mul-before-div order |
| `token_standards` | offensive, defensive | ERC-20/721 compliance gaps |

**Tại sao multi-persona:** Mỗi domain có 2–3 góc nhìn khác nhau (tấn công / phòng thủ / audit
chuẩn). Cùng một đoạn code, persona offensive tìm exploit path, persona defensive tìm missing
guard. Tăng độ phủ mà không cần thêm agents.

---

## Phase 1 — Round 1: Independent Discovery

**File:** `cyber_session_orchestrator.py::_run_discovery_round()` (~line 2473)
**Prompt builder:** `contract_oasis_env.py::build_round1_prompt()`
**Parser:** `contract_oasis_env.py::parse_contract_finding_from_text()`

### Cơ chế

19 agents chạy **song song** (`ThreadPoolExecutor`), mỗi agent:
1. Nhận prompt riêng theo domain + persona (không biết agents khác đang tìm gì)
2. Gọi LLM để phân tích toàn bộ source code
3. Output các `FINDING` block theo format bắt buộc

### Output Format (mỗi FINDING)

```
FINDING: <title>
CONTRACT: <contract_name>
FUNCTION: <function_name>
SEVERITY: CRITICAL | HIGH | MEDIUM | LOW
CODE_ANCHOR: <verbatim snippet, phải tồn tại trong source>
EVIDENCE: CODE: <snippet> | MISSING: <what> AT: <loc> | SEQ: ... | INV: ... | DESIGN: ...
ATTACK_PATH:
  ACTOR: <ai tấn công>
  CALL: <hàm nào, theo thứ tự>
  STATE_CHANGE: <state variable nào bị sai và như thế nào>
  OUTCOME: <impact đo được>
DESCRIPTION: <giải thích>
PATCH: <đề xuất fix>
```

### Evidence Gate (Parser)

Parser reject finding nếu EVIDENCE không có ít nhất 1 trong:
- Named Solidity function (e.g., `transfer()`, `approve()`)
- Solidity-specific pattern (e.g., `msg.sender`, `require(`, `mapping(`)

**Tại sao:** Lọc findings quá chung chung không reference code cụ thể.

### Output của R1

`raw_pool`: Dict[pair_id → finding_meta], thường 80–150 findings từ 19 agents.

---

## Phase 2 — Anchor Dedup

**File:** `cyber_session_orchestrator.py::_run_anchor_dedup()` (~line 2261)

Gồm 2 bước chạy tuần tự:

### Bước 1: Static Anchor Dedup
**Hàm:** `_static_anchor_dedup()` (~line 2276)

Group findings theo key `(contract.lower(), function.lower(), normalize(code_anchor))`.
Cùng key = cùng bug → merge: gộp `submitters`, gộp `evidence_snippets`, giữ primary.

**Complexity:** O(n), single-pass. Không cần LLM.

### Bước 2: LLM Anchor Dedup
**Hàm:** `_llm_anchor_dedup()` (~line 2408)

Với các (contract, function) còn ≥2 findings sau Bước 1 → gửi cho LLM quyết định:
```
MERGE [i] == [j] | REASON: ...
KEEP_SEPARATE [i] | REASON: ...
```
Dùng union-find để merge các cặp được LLM đánh dấu. Chạy song song theo group
(`ThreadPoolExecutor`, `LLM_DEDUP_WORKERS`).

**Tại sao 2 bước:** Static dedup nhanh và không tốn token cho các trường hợp rõ ràng
(cùng anchor). LLM dedup xử lý các trường hợp khó hơn (cùng bug, anchor hơi khác nhau).

**Output:** `candidate_pool` sau merge, thường giảm 20–40% so với raw.

---

## Phase 3 — Pre-R2 FP Check

**File:** `cyber_session_orchestrator.py::_dedup_pre_r2()` (~line 2187)

Hai check deterministic, không cần LLM:

### Check 1: CODE_ANCHOR Validation
Normalize `code_anchor` (xóa comments, collapse whitespace, lowercase, cắt 100 ký tự)
→ kiểm tra substring trong normalized source.

Nếu không tìm thấy → drop (agent bịa anchor không tồn tại trong contract).

**Toggle:** `R3_CODE_FP_CHECK=false` để disable.

### Check 2: ATTACK_PATH Structure Validation
**Hàm:** `_validate_attack_path()` (~line 2167)

ATTACK_PATH phải có ≥ 3/4 subfields: `ACTOR:`, `CALL:`, `STATE_CHANGE:`, `OUTCOME:`.
Tối thiểu 50 ký tự.

Nếu thiếu → drop (finding không thể mô tả được exploit path cụ thể → likely FP).

**Toggle:** `ATTACK_PATH_VALIDATION=false` để disable.

**Tại sao tách biệt với dedup:** Đây là FP filter (hallucination detection), không phải
duplicate removal. Chạy sau dedup để không waste filter budget trên findings sẽ bị merge.

**Output:** `candidate_pool` sau lọc, thường giảm thêm 30–50%.

---

## Phase 4 — Round 2: Adversarial Voting

**File:** `cyber_session_orchestrator.py::_run_voting_round()` (~line 2587)
**Prompt builder:** `contract_oasis_env.py::build_round2_prompt()`
**Parser:** `contract_oasis_env.py::parse_round2_votes_from_text()`

### Framing: Adversarial (không phải verification)

> *"Tìm lý do CỤ THỂ để REJECT finding này. Nếu không tìm được → ACCEPT."*

Gánh nặng chứng minh thuộc về bên REJECT, không phải ACCEPT.
Khi uncertain → ACCEPT.

**Tại sao:** Framing "verify exploitability" tạo bias về phía ACCEPT (uncertain → ACCEPT vì
không có cost). Adversarial framing yêu cầu REJECT phải có code reference cụ thể → agents
không thể lazy REJECT.

### Phase 4A: Initial Voting

19 agents chạy song song, **self-exclusion**: agent không vote finding do mình submit.

**Vote format:**
```
VERDICT: ACCEPT | REJECT
PAIR: <pair_id>
COUNTER_TYPE: PHANTOM | ACCESS_BLOCKED | NO_STATE_CHANGE | NO_IMPACT  (chỉ nếu REJECT)
COUNTER: <code element cụ thể — function name, modifier, state variable, ≥ 20 chars>
```

**4 loại REJECT hợp lệ (COUNTER_TYPE):**
| Type | Ý nghĩa |
|------|---------|
| `PHANTOM` | Snippet/function không tồn tại ở location đã claim |
| `ACCESS_BLOCKED` | Path bị chặn bởi modifier (onlyOwner, v.v.) |
| `NO_STATE_CHANGE` | Operation là read-only, không mutate state |
| `NO_IMPACT` | Outcome mô tả không reachable trong execution path |

**Lazy REJECT = Neutral:** REJECT không có COUNTER_TYPE hợp lệ hoặc COUNTER < 20 chars
→ không được đếm vào scoring → finding dễ pass hơn → disincentive để lazy REJECT.

**Hàm validate:** `_is_valid_reject()` (~line 2178)

### Phase 4B: Evidence Reveal + Update Vote

Sau khi collect tất cả initial votes → aggregate evidence theo pair →
gửi lại cho mỗi agent xem evidence của tất cả voters → agent có thể cập nhật vote.

**Tại sao:** Cho phép genuine information sharing. Agent A tìm được "read-only" → 
Agent B chưa nhận ra → B đổi sang REJECT sau khi thấy lý do của A. Không phải echo chamber
vì agent A cũng có thể thay đổi nếu thấy counter-evidence từ B.

### Phase 4C: Scoring

```
k            = số agents submit finding này ở R1 (free votes)
accept       = số ACCEPT votes từ eligible agents
valid_reject = số REJECT có COUNTER_TYPE hợp lệ + COUNTER ≥ 20 chars
eligible     = accept + valid_reject
score        = (k + accept) / (k + eligible)   nếu (k + eligible) > 0 else 0
```

**Pass khi cả hai điều kiện thỏa mãn:**
```
score ≥ 0.42   (R2_THRESHOLD, env: R2_SCORE_THRESHOLD)
accept ≥ 4     (r_min, env: R2_R_MIN)
```

**Tại sao formula mới (không dùng n_agents ở denominator):**
- Lazy REJECT (không có COUNTER_TYPE) không ảnh hưởng score
- Valid REJECT mới làm giảm score → chỉ REJECT có lý do cụ thể mới "kill" finding
- r_min=4 bảo vệ high-k findings khỏi pass với quá ít community validation

**Output:** `accepted_findings` (list), `all_votes` (dict).

---

## Phase 5 — Post-R2 Score Cap

**File:** `cyber_session_orchestrator.py::_dedup_pre_r3()` (~line 2187)

Sort `accepted_findings` theo `round2_score` descending → giữ top `R3_MAX_FINDINGS` (default 40).

**Tại sao:** Giới hạn số lượng output tránh noise. Findings với score cao nhất được ưu tiên.

---

## Phase 6 — Output + Evaluation

### Build Output
**File:** `app/services/consensus_engine.py::build_v2_output()` (~line 1092)

Convert accepted findings sang schema chuẩn:
```json
{
  "finding_id": "finding_xxxxx",
  "title": "...",
  "description": "...",
  "attack_path": "...",
  "contract_name": "...",
  "function_name": "...",
  "severity": "high | medium | low",
  "confidence_score": 0.0–1.0,
  "evidence": "...",
  "patch": "...",
  "supporting_domains": ["appsec", "defi", ...],
  "v2_pair_id": "...",
  "v2_round2_score": 0.0–1.0
}
```

**Severity mapping:** confidence ≥ 0.7 → high | ≥ 0.4 → medium | < 0.4 → low.

**Output files:** `audit_report.json`, `audit_report.md`, `session_result.json`

### Evaluation (Web3Bugs F1)
**File:** `scripts/evaluate/web3bugs_eval.py`

Match findings với Ground Truth (H-bug list) theo:
1. Filter theo `(contract_name, function_name)` → candidates
2. LLM semantic judge: `judge_match(gt_bug, candidate)` → True/False
3. Tính TP/FP/FN → Precision / Recall / F1

**GT format:** `scripts/evaluate/gt/gt_<contest_id>.json`

---

## Env Vars Quan Trọng

| Var | Default | Ý nghĩa |
|-----|---------|---------|
| `AUDIT_PIPELINE_VERSION` | `v1` | Phải set `v2` để dùng pipeline này |
| `R2_SCORE_THRESHOLD` | `0.42` | Score tối thiểu để finding pass R2 |
| `R2_R_MIN` | `4` | Số ACCEPT tối thiểu để pass R2 |
| `R3_MAX_FINDINGS` | `40` | Global cap số findings sau R2 |
| `R3_CODE_FP_CHECK` | `true` | Bật/tắt CODE_ANCHOR existence check |
| `ATTACK_PATH_VALIDATION` | `true` | Bật/tắt ATTACK_PATH structure check |
| `LLM_MAX_WORKERS` | `1` | Concurrency cho R1 + R2 agent calls |
| `LLM_DEDUP_WORKERS` | `2` | Concurrency cho LLM anchor dedup |
| `STOP_AFTER_R1` | `false` | Dừng sau R1+dedup, dump findings ra file |
| `BOOST_MODEL_NAME` | — | Model nặng hơn cho STEP 1.1 intent + STEP 1.5 invariant extraction |
| `BOOST_BASE_URL` | — | Vertex AI endpoint cho BOOST model (có thể khác project với LLM primary) |
| `LLM_VERTEX_AI_KEY_FILE` | — | Service account JSON cho LLM primary pool (cũng dùng cho BOOST nếu không set BOOST_API_KEY) |
| `LLM2_VERTEX_AI_KEY_FILE` | — | Service account JSON cho LLM secondary pool (load-balance với primary) |
| `LLM2_BASE_URL` | — | Vertex AI endpoint cho account thứ 2 |
| `LLM2_GLOBAL_RPM_LIMIT` | — | RPM limit cho account thứ 2 |

---

## Luồng Dữ Liệu Tóm Tắt

```
Source code
    │
    ├─[Slither]──→ known_functions, dep_graph
    ├─[KG Builder]─→ graph_id, contract_summary
    └─[Profile Gen]─→ 19 T1 agent profiles
                              │
                    ┌─────────▼─────────┐
                    │    Round 1 (R1)   │  19 agents parallel
                    │  build_round1_    │  → 80–150 raw findings
                    │  prompt() + parse │
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Anchor Dedup    │  static (O(n)) + LLM
                    │  _static_anchor_  │  → merge duplicates
                    │  _llm_anchor_     │  → -20–40%
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Pre-R2 FP Check  │  deterministic, no LLM
                    │  CODE_ANCHOR +    │  → drop hallucinations
                    │  ATTACK_PATH      │  → -30–50%
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │    Round 2 (R2)   │  19 agents parallel
                    │  Adversarial Vote │  → score per finding
                    │  + Evidence Reveal│  threshold=0.42, r_min=4
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Post-R2 Score Cap│  top 40 by score
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Output + Eval   │  audit_report.json
                    │  build_v2_output  │  web3bugs_eval.py
                    └───────────────────┘
```

---

## Ghi Chú

- **Round 3 (Attacker Validation):** Đã implement nhưng hiện **disabled** trong luồng chính.
  Code vẫn còn trong `_run_attacker_round()` nhưng không được gọi. Có thể re-enable sau.
- **v1 pipeline:** Vẫn còn trong codebase (10-round Phase A/B/C), dùng khi
  `AUDIT_PIPELINE_VERSION` không phải `v2`.
- **Zep Cloud:** Dùng cho KG storage. Cần `ZEP_API_KEY` hợp lệ. Nếu quota hết →
  update key mới trong `.env`.
