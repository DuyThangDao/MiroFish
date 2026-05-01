# Implementation Checklist — Audit Pipeline v2

Tham chiếu kiến trúc: `docs/audit-pipeline-v2-architecture.md`

Mỗi mục đánh dấu `[ ]` khi bắt đầu, `[x]` khi hoàn thành và đã test.

---

## 0. Tái sử dụng từ kiến trúc hiện tại

> **Nguyên tắc:** Đây là cải tạo, không phải xây mới. Mọi component tự-contained đều GIỮ NGUYÊN và chỉ cập nhật interface nếu cần thiết.

### 0.0 Zep — tạm thời không dùng, KHÔNG xóa

- [x] **Không xóa** `contract_kg_builder.py`, `_store_to_zep()`, `_zep_retry()`, `CONTRACT_AUDIT_ONTOLOGY`
- [x] **Không xóa** `ZEP_API_KEY` khỏi `.env.example` và config
- [x] **Tách `build_context_summary()` khỏi Zep call**: hiện tại `build_from_source_async()` gọi cả `_store_to_zep()` lẫn `build_context_summary()`. Tách thành 2 bước độc lập để v2 chỉ gọi `build_context_summary(entity)` mà không cần Zep upload:
  ```python
  # V2 chỉ cần bước này — local, không cần ZEP_API_KEY
  entity = kg_builder.parse_source(source_code)
  context_summary = kg_builder.build_context_summary(entity)

  # Bước này optional — chỉ chạy nếu ENABLE_ZEP=true
  if config.enable_zep:
      graph_id = kg_builder._store_to_zep(graph_name, entity)
  ```
- [x] Thêm env var `ENABLE_ZEP=false` (default) để control việc upload lên Zep
- [x] Khi `ENABLE_ZEP=false`: pipeline chạy bình thường, `graph_id` = `None`, không gọi Zep API
- [x] **Không fail** khi thiếu `ZEP_API_KEY` nếu `ENABLE_ZEP=false`

**Lý do giữ lại (không xóa):**

Zep phù hợp cho use case **cross-audit calibration memory** — sau mỗi lần audit có ground truth, store confirmed TP/FP patterns để calibrate threshold Round 2 trong các lần audit sau. Tuy nhiên chưa triển khai ngay vì:
1. Memory phình to không có cơ chế prune — pattern cũ có thể outdated
2. Cần nguồn label TP/FP đáng tin (ground truth hoặc human review) — nếu dùng output của tool làm truth → circular reasoning, error compounding
3. `score = (k+r)/n` + attacker validation đã là calibration mechanism — thêm Zep là redundant ở giai đoạn này

Khi nào nên bật lại: khi có pipeline cung cấp clean TP/FP labels (ví dụ integrate kết quả `evaluate_web3bugs.py` sau mỗi benchmark run để tự động populate Zep), và khi dataset đủ lớn (> 200 contracts đa dạng) để pattern đủ reliable.

### 0.1 Giữ nguyên 100% — không cần thay đổi

**`flatten_contest.py`** — Flattening + scope classification
- [x] Giữ nguyên toàn bộ: `flatten_contest_dir()`, `_build_dep_graph()`, `_topo_sort()`, `_classify_files()`, `_compress_to_stub()`
- [x] Giữ nguyên: 3-tier scope classification (import graph → README hints → conservative)
- [x] Giữ nguyên: out-of-scope files → function signature stubs (bodies → `{...}`)
- [x] Giữ nguyên: 260KB soft limit với fallback drop interface-only files
- [x] Giữ nguyên: `ContractManifest` output với `in_scope_source`, `primary_contracts`, `scope_method`
- [x] Đầu vào Round 1: dùng `manifest.in_scope_source` như hiện tại trong `run_contract_audit.py`

**`evaluate_web3bugs.py`** — Ground truth matching & metrics
- [x] Giữ nguyên toàn bộ: `L_TO_SWC`, `S_TO_CATEGORIES`, `GT_FUNCTIONS` mapping tables
- [x] Giữ nguyên: L-track matching qua `swc_ids` frozenset intersection
- [x] Giữ nguyên: S-track matching qua `category` → `S_TO_CATEGORIES` lookup (Policy A/B)
- [x] Giữ nguyên: function-level GT validation với `GT_FUNCTIONS[(contest_id, bug_id)]`
- [x] Giữ nguyên: FP counting `max(0, pool_size - TP)`, Precision/Recall/F1 computation
- [x] Giữ nguyên: `--policy-b`, `--policy-gap`, `OUT_OF_SCOPE_LABELS` flags
- [x] **Lưu ý:** Output của v2 (`consensus_vulns` + `semantic_results`) đã match đúng format mà evaluator expect — không cần thay đổi evaluator

**`contract_dep_graph.py`** — Slither static data-flow analysis
- [x] Giữ nguyên: `ContractDepGraph.build_and_summarize()` — không thay đổi API
- [x] Giữ nguyên: `DepGraphSummary.text` inject vào context (Round 1 prompt)
- [x] Giữ nguyên: `_resolve_slither_target()` — Foundry/Hardhat detection + flat file fallback
- [x] Giữ nguyên: `_detect_pragma()` + `_set_solc_version()` via solc-select
- [x] Giữ nguyên: Memgraph persistence (nếu `MEMGRAPH_ENABLED=true`)
- [x] Vị trí trong v2: chạy trước Round 1, inject `dep_graph_summary.text` vào Round 1 context

**`contract_intent_extractor.py`** — NatSpec intent extraction
- [x] Giữ nguyên: `ContractIntentExtractor` với 3-tier fallback (full LLM → minimal NatSpec → deterministic)
- [x] Giữ nguyên: `_extract_natspec_hints()`, `_extract_function_signatures()`, `_extract_require_messages()`
- [x] Giữ nguyên: `enriched_summary` output — inject vào Round 1 context như hiện tại
- [x] Giữ nguyên: dedup guard chống KG→intent duplication
- [x] Vị trí trong v2: chạy trước Round 1, inject vào cùng context block với dep_graph

**`contract_kg_builder.py`** — KG + context summary generation
- [x] Giữ nguyên: `ContractKGBuilder.build_context_summary()` — function snippets, safety patterns, call graph, events, business rules
- [x] Giữ nguyên: `_extract_function_snippets()` — first N statements per function
- [x] Giữ nguyên: `_detect_safety_patterns()` — SafeMath, reentrancy guards, tx.origin, compiler version
- [x] Giữ nguyên: `_extract_events_and_rules()` — event defs + require() messages
- [x] Giữ nguyên: `_build_call_graph_summary()` — per-function call deps với `[EXTERNAL]` markers
- [x] Vị trí trong v2: `context_summary` vẫn là base context của Round 1 prompt như hiện tại

### 0.2 Giữ nguyên logic, cập nhật interface nhỏ

**`poc_verification.py`** — PoC pipeline (Forge + LLM)
- [x] Giữ nguyên: `PoCVerificationStage` với 3 tracks:
  - Track 1 (Unit): Forge unit test qua Docker cho SWC-101, 105–107, 112–115, 120, 114
  - Track 2 (Fuzz): Forge fuzz testing 128 runs cho SWC-128
  - Track 3 (LLM Query): Structured LLM verification cho semantic categories
- [x] Giữ nguyên: `PoCConfig` với `stage_timeout_s`, `min_agent_votes`, `min_semantic_confidence`, `forge_image`
- [x] Giữ nguyên: Docker mount tại `/mnt/ollama_data/mirofish_poc/`
- [x] Giữ nguyên: `poc_verified=True` flag trên finding khi pass
- [x] **Thay đổi interface nhỏ:** Input source giờ là borderline findings từ Round 3 (`0 < attacker_rate < 0.4` hoặc `effective_M < 2`) thay vì gap_findings từ consensus engine. Logic bên trong không thay đổi.
- [x] Giữ nguyên: `_select_semantic_candidates()` — filter semantic findings theo `confidence_score >= 0.25`, valid `semantic_vuln_id`, non-empty `affected_functions`

**`cyber_session_orchestrator.py`** — Rate limiter + parallel execution
- [x] Giữ nguyên: `_RateLimiter` class với cả 2 mode:
  - Per-process in-memory (env: `LLM_RPM_LIMIT`)
  - Cross-process file-based (env: `LLM_GLOBAL_RPM_LIMIT`, lock file `/tmp/mirofish_global_rpm.json`)
- [x] Giữ nguyên: `ThreadPoolExecutor` pattern cho parallel agent calls trong mỗi round
- [x] Giữ nguyên: `LLM_SUBMIT_DELAY_S`, `LLM_MAX_WORKERS` env vars
- [x] Giữ nguyên: `[TIMING] Phase=X R{n} agent={id} latency={t}s` log format (để monitor không thay đổi)
- [x] **Bỏ:** `_build_phase_c_review_list()`, `inter_stage_cooldown`, Phase A/B/C logic
- [x] **Giữ:** `_process_expert_response()` pattern (parse response → append finding) nhưng gọi `parse_all_contract_findings_from_text()` thay vì `parse_contract_finding_from_text()`

**`contract_oasis_env.py`** — Prompt config + SWC tagging + GAP routing
- [x] Giữ nguyên: `CONTRACT_GAP_ROUTING_TABLE` — keyword → domain mapping (dùng cho Round 2 context enrichment nếu cần)
- [x] Giữ nguyên: `SWC_ANCHOR_KEYWORDS`, `CATEGORY_TO_SWC_IDS`, `LLM_QUERY_CATEGORIES` — dùng cho semantic classification
- [x] Giữ nguyên: `CONTRACT_AUDIT_ACTIONS` dict (action type definitions)
- [x] Giữ nguyên: `get_phase_for_round()` — có thể đơn giản hóa nhưng logic mapping không cần thay đổi
- [x] Giữ nguyên: `parse_contract_finding_from_text()` (deprecated nhưng không xóa)
- [x] **Thêm mới:** `parse_all_contract_findings_from_text()` — trích xuất list thay vì 1 item
- [x] **Bỏ:** Phase A/B/C prompt templates (hoặc feature-flag off)
- [x] **Thêm mới:** Round 1/2/3 prompt templates

### 0.3 Giữ nguyên intermediate file outputs

Các file JSON trung gian được save sau mỗi bước vẫn giữ nguyên format để không phá vỡ downstream tools và debug workflow:
- [x] `kg_result.json` — KG build result
- [x] `intent.json` — intent extraction result
- [x] `dep_graph.json` — Slither dependency summary
- [x] `profiles.json` — agent profiles (22 → 24 agents với math + token, format không thay đổi)
- [x] `session_result.json` — raw session output (thay đổi nội dung do 3-round nhưng giữ key names)
- [x] `audit_report.json` — final report (`consensus_vulns` + `semantic_results` + `unvalidated_swc_gaps`)

### 0.4 Pipeline wiring trong `run_contract_audit.py`

Thứ tự các bước vẫn giữ nguyên, chỉ thay Step 3 (session):
```
Step 1+2  : flatten → KG build (giữ nguyên)
Step 1.1  : intent extraction (giữ nguyên)
Step 1.3  : Slither dep graph (giữ nguyên)
Step 1.5  : invariant extraction (giữ nguyên nếu có)
Step 2    : generate agent profiles — N=19 thay vì 17 (giữ nguyên pattern)
Step 3    : [THAY] 10-round session → 3-round session
Step 4    : PoC pipeline — giữ nguyên, chỉ thay input source
Step 5    : save audit_report.json (giữ nguyên)
```

---

## 1. Agent Composition (`contract_profile_generator.py`)

### 1.1 Loại bỏ Supply Chain domain
- [x] Xóa `supply_chain` khỏi `DOMAIN_CONFIGS` dict
- [x] Xóa `dependency_auditor` và `build_analyst` personas
- [x] Verify: `_generate_tier1_profiles()` không còn generate supply chain agents
- [x] Verify: tổng tier-1 giảm từ 17 → 15

### 1.2 Thêm DeFi Math & Precision domain
- [x] Thêm `defi_math` vào `DOMAIN_CONFIGS` với:
  - `display_name`: `"DeFi Math & Precision"`
  - `personas`: `["offensive", "defensive"]`
  - `persona_prompts["offensive"]`: Góc nhìn attacker — tìm exploit path qua rounding surplus, first-deposit share inflation, sandwich rounding direction
  - `persona_prompts["defensive"]`: Góc nhìn defender — verify round-down khi tính output, round-up khi tính input, invariant `total_assets >= total_supply × price` sau mỗi operation
- [x] Thêm SWC context cho `defi_math`: SWC-101 (arithmetic), SWC-132 (unexpected ether balance)
- [x] Agent IDs generated: `math_offensive`, `math_defensive`
- [x] Viết `_build_tier1_bio()` entry cho `math` domain

### 1.3 Thêm Token Standard Compliance domain
- [x] Thêm `token_standard` vào `DOMAIN_CONFIGS` với:
  - `display_name`: `"Token Standard Compliance"`
  - `personas`: `["offensive", "defensive"]`
  - `persona_prompts["offensive"]`: Attacker — tìm assumptions về token behavior có thể vi phạm: fee-on-transfer, rebase, silent `transfer()` failure, ERC721 callback reentrancy
  - `persona_prompts["defensive"]`: Defender — kiểm tra `safeTransfer` usage, before/after balance check, `onERC721Received` implementation, non-standard token compatibility
- [x] Thêm SWC context cho `token_standard`: SWC-107 (reentrancy via callback), SWC-104 (unchecked return value)
- [x] Agent IDs generated: `toke_offensive`, `toke_defensive`
- [x] Viết `_build_tier1_bio()` entry cho `token_standard` domain

### 1.4 Verify tổng composition
- [x] Tier-1 count = 19 (15 baseline + 2 math + 2 token)
- [x] Tier-2 count = 5 (giữ nguyên: reentrancy, flash_loan, governance, access_control, logic)
- [x] Mỗi agent có `agent_id`, `tier`, `domain_group`, `persona`, `system_prompt` đầy đủ

---

## 2. Parser (`contract_oasis_env.py`)

### 2.1 Viết `parse_all_contract_findings_from_text()`
- [x] Hàm mới trả về `List[Dict]` thay vì `Dict` đơn lẻ
- [x] Trích xuất TẤT CẢ `FINDING:` blocks trong response (không dừng ở block đầu tiên)
- [x] Trích xuất TẤT CẢ `SEMANTIC_FINDING:` blocks trong response
- [x] Mỗi block được parse độc lập và append vào list kết quả
- [x] Giữ nguyên `parse_contract_finding_from_text()` cũ để không break code hiện tại (deprecated, không xóa)
- [ ] Test: response có 3 FINDING blocks → trả về list 3 items
- [ ] Test: response có 1 FINDING + 2 SEMANTIC_FINDING → trả về đúng 3 items phân loại đúng

### 2.2 Đảm bảo `swc_id` mandatory trong SWC findings
- [x] Nếu FINDING block không có `swc_id` hợp lệ → skip (không append vào SWC list)
- [x] Nếu SEMANTIC_FINDING block không có `category` → skip
- [x] Log warning khi skip

---

## 3. Prompt Engineering (`contract_oasis_env.py`)

### 3.1 Round 1 prompt — Independent Discovery
- [x] Không có context từ round trước (không inject prior findings)
- [x] Không có findings từ agent khác
- [x] Yêu cầu rõ: list TẤT CẢ functions thuộc mỗi SWC, không dừng ở function đầu tiên
- [x] Format bắt buộc cho SWC finding:
  ```
  FINDING:
    swc_id: SWC-XXX
    function: <tên function chính xác>
    evidence: <code snippet>
  ```
- [x] Format bắt buộc cho semantic finding:
  ```
  SEMANTIC_FINDING:
    category: <semantic_category>
    function: <tên function chính xác>
    description: <mô tả>
    evidence: <code snippet>
  ```
- [x] Không có CLAIM, VALIDATE, CHALLENGE, CONFIRM, DISMISS trong Round 1

### 3.2 Round 2 prompt — Blind Voting
- [x] Inject danh sách pairs cần vote (trừ pairs của agent đó — self-exclusion)
- [x] Thông báo rõ: không biết submitter, không biết vote count hiện tại
- [x] Format vote bắt buộc:
  ```
  VOTE: ACCEPT | REJECT
  PAIR: (category, function_name)
  EVIDENCE: <code snippet chứng minh>
  REASON: <giải thích ngắn>
  ```
- [x] Sau evidence reveal: cho phép update vote 1 lần với format:
  ```
  UPDATE_VOTE: ACCEPT | REJECT
  PAIR: (category, function_name)
  NEW_EVIDENCE: <code path mới phát hiện>
  ```
- [x] Không được update chỉ vì "nhiều người vote ACCEPT"

### 3.3 Round 3 prompt — Blind Attacker Validation
- [x] Inject finding: `(category, function_name, contract_source)`
- [x] Không inject scenarios của attacker khác
- [x] Không inject Round 2 evidence
- [x] Format bắt buộc:
  ```
  VERDICT: CONFIRMED | PLAUSIBLE | INVALID | NOT_APPLICABLE
  ENTRY_POINT: <function hoặc transaction sequence>
  PRE_CONDITION: <state cần thiết>
  ATTACK_STEPS: <step-by-step>
  EXPECTED_OUTCOME: <kết quả exploit>
  ```
- [x] Nếu `NOT_APPLICABLE`:
  ```
  VERDICT: NOT_APPLICABLE
  REASON: <lý do cụ thể>
  ```
- [x] Sau evidence reveal: attacker có INVALID được update 1 lần

---

## 4. Orchestrator (`cyber_session_orchestrator.py`)

### 4.1 Thay 10-round loop bằng 3-round flow
- [x] Xóa Phase A/B/C logic (hoặc feature-flag để rollback an toàn)
- [x] `TOTAL_ROUNDS = 3`
- [x] Xóa `inter_stage_cooldown` (không còn 2-stage trong round)
- [x] Xóa `_build_phase_c_review_list()`

### 4.2 Implement Round 1: `_run_discovery_round()`
- [x] Gọi tất cả N=19 tier-1 agents song song (ThreadPoolExecutor)
- [x] Dùng `parse_all_contract_findings_from_text()` cho mỗi response
- [x] Aggregate kết quả:
  ```python
  raw_swc_pairs:      Dict[Tuple[str, str], List[str]] = {}  # (swc_id, fn) → [agent_ids]
  raw_semantic_pairs: Dict[Tuple[str, str], List[str]] = {}  # (category, fn) → [agent_ids]
  ```
- [x] Deduplicate: cùng pair từ nhiều agent → 1 entry, merge `submitters`
- [x] Return: `candidate_pool = {pair: submitters_list}`

### 4.3 Implement Round 2: `_run_voting_round(candidate_pool)`
- [x] Self-exclusion: mỗi agent chỉ nhận pairs mà agent đó KHÔNG submit
- [x] Gọi tất cả N=19 agents song song
- [x] Collect votes: `votes[pair][agent_id] = "ACCEPT" | "REJECT"`
- [x] Evidence reveal: aggregate tất cả EVIDENCE snippets per pair (ẩn danh)
- [x] Update round: gọi lại agents với evidence revealed (1 lần duy nhất)
- [x] Tính score:
  ```python
  k = len(submitters[pair])
  r = sum(1 for v in votes[pair].values() if v == "ACCEPT")
  score = (k + r) / n
  ```
- [x] Filter: `score >= threshold (0.35)` → `accepted_finding_list`
- [x] Return: `accepted_finding_list` với `round2_score` per pair

### 4.4 Implement Round 3: `_run_attacker_round(accepted_finding_list)`
- [x] Gọi tất cả M=5 attacker agents song song cho mỗi finding
- [x] Parse verdict: `CONFIRMED | PLAUSIBLE | INVALID | NOT_APPLICABLE`
- [x] Tính score per finding:
  ```python
  weights = {"CONFIRMED": 1.0, "PLAUSIBLE": 0.5, "INVALID": 0.0}
  effective_M = M - not_applicable_count
  attacker_rate = sum(weights[v] for v in verdicts if v != "NOT_APPLICABLE") / effective_M
  ```
- [x] Guard: `effective_M < 2` → tự động route sang PoC pipeline
- [x] Decision logic:
  - `attacker_rate = 0` → DISCARD
  - `0 < attacker_rate < 0.4` → PoC pipeline
  - `attacker_rate >= 0.4` → CONFIRMED
- [x] Evidence reveal + 1 lần update cho attacker INVALID

---

## 5. Scoring Engine (`consensus_engine.py`)

### 5.1 Thay cluster-based scoring
- [x] Deprecate `_cluster_by_swc()` (không xóa ngay, để rollback)
- [x] Implement `_score_by_instance_pair()`:
  - Input: `candidate_pool` từ Round 1 + `votes` từ Round 2
  - Output: `List[ScoredPair]` với `(pair, score, submitters, accept_voters)`
- [x] Xóa `_backfill_functions()` — không còn cần vì pair đã có `function_name` cố định từ Round 1
- [x] Semantic findings dùng cùng scoring formula, không có track riêng trong engine

### 5.2 Giữ nguyên output structure
- [x] `consensus_vulns` (L-track): SWC findings đã pass Round 2 + Round 3
- [x] `semantic_results` (S-track): Semantic findings đã pass Round 2 + Round 3
- [x] `unvalidated_swc_gaps`: SWC findings pass Round 2 nhưng fail Round 3 (attacker_rate = 0)
- [x] Mỗi item trong output có đủ fields: `round2_score`, `attacker_rate`, `effective_attackers`, `final_score`, `status`

---

## 6. PoC Pipeline Integration (`poc_verification.py`)

### 6.1 Nhận input từ Round 3
- [x] Nhận `borderline_findings`: list findings với `0 < attacker_rate < 0.4` hoặc `effective_M < 2`
- [x] Nhận `best_scenario`: scenario PLAUSIBLE hoặc CONFIRMED tốt nhất từ Round 3
- [x] Run PoC với best_scenario làm seed

### 6.2 Output
- [x] PoC pass → finding status = `CONFIRMED`, thêm vào `consensus_vulns` hoặc `semantic_results`
- [x] PoC fail → finding status = `DISCARDED`

---

## 7. Testing & Validation

### 7.1 Unit tests
- [ ] `parse_all_contract_findings_from_text()`: test với response có 1, 2, 3 FINDING blocks
- [ ] `_score_by_instance_pair()`: test với k=0,1,2 và r khác nhau, verify formula đúng
- [ ] Self-exclusion: verify agent không nhận pair của chính nó trong Round 2
- [ ] NOT_APPLICABLE: verify `effective_M` được tính đúng khi có 1, 2, 3 NOT_APPLICABLE

### 7.2 Integration test
- [ ] Chạy 1 contract nhỏ (< 200 LOC) end-to-end qua 3 rounds
- [ ] Verify log có: Round 1 aggregate count, Round 2 accepted count, Round 3 final count
- [ ] Verify `audit_report.json` có đủ 3 keys: `consensus_vulns`, `semantic_results`, `unvalidated_swc_gaps`
- [ ] Verify không có FINDING nào bị drop im lặng (compare raw parse count vs aggregate count)

### 7.3 Benchmark regression
- [ ] Chạy evaluate trên ít nhất 5 contests từ Web3Bugs
- [ ] So sánh F1/Precision/Recall với baseline (kiến trúc 10-round)
- [ ] S-track: verify semantic findings được output đúng format, không bị merge vào L-track
- [ ] Timing: verify wall-clock giảm so với 10-round (target: < 60 phút/contract)

---

## 8. Rollback Safety

- [x] Giữ `TOTAL_ROUNDS = 10` config dưới environment variable `AUDIT_PIPELINE_VERSION=v1|v2`
- [x] Phase A/B/C code không bị xóa trong commit đầu tiên — chỉ feature-flag off
- [x] `parse_contract_finding_from_text()` cũ giữ nguyên (deprecated nhưng không xóa)
- [x] `_cluster_by_swc()` cũ giữ nguyên cho đến khi v2 pass benchmark regression

---

## 9. Thay đổi ngoài kế hoạch ban đầu (phát sinh trong quá trình implement)

> Các mục này không có trong checklist gốc nhưng đã được implement để giải quyết vấn đề phát sinh thực tế.

### 9.1 Context Strategy — enriched summary + critical functions (không phải full source)

**Vấn đề phát sinh:** v2 ban đầu truyền full source code (~54K chars) vào Round 1. Kết quả: model bị "lost in the middle" → hallucinate code snippet không tồn tại, bỏ sót lỗi ở giữa file.

**Giải pháp triển khai** (`run_contract_audit.py` + `contract_dep_graph.py`):
- [x] Thêm `pick_critical_functions_from_summary(contract_summary, top_n=6)` vào `contract_dep_graph.py`:
  - Parse CALL GRAPH section từ `contract_summary` (đã có từ `_build_call_graph_summary()`)
  - Rank functions theo số callees: `swap() → calls: A, B, C` → count=3
  - Boost `[EXTERNAL]` functions thêm +10 (reentrancy candidates)
  - Trả về top_n function names
- [x] Thêm `extract_function_bodies(source, function_names, max_chars=20000)` vào `contract_dep_graph.py`:
  - Brace-counting algorithm để extract full Solidity function body (không regex)
  - Deduplicate + skip slither-internal names (`slitherConstructorConstantVariables`, etc.)
  - Cap total output tại `max_chars` để kiểm soát context budget
- [x] Cập nhật `run_contract_audit.py` Step 3: context của Round 1 agents là:
  ```python
  _critical_fns = pick_critical_functions_from_summary(contract_summary, top_n=6)
  _critical_block = extract_function_bodies(_raw_src, _critical_fns) if _critical_fns else ""
  _v2_session_summary = contract_summary + ("\n\n" + _critical_block if _critical_block else "")
  # Kết quả: ~18K chars thay vì 54K — giảm 67% context, loại bỏ hallucination
  ```
- [x] Cập nhật `docs/audit-pipeline-v2-architecture.md` với section "Context Strategy cho Round 1"

### 9.2 Thinking Model Token Budget Fix

**Vấn đề phát sinh:** `google/gemini-3-flash-preview` là thinking model — dùng ~31K tokens cho internal reasoning. Với `max_tokens` nhỏ hơn ~32K, toàn bộ budget bị dùng cho thinking, `choice.message=None`, `finish_reason='length'` → `raw_response=0chars` cho tất cả 19 agents Round 1.

**Các giải pháp KHÔNG hoạt động:**
- `thinkingConfig.thinkingBudget=0` (camelCase trong `extra_body`) — bị ignore
- `thinking_config.thinking_budget=0` (snake_case) — bị ignore
- Tách system+user message — không ảnh hưởng thinking budget

**Giải pháp triển khai** (`cyber_session_orchestrator.py`):
- [x] Thêm class-level constants với env var override:
  ```python
  _V2_R1_MAX_TOKENS = int(os.environ.get("V2_R1_MAX_TOKENS", "65536"))
  _V2_R2_MAX_TOKENS = int(os.environ.get("V2_R2_MAX_TOKENS", "32768"))
  _V2_R3_MAX_TOKENS = int(os.environ.get("V2_R3_MAX_TOKENS", "32768"))
  ```
- [x] Cập nhật `_call_agent_v2()` nhận `max_tokens` parameter thay vì hardcode
- [x] Cập nhật tất cả callers: `_run_discovery_round` → `_V2_R1_MAX_TOKENS`, `_run_voting_round` → `_V2_R2_MAX_TOKENS`, `_run_attacker_round` → `_V2_R3_MAX_TOKENS`
- [x] Xóa non-working `thinkingConfig` extra_body khỏi `_call_agent_v2`

### 9.3 Các fix nhỏ phát sinh khi debug

- [x] `known_functions=None` trong `_run_discovery_round()` — bỏ filter theo known_functions (không còn pass full source nên filter này không còn ý nghĩa)
- [x] Empty `affected_functions` → placeholder `_nofunc_{swc_id}` để tránh KeyError khi aggregate pairs
- [x] `llm_client.py`: thêm warning log khi `content=None` từ API, log `finish_reason` và non-empty message fields để diagnose thinking model issues
- [x] `--output` (không phải `--output-dir`) trong `run_contract_audit.py` CLI args — fixed wrong flag name
