# PoC Verification Stage — Architecture & Design

> Giai đoạn xác minh tự động cho các finding low-confidence sau Consensus Engine.
> Mục tiêu: giảm FP, upgrade Tier-2 → Tier-1, trong ngân sách thời gian ≤ 5 phút.

---

## 1. Mục tiêu & Ràng buộc

| Mục tiêu | Giá trị mục tiêu |
|---|---|
| Giảm FP trong Tier-2 gap findings | ≥50% |
| Upgrade Tier-2 → Tier-1 khi verified | Toàn bộ confirmed findings |
| Time budget tối đa toàn PoC stage | **5 phút** |
| Không làm tăng FN | Verify fail ≠ drop — giữ nguyên Tier-2 |
| Không phụ thuộc vào network | Chạy hoàn toàn offline |
| Coverage | Easy/Medium SWC + Hard SWC + Semantic S-class |

**Nguyên tắc thiết kế:** PoC/verification chỉ được dùng để **xác nhận** finding. Không bao giờ drop finding chỉ vì PoC fail — exploit viết sai ≠ vulnerability không tồn tại.

---

## 2. Vị trí trong Pipeline

```
Phase A / B / C  (~30–40 phút)
        ↓
Consensus Engine
        ├── Tier-1 (consensus_vulns)
        │         confidence ≥ MIN_CONF + affected_assets + recommendations
        │
        └── Tier-2 (unvalidated_swc_gaps)  ←── PoC stage nhận input từ đây
                  ├── tier2_demoted  (confidence OK, thiếu function location)
                  └── gap findings   (confidence < MIN_CONF)

                          ↓
        ╔════════════════════════════════════════╗
        ║         P O C   V E R I F I C A T I O N   S T A G E          ║
        ║                                        ║
        ║  Track 1: Unit PoC  (Easy/Medium SWC)  ║
        ║  Track 2: Fuzz PoC  (Hard SWC)         ║
        ║  Track 3: LLM Query (Semantic S-class)  ║
        ╚════════════════════════════════════════╝
                          ↓
        Verified findings → nâng lên Tier-1 (consensus_vulns)
        Unverified        → giữ nguyên Tier-2 (unvalidated hints)
```

---

## 3. Kiến trúc Tổng quan — 3 Tracks

```
                 ┌─────────────────────────────────────────────────────┐
                 │               PoC Verification Stage                 │
                 │                                                      │
                 │  P0: Route candidates                                │
Tier-2 gaps ───▶ │      ↓          ↓            ↓                      │
                 │  ┌────────┐ ┌────────┐  ┌─────────┐                │
                 │  │Track 1 │ │Track 2 │  │ Track 3 │                │
                 │  │Unit PoC│ │  Fuzz  │  │LLM Query│                │
                 │  │Easy/   │ │  Hard  │  │Semantic │                │
                 │  │Medium  │ │  SWC   │  │ S-class │                │
                 │  │  SWC   │ │        │  │         │                │
                 │  └───┬────┘ └───┬────┘  └────┬────┘                │
                 │      │         │              │                      │
                 │      ▼         ▼              ▼                      │
                 │  ┌─────────────────────┐  ┌──────────────────────┐ │
                 │  │ P1: Template Match  │  │ P1: Query Build      │ │
                 │  │ P2: LLM Code Gen    │  │ P2: LLM Targeted     │ │
                 │  │    (parallel)       │  │     Query (parallel) │ │
                 │  └──────────┬──────────┘  └──────────┬───────────┘ │
                 │             │                         │              │
                 │             ▼                         │              │
                 │  ┌──────────────────────┐             │              │
                 │  │ P2b: Reviewer Agent  │             │              │
                 │  │ (compile error only, │             │              │
                 │  │  1 retry max)        │             │              │
                 │  └──────────┬───────────┘             │              │
                 │             │                         │              │
                 │             ▼                         │              │
                 │  ┌──────────────────────┐             │              │
                 │  │ P3: forge build      │             │              │
                 │  │ (shared T1+T2, 1x)  │             │              │
                 │  └──────────┬───────────┘             │              │
                 │             │                         │              │
                 │             ▼                         │              │
                 │  ┌──────────────────────┐             │              │
                 │  │ P4: forge test       │             │              │
                 │  │ (unit + fuzz, 1 run) │             │              │
                 │  └──────────┬───────────┘             │              │
                 │             │                         │              │
                 │             └────────────┬────────────┘              │
                 │                          ▼                            │
                 │              ┌───────────────────────┐               │
                 │              │  P5: Result Integration│               │
                 │              │  (T1 + T2 + T3)        │               │
                 │              └───────────────────────┘               │
                 └─────────────────────────────────────────────────────┘
                                          ↓
                               Updated consensus_vulns + gap_findings
```

---

## 4. Phân tích Time Budget

**Ràng buộc:** Tổng wall time ≤ 5 phút.

```
Phase       Task                        Wall time     Ghi chú
──────────  ──────────────────────────  ───────────   ─────────────────────────────
P0          Route candidates            ~0s           In-memory filter
P1          Template + query build      ~0s           Lookup table, không LLM
P2 (T1+T2) Code gen — unit/fuzz        ~25s          asyncio.gather(), tất cả concurrent
P2 (T3)    LLM targeted queries        ~20–25s       asyncio.gather(), chạy song song P2 T1+T2
            ↑ T3 xong ở đây            ✅ ~25s
P2b         Reviewer agent (nếu cần)   +0–20s        Chỉ khi có compile error, max 1 lần
P3          forge build (T1+T2 shared) ~30–60s       Compile 1 lần cho cả 2 tracks
P4          forge test (unit + fuzz)   ~30–60s       1 invocation, forge parallel nội bộ
            ↑ T1+T2 xong ở đây        ✅ ~100–145s
P5          Integrate T1+T2+T3         ~1s           In-memory
──────────────────────────────────────────────────────────────────────────────────
TOTAL wall time (nominal)              ~100–150s     ≈ 1.7–2.5 phút
With reviewer retry + slow compile     ~200s         ≈ 3.5 phút
Hard timeout kill                      300s          5 phút — không bao giờ vượt
```

**Tại sao Track 3 không làm chậm pipeline?**
T3 (LLM targeted queries) chạy đồng thời với P2 code gen của T1+T2. T3 không cần forge → xong trước khi P3 bắt đầu. Thời gian T3 bị "ẩn" trong wait time của forge.

**Tại sao fuzz không làm tăng đáng kể thời gian?**
Forge chạy unit test và fuzz test trong cùng 1 invocation (`forge test`). Fuzz test dùng `--fuzz-runs 128` (giảm từ default 256) để cân bằng coverage vs speed. Thêm ~20–30s so với chỉ unit test.

---

## 5. SWC Scope — Tiêu chí và Phân loại

### 5.1 Tiêu chí để một SWC vào PoC scope

SWC được đưa vào scope khi thoả **cả 3 điều kiện**:

```
✅ Deterministic  — cùng input → cùng output, không phụ thuộc oracle/mempool
✅ Bounded setup  — setUp() hoàn thành < 10s, không cần external state/fork
✅ Observable     — exploit tạo ra assertion đo được (revert / wrong value / gas)
```

SWC bị loại khỏi Unit PoC scope nếu:
- Phụ thuộc vào DEX liquidity thật, oracle feeds, hoặc mempool ordering
- Setup cần simulate full protocol state (cross-contract, multi-block)
- Threshold để trigger không xác định trước được (scale-dependent)

### 5.2 Ma trận phân loại đầy đủ

| SWC | Tên | Track | Template/Strategy | Lý do phân loại |
|---|---|---|---|---|
| SWC-101 | Integer Overflow | ✅ T1 Unit | `boundary_values` | Deterministic, pass max value → check truncation |
| SWC-105 | Unprotected Withdrawal | ✅ T1 Unit | `direct_call` | Gọi trực tiếp từ arbitrary address |
| SWC-106 | Unprotected Selfdestruct | ✅ T1 Unit | `direct_call` | Gọi selfdestruct không qua guard |
| SWC-115 | tx.origin Auth | ✅ T1 Unit | `intermediary_contract` | Gọi qua contract intermediary |
| SWC-107 | Reentrancy | ✅ T1 Unit | `malicious_callback` | Cần mock attacker contract nhưng self-contained |
| SWC-120 | Weak PRNG | ✅ T1 Unit | `deterministic_seed` | Set block.timestamp/difficulty, predict output |
| SWC-114 | Front-running | ✅ T1 Unit | `sandwich_simulation` | Dùng vm.roll() để simulate ordering |
| SWC-112 | Delegatecall | ✅ T1 Unit | `storage_collision` | Craft malicious logic contract |
| SWC-128 | DoS Gas | ⚡ T2 Fuzz | `fuzz_array_size` | Scale-dependent — fuzzer tự tìm threshold |
| S-class: access_control | Missing restriction | 🔍 T3 LLM | targeted query | Cần human-readable code pattern check |
| S-class: incorrect_accounting | Balance/share error | 🔍 T3 LLM | targeted query | Logic-level, không expressible qua assertion đơn |
| S-class: price_oracle | Oracle manipulation | ❌ Skip | — | Cần DEX state thật, không offline |
| S-class: flash_loan | Flash loan attack | ❌ Skip | — | Cần flash loan provider |
| S-class: governance | Vote manipulation | ❌ Skip | — | Multi-block, token distribution phức tạp |

**SWC nằm ngoài scope bị filter tại P0** — không tốn bất kỳ thời gian nào.

**Tại sao SWC-128 cần Fuzz thay vì Unit test?**
DoS gas chỉ trigger khi array đủ lớn (thường > 3000–10000 phần tử). LLM không biết threshold cụ thể → unit test với hardcoded value thường fail vì wrong size. Fuzzer tự khám phá size failing → không cần đoán.

---

## 6. Chi tiết Từng Phase

### P0 — Candidate Routing

```python
def route_poc_candidates(gap_findings: List[dict]) -> PoCRouting:
    t1_unit, t2_fuzz, t3_llm = [], [], []

    for finding in gap_findings:
        # Loại ngay nếu không có function location
        if not finding.get("affected_functions"):
            continue
        if finding.get("agent_vote_count", 0) < 2:
            continue

        swc = finding.get("swc_id", "")
        semantic_cat = finding.get("semantic_category", "")

        if swc in POC_UNIT_SWCS:        # Easy + Medium SWC
            t1_unit.append(finding)
        elif swc in POC_FUZZ_SWCS:      # Hard SWC (SWC-128)
            t2_fuzz.append(finding)
        elif semantic_cat in LLM_QUERY_CATEGORIES:   # Semantic S-class
            t3_llm.append(finding)
        # Còn lại: skip (S-class oracle/flash/governance)

    return PoCRouting(
        unit=t1_unit[:MAX_UNIT_CANDIDATES],   # default: 10
        fuzz=t2_fuzz[:MAX_FUZZ_CANDIDATES],   # default: 4 (fuzz chậm hơn)
        llm=t3_llm[:MAX_LLM_CANDIDATES],      # default: 8
    )
```

---

### P1 — Template / Query Matching

Lookup table — không LLM, thực thi ngay lập tức:

```python
POC_UNIT_TEMPLATES: Dict[str, PoCTemplate] = {
    "SWC-101": PoCTemplate(
        strategy="boundary_values",
        assertion="Verify no silent truncation at type(uintN).max boundaries",
        setup_hint="Deploy contract; no special state needed",
    ),
    "SWC-107": PoCTemplate(
        strategy="malicious_callback",
        assertion="Assert balance/state unchanged after reentrant callback",
        setup_hint="Deploy AttackerContract with fallback() calling back into target",
    ),
    "SWC-105": PoCTemplate(strategy="direct_call", ...),
    "SWC-106": PoCTemplate(strategy="direct_call", ...),
    "SWC-115": PoCTemplate(strategy="intermediary_contract", ...),
    "SWC-120": PoCTemplate(strategy="deterministic_seed", ...),
    "SWC-114": PoCTemplate(strategy="sandwich_simulation", ...),
    "SWC-112": PoCTemplate(strategy="storage_collision", ...),
}

POC_FUZZ_TEMPLATES: Dict[str, FuzzTemplate] = {
    "SWC-128": FuzzTemplate(
        fuzz_param="uint16 arraySize",
        setup_template="Create array of {fuzz_param} elements",
        gas_assertion="assertLt(gasUsed, GAS_LIMIT, 'Unbounded gas')",
        fuzz_runs=128,
    ),
}

LLM_QUERY_TEMPLATES: Dict[str, str] = {
    "access_control": (
        "Does {contract}.{function} enforce any access restriction "
        "(onlyOwner, role check, msg.sender validation)? "
        "If missing: which addresses can call it unexpectedly?"
    ),
    "incorrect_accounting": (
        "In {contract}.{function}, do the balance/share calculations "
        "maintain correct invariants? Show the specific arithmetic line "
        "where a discrepancy can occur."
    ),
    "state_machine_bug": (
        "Does {contract}.{function} transition state correctly? "
        "Is there a path where state is left inconsistent or stuck?"
    ),
}
```

---

### P2a — LLM Code Generation (Track 1+2, Parallel)

```python
async def generate_all_poc_codes(
    unit_candidates: List[PoCCandidate],
    fuzz_candidates: List[PoCCandidate],
    flat_source: str,
) -> Dict[str, str]:

    async def generate_one(candidate: PoCCandidate, is_fuzz: bool) -> Tuple[str, str]:
        # Chỉ extract snippet của function cụ thể — không gửi 260K flat file
        snippet = extract_function_snippet(flat_source, candidate.function_name,
                                           max_lines=50)
        template = (POC_FUZZ_TEMPLATES if is_fuzz else POC_UNIT_TEMPLATES)[candidate.swc_id]
        prompt = build_poc_prompt(candidate, snippet, template, is_fuzz=is_fuzz)
        code = await llm_call_async(prompt, model=FAST_MODEL, max_tokens=400,
                                    timeout=30)
        return candidate.id, code

    all_tasks = (
        [generate_one(c, is_fuzz=False) for c in unit_candidates] +
        [generate_one(c, is_fuzz=True)  for c in fuzz_candidates]
    )
    results = await asyncio.gather(*all_tasks, return_exceptions=True)

    return {cid: code for cid, code in results if not isinstance(code, Exception)}
```

**Prompt cho unit test** (token-efficient):
```
[SYSTEM] Foundry security test writer. Write minimal exploit PoC.

[USER]
SWC: {swc_id} — {swc_name}
Contract: {contract_name}  Function: {function_signature}
Strategy: {template.strategy}

Code:
```solidity
{snippet}  // ≤ 50 lines
```

Write ONLY the body of function named: test_{swc_short}_{fn_name}()
Under 30 lines. No imports. Assume `{contract} target` deployed in setUp().
{template.assertion}
```

**Prompt cho fuzz test:**
```
[SYSTEM] Foundry fuzz test writer. Write property-based fuzz test.

[USER]
SWC: {swc_id} — {swc_name}
Contract: {contract_name}  Function: {function_signature}
Fuzz param: {template.fuzz_param}

Code:
```solidity
{snippet}
```

Write ONLY the body of function: testFuzz_{swc_short}_{fn_name}({template.fuzz_param})
The fuzzer will call this with many values. Assert: {template.gas_assertion}
Under 25 lines. No imports. Assume `{contract} target` deployed in setUp().
```

---

### P2b — Reviewer Agent (Compile Error Retry)

Chỉ kích hoạt khi `forge build` fail. Reviewer nhận **code lỗi + error message** — không generate lại từ đầu:

```python
async def review_and_fix_compile_errors(
    poc_file_content: str,
    compile_error: str,
    failed_functions: List[str],  # parse từ error: "Error in test_swc101_mint"
) -> str:
    """Returns fixed poc_file_content. Called max 1 time."""

    async def fix_one(fn_name: str) -> Tuple[str, str]:
        fn_code = extract_function_from_file(poc_file_content, fn_name)
        fn_error = extract_error_for_function(compile_error, fn_name)

        prompt = f"""Fix this Solidity compile error. Return only the corrected function body.
Do NOT change test logic or assertions. Fix syntax only.

Error:
{fn_error}

Code:
```solidity
{fn_code}
```"""
        fixed = await llm_call_async(prompt, model=FAST_MODEL, max_tokens=300,
                                     timeout=20)
        return fn_name, fixed

    # Sửa tất cả functions lỗi song song
    fixes = await asyncio.gather(*[fix_one(fn) for fn in failed_functions],
                                 return_exceptions=True)

    # Patch file: chỉ thay thế functions lỗi, giữ nguyên phần còn lại
    for fn_name, fixed_code in fixes:
        if not isinstance(fixed_code, Exception):
            poc_file_content = replace_function_in_file(poc_file_content,
                                                         fn_name, fixed_code)
    return poc_file_content
```

**Tại sao reviewer agent tốt hơn self-retry:**

| | Self-retry | Reviewer agent |
|---|---|---|
| Input | Full original prompt + error | Code lỗi + error message (focused) |
| Hành vi LLM | Rewrite toàn bộ (hallucinate lại) | Targeted fix (ít thay đổi hơn) |
| Fix rate (compile error) | ~50% | ~70–80% |
| Token cost | Cao | Thấp |
| Áp dụng cho | Compile error | **Compile error only** |
| Logic error (test fail) | ❌ Không retry | ❌ Không retry |

**Logic error không retry** — nếu exploit fail, LLM có thể đã dùng wrong attack vector. Retry với cùng context sẽ fail lại. Giữ finding ở Tier-2.

---

### P2c — LLM Targeted Query (Track 3, Parallel với P2a)

```python
async def run_targeted_queries(
    semantic_candidates: List[SemanticCandidate],
    flat_source: str,
) -> Dict[str, VerificationResult]:

    async def query_one(candidate: SemanticCandidate) -> Tuple[str, VerificationResult]:
        snippet = extract_contract_section(flat_source, candidate.contract_name,
                                           candidate.function_name, max_lines=80)
        query_template = LLM_QUERY_TEMPLATES[candidate.semantic_category]
        question = query_template.format(
            contract=candidate.contract_name,
            function=candidate.function_name,
        )

        prompt = f"""[SYSTEM] Smart contract security verifier.
Answer only what you directly observe. Do not infer or extrapolate.

[USER]
Question: {question}

Evidence from previous audit agents:
{candidate.agent_evidence_summary}

Code:
```solidity
{snippet}
```

Answer format (strict):
VERDICT: YES | NO | INCONCLUSIVE
EVIDENCE: <direct quote or exact line from code above, or "none">
REASONING: <1 sentence maximum>"""

        response = await llm_call_async(prompt, model=FAST_MODEL, max_tokens=150,
                                        timeout=25)
        result = parse_verdict_response(response)
        return candidate.id, result

    results = await asyncio.gather(*[query_one(c) for c in semantic_candidates],
                                   return_exceptions=True)
    return {cid: r for cid, r in results if not isinstance(r, Exception)}
```

**Upgrade rule cho Track 3:**
```python
def should_upgrade_from_query(result: VerificationResult) -> bool:
    return (
        result.verdict == "YES" and
        result.evidence != "none" and  # phải có evidence cụ thể
        result.evidence != ""
    )
    # INCONCLUSIVE và NO → giữ Tier-2
```

**Tại sao cần evidence không rỗng?** LLM có thể trả lời YES nhưng evidence là "none" — đây là hallucination. Chỉ upgrade khi LLM chỉ ra được dòng code cụ thể.

---

### P3 — Forge Build (Track 1+2, 1 lần)

```python
async def build_poc_contracts(contest_dir: str, poc_file_path: Path) -> BuildResult:
    """Attempt forge build. On failure, parse errors and trigger P2b reviewer."""

    proc = await asyncio.create_subprocess_exec(
        "forge", "build", "--silent",
        cwd=contest_dir,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=90)
    except asyncio.TimeoutError:
        proc.kill()
        return BuildResult(success=False, error="timeout", failed_functions=[])

    if proc.returncode == 0:
        return BuildResult(success=True)

    # Parse lỗi để xác định function nào fail
    failed_fns = parse_compile_errors(stderr.decode(), poc_file_path)
    return BuildResult(success=False, error=stderr.decode(), failed_functions=failed_fns)
```

**Forge chạy trên contest directory gốc**, không phải flat file — đây là điều kiện bắt buộc để tránh compile error do import resolution.

---

### P4 — Forge Test (Unit + Fuzz, 1 invocation)

```python
async def run_all_forge_tests(contest_dir: str) -> Dict[str, TestResult]:
    """
    Forge tự phân biệt test_* (unit) và testFuzz_* (fuzz) trong cùng file.
    1 invocation chạy cả 2 loại.
    """
    proc = await asyncio.create_subprocess_exec(
        "forge", "test",
        "--match-contract", "_poc_mirofish",
        "--json",
        "--fuzz-runs", "128",       # giảm từ 256 để tiết kiệm thời gian
        "--no-match-test", "invariant_",
        cwd=contest_dir,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        proc.kill()
        return {}

    return parse_forge_json_output(stdout.decode())
```

**Forge phân biệt tự động:**
- `test_swc101_mint()` → unit test (chạy 1 lần)
- `testFuzz_swc128_distribute(uint16 size)` → fuzz test (chạy 128 lần với random values)

---

### P5 — Result Integration

```python
def integrate_all_results(
    forge_results:  Dict[str, bool],           # T1+T2: {test_name: passed}
    query_results:  Dict[str, VerificationResult],  # T3: {candidate_id: result}
    unit_candidates:  List[PoCCandidate],
    fuzz_candidates:  List[PoCCandidate],
    semantic_candidates: List[SemanticCandidate],
    consensus_vulns: List[ConsensusVulnerability],
    gap_findings: List[dict],
) -> Tuple[List[ConsensusVulnerability], List[dict]]:

    upgrade_ids: Set[str] = set()

    # Track 1+2: forge pass
    for candidate in unit_candidates + fuzz_candidates:
        test_prefix = "testFuzz" if candidate.is_fuzz else "test"
        test_name = f"{test_prefix}_{candidate.swc_short}_{candidate.function_name}"
        if forge_results.get(test_name) is True:
            upgrade_ids.add(candidate.gap_finding_id)

    # Track 3: LLM verdict
    for candidate in semantic_candidates:
        result = query_results.get(candidate.id)
        if result and should_upgrade_from_query(result):
            upgrade_ids.add(candidate.gap_finding_id)

    newly_confirmed, remaining_gaps = [], []
    for gap in gap_findings:
        if gap["id"] in upgrade_ids:
            vuln = upgrade_gap_to_consensus_vuln(gap, poc_confirmed=True)
            newly_confirmed.append(vuln)
        else:
            remaining_gaps.append(gap)

    return consensus_vulns + newly_confirmed, remaining_gaps
```

---

## 7. Error Handling & Graceful Degradation

```
Lỗi                               Track       Hành động
────────────────────────────────  ─────────   ──────────────────────────────────────
forge compile fail (1st attempt)  T1+T2       Kích hoạt P2b reviewer (max 1 retry)
forge compile fail (2nd attempt)  T1+T2       Skip toàn bộ forge, giữ Tier-2
forge test timeout (>120s)        T1+T2       Kill, tất cả candidates giữ Tier-2
LLM code gen timeout (>30s)       T1+T2       Skip candidate đó, tiếp tục
LLM query timeout (>25s)          T3          Skip candidate, INCONCLUSIVE → Tier-2
LLM verdict = INCONCLUSIVE        T3          Giữ Tier-2 (không upgrade)
LLM verdict = YES nhưng no evid.  T3          Giữ Tier-2 (hallucination guard)
No candidates pass P0 filter      All         Bỏ qua PoC stage hoàn toàn (0s overhead)
Total time > 300s                 All         Kill everything, tất cả giữ Tier-2
```

**Nguyên tắc:** PoC stage có thể fail hoàn toàn mà không block pipeline. Tất cả failure modes đều dẫn đến "giữ nguyên Tier-2", không bao giờ "drop findings".

---

## 8. Configuration Parameters

```python
@dataclass
class PoCConfig:
    enabled: bool = True

    # Candidate selection
    min_agent_votes:        int   = 2
    max_unit_candidates:    int   = 10
    max_fuzz_candidates:    int   = 4      # fuzz chậm hơn, giới hạn thấp hơn
    max_llm_candidates:     int   = 8

    # LLM
    code_gen_model:         str   = "claude-haiku-4-5-20251001"
    code_gen_timeout_s:     int   = 30
    code_gen_max_tokens:    int   = 400
    query_timeout_s:        int   = 25
    query_max_tokens:       int   = 150    # verdict ngắn gọn
    reviewer_max_tokens:    int   = 300
    reviewer_enabled:       bool  = True

    # Forge
    compile_timeout_s:      int   = 90
    test_timeout_s:         int   = 120
    fuzz_runs:              int   = 128    # giảm từ default 256
    snippet_max_lines:      int   = 50

    # Hard budget
    stage_timeout_s:        int   = 300
```

---

## 9. Hardware Requirements & Disk Setup

### 9.1 Requirements

| Resource | Tối thiểu | Khuyến nghị | Lý do |
|---|---|---|---|
| CPU | 2 cores | 4+ cores | forge compile dùng multi-core; Python asyncio chỉ cần 1 core |
| RAM | 2 GB | 4+ GB | forge giữ AST + artifacts trong RAM khi compile |
| **Disk** | HDD | **SSD bắt buộc** | forge tạo hàng nghìn artifact files; HDD ~3–5x chậm hơn SSD |
| Disk space (SSD) | 500 MB free | 1 GB free | `out/` artifacts ~50–200 MB per contest |
| Network | Không cần | Không cần | Chạy offline hoàn toàn (không mainnet fork) |

**Điểm quan trọng nhất: SSD.** Forge compile Solidity sinh ra nhiều small files trong `out/`. Trên HDD, bước P3 có thể mất 3–5 phút thay vì 30–60 giây — vượt time budget.

**Song song là I/O concurrency**, không phải CPU parallelism. `asyncio.gather()` chạy trên 1 thread/1 CPU core. Không cần multi-core cho phía Python — bottleneck là forge subprocess.

---

### 9.2 Cấu hình Disk Thực tế (⚠️ Đọc trước khi triển khai)

Scan máy hiện tại cho thấy:

| Disk | Loại | Size | Mount | Free | Ghi chú |
|---|---|---|---|---|---|
| `/dev/sda` | **HDD** (ROTA=1) | 300 GB | `/` | **7.6 GB (3%)** | Source code project nằm ở đây |
| `/dev/sdb` | **SSD** (ROTA=0) | 40 GB | `/mnt/ollama_data` | 15 GB | ← Đặt PoC workspace ở đây |

**⚠️ Hai cảnh báo quan trọng:**
1. **HDD gần đầy (97%)** — nếu forge build chạy trên HDD, artifacts ~100–200 MB/contest có thể lấp đầy 7.6 GB còn lại sau vài lần chạy.
2. **Source code trên HDD** — không thể chuyển toàn bộ project sang SSD, nhưng phần **ghi nhiều** (artifacts, cache, test output) phải nằm trên SSD.

---

### 9.3 Chiến lược: PoC Workspace trên SSD

**Nguyên tắc:** Source code đọc từ HDD (sequential read — HDD chấp nhận được), tất cả **ghi** (artifacts, cache, generated tests) đặt trên SSD.

```
/mnt/ollama_data/mirofish_poc/          ← SSD workspace root
└── {contest_id}/                        ← workspace per contest (auto-created + cleaned up)
    ├── foundry.toml                     ← config trỏ src về HDD, out/cache về SSD
    ├── test/
    │   └── _poc_mirofish.t.sol          ← generated PoC file (ghi lên SSD)
    ├── out/                             ← forge artifacts     (ghi lên SSD)
    └── cache/                           ← forge build cache   (ghi lên SSD)
```

**`foundry.toml` được generate tự động khi tạo workspace:**

```toml
[profile.default]
# Source từ HDD (chỉ đọc — sequential read, acceptable)
src   = "/home/thangdd/repos/MiroFish/DeFiHackLabs/web3bugs/contracts/{contest_id}"

# Tất cả write operations → SSD
test  = "test"        # relative → /mnt/ollama_data/mirofish_poc/{contest_id}/test/
out   = "out"         # relative → /mnt/ollama_data/mirofish_poc/{contest_id}/out/
cache_path = "cache"  # relative → /mnt/ollama_data/mirofish_poc/{contest_id}/cache/
```

**forge chạy từ SSD workspace** (không phải contest dir gốc):

```python
POC_WORKSPACE_ROOT = Path("/mnt/ollama_data/mirofish_poc")

def create_poc_workspace(contest_id: str, contest_src_dir: str) -> Path:
    workspace = POC_WORKSPACE_ROOT / contest_id
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "test").mkdir(exist_ok=True)

    # Generate foundry.toml với absolute path trỏ về HDD source
    foundry_toml = workspace / "foundry.toml"
    foundry_toml.write_text(f"""[profile.default]
src        = "{contest_src_dir}"
test       = "test"
out        = "out"
cache_path = "cache"
""")
    return workspace

def cleanup_poc_workspace(contest_id: str):
    """Xoá workspace sau khi PoC xong để giải phóng SSD space."""
    import shutil
    workspace = POC_WORKSPACE_ROOT / contest_id
    if workspace.exists():
        shutil.rmtree(workspace)
```

**Tích hợp vào P3:**

```python
async def build_poc_contracts(contest_id: str, contest_src_dir: str,
                               poc_file_content: str) -> BuildResult:
    workspace = create_poc_workspace(contest_id, contest_src_dir)

    # Ghi PoC file lên SSD (không phải HDD)
    poc_path = workspace / "test" / "_poc_mirofish.t.sol"
    poc_path.write_text(poc_file_content)

    # forge build từ SSD workspace
    proc = await asyncio.create_subprocess_exec(
        "forge", "build", "--silent",
        cwd=workspace,           # ← chạy từ SSD, không phải HDD contest dir
        ...
    )
    ...
```

**Cleanup:** Gọi `cleanup_poc_workspace()` ở P5 sau khi integrate results, để không để lại artifacts tích lũy trên SSD.

---

## 10. Integration Point trong Codebase

```python
# Trong contract_oasis_env.py hoặc pipeline orchestrator

# Step 6: Consensus
engine = ConsensusEngine(...)
consensus_vulns = engine.compute(expert_findings, attacker_findings)
gap_findings    = engine.enforce_swc_coverage(consensus_vulns)

# Step 7: PoC Verification (NEW)
if poc_config.enabled:
    poc_stage = PoCVerificationStage(config=poc_config)
    consensus_vulns, gap_findings = await poc_stage.run(
        candidates_pool = gap_findings,
        flat_source     = flat_source,     # đã có từ flatten_contest
        contest_dir     = contest_dir,     # gốc — không phải flat file path
        consensus_vulns = consensus_vulns,
    )

# Step 8: Build report
report = build_audit_report(consensus_vulns, gap_findings)
```

---

## 11. Ví dụ End-to-End: Contest 35

**Gap findings đầu vào:**
```
Finding A: SWC-101, ConcentratedLiquidityPool, fns=[_mint, _burn, to128], votes=5 → Track 1
Finding B: SWC-128, ConcentratedLiquidityPool, fns=[_updateLiquidity], votes=3   → Track 2
Finding C: access_control, PositionManager, fns=[collect], votes=2               → Track 3
Finding D: price_oracle, Pool, fns=[swap], votes=4                                → Skip
```

**P0:** D bị loại (price_oracle không trong LLM_QUERY_CATEGORIES).

**P2a ‖ P2c (concurrent, ~25s):**
- T1: LLM viết `test_swc101_mint()` cho Finding A
- T2: LLM viết `testFuzz_swc128_updateLiquidity(uint16)` cho Finding B
- T3: LLM query "Does PositionManager.collect() enforce access restriction?" cho Finding C

**P2b (nếu cần):** forge compile fail vì type error trong fuzz test → reviewer fix `uint16 → uint256` → recompile.

**P3:** `forge build` ~45s

**P4:** `forge test --fuzz-runs 128 --json` ~35s
- `test_swc101_mint`: PASS ✅
- `testFuzz_swc128_updateLiquidity`: PASS (fuzzer tìm ra size=4096 gây gas exhaustion) ✅

**P2c result:** Finding C → `VERDICT: YES, EVIDENCE: "collect() has no msg.sender check at line 45"` ✅

**P5:** A, B, C → upgrade to `consensus_vulns` với `poc_confirmed=True`. D → giữ Tier-2.

**Tổng thời gian:** ~105s (≈ 1.75 phút)

---

## 12. Điều kiện Xác nhận Hiệu quả

```
Sau khi implement:
1. Tier-2 findings được upgrade vào consensus_vulns qua PoC/query
2. F1_L_fn > 0 (upgraded findings có function location)
3. Tổng PoC stage time < 5 phút
4. Không tăng FP đáng kể (forge pass = exploit thực sự; LLM YES + evidence = code-backed)
5. Pipeline không bị block khi compile fail (graceful degradation)
6. forge chạy trên contest_dir gốc, không phải flat file
```

---

## 13. Giới hạn Còn Lại

1. **S-class oracle/flash/governance**: Không trong scope bất kỳ track nào. Cần mainnet fork + phức tạp quá cho time budget.
2. **LLM Targeted Query recall ceiling**: Track 3 vẫn là LLM reasoning (không phải execution). Evidence guard giảm FP nhưng vẫn có FP nhất định.
3. **Fuzz track FN risk**: `testFuzz_` với 128 runs có thể không tìm được failing input nếu threshold cao. Tăng `fuzz_runs` → tăng coverage nhưng tăng thời gian.
4. **Compile dependency**: Contest với complex imports (multiple @openzeppelin versions) vẫn có thể fail forge build. Reviewer agent không fix được structural dependency issues.
5. **SWC-107 PoC quality**: LLM cần viết đúng re-entrant callback pattern — error rate cao hơn (~40%) so với SWC-101 (~15%).
