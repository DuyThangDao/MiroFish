# Plan: Migrate Audit Output từ SWC+Category sang Natural Language

## Mục tiêu

Thay thế cơ chế output hiện tại (FINDING/SWC + SEMANTIC_FINDING/category) bằng
một format thống nhất dạng natural language. Loại bỏ L-track / S-track split.
Evaluate với GT là bài toán riêng — không thay đổi trong plan này.

---

## Hiện trạng

### R1 output (2 format riêng biệt)
```
FINDING: <title>
SWC: SWC-101
FUNCTION: burn()
EVIDENCE: ...

SEMANTIC_FINDING: <title>
CATEGORY: incorrect_accounting
FUNCTION: mint()
ATTACK_PATH: ...
```

### R2 clustering key
- SWC findings: `(swc_id, function_name)` — ví dụ `("SWC-101", "burn")`
- Semantic findings: `(category, function_name)` — ví dụ `("incorrect_accounting", "mint")`

### consensus_engine output
- `consensus_vulns` — L-track (SWC-based)
- `semantic_results` — S-track (category-based)
- Hai pipeline hoàn toàn riêng biệt

---

## Thiết kế sau migration

### R1 output — single unified format
```
FINDING: <concise NL title>
CONTRACT: <contract name, e.g. ConcentratedLiquidityPool>
FUNCTION: <exact function name>
SEVERITY: <critical|high|medium|low>
EVIDENCE: <code snippet hoặc specific pattern>
ATTACK_PATH: <step-by-step exploit scenario>
DESCRIPTION: <why exploitable>
PATCH: <concrete fix>
```

Không còn `SWC:` field. Không còn `CATEGORY:` field.
`swc_focus` trong agent profile vẫn giữ như gợi ý trong system prompt
("Your domain is sensitive to integer overflow/underflow patterns") nhưng
không yêu cầu agent classify ra SWC ID.

**`CONTRACT:` field là bắt buộc.** Lý do:

- Contest thường có nhiều contracts với function trùng tên (e.g., `burn()` tồn tại
  trong cả `ConcentratedLiquidityPool` lẫn `ConcentratedLiquidityPosition`)
- Contest thường có nhiều contracts với function trùng tên — `contract_name` là
  thông tin cần thiết cho auditor và cho evaluate step
- Evaluation dedup key: `(H_id, function_name, contract_name)` sau khi match GT —
  đảm bảo 1 GT bug chỉ count tối đa 1 TP

Thêm vào R1 prompt instruction bắt buộc:
```
CONTRACT field is MANDATORY.
- Write the exact contract name where the vulnerable function is defined.
- Example: if burn() is in ConcentratedLiquidityPool.sol, write CONTRACT: ConcentratedLiquidityPool
- Do NOT write the file path or .sol extension — contract name only.
- If the function exists in multiple contracts, write a separate FINDING for each contract.
```

### R2 — không clustering, không dedup

R2 nhận **raw findings list** từ R1, không qua bất kỳ bước clustering hay
deduplication nào.

**Lý do bỏ clustering:**
- Cùng `(contract, function)` có thể chứa nhiều H bugs khác nhau (H-09 và H-14
  đều trong `rangeFeeGrowth` của `ConcentratedLiquidityPool`)
- Clustering theo location sẽ merge 2 bugs đó thành 1 pair → mất TP
- LLM similarity clustering để sub-cluster cũng không reliable — có thể merge
  nhầm 2 bugs khác nhau hoặc split nhầm cùng 1 bug
- Không có cách nào phân biệt "cùng bug, description khác" với "2 bugs khác nhau,
  cùng location" mà không có ground truth H ID

**Hệ quả:** Output có thể chứa duplicate findings về cùng 1 bug. Đây là giới hạn
được chấp nhận — dedup duy nhất xảy ra ở evaluate step sau khi match GT.

### consensus_engine output — unified list
```python
{
    "findings": [
        {
            "title": "...",
            "description": "...",
            "attack_path": "...",
            "contract_name": "...",
            "function_name": "...",
            "severity": "high",
            "confidence": 0.72,
            "evidence": [...],
            "patch": "..."
        },
        ...
    ]
}
```

Không còn `consensus_vulns` / `semantic_results` split.

---

## Các file cần thay đổi

### 1. `backend/app/services/contract_oasis_env.py`

**`build_round1_prompt()`** (line ~1360)

- Xóa `MANDATORY COVERAGE` block liệt kê SWC IDs (giữ nội dung dưới dạng
  "check these vulnerability classes" mà không reference SWC code)
- Xóa `SEMANTIC_FINDING` format block
- Thay bằng single `FINDING` format với `CONTRACT:` field, `ATTACK_PATH:` field
- Xóa `swc_focus_block` inject SWC IDs (thay bằng plain-language domain hint)
- Xóa `CATEGORY:` instruction, xóa `SEMANTIC_CATEGORY_PIPE_STRING` reference
- Thêm instruction bắt buộc `CONTRACT:` field với ví dụ cụ thể và rule:
  "If the function exists in multiple contracts, write a separate FINDING for each"

**`build_round2_prompt()`** (line ~1444)

- `pair_lines` display: thay `SWC [SWC-101]` / `SEMANTIC [incorrect_accounting]`
  bằng `FINDING` với title excerpt
- Xóa `kind == "semantic"` branch
- Param `candidate_pairs` dict: bỏ `kind`, `swc_id`, `category`; thêm `contract_name`, `title`

**`build_round2_update_prompt()`** (line ~1518)

- Tương tự build_round2_prompt: xóa kind/swc_id/category, thêm contract_name/title

---

### 2. `backend/app/services/cyber_session_orchestrator.py`

**`_collect_candidates()`** (line ~2200)

Hiện tại:
```python
results.append(("swc", f.get("swc_id",""), fn, ev))
results.append(("semantic", f.get("category","other"), fn, ev))
```

Sau migration:
```python
contract = f.get("contract_name", "")
results.append((contract, fn, title, ev))
```

Không clustering — mỗi finding từ R1 là 1 candidate pair riêng biệt trong R2.

**`_build_candidate_pairs()`** (hoặc đoạn tương đương tạo R2 pairs)

- Bỏ `"kind": "swc"/"semantic"`, `"swc_id"`, `"category"` từ pair dict
- Thêm `"contract_name"`, `"title"` vào pair dict
- Không merge findings — 1 finding = 1 pair

**Output assembly** (line ~2030–2100, đoạn build semantic_results / consensus_vulns)

- Xóa đoạn build `semantic_results` riêng
- Unified: mọi finding đi qua consensus_engine dưới dạng NL

**R2 setup** (line ~2305)

- Update cách pass `agent_pairs` sang `build_round2_prompt` theo schema mới

**R2u setup** (line ~2363)

- Update `revealed_evidence` dict theo schema mới (bỏ kind/swc_id/category)

---

### 3. `backend/app/services/consensus_engine.py`

**`run()`** (line 180)

- Bỏ param `semantic_findings_raw`
- Return type: `List[Dict]` thay vì `Tuple[List[ConsensusVulnerability], List[Dict]]`
- Xóa call `_run_semantic_consensus()`

**`_run_semantic_consensus()`** (line 829)

- Xóa hoàn toàn (hoặc `# deprecated` nếu muốn rollback dễ)

**`_cluster_findings()`** (đoạn hiện dùng SWC để cluster)

- Xóa hoàn toàn — không clustering trong pipeline mới
- Mỗi finding đi thẳng vào consensus vote như 1 unit độc lập

**`ConsensusVulnerability`** dataclass (nếu có)

- Xóa field `swc_ids`, `category`
- Thêm field `contract_name`, `attack_path`

**Output dict builder** (line ~590–610)

- Bỏ `swc_ids`, `category` khỏi output dict
- Thêm `contract_name`, `attack_path`

---

### 4. API / Frontend (scope nhỏ)

- `audit_report.json`: field `findings` thay vì `consensus_vulns` + `semantic_results`
- Frontend display: nếu đang render `swc_id` / `category` label, chuyển sang `title`

---

## Thứ tự triển khai

```
Phase 1 — R1 prompt (contract_oasis_env.py)
  ├── Unified FINDING format (bỏ SEMANTIC_FINDING)
  ├── Thêm CONTRACT: field
  └── Xóa SWC: / CATEGORY: fields

Phase 2 — Candidate collection (orchestrator.py)
  ├── Bỏ clustering — 1 R1 finding = 1 R2 pair
  └── New pair dict schema (title, contract_name; bỏ kind/swc_id/category)

Phase 3 — R2/R2u prompts (contract_oasis_env.py)
  └── Update pair display format theo schema mới

Phase 4 — consensus_engine.py
  ├── Xóa _cluster_findings()
  ├── Remove semantic track
  └── New output schema (findings[])

Phase 5 — Integration test
  └── Chạy contest 35, verify output có title/contract_name/function_name
```

---

## Không thay đổi

- Round mechanics (R1 → R2 blind vote → R2u reveal → R3)
- Confidence formula: `(k + r) / n_agents`
- Thresholds (R2=0.35, R3=0.50)
- `contract_kg_builder.py` — `swc_focus` giữ nguyên là internal hint
- `evaluate_web3bugs.py` — out of scope, sẽ redesign riêng

---

## Module Evaluate (thiết kế mới — tách biệt 2 phần)

### Kiến trúc

```
backend/scripts/evaluate/
├── smartbugs_eval.py     # Part 1 — SWC detection
├── web3bugs_eval.py      # Part 2 — H-bug matching
├── llm_judge.py          # Shared: LLM judge
└── metrics.py            # Shared: precision / recall / F1
```

---

### Part 1 — SmartBugs (SWC-based)

**Ground truth:** `{contract_id → [SWC-101, SWC-107, ...]}`
**Tool output:** NL findings với `(title, description, contract_name, function_name)`

Vì tool không còn output SWC ID, cần bước map NL → SWC tại eval time:

```
findings[] cho 1 contract
      ↓
[Keyword pre-filter]
  title/description chứa "overflow"            → candidate SWC-101
  "reentrancy" / "re-entrancy"                 → candidate SWC-107
  "access control" / "onlyOwner" / "modifier"  → candidate SWC-105
  "unbounded loop" / "gas limit"               → candidate SWC-128
  ...
      ↓
[LLM judge] — chỉ gọi khi keyword filter không rõ ràng
  "Does this finding describe an integer overflow vulnerability?"
  → YES / NO
      ↓
[Match với GT SWC list]
  TP: GT_SWC được detect bởi ít nhất 1 finding
  FP: finding không map được SWC nào trong GT của contract đó
  FN: GT_SWC không có finding tương ứng
      ↓
Metrics: per-SWC + aggregate F1
```

**Dedup:** Nhiều findings cùng map về SWC-101 trong 1 contract → chỉ count 1 TP.

---

### Part 2 — Web3Bugs (H-bug-based)

**Ground truth:** JSON file per contest (e.g. `gt_35.json`), parse từ
`../web3bugs/reports/{id}.md` — bước one-time bên ngoài module.

Schema mỗi item:
```json
{
  "h_id": "H-01",
  "title": "Unsafe cast in ConcentratedLiquidityPool.burn leads to attack",
  "description": "The ConcentratedLiquidityPool.burn function performs...",
  "function_name": "burn",
  "contract_name": "ConcentratedLiquidityPool"
}
```
Metric tính theo H bug — không phân theo label L/S.

**Tool output:** NL findings với `(title, description, contract_name, function_name, attack_path)`

```
findings[] cho 1 contest  ← raw, không dedup
      ↓
Với mỗi GT H bug:
  [Location filter]
    candidates = findings WHERE function_name=H.function
                                AND contract_name=H.contract
    → trả về candidates list
    → findings NGOÀI list này vẫn là pool cho các H bug khác
      ↓
  [LLM judge]
    Với mỗi candidate:
      Input:  GT description + predicted description/attack_path
      Output: YES / NO + reason
      → YES: TP cho H này
      → NO:  finding không match H này, vẫn còn trong pool cho H khác
      ↓
[Tổng hợp sau khi xử lý hết tất cả H bugs]
  Post-match dedup: (H_id, function_name, contract_name)
  → 1 GT H bug count tối đa 1 TP dù có nhiều findings match
  TP: H bugs có ít nhất 1 finding được judge YES
  FP: findings không match bất kỳ H bug nào
  FN: H bugs không có finding nào được judge YES
      ↓
Metrics: aggregate F1 theo H bug
```

**Không dedup findings ở bất kỳ bước nào trước match:**
- Cùng `(contract, function)` có thể có nhiều H bugs khác nhau
- Cùng bug có thể có nhiều findings (duplicate từ nhiều agents) — chấp nhận, không merge
- Dedup duy nhất là `(H_id, function_name, contract_name)` sau match để tránh count 1 TP hai lần

---

### LLM Judge — interface chung

```python
def judge_match(gt_bug: dict, predicted: dict) -> tuple[bool, str]:
    """
    gt_bug:    {title, description, function_name, contract_name}
    predicted: {title, description, attack_path, function_name, contract_name}
    returns:   (is_match: bool, reason: str)
    """
```

Prompt template:
```
You are a security audit evaluator.

GROUND TRUTH BUG:
Function: {gt.function_name} in {gt.contract_name}
Description: {gt.description}

PREDICTED FINDING:
Function: {pred.function_name} in {pred.contract_name}
Title: {pred.title}
Description: {pred.description}
Attack path: {pred.attack_path}

Does the predicted finding identify the same vulnerability as the ground truth?
Answer: YES or NO
Reason: (one sentence)
```

**Cost control:**
- Gọi judge chỉ khi location filter pass (function_name + contract_name match)
- Cache kết quả theo `(H_id, predicted_hash)`
- Batch: gộp nhiều pairs vào 1 API call per contest

---

### Điểm khác biệt then chốt

| | SmartBugs | Web3Bugs |
|---|---|---|
| GT granularity | Contract-level SWC | H bug + function + contract |
| Matching | Keyword heuristic + LLM SWC classifier | LLM semantic judge |
| Dedup TP | Per (contract, SWC) | Per (H_id, function_name, contract_name) |
| FP definition | Finding không map SWC nào trong GT contract | Finding không match H bug nào |
| Metric unit | Per-SWC, per-contract | Per-H (aggregate F1) |

---

## Rủi ro

| Rủi ro | Khả năng | Giảm thiểu |
|--------|----------|-----------|
| Agents không output CONTRACT: field | Thấp (field là mandatory với ví dụ rõ) | Fallback: extract từ context_summary header nếu chỉ có 1 contract |
| Clustering (contract, function) quá broad — nhiều bugs khác nhau trong 1 function bị merge | Có (H-09/H-14 case) | Chấp nhận: merge chỉ ảnh hưởng evidence pool, không merge final output |
| Agents không còn SWC anchor → miss systematic patterns | Thấp | swc_focus hint vẫn giữ trong system prompt |
| evaluate_web3bugs.py break | Chắc chắn | Đã xác nhận out of scope; run evaluate bằng script cũ song song trong transition |
