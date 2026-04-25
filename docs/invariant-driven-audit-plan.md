# Invariant-Driven Adversarial Audit — Implementation Plan

## Motivation

Hệ thống hiện tại audit theo hướng **pattern-based**: agents tìm "code nào trông nguy hiểm".  
S-category bugs (S3 state machine, S6 accounting) bị miss vì cần hỏi câu khác:  
*"Protocol này cam kết điều gì? Code có vi phạm cam kết đó không?"*

Giải pháp: thêm **invariant layer** chạy song song (additive, không thay thế open-ended scan).

---

## Flow mới

```
Source code
    ↓
[Step 1] KG Builder → context_summary          (không đổi)
    ↓
[Step 2 — NEW] InvariantExtractor
    → invariant_list (JSON)
    → context_summary được bổ sung PROTOCOL INVARIANTS section
    ↓
[Step 3] Profile Generator                     (không đổi, nhận enriched context_summary)
    ↓
[Step 4] Session
    Phase A (rounds 1–4):  Expert findings     (không đổi)
    Phase B (rounds 5–7):  Cross-domain debate (không đổi)
    Phase C (rounds 8–10): [MODIFIED] Attacker nhận invariant attack goals
                            → action mới: ATTACKER_EXPLOIT
    ↓
[Step 5] Consensus + Report
    → thêm invariant_coverage[] section
```

---

## Component 1 — `ContractInvariantExtractor`

**File mới**: `backend/app/services/contract_invariant_extractor.py`  
**Effort**: ~1 ngày  
**Dependency**: độc lập, test được ngay

### Nhiệm vụ
1 LLM call với source_code + context_summary → trả về danh sách invariants có cấu trúc.

### Input / Output

```python
def extract(source_code: str, context_summary: str) -> dict:
    """
    Returns:
        {
            "invariants": [...],           # list các invariant objects
            "enriched_summary": str,       # context_summary + PROTOCOL INVARIANTS section
        }
    """
```

### Invariant object schema

```json
{
  "id": "INV-001",
  "category": "access_control",
  "statement": "Only the designated router can add/remove its own liquidity",
  "functions": ["addLiquidity", "removeLiquidity"],
  "violation_hint": "addLiquidity() has no require(router == msg.sender) check"
}
```

### Categories

| Category | Mô tả | Ví dụ |
|----------|--------|-------|
| `access_control` | Ai được phép gọi gì | "Only owner can pause" |
| `state_integrity` | State phải nhất quán sau mỗi tx | "approve must reset to 0 after fulfill" |
| `economic` | Bất biến về balance/liquidity | "Total liquidity = sum of router deposits" |
| `temporal` | Thứ tự và timing | "Cancel only after expiry" |
| `atomicity` | Các bước phải xảy ra cùng nhau | "Swap và update price trong cùng tx" |

### LLM Prompt strategy

```
System: You are a smart contract invariant analyst.
        Read the contract source and context summary.
        Extract invariants the protocol MUST maintain.
        Focus on: access rules, state consistency, economic correctness.
        Avoid cross-chain invariants (unverifiable from source alone).
        Output strict JSON array.

User: [source_code + context_summary]
      Extract up to 10 invariants. For each, include:
        id (INV-001..INV-010), category, statement, functions[], violation_hint.
```

### Inject vào context_summary

```
PROTOCOL INVARIANTS (verify each before reporting findings):
  [INV-001] access_control: Only designated router can manage its own liquidity
            functions: addLiquidity, removeLiquidity
            hint: no require(router == msg.sender)
  [INV-002] state_integrity: ERC20 approval must reset to 0 after fulfill
            functions: fulfill
            hint: no approve(addr,0) after IFulfillHelper.addFunds() reverts
  ...
```

---

## Component 2 — Goal-directed Attacker

### 2a. New action: `ATTACKER_EXPLOIT`

**File**: `backend/app/services/contract_oasis_env.py`

```python
class ContractAttackerAction:
    CONFIRM   = "ATTACKER_CONFIRM"    # confidence_delta: +0.15
    DISMISS   = "ATTACKER_DISMISS"    # confidence_delta: -0.20
    ADD_PATH  = "ATTACKER_ADD_PATH"   # confidence_delta: 0.0, creates finding
    ESCALATE  = "ATTACKER_ESCALATE"   # confidence_delta: +0.10
    DOWNGRADE = "ATTACKER_DOWNGRADE"  # confidence_delta: -0.10
    EXPLOIT   = "ATTACKER_EXPLOIT"    # NEW — confidence_delta: +0.25, creates invariant finding
```

**Output format attacker phải dùng**:
```
[ATTACKER_EXPLOIT INV-001]
Path: 1. Call addLiquidity(amount, assetId, victimRouter) from any address
      2. No require() or modifier prevents this
      3. Attacker can drain victim router's liquidity via removeLiquidity()
Impact: Full liquidity drain of any router
Feasible: yes
```

**Regex parser** (thêm vào `parse_from_text()`):
```python
_EXPLOIT_RE = re.compile(
    r'\[ATTACKER_EXPLOIT\s+(INV-\d+)\]',
    re.IGNORECASE
)
```

### 2b. Phase C instruction — thêm attack objectives

**File**: `contract_oasis_env.py` — `PHASE_CONFIG["C"]["instruction_addition"]`

Thêm section sau "UNVERIFIED CLAIMS":
```
INVARIANT ATTACK OBJECTIVES — Prove or disprove each invariant:
{invariant_goals}

For each invariant you can VIOLATE, use:
  [ATTACKER_EXPLOIT INV-001]
  Path: step-by-step exploit
  Impact: what attacker gains
  Feasible: yes/no
```

`{invariant_goals}` được inject tại runtime bởi `_build_phase_c_review_list()`.

### 2c. Sửa `_build_phase_c_review_list()`

**File**: `backend/app/services/cyber_session_orchestrator.py`

```python
def _build_phase_c_review_list(
    self,
    session_state: CyberSessionState,
    invariants: Optional[List[dict]] = None,   # NEW param
) -> str:
    # ... existing expert findings list (không đổi) ...

    # NEW: append invariant attack goals
    if invariants:
        lines.append("\nINVARIANT ATTACK OBJECTIVES:")
        for inv in invariants[:10]:
            lines.append(
                f"  [{inv['id']}] {inv['statement']}\n"
                f"    → Try to violate via: {', '.join(inv['functions'])}\n"
                f"    → Hint: {inv['violation_hint']}"
            )
    return "\n".join(lines)
```

### 2d. Sửa `_process_attacker_response()`

**File**: `cyber_session_orchestrator.py`

Thêm branch cho `ATTACKER_EXPLOIT`:
```python
elif action["action_type"] == ContractAttackerAction.EXPLOIT:
    inv_id = action.get("invariant_id")   # parsed từ [ATTACKER_EXPLOIT INV-001]
    feasible = action.get("feasible", "").lower() == "yes"
    if feasible:
        session_state.attacker_findings.append({
            "finding_id":        f"af_{uuid4().hex[:8]}",
            "invariant_id":      inv_id,
            "attacker_profile":  profile.persona,
            "title":             f"Invariant Violated: {inv_id}",
            "description":       action.get("reason", ""),
            "path_description":  action.get("path", ""),
            "severity":          "high",
            "base_confidence":   0.70,
            "source":            "invariant_exploit",
        })
```

---

## Component 3 — Tích hợp vào `run_audit()`

**File**: `backend/scripts/run_contract_audit.py`

### Thêm Step 1.5

```python
# STEP 1.5: Extract protocol invariants (additive layer)
logger.info("[STEP 1.5/4] Extracting protocol invariants...")
from app.services.contract_invariant_extractor import ContractInvariantExtractor

invariant_extractor = ContractInvariantExtractor(llm_client=llm_client)
inv_result = invariant_extractor.extract(
    source_code=source_code,
    context_summary=contract_summary,
)
invariants        = inv_result["invariants"]
contract_summary  = inv_result["enriched_summary"]   # bổ sung invariants section

_save_json(output_dir, "invariants.json", invariants)
logger.info(f"  Extracted {len(invariants)} invariants")
```

### Pass invariants vào session

```python
task_id = orchestrator.run_session_async(
    graph_id=graph_id,
    network_summary=contract_summary,
    profiles=profiles,
    mode="contract_audit",
    invariants=invariants,          # NEW
)
```

---

## Component 4 — `invariant_coverage` trong Report

**File**: `backend/app/services/vuln_report_agent.py`

Thêm vào `audit_report.json`:
```json
"invariant_coverage": [
  {
    "id": "INV-001",
    "statement": "Only designated router can manage its own liquidity",
    "status": "VIOLATED",
    "finding_ref": "af_a1b2c3d4",
    "attacker": "reentrancy_exploiter"
  },
  {
    "id": "INV-002",
    "statement": "ERC20 approval must reset to 0 after fulfill",
    "status": "UNVERIFIED"
  },
  {
    "id": "INV-003",
    "statement": "Each transactionId can only be fulfilled once",
    "status": "HOLDS"
  }
]
```

---

## Thứ tự implement

| Bước | Task | File(s) | Effort | Dependency |
|------|------|---------|--------|------------|
| **1** | `ContractInvariantExtractor` — LLM call + JSON parse | `contract_invariant_extractor.py` (mới) | 1 ngày | Độc lập |
| **2** | Inject invariants vào `context_summary` + step 1.5 trong `run_audit()` | `run_contract_audit.py` | 0.5 ngày | Sau bước 1 |
| **3** | Thêm `ATTACKER_EXPLOIT` action + regex parser | `contract_oasis_env.py` | 0.5 ngày | Độc lập |
| **4** | Sửa Phase C instruction + `_build_phase_c_review_list()` | `contract_oasis_env.py`, `cyber_session_orchestrator.py` | 0.5 ngày | Sau bước 1 + 3 |
| **5** | Sửa `_process_attacker_response()` | `cyber_session_orchestrator.py` | 0.5 ngày | Sau bước 3 |
| **6** | Thêm `invariant_coverage` vào report output | `vuln_report_agent.py` | 0.5 ngày | Sau bước 4 + 5 |
| **7** | Chạy Contest 19 re-run + evaluate | — | 1 ngày | Sau bước 1–6 |

**Tổng**: ~4.5 ngày

---

## Test strategy

### Bước 1 — Unit test InvariantExtractor (không cần full run)

```bash
python3 -c "
from backend.app.services.contract_invariant_extractor import ContractInvariantExtractor
extractor = ContractInvariantExtractor(...)
result = extractor.extract(source_code=open('/tmp/web3bugs_contest_19.sol').read(), ...)
print(result['invariants'])
"
```

Kỳ vọng với Contest 19:
- `INV-xxx`: "Only designated router can manage its own liquidity" (→ match H-01)
- `INV-xxx`: "ERC20 approval resets to 0 after fulfill" (→ match H-05)
- `INV-xxx`: "Each transactionId fulfilled exactly once"

### Bước 7 — Full re-run Contest 19

So sánh với Run #4 baseline:

| Metric | Run #4 (baseline) | Run #5 (invariant-driven) | Target |
|--------|-------------------|--------------------------|--------|
| L-recall | 0/1 = 0% | ? | ≥ 0% (H-02 không có invariant dễ extract) |
| S-recall (in-scope) | 1/2 = 50% | ? | ≥ 2/2 = 100% (H-01 + H-05) |
| F1 | 0.200 | ? | > 0.300 |
| Invariant violations found | N/A | ? | ≥ 2 |

---

## Scope limitations (không implement)

- **Cross-chain invariants** (H-03 SC, H-04 SE-2): không extract được từ source → vẫn OOS
- **H-02 (L4, gas DoS)**: invariant "array should not grow unbounded" khó express → có thể miss
- **Invariant quality**: phụ thuộc vào LLM extraction → sẽ có false/missing invariants

---

## Paper narrative

> MECAP introduces **invariant-driven adversarial auditing**: before the multi-agent debate begins,
> a dedicated extractor derives protocol invariants directly from source code — what the contract
> guarantees about access, state, and economics. The attacker layer then receives explicit
> violation objectives derived from these invariants, transforming it from a reactive
> confirm/dismiss role into a goal-directed exploit searcher. This architectural contribution
> directly addresses the fundamental limitation of pattern-based approaches (GPTScan, static tools):
> the inability to reason about *what should be true* rather than *what pattern matches*.
