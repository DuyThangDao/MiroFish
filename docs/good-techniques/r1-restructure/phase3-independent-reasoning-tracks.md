# Phase 3 — Independent Reasoning Tracks

## Mục tiêu

Bổ sung 4 reasoning tracks vào Turn 2 prompt để agent tìm được novel bugs nằm ngoài
HIST-INV patterns — không phụ thuộc vào RAG hay historical data.

## Prerequisites

- [x] Phase 2 hoàn thành — RAG đã remove khỏi R1
- [x] Phase 2 benchmark xác nhận F1 ≥ baseline

---

## Background: Tại sao cần Independent Reasoning Tracks

Sau khi remove RAG khỏi R1, agents chỉ còn:
1. Verify HIST-INV annotations có trên source
2. Viết INV từ code rồi check violation

Điều này vẫn bỏ sót novel bugs: lỗi chưa từng xuất hiện trong RAG DB, lỗi logic phức tạp
không có historical precedent, lỗi xuất hiện từ tổ hợp nhiều function.

4 tracks bổ sung đảm bảo agents reason từ **first principles**, không chỉ pattern matching.

---

## Step 3.1 — Track A: Adversarial Input Enumeration

**Assign cho**: tất cả agents (thêm vào Turn 2 global instructions)

**Vị trí**: `backend/app/services/contract_oasis_env.py` — sau `_STEP1_BLOCK`, trong Turn 2 prompt

```
TRACK A — ADVERSARIAL INPUTS:
  For functions you are analyzing, enumerate extreme inputs:
  - Numeric bounds: 0, 1, type(uint256).max, type(int256).min
  - Address edge cases: address(0), address(this), msg.sender
  - Array edge cases: empty array [], single element, length > expected
  - Sequence attacks: call function A then B to leave state invalid

  For each input: does the function handle it correctly, or does it revert/corrupt state?
  If it corrupts state without reverting → candidate FINDING.
```

---

## Step 3.2 — Track B: Trust Assumption Analysis

**Assign cho**: `appsec_researcher`, `appsec_hardener` — thêm vào `system_prompt` của 2 agents này

**Vị trí**: `backend/app/services/contract_profile_generator.py`

```
TRACK B — TRUST ASSUMPTIONS:
  Identify what this contract IMPLICITLY trusts without on-chain verification:
  - Token transfer returns exact amount (may fail for fee-on-transfer tokens)
  - Oracle price is not manipulatable in a single transaction
  - External contract called does not re-enter this contract
  - msg.sender is an EOA, not a contract
  - Return value of low-level call is not checked

  For each assumption: is it ALWAYS guaranteed by the protocol design?
  If no → candidate FINDING with the specific assumption and how it can be violated.
```

---

## Step 3.3 — Track C: State Consistency Across Calls

**Assign cho**: `state_machine_analyst`, `reentrancy_specialist` — thêm vào `system_prompt`

**Vị trí**: `backend/app/services/contract_profile_generator.py`

```
TRACK C — STATE CONSISTENCY:
  Identify storage variables written by more than one function.
  For each shared variable:
  - Is there an ordering where function A partially updates and function B reads stale state?
  - Can a reentrancy path (function A → external call → function A again) leave accounting corrupt?
  - Is there a window between two related storage writes where state is transiently invalid?

  Focus on: cumulative totals, balance mappings, index variables, linked list pointers.
  If inconsistent state is reachable → candidate FINDING with the exact call sequence.
```

---

## Step 3.4 — Track D: Spec vs Implementation Gap (per domain)

**Assign theo domain group** — thêm vào từng `system_prompt` trong `contract_profile_generator.py`

| Domain | Track D instruction |
|---|---|
| `code_security` | "Does every external call follow CEI (Checks-Effects-Interactions)? Is there any state read that happens after an external call that could return stale data?" |
| `crypto_math` | "Is there any intermediate multiplication where the product can overflow uint256 before division? Is there any division-before-multiplication that truncates precision?" |
| `defi_economics` | "After any sequence of deposits, borrows, and withdrawals: can total protocol liabilities exceed total assets? Can a single actor manipulate share price by donating tokens?" |
| `governance` | "Is there any function that changes protocol parameters callable without timelock or multisig? Can a proposal be executed before the voting period ends?" |
| `standards` | "Does this token's transfer/transferFrom match ERC20 spec exactly? Is allowance correctly decremented? Does balanceOf return accurate values after every operation?" |
| `deep_analysis` | "Is there any library function that assumes a precondition not enforced by the caller? Are there any integer casts (explicit or implicit) that silently truncate?" |

---

## Step 3.5 — Cập nhật `_STEP1_BLOCK` priority

**Vị trí**: `backend/app/services/contract_oasis_env.py`

Thêm Track A vào phần `STEP 2 — FIND VIOLATIONS` sau INV check section:

```python
_INDEPENDENT_TRACKS_BLOCK = """
INDEPENDENT REASONING TRACKS — run these regardless of HIST-INV annotations:

TRACK A — ADVERSARIAL INPUTS:
  For the 2-3 most complex functions: test numeric bounds (0, max_uint),
  address(0), empty arrays, and cross-function call sequences.
  Any input that corrupts state without reverting = FINDING candidate.

TRACK B/C/D: applied per your domain expertise (see your system prompt).
"""
```

Inject `_INDEPENDENT_TRACKS_BLOCK` vào Turn 2 prompt builder trong `contract_oasis_env.py` như một **static component** — unconditional, không qua `step2_hint`.

**Lý do**: Phase 2 đã làm `step2_hint = ""` luôn luôn → `hint_section` luôn rỗng. `_INDEPENDENT_TRACKS_BLOCK` phải được append trực tiếp trong prompt builder (sau `hint_section`), không phụ thuộc vào `step2_hint` có giá trị hay không.

---

## Step 3.6 — Benchmark

```bash
bash scripts/run_benchmark.sh \
  /home/thangdd/repos/web3bugs/contracts/42 \
  ../benchmark/web3bugs/agent-redesign/42/run-phase3

python3 scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_42.json \
  ../benchmark/web3bugs/agent-redesign/42/run-phase3/*/audit_report_dedup.json \
  --verbose | tee ../benchmark/web3bugs/agent-redesign/42/run-phase3/eval_result.txt
```

**Dấu hiệu thành công:**
- F1 tăng so với Phase 2 (novel bugs được tìm thêm)
- FP không tăng quá 5 so với Phase 2 (tracks không flood false positives)
- Các H bugs bị miss ở Phase 2 được recover bởi Track A/B/C/D

**Nếu FP tăng nhiều:**
- Tăng evidence requirement: agent phải cite exact code lines cho Track A/B/C/D findings
- Chạy Track D riêng cho từng domain, tắt những track gây noise nhiều nhất

---

## Checklist

- [ ] Thêm Track A instruction vào Turn 2 global prompt (Step 3.1)
- [ ] Thêm Track B vào `appsec_researcher` + `appsec_hardener` system_prompt (Step 3.2)
- [ ] Thêm Track C vào `state_machine_analyst` + `reentrancy_specialist` system_prompt (Step 3.3)
- [ ] Thêm Track D per-domain instruction vào 6 domain groups (Step 3.4)
- [ ] Thêm `_INDEPENDENT_TRACKS_BLOCK` vào Turn 2 prompt (Step 3.5)
- [ ] Chạy benchmark contest 42
- [ ] So sánh F1 + FP với Phase 2 baseline
