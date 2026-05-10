# R1 RC Fixes v2 — Root Cause Fixes cho 6 FN Miss (Contest 35)

**Trạng thái:** Draft — chưa implement  
**Ngày:** 2026-05-08  
**Baseline:** RC fixes v1 → TP=9/17, Recall=52.9%, F1=0.265 (từ baseline TP=7)  
**Target:** Fix thêm H-01, H-06, H-07, H-12, H-16 → TP≥12  

Mỗi fix được ghi theo dạng: Root cause → Nguyên tắc chung → Nội dung thêm vào prompt.  
Tất cả fix phải **không chứa function/variable name cụ thể của contest 35**.

---

## Nhóm 1: Wrong Function Attribution (H-12)

**Root cause:** Agents attribute ordering bugs theo "nơi expression tồn tại trong source" thay vì "nơi bug manifests." Với accumulator updates được gọi từ nhiều callers, agents gán FUNCTION cho caller phổ biến nhất thay vì caller có ordering error.

**File:** `contract_oasis_env.py` — `build_round1_prompt`  
**Vị trí:** Trong block `STATE UPDATE ORDERING`, sau đoạn INTRA-FUNCTION  

**Nội dung thêm vào:**

```
FUNCTION ATTRIBUTION FOR ORDERING BUGS:
  FUNCTION field = outer function that CONTROLS the execution sequence, NOT the helper/internal
  function containing the accumulator expression.
  Rationale: the fix location is always the outer function (reorder the calls), not inside the helper.
  
  Test: "If I fix this bug, which function's source code changes?"
  → That function is the correct FUNCTION field value.
  
  Example (abstract): if outer() calls updateAcc(stateVar) AFTER changing stateVar,
  the ordering error is in outer() — write FUNCTION: outer, even if updateAcc() contains
  the accumulator expression.
  
  This rule applies regardless of whether the outer function is called mint/burn/swap/deposit/
  stake/harvest or any other name — it is the function that controls call order.
```

**Rủi ro:** Thấp. Rule viết theo abstract principle, không hardcode function names. Không ảnh hưởng dedup (dedup dùng code_anchor, không dùng FUNCTION field).

---

## Nhóm 2: Wrong Direction/Description (H-06)

**Root cause:** Agents không trace arithmetic direction khi mô tả staleness bugs. Mental default "stale = accounting error = loss" gây ra description ngược chiều. Ngoài ra, RC3 instruction map "READER before WRITER" pattern cho H-06, trong khi H-06 thực chất là "missing sync in conditional branch" — khác về structure.

**File:** `contract_oasis_env.py` — `build_round1_prompt`  
**Vị trí:** Trong block `STATE UPDATE ORDERING`, phần CROSS-CALL SEQUENCING  

**Nội dung thêm vào (thay thế/bổ sung phần direction):**

```
STALENESS DIRECTION ANALYSIS — bắt buộc trước khi viết OUTCOME cho cross-call findings:

  Step 1: READER tính gì?
    Case A: `reward = accumulator_global - position.accumulator`
      → stale position.accumulator (lower than actual) → delta LARGER → user gets MORE than owed
      → OUTCOME: attacker/user claims excess fees/rewards (overpayment)
    Case B: `reward = position.accumulator - baseline`  
      → stale position.accumulator (higher than actual) → delta SMALLER → user gets LESS
      → OUTCOME: user's reward is diluted (underpayment)
  
  Do NOT write generic "accounting error" or "fee loss" — always specify direction.

CONDITIONAL SYNC SKIP — additional cross-call pattern (beyond READER/WRITER ordering):
  Signal: function has a branch `if (condition) { sync_state(); update_position_snapshot(); }`
  When the branch is NOT taken → position snapshot is NOT updated.
  If another function later reads the position snapshot → stale read, regardless of call order.
  Check: what are all the early-return or skip-sync branches? What state remains unsynced?
  EVIDENCE: MISSING: sync call AT: function() for the branch that skips it
```

**Rủi ro:** Phần direction analysis là pure arithmetic reasoning — không có tên hàm cụ thể. Phần conditional sync skip mô tả structural pattern (branch skip) mà không nhắc collect()/BentoBox/contest-specific names. Applicable to vault protocols, lending protocols, AMMs.

---

## Nhóm 3: Coverage Gap — Same Pattern, Different Variable Name (H-01)

**Root cause:** COVERAGE RULE reactive — trigger sau khi tìm pattern ở function A, nhưng không cover khi variable name khác ở function B. Agents không proactively enumerate tất cả instances của cùng cast operator.

**File:** `contract_oasis_env.py` — `build_round1_prompt`  
**Vị trí:** Trong block `CAST & COMPARISON PRECISION`, sau Q1→Q3 rules  

**Nội dung thêm vào:**

```
CAST CROSS-FUNCTION SCAN — sau khi tìm bất kỳ cast-related finding:
  Với mỗi cast operator đã tìm ra finding (e.g., int128(), uint128(), int24(), uint96()):
  1. Scan TẤT CẢ functions trong contract cho cùng cast operator — bất kể tên biến
  2. Áp dụng Q1→Q3 cho mỗi instance tìm được
  3. Nếu YES → viết FINDING riêng cho mỗi function (COVERAGE RULE)
  
  Lý do: cùng cast type với tên biến khác nhau có thể có max-value khác nhau.
  Không được dừng lại ở function đầu tiên tìm thấy.
  Scan TẤT CẢ functions — không ưu tiên hay bỏ qua bất kỳ function nào.
```

**Rủi ro:** Thấp — "scan same cast operator across all functions" là hành động có thể thực hiện được với full source. Không hardcode function names. Chi phí token tăng nhẹ (khoảng 150 token/agent khi có cast finding). "liquidity math, reserve accounting, fee calculations" là domain categories chung, không contest-specific.

---

## Nhóm 4: Fix Trigger Sai — Parameter Propagation (H-07)

**Root cause:** MULTI-ANGLE là reactive follow-up — chỉ chạy sau khi có finding. H-07 cần proactive investigation: agents phải chủ động trace address parameters trong wrapper contracts trước khi viết finding, không phụ thuộc vào kết quả primary analysis.

**File:** `contract_oasis_env.py` — `build_round1_prompt`  
**Vị trí:** Thêm block mới sau `STATE UPDATE ORDERING`, TRƯỚC `OUTPUT FORMAT`  
**Tên block:** `PARAMETER PROPAGATION IN WRAPPER CONTRACTS`

**Nội dung:**

```
PARAMETER PROPAGATION IN WRAPPER CONTRACTS — chạy độc lập, không phụ thuộc findings:

Nếu contract trong scope đóng vai trò WRAPPER/MANAGER (gọi vào inner contract/pool):

Step 1 — Identify address parameters:
  Trong mỗi external/public function: tìm tất cả address-type parameters
  (tên thường là: recipient, to, beneficiary, owner, receiver, destination)

Step 2 — Trace propagation:
  Address đó được pass vào inner call nào? Trace mọi inner contract call nhận address parameter đó.

Step 3 — Scope check:
  Inner function dùng address để distribute assets của:
  (A) CHỈ position/account của caller → safe
  (B) TẤT CẢ accumulated assets trong tick range / pool bucket / vault tranche → potential bug

Step 4 — Access control check:
  Nếu (B): ai kiểm soát address parameter? Chỉ position owner, hay bất kỳ ai?
  Nếu bất kỳ caller nào có thể set address → attacker redirect assets của người khác.

EVIDENCE format: CODE: <inner call với address parameter>
ATTACK_PATH: ACTOR: any caller / CALL: wrapper.fn(victim_addr) → inner.fn(victim_addr) /
             STATE_CHANGE: inner distributes pool-level assets to victim_addr /
             OUTCOME: attacker claims assets belonging to other users
```

**Rủi ro:** Trung bình. Step 3 "scope check" yêu cầu agents hiểu semantics của inner contract — nếu inner contract source không available trong context, agents sẽ phải infer, có thể sinh FP. Trong contest settings với full source, acceptable.

---

## Nhóm 5: Fix bị Conflate — Passive Bug vs Active Exploit (H-12 + H-16)

**Root cause:** Khi một state variable vừa có (A) passive implementation bug (ordering error → wrong value bất kể ai) vừa có (B) active economic exploit (attacker timing → profit), agents generate 1 finding mô tả hybrid. Không đủ precise cho cả hai GT entries. Hai bugs có FUNCTION khác nhau, fix location khác nhau, và impact category khác nhau.

**File:** `contract_oasis_env.py` — `build_round1_prompt`  
**Vị trí:** Thêm vào `MULTI-ANGLE EXHAUSTION` block, sau phần (B) INTERACTIONS  

**Nội dung thêm vào:**

```
FINDING SPLITTING RULE — passive bug vs active exploit:

Nếu phát hiện state variable X mà:
  (A) PASSIVE: X được tính sai bởi code logic bất kể có attacker hay không
      (ordering error, missing update, wrong accumulator formula)
  (B) ACTIVE: attacker có thể khai thác X sai bằng cách timing transactions để profit
      (JIT attack, sandwich, front-run reward claim)

→ Viết HAI FINDING riêng biệt:

  Finding A — Implementation Bug:
    FUNCTION: function chứa ordering/calculation error (nơi fix sẽ thay đổi code)
    SEVERITY: dựa trên impact của passive bug với normal users
    EVIDENCE: SEQ: hoặc CODE: (chứng minh ordering/logic error)
    ATTACK_PATH ACTOR: any user / LP (không cần adversarial timing)

  Finding B — Economic Exploit:
    FUNCTION: function attacker gọi để profit (claimReward, withdraw, harvest, collect)
    SEVERITY: dựa trên max profit attacker có thể extract
    EVIDENCE: DESIGN: (mô tả mechanism bị abuse)
    ATTACK_PATH ACTOR: attacker (cần adversarial timing)

KHÔNG gộp hai finding. Lý do:
- Fix location khác nhau: Finding A fix ở accumulator update, Finding B cần minimum hold period
- Audit category khác nhau: A = implementation bug, B = economic design flaw
- Impact path khác nhau: A ảnh hưởng tất cả users, B chỉ khi bị exploit chủ động

Pattern phổ biến: bất kỳ accumulator thời gian (secondsPerLiquidity, rewardPerShare,
cumulativeIndex) vừa có ordering bug vừa có JIT attack surface.
```

**Rủi ro:** Thấp. Rule mô tả abstract structural pattern (passive vs active), không nhắc function/variable names cụ thể. Áp dụng cho AMM, lending, yield farming, staking protocols. Trade-off: tăng số findings (có thể +1 per such mechanism) → FP count có thể tăng nhẹ nếu agents over-apply. Mitigate: "bất kỳ accumulator thời gian" là bounded category.

---

## Tóm tắt các file cần thay đổi (khi implement)

| Fix | File | Vị trí |
|-----|------|--------|
| Nhóm 1 (Attribution) | `contract_oasis_env.py` | STATE UPDATE ORDERING block |
| Nhóm 2 (Direction + Conditional) | `contract_oasis_env.py` | STATE UPDATE ORDERING → CROSS-CALL |
| Nhóm 3 (Cross-function scan) | `contract_oasis_env.py` | CAST & COMPARISON PRECISION block |
| Nhóm 4 (Wrapper parameter) | `contract_oasis_env.py` | New block trước OUTPUT FORMAT |
| Nhóm 5 (Split rule) | `contract_oasis_env.py` | MULTI-ANGLE EXHAUSTION block |

Tất cả 5 fix đều trong cùng file, cùng function `build_round1_prompt`.  
Không thay đổi `contract_profile_generator.py` (persona prompts) cho v2 này.

---

## Verification plan (sau khi implement)

```bash
cd /home/thangdd/repos/MiroFish/backend
LOG=/tmp/web3bugs_35_rcv2_$(date +%Y%m%d_%H%M%S).log
DEDUP_OUT=/tmp/dedup_findings_35_rcv2_$(date +%Y%m%d_%H%M%S).json

STOP_AFTER_DEDUP=true STOP_AFTER_DEDUP_OUT=$DEDUP_OUT \
nohup bash -c '
  source .venv/bin/activate
  exec python scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
    --output ./results/web3bugs_trial/contest_35_rcv2 \
    --timeout 7200 --verbose
' >> "$LOG" 2>&1 &

# Evaluate
python scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_35.json $DEDUP_OUT --verbose
```

**Target:** TP ≥ 12 (từ current TP=9), FP không tăng quá 10% (từ 42).  
**Target bugs:** H-01, H-07, H-12, H-16 (H-06 cải thiện direction, có thể cũng match).
