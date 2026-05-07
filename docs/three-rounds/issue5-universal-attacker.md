# Issue 5: R3 Universal Attacker — Thiết Kế & Lý Do

> Tài liệu này mô tả kiến trúc thay thế cho R3 Attacker Validation:
> từ 5 specialized attackers (5N calls) xuống 1 universal attacker (N calls).

---

## 1. Kiến Trúc Hiện Tại

R3 dùng 5 Tier-2 attacker profiles, **tất cả 5** đều chạy với **từng finding**:

| Attacker | Chuyên môn | Skill |
|---|---|---|
| `reentrancy_exploiter` | Drain ETH via recursive calls | medium |
| `flash_loan_attacker` | Oracle manipulation, governance via flash loan | expert |
| `governance_attacker` | Malicious proposal, timelock bypass | expert |
| `access_control_exploiter` | Privilege escalation, missing modifier | medium |
| `logic_exploiter` | Rounding errors, state machine bugs, invariants | expert |

**Số calls:** `5 × N findings` — với N=45 (contest 35) → 225 calls.

### Vấn đề

**Nghẽn cổ chai theo cấp số nhân:**
```
Contest nhỏ  (~10 findings) →  50 calls
Contest vừa  (~45 findings) → 225 calls
Contest lớn  (~100 findings)→ 500 calls
```

**Lãng phí tài nguyên:**
Với 1 finding về AMM math bug, chỉ `logic_exploiter` viết được scenario chất lượng.
4 attackers còn lại hoặc DISMISS hoặc viết generic output không có giá trị.

Ví dụ thực tế từ contest 35 (Trident AMM):
- Phần lớn H-bugs là math/logic bugs → `reentrancy_exploiter`, `governance_attacker`,
  `access_control_exploiter` không có chuyên môn phù hợp → 3/5 calls lãng phí/finding.

---

## 2. Lý Do Chuyển Sang Universal Attacker

### 2.1 Mục tiêu R3 là Confirm, không phải PoC

R3 chỉ cần trả lời: **"Finding này có thực sự exploitable không?"**

Không cần:
- Working PoC code (bước này đã bỏ)
- Deep multi-angle analysis
- Cross-attacker consensus

Chỉ cần: 1 attack scenario đủ thuyết phục để xác nhận hoặc bác bỏ finding.

### 2.2 Pro Model Đã Có Đủ Cross-Domain Knowledge

R3 dùng **Boost LLM** (`BOOST_MODEL_NAME` — hiện tại Gemini 3.1 Pro Preview).
Pro model có built-in knowledge về tất cả attack categories mà 5 specialized prompts
đang encode. Specialization ban đầu được thiết kế để bù cho model yếu cần explicit
guidance — Pro model không cần scaffold đó.

### 2.3 Trade-off Chấp Nhận Được

| | 5 attackers | 1 universal |
|---|---|---|
| Calls (N=45) | 225 | 45 |
| Depth per finding | High (specialized) | Medium-High (Pro model) |
| PoC quality | High | Medium |
| Confirm/Dismiss accuracy | High | Sufficient |

Với mục tiêu hiện tại (confirm exploitability), "Sufficient" là đủ.

---

## 3. Thiết Kế Universal Attacker Prompt

### 3.1 Yêu Cầu Thiết Kế

1. **Force declare attack angle** — model phải chọn angle trước khi viết scenario,
   tránh default về 1 type silently.
2. **NOT_EXPLOITABLE path rõ ràng** — model phải có exit rõ ràng thay vì cố bịa scenario.
3. **Compact output** — không cần elaborate, chỉ cần đủ để judge.

### 3.2 Output Format

```
ATTACK_ANGLE: <reentrancy | flash_loan | governance | access_control | logic_math | other>
EXPLOITABLE: <YES | NO | UNCERTAIN>
SCENARIO:
  1. <bước tấn công 1>
  2. <bước tấn công 2>
  ...
IMPACT: <mô tả hậu quả cụ thể — số token, ETH, hoặc state bị phá vỡ>
PRECONDITION: <điều kiện cần để exploit hoạt động, hoặc NONE>
```

Khi `EXPLOITABLE: NO`:
```
ATTACK_ANGLE: <angle đã xét>
EXPLOITABLE: NO
REASON: <lý do cụ thể tại sao không exploit được>
```

### 3.3 System Prompt Structure

```
You are a smart contract security attacker with expertise across ALL attack domains:
reentrancy, flash loans, governance attacks, access control exploitation,
and business logic / math vulnerabilities.

=== FINDING TO EVALUATE ===
Title: {finding["title"]}
Function: {finding["function_name"]}
Evidence: {finding["evidence_snippets"][0]}
Description: {finding["description"]}

=== CONTRACT CONTEXT ===
{contract_source_truncated}

=== YOUR TASK ===
Determine if this finding is exploitable. Analyze from ALL relevant attack angles,
then select the most applicable one.

Step 1 — Declare your attack angle:
  ATTACK_ANGLE: <reentrancy | flash_loan | governance | access_control | logic_math | other>

Step 2 — Assess exploitability:
  EXPLOITABLE: YES / NO / UNCERTAIN

Step 3 — If YES or UNCERTAIN, write a concrete attack scenario:
  SCENARIO: step-by-step attack path
  IMPACT: quantified impact (ETH drained, tokens minted, invariant broken)
  PRECONDITION: required setup (e.g., "attacker must have LP position", or NONE)

Step 4 — If NO, explain:
  REASON: specific technical reason why the finding is not exploitable

Rules:
- Be specific — generic scenarios ("attacker calls the function") are invalid
- If the finding describes a real code bug but you cannot construct an exploit path → UNCERTAIN
- Do not fabricate code snippets that don't exist in the contract
```

---

## 4. Thay Đổi Implementation

### 4.1 Files Cần Thay Đổi

**`contract_profile_generator.py`:**
- Giữ nguyên `CONTRACT_ATTACKER_PROFILES` dict (backward compat với v1 pipeline)
- Thêm hàm `build_universal_attacker_prompt()` mới

**`cyber_session_orchestrator.py` — `_run_attacker_round()`:**
- Thay vì loop `for attacker in t2_profiles: for finding in accepted_findings`
- Chuyển thành `for finding in accepted_findings: call universal_attacker`
- `t2_profiles` không còn được dùng trong v2 path

**`contract_oasis_env.py` — `r3_prompt()`:**
- Thêm overload hoặc flag `use_universal=True`

### 4.2 Thay Đổi Scoring

Hiện tại R3 aggregates votes từ 5 attackers. Với 1 attacker, scoring đơn giản hơn:

```python
# Cũ: majority vote từ 5 attackers
confirmed   = [f for f in accepted if attacker_votes[f] >= 3]
borderline  = [f for f in accepted if attacker_votes[f] == 2]
discarded   = [f for f in accepted if attacker_votes[f] <= 1]

# Mới: single attacker decision
confirmed   = [f for f in accepted if f["r3_result"] == "YES"]
borderline  = [f for f in accepted if f["r3_result"] == "UNCERTAIN"]
discarded   = [f for f in accepted if f["r3_result"] == "NO"]
```

---

## 5. Env Var Để Toggle

Để không break v1 pipeline và hỗ trợ A/B test:

```bash
# .env
R3_UNIVERSAL_ATTACKER=true   # false = dùng 5 specialized attackers (v1 behavior)
```

---

## 6. Impact Dự Kiến

| Metric | Trước | Sau |
|---|---|---|
| R3 calls (N=45) | 225 | 45 |
| R3 wall time | ~30–60 phút | ~6–12 phút |
| Rate limit errors | Cao | Thấp đáng kể |
| Confirm accuracy | Baseline | Cần benchmark |

Cần chạy contest 35 với universal attacker để đo Precision/Recall thực tế so với baseline.

---

## 7. Rủi Ro & Mitigation

### 7.1 Model "Anchor" vào 1 attack type

Pro model có thể default về `logic_math` cho mọi findings (vì đó là type phổ biến nhất
trong training data DeFi audit). Force declare `ATTACK_ANGLE` trước scenario giúp phát
hiện điều này trong logs.

**Mitigation:** Log distribution của `ATTACK_ANGLE` qua các runs. Nếu >80% là `logic_math`
cho contest có mixed bug types → cần cải thiện prompt instruction.

### 7.2 UNCERTAIN overuse

Model có thể dùng UNCERTAIN quá nhiều để tránh commit vào YES/NO.

**Mitigation:** Treat UNCERTAIN như borderline (giữ finding nhưng flag). Monitor tỉ lệ
UNCERTAIN trong logs — nếu >30% → prompt cần cứng hơn ở decision rule.

### 7.3 Mất coverage với specialized bugs

Reentrancy bugs cần hiểu CEI pattern cụ thể. Flash loan bugs cần biết Aave V3 interface.
Universal attacker có thể miss subtle cases mà specialized attacker bắt được.

**Mitigation:** Chấp nhận trade-off này vì mục tiêu là confirm, không discover. R1/R2
đã discover bugs rồi — R3 chỉ cần confirm exploitability ở level "có attack path hay không".
