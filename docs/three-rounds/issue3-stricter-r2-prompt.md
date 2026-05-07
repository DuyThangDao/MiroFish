# Issue 3: R2 Accept 100% — Phân Tích & Giải Pháp

> Tài liệu này phân tích tại sao R2 accept 100% findings và kết luận
> rằng root fix nằm ở upstream (R1), không phải R2.

---

## 1. Cơ Chế Tính Điểm R2 Hiện Tại

```
k     = số agents submit finding này ở R1 (tính như "free votes")
r     = số ACCEPT votes ở R2 (self-exclusion: submitters không vote)
score = (k + r) / n_agents     [n_agents = 19]
threshold = 0.35
```

**Để pass:** cần k + r ≥ 7

| k (submitters) | r cần thêm | % voters phải ACCEPT |
|---|---|---|
| 1 | ≥ 6 | 6/18 = 33% |
| 2 | ≥ 5 | 5/17 = 29% |
| 3 | ≥ 4 | 4/16 = 25% |

→ Ngưỡng thấp: chỉ cần 1/3 agents "không phản đối" là finding pass.

---

## 2. Các Hướng Fix R2 Đã Xét — Và Tại Sao Không Ổn

### 2.1 Raise Threshold (0.35 → 0.55)

**Vấn đề:** Specialized bugs chỉ được discover bởi 1 domain-specific agent (k=1).
Với threshold cao hơn, cần đa số agents đồng ý — nhưng non-domain agents không đủ
kiến thức để evaluate → bug bị kill không vì sai, mà vì voters sai chuyên môn.

### 2.2 Default REJECT Framing

**Vấn đề:** Agents không tìm ra bug ở R1 vì thiếu domain knowledge (TYPE A) sẽ
không thể prove exploitability ở R2 dù có context. Với strict prompt, họ sẽ
default REJECT mọi thứ không chắc chắn → over-correct, kill TP phức tạp.

### 2.3 ABSTAIN Vote

**Vấn đề:** Không có cost để ABSTAIN → agents sẽ ABSTAIN mọi case khó để tránh
rủi ro sai. Không có cơ chế nào ngăn được behavior này một cách robust.

### 2.4 Domain Routing

**Vấn đề:** Chỉ gửi finding đến relevant domain agents → mất cross-domain perspective.
Một AMM math finding có thể có access control implication mà governance agent mới thấy.
Đây là một trong những giá trị cốt lõi của 19-agent pipeline.

### 2.5 System-Weighted Voting

**Vấn đề:** Không có cơ sở để xác định weight matrix (defi_math = 1.0, appsec = 0.3...).
Bất kỳ weight nào cũng là hand-crafted assumptions không có ground truth để validate.
Cần nhiều contests với GT data mới calibrate được.

### Kết Luận Về R2

Tất cả các hướng fix R2 đều có vấn đề cơ bản. **Root cause không nằm ở R2**
mà nằm ở upstream: R1 đang produce quá nhiều FP findings với evidence mơ hồ,
khiến R2 không thể phân biệt được.

---

## 3. Root Cause: ATTACK_PATH Không Được Validate Chất Lượng

### 3.1 R1 Hiện Tại Đã Chặt Về Format

R1 đã enforce:
- `CODE_ANCHOR`: grep-verified — phải tồn tại verbatim trong source ✓
- `EVIDENCE`: mandatory với 5 format cụ thể (CODE/MISSING/SEQ/INV/DESIGN) ✓
- `CONTRACT`, `FUNCTION`: mandatory ✓

### 3.2 Nhưng ATTACK_PATH Không Có Quality Check

```
ATTACK_PATH: step-by-step exploit scenario   ← required nhưng content không validated
```

FP finding vẫn pass vì:
```
CODE_ANCHOR: incentives[position.pool]  ✓  (tồn tại trong source)
EVIDENCE:    CODE: incentives[position.pool]  ✓  (format valid)
ATTACK_PATH: "An attacker can exploit the unvalidated mapping access..."
             ← vague, không có specific function call, nhưng không bị drop
```

### 3.3 Tại Sao ATTACK_PATH Là Leverage Point

**Real vulnerability bắt buộc phải có concrete attack path. FP thì không thể.**

FP `incentives[position.pool]` không thể fill được ATTACK_PATH cụ thể:
- Không có function nào để call để exploit mapping access này
- Read-only operation, không mutate state
- Không có measurable outcome

H-10 `burn()` wrong reserve fill được dễ dàng:
- Actor: LP holder
- Call: `burn(liquidity)` → transfers `amount0 + amount0fees`
- State change: `reserve0 -= amount0fees` only (missing `amount0`)
- Outcome: `reserve0 > actual balance` → subsequent mints over-allocate

---

## 4. Giải Pháp: Structured ATTACK_PATH + Parser Validation

### 4.1 Format Mới Cho ATTACK_PATH

Thêm cấu trúc bắt buộc:

```
ATTACK_PATH:
  ACTOR: <who initiates — attacker/user/LP holder/any caller>
  CALL: <exact function(s) in sequence, e.g. burn() → transfer()>
  STATE_CHANGE: <what state variable becomes incorrect>
  OUTCOME: <measurable result — X tokens drained / invariant Y broken>
```

### 4.2 Ví Dụ

**FP — `incentives[position.pool]` (mapping access):**
```
ATTACK_PATH:
  ACTOR: attacker
  CALL: ???       ← không có function exploit được
  STATE_CHANGE: ??? ← read-only, không mutate
  OUTCOME: ???    ← không có outcome đo được
→ Agent không viết được cụ thể → không submit → không vào pool ✓
```

**TP — H-10 `burn()` wrong reserve:**
```
ATTACK_PATH:
  ACTOR: LP holder with existing position
  CALL: burn(liquidity) → internally transfers amount0 + amount0fees to user
  STATE_CHANGE: reserve0 decremented by amount0fees only, not amount0
  OUTCOME: reserve0 > actual token balance → subsequent mint() over-allocates tokens
→ Cụ thể, verifiable → pass ✓
```

**TP — H-15 `initialize()` missing check:**
```
ATTACK_PATH:
  ACTOR: anyone calling initialize()
  CALL: initialize(sqrtPrice) with sqrtPrice outside valid range
  STATE_CHANGE: pool initialized with invalid price, nearestTick set incorrectly
  OUTCOME: all subsequent swap() calls compute wrong amounts → fund loss
→ Cụ thể dù là MISSING type → pass ✓
```

### 4.3 Parser Validation (Deterministic, Không Cần LLM)

```python
def _validate_attack_path(attack_path: str) -> bool:
    """
    Drop finding nếu ATTACK_PATH không đủ cụ thể.
    Chạy cùng level với FP check, trước khi vào R2.
    """
    if not attack_path or len(attack_path.strip()) < 50:
        return False

    # Phải có ít nhất 3 trong 4 ACTOR/CALL/STATE_CHANGE/OUTCOME fields
    structured_fields = sum([
        "ACTOR:" in attack_path,
        "CALL:" in attack_path,
        "STATE_CHANGE:" in attack_path,
        "OUTCOME:" in attack_path,
    ])
    return structured_fields >= 3
```

**Lý do đơn giản hóa:** `has_structure` đã là điều kiện đủ — finding có đủ 3/4 fields
thì valid, thiếu thì drop. Không cần thêm condition nào khác.

### 4.4 R1 Prompt Update

Thêm example và rules cho ATTACK_PATH:

```
ATTACK_PATH — MANDATORY. Must follow structured format:
  ACTOR: <who initiates the attack>
  CALL: <exact function(s) from THIS contract, in sequence>
  STATE_CHANGE: <which state variable becomes incorrect and how>
  OUTCOME: <measurable impact — specific tokens/ETH lost, invariant broken>

✓ Good:
  ACTOR: Any LP holder
  CALL: burn(liquidity) → sends amount0 + amount0fees to user
  STATE_CHANGE: reserve0 -= amount0fees (missing amount0 subtraction)
  OUTCOME: reserve0 inflated → next mint() caller receives excess tokens

✗ Bad (will be dropped):
  ATTACK_PATH: An attacker can exploit this vulnerability to drain funds from the contract.
```

---

## 5. R1 ATTACK_PATH Fix — Ưu Điểm Và Phạm Vi

| Pendekatan | Kompleksitas | Risiko | Kết quả |
|---|---|---|---|
| Fix R2 (threshold/ABSTAIN/routing/weight) | Cao | Cao (nhiều edge case) | Không chắc |
| Fix R1 ATTACK_PATH | Thấp | Thấp (deterministic check) | FP gugur trước R2 |

- **Deterministic**: parser check, không cần LLM thêm
- **Đúng chỗ**: FP bị drop ở R1 trước khi tốn R2 calls
- **Không ảnh hưởng TP**: real bugs luôn có concrete attack path

**Giới hạn:** R1 fix chỉ giải quyết FP do ATTACK_PATH vague. Vẫn còn FP lọt qua nếu agent
viết ATTACK_PATH trông có vẻ đúng format nhưng nội dung sai. R2 cần mechanism riêng để lọc.

---

## 6. R2 Mechanism — Adversarial Framing

### 6.1 Vấn Đề Với Framing Hiện Tại

Câu hỏi R2 hiện tại: *"Bạn có verify được vulnerability này không?"*

Khi agent uncertain → mặc định **ACCEPT** (không có cost để không làm gì).
Agent thấy snippet thật + description nghe hợp lý → ACCEPT mà không cần prove exploitability.
Kết quả: 108/108 findings pass (100% pass rate sau khi fix FP check).

### 6.2 Đảo Framing Sang Adversarial

Thay vì hỏi "tìm lý do để ACCEPT", hỏi:

> *"Hãy tìm lý do CỤ THỂ để REJECT finding này. Nếu không tìm được → ACCEPT."*

**Output format — REJECT phải có COUNTER_TYPE:**

```
VERDICT: ACCEPT | REJECT

[nếu REJECT]
COUNTER_TYPE: PHANTOM | ACCESS_BLOCKED | NO_STATE_CHANGE | NO_IMPACT
COUNTER: <one sentence with specific code element — function name, modifier, or state variable>

[nếu ACCEPT]
COUNTER: No specific counter-argument found
```

**Bốn loại REJECT hợp lệ (COUNTER_TYPE):**
- `PHANTOM` — snippet hoặc function không tồn tại tại location đã claim trong source
- `ACCESS_BLOCKED` — function/path yêu cầu role/modifier mà attack vector không có (e.g., `onlyOwner`, `msg.sender == owner`)
- `NO_STATE_CHANGE` — operation là read-only/view, không mutate state variable nào
- `NO_IMPACT` — outcome mô tả không reachable (e.g., fund transfer không tồn tại trong execution path)

**Không đủ để REJECT — sẽ bị treat là neutral:**
> `"I don't think it's valid"`, `"Uncertain"`, `"Cannot fully verify"`, `"This seems incorrect"` → **không có COUNTER_TYPE cụ thể → không được đếm vào scoring**

Khi uncertain → **ACCEPT**. Gánh nặng chứng minh thuộc về bên REJECT.

### 6.2.1 Enforcement: Lazy REJECT = Neutral

**Vấn đề:** Agent có thể viết REJECT với lý do chung chung để tránh phải ACCEPT — tương tự lazy ACCEPT ở phiên bản cũ, nhưng ngược chiều.

**Giải pháp:** Lazy REJECT không được đếm vào scoring (treated as neutral — không giúp cũng không hại finding). Chỉ **valid REJECT** (có đủ COUNTER_TYPE + COUNTER ≥ 20 chars) mới được đếm.

```python
def _is_valid_reject(vote: dict) -> bool:
    """REJECT chỉ valid nếu có COUNTER_TYPE thuộc 4 loại + COUNTER đủ dài."""
    valid_types = {"PHANTOM", "ACCESS_BLOCKED", "NO_STATE_CHANGE", "NO_IMPACT"}
    counter_type = vote.get("counter_type", "").strip().upper()
    counter      = vote.get("counter", "").strip()
    return counter_type in valid_types and len(counter) >= 20
```

**Tác dụng của lazy REJECT = neutral:**
- Agent viết lazy REJECT → vote không được đếm → score finding đi lên nhẹ
- Agent vô tình *giúp* finding mà họ muốn kill → disincentive mạnh hơn
- Không có middle ground an toàn: phải ACCEPT thật hoặc REJECT với code reference cụ thể

### 6.3 Tại Sao Khác Default REJECT

| | Default REJECT | Adversarial Framing |
|---|---|---|
| Uncertain → | REJECT | ACCEPT |
| Non-domain agent gặp complex DeFi bug → | REJECT | ACCEPT (cannot find specific reason) |
| Non-domain agent gặp FP read-only snippet → | REJECT | **REJECT** (can find "no state mutation") |
| Domain agent gặp TP → | ACCEPT | ACCEPT (tries, fails to find counter-arg) |

Non-domain agents vẫn có thể REJECT FP bằng structural reasoning: "read-only", "protected by
modifier", "no fund path". Nhưng không thể REJECT TP phức tạp nếu không có concrete counter-argument.

**Ví dụ:**

FP `incentives[position.pool]`:
```
VERDICT: REJECT
COUNTER_TYPE: NO_STATE_CHANGE
COUNTER: incentives[pool] is a read-only mapping access — no write path exists,
         no state variable is mutated, funds cannot be drained.
```
→ Không cần hiểu AMM để nhận ra "read-only = không exploit được"

TP `burn()` wrong reserve:
```
VERDICT: ACCEPT
COUNTER: No specific counter-argument found. Searched for any path where reserve0
         is correctly decremented by amount0 in burn() — none exists.
```

Lazy REJECT (bị treat là neutral):
```
VERDICT: REJECT
COUNTER_TYPE: (bỏ trống)
COUNTER: I don't think this is a real vulnerability.
```
→ `_is_valid_reject()` → False → không đếm vào denominator → score đi lên → finding dễ pass hơn → agent tự hại mình

### 6.4 Phase 2 Vẫn Có Giá Trị

Nếu 5 agents tìm được counter-argument "read-only" và share trong Phase 2 (evidence reveal),
3 agents đã ACCEPT (không tự tìm được) có thể update sang REJECT sau khi thấy lý do.
Đây là genuine new information — không phải echo chamber.

---

## 7. R2 Scoring — Điều Chỉnh

### 7.1 Ba Điểm Yếu Cần Điều Chỉnh Sau Adversarial Framing

**1. Threshold 0.35 không phản ánh đúng bar cao hơn:**
Mỗi ACCEPT vote giờ mang ý nghĩa "đã thử reject và không làm được" — signal mạnh hơn
"sounds plausible". Cần raise threshold để phản ánh.

**2. High-k findings có thể pass với r quá nhỏ:**
```
k=5 agents submit cùng finding
score = (5+r)/19 ≥ 0.35  →  chỉ cần r ≥ 2 từ 14 eligible (14%)
```
2 agents tình cờ không tìm được counter-argument → FP pass.

**3. Lazy REJECT làm nhiễu denominator:**
Công thức cũ `(k+r)/n_agents` tính r = ACCEPT, còn REJECT chỉ là "không ACCEPT".
Lazy REJECT hiện tại vẫn làm giảm denominator effective → ảnh hưởng score không đúng.
Cần tách valid REJECT khỏi lazy REJECT trong scoring.

### 7.2 Đề Xuất: Formula Mới + Raise Threshold + Minimum Validation

**Formula mới — chỉ đếm valid REJECT:**

```python
accept       = số ACCEPT votes từ eligible agents
valid_reject = số REJECT votes có COUNTER_TYPE hợp lệ + COUNTER ≥ 20 chars
# lazy_reject không được đếm — không ảnh hưởng score

eligible = accept + valid_reject
score    = (k + accept) / (k + eligible)
```

Thêm 2 điều kiện song song:

```python
# Điều kiện 1: score tổng
score_pass = (k + r) / n_agents >= 0.42      # raise từ 0.35

# Điều kiện 2: minimum community validation
community_pass = r >= 4                       # ít nhất 4 eligible agents ACCEPT

# Pass khi CẢ HAI thỏa mãn
finding_pass = score_pass and community_pass
```

### 7.3 Ảnh Hưởng Lên Các Case (n_agents = 19)

| Scenario | k | Cần r ≥ | Từ eligible | % eligible |
|---|---|---|---|---|
| Specialized TP (k=1) | 1 | max(7, 4) = **7** | 18 | 39% |
| Normal TP (k=3) | 3 | max(5, 4) = **5** | 16 | 31% |
| Widely-found FP (k=5) | 5 | max(3, 4) = **4** | 14 | 29% |
| High-k same-snippet (k=8) | 8 | max(0, 4) = **4** | 11 | 36% |

`r_min` chủ yếu binding ở high-k cases — đây đúng là case cần protect nhất.

Với adversarial framing, getting r ≥ 4 trên FP đòi hỏi 4 agents đều fail to find
"read-only / no state mutation" → rất khó trong thực tế.

---

## 8. Thứ Tự Triển Khai

```
# Phase 1 — R1 Fix
Bước 1: Update build_round1_prompt() — structured ATTACK_PATH format + example
Bước 2: Update parser — thêm _validate_attack_path() vào FP check layer
Bước 3: Chạy contest 35 với STOP_AFTER_R1=true → measure drop rate
Bước 4: Nếu drop rate 10–30% → proceed; nếu TP bị drop → relax has_function requirement

# Phase 2 — R2 Fix (sau khi R1 benchmarked)
Bước 5: Update build_round2_prompt() — adversarial framing + COUNTER_TYPE/COUNTER format
Bước 6: Update parse_round2_vote_from_text() — parse COUNTER_TYPE và COUNTER fields
Bước 7: Add _is_valid_reject() — check COUNTER_TYPE ∈ {PHANTOM|ACCESS_BLOCKED|NO_STATE_CHANGE|NO_IMPACT} + len(COUNTER) ≥ 20
Bước 8: Update _run_voting_round() — scoring formula mới (chỉ đếm valid REJECT) + r_min=4 + threshold=0.42
Bước 9: Full run contest 35 → compare Precision/Recall với baseline

# Rollback nếu cần
# Recall giảm (TP bị kill): lower r_min (4→3) hoặc threshold (0.42→0.40)
# Precision chưa đủ: raise r_min (4→5) hoặc threshold (0.42→0.45)
```
