# Issue 2: Cross-Type Dedup — Phân Tích & Giải Pháp

> Tài liệu này phân tích tại sao dedup cross-type evidence là bài toán không có lời giải
> tốt nếu chỉ dựa vào output hiện tại, và đề xuất root fix thông qua BUG_ID slug.

---

## 1. Bối Cảnh: Cùng 1 Bug, 4 Evidence Types Khác Nhau

H-10 (`ConcentratedLiquidityPool.burn()` — wrong reserve update) xuất hiện 5 lần trong
top 40 với 4 evidence types:

```
Row 1  CODE:    reserve0 -= uint128(amount0fees)
Row 3  MISSING: reserve0 -= uint128(amount0) AT: burn()
Row 12 SEQ:     burn() sends amount0 → reserve only subtracts fees
Row 14 INV:     after burn(), reserve0 == balance
Row 20 CODE:    reserve0 -= uint128(amount0fees)   ← exact dup của row 1
```

Row 20 được Layer 1B (exact dedup) merge vào Row 1.
Row 3, 12, 14 **không được merge** dù cùng mô tả H-10.

Hệ quả: 4 slots trong top 40 bị chiếm bởi 1 bug → H-03, H-09, H-15, H-17 không có slot.

---

## 2. Tại Sao Cùng 1 Bug Có Nhiều Evidence Types

Đây là thiết kế **có chủ đích**, không phải lỗi agent. Mỗi type tiếp cận bug từ góc độ khác:

| Type | Agent nhìn vào | Với H-10 |
|------|---------------|----------|
| `CODE:` | Dòng code sai | `reserve0 -= uint128(amount0fees)` — sai vì thiếu `amount0` |
| `MISSING:` | Cái cần thêm | `reserve0 -= uint128(amount0)` bị thiếu |
| `SEQ:` | Execution flow | `burn()` transfer `amount0 + fees` nhưng reserve chỉ trừ `fees` |
| `INV:` | Mathematical invariant | `reserve0 == balance` bị vi phạm sau burn |
| `DESIGN:` | Economic mechanism | (không áp dụng cho H-10) |

Tất cả 4 mô tả đều **đúng**. Vấn đề không phải agents sai — mà dedup không nhận ra
4 mô tả đúng này là cùng 1 bug.

---

## 3. Tại Sao Các Signal Dedup Hiện Tại Không Hoạt Động

### Signal A: `(contract, function)` — Quá rộng

```
ConcentratedLiquidityPool.rangeFeeGrowth có 3 bugs khác nhau:
  H-09: feeGrowthInside underflow khi tick crossing
  H-14: missing unchecked block
  H-17: nearestTick initialization invariant

→ Không thể merge tất cả findings trong cùng function
```

### Signal B: Evidence embedding similarity — Quá hẹp

```python
# Evidence 4 findings của H-10 sau khi normalize:
texts = [
    "reserve0 -= uint128(amount0fees)",              # CODE
    "reserve0 -= uint128(amount0) at burn()",        # MISSING
    "burn() sends amount0 reserve only subtracts",   # SEQ
    "after burn() reserve0 == balance",              # INV
]

# Cosine similarity thực tế (all-MiniLM-L6-v2):
sim(CODE, MISSING) ≈ 0.38   # dưới 0.92 → không merge
sim(CODE, SEQ)     ≈ 0.29   # dưới 0.92 → không merge
sim(CODE, INV)     ≈ 0.21   # dưới 0.92 → không merge
sim(MISSING, SEQ)  ≈ 0.55   # dưới 0.92 → không merge
```

**Lý do similarity thấp theo thiết kế:**
CODE mô tả code sai, MISSING mô tả code cần thêm (ngược nghĩa), SEQ mô tả execution
flow, INV mô tả mathematical property — vocabulary hoàn toàn khác nhau dù cùng 1 bug.
Không có threshold nào bắt được cross-type mà không gây false merge.

### Signal C: Title embedding — Không đáng tin

Agents viết title **độc lập**, cùng 1 bug có thể ra:

```
"Incorrect reserve update in burn"              → Agent 1
"burn() uses wrong subtraction for reserve"     → Agent 2
"reserve0 not decremented after liquidity exit" → Agent 3
"Invariant violated: reserve0 != balance"       → Agent 4
```

Agent 4 (INV type) có wording khác hoàn toàn → cosine title thấp dù cùng bug.
Không có đảm bảo về vocabulary convergence.

### Kết Luận

**Không có signal nào trong output hiện tại của agent đủ mạnh để dedup cross-type
một cách đáng tin.** Dedup post-hoc chỉ xử lý được same-type near-dups.

Root fix phải nằm ở **upstream** — thay đổi format output R1 để tạo signal dedup
explicit ngay từ đầu.

---

## 4. Root Fix: BUG_ID Slug

### Thiết kế

Thêm field `BUG_ID` vào R1 output format:

```
BUG_ID: <contract_name>/<function_name>/<3-5-word-kebab-slug>
```

Slug mô tả **bản chất lỗi** (bug), không phải **cách phát hiện** (evidence type).

### Ví dụ cho H-10

```
# Agent 1 (CODE approach):
BUG_ID: ConcentratedLiquidityPool/burn/reserve-subtracts-fees-only

# Agent 2 (MISSING approach):
BUG_ID: ConcentratedLiquidityPool/burn/reserve-subtracts-fees-only

# Agent 3 (SEQ approach):
BUG_ID: ConcentratedLiquidityPool/burn/reserve-subtracts-fees-only

# Agent 4 (INV approach):
BUG_ID: ConcentratedLiquidityPool/burn/reserve-subtracts-fees-only
```

Tất cả hội tụ về cùng slug vì slug mô tả bug, không phải evidence type.

### Ví dụ cho rangeFeeGrowth (3 bugs khác nhau)

```
H-09: ConcentratedLiquidityPool/rangeFeeGrowth/feegrowth-subtraction-underflow
H-14: ConcentratedLiquidityPool/rangeFeeGrowth/missing-unchecked-arithmetic
H-17: ConcentratedLiquidityPool/rangeFeeGrowth/neartick-feegrowth-init-wrong
```

3 slugs khác nhau → 3 findings được giữ riêng ✓

### Dedup logic sau khi có BUG_ID

```python
# Layer 1B (pre-R2): exact dedup bằng BUG_ID thay vì (contract, function, evidence)
def build_dedup_key(finding: dict) -> str:
    bug_id = finding.get("bug_id", "").strip().lower()
    if bug_id:
        return bug_id  # Exact match trên BUG_ID
    # Fallback nếu agent không viết BUG_ID (backward compat)
    contract = finding.get("contract_name", "").strip()
    function = finding.get("function_name", "").strip()
    ev       = normalize_evidence(finding.get("evidence", ""))
    return f"{contract}::{function}::{ev}"
```

Khi nhiều findings có cùng BUG_ID → giữ 1 representative theo priority:
```
CODE > MISSING > SEQ > INV > DESIGN
```

Lý do priority này: CODE evidence có thể verify tự động (snippet tồn tại trong source),
MISSING có thể partial-verify, SEQ/INV/DESIGN cần LLM judge.

---

## 5. Evidence: Giữ Nguyên, Dùng Để Strict

Evidence **không bị bỏ** sau khi có BUG_ID. Evidence có vai trò khác:

### 5.1 Validation gate (pre-R2)

```
CODE:    FP check — snippet phải tồn tại trong source
MISSING: Content check — phần trước AT: phải ≥ 10 ký tự (Issue 6)
SEQ:     Format check — phải có cả SEQ: và THEN: fields
INV:     Format check — phải có VIOLATED_AT: field
DESIGN:  Format check — phải có EXPLOIT: field
```

Findings thiếu evidence hợp lệ → drop ngay tại Layer 1A, không vào R2.
BUG_ID không thể cứu một finding không có evidence.

### 5.2 R2 voting context

Evidence là input quan trọng cho R2 agents khi vote ACCEPT/REJECT:

```
Finding: BUG_ID=burn/reserve-fees-only
Evidence: CODE: reserve0 -= uint128(amount0fees)
```

R2 agent đọc evidence → quyết định finding có hợp lệ không. Evidence càng cụ thể
(CODE snippet thực tế) → R2 agent có thể verify → vote chính xác hơn.

### 5.3 R3 attacker context

Evidence cung cấp attack surface cụ thể cho R3 attacker agent:

```
INV: after burn(), reserve0 == balance
VIOLATED_AT: burn()
COUNTEREXAMPLE: amount0 transferred out but only amount0fees subtracted
```

Attacker dùng counterexample để construct PoC exploit.
Thiếu evidence cụ thể → attacker phải đoán → verdict kém chính xác.

### 5.4 Report readability

Evidence xuất hiện trong final audit report cho người đọc:
- CODE snippet → reviewer biết đích xác dòng nào bị lỗi
- MISSING check → developer biết phải thêm gì
- INV counterexample → auditor biết cách reproduce

### Tóm tắt vai trò sau khi có BUG_ID

```
BUG_ID   → dùng để DEDUP (primary key)
Evidence → dùng để VALIDATE + VOTE + ATTACK + REPORT
```

Hai concerns tách biệt hoàn toàn.

---

## 6. R1 Prompt Changes

```
EVIDENCE field — MANDATORY. Chọn 1 trong 5 formats:
  CODE: <exact snippet from source, max 120 chars>
  MISSING: <what should exist> AT: <Contract.function()>
  SEQ: <fn_a> → <fn_b> via <state_var> | ISSUE: <why wrong>
  INV: <invariant> | VIOLATED_AT: <fn> | COUNTEREXAMPLE: <condition>
  DESIGN: <mechanism> | EXPLOIT: <scenario> | NO_MITIGATION: <what's missing>

BUG_ID field — MANDATORY. Format:
  BUG_ID: <ContractName>/<functionName>/<2-4-word-kebab-slug>

Rules cho slug:
  ✓ Mô tả bản chất lỗi: reserve-subtracts-fees-only, missing-reentrancy-guard
  ✗ Không dùng evidence keywords: missing-code, invariant-violated, sequence-error
  ✓ Nếu bạn phát hiện cùng 1 bug với agent khác, dùng cùng BUG_ID
  ✓ Mỗi bug KHÁC NHAU trong cùng function → slug KHÁC NHAU

Ví dụ đúng:
  BUG_ID: ConcentratedLiquidityPool/burn/reserve-subtracts-fees-only
  BUG_ID: ConcentratedLiquidityPool/rangeFeeGrowth/feegrowth-subtraction-underflow
  BUG_ID: ConcentratedLiquidityPoolManager/claimReward/jit-liquidity-no-lockup
```

---

## 7. Parser Changes

```python
# contract_oasis_env.py — parse_contract_finding_from_text()

def _parse_bug_id_field(raw: str) -> str:
    """
    Parse BUG_ID field. Expected format: Contract/function/slug
    Returns empty string if invalid.
    """
    raw = raw.strip().lower()
    parts = raw.split("/")
    if len(parts) != 3:
        return ""
    contract, function, slug = parts
    # Validate slug: kebab-case, 2-4 words
    words = slug.split("-")
    if not (2 <= len(words) <= 5):
        return ""
    if not all(re.fullmatch(r'[a-z0-9]+', w) for w in words):
        return ""
    return raw  # normalized lowercase

def build_dedup_key(finding: dict) -> str:
    bug_id = finding.get("bug_id", "")
    if bug_id:
        return bug_id
    # Fallback
    contract = finding.get("contract_name", "").strip().lower()
    function = finding.get("function_name", "").strip().lower()
    ev       = _normalize_evidence((finding.get("evidence_snippets") or [""])[0])
    return f"{contract}::{function}::{ev}"
```

---

## 8. Hạn Chế & Giải Pháp Thay Thế

> **Note:** BUG_ID slug có điểm yếu cơ bản: agents hoạt động độc lập →
> không có gì đảm bảo slug converge về cùng string cho cùng bug.
> Giải pháp tốt hơn là **Merger Agent** — xem [`issue2-merger-agent.md`](issue2-merger-agent.md).

## 8. Hạn Chế Còn Lại (của BUG_ID approach)

### 8.1 Agent không convergence

Nếu agents viết slug không nhất quán:
```
Agent 1: burn/reserve-subtracts-fees-only
Agent 2: burn/wrong-reserve-update        ← slug khác
Agent 3: burn/reserve-accounting-error    ← slug khác
```
→ 3 slug → không merge được → vẫn bị duplicate.

**Mitigation:** R2 prompt nhắc agents: "nếu finding mô tả cùng bug với finding đã có
trong danh sách, sử dụng cùng BUG_ID." R2 agents có thể normalize slug.

### 8.2 False merge

Nếu 2 bugs khác nhau nhưng agents đặt cùng slug:
```
Bug A: burn/reserve-fee-error  (H-10: wrong amount)
Bug B: burn/reserve-fee-error  (hypothetical H-X: wrong token)
```
→ Merge nhầm → miss một bug.

**Mitigation:** slug phải đủ specific (2-4 words về bản chất lỗi cụ thể, không generic).
Parser reject slug quá chung như `calculation-error`, `wrong-value`.

### 8.3 BUG_ID thiếu

Agent không viết BUG_ID (format không đúng, bỏ qua) → fallback về key cũ
`(contract, function, evidence)` → chỉ bắt được same-type dups.

**Mitigation:** Parser log warning. Nếu BUG_ID missing rate cao → tăng cường R1 prompt.

---

## 9. Impact Dự Kiến (Contest 35)

| Scenario | Top-40 TPs | Notes |
|----------|-----------|-------|
| Hiện tại (không BUG_ID) | 9/17 | H-10 chiếm 4 slots, 8 bugs miss |
| Với BUG_ID (slug convergence 80%) | ~11/17 | Giải phóng ~4 slots, một số H-bugs được vào |
| Với BUG_ID (slug convergence 95%) | ~12-13/17 | Best case |

BUG_ID giải quyết precision problem (giảm FP slots bị chiếm bởi same-bug duplicates).
Recall problem (8 H-bugs không được discover) cần specialized agents riêng (Issue 4).
