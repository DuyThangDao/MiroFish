# Known Issues & Proposals — 3-Round Audit Pipeline

> Phân tích từ contest 35 (Trident AMM). Baseline: 17 H-bugs GT.
> Kết quả hiện tại: 9/17 H-bugs hit trong top 40, 27/40 FP, pipeline R3 mất vài giờ.

---

## Issue 1: Parser Bug — Function Name Sai

### Mô tả

Parser `parse_contract_finding_from_text()` đang nhặt **parameter type** hoặc **parameter name**
thay vì tên function thật từ FUNCTION field. Xảy ra khi agent ghi sai format hoặc ghi nhiều
dòng trong FUNCTION field.

### Ví dụ thực tế (contest 35, top 40)

```
concentratedliquiditypoolmanager.bytes
concentratedliquiditypoolmanager.data
concentratedliquiditypoolmanager.positionid
concentratedliquiditypoolmanager.incentiveid
concentratedliquiditypoolmanager.recipient
concentratedliquiditypoolmanager.bool
concentratedliquiditypoolmanager.unwrapbento
```

12/40 findings trong top 40 có function name là garbage → chiếm slot của TP thật.

### Root cause

Agent viết FUNCTION field dạng:
```
FUNCTION: claimReward(uint256 positionId, address recipient, bool unwrapBento)
```
Parser `_parse_function_field()` tách nhầm các token trong parameter list thành function names.

### Đề xuất fix

Trong `_parse_function_field()`: sau khi split, chỉ giữ token đầu tiên (trước dấu `(`),
drop tất cả phần còn lại. Thêm blocklist cho các Solidity keywords/types:
```python
_SOLIDITY_TYPES = {
    "uint256","uint128","uint64","uint32","uint8","int256","int128",
    "address","bool","bytes","bytes32","string","memory","calldata",
    "storage","public","external","internal","private","view","pure",
}
```
Nếu tên function (sau khi strip `()`) nằm trong blocklist → drop finding.

---

## Issue 2: Dedup Không Lọc Hết Same-Bug

### Mô tả

Embedding threshold 0.92 chỉ merge các NL evidence **gần giống nhau về wording**.
Cùng một bug nhưng được mô tả bằng 4 evidence types khác nhau (CODE, MISSING, SEQ, INV)
→ không merge được → nhiều slots bị chiếm bởi cùng 1 bug.

### Ví dụ thực tế (contest 35 — H-10: burn() wrong reserve)

5 findings trong top 40 cùng mô tả H-10:
```
row 1:  CODE:    reserve0 -= uint128(amount0fees)          ← exact snippet
row 3:  MISSING: reserve0 -= uint128(amount0) AT: burn()   ← missing fix
row 12: SEQ:     burn() sends amount0 → reserve only subtracts fees
row 14: INV:     after burn(), reserve0 == balance
row 20: CODE:    reserve0 -= uint128(amount0fees)          ← dup của row 1
```

5 slots dùng cho 1 bug → 4 slots thừa đáng ra nhường cho H-03, H-09, H-15, H-17.

### Root cause

Không có signal nào trong output hiện tại đủ tin cậy để dedup cross-type:

- `(contract, function)` → quá rộng: rangeFeeGrowth có 3 bugs khác nhau (H-09, H-14, H-17)
- Evidence embedding → quá hẹp: cross-type cosine similarity ~0.2-0.5, dưới mọi threshold hợp lý
- Title embedding → không đáng tin: agents viết title độc lập, cùng bug có thể ra wording khác nhau

Dedup post-hoc không có cơ sở vững. Root fix phải nằm ở upstream.

### Đề xuất fix

**Thêm BUG_ID field vào R1 output** — agents tự canonical hóa bug slug:

```
BUG_ID: <ContractName>/<functionName>/<2-4-word-kebab-slug>

Ví dụ:
BUG_ID: ConcentratedLiquidityPool/burn/reserve-subtracts-fees-only
BUG_ID: ConcentratedLiquidityPool/rangeFeeGrowth/feegrowth-subtraction-underflow
```

Dedup key = BUG_ID (exact match). Khi nhiều findings cùng BUG_ID → giữ 1 theo priority:
`CODE > MISSING > SEQ > INV > DESIGN`.

Evidence **không bị bỏ** — chỉ tách vai trò: BUG_ID dùng để dedup, Evidence dùng để
validate + R2 voting + R3 attack context + report.

> Phân tích đầy đủ tại [`docs/three-rounds/issue2-bug-id-dedup.md`](issue2-bug-id-dedup.md)

---

## Issue 3: R2 Accept 100% — Threshold Quá Thấp

### Mô tả

Sau khi fix FP check (Issue đã fix), tất cả 108/108 findings pass R2 voting.
Snippet tồn tại trong source → agents ACCEPT → score ≥ 0.35, nhưng snippet thật ≠ vulnerability.

### Công thức R2 hiện tại

```
k = số R1 agents submit finding này
r = số R2 agents vote ACCEPT
score = (k + r) / n_agents

Threshold = 0.35, n_agents = 22
→ cần k + r ≥ 8 để pass
→ với k=1 submitter + r=7 ACCEPT votes: score = 8/22 = 0.36 → pass
```

### Ví dụ vấn đề

```
CODE: incentives[position.pool]
```
Snippet thật trong source → 22 agents thấy snippet real + description nghe hợp lý → ≥7 ACCEPT → score 0.79 → vào top 40. Nhưng đây chỉ là cách truy cập mapping, không phải bug.

### Đề xuất fix

**Hướng 1 — Tăng threshold R2:**
Nâng `R2_SCORE_THRESHOLD` từ 0.35 → 0.55. Với n_agents=22, cần k+r ≥ 13 → cần đa số agents đồng ý.

**Hướng 2 — Stricter evidence validation trong R2 prompt:**
Yêu cầu agent giải thích cụ thể TẠI SAO evidence này là bug, không chỉ ACCEPT/REJECT.
Parse explanation → nếu quá chung chung → downgrade vote.

**Hướng 3 — CODE: evidence cần thêm vulnerability pattern check:**
FP check hiện tại chỉ verify snippet tồn tại. Thêm check: snippet phải chứa ít nhất 1
vulnerability marker (unsafe cast, missing check, wrong operator, etc.) mới pass.

---

## Issue 4: 8/17 H-bugs Bị Miss Hoàn Toàn

### Mô tả

8 H-bugs không xuất hiện trong bất kỳ finding nào của top 40, agent không discover được.

### Chi tiết từng bug bị miss

| H-bug | Contract.function | Lý do miss |
|-------|------------------|-----------|
| H-03 | Manager.`reclaimIncentive` | Agent nhầm sang `claimReward`, không scan `reclaimIncentive` |
| H-05 | Pool.`_getAmountsForLiquidity` | Internal function có underscore prefix, agent bỏ qua |
| H-06 | Position.`collect` | Cross-contract flow (Position → Pool), agent không trace |
| H-09 | Pool.`rangeFeeGrowth` | Cần hiểu Uniswap V3 wrap-around math để nhận ra |
| H-11 | Ticks.`cross` | `Ticks.sol` là library, có thể bị classify out-of-scope |
| H-14 | Pool.`rangeFeeGrowth` | Same function H-09, miss cùng lý do |
| H-15 | Pool.`initialize` | Missing validation không có code sai → khó detect với CODE: type |
| H-17 | Pool.`rangeFeeGrowth` | Invariant phức tạp liên quan đến nearestTick |

### Đề xuất fix

**Nhóm H-09, H-14, H-17 (rangeFeeGrowth):** Thuộc loại INVARIANT — cần `invariant_verifier`
specialized agent (xem `docs/three-rounds/plan-specialized-agents.md`).

**Nhóm H-06 (collect → burn double-yield):** Thuộc loại SEQUENCE — cần `ordering_analyst`
specialized agent.

**H-05 (_getAmountsForLiquidity):** Internal function. Thêm directive vào R1 prompt:
```
COVERAGE RULE — scan ALL functions including internal/private with _ prefix.
```

**H-03 (reclaimIncentive), H-15 (initialize):** Thuộc loại MISSING — standard agents
với đủ context nên detect được. Vấn đề có thể do Ticks.sol / Manager.sol bị mark
out-of-scope trong flatten. Cần verify scope sau Slither fix.

**H-11 (Ticks.cross):** Verify `Ticks.sol` được include trong flattened source.

---

## Issue 5: R3 Overload

### Mô tả

Mỗi finding chạy tối đa **2 lượt attacker**:
- Lượt 1 (initial): 5 attackers × N findings = 5N calls
- Lượt 2 (update): chỉ INVALID attackers reconsider → thêm tối đa 5N calls

Worst case: 40 × 5 × 2 = **400 calls**. Với rate limiting → mất 3-6 giờ.

### Ví dụ từ run thực tế (contest 35)

```
Run 1 (trước dedup): 123 findings × 5 attackers = 615 initial calls
                   + update pass                 = ~500 thêm
                   → 5,083 rate limit errors, >6 giờ, bị kill
```

### Đề xuất fix (theo thứ tự triển khai)

**Hướng A — Giảm số attackers (3 thay vì 5):**
Điều chỉnh threshold tương ứng. Giảm 40% calls ngay lập tức.
Rủi ro thấp, implement trong 30 phút.

**Hướng B — Score-stratified R3:**
```
R2 score > 0.80 → 1 attacker (fast confirm)
R2 score 0.50–0.80 → 3 attackers
R2 score 0.35–0.50 → 5 attackers hoặc drop
```
Với phân phối score thực tế (nhiều 0.79), hướng này giảm ~60% calls.

**Hướng C — Function-only context:**
Thay vì gửi toàn bộ source (~150KB), chỉ gửi function body + callees từ dep_graph.
Mỗi call nhẹ hơn 10-20x → wall time giảm dù số calls không đổi.

**Hướng D — Evidence fast lane (dài hạn):**
- CODE: evidence đã verified tồn tại → dùng Slither pattern check thay LLM
- Chỉ MISSING/SEQ/INV/DESIGN → cần attacker LLM
- ~55% findings bypass R3 hoàn toàn

**Khuyến nghị kết hợp ngắn hạn:** A + B + C → giảm ~70% wall time mà không thay đổi logic.

---

## Issue 6: MISSING Evidence Thiếu Nội Dung

### Mô tả

Agent viết MISSING evidence nhưng bỏ qua phần quan trọng nhất — **missing cái gì**.
Kết quả là evidence không dedup được và không cung cấp context cho attacker R3.

### Ví dụ thực tế

```
❌ Sai:
MISSING AT: TridentRouter.sweepNativeToken()

✓ Đúng:
MISSING: onlyOwner modifier AT: TridentRouter.sweepNativeToken()
```

```
❌ Sai:
MISSING: input validation AT: ConcentratedLiquidityPool.initialize()

✓ Đúng:
MISSING: require(initialPrice >= MIN_SQRT_RATIO && initialPrice <= MAX_SQRT_RATIO)
         AT: ConcentratedLiquidityPool.initialize()
```

### Hệ quả

- `_has_specific_evidence()`: pass (có prefix `MISSING:`) → không bị drop
- Embedding dedup: 2 findings `MISSING AT: fn()` với function khác nhau có cosine ~0.95 → merge sai
- R3 attacker: thiếu context → verdict không reliable
- Người đọc report: không hiểu bug là gì

### Đề xuất fix

**1. Parser validation:** Sau khi parse MISSING evidence, check content trước `AT:` có ≥ 10 ký tự.
Nếu không → drop finding (cùng level với FP check).

**2. R1 prompt update:** Làm rõ hơn format MISSING trong hướng dẫn:
```
MISSING: <tên check/code cụ thể cần có> AT: <Contract.function()>
  ✓ MISSING: require(amount > 0) AT: Pool.mint()
  ✗ MISSING: input validation AT: Pool.mint()   ← quá chung chung, sẽ bị drop
```

---

## Tóm Tắt Ưu Tiên

| # | Issue | Impact on Recall | Impact on Precision | Độ khó | Ưu tiên |
|---|-------|-----------------|--------------------|----|---------|
| 1 | Parser bug function name | Trung bình | Cao (12/40 garbage) | Thấp | **P0** |
| 3 | R2 accept 100% | Thấp | Cao (27/40 FP) | Trung bình | **P0** |
| 5 | R3 overload | — | — | Trung bình | **P0** |
| 2 | Dedup same-bug | Trung bình | Trung bình | Trung bình | **P1** |
| 4 | 8 H-bugs miss | Cao | — | Cao | **P1** |
| 6 | MISSING evidence thiếu | Thấp | Thấp | Thấp | **P2** |

**P0 (fix trước):** Trực tiếp gây pipeline chạy sai hoặc chậm nghiêm trọng.
**P1 (fix sau P0):** Cải thiện recall/precision đáng kể.
**P2 (cải tiến dài hạn):** Quality of life, không blocking.
