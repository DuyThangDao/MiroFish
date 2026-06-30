# Hướng dẫn Manual Slither Matching cho Web3Bugs Evaluation

## Mục tiêu

Claude đọc Slither filtered findings và GT bugs, so sánh semantic để xác định TP/FP/FN.
Tương tự eval-manual-matching-guide.md nhưng điều chỉnh cho đặc thù Slither output.

---

## Files cần đọc

| File | Nội dung |
|------|---------|
| `backend/scripts/evaluate/gt/gt_<contest_id>.json` | Ground truth H-bugs |
| `benchmark/web3bugs/slither/<contest_id>/slither_findings_filtered.json` | Slither findings đã filter theo GT contracts |

---

## Cấu trúc GT bug

```json
{
  "h_id": "H-01",
  "title": "Unchecked ERC20 return value in transferOut",
  "description": "The transferOut function calls iERC20(_token).transfer(...) without checking...",
  "function_name": "transferOut",
  "contract_name": "Pools"
}
```

## Cấu trúc Slither finding

```json
{
  "check": "unchecked-transfer",
  "impact": "High",
  "confidence": "Medium",
  "title": "[unchecked-transfer] Pools.transferOut",
  "description": "Pools.transferOut(address,address,uint256) ignores return value by iERC20(_token).transfer(_recipient, _amount)",
  "contract_name": "Pools",
  "function_name": "transferOut",
  "source_file": "contracts/Pools.sol",
  "source_lines": [42, 43]
}
```

**Khác biệt quan trọng so với agent findings:**
- `check` là tên detector cố định (pattern-based), không phải phân tích tự do
- `description` được sinh tự động từ template — ngắn, chính xác về code location, nhưng không có reasoning
- Không có `attack_path`
- `impact` là của detector (cố định theo loại pattern), không phải semantic judgment
- Một detector có thể fire nhiều lần tại cùng function cho cùng pattern

---

## Danh sách Slither detectors và patterns hay gặp

| Detector | Impact | Pattern detect được |
|----------|--------|-------------------|
| `unchecked-transfer` | High | ERC20 transfer/transferFrom return value không check |
| `unchecked-lowlevel` | Medium | Low-level call return value không check |
| `tx-origin` | Medium | Dùng `tx.origin` thay `msg.sender` |
| `reentrancy-eth` | High | Reentrancy với ETH |
| `reentrancy-no-eth` | Medium | Reentrancy không ETH |
| `arbitrary-send-eth` | High | Gửi ETH đến address tùy ý |
| `divide-before-multiply` | Medium | Chia trước nhân sau → precision loss |
| `incorrect-equality` | Medium | Dùng `==` với ETH amount (nên dùng `>=`) |
| `uninitialized-state` | High | State variable chưa khởi tạo |
| `controlled-array-length` | High | Array length kiểm soát bởi user |
| `suicidal` | High | Ai cũng có thể selfdestruct contract |
| `weak-prng` | High | Randomness yếu (block.timestamp, blockhash) |
| `shadowing-state` | High | State variable bị shadow bởi local variable |
| `locked-ether` | Medium | Contract nhận ETH nhưng không có hàm withdraw |
| `constant-function-changing-state` | Medium | `view`/`pure` function thay đổi state |
| `tautology` | Medium | Điều kiện luôn đúng/sai |

---

## Quy trình matching

### Bước 1 — Load data

```python
import json

gt_bugs  = json.load(open('backend/scripts/evaluate/gt/gt_<id>.json'))
slither  = json.load(open('benchmark/web3bugs/slither/<id>/slither_findings_filtered.json'))
findings = slither['findings']
```

### Bước 2 — Với mỗi GT bug, tìm T1 candidates

**T1** = findings có **cùng function_name VÀ contract_name** (case-insensitive):

```python
gt_fn  = gt['function_name'].lower().rstrip('()')
gt_con = gt['contract_name'].lower()

t1 = [f for f in findings
      if f['function_name'].lower().rstrip('()') == gt_fn
      and gt_con in f['contract_name'].lower()]
```

### Bước 3 — Với mỗi GT bug, tìm T2 candidates

**T2** = findings không phải T1 nhưng `description` đề cập GT function VÀ GT contract:

```python
t2 = [f for f in findings
      if f not in t1
      and gt_fn in f['description'].lower()
      and gt_con[:6] in f['description'].lower()]
```

*Lưu ý: Slither description ngắn, T2 ít gặp hơn agent findings.*

### Bước 4 — Semantic matching

Đọc GT description và Slither finding description, so sánh:

**Tiêu chí MATCH:**
- Slither detector bắt đúng **code pattern gây ra bug trong GT**
  - Ví dụ: GT = "ERC20 return value not checked" + `check = unchecked-transfer` tại đúng function → MATCH
  - Ví dụ: GT = "wrong formula" + `check = divide-before-multiply` tại đúng function → cần đọc description để xác nhận đây là cùng dòng code
- Finding fire tại **đúng dòng code** là root cause của GT bug (xem `source_lines`)
- Cho phép detector chỉ bắt được **triệu chứng** của bug, không cần bắt được toàn bộ impact

**Tiêu chí NO MATCH:**
- Detector bắt đúng pattern nhưng **tại dòng khác** trong cùng function (cùng check, cùng function, khác code location)
- Detector bắt được **side effect** chứ không phải root cause:
  - Ví dụ: GT là "wrong formula gây underflow", Slither bắt `integer-overflow` ở function đó nhưng tại expression khác → MISS
- GT là business-logic bug hoàn toàn không có pattern static tương ứng (flash loan, governance manipulation, economic attack...)

### Bước 5 — Ưu tiên T1 → T2

- Check T1 hết trước. Nếu có 1 T1 match → DONE
- Nếu T1 toàn MISS → check T2
- **Không có T3** cho Slither: Slither luôn attribute đúng contract nơi code tồn tại — nếu T1=0 thường là MISS thật

### Bước 6 — Script tổng hợp T1/T2

```python
import json

gt_bugs  = json.load(open('backend/scripts/evaluate/gt/gt_<id>.json'))
slither  = json.load(open('benchmark/web3bugs/slither/<id>/slither_findings_filtered.json'))
findings = slither['findings']

for b in gt_bugs:
    gt_fn  = b['function_name'].lower().rstrip('()')
    gt_con = b['contract_name'].lower()
    t1 = [f for f in findings
          if f['function_name'].lower().rstrip('()') == gt_fn
          and gt_con in f['contract_name'].lower()]
    t2 = [f for f in findings if f not in t1
          and gt_fn in f['description'].lower()
          and gt_con[:6] in f['description'].lower()]
    print(f"{b['h_id']} | {b['contract_name']}.{b['function_name']} | T1:{len(t1)} T2:{len(t2)}")
    print(f"  GT: {b['description'][:100]}")
    for f in t1:
        print(f"  T1 [{f['impact']}][{f['check']}]: {f['description'][:100]}")
    print()
```

---

## Đặc thù Slither cần lưu ý khi judge

### 1. Cùng check fire nhiều lần tại cùng function

Slither có thể báo `unchecked-transfer` 3 lần tại `transferOut` vì có 3 lần gọi transfer.
Chỉ cần **1 trong số đó** match GT root cause là đủ MATCH.

### 2. Detector bắt pattern, không phải semantic

`divide-before-multiply` fire khi có phép tính `a / b * c` — nhưng không biết đây có phải bug không.
Cần đọc `description` để xem expression cụ thể và so với GT description.

### 3. Business-logic bugs → Slither luôn MISS

Các bug sau **không có detector** tương ứng, sẽ là FN:
- Flash loan / sandwich attack
- Governance manipulation
- Wrong formula (nếu không có divide-before-multiply)
- Uninitialized mapping key
- Missing access control (trừ khi có `missing-zero-check` hoặc `suicidal`)
- Wrong event emission
- Economic / tokenomics bugs

### 4. `tx-origin` detector bắt được H-bug tx.origin

Nếu GT mô tả "dùng `tx.origin` thay `msg.sender`" → Slither `tx-origin` bắt tại đúng function → MATCH.
Nhưng `tx-origin` sẽ fire ở **tất cả** function dùng `tx.origin` — chỉ count TP cho GT bugs thực sự dùng pattern đó.

### 5. `incorrect-equality` không phải `==` vs `=` typo

Detector này bắt `balance == value` (nên dùng `>=`) — **không phải** typo assignment `status == false` vs `status = false`.
Ví dụ: H-02 contest 71 (== vs = typo trong unlock()) → `incorrect-equality` không bắt được → MISS.

---

## Ghi kết quả

```
H-01: MATCH [T1]
  → check: unchecked-transfer | impact: High
  → description: "Pools.transferOut(...) ignores return value by iERC20(_token).transfer(...)"
  → reason: GT mô tả ERC20 transfer return unchecked tại transferOut — detector bắt đúng pattern tại đúng function

H-07: MISS
  → T1: 4 candidates — check: divide-before-multiply (2), integer-overflow (1), tautology (1)
  → divide-before-multiply tại calcLiquidityUnits dòng 89: `(P * tB) / (2 * T * B)` — KHÁC với GT formula error
  → GT: sai parenthesization `(P*part1 + part2)/part3` — không phải divide-before-multiply
  → Root cause: formula parenthesization error không có Slither detector tương ứng
```

---

## Output file

Lưu vào: `benchmark/web3bugs/slither/<contest_id>/eval_result_manual.txt`

Format header:
```
================================================================================
SLITHER EVALUATION — Contest <id> (<name>)
================================================================================
Run tool:      Slither 0.11.5
Findings file: benchmark/web3bugs/slither/<id>/slither_findings_filtered.json
GT file:       backend/scripts/evaluate/gt/gt_<id>.json
Evaluator:     Claude manual (semantic matching per eval-slither-matching-guide.md)
Date:          <date>

METRICS
-------
Total GT H-bugs : <N>
Total findings  : <N> (all impact levels, GT contracts only)
  High: X | Medium: Y | Low: Z | Informational: W
TP              : <N>
FP              : <N>
FN              : <N>
Precision       : X% (TP / total_findings)
Recall          : X% (TP / GT_bugs)
F1              : X%
```

---

## So sánh với agent findings

| Đặc điểm | Agent findings | Slither findings |
|----------|---------------|-----------------|
| Mô tả | Prose phân tích tự do | Template từ detector |
| Root cause | Thường rõ ràng | Pattern-level, cần verify |
| Business logic | Có thể bắt | Không bắt được |
| FP rate | Cao (nhiều false positive) | Trung bình (pattern có thể fire ở non-bug) |
| T2 chance | Thường xuyên | Hiếm (description ngắn) |
| Kết quả kỳ vọng | Recall cao | Recall thấp (~5-20%) |
