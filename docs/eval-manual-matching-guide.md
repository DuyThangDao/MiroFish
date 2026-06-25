# Hướng dẫn Manual GT Matching cho Web3Bugs Evaluation

## Mục tiêu

Thay vì dùng LLM judge qua Vertex AI (tốn quota, không ổn định với batch), Claude trực tiếp đọc và so sánh semantic giữa GT bug và findings. Cho kết quả ổn định và không tốn API.

---

## Files cần đọc

| File | Nội dung |
|------|---------|
| `backend/scripts/evaluate/gt/gt_<contest_id>.json` | Ground truth bugs |
| `benchmark/web3bugs/agent-redesign/<id>/<run_dir>/audit_report_35_raw.json` hoặc `audit_report_dedup.json` | Findings cần eval |

---

## Cấu trúc GT bug

```json
{
  "h_id": "H-01",
  "title": "Unsafe cast in ConcentratedLiquidityPool.burn leads to attack",
  "description": "The burn function performs an unsafe cast of amount (uint128) to -int128(amount)...",
  "function_name": "burn",
  "contract_name": "ConcentratedLiquidityPool"
}
```

## Cấu trúc Finding

```json
{
  "title": "Missing Reserve Update for Principal Liquidity in Burn",
  "description": "In the burn function, the contract calculates amount0 and amount1...",
  "attack_path": "...",
  "function_name": "burn",
  "contract_name": "ConcentratedLiquidityPool"
}
```

---

## Quy trình matching từng bước

### Bước 1 — Load data

```python
import json

gt_bugs = json.load(open('backend/scripts/evaluate/gt/gt_35.json'))
report   = json.load(open('benchmark/.../audit_report_35_raw.json'))
findings = report.get('findings') or report.get('consensus_vulns') or []
```

### Bước 2 — Với mỗi GT bug, tìm T1 candidates

**T1** = findings có **cùng function_name VÀ contract_name** (case-insensitive, strip trailing `()`):

```python
gt_fn  = gt['function_name'].lower().rstrip('()')
gt_con = gt['contract_name'].lower()

t1 = [f for f in findings
      if (f.get('function_name') or '').lower().rstrip('()') == gt_fn
      and (f.get('contract_name') or '').lower() == gt_con]
```

### Bước 3 — Với mỗi GT bug, tìm T2 candidates

**T2** = findings **không phải T1** nhưng đề cập GT function **VÀ** GT contract trong `attack_path` hoặc `description`:

```python
t2 = []
for f in findings:
    fn  = (f.get('function_name') or '').lower().rstrip('()')
    con = (f.get('contract_name') or '').lower()
    if fn == gt_fn and con == gt_con:
        continue  # already T1
    text = ((f.get('attack_path') or '') + ' ' + (f.get('description') or '')).lower()
    if gt_fn in text and gt_con in text:
        t2.append(f)
```

### Bước 4 — Semantic matching

Đọc **GT description** và **finding description + attack_path**, so sánh:

**Tiêu chí MATCH (YES):**
- Finding mô tả **cùng root cause** — cùng biến/dòng code bị lỗi, cùng cơ chế exploit
- Cho phép khác tên finding, khác cách diễn đạt
- Finding có thể attribute ở caller function (T2) thay vì library function (T1) — vẫn count nếu mô tả đúng bug

**Tiêu chí NO MATCH:**
- Finding mô tả **triệu chứng khác** — cùng function nhưng khác lỗi (vd: H-01 là unsafe cast, finding khác là missing reserve update — cùng function `burn` nhưng khác bug)
- Finding chỉ đề cập function/contract trong ví dụ, không phải bug chính
- Finding mô tả FP chung chung (vd: "missing access control" cho function không liên quan)

### Bước 5 — Ưu tiên T1 → T2 → T3

- Check T1 hết trước. Nếu có 1 T1 match → DONE, không cần check T2/T3
- Nếu T1 toàn NO → check T2
- Nếu T2 toàn NO → check T3 (xem bên dưới)
- T2/T3 match cũng count là TP, chỉ ghi thêm tier

### Bước 5b — T3: cùng function_name, khác contract_name

**T3** = findings có **cùng `function_name`** với GT nhưng **khác `contract_name`**:

```python
t3 = [f for f in findings
      if (f.get('function_name') or '').lower().rstrip('()') == gt_fn
      and gt_con.lower() not in (f.get('contract_name') or '').lower()]
```

Dùng khi T1=0 và T2=0. Hai pattern T3 bắt được:

| Pattern | Ví dụ |
|---|---|
| **Delegation** | GT ở `CLPosition.burn`, bug surface ở `CLP.burn` (callee) — cùng fn name |
| **Inheritance** | GT attribute `Child.fn`, finding attribute `Parent.fn` nơi fn được define |

**Semantic check thủ công bắt buộc** vì false positive cao — cùng tên function (`burn`) tồn tại ở nhiều contracts, phải đọc description để confirm cùng root cause.

### Bước 6 — Semantic scan từng finding (KHÔNG dùng keyword filter)

**Quan trọng**: Không được filter findings bằng keyword rồi chỉ đọc kết quả lọc. Phải đọc **toàn bộ** T1 candidates và so sánh semantic với GT description.

Workflow:
1. In toàn bộ T1 (title + description + attack_path ngắn gọn)
2. Đọc GT description — xác định **root cause cụ thể** (biến nào, cơ chế nào)
3. Đọc từng finding, hỏi: "Finding này có mô tả cùng root cause không?"
4. Nếu T1 toàn MISS → lặp lại với T2, rồi T3

**Tại sao không dùng keyword?** Ví dụ H-16 (JIT attack): search `jit`, `flash`, `temporal` cho 0 kết quả, nhưng thực ra cần đọc cả 70 T1 findings mới confirm miss — một finding có thể dùng từ "same transaction", "atomic sequence", "front-run mint" mà không có keyword trên.

### Bước 7 — Ghi kết quả

Với mỗi GT bug, output:
```
H-01: NO MATCH
  → T1: 12 candidates — đọc hết, tất cả về reserve/order issues, không có unsafe cast uint128→int128
  → T2: 15 candidates — đọc hết, không tìm thấy
  → T3: 8 candidates (CLPosition.burn) — đọc hết, không có signed negation

H-02: MATCH [T1]
  → finding: "Incorrect Storage Lookup Key in Subscription Logic"
  → reason: "uses positionId instead of incentiveId to look up incentive" — khớp GT
```

---

## Các edge cases quan trọng

### 1. Cùng function, nhiều GT bugs khác nhau
Ví dụ contest 35: H-10 và H-13 đều là `ConcentratedLiquidityPool.burn`, đều về reserve update. GT mô tả từ góc độ khác nhau nhưng có thể match cùng finding. **Cho phép** 1 finding match nhiều GT bugs.

### 2. Library function vs caller function (T2 case)
Ví dụ: H-11 GT ở `Ticks.cross()`, finding ở `ConcentratedLiquidityPool.swap()`. `swap()` gọi `Ticks.cross()` — đây là T2 hợp lệ nếu finding mô tả đúng bug (wrong variable assignment khi zeroForOne=true).

**Kiểm tra:** function trong finding có **gọi** function trong GT không? Nếu có → T2 valid.

### 3. Tên finding misleading
Tên finding không đáng tin cậy, phải đọc description. Ví dụ: "Shared Position Fee Cannibalization" thực ra mô tả recipient attack trong burn → match H-07.

### 4. GT có 0 T1 candidates
Thường xảy ra với library functions (Ticks, DyDxMath, ...) hoặc function tên bị viết khác. Chuyển thẳng sang T2 search. Nếu T2 cũng 0 → confirmed MISS.

### 6. Inheritance attribution mismatch (T1=0 nhưng bug thực sự đã được tìm thấy)
**Tình huống**: GT attribute function cho top-level contract (e.g., `CrossMarginTrading`), nhưng finding attribute cho parent contract nơi function được *định nghĩa* (e.g., `CrossMarginAccounts`). T1=0 vì contract name không khớp, T2=0 vì text không mention GT contract.

**Ví dụ thực tế (contest 3, H-05)**:
- GT: `CrossMarginTrading.belowMaintenanceThreshold`
- Finding: `CrossMarginAccounts.belowMaintenanceThreshold` — mô tả ĐÚNG bug (`>=` thay `<=`)
- Thực tế: hàm được **định nghĩa** tại `CrossMarginAccounts.sol` (internal), kế thừa lên `CrossMarginTrading`
- T1 miss vì `crossmarginaccounts ≠ crossmargintrading`, dù description đúng 100%

**Cách xử lý khi T1=0 và T2=0**:
1. Kiểm tra findings có `function_name` khớp GT nhưng `contract_name` khác không
2. Nếu có → kiểm tra file source: hàm được **định nghĩa** ở contract nào?
   ```bash
   grep -rn "function <fn_name>" /path/to/contracts/ | grep -v "node_modules"
   ```
3. Nếu hàm định nghĩa ở parent contract AND finding attribute đúng parent → **count as TP**
   - Ghi chú trong eval: "MATCH [T1-inheritance] — function defined in parent `ParentContract`, GT attributes to child `ChildContract`"
4. Nếu không tìm thấy finding nào có function name khớp → confirmed MISS

**Phân biệt hai loại miss**:
- `T1=0 vì wrong contract (inheritance)` → kiểm tra source → có thể là TP ẩn
- `T1=0 vì wrong function name` → T2 search → nếu vẫn 0 → MISS

### 7. T3 — Delegation chain (cùng fn name, khác contract)

**Tình huống**: Bug ở contract A gọi sang contract B. GT attribute cho A, finding attribute cho B.
- H-07: GT `CLPosition.burn`, finding `CLP.burn` — mô tả đúng cơ chế recipient forwarding
- T1 miss (wrong contract), T2 catch được (description đề cập cả hai contract)
- **Nếu T2 cũng miss**: check T3 = cùng `function_name`, khác `contract_name`

**Khi nào T3 hợp lệ**: finding mô tả bug xảy ra *qua* delegation chain (A gọi B), không phải bug độc lập ở B.

### 8. Không dùng keyword filter thay cho semantic scan

**Sai**: Grep `jit`, `flash`, `temporal` trong 70 findings → 0 kết quả → kết luận MISS.
**Đúng**: Đọc toàn bộ 70 findings, so sánh từng cái với GT description về JIT mint-claim-burn attack.

Lý do: finding có thể dùng từ khác ("same transaction", "atomic sequence", "front-run mint") mà không có keyword cụ thể. Keyword filter bỏ sót false negative.

### 5. Nhiều findings cùng mô tả một bug
Với 40+ T1 candidates (vd: H-04 mint có 43 candidates), đọc title + description 2-3 dòng đầu của mỗi finding. Không cần đọc attack_path trừ khi description không đủ rõ.

---

## Workflow Claude thực hiện

Khi user yêu cầu eval manual:

1. **Đọc GT file**: `Read backend/scripts/evaluate/gt/gt_<id>.json`
2. **Đọc findings**: `Read benchmark/.../audit_report_*.json`
3. **Script Python** để lấy T1/T2/T3 counts và in toàn bộ candidates:
   ```bash
   python3 -c "
   import json
   bugs = json.load(open('...gt_35.json'))
   findings = json.load(open('...raw.json'))['findings']
   for b in bugs:
       gt_fn = b['function_name'].lower().rstrip('()')
       gt_con = b['contract_name'].lower()
       t1 = [f for f in findings
             if (f.get('function_name') or '').lower().rstrip('()') == gt_fn
             and gt_con in (f.get('contract_name') or '').lower()]
       t2 = [f for f in findings if f not in t1
             and gt_fn in ((f.get('description') or '')+(f.get('attack_path') or '')).lower()
             and gt_con[:10] in ((f.get('description') or '')+(f.get('attack_path') or '')).lower()]
       t3 = [f for f in findings if f not in t1 and f not in t2
             and (f.get('function_name') or '').lower().rstrip('()') == gt_fn]
       print(f\"{b['h_id']} T1:{len(t1)} T2:{len(t2)} T3:{len(t3)} | GT: {b['description'][:80]}\")
       for f in t1:
           print(f\"  T1: {f.get('title','')[:60]} | {(f.get('description') or '')[:100]}\")
   "
   ```
4. **Semantic scan từng finding** — đọc ALL T1 candidates (không filter keyword), so sánh với GT root cause
5. **Nếu T1 toàn MISS** → scan T2 (full), rồi T3 (full)
6. **Output bảng tổng kết** TP/FP/FN + list matched H bugs
7. **Lưu kết quả** vào `benchmark/web3bugs/agent-redesign/<id>/<run_dir>/eval_result_manual.txt`
   - Tên file phải là `eval_result_manual.txt` (không phải `eval_result.txt`)
   - Format: header (Run/Findings file/GT file/Evaluator/Date) → metrics → Matched H bugs (chi tiết finding + reason) → Missed H bugs (chi tiết T1/T2/T3 count + root cause miss) → Notes

---

## Lưu ý về độ chính xác

- **Không dùng batch** — so sánh từng cặp (GT bug, finding) riêng lẻ
- **Ưu tiên description** hơn title
- **Khi uncertain**: đọc thêm `attack_path` và so sánh với GT description chi tiết hơn
- **T2 cần thận trọng hơn T1**: chỉ count khi finding rõ ràng mô tả cùng root cause, không chỉ đề cập function tình cờ

---

## Độ tin cậy so với LLM judge

| Phương pháp | Ổn định | Tốc độ | Chi phí |
|------------|---------|--------|---------|
| LLM judge batch 10 | Thấp (±3 TP) | Nhanh | Vertex quota |
| LLM judge single pair | Trung bình (±1-2 TP) | Chậm | Vertex quota |
| Claude manual | Cao (±0-1 TP) | Trung bình | Không tốn quota |
