# Hướng dẫn Manual GT Matching cho LLMSmartAudit BA Output

## Tổng quan

LLMSmartAudit **SmartContractBA** tạo ra **markdown free-form text** thay vì structured JSON.
Cần quy trình eval khác với `eval-manual-matching-guide.md` (dùng cho audit JSON output).

---

## ⚠️ Cảnh báo quan trọng nhất: Keyword matching SAI

**KHÔNG ĐƯỢC** tìm kiếm keyword trong toàn bộ log file và kết luận "found = matched."

### Tại sao keyword matching sai?

Log file của LLMSmartAudit BA chứa nhiều loại nội dung khác nhau:

| Loại nội dung | Chiếm % log | Nguy hiểm? |
|---------------|------------|-----------|
| Source code của contract (paste vào prompt) | ~60-70% | ⚠️ Cao — tên function, biến xuất hiện ở đây |
| System prompts, role descriptions | ~10% | ⚠️ Trung bình |
| Model metadata (`GEMINI_FLASH_PREVIEW`) | ~5% | ⚠️ "flash" keyword |
| Conversation history (lặp lại qua rounds) | ~10% | ⚠️ Cùng finding lặp lại N lần |
| **Actual vulnerability findings** | **~10-15%** | ✓ Phần cần đọc |

**Ví dụ thực tế (contest 35):**
- Keyword search trên toàn log → **16/17 = 0.94** (FALSE)
- Semantic eval sau khi đọc descriptions thực sự → **5/17 = 0.29** (ĐÚNG)

---

## Cấu trúc Log File BA

```
1. [Metadata tables — JSON-like tables với |**key**| value|]
2. [Source code contract (paste đầy đủ vào prompt)]
3. [Conversation Round 1: ContractAnalysis]
   CEO ↔ Security Analyst
4. [Conversation Round 2-4: CodeReview (3 cycles)]
   Security Analyst → finds bugs
   → ContractReviewComment: list findings
   → BugsSummary: summary
5. [Conversation Round 5: TestBugsSummary]
   Security Testing Engineer → test scenarios
6. [Kết quả cuối]
```

---

## Bước 1 — Trích xuất Findings Thực Sự

### Pattern nhận biết vulnerability findings:

```
### 1. <Vulnerability Title>
<description of root cause>
**Issue:** ...
**Impact:** ...
```

Hoặc:
```
DETAILED DESCRIPTION:
In the `function_name()` function, <specific bug description>
```

### Các format finding BA sử dụng

BA dùng nhiều format, tất cả đều cần extract:

```
# Format 1: Numbered heading (phổ biến nhất)
### 1. Critical Accounting Bug in `burn()`

# Format 2: Bold numbered (trong Summary sections)
1. **Critical Arithmetic Revert (Solidity 0.8+):** The fee calculation...

# Format 3: Sub-heading
#### A. Critical Logic Flaw: Parity-Based Liquidity Tracking

# Format 4: Plain paragraph (ít phổ biến)
The contract's `burn` function contains a critical accounting error...
```

### Script Python trích xuất (cover all formats):

```python
import re

def extract_ba_findings(log_path):
    """Extract unique vulnerability sections from a BA log file."""
    with open(log_path) as f:
        text = f.read()
    
    findings = []
    
    # Format 1: ### N. Title sections (most common)
    sections = re.findall(
        r'###\s+\d+\.\s+(.+?)(?=###\s+\d+\.|$)',
        text,
        re.DOTALL
    )
    findings.extend(sections)
    
    # Format 2: Bold numbered **N. Title** inside summary sections
    bold_items = re.findall(
        r'\d+\.\s+\*\*([^*]+)\*\*[:\s]+(.{50,500}?)(?=\d+\.\s+\*\*|\Z)',
        text,
        re.DOTALL
    )
    findings.extend([f"{t}: {d}" for t, d in bold_items])
    
    # Deduplicate (log repeats content across rounds)
    seen = set()
    unique = []
    for s in findings:
        key = s.strip()[:100]
        if key not in seen:
            seen.add(key)
            unique.append(s.strip())
    
    return unique

# Usage
findings = extract_ba_findings('ConcentratedLiquidityPool.log')
for i, f in enumerate(findings):
    title = f.split('\n')[0][:80]
    desc = ' '.join(f.split('\n')[1:3])[:200]
    print(f'[{i+1}] {title}')
    print(f'     {desc}')
```

### Dấu hiệu KHÔNG phải findings (bỏ qua):

```
| **task_prompt** | ...  ← metadata table
| **model_type** | ...  ← metadata table
pragma solidity >=0.8.0;  ← source code
contract ConcentratedLiquidityPool is IPool {  ← source code
As the Security Analyst, our primary objective...  ← system prompt
```

---

## Bước 2 — Đọc Finding Descriptions

Với mỗi unique finding, đọc **đủ cả description**, không chỉ title:

```
### 1. Critical Accounting Bug in `burn()`
In the `burn` function, the contract calculates the principal amounts
(`amount0`, `amount1`)... It then updates reserves:
  reserve0 -= uint128(amount0fees);  // BUG: Should be amount0
The reserve trackers are only decremented by the fees, but
_transferBothTokens sends out the total (principal + fees).
```

→ Đọc xong biết ngay: đây là H-10/H-13 của contest 35 (reserve accounting).

---

## Bước 3 — Semantic Matching

### Tiêu chí MATCH (cả 3 phải đúng):

1. **Cùng buggy code location**: Finding explicitly mentions function/line/variable bị lỗi
2. **Cùng root cause**: Mechanism mô tả đúng — không chỉ consequence
3. **Explicit description**: Finding HAS TO explicitly describe the bug, không chỉ mention trong code snippet

### Tiêu chí NO MATCH:

- Finding mô tả **generic issue** nhưng GT bug là specific attack vector
  - Ví dụ: "uint128 overflow possible" vs GT "amount = 2^128-1 → -int128 = -1"
- Từ khóa xuất hiện **trong source code** embedded trong log, không trong finding
- Finding mô tả **khác bug** dù cùng function
  - Ví dụ: "CEI violation" vs GT "arithmetic underflow"
- Keyword từ **model name** "GEMINI_FLASH_PREVIEW" → "flash" ≠ JIT attack

### Checklist 3 câu hỏi:

```
□ 1. Root cause match? Finding mô tả cùng mechanism với GT?
□ 2. Location match? Đúng function/contract được mentioned explicitly?
□ 3. Explicit? Description nói rõ bug (không chỉ tên function trong code snippet)?
```

Nếu bất kỳ câu nào là NO → **NO MATCH**.

---

## Bước 4 — Xử lý Đặc thù BA

### 4a. Findings lặp lại nhiều lần

BA chạy 3 CodeReview cycles → mỗi cycle tạo ra findings, nhiều finding lặp lại.
**Dedup trước khi đếm** — chỉ cần 1 instance để xác nhận MATCH.

### 4b. Không có T1/T2/T3 framework

Pipeline dùng function_name + contract_name để tìm T1 candidates.
BA không có cấu trúc này — findings là free-form text, cần đọc toàn bộ.

### 4c. Severity label ≠ GT severity

BA tự gán severity ("Critical", "High", "Low", "Informational"). **Đừng skip finding vì label nhỏ.**

Ví dụ thực tế (contest 35):
- H-01 (unsafe cast uint128→-int128) = **Critical exploit trong GT**
- BA gán label: **"Informational: Potential for Revert on Large Liquidity Amounts"**

→ Luôn đọc description, không chỉ nhìn severity label.

### 4e. Non-GT contract files

BA chạy mỗi file riêng lẻ → **cross-contract bugs thường bị miss**.

Pattern bị miss:
- Bug xảy ra khi contract A calls contract B với assumption sai về B's behavior
- Bug yêu cầu biết contract C's storage layout
- Bug về interaction giữa nhiều contracts

### 4d. Non-GT contract files — skip hay đọc?

Khi chạy BA trên full contracts_dir (vd: Factory.sol, Helper.sol, TridentNFT.sol ngoài 4 GT contracts), những log này **không cần đọc để match GT bugs**.

Lý do: BA per-file không có cross-contract context. Factory.log sẽ không mention bugs trong ConcentratedLiquidityPool.sol.

**Chỉ cần đọc log của GT contracts** (contract_name khớp với GT `contract_name` field).

### 4f. Source code paste vào prompt

Full source code xuất hiện nhiều lần trong log:
- Lần 1: Trong task_prompt (metadata table)
- Lần 2: Trong conversation messages (truncated)
- Lần N: Trong placeholders/memory sections

**Bất kỳ tên function hay biến nào trong contract đều xuất hiện nhiều lần** trong log
mà không liên quan đến vulnerability finding.

---

## Bước 5 — Workflow Đầy Đủ

```
Với mỗi GT bug (H-01, H-02, ...):

1. Xác định contract_name từ GT
2. Mở {contract_name}.log
3. Chạy extract_ba_findings() → get unique_findings list
4. Đọc từng finding:
   a. Đọc title → có liên quan đến GT function không?
   b. Đọc description đầy đủ (2-3 đoạn)
   c. Hỏi 3 câu checklist
   d. Nếu YES cả 3 → MATCH, ghi lại finding title + snippet
5. Nếu không thấy trong 20-30 unique findings → NO MATCH
   (không có T2/T3 cho BA — cross-contract bugs miss là expected)
```

---

## Bước 6 — Ghi Kết Quả

File: `benchmark/web3bugs/llmsmartaudit/<contest_id>/eval_result_manual.txt`

```
================================================================================
MANUAL EVALUATION — Contest X — LLMSmartAudit BA
================================================================================
Tool    : LLMSmartAudit (SmartContractBA)
Model   : google/gemini-3-flash-preview
Files   : <list of .sol files>
GT file : backend/scripts/evaluate/gt/gt_X.json  (N H bugs)
Evaluator: Claude
Date    : YYYY-MM-DD

METRICS
-------
TP = N   (H-xx, H-xx, ...)
FP = (not enumerated — free-form output)
FN = N   (H-xx, H-xx, ...)
Recall = N/Total

MATCHED H BUGS
--------------
H-xx: MATCH — <contract>.log
  GT  : function/Contract — root cause
  Finding: "<Title> — description snippet showing root cause match"
  Verdict: Why it matches (root cause alignment)

MISSED H BUGS
-------------
H-xx: NO MATCH
  GT  : function/Contract — root cause
  Found: What keywords appeared but why they don't match (source code / wrong context)

NOTES
-----
- Per-file limitation → cross-contract bugs X
- Source code embedding → keyword Y appears in source not in finding
- Model name "GEMINI_FLASH_PREVIEW" → "flash" keyword false positive
```

---

## Lỗi thường gặp

| Lỗi | Hậu quả | Cách tránh |
|-----|---------|-----------|
| Keyword search trên full log | Over-count TP ~3x | Chỉ đọc `### N.` sections |
| `flash` → JIT attack | False positive | Check context: model name vs attack description |
| Function name in code = finding | False positive | Đọc surrounding text |
| Đếm repeated findings nhiều lần | Over-count | Dedup bằng first-100-chars key |
| Generic finding = specific GT | False positive | Root cause phải match, không chỉ function name |
| "Critical arithmetic" = mọi arithmetic bug | False positive | Đọc full description để xác định exact mechanism |

---

## So sánh với eval-manual-matching-guide.md (Audit)

| Khía cạnh | Audit Guide | BA Guide |
|-----------|---------------|---------|
| Output | Structured JSON findings[] | Free-form markdown |
| Search method | T1/T2/T3 framework | Manual section reading |
| Cross-contract | T2 catches caller-callee | Not applicable |
| False positive risk | Thấp | Rất cao (keyword search) |
| Per-contract | Many findings per fn | ~5-30 unique findings per file |
| Dedup needed? | Không | **Có** (conversation repeats) |

---

## Ví dụ Cụ Thể

### FALSE POSITIVE — H-09 (contest 35)

```
GT H-09: rangeFeeGrowth/CLP — subtraction reverts in Solidity 0.8
         because fee growth accumulates via modular arithmetic

Naive keyword search: "rangefeegrowth" + "wrap" → FOUND → MATCH ❌

Reality: "rangefeegrowth" xuất hiện trong function signature trong source code
         "wrap" xuất hiện trong comment "wrapping arithmetic" trong source code
         KHÔNG có finding nào mô tả: "rangeFeeGrowth subtraction reverts
         in Solidity 0.8 because feeGrowthGlobal < feeGrowthBelow + feeGrowthAbove"
```

### TRUE MATCH — H-10 (contest 35)

```
GT H-10: burn/CLP — reserve0 -= amount0fees (fees only)
         but sends amount0 (fees + principal) → reserves inflated

Finding section found:
### 1. Critical Accounting Bug in `burn()`
In the `burn` function...
  reserve0 -= uint128(amount0fees); // BUG: Should be reserve0 -= uint128(amount0)
The reserve trackers are only decremented by the fees, but
_transferBothTokens sends out the total (principal + fees).

Verdict: MATCH ✓
- Root cause: explicit "reserve0 -= amount0fees instead of amount0"
- Location: explicit "burn() function"
- Explicit: description names the exact buggy line
```

### FALSE POSITIVE — H-16 (contest 35)

```
GT H-16: claimReward/Manager — JIT attack: mint just before claimReward
         to inflate secondsPerLiquidity share

Naive search: "flash" keyword → FOUND

Reality: grep -n "flash" Manager.log | grep -v GEMINI_FLASH
         → 0 results. All "flash" matches = "GEMINI_FLASH_PREVIEW" model name.
         
Verdict: NO MATCH ✗
```
