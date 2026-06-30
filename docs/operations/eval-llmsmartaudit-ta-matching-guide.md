# Hướng dẫn Manual GT Matching cho LLMSmartAudit TA Output

## Tổng quan

LLMSmartAudit **SmartContractTA** chạy 41 detectors tuần tự, mỗi detector là 1 SimplePhase độc lập hỏi LLM về 1 vulnerability type cố định. Output lưu vào `findings_all.json` (structured) và WareHouse log (raw).

Auto-eval dùng `web3bugs_eval.py` nhưng **có lỗi regex parse function_name** dẫn đến bỏ sót TP. Hướng dẫn này mô tả cách kiểm tra và correct thủ công.

---

## ⚠️ Lỗi Quan Trọng Nhất: Regex parse function_name

### Nguyên nhân

`parse_log()` trong `backend/scripts/run_llmsmartaudit_benchmark.py` extract function_name bằng:

```python
fn_match = re.search(r"`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", description)
function_name = fn_match.group(1) if fn_match else None
```

Regex yêu cầu pattern `` `funcName(`` — backtick mở + tên + dấu `(` ngay sau.

### Khi nào bị miss

Descriptions của TA thường viết dạng `` `claimRewardAsMochi` function... `` (đóng backtick trước, không có paren liền sau). Kết quả: `function_name = None`.

| Description format | Regex match? |
|--------------------|-------------|
| `` `transfer(` `` → extract `transfer` | ✅ |
| `` `transfer` function performs... `` | ❌ → None |
| `` `claimRewardAsMochi` function... `` | ❌ → None |

### Hậu quả

Findings với `function_name = None`:
- **T1 = 0** (eval framework bỏ qua hoàn toàn)
- **T2 = 0 thường** (T2 search text descriptions, nhưng chỉ check nếu T1 > 0 trước)
- → Finding bị miss dù mô tả đúng bug

**Ví dụ thực tế (contest 42, ReferralFeePoolV0):**

```
GT H-03: claimRewardAsMochi — array path[2] out of bounds
GT H-06: claimRewardAsMochi — reward[msg.sender] không reset sau claim

Findings auto-eval T1 = 0 vì:
  "ARRAY OUT-OF-BOUNDS DUE TO INCORRECT FIXED-LENGTH INITIALIZATION"
    → description: "The `claimRewardAsMochi` function initializes..."
    → regex: `` `claimRewardAsMochi` `` (không có `(`) → function_name = None
```

---

## Cấu trúc Output TA

### findings_all.json

```json
{
  "contest_id": "42",
  "contracts": [
    {"contract_name": "MochiVault", "status": "ok", "findings_count": 153},
    {"contract_name": "FeePoolV0",  "status": "ok_partial", "findings_count": 117}
  ],
  "findings": [
    {
      "contract_name": "MochiVault",
      "detector_phase": "ArithmeticDetector",
      "vulnerability_name": "INTEGER OVERFLOW IN BORROW",
      "function_name": "borrow",        ← có thể None nếu regex miss
      "description": "The `borrow` function..."
    }
  ]
}
```

### WareHouse Log Format

Mỗi phase tạo 1 vulnerability block nếu tìm thấy bug:

```
execute SimplePhase:[PriceManipulationDetector] ...

VULNERABILITY NAME
SANDWICH ATTACK / SLIPPAGE MANIPULATION IN DISTRIBUTEMOCHI
'''
DETAILED DESCRIPTION of the vulnerability...
The `distributeMochi` function performs a Uniswap swap without slippage protection...
'''

<INFO> SANDWICH ATTACK / SLIPPAGE MANIPULATION IN DISTRIBUTEMOCHI Identified.
```

Nếu không tìm thấy: `<INFO> NO Sandwich Attack / Slippage Manipulation.`

---

## Bước 1 — Chạy Auto-eval

```bash
# Convert findings_all.json sang eval format
python3 -c "
import json
data = json.load(open('benchmark/web3bugs/llmsmartaudit-ta/<id>/findings_all.json'))
findings = []
for f in data['findings']:
    findings.append({
        'title': f.get('vulnerability_name', ''),
        'description': f.get('description', ''),
        'attack_path': '',
        'contract_name': f.get('contract_name', ''),
        'function_name': f.get('function_name', ''),
        'severity': 'high',
    })
json.dump({'findings': findings}, open('/tmp/ta_report_eval.json','w'), indent=2)
print(len(findings), 'findings')
"

cd backend/scripts/evaluate && source ../../.venv/bin/activate
python3 web3bugs_eval.py gt/gt_<id>.json /tmp/ta_report_eval.json --verbose \
  | tee ../../benchmark/web3bugs/llmsmartaudit-ta/<id>/eval_result.txt
```

---

## Bước 2 — Xác Định Findings bị Miss do Regex

Với mỗi GT bug bị auto-eval báo `no match`, kiểm tra:

```python
import json
data = json.load(open('benchmark/web3bugs/llmsmartaudit-ta/<id>/findings_all.json'))
findings = data['findings']

gt_contract = 'ReferralFeePoolV0'   # contract của GT bug cần check
gt_fn       = 'claimRewardAsMochi'  # function của GT bug

# Tìm findings cùng contract, function_name = None
candidates = [f for f in findings
              if f['contract_name'].lower() == gt_contract.lower()
              and f['function_name'] is None]

for f in candidates:
    # Check nếu description nhắc đến GT function
    if gt_fn.lower() in f['description'].lower():
        print(f['vulnerability_name'])
        print(f['description'][:300])
        print()
```

Nếu tìm được finding: **đây là T1 miss do regex** — ghi nhận thủ công.

---

## Bước 3 — Semantic Match

Với mỗi candidate tìm được, đọc đầy đủ description và hỏi 3 câu:

```
□ 1. Root cause match?
      Finding mô tả đúng cùng mechanism với GT (không chỉ consequence)?

□ 2. Location match?
      Description đề cập đúng function/contract được mentioned explicitly?

□ 3. Explicit?
      Description mô tả rõ bug mechanism (không chỉ tên function trong noise)?
```

Cả 3 YES → **MATCH (T1 manual)**. Bất kỳ NO → no match.

### Ví dụ MATCH

```
GT H-03: claimRewardAsMochi — path array length 2 nhưng gán path[2] → OOB

Finding: "ARRAY OUT-OF-BOUNDS DUE TO INCORRECT FIXED-LENGTH INITIALIZATION"
  "The `claimRewardAsMochi` function initializes a memory-based dynamic array
   `path` with a fixed length of 2 (`new address[](2)`). However, the function
   logic attempts to define a three-token swap route (USDM → WETH → MOCHI) by
   assigning values to `path[0]`, `path[1]`, and `path[2]`."

□ Root cause: path[2] OOB → YES
□ Location: claimRewardAsMochi explicit → YES
□ Explicit: mô tả rõ array size 2 vs assignment path[2] → YES
→ MATCH ✓
```

### Ví dụ NO MATCH

```
GT H-11: _shareMochi — treasuryShare reset sai về 0

Finding: "INTEGER UNDERFLOW IN RATIO CALCULATION"
  "_shareMochi sets mochiShare and treasuryShare to 0; if ratio inputs
   không có validation → underflow khi tính toán."

□ Root cause: GT = treasuryShare bị reset không đúng lúc;
              Finding = underflow do thiếu validation → KHÁC
→ NO MATCH ✗
```

---

## Bước 4 — Lưu Kết Quả

Append vào cuối `eval_result.txt`:

```
=== Manual Correction (YYYY-MM-DD) ===
Lý do correction: parse_log() regex miss function_name khi descriptions dùng
  `funcName` format (không có dấu `(` ngay sau backtick).

H-XX [T1 thực tế]: "<VULNERABILITY_NAME>"
  Descriptions mô tả đúng <fn>: <root cause ngắn>.

=== Corrected Results ===
TP=N  FP=M  FN=K
Precision=X  Recall=Y  F1=Z

Matched H bugs:
  H-XX [T1 manual] ← finding '<VULNERABILITY_NAME>'
  H-YY [T1]        ← finding '...'
  ...
```

---

## Checklist Nhanh

```
□ Chạy auto-eval trước để có baseline
□ Với mỗi GT bug "no match":
    □ Tìm findings cùng contract, function_name = None
    □ Check description có chứa GT function name không
    □ Nếu có: đọc full description + 3-câu checklist
    □ Nếu MATCH → ghi nhận T1 manual
□ Append manual correction vào eval_result.txt
□ Tính lại TP/Recall
```

---

## Điểm Khác Biệt so với Các Tool Khác

| Khía cạnh | TA | BA | MECAP |
|-----------|----|----|-------|
| Output format | Structured JSON | Free-form markdown | Structured JSON |
| Auto-eval | `web3bugs_eval.py` | Manual | `web3bugs_eval.py` |
| Lỗi chính | Regex function_name miss | Keyword false positive | Ít lỗi |
| Cross-contract | Không (per-file) | Không (per-file) | Có (T2 caller-callee) |
| Dedup cần? | Không (mỗi detector 1 lần) | Có (conversation repeats) | Không (đã dedup) |
| 41 detectors | Tất cả chạy tuần tự | — | — |
| Partial run | Có thể bị timeout | — | Không |

---

## Xử Lý Partial Run

Khi 1 contract bị timeout (chạy X/41 phases):

1. Kiểm tra 4 phases thiếu là gì (so sánh với MochiVault log đủ 41 phases)
2. Đối chiếu với GT bugs của contract đó: phases thiếu có liên quan không?
3. Nếu không liên quan → dùng partial log, ghi rõ trong eval_result
4. Merge partial findings vào findings_all.json:

```python
import re, json
from pathlib import Path

_VULN_BLOCK_RE = re.compile(
    r'([A-Z][A-Z 0-9_\-/()+]+)\s*\n\s*\'\'\'\s*\n(.*?)\n\s*\'\'\'',
    re.DOTALL,
)
_INFO_FOUND_RE = re.compile(
    r'<INFO>\s*(.+?(?:Identified|Found|Detected|Vulnerability|Vulnerable)[^<\n]*)',
    re.IGNORECASE,
)
_PHASE_RE = re.compile(r'execute SimplePhase:\[(\w+)\]')

def parse_log(log_path, contract_name):
    text = Path(log_path).read_text(encoding='utf-8', errors='replace')
    phase_positions = [(m.start(), m.group(1)) for m in _PHASE_RE.finditer(text)]
    segments = []
    for i, (pos, phase_name) in enumerate(phase_positions):
        end = phase_positions[i+1][0] if i+1 < len(phase_positions) else len(text)
        segments.append((phase_name, text[pos:end]))
    findings = []
    for phase_name, segment in segments:
        if not _INFO_FOUND_RE.search(segment):
            continue
        for m in _VULN_BLOCK_RE.finditer(segment):
            vuln_name = m.group(1).strip()
            description = m.group(2).strip()
            fn_match = re.search(r'`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', description)
            function_name = fn_match.group(1) if fn_match else None
            findings.append({
                'contract_name': contract_name,
                'detector_phase': phase_name,
                'vulnerability_name': vuln_name,
                'function_name': function_name,
                'description': description[:600],
            })
    return findings
```
