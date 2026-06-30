# GPTScan Benchmark — Manual Eval Guide

## Mục tiêu

Đánh giá GPTScan trên 9 benchmark contests bằng cách so sánh findings với GT H-bugs.  
Metric: **TP / FP / FN / Precision / Recall / F1** (cùng formula với Slither benchmark).

---

## GPTScan khác Slither thế nào

| | Slither | GPTScan |
|---|---|---|
| Phương pháp | Pattern matching trên AST/IR | LLM multi-step reasoning trên source |
| Output | `check` + `description` | `code` (rule name) + `title` |
| Function granularity | Có (detector fires per function) | Có nhưng theo line range |
| Filter contract | Post-processing | Post-processing |
| Rules | ~100 detectors | 10 rule types (xem bên dưới) |

---

## 10 Rule Types của GPTScan

| Rule `code` | Mô tả |
|-------------|-------|
| `price-manipulation` | Flash loan thao túng giá oracle |
| `insecure-buying-behavior` | Flash loan thao túng giao dịch mua |
| `insecure-vote-calculation` | Flash loan thao túng vote |
| `first-deposit` | First depositor attack (share dilution) |
| `unauthorized-transfer` | `transferFrom` với `from` = attacker-controlled |
| `approval-not-clear` | Approval không bị clear sau khi dùng |
| `no-slippage-limit-check` | Không có slippage protection |
| `front-running` | Frontrunnable function |
| `wrong-order-checkpoint` | Checkpoint/reward update sai thứ tự |
| `wrong-order-interest` | Interest calculation sai thứ tự |

---

## Format file findings

File: `benchmark/web3bugs/gptscan/<contest_id>/gptscan_findings_filtered.json`

```json
{
  "contest_id": "71",
  "name": "Insure Protocol",
  "gt_contracts": ["Vault", "PoolTemplate", ...],
  "total_raw": 15,
  "total_findings": 8,
  "by_rule": {"first-deposit": 2, "price-manipulation": 1, ...},
  "findings": [
    {
      "code": "first-deposit",
      "title": "MWE-105: First Deposit Bug",
      "description": "...",
      "contract_name": "PoolTemplate",
      "function_a_file": "/abs/path/PoolTemplate.sol",
      "function_a_start": 807,
      "function_a_end": 840,
      "function_b_file": null,
      "function_b_start": null,
      "function_b_end": null,
      "function_b_contract": null
    }
  ]
}
```

**Lưu ý**: GPTScan không output function name — chỉ có file path + line range.  
→ Cần tìm function name bằng cách tra source code tại line đó.

---

## Matching tiers

### T1 — Function-level match (strong)

Điều kiện:
1. `contract_name` của finding == GT bug's `contract_name` (case-insensitive)
2. Line range `[function_a_start, function_a_end]` **overlap** với function được GT nêu  
   (tra source file tại line đó để xác nhận function name)
3. Rule type liên quan đến root cause của GT bug

**Cách kiểm tra line range overlap:**
```bash
sed -n '<start_line>,<end_line>p' /path/to/Contract.sol | head -5
```

### T2 — Contract-level match (weak)

Điều kiện:
1. `contract_name` của finding == GT bug's `contract_name`
2. Rule type có thể liên quan đến GT bug (theo bảng mapping bên dưới)
3. KHÔNG overlap line range với GT function

T2 **không tính TP** — chỉ ghi nhận là near-miss.

---

## Rule → GT bug mapping heuristic

| Rule | Loại GT bug có thể detect được |
|------|-------------------------------|
| `price-manipulation` | Flash loan giá oracle, giá bị thao túng |
| `first-deposit` | Share dilution, first depositor exploit |
| `unauthorized-transfer` | `transferFrom` với arbitrary `from` address |
| `wrong-order-checkpoint` | Reward/checkpoint update sau khi transfer |
| `wrong-order-interest` | Interest update sai thứ tự |
| `no-slippage-limit-check` | Thiếu slippage guard trong swap |
| `approval-not-clear` | Stale approval sau ERC20 transfer |
| `front-running` | Frontrunnable state changes |
| `insecure-buying-behavior` | Flash loan exploit trong buy flow |
| `insecure-vote-calculation` | Flash loan exploit trong governance |

---

## Định nghĩa TP / FP / FN

**TP**: Finding có T1 match với ít nhất 1 GT H-bug.  
**FP**: `total_findings - TP` (mọi finding không T1-match được GT bug nào).  
**FN**: GT H-bugs không được T1-match bởi bất kỳ finding nào.

```
Precision = TP / (TP + FP) = TP / total_findings
Recall    = TP / (TP + FN) = TP / total_GT_bugs
F1        = 2 * TP / (2 * TP + FP + FN)
```

**Lưu ý đặc biệt GPTScan:**
- Mỗi GT H-bug chỉ tính tối đa **1 TP** dù có nhiều findings overlap.
- Nếu finding có 2 `affectedFiles` (function_a + function_b): contract_name được lấy từ **function_a**. Nếu function_a không trong GT nhưng function_b trong GT → ghi nhận near-miss, không tính TP.

---

## Quy trình eval từng contest

### Bước 1 — Chuẩn bị

```bash
GT_FILE=/home/thangdd/repos/MiroFish/backend/scripts/evaluate/gt/gt_<id>.json
FINDINGS=/home/thangdd/repos/MiroFish/benchmark/web3bugs/gptscan/<id>/gptscan_findings_filtered.json

# Xem GT bugs
cat $GT_FILE | python3 -c "import json,sys; [print(f\"H-{i+1:02d} {b['contract_name']}.{b['function_name']}: {b['title'][:60]}\") for i,b in enumerate(json.load(sys.stdin))]"

# Xem findings theo rule
cat $FINDINGS | python3 -c "import json,sys; d=json.load(sys.stdin); [print(f\"[{f['code']}] {f['contract_name']} L{f['function_a_start']}-{f['function_a_end']}\") for f in d['findings']]"
```

### Bước 2 — T1 matching cho từng GT bug

Với mỗi H-bug (contract_name, function_name):

1. Lọc findings có `contract_name` match → tìm function theo line range
2. Tra source để xác nhận function:
   ```bash
   grep -n "function <name>" /path/to/Contract.sol
   ```
3. Kiểm tra rule type có phù hợp với GT root cause

### Bước 3 — Viết eval_result_manual.txt

Lưu tại `benchmark/web3bugs/gptscan/<contest_id>/eval_result_manual.txt`.  
Format giống Slither eval (xem `benchmark/web3bugs/slither/5/eval_result_manual.txt`).

---

## Template eval_result_manual.txt

```
================================================================================
GPTSCAN EVALUATION — Contest <ID> (<Name>)
================================================================================
Run tool:      GPTScan (falcon-analyzer 0.2.28, Gemini Flash via Vertex AI)
Findings file: benchmark/web3bugs/gptscan/<id>/gptscan_findings_filtered.json
GT file:       backend/scripts/evaluate/gt/gt_<id>.json
Evaluator:     Claude manual (semantic matching per eval-gptscan-matching-guide.md)
Date:          <date>

METRICS
-------
Total GT H-bugs : <N>
Total findings  : <M> (GT contracts only)
  by_rule: <rule: count, ...>
TP              : <X>
FP              : <M - X>
FN              : <N - X>
Precision       : <X/M %>
Recall          : <X/N %>
F1              : <...%>

================================================================================
MATCHED H-BUGS (TP = <X>)
================================================================================

H-<N> | <Contract>.<function> | MATCH [T1]
  GT: <root cause description>
  Finding: [<rule-code>] <contract> L<start>-<end> — "<title>"
  Match reason: <why rule maps to GT root cause>

================================================================================
MISSED H-BUGS (FN = <Y>)
================================================================================

H-<N> | <Contract>.<function> | MISS
  GT: <root cause description>
  T1: <N findings at same contract> — <best candidate rule if any>
  Root cause miss: <why no GPTScan rule covers this>

================================================================================
NOTES
================================================================================
- <summary of what GPTScan found/missed>
- <notable near-misses or false positives>
```

---

## Lưu ý khi eval

### GPTScan có thể bỏ sót vì:
- Compile fail (falcon không resolve được imports) → 0 findings cho contract đó
- Rule coverage hẹp: chỉ 10 patterns, không có reentrancy, access-control, arithmetic bugs
- LLM false negative: model tự đánh giá "no vulnerability" dù có

### Cách check compile fail:
```bash
# Nếu total_raw = 0 và không có error trong run log → có thể compile fail
# Re-run với verbose để xem:
cd /home/thangdd/repos/MiroFish/GPTScan/src
export LLM5_VERTEX_AI_KEY_FILE=...
export LLM5_BASE_URL=...
python main.py -s <contracts_dir> -o /tmp/test.json -k dummy 2>&1 | grep -i "error\|warn\|compil"
```

### GPTScan vs Slither rule overlap:
- `unauthorized-transfer` ↔ Slither `arbitrary-send-erc20`
- `first-deposit` ↔ Slither `divide-before-multiply` (partially)
- `price-manipulation` → NO Slither equivalent (LLM-only)
- `wrong-order-*` → partially covered by Slither `reentrancy-*`
