# Hướng dẫn Manual Dedup Findings

## Mục tiêu

Từ raw report (~300–400 findings), collapse về tập findings riêng biệt (~80–120) bằng cách loại bỏ semantic duplicates — các findings mô tả **cùng root cause** ở cùng đoạn code.

Dedup là bước tiền xử lý **trước eval**. Kết quả lưu vào `audit_report_dedup.json`.

---

## Input / Output

| | File |
|--|------|
| Input | `audit_report_<id>_raw.json` — raw findings từ simulation |
| Output | `audit_report_dedup.json` — deduplicated findings |

---

## Bước 1 — Normalize function name

Agent đôi khi ghi `function_name` theo nhiều format khác nhau cho cùng một function:
- `lock`, `lock()`, `lock(uint256)` → base = `lock`
- `claimRewardAsMochi`, `claimRewardAsMochi()` → base = `claimRewardAsMochi`
- `borrow`, `borrow()`, `borrow(uint256,uint256,bytes)` → base = `borrow`

**Quy tắc normalize**: lấy phần trước dấu `(` đầu tiên, giữ nguyên case.

```python
def normalize_fn(fn: str) -> str:
    return (fn or '').split('(')[0].strip()
```

Sau normalize, group tất cả findings theo `(normalize_fn(fn), contract_name.lower())`.

Script lấy group counts:
```python
import json
from collections import defaultdict

report = json.load(open('audit_report_42_raw.json'))
findings = report.get('findings') or []

groups = defaultdict(list)
for i, f in enumerate(findings):
    key = (normalize_fn(f.get('function_name','')), (f.get('contract_name') or '').lower())
    groups[key].append((i, f))

for key, items in sorted(groups.items(), key=lambda x: -len(x[1])):
    print(f'[{len(items):3d}] {key[0]}/{key[1]}')
```

---

## Bước 2 — Phân loại từng group

Với mỗi group `(fn, contract)`, đọc title + description (2–3 câu đầu) của tất cả findings, phân thành các **root cause cluster**:

### 2a. Single root cause (toàn bộ group mô tả 1 bug)

Ví dụ: `_buyCRV/MochiTreasuryV0` — 13 findings, tất cả đều là sandwich attack vì slippage = 0/1.
→ Giữ 1 finding đại diện tốt nhất (xem Bước 3).

### 2b. Nhiều root cause trong cùng group

Ví dụ: `claimRewardAsMochi/ReferralFeePoolV0` — 14 findings gồm:
- Cluster A: out-of-bounds array access (path[2] on length-2 array) → DoS
- Cluster B: missing state update (reward balance not reset) → infinite drain
- Cluster C: sandwich attack on swap

Mỗi cluster → giữ 1 finding đại diện.

### 2c. FP cluster (nhiều findings mô tả 1 non-bug)

Ví dụ: `utilizationRatio/MochiProfileV0` — 13 findings về division-by-zero khi creditCap = 0.
Nếu đây là FP (creditCap=0 là trạng thái hợp lệ / không exploit được) → **drop toàn bộ cluster**.
Nếu là TP → giữ 1.

**Nguyên tắc phân cluster**: Hai findings là cùng cluster nếu:
- Cùng biến/dòng code bị lỗi (vd: cùng đều về `_burn(msg.sender)`)
- Cùng cơ chế exploit (vd: cùng đều về sandwich với amountOutMin=1)
- Fix của chúng là y hệt nhau

Hai findings là **khác cluster** nếu:
- Khác biến bị lỗi (vd: `debts` vs `debtIndex`)
- Khác cơ chế (vd: reentrancy vs missing state update)
- Fix khác nhau

---

## Bước 3 — Chọn finding đại diện cho mỗi cluster

Trong 1 cluster, chọn finding có:
1. **Description đầy đủ nhất** — mô tả rõ root cause, không chỉ nêu triệu chứng
2. **Attack path cụ thể** — có bước exploit rõ ràng
3. **Không bị noise** — không mix với bug khác trong cùng description

Nếu không có finding nào đủ tốt → giữ finding ngắn gọn nhất, rõ ràng nhất về root cause.

---

## Bước 4 — Check cross-group duplicates

Sau khi collapse từng group, kiểm tra xem có findings từ **các group khác nhau** mô tả cùng 1 bug không.

**Bốn pattern phổ biến:**

### Pattern A: Caller-callee (fn khác, contract khác)

Ví dụ: Bug trong `_shareMochi()` được report cả ở `updateReserve()` (caller) lẫn `_shareMochi()` (callee).

Kiểm tra: Nếu finding A tại `fn1/con1` và finding B tại `fn2/con2` mô tả **cùng đoạn code bị lỗi** (cùng biến, cùng logic) → giữ cái nào mô tả chính xác hơn vị trí lỗi, drop cái còn lại.

### Pattern B: Cùng bug, khác contract (inheritance)

Ví dụ: `lock()` được report ở cả `VestedRewardPool` và một parent contract.

Kiểm tra source để xác định nơi function được định nghĩa → giữ finding attribute đúng contract.

### Pattern C: Misattribution — description contradicts fn/contract metadata

Agent đôi khi ghi nhầm `function_name` hoặc `contract_name` không khớp với nội dung description.

**Dấu hiệu**: Description mở đầu bằng *"In `X()`..."* hoặc *"The `X` function in `ContractY`..."* nhưng metadata lại ghi `fn=Z, contract=W`.

**Ví dụ thực tế (contest 42)**:
- raw[162]: `fn=updateReserve()/MochiVault` — desc nói *"In `flashLoan`, the contract attempts to pull the fee..."* → thực ra là `flashLoan/MochiVault`, duplicate của raw[163]
- raw[161]: `fn=_buyMochi()/MochiVault` — desc nói *"The `_buyMochi` function in `FeePoolV0`..."* → thực ra là `FeePoolV0._buyMochi`, duplicate của raw[3]

**Quy trình check**:
1. Với mỗi **singleton group** trong output: đọc 1–2 câu đầu description, kiểm tra tên function/contract có khớp metadata không.
2. Nếu mismatch → tìm group đúng theo description → nếu đã có representative → **drop**.
3. Nếu group đúng chưa có representative → sửa lại `function_name`/`contract_name` trong finding rồi giữ.

Script check nhanh misattributed singletons:
```python
# In ra singletons nơi description nhắc tên function khác
import re
for f in dedup_findings:
    fn_meta = normalize_fn(f.get('function_name',''))
    desc = (f.get('description') or '')[:300]
    # Tìm "In `X`" hoặc "The `X` function" trong desc
    mentioned = re.findall(r'`([a-zA-Z_][a-zA-Z0-9_]*)\(\)`', desc)
    if mentioned and fn_meta not in mentioned:
        idx = get_raw_idx(f)
        print(f'raw[{idx}] meta={fn_meta} | desc mentions: {mentioned[:3]}')
```

### Pattern D: Cùng vuln type lặp lại trên N functions

Ví dụ: "Unrevoked token allowances" xuất hiện ở `changeUSDM`, `changeMinter`, `changeFeePool`, `changeReferralFeePool` — cùng title, cùng pattern.

**Rule phân loại**:
- Nếu mỗi function cần **fix code riêng biệt** (ví dụ: mỗi `changeX` phải tự revoke allowance của mình) → **giữ riêng** từng finding.
- Nếu toàn bộ pattern có thể fix bằng **1 thay đổi duy nhất** (ví dụ: thêm validation ở base contract) → **collapse còn 1 representative**, ghi note số functions bị ảnh hưởng.

**Heuristic nhanh**: Nếu `fix` cho mỗi instance là thêm code vào **cùng 1 dòng/function** → collapse. Nếu fix phải thêm code ở **N nơi khác nhau** → giữ riêng.

Ví dụ thực tế (contest 42):
- 4× "Unrevoked allowances" (`changeUSDM/changeMinter/changeFeePool/changeReferralFeePool`) → giữ riêng (mỗi fn cần revoke riêng)
- 14× "Missing zero-address" across all `changeX/MochiEngine` → có thể collapse còn 1 (tất cả đều là FP so với GT, pattern identical)

**Scope cross-group check**: Chỉ cần check với các groups **cùng contract** hoặc có **caller-callee relationship** rõ ràng. Không cần check toàn bộ N² pairs.

---

## Bước 5 — Output format

Giữ nguyên JSON structure của finding gốc. File output:

```json
{
  "findings": [
    {
      "title": "...",
      "description": "...",
      "attack_path": "...",
      "function_name": "...",
      "contract_name": "...",
      "_dedup_note": "Representative of 17 findings in _buyMochi/FeePoolV0 (sandwich cluster)"
    },
    ...
  ],
  "_dedup_meta": {
    "raw_count": 359,
    "dedup_count": 101,
    "date": "2026-06-26"
  }
}
```

Thêm field `_dedup_note` để ghi lại số findings đã collapse (optional nhưng useful cho debug).

---

## Workflow tổng thể

```
1. Load raw report
2. Normalize fn_name cho tất cả findings
3. Group by (fn_base, contract)
4. Với mỗi group:
   a. Đọc toàn bộ titles
   b. Phân thành clusters theo root cause
   c. Chọn 1 finding đại diện mỗi cluster
   d. Drop clusters là FP
5. Cross-group check (cùng contract / caller-callee)
6. Write audit_report_dedup.json
```

---

## Checklist từng group

Với mỗi group, điền:

```
[fn/contract]  raw=N
  Cluster 1: <root cause ngắn gọn>  → giữ finding #idx
  Cluster 2: <root cause>           → giữ finding #idx
  Cluster 3: <FP — drop>
  ...
  → dedup: M findings
```

---

## Các lỗi thường gặp

| Lỗi | Hậu quả | Cách tránh |
|-----|---------|-----------|
| Gộp 2 bug khác nhau vì cùng fn | Miss 1 bug trong eval | **Đọc description 2–3 câu đầu của MỌI finding trong group, không chỉ đọc title** |
| Giữ finding kém nhất trong cluster | Eval miss vì description không đủ rõ | Ưu tiên finding có attack_path cụ thể |
| Không check cross-group | Duplicate trong output | Check groups cùng contract sau khi collapse |
| Normalize sai (strip quá nhiều) | Gộp nhầm overloaded functions khác nhau | Dùng split('(')[0] thay vì regex phức tạp |
| Singleton không check misattribution | Duplicate ẩn trong output | Với singleton: đọc câu đầu desc, xem có nhắc fn/contract khác không (Pattern C) |
| Giữ hết N findings cùng pattern across N fns | FP count thổi phồng | Hỏi: "N functions cần N fix riêng không?" — nếu không → collapse (Pattern D) |

### ⚠️ Lỗi hay tái phạm nhất: gộp nhầm vì title nghe giống

Hai case thực tế đã bị miss vì gộp nhầm:

**Contest 61 — lockTokens/AaveYield:**
- raw[185] "Inflation Attack via Direct aToken Donation" → cần attacker donate
- raw[192] "Yield Theft via Liquidity Index Manipulation" → **"even without any external donation"** → natural rebasing tự xảy ra
- Gộp vì cả hai về "aToken balance delta" → miss H-05 (rebasing)

**Contest 71 — compensate/IndexTemplate:**
- raw[314] "Index Solvency Risk — unchecked CDS shortfall" → CDS bên ngoài không cover đủ
- raw[321] "Potential Debt-Credit Mismatch" → **vault.offsetDebt burn sai số attributions** (integer division precision loss)
- Gộp vì cả hai về "compensation không chính xác" → miss H-08 (precision loss)

**Checklist bắt buộc khi cluster:**

Trước khi gộp 2 finding vào cùng cluster, trả lời:
1. **Fix có giống nhau không?** Nếu fix khác nhau → tách cluster.
2. **Cơ chế exploit có giống không?** (external vs internal, attacker-required vs natural)
3. **Biến/dòng code bị lỗi có giống không?**

Nếu bất kỳ câu nào là "không" → **tách thành 2 cluster riêng**.

---

## Ví dụ thực tế — Contest 42

### Group: `borrow/MochiVault` (raw=32)

Đọc titles → 3 clusters:
- **Cluster A** (27 findings): debt accounting mismatch — global `debts` vs individual `details.debt` fee discrepancy
  → Giữ finding có description mô tả rõ `increasingDebt = amount * 1005/1000` vs `debts += amount`
- **Cluster B** (4 findings): oracle price check missing / unvalidated collateral factor
  → Giữ finding về missing CSSR price freshness check
- **Cluster C** (1 finding): unprotected vault initialization
  → Giữ nguyên

→ dedup: 3 findings (từ 32)

### Group: `_buyMochi/FeePoolV0` (raw=17)

Đọc titles → tất cả về sandwich attack / slippage = 0 / amountOutMin hardcoded.
→ 1 cluster, giữ finding mô tả rõ nhất attack path (flash buy Mochi → trigger _buyMochi → sell).
→ dedup: 1 finding (từ 17)

### Group: `claimRewardAsMochi/ReferralFeePoolV0` (raw=14)

Đọc titles → 3 clusters:
- **Cluster A** (10 findings): out-of-bounds `path[2]` on `new address[](2)` → always revert → DoS
- **Cluster B** (3 findings): missing `reward[msg.sender] -= amount` → infinite drain
- **Cluster C** (1 finding): sandwich on swap (có thể FP nếu không exploit được trực tiếp)

→ dedup: 2–3 findings (từ 14)

---

## Script khởi đầu (để Claude chạy)

```python
import json
from collections import defaultdict

def normalize_fn(fn):
    return (fn or '').split('(')[0].strip()

report = json.load(open('audit_report_42_raw.json'))
findings = report.get('findings') or []

groups = defaultdict(list)
for i, f in enumerate(findings):
    key = (normalize_fn(f.get('function_name','')), (f.get('contract_name') or '').lower())
    groups[key].append((i, f))

# Print all groups với titles để Claude đọc
for (fn, con), items in sorted(groups.items(), key=lambda x: -len(x[1])):
    print(f'\n[{len(items)}] {fn}/{con}')
    for idx, f in items:
        print(f'  [{idx}] {f.get("title","")[:80]}')
        print(f'       {(f.get("description") or "")[:100]}')
```
