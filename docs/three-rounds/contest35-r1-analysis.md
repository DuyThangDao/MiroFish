# Contest 35 — R1 Recall Analysis

**Ngày phân tích:** 2026-05-07  
**Pipeline version:** v2 (3-round: R1 discovery → dedup → R2 adversarial voting)  
**Kết quả sau anchor dedup:** 54 findings → TP=7, FP=47, FN=10, F1=0.192  
**Kết quả sau R2 adversarial:** 15 findings → TP=1, FP=14, FN=16, F1=0.062 (regression)

---

## Cách chạy Contest 35

### Chạy đầy đủ pipeline (background)
```bash
cd /home/thangdd/repos/MiroFish/backend

LOG=/tmp/web3bugs_35_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
  source .venv/bin/activate
  exec python scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
    --output      ./results/web3bugs_trial/contest_35_<label> \
    --timeout     21600 \
    --verbose
' >> "$LOG" 2>&1 &
echo "PID=$!  LOG=$LOG"
```

### Evaluate kết quả
```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

REPORT=$(ls -t results/web3bugs_trial/contest_35_<label>/*/audit_report.json | head -1)
python scripts/evaluate/web3bugs_eval.py scripts/evaluate/gt/gt_35.json "$REPORT" --verbose
```

### Exit points có sẵn

| Env var | Dừng tại | Output |
|---|---|---|
| `STOP_AFTER_DEDUP=true` | Sau anchor dedup (54 findings) | `/tmp/dedup_findings_35.json` (configurable via `STOP_AFTER_DEDUP_OUT`) |
| `STOP_AFTER_R1=true` | Sau pre-R2 FP check (28 findings) | `/tmp/r1_findings.json` |
| *(không set)* | Full pipeline kể cả R2 | `audit_report.json` trong output dir |

**Ví dụ STOP_AFTER_DEDUP:**
```bash
STOP_AFTER_DEDUP=true \
STOP_AFTER_DEDUP_OUT=/tmp/dedup_findings_35.json \
python scripts/run_contract_audit.py \
  --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
  --output      ./results/web3bugs_trial/contest_35_dedup_eval \
  --timeout     7200 --verbose
```

**Evaluate raw list (output của STOP_AFTER_DEDUP):**
```bash
# eval script tự xử lý cả list lẫn {"findings": [...]}
python scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_35.json /tmp/dedup_findings_35.json --verbose
```

---

## Fluồng dữ liệu thực tế (run dedup_eval 2026-05-07)

```
19 agents × ~7 findings = 131 raw R1 findings
  → 54  sau anchor dedup   (−77 merged by exact anchor + LLM dedup)
  → 28  sau pre-R2 FP check (−26, 48% drop — ATTACK_PATH + CODE_ANCHOR validation)
  → 15  sau R2 adversarial  (−13 rejected)
```

**R1 ceiling:** 7 TP / 17 GT bugs = Recall 0.412 (sau khi bỏ H-15 là broken entry: 7/16 = 43.75%)

### Đường dẫn kết quả mới nhất

| Run | Đường dẫn | Mô tả |
|---|---|---|
| R1 + anchor dedup | `results/web3bugs_trial/contest_35_dedup_eval/35_20260507_104828/` | STOP_AFTER_DEDUP — 54 findings, F1=0.192 |
| Full pipeline R2 adversarial | `results/web3bugs_trial/contest_35_r2adv/35_20260507_093510/` | Pipeline đầy đủ — 15 findings, F1=0.062 |
| Raw dedup findings (JSON) | `/tmp/dedup_findings_35.json` | 54 findings sau anchor dedup, dùng để evaluate R1 ceiling |
| Log dedup run | `/tmp/web3bugs_35_dedup_20260507_104731.log` | Log chi tiết của run dedup_eval |
| Log R2 adversarial run | `/tmp/web3bugs_35_r2adv_20260507_093413.log` | Log chi tiết của run r2adv |

---

## Phần 1: Tại sao 1 bug cover được 2 GT entry?

### Giải thích

Web3Bugs là **competitive auditing contest** — nhiều auditor độc lập tham gia và nộp report riêng. Nếu 2 auditor khác nhau cùng tìm ra 1 bug, **cả 2 đều được credit riêng** trong GT. Contest không merge các submission trùng nhau.

Kết quả: GT dataset có thể chứa nhiều entry mô tả cùng 1 root cause, chỉ khác framing hoặc góc nhìn.

### Các cặp duplicate trong Contest 35

**Cặp 1: H-09 và H-14 (rangeFeeGrowth)**

| | H-09 | H-14 |
|---|---|---|
| Title | rangeFeeGrowth underflow causes pool to become permanently broken | rangeFeeGrowth and secondsPerLiquidity math needs to be unchecked |
| Góc nhìn | Tick crossing chỉ update 1 trong 2 `feeGrowthOutside`, khiến `feeGrowthBelow + feeGrowthAbove` vượt `feeGrowthGlobal` → underflow revert | Uniswap V3 fee growth **intentionally wraps** (modular arithmetic), cần `unchecked` block |
| Root cause | Cùng root: **thiếu `unchecked`** cho fee growth wrap-around |

R1 finding match cả 2: `Arithmetic revert on fee growth wrap-around (SWC-123)`

**Cặp 2: H-10 và H-13 (burn reserves)**

| | H-10 | H-13 |
|---|---|---|
| Title | ConcentratedLiquidityPool.burn() wrong reserve update | Burning does not update reserves correctly |
| Mô tả | `burn()` chỉ trừ `amount0fees` khỏi reserve thay vì toàn bộ `amount0` | `burn()` gửi ra `amount0` nhưng chỉ giảm reserve `amount0fees` |
| Root cause | Cùng root: **không trừ principal** khỏi reserve khi burn |

R1 finding match cả 2: `Reserves Accounting Error - Principal Not Subtracted`

### Hệ quả cho metric

- **Tốt:** 1 R1 finding tốt có thể earn 2 TP — phản ánh đúng thực tế (1 fix close cả 2 report)
- **Cần lưu ý:** F1 bị inflate nhẹ so với bug count thực sự (17 GT entry nhưng thực chất chỉ ~15 bug unique)
- **Khuyến nghị:** Khi so sánh F1 giữa các run, cần nhất quán dùng cùng GT file để không lệch

---

## Phần 2: reclaimIncentive và H-15

### H-03 — reclaimIncentive (stochastic miss)

**Tình trạng:** Function có đầy đủ trong contract summary. Bug rõ ràng: `reclaimIncentive()` không decrement `incentive.rewardsUnclaimed` sau khi transfer → attacker drain liên tục.

| Run | Kết quả |
|---|---|
| `contest_35_r2adv` (2026-05-07 09:35) | **TÌM RA** — TP cho H-03, finding: "Missing reward accounting update in incentive reclaim" |
| `contest_35_dedup_eval` (2026-05-07 10:48) | **BỎ SÓT** — không có finding nào cho reclaimIncentive trong 54 findings |

**Nguyên nhân:** Stochastic — với 19 agents chạy song song, coverage từng function không đảm bảo 100% mỗi run. Bug không bị miss hệ thống, chỉ bị miss ngẫu nhiên lần này.

**Tác động:** H-03 tính vào FN (−1 TP tiềm năng). Không cần fix pipeline, chỉ cần tăng agent count hoặc retry logic.

---

### H-15 — initialize / constructor (GT data issue)

**Tình trạng:** Đây là **broken GT entry** — function không tồn tại trong contract.

**Bug thực tế:** Constructor của `ConcentratedLiquidityPool` nhận `_price` từ `_deployData` nhưng **không validate** `_price ∈ [MIN_SQRT_RATIO, MAX_SQRT_RATIO]`:

```solidity
// ConcentratedLiquidityPool constructor (line 111)
constructor(bytes memory _deployData, IMasterDeployer _masterDeployer) {
    (address _token0, address _token1, uint24 _swapFee, uint160 _price, ...) = abi.decode(...);
    // ...validation cho token0, swapFee...
    price = _price;  // ← KHÔNG validate _price bounds
    // nếu _price = 0 → Ticks.insert() revert → pool permanently broken
}
```

**Vấn đề với GT:**
- `function_name = "initialize"` — **không tồn tại** trong `ConcentratedLiquidityPool.sol`
- Function thực tế là `constructor`
- `grep -rn "function initialize" contracts/35/trident/contracts/pool/concentrated/` → 0 kết quả

**Hệ quả cho eval:**
- Nếu R1 agents tìm ra bug này và label là `constructor` → eval **không match** vì location filter dùng `contract_name + function_name`
- Agents trong cả 2 run không generate finding nào về missing price validation trong constructor
- H-15 là **double miss**: agents không tìm + GT có tên hàm sai

**Khuyến nghị:** Sửa GT file: `"function_name": "constructor"`. Sau đó kiểm tra lại liệu agents có tìm ra không.

**Effective R1 ceiling:** 7/16 = 43.75% (bỏ H-15 khỏi denominator)

---

## Phần 3: Các TP miss — nguyên nhân theo pattern

### Tổng quan

| Status | H-bugs | Count |
|---|---|---|
| TP (R1 tìm đúng) | H-02, H-04, H-09, H-10, H-11, H-13, H-14 | 7 |
| FN — stochastic | H-03 (reclaimIncentive) | 1 |
| FN — GT broken | H-15 (initialize = constructor) | 1 |
| FN — missed bugs | H-01, H-05, H-06, H-07, H-08, H-12, H-16, H-17 | 8 |

### Chi tiết 8 FN — missed bugs

#### Pattern A: Unsafe typecast (H-01, H-05)

R1 agents tìm overflow/accounting bugs nhưng bỏ qua **explicit cast không có bounds check**.

**H-01 — burn() unsafe cast:**
```solidity
// Bug: khi amount = 2^128 - 1
// -int128(amount) được interpret là -(-1) = +1
// → _updatePosition(+1 liquidity) thay vì (-amount)
```
R1 tìm: reserve errors, rounding. **Bỏ sót:** `uint128 → int128` cast với `amount = 2^128-1`.

**H-05 — _getAmountsForLiquidity typecast overflow:**
```solidity
// Bug: getDy/getDx trả uint256, cast về uint128 không check
uint128 amount0 = uint128(DyDxMath.getDx(...));  // overflow nếu > 2^128
```
R1 tìm: "Rounding direction in burn favors user". **Bỏ sót:** cast overflow có thể bị exploit.

---

#### Pattern B: Boundary condition và update ordering (H-08, H-12)

R1 tìm visible overflow bugs, bỏ qua **subtle boundary/ordering conditions**.

**H-08 — mint() wrong inequality:**
```solidity
// Bug: strict < thay vì <=
if (priceLower < currentPrice && currentPrice < priceUpper) {
//                                             ↑ nên là <=
    liquidityGlobal += liquidity;
}
// Khi currentPrice == priceUpper: liquidity không được count → sai
```
R1 tìm: 5 overflow bugs trong mint. **Bỏ sót:** `<` vs `<=` edge case.

**H-12 — mint() secondsPerLiquidity ordering:**
```solidity
// Bug: update secondsPerLiquidity SAU KHI thay đổi liquidity
liquidityGlobal += liquidity;               // ← liquidity thay đổi trước
secondsPerLiquidity += diff / liquidityGlobal; // ← dùng liquidity mới → sai
// Cần update secondsPerLiquidity TRƯỚC khi thay đổi liquidity
```
R1 tìm: 5 overflow bugs. **Bỏ sót:** ordering dependency.

---

#### Pattern C: Economic attack vector (H-16)

R1 tìm code-level bugs, bỏ qua **attack scenario kinh tế**.

**H-16 — claimReward() JIT liquidity attack:**
- `claimReward` distribute tokens theo `secondsPerLiquidity`
- Attacker mint large tight-range position ngay trước khi claim → thu phần lớn reward → burn ngay
- R1 tìm: math errors (max vs min, bit-shift). **Bỏ sót:** JIT economic manipulation.

---

#### Pattern D: Wrong interpretation / different angle (H-06, H-07, H-17)

R1 tìm bug trong đúng function nhưng **sai root cause**.

**H-06 — Position.collect() double yield:**
- GT: `collect()` trước `burn()` → dùng stale `feeGrowthInside` → double counting fees
- R1 tìm: fee entanglement, rounding surplus. **Bỏ sót:** state staleness khi gọi collect trước burn.

**H-07 — Position.burn() fee theft:**
- GT: `burn()` pass external recipient → `pool.burn()` trả toàn bộ fees của tick range → theft
- R1 tìm: "Reentrancy in burn()". **Hoàn toàn sai hướng.**

**H-17 — rangeFeeGrowth() nearestTick:**
- GT: `nearestTick` không phải reference point đúng — có thể point đến uninitialized tick
- R1 tìm: arithmetic revert do thiếu `unchecked` (đây là bug khác, đã match H-09/H-14)
- **Bỏ sót:** logic error về tick reference selection.

---

### Tóm tắt gap và đề xuất cải thiện R1 prompt

| Pattern | Bugs bị miss | Cải thiện đề xuất |
|---|---|---|
| A — Unsafe typecast | H-01, H-05 | Thêm explicit instruction: "check tất cả explicit cast từ uint256/int256 xuống smaller type" |
| B — Boundary/ordering | H-08, H-12 | Thêm: "check strict vs non-strict inequality ở boundary; check state update ordering" |
| C — Economic attack | H-16 | Thêm agent role chuyên economic/game-theory analysis |
| D — Wrong angle | H-06, H-07, H-17 | Khó fix ở prompt level — cần broader function-level analysis coverage |
| Stochastic | H-03 | Tăng agent count hoặc thêm retry cho functions có incentive/reward logic |

**Effective ceiling sau fix:** Nếu fix được Pattern A + B + C → +4 TP → TP=11/16, Recall=0.6875
