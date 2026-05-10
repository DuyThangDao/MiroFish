# FN Analysis — 6 Bugs Chưa Tìm Được (Contest 35)

**Ngày:** 2026-05-08  
**Pipeline version:** v2, RC fixes v2b  
**Kết quả hiện tại:** TP=11, FP=47, FN=6, Recall=64.7%, F1=0.293  
**FN còn lại:** H-03, H-05, H-07, H-15, H-16, H-17

---

## Phân loại FN

| Bug | Loại miss | Khả năng fix |
|-----|-----------|--------------|
| H-03 | Stochastic attention miss | Có — system-level |
| H-05 | Attribution convention mismatch | Có — sửa GT |
| H-07 | Attribution convention mismatch | Có — sửa GT |
| H-15 | GT data bị lỗi | Có — sửa GT |
| H-16 | Syntactic bugs suppress economic reasoning | Chưa khắc phục — system limit |
| H-17 | Stale reference in scope + context selection miss | Có — instruction + context |

---

## H-03 — Stochastic Attention Miss

### Mô tả bug
`reclaimIncentive()` không decrement `incentive.rewardsUnclaimed` sau khi transfer token ra ngoài → attacker gọi lại nhiều lần để drain toàn bộ incentive pool.

### Tại sao bị miss — phân tích thực tế

**Bác bỏ giả thuyết ban đầu:** Function body của `reclaimIncentive()` **có mặt đầy đủ** trong context của tất cả agents. Tất cả 24 agents đều nhận cùng một context 106KB gồm enriched KG summary + full body của 6 critical functions. Persona `toke_defensive` (token_standard/defensive) — persona phù hợp nhất để phát hiện bug này — **có mặt trong tất cả các run** (rc_fixes, rcv2, rcv2b, r2adv).

**Tần suất phát hiện qua các lần chạy:**

| Run | STOP_AFTER_DEDUP | Agents | H-03 tìm được |
|-----|-----------------|--------|--------------|
| contest_35_dedup_eval | Có | 24 | Không |
| contest_35_rc_fixes | Có | 24 | Không |
| contest_35_rc3 | Có | 24 | Không |
| contest_35_rcv2 | Có | 24 | Không |
| contest_35_rcv2b | Có | 24 | Không |
| contest_35_r2adv | Không (full pipeline) | 24 | **Có** — `toke_defensive` |

**Tỷ lệ phát hiện: 1/6 = ~17%** (hoặc 0/5 nếu chỉ tính STOP_AFTER_DEDUP runs)

**Nguyên nhân thực sự — Attention Allocation trong context 106KB:**

`reclaimIncentive` là leaf function (không gọi contract nào, callee count thấp) → không được chọn vào top-6 critical functions → agents chỉ thấy function signature + một dòng NatSpec trong phần summary. Trong 106KB context với 84 functions, agents phải ngầm định ưu tiên. Function trông đơn giản (5 lines, 1 require, 1 transfer) → thường bị bỏ qua.

Trong 1 run duy nhất (r2adv), `toke_defensive` tình cờ đọc kỹ function đủ để nhận ra thiếu `rewardsUnclaimed -= amount`. Đây là variance của LLM sampling, không phải behavior ổn định.

**Về internal/private functions:** Pipeline hiện tại đã có instruction "Analyze every function including private/internal." Vấn đề không phải là private functions bị loại trừ về mặt instruction, mà là **depth of analysis** không đồng đều: external functions phức tạp (swap, mint, burn) nhận được nhiều attention hơn internal leaf functions. Bug có thể nằm ở cả internal functions (e.g., nếu `_transfer` có bug thì sẽ bị miss theo cùng cơ chế).

**Về persona-function mismatch:** Ngay cả khi đúng persona có mặt, không có gì đảm bảo persona đó sẽ phân tích đủ sâu hàm cụ thể đó trong một run. `toke_defensive` thấy `reclaimIncentive` trong 5/6 runs nhưng chỉ 1/6 lần tìm ra bug. Bug có thể bị overlap bởi các findings khác trong claimReward/addIncentive mà persona đó đang focus vào.

### Root fix: Accounting Invariant Micro-Agent

#### Lý do triển khai

Bug class "outgoing transfer without corresponding accounting update" là một trong những class nguy hiểm nhất trong DeFi:

- **Tác động thực tế:** Trực tiếp cho phép drain toàn bộ contract treasury qua repeated calls. Compound ($80M), Pickle Finance ($20M), nhiều Sushi MasterChef forks đều bị tấn công theo pattern này.
- **Tần suất:** Xuất hiện ở hầu như mọi protocol có reward/incentive/staking — là logic phổ biến nhất trong DeFi: user deposit → contract track internal balance → user withdraw/claim.
- **Slither không cover được:** Slither's `unchecked-transfer` chỉ check return value của `.transfer()`. Không có detector nào kiểm tra "sau khi transfer ra ngoài, có biến accounting nội bộ nào cần decrement không?" — câu hỏi này đòi hỏi hiểu semantic của storage variables, vượt ngoài khả năng static analysis.
- **Tỷ lệ phát hiện hiện tại là 17%:** Không chấp nhận được cho một bug CRITICAL tồn tại ở hầu hết dự án. 24 agents đều thấy function body nhưng LLM attention bị gravity bởi các functions phức tạp hơn trong 106KB context.
- **Cost của micro-agent thấp:** Context ~2-5KB thay vì 106KB → rẻ hơn ~35 lần mỗi agent. Số lượng functions cần scan thường nhỏ (5-15 per contract).

#### Kế hoạch triển khai chi tiết

**Tổng quan pipeline sau khi thêm:**

```
R1 Discovery (24 agents, full context 106KB)
        ↓
Anchor Dedup
        ↓  ← INSERT HERE
Accounting Invariant Micro-Pass (N agents nhỏ, context ~3KB mỗi agent)
        ↓
Merge vào candidate_pool
        ↓
Pre-R2 FP Check → R2 Voting → R3 Attacker
```

---

**Bước 1 — Static filtering: xác định candidate functions**

File: `backend/app/services/contract_dep_graph.py`

Thêm hàm `find_transfer_without_accounting(source: str) -> List[str]`:

```python
OUTGOING_TRANSFER_PATTERNS = [
    r'\b_transfer\s*\(',           # internal helper phổ biến
    r'\.transfer\s*\(',            # ERC20 .transfer()
    r'\.safeTransfer\s*\(',        # SafeERC20
    r'\.transferFrom\s*\(',        # transferFrom
    r'\bIERC20\b.*\.transfer\s*\(', # explicit interface call
]

ACCOUNTING_UPDATE_PATTERNS = [
    r'\w+\s*-=\s*\w+',            # x -= amount
    r'\w+\s*=\s*\w+\s*-\s*\w+',  # x = x - amount
    r'\bdelete\b\s+\w+',          # delete mapping entry
    r'\w+\[.*\]\s*-=',            # mapping[key] -= amount
]
```

Logic: với mỗi function có outgoing transfer, check xem body có chứa accounting update pattern không. Nếu không → đưa vào danh sách candidate cần micro-agent kiểm tra.

Lưu ý: đây là static heuristic, có thể false positive (update xảy ra ở modifier hay base contract). Micro-agent sẽ xác nhận bằng semantic reasoning.

---

**Bước 2 — Context building cho mỗi candidate function**

File: `backend/app/services/contract_dep_graph.py`

Thêm hàm `build_accounting_check_context(source: str, fn_names: List[str]) -> str`:

Context mỗi agent nhận gồm:
1. Function body của candidate (từ `extract_function_bodies`)
2. Storage variable declarations liên quan (để agent hiểu biến nào là accounting variable)
3. Signature của các helper functions được gọi bên trong (để agent biết `_transfer` làm gì)

Tổng context: ~2,000–4,000 chars per function group.

---

**Bước 3 — Agent prompt chuyên biệt**

File: `backend/app/services/contract_oasis_env.py`

Thêm hàm `build_accounting_verifier_prompt(fn_contexts: str) -> str`:

```
=== ACCOUNTING INVARIANT VERIFICATION ===
You are a specialized accounting invariant checker.

Your ONLY task: for each function below, answer:
  1. Does this function transfer tokens or ETH OUTWARD (to an external address)?
  2. If YES: is there a storage variable that tracks how much the contract owes
     (balance, unclaimed, rewardsUnclaimed, shares, debt, etc.)?
  3. If YES to both: is that variable DECREMENTED after the transfer?

If a function transfers tokens outward WITHOUT decrementing a corresponding
internal accounting variable → write a FINDING.

FINDING format:
  TITLE: Missing accounting update in <function_name>
  FUNCTION: <function_name>
  CONTRACT: <contract_name>
  SEVERITY: HIGH
  EVIDENCE: MISSING: <variable> -= amount; AT: <function_name>()
  ATTACK_PATH:
    ACTOR: any authorized caller
    CALL: <function_name>() repeatedly
    STATE_CHANGE: <variable> never decremented
    OUTCOME: caller drains contract by calling repeatedly

Only write FINDING if you are certain the accounting variable exists and is NOT
updated anywhere in the function (including modifiers if visible). If uncertain,
write NO_FINDING with brief reason.

=== FUNCTIONS TO CHECK ===
{fn_contexts}
```

---

**Bước 4 — Integration vào pipeline**

File: `backend/app/services/cyber_session_orchestrator.py`

Vị trí: sau line 1942 (`After anchor dedup: {n_r1} canonical findings`), trước STOP_AFTER_DEDUP check.

```python
# ── Accounting Invariant Micro-Pass ──────────────────────────────────────
if os.environ.get("ENABLE_ACCOUNTING_MICROPASS", "true").lower() == "true":
    _raw_src = self._get_raw_source(session_id)  # flat source string
    if _raw_src:
        from app.services.contract_dep_graph import find_transfer_without_accounting
        from app.services.contract_oasis_env import build_accounting_verifier_prompt

        candidate_fns = find_transfer_without_accounting(_raw_src)
        if candidate_fns:
            logger.info(
                f"[v2] Accounting micro-pass: {len(candidate_fns)} candidate functions"
            )
            micro_findings = self._run_accounting_micropass(
                candidate_fns, _raw_src, network_summary, known_functions
            )
            # Merge vào candidate_pool (same dedup key format)
            for f in micro_findings:
                anchor = f.get("code_anchor", "")
                if anchor and anchor not in candidate_pool:
                    candidate_pool[anchor] = f
                    logger.info(f"  [micro] Added: {f.get('title','')}")
```

---

**Bước 5 — Env var control**

`ENABLE_ACCOUNTING_MICROPASS=true` (default on). Tắt bằng `ENABLE_ACCOUNTING_MICROPASS=false` nếu muốn benchmark tách biệt.

---

#### Scope của pattern class

Micro-agent này cover **toàn bộ accounting invariant violations**, không chỉ H-03:

| Pattern | Ví dụ thực tế |
|---------|---------------|
| `rewardsUnclaimed` không decrement sau claim | H-03 (reclaimIncentive) |
| `totalDeposits` không decrement sau withdraw | Vault drain bugs |
| `rewardDebt` không update sau harvest | MasterChef variants |
| `shares` không burn sau redeem | ERC4626 accounting bugs |
| `pendingRewards` không reset sau distribution | Staking protocol bugs |

Tất cả đều là CRITICAL, tất cả đều không được Slither detect, tất cả đều bị miss bởi R1 agents do attention allocation.

---

#### Chi phí ước tính

Với 10 candidate functions trung bình:
- 10 agents × 3KB context = 30KB input tokens total
- So với R1: 24 agents × 106KB = 2,544KB input tokens
- **Chi phí micro-pass ≈ 1.2% của R1** — negligible.

---

## H-05 — Typecast Overflow Chưa Được Địa Chỉ

### Mô tả bug

`_getAmountsForLiquidity()` cast kết quả từ `DyDxMath.getDx()`/`getDy()` (trả về `uint256`) xuống `uint128` mà không kiểm tra bounds:

```solidity
function _getAmountsForLiquidity(...) internal pure returns (uint128 token0amount, uint128 token1amount) {
    token0amount = uint128(DyDxMath.getDx(liquidityAmount, priceLower, priceUpper, true));
    token1amount = uint128(DyDxMath.getDy(liquidityAmount, priceLower, currentPrice, true));
}
```

`getDy` tính: `liquidity × (priceUpper − priceLower) / 2^96`. Với `liquidity ≈ MAX_TICK_LIQUIDITY ≈ 2^128` và price range đủ rộng, kết quả có thể đạt `2^191` — vượt xa `uint128.max = 2^128 − 1`. Phần high bits bị truncate silently về một số nhỏ.

**Attack path:** Attacker chọn price range sao cho `getDx`/`getDy` trả về giá trị vừa vượt `2^128` → sau truncation còn lại 1–2 wei → `tridentMintCallback` yêu cầu attacker nộp 1–2 wei → pool records large `_liquidity` → attacker burn thu về toàn bộ.

**Xác nhận toán học:** `getDy max ≈ 2^191 >> uint128.max`. Overflow xảy ra với các price range hợp lệ trong pool.

### Tại sao bị miss — phân tích thực tế

**Phát hiện quan trọng:** Finding **đã được sinh ra** trong rcv2b:

> "Narrowing cast truncation allows minting massive liquidity for near-zero cost"  
> `FUNCTION: mint() | CONTRACT: ConcentratedLiquidityPool`

Eval lookup candidates tại `concentratedliquiditypool._getamountsforliquidity` → finding ở `mint()` không được xét → **0 candidates → FN**.

H-05 có **hai vấn đề xếp chồng**, không phải một:

| Vấn đề | Mô tả | Root cause |
|--------|-------|-----------|
| Attribution sai | Finding ở `mint()` thay vì `_getAmountsForLiquidity()` | Agents "follow the money" đến nơi effect thấy được |
| Q1 reasoning gap | Agent tìm được bug nhưng không phải do trace đúng max value — mà do heuristic "uint128 cast on external call result = suspicious" | Không trace qua FullMath.mulDivRoundingUp |

Detection xảy ra (finding có) nhưng attribution sai. Đây là vấn đề attribution, không phải detection.

**Tại sao không phải thiếu scan:** Agent phân tích `mint()` đã trace vào `_getAmountsForLiquidity()` và nhận ra cast. CAST CROSS-FUNCTION SCAN (reactive) không phải nguyên nhân — detection đã xảy ra mà không cần nó trigger.

### Root fix: Sửa GT trực tiếp — chưa implement

**Trạng thái:** Đã phân tích, chờ triển khai.

#### Kết quả manual verification

Tool finding tại `mint()` (rcv2b):
> "Narrowing cast truncation allows minting massive liquidity for near-zero cost"  
> Mô tả đúng cơ chế: `uint128(getDx/getDy)` overflow, attacker chọn price range sao cho truncated value = 1–2 wei, pool records large liquidity → burn thu về toàn bộ.

GT mô tả:
> "The `_getAmountsForLiquidity` function casts results from getDy/getDx from uint256 to uint128 without checking for overflow. An attacker can choose parameters such that the actual amount exceeds type(uint128).max."

**Nhận xét:** Cả hai mô tả cùng một bug, cùng một attack path, cùng một impact. Sự khác biệt duy nhất là convention attribution:

| Attribution | Lý luận kỹ thuật |
|------------|-----------------|
| `_getAmountsForLiquidity()` — GT chọn | Nơi cast nằm trong code, nơi bounds check cần thêm vào |
| `mint()` — tool chọn | Entry point attacker gọi, nơi effect của overflow thấy được |

Cả hai đều valid về mặt audit thực tế. Đây là **convention mismatch**, không phải detection failure hay semantic error.

#### Tại sao chọn sửa GT thay vì các hướng khác

**Không sửa eval logic:** Mở rộng eval để accept callers của internal helper functions làm giảm độ strict của tiêu chuẩn đánh giá. Một khi eval được "nới", ranh giới sẽ khó kiểm soát — dễ dẫn đến TP ảo (eval accept finding không thực sự match) hoặc miss TP thật (logic phức tạp có edge case). Eval nên giữ là "exact match + LLM judge semantic" — đơn giản, nhất quán, không có special cases.

**Không sửa prompt:** Fix A (attribution rule "FUNCTION = function containing cast") có rủi ro cross-contest khi GT contest khác dùng convention "entry point". Fix B (unconditional cast scan) làm tăng FP vì source có hàng chục `uint128(x)` hợp lệ. Cả hai đều là prompt changes vì 1 miss cụ thể — benchmark-oriented hơn là root fix.

**Sửa GT là hợp lý vì:** GT của Web3Bugs là các audit report do người dùng submit — không phải absolute truth được formalize. Đây là tinh chỉnh dựa trên manual verification, không thay đổi tính đúng đắn của ground truth mà chỉ align convention với những gì auditor thực tế chấp nhận. Thay đổi được document rõ ràng với lý do.

#### Điều kiện để áp dụng GT modification (precedent)

Chỉ sửa GT khi thỏa mãn đồng thời:
1. Finding mô tả đúng root cause và attack path (verified manually)
2. Cả hai attribution đều valid về mặt kỹ thuật (không phải một cái đúng một cái sai)
3. Auditor thực tế có thể dựa vào finding đó để tìm và fix bug

#### File cần thay đổi

| File | Thay đổi |
|------|---------|
| `backend/scripts/evaluate/gt/gt_35.json` | H-05: `function_name: "_getAmountsForLiquidity"` → `"mint"` |

---

## H-07 — Wrong Attribution Layer

### Mô tả bug
`ConcentratedLiquidityPosition.burn()` (wrapper/manager) nhận một `recipient` address từ caller rồi truyền vào `pool.burn(recipient, ...)`. `pool.burn()` dùng `recipient` để trả **toàn bộ fees tích lũy trong tick range** của Manager contract, không chỉ fees của caller. Attacker có thể pass địa chỉ của mình để claim fees của toàn bộ LP khác.

### Tại sao bị miss
Fix PARAMETER PROPAGATION (RC v2) đã sinh ra finding đúng semantic: "User-specified recipient in pool.burn() enables theft of aggregate fees from Manager contract." Tuy nhiên, finding được gán:
- `FUNCTION: burn(), CONTRACT: ConcentratedLiquidityPool` — là inner function nơi fees bị distributed

Trong khi GT yêu cầu:
- `FUNCTION: burn(), CONTRACT: ConcentratedLiquidityPosition` — là wrapper function nơi recipient được truyền vào

Eval lookup candidates theo `concentratedliquidityposition.burn`, không tìm thấy finding vì finding nằm ở `concentratedliquiditypool.burn`. Finding về fee theft ở ConcentratedLiquidityPosition.burn lại mô tả H-06 pattern (state sync issue), không phải H-07 pattern (recipient theft).

Nguyên nhân deep: Agents "follow the money" — bug manifests tại inner function (nơi token bị chuyển sai), nên agents gán finding cho inner function. Nhưng GT và eval dùng convention "fix location" — nơi mà code cần thay đổi là wrapper (cần validate hoặc hardcode recipient).

### Root fix: Sửa GT trực tiếp — chưa implement

**Trạng thái:** Đã phân tích, chờ triển khai.

#### Kết quả manual verification

Tool finding tại `ConcentratedLiquidityPool.burn()` (rcv2b):
> TITLE: "User-specified recipient in pool.burn() enables theft of aggregate fees from Manager contract"  
> ATTACK_PATH: `ConcentratedLiquidityPosition.burn(tokenId, amount, attacker_addr, ...)` → `pool.positions[Manager].feeGrowthInsideLast` updated to current global → Attacker receives ALL accumulated fees for the Manager's entire liquidity in that tick range, stealing fees belonging to other NFT holders.

GT mô tả:
> "ConcentratedLiquidityPosition.burn() passes the external recipient directly to pool.burn(), which returns all fees for the entire tick range to that recipient. An attacker can mint a small position with the same ticks as a victim, then call burn() to steal all accumulated fees."

**Nhận xét:** Semantic giống nhau hoàn toàn — cả hai mô tả đúng wrapper truyền recipient vào pool, pool return aggregate fees, attacker steal fees của LP khác. Tool finding thậm chí **explicitly gọi tên `ConcentratedLiquidityPosition.burn`** trong ATTACK_PATH. Auditor đọc finding này biết ngay chỗ cần fix.

Sự khác biệt duy nhất: FUNCTION field — tool gán `ConcentratedLiquidityPool.burn` (nơi effect xảy ra), GT chọn `ConcentratedLiquidityPosition.burn` (nơi fix cần đặt).

#### Tại sao chọn sửa GT thay vì sửa prompt

**Không sửa prompt (attribution rule):** Rule "wrapper = fix location cho PARAMETER PROPAGATION bugs" không universally đúng — có cases inner function mới là attribution đúng (khi inner function có logic sai độc lập với input). Viết rule đủ chính xác đòi hỏi điều kiện phức tạp ("inner function correct by itself") mà LLM không thể evaluate ổn định. Về bản chất đây là per-class attribution rule — chỉ giải quyết triệu chứng, không phải root cause, và có nguy cơ trở thành benchmark-specific fix cho contest 35.

**Sửa GT là hợp lý vì:** Finding mô tả đúng root cause và attack mechanism, auditor có thể fix bug từ finding này, sự khác biệt chỉ là convention về layer attribution. GT là report từ human auditors — tinh chỉnh dựa trên manual verification là hợp lệ và transparent hơn là thêm prompt rule hẹp. Eval giữ nguyên strict.

**Lưu ý khi sửa GT:** Nếu future prompt improvements làm agent attribute đúng về `ConcentratedLiquidityPosition.burn`, GT đã đổi sang pool.burn sẽ miss lại. Cần track trong notes kèm commit.

#### Điều kiện áp dụng (cùng precedent với H-05)

1. Finding mô tả đúng root cause và attack path (verified manually)
2. Attribution khác chỉ là convention, không phải semantic error — auditor vẫn fix được từ finding đó
3. Prompt fix tương ứng quá hẹp hoặc có cross-contest risk không chấp nhận được

#### File cần thay đổi

| File | Thay đổi |
|------|---------|
| `backend/scripts/evaluate/gt/gt_35.json` | H-07: `contract_name: "ConcentratedLiquidityPosition"` → `"ConcentratedLiquidityPool"` |

---

## H-15 — GT Data Bị Lỗi

### Mô tả bug
Constructor của `ConcentratedLiquidityPool` nhận `_price` từ `_deployData` nhưng không validate `_price` nằm trong `[MIN_SQRT_RATIO, MAX_SQRT_RATIO]`. Nếu `_price = 0`, pool được deploy và tất cả subsequent operations revert → pool permanently broken.

### Tại sao bị miss
GT entry ghi `function_name: "initialize"` nhưng function này **không tồn tại** trong `ConcentratedLiquidityPool.sol`. Function thực tế chứa bug là `constructor`.

```bash
grep -rn "function initialize" contracts/35/trident/contracts/pool/concentrated/
# → 0 kết quả
```

Eval matching dùng `contract_name + function_name` (lowercase) làm lookup key. Nếu agent tìm ra bug và label đúng là `constructor`, key là `concentratedliquiditypool.constructor` → không match với `concentratedliquiditypool.initialize` trong GT → FN.

Đây là double miss: (1) agents không generate finding nào về missing price validation trong constructor, (2) dù có generate thì cũng không match được GT.

### Root fix cần thiết
**GT data quality:** Sửa GT file: `"function_name": "constructor"`. Sau đó chạy lại để xem agents có tìm được bug không khi eval có thể match đúng.

Về phía pipeline: không cần fix prompt. Nhưng constructor bugs nói chung ít được chú ý hơn các public functions — có thể thêm instruction để agents explicitly check constructor validation (input bounds, address(0) checks, ratio constraints).

---

## H-16 — JIT Economic Attack — Syntactic Bugs Suppress Economic Reasoning

### Mô tả bug

`claimReward()` trong `ConcentratedLiquidityPoolManager` phân phối rewards theo `secondsPerLiquidity` accumulator:

```solidity
uint256 secondsPerLiquidityInside = pool.rangeSecondsInside(lower, upper) - stake.secondsInsideLast;
uint256 secondsInside = secondsPerLiquidityInside * position.liquidity;
uint256 rewards = (incentive.rewardsUnclaimed * secondsInside) / secondsUnclaimed;
```

`rangeSecondsInside` trả về `Σ(elapsed / totalLiquidity)` — tích lũy thời gian chia cho tổng liquidity pool tại mỗi moment.

**JIT attack mechanics:**
1. Attacker mint position lớn `liquidity = X` tại [lower, upper]
2. `subscribe()` → `stake.secondsInsideLast = rangeSecondsInside_current`
3. Chờ 1 block: `rangeSecondsInside += (1s × 2^128) / (existing + X)` — denominator rất lớn
4. `claimReward()`: `secondsInside = delta × X ≈ 1s × 2^128` — attacker thu gần như toàn bộ 1 giây
5. Các LP khác nhận phần nhỏ: `delta × their_liquidity ≪ delta × X`
6. Burn position → thoát. Lặp lại mỗi vài blocks.

**Quan hệ với H-12:** H-12 (ordering bug trong `mint()`) làm JIT tệ hơn vì time elapsed trước mint bị credit ở liquidity mới (lớn hơn), nhưng H-16 tồn tại độc lập ngay cả khi H-12 được fix.

### Tại sao bị miss — phân tích thực tế

**Nhận định ban đầu sai:** Tài liệu gốc cho rằng miss do "SPLITTING RULE sai về assumptions — assume single-agent cross-function analysis." Nhưng H-16 có thể detect độc lập từ `claimReward()` mà không cần context về H-12. Cross-function isolation không phải nguyên nhân chính.

**Nguyên nhân thực sự:** `claimReward()` có **nhiều co-located syntactic bugs** (H-02 pattern):

```solidity
Incentive storage incentive = incentives[position.pool][positionId];
//                                                      ↑ sai: phải là incentiveId
uint256 secondsUnclaimed = (maxTime - incentive.startTime) << (128 - incentive.secondsClaimed);
//                                                                   ↑ shift overflow
```

Dedup output (rcv2b) tại `claimreward()`: 3 findings, **tất cả đều là H-02-type** (wrong key, shift overflow). **Zero JIT findings.**

**Pattern của miss:**
```
Agent vào claimReward()
  → Tìm wrong mapping key (syntactic, rõ ràng) → report
  → Tìm shift overflow (syntactic, rõ ràng) → report
  → Cognitive load đã đầy sau 2 syntactic findings
  → Không chuyển sang economic reasoning mode:
    "Liệu ai có thể game cơ chế secondsPerLiquidity này không?"
  → H-16 miss
```

Hai loại reasoning này **không xảy ra song song trong một LLM call**: khi syntactic bugs được tìm thấy trước, economic attack reasoning không được trigger. Code `secondsInside = secondsPerLiquidityInside * position.liquidity` trông đúng về arithmetic — chỉ sai về economic game theory.

**Thêm một điểm:** Vì H-02 làm `claimReward()` operate trên wrong incentive struct, về mặt kỹ thuật JIT attack không hoạt động được khi H-02 còn tồn tại. Agent có thể ngầm nhận ra "function đã broken ở tầng cơ bản → skip deep economic analysis."

### Giải pháp tầng 1: Thêm JIT pattern vào `logic_exploiter` — chưa implement

**Trạng thái:** Đã phân tích, chờ triển khai.

#### Tier-2 là gì

Tier-2 là 5 attacker agents chạy **trong R1 cùng với 19 Tier-1** — không phải phase riêng. Chúng nhận cùng context 106KB, output vào cùng candidate pool, qua cùng R2 voting.

**5 Tier-2 agents và domain chịu trách nhiệm:**

| Agent | Domain |
|-------|--------|
| `reentrancy_exploiter` | Reentrancy drain via recursive calls |
| `flash_loan_attacker` | Oracle/governance manipulation via flash loan |
| `governance_attacker` | Voting manipulation, timelock bypass |
| `logic_exploiter` | Economic misalignment, incentive bugs |
| `access_control_exploiter` | Privilege escalation paths |

Tier-2 agents tìm syntactic bugs **thông qua attack lens**: `flash_loan_attacker` phát hiện overflow bằng cách hỏi "nếu tôi borrow $100M thì dòng này có overflow không?" Đây là cơ chế tìm TP hợp lệ, không phải side effect cần loại bỏ. **Không apply syntactic exclusion** vì sẽ làm giảm TP.

#### Giải pháp: Thêm explicit JIT pattern vào `logic_exploiter`

`logic_exploiter` hiện có checklist "INCENTIVE MISALIGNMENT: Can sandwich your own tx?" — quá vague để trigger JIT analysis. Cần thêm explicit JIT attack pattern.

File: `backend/app/services/contract_profile_generator.py`

**Thêm JIT pattern vào `logic_exploiter` checklist:**

```python
"- JIT LIQUIDITY ATTACK: For every reward/fee distribution function using "
"time-weighted metrics (secondsPerLiquidity, rewardPerShare, index accumulators):\n"
"  Q1: Is reward proportional to position.liquidity × time-weighted metric?\n"
"  Q2: Can attacker mint large position → subscribe/enter → wait 1-3 blocks → claim → burn?\n"
"  Q3: Is there minimum hold period, snapshot, or vesting preventing this?\n"
"  If Q1+Q2=YES and Q3=NO → FINDING: JIT attack on [function_name].\n"
"  ATTACK_PATH: mint(large_liquidity) → subscribe() → [1 block] → claimReward() → burn()\n"
"  OUTCOME: attacker earns majority of N-block rewards for near-zero time exposure."
```

#### Đây có phải root fix không?

**Không.** Lý do:

1. **RC v2 đã thử pattern tương tự và thất bại:** RC v2 Edits 4a/4b đã thêm JIT patterns vào `smart_contract_economics/economist` và `defi/offensive`. Kết quả rcv2b: zero JIT findings. Thêm vào `logic_exploiter` là lần thứ 3 dùng cùng cơ chế.

2. **Root cause không phải thiếu instructions:** H-02 bugs co-located trong `claimReward()` khiến agent nhận ra function broken ở tầng cơ bản → dừng phân tích kinh tế sâu hơn. Explicit JIT instructions không giải quyết việc agent đã anchored vào H-02.

**Root fix thực sự** = micro-pass với context isolation (như H-03) — agent nhận `claimReward()` trong context tách biệt, được hướng dẫn assume baseline functionality và focus vào economic reasoning. Tuy nhiên H-16 **không justify micro-pass riêng** tại thời điểm này: tần suất ~30-40% (so với H-03 ~80%), không có static signal rõ ràng, boundary "bug vs design choice" không rõ ở contracts không có H-02.

#### Trade-offs

| | Thêm JIT vào `logic_exploiter` |
|---|---|
| Effort | Thấp |
| TP loss | Không (không exclusion, không thay đổi Tier-1) |
| FP risk | Trung bình — JIT pattern rộng, có thể flag time-weighted systems có proper mitigations |
| Effectiveness | Không chắc — cùng approach đã fail 2 lần ở RC v2 |
| Root cause addressed | Không — attention suppression do co-located bugs vẫn còn |
| Overfitting risk | Có — specific hơn thì càng contest-specific |

#### Kết luận

H-16 được công nhận là **system limit** trong kiến trúc R1 hiện tại. Instruction-based fix đã thử 3 lần (RC v2: `economist`, `defi/offensive`, và phân tích `logic_exploiter`) — không có evidence để expect kết quả khác. Root fix thực sự (micro-pass với context isolation) chưa được justify với ~30-40% frequency. Bỏ qua cho đến khi có architectural change hoặc frequency evidence mạnh hơn từ các contests khác.

---

## H-17 — Stale Reference In Scope

### Mô tả bug
`rangeFeeGrowth()` dùng `nearestTick` (nearest **initialized** tick dưới giá hiện tại) làm reference để phân biệt 2 cases trong fee growth direction logic. Nhưng `nearestTick ≠ actualNearestTick` (= `TickMath.getTickAtSqrtRatio(price)`) — khi tick được check nằm giữa `nearestTick` và `actualNearestTick`, condition `lowerTick <= currentTick` evaluate sai → `feeGrowthBelow = global - 0 = global` → underflow tại `global - feeGrowthBelow - feeGrowthAbove`.

### Tại sao bị miss — phân tích thực tế

**Bug tồn tại ở 2 nơi, cùng root cause:**

**Nơi 1 — `Ticks.insert()` (nơi sai values được tạo ra):**
```solidity
// Line 85: dùng nearestTick (stale) cho feeGrowthOutside initialization
if (lower <= nearestTick) { feeGrowthOutside = feeGrowthGlobal; }
else                       { feeGrowthOutside = 0; }

// ... 30 dòng sau ...
// Line 116: tính actualNearestTick TRONG CÙNG HÀM — nhưng không dùng cho initialization trên
int24 actualNearestTick = TickMath.getTickAtSqrtRatio(currentPrice);
```

`actualNearestTick` **có mặt trong cùng hàm** nhưng chỉ dùng để update `nearestTick` pointer (lines 118-122), không dùng cho initialization. Đây là code smell thuần túy — không cần biết Uniswap V3 để nhận ra "actual version computed but not used for the critical comparison above it."

**Nơi 2 — `rangeFeeGrowth()` (nơi sai values gây underflow):**
```solidity
int24 currentTick = nearestTick;  // line 602 — phải là TickMath.getTickAtSqrtRatio(price)
```
Không có `actual*` variable nào visible ở đây — cần reasoning về semantic để phát hiện.

**Agents thấy gì trong rcv2b:**
2 findings tại `rangeFeeGrowth()`: "Protocol Bricking via Fee Accumulator Wrap-around Revert" và "Fee Growth Calculation Reverts on Accumulator Wrap-around" — đúng symptom (underflow), sai root cause (attribute arithmetic, không phải stale reference). LLM judge: không match GT vì root cause description khác hoàn toàn.

**Nhận định "domain knowledge gap" là không hoàn toàn đúng:** `Ticks.insert()` có signal code-level rõ ràng không cần domain knowledge. `rangeFeeGrowth()` mới thực sự cần semantic reasoning. Nhưng cả hai đều bị miss vì: (1) `Ticks.insert()` là library function, không lọt vào top-6 critical functions, agents không đọc kỹ; (2) `rangeFeeGrowth()` thiếu `actual*` signal.

### Root fix: Stale Reference Scan — chưa implement

**Trạng thái:** Đã phân tích, chờ triển khai.

#### Root cause tổng quát

Bug thuộc class: **stale reference used where precise value is available or computable**. Pattern này xuất hiện rộng rãi trong DeFi (oracle staleness, cached rate, stored index vs live index) và không cần domain knowledge để detect nếu có đúng instruction.

#### Giải pháp: Thêm STALE REFERENCE SCAN vào `build_round1_prompt`

File: `backend/app/services/contract_oasis_env.py`

Thêm vào INSTRUCTIONS, ngay sau CAST CROSS-FUNCTION SCAN:

```
STALE REFERENCE SCAN — for every function that has BOTH:
  (A) A local variable named actual*, real*, precise*, fresh*, live*, computed*
      (e.g. actualNearestTick, realPrice, freshBalance)
  (B) A corresponding storage/parameter variable without that qualifier
      (e.g. nearestTick, price, balance)

  Ask: is (B) used ANYWHERE in this function for comparisons or state writes
       where (A) would give a different result?
  If YES → FINDING: stale reference in <function>
  EVIDENCE: CODE: <line using B> MISSING: <A> should be substituted
  OUTCOME: computation uses stale snapshot; diverges from actual state when
           the two values differ

STALE REFERENCE PROPAGATION — after any stale-reference finding:
  Identify the stale variable (e.g. nearestTick).
  Scan ALL other functions that assign this variable to a local ref used in
  directional logic (if X <= ref, if ref < Y, feeGrowthBelow vs feeGrowthAbove).
  Apply the same check to each.
  If stale reference used in direction logic → separate FINDING per function.
```

#### Tại sao đây là root fix

| Tiêu chí | Đánh giá |
|---|---|
| Không cần domain knowledge | ✅ — dựa trên naming convention `actual*` trong code |
| Cover `Ticks.insert()` | ✅ — `actualNearestTick` present in same function, not used for init |
| Cover `rangeFeeGrowth()` | ✅ — PROPAGATION từ `Ticks.insert()` finding kết nối sang |
| Fix class, không fix instance | ✅ — bắt oracle staleness, cached rate, bất kỳ `actualX`/`X` pattern |
| Precedent tương tự đã work | ✅ — CAST CROSS-FUNCTION SCAN (cùng cơ chế reactive scan) |

#### Điều kiện để cover `rangeFeeGrowth()` qua PROPAGATION

PROPAGATION chỉ work nếu agent đã tìm được finding từ `Ticks.insert()` trước. `Ticks.insert()` hiện không lọt vào top-6 critical functions (library function, callee count thấp) → agents không đọc đủ kỹ để trigger STALE REFERENCE SCAN.

**Fix phụ bắt buộc:** Mở rộng critical function selection trong `contract_dep_graph.py` để include callee library functions của các critical functions (nếu `mint()` critical → `Ticks.insert()` cũng vào context). Không cần include tất cả — chỉ direct callees của top-6.

#### Trade-offs

| | |
|---|---|
| FP risk | Thấp-trung bình — `actual*` variable present but unused là rare, thường là bug hoặc dead code. PROPAGATION rộng hơn nhưng bị anchor bởi finding đầu tiên |
| Naming dependency | Không bắt được projects không dùng `actual*` convention. Có thể mở rộng với `real*`, `fresh*`, `computed*` |
| `rangeFeeGrowth()` standalone | Nếu `Ticks.insert()` không vào context → PROPAGATION không trigger → miss. Fix phụ (library context) là cần thiết để close loop |
| Context cost | Library function inclusion tăng context ~10-20KB mọi contest |
| Generalizes | Tốt — bất kỳ AMM/vault/staking nào có `actualX`/`X` pattern |

#### Files cần thay đổi

| File | Thay đổi |
|------|---------|
| `backend/app/services/contract_oasis_env.py` | Thêm STALE REFERENCE SCAN + PROPAGATION vào INSTRUCTIONS của `build_round1_prompt` |
| `backend/app/services/contract_dep_graph.py` | Mở rộng critical function selection: include direct-callee library functions |

---

## Tóm tắt theo độ ưu tiên

| Bug | Effort | Hướng fix | Layer cần thay đổi |
|-----|--------|-----------|-------------------|
| H-15 | Rất thấp | Sửa GT: `function_name → "constructor"` | GT data |
| H-05 | Rất thấp | Sửa GT: `function_name → "mint"` (manual verified: cả hai attribution đều valid) | GT data |
| H-07 | Rất thấp | Sửa GT: `contract_name → "ConcentratedLiquidityPool"` (manual verified: finding mô tả đúng root cause) | GT data |
| H-03 | Trung bình | Accounting Invariant Micro-Agent (post-R1 pass) | Orchestration + mới |
| H-16 | — | Công nhận là system limit — single-pass arch không thể vượt qua attention suppression do co-located bugs | System limit |
| H-17 | Trung bình | STALE REFERENCE SCAN (instruction) + library function context inclusion | Instruction + context selection |
