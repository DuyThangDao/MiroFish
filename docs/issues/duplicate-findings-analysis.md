# Duplicate Findings Analysis — Contest 3 (MarginSwap, sim_e2e_r1)

**Date**: 2026-06-20  
**Run**: `benchmark/web3bugs/agent-redesign/3/sim_e2e_r1`  
**Total raw findings**: 723 | **GT H bugs**: 11 | **TP**: 6/11

---

## Tóm tắt nhanh

| Metric | Giá trị |
|--------|---------|
| Total findings | 723 |
| Unique by (title+fn+contract) | 701 — chỉ 22 exact title dups |
| Unique (fn, contract) pairs targeted | 142 |
| Findings per unique function | **5.1x** |
| Severity T3 (High) | 270 (37%) |
| Severity T2 (Medium) | 453 (63%) |

---

## Type A — Intra-chunk, cùng function, khác agents

**Mô tả**: Trong 1 chunk, nhiều agents cùng flag cùng 1 (fn, contract).  
**Số findings liên quan**: 565  
**Đánh giá**: **Intentional** — mỗi agent phân tích từ góc nhìn khác nhau (re-entrancy, access control, math...). Thường không duplicate về nội dung.  

Ví dụ: `CrossMarginAccounts.addHolding` trong `access_reward/CrossMarginAccounts` bị flag bởi 4 agents: `state_machine_analyst`, `clmm_specialist`, `token_flow_tracer`, `appsec_hardener`.

Chunks có nhiều overlap nhất:

| Chunk | Số (fn,contract) pairs với >1 agent |
|-------|-------------------------------------|
| access_reward/CrossMarginAccounts | 11 |
| general/MarginRouter | 11 |
| general/Lending | 10 |
| access_reward/Lending | 9 |
| general/IncentiveDistribution | 9 |

---

## Type B — Cross-chunk, cùng function, khác chunks ← **Vấn đề chính**

**Mô tả**: Cùng 1 (fn, contract) xuất hiện trong nhiều chunk khác nhau.  
**Số findings liên quan**: 576  

### Breakdown theo loại function

| Loại | Findings | Ghi chú |
|------|----------|---------|
| GT function (bug target) | 116 | Tốt — cần nhiều góc nhìn |
| GT contract, non-GT function | **462** | **Nguồn FP lớn nhất** |
| AUX / non-GT contract | 2 | Không đáng kể |

### GT functions bị cover nhiều nhất (116 findings)

| Function | Findings | Chunks |
|----------|----------|--------|
| IncentiveDistribution.withdrawReward | 27 | 3 |
| MarginRouter.crossSwapExactTokensForTokens | 21 | 6 |
| CrossMarginTrading.registerTradeAndBorrow | 19 | 3 |
| PriceAware.getCurrentPriceInPeg | 18 | 4 |
| CrossMarginAccounts.addHolding | 17 | 2 |
| Lending.buyBond | 6 | 3 |

### GT-contract helper functions bị lặp nhiều nhất (462 findings — FP noise)

| Function | Findings | Chunks |
|----------|----------|--------|
| IncentiveDistribution._updateTrancheTotals | 42 | 3 |
| Lending.applyBorrowInterest | 32 | **10** |
| Lending.haircut | 31 | **12** |
| Lending.disburse | 28 | 8 |
| IncentiveDistribution.updateAccruedReward | 20 | 3 |
| IncentiveDistribution.addToClaimAmount | 17 | 3 |
| CrossMarginAccounts.borrow | 12 | 2 |
| CrossMarginAccounts.extinguishDebt | 12 | 2 |
| Lending.registerBorrow | 12 | 7 |
| MarginRouter._swap | 12 | 6 |

**Root cause**: `Lending.haircut`, `Lending.applyBorrowInterest`, `Lending.disburse` là helper functions được import làm AUX trong nhiều GT contracts (MarginRouter, CrossMarginTrading, CrossMarginAccounts...). Khi 6–12 chunks khác nhau đều include Lending source làm aux, tất cả agents trong các chunks đó đều flag các helper functions này → 462 findings "lạc".

---

## Type C — Near-duplicate titles trong cùng chunk

**Mô tả**: Hai findings trong cùng chunk có title giống nhau >80% (SequenceMatcher).  
**Số cặp**: 110  
**Đánh giá**: Agents sinh template title giống nhau cho các functions tương tự. Không ảnh hưởng recall nhưng tăng FP count.

Ví dụ:
- `"Incorrect Global Exposure Accounting in registerBorrow"` vs `"...in registerDeposit"` (sim=0.90)
- `"Stale Accumulator in viewBorrowInterest"` vs `"Stale accumulator usage in applyBorrowInterest"` (sim=0.80)
- `"Unaccounted Swap Fees Locked in Fund Contract"` vs `"...in Fund Contract (Output Side)"` (sim=0.87)

---

## Type D — Same title across different contracts

**Số titles xuất hiện ở 3+ contracts**: 0  
Không có cross-contract title spam.

---

## Top agents theo số findings

| Agent | Findings |
|-------|----------|
| appsec_hardener | 87 |
| token_specialist | 69 |
| logic_exploiter | 67 |
| defi_attacker | 59 |
| validation_checker | 55 |
| mev_analyst | 49 |
| state_dep_checker | 48 |
| governance_specialist | 41 |

---

## Improvement opportunity

**64% tổng findings (462/723) là findings về GT-contract non-GT-function** — đây là FP lớn nhất, chủ yếu do helper functions xuất hiện trong AUX context của nhiều chunks.

**Hướng fix tiềm năng**: Ưu tiên (boost score / lọc trước dedup) các findings thuộc "primary contract của chunk" thay vì findings về aux functions. Mỗi chunk có 1 GT contract làm primary — findings về contract đó nên được weight cao hơn findings về contracts xuất hiện qua import.

Dedup step hiện tại sẽ cắt từ 723 xuống ~100–150, nhưng phần lớn là Type B. Type A (intentional multi-angle) vẫn giữ nguyên sau dedup.
