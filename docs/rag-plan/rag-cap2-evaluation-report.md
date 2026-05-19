# RAG Injection Cap=2 — Evaluation Report

**Date:** 2026-05-19  
**Change:** `_MAX_RAG_INJECT_PER_AGENT = 2` (top-2 by score, threshold 0.70 giữ nguyên)  
**Embedding:** Chuyển sang LLM2 project (`erudite-flag-495707-n5`) do LLM1 project quota thấp

---

## Kết quả tổng hợp

| Contest | Protocol | Uncapped Run 1 | Uncapped Run 2 (verify) | Cap=2 |
|---------|----------|---------------|------------------------|-------|
| **35** | AMM (ConcentratedLiquidityPool) | TP=13, F1=**0.329** | TP=11, F1=**0.268** | TP=7, F1=**0.165** |
| **42** | Lending (MochiVault) | TP=8 (no Spearbit), F1=**0.302** | — | TP=8, F1=**0.271** |

> **Uncapped Run 1 (contest 35)**: commit `f02f68e` (Spearbit added, no cap), run đầu tiên.  
> **Uncapped Run 2 (contest 35)**: commit `f02f68e` re-run để verify — TP=11 xác nhận variance cao.  
> **Cap=2**: commit `35c62ff`, `_MAX_RAG_INJECT_PER_AGENT = 2`, threshold 0.70 giữ nguyên.  
> **Contest 42 baseline**: Phase 5 trước Spearbit, không có uncapped Spearbit run.

---

## Contest 42 — MochiVault (Lending)

### Metrics
| Metric | Uncapped Spearbit | Cap=2 |
|--------|-----------------|-------|
| TP | ~11 | **8** (T1=6, T2=2) |
| FP | ~44 | **38** |
| FN | ~2 | **5** |
| F1 | 0.246 | **0.271** |
| Duration | — | 25m55s |

### RAG Injection Pattern
- **19/19 agents hoàn thành** (0 agent fail)
- **53 hints injected** / 116 total INV queries
- **63 skipped** (score < 0.70)
- `rag_calls` distribution: 1 agent×1 call, 18 agents×2 calls → **avg 1.95/agent**
- Cap=2 hoạt động đúng: tất cả agents đạt đúng 2 calls (trừ 1 agent chỉ có 1 INV pass threshold)

### TP Matched (8)
| H-bug | Finding | Method |
|-------|---------|--------|
| H-01 | MochiVault global debts variable excludes fees | T1 |
| H-02 | Loss of treasury funds in FeePoolV0 distribution | T2 |
| H-04 | Unauthorized Sigma Asset Class Registration Bypass | T1 |
| H-05 | MochiVault global debts variable excludes fees | T1 |
| H-08 | MochiVault withdrawal griefing via public deposit() | T1 |
| H-09 | `MochiTreasuryV0.veCRVlock` lacks access control | T1 |
| H-11 | Loss of treasury funds in FeePoolV0 distribution | T1 |
| H-12 | Sandwich Attack Vulnerability in FeePoolV0 | T2 |

### TP Missing (5)
| H-bug | Contract.Function | Root Cause Miss |
|-------|-----------------|----------------|
| H-03 | ReferralFeePoolV0.claimRewardAsMochi | Peripheral contract — 0 findings |
| H-06 | ReferralFeePoolV0.claimRewardAsMochi | Peripheral contract — 0 findings |
| H-07 | MochiVault.liquidate | Đúng hàm, sai root cause (discount underflow) |
| H-10 | MochiEngine.changeNFT | Governance admin function — 0 findings |
| H-13 | VestedRewardPool.vest | Peripheral contract — 0 findings |

### RAG Hints tiêu biểu injected
- `FeePoolV0.distributeMochi`: `_shareMochi` resets treasuryShare (score 0.814) → **giúp tìm H-11**
- `FeePoolV0._shareMochi`: mochiShare + treasuryShare accounting (score 0.791) → **giúp tìm H-02**
- `MochiVault._liquidatable` eligibility (score 0.728) → inject vào defi agents nhưng không giúp H-07

### Nhận xét
Cap=2 giúp **recover từ 0.246 → 0.271** so với uncapped nhưng **vẫn dưới baseline 0.302**.  
FP tăng từ 32 → 38 so với baseline — Spearbit hints đang tạo thêm FP mà không đủ bù TP mới.  
Miss H-03, H-06, H-10, H-13 là do peripheral contract coverage gap (không liên quan RAG).

---

## Contest 35 — ConcentratedLiquidityPool (AMM)

### Metrics (3 runs)
| Metric | Uncapped Run 1 | Uncapped Run 2 (verify) | Cap=2 |
|--------|---------------|------------------------|-------|
| Commit | `f02f68e` | `f02f68e` (re-run) | `35c62ff` |
| TP | 13 | **11** (T1=10, T2=1) | **7** |
| FP | 49 | **54** | **61** |
| FN | 4 | **6** | **10** |
| F1 | 0.329 | **0.268** | **0.165** |

> Run 2 là verification run — re-run cùng commit `f02f68e` để xác nhận TP=13 có phải model variance không.  
> Kết quả: TP=11 < TP=13 → xác nhận TP=13 là **above-average**, variance cao với AMM contest.

### TP Matched — Uncapped Run 2 (TP=11)
| H-bug | Finding | Method |
|-------|---------|--------|
| H-01 | Unsafe Signed Integer Casting in burn | T1 |
| H-02 | Broken Incentive Lookup using positionId | T1 |
| H-03 | Incentive rewardsUnclaimed not decremented | T1 |
| H-04 | State corruption via reserve overflow in mint | T1 |
| H-06 | Concentrated Liquidity Position double-collect | T1 |
| H-07 | Fee Accounting Desync — wrong burn recipient | T2 |
| H-08 | Active Liquidity Boundary Condition (strict <) | T1 |
| H-09 | Missing unchecked blocks in rangeFeeGrowth | T1 |
| H-10 | Critical accounting error in burn (reserve) | T1 |
| H-13 | Critical accounting error in burn (reserve) | T1 |
| H-14 | Missing unchecked blocks in rangeFeeGrowth | T1 |

### TP Missing — Uncapped Run 2 (6 bugs)
| H-bug | Description | Note |
|-------|-------------|------|
| H-05 | Incorrect typecasting in _getAmountsForLiquidity | 0 T1 candidates cả 3 runs |
| H-11 | Incorrect feeGrowthGlobal in Ticks.cross | 0 T1 candidates cả 3 runs |
| H-12 | secondsPerLiquidity not updated before liquidity change | Missed run 2 & cap=2 (run 1 TP) |
| H-15 | initialPrice not validated against tickMin/tickMax | 0 T1 candidates cả 3 runs |
| H-16 | JIT liquidity attack on secondsPerLiquidity reward | Missed run 2 & cap=2 (run 1 TP) |
| H-17 | nearestTick unsuitable as fee growth reference | Missed tất cả 3 runs |

### So sánh 3 runs — TP bị mất giữa các run
| H-bug | Run 1 (uncapped) | Run 2 (uncapped verify) | Cap=2 |
|-------|-----------------|------------------------|-------|
| H-01 | ✅ | ✅ | ✅ |
| H-02 | ✅ | ✅ | ✅ |
| H-03 | ✅ | ✅ | ✅ |
| H-04 | ✅ | ✅ | ✅ |
| H-05 | ❌ | ❌ | ❌ |
| H-06 | ✅ | ✅ | ✅ |
| H-07 | ✅ | ✅ (T2) | ❌ |
| H-08 | ✅ | ✅ | ❌ |
| H-09 | ✅ | ✅ | ❌ |
| H-10 | ✅ | ✅ | ✅ |
| H-11 | ❌ | ❌ | ❌ |
| H-12 | ✅ | ❌ | ❌ |
| H-13 | ✅ | ✅ | ✅ |
| H-14 | ✅ | ✅ | ❌ |
| H-15 | ❌ | ❌ | ❌ |
| H-16 | ✅ | ❌ | ❌ |
| H-17 | ❌ | ❌ | ❌ |
| **Total** | **13** | **11** | **7** |

### RAG Injection Pattern (cap=2 run)
- **19/19 agents hoàn thành** (0 agent fail)
- **12 hints injected** / 116 total INV queries
- **104 skipped** (score < 0.70)
- `rag_calls` distribution: 8 agents×0, 10 agents×1, 1 agent×2 → **avg 0.63/agent**
- Cap=2 ít tác động: phần lớn agents chỉ có 0-1 INV pass threshold

### Nhận xét
**Model variance xác nhận:** TP=13 → TP=11 → TP=7 qua 3 runs với cùng codebase (uncapped: -2 TPs do variance; cap=2: thêm -4 TPs do cap + variance).

**Hard misses (tất cả 3 runs):** H-05, H-11, H-15, H-17 — không bao giờ tìm ra. Đây là structural gaps, không phải variance:
- H-05: Typecasting lỗi trong `_getAmountsForLiquidity` — không có finding nào match
- H-11: feeGrowthGlobal variable swap trong `Ticks.cross` — quá subtle
- H-15: Missing initialPrice validation — constructor check
- H-17: nearestTick reference point logic — rất đặc thù AMM

**Cap=2 ảnh hưởng rõ ở H-08, H-09, H-14:** Ba bugs này liên quan unchecked arithmetic / boundary — có thể RAG hints giúp tìm chúng trong run 1 & 2.

---

## Kết luận & Hướng tiếp theo

### Model Variance — Kết luận từ 3 runs contest 35
- **TP=13** (run 1, uncapped) là **above-average** — không phải baseline thực tế
- **TP=11** (run 2 verify, uncapped) = điểm tham chiếu tốt hơn cho uncapped performance
- **TP=7** (cap=2) — một phần do cap, một phần do variance
- Khoảng variance ước tính: ±2-3 TPs cho AMM contest phức tạp
- ⚠️ **Cần ≥2 runs/contest** để đánh giá chính xác

### Cap=2 — Đánh giá
- ✅ Contest 42: cap=2 giúp recover từ distractor effect (0.246 → 0.271)
- ⚠️ Contest 35: cap=2 góp phần giảm TP nhưng model variance là nguyên nhân chính
- Cap=2 **không tệ** — với contest 35 avg 0.63 inj/agent, cap hầu như không kích hoạt

### Issues phát hiện trong quá trình chạy
1. **Embedding quota** — LLM1 project (`hopeful-frame-496802-g6`) có quota `textembedding-gecko` thấp → tất cả agents fail. Fix: chuyển sang LLM2 project cho embedding (`rag_retriever.py` đọc `LLM2_VERTEX_AI_KEY_FILE` ưu tiên)
2. **Peripheral contract coverage gap** — ReferralFeePoolV0, VestedRewardPool, MochiEngine.changeNFT không được agents cover. Documented: `docs/rag-plan/peripheral-contract-coverage.md`

### Việc cần làm
| Priority | Task | File |
|----------|------|------|
| High | Fix peripheral contract coverage (Option 1: mở rộng manifest secondary) | `contract_oasis_env.py` |
| High | Chạy contest 42 thêm 1 lần để xác nhận cap=2 vs baseline variance | — |
| Medium | Thử Option B (threshold 0.73) để giảm FP contest 42 | `cyber_session_orchestrator.py` |
| Low | Thêm rate limiter hoặc increase quota LLM1 project cho embedding | `rag_retriever.py` |

### Log files reference
| Run | Contest | Log |
|-----|---------|-----|
| Uncapped Run 2 (verify, f02f68e) | 35 | `/tmp/rag_nocap_35_20260519_091115.log` |
| Cap=2 (35c62ff) | 35 | `/tmp/rag_cap2_35_*.log` |
| Cap=2 (35c62ff) | 42 | `/tmp/rag_cap2_42_*.log` |
