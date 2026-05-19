# RAG Injection Cap=2 — Evaluation Report

**Date:** 2026-05-19  
**Change:** `_MAX_RAG_INJECT_PER_AGENT = 2` (top-2 by score, threshold 0.70 giữ nguyên)  
**Embedding:** Chuyển sang LLM2 project (`erudite-flag-495707-n5`) do LLM1 project quota thấp

---

## Kết quả tổng hợp

| Contest | Protocol | Baseline (Phase 5, no cap) | Cap=2 | Delta |
|---------|----------|---------------------------|-------|-------|
| **35** | AMM (ConcentratedLiquidityPool) | TP=13, FP=49, F1=**0.329** | TP=7, FP=61, F1=**0.165** | **-0.164** |
| **42** | Lending (MochiVault) | TP=8, FP=32, F1=**0.302** | TP=8, FP=38, F1=**0.271** | **-0.031** |

> **Baseline** = Phase 5 invariant RAG với Spearbit findings, chưa có cap.  
> Contest 35 baseline F1=0.329 là run có Spearbit (uncapped, avg ~0.9 inj/agent).  
> Contest 42 baseline F1=0.302 là run Phase 5 trước khi thêm Spearbit.

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

### Metrics
| Metric | Uncapped Spearbit | Cap=2 |
|--------|-----------------|-------|
| TP | 13 | **7** |
| FP | 49 | **61** |
| FN | 4 | **10** |
| F1 | 0.329 | **0.165** |
| Duration | — | 34m43s |

### RAG Injection Pattern
- **19/19 agents hoàn thành** (0 agent fail)
- **12 hints injected** / 116 total INV queries
- **104 skipped** (score < 0.70)
- `rag_calls` distribution: 8 agents×0, 10 agents×1, 1 agent×2 → **avg 0.63/agent**
- Cap=2 ít tác động: phần lớn agents chỉ có 0-1 INV pass threshold

### TP Matched (7)
| H-bug | Finding | Method |
|-------|---------|--------|
| H-01 | Inverse Cast Overflow in Burn | T1 |
| H-02 | Incorrect Incentive Lookup via positionId | T1 |
| H-03 | Incentive Token Drain via Missing Decrement | T1 |
| H-04 | ConcentratedLiquidityPool reserve overflow | T1 |
| H-06 | ConcentratedLiquidityPosition double-collect | T1 |
| H-10 | Critical Accounting Bug: Missing reserve subtract | T1 |
| H-13 | Critical Accounting Bug: Missing reserve subtract | T1 |

### TP Missing so với run trước (6 bugs bị mất)
| H-bug | Trước (uncapped) | Sau (cap=2) | Ghi chú |
|-------|-----------------|-------------|---------|
| H-08 | ✅ Strict Boundary Inequality | ❌ miss | Boundary condition |
| H-09 | ✅ Fee Growth Accumulator Revert | ❌ miss | unchecked arithmetic |
| H-12 | ✅ Stale secondsPerLiquidity | ❌ miss | State update ordering |
| H-14 | ✅ Fee Growth Accumulator Revert | ❌ miss | unchecked arithmetic |
| H-16 | ✅ JIT Liquidity attack | ❌ miss | Economic exploit |
| H-07 | ✅ Fee Accounting Desync | ❌ miss | Wrong burn recipient |

### RAG Hints tiêu biểu injected
- `ConcentratedLiquidityPoolManager.rewardsUnclaimed` (score 0.703) → inject vào apps_defensive
- `nearestTick` constraint (score 0.712) → inject vào bloc_auditor
- `HybridPool` StableSwap invariant D (score 0.704-0.735) → inject vào defi agents

### Nhận xét
**Regression lớn: F1 0.329 → 0.165 (-0.164).**  
Tuy nhiên cap=2 KHÔNG phải nguyên nhân chính vì:
- Avg injection chỉ 0.63/agent (thấp hơn uncapped ~0.9/agent không nhiều)
- Cap=2 hầu như không thay đổi behavior với contest 35

**Nguyên nhân khả năng cao: model variance.**  
AMM bugs (fee growth underflow, secondsPerLiquidity ordering, unchecked overflow) yêu cầu reasoning chính xác về LP math phức tạp. Single-run variance cao với contest này.

---

## Kết luận & Hướng tiếp theo

### Cap=2 — Đánh giá
- ✅ Contest 42: cap=2 giúp reduce distractor effect (0.246 → 0.271)
- ❌ Contest 35: cap=2 không giải thích được regression (model variance)
- ⚠️ **Cần ≥2 runs/contest** để đánh giá chính xác do model variance cao

### Issues phát hiện trong quá trình chạy
1. **Embedding quota** — LLM1 project (`hopeful-frame-496802-g6`) có quota `textembedding-gecko` thấp → tất cả agents fail. Fix: chuyển sang LLM2 project cho embedding (`rag_retriever.py` đọc `LLM2_VERTEX_AI_KEY_FILE` ưu tiên)
2. **Peripheral contract coverage gap** — ReferralFeePoolV0, VestedRewardPool, MochiEngine.changeNFT không được agents cover. Documented: `docs/rag-plan/peripheral-contract-coverage.md`

### Việc cần làm
| Priority | Task | File |
|----------|------|------|
| High | Chạy thêm run contest 35 để xác nhận variance | — |
| High | Fix peripheral contract coverage (Option 1: mở rộng manifest secondary) | `contract_oasis_env.py` |
| Medium | Thử Option B (threshold 0.73) nếu FP vẫn cao | `cyber_session_orchestrator.py` |
| Low | Thêm rate limiter hoặc increase quota LLM1 project cho embedding | `rag_retriever.py` |
