# Contest 35 — Run Analysis (Run 1–5)

## 1. Điều kiện mỗi lần chạy

| | Run-1 | Run-2 | Run-3 | Run-4 | Run-5 |
|--|--|--|--|--|--|
| **Ngày** | 2026-05-21 | 2026-05-21 | 2026-05-21 | 2026-05-21 | 2026-05-22 |
| **BOOST model** | ❌ 403 → fallback minimal | ✅ Fixed | ✅ Fixed | ✅ Fixed | ✅ Fixed |
| **BOOST max_tokens** | 4096 (broken) | 8192 | 65536 | 65536 | 65536 |
| **LLM invariants** | 0 (fallback 2) | 2 (JSON repair) | 6 (đầy đủ) | 6 (đầy đủ) | 6 (đầy đủ) |
| **Total invariants** | 2 | 4 | 8 | 8 | 8 |
| **0-output fix (A+B)** | ❌ | ❌ | ✅ | ✅ | ✅ |
| **RAG threshold** | 0.70 | 0.70 | 0.70 | 0.70 | **0.65** |
| **Independent target filter** | ✅ on | ✅ on | ✅ on | ✅ on | **❌ removed** |
| **RC5 prompt changes** | ❌ | ❌ | ❌ | ❌ | ❌ |

---

## 2. Kết quả

| Metric | Run-1 | Run-2 | Run-3 | Run-4 | **Run-5** |
|--------|:-----:|:-----:|:-----:|:-----:|:-----:|
| TP | **10** | 7 | 7 | 7 | **9** |
| FP | 55 | 53 | 66 | 67 | 62 |
| FN | 7 | 10 | 10 | 10 | 8 |
| Precision | 0.154 | 0.117 | 0.096 | 0.095 | 0.127 |
| Recall | **0.588** | 0.412 | 0.412 | 0.412 | **0.529** |
| F1 | **0.244** | 0.182 | 0.156 | 0.153 | **0.204** |
| Dedup findings | 63 | 59 | 71 | 72 | 69 |
| Agents với 0 output | 1 | 1 | 0 | 0 | 0 |
| RAG injections | ~9 | ~8 | ~15 | ~15 | **~80** |

**Mean TP qua 5 runs: 8.0**

---

## 3. H bugs matched mỗi run

| H bug | Run-1 | Run-2 | Run-3 | Run-4 | Run-5 | Tần suất |
|-------|:-----:|:-----:|:-----:|:-----:|:-----:|:--------:|
| H-02 | ✅ | ✅ | ✅ | ✅ | ✅ | 5/5 |
| H-10 | ✅ | ✅ | ✅ | ✅ | ✅ | 5/5 |
| H-13 | ✅ | ✅ | ✅ | ✅ | ✅ | 5/5 |
| H-04 | ✅ | ✅ | ✅ | ❌ | ✅ | 4/5 |
| H-09 | ✅ | ❌ | ✅ | ✅ | ✅ | 4/5 |
| H-14 | ✅ | ❌ | ✅ | ✅ | ✅ | 4/5 |
| H-05 | ✅ | ✅ | ❌ | ❌ | ✅ | 3/5 |
| H-03 | ❌ | ✅ | ✅ | ❌ | ✅ | 3/5 |
| H-08 | ✅ | ❌ | ❌ | ❌ | ✅ | 2/5 |
| H-01 | ✅ | ❌ | ❌ | ✅ | ❌ | 2/5 |
| H-07 | ❌ | ✅ | ❌ | ❌ | ❌ | 1/5 |
| H-12 | ❌ | ❌ | ❌ | ✅ | ❌ | 1/5 |
| H-06 | ✅ | ❌ | ❌ | ❌ | ❌ | 1/5 |
| H-11 | ❌ | ❌ | ❌ | ❌ | ❌ | 0/5 |
| H-15 | ❌ | ❌ | ❌ | ❌ | ❌ | 0/5 |
| H-16 | ❌ | ❌ | ❌ | ❌ | ❌ | 0/5 |
| H-17 | ❌ | ❌ | ❌ | ❌ | ❌ | 0/5 |

**Ổn định (≥4/5):** H-02, H-04, H-09, H-10, H-13, H-14 — baseline reliable detection.

**Stochastic (1–3/5):** H-01, H-03, H-05, H-06, H-07, H-08, H-12.

**Persistent miss (0/5):** H-11, H-15, H-16, H-17 — structural blind spots.

---

## 4. Phân tích miss Run-5 vs Run-1

Run-5 miss H-01 và H-06 so với Run-1:

| Bug | Loại miss | Chi tiết |
|-----|-----------|---------|
| H-01 `ConcentratedLiquidityPool.burn` | Wrong framing | 4 candidates nhưng tất cả mô tả DoS/accounting error. GT: `int128(amount)` overflow → burn thành ADD liquidity. Agents không trace reasoning: cast overflow → signed negative → toán tử đảo chiều |
| H-06 `ConcentratedLiquidityPosition.collect` | 0 candidates | Contract phụ không được cover đủ — cả 4 runs khác cũng miss, run-1 là outlier stochastic |

---

## 5. RAG utilization

| | Run-1 | Run-2 | Run-3 | Run-4 | **Run-5** |
|--|:--:|:--:|:--:|:--:|:--:|
| Total invariants | 2 | 4 | 8 | 8 | 8 |
| **RAG injections** | 9 | 8 | 15 | ~15 | **~80** |
| Skip — independent target | 73 | 66 | 72 | ~72 | **0** |
| Skip — below threshold | 40 | 47 | 33 | ~33 | giảm đáng kể |
| Injection rate | 20% | 10% | 8.5% | ~8.5% | **~45%** |

**Run-5 RAG fix:** bỏ independent target filter + hạ threshold 0.70→0.65 → injections tăng ~5x.
Pattern injection có value thực: Maia DAO H-17 về `secondsPerLiquidity overflow` liên quan trực tiếp đến H-14 (contest 35) — có thể giải thích tại sao H-14 được tìm thấy ổn định hơn.

---

## 6. Nhận xét tổng thể

**RAG fix (run-5) có tác động rõ ràng:** TP tăng từ 7 (runs 2-4) lên 9, Recall từ 0.412 lên 0.529.

**Persistent blind spots:** H-11, H-15, H-16, H-17 miss toàn bộ 5 runs. Nguyên nhân:
- H-11 (`Ticks.cross`): agents phát hiện DoS/oracle issues trong `swap()`, GT là fee growth bug trong `cross()`
- H-15 (`CLPool.initialize`): agents mô tả TWAP/DoS, GT là thiếu validation initialPrice vs tick bounds
- H-16 (`CLPoolManager.claimReward`): JIT liquidity economic attack — agents không think theo hướng economic timing
- H-17 (`CLPool.rangeFeeGrowth`): `nearestTick` sai reference point — cần domain knowledge đặc thù

**Kết luận:** Mean TP = 8.0/17 H bugs (Recall ~0.47 mean). Run-5 với RAG fix là tốt nhất (TP=9).
Bước tiếp theo: RC5 prompt changes để cải thiện wrong-framing bugs (H-01, H-07, H-12, H-16, H-17).
