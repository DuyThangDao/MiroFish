# Evaluation: RC Fixes (G-RC-1 → G-RC-4) — Contest 35

> Run: `35_20260427_123443` | Duration: 75 min | 0 error 429  
> Flat file: 248,342 chars (35/46 files sau khi drop interface-only)  
> Baseline so sánh: `contest35_flat_20260426_144308_20260426_160932` (Gemini 3.x, không có RC fixes)

---

## 1. Kết quả tổng quan

| Track | Baseline | RC Fixes | Delta |
|---|---|---|---|
| **L F1** | 0.000 | **0.857** | **+0.857** |
| L: TP / FP / FN | 0 / 10 / 6 | **6 / 2 / 0** | |
| **S F1** | 0.154 | **0.167** | +0.013 |
| S: TP / FP / FN | 1 / 7 / 4 | 1 / 6 / 4 | |
| **Combined F1** | 0.069 | **0.538** | **+0.469** |

**Ground truth (in-scope):** G_L=6 (tất cả L7 — unsafe cast/overflow) | G_S=5 (S3-1, S6-1, S6-3, S6-4×2) | OOS=6

---

## 2. L-track: Phân tích cải thiện đột phá (0.000 → 0.857)

### 2.1 Cơ chế matching

Eval framework dùng **lenient class-level match**:

```python
def _match_l(bug, findings):
    expected_swcs = L_TO_SWC.get(bug.label)  # L7 → {SWC-101}
    for f in findings:
        if f.source in ("consensus", "gap") and f.swc_ids & expected_swcs:
            return True  # 1 finding đúng class → tất cả bugs cùng class được tính TP
```

→ **1 finding có SWC-101 = 6 TP** (vì cả 6 GT bugs đều là L7 → SWC-101).

### 2.2 Root cause: G-RC-1 SWC tagging rules

| | Baseline | RC Fixes |
|---|---|---|
| SWC-101 trong `mitre_techniques` | **Không có** | **Có** |
| Finding với SWC-101 | — | `"Silent Truncation in Explicit Type Casting (Solidity 0.8.2)"` |
| L7 GT bugs matched | 0/6 | **6/6** |

Baseline agents nhầm lẫn: vì contest dùng Solidity 0.8.x, agents nghĩ overflow đã được compiler bảo vệ → không tag SWC-101. Tuy nhiên **explicit casting** (e.g., `uint256 → uint128`) **không được bảo vệ bởi 0.8** — vẫn là SWC-101.

G-RC-1 thêm rule này rõ ràng vào `stage1_instruction`:
> *"Solidity 0.8 chỉ protect arithmetic overflow trong unchecked scope. Explicit type casting (uint256→uint128, int256→int128) vẫn có thể truncate — vẫn là SWC-101."*

→ Agents lần này tag đúng SWC-101, matching tất cả 6 L7 bugs.

### 2.3 FP giảm từ 10 → 2

Baseline có 10 L-FP vì L-pool=10 nhưng TP=0. New run L-pool=8, TP=6 → FP=2. Pool nhỏ hơn + recall cao hơn = precision tốt hơn đáng kể (0.75 vs 0.00).

---

## 3. S-track: Cải thiện nhỏ (0.154 → 0.167)

### 3.1 TP giữ nguyên (1/5)

Finding duy nhất match: **H-03 (S3-1)** — `ConcentratedLiquidityPoolManager's incentives can be stolen` → category `state_machine_bug`.

### 3.2 Bugs bị bỏ sót (4/5 đều là S6)

| Bug | Category | Mô tả | Lý do miss |
|---|---|---|---|
| H-08 | S6-4 | Wrong `<` vs `<=` khi add/remove liquidity in range | Cần verify tick math correctness |
| H-10 | S6-3 | `burn()` wrong implementation | Logic lỗi sâu trong concentrated liquidity |
| H-11 | S6-4 | Sai `feeGrowthGlobal` khi crossing ticks | Yêu cầu hiểu Uniswap V3 fee accumulator |
| H-12 | S6-1 | `secondsPerLiquidity` không update khi pool liquidity thay đổi | Invariant phức tạp, domain-specific |

**Root cause S6 miss:** Tất cả 4 bugs là **algorithm correctness errors** trong AMM V3 math (tick-based concentrated liquidity). Để detect cần agents có thể verify implementation đúng theo Uniswap V3 whitepaper spec — vượt ngoài khả năng của intent/invariant extraction hiện tại.

### 3.3 Tại sao G-RC-3/G-RC-4 không giúp S-track nhiều hơn?

| Feature | Kết quả thực tế | Lý do không đủ |
|---|---|---|
| **G-RC-4 Intent extractor** | 0 intent statements (LLM trả về rỗng) | NatSpec của contest 35 ngắn, LLM không extract được gì hữu ích |
| **G-RC-3 Invariant extractor** | 10 invariants (9 structural + 1 LLM economic) | Invariants generated đều structural/access-control, không capture tick math |
| **G-RC-2 Contract manifest** | `primary=so` (sai) | Heuristic chọn sai primary contract |
| **G-RC-1b Dep graph** | Skipped (Slither không cài) | Không chạy được |

---

## 4. Phân tích từng feature mới

### G-RC-1: SWC Tagging Rules ✅ Hiệu quả cao

**Impact:** L F1 0.000 → 0.857. Feature có impact lớn nhất.

Cơ chế: Rule tường minh trong `stage1_instruction` giúp agents không bỏ sót SWC-101 trên Solidity 0.8.x. Trước đây agents nhầm lẫn "0.8 safe = không có overflow" → bỏ sót toàn bộ explicit cast bugs.

### G-RC-2: Contract Manifest + Focus Directive ⚠️ Lỗi heuristic

**Impact:** Không rõ (không thể tách biệt với G-RC-1).

Manifest trả ra `primary=so, secondary=['that', 'PoolDeployer', 'for']` — các token nonsensical. Heuristic scoring (LOC + class name pattern + in-degree) đang chọn sai khi contest có cấu trúc phức tạp. Cần điều tra và fix heuristic cho contest 35.

### G-RC-3: Invariant Extractor Mở rộng ⚠️ Hiệu quả hạn chế

**Impact:** Marginal — 10 invariants generated nhưng chủ yếu structural/access-control, không bắt được S6 AMM math bugs.

Vẫn thiếu invariant templates cho AMM V3 tick math cụ thể:
- `feeGrowthGlobal` phải tăng monotonically
- `secondsPerLiquidity` phải update bất cứ khi nào active liquidity thay đổi
- Tick crossing phải flip đúng chiều

### G-RC-4: Intent Extractor (S5) ❌ Không chạy hiệu quả

**Impact:** 0 intent statements extracted.

12 NatSpec hints được tìm thấy nhưng LLM trả về `intent_statements: []` — có thể do source code quá dài (248K chars, truncated tại 50K) và NatSpec của Trident pool không có đủ @notice/@dev mô tả invariants quan trọng.

### G-RC-1b: Dep Graph (Slither) ❌ Không chạy

Slither không được cài trong venv hiện tại. Feature bị skip hoàn toàn.

---

## 5. Findings chi tiết

### consensus_vulns (L-pool, 7 findings)

| Severity | Title | SWC | Match GT? |
|---|---|---|---|
| high | Cross-Function Reentrancy in flashSwap | SWC-107 | FP |
| medium | Silent Truncation in Explicit Type Casting | **SWC-101** | **→ 6 TP (L7)** |
| critical | DoS with Failed Call in `_handleFee()` | SWC-128 | FP |
| medium | Hardcoded Gas Stipend in ETH Transfers | SWC-134 | FP (không có GT) |
| high | Deterministic DOMAIN_SEPARATOR Collision | SWC-121 | FP |
| high | Missing Initializer Protection on Master | SWC-112 | FP |
| low | Hash Collision in `_calculateDomainSeparator` | SWC-133 | FP |

### semantic_results (S-pool, 7 findings)

| Severity | Title | Category | Match GT? |
|---|---|---|---|
| high | Price Manipulation via BentoBox "Donation" | price_oracle | FP |
| critical | Unauthorized Master Contract Approval | access_control | FP |
| high | Missing Slippage Protection on AMM State | business_flow | FP |
| medium | Reflexive Deleveraging Spiral | business_flow | FP |
| medium | Front-runnable Fee Expropriation | business_flow | FP |
| high | Inconsistent State Update in FlashSwap Reentrancy | state_machine_bug | FP |
| medium | Single EOA Privilege Escalation | access_control | FP |

**Lưu ý:** S-track TP (H-03: incentives stolen) không xuất hiện trực tiếp trong list này — match xảy ra qua category `state_machine_bug` overlap với S3-1.

---

## 6. Điểm yếu còn lại

1. **S6 (Algorithm Error) vẫn là blind spot**: 4/5 S-track misses đều là S6. Cần chiến lược riêng — có thể reference implementation comparison hoặc formal spec verification.

2. **G-RC-2 manifest heuristic lỗi**: `primary=so` là sai hoàn toàn. Cần xem lại logic `_compute_manifest()` với contest có nhiều contract nhỏ.

3. **Intent extractor không extract được**: 0/10 intent statements với contract 248K chars. Cần tune `max_source_chars` và NatSpec parser cho flattened multi-contract files.

4. **Slither không cài**: Dep graph hoàn toàn bị skip. Cần `uv add slither-analyzer` vào venv.

5. **FP cao trong S-pool**: 6/7 S-findings là FP → precision S = 0.143. Consensus engine cần bộ lọc S mạnh hơn.

---

## 7. So sánh với aggregate baseline (3 contests)

| | Gemini 3.x Baseline | RC Fixes (C35 only) |
|---|---|---|
| C35 L F1 | 0.000 | **0.857** |
| C35 S F1 | 0.154 | 0.167 |
| C35 Combined | 0.069 | **0.538** |
| Aggregate L F1 (C19+C03+C35) | 0.176 | TBD (C03 đang chạy) |
| Aggregate S F1 | 0.294 | TBD |

Contest 3 đang được re-run để có aggregate comparison. Kết quả sẽ được cập nhật.
