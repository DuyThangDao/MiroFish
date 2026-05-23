# Miss Analysis — Run-12 Contest 35

**Ngày:** 2026-05-23  
**Kết quả run-12:** TP=7, FP=73, FN=10 | Precision=0.087, Recall=0.412, F1=0.144  
**Mục tiêu:** TP ≥ 10, FP ≤ 30, Precision ≥ 0.25

---

## Tổng quan 3 vấn đề

| # | Vấn đề | TP tác động | FP tác động | Trạng thái |
|---|--------|:-----------:|:-----------:|:----------:|
| M1 | P1 positive filter chưa implement | 0 | **-46 FP** | Chưa làm |
| M2 | Single-hypothesis bias | **-3~4 TP** | +5 FP | Chưa làm |
| M3 | Function coverage gap | **-4~5 TP** | +5 FP | Chưa làm |

Thứ tự ưu tiên: **M1 → M3 → M2** (M1 cắt FP trước, M3 tăng TP nhiều nhất, M2 tinh chỉnh sau).

---

## M1 — P1 Positive Filter Chưa Implement

### Bằng chứng

Phân phối 79 dedup findings theo contract (run-12):

| Contract | Findings | Loại |
|----------|:--------:|------|
| ConcentratedLiquidityPool | 23 | PRIMARY |
| ConcentratedLiquidityPoolManager | 8 | PRIMARY |
| ConcentratedLiquidityPosition | 2 | PRIMARY |
| TridentRouter | 16 | **NON-TARGET → FP** |
| HybridPool | 14 | **NON-TARGET → FP** |
| IndexPool | 10 | **NON-TARGET → FP** |
| ConstantProductPool | 6 | **NON-TARGET → FP** |

**46/79 findings (58%) là về non-target contracts → tất cả FP.**

### Nguyên nhân

`_build_invariant_rag_hints` (trong `cyber_session_orchestrator.py`) không có filter — query RAG cho tất cả invariants kể cả những cái về HybridPool/IndexPool/TridentRouter. Agents nhận RAG hints về các contracts đó → sinh findings về chúng → FP tràn lan.

Giải pháp này đã được mô tả chi tiết trong [open-problems.md](open-problems.md) (mục P1) nhưng **chưa được implement**.

### Giải pháp

Thêm positive filter trong `_build_invariant_rag_hints`: chỉ query RAG cho invariants có nhắc đến ít nhất 1 contract trong `target_contracts`.

**File:** `backend/app/services/cyber_session_orchestrator.py`  
**Vị trí:** Hàm `_build_invariant_rag_hints`, vòng lặp `for i, inv in enumerate(invariants)`, trước dòng cache check.

```python
for i, inv in enumerate(invariants):
    # ── M1 FIX: positive filter ──────────────────────────────────────
    if target_contracts:
        inv_lower = inv.lower()
        if not any(c.lower() in inv_lower for c in target_contracts):
            logger.info(
                f"[RAG] agent={agent_id} inv={i+1} → skip (not about primary target)"
            )
            continue
    # ─────────────────────────────────────────────────────────────────
    # FIX-3: semantic dedup ...
    cache_key = _normalize_inv_key(inv, target_contracts or [])
```

### Expected impact

- FP: 73 → ~27 (xóa ~46 non-target findings)
- TP: không đổi (7)
- Precision: 0.087 → ~0.206

### Trade-off

- Generic invariants (không nhắc tên contract cụ thể) cũng bị skip → mất một số RAG hints
- Acceptable: generic invariants generate generic RAG patterns, signal thấp

### Độ phức tạp

**Thấp** — 5–7 lines, không thay đổi kiến trúc.

---

## M2 — Single-Hypothesis Bias

### Bằng chứng

**CLP.mint() có 5 findings, tất cả về overflow/cast:**

| Finding | Gì agent nói | H bug thực tế |
|---------|-------------|--------------|
| p_5110bf | Narrowing cast overflow | (H-05 partial) |
| p_20ee9e | Liquidity sign flip via cast | — |
| p_6510ec | Reserve overflow unchecked | H-04 ✅ |
| p_752213 | Read-only reentrancy | — |
| p_498bf9 | Reserve overflow | — |

**H-08** (wrong inequality `<=` vs `<` trong price range check) → **0 findings**. 5 agents nhìn vào mint() đều nghĩ đến overflow/cast, không ai kiểm tra logic boundary condition.

**H-12** (secondsPerLiquidity phải update TRƯỚC khi liquidity thay đổi) → 0 findings. `state_machine_analyst` có INV-4 về `secondsPerLiquidity` RAG score 0.725, được inject hint — nhưng Turn 2 vẫn viết về overflow thay vì ordering.

**Pattern chung từ eval runs 10-12:**

| H Bug | Function | Vì sao miss |
|-------|----------|------------|
| H-01 | CLP.burn | Agent thấy burn(), focus vào reserve accounting, miss int128 cast |
| H-08 | CLP.mint | 5 findings về mint nhưng không ai check boundary `<=` vs `<` |
| H-12 | CLP.mint | secondsPerLiquidity invariant có RAG hint nhưng model vẫn viết overflow |
| H-16 | CLM.claimReward | 4 findings về claimReward nhưng không ai think JIT |

### Phân tích: Prompt hiện tại đã có multi-angle instructions

Kiểm tra `contract_oasis_env.py` cho thấy Turn 2 prompt **đã có đầy đủ** tất cả những gì M2 đề xuất ban đầu:

| Angle M2 muốn thêm | Đã có trong prompt | Vị trí |
|--------------------|-------------------|--------|
| arithmetic (overflow, cast) | CAST & COMPARISON PRECISION | line 1487 |
| logic (wrong operator `<` vs `<=`) | "For every strict inequality at boundary" | line 1497 |
| ordering (state update order) | STATE UPDATE ORDERING + explicit `secondsPerLiquidity` | line 1510, 1516 |
| economic (JIT, griefing) | FINDING SPLITTING RULE — passive+active split | line 1650 |
| multi-hypothesis per function | MULTI-ANGLE EXHAUSTION | line 1641 |

**Thêm MULTI-HYPOTHESIS RULE mới = instruction thứ hai nói cùng một điều → không tăng TP, chỉ thêm nhiễu.**

### Root cause thực sự

Instruction đã có nhưng **không được apply hiệu quả** do 2 lý do cấu trúc:

**Lý do 1 — Sai vị trí trong prompt:**  
`MULTI-ANGLE EXHAUSTION` (line 1641) và `FINDING SPLITTING RULE` (line 1650) xuất hiện **sau** OUTPUT FORMAT block (line 1572). Model đọc format rules, bắt đầu viết FINDING, rồi mới gặp 2 sections này — lúc đó analysis phase đã kết thúc. Hai sections trở thành afterthought, bị áp dụng hời hợt hoặc bỏ qua hoàn toàn.

**Lý do 2 — STATE UPDATE ORDERING không bắt buộc trace từng dòng:**  
Với H-12, model đọc "check EVERY function modifies 2+ state variables" → nhìn vào mint() → high-level reasoning "có vẻ đúng" → không có FINDING. Model không bị buộc phải liệt kê thứ tự thực thi từng dòng → dễ bị sai về ordering trong source code phức tạp.

### Giải pháp điều chỉnh — 2 fixes cấu trúc

**Fix 2a — Di chuyển vị trí:**  
Chuyển `MULTI-ANGLE EXHAUSTION` và `FINDING SPLITTING RULE` lên **trước** OUTPUT FORMAT block. Hai sections này cần được apply trong analysis phase, không phải sau khi model đã viết findings xong.

**Fix 2b — Bắt buộc trace từng dòng trong STATE UPDATE ORDERING:**  
Thêm bước mandatory line-by-line trace:

```
For every function flagged by STATE UPDATE ORDERING:
  Step 1: List ALL state-modifying lines IN ORDER as they appear in the function body.
          Format: line_content → modifies: <variable>
  Step 2: For each accumulator (secondsPerLiquidity, feeGrowthInside, rewardPerShare,
          rewardDebt): does any READ of it appear AFTER the denominator it depends on
          (liquidity, totalShares, totalSupply) has been modified?
  If YES → write FINDING with EVIDENCE: SEQ:
```

### Expected impact sau 2 fixes

- **TP: +1–2** (H-12 ordering có thể được catch với trace bắt buộc; H-16 JIT có thể được catch với FINDING SPLITTING RULE xuất hiện sớm hơn)
- **FP: +2–5** (nhỏ — không thêm instruction mới, chỉ tái cấu trúc và làm rõ existing sections)
- **Không có nguy cơ giảm TP** — chỉ thay đổi vị trí và làm rõ, không xóa nội dung

### Trade-off

| | Fix 2a (vị trí) | Fix 2b (trace bắt buộc) |
|-|:--------------:|:----------------------:|
| TP gain ước tính | +0–1 (H-16 JIT) | +1–2 (H-12 ordering) |
| FP tăng | +1–3 | +1–3 |
| Độ phức tạp | Thấp — cut/paste | Thấp — thêm 8–10 lines |
| Rủi ro | Rất thấp | Thấp |

### Độ phức tạp

**Thấp** — Fix 2a là reorder đoạn text trong prompt. Fix 2b thêm 8–10 lines vào STATE UPDATE ORDERING section.

---

## M3 — Function Coverage Gap

### Bằng chứng

6 H bugs hoàn toàn không có bất kỳ findings nào (0 T1 + 0 T2 candidates):

| H Bug | Function | Root cause | Lý do bị bỏ qua |
|-------|----------|-----------|-----------------|
| H-03 | CLM.reclaimIncentive | Incentives bị drain bởi owner | Không phải top-level fn thường được inspect |
| H-09 | CLP.rangeFeeGrowth | Underflow khóa pool vĩnh viễn | Helper function, không được agents target |
| H-11 | Ticks.cross | feeGrowthGlobal accounting sai | Library function trong file riêng |
| H-14 | CLP.rangeFeeGrowth | rangeFeeGrowth + secondsPerLiquidity sai | Cùng helper bị bỏ qua như H-09 |
| H-15 | CLP.initialize | initialPrice không validate với tick | Init function, agents không focus |
| H-17 | CLP.rangeFeeGrowth | nearestTick không phù hợp làm reference | Cùng helper như H-09 |

**3 trong 6 bugs ở cùng 1 function: `rangeFeeGrowth`** — helper function tính fee growth trong range. Agents không bao giờ target function này.

### Nguyên nhân gốc

Turn 2 prompt hướng agents tập trung vào functions từ Turn 1 invariants. Invariants thường về các operations chính (mint/burn/swap/collect). `rangeFeeGrowth`, `Ticks.cross`, `initialize` không xuất hiện trong invariants → không được inspect trong Turn 2.

Thêm vào đó, Turn 1 `core_question` của mỗi agent hỏi về "operation sequences" — theo đó model suy nghĩ về flow chính, bỏ qua helper functions.

### Giải pháp

Thêm section **SECONDARY FUNCTION SWEEP** vào Turn 2 prompt — buộc agents phải inspect một danh sách functions cụ thể nằm ngoài main operations:

**File:** `backend/app/services/contract_oasis_env.py`  
**Vị trí:** Sau PARAMETER PROPAGATION section, trước "Write ALL findings".

```
SECONDARY FUNCTION SWEEP:
After analyzing main operations, explicitly inspect these function categories:
  - Initialization functions (initialize, constructor, setUp): validate all input parameters
    against contract state constraints (tick bounds, price ranges, hard-coded limits).
  - Helper/view functions used in reward/fee calculations (rangeFeeGrowth, getAmounts,
    computeStep): check for underflow, wrong variable order, stale data usage.
  - Library functions called during tick/position updates (cross, update, tock):
    verify fee growth indices are assigned correctly (not swapped).
  - Admin/reclaim functions (reclaimIncentive, withdraw, skim): check access control
    and whether caller can drain funds belonging to other users.
For each function in these categories: write a FINDING if you find any violation,
or skip explicitly ("CHECKED: <fn> — no issue") if safe.
```

### Expected impact

- TP: +3–4 (H-03, H-09/H-14, H-11, H-15/H-17)
- FP: +5–8 (thêm functions được inspect → thêm false alarms)

### Trade-off

- Prompt dài hơn (~15 lines) → token cost tăng nhẹ
- "CHECKED: fn — no issue" instruction tạo overhead output nhưng tránh model skip silently
- Có thể bị model over-apply: inspect quá nhiều helper functions → noise tăng

### Độ phức tạp

**Trung bình** — cần balance giữa "đủ specific để model hiểu" và "không quá dài gây attention dilute".

---

## Roadmap Triển Khai

```
M1 (positive filter RAG) ← ĐÃ IMPLEMENT
  → Run-13 → Verify FP giảm ~16, TP không đổi

M3 (Secondary function sweep)
  → Implement → Run-14 → Verify TP tăng +3-4

M2 — Fix 2a (reorder MULTI-ANGLE EXHAUSTION + FINDING SPLITTING RULE)
  → Implement cùng M3 hoặc sau → Run-15 → Verify H-16 JIT catch rate

M2 — Fix 2b (STATE UPDATE ORDERING trace bắt buộc)
  → Implement sau 2a → Run-16 → Verify H-12 ordering catch rate
```

**Chú thích quan trọng về FP:**  
M1 chỉ giảm ~16 FP (IndexPool + ConstantProductPool). TridentRouter (16) + HybridPool (14) vẫn còn trong `_tc` → vẫn sinh FP. FP sau M1 ước tính ~57, không phải ~27.

**Target sau tất cả fixes:**

| Metric | Hiện tại (run-12) | Sau M1 (ước tính) | Target sau M1+M2+M3 |
|--------|:-----------------:|:-----------------:|:-------------------:|
| TP | 7 | 7 | 10–12 |
| FP | 73 | ~57 | 35–45 |
| Precision | 0.087 | ~0.11 | 0.20–0.27 |
| Recall | 0.412 | 0.412 | 0.59–0.71 |
| F1 | 0.144 | ~0.18 | 0.30–0.38 |

---

---

## M4 — Hypothesis Generation Bias (Post Run-13)

**Cập nhật sau run-13 (TP=10):** M1+M2+M3 đã fix các bugs bị miss do function coverage gap và instruction ordering. Remaining misses (H-06, H-16) có pattern khác: agents **tìm đúng function** nhưng **generate sai vulnerability class**.

### H-06 — Double Yield trong `CLPosition.collect()`

**Bằng chứng:** 3 candidates cho `collect()` trong run-13, tất cả về DoS/unchecked arithmetic. Bug thực: `tokensOwed0/1` không được zero trước transfer → gọi lại nhiều lần → nhận double fee.

**Root cause:** Agents bị kéo sang "arithmetic overflow" pattern (do RAG hints về unchecked math) thay vì nhận ra CEI violation.

**Giải pháp — Thêm CEI CHECK FOR CLAIM FUNCTIONS:**
```
CEI CHECK FOR CLAIM FUNCTIONS:
For every function that transfers tokens to a user based on an
internal accounting variable (tokensOwed, rewardsAccrued, fees, yield):
  Step 1: Does the function zero/decrement the accounting variable
          BEFORE making the external transfer?
  Step 2: If the variable is decremented AFTER the transfer (or not at all):
          → User can call again before state updates → double-claim.
  EVIDENCE: CODE: <transfer line> followed by <state update line>
  OUTCOME: user receives 2× entitled amount
```

**Đặc điểm:** Generic — áp dụng cho lending, farming, fee collection, staking. Không hardcode CLP. FP risk thấp vì chỉ trigger khi có state-after-transfer pattern rõ ràng.

**Vị trí insert:** Trong Turn 2 prompt, sau STATE UPDATE ORDERING, trước CROSS-CALL SEQUENCING.

---

### H-16 — JIT Liquidity Attack trên `CLM.claimReward()`

**Bằng chứng:** 2 candidates cho `claimReward()` trong run-13, đều về wrong mapping index và math error. Bug thực: attacker add large liquidity ngay trước reward snapshot, remove sau → nhận reward không tương xứng với thời gian provide.

**Root cause:** Agents không biết JIT attack vector — cần domain knowledge về time-weighted reward accumulation. Không phải context issue.

**Giải pháp — Thêm JIT LIQUIDITY ATTACK pattern vào FINDING SPLITTING RULE:**
```
JIT LIQUIDITY ECONOMIC ATTACK:
For every reward/incentive distribution function that uses
time-weighted metrics (secondsPerLiquidity, rewardsPerShare,
accumulated rewards per block/second):
  Q1: Can an attacker add large liquidity in the SAME block/tx as
      the reward snapshot or claim trigger?
  Q2: Is there a minimum time requirement or lock period before
      claiming?
  If Q1=YES and Q2=NO → JIT attack: attacker captures
  disproportionate rewards with near-zero capital commitment.
  ATTACK_PATH ACTOR: attacker / CALL: mint() → claimReward() → burn()
    in sequence / OUTCOME: attacker drains reward pool
```

**Đặc điểm:** Specific hơn H-06 fix — chỉ áp dụng cho AMM/farming protocols với time-weighted rewards. FP risk trung bình (cần model hiểu "cùng block/tx" semantic). Cân nhắc kỹ trước khi add để tránh noise trên contests không có AMM.

**Vị trí insert:** Trong FINDING SPLITTING RULE block, sau passive/active attack split.

---

### Trade-off tổng hợp M4

| Fix | TP gain | FP risk | Generic | Độ phức tạp |
|-----|:-------:|:-------:|:-------:|:-----------:|
| CEI claim check (H-06) | +1 | Thấp | Cao | Thấp |
| JIT pattern (H-16) | +1 | Trung bình | Thấp | Trung bình |

**Thứ tự ưu tiên:** CEI check trước (generic, low risk), JIT sau khi verify CEI không tăng FP quá nhiều.

---

## Xem thêm

- [open-problems.md](open-problems.md) — P1–P5 từ session trước (P1/P5 overlap với M1)
- [rag-pipeline-diagnosis.md](rag-pipeline-diagnosis.md) — RAG coverage analysis và skepticism gate
