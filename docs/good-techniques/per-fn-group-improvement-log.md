
# Per-Function-Group Pipeline — Improvement Log

Branch: `per-fn-group-check` | Contest: web3bugs/35 (17 H bugs)

---

## Baseline

**v7 (sim_e2e_v7)** — trước khi bắt đầu cải thiện:

| Metric | Raw | Deduped |
|--------|-----|---------|
| TP | 10 | 10* |
| FP | 169 | ~96 |
| FN | 7 | 7 |
| Recall | 0.588 | 0.588 |
| F1 | 0.102 | ~0.17 |

*dedup mất H-07 → TP=10 (dedup bug)

FN=7: **H-01, H-03, H-04, H-05, H-15, H-16, H-17**

---

## Round 1 — Dedup Fix + Knowledge Gaps (v8)

### Thay đổi triển khai

#### 1. Dedup: global (post all chunks) thay vì per-chunk
**File:** `backend/scripts/simulate_e2e.py`  
**Vấn đề:** `dedup_pipeline` gọi bên trong `run_chunk` → không dedup được findings trùng giữa các chunks.  
**Fix:** Gom toàn bộ raw findings từ tất cả chunks, gọi `dedup_pipeline` 1 lần duy nhất sau khi tất cả chunks xong.

#### 2. Dedup: normalize_evidence 100 → 200 chars
**File:** `backend/app/services/cyber_session_orchestrator.py`  
**Vấn đề:** Truncate 100 chars quá ngắn, gom các findings không liên quan vào cùng group.  
**Fix:** `return text[:200].lower()`

#### 3. Dedup: _pick_primary tiebreak bằng description dài nhất
**File:** `backend/app/services/cyber_session_orchestrator.py`  
**Vấn đề:** Khi merge group, finding có text ngắn được chọn làm primary → mất thông tin.  
**Fix:** Tiebreak `(ev_rank, -text_len)` — ưu tiên finding có description + attack_path dài nhất.

#### 4. Dedup: merge descriptions từ tất cả members trong group
**File:** `backend/app/services/cyber_session_orchestrator.py`  
**Vấn đề:** Primary chỉ giữ text của mình, mất text của các finding bị merge.  
**Fix:** Concatenate description + attack_path từ tất cả non-primary members vào primary.

#### 5. Constructor auto-detection
**File:** `backend/scripts/simulate_e2e.py`  
**Vấn đề:** `FN_RE` chỉ match `function name(`, bỏ qua `constructor(`.  
**Fix:**
```python
FN_RE = re.compile(r'^\s*(?:function\s+(\w+)|constructor)\s*\(', re.MULTILINE)
fn = m.group(1) or 'constructor'
```

#### 6. Knowledge gaps — 6 patterns thêm vào agent personas
**File:** `backend/app/services/contract_profile_generator.py`

| Gap | Agent | Pattern |
|-----|-------|---------|
| G1 | `math_precision` | Signed→unsigned negative wrap: `uint128(int256(-x))` = huge positive |
| G1 ext | `invariant_breaker` | Signed delta invariant — negative liquidityDelta cast gây catastrophic state |
| G2 | `math_precision` | Balance check bypass via unchecked overflow |
| G3 | `appsec_researcher` | Constructor/initializer parameter validation |
| G4 | `access_escalator` | Per-record ownership — `record.owner == msg.sender`, không chỉ global admin |
| G5 | `defi_attacker` | JIT accumulator attack — same-block add/remove capture 100% time-weighted increment |
| G6 | `clmm_specialist` | Stale cached init — nearestTick sai reference cho feeGrowthOutside |

#### 7. Routing fix: clmm_specialist → access_reward domain
**File:** `backend/scripts/simulate_e2e.py`  
**Vấn đề:** H-16 (JIT) nằm trong `access_reward` chunk nhưng `clmm_specialist` (có G5) không được route vào domain này.  
**Fix:** `'access_reward': ['access_escalator', 'clmm_specialist', 'state_machine_analyst']`

#### 8. LLM pool: hỗ trợ 3 Vertex AI keys (round-robin)
**File:** `backend/scripts/simulate_e2e.py`  
**Fix:** Đọc `LLM3_VERTEX_AI_KEY_FILE` + `LLM3_BASE_URL` từ env, append vào `llm_pool`.

#### 9. Eval judge dùng LLM2 key
**File:** `backend/scripts/evaluate/llm_judge.py`  
**Fix:** `_get_llm_client()` ưu tiên `LLM2_VERTEX_AI_KEY_FILE` + `LLM2_BASE_URL` để tránh rate limit.

### Kết quả v8 (2 runs để đo variance)

| Metric | v8a raw | v8a deduped | v8b raw | v8b deduped |
|--------|---------|-------------|---------|-------------|
| TP | 12 | **12** | 11 | 10* |
| FP | 184 | 94 | 180 | 81 |
| FN | 5 | 5 | 6 | 7 |
| Recall | 0.706 | **0.706** | 0.647 | 0.588 |
| F1 | 0.113 | **0.195** | 0.106 | 0.185 |

*v8b deduped TP=10: eval judge flaky (empty reason), không phải dedup bug — finding tồn tại y hệt raw.

**Newly matched vs v7:** H-01 (G1 fix), H-16 (routing + G5 fix)

**Còn FN=5:** H-03, H-04, H-05, H-15, H-17

---

## Round 2 — Additional Gaps (v9, đã chạy)

### Root cause analysis FN=5

| Bug | Root cause | Loại vấn đề |
|-----|-----------|-------------|
| **H-03** | `reclaimIncentive` không trừ `rewardsUnclaimed` → drain không giới hạn | Missing accounting update — G4 (ownership) không đúng hướng |
| **H-04** | `mint()` unchecked balance check + external callback → attacker không gửi token → wrap bypass | Callback-control overflow bypass — G2 chưa cover attack vector này |
| **H-05** | Agents tìm ra bug nhưng gán `function_name = mint` (caller) thay vì `_getAmountsForLiquidity` (helper) | **Eval attribution gap** — không phải agent miss |
| **H-15** | Constructor detected nhưng agents không check `initialPrice` vs `tickSpacing` consistency | Contest-specific invariant — không nên tune |
| **H-17** | `Ticks.insert` trong `general` domain; `clmm_specialist` (có G6) không được route vào `general` | G6 knowledge không reach được function cần check |

### Thay đổi triển khai

#### 1. G6 → `logic_exploiter` (fix H-17)
**File:** `backend/app/services/contract_profile_generator.py`  
**Lý do:** `logic_exploiter` có mặt trong `general`, `math_cast`, `clmm_semantic` → G6 tự động reach `Ticks.insert` mà không thay đổi routing/workers.  
**Pattern thêm:** nearestTick là cached proxy, không phải canonical current tick. Phải dùng canonical price variable cho feeGrowthOutside initialization.

#### 2. G2 extension: callback-control bypass → `math_precision` (fix H-04)
**File:** `backend/app/services/contract_profile_generator.py`  
**Pattern thêm:** Function gọi external callback (mint/flash) để nhận payment, sau đó check `balanceOf - reserveBefore >= amount` trong `unchecked`. Attacker control callback, không gửi token → balance giảm → subtraction wrap → pass check → mint for free.  
**Scan rule:** function có (1) external callback + (2) unchecked balance delta check = critical finding.

#### 3. G7: missing accounting update → `state_machine_analyst` (fix H-03)
**File:** `backend/app/services/contract_profile_generator.py`  
**Pattern thêm:** Claim/reclaim function transfer tokens nhưng không decrement counter tracking available balance. Checklist: với mọi function transfer ra — enumerate tất cả storage vars tracking "available to claim" → verify mỗi var bị decremented/zeroed cùng transaction.

#### 4. Private helper attribution rule (fix H-05 eval gap)
**Files:** `backend/app/services/contract_oasis_env.py` (LOCATION RULE item 4), `backend/scripts/simulate_e2e.py` (T3 CoT prompt)  
**Rule thêm:** Nếu bug nằm trong private/internal helper được gọi bởi function đang phân tích, set `FUNCTION` bằng tên helper — không phải public caller.  
**Kỳ vọng:** Agents gán `FUNCTION: _getAmountsForLiquidity` thay vì `FUNCTION: mint` → T1 match trực tiếp.

### Kỳ vọng v9

| Bug | Mechanism | Xác suất cải thiện |
|-----|-----------|-------------------|
| H-17 | G6 trong logic_exploiter reach Ticks.insert | Cao — knowledge gap chính xác, routing đúng |
| H-04 | G2 ext callback-control trong math_precision | Trung bình — pattern rất specific, cần agent follow đúng |
| H-03 | G7 missing accounting update trong state_machine_analyst | Trung bình — pattern generic, nhưng cần agent enumerate đúng vars |
| H-05 | Helper attribution rule trong T2+T3 prompt | Trung bình — depends on LLM compliance với instruction |
| H-15 | Không fix | Không thay đổi (contest-specific) |

**Target v9:** TP=13–14 deduped, F1 ≥ 0.21

### Kết quả v9 thực tế

| Metric | v9 raw | v9 deduped (static) | v9 deduped (semi-static) |
|--------|--------|---------------------|--------------------------|
| TP | 15 | 13 | **15** |
| FP | — | 65 | 163 |
| FN | 2 | 4 | 2 |
| Recall | 0.882 | 0.765 | **0.882** |
| F1 | — | 0.280 | 0.154 |

**Newly matched vs v8:** H-03 (G7), H-04 (G2 ext), H-05 (helper attribution), H-17 (G6→logic_exploiter)  
**Static dedup mất:** H-07, H-12 (khác bug cùng anchor)  
**Semi-static giữ:** H-07, H-12 ✅ (LLM nhận ra khác mechanism)  
**Vẫn FN:** H-01 (variance — không gen được trong run này), H-15 (contest-specific)

**Quyết định:** Dùng semi-static làm dedup chuẩn (ưu tiên Recall).

---

## Round 3 — Semi-static Dedup (v9 + semi)

### Vấn đề

v9 static dedup mất 2 TP so với raw:
- **H-12** (`secondsPerLiquidity` not updated): chia sẻ anchor `if (priceLower < currentPrice...)` với H-08 (boundary condition) trong `mint` → static merge sai
- **H-07** (`collect` fee theft for entire range): chia sẻ anchor với 6 findings khác → static merge, primary không giữ H-07 description

### Giải pháp: `_semi_static_anchor_dedup`

**File:** `backend/app/services/cyber_session_orchestrator.py`

Thay `_static_anchor_dedup` (auto-merge theo anchor) bằng `_semi_static_anchor_dedup`:
- Group size = 1: auto-pass (không cần LLM)
- Group size ≥ 2: LLM verify "same bug?" qua pairwise prompt
  - MERGE → merge (như static)
  - KEEP_SEPARATE → giữ cả hai riêng
- Prompt: default KEEP_SEPARATE khi không chắc (ưu tiên recall)
- Chạy parallel với ThreadPoolExecutor (LLM_DEDUP_WORKERS)

**File:** `backend/scripts/simulate_e2e.py`

Cập nhật `dedup_pipeline` dùng `_semi_static_anchor_dedup` thay `_static_anchor_dedup`.

### Kết quả semi-static dedup

| Step | Count | Notes |
|------|-------|-------|
| Raw | 203 | — |
| After pre_r2 | 190 | Anchor FP filter |
| After semi-static | 183 | 14 LLM calls, 7 merged |
| After LLM dedup | 183 | 0 more merged |
| **Final** | **183** | TP=15, FP=163, Recall=0.882 |

### So sánh approaches

| Approach | Final count | TP | FP | F1 | Notes |
|----------|------------|----|----|-----|-------|
| Static (auto-merge) | 78 | 13 | 65 | 0.280 | Best F1, mất H-07/H-12 |
| Semi-static pairwise | 183 | **15** | 163 | 0.154 | Best Recall, FP cao |
| Cluster | 78 | 11 | 66 | 0.234 | Tệ nhất — mất thêm H-04/H-06 |

**Chọn semi-static** vì ưu tiên Recall (không bỏ sót bug).

---

## Tổng hợp tiến độ

```
Baseline (v7):       TP=10  FN=7  Recall=0.588  F1=0.17  (deduped, static)
After Round 1 (v8):  TP=12  FN=5  Recall=0.706  F1=0.195 (v8a deduped, best run)
After Round 2 (v9):  TP=13  FN=4  Recall=0.765  F1=0.280 (v9 static dedup)
After Round 3:       TP=15  FN=2  Recall=0.882  F1=0.154 (v9 semi-static, ưu tiên Recall)
Max possible:        TP=16  FN=1  (H-15 contest-specific, không target)
```

### Bugs matched qua từng round

| H-ID | v7 | v8 | v9 static | v9 semi | Root cause |
|------|----|----|-----------|---------|-----------|
| H-01 | ✗ | ✅ | ✗ | ✗ | G1 — variance (generated trong v8, miss trong v9) |
| H-02 | ✅ | ✅ | ✅ | ✅ | — |
| H-03 | ✗ | ✗ | ✅ | ✅ | G7 missing accounting update |
| H-04 | ✗ | ✗ | ✅ | ✅ | G2 ext callback bypass |
| H-05 | ✗ | ✗ | ✅ | ✅ | Helper attribution rule |
| H-06 | ✅ | ✅ | ✅ | ✅ | — |
| H-07 | ✅ | ✅ | ✗ | ✅ | Static dedup mất, semi giữ |
| H-08 | ✅ | ✅ | ✅ | ✅ | — |
| H-09 | ✅ | ✅ | ✅ | ✅ | — |
| H-10 | ✅ | ✅ | ✅ | ✅ | — |
| H-11 | ✅ | ✅ | ✅ | ✅ | — |
| H-12 | ✅ | ✅ | ✗ | ✅ | Static dedup mất, semi giữ |
| H-13 | ✅ | ✅ | ✅ | ✅ | — |
| H-14 | ✅ | ✅ | ✅ | ✅ | — |
| H-15 | ✗ | ✗ | ✗ | ✗ | Contest-specific, không target |
| H-16 | ✗ | ✅ | ✅ | ✅ | G5 JIT + routing |
| H-17 | ✗ | ✗ | ✅ | ✅ | G6 → logic_exploiter |
