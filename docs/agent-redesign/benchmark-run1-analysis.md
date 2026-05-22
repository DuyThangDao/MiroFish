# Benchmark Run-1 Analysis — Contests 35, 42, 104

## 1. Kết quả tổng hợp

| Contest | H bugs | TP | FP | FN | Precision | Recall | F1 | Dedup findings |
|---------|--------|----|----|-----|-----------|--------|----|----------------|
| 35      | 17     | 10 | 55 | 7   | 0.154     | 0.588  | 0.244 | 63          |
| 42      | 13     | 7  | 39 | 6   | 0.152     | 0.538  | 0.237 | 44          |
| 104     | 9      | 7  | 26 | 2   | 0.212     | 0.778  | 0.333 | 33          |

**Nhận xét:**
- Contest 104 cho kết quả tốt nhất (Recall=0.778, FP thấp nhất) — scope nhỏ, single-cluster, contracts đơn giản hơn
- Contest 35 và 42 tương đương nhau (Recall ~0.54) — cả hai đều có multi-target context và nhiều peripheral contracts
- FP rất cao ở cả 3 contest (26–55): precision thấp là vấn đề hệ thống, nhưng trong giai đoạn tăng recall thì chấp nhận được

---

## 2. Lỗi và vấn đề trong quá trình chạy

### Contest 35
- **403 PERMISSION_DENIED trên BOOST model** (2 lần): intent extraction attempt 1 fail → fallback sang minimal (2 statements: ORDERING, ACCOUNTING); invariant extraction fail hoàn toàn → 0 invariants được inject vào RAG
- **Rate limit** (4 lần): attempt 1-3, tổng delay ~105s. Xảy ra trong R1 agent inference — không ảnh hưởng kết quả cuối do retry thành công
- **proxy_safety_auditor: 0 findings** — agent duy nhất không trả về findings trong cả 3 contest
- Context: 156,559 chars (4 independent audit targets trong 1 prompt)

### Contest 42
- **403 PERMISSION_DENIED trên BOOST model** (2 lần): intent và invariant extraction đều fail, fallback minimal
- Không có rate limit
- Tất cả 20 agents có findings (min: proxy_safety_auditor=4)
- Context: không có 403 khi compile, Slither chạy bình thường

### Contest 104
- **403 PERMISSION_DENIED trên BOOST model** (2 lần): cùng pattern với 35 và 42
- **Slither partial failure**: `CoreCollection` và `MultiSigWallet` not found in compiled output → 2 contracts không có dep graph → agents không có critical function enrichment cho các contracts này
- Không có rate limit
- Tất cả agents có findings (min: math_precision=4)

---

## 3. Missed TPs — phân tích từng H bug bị miss

### Contest 35 (FN=7)

| H bug | Contract.Function | Lý do miss |
|-------|-------------------|-----------|
| H-03 | CLPoolManager.reclaimIncentive | 0 candidates — function không được agents target trực tiếp |
| H-07 | CLPosition.burn | Có 1 T1 candidate nhưng **wrong framing**: predicted mô tả loss của chính caller (accounting error), GT mô tả theft của người khác (wrong recipient) |
| H-11 | Ticks.cross | 0 T1, 4 T2 nhưng tất cả sai: agents phát hiện DoS/oracle issues trong swap(), GT là bug swap biến feeGrowthOutside trong cross() |
| H-12 | CLPool.mint | 5 T1, 1 T2 nhưng tất cả sai: agents focus vào casting/overflow/boundary, GT là **state update ordering** (secondsPerLiquidity phải update trước khi liquidity thay đổi) |
| H-15 | CLPool.initialize | 0 T1, 3 T2 sai: agents mô tả TWAP/DoS, GT là **thiếu validation initialPrice vs tick bounds** |
| H-16 | CLPoolManager.claimReward | 4 T1, 1 T2 sai: agents mô tả mapping key error/math error, GT là **JIT liquidity attack** (economic design exploit) |
| H-17 | CLPool.rangeFeeGrowth | 1 T1 sai: predicted mô tả unchecked block (đúng fix nhưng sai root cause), GT là **nearestTick sai reference point** cho fee growth initialization |

### Contest 42 (FN=6)

| H bug | Contract.Function | Lý do miss |
|-------|-------------------|-----------|
| H-03 | ReferralFeePoolV0.claimRewardAsMochi | 0 candidates — **peripheral contract**, bị skeletonize hoặc agents không focus |
| H-04 | MochiProfileV0.registerAsset | 0 candidates — subtle overwrite logic (registerAsset ghi đè _assetClass khi gọi lần 2) |
| H-06 | ReferralFeePoolV0.claimRewardAsMochi | 0 candidates — cùng peripheral contract với H-03 |
| H-08 | MochiVault.deposit | 2 T1 + 1 T2 candidates nhưng tất cả sai: agents mô tả collateral theft/FoT insolvency, GT là **zero-deposit griefing** (reset withdrawal timer) — đây là design-level griefing, agents không nghĩ theo hướng này |
| H-10 | MochiEngine.changeNFT | 0 candidates — peripheral contract (changeNFT phá vỡ NFT discount system) |
| H-13 | VestedRewardPool.vest | 0 candidates — **peripheral contract** (vest() frontrunning) |

### Contest 104 (FN=2)

| H bug | Contract.Function | Lý do miss |
|-------|-------------------|-----------|
| H-01 | CoreCollection.mintToken | 1 T1 + 1 T2 candidates nhưng sai: agents detect reentrancy (H-07), không detect **return value không checked** (H-01). Cùng 1 function, khác root cause — LLM chọn nhầm hướng |
| H-06 | CoreProxy.constructor | 0 candidates — **storage collision** giữa proxy và implementation (EIP-1967 slot conflict) — Slither không compile được CoreProxy, không có dep graph |

---

## 4. Vấn đề chung trên cả 3 contest

### Vấn đề 1 — BOOST model 403 làm suy yếu invariants và RAG (xuất hiện ở cả 3) ✅ ĐÃ FIX

**Mô tả:** BOOST model (Gemini thinking) bị 403 PERMISSION_DENIED khi gọi `intent extraction` và `invariant extraction`. Pipeline fallback sang minimal invariant set thay vì bỏ qua hoàn toàn — RAG có hoạt động nhưng bị hạn chế nặng.

**Bằng chứng — số invariants và RAG injection thực tế:**

| Contest | Invariants extracted | RAG injected | RAG skip |
|---------|---------------------|-------------|---------|
| 35      | 2 (minimal fallback) | 6/120 (5%) | 114 |
| 42      | 5 (better fallback)  | 26/120 (22%) | 96 |
| 104     | **0** (total fail)   | 1/120 (<1%) | 127 |

- Contest 35/42: BOOST fail → fallback sang 2–5 invariants generic thay vì 8–12 invariants đặc thù → RAG hoạt động nhưng underfit
- Contest 104: BOOST fail + Slither partial fail → 0 invariants → RAG gần như bị vô hiệu hóa hoàn toàn

**Hậu quả:**
- Contest 104 chạy gần như không có RAG dù `RAG_ENABLED=true` — kết quả cao (Recall=0.778) nhờ scope nhỏ và contracts đơn giản, không phải nhờ RAG
- Contest 42 được RAG hỗ trợ nhiều nhất (26 injections) và có Recall cao nhì (0.538)
- Với BOOST hoạt động đúng, contest 35 và 42 kỳ vọng có 8–12 invariants → 40–60 injections → nhiều agent được guide đúng hướng hơn

**Ảnh hưởng đến TP:** Có. Invariant injection giúp agents focus đúng vào các state variables quan trọng. H-11, H-12 (fee accounting, ordering) là dạng bugs cần biết invariant đúng để phát hiện — với 0–2 invariants, agents tự suy luận từ đầu.

**Giải pháp:** Kiểm tra và fix permission cho BOOST model endpoint. Nếu BOOST fail, dùng main model làm fallback cho intent/invariant extraction (thay vì fallback sang empty/minimal). Đây là fix có ROI cao nhất.

**✅ Đã fix (2026-05-21):**
- Root cause: `BOOST_VERTEX_AI_KEY_FILE` không được khai báo trong `Config` class → env var bị bỏ qua; `_try_build_boost_client()` hardcode dùng `LLM_VERTEX_AI_KEY_FILE` thay vì BOOST key
- Fix 1: thêm `BOOST_VERTEX_AI_KEY_FILE = os.environ.get('BOOST_VERTEX_AI_KEY_FILE')` vào `backend/app/config.py:52`
- Fix 2: `cyber_session_orchestrator.py:2018` — `vertex_key_file` giờ ưu tiên `BOOST_VERTEX_AI_KEY_FILE`, fallback về `LLM_VERTEX_AI_KEY_FILE`
- Verified: BOOST `gemini-3.1-pro-preview` trả về response OK sau fix

---

### Vấn đề 2 — Peripheral contracts có 0 candidates: context overload + attention bias (xuất hiện ở 35 và 42)

**Mô tả:** Các contracts không phải primary cluster (ReferralFeePoolV0, VestedRewardPool, MochiEngine, CLPoolManager.reclaimIncentive) không có finding candidates nào, dù đây là H bugs.

**Bằng chứng:**
- Contest 42: H-03, H-06 (ReferralFeePoolV0), H-10 (MochiEngine), H-13 (VestedRewardPool) — cả 4 đều 0 candidates
- Contest 35: H-03 (CLPoolManager.reclaimIncentive) — 0 candidates

**Nguyên nhân gốc — BFS scope selection loại hoàn toàn peripheral contracts:**

Mặc dù flatten ban đầu có "55 Tier1 full, 0 skeleton" nhưng pipeline tiếp tục dùng `in_scope_source` (BFS từ primary contracts) làm context thực tế cho agents. Kiểm tra `contract_summary.txt` của contest 42 xác nhận: chỉ có 6 contracts trong context agents thấy — **ReferralFeePoolV0, VestedRewardPool, MochiEngine hoàn toàn vắng mặt**, không có stub, không có gì.

Context thực tế agents nhận (chars):
- Contest 42: 136K flatten → **46K agent context** (6 contracts)
- Contest 104: 58K flatten → **59K agent context**
- Contest 35: 199K flatten → **156K agent context** (lớn hơn vì nhiều primary targets)

Peripheral contracts bị loại vì BFS không reach được từ primary contracts → drop hoàn toàn.

**Hậu quả:** 4/6 FN của contest 42 và 1/7 FN của contest 35 là do peripheral contract bị bỏ qua dù có trong context.

**Ảnh hưởng đến TP:** Có trực tiếp — fix được vấn đề này sẽ tăng ít nhất 4–5 TP.

**Giải pháp:**
- Mở rộng BFS scope để include các contracts có import trực tiếp đến primary (reverse BFS / caller analysis)
- Hoặc thêm 1 pass riêng: với mỗi contract bị drop khỏi `in_scope_source`, tạo agent context riêng chỉ chứa contract đó

---

### Vấn đề 3 — Wrong framing: candidates tồn tại nhưng mô tả sai root cause (xuất hiện ở cả 3)

**Mô tả:** Agents tìm đúng function có bug nhưng mô tả sai cơ chế — LLM judge từ chối vì "different root cause".

**Bằng chứng:**
- Contest 35: H-07 (burn: loss of own fees vs theft of others'), H-12 (ordering vs overflow), H-16 (math error vs JIT attack), H-17 (unchecked block vs wrong reference point)
- Contest 42: H-08 (FoT insolvency vs zero-deposit griefing)
- Contest 104: H-01 (reentrancy vs return value check) — agent chọn reentrancy (H-07) bỏ qua return value

**Hậu quả:** ~3–4 TP bị miss vì framing, không phải vì thiếu coverage.

**Ảnh hưởng đến TP:** Có. Đây là "near miss" — agent đã scan đúng chỗ, chỉ cần output thêm 1 framing khác.

**Giải pháp:**
- Khuyến khích agents viết **nhiều hypotheses per function** thay vì 1 finding per root cause — nếu 1 function suspicious, list 2–3 góc tấn công khác nhau
- RC5a đã thêm "write a FINDING first, then articulate worst-case" cho logic_exploiter — cần extend pattern này cho các agents khác

---

### Vấn đề 4 — Kinh tế/Design exploits bị miss (xuất hiện ở 35 và 42)

**Mô tả:** Agents giỏi tìm implementation bugs (overflow, bad cast, missing check) nhưng miss các economic design exploits.

**Bằng chứng:**
- Contest 35: H-16 JIT liquidity attack (0/5 candidates match) — agents phát hiện mapping key bug, không phát hiện economic timing attack
- Contest 42: H-08 zero-deposit griefing — agents phát hiện FoT và collateral theft, không nghĩ đến "deposit 0 để reset timer"

**Hậu quả:** 2 TP miss trực tiếp. Economic attacks là category H bugs thường gặp trong DeFi.

**Ảnh hưởng đến TP:** Có. Đây là blind spot rõ ràng.

**Giải pháp:**
- Bổ sung prompt cho `economic_attacker` và `logic_exploiter`: *"For every time-based or liquidity-weighted reward mechanism, ask: can an attacker enter at T-1, collect full reward, exit at T+1?"*
- Bổ sung prompt: *"For every state-reset operation (deposit, initialize, register), ask: what happens with zero/minimal input? Does it reset a timer or accounting variable?"*
