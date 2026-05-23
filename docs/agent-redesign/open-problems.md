# Open Problems — Pipeline Smart Contract Audit

**Cập nhật lần cuối:** 2026-05-22  
**Baseline:** contest 35, 5 runs — TP mean=8.0±1.4, Recall=0.471, Precision=0.118

Tài liệu này liệt kê 5 vấn đề còn mở sau khi đã fix 3 vấn đề trước đó (BOOST truncation, 0-output agents, RAG threshold). Mỗi vấn đề có bằng chứng cụ thể, giải pháp đề xuất và ước tính trade-off.

---

## Đã fix (tham khảo)

| # | Vấn đề | Fix | Kết quả |
|---|--------|-----|---------|
| F1 | BOOST model 403 + max_tokens=4096 truncation | config key file + max_tokens=65536 | 0→6 LLM invariants/run |
| F2 | 0-output agents (thinking token exhaust) | Retry Option A + OUTPUT COMMITMENT Option B | 0 agents với 0 output từ run-3 |
| F3 | RAG score threshold 0.70 block 60% relevant patterns | Hạ xuống 0.65 | Injections tăng ~3x |

---

## P1 — RAG Dilution: bỏ filter làm loãng focus vào primary target

### Bối cảnh

Vấn đề này được **giới thiệu trong run-5** khi bỏ hoàn toàn independent target filter để fix bug
filter block nhầm (xem `rag-utilization-issues.md`). Fix đúng hướng nhưng chưa đủ — bỏ filter
tạo side effect mới.

### Mô tả

BOOST phân tích toàn bộ codebase nên Turn 1 của mỗi agent extract invariants về **tất cả contracts**
(không chỉ primary target). Khi không có filter, tất cả invariants này đều được dùng làm RAG query.

**Dữ liệu run-5 (contest 35):**

```
62 unique invariants dùng làm RAG query:
  13 về ConcentratedLiquidityPool  (21%)
  49 về CPP / HybridPool / IndexPool / TridentRouter  (79%)

→ 51/68 actual RAG injections (75%) là patterns về non-primary contracts
```

Hệ quả: agents nhận hints về HybridPool/CPP → sinh findings về các pool đó → focus vào CLP
giảm.

**So sánh run-1 vs run-5:**

| Metric | Run-1 | Run-5 |
|--------|:-----:|:-----:|
| CLP findings | 31 | 28 |
| ConcentratedLiquidityPosition findings | **3** | **0** |
| Non-CLP pool findings | 21 | 30 |
| H-06 (Position.collect) | ✅ | ❌ |

H-06 mất hoàn toàn trong run-5 vì 0 Position findings — trực tiếp do dilution effect.

### Nguyên nhân gốc

`_build_invariant_rag_hints` không phân biệt invariants về primary target hay non-primary. Không
có filter nào → 79% RAG budget đổ vào noise.

### Giải pháp

**Positive filter trên invariants**: chỉ dùng invariants có nhắc đến ít nhất 1 contract trong
`target_contracts` làm RAG query. Invariants về non-primary contracts bị skip (không inject).

Đây là positive filter (whitelist) thay cho negative filter (blacklist) bị bug trước đây — đúng
semantic hơn, không phụ thuộc vào cách xác định "independent targets".

**Thay đổi code cần thiết:**

File: `backend/app/services/cyber_session_orchestrator.py`

1. Thêm parameter `target_contracts` vào `_build_invariant_rag_hints`:

```python
# Trước:
def _build_invariant_rag_hints(invariant_text: str, agent_id: str) -> tuple:

# Sau:
def _build_invariant_rag_hints(invariant_text: str, agent_id: str,
                                target_contracts: list[str] | None = None) -> tuple:
```

2. Thêm positive filter trong vòng lặp invariants (trước cache check):

```python
for i, inv in enumerate(invariants):
    # Positive filter: chỉ query RAG cho invariants về primary targets
    if target_contracts:
        inv_lower = inv.lower()
        if not any(c.lower() in inv_lower for c in target_contracts):
            logger.info(f"[RAG] agent={agent_id} inv={i+1} → skip (not about primary target)")
            continue
    # FIX-3: semantic dedup ...
    cache_key = _normalize_inv_key(inv, target_contracts or [])
```

3. Truyền `target_contracts` ở call site:

```python
hint_block, rag_calls = _build_invariant_rag_hints(
    turn1_response, profile.agent_id,
    target_contracts=target_contracts,
)
```

**Lưu ý cho contests single-target:** `target_contracts` thường là list chứa 1 contract chính.
Invariants về contract đó sẽ pass filter. Generic invariants (không nhắc contract cụ thể) bị
loại — đây là acceptable vì generic invariants generate generic RAG patterns, ít signal.

### Trade-off

| | Trước fix | Sau fix |
|-|-----------|---------|
| CLP RAG injections | ~17/run | ~35-40/run (ước tính) |
| Non-CLP injections | ~51/run | ~5-10/run |
| Generic invariant coverage | Có | Mất |
| Context tăng | Không | Không |

### Expected gain

+1 TP (H-06 type — Position contract findings phục hồi). Precision cải thiện vì ít non-CLP FP hơn.

### Độ phức tạp

Thấp — 5–8 lines thay đổi, không ảnh hưởng flow chính.

---

## P2 — Peripheral Contract Coverage: BFS bỏ sót contracts gọi qua interface

### Mô tả

Pipeline dùng BFS từ primary contracts để xác định `in_scope_source` — context thực tế agents
nhận. Contracts chỉ được gọi qua interface (không có `import` trực tiếp) bị drop hoàn toàn:
không có stub, không có code, không có gì.

**Bằng chứng contest 42:**

```
Flatten ban đầu: 136K chars (toàn bộ codebase)
Agent context thực tế: 46K chars (chỉ 6 contracts từ BFS)

Bị drop hoàn toàn:
  ReferralFeePoolV0  → H-03 (array OOB), H-06 (drain)     = 2 TP miss
  VestedRewardPool   → H-13 (frontrunning vest())           = 1 TP miss
  MochiEngine        → H-10 (changeNFT breaks protocol)     = 1 TP miss

4/6 FN contest 42 = peripheral contract miss
```

**Cơ chế:**

Primary contracts import `IReferralFeePool` (interface), không import `ReferralFeePoolV0`
(concrete implementation). BFS chỉ follow `import` statements → concrete implementation không
reachable → bị drop.

### Giải pháp đề xuất (Option B — Interface Mapping)

Sau BFS, thực hiện thêm bước:
1. Scan `in_scope_source`: tìm tất cả `interface IFoo { ... }` và `IFoo` references
2. Search codebase: tìm `contract FooV0 is IFoo` hoặc `contract Foo is IFoo, ...`
3. Add compressed summary (~3–5K chars/contract) của mỗi concrete implementation vào context

**Ưu điểm:** Chính xác (chỉ add contracts thực sự được call), context tăng nhẹ (~5–15K/contest).

**Nhược điểm:** Cần implement regex logic matching interface → implementation. Có thể miss edge
cases (contracts implement interface qua inheritance chain).

**Option C thay thế (Per-peripheral mini-audit):** Sau R1 main, identify dropped contracts, chạy
3–5 agents riêng với context chỉ chứa contract đó. Merge vào dedup pool chung.
- Ưu: Coverage đầy đủ, không ảnh hưởng R1
- Nhược: Cost và thời gian +30–50%

### Trade-off

| | Option B (interface mapping) | Option C (mini-audit) |
|-|-----------------------------|-----------------------|
| Context tăng | +5–15K/contest | Không đổi R1 |
| Time tăng | <5% | +30–50% |
| Coverage | Tốt (direct impls) | Đầy đủ nhất |
| Độ phức tạp | Trung bình | Cao |

### Expected gain

**+4–5 TP/contest** cho contests có nhiều peripheral contracts (như contest 42). Đây là vấn đề
có ROI cao nhất về TP tuyệt đối.

### Độ phức tạp

Trung bình. Cần implement interface-to-implementation resolver. Nên làm sau khi có baseline
contest 42 mới (re-run sau BOOST fix) để đo ROI chính xác.

---

## P3 — Single-Hypothesis Bias: agent dừng ở root cause đầu tiên

### Mô tả

Agents tìm đúng function có bug nhưng chỉ output 1 hypothesis và chọn nhầm root cause. LLM judge
từ chối vì "different root cause" — TP bị miss dù function đã được inspect.

**Bằng chứng:**

| H bug | Function | Agent output | Ground truth | Lý do judge từ chối |
|-------|----------|-------------|-------------|---------------------|
| H-07 (35) | CLPosition.burn | Loss of caller's fees (accounting error) | Theft from other users (wrong recipient) | Different actor, different mechanism |
| H-01 (35) | CLPool.burn | Accounting/DoS (reserve desync) | int128 cast overflow → adds liquidity instead of removing | Different root cause entirely |
| H-12 (35) | CLPool.mint | Overflow/casting bugs | State update ordering (secondsPerLiquidity before liquidity) | Wrong category of bug |
| H-08 (42) | MochiVault.deposit | FoT insolvency / collateral theft | Zero-deposit griefing (resets withdrawal timer) | Wrong attack scenario |
| H-01 (104) | CoreCollection.mintToken | Reentrancy (H-07 pattern) | Return value unchecked (H-01 pattern) | Wrong vulnerability class |

**Pattern chung:** Agent chọn "most obvious" root cause (overflow, reentrancy, accounting error) và
dừng. Root cause đúng thường là subtler (ordering, wrong recipient, economic timing).

### Giải pháp

Thêm instruction vào Turn 2 system prompt (tất cả agents):

```
If a function looks suspicious, generate FINDING blocks for each distinct
attack vector you can identify — do not stop at the first explanation.
A function with multiple concerns warrants multiple FINDINGs with different
root causes and severity assessments.
```

Instruction này push agents không prune output về 1 hypothesis mà explore đa hướng.

### Trade-off

- FP tăng nhẹ: mỗi suspicious function có thể tạo 2–3 findings thay vì 1. Dedup sẽ merge
  các findings trùng nhau.
- Không thay đổi kiến trúc, không thêm API call.
- Có thể tương tác với OUTPUT COMMITMENT (agents đã được push để output, giờ thêm push để
  output nhiều hypotheses — có thể gây hallucination tăng).

### Expected gain

+1–2 TP/run cho các bugs dạng "wrong framing" (H-07, H-01, H-08 contest 42).

### Độ phức tạp

Thấp — 3–4 lines thêm vào prompt template trong `contract_oasis_env.py`.

---

## P4 — Economic/Design Attack Blind Spots

### Mô tả

Agents giỏi phát hiện implementation bugs (overflow, bad cast, missing check, reentrancy) nhưng
miss các **economic design exploits** — attacks khai thác timing, ordering hoặc economic incentive
thay vì code bug trực tiếp.

**Bằng chứng:**

| H bug | Attack type | Agent output | Ground truth |
|-------|------------|-------------|-------------|
| H-16 (35) | JIT liquidity attack | Mapping key error / math error / DoS | Add large liquidity 1 block before reward snapshot, claim, exit |
| H-08 (42) | State-reset griefing | FoT insolvency, collateral theft | deposit(0) resets 7-day withdrawal timer, griefing other users |

**Pattern chung:**
- Agents mô tả technical bugs trong code (sai variable, sai index, sai math)
- GT là economic timing exploit hoặc griefing qua minimal/zero input

H-16 miss **toàn bộ 5/5 runs** — đây là persistent blind spot rõ ràng, không phải stochastic.

### Giải pháp

Thêm 2 attack pattern templates vào `economic_attacker` system prompt:

```
PATTERN: JIT (Just-In-Time) Liquidity Attack
For every time-weighted, liquidity-proportional, or snapshot-based reward:
- Can an attacker add large liquidity 1 block before the snapshot/claim window?
- Can they claim the full reward period and exit immediately after?
- Is there a minimum lock duration? Is it enforced?

PATTERN: State-Reset Griefing
For every function that resets a timer, counter, or accounting variable:
- What happens with amount=0 or amount=1?
- Does a minimal deposit/operation reset a cooldown that harms other users?
- Who bears the cost of the reset vs who triggers it?
```

### Trade-off

- FP tăng trong economic attack category (~3–5 FP mới/run). Acceptable vì hiện tại category
  này gần như không có FP (agents không detect được thì cũng không FP).
- Không ảnh hưởng agents khác.
- Cần verify: prompt không làm economic_attacker bị distract khỏi technical bugs hiện đang
  detect tốt.

### Expected gain

+1–2 TP/run cho JIT và griefing bugs. H-16 có khả năng được catch ổn định hơn.

### Độ phức tạp

Thấp — 5–10 lines thêm vào `economic_attacker` system prompt trong `contract_oasis_env.py`.

---

## P5 — Cache Key Bug: `_normalize_inv_key` luôn nhận list rỗng

### Mô tả

`_normalize_inv_key` được thiết kế để include contract name vào cache key (tránh collision giữa
invariants về các contracts khác nhau). Tuy nhiên bị gọi với `[]` ở mọi call site → `matched_contract`
luôn là `"unknown"` → keys mất phần contract prefix.

**Code:**

```python
# cyber_session_orchestrator.py line 211 — bug:
cache_key = _normalize_inv_key(inv, [])  # [] → matched_contract = "unknown" always

# _normalize_inv_key (line 179):
matched_contract = next(
    (c for c in target_contracts if c.lower() in inv_lower), "unknown"
)
clean_meaning = build_rag_query("", inv).lower()
words = clean_meaning.split()
return f"{matched_contract.lower()}::{' '.join(words[:8])}"
# → "unknown::in '', the global 'liquidity' variable ..."  (always "unknown")
```

**Hệ quả:** Invariants về CLP và HybridPool strip về cùng 8 words đầu → cùng cache key →
agent sau nhận RAG pattern của agent trước dù về contract khác.

**Bằng chứng run-5:** 24 cache reuse hits — số lượng false hits không rõ nhưng với 79% non-CLP
invariants, khả năng cao nhiều reuses là cross-contract collision.

### Giải pháp

Fix kết hợp với P1 — khi truyền `target_contracts` xuống `_build_invariant_rag_hints`, truyền
tiếp vào `_normalize_inv_key`:

```python
# Line 211 — sửa từ:
cache_key = _normalize_inv_key(inv, [])

# Thành (target_contracts được truyền từ parameter mới của P1):
cache_key = _normalize_inv_key(inv, target_contracts or [])
```

Đây là 1-line fix, dependency trực tiếp vào P1.

### Trade-off

- Ít cache reuse hơn → nhiều API calls hơn (~5–10%). Minor cost.
- Kết quả RAG chính xác hơn (đúng pattern cho đúng contract).

### Expected gain

Không trực tiếp tăng TP. Là correctness fix — đảm bảo cache dedup hoạt động đúng semantic.
Có thể tăng chất lượng RAG hints gián tiếp.

### Độ phức tạp

Thấp — 1 line, fix cùng commit với P1.

---

## Tóm tắt và roadmap

| # | Vấn đề | TP gain ước tính | Độ phức tạp | Phụ thuộc | Ưu tiên |
|---|--------|:----------------:|:-----------:|:---------:|:-------:|
| P1 | RAG dilution (positive filter) | +1 | Thấp (5–8 lines) | Không | **Ngay** |
| P5 | Cache key bug | +0 (quality fix) | Thấp (1 line) | P1 | **Ngay** (cùng P1) |
| P3 | Single-hypothesis bias | +1–2 | Thấp (3–4 lines prompt) | Không | **Ngay** |
| P4 | Economic attack blind spots | +1–2 | Thấp (5–10 lines prompt) | Không | **Ngay** |
| P2 | Peripheral contract coverage | +4–5 | Cao (interface mapping) | Re-run contest 42 trước | **Sau** |

**P1 + P5 + P3 + P4** có thể làm trong 1 commit nhỏ (tổng <30 lines code/prompt), không cần
thay đổi kiến trúc, không có regression risk đáng kể.

**P2** nên defer đến sau khi có baseline contest 42 với BOOST fix để xác nhận ROI thực tế
(4–5 TP ước tính nhưng chưa verify).

**Nếu fix P1+P3+P4:** dự kiến mean TP tăng từ 8.0 lên ~10–11/17 H bugs (Recall ~0.59–0.65).
