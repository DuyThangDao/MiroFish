# Phân tích Mô hình Giao tiếp Agent — OASIS vs. Current Architecture

**Ngày:** 2026-04-25
**Bối cảnh:** Sau khi đánh giá contest 3 (MarginSwap), S-track F1 = 0.000 do semantic pipeline hoàn toàn thất bại. Phân tích nguyên nhân dẫn đến câu hỏi: liệu việc chuyển sang mô hình OASIS thật sự có cải thiện kết quả không?

---

## 1. Kiến trúc hiện tại — Không phải OASIS

Mặc dù project ban đầu hướng tới OASIS, pipeline contract audit hiện tại **không sử dụng** thư viện `oasis` hay `camel-ai` ở bất kỳ đâu. Đây là custom LLM loop hoàn toàn khác.

### 1.1 True OASIS (run_reddit_simulation.py)

```python
from oasis import ActionType, LLMAction, generate_reddit_agent_graph
import oasis

env = oasis.make(agent_graph=agent_graph, platform=oasis.DefaultPlatformType.REDDIT, ...)
await env.reset()

# Mỗi round: agents TỰ QUYẾT ĐỊNH action
actions = {agent: LLMAction() for agent in active_agents}
await env.step(actions)
```

**Đặc điểm:**
- Mỗi agent thấy **toàn bộ social feed** (posts, comments, likes) sau mỗi `env.step()`
- Agent tự chọn action: `CREATE_POST`, `CREATE_COMMENT`, `LIKE_POST`, `SEARCH_POSTS`, `FOLLOW`, `DO_NOTHING`...
- Agent B có thể comment trực tiếp vào post của Agent A → giao tiếp organic
- Communication là **reactive** — agent phản hồi theo những gì đang xảy ra trong môi trường

### 1.2 Current Contract Audit (cyber_session_orchestrator.py)

```python
# Build 1 prior_context duy nhất cho tất cả agents trong round
prior_context = self._build_prior_context(session_state)

# 17 agents nhận cùng context, gọi song song
for profile in active_profiles:
    response = self._call_agent(profile, prior_context=prior_context, ...)
```

**Đặc điểm:**
- Tất cả 17 agents nhận **cùng 1 prior_context** = tóm tắt findings từ các round trước (title + severity + confidence)
- Agents viết song song trong cùng 1 round — không ai biết người kia đang viết gì
- Không có direct agent-to-agent communication
- Prior context chỉ chứa **parsed titles**, không có reasoning hay evidence đầy đủ

### 1.3 Bảng so sánh

| Tiêu chí | True OASIS | Current System |
|----------|-----------|----------------|
| Library | `oasis`, `camel-ai` | Custom LLM loop |
| Agent thấy nhau | Toàn bộ social feed sau mỗi step | Summary titles từ round trước |
| Intra-round | Agent B đọc Agent A và reply ngay | 17 agents viết song song, không biết nhau |
| Agent action | Tự quyết (post/comment/like/search) | Orchestrator gọi trực tiếp |
| Communication | Organic, reactive | Centralized, broadcast |
| Output | Social media posts | Structured FINDING/SEMANTIC_FINDING |

---

## 2. Bằng chứng từ feed.jsonl — Vấn đề thật là gì

Mỗi agent post được lưu trong `uploads/cyber_sessions/{session_id}/feed.jsonl`. Contest 3 có 185 posts. Phân tích feed.jsonl cho thấy:

### 2.1 H-03 (price_manipulation) — Detect đúng, format sai

```
defi_analyst R1:   "AMM Spot Price Oracle Manipulation"  SWC: FLASH_LOAN_PRICE_MANIPULATION
defi_defensive R1: "AMM Spot Price Oracle Manipulation"  SWC: FLASH_LOAN_PRICE_MANIPULATION
defi_offensive R1: "Flash Loan Price Oracle Manipulation" SWC: FLASH_LOAN_PRICE_MANIPULATION
```

**22 posts** đề cập đúng bug H-03 trong suốt 10 rounds. Vấn đề không phải agents không phát hiện — mà là họ dùng **`FINDING` format với SWC ID tự chế** thay vì `SEMANTIC_FINDING` với category đúng.

Kết quả: Bug đi vào `consensus_vulns` với `mitre_techniques=["DEFI-FLASH_LOAN"]` — không bao giờ đi vào `semantic_results`.

### 2.2 H-07 (holdsToken never reset) — Hoàn toàn bị bỏ qua

```
Posts mentioning "holdsToken":   0
Posts mentioning "applyInterest": 0
```

Không một agent nào trong 185 posts đề cập đến những biến này. Đây là **coverage gap** — agents tập trung vào patterns nổi bật (reentrancy, oracle, gas limit) trong file 134K chars, bỏ qua state machine tinh tế.

### 2.3 SEMANTIC_FINDING duy nhất — Sai cú pháp

```
# R2 apps_defensive:
FINDING: Missing Input Validation for Bond Runtime Parameter
SWC: SEMANTIC_FINDING    ← viết sai: dùng như SWC value, không phải format header
EVIDENCE: Knowledge Graph entry [INV-001]   ← quá ngắn, bị evidence gate drop
```

Parser yêu cầu `SEMANTIC_FINDING: <title>` ở đầu dòng. Agent viết sai → được parse như FINDING bình thường → vào consensus_vulns, không vào semantic_results.

**Kết luận từ feed analysis:** Vấn đề là **output format** và **coverage**, không phải communication model.

---

## 3. Tại sao True OASIS sẽ làm audit TỆ HƠN

### 3.1 Token explosion → 429 catastrophic

Trong OASIS, mỗi agent đọc **toàn bộ social feed** trước khi hành động. Feed tăng tuyến tính:

```
Contest 3 (134K chars flat file):
  185 posts × 200 chars avg = 37K chars feed
  Flat file:                = 134K chars
  Tổng/request:             = 171K chars ≈ 42K tokens

  Vertex AI TPM quota hiện tại: ~40K tokens/phút
  → 429 từ round 1, mỗi request
```

So với hiện tại (33K tokens/request đã gây 8 lần 429 trong 98 phút), true OASIS sẽ bị throttle liên tục từ đầu.

### 3.2 Sai tool cho công việc này

OASIS được thiết kế cho **social opinion formation** — mô phỏng cách thông tin lan truyền trên mạng xã hội, cách ý kiến hội tụ theo nhóm xã hội. Output là hành vi xã hội (ai follow ai, tin nào viral).

Smart contract audit cần **structured technical output**:

```
FINDING: <title>
SWC: SWC-107
SEVERITY: critical
FUNCTION: disburse()
EVIDENCE: <code quote với dòng cụ thể>
PATCH: <cách fix>
```

Parse structured findings từ organic Reddit thread = khó và unreliable. Format sẽ bị drift sau vài rounds khi agents bắt đầu viết theo style xã hội.

### 3.3 Hallucination khuếch đại

Trong mạng xã hội, thông tin sai lan nhanh hơn thông tin đúng. Một finding sai nhưng có title ấn tượng sẽ được nhiều agent LIKE → consensus engine nhầm tưởng là high confidence → FP rate tăng.

Hiện tại, FP đã là vấn đề (L-track precision = 0.250 cho contest 3). True OASIS sẽ làm precision giảm thêm.

### 3.4 Speed regression

True OASIS có thể sequential trong mỗi step (env.step() xử lý tuần tự hoặc semi-parallel). Hệ thống hiện tại gọi 17 agents song song trong 1 round với rate limiting 1s/agent. Chuyển sang OASIS sẽ tăng thời gian audit.

---

## 4. Giá trị thật của OASIS — Và cách lấy lợi ích đó mà không rebuild

### 4.1 Insight cốt lõi của OASIS có ý nghĩa gì với audit

OASIS cho phép Agent B **đọc full reasoning của Agent A** và xây dựng trên đó:

> "defi_analyst tìm được `getPriceFromAMM()` vulnerable với flash loan. Tôi trace thêm call graph và thấy `holdsToken` flag cũng không bao giờ được reset khi oracle price thay đổi — đây là composite bug."

Điều này không cần full OASIS. Vấn đề là hiện tại prior_context chỉ chứa:

```
[CRITICAL] AMM Spot Price Oracle Manipulation (by defi/analyst, confidence: 0.70)
```

Không có evidence, không có function name trace, không có reasoning chain. Agents round sau không thể build on it một cách meaningful.

### 4.2 Ba option để capture OASIS insight mà không dùng OASIS library

#### Option A — Pass full evidence vào prior_context (ít thay đổi nhất)

Thay vì chỉ show title + confidence, show thêm top-3 findings với full evidence:

```python
top_findings = sorted(windowed, key=lambda f: f["confidence"], reverse=True)[:3]
for f in top_findings:
    lines.append(f"=== HIGH-CONFIDENCE FINDING (full evidence) ===")
    lines.append(f"[{f['severity'].upper()}] {f['title']}")
    lines.append(f"Function: {', '.join(f.get('affected_functions', []))}")
    lines.append(f"Evidence: {f.get('evidence', '')[:500]}")
```

**Token impact:** +~1.5K tokens/request. Chấp nhận được.
**Benefit:** Agents có thể trace logic từ evidence của agent khác, build on it.
**Risk:** Context window lớn hơn một chút.

#### Option B — Synthesizer agent sau mỗi Phase (hiệu quả nhất)

```
Phase A (rounds 1-4) hoàn thành
    ↓
Synthesizer agent nhận TOÀN BỘ 70 posts từ Phase A
    ↓
Task: "Group these findings. Identify duplicates.
       For findings using non-standard SWC IDs (DEFI-*, FLASH_LOAN_*,
       custom IDs), reclassify as SEMANTIC_FINDING with correct category.
       Identify state machine bugs missed by agents."
    ↓
Structured synthesis: 1 văn bản ngắn (~500 tokens) làm prior_context cho Phase B/C
```

**Cost:** +3 API calls cho toàn bộ audit (1 per phase transition).
**Benefit:** 
- Agents Phase B/C nhận context chất lượng cao hơn
- FINDING với SWC tự chế được tự động reclassify → semantic findings tăng
- State machine bugs từ Phase A được tổng hợp và nhấn mạnh cho Phase B/C

#### Option C — Format reclassification pass (fix nhanh nhất, 0 thay đổi architecture)

Sau khi parse FINDING từ agent post, kiểm tra SWC ID:

```python
NON_STANDARD_SWC_TO_SEMANTIC = {
    "FLASH_LOAN_PRICE_MANIPULATION": "price_manipulation",
    "PRICE_ORACLE_STALENESS":        "price_manipulation",
    "DEFI-FLASH_LOAN":               "price_manipulation",
    "DEFI-PRICE_ORACLE":             "price_manipulation",
    "DEFI-COMPOSABILITY":            "defi_integration_error",
    "DEFI-LIQUIDATION":              "defi_liquidation_error",
}

# Trong _process_expert_response():
if swc_id not in STANDARD_SWC_IDS and swc_id in NON_STANDARD_SWC_TO_SEMANTIC:
    # Redirect sang semantic pipeline
    semantic_category = NON_STANDARD_SWC_TO_SEMANTIC[swc_id]
    session_state.semantic_findings.append({
        "category": semantic_category,
        "title": finding_title,
        "evidence": finding_evidence,
        ...
    })
    # Không thêm vào expert_findings
```

**Cost:** Thay đổi ~20 dòng code.
**Benefit:** H-03 (price_manipulation) từ near-miss thành TP ngay, không cần thay đổi agent behavior.
**Risk:** None — chỉ là post-parsing reclassification.

---

## 5. Root Cause Summary — 3 lớp vấn đề độc lập

```
┌─────────────────────────────────────────────────────────────────┐
│ Lớp 1: FORMAT (fix nhanh)                                       │
│                                                                 │
│ Agents detect đúng bug nhưng dùng FINDING + SWC tự chế         │
│ → bypass semantic pipeline                                      │
│                                                                 │
│ Nguyên nhân: Agents luôn tìm SWC analog, kể cả khi không có    │
│ Fix: Option C — reclassify non-standard SWC → SEMANTIC_FINDING  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Lớp 2: COVERAGE (fix trung hạn)                                 │
│                                                                 │
│ Agents không trace được state machine bugs trong 134K chars     │
│ holdsToken, applyInterest = 0 mentions                          │
│                                                                 │
│ Nguyên nhân: Flat file quá lớn, agents bị overloaded           │
│ Fix: Domain-specific prompts, hoặc synthesizer agent            │
│ highlight state machine patterns sau Phase A                    │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Lớp 3: CONTEXT QUALITY (fix dài hạn)                           │
│                                                                 │
│ Prior context chỉ có titles — agents không thể build on        │
│ reasoning của nhau                                              │
│                                                                 │
│ Nguyên nhân: "OASIS in name only" — mất phần quan trọng nhất   │
│ của OASIS (agents đọc reasoning đầy đủ)                        │
│ Fix: Option A (full evidence in context) hoặc Option B          │
│ (synthesizer agent)                                             │
└─────────────────────────────────────────────────────────────────┘
```

OASIS thật sự không fix được lớp nào trong số này — nó tạo ra vấn đề mới (token explosion, unstructured output) mà không giải quyết được root cause.

---

## 6. Kế hoạch hành động đề xuất

| Priority | Action | Expected Impact | Effort |
|----------|--------|-----------------|--------|
| P0 | Option C: Reclassify non-standard SWC → SEMANTIC_FINDING | H-03 contest 3: near-miss → TP; S F1 từ 0 → ~0.25 | 1-2 giờ |
| P1 | Pass full evidence top-3 findings vào prior_context | Agents build on nhau tốt hơn; coverage state machine tăng | 2-4 giờ |
| P2 | Synthesizer agent sau Phase A | Tự động detect format errors, reclassify, summarize | 1-2 ngày |
| P3 | Domain slicing flat file | Giải quyết 429 root cause; mỗi agent nhận subset relevant | 3-5 ngày |

**Không nên làm:** Migrate sang true OASIS library cho contract audit mode. Chi phí implement cao, token cost tăng catastrophically, và không giải quyết root cause của bất kỳ vấn đề nào đang có.

---

## 7. Lưu ý về Vision ban đầu

OASIS spirit — **agents ảnh hưởng lẫn nhau thông qua thông tin được chia sẻ** — vẫn có thể đạt được trong audit context mà không cần OASIS framework. Điểm khác biệt then chốt:

- **OASIS cho social simulation:** Agents lan truyền opinions, hành vi emergent từ social dynamics
- **Audit cần:** Agents converge về technical truth thông qua evidence và structured reasoning

Hai mục tiêu này có overlap (cả hai cần agents ảnh hưởng lẫn nhau) nhưng cơ chế tốt nhất khác nhau. Với audit, **evidence-driven synthesis** (Options A/B) phù hợp hơn **social dynamics** (OASIS).

Nếu muốn OASIS library vẫn được dùng, hướng phù hợp là giữ OASIS cho **social spread simulation** (phần original của MiroFish — phân tích thông tin lan truyền), và dùng custom pipeline cho **technical audit**. Hai mode này có yêu cầu khác nhau cơ bản.
