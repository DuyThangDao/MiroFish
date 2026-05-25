# Kiến trúc Pin Context + Dynamic Context Loading cho Smart Contract Audit

## I. Vấn đề cần giải quyết

Có hai vấn đề độc lập khi dùng LLM để quét lỗ hổng trên codebase lớn:

**Vấn đề 1 — Dependency code bị mù:**
Primary contracts được truyền vào full source. Nhưng dependency/out-of-scope contracts chỉ có stub (signatures, không có body). Nếu một dependency contract có logic nguy hiểm bên trong (reentrancy hook, fee-on-transfer, custom transfer logic), agent không thể thấy vì chỉ có stub.

**Vấn đề 2 — Attention bias dù code có mặt:**
Full source được truyền vào nhưng agent vẫn có thể lướt qua một số function do "Lost in the Middle" effect (Liu et al., 2023). Code hiện diện trong context không đảm bảo agent đã xử lý kỹ từng function.

**Tại sao không tách thành hai pass riêng biệt:**
Phương án "R1 broad scan → Pass 2 deep scan" về bản chất là duyệt toàn bộ dự án hai lần. Đây là duplication nhân tạo — một auditor thật không đọc lại từ đầu, mà đào sâu ngay tại chỗ khi thấy nghi ngờ trong lần đọc đầu tiên.

---

## II. Kiến trúc tổng quan

Hai bước, không còn duplication:

```
Codebase
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  R1/R2/R3 — Enhanced Multi-Agent Scan                           │
│                                                                 │
│  19 agents × (enriched summary + request_context() tool)        │
│                                                                 │
│  Agent bắt đầu với enriched summary (broad view)                │
│  → Khi phát hiện suspicious signal trong domain của mình        │
│  → Gọi request_context() để fetch full implementation           │
│  → Phân tích sâu ngay tại chỗ, không cần pass riêng            │
│                                                                 │
│  Output: findings + taint signals (từ một lần duyệt duy nhất)  │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  Verification — Targeted Confirm/Reject                         │
│                                                                 │
│  finding + relevant snippet → confirm hoặc reject               │
│  Không scan thêm — chỉ đọc snippet đã biết                     │
│                                                                 │
│  Output: FP eliminated, confidence score updated                │
└─────────────────────────────────────────────────────────────────┘
    │
    ▼
  Final report
```

---

## III. Enhanced R1 — Cơ chế hoạt động

### Context layout mỗi lần gọi API

```
┌──────────────────────────────────────────────────────┐
│                   MỖI LẦN GỌI API                    │
│                                                      │
│  ┌──────────────────────┐  ← bất biến, luôn ở đầu   │
│  │      PIN CONTEXT      │    (~2k–4k tokens)        │
│  │  - Inheritance tree   │                           │
│  │  - State variables    │                           │
│  │  - Interface sigs     │                           │
│  │  - Taint records      │  ← cập nhật mỗi call     │
│  └──────────────────────┘                           │
│                                                      │
│  ┌──────────────────────┐  ← core, không đổi        │
│  │   ENRICHED SUMMARY    │    (~16k–24k tokens)      │
│  │  - Full primary src   │                           │
│  │  - KG entities        │                           │
│  │  - Intent + invariants│                           │
│  │  - Dep graph          │                           │
│  └──────────────────────┘                           │
│                                                      │
│  ┌──────────────────────┐  ← append khi cần         │
│  │  DYNAMIC CONTEXT      │    (~0–8k tokens)         │
│  │  [fetched via         │                           │
│  │   request_context()]  │                           │
│  └──────────────────────┘                           │
│                                                      │
│  ┌──────────────────────┐                           │
│  │   WORKING MEMORY      │    (~1k–2k tokens)        │
│  │  - Tool call log      │                           │
│  │  - Reasoning notes    │                           │
│  └──────────────────────┘                           │
└──────────────────────────────────────────────────────┘
```

### Tool interface

Agent có hai tools mới trong R1:

```python
# Gọi khi cần full implementation của dependency function
request_context(
    reason="hàm _transfer() được gọi từ deposit() nhưng chỉ có stub",
    target_function="_transfer",
    target_contract="BaseToken",
    current_hypothesis="suspect fee-on-transfer hoặc reentrancy hook"
)

# Gọi khi kết thúc phân tích, thay cho response thông thường
submit_findings(
    findings=[...],        # flush ra findings_temp.jsonl
    taint_updates=[...]    # push lên pin context để agents sau thấy
)
```

**Flow trong một R1 call:**

```
Agent nhận enriched summary + pin context
    │
    ├─→ Phân tích với epistemic lens của mình
    │
    ├─→ [Nếu thấy suspicious] gọi request_context()
    │       Orchestrator trả full body của target function
    │       Append vào Dynamic Context slot
    │       Agent tiếp tục phân tích với đầy đủ thông tin
    │       (có thể gọi request_context() thêm lần nữa nếu cần)
    │
    └─→ Gọi submit_findings()
            Orchestrator flush findings → findings_temp.jsonl
            Update taint records trong pin context
            Sẵn sàng cho R2
```

### Constraint để kiểm soát cost

Rủi ro duy nhất của kiến trúc này: agents gọi `request_context()` tùy tiện → cost bùng nổ. Cần hai ràng buộc cứng:

**Ràng buộc 1 — Threshold cao, không gọi suy đoán:**

| Được gọi | Không được gọi |
|----------|---------------|
| "Hàm này gọi external contract nhưng tôi chỉ thấy stub" | "Tôi muốn xem thêm về contract này cho chắc" |
| "State variable này được set từ contract khác, cần xem implementation" | "Contract này trông quan trọng" |
| "Modifier ở contract cha, không thấy body" | Bất kỳ lý do không có signal cụ thể |

**Ràng buộc 2 — Domain-gated, chỉ fetch code thuộc domain của mình:**

| Agent | Được fetch |
|-------|-----------|
| Reentrancy specialist | Functions có external call + state write |
| Oracle agent | Price feed implementations, aggregator contracts |
| Access control agent | Modifier definitions, role management functions |
| ERC20 compliance | transfer/approve/allowance implementations |

Không agent nào được fetch code ngoài domain. Với hai constraint này, số tool calls thực tế ở mức 1–2 per agent per round.

---

## IV. Pin Context

**Mục đích:** "Mỏ neo" bất biến — agent luôn biết mình đang phân tích cái gì, bất kể đang trong call nào của R1/R2/R3.

**Nội dung tĩnh (không đổi suốt session):**
- Inheritance tree (Slither)
- State variables toàn cục của primary contracts
- Interface signatures (function selectors)
- Protocol intent summary (1–2 đoạn)

**Nội dung động (cập nhật sau mỗi `submit_findings()`):**
- Taint records — xem mục V

**Tại sao dùng Slither để trích xuất:**
Solidity inheritance có thể 5–7 tầng (e.g., `ERC20Votes → ERC20Permit → ERC20 → IERC20`). State variable kế thừa từ base contracts không visible nếu chỉ đọc file chính — đây là nơi reentrancy và storage collision hay ẩn náu.

---

## V. Taint Tracking Memory

Thành phần quyết định để detect lỗ hổng xuyên ngữ cảnh trong cùng một R1 session.

**Vấn đề:** Agent A phân tích `deposit()` thấy bình thường, submit findings, tiếp tục. Agent B sau đó phân tích `withdraw()` cũng thấy bình thường. Nhưng kết hợp state mutation giữa hai hàm tạo ra reentrancy. Không có taint tracking, Agent B không biết `deposit()` đã làm gì với state.

**Schema taint record:**

```json
{
  "taint_id": "T-003",
  "created_by_agent": "reentrancy_specialist",
  "source_function": "deposit(uint256)",
  "source_contract": "Vault",
  "mutation_type": "state_write",
  "affected_var": "balances[msg.sender]",
  "check_before_write": false,
  "external_call_after": true,
  "risk_signal": "write before external call — potential reentrancy entry point",
  "resolved": false
}
```

**Vòng đời:**
- Tạo qua `submit_findings(taint_updates=[...])` khi agent phát hiện state mutation hoặc external call đáng ngờ
- Tồn tại trong pin context (visible cho tất cả agents trong R2/R3)
- Resolved khi một agent sau xác nhận có guard (reentrancy lock, CEI pattern...)
- Cuối session vẫn `resolved: false` → escalate thành finding cho Verification

**Eviction policy:** Tối đa 15 records. Khi vượt, evict record có `risk_signal` thấp nhất và cũ nhất trước.

---

## VI. External Memory — Findings Temp File

Findings flush ra ngoài context qua `submit_findings()`. Agent không nhớ những gì đã tìm — dồn toàn attention cho phần phân tích tiếp theo.

**Schema finding:**

```json
{
  "finding_id": "F-007",
  "round": "R1",
  "agent_lens": "reentrancy_specialist",
  "severity": "HIGH",
  "title": "Reentrancy in withdraw() via external call before state update",
  "contract": "Vault",
  "function": "withdraw(uint256)",
  "line_range": [142, 167],
  "evidence_snippet": "...",
  "fetched_via_request_context": false,
  "hypothesis": "balances[msg.sender] updated after external call",
  "confidence": 0.85,
  "needs_verification": true,
  "related_taint_ids": ["T-003"]
}
```

Trường `fetched_via_request_context` ghi lại finding này được phát hiện nhờ dynamic fetch hay từ enriched summary gốc — giúp đánh giá hiệu quả của cơ chế tool calling.

---

## VII. Verification Step

**Mục đích duy nhất:** Confirm hoặc reject từng finding — không làm discovery, không scan thêm.

**Input cho mỗi verification call:**
```
finding (từ findings_temp.jsonl)
  + evidence_snippet (từ finding)
  + expanded context: các function liên quan trực tiếp
  + taint records liên quan (related_taint_ids)
```

**Output:** `confirmed / rejected + reason`

**Ví dụ FP điển hình được catch ở đây:**
Finding "missing access control trên `setPrice()`" → Verification đọc `setPrice()` + modifiers của nó từ contract cha → tìm thấy `onlyOwner` → reject finding.

Verification không cần sliding window hay scan rộng — chỉ cần đúng đoạn code liên quan đến finding đó.

---

## VIII. Phân tích chi phí

Cost của kiến trúc mới phụ thuộc vào tần suất gọi `request_context()`:

```
R1/R2/R3 base (không đổi):   ~1.44M tokens
Tool calls (variable):        19 agents × X calls/agent × 28k tokens
Verification:                 ~0.09M tokens
```

| Tần suất tool call | Tổng cost | So với baseline |
|--------------------|-----------|-----------------|
| 0 call/agent (không dùng tool) | ~1.53M | +6%  |
| 1 call/agent | ~1.87M | +30% |
| 2 call/agent | ~2.42M | +68% |
| 3 call/agent | ~2.96M | +106% |

**So sánh với phương án 2-pass (đã loại bỏ):**

| Phương án | Cost | Duplication | Ghi chú |
|-----------|------|-------------|---------|
| Hiện tại (R1 only) | 1.44M | Không | Baseline, thiếu depth |
| 2-pass (R1 + Pass 2) | ~2.37M (+65%) | Có — duyệt 2 lần | Đã loại bỏ |
| **Kiến trúc này (dynamic fetch)** | **~1.87–2.42M (+30–68%)** | **Không** | **Phương án được chọn** |

Với constraint domain-gated + threshold cao, thực tế agents gọi 1–2 tool calls/agent → cost tăng ~30–68%, **không còn duplication**, và phản ánh đúng cách auditor thật làm việc.

---

## IX. Phân bổ token budget

### Sweet spot theo model

| Model | Enriched summary | Dynamic context slot | Lý do |
|-------|-----------------|----------------------|-------|
| GPT-3.5 / Claude 2 | 8k–12k | 4k | "Lost in middle" rõ rệt |
| GPT-4o / Claude Sonnet 3.5 | 16k–24k | 6k–8k | Attention cải thiện |
| Claude Sonnet 4+ / GPT-4.1 | 20k–28k | 8k | Benchmark trước khi commit |

### Phân bổ chi tiết (ví dụ tổng 32k tokens)

| Thành phần | Budget | Nội dung |
|------------|--------|---------|
| Pin Context (tĩnh) | 2k–3k | Inheritance tree, state vars, interface sigs, protocol summary |
| Pin Context (taint) | 0.5k–1k | Taint records (tối đa 15) |
| Enriched Summary | 16k–20k | Full primary source + KG + intent + dep graph |
| Dynamic Context | 0–8k | Fetched dependency implementations (chỉ khi cần) |
| Working Memory | 1k–2k | Tool call log + reasoning notes |
| System prompt | ~1k | Cố định |

---

## X. Thứ tự implement

| Bước | Thành phần | Độ ưu tiên | Ghi chú |
|------|-----------|-----------|---------|
| 1 | `request_context()` tool + orchestrator handler | Cao | Foundation — không có thì dynamic loading không chạy được |
| 2 | `submit_findings()` tool thay cho response format hiện tại | Cao | Cần để taint updates hoạt động |
| 3 | Taint Tracking Memory + eviction policy | Cao | Thiếu thì cross-agent detection fail |
| 4 | Pin context builder (Slither → inheritance + state vars) | Cao | Cần wrapper nhỏ quanh Slither output hiện có |
| 5 | Domain-gated constraint trong system prompt mỗi agent | Trung bình | Kiểm soát cost, ngăn tool call tùy tiện |
| 6 | Verification step với snippet injection | Trung bình | Extend dedup/consensus hiện tại |
| 7 | Logging `fetched_via_request_context` để đánh giá ROI | Thấp | Sau khi pipeline chạy được |
| 8 | Benchmark tool call frequency per model/contest | Thấp | Calibrate cost estimate |
