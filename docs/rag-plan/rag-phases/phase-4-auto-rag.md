# Phase 4 — Auto-RAG: Draft-then-Query Architecture

## Bối cảnh & Vấn đề

### Kết quả Phase 3 (STEP 2.5 — ReACT loop)

| Metric | RAG disabled | RAG enabled (Phase 3) | Delta |
|---|---|---|---|
| Findings | 59 | 51 | -8 |
| TP | 5 | 9 | +4 |
| FP | 55 | 42 | -13 |
| Recall | 0.294 | 0.529 | **+0.235** |
| F1 | 0.130 | 0.265 | **+0.135** |

F1 tăng gấp đôi — nhưng chưa phải do RAG content có ích. RAG thực tế **không trả về findings relevant** vì agents tạo query sai.

### Root Cause: Query quá protocol-specific

Agents gọi `ACTION: rag_search(...)` với short phrases gắn vào tên contract/hàm:

```
❌ "Trident IndexPool _pow implementation bug Balancer math"
❌ "ConcentratedLiquidityPoolManager claimReward positionId"
❌ "stableswap dy = adjustedReserve1 - y - 1 underflow"
```

Embedding model học **vulnerability pattern**, không học tên protocol. Kết quả: similarity 0.60–0.67, findings trả về không liên quan.

### RAG DB thực sự có data relevant

Khi query bằng full bug description (title + 300 chars), scores tăng lên 0.70–0.76:

| GT Bug | RAG Match | Score |
|---|---|---|
| H-09: rangeFeeGrowth underflow | "Underflow calculating Uniswap V3 fee growth" (Particle) | **0.755** |
| H-14: unchecked math required | "get_fee_growth_inside should allow underflow" (Superposition) | **0.758** |
| H-11: feeGrowthGlobal sai | "stale feeGrowthInside0LastX128" (Particle) | **0.737** |
| H-12: secondsPerLiquidity ordering | "Wrong invocation of updateFeesAndRewards" (Olas) | **0.703** |

→ DB có data tốt. Vấn đề nằm ở **cách agents tạo query**, không phải DB.

---

## Giải pháp: Auto-RAG (Draft-then-Query)

### Ý tưởng cốt lõi

Thay vì để agent tự formulate query rồi gọi `ACTION: rag_search(...)`, đổi flow thành:

```
FLOW HIỆN TẠI (Phase 3):
  agent phân tích contract
  → agent tự nghĩ ra short query
  → ACTION: rag_search({"query": "short phrase"})  ← query kém
  → OBSERVATION (findings không liên quan)
  → agent viết FINDING (không được help từ RAG)

FLOW MỚI (Phase 4):
  agent phân tích contract
  → agent viết DRAFT_FINDING (title + description đầy đủ)
  → system TỰ ĐỘNG extract title + description từ DRAFT_FINDING
  → system TỰ ĐỘNG query RAG với text đó  ← query chất lượng cao
  → OBSERVATION inject vào conversation
  → agent viết FINDING chính thức (có historical context)
```

**Lợi ích chính:** loại bỏ hoàn toàn vấn đề query quality — query được build từ chính description của agent, giống hệt cách query thủ công đạt score 0.70–0.76.

---

## Thiết kế kỹ thuật

### Format DRAFT_FINDING

Thêm vào prompt một block format mới cho agent viết draft trước khi system query RAG:

```
DRAFT_FINDING
TITLE: <tên vulnerability ngắn gọn>
DESCRIPTION: <mô tả kỹ thuật đầy đủ, 2-5 câu, focus vào vulnerability pattern>
FUNCTION: <tên hàm bị ảnh hưởng>
END_DRAFT
```

Sau mỗi `DRAFT_FINDING...END_DRAFT`, system tự động:
1. Parse `TITLE` + `DESCRIPTION`
2. Build query: `f"{title}. {description}"`
3. Gọi `_execute_rag_search(query, n_results=3)`
4. Inject OBSERVATION vào conversation

### Thay đổi prompt (`_RAG_TOOL_SPEC` mới)

```
=== AUTO-RAG: DRAFT-THEN-VALIDATE ===
Thay vì tự đặt query, bạn viết DRAFT_FINDING trước.
System sẽ tự động tìm historical findings tương tự và trả về OBSERVATION.

Khi bạn nghi ngờ một vulnerability, viết:

DRAFT_FINDING
TITLE: <tên ngắn gọn mô tả vulnerability pattern>
DESCRIPTION: <mô tả kỹ thuật 2-5 câu: root cause, điều kiện vi phạm, impact>
FUNCTION: <hàm bị ảnh hưởng>
END_DRAFT

Sau đó DỪNG và chờ OBSERVATION từ system.

Quy tắc viết DESCRIPTION để RAG hiệu quả:
  ✓ Mô tả vulnerability pattern: "unchecked arithmetic causes underflow in fee growth calculation"
  ✓ Mô tả root cause: "feeGrowthOutside values can exceed feeGrowthGlobal when crossing tick"
  ✗ Không dùng tên protocol/contract cụ thể: "Trident IndexPool"
  ✗ Không dùng tên hàm cụ thể: "ConcentratedLiquidityPoolManager.claimReward"

Sau OBSERVATION:
  - Score >= 0.70: historical precedent tốt, reference vào FINDING
  - Score < 0.70: novel pattern, vẫn viết FINDING nếu code evidence đủ mạnh
  - Không có results: viết FINDING bình thường, không cần RAG confirm

Giới hạn: tối đa 3 DRAFT_FINDING per analysis session.
=== END AUTO-RAG ===
```

### Thay đổi `_discover_one` (orchestrator)

Thay regex parse `ACTION: rag_search(...)` bằng regex parse `DRAFT_FINDING...END_DRAFT`:

```python
DRAFT_PATTERN = re.compile(
    r'DRAFT_FINDING\s+'
    r'TITLE:\s*(.+?)\s*\n'
    r'DESCRIPTION:\s*(.+?)\s*\n'
    r'(?:FUNCTION:\s*(.+?)\s*\n)?'
    r'END_DRAFT',
    re.DOTALL | re.IGNORECASE,
)

def _discover_one(profile) -> list:
    # ... setup như cũ ...
    while True:
        response = self.llm.chat(messages, ...)

        draft_match = DRAFT_PATTERN.search(response)
        if draft_match and rag_enabled and rag_calls < MAX_RAG_CALLS:
            title = draft_match.group(1).strip()
            description = draft_match.group(2).strip()
            query = f"{title}. {description}"  # ← giống cách manual query đạt 0.75

            rag_calls += 1
            observation = _execute_rag_search(query, n_results=3)
            logger.info(f"[RAG] agent={profile.agent_id} call={rag_calls}/{MAX_RAG_CALLS} "
                        f"auto_query='{query[:70]}'")

            messages.append({"role": "assistant", "content": response})
            messages.append({"role": "user", "content": (
                f"OBSERVATION for your DRAFT_FINDING '{title}':\n{observation}\n\n"
                f"Now write the official FINDING block based on your draft and the historical context above. "
                f"You have {MAX_RAG_CALLS - rag_calls} draft(s) remaining."
            )})
            continue

        # Không có DRAFT_FINDING hoặc hết quota → response là final
        break
```

### Thay đổi `build_round1_prompt` (`contract_oasis_env.py`)

Thay `rag_block` (tool spec cũ) và `rag_step` (STEP 2.5) bằng format mới:

```python
rag_block = _RAG_AUTO_SPEC if rag_enabled else ""  # constant mới

rag_step = (
    "\nSTEP 2.5 — DRAFT_FINDING (mandatory khi tìm thấy potential vulnerability):\n"
    "  Với MỖI potential violation từ STEP 2, trước khi viết FINDING chính thức:\n"
    "  1. Viết DRAFT_FINDING block (xem format ở đầu prompt)\n"
    "  2. Dừng và chờ OBSERVATION từ system\n"
    "  3. Dùng OBSERVATION để strengthen hoặc dismiss hypothesis\n"
    "  4. Viết FINDING chính thức\n"
    "  Tối đa 3 DRAFT_FINDING per session.\n"
) if rag_enabled else ""
```

---

## So sánh với Phase 3

| Khía cạnh | Phase 3 (ACTION: rag_search) | Phase 4 (Auto-RAG) |
|---|---|---|
| Agent tự viết query | ✓ (ngắn, sai) | ✗ (system tự build) |
| Query quality | Thấp (0.60–0.67) | Cao (0.70–0.76 theo benchmark) |
| Agent biết cách query | Cần hướng dẫn phức tạp | Không cần — viết description bình thường |
| Trigger condition | Agent phải chủ động gọi | Agent viết DRAFT_FINDING là tự động trigger |
| Backward compatible | — | Vẫn dùng `_execute_rag_search` |

---

## Test Plan

### Bước 1: Unit test query quality

```python
# Verify auto-query đạt score tương đương manual benchmark
from scripts.rag.rag_retriever import SolodirRetriever

r = SolodirRetriever()
# Simulate agent viết DRAFT_FINDING cho H-14
title = "rangeFeeGrowth requires unchecked arithmetic to handle fee growth underflow"
desc = "The fee growth mechanism uses feeGrowthGlobal - feeGrowthBelow - feeGrowthAbove. This subtraction can legitimately underflow in Solidity 0.8 due to how Uniswap V3 relies on wrapping arithmetic. Without unchecked block, the function reverts and permanently breaks the pool."
query = f"{title}. {desc}"
results = r.query(query, n_results=3)
# Expect: results[0]["score"] >= 0.70
```

### Bước 2: Integration test contest 35

```bash
cd /home/thangdd/repos/MiroFish/backend
LOG=/tmp/rag_phase4_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
  source .venv/bin/activate
  V2_DEBUG_DIR=/tmp/r1_debug_p4 AUDIT_PIPELINE_VERSION=v2 STOP_AFTER_DEDUP=true RAG_ENABLED=true \
  exec python -u scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
    --output ./results/rag_phase4_test/contest_35 \
    --verbose
' >> "$LOG" 2>&1 &
```

### Bước 3: Đánh giá

```bash
# Sau khi chạy xong
python scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_35.json \
  /tmp/dedup_findings.json --verbose
```

**Pass criteria:**
- Ít nhất 8/19 agents có `DRAFT_FINDING` trong response (trigger rate > 40%)
- RAG top-1 score trung bình >= 0.70
- F1 >= 0.30 (so với Phase 3: 0.265)

---

## Rủi ro & Mitigations

| Rủi ro | Khả năng | Mitigation |
|---|---|---|
| Agent không viết DRAFT_FINDING format đúng | Trung bình | Regex forgiving, fallback về old ACTION format |
| Agent viết DESCRIPTION vẫn dùng tên protocol | Thấp | Instruction rõ trong prompt + ví dụ xấu/tốt |
| DRAFT_FINDING + FINDING làm prompt quá dài | Thấp | MAX_RAG_CALLS=3 giới hạn số lượt |
| Latency tăng do thêm RAG calls | Có | Acceptable — Phase 3 đã chứng minh latency ok |
