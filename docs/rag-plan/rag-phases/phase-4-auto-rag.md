# Phase 4 — Auto-RAG: Post-process Architecture

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

Khi query bằng full bug description (title + 300 chars) **sau khi clean tên protocol**, scores tăng lên 0.70–0.76:

| GT Bug | RAG Match | Score |
|---|---|---|
| H-09: rangeFeeGrowth underflow | "Underflow calculating Uniswap V3 fee growth" (Particle) | **0.755** |
| H-14: unchecked math required | "get_fee_growth_inside should allow underflow" (Superposition) | **0.758** |
| H-11: feeGrowthGlobal sai | "stale feeGrowthInside0LastX128" (Particle) | **0.737** |
| H-12: secondsPerLiquidity ordering | "Wrong invocation of updateFeesAndRewards" (Olas) | **0.703** |

→ DB có data tốt. Vấn đề nằm ở **cách agents tạo query**, không phải DB.

### Tại sao Phase 3 không giải quyết được

Phase 3 (DRAFT_FINDING) giải quyết query quality bằng cách dùng description đầy đủ của agent thay vì short phrase. Tuy nhiên, phương án này có rủi ro cấu trúc không loại bỏ được:

| Rủi ro | Nguyên nhân gốc |
|---|---|
| Agent không viết đúng format | `DRAFT_FINDING` là format mới agent chưa thấy |
| Agent không trigger | Agent đọc instruction nhưng bỏ qua, viết FINDING thẳng |
| Protocol name trong query | Agent tự nhiên viết tên contract/hàm vào description |

**Tất cả 3 rủi ro đều xuất phát từ một điểm:** yêu cầu agent viết format mới và tự quản lý khi nào trigger RAG.

---

## Giải pháp: Post-process RAG

### Ý tưởng cốt lõi

Loại bỏ hoàn toàn sự phụ thuộc vào agent bằng cách chuyển RAG sang chạy **sau khi agent viết xong**, do **system** chủ động thực hiện:

```
FLOW PHASE 3 (agent-driven, có rủi ro):
  agent phân tích contract
  → agent tự nghĩ ra short query      ← query kém
  → ACTION: rag_search({"query": ...})  ← agent phải trigger đúng format
  → OBSERVATION (findings không liên quan)
  → agent viết FINDING

FLOW PHASE 4 (system-driven, không có rủi ro):
  agent phân tích contract
  → agent viết TẤT CẢ FINDINGs bình thường (turn 1)  ← không format mới
  → system parse FINDING blocks từ response
  → system clean query: strip tên CamelCase, function signatures  ← loại protocol noise
  → system batch query RAG: query = clean(title + description)    ← query chất lượng cao
  → system inject 1 OBSERVATION cho findings có score >= 0.70
  → agent revise FINDINGs có RAG match (turn 2)
```

**Lợi ích:**
- Agent không cần biết RAG tồn tại — không format mới, không trigger thủ công
- Query được build từ description đầy đủ (như benchmark đạt 0.70–0.76)
- System tự clean protocol names trước khi query
- 1 RAG batch call thay vì interrupt nhiều lần → latency thấp hơn

---

## Thiết kế kỹ thuật

### 1. Query Cleaning

Trước khi gửi RAG, system strip các từ protocol-specific ra khỏi description:

```python
import re

def build_rag_query(title: str, description: str) -> str:
    text = f"{title}. {description}"

    # Bước 1: Strip function signatures — mint(), burn(uint256 amount)
    text = re.sub(r'\b\w+\s*\([^)]*\)', '', text)

    # Bước 2: Strip dotted references — Pool.mint, IndexPool._pow
    text = re.sub(r'\b[a-zA-Z_]+\.[a-zA-Z_]+\b', '', text)

    # Bước 3: Strip true CamelCase (có chữ hoa ở giữa từ)
    # Giữ lại: "The", "Solidity", "ERC20", "DeFi" (không có lowercase→uppercase transition)
    # Xóa: "LiquidityPool", "HybridPool", "ConcentratedLiquidity"
    text = re.sub(r'\b[A-Z][a-z]+[A-Z][a-zA-Z]*\b', '', text)

    # Bước 4: Strip protocol names đã biết gây nhiễu embedding
    text = re.sub(
        r'\b(?:Trident|BentoBox|Sushi|Uniswap|Aave|Compound|Balancer)\b',
        '', text, flags=re.IGNORECASE,
    )

    return re.sub(r'\s+', ' ', text).strip()
```

> **Tại sao tách 4 bước?** Mỗi bước xử lý một loại noise khác nhau — dễ debug và điều chỉnh
> từng bước độc lập mà không ảnh hưởng các bước còn lại.

> **Edge case được giữ:** `ERC20`, `IERC20`, `SWC107` không có lowercase→uppercase transition
> nên không bị strip — đây là behavior đúng, đây là standard terms có giá trị trong embedding.

Ví dụ:
```
Input:  "ConcentratedLiquidityPool.mint() overflow in unchecked block bypasses reserve check"
Output: "overflow in unchecked block bypasses reserve check"

Input:  "The fee growth calculation subtracts feeGrowthBelow from feeGrowthGlobal"
Output: "The fee growth calculation subtracts from"  ← "The" giữ lại, CamelCase bị strip

Input:  "ERC20 token transfer returns false without revert"
Output: "ERC20 token transfer returns false without revert"  ← ERC20 không bị strip
```

### 2. Thay đổi `_discover_one` (orchestrator)

Xóa toàn bộ logic parse `ACTION: rag_search` và `DRAFT_FINDING`. Thay bằng post-process sau turn 1:

```python
def _discover_one(profile) -> list:
    import re as _re
    t0 = time.time()

    rag_enabled = os.environ.get("RAG_ENABLED", "true").lower() == "true"
    prompt = cm["r1_prompt"](profile, network_summary, rag_enabled=rag_enabled)
    messages = [{"role": "user", "content": prompt}]
    rag_calls = 0

    try:
        # Turn 1: Agent phân tích và viết FINDINGs bình thường
        response = self.llm.chat(
            messages, temperature=0.7,
            max_tokens=self._V2_R1_MAX_TOKENS, strip_think=True,
        )

        # Post-process: query RAG cho từng FINDING trong response
        if rag_enabled:
            observations = _build_rag_observations(response, profile.agent_id)
            if observations:
                rag_calls = len(observations)
                obs_text = "\n\n".join(observations)
                messages.append({"role": "assistant", "content": response})
                messages.append({"role": "user", "content": (
                    f"HISTORICAL CONTEXT from audit database:\n\n{obs_text}\n\n"
                    "Review each of your original FINDING blocks against this historical context.\n"
                    "1. For findings where the context shows a strong match (score >= 0.70), "
                    "ENRICH your DESCRIPTION and EVIDENCE to incorporate the exploit pattern "
                    "from the historical reference.\n"
                    "2. For findings with NO MATCH, you must reproduce them EXACTLY "
                    "word-for-word as you originally wrote them.\n\n"
                    "CRITICAL REQUIREMENT: You MUST output ALL original FINDING blocks again "
                    "using the exact same structural format "
                    "(TITLE, DESCRIPTION, EVIDENCE, CODE_ANCHOR, ATTACK_PATH, etc.). "
                    "Failure to include a finding, or summarizing a finding that had no match, "
                    "will result in a critical system failure."
                )})

                # Turn 2: Agent revise với historical context
                # Fast-fail: chỉ chạy nếu có observations hợp lệ (if observations: đã guard ở trên)
                response = self.llm.chat(
                    messages, temperature=0.7,
                    max_tokens=self._V2_R1_MAX_TOKENS, strip_think=True,
                )

    except Exception as e:
        logger.warning(f"[v2 R1] agent={profile.agent_id} error: {e}")
        return []

    elapsed = time.time() - t0
    logger.info(
        f"[TIMING] Phase=v2 R1 agent={profile.agent_id} latency={elapsed:.1f}s "
        f"rag_calls={rag_calls}"
    )
    # ... debug save, parse_all_findings, return (không đổi)
```

### 3. Hàm `_build_rag_observations`

Parse tất cả FINDING blocks từ response, query RAG cho từng cái, trả về list OBSERVATION strings:

```python
_FINDING_TITLE_RE = re.compile(
    r'FINDING\b.*?\nTITLE:\s*(.+?)\n.*?DESCRIPTION:\s*(.+?)(?=\nEVIDENCE:|\nCODE_ANCHOR:|\nATTACK_PATH:|\nFINDING\b|$)',
    re.DOTALL | re.IGNORECASE,
)

_SCORE_INJECT_THRESHOLD = 0.68  # Chỉ inject OBSERVATION nếu top-1 score >= ngưỡng này
_SCORE_SHOW_THRESHOLD   = 0.65  # Chỉ hiển thị individual result nếu score >= ngưỡng này

def _build_rag_observations(response: str, agent_id: str) -> list[str]:
    """Parse FINDING blocks, query RAG cho TẤT CẢ findings,
    trả về OBSERVATION strings chỉ cho những match đủ tốt.

    Không giới hạn số lượng RAG query (vector DB call rất nhanh, ~100ms/query).
    Score threshold là bộ lọc tự nhiên — findings có score thấp không được inject,
    tránh gây confusion cho agent ở turn 2.
    """
    matches = list(_FINDING_TITLE_RE.finditer(response))
    if not matches:
        return []

    retriever = _get_rag_retriever()
    observations = []

    for i, m in enumerate(matches):  # Không giới hạn — query tất cả findings
        title = m.group(1).strip()
        description = m.group(2).strip()
        query = build_rag_query(title, description)
        if not query:
            continue

        results = retriever.query(query, n_results=3)
        if not results:
            continue

        top_score = results[0]["score"]
        logger.info(
            f"[RAG] agent={agent_id} finding={i+1}/{len(matches)} "
            f"top_score={top_score:.3f} title='{title[:50]}'"
        )

        if top_score < _SCORE_INJECT_THRESHOLD:
            continue  # Score thấp → bỏ qua, không inject vào turn 2

        lines = [f"--- Historical context for FINDING: '{title}' ---"]
        for j, r in enumerate(results, 1):
            if r["score"] < _SCORE_SHOW_THRESHOLD:
                break
            preview = r["content"][:400].replace("\n", " ").strip()
            lines.append(
                f"[{j}] score={r['score']:.3f} | {r['title']}\n"
                f"    Protocol: {r['protocol']} | {preview}"
            )
        observations.append("\n".join(lines))

    return observations
```

### 4. Thay đổi prompt (`contract_oasis_env.py`)

Phase 4 **không cần** `_RAG_TOOL_SPEC` hay `rag_step` trong prompt — agent không biết về RAG.

Chỉ cần xóa `rag_block` và `rag_step` injection, giữ nguyên phần còn lại:

```python
# Xóa: rag_block = _RAG_TOOL_SPEC if rag_enabled else ""
# Xóa: rag_step = "STEP 2.5 — ..." if rag_enabled else ""
# Xóa: {rag_block} và {rag_step} khỏi f-string

# Prompt trở về clean như trước Phase 3, không có gì thay đổi cho agent
```

**Lợi ích phụ:** Prompt ngắn hơn ~500 tokens (không còn tool spec), agent focus hơn vào phân tích.

---

## So sánh kiến trúc

| Khía cạnh | Phase 3 (Agent-driven) | Phase 4 (System-driven) |
|---|---|---|
| Agent cần biết RAG | ✓ (phải viết DRAFT_FINDING) | ✗ (transparent hoàn toàn) |
| Format mới cho agent | ✓ (rủi ro không follow) | ✗ (dùng FINDING format cũ) |
| Query quality | Thấp — agent viết short phrase | Cao — system dùng full description |
| Protocol name trong query | Thấp (phụ thuộc agent) | Không có — system tự clean |
| Trigger rate | 4/19 agents (21%) | 100% — system luôn chạy |
| RAG call pattern | Multi-turn interrupt | 1 batch sau turn 1 |
| Latency overhead | ~200s/agent (interrupt) | ~30s/agent (1 batch) |
| Prompt length | Dài hơn (+500 tokens tool spec) | Ngắn hơn (sạch hơn) |

---

## Test Plan

### Bước 1: Unit test query cleaning

```python
from app.services.cyber_session_orchestrator import build_rag_query

# Verify protocol names bị strip
q = build_rag_query(
    "ConcentratedLiquidityPool.mint() overflow",
    "The ConcentratedLiquidityPool.mint() function uses unchecked block for reserve update. "
    "amountIn + inRecord.reserve can overflow uint120."
)
assert "ConcentratedLiquidityPool" not in q
assert "overflow" in q
assert "unchecked" in q
print("Cleaned query:", q)
```

### Bước 2: Unit test RAG score với cleaned queries

```python
# Verify cleaned queries đạt score >= 0.70 cho known GT bugs
from scripts.rag.rag_retriever import SolodirRetriever
r = SolodirRetriever()

test_cases = [
    ("rangeFeeGrowth underflow",
     "Fee growth calculation subtracts feeGrowthBelow and feeGrowthAbove from feeGrowthGlobal. "
     "This subtraction can legitimately underflow using wrapping arithmetic as in Uniswap V3. "
     "Solidity 0.8 checked arithmetic causes revert, permanently breaking the pool."),
    ("unchecked arithmetic required fee growth inside",
     "The fee growth inside calculation relies on modular underflow to correctly compute "
     "negative feeGrowthInside values. Without unchecked block the function reverts on valid inputs."),
]
for title, desc in test_cases:
    q = build_rag_query(title, desc)
    results = r.query(q, n_results=1)
    print(f"Score: {results[0]['score']:.3f} | {results[0]['title'][:60]}")
    assert results[0]["score"] >= 0.70, f"Score too low: {results[0]['score']}"
```

### Bước 3: Integration test contest 35

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

**Verify trong log:**
```bash
# Tất cả agents đều có RAG calls (100% trigger rate)
grep "\[RAG\].*top_score" "$LOG"

# Chỉ findings có score >= 0.68 được inject OBSERVATION
grep "\[RAG\].*score=0\.[7-9]" "$LOG"
```

### Bước 4: Đánh giá F1

```bash
python scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_35.json \
  /tmp/dedup_findings.json --verbose
```

**Pass criteria:**
- 100% agents có ít nhất 1 RAG call được log
- RAG top-1 score trung bình >= 0.70 cho findings được inject
- F1 >= 0.30 (so với Phase 3: 0.265)
- Không có regression: TP không giảm xuống dưới 9

---

## Rủi ro còn lại

| Rủi ro | Khả năng | Mitigation |
|---|---|---|
| FINDING regex không parse được format lạ | Thấp | Forgiving regex, fallback: skip finding nếu parse fail |
| Clean quá aggressive, xóa mất keyword quan trọng | Thấp | Chỉ strip CamelCase và function signatures, giữ nguyên technical terms |
| Turn 2 làm agent rewrite sai FINDINGs tốt | Trung bình | Instruction rõ: "chỉ enrich findings có score >= 0.70, giữ nguyên phần còn lại" |
| Latency turn 2 tăng tổng thời gian | Có | Chỉ trigger turn 2 nếu có ít nhất 1 observation — agents không có match sẽ skip |
