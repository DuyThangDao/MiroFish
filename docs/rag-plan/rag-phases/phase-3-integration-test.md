# Phase 3 — Tích hợp RAG vào R1 Discovery (ReACT loop)

**Mục tiêu:** Chuyển R1 discovery từ single-shot thành ReACT loop có tool `rag_search`.
Agent phân tích code, khi phát hiện pattern nghi ngờ → gọi `rag_search` → nhận historical
findings → validate hypothesis → viết FINDING với evidence chính xác hơn.

**Tham chiếu:** [rag-implementing-plan-2.md](../rag-implementing-plan-2.md) — Step 5.2, 5.4

**Điều kiện tiên quyết:** Phase 2 hoàn thành — `data/rag_db/` có đầy đủ dữ liệu.

---

## Kiến trúc

### Tại sao phải là ReACT trong R1?

Recall = TP / (TP + FN). Chỉ R1 có thể tăng Recall vì R2 chỉ validate findings đã có.

Hiện tại R1 là **single-shot**: đọc code → "đoán" vulnerability → write FINDING.
Vấn đề: agent thiếu knowledge base về các pattern đã được confirm → sinh FP (đoán sai
severity/pattern) hoặc FN (bỏ qua vì không đủ confidence).

**Flow đúng (từ rag-implementing-plan-2.md Step 5.4):**
```
Đọc code → Phát hiện pattern nghi ngờ → Query RAG → Validate → FINDING chính xác
```

### Luồng ReACT trong `_discover_one()`

```
Initial prompt (contract code + invariant instructions + rag_search tool spec)
    │
    ▼ LLM response
    ┌─ Có ACTION: rag_search({query}) ?
    │   YES → execute rag_search(query)
    │         append OBSERVATION vào messages
    │         loop lại (tối đa MAX_RAG_CALLS=3 lần)
    │
    └─ NO (không có ACTION) → parse FINDING blocks → return findings
```

Agent sẽ:
1. Đọc invariants, scan code
2. Phát hiện "hàm X có external call trước khi update state — nghi reentrancy"
3. Gọi `rag_search({"query": "reentrancy via external call before state update withdraw"})`
4. Nhận: "Similar finding score=0.81: Protocol GTE, confirmed HIGH, exploit drains..."
5. Confirm hypothesis → viết FINDING với confidence cao, evidence đúng

---

## Checklist

- [ ] 1. Test retriever thủ công (CLI)
- [ ] 2. Thêm `_get_rag_retriever()` singleton vào orchestrator
- [ ] 3. Thêm `rag_search` tool spec vào R1 prompt (`build_round1_prompt`)
- [ ] 4. Chuyển `_discover_one()` sang ReACT loop
- [ ] 5. Test với 1 contest — verify agent gọi RAG
- [ ] 6. *(Sau)* So sánh F1 baseline vs RAG-enabled

---

## Bước 1 — Test retriever thủ công (CLI)

```bash
cd /home/thangdd/repos/MiroFish/backend
set -a && source /home/thangdd/repos/MiroFish/.env && set +a

.venv/bin/python -c "
import sys
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

from scripts.rag.rag_retriever import SolodirRetriever

retriever = SolodirRetriever()
print('DB chunks:', retriever._col.count())
print()

for q in [
    'reentrancy via external call before state update withdraw',
    'missing access control on privileged admin function',
    'flash loan price oracle manipulation AMM single block',
]:
    res = retriever.query(q, n_results=3)
    print(f'[{q[:60]}]')
    for r in res:
        print(f'  {r[\"score\"]:.3f} | {r[\"title\"][:65]}')
    print()
"
```

**Pass nếu:** scores > 0.5, content > 500 chars.

---

## Bước 2 — Singleton trong orchestrator

File: `backend/app/services/cyber_session_orchestrator.py`

Thêm sau phần imports (gần line 78):

```python
# RAG retriever singleton — khởi tạo lần đầu khi agent đầu tiên gọi rag_search
_rag_retriever = None

def _get_rag_retriever():
    global _rag_retriever
    if _rag_retriever is None:
        import sys
        __import__('pysqlite3')
        sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
        from scripts.rag.rag_retriever import SolodirRetriever
        _rag_retriever = SolodirRetriever()
    return _rag_retriever


def _execute_rag_search(query: str, n_results: int = 3) -> str:
    """Tool function: query RAG DB, trả về formatted observation cho agent."""
    try:
        retriever = _get_rag_retriever()
        results = retriever.query(query, n_results=n_results)
    except Exception as e:
        return f"[RAG ERROR] {e}"

    if not results:
        return "[RAG] No similar findings found. This may be a novel pattern."

    lines = [f"[RAG] Found {len(results)} similar historical findings:\n"]
    for i, r in enumerate(results, 1):
        # 500 chars preview — đủ để agent nhận ra pattern, không quá dài cho context window
        preview = r["content"][:500].replace("\n", " ").strip()
        if len(r["content"]) > 500:
            preview += "..."
        lines.append(
            f"--- Finding {i} (similarity: {r['score']:.3f}) ---\n"
            f"Title: {r['title']}\n"
            f"Protocol: {r['protocol']} | Severity: {r['impact']}\n"
            f"Source: {r['source']}\n"
            f"Pattern: {preview}\n"
        )
    return "\n".join(lines)
```

---

## Bước 3 — Thêm `rag_search` tool spec vào R1 prompt

File: `backend/app/services/contract_oasis_env.py`

Thêm constant sau phần imports:

```python
_RAG_TOOL_SPEC = """
=== RAG SEARCH TOOL ===
You have access to a database of HIGH severity findings confirmed in real smart contract audits.
Use it when you have a CONCRETE hypothesis and want to validate against historical precedent.

Call format:
  ACTION: rag_search({"query": "specific technical description of the suspected vulnerability"})

Query guidelines:
  GOOD: "reentrancy in withdraw via external call before balance update"
  GOOD: "integer overflow in unchecked cast uint256 to uint128 token amount"
  BAD:  "check for bugs"  ← too vague
  BAD:  "vulnerability"   ← not a query

After ACTION, you will receive an OBSERVATION with similar historical findings.
Use the OBSERVATION to:
  - Confirm or dismiss your hypothesis based on pattern match
  - Strengthen FINDING evidence if confirmed
  - Drop the hypothesis ONLY if the pattern clearly doesn't match the code evidence

⚠ CRITICAL — RAG does NOT gatekeep your findings:
  - If RAG returns low similarity scores or no results → this does NOT invalidate your finding.
    It may mean the vulnerability is novel or not yet in the database. Report it anyway.
  - If RAG returns high similarity → use as supporting evidence, not as proof of existence.
    You still must verify the pattern exists in THIS contract's code.
  - Your independent code analysis always takes priority over RAG results.
    Never suppress a finding solely because RAG could not confirm it.

Limits:
  - Maximum 3 rag_search calls per analysis session
  - Only call when you have a specific hypothesis — NOT for every function
  - RAG is supplementary intelligence, not a prerequisite for writing FINDINGs

If you have no more searches to do, proceed directly to writing FINDING blocks.
=== END RAG TOOL SPEC ===
"""
```

Sửa `build_round1_prompt()` — thêm param `rag_enabled` và inject tool spec:

```python
def build_round1_prompt(
    agent_profile: "ContractAgentProfile",
    context_summary: str,
    dep_graph_text: str = "",
    intent_summary: str = "",
    focus_directive: str = "",
    rag_enabled: bool = False,      # ← thêm
) -> str:
    dep_block    = f"\n=== STATIC DATA-FLOW SUMMARY ===\n{dep_graph_text}\n" if dep_graph_text else ""
    intent_block = f"\n=== CONTRACT INTENT ===\n{intent_summary}\n" if intent_summary else ""
    focus_block  = f"\n{focus_directive}\n" if focus_directive else ""
    rag_block    = _RAG_TOOL_SPEC if rag_enabled else ""

    return f"""\
=== ROUND 1 — INDEPENDENT DISCOVERY ===
...  (phần hiện tại)
{rag_block}
=== CONTRACT UNDER REVIEW ===
{context_summary}
...
```

---

## Bước 4 — Chuyển `_discover_one()` sang ReACT loop

File: `backend/app/services/cyber_session_orchestrator.py`

Trong `_run_discovery_round()`, thay thế phần `_discover_one`:

**Trước (single-shot):**
```python
def _discover_one(profile) -> list:
    t0 = time.time()
    prompt = cm["r1_prompt"](profile, network_summary)
    try:
        response = self._call_agent_v2(prompt, max_tokens=self._V2_R1_MAX_TOKENS)
    except Exception as e:
        logger.warning(f"[v2 R1] agent={profile.agent_id} error: {e}")
        return []
    ...
    parsed = cm["parse_all_findings"](response, profile, 1, known_functions=known_functions)
    ...
```

**Sau (ReACT loop):**
```python
def _discover_one(profile) -> list:
    import re as _re
    t0 = time.time()

    rag_enabled = os.environ.get("RAG_ENABLED", "true").lower() == "true"
    prompt = cm["r1_prompt"](profile, network_summary, rag_enabled=rag_enabled)

    messages = [{"role": "user", "content": prompt}]
    MAX_RAG_CALLS = 3
    rag_calls = 0
    force_stop_sent = False   # True sau khi đã gửi "SYSTEM LIMIT REACHED" 1 lần
    response = ""

    try:
        while True:
            response = self.llm.chat(
                messages,
                temperature=0.7,
                max_tokens=self._V2_R1_MAX_TOKENS,
                strip_think=True,
            )

            # Regex bao dung — bắt cả trường hợp LLM quên ngoặc tròn hoặc thêm khoảng trắng
            action_match = _re.search(
                r'ACTION:\s*rag_search[^(]*\(?\s*(\{.*?\})\s*\)?',
                response,
                _re.DOTALL,
            )

            if action_match and rag_enabled:
                if rag_calls < MAX_RAG_CALLS:
                    # Còn quota → thực thi tool
                    try:
                        args = json.loads(action_match.group(1))
                        query = args.get("query", "").strip()
                    except (json.JSONDecodeError, KeyError):
                        query = ""

                    if query:
                        rag_calls += 1
                        observation = _execute_rag_search(query, n_results=3)
                        logger.info(
                            f"[RAG] agent={profile.agent_id} call={rag_calls}/{MAX_RAG_CALLS} "
                            f"query='{query[:70]}'"
                        )
                        messages.append({"role": "assistant", "content": response})
                        messages.append({
                            "role": "user",
                            "content": (
                                f"OBSERVATION:\n{observation}\n\n"
                                "Continue your analysis. "
                                f"You have {MAX_RAG_CALLS - rag_calls} rag_search call(s) remaining. "
                                "If you have enough information, write your FINDING blocks immediately."
                            ),
                        })
                        continue

                elif not force_stop_sent:
                    # Hết quota, lần đầu → ép agent viết FINDING
                    force_stop_sent = True
                    logger.info(
                        f"[RAG] agent={profile.agent_id} exceeded MAX_RAG_CALLS — "
                        f"forcing FINDING generation"
                    )
                    messages.append({"role": "assistant", "content": response})
                    messages.append({
                        "role": "user",
                        "content": (
                            "SYSTEM LIMIT REACHED: You cannot use rag_search anymore. "
                            "Based on all information gathered, write your final FINDING blocks immediately."
                        ),
                    })
                    continue

                else:
                    # Đã gửi force stop nhưng agent vẫn cố gọi tool → break, parse những gì có
                    logger.warning(
                        f"[RAG] agent={profile.agent_id} ignored SYSTEM LIMIT — breaking loop"
                    )
                    break

            # Không có ACTION → response này chứa FINDING blocks
            break

    except Exception as e:
        logger.warning(f"[v2 R1] agent={profile.agent_id} error: {e}")
        return []

    elapsed = time.time() - t0
    logger.info(
        f"[TIMING] Phase=v2 R1 agent={profile.agent_id} latency={elapsed:.1f}s "
        f"rag_calls={rag_calls}"
    )

    if _debug_dir:
        try:
            import pathlib
            pathlib.Path(_debug_dir).mkdir(parents=True, exist_ok=True)
            with open(os.path.join(_debug_dir, f"r1_{profile.agent_id}.txt"), "w") as fh:
                fh.write(response)
        except Exception:
            pass

    parsed = cm["parse_all_findings"](response, profile, 1, known_functions=known_functions)
    n_findings = len(parsed)
    logger.info(
        f"[v2 R1] agent={profile.agent_id}: parsed={n_findings}findings rag_calls={rag_calls}"
    )

    results = []
    for f in parsed:
        fns = f.get("affected_functions") or ["_nofunc"]
        contract    = f.get("contract_name", "")
        title       = f.get("title", "")
        description = f.get("description", "") or ""
        attack_path = f.get("attack_path", [])
        ev          = (f.get("evidence") or [""])[0]
        code_anchor = f.get("code_anchor", "")
        for fn in fns:
            results.append((contract, fn, title, description, attack_path, ev, code_anchor))

    return results
```

---

## Bước 5 — Test và verify

### 5.1 Chạy với STOP_AFTER_DEDUP để test nhanh

```bash
cd /home/thangdd/repos/MiroFish/backend
set -a && source /home/thangdd/repos/MiroFish/.env && set +a

LOG=/tmp/rag_phase3_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
  source .venv/bin/activate
  AUDIT_PIPELINE_VERSION=v2 STOP_AFTER_DEDUP=true RAG_ENABLED=true \
  exec python -u scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
    --output      ./results/rag_phase3_test/contest_35 \
    --verbose
' >> "$LOG" 2>&1 &

echo "PID=$!  LOG=$LOG"
```

### 5.2 Verify agent đã gọi RAG

```bash
# Mỗi dòng log = 1 rag_search call
grep "\[RAG\]" "$LOG"
# Expect: [RAG] agent=bloc_offensive call=1/3 query='reentrancy in withdraw...'

# Xem timing (RAG calls làm tăng latency — mỗi call ~400ms Vertex AI)
grep "\[TIMING\].*rag_calls" "$LOG"
# Expect: [TIMING] Phase=v2 R1 agent=... latency=12.3s rag_calls=2
```

### 5.3 Nếu không có dòng [RAG] nào

Kiểm tra:
1. Agent có thực sự gọi tool không? Dùng `V2_DEBUG_DIR` để xem raw response:
   ```bash
   V2_DEBUG_DIR=/tmp/r1_debug ... run audit ...
   grep "ACTION: rag_search" /tmp/r1_debug/r1_*.txt
   ```
2. Nếu không có ACTION → agent không nhận ra tool spec → kiểm tra `rag_block` có được inject vào prompt không

---

## Bước 6 — *(Sau)* So sánh F1 baseline vs RAG

```bash
cd /home/thangdd/repos/MiroFish/backend
set -a && source /home/thangdd/repos/MiroFish/.env && set +a

# Baseline
RAG_ENABLED=false AUDIT_PIPELINE_VERSION=v2 nohup bash -c '
  source .venv/bin/activate && exec python -u scripts/run_contract_audit.py \
  --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
  --output ./results/rag_baseline/contest_35 --timeout 7200 --verbose
' >> /tmp/rag_baseline.log 2>&1 &

# RAG enabled
RAG_ENABLED=true AUDIT_PIPELINE_VERSION=v2 nohup bash -c '
  source .venv/bin/activate && exec python -u scripts/run_contract_audit.py \
  --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
  --output ./results/rag_enabled/contest_35 --timeout 7200 --verbose
' >> /tmp/rag_enabled.log 2>&1 &

# So sánh (sau khi cả hai xong)
cd scripts/evaluate
python web3bugs_eval.py gt/gt_35.json \
  ../../results/rag_baseline/contest_35/*/audit_report.json --verbose
python web3bugs_eval.py gt/gt_35.json \
  ../../results/rag_enabled/contest_35/*/audit_report.json --verbose
```

**Kết quả mong đợi:**
- Recall RAG ≥ Recall baseline (agent tìm được nhiều TP hơn)
- Precision không giảm quá 5% (RAG không tạo FP vì agent vẫn cần evidence)
- Latency R1 tăng (rag_calls × ~400ms Vertex AI) — là trade-off chấp nhận được

---

## Troubleshooting

### Agent không gọi `rag_search`

Nguyên nhân thường gặp:
1. **Tool spec không được inject** → kiểm tra `rag_enabled=True` được truyền vào `build_round1_prompt`
2. **Agent bỏ qua tool spec** → thêm dòng nhắc nhở vào R1 prompt: `"You MAY call rag_search when you suspect a specific vulnerability pattern."`
3. **Query format sai** → đảm bảo regex parse đúng: `ACTION: rag_search({"query": "..."})`

### RAG kết quả score thấp (< 0.45)

Mặc định không lọc theo score trong `_execute_rag_search` — agent sẽ nhận tất cả và tự đánh giá. Nếu muốn filter:
```python
results = [r for r in results if r["score"] >= 0.4]
```

### Context window bị bloat

Với `MAX_RAG_CALLS=3`, mỗi call thêm ~600 chars OBSERVATION + agent response. Tổng thêm ~5k chars.
Nếu LLM bị OOM → giảm preview từ 500 xuống 300 chars trong `_execute_rag_search`.

---

## Kết thúc Phase 3

| Tiêu chí | Kết quả mong đợi |
|---|---|
| Retriever CLI | Score > 0.5 cho queries chuẩn |
| `[RAG]` log | Ít nhất 1 agent gọi `rag_search` trong R1 |
| FINDING quality | Findings được xác nhận bởi RAG có evidence cụ thể hơn |
| Graceful fail | RAG down → R1 chạy single-shot bình thường (không crash) |
| F1 impact | Recall RAG-enabled ≥ baseline |
