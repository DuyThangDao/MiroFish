# HIST-INV v4b — Adaptive Threshold với [TECH]/[LOGIC] Query Categorization

## Bối cảnh: Vấn đề của v4 trên contest 42

### Kết quả benchmark

| Contest | Baseline | v4 | Delta |
|---------|---------|-----|-------|
| Contest 35 (AMM/CLP) | F1=0.268 | F1=0.245–0.276 | ±0 |
| Contest 42 (Vault/Lending) | F1=0.311 | F1=0.250 | **-0.061** |

### Root cause: 2 tầng lỗi cho logic bugs

**Tầng 1 — Query generation sai**: Prompt v4 yêu cầu LLM focus vào
`"type casts, arithmetic operations, state updates, unchecked blocks"` →
LLM enumerate low-level arithmetic patterns, bỏ qua các logic bug patterns.

Ví dụ contest 42:
```
H-02 distributeMochi(): Bug = wrong state reset (_shareMochi resets cả 2 shares)
  → LLM sinh: "uint256 division before multiplication", "unsafe type cast uint256 to uint128"
  → Không có query nào về "unexpected side effect of sub-function"

H-04 registerAsset(): Bug = missing existence check (permissionless overwrite)
  → LLM sinh: "external call engine cssr", "getLiquidity with address parameter"
  → Không có query nào về "missing duplicate check before state write"

H-08 deposit(): Bug = zero-amount griefing resets timestamp
  → LLM sinh: "enum comparison in require", "address type casting"
  → Không có query nào về "missing zero-amount validation"
```

**Tầng 2 — RAG coverage kém cho logic bugs**: Ngay cả nếu query đúng,
arithmetic bug findings cluster chặt (same technical terms) → cosine similarity cao.
Logic bug findings dùng ngôn ngữ đa dạng theo protocol → similarity thấp hơn.

### Tại sao threshold 0.65 gây noise cho logic queries

Khi LOGIC query không có RAG finding thực sự phù hợp (score < 0.72),
RAG trả về findings khác nhau nhất ở score 0.65–0.71 (arithmetic/AMM/bridge findings).
Inject những findings này vào call graph → agent bị mislead → FP tăng.

---

## Giải pháp v4b: Phân loại query + Adaptive threshold

### Thay đổi 1: Prompt — output 2 loại query có prefix

```python
prompt = (
    "You are a Solidity code analyst.\n\n"
    f"Function: {fn_name}()\n"
    f"Body:\n{fn_body.strip()}\n\n"
    "Generate search queries to find historical vulnerability findings "
    "related to this function.\n"
    "Each query must target a DIFFERENT operation or pattern.\n"
    "List ALL distinct operations — do not merge or skip any.\n\n"
    "Categorize each query with a prefix:\n"
    "[TECH]: type casts, arithmetic operations, unchecked blocks, "
    "overflow/underflow, unsafe downcasting\n"
    "[LOGIC]: missing input validation (zero amounts, bounds, existence checks), "
    "access control (who can call, what they overwrite), "
    "state consistency (variables that should update together), "
    "unexpected side effects of sub-function calls\n\n"
    "Be specific: reference exact variable names and data types from the code.\n"
    "Do NOT describe business purpose. Do NOT add 'vulnerability' keyword.\n"
    "Format: [PREFIX] query text, one per line, max 15 words each.\n"
    "Output ONLY the queries, nothing else."
)
```

**Output mẫu cho `deposit()` trong MochiVault:**
```
[TECH] uint256 arithmetic in collateral calculation without SafeMath
[TECH] unsafe cast from uint256 to uint128 in fee calculation
[LOGIC] missing zero-amount check before updating lastDeposit timestamp
[LOGIC] any caller can reset withdrawal period by depositing zero collateral
[LOGIC] deposit to arbitrary position ID without ownership validation
```

### Thay đổi 2: RAG loop — parse prefix, apply adaptive threshold

```python
_LOGIC_THRESHOLD = float(os.getenv("HIST_INV_LOGIC_THRESHOLD", "0.72"))
_TECH_THRESHOLD  = score_threshold  # default 0.65

for q in queries:
    # Parse prefix → threshold + clean query
    q_stripped = q.strip()
    if q_stripped.startswith('[LOGIC]'):
        threshold = _LOGIC_THRESHOLD
        q_clean = q_stripped[7:].strip()
    elif q_stripped.startswith('[TECH]'):
        threshold = _TECH_THRESHOLD
        q_clean = q_stripped[6:].strip()
    else:
        threshold = _TECH_THRESHOLD   # fallback: treat as TECH
        q_clean = q_stripped

    if not q_clean:
        continue

    try:
        docs = retriever.query(q_clean, n_results=3)
        for d in (docs or []):
            all_candidates.append({
                "query": q_clean[:80],
                "query_type": "LOGIC" if threshold == _LOGIC_THRESHOLD else "TECH",
                "score": round(d['score'], 3),
                "passed": d['score'] >= threshold,
                "title": d['title'][:80],
            })
            if d['score'] < threshold:
                continue  # MMR không sort DESC
            ann = ContractKGBuilder._make_hist_annotation(d)
            if ann not in seen_ann:
                seen_ann.add(ann)
                ordered_ann.append(ann)
                break
    except Exception:
        pass
```

### Tại sao threshold 0.72 cho LOGIC queries

- Score ≥ 0.72: RAG có finding thực sự tương đồng → inject có giá trị
- Score 0.65–0.71: RAG không có finding tốt, trả về nearest neighbor sai protocol/sai loại → noise
- Thà không inject còn hơn inject noise làm agent mislead

---

## So sánh v4 vs v4b

| | v4 (current) | v4b |
|--|-------------|-----|
| Query categories | 1 (all technical) | 2 ([TECH] + [LOGIC]) |
| Threshold | 0.65 uniform | 0.65 (TECH) / 0.72 (LOGIC) |
| Coverage | Arithmetic bugs tốt, logic bugs miss | Cả hai |
| Noise control | Per-query top-1 + dedup | + Stricter threshold cho LOGIC |
| LLM calls | 1/function | 1/function (không đổi) |
| RAG calls | ~N/function | ~N/function (có thể tăng nhẹ) |

---

## Files cần thay đổi

Chỉ 1 file: `backend/app/services/contract_kg_builder.py`

1. `_generate_fn_queries()` (line ~555): Update prompt, **giữ prefix trong return value**
2. `_process_entry()` (line ~697): Parse prefix trước RAG loop, apply adaptive threshold
3. Thêm env var `HIST_INV_LOGIC_THRESHOLD` (default 0.72)

---

## Kiểm tra tính khả thi

Trước khi implement production, chạy test script:
`backend/scripts/test_hist_inv_v4b_prefix.py`

Test các functions của contest 42 bị miss (distributeMochi, registerAsset, deposit):
1. LLM có sinh ra [LOGIC] queries đúng không?
2. Với threshold 0.72, RAG có trả về findings hữu ích không hay empty?
3. So sánh với v4 (threshold 0.65) để đánh giá noise reduction

**Dấu hiệu thành công:**
- `distributeMochi` có [LOGIC] query về "wrong state reset in sub-function call"
- `registerAsset` có [LOGIC] query về "missing existence check before write"
- `deposit` có [LOGIC] query về "missing zero-amount validation"
- Với threshold 0.72: LOGIC queries inject ít hơn nhưng chính xác hơn

---

## Rủi ro

| Rủi ro | Mức độ | Mitigation |
|--------|--------|-----------|
| LLM không tuân thủ prefix format | Trung bình | Fallback: query không có prefix → treat as TECH |
| RAG không có LOGIC findings cho bất kỳ query nào | Cao | Chấp nhận — đây là honest thừa nhận giới hạn RAG |
| Threshold 0.72 quá cao, bỏ sót valid LOGIC findings | Thấp-trung bình | Tuneable via env var |
| Tăng số queries → tăng RAG cost nhẹ | Thấp | Acceptable |

---

## Kỳ vọng sau v4b

- Contest 35: Giữ nguyên hoặc cải thiện nhẹ (LOGIC queries thêm coverage cho H-03, H-07 type)
- Contest 42: Recover H-02, H-04, H-08 nếu LLM sinh đúng LOGIC queries và RAG có findings
- FP: Không tăng hoặc giảm (LOGIC threshold cao hơn giảm noise)
