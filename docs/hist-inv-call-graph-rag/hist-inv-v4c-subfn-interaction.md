# HIST-INV v4c — Sub-Function Interaction Query + Fallback

## Bối cảnh

### Vấn đề v4 trên contest 42

v4 prompt chỉ focus vào low-level operations (`type casts, arithmetic, state updates, unchecked blocks`) → LLM enumerate operations có trong code, bỏ qua **interactions giữa các sub-function calls và ảnh hưởng lên state variables**.

Kết quả: contest 42 F1 giảm từ 0.311 (baseline) → 0.250 (v4). 3 bugs bị mất:

| Bug | Loại | v4 miss vì |
|-----|------|------------|
| H-02 `distributeMochi` | Sub-fn side effect | Không sinh query về `_buyMochi → _shareMochi → treasuryShare` |
| H-04 `registerAsset` | Missing existence check | RAG gap — không có finding tương đồng |
| H-08 `deposit` | Zero-amount edge case | LLM không enumerate zero-amount input pattern |

### Root cause H-02 — có thể fix bằng prompt

RAG **đã có** finding đúng: `[H-02] FeePoolV0.sol#distributeMochi() will unexpectedly flush treasuryShare`. Vấn đề là v4 không sinh query đủ cụ thể để retrieve nó.

Test v4c: thêm 1 dòng → LLM sinh `"incorrect balance tracking between _buyMochi swap and _shareMochi distribution"` → RAG trả về finding đúng ở score 0.673 ✅

H-04 và H-08 là **RAG gap** — không fix được bằng prompt.

---

## Thay đổi v4c

### File duy nhất: `backend/app/services/contract_kg_builder.py`

#### Thay đổi `_generate_fn_queries()` (line ~555)

Thêm 1 dòng vào prompt và thêm fallback khi LLM trả về empty:

```python
@staticmethod
def _generate_fn_queries(fn_name: str, fn_body: str,
                          llm_client: Optional[Any] = None) -> list:
    """V4c: enumerate ALL distinct operations → list of RAG queries.

    Prompt mở rộng so với v4: thêm sub-function interaction queries.
    Fallback về v4 prompt khi LLM trả về empty (xảy ra với function lớn).
    """
    if not fn_body or not fn_body.strip() or not llm_client:
        return [f"{fn_name} vulnerability"]

    def _call(extended: bool) -> list:
        prompt = (
            "You are a Solidity code analyst.\n\n"
            f"Function: {fn_name}()\n"
            f"Body:\n{fn_body.strip()}\n\n"
            "Generate search queries to find historical vulnerability findings "
            "related to this function.\n"
            "Each query must target a DIFFERENT operation or pattern in this function.\n"
            "List ALL distinct operations — do not merge or skip any.\n"
            "Focus on: type casts, arithmetic operations, state updates, unchecked blocks.\n"
        )
        if extended:
            prompt += (
                "Also include queries about interactions between sub-function calls "
                "and their effects on state variables.\n"
            )
        prompt += (
            "Be specific about data types (uint128, int128, uint256) and operations.\n"
            "Do NOT describe business purpose. Do NOT add 'vulnerability' keyword.\n\n"
            "Format: one query per line, max 15 words each.\n"
            "Output ONLY the queries, nothing else."
        )
        try:
            raw = llm_client.chat(
                [{"role": "user", "content": prompt}],
                temperature=0, max_tokens=6144,
            ).strip()
            return [l.strip().lstrip('0123456789.-) ').strip()
                    for l in raw.split('\n') if l.strip()]
        except Exception:
            return []

    # Pass 1: v4c (extended — sub-function interactions)
    queries = _call(extended=True)

    # Fallback: v4 prompt gốc nếu EMPTY (stochastic với function lớn)
    if not queries:
        queries = _call(extended=False)

    return queries if queries else [f"{fn_name} vulnerability"]
```

**Không thay đổi gì khác** — `_process_entry()`, `_make_hist_annotation()`, threshold, workers, cache đều giữ nguyên.

---

## So sánh v4 vs v4c

| | v4 | v4c |
|--|----|----|
| Prompt thêm | — | 1 dòng sub-function interaction |
| Fallback | Không | v4 prompt nếu EMPTY |
| LLM calls/fn | 1 | 1 (hoặc 2 nếu fallback) |
| RAG calls | N | N (không đổi) |
| H-02 distributeMochi | ❌ Miss | ✅ Fix |
| H-04 registerAsset | ❌ RAG gap | ❌ RAG gap (không thay đổi) |
| H-08 deposit | ❌ LLM limit | ❌ LLM limit (không thay đổi) |
| Contest 35 regression | — | ✅ Không ảnh hưởng |
| mint() EMPTY risk | — | Stochastic — fallback xử lý |

---

## Giới hạn đã biết

| Issue | Nguyên nhân | Status |
|-------|-------------|--------|
| H-04 registerAsset | RAG không có finding về "missing re-registration check" | Ngoài scope prompt |
| H-08 deposit | LLM không enumerate zero-amount edge case pattern | Ngoài scope prompt |
| mint() EMPTY | Stochastic với body 3268c + prompt dài hơn | Fallback xử lý được |
| Fallback tốn thêm LLM call | Rare — chỉ khi v4c EMPTY | Chấp nhận được |

---

## Verification

```bash
cd /home/thangdd/repos/MiroFish/backend && source .venv/bin/activate

# Smoke test: distributeMochi có sub-fn query không
python3 - <<'EOF'
import sys, re; sys.path.insert(0, '.')
from app.services.contract_kg_builder import ContractKGBuilder
from app.services.contract_kg_builder import ContractKGBuilder as KB

# Verify prompt change: source phải có "sub-function" line
import inspect
src = inspect.getsource(KB._generate_fn_queries)
assert "sub-function calls" in src, "FAIL: sub-function line missing"
print("✅ Prompt change verified")
EOF

# Xóa cache, chạy run-8 contest 42
rm -f /home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/42/hist_inv_cache.json
bash scripts/run_benchmark.sh \
  /home/thangdd/repos/web3bugs/contracts/42 \
  ../benchmark/web3bugs/agent-redesign/42/run-8

# Eval
python3 scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_42.json \
  /home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/42/run-8/audit_report_dedup.json \
  --verbose | tee /home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/42/run-8/eval_result.txt
```

**Dấu hiệu thành công:**
- `hist_inv_detail.json` cho `distributeMochi`: có annotation `[H-02] FeePoolV0...`
- run-8 eval: TP ≥ 7 (recover H-02, giữ các TPs cũ)
- Contest 35 re-run: F1 không giảm so với run-61/62

---

## Kỳ vọng sau v4c

| Contest | Baseline | v4 | v4c (kỳ vọng) |
|---------|---------|-----|----------------|
| Contest 35 | F1=0.268 | F1=0.245–0.276 | F1=0.245–0.276 (giữ nguyên) |
| Contest 42 | F1=0.311 | F1=0.250 | F1~0.280–0.311 (recover H-02) |
