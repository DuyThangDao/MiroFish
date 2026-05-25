# RAG Hint Contamination — M10 Fix

## Tóm tắt

Run-25 (M9) tụt từ TP=9 xuống TP=6 dù Fix 1b (chunk_content 700 chars) tăng coverage hint từ 9% lên 23%. Nguyên nhân: chunk excerpt chứa code pattern cụ thể từ Solodit → agents pattern-match code thay vì tự suy luận → viết sai hướng bug.

---

## Dữ liệu

| Run | TP | FP | Thay đổi RAG hint |
|-----|----|----|-------------------|
| run-13 | 10 | 70 | `content[:350]` (header-only, ~9%) |
| run-24 | 9  | 73 | `content[:350]` + structural RAG thêm |
| run-25 | 6  | 68 | `[impact] title (protocol)` + `chunk_content[:700]` |

---

## Root cause: Anchoring từ code pattern

### Cơ chế contamination

Khi chunk_content chứa code snippet cụ thể (ví dụ: pattern "underflow" từ Solodit finding về reserve subtraction), agents đọc hint → **pattern-match code** → apply pattern đó lên contract hiện tại dù root cause khác.

**Ví dụ thực tế — H-10 + H-13 (burn reserves):**

```
Solodit chunk hint (700 chars):
  [HIGH] Fee accumulator underflow in reserve accounting (Protocol XYZ)
      ...subtracting more than available, causing reserve0 -= amount leads to
      underflow revert... PoC: attacker calls burn() repeatedly...
      Code: reserve0 -= amount0; // underflow when...
```

Kết quả:
- run-24 (không có chunk): `proxy_safety_auditor` + 4 agents suy luận độc lập → viết **đúng**: "reserves NOT decremented" → match H-10 + H-13
- run-25 (có chunk 700 chars): 9 agents đọc chunk về "underflow" → viết **sai hướng**: "Reserve Accounting **Underflow**" (trừ quá nhiều) thay vì "không trừ đủ"

Tương tự:
- **H-06** (double fee collection): agents viết "DoS via overflow" — sai, ground truth là logic error double-collection
- **H-08** (wrong inequality `<` vs `<=`): agents không còn tìm boundary condition logic — bị distract bởi arithmetic hints

### Tại sao content[:350] (run-24) ít gây contamination hơn?

`content[:350]` chủ yếu chứa **metadata header** (title + impact + protocol + 1-2 câu mô tả chung), gần như không có code snippet. Agents đọc và chỉ biết "có bug dạng này tồn tại" → tự suy luận độc lập trên contract. Đây là lý do run-13/run-24 với content[:350] bắt được H-10/H-13/H-06/H-08.

### Insight chính

**Hint nhiều hơn ≠ tốt hơn khi hint có code pattern cụ thể.** Solodit DB thiên nặng về arithmetic/overflow bugs (chiếm đa số H bugs các contest). Chunk excerpt mang code overflow pattern vào context → bias agents theo hướng đó kể cả khi bug thực tế là logic error.

---

## Fix M10: title_line + description excerpt (bỏ header, không dùng chunk)

### Nguyên lý

```
title_line (metadata clean)     → agent biết: loại bug, severity, protocol
+ content[100:400] (description) → agent biết: cơ chế bug (không có code)
```

- `content[:100]`: header lặp lại title/impact/protocol — **bỏ** (đã có trong title_line)
- `content[100:400]`: đoạn description mechanism — **giữ** (không có code, không anchor)
- `chunk_content`: code snippet matched — **bỏ** (gây contamination)

### Thay đổi cần thiết

File: `backend/app/services/cyber_session_orchestrator.py`

**Tại line 249–251 (invariant track) và line 379–381 (structural track):**

```python
# M9 (run-25) — gây contamination:
title_line = f"[{r.get('impact', '?')}] {r['title']} ({r.get('protocol', '')})"
chunk_excerpt = (r.get("chunk_content") or r["content"])[:700].replace("\n", " ").strip()
block.append(f"  [{j}] {title_line}\n      {chunk_excerpt}")

# M10 — fix contamination:
title_line = f"[{r.get('impact', '?')}] {r['title']} ({r.get('protocol', '')})"
desc_excerpt = r["content"][100:400].replace("\n", " ").strip()
block.append(f"  [{j}] {title_line}\n      {desc_excerpt}")
```

`chunk_content` không cần xóa khỏi `rag_retriever.py` — vẫn trả về, chỉ không dùng ở format hint.

### Lý do chọn `[100:400]` thay vì `[0:350]`

```
content[0:100]   — Title (lặp lại) + "Impact: HIGH" + "Protocol: XYZ"  → đã có trong title_line
content[100:400] — Description cơ chế (không code): "By applying X, attacker can Y..."
content[400+]    — Code snippet, PoC, function references → gây anchoring
```

300 chars description = đủ để hint loại bug, không đủ để anchor code pattern.

Với median finding 3,861 chars: `content[100:400]` luôn có dữ liệu (0 findings ngắn hơn 400 chars).

---

## So sánh các approach

| | run-13/24 `content[:350]` | run-25 `chunk[:700]` | M10 `content[100:400]` |
|--|--------------------------|----------------------|------------------------|
| Metadata (title/impact) | Lẫn vào text | Tách riêng title_line ✓ | Tách riêng title_line ✓ |
| Description cơ chế | ~50 chars (bị header chiếm) | Không (chỉ có code) | ~300 chars ✓ |
| Code pattern | Không | Có (700 chars) → contaminate ✗ | Không ✓ |
| Anchoring risk | Thấp | Cao ✗ | Thấp |
| Coverage | ~9% | ~23% (code) | ~8% (description only) |
| run-25 impact | TP=9 (run-24) | TP=6 ✗ | Dự kiến ≥9 |

---

## Verification sau khi implement

```bash
# Kiểm tra format hint trong log sau run-26
grep -A3 "INV historical findings" benchmark/web3bugs/agent-redesign/35/run-26/run.log | head -20

# Không được thấy code snippet (function(), require(), uint128, etc.) trong hint block
# Phải thấy description text (plain English mechanism description)
```

Target run-26: TP ≥ 9 (giữ nguyên H-10/H-13/H-06/H-08), TP = 10 nếu vẫn giữ H-01.

---

## File cần sửa

- `backend/app/services/cyber_session_orchestrator.py`
  - Line 249–251: invariant track hint format
  - Line 379–381: structural track hint format
  - Đổi `chunk_excerpt = (r.get("chunk_content") or r["content"])[:700]` → `desc_excerpt = r["content"][100:400]`
