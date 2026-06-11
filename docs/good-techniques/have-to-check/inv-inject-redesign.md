# INV Injection Redesign — Ý tưởng & Kế hoạch

## Bối cảnh

Simulation contest 35 (run-74) cho thấy HIST-INV Verifier **confirmed=0** dù retrieval quality tốt.
Sau nhiều simulation, xác định 3 root causes xếp theo độ ảnh hưởng:

---

## Root Cause 1 — Full source overwhelms agents (quan trọng nhất)

**Hiện tượng:**
- Isolated simulation (1 contract, ~700 dòng): `clmm_specialist` tìm được H-16, H-17 ✅
- Real pipeline (24 contracts, 3591 dòng, 150KB): `clmm_specialist` miss H-16, H-17 ❌
- Agent bị thu hút vào **pattern nổi bật nhất** (overflow/unchecked) và miss semantic bugs (JIT, nearestTick stale)

**Insight:** Vấn đề không chỉ là "không biết nhìn vào đâu" mà còn là "nhìn đúng function nhưng focus vào pattern sai".

**Ý tưởng fix:**
- Thay vì pass toàn bộ `network_summary` (150KB), chỉ pass contracts có `[HIST-INV]` annotations
- Hoặc pass per-contract chunks: mỗi agent nhận từng contract riêng, không concatenated

---

## Root Cause 2 — Slug cap drop custom inv đúng

**Hiện tượng:**
```python
# run_contract_audit.py — _build_inv_map_from_slugs()
for slug in slugs[:2]:   # chỉ lấy 2 slug đầu
    inv_lines.extend(lines[:2])
return "\n".join(inv_lines[:3])
```
Custom slug có invariant chính xác nhất nhưng xếp thứ 3+ → bị drop.

**Ý tưởng fix (đã test trong simulation):**
```python
# Custom slugs lên đầu, không cap slug, tăng total lines
custom = [s for s in slugs if s.startswith('custom_')]
others = [s for s in slugs if not s.startswith('custom_')]
lines = []
for s in custom + others:          # no slug cap
    lines.extend((inv_lookup.get(s) or [])[:2])
return '\n'.join(lines[:6])         # tăng từ 3 → 6
```

**Kết quả simulation:** H-01 no_inv ❌ → with_inv ✅ (cả old lẫn new mechanism đều giúp được).

---

## Root Cause 3 — Turn2 truncation + secondary contracts out of scope

**Hiện tượng:**
```python
# Turn 2 chỉ nhận 3000 ký tự đầu của primary source
.replace("{source}", primary_source[:3000])
```
- `rangeFeeGrowth` ở dòng 601 → không vào được Turn2
- H-03, H-16 ở `ConcentratedLiquidityPoolManager` → `_filter_source_to_primary` loại bỏ hoàn toàn

**Ý tưởng fix:**
- Turn2 dùng function body thay vì `primary_source[:3000]`
- Pass full annotated source (all contracts có `[HIST-INV]`) thay vì chỉ primary

---

## Simulation Results Summary

| Condition | Isolated (1 contract) | Notes |
|-----------|----------------------|-------|
| No-INV | 2/5 | H-16, H-17 found (clmm_specialist built-in) |
| Old-INV | 3/5 | +H-01 |
| New-INV | 3/5 | +H-01 (same as old for này test) |
| Run-74 (full) | 0/5 | Source overwhelm effect |

**Key finding:** HIST-INV injection giúp ích nhưng chỉ khi source đủ nhỏ để agent không bị overwhelm.

---

## Ý tưởng redesign tổng thể

### Approach A — Per-contract chunking (giải quyết root cause 1)

Thay vì mỗi agent đọc toàn bộ network_summary, chia thành chunks theo contract:
```
Agent run: [contract_1] → findings_1
Agent run: [contract_2] → findings_2
...merge...
```
- Pro: mỗi agent focus vào 1 contract → ít overwhelm hơn
- Con: tốn gấp N lần LLM calls; cross-contract bugs có thể bị miss

### Approach B — Annotated-only source filter (dễ implement hơn)

Chỉ pass vào verifier các contracts có `[HIST-INV]` annotations:
```python
annotated_contracts = _filter_contracts_with_hist_inv(network_summary)
# Thường chỉ 2-3 contracts thay vì 24
```
- Pro: giảm source size đáng kể, giữ nguyên flow
- Con: chỉ giải quyết cho HIST-INV Verifier, không cho R1 agents

### Approach C — Function-targeted injection cho R1 (experimental)

Inject HIST-INV vào R1 agents thay vì chỉ vào HIST-INV Verifier.
R1 agents đọc full source nhưng có `[HIST-INV]` hints → tự anchor attention vào đúng function.
- Pro: leverage existing R1 agents với built-in domain knowledge
- Con: có thể gây anchor bias (agent follow inv pattern thay vì code evidence)

---

## Triển khai sau

Priority theo impact:
1. **Root cause 2** (slug cap fix) — dễ nhất, test đã xác nhận giúp H-01
2. **Root cause 3** (Turn2 source fix) — moderate complexity
3. **Root cause 1** (chunking hoặc annotated-only filter) — cần thêm experiment

File liên quan: `docs/good-techniques/hist-inv-pipeline-issues.md`
