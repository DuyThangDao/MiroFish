# RAG Utilization Issues

## Tóm tắt

Pipeline có RAG DB phong phú (Spearbit + past audits) nhưng injection rate thực tế rất thấp:
- Run-3 contest 35: **15 injections / 176 possible** (8.5%)
- Phần lớn bị block bởi 2 vấn đề dưới đây

---

## Vấn đề 1 — Score threshold quá cao

### Mô tả

`_SCORE_INJECT_THRESHOLD_INV = 0.70` tại `cyber_session_orchestrator.py:111`

Comment trong code: *"calibrated from Phase 5c score distribution (0.576–0.737)"*

Tức là observed scores chỉ trải từ **0.576–0.737**. Threshold 0.70 đang block tất cả patterns
có score **0.576–0.699** — khoảng **60-70% của toàn bộ data có liên quan**.

### Cơ chế query

`build_rag_query(inv_text)` strip aggressively trước khi embed:
- Bỏ function signatures, dotted refs
- **Bỏ CamelCase** → `ConcentratedLiquidityPool`, `secondsPerLiquidity` biến mất
- Bỏ protocol names (Uniswap, Aave, ...)

Kết quả: query text rất generic → similarity tự nhiên với historical patterns chỉ đạt 0.65–0.73.
Không phải text về invariant và về violation là "khác bản chất" — về semantics chúng vẫn related
(đều nói về reserve accounting, liquidity, fee state). Vấn đề là score range tự nhiên của
embedding similarity thấp, và threshold 0.70 đang ở top 30% của range đó.

### Bằng chứng (run-3, contest 35)

| Loại | Count |
|------|-------|
| Injected (score ≥ 0.70) | 15 |
| Skipped — below threshold (0.65–0.69) | 33 |
| Skipped — independent audit target | 72 |

Với threshold = 0.65 → 33 injections thêm (tổng ~48), gấp ~3x hiện tại.

### Giải pháp đề xuất

Hạ `_SCORE_INJECT_THRESHOLD_INV` từ 0.70 xuống **0.65**.

Rủi ro: patterns ở 0.65–0.69 có thể ít chính xác hơn → thêm noise. Cần test bằng 1 run.

`_MAX_RAG_INJECT_PER_AGENT = 4` vẫn giữ nguyên — chỉ inject top-4 by score → ngay cả khi
threshold hạ, mỗi agent tối đa 4 patterns.

---

## Vấn đề 2 — "Independent audit target" filter có bug logic

### Mô tả

Với multi-target contest (e.g., contest 35 có 4 pools), code tại `cyber_session_orchestrator.py:194`:

```python
def _extract_independent_targets(network_summary, primary):
    # Lấy tất cả targets rồi loại bỏ primary
    targets = re.findall(r'TARGET \d+.*?(\w+)\s*\(primary\)', network_summary)
    return [t for t in targets if t != primary]
```

`_primary = target_contracts[0]` = **ConcentratedLiquidityPool** (primary của contest).

Kết quả `_independent_targets = ["HybridPool", "ConstantProductPool", "IndexPool"]`.

List này được dùng **giống nhau cho TẤT CẢ 22 agents** — không phân biệt agent đang phân tích
target nào.

### Bug

Filter logic tại line 210–217:

```python
if any(t.lower() in inv_lower for t in independent_targets):
    skip
```

**Scenario bị ảnh hưởng:** Agent đang phân tích `HybridPool` (Target 2). Turn 1 extract
`INV-2: "In HybridPool, reserve0 and token1 must always..."`. Filter kiểm tra:
"HybridPool" có trong `_independent_targets`? → **YES → SKIP**.

→ Agent phân tích HybridPool nhưng invariant về chính HybridPool bị skip — vô lý.

### Nguyên nhân

Filter được thiết kế với giả định "chỉ 1 primary target," nhưng contest 35 có **4 independent
primary targets**. Hệ quả: invariants về bất kỳ pool nào ngoài ConcentratedLiquidityPool đều bị
skip, kể cả khi agent đang phân tích đúng pool đó.

### Bằng chứng

Contest 35 run-3: **72/120 checked = 60% bị skip** do filter này.

### Giải pháp đề xuất

Thay vì 1 list `_independent_targets` chung cho tất cả, truyền **target hiện tại** của từng agent
và skip invariant nếu nó nhắc đến target KHÁC (không phải target agent đang phân tích):

```python
# Hiện tại (bug): dùng 1 list cứng cho tất cả agents
_independent_targets = ["HybridPool", "ConstantProductPool", "IndexPool"]

# Đề xuất: mỗi agent biết target của mình, skip invariants về targets khác
# agent phân tích HybridPool → skip INVs về CLP, CPP, IndexPool
# agent phân tích CLP → skip INVs về Hybrid, CPP, IndexPool
```

Tuy nhiên cần cẩn thận: hiện tại agents không được gán target cụ thể (tất cả nhận cùng
`network_summary` chứa cả 4 pools). Cần thêm metadata `agent.primary_target` hoặc đọc từ profile.

Nếu không muốn thay đổi kiến trúc: giải pháp đơn giản hơn là **bỏ filter này hoàn toàn** và
để threshold tự lọc. RAG patterns trong DB là từ historical audits (không phải từ contest này)
nên không có nguy cơ cross-contamination thực sự — chỉ là historical patterns về AMM/DeFi
bugs nói chung.

---

## Độ ưu tiên

| Vấn đề | ROI | Độ phức tạp | Đề xuất |
|--------|-----|------------|---------|
| Hạ threshold 0.70 → 0.65 | Trung bình | Thấp (1 dòng) | Thử ngay |
| Fix independent target filter | Cao (giải phóng 72 skips/run) | Trung bình | Xem xét sau |

Nên thử hạ threshold trước (1 dòng code, ít rủi ro), sau đó đánh giá kết quả rồi quyết định
có fix filter không.
