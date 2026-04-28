# Consensus Vote Fragmentation — Phân tích và Hướng khắc phục

> Vấn đề phát lộ khi kết hợp prompt enforcement (split finding per function) với manifest fix (focus directive đúng contract) — findings bị phân tán votes, không ai đủ ngưỡng vào consensus.

---

## 1. Cơ chế hiện tại

### 1.1 Pipeline từ agent output đến consensus_vulns

```
Phase A/B/C (10 rounds, ~20 agents)
    ↓
Raw findings: ExpertFinding objects (title, SWC, function, evidence)
    ↓
Consensus Engine — _cluster_findings()
  Cluster theo title similarity + SWC anchor keywords
  Mỗi cluster = 1 candidate finding
    ↓
Confidence scoring:
  L1 (intra-group) = % agents trong cùng domain group đồng ý   × WEIGHT 0.40
  L2 (cross-group) = số domain groups khác nhau có finding     × WEIGHT 0.60
  confidence = L1×0.40 + L2×0.60 × attacker_gate
    ↓
Filter: confidence < MIN_CONFIDENCE (0.35) → drop → enforce_swc_coverage → gap
    ↓
Step 6b Tier routing:
  _backfill_functions(): extract fns từ description nếu affected_assets rỗng
  _is_tier1(): bool(affected_assets) AND bool(recommendations)
  Tier 1 → consensus_vulns   (actionable)
  Tier 2 → unvalidated_swc_gaps  (triage signal)
```

### 1.2 Clustering hiện tại

Clustering dùng **title fuzzy match + SWC anchor keywords**:

```python
# Hai findings được merge nếu:
# - Jaccard similarity của title tokens > threshold
# - Hoặc cùng SWC anchor keyword (vd: "overflow", "reentrancy")
```

Findings với title khác nhau về function name KHÔNG tự động merge:
```
"SWC-101 in _mint()"     → cluster A (2 votes)
"SWC-101 in _burn()"     → cluster B (1 vote)
"SWC-101 in to128()"     → cluster C (2 votes)
```

---

## 2. Vấn đề gặp phải

### 2.1 Vote Fragmentation (Nhóm A)

**Điều kiện xảy ra:** Prompt enforcement có câu *"If the same SWC appears in N functions, write N separate FINDINGs"* → agents split 1 vulnerability thành nhiều findings function-specific.

**Hệ quả:**

```
Không có split (run cũ):
  "SWC-101 unsafe cast" ← 7 agents đồng ý → confidence cao → PASS MIN_CONFIDENCE ✅

Có split (run mới):
  "SWC-101 in _mint()"    ← 2 agents → confidence thấp → FAIL ❌
  "SWC-101 in _burn()"    ← 1 agent  → confidence thấp → FAIL ❌
  "SWC-101 in to128()"    ← 2 agents → confidence thấp → FAIL ❌
  → Tổng: 5 agent signals tồn tại nhưng không ai vượt ngưỡng
  → SWC-101 rớt xuống gap với note "Multi-domain gap — 3 domains"
```

**Bằng chứng:** Run 2 (prompt enforcement, manifest sai `primary=so`) → SWC-101 vào consensus vì agents không follow focus directive, tất cả gộp vào 1 generic finding. Run 4 (prompt enforcement, manifest đúng `primary=ConcentratedLiquidityPool`) → SWC-101 không vào consensus vì agents focus đúng → split findings → vote fragmentation.

### 2.2 Low Attention Signal (Nhóm B)

**Điều kiện xảy ra:** Vulnerability nằm trong 1 function ít nổi bật, hoặc yêu cầu domain knowledge chuyên sâu → chỉ 1–2 specialist agent nhận ra.

**Hệ quả:** Ngay cả khi không có split, confidence của 1–2 agents vẫn thấp hơn MIN_CONFIDENCE (0.35). Không có cơ chế nào tăng weight cho finding từ specialist.

**Ví dụ:** L7 bugs trong contest 35 là unsafe cast ở tick math functions (`_getAmountsForLiquidity`) — pattern rất specific, chỉ agents có context về concentrated liquidity mới nhận ra.

### 2.3 Quan hệ giữa 2 nhóm

```
Nhóm A (Vote fragmentation)     Nhóm B (Low attention signal)
────────────────────────────    ─────────────────────────────
Nguyên nhân: Split findings     Nguyên nhân: Ít agents chú ý
Fix được bởi: Đề xuất 1/2/3    Fix được bởi: Đề xuất 4/5
Tần suất: Cao (mỗi khi          Tần suất: Trung bình (khi
  prompt enforcement bật)         vulnerability obscure/rare)
```

---

## 3. Tác động

| Metric | Không có vấn đề | Có vấn đề |
|---|---|---|
| SWC-101 trong consensus | ✅ | ❌ (rơi xuống gap) |
| F1_L_class | 0.857 | 0.706–0.750 (vẫn đo được qua gap) |
| F1_L_fn | ~0.857 | **0.000** (gap không tính vào Tier-1) |
| Report value | Có function location | Chỉ có class-level hint |

**Tác động thực tế cho auditor:**
- F1_L_class không bị ảnh hưởng nhiều (gap vẫn được đếm vào class-level pool)
- F1_L_fn bị ảnh hưởng nặng nhất — không có Tier-1 finding → report không chỉ rõ function location
- Auditor nhận được hint "có SWC-101" nhưng không biết function nào cụ thể

---

## 4. Hướng khắc phục

### 4.1 Đề xuất 1 — SWC-aware clustering [Nhóm A]

Thêm bước cluster theo SWC ID trước title-similarity clustering. Tất cả findings có cùng SWC được gộp thành 1 cluster, confidence tính trên toàn bộ pool, function locations được merge từ tất cả contributors.

```python
# Pseudo-code
def _swc_aware_cluster(findings):
    swc_clusters = defaultdict(list)
    for f in findings:
        for swc in f.swc_ids:
            swc_clusters[swc].append(f)
    
    merged = []
    for swc, group in swc_clusters.items():
        merged_finding = merge(group)  # union of all fns, max severity, etc.
        merged.append(merged_finding)
    return merged
```

| Ưu điểm | Trade-off |
|---|---|
| Giải quyết trực tiếp vote fragmentation | Cùng SWC ở 2 contract khác nhau bị merge thành 1 finding → mất granularity |
| L1/L2 tính trên toàn bộ SWC signals | Phân biệt 2 instances độc lập của cùng SWC phức tạp hơn |
| Giữ đủ function locations | Implementation trung bình phức tạp |

### 4.2 Đề xuất 2 — Đổi prompt: list functions trong 1 finding [Nhóm A]

Bỏ *"write N separate FINDINGs"*, thay bằng yêu cầu liệt kê nhiều functions trong 1 finding:

```
FINDING: SWC-101 Silent Truncation
SWC: SWC-101
FUNCTION: _mint(), _burn(), to128(), _getAmountsForLiquidity()
DESCRIPTION: Explicit casts in these functions silently truncate...
```

| Ưu điểm | Trade-off |
|---|---|
| Đơn giản nhất — chỉ sửa prompt | Agents có thể bỏ sót functions khi liệt kê |
| Agents converge về 1 title → L1 cao | FUNCTION field cần parse list thay vì single name |
| Không đụng kiến trúc engine | Một số agents vẫn có thể split (LLM không hoàn toàn follow instruction) |

### 4.3 Đề xuất 3 — Two-stage confidence: class-level threshold → function extraction [Nhóm A]

Tách scoring thành 2 bước độc lập:
1. **Stage 1 — Class gate:** Tính confidence ở SWC class level (gộp tất cả findings cùng SWC). Nếu pass MIN_CONFIDENCE → tạo base finding.
2. **Stage 2 — Function enrichment:** Extract và merge tất cả function locations từ contributing findings vào base finding.

```
SWC-101 class confidence = f(all SWC-101 findings) → pass threshold
    ↓
Base finding: SWC-101
    ↓
Enrich: fns = union([f.fns for f in swc101_findings]) = {_mint, _burn, to128}
    ↓
Output: SWC-101 finding với đầy đủ function locations
```

| Ưu điểm | Trade-off |
|---|---|
| Kiến trúc đúng nhất — class detection và function localization là 2 concerns riêng | Thay đổi lớn nhất — cần refactor consensus engine |
| Không phụ thuộc vào cách agents viết title | Rủi ro introduce bugs mới trong engine |
| Preserves tất cả function signals | Phức tạp hơn để maintain |

**Lưu ý:** Đề xuất 3 vẫn bị ảnh hưởng bởi Nhóm B — nếu chỉ 1–2 agents nhận ra SWC, class-level confidence vẫn thấp hơn MIN_CONFIDENCE.

### 4.4 Đề xuất 4 — Domain-weighted confidence [Nhóm B]

Findings được confirm bởi specialist agent (agent có domain match với SWC) được weight cao hơn.

```python
SPECIALIST_WEIGHT = {
    "overflow_expert":    ("SWC-101", 2.5),  # 1 specialist = 2.5x normal vote
    "reentrancy_expert":  ("SWC-107", 2.5),
    "defi_analyst":       ("SWC-101", "SWC-107", 1.5),
}
```

| Ưu điểm | Trade-off |
|---|---|
| Giải quyết được rare/single-function vulnerabilities | Cần define specialist mapping cho từng SWC — maintenance overhead |
| 1 specialist + 1 cross-domain có thể đủ pass threshold | Specialist agents có thể hallucinate với high-weight |
| Phản ánh đúng domain knowledge value | Cần calibrate weights cẩn thận để không tăng FP |

### 4.5 Đề xuất 5 — Targeted verification round [Nhóm B]

Sau Phase C, inject thêm 1 round chuyên biệt: dựa vào SWC candidates đã detect, hỏi specialist agents trực tiếp:

```
"ConcentratedLiquidityPool có explicit casts không?
 Liệt kê tất cả uint128(x), int24(y) trong các functions sau: ..."
```

| Ưu điểm | Trade-off |
|---|---|
| Tăng attention cho vulnerable patterns cụ thể | Thêm 1 round = thêm ~8–10 phút và LLM cost |
| Specialist được hỏi trực tiếp → signal mạnh hơn | Cần biết SWC candidates trước (từ Phase A/B output) |
| Tổng quát — không phụ thuộc vào tên function hay contract | Tăng độ phức tạp pipeline |

---

## 5. Ma trận lựa chọn

| Đề xuất | Giải quyết nhóm | Độ phức tạp | Rủi ro FP | Ưu tiên |
|---|---|---|---|---|
| 2 — Đổi prompt (list functions) | A | Thấp | Thấp | **Thử trước** |
| 1 — SWC-aware clustering | A | Trung bình | Thấp | Sau đề xuất 2 |
| 4 — Domain-weighted confidence | B | Trung bình | Trung bình | Song song |
| 3 — Two-stage confidence | A | Cao | Thấp | Dài hạn |
| 5 — Targeted verification round | B | Cao | Thấp | Dài hạn |

**Khuyến nghị triển khai:**
- **Ngắn hạn:** Đề xuất 2 + theo dõi F1_L_fn
- **Trung hạn:** Đề xuất 1 làm safety net nếu Đề xuất 2 không đủ
- **Dài hạn:** Đề xuất 3 (refactor engine) hoặc Đề xuất 5 (targeted round)

---

## 6. Điều kiện để xác nhận fix hiệu quả

Sau khi implement bất kỳ đề xuất nào:

```
Điều kiện thành công:
1. SWC-101 vào consensus_vulns (không nằm trong gap) ổn định qua ≥ 2 lần chạy
2. F1_L_fn > 0 cho contest 35
3. |F1_L_class - F1_L_fn| < 0.10 (đang hội tụ)
4. Pool size Tier-1 không tăng quá nhiều (FP không tăng đột biến)
```
