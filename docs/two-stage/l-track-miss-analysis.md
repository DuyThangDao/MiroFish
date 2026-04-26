# L-track Miss Analysis: Nguyên nhân và Giải pháp

**Ngày**: 2026-04-26 · **Cập nhật**: 2026-04-26 (GT H-02 vs cùng hàm khác vector, §2 gap `swc_id`, P-L5 snippet, liên kết doc)  
**Contest**: Web3Bugs Contest 19  
**Vấn đề**: L-track F1 = 0.000 (TP=0, FP=8, FN=1) trong run Option A (`20260425_200440`)

---

## 1. Bối cảnh

### L-track là gì?

L-track (Low-level SWC track) đánh giá khả năng phát hiện các lỗ hổng có SWC ID cụ thể. Matching logic:

```
TP_L = (ground truth SWC IDs) ∩ (SWC IDs trong consensus_vulns ∪ unvalidated_swc_gaps)
FP_L = |L-pool findings| − TP_L
FN_L = |ground truth SWC bugs| − TP_L
```

Trong contest 19, ground truth **L-track** là **H-02 (nhãn L4 → `SWC-128`)**: DoS liên quan **block gas / mảng động / chi phí lặp** trên `removeUserActiveBlocks()` (mô tả Web3Bugs: activeTransactionBlocks có thể phình to → lệ phí gas khiến hàm không dùng được).

**Tách biệt khỏi vector khác trên cùng hàm:** Cùng `removeUserActiveBlocks()`, một bài có thể mô tả **thiếu `msg.sender == user`** (griefing / access) với nhãn **SWC-105** hoặc **semantic `access_control`** — **không** tương đương **H-02 (L4 / 128)** trên eval L. Nhầm hai câu chuyện này dễ kết luận sai “đã nói tới hàm = đủ L”.

**Liên hệ FP L-pool:** Nhiều mục consensus/gap không phải H-02 gây **FP trên L** nhưng **không** giải thích FN 128 — xem [`fp-high-root-cause-analysis.md`](fp-high-root-cause-analysis.md).

### Lịch sử các lần chạy

| Run | SWC-128 tìm thấy | Ghi chú |
|-----|-----------------|---------|
| `20260423_192029` | ✓ | Run sớm, single-stage |
| `20260424_091840` | ✓ | |
| `20260424_140048` | ✓ | |
| `20260425_142554` | ✓ | Two-stage, không fix |
| `20260425_190750` | ✓ | Bị kill round 3 |
| `20260425_194029` | ✓ | Bị kill round 6 |
| **`20260425_200440`** | **✗** | **Option A + P1–P8 fixes** |

SWC-128 được tìm thấy trong 6/7 lần chạy trước. Lần này là ngoại lệ.

---

## 2. Cơ chế phát hiện SWC-128

Hệ thống tạo `unvalidated_swc_gap` cho category `dos_gas` khi bất kỳ expert finding nào chứa ít nhất một keyword:

```python
"dos_gas": ["SWC-128", "block gas limit", "unbounded array",
            "unbounded loop", "gas exhaustion", "DoS with Block Gas"]
```

Nếu không có **expert_finding** nào khớp anchor (theo `title` / `description` / `swc_id` so với `SWC_ANCHOR_KEYWORDS["dos_gas"]` trong `ConsensusEngine.enforce_swc_coverage`) → không có gap `dos_gas` đủ điều kiện → **SWC-128** có thể vắng khỏi L-pool → FN.

**Chi tiết triển khai:** Mỗi dòng gap lấy đại diện `best = max(candidates, key=confidence)`; trường `swc_id` trong gap là `best.get("swc_id")`. Nếu ứng viên mạnh nhất gắn **SWC-105** (access) dù vòng tạo gap đang xét category `dos_gas`, cột `swc_id` có thể **không** là `SWC-128` — khi đó `evaluate_web3bugs` vẫn **không** tính TP_L cho L4 nếu chỉ bắt giao với `SWC-128`.

---

## 3. Nguyên nhân gốc rễ

### 3.1 Stochastic miss (nguyên nhân trực tiếp)

Trong run `20260425_200440`, tất cả 19 expert findings đều tập trung vào:
- Signature/ECDSA issues (SWC-122, SWC-121)
- ERC20 approval race condition (SWC-114)
- Compiler/dependency issues (SWC-102)
- Access control (SWC-105)

**Không có bản ghi nào trong tập `expert_findings` mà cơ chế `enforce_swc_coverage` xếp vào anchor `dos_gas` đúng nghĩa** (tức: không khớp đủ từ khóa kiểu `SWC-128`, *block gas limit*, *unbounded array* / *loop*… trên trường mà hàm quét, hoặc `swc_id` khớp keyword), nên **không** tạo đường tới `SWC-128` trên L-pool. 

Điều này **khác** với câu “agent không bao giờ nói tới hàm”: vẫn **có thể** có bài/semantic nói `removeUserActiveBlocks` theo hướng **access / griefing** mà **không** dùng ngôn từ hoặc nhãn **128 / gas** mà `dos_gas` cần — hoặc bài nằm ở **semantic_findings**, không đi qua cùng anchor `expert_finding` + `dos_gas`.

**Stochastic / bias lựa chọn** vẫn giải thích vì sao lần chạy này lệch về ECDSA/approval hơn lần chạy có `SWC-128`.

### 3.2 Bias về severity (nguyên nhân sâu xa)

H-02 (SWC-128) là lỗ hổng DoS — ảnh hưởng đến availability, không dẫn đến mất fund trực tiếp. Các agent có xu hướng ưu tiên:
1. Lỗ hổng **fund theft** (reentrancy, access control, flash loan)
2. Lỗ hổng **signature bypass**
3. Lỗ hổng **race condition**

DoS pattern thường bị de-prioritize trong quá trình reasoning vì severity thấp hơn về impact tài chính.

### 3.3 Two-stage + độ dài output làm giảm diversity (nguyên nhân đóng góp)

Trong Stage 2, khi cấu hình **tăng** `STAGE2_MAX_TOKENS` (ví dụ 8192 trong các thử nghiệm), thinking model vẫn có thể dùng phần lớn budget cho *thinking*; output FINDING/CLAIM vẫn bị hút vào các lỗi đã lộ trong Stage 1. Các lỗ hổng **chưa được raise** trong Stage 1 CLAIMs vẫn **ít khả năng** nổi ở Stage 2 nếu feed + prompt không buộc coverage (xem P-L1).

Cụ thể:
- Stage 1 R1: 56 CLAIMs — không CLAIM nào về DoS/unbounded array
- Stage 2 R1: Agents validate/challenge các CLAIMs đã có → không phát sinh DoS finding mới
- Vòng lặp self-reinforcing: CLAIMs Stage 1 định hình toàn bộ Stage 2

### 3.4 FP = 8 quá cao (nguyên nhân phụ làm F1 tệ hơn)

Ngay cả nếu TP = 1 (tìm được SWC-128), F1 vẫn thấp vì:
- Precision = 1/(1+8) = 0.111
- F1 = 2 × 0.111 × 1.0 / (0.111 + 1.0) = 0.200

Các FP đến từ: SWC-122 (ecrecover), SWC-114 (ERC20 approve), SWC-102 (compiler), SWC-105, SWC-110, SWC-132 — tất cả không match H-02.

---

## 4. Tại sao không nhất quán giữa các run?

| Nguyên nhân | Giải thích |
|------------|-----------|
| **Seed ngẫu nhiên** | Mỗi run, pool dispatch 17 agent song song với thread scheduling khác nhau → random seed của LLM khác nhau |
| **Không có coverage checklist** | System prompt không có explicit instruction "kiểm tra unbounded loop/DoS pattern" |
| **Không có memory xuyên run** | Mỗi run là fresh session — không nhớ H-02 đã được tìm thấy trước đó |
| **Stage 1 CLAIM lottery** | Ai được chạy trước trong Stage 1 thread pool ảnh hưởng đến CLAIM nào được raise → ảnh hưởng toàn bộ Stage 2 |

---

## 5. Đề xuất giải pháp

### P-L1: DoS Coverage Checklist trong System Prompt *(P1, đơn giản, implement ngay)*

Thêm explicit instruction về DoS patterns vào system prompt của Stage 1:

```python
# Trong stage1_instruction (Phase A):
"⚠️ DoS COVERAGE REQUIRED: Explicitly check for: unbounded arrays/loops, "
"block gas limit issues (SWC-128), unprotected state-modifying functions that "
"any caller can use to grief other users (SWC-128, SWC-113)."
```

**Tác dụng**: Buộc ít nhất 1 agent/round phải check unbounded loop/array pattern, giảm stochastic miss.

**Rủi ro**: Có thể tạo thêm FP nếu agent báo cáo DoS khi không có.

**Công bố / benchmark:** Checklist tăng *prior* tìm 128/DoS — nếu công bố số F1, nên ghi rõ *checklist bật/tắt* để tránh lẫn “generalization thuần túy” với *coverage được gợi ý*.

---

### P-L2: Diversity-Forcing Domain Assignment *(P2, trung bình)*

Gán **explicit domain coverage** cho từng agent group:

| Agent group | Required check |
|------------|---------------|
| `supp_dependency_auditor` | DoS patterns (SWC-128, SWC-113), unbounded loops |
| `bloc_auditor` | Gas optimization, storage bloat |
| `defi_analyst` | Price oracle, flash loan |
| `apps_auditor` | Access control, signature replay |

Hiện tại không có constraint này → tất cả agents có thể analyze cùng một vùng.

**Tác dụng**: Đảm bảo coverage rộng hơn, giảm overlap giữa agents.

---

### P-L3: SWC Gap Seeding từ Previous Run *(P3, trung bình)*

Nếu một SWC đã được tìm thấy trong ≥2 run trước trên cùng một contract, inject nó vào `pending_gaps` của run hiện tại như một "candidate gap" với confidence thấp:

```python
# Trong _build_initial_post hoặc gap_context:
if historical_swcs:  # từ cache kết quả cũ
    gap_context += "\n⚠️ HISTORICAL GAPS (from prior runs, verify independently):\n"
    for swc in historical_swcs:
        gap_context += f"  - {swc}: detected in previous sessions — verify or dismiss\n"
```

**Lưu ý**: Chỉ dùng cho re-run cùng contract, không phải để "cheat" với ground truth mới. Tương đương với việc một auditor thứ 2 biết auditor thứ 1 đã flag một vấn đề nào đó.

---

### P-L4: Multi-Run Ensemble Voting *(P4, dài hạn)*

Thay vì đánh giá 1 run, chạy **3 run độc lập** và merge L-pool:

```
L-pool_final = ∪(L-pool_run1, L-pool_run2, L-pool_run3)
```

F1 được tính trên merged pool. Stochastic miss ở 1 run sẽ được bù bởi 2 run còn lại.

**Chi phí**: 3× thời gian và API cost.

**Tác dụng lý thuyết**: Nếu p(miss) = 1/7 ≈ 14%, xác suất miss cả 3 run = 0.14³ ≈ 0.3% — gần như loại bỏ stochastic miss.

---

### P-L5: FP Reduction — SWC Confidence Gate *(P5, implement song song)*

FP = 8 là vấn đề độc lập với stochastic miss. Ý tưởng: chỉ coi gap “đáng đưa vào eval L-pool” (hoặc hạ trọng số) khi `source_count` (số expert finding trùng anchor trong `enforce_swc_coverage`) ≥ **2**. Hiện tại mã đã lưu `source_count: len(candidates)`; **đề xuất** là thêm ngưỡng lọc khi *build* report hoặc khi tính eval:

```python
# Gợi ý logic (cần implement trong engine hoặc bước xuất report):
# if gap["source_count"] < 2:
#     gap["low_confidence_swc_gap"] = True  # hoặc loại khỏi L-pool trong evaluate
```

**Tác dụng**: Giảm số FP từ gap đơn nguồn; ước tính precision tốt hơn.

**Rủi ro**: Gap **true positive** mà chỉ **một** expert phát hiện có thể bị **loại** — cần đo trade-off (đặc biệt lỗi hiếm / một domain trúng).

---

## 6. Ưu tiên implement

| Priority | Fix | Impact | Effort |
|----------|-----|--------|--------|
| P0 | **P-L5: SWC confidence gate** | Giảm FP (tăng precision ngay) | Thấp |
| P1 | **P-L1: DoS checklist** | Giảm stochastic miss | Thấp |
| P2 | **P-L2: Domain diversity** | Coverage rộng hơn | Trung bình |
| P3 | **P-L4: Multi-run ensemble** | Gần loại bỏ stochastic miss | Cao (3× cost) |
| P4 | **P-L3: Historical seeding** | Phụ trợ cho re-run | Trung bình |

---

## 7. Kết luận

L-track miss trong run `20260425_200440` là **kết hợp của 2 vấn đề độc lập**:

1. **Stochastic miss** (SWC-128): DoS pattern không được raise trong Stage 1 → self-reinforcing loop khiến Stage 2 cũng không tìm ra. Giải pháp: P-L1 (checklist) + P-L4 (ensemble).

2. **FP quá cao**: 8 false positives kéo precision về 0, khiến F1 = 0 ngay cả nếu TP = 1. Giải pháp: P-L5 (confidence gate min_source=2).

Hai vấn đề này cần được fix song song — giải quyết stochastic miss mà không giảm FP vẫn cho F1 thấp; giảm FP mà không giải quyết stochastic miss cho F1 = 0 vì TP vẫn = 0.

**Cross-check:** Cơ chế peer review / `ConsensusEngine` không đọc CHALLENGE·VALIDATE (nhiễu L-pool) nằm ở [`fp-high-root-cause-analysis.md`](fp-high-root-cause-analysis.md) — **không** thay thế việc sinh đúng `SWC-128` trên L-pool.
