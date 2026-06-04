# HIST-INV Recall Analysis — Contest 5

Phân tích tại sao 8 FN bugs bị bỏ sót trong run-1 (F1=0.323, Recall=0.667).
Dữ liệu từ: `benchmark/web3bugs/agent-redesign/5/run-1/`.

---

## Kết quả tổng quan

| Metric | Giá trị |
|--------|---------|
| TP | 16 (T1=14, T2=2) |
| FP | 59 |
| FN | 8 |
| Precision | 0.213 |
| Recall | 0.667 |
| F1 | 0.323 |

---

## Phân loại 8 FN bugs

### Category 1 — RAG có data, HIST query không surface được

Bug nằm trong RAG (score ≥ 0.65 khi query bằng GT description), nhưng HIST build
generate queries từ operations không đủ gần với ngôn ngữ của finding đó.

| Bug | RAG score (GT query) | Top RAG result | HIST query thực tế | Vấn đề |
|-----|---------------------|----------------|--------------------|--------|
| **H-15** `swapWithSynthsWithLimit` | 0.701 | "swapOut invalid slippage check" | OP: transfer ordering, arithmetic overflow | ST query không generate "wrong variable in second swap leg" |
| **H-18** `_deposit` | 0.673 | "SynthVault rewards can be gamed — Spartan Protocol" | OP: block.timestamp, nested mapping overflow | ST query không generate "spot price weight inflation" |

**Root cause:** ST prompt (`_generate_structural_queries`) describe structural properties của code nhưng không capture được economic attack intent. Với `_deposit()`, ST detect "state written to mapping" nhưng không detect "weight calculated from manipulable spot price".

**Fix hướng tới:** ST prompt cần thêm property: *"External value (price, balance, rate) used in weight/share calculation without manipulation protection."*

---

### Category 2 — RAG có data, dưới threshold

Bug có finding liên quan trong RAG nhưng score < 0.65 (threshold hiện tại).

| Bug | RAG score (GT query) | Top RAG result | Khoảng cách tới threshold |
|-----|---------------------|----------------|--------------------------|
| **H-04** `cancelProposal` | 0.625 | "Any signer can cancel a pending proposal" | −0.025 |
| **H-13** `mintSynth` | 0.646 | "Synth tokens can get over-minted" | −0.004 |

**Root cause:** Threshold 0.65 quá cao cho các bug class ít phổ biến. Các finding liên quan tồn tại trong RAG nhưng bị loại bởi threshold.

**Fix hướng tới:** Xem xét giảm threshold xuống 0.62-0.63, hoặc dùng per-class threshold khác nhau.

---

### Category 3 — HIST assign nhầm function

Bug có HIST annotation đúng nhưng bị gán vào function sai trong call graph.

| Bug | Annotation | Gán vào | Đúng ra phải ở |
|-----|-----------|---------|---------------|
| **H-03** `changeDAO` | `[H-03] Missing DAO functionality to call changeDAO()` (score 0.708) | `DAO()` getter (leaf node) | `changeDAO()` hoặc cross-contract section |

**Root cause:** RAG retrieve đúng finding nhưng HIST builder gán annotation vào function có tên gần nhất (DAO getter), không phải function chứa bug thực (changeDAO).

**Fix hướng tới:** Khi RAG title mention một function name cụ thể (`changeDAO`), annotate đúng function đó thay vì function đang được process.

---

### Category 4 — RAG thiếu data thực sự

Không có finding liên quan trong RAG dù query bằng GT description.

| Bug | RAG score (GT query) | Lý do thiếu |
|-----|---------------------|-------------|
| **H-09** `Router.init` | 0.615 | "Wrong constant value in init" — class hiếm gặp trong RAG |
| **H-25** `Vader.init` | 0.596 | Cùng class với H-09, `secondsPerEra = 1` thay vì 86400 |
| **H-19** `harvest` | 0.627 | "Uninitialized mapping in reward timing" — pattern hiếm |

**Aggravating factor cho H-19:** HIST build LLM call bị fail, fallback về query `"harvest vulnerability"` → score = 0.0, không có annotation nào.

**Root cause:** RAG database (8392 entries từ Solodit) có bias mạnh về access control, reentrancy, arithmetic overflow — các bug class phổ biến. "Wrong constant value" và "uninitialized mapping in time tracking" xuất hiện ít hơn nhiều trong lịch sử.

**Fix hướng tới:** Bổ sung RAG sources (Code4rena, Immunefi) hoặc synthetic examples cho các class hiếm.

---

## Observation: HIST dẫn agents đi sai hướng (H-09, H-25)

Đây là vấn đề phụ nhưng đáng chú ý. Với `init()` functions:

- HIST annotations: "Lack of access controls", "VaultProxy can be initialized by anyone", "Public access to all functions"
- Agents đọc annotations này → focus vào access control → tìm ra "missing access control on init()" → FP
- Trong khi GT bug là "wrong constant value in init()"

HIST không sai (init() historically hay bị access control issues), nhưng annotation density cao cho access control class dẫn đến **confirmation bias** — agents confirm pattern quen thuộc thay vì tìm pattern lạ.

---

## Passive vs Active HIST

Hiện tại HIST annotations là **passive context** — inject vào call graph section của system prompt nhưng không có instruction bắt agent verify từng annotation. Với 795 annotations trải dài 3000+ dòng, agents thực tế:
- Dùng HIST khi annotation trùng với reasoning hiện tại
- Bỏ qua khi không match

**Kết quả test:** 0/192 R1 findings mention "HIST" trong description — agents không explicitly cite hay trace từ HIST annotations.

Việc chuyển HIST sang **active checklist** (agent phải confirm/deny từng annotation) có thể tăng recall nhưng:
1. Không tăng số LLM calls (chỉ thay đổi instruction format)
2. Với H-09/H-25: có thể phản tác dụng (reinforce sai hướng)
3. Với H-03: có thể giúp nếu agent kết nối được `DAO()` getter annotation với `changeDAO()` function

---

## Tóm tắt nguyên nhân và fix

| Nguyên nhân | Bugs ảnh hưởng | Fix |
|-------------|---------------|-----|
| ST query không capture economic intent | H-15, H-18 | Cải thiện ST prompt — thêm property "external value in weight calc" |
| Score threshold quá cao | H-04, H-13 | Giảm threshold hoặc dùng per-class threshold |
| HIST gán nhầm function | H-03 | Title-guided function assignment |
| RAG thiếu coverage | H-09, H-19, H-25 | Mở rộng RAG sources |
| LLM fail → fallback query | H-19 (aggravated) | Retry logic hoặc multi-attempt cho HIST build |

**Không phải vấn đề:**
- Dual-track đã được implement và chạy trong run-1
- Query generation (OP track) hoạt động đúng — vấn đề là ST track chưa đủ tốt
- RAG database size (8392) đủ lớn cho các class phổ biến

---

## Expected recall nếu fix từng nhóm

| Fix | Bugs có thể recover | Recall mới (ước tính) |
|-----|--------------------|-----------------------|
| Cải thiện ST prompt | H-15, H-18 | +2 TP → Recall ~0.75 |
| Giảm threshold | H-04, H-13 | +2 TP → Recall ~0.75 |
| Title-guided assignment | H-03 | +1 TP → Recall ~0.71 |
| Mở rộng RAG | H-09, H-19, H-25 | +2-3 TP → Recall ~0.79-0.83 |
| **Tất cả** | **7-8 bugs** | **Recall ~0.90+** |

*Lưu ý: Các fix có thể overlap (TP tăng không cộng dồn hoàn toàn). FP có thể tăng khi giảm threshold.*
