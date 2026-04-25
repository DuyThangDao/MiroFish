# Web3Bugs — Evaluation protocol (MiroFish)

> **Mục tiêu:** Định nghĩa thống nhất cách đánh giá trên [Web3Bugs](https://github.com/ZhangZhuoSJTU/Web3Bugs) để báo cáo trong paper: **hai track độc lập** (L→SWC và S→semantic), **loại SE/SC khỏi ground truth chính**, và **Precision / Recall / F1** riêng cho từng track.  
> **Triển khai tham chiếu:** `backend/scripts/evaluate_web3bugs.py` (cần đồng bộ logic với tài liệu này khi chỉnh script).

---

## 1. Phạm vi và nguyên tắc

| Thành phần | Quyết định |
|------------|------------|
| **Nguồn GT** | `results/bugs.csv` — cột Contest ID, Bug ID, Bug Label, mô tả. |
| **Track L (pattern / SWC)** | Mọi nhãn **L\*** (L1, L2, …, LA, LB) → ánh xạ sang **một tập SWC** kỳ vọng (xem bảng trong code: `L_TO_SWC`). |
| **Track S (semantic)** | Mọi nhãn **S1\*, S2\*, …, S6\*** → ánh xạ sang **category** semantic của tool (`S_TO_CATEGORIES` trong code). |
| **Loại khỏi GT chính** | **SE**, **SE-1 … SE-4**, **SC** — không đưa vào mẫu số recall cho metric chính (xem §3). |
| **Hai chỉ số riêng** | **P/R/F1\_L** chỉ từ L-bugs và findings SWC; **P/R/F1\_S** chỉ từ S-bugs (S1–S6) và `semantic_results` (+ quy tắc chồng chéo SWC→semantic nếu có — §5). |

**Căn cứ taxonomy gốc:** [Web3Bugs `docs/standard.md`](https://github.com/ZhangZhuoSJTU/Web3Bugs/blob/main/docs/standard.md).  
**Lưu ý:** Ánh xạ L→SWC và S→chuỗi semantic là **quy ước kỹ thuật** (hai taxonomy ghép nhau); cần **công bố bảng map** trong paper hoặc appendix, không gọi là “bảng chính thức từ tác giả Web3Bugs”.

---

## 2. Tại sao tách L và S, và tại sao bỏ SE/SC

- **L\***: bug có oracle kiểm tra tương đối tổng quát (reentrancy, overflow, gas, …) → phù hợp **SWC / static+LLM** có detector pattern.
- **S1–S6**: cần hiểu **ngữ nghĩa / business** → phù hợp **semantic track** (category có cấu trúc).
- **SE / SC**: “unexpected operations” hoặc **implementation-specific**; lớp GT quá rộng hoặc phụ thuộc ngữ cảnh ngoài source → đưa vào denominator làm metric **khó bảo vệ** và dễ **FP/lenient-TP ảo** nếu gom vào `other`.

---

## 3. Ground truth cho từng track

### 3.1 Tập bug dùng cho metric chính (in-scope)

- **G\_L:** tất cả bug có nhãn bắt đầu bằng `L` (theo `Bug Label`).
- **G\_S:** tất cả bug có nhãn thuộc **S1 … S6** (gồm cả nhánh con S1-1, S2-1, …).
- **Không thuộc metric chính:** mọi nhãn **SE\***, **SC**, **O\***, và các nhãn không parse được.

### 3.2 Báo cáo bổ sung (khuyến nghị)

- Bảng **per contest:** số bug **bị loại** theo nhãn (SE/SC/O/…) để tránh nghi ngờ cherry-picking.
- (Tùy chọn) **Track phụ:** chỉ báo recall qualitative hoặc confusion nhỏ trên SE/SC nếu sau này tool ổn định với bucket `other` — **không** trộn vào F1 chính.

---

## 4. Pool finding của tool (đầu vào matcher)

| Nguồn | Dùng cho track |
|--------|----------------|
| `consensus_vulns[]` — trường `mitre_techniques` (SWC) | **L** (+ có thể suy ra category cho §5) |
| `unvalidated_swc_gaps[]` (SWC thứ cấp) | **L** (ghi rõ trong paper nếu tính vào L — tránh đếm trùng) |
| `semantic_results[]` — `category` | **S** |

**Chuẩn hóa tên hàm** (nếu dùng strict match): theo quy ước trong `evaluate_web3bugs.py` (`_norm_fn`).

---

## 5. Quy tắc match TP (tối thiểu)

### 5.1 Lenient (mặc định khuyến nghị cho báo cáo chính khi GT không có tên hàm)

- **L:** Tồn tại ít nhất một finding có **SWC ∩ L\_TO\_SWC(label)** khác rỗng.
- **S:** Tồn tại ít nhất một finding semantic có `category` thuộc tập cho nhãn đó (`S_TO_CATEGORIES`).

### 5.2 Strict (tùy chọn)

- Ngoài điều kiện lenient, **finding phải có tập hàm không rỗng** và **giao hàm** với tập hàm GT **khi** GT có danh sách hàm đáng tin (hiện `bugs.csv` không có — có thể bổ sung sau từ annotation tay hoặc report Code4rena).

### 5.3 Chồng chéo SWC ↔ semantic (cùng một bug S)

- Nếu bug thuộc **G\_S** nhưng tool **chỉ** báo SWC (không báo đúng category semantic), có hai lựa chọn **nhất quán**:
  - **A:** chỉ tính TP cho **track S** khi khớp **`semantic_results.category`** (không dùng SWC làm chứng cứ cho TP\_S). SWC trùng họ lỗi có thể ghi **phụ lục** (“SWC-aligned detection on S-class bugs”) — không đếm đôi một bug vào cả L và S.
  - **B:** cho phép **fallback** SWC→semantic qua bảng cố định (`SWC_TO_SEMANTIC` trong code) **chỉ** cho track S — cần mô tả rõ trong paper (*S-detection with SWC assist*).

Chọn **một** chính sách cho mỗi **bảng kết quả** báo cáo; xem **§5.5** nếu dùng lộ trình hai bước A → B.

### 5.4 Ghi chú — ưu tiên **rõ ràng, dễ giải thích** (clarity)

Khi mục tiêu paper là **metric dễ bảo vệ** và **một câu chuyện đơn giản** cho reviewer:

| Mục tiêu | Chính sách | Lý do |
|----------|------------|--------|
| **Rõ ràng nhất** | **A** | Một câu đủ: *track L đo khớp SWC; track S đo khớp category từ semantic pipeline — hai kênh tách bạch.* Không phải giải thích thêm vì sao bug nhãn S lại được TP từ nhánh SWC. |
| **Recall S cao hơn / “có bắt được bug S hay không”** | **B** | Cho phép tính TP\_S khi chỉ có SWC khớp `SWC_TO_SEMANTIC`. Cần **subsection hoặc đoạn định nghĩa** rõ: ranh giới với track L, và vẫn **một bug = một TP** (không nhân đôi). |

**Đánh đổi với A:** Một phần bug trong **G\_S** có thể **chỉ** xuất hiện dưới dạng finding SWC (`consensus_vulns`) mà `semantic_results` chưa gán đúng category → **recall / F1\_S có thể thấp hơn B**. Điều đó **không sai methodology**; nên ghi thẳng trong paper, ví dụ: *một phần bug phân loại S trong Web3Bugs vẫn có thể được báo cáo ở track L nếu khớp SWC — metric S chỉ phản ánh đầu ra semantic.*

**Khuyến nghị mặc định cho MiroFish (paper):** **A** nếu ưu tiên clarity; **B** chỉ khi sẵn sàng viết dài hơn và đồng nhất story “phát hiện bug S qua mọi kênh hợp lệ”.

### 5.5 Chiến lược hai bước: **A trước**, **B** khi cần (sensitivity / bound)

Hợp lý trong R&D: chạy và báo cáo **A** trước; nếu **recall S / F1\_S** quá thấp trong khi **SWC đã chỉ đúng họ lỗi** nhưng `semantic_results` chưa khớp category (FN “do lọt” theo A), có thể **bổ sung** chạy **B** trên **cùng** output và GT.

**Cách trình bày trong paper (tránh hiểu nhầm cherry-picking):**

| Vai trò | Chính sách | Ghi chú |
|---------|------------|---------|
| **Chính (primary)** | **A** | Abstract, bảng đầu tiên, claim chính về *semantic pipeline*. |
| **Phụ (secondary)** | **B** | Một cột hoặc bảng riêng: *“S-track with SWC assist (def. §5.3-B)”* — diễn giải là **phân tích nhạy cảm** hoặc **upper bound** trên recall S khi cho phép chứng cứ SWC, **không** thay thế định nghĩa primary. |

**Việc nên làm trước khi quyết định B:** Thống kê **phụ lục** dưới A — ví dụ số bug ∈ G\_S bị FN theo A nhưng có finding SWC khớp `SWC_TO_SEMANTIC` (ước lượng “B sẽ cứu được bao nhiêu TP”) để biện minh **B có cơ sở**, không chỉ vì số xấu.

**Không nên:** Đổi hoàn toàn story paper sang **chỉ B** sau khi thấy A xấu mà **không** giữ hàng A và **không** giải thích vai trò hai bước — dễ bị reviewer hỏi về **post-hoc** chọn metric.

---

## 6. TP, FP, FN và P / R / F1 **riêng từng track**

Đếm theo **từng bug** trong tập GT của track (bug-level).

- **TP\_L:** số bug ∈ G\_L được match theo §5 (L).
- **FN\_L:** |G\_L| − TP\_L.
- **FP\_L:** số finding (hoặc “báo cáo lỗi” atomic theo quy ước) **không** gán được cho bất kỳ bug nào ∈ G\_L như một TP — **hoặc** quy ước đơn giản hóa như script hiện tại: `FP = max(0, N_findings_L − TP_L)` với `N_findings_L` là số finding có SWC “lành mạnh” cho track L (cần định nghĩa để tránh đếm semantic-only vào L).

**Khuyến nghị làm rõ trong paper (điều chỉnh so với script thô):**

- **Cách 1 (bug-centric precision):** mỗi finding chỉ “ăn” tối đa **một** TP bug; finding thừa = FP. Công bằng hơn khi tool bắn nhiều cảnh báo.
- **Cách 2 (script-style upper bound):** giữ công thức đơn giản nhưng **ghi rõ** là conservative / approximate.

Tương tự cho **S:**

- **TP\_S, FN\_S** trên G\_S.
- **FP\_S** theo cùng quy ước đã chọn.

**Công thức:**

\[
\text{Precision} = \frac{TP}{TP+FP},\quad
\text{Recall} = \frac{TP}{TP+FN},\quad
F1 = \frac{2PR}{P+R}
\]

(Tránh chia cho 0; quy ước P=R=F1=0 khi mẫu số 0.)

---

## 7. Gộp nhiều contest: micro vs macro

- **Micro:** cộng tất cả TP/FP/FN trên toàn contests → một bộ P/R/F1. Ổn khi số bug/contest không cực lệch.
- **Macro:** tính F1 từng contest rồi **trung bình** (có thể bỏ qua contest |G|=0). Phản ánh tốt hơn contest nhỏ.

**Khuyến nghị:** báo **micro** trong bảng chính; **macro** ở appendix hoặc ngược lại tùy story — nhưng phải **chọn một** làm số “chính” trong abstract.

---

## 8. So sánh baseline (paper)

- **Slither / Mythril:** chủ yếu **track L** (và có thể một phần SWC trùng họ S nếu báo cáo riêng).
- **GPTScan / LLM baseline:** trích dẫn hoặc rerun với **cùng in-scope GT** và **cùng matcher**; không so sánh số F1 “full paper họ” nếu protocol khác.

---

## 9. Checklist triển khai

- [ ] Đồng bộ `evaluate_web3bugs.py`: **loại SE/SC khỏi G\_S và G\_L** (hiện SE/SC vẫn có thể đang được tính vào nhánh S — cần sửa nếu muốn khớp §3).
- [ ] Cố định bảng `L_TO_SWC`, `S_TO_CATEGORIES`, (optional) `SWC_TO_SEMANTIC`.
- [ ] Chính sách match S: **A = primary**; **B = secondary** nếu áp dụng §5.5 — cả hai phải có trong paper nếu báo B. Cách **FP** (§6).
- [ ] Appendix: số bug loại theo nhãn; danh sách contest; phiên bản snapshot Web3Bugs (commit hash).

---

## 10. Điều chỉnh / note thêm so với plan ban đầu

1. **Sửa evaluator nếu cần:** đảm bảo SE/SC **không** vào denominator của F1\_S chính (tránh mâu thuẫn với §3).
2. **Không gộp F1\_L và F1\_S thành một số duy nhất** trong abstract — hoặc nếu có “combined”, định nghĩa rõ (ví dụ trung bình hai F1 macro) và gọi là secondary.
3. **Ghi rõ model/API và seed** cho reproducibility.
4. **Strict/lenient:** ít nhất một dòng trong paper về mode chính; strict chỉ khi có GT hàm đáng tin.

---

*Tài liệu này mô tả protocol mục tiêu; mọi lệch so với code hiện tại cần được reconcile trước khi chạy số cho paper.*
