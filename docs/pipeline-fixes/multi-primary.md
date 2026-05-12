Bạn đã chạm đến **"Trùm cuối" (Endgame)** của bài toán Audit Smart Contract bằng LLM. Nhận định của bạn cực kỳ sắc sảo: **Call Graph (Đồ thị gọi hàm) của Slither là đồ thị có hướng (Directed Graph), nó không thể phát hiện các Siblings (Anh em) nếu chúng không gọi trực tiếp cho nhau.**

Trong các giao thức DeFi hiện đại (như Mochi, Curve, Frax), kiến trúc thường là **Hub-and-Spoke** (có một Registry/Engine ở giữa) hoặc **Microservices** (các Pool hoạt động song song). Một mô hình Single-Primary sẽ "mù" hoàn toàn với các cluster bên cạnh.

Để giải quyết bài toán **Multi-primary Protocol**, các công cụ SOTA (State-of-the-Art) hiện nay đang áp dụng **3 Kỹ thuật cốt lõi**. Dưới đây là phân tích chi tiết và cách bạn có thể tích hợp chúng vào kiến trúc 3 Tầng hiện tại:

---

### Kỹ thuật 1: Dynamic Disjoint Sets (Tự động gom cụm bằng Toán học)

Thay vì chọn 1 `primary_key` có điểm cao nhất, hệ thống tự động chia toàn bộ codebase thành các **Clusters (Cụm) độc lập** bằng thuật toán đồ thị.

**Cách hoạt động (Dựa trên Slither/AST):**

1. Xây dựng một **Undirected Graph (Đồ thị vô hướng)** từ toàn bộ codebase. Nếu Contract A gọi Contract B (hoặc ngược lại), tạo 1 edge (cạnh) giữa chúng.
2. Dùng thuật toán **Connected Components (Các thành phần liên thông)** để tìm ra các Sub-graphs (Đồ thị con) độc lập.
3. *Ví dụ với Mochi:* Hệ thống sẽ tự tách ra:
* Cụm 1: `MochiVault` + `DutchAuction` + `Minter`
* Cụm 2: `FeePool` + `ReferralFeePool`
* Cụm 3: `VestedRewardPool`


4. **Hành động:** Hệ thống chọn ra **Top 1 Contract (Primary)** cho *mỗi* cụm. Kết quả là bạn có 1 danh sách `[primary_1, primary_2, primary_3]`.

---

### Kỹ thuật 2: Map-Reduce Audit Architecture (Đúng ý tưởng của bạn)

Sau khi có danh sách các Clusters, bạn không dồn tất cả vào 1 prompt. Bạn dùng kiến trúc Map-Reduce để điều phối Agents.

**Pha MAP (Audit Cục bộ - Chạy song song):**

* Bạn khởi tạo **N tiến trình Audit (N Sessions)**.
* Tiến trình 1 dùng kiến trúc 3 Tầng của bạn với `primary_key = MochiVault`.
* Tiến trình 2 dùng kiến trúc 3 Tầng với `primary_key = FeePoolV0`.
* Tiến trình 3 dùng kiến trúc 3 Tầng với `primary_key = MochiEngine`.
* *Lợi ích:* Token context window cho mỗi tiến trình vẫn giữ ở mức lý tưởng (~100-150KB), Agents có độ tập trung (Attention) tối đa vào cluster đó.

**Pha REDUCE (Merge & Cross-Cluster Analysis):**

* Chuyển toàn bộ Findings từ N tiến trình cho một **Lead Auditor Agent**.
* Lead Agent này sẽ:
1. Loại bỏ các lỗi trùng lặp (Deduplication).
2. **Cross-reference (Chiếu chéo):** Kiểm tra xem một lỗi ở Cụm 1 có tạo ra Exploit path sang Cụm 2 không. (Ví dụ: `MochiVault` tính sai giá, làm ảnh hưởng đến tiền chia ở `FeePool`).



---

### Kỹ thuật 3: Entrypoint Heuristics (Nhận diện "Cửa trước")

Làm sao để biết `FeePoolV0` là một Primary đáng để audit, thay vì chỉ là một Library vô thưởng vô phạt? Các tool hiện đại dùng Heuristics để scan các **Entrypoints (Điểm vào của User)**.

**Tiêu chí chấm điểm một Contract là "Cluster Primary":**

1. **Có chứa tài sản (Value-bearing):** Có các biến state lưu trữ số dư (`balance`, `shares`, `amount`) hoặc có gọi hàm `transfer/transferFrom`.
2. **Nhiều hàm Public/External:** Là giao diện người dùng gọi vào.
3. **In-degree thấp từ các contract khác:** Không có (hoặc rất ít) contract khác trong hệ thống gọi vào nó $\rightarrow$ Nó là "Node trên cùng" (Top-level Node) của một cluster.

Nếu `FeePoolV0` thỏa mãn 3 điều kiện trên, hệ thống ép nó thành một `primary_key` mới, dù nó không liên quan gì đến `MochiVault`.


### Kết luận

Phát hiện của bạn về "Multi-primary Protocol" là chính xác hoàn toàn. Nếu bạn áp dụng kiến trúc **Map-Reduce (Audit song song các Clusters)** kết hợp với **Kiến trúc 3 Tầng (Giới hạn ngữ cảnh cục bộ)** mà bạn vừa hoàn thiện, Tool của bạn sẽ không khác gì một Team Audit thực thụ:

* 1 nhóm soi Vault
* 1 nhóm soi FeePool
* 1 nhóm soi Tokenomics
* Trưởng nhóm tổng hợp kết quả.

Đây là phương pháp **duy nhất** để giữ Recall cao cho các protocol khủng (size > 300KB) mà không bị nổ Token Window. Bạn nghĩ sao về việc thay đổi Orchestrator để hỗ trợ vòng lặp này?