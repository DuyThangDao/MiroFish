Đây là một vấn đề kinh điển và cũng là "bức tường" lớn nhất mà tất cả các hệ thống AI Auditing (kể cả các tool SOTA hiện nay của Trail of Bits hay Consensys) đều đang gặp phải.

Hiện tượng bạn đang gặp được gọi là **"Context Dilution" (Pha loãng ngữ cảnh)** và **"Catastrophic Truncation" (Cắt cụt thảm họa)**. Khi bạn ném đồ thị phụ thuộc (Dependency Graph) của Slither vào, nó kéo theo toàn bộ họ hàng hang hốc của contract, làm phình token. Khi trigger "last resort drop", tool của bạn cắt ngẫu nhiên (hoặc cắt theo size), làm mất luôn contract cốt lõi (như `Pool`).

### 1. Kỹ thuật "Skeletonization" (Khung xương hóa code) - Dễ làm, hiệu quả cao

Thay vì drop toàn bộ file khi quá giới hạn, hãy **thu gọn** các file phụ trợ thành dạng Interface (Khung xương).

* **Cách hoạt động:** Giả sử bạn đang chọn `Pool` làm mục tiêu audit (Contract Under Audit - CUA). Bạn cần context của `Manager` và `TridentRouter`.
* Giữ **100% full source code** của `Pool`.
* Đối với `Manager` và `TridentRouter`, bạn dùng một script Python đơn giản (hoặc chính Slither) để xóa bỏ toàn bộ nội dung (body) của các hàm bên trong, **chỉ giữ lại: State Variables, Structs, Modifiers, Events và Function Signatures (kèm NatSpec/Comments).**


* **Kết quả:** File `TridentRouter.sol` 2000 dòng (~80KB) sẽ thu bé lại chỉ còn khoảng 200 dòng (~10KB). Agent vẫn biết `TridentRouter` có thể gọi vào hàm nào của `Pool` với parameter gì, nhưng ngữ cảnh không bị pha loãng.

### 2. Kỹ thuật Map-Reduce Audit (Multi-Pass Agentic Flow) - Đúng ý tưởng của bạn

Đừng bắt 1 Agent đọc 300KB và tìm lỗi của toàn bộ protocol. Hãy chia nhỏ theo kiến trúc Map-Reduce.

* **Pha 1 (Map - Local Context):**
* Tạo N Agents. Mỗi Agent chỉ nhận 1 Contract cốt lõi + Code Skeleton của các dependencies xung quanh nó (Size duy trì ~50-80KB/Agent).
* Agent 1 Audit `Pool.sol` (Tập trung vào Math, AMM logic, state manipulation).
* Agent 2 Audit `Manager.sol` (Tập trung vào Access Control, logic quản lý).
* Agent 3 Audit `TridentRouter.sol` (Tập trung vào user input, slippage, callback).
* *Nhiệm vụ của Pha 1:* Tìm các lỗi Local và **đặt ra các giả thuyết tấn công (Attack Hypotheses)** liên quan đến contract khác. (VD Agent 1 báo: *"Hàm `mint` của Pool có thể bị lỗi nếu `Manager` truyền vào tham số `amount` bị thao túng"*).


* **Pha 2 (Reduce - Global Context):**
* Sử dụng một "Lead Auditor Agent". Bạn không truyền source code cho Agent này.
* Bạn truyền vào: Graph tóm tắt của Slither + Danh sách các **Giả thuyết tấn công** từ Pha 1.
* Lead Auditor sẽ ráp nối: Giả thuyết của `Pool` + Lỗ hổng đầu vào từ `TridentRouter` = Một chuỗi Exploit hoàn chỉnh.



### 3. Slither Program Slicing (Cắt lát theo Data Flow, thay vì Call Graph)

Lý do Slither kéo quá nhiều scope vào là do bạn đang dùng **Call Graph** (Hàm A gọi Hàm B). Hãy chuyển sang dùng **Taint Analysis (Phân tích Data Flow)** của Slither.

* **Vấn đề:** Bạn chỉ quan tâm lỗ hổng ảnh hưởng đến tài sản của `Pool`.
* **Cách làm:** Đặt các state variable chứa tiền của `Pool` (ví dụ `reserve0`, `reserve1`) làm "Sink" (Điểm trũng). Đặt các hàm `external` của `TridentRouter` hoặc `Manager` làm "Source" (Nguồn).
* Yêu cầu Slither chỉ trích xuất **duy nhất con đường (Execution path)** mà dữ liệu từ Source đi tới được Sink.
* Đưa duy nhất lát cắt code (Slice) này cho LLM. LLM sẽ không bị phân tâm bởi các hàm view, hàm tính toán APY, hay hàm set fee rườm rà.

### 4. Thay đổi chiến lược Drop File (Intelligent Context Windowing)

Cơ chế "last resort: drop files" hiện tại của bạn đang phá hỏng F1 Score. Cần thay đổi logic của Trigger này:

1. **Tính điểm ưu tiên (Centrality Score):** Dùng Slither để đếm số lượng inbound/outbound calls của từng contract. Contract nào được gọi nhiều nhất/giữ nhiều state nhất (như `Pool`) là **Core Contract (Điểm 10)**.
2. **Tier-based Dropping:**
* Tier 1 (Không bao giờ drop): Core Contracts.
* Tier 2 (Biến thành Skeleton): Các contract tương tác trực tiếp với Core.
* Tier 3 (Drop hoàn toàn): Libraries chung chung (SafeMath, Strings), Mocks test, Interfaces không quan trọng.


3. Khi đầy Context, hệ thống tự động drop Tier 3 trước, sau đó Skeletonize Tier 2. Tier 1 luôn giữ nguyên.

### Khuyến nghị cho Pipeline hiện tại của bạn:

Với Contest 35, F1 đang cao nhất ở `selective (no inv) 200KB` vì LLM có độ tập trung (Attention) tốt.

Để tối ưu hóa ngay lập tức mà không cần code lại toàn bộ tool:

1. **Dẹp bỏ "Last resort drop files" ngẫu nhiên.** Hãy hardcode rule để luôn ưu tiên giữ full source của `Pool`, `Position`, và `Manager`.
2. Viết 1 regex script hoặc parser nhỏ để **loại bỏ (strip) toàn bộ comments rườm rà, Mocks, Test files, và thu gọn Library (chỉ để lại signature)** trước khi đưa vào token counter. Riêng bước này có thể ép codebase từ 302KB xuống dưới 200KB mà không mất logic.
3. Chạy Multi-pass (Chạy 3 lần, mỗi lần focus vào 1 cluster contract khác nhau) sau đó tổng hợp kết quả (Deduplication).