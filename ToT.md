**Tree of Thoughts (ToT)** (Cây suy nghĩ) là một kỹ thuật nâng cao dành cho các mô hình ngôn ngữ lớn (LLM), được giới thiệu vào năm 2023 nhằm khắc phục điểm yếu chí mạng của các mô hình AI: **Tư duy tuyến tính**.

Để bạn dễ hình dung, cơ chế tạo văn bản mặc định của LLM giống như một người nói mà không kịp nghĩ—từ sau nối tiếp từ trước từ trái sang phải mà không có khả năng quay lại sửa sai nếu lỡ đi vào ngõ cụt.

---

## 1. Sự tiến hóa từ Prompt truyền thống đến ToT

Để hiểu ToT, hãy nhìn vào hành trình tiến hóa của cách chúng ta "ra lệnh" cho AI:

* **Standard Prompting (Hỏi-Đáp thông thường):** Đưa đầu vào và bắt AI ra ngay kết quả. (Ví dụ: *"Hãy giải bài toán này"* $\rightarrow$ AI đưa ra một đáp án duy nhất).
* **Chain of Thought (CoT - Chuỗi suy nghĩ):** Yêu cầu AI *"Hãy suy nghĩ từng bước một"*. Kỹ thuật này bắt AI viết ra các bước trung gian theo một đường thẳng tuyến tính.
* **Tree of Thoughts (ToT - Cây suy nghĩ):** Thay vì chỉ đi theo một con đường duy nhất, ToT cho phép AI **tự rẽ nhánh** thành nhiều hướng suy nghĩ khác nhau, tạo thành một cấu trúc hình cây. Tại mỗi nhánh, AI sẽ tự đánh giá xem hướng đi đó có triển vọng không. Nếu bế tắc, nó sẽ **quay lui (backtrack)** để thử nhánh khác.

---

## 2. Cách thức hoạt động của Tree of Thoughts

Một chu trình ToT hoàn chỉnh mô phỏng rất chính xác cách bộ não con người giải quyết các bài toán khó (System 2 - Tư duy chậm và thấu đáo), bao gồm 4 bước chính được lặp đi lặp lại:

### Bước 1: Phân rã bài toán thành các "Suy nghĩ" (Thoughts)

Thay vì bắt AI giải cả bài toán lớn, hệ thống yêu cầu AI sinh ra các bước trung gian (gọi là một *thought*). Ví dụ, trong bài toán lập kế hoạch, một *thought* có thể là "Lên danh sách các việc cần làm trong ngày đầu tiên".

### Bước 2: Sinh ra các nhánh suy nghĩ (Thought Generator)

Tại một bước, thay vì chỉ chọn 1 cách giải quyết, AI sẽ đề xuất ra 3-4 phương án khác nhau (các nhánh cây).

* *Nhánh A:* Giải quyết bằng cách tối ưu chi phí.
* *Nhánh B:* Giải quyết bằng cách tối ưu thời gian.
* *Nhánh C:* Giải quyết bằng cách dùng bên thứ ba.

### Bước 3: Tự đánh giá các nhánh (State Evaluator)

Đây là phần cốt lõi tạo nên sự khác biệt. AI đóng vai một "Giám khảo" độc lập để chấm điểm cho các nhánh do chính nó sinh ra ở bước 2. Nó thường phân loại theo 3 trạng thái:

* `Sure` (Chắc chắn đúng hướng).
* `Maybe` (Có khả năng đúng, cần phân tích tiếp).
* `Impossible` (Vô lý/Ngõ cụt $\rightarrow$ Loại bỏ ngay để tiết kiệm tài nguyên).

### Bước 4: Thuật toán tìm kiếm (Search Algorithm)

Hệ thống sử dụng các thuật toán tìm kiếm kinh điển trong tin học như **BFS (Tìm kiếm theo chiều rộng)** hoặc **DFS (Tìm kiếm theo chiều sâu)** để duyệt qua các nhánh cây suy nghĩ này nhằm tìm ra lộ trình từ gốc đến ngọn (đáp án cuối cùng) có điểm số cao nhất.

---

## 3. Tại sao ToT lại cực kỳ hiệu quả cho việc Audit Smart Contract hay Tìm Bug?

Trong các bài báo nghiên cứu bảo mật Web3 gần đây (như bài *Logic Meets Magic* năm 2025), khi họ tuyên bố đạt Recall gần như tuyệt đối (95-99%) trên tập Web3Bugs, họ đều phải cấu hình LLM chạy theo framework Tree of Thoughts này. Lý do là vì:

* **Khả năng "Giả định lập luận" (Hypothetical Reasoning):** Để tìm một lỗi logic phức tạp (ví dụ: *Flash Loan Attack*), AI không thể nhìn vào code là ra ngay lỗi. Với ToT, nó sẽ giả định:
* *Nhánh 1:* "Nếu hacker gọi hàm `deposit()` rồi ngay lập tức gọi `withdraw()` trong cùng 1 block thì sao?" $\rightarrow$ Tự chạy thử luồng code $\rightarrow$ Đánh giá xem có lỗi không.
* *Nhánh 2:* "Nếu hacker thao túng giá trị Oracle trước khi gọi hàm?" $\rightarrow$ Tự chạy thử luồng code $\rightarrow$ Phát hiện thấy biến số dư bị âm $\rightarrow$ Đánh dấu đây là lỗ hổng trọng yếu.


* **Hạn chế việc AI "Báo lỗi bừa":** Nhờ có bước 3 (Self-evaluation), một AI Agent đóng vai Auditor sẽ liên tục bác bỏ các suy nghĩ sai lệch hoặc hoang tưởng (hallucination) của AI Agent sinh mã, giúp kết quả trả ra có độ tin cậy cao hơn nhiều.

**Nhược điểm lớn nhất:** Kỹ thuật này cực kỳ tốn token và tốn thời gian, vì bạn phải gọi API LLM liên tục hàng chục lần chỉ để giải quyết một bài toán duy nhất. Do đó, nó thường chỉ được dùng trong nghiên cứu hoặc các tác vụ đòi hỏi độ chính xác tuyệt đối chứ ít khi xuất hiện ở các công cụ chat phổ thông.