Context Caching (Bộ nhớ đệm bối cảnh) — Tối ưu cho bối cảnh lớn và cố định

Nếu bạn có một lượng ngữ cảnh rất lớn (như một cuốn sách, tài liệu API dài, mã nguồn dự án, video, hoặc danh sách hệ thống hướng dẫn `system_instruction` phức tạp) mà **nhiều API call tiếp theo đều cần dùng lại**, thì **Context Caching** là tính năng hoàn hảo.

* **Cách hoạt động:** Bạn gửi bối cảnh lớn đó lên một lần duy nhất để tạo một đối tượng `CachedContent`. Vertex AI sẽ xử lý trước (precompute) và lưu trữ nó dưới dạng một mã bộ nhớ đệm (**Cache Name/ID**). Ở các API call tiếp theo, bạn chỉ cần truyền câu hỏi mới của user kèm theo cái ID này.
* **Lợi ích vượt trội:**
* **Tiết kiệm chi phí lên tới 90%:** Đối với các dòng model Gemini, các token được gọi từ Explicit Cache sẽ được giảm giá sâu so với giá input token thông thường.
* **Giảm đáng kể độ trễ (Latency):** Mô hình không cần phải tính toán lại toàn bộ ma trận bối cảnh khổng lồ từ đầu.


* **Cơ chế hỗ trợ:** * *Explicit Caching (Tường minh):* Bạn chủ động tạo cache thông qua API, đặt thời gian hết hạn (TTL) và gọi đích danh khi cần.
* *Implicit Caching (Ngầm định):* Hệ thống tự động tối ưu và lưu cache các token trùng lặp từ các request trước đó mà bạn không cần thay đổi cấu trúc code.



### Ví dụ minh họa cấu trúc gọi API (Python):

```python
from google import genai
from google.genai import types

client = genai.Client()

# Bước 1: Tạo cache cho phần bối cảnh lớn ban đầu
cache = client.caches.create(
    model="gemini-2.5-flash",
    config=types.CreateCachedContentConfig(
        contents=[document_lon_hoac_video],
        system_instruction="Hướng dẫn hệ thống dài..."
    )
)

# Bước 2: Ở các API call sau, chỉ truyền ID thay vì truyền lại cả cụm dữ liệu
response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="Câu hỏi cụ thể của user lúc này",
    config=types.GenerateContentConfig(
        cached_content=cache.name  # Inject ngữ cảnh động bằng ID
    )
)

```

---

## 1. Bản chất của việc "Đọc" prompt: Giai đoạn Prefill

Khi bạn gửi một câu lệnh (prompt) đến LLM, trước khi mô hình sinh ra token đầu tiên, nó phải trải qua giai đoạn gọi là **Prefill (Nạp và xử lý prompt)**.

Trong kiến trúc Transformer, cơ chế Tự chú ý (Self-Attention) yêu cầu mô hình phải tính toán mối quan hệ giữa **tất cả các token với nhau**. Đối với mỗi token trong prompt, GPU phải thực hiện hàng loạt phép nhân ma trận khổng lồ để tạo ra 3 vector: $Q$ (Query), $K$ (Key), và $V$ (Value).

* **Chi phí tính toán của Self-Attention tăng theo hàm mũ bậc hai $O(N^2)$** với $N$ là độ dài prompt.
* Nếu prompt của bạn dài 100,000 token, GPU sẽ phải tiêu tốn một lượng tài nguyên cực kỳ khủng khiếp (Compute/FLOPs) chỉ để làm một việc duy nhất: Tính toán xong ma trận $K$ và $V$ cho 100,000 token đó.

---

## 2. Điểm khác biệt cốt lõi: Pinning Text vs. KV Caching

### Kịch bản A: Chỉ Pin ngữ cảnh (Như cách append text thông thường)

Mỗi khi bạn thực hiện một API call mới:

1. Bạn gửi câu hỏi mới + File `CLAUDE.md` (dưới dạng text thuần).
2. Hệ thống coi đây là một prompt hoàn toàn mới.
3. **GPU buộc phải cày lại từ đầu:** Nó thực hiện lại toàn bộ các phép nhân ma trận $O(N^2)$ cho các token trong file `CLAUDE.md` để tạo lại các vector $K$ và $V$.
4. **Kết quả:** Bạn bị tính đầy đủ tiền Input Token cho mỗi lượt gọi, vì nhà cung cấp phải cho GPU chạy hết công suất để xử lý lại đống text đó.

### Kịch bản B: Sử dụng Context Caching (Vertex AI / Anthropic Prompt Caching)

Ở lần gọi đầu tiên (hoặc khi khởi tạo cache), mô hình xử lý context lớn đó và sinh ra các ma trận $K$ và $V$. Thay vì xóa bỏ chúng sau khi trả lời, Vertex AI sẽ **đóng băng và lưu toàn bộ ma trận $K$ và $V$ này vào bộ nhớ tốc độ cao (HBM của GPU hoặc RAM phân tán)**.

Ở các API call tiếp theo:

1. Bạn chỉ gửi câu hỏi mới (ví dụ: 100 token) kèm theo ID của Cache.
2. Mô hình **bỏ qua hoàn toàn** việc tính toán ma trận cho 100,000 token cũ. GPU không phải chạy lại các lớp tuyến tính (linear layers) cho phần ngữ cảnh đó nữa.
3. Mô hình chỉ cần tính $Q, K, V$ cho 100 token mới, sau đó "chấm" (attend) trực tiếp vào ma trận $K, V$ đã được lưu sẵn trong bộ nhớ.
4. **Kết quả:** Bản chất agent **không đọc lại full context**. Nó chỉ truy xuất (look up) các trạng thái toán học đã tính toán xong từ trước.

---

## 3. Tại sao nhà cung cấp lại giảm giá sâu cho bạn?

Các nền tảng đám mây (Google Cloud, AWS) định giá API dựa trên hai yếu tố chính: **Năng lượng tính toán của GPU (Compute)** và **Băng thông bộ nhớ (Memory Bandwidth)**.

* Khi xử lý prompt thông thường (Prefill), GPU bị nghẽn ở **Compute** (phải tính toán ma trận quá nhiều). Đây là tác vụ tốn kém nhất về cả thời gian lẫn tiền điện.
* Khi dùng Context Caching, tác vụ chuyển từ nghẽn Compute sang nghẽn **Memory** (chỉ việc đọc dữ liệu có sẵn từ bộ nhớ ra). Việc đọc từ bộ nhớ tiết kiệm năng lượng và thời gian hơn việc bắt GPU tính toán lại từ đầu hàng tỷ phép tính rất nhiều.

Vì Google tiết kiệm được một lượng lớn tài nguyên tính toán (GPU FLOPs) trên hạ tầng của họ, họ sẵn sàng giảm giá cho bạn (thường rẻ hơn tới 80% - 90% so với giá token thông thường) và giảm luôn cả độ trễ (Time-to-First-Token) cho ứng dụng của bạn.

---

## Tóm tắt so sánh

| Tiêu chí | Pinning Context (Text Append) | Context Caching (KV Cache) |
| --- | --- | --- |
| **Dữ liệu lưu trữ** | Văn bản thô (Strings/Tokens) | Trạng thái toán học ($K$ và $V$ matrices) |
| **Hành vi của GPU** | Phải tính toán lại toàn bộ từ đầu cho mỗi API call. | Bỏ qua tính toán phần cũ, chỉ nạp từ bộ nhớ vào và tính toán phần mới. |
| **Độ phức tạp tính toán** | $O(N^2)$ trên toàn bộ prompt (bao gồm cả context cũ). | $O(M^2) + O(M \times N)$ với $M$ là số token mới ($M \ll N$). |
| **Chi phí** | Tính đủ 100% giá trị Input Token cho mỗi lần gọi. | Giảm giá sâu (chỉ bằng ~10% - 20% giá gốc) cho các token nằm trong cache. |