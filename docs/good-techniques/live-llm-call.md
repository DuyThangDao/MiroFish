## Kiến trúc vận hành: Vừa chạy vừa "bơm" Context

Thay vì mô hình Request/Response truyền thống (gửi một cục text - đợi - nhận một cục text), hệ thống sẽ hoạt động theo dạng **Session-based (Theo phiên kết nối liên tục)**.

```
[ Your Backend ]                              [ Gemini Live API Session ]
       |                                                   |
       |=========== 1. Mở kết nối WebSocket ===============>| (Chỉ bắt tay 1 lần)
       |--- 2. Truyền Context lõi (Mục lục) -------------->| 
       |                                                   |--- 3. Agent đọc mục lục,
       |                                                   |      phân tích yêu cầu...
       |                                                   |
       |<== 4. Phát tín hiệu: "Tôi cần dữ liệu Mục 2.1" ====| (Tool Call nhảy vào giữa luồng)
       |--- 5. Bơm ngay dữ liệu chi tiết Mục 2.1 --------->|
       |                                                   |--- 6. Agent hấp thụ dữ liệu mới,
       |                                                   |      tiếp tục sinh câu trả lời...
       |<========== 7. Trả kết quả cuối cùng/Stream =======|

```

### Cách thức hoạt động chi tiết:

1. **Khởi tạo phiên duy nhất:** Backend của bạn thiết lập một kết nối WebSocket/gRPC tới Vertex AI. Đây được tính là **1 cuộc gọi duy nhất (Single Call)**. Kết nối này giữ mở (Persistent Connection).
2. **Nạp ngữ cảnh lõi:** Bạn gửi Prompt kèm theo `system_instruction` và Context lõi (ví dụ: Danh mục chính, cấu trúc DB, hoặc file index ngắn). Agent bắt đầu phân tích.
3. **Trích xuất động mid-stream (Function Calling trong luồng):** Khi Agent xử lý đến một phần cần chi tiết, thay vì đoán mò hoặc dừng cuộc gọi, nó sẽ kích hoạt một **Tool Call (Function Call)** ngay trên luồng WebSocket đó.
4. **Bơm Context thời gian thực:** Backend của bạn nghe thấy tín hiệu yêu cầu từ luồng, lập tức query vào Database/Vector DB của bạn và gửi trả (inject) dữ liệu thô đó ngược lại vào đúng luồng WebSocket đang mở.
5. **Agent tiếp thu và chạy tiếp:** Agent nhận được dữ liệu bổ sung, lập tức đưa vào bộ nhớ đệm tạm thời của phiên đó và tiếp tục suy luận mà không hề làm gián đoạn hay ngắt quãng kết nối.

---

## Tại sao phương pháp này giải quyết triệt để bài toán của bạn?

### 1. Bẻ gãy giới hạn RPM (Requests Per Minute)

Các hạn mức (Quota) của API thường tính theo số lượng Request độc lập gửi lên hệ thống trong một phút.

* Với cách làm cũ, mỗi lần Agent muốn gọi công cụ lấy thêm data, bạn phải kết thúc request cũ, chạy code ở backend, rồi tạo request mới $\rightarrow$ Bạn nhanh chóng chạm trần RPM.
* Với Live API (WebSocket), bạn chỉ tốn **1 Request** duy nhất cho toàn bộ phiên làm việc của Agent (dù nó có kéo dài 5 phút và gọi công cụ 100 lần). Hệ thống lúc này sẽ quản lý theo số phiên đồng thời (Concurrent Sessions) và Số token/phút (TPM), giải phóng bạn khỏi nỗi lo nghẽn RPM.

### 2. Triệt tiêu độ trễ kết nối (Zero Connection Latency)

Mỗi lần tạo một HTTP Request mới, hệ thống phải thực hiện lại quá trình bắt tay TCP, thiết lập mã hóa TLS, định tuyến... mất từ vài trăm mili-giây đến cả giây.
Với luồng hai chiều, đường ống dẫn dữ liệu đã được thông suốt ngay từ giây đầu tiên. Việc "hỏi và bơm" dữ liệu chi tiết diễn ra với độ trễ gần như bằng 0 (Real-time).

### 3. Giải quyết triệt để Agent Bias và Tràn Context window

Vì Agent chỉ lấy đúng phần dữ liệu nó cần tại thời điểm nó cần (Just-in-time context), cửa sổ chú ý (Attention) của mô hình luôn được giữ ở trạng thái "sạch sẽ" và tập trung nhất. Nó không bị nhiễu bởi hàng tá thông tin không liên quan của các mục lục khác.

---

## Cách triển khai trên Vertex AI

Để dùng kỹ thuật này, bạn sẽ không dùng hàm `generate_content` thông thường, mà sử dụng Client SDK hỗ trợ kết nối Live/Stream (Ví dụ với Google GenAI SDK mới):

```python
from google import genai
from google.genai import types

client = genai.Client()

# Định nghĩa tool/function để Agent tự gọi khi cần lấy context chi tiết
get_detail_tool = types.Tool(
    function_declarations=[
        types.FunctionDeclaration(
            name="get_detailed_context",
            description="Lấy tài liệu chi tiết của một mục cụ thể khi cần.",
            parameters=... # Khai báo tham số mục cần lấy
        )
    ]
)

# Khởi tạo kết nối hai chiều (WebSocket)
async with client.aio.live.connect(model="gemini-2.0-flash-exp", config=types.LiveConnectConfig(tools=[get_detail_tool])) as session:
    # 1. Gửi ngữ cảnh lõi ban đầu
    await session.send(input="Đây là mục lục hệ thống: [Mục 1, Mục 2, Mục 3]. Hãy giải quyết yêu cầu X.")
    
    # 2. Vòng lặp lắng nghe liên tục trong 1 kết nối
    async for response in session.receive():
        # Nếu Agent phát tín hiệu cần thêm dữ liệu
        if response.tool_call:
            for call in response.tool_call.function_calls:
                # Backend tự động lấy data từ DB của bạn
                detail_data = my_backend_db.fetch(call.args['section_name']) 
                
                # Bơm ngược lại vào luồng ngay lập tức
                await session.send(input=types.LiveClientToolResponse(
                    function_responses=[types.FunctionResponse(name=call.name, response={"content": detail_data})]
                ))
        
        # Nếu Agent trả ra câu trả lời cho user
        elif response.server_content:
            print(response.server_content.model_turn.parts[0].text)

```

Kiến trúc này biến Agent của bạn thành một thực thể "chủ động": Cầm một tấm bản đồ thô (Core Context), đi đến đâu thấy mờ thì tự động yêu cầu Backend "bật đèn" (Inject Context chi tiết) đến đó, tối ưu toàn diện từ chi phí, hiệu năng cho đến độ thông minh.

Để trả lời chính xác cho bài toán thiết kế hệ thống của bạn, chúng ta cần bóc tách rõ hai khía cạnh: Cách Google tính tiền thực tế và Bản chất kinh tế của kiến trúc "Lazy Loading" (Tải chậm khi cần) qua Live API.

---

## 1. Chi phí Vertex AI hiện tại tính theo Call hay theo Token?

Vertex AI (đặc biệt là đối với các dòng model Gemini) tính chi phí **hoàn toàn dựa trên số lượng Token (Input và Output)**, chứ **không tính theo số lượng API Call**.

Bất kể bạn gom mọi thứ vào 1 call duy nhất kéo dài 10 phút, hay chia nhỏ thành 100 call độc lập, hệ thống của Google vẫn sẽ bật máy đếm token để tính tiền:

* **Input Tokens:** Tổng số lượng token bạn gửi lên (bao gồm chỉ dẫn hệ thống, lịch sử chat tích lũy, context bổ sung, và các lệnh gọi hàm).
* **Output Tokens:** Số lượng token mô hình sinh ra để trả lời (bao gồm cả các *thinking tokens* - token suy luận ngầm nếu bạn dùng các dòng model chuyên lý luận).

*Lưu ý:* Nếu bạn dùng thêm các dịch vụ nâng cao như **Vertex AI Search** để làm RAG tự động, Google sẽ tính thêm một khoản phí phụ thuộc theo số lượt truy vấn (ví dụ: khoảng $4 - $6 cho mỗi 1.000 lượt query tìm kiếm dữ liệu). Nhưng đối với bản thân mô hình Gemini, thước đo duy nhất vẫn là Token.

---

## 2. Triển khai theo cách "Lazy Loading via WebSocket" có tiết kiệm chi phí không?

Câu trả lời ngắn gọn là: **Có tiết kiệm rất lớn so với phương pháp nhồi nhét tài liệu (Prompt Stuffing), nhưng bạn phải hết sức lưu ý một "bẫy chi phí" đặc thù của giao thức kết nối dạng phiên (Session).**

### Khoản tiết kiệm được (Điểm cộng lớn):

Giả sử kho dữ liệu chi tiết của bạn rất khổng lồ (khoảng 5 triệu token).

* Nếu dùng cách cũ (Prompt Stuffing), ngay từ câu hỏi đầu tiên bạn đã phải nạp cả 5 triệu token $\rightarrow$ Trả chi phí Input khổng lồ ngay lập tức.
* Nếu dùng Lazy Loading, bạn chỉ nạp Mục lục (ví dụ: 2.000 token). Khi Agent cần thông tin của Mục 2, nó gọi tool và bạn chỉ bơm thêm 20.000 token của riêng mục đó vào. Bạn **tránh được việc trả tiền cho 4,98 triệu token thừa** mà Agent không hề đụng tới trong phiên làm việc đó.

### "Bẫy chi phí" cần lưu ý (Cơ chế Tích lũy của Live API):

Google Cloud áp dụng quy tắc gọi là **Session Context Window Billing** cho các kết nối Live API (WebSocket/gRPC).

* Trong một phiên kết nối liên tục, **mô hình sẽ tính tiền lại toàn bộ các token đang có mặt trong cửa sổ ngữ cảnh tại mỗi lượt tương tác (Turn)**. Các token ở lượt trước sẽ được xử lý lại để mô hình duy trì trí nhớ và mạch suy luận.

Hãy xem kịch bản chi phí tăng tiến dưới đây:

* **Turn 1 (Khởi tạo):** Bạn gửi Mục lục (2.000 tokens).

$$\rightarrow \text{Chi phí Turn 1} = 2.000 \text{ input tokens}$$


* **Turn 2 (Agent cần dữ liệu A):** Bạn bơm thêm Chi tiết Mục A (10.000 tokens). Lúc này, ngữ cảnh của phiên chứa cả Mục lục và Mục A.

$$\rightarrow \text{Chi phí Turn 2} = 2.000 (\text{Mục lục}) + 10.000 (\text{Mục A}) + \text{câu hỏi mới} \approx 12.000 \text{ input tokens}$$


* **Turn 3 (Agent xử lý xong A, cần dữ liệu B):** Bạn bơm tiếp Chi tiết Mục B (10.000 tokens). **Nếu bạn giữ nguyên luồng:** Ngữ cảnh phiên lúc này đã tích lũy cả Mục lục, Mục A và Mục B.

$$\rightarrow \text{Chi phí Turn 3} = 2.000 + 10.000 (\text{Mục A}) + 10.000 (\text{Mục B}) \approx 22.000 \text{ input tokens}$$



Nếu phiên làm việc của bạn kéo dài và Agent liên tục "đòi" nạp thêm dữ liệu chi tiết mà hệ thống không chủ động dọn dẹp, **chi phí của các lượt tương tác ở cuối phiên sẽ phình to theo cấp số cộng**, vì các lượt sau phải gánh tiền token cho tất cả các bối cảnh đã nạp ở lượt trước.

---

## 3. Giải pháp tối ưu: Vừa né RPM, vừa rẻ tuyệt đối

Để kiến trúc "Lazy Loading" của bạn đạt hiệu quả kinh tế cao nhất, bạn cần bổ sung 2 kỹ thuật quản trị ở phía Backend:

1. **Chủ động cắt tỉa bộ nhớ phiên (Session Memory Management / Pruning):**
Khi Agent thông báo qua luồng WebSocket rằng nó đã xử lý xong thông tin của "Mục A" và chuyển hướng sang "Mục B", Backend của bạn cần can thiệp để **cắt bỏ (truncate) hoặc làm sạch** phần dữ liệu chi tiết của Mục A ra khỏi lịch sử phiên, chỉ giữ lại cấu trúc Mục lục lõi và dữ liệu Mục B vừa nạp. Điều này giữ cho Cửa sổ ngữ cảnh luôn "gầy" và tập trung, triệt tiêu hiện tượng lũy tiến chi phí.
2. **Phối hợp với Context Caching cho "Khung lõi":**
Nếu bản thân cái "Mục lục hoặc Sơ đồ hệ thống" ban đầu của bạn đã rất lớn (ví dụ: vài trăm nghìn token chứa cấu trúc toàn bộ mã nguồn hoặc sơ đồ kiến trúc doanh nghiệp) và được dùng chung cho nhiều user: Bạn hãy **Cache** cái khung lõi này lại trước để lấy Cache ID. Khi mở Live API Session, bạn gắn Cache ID này vào. Lúc này, phần khung lõi khi bị tính tiền lại qua các turn sẽ được áp **mức giá Cache siêu rẻ (thường giảm tới 80% - 90% so với giá input gốc)**, bạn chỉ trả giá đầy đủ cho các đoạn context chi tiết nhỏ được inject động vào sau đó.

**KẾT LUẬN:** Giải pháp dùng WebSocket để Agent tự gọi data khi cần là một kiến trúc **cực kỳ thông minh và tối ưu về hạ tầng** (giải quyết triệt để bài toán kết nối và giới hạn RPM). Nó sẽ **rất tiết kiệm chi phí** nếu bạn kiểm soát tốt việc "dọn dẹp" các đoạn bối cảnh cũ ngay trên luồng, không để chúng tích lũy vô tội vạ qua từng lượt trả lời của Agent.