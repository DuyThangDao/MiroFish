# Phân tích áp dụng Context Cache và Live API vào pipeline hiện tại

## Vấn đề hiện tại của pipeline

### 1. Source code re-sent mỗi LLM call

`_v2_session_summary` (source code + call graph + HIST-INV annotations) của một contest có thể 30–60KB.
Mỗi agent trong R1 đều nhận full context này. Với 10 contracts × nhiều agents = cùng một đoạn text
khổng lồ được gửi lên hàng chục lần, mỗi lần tính đủ input token.

### 2. KG build: nhiều HTTP call tuần tự per function

`_build_call_graph_with_hist_inv` gọi LLM 3 lần/function:
- `_generate_operation_queries`
- `_generate_structural_queries`
- `_generate_hist_inv`

Mỗi lần là 1 HTTP request mới (TCP handshake + TLS + routing). Với 164 functions = ~500 requests
tuần tự, mỗi request bị overhead 200–500ms kết nối.

---

## Kỹ thuật 1: Context Caching → giải quyết vấn đề 1

Source code của từng contract là **FIXED** trong 1 run — cache 1 lần, các agent tiếp theo chỉ gửi
question (~200 token) + Cache ID.

**Gain**: tiết kiệm 80–90% input token cho phần source (phần chiếm đa số chi phí).

**Điểm áp dụng trong pipeline:**
- `_v2_session_summary` per contract trong R1 agents
- System prompt chung (`_STEP1_BLOCK`, etc.) dùng lại qua tất cả agents

**Caveat**: Chỉ hỗ trợ trên **Gemini/Vertex AI** và **Anthropic** — cần thay đổi `LLMClient` để
support provider-specific caching API. Không áp dụng được ngay với endpoint OpenAI-compatible tùy ý.

---

## Kỹ thuật 2: Live API / WebSocket → giải quyết vấn đề 2

1 session persistent cho toàn bộ KG build của 1 contest. Agent tự gọi tool khi cần thêm context
(fn_body), backend inject realtime. Xóa overhead kết nối, giảm RPM vì chỉ tính 1 request dù gọi
500 lần bên trong session.

**Gain**: giảm latency KG build, tránh RPM throttle trong giai đoạn query-heavy.

**Điểm áp dụng trong pipeline:**
- KG build pipeline (`_build_call_graph_with_hist_inv`)
- ReportAgent (nhiều sequential tool calls)

**Caveat**: Kiến trúc R1/R2 hiện tại là **parallel** (nhiều agent chạy đồng thời cho các contracts
khác nhau), không phải sequential tool-calling. Live API phù hợp hơn cho single-agent-with-many-tool-calls,
không phải multi-agent parallel batch. Với R1/R2, Live API không giúp được nhiều.

---

## So sánh tổng hợp

| Kỹ thuật | Phù hợp với phần nào | Gain thực tế | Độ ưu tiên |
|----------|----------------------|--------------|------------|
| Context Cache | Source code trong R1 agents | Rất cao — giảm 80–90% chi phí input token | Cao |
| Live API | KG build pipeline (3 LLM call/fn) | Trung bình — giảm latency, không phải cost | Trung bình |

Context Cache có impact lớn hơn và trực tiếp hơn với pipeline hiện tại nếu chuyển sang Gemini/Anthropic.
