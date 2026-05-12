# Context Fatigue trong LLM Audit Pipeline

## 1) Bối cảnh bài toán

Trong pipeline audit hợp đồng thông minh, hiện tượng "context fatigue" xuất hiện khi đưa quá nhiều source code vào một phiên suy luận duy nhất. Dù model có context window lớn, khả năng truy xuất thông tin nằm ở giữa prompt thường giảm rõ rệt (lost in the middle), dẫn tới recall thấp ở các cụm contract nhỏ hoặc nằm giữa tài liệu.

Map-Reduce theo nhiều session giúp tăng recall, nhưng đánh đổi bằng chi phí token và thời gian chạy tăng theo số session (`N`), đặc biệt khi chạy tuần tự.

Tài liệu này tổng hợp các paper học thuật liên quan và kỹ thuật có thể dùng để giảm trade-off này.

---

## 2) Nhóm paper nền tảng về suy giảm chất lượng ở long context

### 2.1 Lost in the Middle: How Language Models Use Long Contexts
- Link: <https://arxiv.org/abs/2307.03172>
- Venue: TACL 2024 (bản preprint 2023)
- Ý chính:
  - Hiệu năng thường cao khi thông tin liên quan ở đầu hoặc cuối context.
  - Hiệu năng giảm mạnh khi thông tin nằm ở giữa (đường cong dạng U theo vị trí).
  - Hiện tượng vẫn xảy ra ở các model quảng cáo hỗ trợ long context.
- Kỹ thuật/khuyến nghị rút ra:
  - Không nên nhồi toàn bộ dữ liệu vào một prompt phẳng.
  - Cần re-order, chunk, hoặc route để đưa thông tin quan trọng vào vị trí thuận lợi.
  - Cần benchmark theo vị trí thông tin, không chỉ theo độ dài context.

---

## 3) Nhóm paper giảm token và giảm position bias bằng nén ngữ cảnh

### 3.1 LongLLMLingua
- Link: <https://aclanthology.org/2024.acl-long.91/>
- Ý chính:
  - Nén prompt theo chiến lược coarse-to-fine và question-aware.
  - Kết hợp reordering để giảm position bias.
- Kỹ thuật đề xuất:
  - **Prompt Compression**: bỏ token ít giá trị thông tin.
  - **Question-aware filtering**: giữ lại nội dung liên quan câu hỏi/task.
  - **Reordering**: đưa thông tin trọng yếu về vị trí có lợi (đầu/cuối).
- Ý nghĩa cho pipeline:
  - Trước khi chạy R1 agents, nén mỗi cluster source (và docs) để giảm token per session.
  - Có thể giảm cost và latency mà không cần giảm số lượng cluster.

### 3.2 LLMLingua-2: Data Distillation for Efficient Prompt Compression
- Link: <https://arxiv.org/abs/2403.12968>
- Venue: Findings ACL 2024
- Ý chính:
  - Đóng bài toán nén thành token classification bằng encoder nhỏ.
  - Distill tín hiệu "token quan trọng" từ model lớn.
- Kỹ thuật đề xuất:
  - **Task-agnostic compression model** để chạy nhanh.
  - **Bidirectional encoding** (không chỉ causal entropy) để chọn token tốt hơn.
  - Tối ưu cả faithfulness lẫn throughput.
- Ý nghĩa cho pipeline:
  - Dùng compressor nhanh ở bước tiền xử lý thay vì gọi LLM lớn để nén mỗi lần.
  - Hữu ích khi cần audit nhiều contest liên tục.

---

## 4) Nhóm paper route động để không phải chạy full budget cho mọi truy vấn

### 4.1 Self-RAG: Learning to Retrieve, Generate, and Critique through Self-Reflection
- Link: <https://arxiv.org/abs/2310.11511>
- Venue: ICLR 2024
- Ý chính:
  - Model tự quyết định khi nào cần retrieve thêm tri thức.
  - Kèm cơ chế self-critique để kiểm soát chất lượng đầu ra.
- Kỹ thuật đề xuất:
  - **Adaptive retrieval gating** theo độ bất định/độ khó.
  - **Self-reflection tokens** để điều phối hành vi retrieve-generate-critique.
- Ý nghĩa cho pipeline:
  - Không phải cluster nào cũng cần chạy full 19 agents.
  - Có thể dùng pass nhẹ để ước lượng độ khó rồi mới "escalate" compute.

### 4.2 Self-Route (RAG vs Long-Context Routing)
- Link: <https://arxiv.org/abs/2410.09342>
- Ý chính:
  - Router quyết định query nào dùng RAG rẻ, query nào dùng long context đắt.
- Kỹ thuật đề xuất:
  - **Selective routing theo self-reflection hoặc confidence**.
  - Mục tiêu là giữ chất lượng gần long-context nhưng giảm cost lớn.
- Ý nghĩa cho pipeline:
  - Áp dụng tư tưởng tương tự ở cấp cluster:
    - Cluster low-risk -> chạy path nhẹ.
    - Cluster high-risk/uncertain -> chạy full multi-agent path.

---

## 5) Nhóm paper kiến trúc memory/attention cho context rất dài

### 5.1 Infini-attention (Leave No Context Behind)
- Link: <https://arxiv.org/abs/2404.07143>
- Ý chính:
  - Kết hợp local attention với compressive memory để xử lý chuỗi cực dài.
  - Bộ nhớ tăng chậm hơn so với attention đầy đủ.
- Kỹ thuật đề xuất:
  - **Compressive memory inside attention block**.
  - **Segment-level processing** nhưng vẫn truy xuất được tín hiệu dài hạn.
- Ý nghĩa cho pipeline:
  - Đây là hướng đổi model/kiến trúc nền, không phải patch nhanh ở tầng orchestration.
  - Hợp với roadmap dài hạn nếu muốn giảm phụ thuộc vào chunking thủ công.

### 5.2 MemGPT: Towards LLMs as Operating Systems
- Link: <https://arxiv.org/abs/2310.08560>
- Ý chính:
  - Quản lý bộ nhớ theo kiểu phân tầng: context ngắn hạn + external memory.
- Kỹ thuật đề xuất:
  - **Memory paging** giữa "active context" và "external store".
  - Agent tự quyết định khi nào nạp/đẩy thông tin.
- Ý nghĩa cho pipeline:
  - Có thể lưu "findings/intermediate evidence" ngoài prompt và chỉ nạp khi cần.
  - Giảm pressure lên một prompt dài duy nhất.

---

## 6) Nhóm paper Map-Reduce/hierarchical reasoning cho tài liệu dài

### 6.1 Hierarchical Question Answering for Long Documents
- Link: <https://arxiv.org/abs/1611.01839>
- Ý chính:
  - Coarse-to-fine: chọn đoạn liên quan trước, rồi mới chạy model đắt cho phần đã chọn.
- Kỹ thuật đề xuất:
  - **Two-stage inference**: retriever/ranker nhẹ -> reader nặng.
  - Giảm compute đáng kể so với đọc toàn bộ document.
- Ý nghĩa cho pipeline:
  - Đúng với ý tưởng "triage trước, audit sâu sau".

### 6.2 ToM: Tree-oriented MapReduce for Long-Context Reasoning in LLMs
- Link: <https://aclanthology.org/2025.emnlp-main.899/>
- Ý chính:
  - Map-Reduce theo cấu trúc cây thay vì reduce phẳng.
  - Tổng hợp dần từ lá lên gốc để giữ coherence và xử lý conflict tốt hơn.
- Kỹ thuật đề xuất:
  - **Hierarchical aggregation**.
  - **Conflict-aware merging** ở nhiều mức.
- Ý nghĩa cho pipeline:
  - Hữu ích cho bước `merge_cluster_findings`: có thể giảm miss chain phức tạp.

---

## 7) Kỹ thuật khả thi cho Phase 4 để giảm Cost/Latency

Các kỹ thuật dưới đây rút trực tiếp từ các paper trên và có thể triển khai dần:

1. **Adaptive Budget Routing (quan trọng nhất)**
   - Thêm "pass nhẹ" để chấm điểm từng cluster (risk score + uncertainty score).
   - Chỉ top-k cluster chạy full 19-agent; cluster còn lại chạy path rút gọn.
   - Nguồn cảm hứng: Self-RAG, Self-Route, Hierarchical QA.

2. **Progressive Widening**
   - Vòng 1: ít agent/ít round cho tất cả cluster.
   - Vòng 2: chỉ mở rộng compute cho cluster có tín hiệu high severity hoặc consensus thấp.

3. **Prompt Compression trước R1**
   - Nén source/skeleton/profile trước khi đưa vào agent.
   - Nguồn cảm hứng: LongLLMLingua, LLMLingua-2.

4. **Tree-Reduce thay vì Flat Reduce**
   - Merge theo cặp cluster liên quan trước, rồi mới global merge.
   - Nguồn cảm hứng: ToM.

5. **Memory Tier cho Cross-cluster**
   - Lưu intermediate findings/exploit hypotheses vào bộ nhớ ngoài có chỉ mục.
   - Chỉ inject phần liên quan vào prompt mỗi session.
   - Nguồn cảm hứng: MemGPT.

---

## 8) Gợi ý roadmap triển khai ngắn hạn

- **P0 (dễ, hiệu quả nhanh):**
  - Thêm risk triage + adaptive routing (top-k full, phần còn lại lite).
  - Thêm prompt compression ở pre-processing.

- **P1 (trung bình):**
  - Progressive widening nhiều vòng theo uncertainty.
  - Tree-based merge cho cross-cluster findings.

- **P2 (dài hạn):**
  - Nghiên cứu memory-tier/or external state manager.
  - Đánh giá model/serving hỗ trợ attention-memory tốt hơn.

---

## 9) Kết luận

Map-Reduce nhiều session là hướng đúng để tăng recall khi gặp lost-in-the-middle, nhưng không nhất thiết phải trả giá `N x` một cách cứng nhắc. Các hướng khả thi nhất theo literature là:

- route compute theo độ khó/rủi ro (thay vì full compute cho mọi cluster),
- nén context trước khi suy luận,
- reduce theo cấu trúc phân cấp thay vì gộp phẳng.

Kết hợp 3 hướng này thường cho tỉ lệ "Recall tăng / Cost tăng" tốt hơn đáng kể so với Map-Reduce thuần.
