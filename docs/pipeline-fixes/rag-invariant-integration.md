# Tích hợp RAG + Invariants vào Multi-Persona Architecture

## Bối cảnh

Hai cải tiến đã được thiết kế độc lập:
- **Invariant-Driven R1** (`invariant-driven-r1.md`): Mỗi R1 agent tự list protocol-specific invariants trước khi tìm bugs
- **RAG** (chưa implement): Inject relevant historical write-ups vào R1 context

Câu hỏi: Hai cơ chế này có xung đột với kiến trúc Multi-Persona không?

---

## Không xung đột, nhưng có rủi ro Homogenization

### Tại sao không xung đột về nguyên lý

Invariants và RAG đóng hai vai trò khác nhau:
- **Invariants** = mục tiêu kiểm tra ("protocol này PHẢI duy trì gì?")
- **RAG** = gợi ý từ lịch sử ("các protocols tương tự đã bị tấn công như thế nào?")

Chúng bổ sung cho nhau: RAG giúp agent biết *loại vi phạm nào đáng tìm*, Invariants giúp agent xác định *cụ thể cái gì cần bảo toàn*.

### Rủi ro Homogenization (có thật, nhưng ở mức độ nào?)

Kiến trúc Multi-Persona hoạt động nhờ **diversity góc nhìn** — `defi_math` thấy lỗi mà `appsec` bỏ qua.

**Điểm quan trọng:** Hiện tại 19 agents đã cùng đọc 1 contract source, cùng dep_graph, cùng intent_summary. Điều tạo ra diversity **không phải** input context mà là **persona (system_prompt)**. Vì vậy:

- Homogenization risk từ uniform RAG injection là **có thật nhưng ít nghiêm trọng** hơn tưởng — agents với persona khác nhau sẽ đọc cùng 1 write-up và extract các patterns khác nhau
- Rủi ro thực tế hơn là: uniform RAG "loãng" persona signal — agent bị kéo về các patterns trong write-up thay vì suy luận từ góc nhìn chuyên môn

**Vấn đề cụ thể của naive implementation:** Nếu inject top-5 write-ups giống hệt nhau vào cả 19 agents → tất cả đều focused vào cùng attack categories → overlapping findings → API cost tăng không kèm diversity tăng.

---

## Giải pháp: Persona-Aware Injection

### A. Invariants — Đã giải quyết bởi thiết kế hiện tại

Self-generated invariants (thiết kế trong `invariant-driven-r1.md`) **đã tránh hoàn toàn** homogenization:
- Mỗi agent tự viết invariants từ lăng kính chuyên môn của mình
- `defi_math` → "Tích x*y không đổi sau mỗi swap"
- `appsec` → "updateFee() chỉ được gọi bởi timelock address"

Không cần thay đổi gì thêm cho phần invariants.

### B. RAG — Cần Persona-Routed Retrieval

Thay vì 1 query chung cho cả pipeline, mỗi agent query với `agent_domain` của mình:

```
Query template: "{agent_domain} vulnerability patterns in {contract_type}"

Agent defi_offensive → "DeFi offensive flashloan price manipulation in AMM"
    → RAG trả về: Uniswap reentrancy, flash loan oracle attacks, sandwich attacks

Agent governance_security → "governance access control vulnerabilities in DeFi"
    → RAG trả về: proposal replay, timelock bypass, quorum manipulation

Agent appsec → "application security reentrancy signature replay in smart contracts"
    → RAG trả về: reentrancy patterns, EIP-712 replay, msg.value in loops
```

**Kết quả:** Mỗi agent nhận top-3 write-ups liên quan đến domain của mình → diversity được bảo toàn.

---

## Luồng tích hợp vào Round 1

```
[Pre-Round 1 — Per Agent]
1. Xác định agent_domain từ agent profile
2. Query RAG: "{agent_domain} vulnerabilities in {contract_type}"
3. Lấy top-3 write-up excerpts → RELEVANT HISTORICAL CONTEXT block

[Round 1 — Prompt Structure]
=== RELEVANT HISTORICAL CONTEXT (for {agent_domain}) ===
[Top-3 write-up excerpts — domain-specific]

=== CONTRACT UNDER REVIEW ===
[Source code]

=== PROTOCOL INVARIANT ANALYSIS ===
[Agent tự list 3–6 invariants từ góc nhìn domain]

[Agent dùng cả RAG context + invariants để tìm violations → FINDING]
```

RAG context đứng **trước** invariant listing — gợi ý loại vi phạm nào đáng tìm, agent tự convert thành invariants cụ thể cho protocol đang review.

---

## So sánh Naive vs Persona-Aware

| | Naive Injection | Persona-Aware |
|---|---|---|
| RAG query | 1 query chung | Per-agent query với domain |
| Write-ups inject | Giống hệt 19 agents | Khác nhau theo domain |
| Diversity impact | Giảm (agents converge) | Bảo toàn (agents diverge) |
| Invariant source | Pre-extracted, uniform | Self-generated per persona |
| Implementation complexity | Thấp | Trung bình |

---

## Thứ tự triển khai

RAG chưa được build — đây là thiết kế dự kiến cho khi RAG được implement.

**Bước 1 (hiện tại):** Implement Invariant-Driven R1 theo `invariant-driven-r1.md` — không cần RAG.

**Bước 2 (khi có RAG):**
1. Build vector DB từ DeFiHackLabs/Solodit write-ups
2. Implement per-agent query với `agent_domain + contract_type`
3. Inject top-3 excerpts vào R1 prompt trước invariant listing block
4. Verify diversity: kiểm tra findings của các agents có persona khác nhau — nếu quá giống nhau → persona signal bị lấn át → cần giảm RAG context hoặc tăng persona weight

**Signal để điều chỉnh RAG weight:**
- Jaccard similarity giữa finding titles của các agents cùng run: nếu > 0.5 → RAG quá dominant
- FP tăng sau khi thêm RAG → write-ups đang tạo false pattern matches

---

## Files liên quan

| Tài liệu | Nội dung |
|----------|---------|
| `docs/pipeline-fixes/invariant-driven-r1.md` | Thiết kế self-generated invariants cho R1 |
| `docs/pipeline-fixes/issue3-solutions.md` | Phân tích 4 kỹ thuật giải quyết pattern coverage |
