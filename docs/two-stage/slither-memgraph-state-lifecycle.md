# Đồ thị phụ thuộc dữ liệu tĩnh: Slither/SlithIR → Memgraph (Cypher)

> Tài liệu kỹ thuật bổ sung cho **G-RC-2 / S2a — Bước 1b** trong MiroFish (xem [contest35-fn-root-cause.md](contest35-fn-root-cause.md) — mục *G-RC-2*). Chủ đề: theo dõi **vòng đời tĩnh** của biến trạng thái (ví dụ `reserves`, `reserve0`/`reserve1`) — hàm nào **ghi**, hàm nào **đọc** — để hỗ trợ manifest, thứ tự suy luận (invariant / ordering), và tóm tắt inject vào context.

---

## 1. Vấn đề cần giải

- **Call graph / import graph** trả lời “ai gọi ai”, chưa đủ cho câu hỏi “**luồng dữ liệu** của state quan trọng chạy qua đâu”.
- Muốn trả lời tĩnh ở mức Solidity, cần **lõi IR sâu** (AST + phân tích hàm), không chỉ regex trên source flat.
- Đồ thị lưu trong **property graph** + **Cypher** phù hợp truy vấn dạng: từ biến `X` → tập writer/reader, đường đi ngắn, subgraph quanh một hàm.

---

## 2. Stack đề xuất

| Thành phần | Vai trò |
|------------|--------|
| **Slither** | Parse contract, chạy phân tích tĩnh, API truy cập contract / function / state variables. |
| **SlithIR** | Biểu diễn trung gian trong hàm (operations, variables) — cơ sở để map **đọc/ghi** chính xác hơn so với chỉ grep text. |
| **Export** | Script (Python) đọc từ Slither: cặp `(function, state_variable, READ\|WRITE)` (và metadata: contract, visibility, v.v.). |
| **Memgraph** (hoặc tương đương) | Lưu **nodes** (Contract, Function, StateVar) và **edges** (READS, WRITES, DECLARES_IN, CALLS nếu cần). |
| **Cypher** | Truy vấn: “mọi writer của `reserve0`”, “intersection reader giữa hai hàm”, path ngắn, v.v. |

**Tương đương nhẹ (không bắt buộc Memgraph):** `dict` (function → tập read/write) hoặc **NetworkX** cho đồ thị nhỏ vừa phải; chỉ cần **Memgraph** (và Cypher) khi query phức tạp, lưu bền, hoặc nhiều contest tái sử dụng cùng store.

**Entry point API Slither (Python) — tối thiểu cần cho export:** với mỗi `Function` (lấy từ `contract.functions` / `contract.functions_declared`):

- `function.state_variables_read` → tập `StateVariable` mà hàm **đọc** (có thể gồm biến state của contract cơ sở / mixin).
- `function.state_variables_written` → tập `StateVariable` mà hàm **ghi**.

Từ đó tạo cạnh `READS` / `WRITES` sang node biến trạng thái. SlithIR chỉ cần khi muốn tinh hơn (dòng gán, alias, flow nội bộ hàm).

**Lưu ý:** Giai đoạn đầu có thể dựng bản tối thiểu từ hai thuộc tính trên trước; mở rộng theo **SlithIR** khi cần flow chi tiết hơn (gán qua nhiều bước, inner locals).

---

## 3. Integration với MiroFish workflow (đích gắn code)

> Trạng thái hiện tại: **manifest S2a** trong [contest35-fn-root-cause](contest35-fn-root-cause.md) vẫn là spec; `flatten` đã có, bước Slither/Memgraph là kéo tùy bản triển khai. Phần dưới mô tả **chỗ móc** hợp lý để implementor không mất hướng.

| Câu hỏi | Trả lời ngắn |
|--------|----------------|
| Slither chạy trên cái gì? | **Thư mục contest gốc** (cây `.sol` + cấu hình build nếu có) — cùng **đường dẫn `contest_dir`** mà flow flatten dùng, **không** chạy trên bản *flat* một chuỗi (một file khổng lồ dễ phá cấu trúc compile; Slither/crytic-compile cần project như bình thường). |
| Gắn trước/sau bước nào? | **Sau (hoặc song song) khi** đã cần tín hiệu multi-contract — có thể dùng kết quả [flatten_contest.py](../../backend/scripts/flatten_contest.py) (`flatten_contest_dir`) để lấy `total_chars` / quyết định “repo lớn → inject”. **Trước** khi build nội dung đi vào agent: `ContractManifest` + tóm tắt graph nên tồn tại cùng lúc (graph → hỗ trợ chọn `primary`/`secondary`, manifest dùng cho prompt). |
| Codebase đích tiêu thụ | Phần **hướng dẫn / instruction Stage 1** nằm ở [contract_oasis_env.py](../../backend/app/services/contract_oasis_env.py) (`PHASE_CONFIG[...]['stage1_instruction']`). Khi S2a có inject động (multi-contract, focus directive), **đây** là nơi merge chuỗi từ template + `primary` + `secondary` + block graph tóm tắt. |
| Script gợi ý mới (chưa có) | Có thể tách: ví dụ `backend/scripts/slither_export_state_graph.py` (input: `contest_dir` → output: JSON/Memgraph driver + `graph_summary` cho bước sau). Bước này **độc lập** với `flatten_contest_dir` về mặt I/O, chỉ cùng **input `contest_dir`**. |
| `cyber_session_orchestrator` | Orchestrator nạp OASIS từ `contract_oasis_env` — nếu sau này truyền `extra_context` / manifest từ session, integration point theo từng PR sẽ là: load artifact graph + manifest trước `_run_stage1`, dồn vào feed/phase config. (Chi tiết tùy implement; doc chỉ khoá **đúng tầng**: tải artifact (graph/manifest) trước session → cấu hình env / Stage 1.) |

Tóm tắt thứ tự đề xuất:

1. Vào `contest_dir` (nguồn thật).  
2. (Tuỳ) `flatten_contest_dir` → `total_chars`, cảnh báo multi-contract.  
3. `Slither(contest_dir)` (hoặc tương đương) → lặp `function` + `state_variables_read` / `state_variables_written` → export / Memgraph.  
4. Build manifest (heuristic + graph).  
5. Khi tạo prompt Stage 1, ghép summary nhỏ + [focus directive](contest35-fn-root-cause.md) vào luồng từ `contract_oasis_env`.

---

## 4. Schema graph gợi ý (tối thiểu)

- **Nodes:** `(:Contract {name})`, `(:Function {qualified_name, contract})`, `(:StateVar {name, contract, slot?})`
- **Edges:**  
  `(:Function)-[:WRITES]->(:StateVar)`  
  `(:Function)-[:READS]->(:StateVar)`  
  Tùy bài toán: `(:Function)-[:CALLS]->(:Function)` để nối với Bước 1b (call graph).

**Id ổn định:** dùng tên qualify đầy đủ (vd. `ContractName::functionName`, `ContractName::varName`) để tránh trùng khi multi-file / flatten.

---

## 5. Pipeline tóm tắt

```text
Repo / flatten  →  Slither (compile + analyze)
                      ↓
              Extract READ/WRITE (SlithIR khi cần)
                      ↓
              Batch MERGE vào Memgraph
                      ↓
              Cypher: query theo state var / contract / function
                      ↓
              Summary (top N writers/readers, top edges)  →  inject cùng manifest (S2a)
```

**Token / noise:** toàn bộ graph lớn **không** nên dump nguyên vào prompt. Rút cùng nguyên tắc với [contest35 — Bước 1b](contest35-fn-root-cause.md): chỉ **summary** (vd. 5–7 hàm liên quan trực tiếp tới 1–2 biến trọng tâm, hoặc bullet thay vì Mermaid full).

---

## 6. Giới hạn (phải tài liệu hóa)

- **Tĩnh:** gọi ngoài, `delegatecall`/`staticcall` phức tạp, factory, proxy, `assembly` — dòng dữ liệu có thể **hụt** hoặc **over-approx**; kết quả là **gợi ý** cho auditor/agent, không phải bằng chứng thực thi.
- So khớp với G-RC-2: graph **không** sửa L/S eval; cùng tác động gián tiếp như call graph — giúp **nhìn đúng module / đúng luồng state**.
- **G-RC-1 / S3** vẫn độc lập: SWC chuẩn và invariant protocol sâu không được “fix” chỉ bằng graph.

---

## 7. Liên hệ roadmap MiroFish

- Xếp **P3 (hạ tầng tùy chọn)**: triển khai khi S2a (manifest + focus) đã có, và khi cần bước sau call-only graph.
- File gốc: [contest35-fn-root-cause.md](contest35-fn-root-cause.md) (G-RC-2, *Bước 1b*).

---

## 8. Tham chiếu ngoài (đọc thêm)

- [Slither documentation](https://github.com/crytic/slither/wiki) — API Python, printer/detectors.
- [Memgraph Cypher](https://memgraph.com/docs) — tương thích phần lớn Cypher mở (OpenCypher).
