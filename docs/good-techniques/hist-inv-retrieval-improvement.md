# HIST-INV Retrieval Improvement — 2 Hướng Đề Xuất

## Bối cảnh vấn đề

HIST-INV build hiện tại dùng `_collect_track()` để sinh op queries từ function body, rồi query `solodit_op` ChromaDB collection. Cơ chế này match theo **cơ chế thực thi** (external calls, type casts, arithmetic ops) — không phải theo **semantic của lỗi**.

Hệ quả: function `borrow` của MochiVault có ops về `engine.cssr().update`, `mochiProfile().maxCollateralFactor` → match với các findings về cross-chain/access control, bỏ sót `h-05-debts-calculation` dù nó đúng là Mochi finding trong RAG.

---

## Hướng 1 — Query theo State Variables bị Modify

### Ý tưởng

Thay vì query theo "function làm gì về mặt kỹ thuật" (external calls, casts), query theo "function ghi gì vào state" — state variable write patterns gần với bug semantic hơn.

### Ví dụ

`MochiVault.borrow` ghi vào:
- `debtIndex[asset][msg.sender]`
- `debts[asset]` (global accumulator)
- `borrowInfo[asset][msg.sender].debt`

Query mới: `"uint256 global debt accumulator incremented per borrow position"` → sẽ match gần với `h-05` hơn nhiều.

### Cách triển khai

1. **Source:** Dùng Slither dep graph đã có (`dep_graph.json`) — đã có danh sách state vars mà mỗi function write.
2. **Query generation:** Với mỗi function, sinh query từ danh sách state vars mà nó write:
   - Tên biến + type + operation (increment/decrement/assign)
   - Ví dụ: `"uint256 debts[asset] += amount in borrow function"`
3. **Collection target:** Vẫn dùng `solodit_op` (per-op-line) hoặc `solodit_vul` (vulnerability prose).
4. **Tích hợp:** Thêm state-write queries song song với op queries hiện tại trong `_collect_track()`, hoặc tạo track riêng.

### Ưu điểm
- Không cần biết vul type trước
- Dep graph đã có sẵn → không cần LLM thêm
- State writes là dấu hiệu trực tiếp của bug impact (sai state → sai behavior)

### Nhược điểm
- Slither có thể fail trên một số contests → fallback về regex
- State var names có thể bị obfuscate → normalize cần thiết
- Dep graph chỉ có per-contract, không phải per-function granularity trong mọi trường hợp

---

## Hướng 2 — Query từ solodit_vul bằng Function Intent

### Ý tưởng

Dùng **NatSpec + require statements + function signature** làm query để tìm trong `solodit_vul` collection (prose mô tả lỗi), thay vì dùng op-mechanics để tìm trong `solodit_op`.

Intent của function là "function này dùng để làm gì" — gần với semantic bug hơn mechanical ops.

### Ví dụ

`MochiVault.borrow`:
- NatSpec/intent: `"borrow stablecoin against collateral, track user debt position"`
- require: `"collateral factor check, credit cap check"`

Query từ intent → `solodit_vul` prose → sẽ match các findings mô tả "debt tracking inconsistency", "global vs local accounting mismatch" — đúng là H-01/H-05.

### Cách triển khai

1. **Source:** Intent statements đã có (`intent.json` từ Step 1.1) — đã extract per-function intent từ NatSpec/sigs/requires.
2. **Query generation:** Dùng function intent statement làm query string trực tiếp, hoặc rephrase thành "what could go wrong" prompt ngắn (1 lần LLM call per function).
3. **Collection target:** `solodit_vul` (prose description của vulnerability) — cần verify collection này đã được embed đầy đủ.
4. **Tích hợp:** Thêm "vul track" vào `_collect_track()` song song với op track hiện tại.

### Ưu điểm
- Intent đã có sẵn từ pipeline (không tốn thêm LLM call lớn)
- `solodit_vul` prose gần với semantic bug hơn `solodit_op` mechanics
- Tự nhiên capture được "state consistency" bugs vì intent mô tả business logic

### Nhược điểm
- `solodit_vul` collection chưa được embed đầy đủ (Phase 1 RAG migration chưa xong)
- Intent extraction đôi khi generic ("borrow stablecoin") → query noise
- False positive cao hơn nếu intent phrases trùng nhau giữa các protocols

---

## So sánh 2 hướng

| Tiêu chí | Hướng 1 (State Vars) | Hướng 2 (Intent + solodit_vul) |
|---|---|---|
| Phụ thuộc mới | Dep graph (đã có) | `solodit_vul` embed (chưa xong) |
| LLM call thêm | Không | Tùy (nếu rephrase intent) |
| Precision | Cao (state writes cụ thể) | Trung bình (intent có thể generic) |
| Recall | Trung bình (chỉ capture state bugs) | Cao hơn (capture semantic bugs rộng hơn) |
| Dễ implement | Trung bình (cần parse dep graph per-fn) | Cao (intent đã có, chỉ đổi collection) |
| Sẵn sàng ngay | Có thể (dep graph có) | Chờ solodit_vul embed xong |

---

## Đề xuất kết hợp

Chạy song song cả 2 track, merge kết quả trước khi chọn top slugs:

```
borrow function
  → op track (hiện tại):     [slug_A, slug_B, slug_C, ...]
  → state-write track:       [slug_D, slug_E, slug_F, ...]   ← Hướng 1
  → intent+vul track:        [slug_G, slug_H, slug_I, ...]   ← Hướng 2
  → merge + rerank by score → top 6 slugs
```

Với data leakage case (Mochi), `h-05-debts-calculation` sẽ được kéo lên từ state-write track hoặc intent track, dù op track bỏ sót.

---

## Trạng thái

- Hướng 1: Có thể implement ngay — dep graph available
- Hướng 2: Chờ `solodit_vul` embed (Phase 1 RAG migration)
- Cả 2 chưa implement
