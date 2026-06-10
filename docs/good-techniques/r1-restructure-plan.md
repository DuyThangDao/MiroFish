# R1 Restructure Plan — Independent Reasoning + RAG Separation of Concerns

## 1. Kiến trúc hiện tại

### Pipeline tổng quan
```
HIST-INV build  →  source code annotated  →  R1 (Turn 1 + Turn 2)  →  gap-fill  →  dedup
```

### Các thành phần đang hoạt động

#### HIST-INV Build (`contract_kg_builder.py`)
- Với mỗi function trong call graph: tạo operation queries bằng prompt chuyên biệt
- Query `solodit_findings` (blob collection) → lấy historical hints
- Ghi `// [HIST-INV]: <hint>` trực tiếp vào source code
- **Tốt**: tách biệt hoàn toàn với agent reasoning, pre-processed trước R1

#### R1 Turn 1 (`invariant_only=True`)
- 20 agent (6 domain groups + `clmm_specialist` + `code_similarity_auditor`)
- Mỗi agent có `system_prompt` (worldview) + `core_question` (epistemic lens)
- Agent đọc source đã annotated → viết `INV-1..INV-N` invariants
- **Vấn đề**: nếu agent viết được INV, nó đã reasoning về code rồi

#### System: `_build_invariant_rag_hints`
- Lấy INV lines từ Turn 1 → query `solodit_findings` → build hint block
- Inject vào Turn 2 prompt dưới dạng "HISTORICAL VIOLATION PATTERNS"
- **Vấn đề**: semantic mismatch (INV = property assertion ≠ vulnerability description)
- **Vấn đề**: nếu agent viết được INV thì nó đã biết vi phạm hay không → query này circular

#### R1 Turn 2
- Nhận: source + INV từ Turn 1 + RAG hints (nếu có)
- Task: check từng INV có bị vi phạm không → viết FINDING

#### `code_similarity_auditor` (agent đặc biệt)
- Turn 1: sinh FUNC mechanics blocks
- System: `_build_code_similarity_rag_hints` → query `solodit_findings` bằng FUNC blocks
- **Vấn đề**: HIST-INV build đã làm việc này rồi → duplicate

#### `_build_rag_observations`
- **Dead code**: định nghĩa nhưng không được gọi ở đâu

#### Gap-fill
- Sau R1: GAP declarations được route đến domain groups
- Cũng dùng `_build_invariant_rag_hints` → cùng vấn đề semantic mismatch

#### RAG collection hiện tại: `solodit_findings`
- Full-text blob dump của 3366 audit reports
- Không được index theo dimension cụ thể
- Mix giữa prose description, code snippet, protocol context, attack narrative

---

## 2. Vấn đề cốt lõi

### 2.1 RAG đang được dùng sai mục đích

**RAG đúng nghĩa**: cung cấp prior knowledge để agent reasoning — agent chưa biết gì, RAG cho nó biết *nên nhìn vào đâu*.

**Cách dùng hiện tại**: agent đã reasoning (INV), xong lại query RAG để confirm — đây là circular.

```
Sai: agent writes INV → system queries RAG with INV → injects violations → agent checks violations
     ↑ agent đã biết rồi                              ↑ chỉ là confirmation
     
Đúng: RAG injects knowledge TRƯỚC khi agent reasons → agent dùng knowledge đó để reason
```

### 2.2 Semantic mismatch ở Turn 2 RAG query

| Thứ dùng để query | Thứ trong DB |
|---|---|
| `INV-3: balance must equal sum of deposits` (property) | `"Unsafe cast causes overflow in burn()"` (violation description) |

Text embedding sẽ cho cosine similarity thấp hoặc match sai findings không liên quan.

### 2.3 Independent reasoning bị giới hạn vào INV check

Hiện tại agent chỉ:
1. Viết INV từ code
2. Check INV đó có bị vi phạm không

→ Nếu lỗi nằm ngoài những gì HIST-INV annotated và ngoài INV agent tự viết → bị bỏ qua.

### 2.4 `solodit_findings` là blob — không optimal cho bất kỳ track nào

HIST-INV query bằng operation descriptions nhưng index vào blob có cả prose + code + narrative → noise.

---

## 3. Target Architecture

### Nguyên tắc thiết kế

1. **RAG = pre-processing knowledge** — inject TRƯỚC khi agent reasons, không phải sau
2. **Agent reasons từ first principles** — không chỉ verify patterns đã có sẵn
3. **Separation of concerns**: HIST-INV build làm toàn bộ RAG work; R1 agents thuần reasoning
4. **solodit_op** thay `solodit_findings` cho HIST-INV → semantic coherent

### Pipeline mới

```
HIST-INV build (solodit_op)
    │
    ↓ source annotated với operation-pattern hints
    │
R1 agents (độc lập):
    ├── Verify HIST hints (check code có thực sự vi phạm không)
    └── Independent reasoning tracks (không depend vào RAG)
    │
    ↓
gap-fill (thuần reasoning, không query RAG)
    │
    ↓
dedup → attacker gate → output
```

---

## 4. Thay đổi cụ thể

### 4.1 GIỮ NGUYÊN

- **HIST-INV build structure**: tách biệt, pre-processed, inject vào source — đúng hướng
- **20 agent profiles** với epistemic lens (`core_question`, `system_prompt`) — đây là nền tảng của independent reasoning
- **`_STEP1_BLOCK` priority cho `[HIST-INV]` functions** — agents explicitly check hints
- **Turn 2 full analysis** — logic check INV violation giữ nguyên

### 4.2 LOẠI BỎ

| Thành phần | Lý do |
|---|---|
| `_build_invariant_rag_hints` (Turn 2) | Semantic mismatch + circular reasoning |
| `_build_invariant_rag_hints` (gap-fill) | Cùng lý do |
| `_build_code_similarity_rag_hints` | Duplicate với HIST-INV build |
| `_build_rag_observations` | Dead code |
| Query `solodit_findings` trong HIST-INV | Thay bằng `solodit_op` |

### 4.3 NÂNG CẤP HIST-INV BUILD

Khi `solodit_op` collection sẵn sàng:

```python
# Hiện tại: query solodit_findings (blob)
retriever.query(op_query, collection="solodit_findings")

# Sau: query solodit_op (per-operation docs)
retriever.query(op_query, collection="solodit_op")
```

Per-operation embedding → cosine similarity tốt hơn cho short operation queries.

### 4.4 BỔ SUNG INDEPENDENT REASONING TRACKS vào Turn 2 prompt

Hiện tại Turn 2 chỉ check INV violation. Thêm 4 mandatory reasoning tracks sau INV check:

#### Track A — Adversarial Input Enumeration
> "For each function: what happens with inputs 0, max_uint, empty array, address(0)?  
> Can an attacker craft a sequence of calls to put the contract in an unexpected state?"

#### Track B — Trust Assumption Analysis
> "What does this contract IMPLICITLY trust without verifying?
> - Token always transfers the full amount (fee-on-transfer)
> - Oracle price is not manipulated
> - External call does not re-enter
> - msg.sender is EOA
> For each assumption: is it always guaranteed?"

#### Track C — State Consistency Across Calls
> "Pick any two functions that write to the same storage slot.  
> Is there an interleaving where function A runs, then function B runs, leaving state inconsistent?  
> Focus on functions that: update accounting variables, delete/overwrite entries, modify cumulative totals."

#### Track D — Spec vs Implementation Gap (domain-specific)
> Được customize per domain group:
> - `code_security`: "Does every external call follow CEI pattern?"
> - `crypto_math`: "Is there any intermediate computation that can overflow before the final result is bounded?"
> - `defi_economics`: "Can total assets ever exceed total shares * price_per_share after any sequence of operations?"
> - `governance`: "Is there any path where a single actor can unilaterally change protocol parameters?"

### 4.5 CẬP NHẬT `clmm_specialist` và `code_similarity_auditor`

**`clmm_specialist`**:
- Hiện tại: đặc biệt bypass M1 filter trong INV RAG query
- Sau: không cần bypass vì Turn 2 RAG query được loại bỏ
- Giữ nguyên system_prompt và core_question — vẫn valuable

**`code_similarity_auditor`**:
- Hiện tại: phụ thuộc hoàn toàn vào `_build_code_similarity_rag_hints`
- Sau: cần redesign hoặc loại bỏ
- **Đề xuất**: merge vào `logic_exploiter` với track C (state consistency) thay thế
- Hoặc giữ agent nhưng đổi task: "compare HIST-INV annotated patterns against actual code mechanics"

---

## 5. Kết quả kỳ vọng

| Metric | Hiện tại | Sau restructure |
|---|---|---|
| RAG queries trong R1 | ~60-100 per session (INV + code_sim) | 0 (pre-done ở HIST-INV) |
| Novel bug coverage | Thấp (bounded by INV agent writes) | Cao hơn (4 independent tracks) |
| False positive từ RAG noise | Có (INV query match wrong findings) | Giảm |
| Latency R1 per agent | 2 LLM calls + N RAG queries | 2 LLM calls (pure reasoning) |
| Semantic coherence HIST-INV | Trung bình (solodit_findings blob) | Tốt (solodit_op per-op docs) |

---

## 6. Trade-off: Có nên giữ RAG trong R1 không?

### Lợi ích nếu giữ RAG trong R1

- **Concrete examples**: Agent không chỉ biết INV abstract mà còn thấy cách một protocol bị exploit cụ thể → viết attack path rõ ràng hơn, finding sắc bén hơn
- **Coverage safety net**: Nếu HIST-INV build miss một function (call graph không đầy đủ), R1 RAG vẫn có thể kéo về relevant findings theo hướng khác
- **Novel pattern confirmation**: Agent tự reasoning ra pattern → query RAG xem có precedent → nếu có thì confidence cao hơn, ít FP hơn

### Vấn đề không phải "có RAG hay không" — mà "dùng RAG ở đâu và bằng gì"

| Hook | Cách dùng | Đánh giá |
|---|---|---|
| INV → `solodit_findings` | Agent viết INV → system query | ❌ Circular + semantic mismatch |
| FUNC blocks → `solodit_findings` | Turn 1 mechanics → system query | ❌ Duplicate HIST-INV |
| **FINDING candidate → `solodit_op`** | Agent đã reason xong → query lấy concrete example | ✅ Evidence enrichment |

### Middle ground: Evidence-Enrichment RAG (optional, thêm sau Phase 2)

Thay vì bỏ hoàn toàn RAG khỏi R1, thêm 1 hook mới khi agent đã **independently** tìm ra finding:

```
Agent Turn 2 (independent reasoning):
  1. Reason độc lập → tìm ra POTENTIAL FINDING
  2. Tự mô tả operation gây ra lỗi (~1 câu ngắn)
  3. System query solodit_op bằng mô tả đó
  4. Inject: "Historical precedent for this pattern: [example with slug + inv]"
  5. Agent dùng precedent để viết attack path cụ thể hơn
```

RAG lúc này **sharpen findings đã có**, không drive reasoning ban đầu — tránh circular hoàn toàn.

**Rủi ro còn lại**: confirmation bias — agent force-fit finding vào historical example dù không match.
**Mitigation**: thêm instruction *"If your finding does not match the historical pattern mechanically, do not cite it."*

### Chiến lược triển khai

**Remove trước, benchmark, rồi quyết định:**

1. Phase 2: Remove 3 RAG hooks hiện tại (circular/duplicate) → benchmark
2. Nếu recall ổn → giữ nguyên, không cần thêm gì
3. Nếu recall drop → add Evidence-Enrichment RAG (finding → `solodit_op`) thay vì rollback về INV → `solodit_findings`

Không giữ cái đang broken chỉ vì sợ mất coverage.

---

## 8. Thứ tự triển khai

Chi tiết từng phase xem trong thư mục `r1-restructure/`:

| Phase | File | Trạng thái | Mục tiêu |
|---|---|---|---|
| Phase 1 | [phase1-solodit-op-embed.md](r1-restructure/phase1-solodit-op-embed.md) | ⏳ Chờ fill_inv xong | Embed solodit_op, update HIST-INV build |
| Phase 2 | [phase2-remove-rag-r1.md](r1-restructure/phase2-remove-rag-r1.md) | ⏳ Chờ Phase 1 | Remove 3 RAG hooks, benchmark |
| Phase 3 | [phase3-independent-reasoning-tracks.md](r1-restructure/phase3-independent-reasoning-tracks.md) | ⏳ Chờ Phase 2 | Thêm 4 reasoning tracks vào agents |
| Phase 4 | [phase4-code-similarity-auditor.md](r1-restructure/phase4-code-similarity-auditor.md) | ⏳ Chờ Phase 3 | Redesign hoặc loại bỏ code_similarity_auditor |

**Phase 5** (tương lai, không ưu tiên): nếu cần, build `solodit_inv` ChromaDB collection
để agents query invariants cho các domain patterns chưa có trong HIST-INV DB.

---

## 9. Rủi ro

| Rủi ro | Mức độ | Mitigation |
|---|---|---|
| Remove RAG Turn 2 làm drop recall | Medium | Benchmark từng bước, rollback nếu F1 drop >2 |
| Independent tracks tăng false positive | Medium | Giữ attacker gate, tăng evidence requirement |
| `code_similarity_auditor` mất coverage | Low | Track C (state consistency) bù được |
| HIST-INV `solodit_op` chất lượng thấp hơn dự kiến | Low | Simulate trước khi migrate (đã làm) |

---

## 10. Files cần thay đổi

| File | Thay đổi |
|---|---|
| `cyber_session_orchestrator.py` | Remove 3 RAG functions + call sites |
| `contract_oasis_env.py` | Add 4 independent reasoning tracks vào Turn 2 prompt |
| `contract_kg_builder.py` | Switch HIST-INV retriever sang `solodit_op` |
| `contract_profile_generator.py` | Update `code_similarity_auditor` (Phase 4) |
| `scripts/rag/rag_retriever.py` | Add `solodit_op` collection support |
