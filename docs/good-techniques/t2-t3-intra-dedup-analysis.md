# T2 vs T3 Intra-function Duplicate Analysis

## Bối cảnh

Pipeline sim_e2e sinh findings qua 2 turns per agent:
- **T2** — Invariant-guided: agent dùng invariants T1 + HIST-INV annotations để tìm violations
- **T3** — Independent CoT sweep: agent trace độc lập từng function, không dùng kết quả T2

Do cùng agent nhìn vào cùng source, T2 và T3 thường phát hiện **cùng bug nhưng diễn đạt khác nhau** → duplicate.

---

## Đo lường thực tế (contest 35, sim_e2e_fix_efgh)

Script: `/tmp/sim_intra_dedup.py` — so sánh T2 vs T3 theo `function_name` bằng title Jaccard + anchor similarity.

| Chunk | Total | T2 | T3 | T3 removable | % |
|---|---|---|---|---|---|
| access_reward_CLPM | 48 | 32 | 16 | 11 | 69% |
| math_cast_CLPosition | 46 | 33 | 13 | 9 | 69% |
| general_CLPosition | 52 | 32 | 20 | 10 | 50% |
| general_CLPM | 50 | 31 | 19 | 9 | 47% |
| clmm_semantic_CLP | 22 | 13 | 9 | 4 | 44% |
| state_ordering_CLPosition | 22 | 15 | 7 | 3 | 43% |
| math_cast_CLP | 40 | 26 | 14 | 5 | 36% |
| general_CLP | 35 | 26 | 9 | 3 | 33% |
| **TOTAL** | **315** | **208** | **107** | **54** | **50%** |

**50% T3 findings là duplicate của T2** → intra-dedup loại được 54/315 = **17% tổng findings** (lower bound vì dùng threshold cao, không dùng LLM).

---

## Tại sao dedup hiện tại không bắt được

Dedup pipeline 3 layers (`_dedup_pre_r2` → `_semi_static_anchor_dedup` → `_llm_anchor_dedup`):

**Layer 1 (`_dedup_pre_r2`)**: Không phải dedup — chỉ drop findings có anchor không tồn tại trong source hoặc attack_path thiếu cấu trúc. T2/T3 cùng agent đều pass.

**Layer 2 (`_semi_static_anchor_dedup`)**: Group theo `(contract, function, exact_normalized_anchor)`. T2 và T3 cùng bug thường có anchor hơi khác nhau (T2 trỏ dòng X, T3 trỏ dòng X±1 hoặc diễn đạt khác) → miss.

**Layer 3 (`_llm_anchor_dedup`)**: Group theo `(contract, function)`, batch size=8, iterative reduction (6 rounds). Lý thuyết có thể bắt được, nhưng:
- Function có nhiều findings (20-30) → split nhiều batch → T2 và T3 của cùng agent dễ rơi vào batch khác nhau
- Không guaranteed compare mọi cặp dù có nhiều rounds

---

## Ví dụ T2/T3 duplicates bị miss

```
fn=reclaimIncentive  [anchor_match(1.00)]
  T2: "Missing Accounting Update for rewardsUnclaimed in reclaimInc..."
  T3: "Missing Accounting Update After Incentive Reclaim (G7)"

fn=subscribe  [anchor_match(1.00)]
  T2: "Incorrect Mapping Lookup in subscribe() uses Position ID as..."
  T3: "Incorrect Mapping Key Usage (positionId used as incentiveId)"

fn=rangeFeeGrowth  [title_sim(0.36)]
  T2: "Arithmetic Revert in Fee Growth Calculation Due to Missing U..."
  T3: "Arithmetic Revert on Fee Growth Accumulator Wrap"
```

Cả 3 ví dụ: cùng anchor hoặc title gần giống nhưng khác đủ để layer 2 miss; nếu khác batch thì layer 3 cũng miss.

---

## 3 options fix

| Option | Cách làm | Ưu | Nhược |
|---|---|---|---|
| **A — T3 aware of T2** | Show T2 findings trong T3 prompt, yêu cầu T3 chỉ report bug chưa có trong T2 | Fix tại nguồn, không tốn thêm LLM call | Tăng context T3, risk T3 bị anchored vào T2, bỏ sót bugs T2 miss |
| **B — Intra-agent dedup** | Sau khi agent xong T2+T3, dedup riêng cặp (T2, T3) của agent đó trước khi merge vào chunk pool | Đơn giản, O(\|T2\|×\|T3\|) nhỏ, không ảnh hưởng generation | Cần lưu `agent_id` trong findings (hiện tại không có) |
| **C — Intra-domain vote** | Agents trong domain vote cho findings sau khi chunk xong | Giảm cả cross-agent FP lẫn T2/T3 dup, đồng thuận chuyên môn | Phức tạp hơn, cần implement riêng |

**Đề xuất trước mắt**: Option A — chỉ cần thêm T2 findings vào T3 prompt context, không cần thay đổi struct.
Option B cần thêm `agent_id` vào findings trước (change nhỏ trong parsing).
Option C là kế hoạch dài hạn (intra-domain verify đã được plan trong sim-e2e-architecture.md).

---

## Kiến trúc dedup đa tầng (đề xuất triển khai)

Dựa trên phân tích trên, dedup nên chạy **liên tục nhiều tầng** thay vì 1 lần cuối:

### 3 tầng chính

```
Sau mỗi agent hoàn thành T2+T3:
  Tầng 1 — Intra-agent (agent_id, fn):
    Compare T2 vs T3 của agent đó
    → LLM judge (~12 pairs/agent, fast)
    → Merge vào chunk pool

Sau tất cả agents trong chunk xong:
  Tầng 2 — Cross-agent (fn), cùng chunk:
    Compare findings của các agents khác nhau cùng fn
    Bỏ qua cặp đã dedup ở Tầng 1
    → LLM judge (~C(n_agents, 2) × findings/agent)

Sau tất cả chunks xong:
  Tầng 3 — Global (fn), cross-chunk:
    Dedup cùng fn xuất hiện trong nhiều chunks (do aux contract injection)
    → LLM judge (ít pairs nhất nhưng cần nhất cho aux contracts)
```

### Tại sao không cần thêm tầng "sau mỗi contract"

Tầng 2 = chunk-level (đã cover cross-agent trong cùng chunk).
Tầng 3 = global (đã cover cross-chunk). Tầng "contract-level" nằm giữa 2 và 3 sẽ redundant vì:
- Cross-chunk cùng contract phần lớn do aux contract injection → Tầng 3 đã xử lý
- Không thêm coverage mới, chỉ tăng complexity

### Ghi chú triển khai

| Tầng | Timing | Input size | LLM cost | Blocking? |
|---|---|---|---|---|
| Tầng 1 | Sau mỗi agent | ~3×4 = 12 pairs | Nhỏ | Non-blocking (agent khác vẫn chạy) |
| Tầng 2 | Sau mỗi chunk | ~15×5 = 75 pairs | Vừa | Blocking (chunk đã xong) |
| Tầng 3 | Sau tất cả chunks | Ít pairs | Nhỏ | Blocking (1 lần cuối) |

**Prerequisite**: Cần thêm `agent_id` vào findings struct (hiện tại `None` trong chunk_raw.json) để Tầng 1 phân biệt được cặp T2/T3 của cùng agent.

### Tại sao text similarity không đủ (kể cả Tầng 1)

Validation trên contest 35: text similarity (Jaccard title + anchor) chỉ bắt được **16%** các cặp duplicate đã xác nhận bằng anchor matching. LLM sinh ra diễn đạt rất khác nhau cho cùng bug → **mọi tầng đều cần LLM judge**, kể cả Tầng 1 (intra-agent).
