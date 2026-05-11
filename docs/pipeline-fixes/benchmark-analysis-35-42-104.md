# Benchmark Analysis: Contest 35, 42, 104

## Kết quả tổng hợp

| Contest | Protocol | GT bugs | TP | FP | Recall | F1 | Scope |
|---------|----------|---------|----|----|--------|----|-------|
| 35 (Trident AMM) | Concentrated liquidity | 17 | 9–11 | 39–47 | 53–65% | 0.22–0.27 | import_graph (size cap) |
| 42 (Mochi) | DeFi lending | 13 | 5 | 68 | 38.5% | 0.116 | multi_root_bfs |
| 104 (MiroPad) | NFT marketplace | 9 | 8 | 20 | 88.9% | 0.432 | multi_root_bfs |

---

## Contest 104 — Tại sao tốt nhất

**Recall 88.9%** — tool hoạt động tốt vì 3 yếu tố hội tụ:

1. **Protocol đơn giản, pattern chuẩn:** Reentrancy, unchecked ERC20 return, unguarded initializer, broken transfer — đây là các SWC-standard bugs mà LLM agents được train rộng rãi trên internet.

2. **Multi-root BFS hoạt động đúng:** 98/99 files in-scope, Splitter/RoyaltyVault/CoreProxy có full source. Bugs phân tán trên nhiều contracts nhưng tất cả đều visible.

3. **Bugs không đòi hỏi cross-contract reasoning phức tạp:** Mỗi bug nằm trong 1 function, 1 contract, logic self-contained.

**FN duy nhất — H-06 (proxy storage collision):** Pattern cần so sánh storage slot layout giữa 2 contracts — zero-shot LLM không làm được mà không có instruction chuyên biệt.

---

## Contest 35 — Tại sao trung bình

**Recall ~53–65%** — tool làm được phần lớn bugs trong scope nhưng bị giới hạn bởi scope.

**Điểm mạnh:** Với 12 bugs in-scope, tool catch được 9–11 (75–92% trong số có thể catch). RC v2b fixes đã target đúng các patterns của contest này.

**Vấn đề cốt lõi — 5/6 FN ổn định do scope:**

| Bug | Location | Vấn đề |
|-----|----------|--------|
| H-02, H-03, H-16 | ConcentratedLiquidityPoolManager | Stubs — size cap 200KB → fallback single-root |
| H-06, H-07 | ConcentratedLiquidityPosition | Stubs — cùng nguyên nhân |
| H-08 | Pool.mint (in-scope) | Boundary condition `<` vs `<=` bị che bởi overflow findings |
| H-17 | Pool.rangeFeeGrowth (in-scope) | Stale nearestTick reference — pattern chưa có instruction |
| H-15 | Pool.initialize | GT ghi sai function name (`initialize` vs `constructor`) |

---

## Contest 42 — Tại sao kém nhất

**Recall 38.5%, FP=68** — kết quả tệ nhất, nhưng nguyên nhân phức tạp hơn scope.

**Tại sao FP=68:**
Mochi là lending protocol với nhiều contracts tương tác (Vault, FeePool, Liquidator, Treasury). Agents generate nhiều findings về reentrancy/overflow/access-control không thực sự exploitable vì:
- Nhiều operations có guard conditions không được agents phát hiện
- Cross-contract invariants phức tạp — agents không model được đầy đủ
- Thiếu attacker gate mạnh: findings không có ATTACK_PATH đủ cụ thể vẫn lọt qua dedup

**FN phân tích theo nhóm:**

| Nhóm | Bugs | Mô tả |
|------|------|-------|
| Caller attribution | H-02 | Tìm được `_shareMochi` (TP) nhưng không scan caller `distributeMochi` |
| Multi-bug anchor | H-06 | Tìm OOB (H-03 TP) rồi dừng, bỏ qua missing `reward=0` cùng function |
| Cross-contract trace | H-07 | Cần trace discount parameter từ Liquidator → Vault.liquidate |
| Griefing zero-value | H-08 | `deposit(id, 0)` reset withdrawal timer người khác — chưa có instruction |
| Missing slippage | H-09, H-12 | Permissionless Uniswap swap không được scan chủ động |
| Admin risk | H-04, H-10 | Missing duplicate check; admin action breaks protocol state |

---

## Tổng hợp vấn đề theo độ ưu tiên

### Vấn đề 1 — Scope (Impact: cao, Fix: rõ ràng)

**Root cause:** Multi-root BFS full union triggers size cap trên large codebases → fallback single-root → contracts quan trọng bị stub.

**Root fix:** Selective secondary roots — xem `docs/pipeline-fixes/selective-multi-root-bfs.md`.
- Bắt đầu từ primary reachable set
- Thêm impl contracts không reachable từ primary làm secondary roots
- Không re-add OZ/utility (đã có qua primary tree)
- Kết quả: contest 35 scope tăng từ 14 → ~19 files, context ~85KB (model xử lý được)

Đây là root fix — không có workaround nào tốt hơn.

---

### Vấn đề 2 — Caller vs Callee Attribution (Impact: trung bình, Fix: instruction)

**Pattern:** Agents tìm bug tại callee X nhưng không tìm tại caller Y gọi X.
Xảy ra: contest 35/H-05, contest 42/H-02, contest 104/H-01.

**Fix:** Thêm instruction "khi phát hiện bug tại function X, scan tất cả functions gọi X — kiểm tra xem caller có expose bug theo cách khác không."

---

### Vấn đề 3 — Pattern Coverage (Impact: cao, nhưng approach hiện tại có vấn đề)

**Thực trạng:** Instructions được thêm dựa trên GT của các contests đã chạy (CAST CROSS-FUNCTION SCAN từ H-01/35, STATE UPDATE ORDERING từ H-12/35, v.v.). Đây là **overfitting** — tuning trên test data.

**Vấn đề với approach hiện tại:**
- Mỗi contest mới lại có pattern mới (sandwich/42, proxy storage/104, griefing zero-value/42)
- Không thể enumerate hết tất cả patterns
- Nếu chỉ add instructions dựa trên GT đã thấy → chỉ đo được "recall trên training set", không phải generalization

**Các kỹ thuật có thể giải quyết:**

| Kỹ thuật | Ý tưởng | Trade-off |
|----------|---------|-----------|
| **Pattern abstraction** | Thay vì "check sandwich attack", dùng rule tổng quát hơn: "mọi permissionless function thực hiện external swap/trade → check slippage protection" | Vẫn cần enumerate categories, nhưng coverage rộng hơn |
| **Retrieval-Augmented Prompting** | Maintain database các vulnerability patterns. Trước mỗi audit, retrieve patterns phù hợp với protocol type (AMM → price manipulation patterns, lending → accounting patterns) | Implementation phức tạp, cần label data |
| **Specialized agents per vulnerability class** | Mỗi agent chỉ check 1 class hẹp nhưng sâu: 1 agent cho "missing state reset after transfer", 1 agent cho "permissionless swap without slippage", v.v. | Token cost tăng; cần curate danh sách classes |
| **Meta-learning từ FN** | Sau mỗi contest, extract abstract pattern từ bugs bị miss, thêm vào pattern library — nhưng chỉ dùng library trên **contests mới** (không dùng lại trên contest đã tuning) | Đúng methodology, nhưng cần nhiều data |

**Kỹ thuật phù hợp nhất hiện tại:** Pattern abstraction + phân tách evaluation.

Cụ thể:
- **Training set (35, 42, 104):** Dùng để tune instructions, chấp nhận là số đẹp do overfitting
- **Test set (các contests chưa chạy):** Đánh giá generalization thực sự — không được nhìn GT trước khi chạy
- Khi add instruction mới, chỉ add nếu nó là **tổng quát** (áp dụng được cho ≥3 protocol types), không add nếu chỉ fix 1 bug của 1 contest

**Kết luận:** Không có silver bullet. Approach đúng là: scope fix (vấn đề 1) cho impact lớn nhất; instructions tổng quát hóa thay vì contest-specific; đánh giá trên held-out test set để đo generalization thực sự.

---

### Vấn đề 4 — Multi-Bug Anchor (Impact: trung bình)

**Pattern:** Khi một function có nhiều bugs, agents tìm được bug đầu tiên rồi dừng — không tiếp tục tìm vulnerabilities khác trong cùng function.

**Ví dụ thực tế — H-06/contest 42:**
- `claimRewardAsMochi()` có 2 bugs: array OOB (H-03) và missing `reward[msg.sender] = 0` (H-06)
- Agents tìm được H-03 (TP), generate findings về OOB, rồi không phát hiện thêm
- Sau khi OOB được fix, bug drain (H-06) vẫn tồn tại — đây là independent vulnerability

**Nguyên nhân:** MULTI-ANGLE EXHAUSTION instruction hiện tại yêu cầu check "different vulnerability class" nhưng agents vẫn bị anchor tâm lý vào finding đầu tiên, không thực sự exhaustive.

**Fix hướng:** Tăng cường instruction: sau khi tìm được finding trong function F, yêu cầu agent explicitly list tất cả state variables được đọc/ghi trong F và check từng cái — không dừng sau finding đầu tiên.

---

### Vấn đề 5 — FP Cao ở Complex Protocols (Impact: cao, khó fix)

**Thực trạng:** Contest 42 (Mochi lending): FP=68, Precision=6.9%. 72 findings mà chỉ 5 đúng.

**Nguyên nhân:**
1. **Lending protocols có nhiều invariants ngầm:** Agents không model được đầy đủ guard conditions giữa các contracts → generate findings về scenarios không thực sự xảy ra được
2. **Attacker gate hiện tại chưa đủ mạnh:** Findings không có ATTACK_PATH cụ thể vẫn lọt qua dedup filter
3. **Thiếu cross-contract invariant reasoning:** Agents check từng function độc lập, không check "function A có thể gọi sau B không? Điều kiện gì cần thỏa mãn?"

**Contrast với contest 104:** FP=20, Precision=28.6% — NFT marketplace đơn giản hơn, ít global invariants phức tạp → agents ít generate false positives hơn.

**Fix hướng:**
- Tăng ATTACK_PATH validation strictness: yêu cầu ACTOR, PRECONDITION, CALL sequence, STATE_CHANGE, OUTCOME — thiếu bất kỳ field nào → drop
- Thêm consensus threshold cao hơn cho lending/complex protocols: cần ≥3 agents độc lập confirm thay vì 2
- Protocol-type detection: nếu là lending protocol → activate stricter false-positive filter

---

## Files liên quan

| Tài liệu | Nội dung |
|----------|---------|
| `docs/pipeline-fixes/multi-root-bfs.md` | Phase 1: full union multi-root BFS |
| `docs/pipeline-fixes/selective-multi-root-bfs.md` | Phase 1b: selective secondary roots (root fix cho contest 35) |
| `docs/pipeline-fixes/slither-dep-graph.md` | Slither dep graph fixes (Phase 2, 3) |
| `benchmark/web3bugs/contest-35/report.md` | Contest 35 detailed report |
| `benchmark/web3bugs/contest-104/report.md` | Contest 104 detailed report |
