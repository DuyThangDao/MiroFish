# Domain Output Constraint — Vấn đề và Thiết kế

## Vấn đề hiện tại

### Agents đang report mọi thứ, không bị constrain

Mỗi agent trong R1 được inject `core_question` (CQ) như một "epistemic lens" — ví dụ `boundary_analyst` được hỏi về `< vs <=` tại range boundaries. Tuy nhiên, prompt chính tại `build_round1_prompt()` yêu cầu:

```
Perform an independent security analysis.

STEP 1 — LIST INVARIANTS:
  Read the full contract source and list 3–6 invariants.

STEP 2 — FIND VIOLATIONS:
  For each invariant listed above, ask: Is there any execution path...
```

Không có câu nào giới hạn **loại findings được phép report**. CQ chỉ là một gợi ý hướng nhìn, không phải bộ lọc output.

### Tại sao CQ không đủ

CQ hoạt động như sau trong prompt:

```
=== YOUR EPISTEMIC LENS ===     ← "hãy để ý đến X"
[Q1] For every comparison involving a range...
[Q2] Where is a two-sided range defined...

STEP 1: list 3-6 invariants     ← không giới hạn domain
STEP 2: check từng invariant    ← findings từ bất kỳ loại invariant nào
TRACK A: adversarial inputs     ← generic, tất cả agents đều có
```

CQ ảnh hưởng đến STEP 1 bằng cách thêm 1 boundary invariant vào danh sách — nhưng không ngăn agent list 5 invariant khác về reserve accounting và unchecked arithmetic, vì đó là các pattern salient nhất trong code.

Ví dụ thực tế: `boundary_analyst` vào chunk `mint/CLP` (500 dòng), thấy các pattern rõ ràng nhất là reserve accounting và unchecked arithmetic → liệt kê các invariant đó trước → STEP 2 check tất cả → report cả 6 findings, trong đó chỉ có thể có 1 finding liên quan đến boundary.

### Dữ liệu minh chứng

Từ phân tích run `sim_e2e_seqcq_r1` (619 raw findings, contest 35):

| Root cause | Count | % |
|---|---|---|
| unchecked_arithmetic | 305 | 49.3% |
| reserve_accounting | 157 | 25.4% |
| mapping_key_wrong | 44 | 7.1% |
| fee_growth_wrap | 30 | 4.8% |
| CEI/reentrancy | 28 | 4.5% |

→ 74.7% findings là 2 pattern dominant nhất — được generate bởi TẤT CẢ agents, kể cả những agent có domain hoàn toàn không liên quan như `boundary_analyst`, `temporal_attack_specialist`, `data_provenance_analyst`.

Ước tính: 619 raw → ~97 independent findings (6.4x duplication ratio).

### Hậu quả với recall

Miss bugs như H-08 (`< vs <=`), H-12 (first-call div-zero), H-16 (JIT), H-17 (data provenance) đều bị nhấn chìm bởi avalanche findings dominant:

- H-08: 29 mint/CLP candidates, tất cả về reserve/CEI, không có boundary finding
- H-12: 29 mint/CLP candidates, tất cả về reserve/CEI, không có first-call div-zero
- H-16: 80 claimReward candidates, tất cả về formula/arithmetic, không có JIT temporal
- H-17: 68 rangeFeeGrowth candidates, tất cả về unchecked arithmetic

---

## Thiết kế giải pháp

### Nguyên tắc

Thay vì CQ là "hướng nhìn" (lens), cần CQ là **output gate**: agent chỉ được phép report findings thuộc domain của nó.

### Approach A: Explicit ONLY/DO NOT instruction (đơn giản nhất)

Thêm vào cuối mỗi agent prompt:

```
=== OUTPUT CONSTRAINT ===
ONLY write FINDING blocks for vulnerabilities within your domain: {domain_description}.

If you detect a bug OUTSIDE your domain — note it briefly as:
  OUT-OF-DOMAIN: {function}() — {one sentence description}
But do NOT write a full FINDING block for out-of-domain bugs.
```

Mỗi agent cần có `domain_description` riêng trong AGENT_MATRIX, ví dụ:

| Agent | domain_description |
|---|---|
| `boundary_analyst` | comparison operator bugs (< vs <=, > vs >=), off-by-one at range boundaries |
| `temporal_attack_specialist` | time-dependent attacks, JIT mint/claim/burn, front-run/sandwich across blocks |
| `data_provenance_analyst` | data source mismatches — when a value is derived from pointer A but should use canonical value B |
| `entry_point_hardener` | first-call initialization bugs, division by zero when denominator is uninitialized state |
| `math_cast_analyst` | unsafe casts (uint256→uint128), signed/unsigned negation overflow |
| `reserve_accounting_specialist` | reserve tracking — does reserve reflect exactly what's held, no more no less |

Agents không có `domain_description` → không áp dụng constraint (giữ behavior cũ).

### Approach B: Per-agent finding cap = 1 (đơn giản hơn)

Hard-cap mỗi agent chỉ trả về 1 finding — buộc agent phải chọn finding quan trọng nhất trong domain của nó.

Ưu điểm: không cần viết domain_description cho từng agent.  
Nhược điểm: nếu agent vẫn chưa có output gate, nó sẽ pick finding salient nhất (reserve accounting) thay vì finding trong domain của nó.

**→ Approach B không giải quyết được vấn đề gốc nếu không kết hợp với Approach A.**

### Approach C: Kết hợp A + B (recommended)

1. Thêm explicit output constraint (Approach A) cho mỗi agent
2. Cap = 1-2 findings per agent
3. Agents không có domain constraint giữ nguyên (general agents)

Kết quả dự kiến: ~619 → ~50-70 findings tổng, dedup ratio từ 6.4x xuống còn 1-2x.

---

## File cần thay đổi

| File | Thay đổi |
|---|---|
| `backend/app/services/contract_profile_generator.py` | Thêm field `domain_output_constraint` vào AGENT_MATRIX cho các agents cần constrain |
| `backend/app/services/contract_oasis_env.py` | Thêm `OUTPUT CONSTRAINT` block vào `build_round1_prompt()` khi agent có `domain_output_constraint` |

### Thay đổi cụ thể trong `contract_profile_generator.py`

```python
"boundary_analyst": {
    "display_name": "Boundary Condition Analyst",
    "domain_group": "state_logic",
    "swc_focus": ["SWC-110", "SWC-113"],
    "domain_output_constraint": (
        "comparison operator bugs (< vs <=, > vs >=, inclusive vs exclusive boundaries). "
        "Includes: off-by-one at price/tick/timestamp ranges, wrong strictness at active range boundaries."
    ),
    "prompt": "...",
    "core_question": "...",
},
```

### Thay đổi cụ thể trong `contract_oasis_env.py`

Trong `build_round1_prompt()`, sau `tracks_block`:

```python
constraint = getattr(agent_profile, "domain_output_constraint", "")
constraint_block = (
    f"\n=== OUTPUT CONSTRAINT ===\n"
    f"ONLY write FINDING blocks for: {constraint}\n\n"
    f"If you detect bugs OUTSIDE this scope — write one line:\n"
    f"  OUT-OF-DOMAIN: {{function}}() — {{one sentence}}\n"
    f"Do NOT write a full FINDING block for out-of-domain bugs.\n"
) if constraint else ""
```

---

## Agents cần constrain (ưu tiên cao — các agent liên quan đến miss bugs)

| Agent | Miss bug cần recover | Constraint cần thêm |
|---|---|---|
| `boundary_analyst` | H-08 (< vs <=) | comparison operators only |
| `entry_point_hardener` | H-12 (first-call div-zero) | first-call init bugs, uninitialized denominator |
| `temporal_attack_specialist` | H-16 (JIT) | time-dependent/cross-block attacks |
| `data_provenance_analyst` | H-17 (nearestTick pointer vs canonical) | data source mismatches |
| `math_cast_analyst` (nếu có) | H-01 (int128 negation), H-05 (uint128 cast) | unsafe casts, signed overflow |

---

## Risks và Mitigation

**Risk: Agent không tìm được finding nào trong domain → TP giảm**

Một số bugs không có đặc điểm domain rõ ràng. Nếu constraint quá strict, agent bỏ qua bugs thực sự.

Mitigation:
- Viết `domain_output_constraint` rộng hơn một chút (include related patterns)
- Chỉ áp dụng cho agents có clear domain (5-8 agents), không áp dụng cho general agents
- Test với 1-2 agents trước khi roll out toàn bộ

**Risk: OUT-OF-DOMAIN notes làm tăng token consumption**

Nếu agent thấy 10 out-of-domain bugs và note tất cả, sẽ tăng output token.

Mitigation: giới hạn `OUT-OF-DOMAIN` notes tối đa 3, phần còn lại bỏ qua hoàn toàn.

---

## Trạng thái

- [ ] Chưa implement
- Ưu tiên: sau khi có kết quả baseline đủ để so sánh
- Thử nghiệm nên bắt đầu với `boundary_analyst` và `entry_point_hardener` (liên quan trực tiếp đến H-08, H-12 — hai miss bugs persistent nhất)
