# Fix: Invariant-Driven Analysis trong R1 Agents

## Vấn đề hiện tại

R1 agents hiện chỉ làm **pattern matching** — scan code tìm các patterns đã được hard-code trong instructions (cast overflow, state update ordering, v.v.). Approach này bị giới hạn bởi số lượng patterns đã biết và dễ bỏ qua các bugs logic đặc thù của từng protocol.

**Điểm yếu cụ thể:**
- Contest 42: H-01/H-05 bị miss vì agents không tự hỏi "global_debts phải bằng tổng individual debts — có đúng không?"
- Contest 42: H-07 bị miss vì agents không trace "discount parameter từ Liquidator có được truyền đúng vào Vault không?"
- Pattern matching hướng agents đến các SWC-standard bugs, không phải protocol-specific logic errors

---

## Giải pháp: Self-Generated Invariants trong R1

Thêm một bước **bắt buộc trước khi tìm bugs**: agent phải tự list ra các quy tắc bất biến protocol-specific dựa trên code đang phân tích, sau đó dùng chính các invariants đó làm "mục tiêu" để tìm violations.

### Nguyên tắc cốt lõi

Thay vì hỏi *"code này có pattern X không?"* → hỏi *"protocol này PHẢI duy trì gì, và code có đảm bảo điều đó không?"*

---

## Instruction Block cần thêm vào R1

**Vị trí:** Trước block `CAST & COMPARISON PRECISION` trong `build_round1_prompt()` (`contract_oasis_env.py`, line ~1414)

```
PROTOCOL INVARIANT ANALYSIS — bắt buộc trước khi viết bất kỳ FINDING nào:

BƯỚC 1 — TỰ LIỆT KÊ INVARIANTS:
  Đọc toàn bộ contract source và liệt kê 3–6 invariants PROTOCOL-SPECIFIC.
  Format: INV-1: <mô tả bất biến>, INV-2: ..., ...

  Invariants PHẢI được suy ra trực tiếp từ code, require() statements, hoặc NatSpec.
  KHÔNG được tự bịa ra business rules hoặc assume tính năng không có trong code.
  (Ví dụ sai: "hợp đồng phải có hàm pause()" nếu code không có pause mechanism.)

  Invariants PHẢI là protocol-specific — KHÔNG chấp nhận:
    ✗ Generic: "không có reentrancy", "không có overflow", "onlyOwner"
    ✓ Specific accounting: "sau borrow(), global_debts phải tăng đúng bằng amount + fee"
    ✓ Specific state: "withdrawalDelay[id] chỉ được set khi msg.sender == owner(id)"
    ✓ Specific flow: "distribute() chỉ được phép giảm mochiShare, KHÔNG được reset treasuryShare"
    ✓ Specific math: "shares * pricePerShare / 1e18 phải bằng underlying assets của depositor"

  Cách tìm invariants tốt:
  - Đọc NatSpec @notice/@dev — chúng thường mô tả điều kiện phải đúng
  - Đọc require() messages — mỗi require là 1 invariant candidate
  - Xem state variables tên có "total", "global", "cumulative" — chúng thường cần bằng tổng các giá trị con
  - Xem functions có "distribute", "reward", "migrate", "sync" — chúng thường có ordering invariants

BƯỚC 2 — TÌM VIOLATIONS:
  Với mỗi invariant vừa list, hỏi:
  Q1: Có execution path nào (sequence of function calls) có thể làm invariant này sai không?
  Q2: Nếu có — attacker kiểm soát được path đó không? Hay chỉ xảy ra do bug logic?
  Q3: Nếu vi phạm xảy ra, hậu quả measurable là gì?

  Nếu Q1 = YES → viết FINDING với:
    EVIDENCE: INV: <phát biểu invariant> | VIOLATED_AT: <fn()> | COUNTEREXAMPLE: <điều kiện gây vi phạm>

  Sau khi liệt kê xong invariants, NGAY LẬP TỨC chuyển sang viết FINDING block.
  Không cần tổng kết hay nhận xét thêm — chuyển thẳng vào findings.
```

---

## Sự khác biệt với STEP 1.5 (ContractInvariantExtractor)

| | STEP 1.5 (hiện tại) | R1 Self-Generated (mới) |
|---|---|---|
| **Ai extract** | Boost LLM call riêng (trước khi agents chạy) | Mỗi R1 agent tự extract |
| **Scope** | Global — toàn bộ protocol | Local — từ góc nhìn của persona agent đó |
| **Dùng ở đâu** | R3 attacker round | R1 discovery (nơi tìm bugs) |
| **Invariant type** | High-level protocol invariants | Function-level, accounting-level |

**Không redundant** — hai cơ chế bổ sung cho nhau:
- STEP 1.5 → R3: xác nhận/bác bỏ các vulnerabilities đã tìm được
- R1 self-generated: dẫn dắt tìm vulnerabilities mới mà pattern matching bỏ sót

---

## Tại sao không chỉ pass STEP 1.5 invariants vào R1?

Pass invariants từ STEP 1.5 vào R1 là cải tiến cần làm (quick win), nhưng chưa đủ:
1. STEP 1.5 extract invariants từ một perspective duy nhất — `defi_offensive` agent có thể tìm thêm invariants mà STEP 1.5 bỏ sót
2. STEP 1.5 invariants là high-level; R1 cần function-level invariants để tìm bugs cụ thể
3. Self-generation bắt agent phải **đọc hiểu code** trước khi tìm bugs — tránh anchoring vào patterns

---

## Rủi ro và mitigation

**Rủi ro 1 — Agent list generic invariants:**
Mitigation: Instruction có ví dụ rõ ràng về ✓ specific vs ✗ generic, kèm pattern nhận biết (total*, global*, cumulative* variables).

**Rủi ro 2 — Hallucinated invariants (tự bịa business rules):**
LLM đôi khi tự chế ra invariants từ protocols khác mà nó đã thấy trong training data, không phải từ code đang review. (Ví dụ: báo lỗi "không có hàm pause()" vì nó thấy pattern này ở protocols khác.)
Mitigation: Rule cứng "MUST be derived from code/require/NatSpec — không assume tính năng không có trong code" đã được thêm vào instruction block.

**Rủi ro 3 — Premature stop (dùng hết token ở bước invariant, quên viết FINDING):**
Mitigation: Instruction yêu cầu "NGAY LẬP TỨC chuyển sang FINDING sau khi liệt kê xong — không tổng kết". Không dùng separator marker vì tốn tokens và không cần thiết (pipeline parse FINDING bằng regex, không phụ thuộc vào markers).

**Rủi ro 4 — Token cost tăng:**
Mỗi agent call thêm ~200–400 tokens cho invariant listing. Với 22 agents, tổng thêm ~5,000–9,000 input tokens/run. Chấp nhận được.

**Rủi ro 5 — Agents dùng nhiều thời gian cho invariant listing, ít thời gian tìm bugs:**
Mitigation: Giới hạn 3–6 invariants. Instruction nhấn mạnh "list nhanh, tìm violations sâu".

---

## Hai bước triển khai

### Bước 1 (Quick win — không thay đổi kiến trúc):

Pass invariants từ STEP 1.5 vào `build_round1_prompt()`. Frame như "gợi ý từ Senior Auditor" để agent không copy lại một cách thụ động — thay vào đó, agent được khuyến khích tìm thêm function-level invariants bổ sung:

```python
# Trong contract_oasis_env.py:
def build_round1_prompt(
    agent_profile,
    context_summary,
    dep_graph_text = "",
    intent_summary = "",
    focus_directive = "",
    invariants = None,   # THÊM
) -> str:
    inv_block = ""
    if invariants:
        inv_lines = "\n".join(
            f"  INV-{i+1}: {inv['statement']}"
            for i, inv in enumerate(invariants[:8])
        )
        inv_block = f"""
=== HIGH-LEVEL PROTOCOL INVARIANTS (từ System Architect) ===
{inv_lines}
Đây là các invariants cấp protocol. Nhiệm vụ của bạn: supplement bằng
function-level invariants cụ thể hơn trước khi tìm violations.
"""
```

**Lưu ý framing:** Không dùng "find what Architect missed" — cách đó khiến agent meta-phân tích thay vì tìm bugs. Dùng "supplement" để tạo cảm giác cộng tác, agent bổ sung thêm mà không bị anchor vào list có sẵn.

### Bước 2 (Full solution — self-generated invariants):

Thêm instruction block PROTOCOL INVARIANT ANALYSIS vào `build_round1_prompt()` như mô tả ở trên.

---

## Kết quả kỳ vọng

| Contest | Bug hiện miss | Invariant sẽ dẫn đến |
|---------|--------------|---------------------|
| 42 | H-01, H-05 | "global_debts == sum(individual debts)" |
| 42 | H-02 | "distributeMochi() không được modify treasuryShare" |
| 42 | H-07 | "amount passed to liquidate() phải = discountedDebt, không phải fullDebt" |
| 42 | H-08 | "lastDeposit[id] chỉ được update bởi owner(id)" |
| 35 | H-17 | "rangeFeeGrowth dùng nearestTick → invariant: reference tick phải reflect current position" |

---

## Files cần thay đổi

| File | Thay đổi |
|------|---------|
| `backend/app/services/contract_oasis_env.py` | Thêm instruction block PROTOCOL INVARIANT ANALYSIS trước CAST & COMPARISON PRECISION; thêm `invariants` parameter vào `build_round1_prompt()` |
| `backend/scripts/run_contract_audit.py` | Pass `invariants` từ STEP 1.5 vào `build_round1_prompt()` call |

---

## Verification

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

# Chạy contest 42 với invariant-driven R1
LOG=/tmp/web3bugs_42_inv_$(date +%Y%m%d_%H%M%S).log
DEDUP=/tmp/dedup_42_inv_$(date +%Y%m%d_%H%M%S).json
STOP_AFTER_DEDUP=true STOP_AFTER_DEDUP_OUT=$DEDUP \
nohup bash -c 'source /home/thangdd/repos/MiroFish/backend/.venv/bin/activate && exec python scripts/run_contract_audit.py \
  --contest-dir /home/thangdd/repos/web3bugs/contracts/42 \
  --output ./results/web3bugs_trial/contest_42_inv --timeout 7200 --verbose' >> "$LOG" 2>&1 &

# Evaluate — target: TP >= 8 (từ 5), FP giảm về < 50
python scripts/evaluate/web3bugs_eval.py scripts/evaluate/gt/gt_42.json $DEDUP --verbose
```

**Target:** TP 5 → 8+ (H-01/H-02/H-05/H-07 có invariant rõ ràng), FP giảm vì agent có "mục tiêu" thay vì scan loạn.
