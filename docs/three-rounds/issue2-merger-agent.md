# Issue 2: Merger Agent — Giải Pháp Dedup Cross-Type

> Giải pháp cho bài toán dedup findings cùng bug nhưng khác evidence type,
> không cần coordination giữa R1 agents và không block tốc độ tìm kiếm.

---

## 1. Vấn Đề Cần Giải Quyết

R1 agents hoạt động độc lập → cùng 1 bug có thể được describe bằng nhiều evidence types:

```
H-10 (burn() wrong reserve) → 5 findings, 4 types:
  CODE:    reserve0 -= uint128(amount0fees)
  MISSING: reserve0 -= uint128(amount0) AT: burn()
  SEQ:     burn() sends amount0 → reserve only subtracts fees
  INV:     after burn(), reserve0 == balance
  CODE:    reserve0 -= uint128(amount0fees)   ← exact dup
```

5 slots dùng cho 1 bug → 4 slots thừa trong top 40.

Không có signal heuristic nào (embedding, BUG_ID slug, token intersection) đủ tin cậy
để dedup cross-type. Lý do căn bản: agents hoạt động độc lập, không có shared vocabulary,
mọi field dùng natural language tự sinh đều diverge.

---

## 2. Giải Pháp: CODE_ANCHOR + Merger Agent

### 2.1 Nguyên tắc cốt lõi

Tất cả vulnerability trong smart contract — dù được describe bằng evidence type nào —
đều có thể anchor vào **một dòng code cụ thể trong source** liên quan trực tiếp đến bug.

Dòng code này là thứ agents **sẽ tự nhiên nhìn vào** khi phát hiện bug, bất kể approach:

```
H-10: Agent dùng CODE → nhìn thẳng vào: reserve0 -= uint128(amount0fees)
      Agent dùng MISSING → trace xem reserve bị thiếu gì → nhìn vào: reserve0 -= uint128(amount0fees)
      Agent dùng SEQ → trace flow burn() → thấy: reserve0 -= uint128(amount0fees) không match transfer
      Agent dùng INV → kiểm tra invariant reserve==balance → trace về: reserve0 -= uint128(amount0fees)
```

→ Tất cả hội tụ về cùng 1 dòng vì đó là điểm bug thực tế trong code.

Đây là signal **grounded vào code artifact**, không phải natural language → có thể converge
mà không cần coordination giữa agents.

### 2.2 Field CODE_ANCHOR (bắt buộc trong R1 output)

```
CODE_ANCHOR: <dòng code trong source gần nhất/liên quan nhất đến bug>
```

**Lưu ý quan trọng:** `CODE_ANCHOR` là identifier để dedup, **không thay thế evidence**.
Evidence vẫn phải đầy đủ như cũ (CODE:/MISSING:/SEQ:/INV:/DESIGN: với đầy đủ format).
Hai field phục vụ mục đích khác nhau: CODE_ANCHOR để định danh bug, Evidence để chứng minh bug.

### 2.3 Định Nghĩa CODE_ANCHOR Theo Từng Evidence Type

**Nguyên tắc chung:** CODE_ANCHOR là **dòng code sẽ xuất hiện trong git diff khi fix bug**.

Framing "git diff line" hoạt động vì dù agent tiếp cận bằng evidence type nào, khi
nghĩ đến "fix thì sửa/thêm/di chuyển dòng nào" → tất cả hội tụ về cùng 1 dòng.
Đây là điểm grounded vào code artifact, không phụ thuộc vào vocabulary của agent.

**Ràng buộc chung áp dụng cho mọi type:**

```
1. Copy nguyên văn từ source — không paraphrase, không viết lại
2. Phải tìm được bằng grep trong flattened source (parser sẽ verify)
3. Tối đa 150 ký tự — nếu dòng dài hơn, lấy từ đầu dòng đến ký tự 150
4. Không lấy dòng comment (// hoặc /* */) hoặc dòng trống
5. Không lấy dòng chỉ có dấu ngoặc ({ hoặc }) hoặc từ khóa đơn độc (else, return)
6. Nếu bug nằm ở multi-line expression: lấy dòng ĐẦU TIÊN của expression đó
7. DESIGN type: anchor BẮT BUỘC phải là dòng `function` declaration —
   KHÔNG dùng control flow opener (while/if/for) dù đó là điểm entry point.
   Lý do: mỗi function chỉ có 1 declaration → convergence cao.
   Control flow opener không unique trong function → gây false merge giữa bugs khác nhau.
```

---

#### CODE — dòng bị thay thế khi fix

**Quy tắc:** Dòng code sai, sẽ bị xóa hoặc sửa trực tiếp trong fix commit.

```
Cách xác định: Đây là dòng mà nếu fix bug, developer sẽ đặt con trỏ vào
và sửa nội dung của chính dòng đó.
```

**Ví dụ đúng:**
```
✓ reserve0 -= uint128(amount0fees);
  (sẽ được sửa thành: reserve0 -= uint128(amount0 + amount0fees);)

✓ position.liquidity -= int128(amount);
  (unsafe cast, sẽ được thêm check overflow)

✓ if (priceLower < currentPrice && currentPrice < priceUpper)
  (điều kiện sai, sẽ được sửa thành <=)
```

**Ví dụ sai:**
```
✗ reserve0 -= fees              ← tự viết, không tồn tại trong source
✗ "the reserve update line"     ← prose
✗ // subtract fees from reserve ← comment, không phải code thực
```

**Edge cases:**

```
Bug trải dài 2 dòng:
  reserve0 -= uint128(
      amount0fees             ← lấy dòng đầu tiên
  );
  CODE_ANCHOR: reserve0 -= uint128(

Nhiều dòng sai cùng loại (reserve0 và reserve1):
  reserve0 -= uint128(amount0fees);   ← lấy dòng ĐẦU TIÊN
  reserve1 -= uint128(amount1fees);
  CODE_ANCHOR: reserve0 -= uint128(amount0fees);
```

---

#### MISSING — dòng cuối cùng trước vị trí cần insert code

**Quy tắc:** Dòng code tồn tại trong source, ngay trước vị trí mà fix sẽ insert thêm.
Không phải dòng missing (nó không tồn tại) mà là "mốc vị trí" để xác định chỗ insert.

```
Cách xác định: Hỏi "fix sẽ insert code mới SAU dòng nào?" →
đó là CODE_ANCHOR.
```

**Ví dụ đúng:**
```
H-15: thiếu range check cho initialPrice trong initialize():

  function initialize(bytes calldata data) public override {
      (uint160 initialPrice, int24 tick, ...) = abi.decode(data, ...);
      ↑ FIX INSERT: require(initialPrice >= MIN_SQRT_RATIO && ...) SAU DÒNG NÀY
      (int24 nearestTick,) = TickMath.getTickAtSqrtRatio(initialPrice);
  }

  CODE_ANCHOR: (uint160 initialPrice, int24 tick, ...) = abi.decode(data, ...);

H-03: thiếu rewardsUnclaimed update trong reclaimIncentive():

  incentive.rewardsUnclaimed -= uint112(reward);
  ↑ FIX INSERT: cập nhật thêm state ở đây
  _transfer(token, reward, to, false);

  CODE_ANCHOR: incentive.rewardsUnclaimed -= uint112(reward);
```

**Edge cases:**

```
Missing check ngay đầu function (trước mọi dòng code):
  function foo(uint256 amount) external {
      ↑ FIX INSERT: require(amount > 0) Ở ĐÂY — không có dòng nào trước
  → Dùng dòng khai báo function làm anchor:
  CODE_ANCHOR: function foo(uint256 amount) external {

Missing function hoàn toàn (cả function không tồn tại):
  → Dùng dòng gọi function đó từ caller:
  CODE_ANCHOR: _updateReserves(amount0, amount1);  ← caller line
  (caller tồn tại, callee bị thiếu)

Missing event emission (sau state change):
  balances[user] -= amount;  ← state change
  ↑ FIX INSERT: emit Transfer(user, to, amount) SAU ĐÂY
  CODE_ANCHOR: balances[user] -= amount;
```

---

#### SEQ — dòng thực thi sai thứ tự

**Quy tắc:** Dòng đọc/sử dụng state đã bị modify sai trước đó — đây là dòng
sẽ được di chuyển lên trước thao tác modify khi fix.

```
Cách xác định: Trong cặp "A rồi B" sai thứ tự,
A modify state, B đọc state đó → CODE_ANCHOR là B
(dòng B sẽ được move lên trước A khi fix).
```

**Ví dụ đúng:**
```
H-12: secondsPerLiquidity dùng liquidity đã bị update:

  liquidity += int128(amount);              ← A: modify liquidity
  secondsPerLiquidity += diff / liquidity;  ← B: đọc liquidity đã sai

  CODE_ANCHOR: secondsPerLiquidity += diff / liquidity;
  Fix: di chuyển dòng B lên trước dòng A

H-06: Position.collect() đọc fees rồi Pool.burn() thu lại fees lần 2:

  // Trong ConcentratedLiquidityPosition.collect():
  feesOwed0 = 0;  ← A: mark as collected
  // Trong ConcentratedLiquidityPool.burn():
  amount0 += position.feesOwed0;  ← B: đọc lại fees đã được collect

  CODE_ANCHOR: amount0 += position.feesOwed0;
  (dòng trong Pool.burn() — đây là dòng đọc state sai)
```

**Edge cases:**

```
3 thao tác sai thứ tự (A → B → C, đúng phải C → A → B):
→ Lấy dòng đầu tiên bị đặt sai vị trí (dòng A trong source hiện tại).

SEQ cross-contract (A trong contract X, B trong contract Y):
→ Vẫn lấy dòng B (dòng đọc state sai), dù ở contract khác.
→ CONTRACT field phải ghi contract chứa dòng B.
```

---

#### INV — dòng computation vi phạm invariant

**Quy tắc:** Dòng thực hiện phép tính mà kết quả của nó vi phạm bất biến của protocol.
Đây là dòng sẽ được wrap trong `unchecked{}` hoặc thêm boundary check khi fix.

```
Cách xác định: Hỏi "phép tính nào cho ra giá trị sai?" →
đó là CODE_ANCHOR.
```

**Ví dụ đúng:**
```
H-09/H-14: feeGrowthInside underflow với Solidity 0.8:

  feeGrowthInside = feeGrowthGlobal - feeGrowthBelow - feeGrowthAbove;
  (subtraction có thể underflow → revert, cần unchecked{})

  CODE_ANCHOR: feeGrowthInside = feeGrowthGlobal - feeGrowthBelow - feeGrowthAbove;

H-17: nearestTick feeGrowthOutside khởi tạo sai:

  ticks[nearestTick].feeGrowthOutside0 = feeGrowthGlobal0;
  (invariant: feeGrowthOutside của nearestTick phải = 0 khi pool mới init)

  CODE_ANCHOR: ticks[nearestTick].feeGrowthOutside0 = feeGrowthGlobal0;
```

**Edge cases:**

```
Invariant violation cần trace qua nhiều bước để thấy:
→ Lấy dòng CUỐI CÙNG trong chain tính toán — dòng produce giá trị sai cuối cùng.

  step1 = a - b;
  step2 = step1 * c;
  result = step2 / d;  ← lấy dòng này nếu result là giá trị vi phạm invariant

Invariant violation là một comparison (không phải assignment):
  require(reserve0 >= amount0);  ← dòng này fail
  CODE_ANCHOR: require(reserve0 >= amount0);
```

---

#### DESIGN — function signature của entry point bị exploit

**Quy tắc:** Dòng khai báo của function mà attacker gọi ĐẦU TIÊN để bắt đầu
attack sequence. Đây là nơi fix sẽ thêm modifier, timelock, hoặc anti-bot guard.

```
Cách xác định: Vẽ attack sequence step-by-step → function đầu tiên
trong sequence mà nếu có guard sẽ chặn được toàn bộ attack →
đó là entry point → lấy dòng khai báo của function đó.
```

**Ví dụ đúng:**
```
H-16: JIT liquidity attack:
  Attack: mint() → claimReward() → burn() trong 1 tx
  Guard hợp lý nhất: thêm minimum hold time vào claimReward()
  (mint không có guard ý nghĩa, burn sau claimReward là quá muộn)

  CODE_ANCHOR: function claimReward(uint256 positionId, address recipient, bool unwrapBento) external {

Flash loan attack qua swap():
  Attack: borrow flashloan → swap() manipulate price → exploit → repay
  Entry point: swap() — nơi có thể thêm price impact limit

  CODE_ANCHOR: function swap(address recipient, bool zeroForOne, ...) external {
```

**Edge cases:**

```
Attack cần 2 transactions riêng biệt:
  Tx1: stake()  → Tx2: claim()
  → Entry point là function của Tx1 vì đó là điểm attacker setup attack:
  CODE_ANCHOR: function stake(uint256 amount) external {

Attack có thể bắt đầu từ nhiều entry points:
  → Chọn entry point mà guard đơn giản nhất sẽ chặn được toàn bộ attack.
  → Không có câu trả lời duy nhất, merger Tầng 2 LLM xử lý trường hợp này.

Bug là vòng lặp không giới hạn (unbounded while) trong swap():
  ✗ CODE_ANCHOR: while (cache.input != 0) {   ← WRONG: không phải function declaration
                                                + không unique trong function
  ✓ CODE_ANCHOR: function swap(address recipient, bool zeroForOne, ...) external {
  Lý do: nhiều bugs khác nhau đều có thể "về" while loop này →
  dùng function declaration để Tầng 1 merge đúng, Tầng 2 tách bugs khác nhau.
```

---

#### Tại sao "git diff line" converge tốt hơn bất kỳ NL field nào

```
H-10 (burn wrong reserve) — 4 agents, 4 approaches:

Agent 1 (CODE):    "dòng nào sai?"              → reserve0 -= uint128(amount0fees)  ✓
Agent 2 (MISSING): "insert sau dòng nào?"        → reserve0 -= uint128(amount0fees)  ✓
Agent 3 (SEQ):     "dòng nào đọc state sai?"     → reserve0 -= uint128(amount0fees)  ✓
Agent 4 (INV):     "computation nào vi phạm?"    → reserve0 -= uint128(amount0fees)  ✓
```

Tất cả hội tụ vì đây là câu trả lời duy nhất cho câu hỏi
"code nào cần thay đổi để fix bug này".

#### Convergence thực tế theo type

| Evidence Type | Tỉ lệ findings | Convergence | Nguyên nhân diverge |
|---------------|---------------|-------------|---------------------|
| `CODE:` | ~55% | ~85-90% | Dòng sai rõ ràng, 1 candidate |
| `INV:` | ~10% | ~80% | 1 computation line, deterministic |
| `SEQ:` | ~10% | ~65% | Cross-contract SEQ khó xác định dòng B |
| `MISSING:` | ~20% | ~40% | "Insert sau dòng nào" không luôn rõ |
| `DESIGN:` | ~5% | ~30% | Nhiều entry point hợp lệ |

**~65-75% findings (CODE + INV) auto-dedup bằng exact anchor match — không cần LLM (Bước 1).**
**~35% còn lại (SEQ/MISSING/DESIGN) fallback Bước 2 LLM với set nhỏ hơn nhiều.**

### 2.3 Convergence theo bug type

```
CODE + INV ≈ 65% findings:
  Có 1 dòng code nổi bật nhất → convergence cao (~85-90%)
  → auto-dedup không cần LLM ✓

SEQ ≈ 10% findings:
  2 dòng liên quan, agents chỉ vào dòng cho kết quả sai → convergence trung bình (~65%)
  → một phần auto-dedup

MISSING ≈ 20% findings:
  Không có dòng sai → agents chỉ vào dòng "dùng value chưa validate" → convergence thấp (~40%)
  → cần LLM fallback trong merger

DESIGN ≈ 5% findings:
  Attack path trải dài nhiều functions → convergence thấp (~30%)
  → cần LLM fallback trong merger
```

**Kết quả:** ~65-75% trường hợp dedup có thể xử lý bằng exact CODE_ANCHOR match,
không cần LLM. Chỉ ~25-35% còn lại cần merger LLM.

---

## 3. Architecture Tổng Quan

```
┌─────────────────────────────────────────────────────────────┐
│  ROUND 1 (parallel)                                          │
│                                                              │
│  Expert Agent 1 ──┐                                         │
│  Expert Agent 2 ──┤  finding = {evidence, CODE_ANCHOR, ...} │
│  Expert Agent 3 ──┼──► raw_pool (98 findings)               │
│        ...        │                                         │
│  Expert Agent N ──┘                                         │
└─────────────────────────────────────────────────────────────┘
                          │
               (tất cả agents hoàn tất)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  DEDUP — Sequential (chạy sau khi R1 xong, ~1-2 phút)        │
│                                                              │
│  Bước 1 — Static dedup (no LLM)                             │
│    group by (contract, function, normalize(code_anchor))     │
│    → merge groups cùng anchor, tích lũy evidence            │
│    → ~46 canonical findings (từ 98)                         │
│                                                              │
│  Bước 2 — LLM dedup (chỉ cần ~11 calls cho contest 35)      │
│    với mỗi function có ≥2 distinct anchor groups:           │
│    → LLM agent: "findings nào cùng 1 bug?"                  │
│    → merge confirmed same-bug pairs                         │
│    → ~43-44 canonical findings                              │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
                    pre-R2 FP check
                    (Layer 1A — CODE_ANCHOR in source)
                          │
                          ▼
                      ROUND 2 INPUT
                 (canonical findings, evidence tích lũy)
```

**Thiết kế sequential vs parallel (cũ):**

| | Sequential (mới) | Parallel blackbox (cũ) |
|---|---|---|
| Complexity | Thấp — chạy sau R1, debug dễ | Cao — queue + thread sync |
| Wall time overhead | ~1.5 phút sau R1 | ~0 (chạy song song) |
| Tổng pipeline time | ~26.5 phút | ~25 phút |
| Tradeoff | Đơn giản hơn 1.5 phút | Phức tạp hơn không đáng |

Chênh lệch wall time chỉ ~1.5 phút trên tổng 25 phút → sequential là lựa chọn hợp lý.

---

## 4. Dedup Logic: 2 Bước Tuần Tự

### Bước 1 — Static dedup: group by (contract, function, code_anchor)

```python
from collections import defaultdict

def normalize_anchor(code: str) -> str:
    code = re.sub(r'//.*', '', code)
    code = re.sub(r'\s+', ' ', code).strip()
    return code.rstrip(';').lower()

def static_dedup(raw_findings: list) -> list:
    """
    Group findings by (contract, function, normalized anchor).
    Same anchor → same bug → merge. No LLM needed.
    """
    groups: dict = defaultdict(list)
    no_anchor: list = []

    for f in raw_findings:
        anchor = normalize_anchor(f.get("code_anchor", ""))
        if anchor:
            key = (f["contract_name"], f["function_name"], anchor)
            groups[key].append(f)
        else:
            no_anchor.append(f)  # no anchor → keep as-is, goes to Bước 2

    canonical = []
    for (contract, fn, anchor), group in groups.items():
        if len(group) == 1:
            canonical.append(group[0])
        else:
            canonical.append(merge_group(group))  # same bug, merge evidence
    canonical.extend(no_anchor)
    return canonical
```

Sau Bước 1 với contest 35: **98 → ~46 findings** (21 anchor groups bị merge).

Bước 2 xử lý các function có ≥2 distinct anchor groups — đây là cases Bước 1 không tự giải quyết được (anchor diverge do MISSING/DESIGN types).

```python
def llm_dedup(canonical: list, source_code: str) -> list:
    """
    Group canonical findings by (contract, function).
    If a function has ≥2 distinct anchor groups → ask LLM to check for same-bug pairs.
    """
    func_groups: dict = defaultdict(list)
    for f in canonical:
        key = (f["contract_name"], f["function_name"])
        func_groups[key].append(f)

    result = []
    for (contract, fn), group in func_groups.items():
        if len(group) <= 1:
            result.extend(group)
        else:
            fn_body = extract_function_body(source_code, contract, fn)
            merged = llm_merge_group(contract, fn, group, fn_body)
            result.extend(merged)
    return result
```

**Lưu ý quan trọng về vai trò của LLM trong Bước 2:**

```
CODE tự group findings theo (contract_name, function_name) — static, không cần LLM.
LLM chỉ nhận danh sách pre-assembled cho từng function cụ thể
và output MERGE/KEEP_SEPARATE — LLM không tự tìm kiếm hay filter.

Luồng chính xác:
  1. Code group tất cả canonical findings theo (contract_name, function_name)
  2. Với mỗi function có len(group) >= 2 → code build prompt + gọi LLM 1 lần
  3. LLM trả về MERGE/KEEP_SEPARATE cho từng cặp trong group đó
  4. Code apply merge decisions (union-find)
```

**LLM prompt cho mỗi function group:**

```
You are a deduplication agent for smart contract audit findings.

CONTRACT: {contract}  FUNCTION: {function}

FUNCTION SOURCE:
{fn_body}

FINDINGS (same function, different code anchors):
  [1] anchor: {f1.code_anchor}
      evidence: {f1.primary_evidence}
      title: {f1.title}

  [2] anchor: {f2.code_anchor}
      evidence: {f2.primary_evidence}
      title: {f2.title}
  ...

TASK: Identify pairs that describe the SAME underlying vulnerability.

Rules:
  - Only merge when CERTAIN they share the same root cause
  - Different anchors usually mean different bugs — when in doubt → KEEP_SEPARATE
  - KEEP_SEPARATE is safer (duplicate is better than missing a TP)

Output one decision per line:
  MERGE: [i] == [j]  | REASON: <one sentence why same root cause>
  KEEP_SEPARATE: [i] | REASON: <one sentence why distinct>
```

**Ví dụ output cho `sweepBentoBoxToken` (1 bug, 2 anchors do type diverge):**
```
MERGE: [1] == [2] | REASON: both describe missing access control on the same function;
                             anchor difference reflects DESIGN vs MISSING approach, not different bugs
```

**Ví dụ output cho `swap()` (nhiều bugs thật sự khác nhau):**
```
KEEP_SEPARATE: [1] | REASON: unbounded tick crossing — gas exhaustion DoS
KEEP_SEPARATE: [2] | REASON: circular linked list at MIN_TICK — infinite loop
KEEP_SEPARATE: [3] | REASON: intermediate overflow in price calculation
```

**Số LLM calls thực tế (contest 35):** ~11 calls cho 11 functions có ≥2 distinct anchor groups.

### Evidence merge khi cùng bug

```python
def merge_into(canonical, new_finding):
    # Tích lũy evidence — không drop bất kỳ evidence nào
    canonical["supporting_evidence"].append({
        "type":        get_evidence_type(new_finding["evidence"]),
        "text":        new_finding["evidence"],
        "code_anchor": new_finding.get("code_anchor", ""),
        "agent_id":    new_finding["agent_id"],
    })
    canonical["submitter_count"] += 1

    # Upgrade primary evidence theo priority: CODE > MISSING > SEQ > INV > DESIGN
    if evidence_priority(new_finding) < evidence_priority(canonical):
        canonical["primary_evidence"] = new_finding["evidence"]
        canonical["code_anchor"]      = new_finding["code_anchor"]
```

---

## 5. Canonical Finding Structure

```json
{
  "canonical_id": "clp-burn-001",
  "contract_name": "ConcentratedLiquidityPool",
  "function_name": "burn",
  "title": "Incorrect reserve update in burn()",
  "description": "reserve0 only subtracts fees but transfers full amount0",
  "code_anchor": "reserve0 -= uint128(amount0fees)",
  "primary_evidence": "CODE: reserve0 -= uint128(amount0fees)",
  "supporting_evidence": [
    {
      "type": "MISSING",
      "text": "MISSING: reserve0 -= uint128(amount0) AT: burn()",
      "code_anchor": "reserve0 -= uint128(amount0fees)",
      "agent_id": "agent_07"
    },
    {
      "type": "SEQ",
      "text": "SEQ: burn() sends amount0 → reserve only subtracts fees",
      "code_anchor": "reserve0 -= uint128(amount0fees)",
      "agent_id": "agent_13"
    },
    {
      "type": "INV",
      "text": "INV: after burn(), reserve0 == balance | VIOLATED_AT: burn()",
      "code_anchor": "reserve0 -= uint128(amount0fees)",
      "agent_id": "agent_19"
    }
  ],
  "submitter_count": 4,
  "severity": "high"
}
```

`submitter_count` là signal tin cậy cho R2: nhiều agents độc lập tìm ra → bug real.

---

## 6. R1 Prompt Changes

```
OUTPUT FORMAT — mỗi finding phải có đầy đủ 5 fields:

TITLE:       <tên bug ngắn gọn>
CONTRACT:    <ContractName>
FUNCTION:    <functionName>
SEVERITY:    critical | high | medium | low

CODE_ANCHOR: <dòng code nguyên văn từ source — xem rule bên dưới>

EVIDENCE:    <chọn 1 trong 5 formats>
  CODE:    <exact snippet, max 120 chars>
  MISSING: <what should exist> AT: <Contract.function()>
  SEQ:     <fn_a> → <fn_b> | ISSUE: <why wrong>
  INV:     <invariant> | VIOLATED_AT: <fn> | COUNTEREXAMPLE: <condition>
  DESIGN:  <mechanism> | EXPLOIT: <scenario> | NO_MITIGATION: <missing>

━━━ RULE CHO CODE_ANCHOR ━━━

CODE_ANCHOR = dòng code sẽ xuất hiện trong git diff khi fix bug.
Copy NGUYÊN VĂN từ source. Không tự viết, không paraphrase, không để N/A.

  Nếu EVIDENCE là CODE:
    → dòng code sai, sẽ được sửa khi fix
    → ví dụ: reserve0 -= uint128(amount0fees);

  Nếu EVIDENCE là MISSING:
    → dòng cuối cùng TRƯỚC vị trí cần insert code mới
    → (sau dòng này, fix sẽ thêm check/update)
    → ví dụ: (uint160 initialPrice, ...) = abi.decode(data, ...);

  Nếu EVIDENCE là SEQ:
    → dòng thực thi sai thứ tự, sẽ bị di chuyển khi fix
    → ví dụ: secondsPerLiquidity += diff / liquidity;

  Nếu EVIDENCE là INV:
    → dòng computation vi phạm invariant, sẽ được wrap/sửa khi fix
    → ví dụ: feeGrowthInside = feeGrowthGlobal - feeGrowthBelow - feeGrowthAbove;

  Nếu EVIDENCE là DESIGN:
    → function signature của entry point bị exploit (dòng khai báo function)
    → ví dụ: function claimReward(uint256 positionId, address recipient, ...) external {

Lưu ý: CODE_ANCHOR để định danh/dedup bug, EVIDENCE để mô tả và chứng minh bug.
Hai field phục vụ mục đích khác nhau — cả hai đều bắt buộc.
```

---

## 7. Sequential Processing — Entry Point

```python
def run_dedup(raw_findings: list, source_code: str) -> list:
    """
    Full dedup pipeline: static → LLM.
    Called once after all R1 agents complete.
    """
    # Bước 1: static dedup bằng anchor exact match (~0.1s, no LLM)
    after_static = static_dedup(raw_findings)
    logger.info(f"[dedup] Bước 1 static: {len(raw_findings)} → {len(after_static)}")

    # Bước 2: LLM dedup cho functions có ≥2 anchor groups (~88s, ~11 calls)
    after_llm = llm_dedup(after_static, source_code)
    logger.info(f"[dedup] Bước 2 LLM: {len(after_static)} → {len(after_llm)}")

    return after_llm
```

Hàm này được gọi trong orchestrator sau khi `_run_discovery_round()` hoàn tất,
thay thế `_dedup_pre_r2()` Layer 1B (đã xoá).

---

## 8. Chi Phí

### Token cost

```
Contest 35: 98 R1 findings

Bước 1 — Static (không LLM):
  21 anchor groups bị merge → 73 findings → 25 canonical
  25 findings unique anchor → giữ nguyên
  Tổng: 98 → ~46 findings, 0 LLM calls

Bước 2 — LLM per function:
  11 functions có ≥2 distinct anchor groups
  Mỗi call: ~1,500 tokens (function body ~60 lines + findings list + prompt)
  11 × 1,500 = ~16,500 tokens

So sánh:
  Merger (parallel blackbox, cũ):  ~6,000 tokens (1 call/finding có conflict)
  Merger (sequential, mới):        ~16,500 tokens (1 call/function)
  R1 cost:                         ~110,000 tokens
  R2 cost:                         ~4,620,000 tokens
  Merger overhead:                  < 0.4% của R2

Lý do token tăng nhẹ so với blackbox: mỗi LLM call trong sequential nhận
toàn bộ function body + tất cả findings của function → context đầy đủ hơn
→ merge decision chính xác hơn. Tradeoff chấp nhận được.
```

### Wall time

```
R1 agents (22 parallel):         20-30 phút
Dedup sequential (chạy sau R1):
  - Bước 1 (no LLM):  ~0.1s cho 98 findings
  - Bước 2 (LLM):     ~11 calls × 8s = ~88s ≈ 1.5 phút

Tổng dedup time: ~1.5 phút
Tổng pipeline: ~26.5 phút (vs ~25 phút với parallel blackbox)
Chênh lệch: 1.5 phút — không đáng kể
```

---

## 9. Rủi Ro & Mitigation

### 9.1 CODE_ANCHOR không converge (MISSING/DESIGN types)

**Vấn đề:** Agents dùng MISSING hoặc DESIGN trỏ vào dòng khác nhau → Bước 1 không merge → Bước 2 LLM xử lý.

**Mitigation:** Bước 2 LLM là safety net. Với MISSING/DESIGN (~25% findings), chi phí LLM rất nhỏ vì đã được pre-filter bởi (contract, function).

### 9.2 CODE_ANCHOR bị thiếu hoặc không phải code thực

**Vấn đề:** Agent viết `CODE_ANCHOR: N/A` hoặc prose thay vì code.

**Mitigation:** Parser validate CODE_ANCHOR:
```python
def validate_code_anchor(anchor: str) -> bool:
    # Phải chứa ít nhất 1 Solidity identifier hoặc operator
    has_identifier = bool(re.search(r'[a-zA-Z_]\w{2,}', anchor))
    is_prose = anchor.lower().startswith(("the ", "this ", "n/a", "none"))
    return has_identifier and not is_prose
```
Nếu invalid → fallback về Bước 2 LLM.

### 9.3 False merge qua CODE_ANCHOR

**Vấn đề:** 2 bugs khác nhau cùng trỏ vào cùng 1 dòng code.

**Khả năng xảy ra:** Thấp. Nếu 2 bugs có cùng (contract, function, code_anchor), chúng có cùng root cause với xác suất rất cao. Trường hợp edge: 1 dòng code tham gia vào 2 bugs khác nhau.

**Mitigation:** Nếu phát hiện qua R2/R3 → reopen finding. Không có cơ chế tự động.

### 9.4 LLM false merge trong Bước 2

**Vấn đề:** LLM merge nhầm 2 bugs khác nhau khi cùng function.

**Mitigation:** Prompt nhấn mạnh "KEEP_SEPARATE là lựa chọn an toàn hơn — duplicate tốt hơn mất TP". LLM chỉ merge khi CHẮC CHẮN.

---

## 10. Tích Hợp Vào Pipeline

```
Hiện tại:
  R1 agents (parallel) → raw_pool → _dedup_pre_r2() [Layer 1A FP] → R2

Sau khi có sequential dedup:
  R1 agents (parallel) → raw_pool (98 findings)
                              │
                        run_dedup()
                          Bước 1: static_dedup()   → anchor exact match
                          Bước 2: llm_dedup()       → per-function LLM
                              │
                        ~43-44 canonical findings
                        (evidence tích lũy, submitter_count)
                              │
                        _dedup_pre_r2()             → Layer 1A FP check
                        (CODE_ANCHOR in source)
                              │
                           R2 voting
                        (nhận submitter_count signal)
```

**Thay đổi code cần implement:**

- `contract_oasis_env.py`: ✅ đã thêm parse `CODE_ANCHOR` field, validate
- `cyber_session_orchestrator.py`: ✅ đã xoá Layer 1B, Layer 2 (embedding), `_embed_model`
- `cyber_session_orchestrator.py`: **TODO** — thêm `run_dedup()` với `static_dedup()` + `llm_dedup()`
- `cyber_session_orchestrator.py`: **TODO** — gọi `run_dedup()` trong pipeline sau `_run_discovery_round()`

---

## 11. Hiệu Quả Dự Kiến

### Contest 35 (data thực tế từ R1 run với CODE_ANCHOR)

```
R1 raw findings: 98
Sau Bước 1 (static dedup): ~46 (21 anchor groups, 73 findings merged)
Sau Bước 2 (LLM dedup):    ~43-44

Top anchor groups bị merge:
  - claimReward/bit-shift (13 findings → 1 canonical, 12 supporting)
  - subscribe/wrong-index (11 findings → 1 canonical, 10 supporting)
  - claimReward/wrong-index (4 findings → 1 canonical)
  - migrate/encoding (5 findings → 1 canonical)
  - rangeFeeGrowth/underflow (4 findings → 1 canonical)
  ...

R2 input (sau dedup): ~43-44 canonical findings vs 98 raw
Slots tiết kiệm: ~54 — không còn bị lãng phí vào same-bug duplicates
```

### Tác dụng phụ tích cực

**`submitter_count` làm R2 signal tin cậy hơn:**
Finding được 4 agents độc lập report (với 4 evidence types khác nhau) →
`submitter_count=4` → R2 agents confident hơn → ACCEPT rate cao hơn cho TP.

**Evidence đa dạng cho R3:**
Canonical finding có CODE snippet (verify) + MISSING (biết fix gì) + INV counterexample (construct PoC).
R3 attacker nhiều context hơn → verdict chính xác hơn.

**CODE_ANCHOR là FP check tốt hơn:**
Pre-R2 FP check hiện tại verify `CODE:` snippet trong source. Với CODE_ANCHOR,
tất cả evidence types (kể cả MISSING/SEQ/INV) đều có code line để verify tồn tại trong source.

---

## 12. So Sánh Các Approach

| Approach | Cross-type dedup? | LLM calls | Complexity | Thay đổi architecture |
|----------|------------------|-----------|-----------|----------------------|
| Embedding (0.92) | Không | 0 | Thấp | Nhỏ |
| BUG_ID slug | Không (diverge) | 0 | Trung bình | Trung bình |
| Parallel blackbox (cũ) | Có | ~5/150 findings | Cao (queue+thread) | Lớn |
| **Sequential dedup (mới)** | **Có** | **~11 calls/run** | **Thấp** | **Trung bình** |

Sequential dedup đơn giản hơn parallel blackbox với chi phí wall time +1.5 phút — không đáng kể.
LLM calls tăng nhẹ (~11 vs ~5) nhưng mỗi call có đầy đủ function context → merge decision tốt hơn.
