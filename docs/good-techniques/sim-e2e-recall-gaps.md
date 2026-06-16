# sim_e2e Recall Gaps — Structural Limitations & Generic Fixes

Phân tích dựa trên benchmark 4 contests (5, 35, 42, 104) với fixes E+F+G+H.
Tập trung vào 2 loại FN: lỗi structural của framework và bugs có thể fix bằng generic improvement.

---

## Phần 1 — Structural Difficulties

### Định nghĩa

"Structural difficulty" là khi bug **không thể được detect** bởi bất kỳ agent nào trong framework hiện tại
vì **chunk context thiếu thông tin cần thiết một cách hệ thống** — không phải do agent thiếu knowledge,
mà do pipeline không tạo ra context đủ để reasoning.

Khác với "knowledge gap" (agent có context nhưng không nhận ra pattern):
- Knowledge gap → fix bằng prompt/agent improvement
- Structural difficulty → fix bằng thay đổi chunking hoặc context injection

---

### Case Study: H-03 (Contest 5 — Vader Protocol)

**Bug:** "Missing DAO functionality to call `changeDAO()` function in Vader"

**Root cause:**
```
Vader.changeDAO() có modifier: require(msg.sender == DAO)
→ chỉ DAO contract mới được gọi changeDAO
→ nhưng DAO contract KHÔNG CÓ function nào gọi Vader.changeDAO
→ deadlock: changeDAO không bao giờ có thể được gọi
```

**Tại sao framework miss:**

Chunk structure cho contest 5:
```
[admin_gov] Vader: ['changeDAO', 'changeUTILS', 'upgrade']   ← Vader source
[admin_gov] DAO:   ['newGrantProposal', 'voteProposal', ...]  ← DAO source (chunk riêng)
```

Agent trong `admin_gov/Vader` chunk chỉ thấy Vader source. Agent thấy:
```solidity
function changeDAO(address newDAO) external {
    require(msg.sender == DAO);   // ← chỉ thấy restriction, không thấy caller side
    DAO = newDAO;
}
```

Agent có thể flag "chỉ DAO có thể gọi" — nhưng không thể kết luận "DAO không có mechanism để gọi"
vì DAO source không có trong chunk này.

**Lý do aux injection không giải quyết được:**

Aux detection hiện tại hoạt động theo hướng: "contract A dùng contract B → inject B làm aux của A".
```python
# aux_map[Vader] = []  (Vader không import DAO)
# aux_map[DAO]   = [Pools, Router, ...]  (DAO gọi nhiều contracts khác)
```

Để detect H-03, cần hướng ngược lại: "function X restrict caller = DAO → kiểm tra DAO có hàm gọi X không".
Đây là **reverse call graph analysis** — nằm ngoài capability của per-chunk aux injection.

**Điều kiện để detect:**

1. Phải có cả Vader + DAO source trong cùng 1 chunk
2. Agent phải reason: "Caller restriction = DAO → does DAO have outgoing call to this function?"
3. Scan DAO source để confirm absence of call

**Hướng fix tiềm năng (cost cao):**

Option A — Inject DAO source làm aux của Vader `admin_gov` chunk:
```python
# Trong aux detection: nếu function có onlyDAO/require(msg.sender == DAO)
# → inject DAO contract làm aux (reverse direction)
```
Risk: tạo circular dependency (DAO inject Vader, Vader inject DAO).

Option B — Thêm cross-contract deadlock check pass riêng:
- Sau khi collect tất cả findings, chạy 1 agent đặc biệt với full system source
- Agent check: "Với mỗi function có access restriction X, contract X có function call ngược lại không?"
Nhược điểm: expensive, không scale well.

**Verdict:** Structural limitation. Không nên fix trong framework hiện tại.
Tần suất pattern "governance deadlock" thấp — trade-off không justify complexity.

---

### Pattern tổng quát: Cross-Contract Absence Analysis

H-03 đại diện cho class rộng hơn: bugs xuất hiện do **sự VẮNG MẶT** của một function trong contract khác.
Không phải "contract A làm gì sai" mà là "contract A thiếu gì".

Các ví dụ tương tự có thể gặp:
- Upgradeability deadlock: implementation có `onlyProxy` nhưng proxy không expose upgrade path
- Role assignment gap: contract require `MINTER_ROLE` nhưng không có function grant role đó
- Withdrawal deadlock: vault nhận deposit nhưng không có withdrawal function

Framework per-chunk không handle được class này vì thiếu "negative space" analysis.

---

## Phần 2 — Generic Fixes có thể Implement

### Fix G1 — Input Token Whitelist Validation

**Bugs cover:** H-11, H-13 (Contest 5) + pattern phổ biến trong DeFi

**Pattern:**

```solidity
// Vulnerable: function nhận token address làm parameter nhưng không validate
function swap(address base, address token, ...) external {
    // assumes base == VADER || base == USDV
    // nhưng KHÔNG CHECK → attacker dùng fake base token
    _processSwap(base, token, ...);
}

function mintSynth(address base, address token, ...) external {
    // cùng pattern: base không được validate
    _processMint(base, token, ...);
}
```

**Tại sao agents miss:**

T1/T2 agents khi thấy `swap()` thường focus vào:
- Slippage protection (MEV/sandwich)
- Reentrancy
- Price oracle manipulation

Không ai check "is this token parameter validated against an approved list?".
Đây là input validation pattern đặc thù cho DeFi protocols dùng dual-token base (e.g., VADER + USDV).

**Generic signal cho agents (prompt addition):**

```
INPUT TOKEN VALIDATION:
When a function accepts an address parameter used as "base token" or "payment token",
check:
1. Is there a require/if statement validating it equals one of the protocol's
   known base tokens (e.g., isBase(token), token == VADER || token == USDV)?
2. If no validation exists → any token can be used as fake base,
   breaking accounting assumptions downstream.
Pattern: missing isBase() check → fake base token exploit
```

**Implementation:**

Thêm vào `contract_oasis_env.py` T1 invariant prompt (hoặc T3 CoT sweep):
- Section: "Input Parameter Validation Checklist"
- Trigger: function có parameter tên `base`, `token`, `asset`, `collateral`, `underlying`
- Check: có whitelist/isBase validation không?

**Tần suất:** Cao — pattern xuất hiện trong bất kỳ protocol nào có dual-token hoặc multi-asset.

**Expected recall gain:** H-11 + H-13 = +2 TP cho contest 5. Likely 1-2 TP ở contests khác.

---

### Fix G2 — Uninitialized Time Variable = 0 Bypass

**Bugs cover:** H-02 (Contest 5)

**Pattern:**

```solidity
// State variable declared but never initialized
uint256 public blockDelay;   // defaults to 0

modifier flashProof(address account) {
    // isMature check: block.number > lastBlock[account] + blockDelay
    require(isMature(account));
    _;
}

function isMature(address account) public view returns (bool) {
    return block.number >= lastBlock[account] + blockDelay;
    // Nếu blockDelay == 0 → LUÔN TRUE → flash protection vô hiệu
}
```

**Tại sao agents miss:**

Agents thấy `flashProof` modifier và `isMature` → assume protection works.
Không ai trace back để check "blockDelay có được set trong constructor/init không?".

Pattern: `uint256 public X` không có giá trị khởi tạo → X = 0 → bất kỳ check nào dùng X như threshold/delay đều bị bypass.

**Generic signal cho agents:**

```
UNINITIALIZED PROTECTION VARIABLE:
When you see a time-based or block-based protection mechanism
(modifier using blockDelay, timelock, cooldown, minDelay, etc.),
check:
1. Is the protection variable initialized in constructor or init()?
2. If not initialized → defaults to 0 → protection is bypassed
3. Especially dangerous for: flash loan guards, cooldown periods,
   vesting durations, rate limits
Pattern: uint256 delay (uninitialized) + require(block >= lastBlock + delay) → always passes
```

**Tần suất:** Medium — pattern xuất hiện trong bất kỳ protocol có time-based protection.
Flash loan guards, vesting contracts, rate limiters đều vulnerable.

**Expected recall gain:** +1 TP contest 5 (H-02). Likely xuất hiện trong contests khác.

---

### Fix G3 — Wrong Constant Value (Initialization)

**Bugs cover:** H-09, H-25 (Contest 5)

**Pattern:**

```solidity
// H-09: Router.init()
secondsPerYear = 1;         // should be 365 days = 31536000
// → IL protection of only 1 second, not 1 year

// H-25: Vader.init()
secondsPerEra = 1;          // should be ~86400 (1 day in seconds)
// → emission rate 86400x too fast → hyper-inflation
```

**Tại sao agents miss:**

Agents không biết "expected" value là bao nhiêu. Không có ground truth để compare.
T2 (HIST-INV) candidates đều nhảy sang access control thay vì check constant values.

**Khả năng generic fix: Thấp**

Để detect, agent cần biết:
- Đơn vị của biến là gì (seconds? blocks? wei?)
- Expected value từ spec/documentation
- Magic number `1` trong context time = "có thể là off-by-unit-error"

Một generic heuristic có thể work:
```
INITIALIZATION CONSTANT CHECK:
When an init() or constructor() sets a time/duration variable to a small integer
(1, 2, 3... vs. expected thousands/millions for seconds/blocks),
flag as potential unit error.
Keywords: secondsPerX, blocksPerX, duration, delay, period, era
Heuristic: if variable name contains "seconds/blocks/period" AND value <= 100 → suspicious
```

Nhưng false positive rate cao — nhiều contracts dùng small values hợp lệ cho testing.
**Verdict:** Implement heuristic là possible nhưng noisy. Tần suất thấp hơn G1/G2.

---

### Fix G4 — Cross-Contract Deadlock (Partial)

**Bugs cover:** H-03 (Contest 5)

**Như đã phân tích ở Phần 1** — structural limitation. Partial fix:

Nếu muốn cover một phần, thêm vào aux injection rule:
```python
# Nếu contract A có function với modifier require(msg.sender == X)
# và X là GT contract → inject X source làm aux của A
```

Cost: phức tạp hóa aux detection. Chỉ cover subset của cross-contract deadlock.

---

## Summary — Priority Matrix

| Fix | Bugs | Pattern | Generic? | Effort | Expected gain |
|-----|------|---------|---------|--------|--------------|
| **G1** | H-11, H-13 | Input token whitelist | ✅ High | Low — prompt addition | +2 TP/contest (DeFi) |
| **G2** | H-02 | Uninitialized time var = 0 | ✅ High | Low — prompt addition | +1 TP/contest |
| **G3** | H-09, H-25 | Wrong constant value | ⚠️ Low | Medium — heuristic noisy | +1-2 TP if lucky |
| **G4** | H-03 | Cross-contract deadlock | ❌ | High — structural change | +1 TP rare |

**Recommended order:**
1. G1 (input token whitelist) — highest ROI, common DeFi pattern
2. G2 (uninitialized time var) — clean pattern, low FP risk
3. G3 — optional, only if noisy FP acceptable
4. G4 — deprioritize

---

## Implementation Location

Tất cả G1 + G2 implement trong **`contract_oasis_env.py`**:
- Target: T3 CoT sweep prompt (Section "Additional Vulnerability Patterns")
- Hoặc: T1 invariant generation prompt (thêm checklist items)
- Không cần thêm agent mới hay thay đổi DOMAIN_AGENTS

G3 implement trong T3 sweep với keyword-based trigger.
G4 implement trong `simulate_e2e.py` aux detection logic.
