# Plan: SWC List Update — Coverage từ 17/37 lên 28/37

## Tình trạng hiện tại

### SWCs đang được cover (17)

| Domain | SWCs |
|--------|------|
| appsec | SWC-101, 104, 105, 107, 113, 115, 128 |
| blockchain | SWC-107, 109, 112, 116, 120, 132 |
| cryptography | SWC-116, 120, 121, 122, 133 |
| defi | SWC-114 |
| defi_math | SWC-101, 132 |
| token_standard | SWC-104, 107 |
| governance | SWC-105, 106, 112, 115 |

**Unique covered**: 101, 104, 105, 106, 107, 109, 112, 113, 114, 115, 116, 120, 121, 122, 128, 132, 133 = **17 SWCs**

### SWCs hoàn toàn bị bỏ qua (20)

100, 102, 103, 108, 110, 111, 117, 118, 119, 123, 124, 125, 126, 127, 129, 130, 131, 134, 135, 136

---

## Phân loại mức độ ưu tiên

### Tier A — High priority (exploit potential cao, thường xuất hiện trong audits)

| SWC | Tên | Mô tả ngắn | Domain đề xuất |
|-----|-----|-----------|----------------|
| SWC-100 | Function Default Visibility | Function không khai báo visibility → public by default (Solidity <0.5) | `appsec` |
| SWC-108 | State Variable Default Visibility | Storage var không khai báo visibility → internal by default, thường bị đọc sai | `appsec` |
| SWC-110 | Assert Violation | Dùng `assert()` sai mục đích (invariant check thay vì input validation) | `appsec` |
| SWC-117 | Signature Malleability | ECDSA cho phép 2 chữ ký hợp lệ cho cùng message (flip `s` value) | `cryptography` |
| SWC-119 | Shadowing State Variables | Child contract khai báo biến trùng tên với parent → shadow storage slot | `blockchain` |
| SWC-123 | Requirement Violation | `require()` dùng để check invariant thay vì input — thực ra là logic error | `appsec` |
| SWC-124 | Write to Arbitrary Storage Location | Assembly/delegatecall ghi vào slot tùy ý không validate | `blockchain` |
| SWC-125 | Incorrect Inheritance Order | C3 linearization sai → wrong function resolution trong diamond inheritance | `blockchain` |
| SWC-126 | Insufficient Gas Griefing | Forward gas không đủ cho sub-call → sub-call fail nhưng caller không biết | `appsec` |
| SWC-134 | Hardcoded Gas Amount | `call{gas: 2300}` cứng → fail khi recipient là contract cần >2300 gas | `blockchain` |

### Tier B — Medium priority (informational + đôi khi exploitable)

| SWC | Tên | Mô tả ngắn | Domain đề xuất |
|-----|-----|-----------|----------------|
| SWC-102 | Outdated Compiler Version | Dùng compiler cũ có known bugs | `blockchain` |
| SWC-103 | Floating Pragma | `^0.8.x` thay vì pin version → build với compiler khác nhau | `blockchain` |
| SWC-111 | Deprecated Solidity Functions | `suicide`, `throw`, `sha3`, `callcode` → bị remove hoặc có side-effects | `blockchain` |
| SWC-118 | Incorrect Constructor Name | Pre-Solidity 0.5: function có tên = contract name, typo → public function thay vì constructor | `blockchain` |
| SWC-136 | Unencrypted Private Data | `private` var vẫn đọc được từ blockchain state — misleading cho dev | `appsec` |

### Tier C — Low priority (bỏ qua hoặc code quality only)

| SWC | Lý do bỏ qua |
|-----|-------------|
| SWC-127 | Arbitrary Jump với function type variable — cực kỳ hiếm trong Solidity hiện đại |
| SWC-129 | Typographical Error (`=` thay vì `==`) — quá hiếm, static analysis đã bắt |
| SWC-130 | RTLO control character — trojan ở source code level, không phải runtime bug |
| SWC-131 | Unused Variables — code quality only, không ảnh hưởng security |
| SWC-135 | Code With No Effects — code quality only |

---

## Lưu ý về vai trò của swc_focus

> **swc_focus KHÔNG ảnh hưởng discovery**. Agents tìm bug qua prompt reasoning, không qua filter.
>
> swc_focus có 2 tác dụng thực tế:
> 1. **Labeling accuracy**: agent được nhắc nhở các SWC liên quan → label đúng SWC thay vì label SWC gần giống
> 2. **Attentional bias**: agent chú ý hơn đến pattern của SWC được list → nhẹ giảm false negative
>
> **Hệ quả**: Thêm SWC-124 vào blockchain không tạo ra khả năng tìm bug mới — nó giúp bug SWC-124 được label đúng thay vì bị label SWC-112 (cả hai đều liên quan delegatecall).

---

## Thay đổi cụ thể — `backend/app/services/contract_profile_generator.py`

### appsec — thêm SWC-100, 108, 110, 123, 126, 136

```python
"swc_focus": [
    "SWC-107", "SWC-101", "SWC-113", "SWC-128",
    "SWC-115", "SWC-104", "SWC-105",
    # Tier A additions
    "SWC-100",  # Function Default Visibility
    "SWC-108",  # State Variable Default Visibility
    "SWC-110",  # Assert Violation
    "SWC-123",  # Requirement Violation
    "SWC-126",  # Insufficient Gas Griefing
    # Tier B additions
    "SWC-136",  # Unencrypted Private Data On-Chain
],
```

Thêm vào persona_prompts (offensive/auditor):
```
SWC-100/108: Check all function and variable declarations for missing visibility.
SWC-110: Check assert() usage — assert should only be used for invariants that should NEVER be false
         (e.g., overflow check in Solidity <0.8). Using assert() for input validation burns all gas on failure.
SWC-123: Requirement Violation — require(condition) where condition is a logic invariant, not input guard.
SWC-126: Insufficient Gas Griefing — when forwarding a call, does the sub-call receive enough gas?
         If the caller forwards only a fraction and the sub-call fails silently, the operation appears
         to succeed while the intended effect is lost.
SWC-136: Private state variables (declared `private`) are still readable from blockchain state via
         eth_getStorageAt. Never store seeds, keys, or sensitive data on-chain.
```

### blockchain — thêm SWC-102, 103, 111, 118, 119, 124, 125, 134

```python
"swc_focus": [
    "SWC-107", "SWC-112", "SWC-116", "SWC-120", "SWC-109", "SWC-132",
    # Tier A additions
    "SWC-119",  # Shadowing State Variables
    "SWC-124",  # Write to Arbitrary Storage Location
    "SWC-125",  # Incorrect Inheritance Order
    "SWC-134",  # Message call with hardcoded gas amount
    # Tier B additions
    "SWC-102",  # Outdated Compiler Version
    "SWC-103",  # Floating Pragma
    "SWC-111",  # Use of Deprecated Solidity Functions
    "SWC-118",  # Incorrect Constructor Name (pre-0.5 legacy)
],
```

Thêm vào persona_prompts (auditor):
```
SWC-119: Check for state variable shadowing — if a child contract declares a variable with the same
         name as a parent, the parent's variable is shadowed and updates in child do not affect parent.
SWC-124: Write to arbitrary storage location — in proxy contracts or contracts using inline assembly,
         verify that no storage slot can be written to with an attacker-controlled key.
SWC-125: Incorrect inheritance order — in multi-inheritance contracts, check C3 linearization.
         `contract C is A, B` resolves differently from `contract C is B, A`.
SWC-134: Hardcoded gas amounts — `addr.call{gas: 2300}(...)` fails when recipient is a contract
         requiring more than 2300 gas (any SSTORE in receive hook). Use `addr.call(...)` with no
         gas limit, or let the callee determine gas requirements.
SWC-102/103: Outdated compiler / floating pragma — check compiler version; known bugs exist in
             older versions. Pin pragma to an exact version.
SWC-111: Deprecated functions — `suicide()` (use `selfdestruct`), `throw` (use `revert`),
         `sha3` (use `keccak256`), `callcode` (use `delegatecall`). Each has subtle behavior differences.
```

### cryptography — thêm SWC-117

```python
"swc_focus": [
    "SWC-120", "SWC-116", "SWC-121", "SWC-122", "SWC-133",
    # Tier A addition
    "SWC-117",  # Signature Malleability
],
```

Thêm vào persona_prompts (offensive):
```
SWC-117: Signature Malleability — ECDSA signatures (r, s, v) have two valid forms for any message
         (flip s to curve_order - s, flip v). If a contract uses raw ecrecover without checking
         s <= secp256k1n/2 or without OpenZeppelin ECDSA library, an attacker can craft a second
         valid signature from a known valid one. This breaks replay protection based on "signature
         already used" checks. Use OpenZeppelin's ECDSA.recover() which enforces s in lower half.
```

---

## Bảng tổng kết sau khi thêm

| Domain | SWCs hiện tại | SWCs thêm | Tổng |
|--------|--------------|-----------|------|
| appsec | 7 | +6 | 13 |
| blockchain | 6 | +8 | 14 |
| cryptography | 5 | +1 | 6 |
| defi | 1 | 0 | 1 |
| governance | 4 | 0 | 4 |
| defi_math | 2 | 0 | 2 |
| token_standard | 2 | 0 | 2 |

**Unique covered sau khi thêm**: 17 + 11 (mới) = **28 SWCs** (từ 17/37 lên 28/37)

SWCs hoàn toàn skip (Tier C + không applicable): 127, 129, 130, 131, 135 + 4 số không có trong registry = **9 SWCs**

---

## Điều kiện không thêm vào swc_focus

- **smart_contract_economics**: Economic attack patterns không map sang SWC — giữ nguyên `[]`
- **defi**: DeFi-specific attacks (flash loan, oracle) không map sang SWC tốt — SWC-114 là ngoại lệ duy nhất
- **defi_math**: Math precision bugs chỉ liên quan SWC-101 — giữ nguyên
- **token_standard**: Token assumption bugs không có SWC riêng — giữ nguyên

---

## Checklist sau khi implement

- [ ] appsec swc_focus: thêm SWC-100, 108, 110, 123, 126, 136
- [ ] blockchain swc_focus: thêm SWC-102, 103, 111, 118, 119, 124, 125, 134
- [ ] cryptography swc_focus: thêm SWC-117
- [ ] Thêm mô tả các SWC mới vào persona_prompts tương ứng
- [ ] Chạy lại 1 contract nhỏ để verify không có regression trong output format
- [ ] So sánh label accuracy trên contest 35 (SWC-124 có được label đúng thay vì SWC-112 không?)
