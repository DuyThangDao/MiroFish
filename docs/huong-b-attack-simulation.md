# Hướng B — Attack Simulation trong Phase C

## Bối cảnh

Phase C hiện tại là **reasoning-based verification**: attacker agents đọc contract source +
expert findings, rồi suy luận bằng ngôn ngữ tự nhiên xem attack có khả thi không.

```
Input : contract source + "SWC-107 trong fulfill()"
Output: [ATTACKER_CONFIRM SWC-107 fulfill()]
        Path: "1. Gọi fulfill() → trigger external call → re-enter → drain"
```

Vấn đề: ATTACKER_CONFIRM vẫn là LLM opinion — model vẫn có thể hallucinate một "path"
nghe hợp lý nhưng thực ra không chạy được. Không có ground truth.

---

## Hướng B đầy đủ — PoC generation + execution

### Ý tưởng

Phase C agent, thay vì chỉ viết text path, viết **Solidity test thực sự**. Backend compile
và chạy test. Kết quả là hard evidence.

```
Phase C agent output:
  [ATTACKER_CONFIRM SWC-107 fulfill()]
  Path: ...
  PoC:
  ```solidity
  contract Attacker {
      IVulnerable victim;
      bool entered;

      function attack() external {
          victim.fulfill(txData);
      }

      fallback() external payable {
          if (!entered) {
              entered = true;
              victim.fulfill(txData);   // re-enter
          }
      }
  }

  function testReentrancy() public {
      Attacker atk = new Attacker(address(victim));
      atk.attack();
      assertGt(address(atk).balance, 0);   // attacker drained funds
  }
  ```

Backend:
  forge test --match-test testReentrancy
  → PASS : confirmed exploit  → confidence × 1.20
  → FAIL : likely FP          → confidence × 0.50
  → ERROR: syntax/setup issue → neutral (không penalize)
```

### Ưu điểm
- Hard proof: PoC chạy được = exploit thực sự tồn tại
- Loại bỏ hoàn toàn khả năng hallucinate ATTACKER_CONFIRM
- Self-verifying: không cần human review từng finding

### Nhược điểm và challenges

| Challenge | Mức độ |
|-----------|--------|
| Resolve imports (`@openzeppelin/...`) | Cao — cần mock hoặc flatten contract |
| LLM viết sai Solidity syntax | Trung bình — cần retry/repair loop |
| Setup state phức tạp (fork mainnet) | Cao — một số bugs cần on-chain state |
| Front-running, MEV bugs | Không thể test trong isolated env |
| Compile time + gas limit | Thấp — forge test nhanh |
| Cần `foundry` installed | Thấp — 1 lần setup |

**Effort ước tính**: ~1 tuần, nhiều edge case cần xử lý.

---

## Hướng B simplified — Structured PoC + AST validation

### Ý tưởng

Không cần compile/run. Giá trị cốt lõi của PoC là **buộc LLM commit vào concrete code**,
không phải chạy được. Khi viết code, LLM không thể ẩn sau vague language.

```
Text path (hiện tại) — có thể hallucinate:
  "fulfill() có thể bị exploit vì external call trước state update"
  → Ngôn ngữ mơ hồ, không verifiable

Structured PoC — phải reference code thật:
  function attack() {
      victim.fulfill(txData);    // ← LLM phải dùng tên hàm thật
      victim.fulfill(txData);    // ← re-enter: nhưng có nonReentrant?
  }
  → Gọi hàm không tồn tại → lộ hallucination ngay
  → Logic sai về guard → có thể detect qua AST
```

### Validation pipeline (không cần external tool)

Contract AST đã có sẵn từ Step 1 (`ContractKGBuilder` parse Solidity):

```python
def validate_poc(poc_code: str, contract_ast: dict) -> float:
    """
    Trả về multiplier [0.5, 1.2] dựa trên chất lượng PoC.
    Không compile, không run — chỉ static analysis trên PoC text.
    """
    real_functions = {f["name"] for f in contract_ast["functions"]}
    called_funcs   = extract_called_functions(poc_code)  # regex parse
    state_vars     = {v["name"] for v in contract_ast["state_vars"]}

    # Check 1: PoC gọi hàm thật không?
    real_calls = called_funcs & real_functions
    if len(real_calls) == 0:
        return 0.50   # 0/n hàm thật → likely hallucination

    coverage = len(real_calls) / len(called_funcs) if called_funcs else 0
    if coverage < 0.5:
        return 0.65   # <50% hàm thật → suspicious

    # Check 2: PoC reference state vars thật không?
    poc_has_state_ref = any(v in poc_code for v in state_vars)

    # Check 3: PoC có modifier guards không (nonReentrant, onlyOwner)?
    guard_pattern = re.search(r'nonReentrant|onlyOwner|require\(msg\.sender', poc_code)
    if guard_pattern:
        # LLM thấy guard → DISMISS thay vì CONFIRM là đúng
        return 0.60

    if coverage >= 0.8 and poc_has_state_ref:
        return 1.10   # PoC solid, reference code thật
    return 0.85       # Partial evidence
```

### Luồng tích hợp vào Phase C

```
Phase C attacker agent output:
  [ATTACKER_CONFIRM SWC-107 fulfill()]
  Path: ...
  PoC:               ← field mới, optional
    attacker.fulfill(txData)  // re-enter
    ...

Backend parse_attacker_response():
  action = "ATTACKER_CONFIRM"
  poc_code = extract_poc(response)

  if poc_code:
      multiplier = validate_poc(poc_code, contract_ast)
      action["poc_quality_multiplier"] = multiplier
      # Dùng multiplier để adjust confidence_delta trong Layer 3
  else:
      # Không có PoC → CONFIRM bình thường, không bonus
      pass
```

### Ưu điểm so với Hướng B đầy đủ

| | Hướng B đầy đủ | Hướng B simplified |
|---|---|---|
| External tool | `foundry` | Không — dùng AST từ Step 1 |
| Kết quả | Hard proof (pass/fail) | Signal (strong/weak evidence) |
| Effort | ~1 tuần | ~2-3 ngày |
| Coverage | Tất cả compilable bugs | Tất cả bugs có function calls |
| Hallucination catch | ~95% | ~60-70% |

### Giới hạn

Hướng B simplified **không thể catch** hallucination kiểu:
- LLM viết PoC đúng syntax, đúng function names, nhưng sai logic (e.g., re-enter vào hàm
  đã có guard nhưng model không nhận ra guard)
- Semantic bugs (price oracle, governance) không có rõ ràng function call pattern

---

## Thứ tự triển khai đề xuất

```
Hiện tại:
  Expert claims → Attacker text reasoning → Consensus (additive)

Phase 1 (đã/đang làm):
  + Root-cause consensus fix: attacker là gate, không additive
  + max_tokens 1500 → 4096 cho Phase C

Phase 2 (ngắn hạn):
  + Hướng B simplified: structured PoC field + AST validation
  → ATTACKER_CONFIRM có bằng chứng code → weighted higher
  → ATTACKER_CONFIRM không có PoC hoặc PoC kém → weighted lower

Phase 3 (dài hạn, nếu cần):
  + Hướng B đầy đủ: foundry execution
  → Chỉ cần khi simplified không đủ precision
  → Bắt đầu với contract không có external imports
```

---

## Kết luận

Root-cause FP fix (Phase 1) là nền tảng — cả hai Hướng B đều phụ thuộc vào việc
ATTACKER_CONFIRM/DISMISS có đủ weight để ảnh hưởng consensus. Không có Phase 1, Hướng B
cũng không hiệu quả.

Hướng B simplified là bước tiếp theo tự nhiên: self-contained, tận dụng AST đã có,
tăng quality của Layer 3 signal mà không cần external dependency.
