# Checklist kiến thức bảo vệ bài báo

> Mục tiêu: nắm đủ để trả lời câu hỏi phản biện — không cần deep expert, cần hiểu đúng và nói được bằng lời của mình.

---

## Nhóm 1 — Blockchain & Smart Contract cơ bản
*Hội đồng sẽ hỏi để verify bạn hiểu domain mình đang audit*

- [ ] **Blockchain là gì** — distributed ledger, immutable, consensus mechanism (PoW vs PoS ở mức khái niệm)
- [ ] **Smart contract là gì** — code chạy trên EVM, không thể sửa sau khi deploy, ai cũng có thể gọi
- [ ] **EVM (Ethereum Virtual Machine)** — bytecode, gas, transaction, state
- [ ] **Solidity cơ bản** — `function`, `modifier`, `mapping`, `require()`, `msg.sender`, `address`
- [ ] **Transaction lifecycle** — từ user ký tx → mempool → miner/validator → state change
- [ ] **Tại sao smart contract bug nguy hiểm hơn web app bug** — immutable, tiền thật, không có hotfix

---

## Nhóm 2 — Vulnerability taxonomy
*Nền tảng để giải thích tại sao tool cần thiết*

- [ ] **SWC Registry** — Smart Contract Weakness Classification, ~37 categories, tương tự CWE cho smart contract
- [ ] **L-category vs S-category (Web3Bugs)** — L: static-detectable (SWC-based), S: semantic/business logic
- [ ] **OOS (Out-of-Scope)** — SC/SE bugs cần cross-chain state, không thể detect từ single-chain source
- [ ] **5 bugs quan trọng nhất:**
  - **SWC-107 Reentrancy** — gọi external contract trước khi update state → attacker re-enter
  - **SWC-105 Access Control** — function modify state của user A mà không check `msg.sender == A`
  - **SWC-101 Integer Overflow** — phép tính tràn số (Solidity < 0.8)
  - **SWC-114 ERC20 approve race condition** — approve không reset về 0
  - **SWC-116 Timestamp dependence** — dùng `block.timestamp` làm điều kiện critical
- [ ] **Contest 19 bugs cụ thể (TransactionManager):**
  - H-01: `addLiquidity()` thiếu `require(msg.sender == router)` → anyone can drain router funds
  - H-05: `approve()` không reset sau khi `IFulfillHelper.addFunds()` revert
  - H-02: `activeTransactionBlocks` array grows unbounded → gas DoS
  - H-03/H-04: cross-chain state assumption → OOS

---

## Nhóm 3 — Kiến trúc MECAP (bài báo của bạn)
*Phần quan trọng nhất — phải giải thích được mọi component*

- [ ] **MECAP là gì** — Multi-Expert Consensus Audit Panel, multi-agent LLM system cho smart contract audit
- [ ] **3-phase session:**
  - Phase A (rounds 1–3): Intra-domain — experts trong cùng nhóm thảo luận
  - Phase B (rounds 4–7): Cross-domain — experts challenge nhau across nhóm
  - Phase C (rounds 8–10): Attacker — 5 attacker profiles confirm/dismiss exploitability
- [ ] **5 domain groups** — appsec, blockchain, defi, governance, cryptography + smart_contract_economics
- [ ] **5 attacker profiles** — reentrancy_exploiter, flash_loan_attacker, governance_attacker, access_control_exploiter, logic_exploiter
- [ ] **GAP declaration mechanism** — agent khai báo những gì không verify được → route sang domain phù hợp
- [ ] **Consensus engine** — 3-layer: expert confidence × attacker corroboration × cross-domain validation
- [ ] **Invariant-driven adversarial audit (contribution mới):**
  - Layer 1 structural scan: tìm `mapping[addr]` write thiếu `require(msg.sender == addr)`
  - Layer 2 LLM missing-enforcement: hỏi "cái gì NÊN được enforce nhưng KHÔNG có trong code"
  - Inject vào Phase C như "attack objectives" cho attacker agents
- [ ] **Tại sao additive chứ không phải replacement** — open-ended scan vẫn chạy, invariant layer là thêm vào
- [ ] **Semantic findings** — track business logic bugs riêng biệt với SWC findings

---

## Nhóm 4 — Evaluation framework
*Hội đồng sẽ hỏi về cách đánh giá*

- [ ] **Web3Bugs benchmark** — 72 contests từ Code4rena, ~180 confirmed high/medium severity bugs
- [ ] **Precision / Recall / F1** — công thức, trade-off, tại sao F1 là metric chính
- [ ] **Strict vs Lenient F1** — strict: cần overlap function name; lenient: chỉ cần match category/SWC
- [ ] **Ground truth format** — L-bugs map sang SWC ID, S-bugs map sang category (access_control, incorrect_accounting...)
- [ ] **OOS bugs không tính vào denominator** — tại sao: không thể detect từ source → không fair để penalize
- [ ] **Kết quả thực tế của tool:**
  - Contest 19 F1 = 0.200 (baseline Run #4)
  - Invariant layer đang được test (Run #8 đang chạy)
- [ ] **So sánh với GPTScan** — Precision=17.39%, Recall=83.33%, F1=27.87% trên Web3Bugs (apples-to-apples)

---

## Nhóm 5 — Related work
*Câu hỏi "tool của bạn khác gì so với X?"*

- [ ] **Slither** — static analysis, ~100 detectors, cần compile được contract, không có semantic reasoning
- [ ] **Mythril** — symbolic execution, tìm được reachability bugs, không hiểu business logic
- [ ] **GPTScan** — LLM matching vulnerability scenarios với function summaries, pattern-based
- [ ] **Traditional audit** — manual, expensive ($50k–$200k), inconsistent, không scalable
- [ ] **Tại sao MECAP khác:**
  - Multi-agent adversarial debate → confidence estimation
  - Cross-domain reasoning → compound vulnerabilities
  - Attacker simulation → exploit path generation
  - Không cần compile → chạy được trên raw source

---

## Nhóm 6 — Câu hỏi khó thường gặp

- [ ] **"F1=0.200 là thấp, tool có thực sự hữu ích không?"**
  → Baseline thấp vì Web3Bugs gồm nhiều S-category và OOS bugs khó. GPTScan F1=27.87% trên cùng benchmark. MECAP đang cải thiện qua invariant layer. Giá trị không chỉ ở recall mà ở exploit path và severity estimation.

- [ ] **"Tại sao dùng LLM thay vì chỉ dùng Slither?"**
  → Slither không phát hiện S-category bugs (business logic). H-01 và H-05 của Contest 19 là S-category — Slither không thể tìm H-05 vì không hiểu luồng control cross-function.

- [ ] **"Multi-agent có thực sự tốt hơn single agent không?"**
  → Adversarial debate giảm false positive qua dismiss mechanism. Attacker layer confirm exploitability — tăng precision. Cross-domain phát hiện compound vulnerabilities mà single-domain bỏ qua.

- [ ] **"Invariant-driven approach có generalizable không?"**
  → Structural patterns generalizable cho access_control category trên DeFi contracts (ownership gap pattern phổ biến). LLM layer generalizable hơn nhưng phụ thuộc vào contract complexity. S-category bugs là vô hạn → không thể fully enumerate bằng structural patterns.

- [ ] **"Tại sao không integrate Slither trực tiếp?"**
  → Slither cần compile được contract (dependencies, compiler version, monorepo). MECAP chạy trên raw source text — practical advantage cho audit-as-a-service. Structural scan của MECAP là lightweight alternative không cần build environment.

- [ ] **"Kết quả có reproducible không?"**
  → LLM stochastic → F1 varies ~±0.05 between runs. Fix: temperature=0.2 cho critical steps, consensus engine normalize qua multiple agents.

---

## Thứ tự ưu tiên học

| Ưu tiên | Nhóm | Lý do |
|---------|------|-------|
| 🔴 Bắt buộc | Nhóm 3 (MECAP architecture) | Đây là contribution của bạn |
| 🔴 Bắt buộc | Nhóm 6 (Câu hỏi khó) | Hội đồng sẽ hỏi |
| 🟠 Quan trọng | Nhóm 2 (Vulnerability taxonomy) | Cần để giải thích tại sao tool cần |
| 🟠 Quan trọng | Nhóm 4 (Evaluation) | Cần để defend kết quả |
| 🟡 Cần biết | Nhóm 5 (Related work) | Câu "khác gì so với X" |
| 🟢 Biết thêm | Nhóm 1 (Blockchain basics) | Nền tảng, ít bị hỏi sâu |
