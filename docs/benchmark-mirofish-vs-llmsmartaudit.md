# Benchmark: MiroFish vs LLMSmartAudit BA

**9 contests · 118 GT H-bugs · 2026-06-28**

Eval method: manual semantic matching theo 3-question checklist (root cause / location / explicitly described).
MiroFish dùng findings từ `benchmark/web3bugs/agent-redesign/{id}/results/multi-agents/`.
BA dùng findings từ `benchmark/web3bugs/llmsmartaudit/{id}/`.

---

## 1. Kết quả tổng hợp

### 1.1 Aggregate metrics

| Metric | MiroFish | LLMSmartAudit BA | Delta |
|--------|----------|------------------|-------|
| Avg Recall (macro) | **0.787** | 0.502 | +56.8% |
| Global Recall (93/118 vs 57/118) | **0.788** | 0.483 | +63% |
| Avg Precision | 0.083 | 0.049 | MiroFish nhỉnh hơn |
| Avg F1 (macro) | **0.146** | 0.087 | +67.8% |

> **Precision MiroFish** = TP / dedup findings. **Precision BA** = TP / raw (pre-dedup) findings.

### 1.2 Per-contest breakdown

| Contest | Protocol | GT | MiroFish TP | BA TP | MiroFish R | BA R | MiroFish F1 | BA F1 | ΔRecall |
|---------|----------|----|-------------|-------|------------|------|-------------|-------|---------|
| #003 | MarginSwap | 11 | 7 | 7 | 0.636 | 0.636 | 0.044 | 0.041 | — |
| #005 | Vader Protocol | 24 | 18 | 12 | 0.750 | 0.500 | 0.080 | 0.065 | +25.0% |
| #030 | yAxis | 10 | 7 | 3 | 0.700 | 0.300 | 0.143 | 0.042 | +40.0% |
| #035 | Trident/Sushi | 17 | 14 | 5 | 0.824 | 0.294 | 0.318 | 0.037 | +53.0% |
| #042 | Mochi | 13 | 11 | 9 | 0.846 | 0.692 | 0.164 | 0.061 | +15.4% |
| #061 | Sublime Finance | 11 | 9 | 3 | 0.818 | 0.273 | 0.100 | 0.043 | +54.5% |
| #071 | InsureDAO | 13 | 12 | 3 | 0.923 | 0.231 | 0.129 | 0.038 | +69.2% |
| #083 | Concur Finance | 10 | 7 | 7 | 0.700 | 0.700 | 0.089 | 0.215 | — |
| #104 | PartyDAO | 9 | 8 | 8 | 0.889 | 0.889 | 0.246 | 0.237 | — |

**Findings count:**

| Contest | MiroFish dedup | BA raw |
|---------|---------------|--------|
| #003 | 311 | 332 |
| #005 | 426 | 347 |
| #030 | 88 | 133 |
| #035 | 71 | 254 |
| #042 | 121 | 284 |
| #061 | 169 | 129 |
| #071 | 173 | 144 |
| #083 | 147 | 55 |
| #104 | 56 | 58 |

**Pattern rõ:** 3 contests không có nhiều cross-contract bugs (104, 83, 3) — BA đạt recall ngang MiroFish. BA thậm chí tốt hơn về F1 ở contest 83 (0.215 vs 0.089) vì chỉ xuất 55 raw findings so với 147 dedup của MiroFish.

---

## 2. Phân tích điểm mạnh / yếu

### 2.1 MiroFish Multi-Agent

**Strengths:**
- **Cross-contract recall** — KG cho phép trace call chain, accounting flow, ownership pattern qua nhiều files. 6/9 contests MiroFish vượt BA rõ rệt.
- **Protocol-specific domain knowledge** — KG được build từ source docs + RAG từ solodit. Tìm được bugs đòi hỏi hiểu AMM tick math (contest 35), Aave/Yearn mechanics (contest 61), insurance lifecycle (contest 71).
- **Accounting bug detection** — Tìm được bugs phức tạp như share price distortion qua earn(), balance denomination mixing, double-counting qua nhiều functions.
- **Precision sau dedup cạnh tranh** — Avg precision 0.083 so với BA 0.049; dedup pipeline giữ lại nhiều TP hơn tương đối.

**Weaknesses:**
- **FP rate cao ở complex protocols** — Contest 5 (Vader): 426 dedup findings cho 18 TP = precision 0.042. Contest 3: 311 dedup cho 7 TP.
- **Chi phí cao** — KG construction + multi-agent simulation + dedup pipeline.
- **F1 tuyệt đối vẫn thấp** — Avg F1 0.146; cần cải thiện precision.

### 2.2 LLMSmartAudit BA (SmartContractBA)

**Strengths:**
- **Competitive trên compact, single-file protocols** — Contest 104 và 83: recall ngang MiroFish. F1 ở 83 (0.215) còn cao hơn MiroFish (0.089) nhờ ít FP hơn nhiều.
- **Chi phí thấp, không cần hạ tầng** — Không cần KG, không cần dedup pipeline, chỉ Vertex AI API.
- **Intra-file pattern bugs** — Tốt ở: inverted conditions, missing state writes, uninitialized variables, access control errors, first-depositor inflation attacks, classic oracle manipulation.

**Weaknesses:**
- **Blind spot hoàn toàn với cross-contract bugs** — Single-file context = không thể trace call chains. Contest 71: 7/13 GT bugs cần ≥2 contracts → BA bắt 3/13.
- **Không có protocol-level domain knowledge** — Bỏ sót AMM math invariants (contest 35), Aave rebasing semantics, Yearn decimals (contest 61).
- **FP rate rất cao ở complex protocols** — Contest 3: 332 raw findings cho 7 TP (precision 0.021). Contest 35: 254 raw findings cho 5 TP (precision 0.020).
- **Arithmetic tracing bị hạn chế** — Tìm ra area của vấn đề nhưng không tính toán đủ sâu để xác định chính xác lỗi (setCap subtraction formula, oracle arg inversion).

---

## 3. Phân tích theo loại bug

| Loại bug | BA | MiroFish | Ví dụ |
|----------|----|----------|-------|
| Access control (wrong modifier) | Tốt | Tốt | C3-H08: withdrawReward chỉ cho isIncentiveReporter |
| Initialization bug (uninitialized var) | Tốt | Tốt | C3-H09: lastUpdatedDay=0 → dayDiff ~19700 → OOG |
| Logic inversion (sai operator) | Tốt | Tốt | C3-H05: belowMaintenanceThreshold trả true khi healthy |
| Missing state write (mapping never set) | Tốt | Tốt | C3-H07: addHolding không set holdsToken=true |
| Duplicate function call | Tốt | Tốt | C3-H10: buyBond gọi depositFor 2 lần |
| Oracle-less valuation / 1:1 parity | Tốt | Tốt | C30-H05/H10: balanceOfThis không dùng price feed |
| Flash loan oracle manipulation | Tốt | Tốt | C3-H03: getCurrentPriceInPeg bị manipulate qua AMM |
| **Cross-contract call chain bug** | **Bỏ sót** | **Tốt** | C71: 7/13 bugs cần Vault → Controller → Strategy |
| **Cross-contract accounting error** | **Bỏ sót** | **Tốt** | C30-H06: earn() giảm share price qua token conversion |
| **AMM / protocol math** | **Bỏ sót** | **Tốt** | C35: tick boundaries, unchecked overflow, secondsPerLiquidity ordering |
| **External protocol semantics** | **Bỏ sót** | **Tốt** | C61-H04/H05: Yearn decimals, Aave rebasing mechanics |
| **State machine lifecycle** | **Bỏ sót** | **Tốt** | C71-H12: paused vs marketStatus là 2 state vars khác nhau |
| **Multi-condition path tracing** | **Bỏ sót** | **Tốt** | C71-H05: else-if branch trong withdrawRedundant → backdoor |
| Decimal denomination mixing (cross-boundary) | Bỏ sót | Tốt | C30-H07/H08: balance() mix normalized vs raw amounts |
| Arithmetic formula error cụ thể | Partial | Tốt | C71-H11: _divCeil(deduction,share) thay vì deduction*share |

**Nhận xét quan trọng:** BA bỏ sót không chỉ cross-contract bugs, mà còn:
- 9 intra-file AMM math bugs trong contest 35 (Trident) vì không có Uniswap V3 domain knowledge
- 6 intra-file bugs trong contest 61 (Sublime) vì không biết Aave/Yearn API semantics
- 5 intra-file bugs trong contest 71 (InsureDAO) về state machine và formula errors

---

## 4. Về nguồn gốc advantage của MiroFish

### 4.1 "Đội ngũ chuyên gia" không phải data leak

Persona knowledge là **domain expertise được cấu trúc hóa**, không phải nhớ đáp án cụ thể. Agents được thiết kế với expert identity + mental model + instinct (worldview bao quát, không pattern matching, không ví dụ cụ thể). Một "math precision agent" biết hỏi *denominator này có nhất quán không?* — đó là lens, không phải lookup.

Cả BA và MiroFish đều dùng cùng LLM base model (Gemini Flash). Nếu model đã thấy Code4rena reports trong pretraining, cả hai benefit như nhau. Persona chỉ là cách khai thác knowledge theo nhiều góc độ chuyên biệt hơn.

### 4.2 solodit_findings — kỹ thuật có overlap nhưng empirically minor

solodit_findings (3366 entries) index Code4rena reports và có overlap với các contests được eval:

| Contest | solodit coverage |
|---------|-----------------|
| yAxis-30 | 9/10 GT bugs (90%) |
| Vader-5 | >100% (duplicates) |
| InsureDAO-71 | 7/13 (54%) |
| Mochi-42 | 8/13 (62%) |
| MarginSwap-3 | 4/11 (36%) |
| **Trident-35** | **0/17 (0%)** |
| **Sublime-61** | **0/11 (0%)** |
| Concur-83 | 2/10 (20%) |
| PartyDAO-104 | >100% |

Về mặt kỹ thuật đây là data leakage. Tuy nhiên, empirically không phải driver chính vì:

1. **Contests 35 và 61 có 0% solodit coverage — MiroFish vẫn thắng +53% và +54.5%.** Đây là bằng chứng rõ nhất về genuine capability.

2. **RAG ablation contest 42:** 12/13 TPs bắt được không cần RAG, chỉ 1 TP (H-11) là RAG-only. Phần lớn recall đến từ KG + multi-agent reasoning, không phải solodit retrieval.

3. **solodit có H-01/H-02 của yAxis nhưng MiroFish vẫn miss** — retrieval không guarantee catch, cần context match đúng.

### 4.3 Genuine advantage đến từ đâu

1. **KG enables cross-file state** — agents biết `Vault.balance()` gọi `balanceOfThis()` gọi `manager.getTokens()` vì KG encode relationship từ source code. Không phải nhớ — là build và query graph.

2. **Structured reasoning diversity** — 5 agents nhìn cùng đoạn code từ 5 góc độc lập, tăng xác suất coverage tổng thể. BA dùng 5 roles tuần tự trong 1 context, không thực sự độc lập.

3. **Persona as lens, not lookup** — thiết kế intentionally bao quát để agent hỏi đúng câu hỏi cho class of bugs, không phải nhớ specific findings.

---

## 5. Khi nào nên dùng gì

| Tình huống | Khuyến nghị |
|-----------|-------------|
| Audit protocol đơn giản, intra-file bugs rõ ràng | BA đủ dùng, precision tốt hơn ở compact protocols |
| Rapid triage, không có infrastructure | BA (không cần KG/dedup) |
| Protocol DeFi phức tạp (AMM, vault, insurance) | MiroFish — cross-contract reasoning quyết định |
| Cần tối đa recall (không quan tâm precision) | MiroFish |
| Cần tối đa F1 trên protocol compact | BA cạnh tranh với MiroFish |

---

## 6. Giới hạn của benchmark hiện tại

- **solodit overlap:** Một phần recall MiroFish có thể đến từ RAG trên data chứa GT. Cần ablation đầy đủ hoặc benchmark từ private audits không có trong solodit.
- **Cleanest data points:** Contests 35 (Trident) và 61 (Sublime) — 0% solodit coverage — là nơi đo genuine capability chính xác nhất.
- **Precision chưa được đánh giá đầy đủ** cho MiroFish (chỉ dùng TP/dedup-count, không manually verify FPs).
- **Chỉ có 9 contests** — sample size còn nhỏ để kết luận statistical.
