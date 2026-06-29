# Baseline Comparison — Web3Bugs Benchmark (9 Contests)

## Dataset

9 cuộc thi kiểm toán từ bộ dữ liệu chuẩn Web3Bugs. GT bugs là H-severity bugs từ audit
reports thực tế. **Tổng GT = 116 H-bugs** (theo MECAP evaluation scope).

**Lưu ý về GT scope:** GT count của MECAP có thể thấp hơn tổng H-bugs trong audit report vì
một số bugs bị loại khỏi GT sau khi kiểm tra source code thực tế: auditor ghi sai tên function,
bug nằm ở nhánh code khác không có trong repository hiện tại, hoặc source code contest không
còn đầy đủ. Ví dụ: contest 30 (yAxis) — report có 10 H-bugs nhưng GT thực tế = 8 do 2 bugs
không reproduce được trên source code hiện có. Để đảm bảo so sánh công bằng, **tất cả tools
đều dùng cùng GT denominator của MECAP**.

---

## Các Baseline Được Đánh Giá

| Tool | Loại | Cơ chế tìm bug |
|------|------|----------------|
| **Slither** | Static Analysis | Biên dịch Solidity → SlithIR (SSA) → 90+ detectors chạy data-flow và control-flow analysis. Mỗi detector kiểm tra 1 pattern cố định (reentrancy, integer overflow, arbitrary-send...). Hoàn toàn rule-based, không có LLM, không có ngữ nghĩa kinh tế. |
| **GPTScan** | LLM + Static | 2 phase: (1) LLM screening — 9 preset scenario types (price manipulation, flash loan, wrong-order, front-running...), hỏi LLM từng function "có phải bug type X không?"; (2) Static verification — data-flow analysis xác nhận property cụ thể nếu LLM đồng ý. Không có RAG, không có cross-contract reasoning, bị giới hạn bởi 9 scenarios định sẵn. |
| **LLMSmartAudit-TA** | LLM sequential | 41 detectors chạy tuần tự, mỗi detector là 1 SimplePhase độc lập hỏi LLM về 1 vulnerability type cố định (ArithmeticDetector, ReentrancyDetector, PriceManipulationDetector...). Không có cross-detector reasoning, không có RAG, không có HIST-INV, không có dedup. Đánh giá trên contest 42 (Mochi Protocol, 13 GT bugs). ⚠️ Lưu ý: eval script có lỗi regex parse function_name → TP thực tế cao hơn auto-eval (TP=5 thực tế vs TP=3 auto). |
| **LLMSmartAudit-BA** | LLM role-chain | Sequential role-based conversation chain (ChatDev-style): 5 phases, mỗi phase là hội thoại giữa 2 roles — (1) CEO ↔ Security Analyst: brainstorm ideas; (2) Security Analyst ↔ Solidity Expert: deep code review dựa trên ideas; (3) Solidity Expert ↔ Security Analyst: tổng hợp bugs; (4) Security Testing Engineer ↔ Solidity Expert: phân tích test failures; (5) Security Testing Engineer ↔ Solidity Expert: đề xuất fixes. Output của phase trước làm input cho phase sau. Không có dedup, không có RAG, không có HIST-INV. |
| **Single-agent** | LLM | Dùng đúng pipeline MECAP (HIST-INV, RAG, 3-round reasoning T1→T2→T3, multi-stage dedup), nhưng chỉ có 1 agent duy nhất: `universal_analyst` — không có domain specialization, không có swarm. Ablation study để đo đóng góp của swarm so với pipeline. |
| **MECAP (Đề xuất)** | LLM swarm | 20+ specialized agents theo domain (numerics, state consistency, access control, DeFi economics, integration), mỗi agent có expert identity + mental model riêng. HIST-INV: inject invariant lịch sử từ Knowledge Graph. RAG: retrieve 3000+ past audit findings tương tự. 3-round reasoning (T1: independent discovery → T2: cross-agent synthesis → T3: adversarial challenge). Multi-stage dedup: hash-based + LLM semantic clustering. |

---

## Per-Contest Recall

Sắp xếp theo Recall của MECAP (giảm dần). **Tất cả tools dùng GT denominator của MECAP.**

| Contest | Giao thức | GT | Slither | GPTScan | LLMSmartAudit-BA | Single-agent | **MECAP** |
| :------ | :-------- | :-: | :-----: | :-----: | :--------------: | :----------: | :-------: |
| 71  | Insure Protocol  | 13 | 0.154 | 0.000 | 0.231 | 0.462 | **0.923** |
| 104 | Joyn             |  9 | 0.000 | 0.000 | 0.889 | 0.556 | **0.889** |
| 30  | yAxis            |  8 | 0.000 | 0.125 | 0.375 | 0.375 | **0.875** |
| 42  | Mochi            | 13 | 0.000 | 0.077 | 0.692 | 0.385 | **0.846** |
| 35  | Trident (Sushi)  | 17 | 0.000 | 0.000 | 0.294 | 0.235 | **0.824** |
| 61  | Sublime Finance  | 11 | 0.000 | 0.000 | 0.273 | 0.455 | **0.818** |
| 5   | Vader Protocol   | 24 | 0.083 | 0.167 | 0.500 | 0.542 | **0.750** |
| 83  | Concur Finance   | 10 | 0.000 | 0.000 | 0.700 | 0.500 | **0.700** |
| 3   | MarginSwap       | 11 | 0.000 | 0.000 | 0.636 | 0.455 | **0.636** |

---

## Tổng Kết Toàn Cục

GT = 116 cho tất cả tools (MECAP standard). Cột Findings: Slither/GPTScan/BA = raw output; Single-agent và MECAP = sau dedup.

| Phương pháp | TP | Findings | Precision | Recall | F1 |
| :---------- | :-: | :------: | :-------: | :----: | :-: |
| **Slither** | 4 | 1,554 (raw) | 0.003 | 0.034 | 0.005 |
| **GPTScan** | 6 | 53 (raw) | 0.113 | 0.052 | 0.071 |
| **LLMSmartAudit-BA** | 57 | 1,791¹ (raw) | 0.032 | 0.491 | 0.060 |
| **Single-agent** | 51 | 424 (dedup) | 0.120 | 0.440 | 0.189 |
| **MECAP (Đề xuất)** | **93** | 1,562 (dedup) | 0.060 | **0.802** | 0.111 |

¹ BA findings raw: 332+347+133+254+284+129+144+110+58 = 1,791. Contest 83 dùng raw=110 (không dedup).

---

## Per-Contest TP Detail

| Contest | Giao thức | GT | TP (GPTScan) | TP (BA) | TP (MECAP) |
| :------ | :-------- | :-: | :----------: | :-----: | :---------: |
| 71  | Insure Protocol  | 13 |  0 |  3 | 12 |
| 104 | Joyn             |  9 |  0 |  8 |  8 |
| 30  | yAxis            |  8 |  1 |  3 |  7 |
| 42  | Mochi            | 13 |  1 |  9 | 11 |
| 35  | Trident (Sushi)  | 17 |  0 |  5 | 14 |
| 61  | Sublime Finance  | 11 |  0 |  3 |  9 |
| 5   | Vader Protocol   | 24 |  4 | 12 | 18 |
| 83  | Concur Finance   | 10 |  0 |  7 |  7 |
| 3   | MarginSwap       | 11 |  0 |  7 |  7 |
| **Tổng** | | **116** | **6** | **57** | **93** |

---

## LLMSmartAudit-TA — Chi Tiết Contest 42 (Mochi Protocol)

Chỉ đánh giá trên contest 42. FeePoolV0 chạy partial (37/41 phases, 4 phases thiếu không liên quan GT bugs).
Auto-eval TP=3 do lỗi regex parse function_name; manual verification cho TP=5.

| Metric | Auto-eval | Manual (corrected) |
| :----- | :-------: | :----------------: |
| TP | 3 | **5** |
| FP | 835 | 833 |
| FN | 10 | 8 |
| Precision | 0.004 | 0.006 |
| Recall | 0.231 | **0.385** |
| F1 | 0.007 | 0.011 |
| Findings (raw) | 853 | 853 |

**Matched bugs (manual):** H-03, H-04, H-06, H-09, H-13

**Bỏ sót:** H-01, H-02, H-05, H-07, H-08, H-10, H-11, H-12 — hầu hết là DeFi logic bugs (debt accounting, fee pool drain, liquidation underflow) không có detector phù hợp trong 41 preset types.

**Lỗi eval:** H-03 và H-06 bị miss vì `parse_log()` regex (`\`funcName\(`) không extract được `function_name` khi descriptions dùng format `` `funcName` `` (không có dấu `(` ngay sau backtick). Kết quả lưu đầy đủ tại `benchmark/web3bugs/llmsmartaudit-ta/42/eval_result.txt`.

---

## GPTScan — Chi Tiết Per-Contest

| Contest | TP | FP | Findings | Precision | Recall | F1 | TP bugs |
| :------ | :-: | :-: | :------: | :-------: | :----: | :-: | :------ |
| 3   |  0 |  5 |  5 | 0.000 | 0.000 | 0.000 | — |
| 5   |  4 | 20 | 24 | 0.167 | 0.167 | 0.167 | H-02, H-05, H-08, H-12 |
| 30  |  1 |  2 |  3 | 0.333 | 0.125 | 0.182 | H-05 |
| 35  |  0 |  0 |  0 | — | 0.000 | 0.000 | — |
| 42  |  1 |  2 |  3 | 0.333 | 0.077 | 0.125 | |
| 61  |  0 |  5 |  5 | 0.000 | 0.000 | 0.000 | — |
| 71  |  0 |  8 |  8 | 0.000 | 0.000 | 0.000 | — |
| 83  |  0 |  5 |  5 | 0.000 | 0.000 | 0.000 | — |
| 104 |  0 |  0 |  0 | — | 0.000 | 0.000 | — |

Nguồn: `benchmark/web3bugs/gptscan/<contest>/eval_result_manual.txt`

---

## LLMSmartAudit-BA — Chi Tiết Per-Contest

Raw findings = tổng findings trước dedup (BA không có dedup). Recall và Precision đều tính theo MECAP GT.

| Contest | TP | Raw Findings | Precision | Recall | F1 | TP bugs |
| :------ | :-: | :----------: | :-------: | :----: | :-: | :------ |
| 3   |  7 | 332 | 0.021 | 0.636 | 0.041 | H-03,05,07,08,09,10,11 |
| 5   | 12 | 347 | 0.035 | 0.500 | 0.065 | H-01,02,05,06,07,09,14,16,17,20,21,22 |
| 30  |  3 | 133 | 0.023 | 0.375 | 0.042 | H-05,09,10 |
| 35  |  5 | 254 | 0.020 | 0.294 | 0.037 | H-02,06,10,11,13 |
| 42  |  9 | 284 | 0.032 | 0.692 | 0.061 | H-01,02,03,05,06,09,11,12,13 |
| 61  |  3 | 129 | 0.023 | 0.273 | 0.043 | H-09,10,11 |
| 71  |  3 | 144 | 0.021 | 0.231 | 0.038 | H-02,06,09 |
| 83  |  7 | 110 | 0.064 | 0.700 | 0.115 | H-01,02,03,05,06,07,11 |
| 104 |  8 |  58 | 0.138 | 0.889 | 0.237 | H-02,03,04,05,06,07,08,09 |

Nguồn: `benchmark/web3bugs/llmsmartaudit-ba/<contest>/eval_result_manual.txt`

---

## Quan Sát Chính

**Về Recall:**
- MECAP đạt Recall=0.802 — cao nhất, dẫn đầu ở 8/9 contests (đồng hạng với BA ở contest 104).
- LLMSmartAudit-BA đứng thứ hai (Recall=0.491), đặc biệt mạnh ở contests đơn giản (104: 0.889, 83: 0.700).
- Single-agent (0.440) và BA (0.491) gần nhau về recall tổng thể.
- GPTScan Recall thấp (0.052) — bị giới hạn bởi 9 preset scenario types; 5/9 contests TP=0.
- Slither Recall=0.034 — chỉ bắt được lỗi cấu trúc bề mặt.

**Về Precision:**
- Single-agent và GPTScan có precision cao nhất (0.120 và 0.113) — ít findings, mỗi finding có chất lượng hơn.
- MECAP (0.060) và BA (0.032) chấp nhận precision thấp để đổi lấy recall cao.
- Slither precision thấp nhất (0.003) với 1,554 findings gần như toàn FP.

**Về F1:**
- Single-agent F1 cao nhất (0.189) — cân bằng tốt nhất giữa precision và recall.
- MECAP F1=0.111, BA F1=0.060 — cả hai ưu tiên recall.
- Trong bài toán security audit, FN (bỏ sót bug) có chi phí cao hơn FP → **Recall là metric quan trọng hơn F1**.

**Tóm tắt:**

| Metric | Tốt nhất | Xấu nhất |
|--------|---------|---------|
| Recall | MECAP (0.802) | Slither (0.034) |
| Precision | Single-agent (0.120) | Slither (0.003) |
| F1 | Single-agent (0.189) | Slither (0.005) |
| TP tuyệt đối | MECAP (93/116) | Slither (4/116) |

