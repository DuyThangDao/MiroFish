# MECAP — Kế hoạch viết báo (VNICT 2026)

**Tiêu đề**: An Application of GenAI in Detecting Logical Flaws in Smart Contracts  
**Hội nghị**: VNICT 2026 — Hội thảo quốc gia lần thứ XXIX, Hà Nội, 7–8/11/2026  
**Format**: IEEE IEEEtran (compsocconf), 2 cột, A4, tiếng Anh, tối đa 6 trang  
**Template**: `base_paper.text` (thầy cung cấp)  
**Nộp bài**: EasyChair

---

## Ràng buộc

- Tối đa **6 trang** (có thể hơn chút, nhưng không quá nhiều)
- Format IEEE — không sửa margin, font, độ rộng cột
- Mọi claim phải có trích dẫn hoặc dữ liệu thực nghiệm
- Ngôn ngữ: tiếng Anh học thuật chuẩn quốc tế
- Ít nhất 1 tác giả phải trình bày tại hội nghị

---

## Phân bổ trang

| Phần | Số trang |
|------|----------|
| Abstract + Keywords | ~0.2 |
| 1. Giới thiệu | ~0.8 |
| 2. Công trình liên quan | ~0.5 |
| 3. Kiến trúc hệ thống | ~1.5 |
| 4. Đánh giá & Kết quả | ~1.5 |
| 5. Kết luận | ~0.2 |
| Tài liệu tham khảo | ~0.8 |
| Hình & Bảng (nằm trong các phần) | phân bổ đều |
| **Tổng** | **~5.5–6.0** |

---

## Quy tắc trích dẫn

### Tiêu chuẩn quốc tế (IEEE)
- Format: IEEE numbered style `[1]`, `[2]`, ... theo thứ tự xuất hiện trong bài
- Mỗi claim quan trọng cần ít nhất 1 citation — không để claim "treo" không có nguồn
- Phân bổ hợp lý: Introduction ~3–5 cite, Related Work ~8–12 cite, System ~3–5 cite, Evaluation ~3–5 cite
- Tổng toàn bài: **15–20 references** là chuẩn cho paper 6 trang IEEE
- Ưu tiên: peer-reviewed papers > technical reports > websites/docs
- Không cite Wikipedia, blog cá nhân, hoặc nguồn không có peer review

### Quy trình làm việc khi cần trích dẫn
1. **Tìm bài**: Claude truy cập internet để lấy thông tin chính xác (tên tác giả, năm, venue, DOI)
2. **Gửi link**: Claude cung cấp link bài báo để bạn confirm trước khi đưa vào .bib
3. **Xác nhận**: Bạn confirm → Claude thêm vào references.bib
4. **Không tự bịa**: Nếu không tìm được nguồn chính xác, Claude sẽ báo thay vì tự điền
5. **Tìm thêm khi cần**: Danh sách ref hiện tại không cố định — trong quá trình viết, nếu nội dung cần thêm evidence hoặc context, Claude sẽ chủ động tìm ref mới, gửi link để confirm trước khi dùng

### Quy tắc bắt buộc — Verify trước khi viết
> **Bất kỳ nội dung nào KHÔNG thuộc về tự thân dự án đều phải được verify qua internet trước khi đưa ra.**

Cụ thể, trước khi viết Claude phải verify:
- Số liệu của tool khác (F1, Precision, Recall, runtime...)
- Điểm yếu/hạn chế của tool khác (FP rate, missed vulnerability types...)
- Số liệu thống kê bên ngoài (tổn thất tài chính, số lượng hacks...)
- Tên tác giả, năm, venue của bất kỳ paper nào
- Bất kỳ claim kỹ thuật nào về framework/tool/dataset bên ngoài

**Không được** lấy từ research proposal, plan, hay memory làm nguồn cuối — đó chỉ là gợi ý để tìm kiếm, không phải nguồn xác thực.

### Bảng loại nội dung

| Loại nội dung | Cần cite? | Ví dụ |
|---------------|-----------|-------|
| Số liệu/kết quả của tool khác | **Bắt buộc** | "Slither achieves F1=0.67" |
| Số liệu tổn thất tài chính thực tế | **Bắt buộc** | "$60M DAO hack", ">$10B DeFi losses" |
| Phương pháp/kỹ thuật của người khác | **Bắt buộc** | RAG, Transformer, multi-agent debate |
| Tên tool/framework bên ngoài | **Bắt buộc** | Slither, Mythril, GPTScan, CAMEL, Zep |
| Kiến trúc/thiết kế do mình đề xuất | **Không cần** | MECAP pipeline, 3-layer consensus, agent matrix |
| Kết quả thực nghiệm của mình | **Không cần** | "MECAP achieves F1=X on SmartBugs" |
| Khái niệm phổ biến trong domain | **Không cần** | "Smart contracts are immutable" |
| Dataset mình dùng | **Bắt buộc** | SmartBugs Curated, DeFiHackLabs |

---

## Checklist viết từng phần

### [ ] 1. Abstract + Keywords
- [ ] ~150 từ, không dùng ký hiệu toán/đặc biệt
- [ ] Bao gồm: vấn đề → phương pháp → kết quả chính
- [ ] Keywords: 4–6 từ (smart contract, multi-agent, vulnerability detection, knowledge graph, consensus mechanism)
> **Trích dẫn**: Không cần cite trong Abstract

### [ ] 2. Giới thiệu (Introduction)
- [ ] Vấn đề: tính bất biến + rủi ro tài chính của smart contract
- [ ] Khoảng trống: công cụ hiện tại (phân tích tĩnh → bỏ sót logic; single-LLM → FP cao; không kiểm tra exploitability)
- [ ] Giải pháp: MECAP — multi-expert panel + KG grounding
- [ ] Đóng góp (bulleted C1–C5):
  - C1: Framework đa chuyên gia đầu tiên cho kiểm toán smart contract
  - C2: Contract KG grounding giảm hallucination
  - C3: Attacker profiles xác nhận exploitability
  - C4: Đồng thuận 3 lớp giảm FP so với single-LLM
  - C5: Phủ lỗ hổng DeFi đặc thù
> **Trích dẫn cần có**:
> - Số liệu tổn thất: DAO hack $60M, tổng DeFi losses >$10B → cite DeFiLlama hoặc bài báo tổng hợp
> - Tên tool khi nhắc đến: Slither [cite], Mythril [cite], GPTScan [cite]
> - Hạn chế của tool khác khi claim cụ thể: "GPTScan does not assess exploitability" → cite GPTScan
> **Không cần cite**: mô tả vấn đề chung, mô tả giải pháp MECAP, danh sách đóng góp

### [ ] 3. Công trình liên quan (Related Work)
- [ ] Phân tích tĩnh: Slither [cite], Mythril [cite]
- [ ] LLM-based: GPTScan [cite], AuditGPT [cite]
- [ ] Multi-agent LLM: CAMEL [cite], AgentVerse [cite], LLM Debate [cite]
- [ ] Knowledge graph + RAG [cite]
- [ ] Kết thúc bằng phát biểu khoảng trống rõ ràng
> **Trích dẫn cần có**: Toàn bộ phần này — mỗi tool/framework/paper được nhắc đến đều phải cite
> **Không cần cite**: câu tổng kết gap do mình phát biểu ("None of the above combines X, Y, and Z")

### [ ] 4. Kiến trúc hệ thống (System Architecture)
- [ ] Hình 1: Tổng quan pipeline MECAP (5 pha)
- [ ] 4.1 Contract Knowledge Graph Builder
- [ ] 4.2 Ma trận Agent — 17 chuyên gia + 5 attacker profiles
- [ ] 4.3 Phiên kiểm toán 3 pha (Phase A → B → C)
- [ ] 4.4 Công thức đồng thuận 3 lớp (w=0.30/0.45/0.25, ngưỡng=0.35)
> **Trích dẫn cần có**:
> - Khi nhắc đến SWC Registry → cite
> - Khi nhắc đến Zep, CAMEL/OASIS làm nền tảng → cite
> - Khi nhắc đến kỹ thuật RAG để giải thích KG grounding → cite Lewis et al.
> - Khi so sánh 3-layer consensus với voting ensemble trong ML → cite Dietterich
> **Không cần cite**: mô tả thiết kế MECAP, công thức tự đề xuất, agent matrix tự xây dựng

### [ ] 5. Đánh giá & Kết quả (Evaluation & Results)
- [ ] Bảng 1: MECAP vs Slither vs Mythril vs GPTScan (P/R/F1)
- [ ] Dataset: SmartBugs Curated 143 contracts, 10 danh mục SWC
- [ ] Tiêu chí đạt: Macro F1 ≥ 0.75, Precision ≥ 0.60, Recall ≥ 0.80
- [ ] Ablation study (V1–V5): đóng góp từng thành phần
- [ ] DeFiHackLabs real-world subset (15–20 contracts)
> **Trích dẫn cần có**:
> - SmartBugs Curated dataset → cite Durieux et al.
> - DeFiHackLabs → cite
> - Số liệu F1 của Slither/Mythril/GPTScan trong bảng so sánh → cite nguồn gốc
> - Định nghĩa Precision/Recall/F1 nếu có → không cần (quá phổ biến)
> **Không cần cite**: kết quả thực nghiệm của MECAP, cách tính ablation, nhận xét phân tích của mình

### [ ] 6. Kết luận (Conclusion)
- [ ] Tóm tắt đóng góp C1–C5
- [ ] 1–2 câu hướng mở rộng
> **Trích dẫn**: Thường không cite trong Conclusion — chỉ cite nếu nhắc tên tool cụ thể

### [ ] 7. references.bib (~15–20 mục)

> Tất cả link đã được verify — bạn confirm từng mục trước khi thêm vào .bib

#### Financial / Background Statistics
- [ ] **DAO Hack** — Mehar et al. (2019) — JCIT Vol.21 No.1 ⚠️ Dùng $50M, không phải $60M
  - *Understanding a Revolutionary and Flawed Grand Experiment in Blockchain: The DAO Attack*
  - DOI: https://doi.org/10.4018/JCIT.2019010102
- [ ] **DeFi Crime Losses ~$10B** — Carpentier-Desjardins et al. (2025) — Journal of Cybersecurity
  - *Mapping the DeFi crime landscape: an evidence-based picture*
  - DOI: https://doi.org/10.1093/cybsec/tyae029

#### FP Rate Evidence
- [ ] **Empirical Review 47,587 contracts** — Durieux, Ferreira, Abreu, Cruz (2020) — ICSE 2020
  - *Empirical Review of Automated Analysis Tools on 47,587 Ethereum Smart Contracts*
  - arXiv: https://arxiv.org/abs/1910.10601
  - DOI: https://dl.acm.org/doi/10.1145/3377811.3380364

#### Static Analysis Tools
- [ ] **Slither** — Feist, Grieco, Groce (2019) — WETSEB 2019
  - *Slither: A Static Analysis Framework For Smart Contracts*
  - https://arxiv.org/abs/1908.09878
- [ ] **Mythril** — Mueller / ConsenSys (2018) — ⚠️ Không có peer-reviewed paper, chỉ có GitHub + HITB talk
  - Cite bằng GitHub: https://github.com/ConsenSysDiligence/mythril
  - → Cần confirm: dùng GitHub citation hay bỏ qua?

#### LLM-based Audit
- [ ] **GPTScan** — Sun et al. (2024) — ICSE 2024 ⚠️ (plan ghi 2023, thực tế venue là ICSE 2024)
  - *GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis*
  - arXiv: https://arxiv.org/abs/2308.03314
  - ACM DL: https://dl.acm.org/doi/10.1145/3597503.3639117
- [ ] **AuditGPT** — Xia et al. (2024) — arXiv preprint (chưa peer-review)
  - *AuditGPT: Auditing Smart Contracts with ChatGPT*
  - https://arxiv.org/abs/2404.04306
- [ ] **SmartInv** — Wang, Pei, Yang (2024) — IEEE S&P 2024
  - *SmartInv: Multimodal Learning for Smart Contract Invariant Inference*
  - https://arxiv.org/abs/2411.09217

#### Dataset & Benchmark
- [ ] **SmartBugs** — Ferreira, Cruz, Durieux, Abreu (2020) — ASE 2020
  - *SmartBugs: A Framework to Analyze Solidity Smart Contracts*
  - arXiv: https://arxiv.org/abs/2007.04771
  - DOI: https://doi.org/10.1145/3324884.3415298
- [ ] **DeFiHackLabs** — SunWeb3Sec — GitHub repository
  - https://github.com/SunWeb3Sec/DeFiHackLabs

#### Multi-Agent LLM
- [ ] **CAMEL** — Li et al. (2023) — NeurIPS 2023
  - *CAMEL: Communicative Agents for "Mind" Exploration of Large Language Model Society*
  - https://arxiv.org/abs/2303.17760
- [ ] **AgentVerse** — Chen et al. (2023) — ICLR 2024
  - *AgentVerse: Facilitating Multi-Agent Collaboration and Exploring Emergent Behaviors*
  - https://arxiv.org/abs/2308.10848
- [ ] **LLM Debate** — Du et al. (2023) — ICML 2024
  - *Improving Factuality and Reasoning in Language Models through Multiagent Debate*
  - https://arxiv.org/abs/2305.14325
- [ ] **OASIS** — Yang et al. (2024) — arXiv preprint
  - *OASIS: Open Agent Social Interaction Simulations with One Million Agents*
  - https://arxiv.org/abs/2411.11581

#### Knowledge Graph & RAG
- [ ] **RAG** — Lewis et al. (2020) — NeurIPS 2020
  - *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks*
  - https://arxiv.org/abs/2005.11401

#### Smart Contract Background
- [ ] **SWC Registry** — Community (EIP-1470) — ⚠️ Không có tác giả cụ thể
  - Official: https://swcregistry.io/
  - GitHub: https://github.com/SmartContractSecurity/SWC-registry
- [ ] **The DAO Hack** — Mehar et al. (2019) — JCIT Vol.21 No.1
  - *Understanding a Revolutionary and Flawed Grand Experiment in Blockchain: The DAO Attack*
  - DOI: https://doi.org/10.4018/JCIT.2019010102
- [ ] **DeFiLlama** — Community platform — cite như website
  - https://defillama.com/

### [ ] 8. Hình 1 — Tổng quan hệ thống
- [ ] TikZ hoặc PDF/PNG ngoài (pipeline: Input → KG → Agents → Session → Consensus → Report)
- [ ] Vừa 1 cột (~3.5in)

### [ ] 9. Bảng 1 — So sánh với baseline
- [ ] Cột: Công cụ | Phương pháp | F1 | Precision | Recall | Exploitability | DeFi Coverage
- [ ] Hàng: Slither | Mythril | GPTScan | MECAP (đề xuất)
- [ ] Ghi chú: GPTScan F1=0.88 đo trên tập con, không phải toàn bộ SmartBugs

### [ ] 10. Lắp ráp file .tex
- [ ] Điền tên tác giả + đơn vị công tác
- [ ] Kết nối references.bib với \bibliographystyle{IEEEtran}
- [ ] Kiểm tra số trang — cắt bớt nếu > 6.5 trang
- [ ] Sửa lỗi: `\section{Releated work}` → `\section{Related Work}`
- [ ] Sửa: `\section*{Cảm tạ}` → `\section*{Acknowledgment}`

### [ ] 11. Hoàn thiện
- [ ] Đọc lại toàn bộ tiếng Anh
- [ ] Kiểm tra mọi claim đều có trích dẫn hoặc số liệu
- [ ] Kiểm tra tất cả \ref và \cite được resolve
- [ ] Compile không lỗi/cảnh báo

---

## Các con số quan trọng cần đưa vào bài

| Chỉ số | Giá trị |
|--------|---------|
| Tổng số agent | 22 (17 chuyên gia + 5 attacker) |
| Số domain | 5 (AppSec, Blockchain, Cryptography, DeFi, Governance) |
| Số pha kiểm toán | 3 (Intra-domain → Cross-domain → Attacker challenge) |
| Trọng số đồng thuận | L1=0.30, L2=0.45, L3=0.25, ngưỡng=0.35 |
| SWC Registry | 40 loại lỗ hổng |
| Dataset SmartBugs | 143 contracts, 10 danh mục SWC |
| Mục tiêu Macro F1 | ≥ 0.75 |
| Mục tiêu Precision | ≥ 0.60 |
| Mục tiêu Recall | ≥ 0.80 |
| Baseline Slither F1 | 0.67 (trên toàn bộ SmartBugs Curated) |
| Chi phí ước tính | ~$1–5 / contract |

---

## Thứ tự viết đề xuất

```
1. Abstract        → xác định narrative tổng thể
2. Introduction    → đặt vấn đề + liệt kê đóng góp
3. Related Work    → định vị MECAP so với SOTA
4. Hình 1          → làm rõ kiến trúc trước khi viết
5. Section 3       → đóng góp kỹ thuật cốt lõi
6. Bảng 1          → neo phần đánh giá
7. Section 4       → đánh giá kèm số liệu
8. Conclusion      → tóm gọn
9. references.bib  → điền song song trong quá trình viết
10. Lắp ráp + hoàn thiện
```

---

*Cập nhật lần cuối: 19/04/2026*
