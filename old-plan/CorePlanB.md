# Tài liệu kế hoạch: Social Engineering Simulation Engine

Dựa trên nền tảng MiroFish — **Hướng B**

## 1. Ý tưởng

### Vấn đề cốt lõi

Phòng thủ an toàn thông tin hiện nay tập trung quá nhiều vào lớp kỹ thuật trong khi bỏ qua lớp con người:

| Vấn đề | Thực tế |
| --- | --- |
| Yếu tố con người bị đánh giá thấp | 82% breach có liên quan đến human element (Verizon DBIR 2024) |
| Đánh giá awareness thiếu thực tế | Khảo sát, quiz, e-learning không phản ánh hành vi thật dưới áp lực công việc |
| Không biết ai là weakest link | Doanh nghiệp không biết phòng ban nào, vai trò nào, thời điểm nào dễ bị tấn công nhất |
| Training theo kiểu "1 lần/năm" | Nhân viên quên 80% nội dung sau 6 tuần; không có cơ chế reinforcement liên tục |

### Ý tưởng giải quyết

Tái sử dụng kiến trúc MiroFish — thay vì mô phỏng hành vi người dùng trên mạng xã hội, mô phỏng **hành vi nhân viên trong tổ chức trước các chiến dịch tấn công Social Engineering**:

- **AttackerAgent (Red)**: Threat actor AI lựa chọn pretext, kênh tấn công, và target dựa trên OSINT thu thập được từ knowledge graph tổ chức. Thích nghi chiến thuật qua từng round dựa trên tỷ lệ thành công.
- **EmployeeAgent**: Nhân viên AI với security awareness score, workload, stress level, trust threshold, và mạng lưới tin tưởng với đồng nghiệp. Quyết định "click / tuân thủ / báo cáo" dựa trên context và peer behavior.
- **SOCAgent / SecurityTeamAgent (Blue)**: Phân tích cảnh báo từ email gateway, phát hiện anomaly, đưa ra phản ứng và điều chỉnh kiểm soát.
- **Environment**: Cơ cấu tổ chức, văn hóa bảo mật, và lịch sử training được encode vào Zep Knowledge Graph.

**Kết quả emergent** — không lập trình kịch bản cứng — tỷ lệ thành công tấn công, đường lan truyền qua trust network, và các khoảng trống awareness xuất hiện tự nhiên từ tương tác agent, phản ánh thực tế hành vi tổ chức tốt hơn bất kỳ bài khảo sát nào.

### Tại sao MiroFish phù hợp đặc biệt

MiroFish ban đầu được xây để mô phỏng **hành vi con người lan truyền thông tin trên mạng xã hội**. Social Engineering Simulation về bản chất là **cùng một mô hình** — chỉ thay môi trường từ Twitter/Reddit sang môi trường tổ chức doanh nghiệp. Đây là extension tự nhiên nhất của MiroFish, tái sử dụng được 70–80% kiến trúc lõi.

---

## 2. Phạm vi triển khai

### Trong phạm vi (luận án thạc sĩ 1.5–2 năm)

- Mô phỏng 4 loại tấn công phổ biến nhất: Spear Phishing, CEO/BEC Fraud, Vishing (voice phishing), và Pretexting qua email.
- Tối thiểu 4 loại EmployeeAgent: C-level/Executive, Finance/Accounting, IT Staff, General Employee — mỗi loại có risk profile và decision model khác nhau.
- Trust network giữa nhân viên: hành vi lan truyền qua mạng lưới tin tưởng (ai forward email lừa đảo cho đồng nghiệp, ai cảnh báo lại).
- Workload & stress modeling: nhân viên bận → threshold cảnh giác giảm → dễ bị tấn công hơn.
- Security awareness decay: hiệu quả training giảm dần theo thời gian nếu không có reinforcement.
- Phân tích kết quả: click rate, report rate, dwell time, lan truyền lateral qua trust network.
- After-Action Review tự động: báo cáo weakest link, thời điểm nguy hiểm, khuyến nghị training.
- Web UI tái sử dụng từ MiroFish với điều chỉnh giao diện phù hợp.

### Ngoài phạm vi (có thể mở rộng sau)

- Tích hợp thật với email server (send phishing email thật).
- Vishing qua voice/phone call simulation.
- Physical security (tailgating, USB drop) — quá phức tạp để model.
- Quy mô tổ chức hàng nghìn nhân viên.
- Tích hợp LMS để trigger training tự động sau simulation.

---

## 3. MiroFish hiện có / Cần xây thêm

### Hiện có — tái dùng trực tiếp

| Component hiện tại | Vai trò trong SE Simulation |
| --- | --- |
| ZepEntityReader + Zep Cloud | Lưu org structure, employee profiles, trust network, training history |
| OASISProfileGenerator | → EmployeeProfileGenerator: tạo persona nhân viên với risk attributes |
| SimulationManager + SimulationRunner | Orchestrate round Red vs. Blue trong môi trường tổ chức |
| simulation_ipc.py | Stream sự kiện tấn công/phản ứng real-time về UI |
| ReportAgent (ReACT) | → AwarenessGapAgent: phân tích weakest link và training gap |
| ZepToolsService | Truy vấn trust network, tìm propagation path của tấn công |
| LLMClient | Backbone LLM cho quyết định của mọi agent |
| Task model (async) | Giữ nguyên — simulation nền, poll status |
| Flask API + Vue 3 frontend | Giữ skeleton, điều chỉnh UI |

### Cần xây mới — phần cốt lõi

**Backend** (`backend/app/services/`):

```text
├── org_structure_builder.py       # Mới: parse mô tả tổ chức → Zep graph
│                                  #   - Employee, Department, Role, ReportingLine
│                                  #   - Trust network (ai làm việc gần ai)
│                                  #   - OSINT exposure score (LinkedIn, web presence)
├── se_attack_library.py           # Mới: thư viện tấn công SE
│                                  #   - Attack templates: Phishing, BEC, Vishing, Pretexting
│                                  #   - Pretext generator (dùng LLM tạo nội dung thuyết phục)
│                                  #   - Targeting logic: chọn target theo role + graph
├── employee_agent.py              # Mới: engine quyết định nhân viên
│                                  #   - Decision model: click / comply / report / ignore
│                                  #   - Factors: awareness_score, workload, stress, trust_sender
│                                  #   - Awareness decay function theo thời gian
│                                  #   - Peer influence: nếu colleague click → threshold giảm
├── attacker_agent.py              # Mới: engine quyết định kẻ tấn công
│                                  #   - OSINT phase: thu thập info từ Zep graph
│                                  #   - Targeting: chọn initial target tối ưu
│                                  #   - Adaptive: điều chỉnh pretext nếu bị từ chối
│                                  #   - Lateral: target người tiếp theo trong trust chain
├── security_team_agent.py         # Mới: SOC/Security team phản ứng
│                                  #   - Monitor: email gateway alerts, user reports
│                                  #   - Response: block sender, alert all-staff, quarantine
│                                  #   - Ràng buộc: capacity, false positive fatigue
├── se_simulation_engine.py        # Mới: game loop chính
│                                  #   - Round-based: mỗi round = 1 giờ làm việc
│                                  #   - Resolve: attacker action → employee decision → blue response
│                                  #   - Propagation: lan truyền qua trust network
│                                  #   - State update: cập nhật compromise status vào Zep
├── awareness_metrics_collector.py # Mới: thu thập metrics
│                                  #   - Click rate, report rate, dwell time
│                                  #   - Phân tích theo dept, role, seniority, time-of-day
│                                  #   - Awareness decay tracking
└── awareness_gap_agent.py         # Mới: After-Action Review (mở rộng ReportAgent)
                                   #   - Phân tích weakest link
                                   #   - Root cause: thiếu training, overload, hay trust network?
                                   #   - Khuyến nghị training có ưu tiên
```

**Frontend** (`frontend/src/components/`):

```text
├── Step1OrgSetup.vue              # Thay Step1GraphBuild: nhập cơ cấu tổ chức
│   └── OrgChartPreview.vue        # D3.js: visualize org chart + trust network
├── Step2CampaignSetup.vue         # Thay Step2EnvSetup: cấu hình chiến dịch SE
├── Step3SESimulation.vue          # Thay Step3Simulation: battle view realtime
│   ├── OrgHeatmap.vue             # D3.js: heatmap phòng ban theo click rate
│   └── PropagationGraph.vue       # D3.js: visualize lan truyền qua trust network
├── Step4AwarenessReport.vue       # Thay Step4Report: dashboard weakest link
└── Step5Debrief.vue               # Thay Step5Interaction: chat với bất kỳ agent
                                   #   "Tại sao bạn click vào email đó?"
```

**Data / schema — cần định nghĩa mới:**

- `Employee` (id, name, department, role, seniority, osint_exposure_score, awareness_score, workload_level, training_history).
- `TrustRelationship` (source_id, target_id, trust_score, interaction_frequency).
- `SEAttack` (type, pretext_content, channel, target_id, timestamp, outcome).
- `SEEvent` (round, agent_id, action, decision, reason, propagated_to[]).
- `SimulationMetrics` (click_rate, report_rate, dwell_time, lateral_spread, weakest_dept).

---

## 4. Input

Người dùng cung cấp **3 loại** đầu vào.

### Input 1: Mô tả cơ cấu tổ chức

Có thể là:

- File văn bản / PDF: sơ đồ tổ chức, danh sách nhân viên theo phòng ban.
- Mô tả dạng text (ví dụ): *"Công ty 200 người, phòng Kế toán 15 người xử lý nhiều giao dịch, IT 5 người, Sales 40 người thường xuyên contact khách hàng ngoài"*.
- *(Tương lai)* Export từ HR system (HRIS).

Hệ thống dùng LLM parse → nạp Zep Graph với các quan hệ:

- Employee → thuộcPhòng → Department.
- Employee → báoCáoVới → Manager.
- Employee → tươngTácNhiềuVới → Employee (trust network — ai làm việc gần ai).
- Employee → có → RiskProfile (OSINT exposure, training recency, workload).
- Department → có → CultureScore (mức độ security-conscious).

### Input 2: Thông số chiến dịch

```jsonc
{
  "campaign_name": "APT nhắm vào công ty tài chính Q1",
  "attack_types": ["spear_phishing", "bec_fraud"],
  "attacker_profile": {
    "sophistication": "APT",         // "opportunistic" | "targeted" | "APT"
    "initial_osint": "linkedin",     // nguồn OSINT kẻ tấn công dùng
    "patience_level": "high"         // ảnh hưởng tốc độ tấn công
  },
  "environment": {
    "simulation_rounds": 40,         // mỗi round = 1 giờ làm việc
    "work_schedule": "8x5",          // giờ làm việc của nhân viên
    "current_workload": "high",      // mùa cao điểm (tháng báo cáo, kiểm toán)
    "last_training_weeks_ago": 24    // training gần nhất cách đây bao lâu
  },
  "blue_team": {
    "email_gateway": true,           // có lọc spam/phishing không
    "security_team_size": 2,
    "incident_response_sla": 4       // giờ
  }
}
```

### Input 3: Lịch sử training và sự cố (tùy chọn)

- Kết quả phishing test thật trước đó (click rate theo phòng ban).
- Lịch sử training: ai đã học gì, khi nào.
- Sự cố bảo mật đã xảy ra: context để model awareness level thực tế.

---

## 5. Output

### Output 1: Realtime simulation feed (trong lúc chạy)

```text
[Round 08 / 40] — Thứ Ba 10:00

ATTACKER → OSINT phase: Thu thập thông tin từ LinkedIn
ATTACKER → Phát hiện: CFO email dạng firstname.lastname@company.com
ATTACKER → Target: Kế toán trưởng (reports to CFO, xử lý wire transfer)

ATTACKER → Gửi BEC email giả CFO: "Chuyển gấp 500tr cho đối tác mới trước 12h"
EMPLOYEE [KT-Agent-02, Kế toán trưởng] → Nhận email
EMPLOYEE → Workload: HIGH (đang vào mùa quyết toán)
EMPLOYEE → Trust check: email domain gần giống thật (company.com vs. c0mpany.com)
EMPLOYEE → Quyết định: COMPLY — gửi yêu cầu chuyển tiền lên ngân hàng
→ COMPROMISED: Bước tấn công thành công

BLUE [SecurityAgent] → Email gateway: không phát hiện (domain gần giống, không có DMARC)
BLUE → Không có alert

ATTACKER → Lateral: KT-Agent-02 forward email "xác nhận" cho KT-Agent-05
EMPLOYEE [KT-Agent-05] → Nhận từ đồng nghiệp tin tưởng → threshold giảm
EMPLOYEE → Quyết định: COMPLY
→ PROPAGATED: Lan truyền qua trust network
```

Hiển thị trên Org Heatmap: phòng ban đổi màu theo mức độ compromise (xanh → vàng → đỏ). PropagationGraph hiển thị đường lan truyền qua trust network theo thời gian thực.

### Output 2: After-Action Review Report

```markdown
# Báo cáo Đánh giá Nhận thức Bảo mật — Chiến dịch Q1

## Tóm tắt
- Tỷ lệ click/comply tổng: 41% (34/83 nhân viên trong simulation)
- Tỷ lệ báo cáo sự cố: 7% (6/83)
- Dwell time trung bình: 2.3 giờ (từ khi attacker gửi đến khi Blue phát hiện)
- Thiệt hại mô phỏng: BEC fraud thành công — 2 yêu cầu chuyển tiền được khởi tạo

## Phân tích theo phòng ban

| Phòng ban      | Tỷ lệ click | Tỷ lệ báo cáo | Điểm rủi ro |
| -------------- | ----------- | ------------- | ----------- |
| Kế toán (15)   | 67%         | 0%            | CRITICAL    |
| C-level (5)    | 20%         | 60%           | LOW         |
| Sales (40)     | 38%         | 5%            | HIGH        |
| IT (5)         | 10%         | 80%           | LOW         |
| HR (8)         | 50%         | 13%           | HIGH        |

## Phân tích theo thời điểm

- Thứ Hai 8:00–9:00: click rate 18% (vừa vào ca, chưa vào guồng)
- Thứ Sáu 16:00–17:30: click rate 61% (cuối tuần, muốn giải quyết nhanh)
- Tháng quyết toán: click rate cao hơn 2.4x so với tháng thường

## Root Cause Analysis

1. **Kế toán — 67% click rate**
   - Training gần nhất: 24 tuần trước → awareness decay đáng kể
   - Workload: HIGH trong mùa quyết toán → threshold cảnh giác giảm
   - Không có quy trình xác minh 2 bước cho wire transfer
   - Không có DMARC → email spoofing không bị chặn

2. **Trust network amplification**
   - 12/34 compromise đến từ lan truyền — nhân viên tin email vì đồng nghiệp forward
   - KT-Agent-02 là "super spreader": compromise 5 người trong trust network

3. **Khoảng trống kỹ thuật**
   - Không có DMARC/DKIM/SPF enforcement
   - Email gateway bỏ qua domain lookalike (c0mpany.com)
   - Không có quy trình Out-of-Band verification cho giao dịch tài chính

## Khuyến nghị (ưu tiên)

### Ưu tiên NGAY (tuần 1–2)
1. [CRITICAL] Bật DMARC enforcement — chặn domain spoofing
2. [CRITICAL] Áp dụng quy trình xác minh phone call cho wire transfer >50tr
3. [HIGH] Micro-training 5 phút cho phòng Kế toán: nhận diện BEC fraud

### Ưu tiên THÁNG NÀY
4. [HIGH] Training targeted cho HR (50% click rate)
5. [MEDIUM] Thiết lập "Phish Alert Button" trong email client
6. [MEDIUM] Simulation lại sau 8 tuần để đo hiệu quả training

### Dài hạn
7. [MEDIUM] Chuyển sang micro-training hàng tháng thay vì annual
8. [LOW] Xem xét Security Champion program trong phòng Kế toán và Sales
```

### Output 3: Exportable artifacts

- PDF báo cáo đầy đủ (cho CISO, ban lãnh đạo).
- JSON metrics (tích hợp security dashboard, GRC tool).
- Simulation replay: tua lại từng round, xem từng quyết định agent.
- Chat với agent: hỏi trực tiếp nhân viên AI — *"Tại sao bạn click vào email đó?"* hoặc hỏi attacker — *"Tại sao bạn chọn Kế toán trưởng là target đầu tiên?"*

---

## 6. Ví dụ kịch bản triển khai cụ thể

### Bối cảnh

- **Khách hàng**: Công ty chứng khoán ABC, 200 nhân viên, team IT 5 người, CISO kiêm nhiệm.
- **Tình trạng**: Đã bị phishing attack 1 lần năm ngoái (nhân viên Sales click link). Training 1 lần/năm, e-learning dạng quiz.
- **Mong muốn**: Biết hiện tại tình trạng awareness thật ra như thế nào trước khi ký hợp đồng SOC outsource.

### Bước 1: Nhập cơ cấu tổ chức (~5 phút)

HR Manager upload mô tả:

```text
Công ty chứng khoán ABC, 200 nhân viên:
- Ban Giám đốc: CEO, CFO, COO (3 người)
- Phòng Môi giới: 60 nhân viên, thường xuyên giao dịch với khách hàng ngoài
- Phòng Kế toán: 15 người, xử lý giao dịch tài chính hàng ngày
- Phòng IT: 5 người, có kiến thức bảo mật tốt hơn
- Phòng HR: 8 người, quản lý dữ liệu nhân viên nhạy cảm
- Phòng Tuân thủ: 6 người, tiếp cận nhiều tài liệu pháp lý
- Back office: 100 nhân viên còn lại
Training gần nhất: 6 tháng trước (online quiz về password)
Sự cố năm ngoái: nhân viên Sales click link trong email giả Amazon
```

Zep graph sau parse (ví dụ quan hệ):

```text
CFO → có → OsintExposure[HIGH] (LinkedIn public profile với email)
KeToan[15] → có → WorkloadLevel[HIGH] (mùa báo cáo tài chính)
KeToan[15] → có → TrainingRecency[24 tuần] → AwarenessScore[LOW]
MoiGioi[60] → thuongXuyenContact → ExternalParties → OsintRisk[HIGH]
IT[5] → có → AwarenessScore[HIGH]
Attacker → cóThể → OsintTừ → LinkedIn[CFO.email = "nguyen.van.a@abc.vn"]
```

### Bước 2: Cấu hình chiến dịch (~2 phút)

```json
{
  "attack_types": ["bec_fraud", "spear_phishing"],
  "attacker_sophistication": "targeted",
  "simulation_rounds": 40,
  "current_period": "month_end_closing",
  "last_training_weeks_ago": 24
}
```

### Bước 3: Simulation chạy (15–25 phút wall-clock)

**Round 1–3: OSINT & Reconnaissance**

```text
ATTACKER → LinkedIn scan: CFO email pattern xác định được
ATTACKER → Web search: tìm thấy tên Kế toán trưởng trong thông cáo báo chí
ATTACKER → Graph build: CFO → supervises → CFO_direct_reports[KT trưởng]
ATTACKER → Kế hoạch: BEC giả CFO nhắm vào KT trưởng trong giờ cao điểm
```

**Round 8–12: Initial Attack**

```text
ATTACKER → Gửi BEC email: từ "nguyen.van.a@abc-vn.com" (lookalike domain)
ATTACKER → Nội dung: "Em xử lý gấp TT 800tr cho đối tác Singapore trước 11h,
           anh đang họp không gọi được. Xác nhận qua email."

EMPLOYEE [KT-01, Kế toán trưởng] → Nhận email lúc 10:47
EMPLOYEE → Workload: CRITICAL (ngày cuối tháng, đang close sổ sách)
EMPLOYEE → Domain check: không để ý "abc-vn.com" khác "abc.vn"
EMPLOYEE → Trust: "CFO thỉnh thoảng email gấp như thế này"
EMPLOYEE → Quyết định: COMPLY → Khởi tạo lệnh chuyển tiền
→ COMPROMISED: Round 8
```

**Round 13–20: Propagation**

```text
ATTACKER → Follow-up email: "Em xác nhận lại với chị [KT-02] nhé"
EMPLOYEE [KT-02] → Nhận forward từ KT-01 (đồng nghiệp tin tưởng)
EMPLOYEE → Trust score với KT-01: 0.87 → threshold giảm mạnh
EMPLOYEE → Quyết định: COMPLY — không kiểm tra lại domain

BLUE [IT-01] → Không alert (email gateway chỉ check blacklist, không check lookalike)
BLUE → Đang xử lý ticket khác
```

**Round 25–30: Detection (muộn)**

```text
EMPLOYEE [KT-05] → Nhận email thứ 3, lần này thấy lạ → GỌI ĐIỆN CHO CFO
CFO → "Anh không gửi email nào hết"
BLUE [IT-01] → Nhận báo cáo → Điều tra → Phát hiện lookalike domain
BLUE → Alert toàn công ty → Block domain
→ DETECTED: Round 28 (sau 20 round = 20 giờ)

Thiệt hại: 2 lệnh chuyển tiền đã được khởi tạo trước khi phát hiện
```

**Round 31–40: Parallel Spear Phishing Campaign**

```text
ATTACKER → Chuyển sang mục tiêu khác: Phòng Môi giới
ATTACKER → Gửi email giả "IT Support": "Hệ thống cần reset password gấp"
EMPLOYEE [MG-12] → Click link fake portal
EMPLOYEE [MG-07] → Report suspicious email → BLUE alert
BLUE → Block campaign trong round 35
→ 8/60 Môi giới compromised trước khi chặn được
```

### Bước 4: After-Action Review

```text
TỔNG KẾT SIMULATION:
Click/Comply rate: 41% (82/200 nhân viên)
Report rate: 7%
Dwell time MTTD: 20 rounds (20 giờ làm việc = 2.5 ngày thật)
BEC success: 2 lệnh TT khởi tạo (800tr + 200tr)

CRITICAL FINDINGS:
1. BEC fraud detection rate: 0% (kỹ thuật) — phát hiện nhờ may mắn user gọi điện
   → Thiếu DMARC, không có OOB verification process cho wire transfer

2. Kế toán: 67% comply rate — cao nhất công ty
   → Training 24 tuần trước + mùa cao điểm + không có quy trình xác minh

3. Trust network amplification: 40% compromise đến từ forward email
   → Một người bị lừa kéo theo nhiều người trong cùng team

4. Detection chỉ nhờ con người, không nhờ tool
   → Không có email security gateway đủ mạnh

SO SÁNH CHI PHÍ:
- Simulation: ~$30–80 API cost
- Phishing test thật (dịch vụ chuyên nghiệp): $5,000–$15,000
- Thiệt hại BEC thật (nếu không phát hiện): 1 tỷ đồng+
```

**Chat sau simulation:**

- **User**: *"KT-01, tại sao bạn không verify lại với CFO qua điện thoại trước khi chuyển tiền?"*
- **KT-Agent-01**: *"Tôi đang close sổ sách cuối tháng, 12 deadline cùng lúc. Email từ địa chỉ trông như của CFO, nội dung khẩn cấp đúng kiểu anh ấy hay gửi. Tôi không có quy trình nào yêu cầu phải gọi điện xác nhận — không ai training cho tôi bước đó. Tôi nghĩ nếu không xử lý nhanh thì lỗi."*

### Giá trị thực tế (so sánh)

| Tiêu chí | Phishing Test truyền thống | SE Simulation (MiroFish) |
| --- | --- | --- |
| Chi phí | $5k–$15k / campaign | $30–$200 (API) |
| Tần suất | 1–2 lần/năm | Không giới hạn |
| Attack types | Thường chỉ email phishing | Đa dạng: BEC, vishing, pretexting |
| Trust network effect | Không model được | Có — thấy lan truyền qua đồng nghiệp |
| Workload/stress factor | Không | Có — click rate thay đổi theo mùa |
| Giải thích tại sao | Không | Có — chat với agent |
| Training recommendation | Generic | Targeted theo phòng ban, thời điểm |
| Replay & học | Không | Có |

---

## 7. Hướng nghiên cứu và khả năng publish

### Research Question đề xuất

> *"Liệu mô hình multi-agent simulation có thể dự đoán chính xác click rate và propagation pattern của Social Engineering attacks trong tổ chức, và từ đó tạo ra khuyến nghị training có hiệu quả cao hơn phương pháp truyền thống?"*

### Evaluation approach

1. **Ground truth**: Chạy simulation → sau đó thực hiện phishing test thật (hoặc dùng data phishing test thật đã có) → so sánh click rate theo phòng ban.
2. **Metric chính**: Pearson correlation giữa predicted click rate (simulation) và actual click rate (real test).
3. **Case study**: Tối thiểu 2 tổ chức khác nhau để chứng minh generalizability.

### Venue publish phù hợp

- **IEEE S&P, ACM CCS, USENIX Security**: competitive nhưng nếu kết quả tốt thì xứng đáng.
- **Computers & Security (Elsevier)**: journal uy tín, phù hợp hơn cho thesis contribution.
- **SOUPS (Symposium On Usable Privacy and Security)**: perfect fit cho human factor security research.
- **ACSAC (Annual Computer Security Applications Conference)**: applied security, rất phù hợp.

---

*Tài liệu phản ánh hiện trạng MiroFish tại commit `1536a79` và kế hoạch luận án thạc sĩ ATTT — Hướng B. Có thể triển khai song song hoặc thay thế Hướng A (CorePlan). Con số chi phí mang tính tham khảo.*
