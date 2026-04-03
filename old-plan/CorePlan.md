# Tài liệu kế hoạch: CyberWar Simulation Engine

Dựa trên nền tảng MiroFish — **Hướng A**

## 1. Ý tưởng

### Vấn đề cốt lõi

Diễn tập an ninh mạng truyền thống (Red Team / Blue Team / Purple Team) có 3 điểm nghẽn lớn:

| Vấn đề            | Thực tế                                                                 |
| ----------------- | ----------------------------------------------------------------------- |
| Chi phí cao       | Một cuộc pentest chuyên nghiệp tốn $20k–$150k; Purple Team exercise tốn $50k–$200k |
| Tần suất thấp     | Doanh nghiệp chỉ diễn tập 1–2 lần/năm — quá ít để xây phản xạ thực chiến |
| Thiếu tính emergent | Red Team con người bị giới hạn bởi kinh nghiệm cá nhân, không cover được attack paths bất ngờ |



### Ý tưởng giải quyết

Tái sử dụng kiến trúc MiroFish — thay vì mô phỏng xã hội trên mạng xã hội, mô phỏng **không gian chiến đấu mạng** với hai phe đối kháng:

- **Red Agents**: Threat actor AI với TTP (Tactics, Techniques, Procedures) từ MITRE ATT&CK, có memory về lịch sử tấn công, học qua các round.
- **Blue Agents**: SOC Analyst AI với kỹ năng, tool, và ràng buộc workload thực tế; phản ứng theo MITRE D3FEND và NIST playbooks.
- **Environment**: Cơ sở hạ tầng mục tiêu encode vào Zep Knowledge Graph (topology, services, lỗ hổng, patch status).

**Kết quả emergent** — không lập trình kịch bản cứng — attack path và khoảng trống phòng thủ xuất hiện tự nhiên từ tương tác agent, phản ánh thực tế tốt hơn pentest script-based.

## 2. Phạm vi triển khai

### Trong phạm vi (luận án thạc sĩ 1.5–2 năm)

- Mô phỏng tấn công theo giai đoạn (Reconnaissance → Initial Access → Lateral Movement → Exfiltration) dựa trên MITRE ATT&CK.
- Tối thiểu 2 loại threat actor (script kiddie và APT-level) với skill profile khác nhau.
- Tối thiểu 2 loại Blue agent (Tier 1 Analyst và Incident Responder) với năng lực khác nhau.
- Topology mạng đơn giản: corporate network với 3–5 subnet zones.
- After-Action Review tự động: báo cáo phân tích gap, detection rate, MTTD/MTTR.
- Web UI tái sử dụng từ MiroFish với điều chỉnh giao diện.

### Ngoài phạm vi (có thể mở rộng sau)

- Môi trường OT/ICS/SCADA.
- Tích hợp real-time với SIEM thật (Splunk, Wazuh).
- Simulation quy mô hàng nghìn agent.
- Môi trường cloud-native và container.
- CI/CD pipeline integration (tự động chạy simulation khi có IaC commit).

## 3. MiroFish hiện có / Cần xây thêm

### Hiện có — tái dùng trực tiếp

| Component hiện tại              | Vai trò trong CyberWar                                                |
| ------------------------------- | --------------------------------------------------------------------- |
| ZepEntityReader + Zep Cloud     | Lưu network topology, CVE graph, quan hệ tài sản                     |
| OasisProfileGenerator           | → CyberActorProfileGenerator: tạo persona Red/Blue                   |
| SimulationManager + SimulationRunner | Orchestrate round Red vs Blue                                  |
| simulation_ipc.py               | Stream sự kiện tấn công/phòng thủ real-time về UI                    |
| ReportAgent (ReACT)             | → AARAgent (After-Action Review): phân tích kết quả                  |
| ZepToolsService                 | Truy vấn attack graph, tìm lỗ hổng liên quan                         |
| LLMClient                       | Giữ nguyên — backbone LLM cho mọi quyết định agent                   |
| Task model (async)              | Giữ nguyên — simulation nền, poll status                             |
| Flask API + Vue 3 frontend      | Giữ skeleton, điều chỉnh UI                                          |

### Cần xây mới — phần cốt lõi

**Backend** (`backend/app/services/`):

```text
├── network_topology_builder.py   # Mới: parse sơ đồ/config mạng → Zep graph
├── mitre_attack_loader.py        # Mới: nạp MITRE ATT&CK TTP làm "action library"
├── mitre_defend_loader.py        # Mới: nạp MITRE D3FEND controls cho Blue agents
├── red_agent.py                  # Mới: engine quyết định Red
│                                 #   - chọn TTP theo trạng thái mạng
│                                 #   - adaptive: học từ round trước
│                                 #   - skill: script kiddie / APT
├── blue_agent.py                 # Mới: engine quyết định Blue
│                                 #   - triage cảnh báo, điều tra, phản ứng
│                                 #   - ràng buộc tài nguyên (attention, fatigue)
│                                 #   - thực thi playbook
├── cyber_simulation_engine.py    # Mới: game loop Red vs Blue
│                                 #   - round-based: mỗi round = 1 "time unit"
│                                 #   - giải quyết hành động tấn công vs phòng thủ
│                                 #   - cập nhật trạng thái mạng vào Zep
├── metrics_collector.py          # Mới: MTTD, MTTR, detection rate
└── aar_agent.py                  # Mới: AAR (mở rộng ReportAgent)
```

**Frontend** (`frontend/src/components/`):

```text
├── Step1NetworkSetup.vue         # Thay Step1GraphBuild: nhập topology, CVE
├── Step2ActorSetup.vue           # Thay Step2EnvSetup: cấu hình Red/Blue
├── Step3CyberSimulation.vue      # Thay Step3Simulation: battle view realtime
│   └── NetworkTopologyMap.vue   # D3.js: tiến trình tấn công trên bản đồ mạng
├── Step4AAR.vue                  # Thay Step4Report: dashboard AAR
└── Step5Debrief.vue              # Thay Step5Interaction: chat với bất kỳ agent
```

**Data / schema** — cần định nghĩa mới:

- NetworkAsset (host, service, danh sách CVE, patch status, zone).
- TTP (map sang MITRE ATT&CK technique ID).
- CyberEvent (hành động tấn công/phòng thủ, outcome, timestamp).
- SimulationMetrics (MTTD, MTTR, coverage, tiến độ kill chain).

## 3.5. Kiến trúc Agent — Số lượng, Giao tiếp, và OASIS

### Số lượng agent mỗi team

Mỗi role nên có **2–3 agent** thay vì 1. Nhiều agent/role tăng coverage và giảm bias, nhưng có giới hạn thực tế cần lưu ý.

#### Red team — nhiều agent tăng attack coverage

```
Red Team (APT group):
  ReconAgent      × 2   → scan attack surface từ nhiều góc độ
  ExploitAgent    × 2   → đề xuất TTP khác nhau, chọn path tốt nhất
  LateralAgent    × 1   → thực thi sau khi có foothold
  ExfilAgent      × 1   → data staging và exfiltration
```

Nhiều Red agent tăng khả năng phát hiện lỗ hổng vì mỗi agent tiếp cận từ góc độ khác nhau:

```
ExploitAgent-1 (web specialist):   "CVE-2021-41773 trên Apache port 443"
ExploitAgent-2 (credential focus): "RDP exposed, thử credential stuffing"
→ 2 attack path khác nhau được khám phá song song
```

**Tuy nhiên**, tăng Red agent có hiệu quả giới hạn nếu thiếu TTP diversity. 1 agent với đầy đủ MITRE ATT&CK library đã cover nhiều angle hơn 3 agent không có structure:

```
1 APT agent + TTP library đầy đủ:
  Recon phase:          10 technique khác nhau để chọn
  Initial Access phase: 9 technique
  Lateral Movement:     9 technique
  → Đã cover nhiều attack angle theo framework

3 APT agent không có TTP structure:
  → Cả 3 có thể converge về cùng approach
  → Không đảm bảo coverage tốt hơn
```

#### Blue team — nhiều agent tăng detection capacity, không phải detection capability

```
Blue Team (SOC):
  Tier1Analyst    × 3   → triage alert queue song song (bottleneck thật)
  Tier2Analyst    × 2   → điều tra sâu, threat hunting
  IncidentResponder × 1 → isolate, contain, remediate
  SOCManager      × 1   → quyết định escalate, communicate lãnh đạo
```

Nhiều Tier1 analyst giúp xử lý nhiều alert hơn song song — đây là bottleneck thật của SOC:

```
3 Tier1Analyst xử lý đồng thời:
  Analyst-1 thấy: PowerShell event trên WKSTN-042
  Analyst-2 thấy: Unusual auth lúc 3am trên FileServer
  Analyst-3 thấy: Large data transfer ra ngoài
  → Kết hợp 3 signal → nhận ra attack chain
  → 1 analyst một mình có thể bỏ qua 2 trong 3 signal vì overload
```

**Giới hạn quan trọng**: bottleneck thật của Blue là **tool capability**, không phải số người:

```
10 analyst KHÔNG CÓ SIEM:
  → Tất cả đọc log thủ công
  → Vẫn miss lateral movement lúc 3am vì không có alert

1 analyst CÓ SIEM tốt:
  → SIEM correlate event tự động
  → Analyst nhận alert đã được prioritize
  → Detect được nhiều hơn 10 analyst không có tool

→ Simulation phải reflect điều này:
  Blue agent với tools_available=[] sẽ miss nhiều dù có 5 analyst
  Blue agent với tools_available=["SIEM","EDR"] sẽ detect tốt hơn dù chỉ 2 analyst
```

#### Diminishing returns — ngưỡng hợp lý

```
2 → 3 agent/role: tăng coverage đáng kể
3 → 5 agent/role: tăng ít, bắt đầu lặp lại kết quả
5 → 10 agent/role: gần như không cải thiện thêm, unrealistic

→ Ngưỡng hợp lý: 2–3 agent/role
→ Tổng toàn simulation: ~10–12 agent (realistic với APT group + SOC thật)
→ Tăng lên 30–50 sẽ không cải thiện đáng kể và mất tính realistic
```

### Giao tiếp nội bộ team — OASIS Feed

Hai team dùng OASIS feed riêng biệt cho giao tiếp nội bộ, tương tự MiroFish gốc:

#### Blue Team Feed — phù hợp nhất, giống SOC thật

SOC thực tế hoạt động chính xác theo mô hình social feed: analyst cùng nhìn SIEM, comment phân tích, build on nhau. OASIS tái sử dụng trực tiếp cho use case này.

```
[Blue Internal Feed — Round 12]

SIEM-bot POST:
  "Alert: Unusual auth from WKSTN-042 → FileServer01 lúc 03:14AM"

Tier1Agent-1 REPLY:
  "WKSTN-042 thuộc Kế toán, không ai làm việc 3am. Suspicious."

Tier1Agent-2 REPLY:
  "Round 8 có helpdesk ticket FileServer chậm — có thể liên quan."

Tier2Agent REPLY:
  "Check rồi — WKSTN-042 có PowerShell event round 8.
   Đây là lateral movement pattern. Escalate ngay."

SOCManagerAgent REPLY:
  "Isolate WKSTN-042 và FileServer01. Tier2 pull full log từ round 8."
```

Insight "nhớ lại round 8" emerge từ feed — không ai lập trình trước.

#### Red Team Feed — hữu ích khi có nhiều agent cùng role

Với Red team có 2+ agent/role, OASIS feed mô phỏng APT war room nội bộ:

```
[Red Internal Feed]

ReconAgent-1 POST:  "WKSTN-042: no EDR, PowerShell 5.1 unrestricted"
ReconAgent-2 POST:  "FileServer01 RDP accessible từ internal, no MFA"

ExploitAgent-1 REPLY: "T1059 PowerShell trên WKSTN trước, ít noise"
ExploitAgent-2 REPLY: "Đồng ý. Sau đó T1078 Pass-the-Hash sang FileServer"

LateralAgent REPLY:   "Nhận. Tôi chuẩn bị pivot path FileServer → DBServer."
```

#### Bản chất khác nhau giữa Red và Blue feed

| | Blue feed | Red feed |
|---|---|---|
| Ai "post" | SIEM-bot (tự động) + Analyst | Agent tự post intel |
| Luồng thông tin | Parallel — nhiều analyst cùng nhìn 1 event | Sequential — Recon feed cho Exploit |
| OASIS fit | Rất cao — giống social feed tự nhiên | Trung bình — có thể dùng direct call |
| Nên implement | Ưu tiên cao | Ưu tiên nếu có 3+ Red agents |

### Kiến trúc tổng thể giao tiếp

```
┌───────────────────────────────────────────┐
│         RED OASIS FEED (nội bộ)           │
│  ReconAgent×2 ↔ ExploitAgent×2            │
│  Chia sẻ intel, vote attack path          │
└──────────────────┬────────────────────────┘
                   │ Red team action (consensus)
                   ▼
┌───────────────────────────────────────────┐
│       SIMULATION ENGINE (xây mới)        │
│  Nhận action → resolve outcome            │
│  Cập nhật Network State (Zep)             │
│  Generate alerts → đẩy vào Blue Feed     │
└──────────────────┬────────────────────────┘
                   │ Alerts + events
                   ▼
┌───────────────────────────────────────────┐
│         BLUE OASIS FEED (nội bộ)          │
│  SIEM-bot → Tier1×2 → Tier2 → IR → Mgr   │
│  Phân tích, escalate, respond             │
└───────────────────────────────────────────┘
```

### So sánh với MiroFish hiện tại

MiroFish có 50 agent nhưng mỗi agent đại diện một **entity khác nhau** từ knowledge graph — không phải nhiều agent cùng role thảo luận với nhau. Mỗi agent hành động độc lập theo persona của nó, không có cơ chế đồng thuận trong cùng role.

Plan A cải tiến điểm này bằng cách có **2–3 agent/role thảo luận qua OASIS feed** trước khi đưa ra quyết định tập thể — giảm bias của single LLM call và tăng chất lượng quyết định.

### Đây là Simulation hay Prediction?

Plan A là **simulation thật**, không phải agents đoán một lần:

```
Prediction (KHÔNG phải Plan A):
  Input → LLM → "Kẻ tấn công sẽ làm X, Y, Z" → output tĩnh

Simulation (Plan A):
  Round 1: Red recon → phát hiện Exchange 2016
  Round 5: Red exploit → SUCCESS → network state thay đổi
  Round 8: Red lateral move → CHỈ KHẢ THI vì Round 5 thành công
  Round 12: Blue detect anomaly → DỰA TRÊN hành động Round 8
  ...
  Kết quả Round N+1 phụ thuộc Round N — phải chạy mới biết kết quả
```

Tương tự chess engine — không "predict" nước đi, mà *chơi* từng nước và kết quả emerge từ tương tác. Đây là điểm phân biệt Plan A với các tool phân tích tĩnh như Checkov hay CVSS scoring.

## 4. Input

Người dùng cung cấp **3 loại** đầu vào.

### Input 1: Mô tả hạ tầng mạng mục tiêu

Hệ thống hỗ trợ 2 chế độ nhập, có thể dùng riêng hoặc kết hợp:

#### Chế độ A — Mô tả văn bản (mặc định, luôn hỗ trợ)

- File văn bản / PDF: tài liệu kiến trúc mạng, kho tài sản.
- Sơ đồ dạng text (ví dụ): *"1 DMZ với 2 web server, mạng nội bộ với file server và workstation, database server tách biệt"*.

Hệ thống dùng LLM parse → nạp Zep Graph. Phù hợp với mọi doanh nghiệp kể cả không dùng IaC.

#### Chế độ B — IaC files + văn bản bổ sung (tùy chọn, tăng độ chính xác)

Nếu doanh nghiệp đang dùng Infrastructure as Code, upload IaC **kèm theo** văn bản mô tả human factor (không dùng IaC một mình vì thiếu context con người):


- **Terraform** (`.tf`): AWS/GCP/Azure resources, security groups, IAM roles
- **Kubernetes** (`.yaml`): deployments, services, network policies
- **Docker Compose** (`.yml`): container topology, port mappings, networks
- **Ansible** (`.yml`): host inventory, service configurations

Parser đọc file code thay vì dùng LLM → graph chính xác hơn, không bị LLM hallucinate topology:

```
Thay vì LLM đoán từ văn bản:          Parser đọc trực tiếp từ Terraform:
"web server kết nối database"    →     aws_security_group.db: ingress port=5432
(mơ hồ, thiếu chi tiết)                cidr="0.0.0.0/0" (chính xác, exploitable ngay)
```

**IaC không dùng một mình** — luôn cần văn bản bổ sung:
- IaC làm "xương sống" topology (chính xác: host, port, security rule, IAM)
- Văn bản bổ sung những gì IaC không có: số lượng analyst, ca làm việc, vendor access, quy trình nội bộ

#### Những gì IaC capture được và không capture được

| IaC capture được | IaC KHÔNG capture được |
|---|---|
| Network topology, subnet, firewall rule | Nhân viên, credential con người |
| Service version, port, configuration | Third-party vendor access |
| IAM role, permission | Legacy system chưa migrate lên IaC |
| Container, cloud resource | Shadow IT, quy trình nội bộ |

→ Đây là lý do IaC là **tùy chọn bổ sung**, không phải input bắt buộc.

#### Phần cần xây thêm cho IaC support

```text
backend/app/services/
└── iac_parser.py     # Mới (nếu implement IaC): parse Terraform/K8s/Compose
                      #   - extract host, service, port, security rule
                      #   - map sang NetworkAsset schema
                      #   - nạp vào Zep graph (thay cho LLM extraction)
```

Hệ thống dùng kết quả parse → nạp Zep Graph với các quan hệ:

- Host → có Service → có Vulnerability (CVE).
- Host → thuộc Zone.
- Zone → kết nối Zone (quy tắc firewall).
- User → quyền trên Host.

### Input 2: Thông số diễn tập

```jsonc
{
  "scenario_name": "APT tấn công công ty tài chính",
  "red_team": {
    "actor_type": "APT",           // "script_kiddie" | "APT" | "nation_state"
    "motivation": "data_exfiltration",
    "initial_access": "phishing",  // vector tấn công ban đầu
    "stealth_level": "high"        // ảnh hưởng tốc độ vs. noise
  },
  "blue_team": {
    "analyst_count": 2,
    "tier_mix": { "tier1": 1, "tier2": 1 },
    "tools_available": ["SIEM", "EDR", "firewall"],
    "shift_schedule": "8x5"       // giới hạn giờ làm việc
  },
  "simulation_rounds": 48,         // mỗi round = 1 giờ thực
  "success_criteria": "exfiltrate_database"
}
```

### Input 3: Threat intelligence (tùy chọn)

- CVE feeds (NIST NVD).
- IOC liên quan ngành.
- Báo cáo sự cố trước đó.

## 5. Output

### Output 1: Realtime simulation feed (trong lúc chạy)

```text
[Round 12 / 48]
RED  → Kỹ thuật: T1566.001 Spearphishing Attachment → Target: john.doe@company.com
RED  → Kỹ thuật: T1059.001 PowerShell → Host: WKSTN-042 → Status: SUCCESS
BLUE → Alert triggered: Suspicious PowerShell execution on WKSTN-042
BLUE → Analyst [Tier1-Agent-1] nhận alert → Triage: Medium priority
BLUE → Analyst đang điều tra... (attention: 73%)
RED  → Kỹ thuật: T1078 Valid Accounts → Lateral move → Server: FILE-SRV-01
BLUE → Alert missed (analyst overloaded với 3 alerts đồng thời)
```

Hiển thị trên D3 network map: node đổi màu theo trạng thái (clean / compromised / detected / contained).

### Output 2: After-Action Review report

```markdown
# After-Action Review — APT Simulation #047

## Executive Summary
- Thời gian Red đạt mục tiêu: 31/48 rounds (31 giờ mô phỏng)
- Detection rate: 58% (7/12 attack steps được phát hiện)
- MTTD: 4.2 rounds (~4.2 giờ)
- MTTR: 8.7 rounds (~8.7 giờ)

## Kill Chain Analysis
| Giai đoạn        | TTPs sử dụng   | Detected | Blocked |
| ---------------- | -------------- | -------- | ------- |
| Initial Access   | T1566.001      | ✗        | ✗       |
| Execution        | T1059.001      | ✓        | ✗       |
| Lateral Movement | T1078, T1021   | ✗        | ✗       |
| Exfiltration     | T1048          | ✓        | ✗       |

## Critical Gaps Identified
1. **Blind spot**: Phishing không bị detect → thiếu Email Security Gateway
2. **Alert fatigue**: Tier1 overwhelm round 10–15, miss 3 critical alerts
3. **Lateral movement**: Không có NDR

## Recommendations (ưu tiên theo MITRE D3FEND)
1. [HIGH] Email sandboxing — map D3-EPA
2. [HIGH] Playbook tự động triage Tier1
3. [MEDIUM] Triển khai NDR

## Comparative Analysis
- Detection: 58% vs. benchmark BFSI ~71%
- MTTD: 4.2h vs. ngành ~2.8h
```

### Output 3: Exportable artifacts

- PDF báo cáo đầy đủ (lãnh đạo).
- JSON metrics (tích hợp security dashboard).
- Simulation replay (tua từng round).
- Chat: hỏi agent — ví dụ *"Tại sao không detect alert ở round 12?"*

## 6. Ví dụ kịch bản triển khai cụ thể

### Bối cảnh

- **Khách hàng**: Công ty chứng khoán ABC, ~200 nhân viên, IT 5 người, chưa có SOC chuyên dụng; muốn biết điểm yếu trước khi outsource SOC.
- **Ngân sách**: Không đủ Red Team thật ($30k+).
- **Ước tính CyberWar (API LLM)**: ~$50–200 / simulation đầy đủ.

### Bước 1: Nhập hạ tầng (~5 phút)

IT Manager upload mô tả văn bản (Chế độ A):


```text
Hạ tầng công ty ABC:
- DMZ: 1 web server (Apache 2.4.49 - CVE-2021-41773), 1 mail server (Exchange 2016)
- Internal: 20 workstations Windows 10, 3 file servers, 1 ERP (SAP)
- Database zone: 2 Oracle DB (chứa dữ liệu giao dịch khách hàng)
- Firewall: Fortigate 60F, cho phép RDP nội bộ
- Security tools: Windows Defender, không EDR, không SIEM
- 2 IT analyst, giờ hành chính
```

Hoặc upload file IaC nếu có (Chế độ B — cho graph chính xác hơn):

```hcl
# main.tf — Terraform ví dụ
resource "aws_security_group" "mail" {
  ingress { from_port = 443, to_port = 443, cidr_blocks = ["0.0.0.0/0"] }
}
resource "aws_instance" "mail_server" {
  ami           = "ami-exchange2016"
  instance_type = "t3.large"
  vpc_security_group_ids = [aws_security_group.mail.id]
}
```

Sau parse Zep (ví dụ quan hệ):

```text
WebServer → hasVuln → CVE-2021-41773 (CVSS 9.8)
MailServer → runsService → Exchange2016
Workstations[20] → inZone → Internal
OracleDB → stores → CustomerTradingData (critical asset)
Firewall → allows → RDP_Internal
BlueTeam → has → ITAnalyst[2] → workHours → 8h/day
```

### Bước 2: Cấu hình diễn tập (~2 phút)

```json
{
  "red_actor": "APT",
  "motivation": "steal_trading_data",
  "initial_vector": "auto_select",
  "simulation_rounds": 72,
  "blue_resources": "realistic"
}
```

### Bước 3: Simulation chạy (20–40 phút wall-clock)

**Round 1–5: Reconnaissance**

```text
RED [APT-Agent] → OSINT scan → phát hiện Exchange 2016 exposed
RED → Tìm CVE-2021-26855 (ProxyLogon) → SUCCESS match
RED → Ghi memory: "mail server vulnerable to ProxyLogon"
```

**Round 6–10: Initial access**

```text
RED → Exploit T1190: CVE-2021-26855 trên MailServer → SUCCESS
RED → Drop webshell → WKSTN-foothold
BLUE [ITAnalyst-1] → Không SIEM → không alert
BLUE → Đang xử lý ticket helpdesk
→ MISS: Initial access không detect
```

**Round 11–20: Persistence + discovery**

```text
RED → T1078: Dump credentials từ Exchange → domain admin password hash
RED → T1110.002: Pass-the-hash → FileServer01
RED → Discovery: enumerate shares → path tới Oracle DB
BLUE [ITAnalyst-2] → User báo "login chậm"
BLUE → Check AD manual → login lạ từ MailServer
BLUE → Triage: "Có thể lỗi sync AD" → low priority
→ PARTIAL DETECT: thấy anomaly nhưng mis-classify
```

**Round 21–35: Lateral movement**

```text
RED → RDP FileServer01 → DBServer01 (firewall cho phép RDP internal)
RED → SQLi tool → dump Oracle DB
BLUE [ITAnalyst-1] → Hết giờ (round 25 = 17:00)
BLUE → Không on-call → monitoring dừng
→ CRITICAL GAP: Không có 24/7 monitoring
```

**Round 36–48: Exfiltration (ngoài giờ)**

```text
RED → T1048: Exfiltrate ~50GB trading data qua HTTPS tới C2
RED → SUCCESS — đạt mục tiêu
→ Tổng: 48 rounds (48h mô phỏng ≈ 2 ngày làm việc)
```

### Bước 4: After-Action Review

Kết quả mẫu:

```text
DETECTION RATE: 16% (1/6 attack steps)
MTTD: 18 rounds (một bước detect, và detect sai)
KILL CHAIN: Completed — data exfiltrated

CRITICAL FINDINGS:
1. CVE-2021-26855 (ProxyLogon) chưa patch — CVSS 9.8
   → PATCH trong 24h

2. Không SIEM → 0 automated alerts
   → Recommendation: Wazuh (open-source) trong 1 tuần

3. RDP nội bộ không hạn chế → lateral movement dễ
   → Chặn RDP, dùng Jump Server

4. Không 24/7 monitoring → exfil ngoài giờ
   → Option A: MDR ~$2k/tháng
   → Option B: Alert tự động SMS on-call

COST COMPARISON:
- Simulation: ~$80 API
- Pentest tương đương: $25,000–$40,000
- Thiệt hại breach thật: $2M–$10M (ước lượng)
```

**Chat sau simulation**

- **User**: *"ITAnalyst-1, tại sao login bất thường là low priority ở round 15?"*
- **ITAnalyst-1**: *"Tôi có 12 alert cùng lúc: 3 máy in, 2 reset mật khẩu, 1 báo mạng chậm. Alert AD từ MailServer — không có EDR/SIEM nên không thấy lateral movement. Chỉ có Event Viewer và workload đó nên tôi gán nhầm là lỗi sync AD."*

### Giá trị thực tế (so sánh)

| Tiêu chí           | Pentest truyền thống | CyberWar Simulation        |
| ------------------ | -------------------- | -------------------------- |
| Chi phí            | $25k–$150k           | $50–$500 (API)             |
| Tần suất           | 1–2 lần/năm          | Không giới hạn             |
| Coverage           | Phụ thuộc pentester  | Theo hệ MITRE ATT&CK       |
| Emergent behavior  | Có (người)           | Có (AI adaptive)          |
| Báo cáo sau tập    | 2–4 tuần             | Ngay                       |
| Replay / học       | Không                | Có                         |
| Blue team training | Không                | Có — agent giải thích quyết định |

---

Tài liệu phản ánh hiện trạng MiroFish tại commit `1536a79` và kế hoạch luận án thạc sĩ ATTT. Con số chi phí mang tính tham khảo (báo cáo thị trường 2024).
