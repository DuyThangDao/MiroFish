# Multi-Expert Panel — Kế hoạch Triển khai (Hướng B)

## Tổng quan

### Ý tưởng cốt lõi

Thay vì mô phỏng tấn công theo kiểu Red vs Blue, hệ thống tập hợp **18 agent LLM** được tổ chức theo **2 tầng**:

- **Tầng 1 — Domain Expert Matrix** (13 agents): Chuyên gia bảo mật với Domain Group × Mindset Persona — phân tích hạ tầng từ góc nhìn phòng thủ và kỹ thuật
- **Tầng 2 — Attacker Profile Agents** (5 agents): Đại diện cho các loại kẻ tấn công thực tế — phân tích cùng hạ tầng từ góc nhìn tấn công với motivation và method khác nhau

Hai tầng thảo luận trên OASIS feed, challenge nhau, tạo ra findings đa chiều mà không tầng nào tìm ra được một mình.

### Tầng 1 — Domain Expert Matrix (13 agents)

Mỗi expert agent có **2 chiều định danh** — tương tự cách MiroFish định nghĩa Twitter user với role + persona:

```
DOMAIN GROUP (biết gì)  ×  MINDSET PERSONA (tiếp cận thế nào)
```

```
                    | Offensive        | Defensive        | Architect/Auditor |
--------------------|------------------|------------------|-------------------|
Network Security    | "Làm sao vào     | "Chỗ nào đang    | "Network design   |
                    |  mạng này?"      |  được bảo vệ?"   |  có logic flaw?"  |
--------------------|------------------|------------------|-------------------|
Application Sec     | "CVE nào         | "Config nào      | "API/auth có      |
                    |  exploitable?"   |  đang sai?"      |  design flaw?"    |
--------------------|------------------|------------------|-------------------|
Endpoint Security   | "Sau khi vào 1   | "EDR coverage    | "Patch mgmt       |
                    |  host, đi đâu?"  |  gap ở đâu?"     |  có lỗ hổng?"    |
--------------------|------------------|------------------|-------------------|
Threat Intelligence | "APT nào hay     | "IoC pattern     |        —          |
                    |  dùng vector?"   |  nào phù hợp?"   |                   |
--------------------|------------------|------------------|-------------------|
Risk & Compliance   | "Business impact | "Regulation nào  |        —          |
                    |  nếu bị breach?" |  bị vi phạm?"    |                   |
```

### Tầng 2 — Attacker Profile Agents (5 agents)

Khác với Tầng 1, các agent này **không có domain chuyên môn** — họ đại diện cho profile kẻ tấn công thực tế với motivation và method khác nhau. Diversity đến từ **context và mục tiêu**, không phải từ kiến thức kỹ thuật.

```
Profile 1 — Opportunistic (Script Kiddie):
  Motivation : Cơ hội, không có mục tiêu cụ thể
  Method     : Chỉ dùng public exploit và automated scanner
  Tìm ra     : Low-hanging fruit — default credential, public CVE chưa patch
  Bỏ sót     : Paths phức tạp cần nhiều bước

Profile 2 — APT (Advanced Persistent Threat):
  Motivation : Data exfiltration, espionage, dài hạn
  Method     : Stealth, lateral movement, sống trong mạng lâu dài
  Tìm ra     : Trust relationship giữa zones, credential reuse, persistence path
  Bỏ sót     : Quick wins (không quan tâm nếu gây noise)

Profile 3 — Insider Threat:
  Motivation : Tư lợi, baokham thù, vô tình
  Method     : Dùng legitimate access, biết hạ tầng từ bên trong
  Tìm ra     : Overprivileged account, internal path không monitored, audit gap
  Bỏ sót     : External attack surface (đã ở trong mạng rồi)

Profile 4 — Ransomware Group:
  Motivation : Tài chính, nhanh
  Method     : Speed > stealth, encrypt và exfiltrate nhanh nhất
  Tìm ra     : Backup system exposure, mass file access path, domain admin path
  Bỏ sót     : Stealthy long-term paths (không cần thiết)

Profile 5 — Supply Chain Attacker:
  Motivation : Tấn công nhiều nạn nhân qua 1 điểm
  Method     : Compromise vendor/3rd-party trước, sau đó pivot vào target
  Tìm ra     : External dependency, vendor access không restricted, update mechanism
  Bỏ sót     : Direct attack path (không phải mục tiêu chính)
```

**Tại sao Tầng 2 tạo ra diversity thật sự:**

Cùng 1 RDP port mở, 5 attacker profiles nhìn khác nhau hoàn toàn:
- Opportunistic: *"Thử default password ngay"*
- APT: *"Dùng valid credential thu thập từ phishing, không để lại dấu vết brute force"*
- Insider: *"Tôi đã có RDP access hợp lệ, vào thẳng"*
- Ransomware: *"RDP → Domain Admin → deploy ransomware toàn mạng trong 4 giờ"*
- Supply Chain: *"Không quan tâm RDP — focus vào update server của vendor"*

Đây là **5 findings khác nhau thật sự** từ cùng 1 điểm yếu — không thể đạt được bằng cách thêm mindset persona.

### Tổng quan agent (18 agents)

```
Tầng 1 — Domain Expert Matrix:
  Network Security    × 3 mindsets = 3 agents
  Application Sec     × 3 mindsets = 3 agents
  Endpoint Security   × 3 mindsets = 3 agents
  Threat Intelligence × 2 mindsets = 2 agents
  Risk & Compliance   × 2 mindsets = 2 agents
  ─────────────────────────────────────────────
  Subtotal Tầng 1                  = 13 agents

Tầng 2 — Attacker Profiles:
  Opportunistic + APT + Insider + Ransomware + Supply Chain = 5 agents
  ─────────────────────────────────────────────────────────────────────
  Subtotal Tầng 2                  = 5 agents

  TỔNG CỘNG                        = 18 agents
```

**Vai trò kép của Tầng 2 trong Hướng C:**
Khi nâng cấp lên Hướng C, Attacker Profile agents tự nhiên trở thành **validator cho Attack Graph paths** — mỗi profile đánh giá path từ góc độ "kẻ tấn công như mình có thật sự dùng path này không?" Không cần viết thêm code, chỉ cần assign đúng paths.

### So sánh với MiroFish gốc

| MiroFish gốc | Multi-Expert Panel |
|---|---|
| Input: Tài liệu xã hội (tin tức, bài đăng) | Input: Mô tả hạ tầng mạng (text, IaC) |
| Zep KG: Entity xã hội (người, tổ chức, sự kiện) | Zep KG: Entity bảo mật (host, zone, CVE, service) |
| OASIS: Mạng xã hội Twitter/Reddit | OASIS: Phòng review bảo mật (security_review_room) |
| Agent role: journalist, politician... | Tầng 1 domain: network, appsec, endpoint... |
| Agent persona: emotional, influencer... | Tầng 1 mindset: offensive, defensive, auditor... |
| — | Tầng 2: attacker profiles (APT, insider, ransomware...) |
| Intra-community → cross-community debate | Intra-group → cross-group → attacker challenge |
| Aggregate vote = social prediction | Weighted consensus (expert + attacker) = vuln confidence |
| ReportAgent: Dự đoán xu hướng xã hội | VulnReportAgent: Báo cáo lỗ hổng có độ tin cậy |

### Kiến trúc tổng thể

```
Input: Mô tả hạ tầng (text/IaC)
        ↓
[Phase 1] Network Knowledge Graph
  LLM extract entities → Zep KG
  (Host, Zone, Service, CVE, SecurityControl)
        ↓
[Phase 2] Agent Setup — 18 agents
  Tầng 1: 5 Domain Groups × 2–3 Mindset Personas = 13 agents
  Tầng 2: 5 Attacker Profile agents (cross-domain)
  → Load vào OASIS Security Review Room
        ↓
[Phase 3] Collaborative Analysis Session — 3 phase
  Phase A (round 1–3)  : Intra-group — Domain experts thảo luận nội bộ
  Phase B (round 4–7)  : Cross-group — Domain groups challenge nhau
  Phase C (round 8–10) : Attacker challenge — 5 attacker profiles
                         đọc toàn bộ findings và phản biện/bổ sung
                         từ góc nhìn của kẻ tấn công thực tế
        ↓
[Phase 4] Consensus Engine
  Domain expert findings + Attacker profile findings → merge
  Confidence = expert cross-group weight + attacker corroboration bonus
        ↓
[Phase 5] Vulnerability Report
  VulnReportAgent (ReACT) tổng hợp → Báo cáo có confidence score
        ↓
Output: Vulnerability list (ranked) + Attack profile breakdown
        + Tool gap analysis + Khuyến nghị
```

---

## Tiến độ tổng quan

```
Phase 1 — Network KG Foundation  (Tháng 1–2):  Schema, parser, Zep storage
Phase 2 — Agent Matrix Core      (Tháng 3–4):  Profile generator, OASIS env
Phase 3 — Analysis Session       (Tháng 5–6):  Orchestrator, consensus engine
Phase 4 — Report & API           (Tháng 7–8):  VulnReportAgent, endpoints
Phase 5 — Frontend & Evaluate    (Tháng 9–12): UI, experiment, luận án
```

---

## Phase 1 — Network Knowledge Graph Foundation

### Mục tiêu
Có Zep graph chứa đầy đủ thông tin hạ tầng mạng. Đây là nền tảng để các expert agent tra cứu khi phân tích.

---

### Bước 1.1 — Định nghĩa Security Data Schema

**File cần tạo**: `backend/app/models/cyber_models.py`

Thay thế social entity schema của MiroFish bằng security schema:

```python
@dataclass
class SecurityControls:
    edr: bool = False   # Endpoint Detection & Response
    siem: bool = False  # Security Information & Event Management
    av: bool = False    # Antivirus
    ndr: bool = False   # Network Detection & Response
    waf: bool = False   # Web Application Firewall
    mfa: bool = False   # Multi-Factor Authentication
    dlp: bool = False   # Data Loss Prevention

@dataclass
class NetworkAsset:
    host_id: str              # "WEB-01"
    hostname: str             # "web-server-01"
    ip: str                   # "10.0.1.10"
    zone: str                 # "DMZ" | "Internal" | "Database" | "Management"
    os: str                   # "Ubuntu 22.04"
    services: List[str]       # ["Apache 2.4.49", "OpenSSH 8.9"]
    vulnerabilities: List[str]# ["CVE-2021-41773"]
    patch_status: str         # "patched" | "unpatched" | "partially_patched"
    is_critical: bool         # True nếu là database server, DC, firewall
    controls: SecurityControls

@dataclass
class ExpertFinding:
    finding_id: str
    author_group: str         # "network_security"
    author_persona: str       # "offensive" | "defensive" | "auditor"
    title: str
    description: str
    affected_assets: List[str]
    severity: str             # "critical" | "high" | "medium" | "low"
    confidence: float         # 0.0 – 1.0
    evidence: List[str]       # dẫn chứng cụ thể từ network state
    recommendations: List[str]
    challenged_by: List[str]  # agent nào đã challenge (group/persona)
    validated_by: List[str]   # agent nào đã validate (group/persona)
    cross_group_validated: bool  # có được group KHÁC validate không

@dataclass
class ConsensusVulnerability:
    vuln_id: str
    title: str
    description: str
    affected_assets: List[str]
    severity: str
    confidence_score: float        # weighted theo group authority
    intra_group_agreement: float   # % agents trong cùng group đồng ý
    cross_group_agreement: float   # % agents từ group khác validate
    supporting_groups: List[str]   # domain groups nào đồng ý
    recommendations: List[str]
    mitre_techniques: List[str]
```

**Kiểm tra xong khi**: Import các class không lỗi, `ExpertFinding` có đủ field phân biệt group và persona.

---

### Bước 1.2 — MITRE TTP Reference Library

**File cần tạo**: `backend/app/services/mitre_reference.py`

TTP library dùng làm **tài liệu tham khảo** cho expert agents — inject vào prompt theo domain và persona:

```python
# Top-20 TTP phổ biến theo DBIR 2024
# Phân nhóm theo domain để inject đúng vào agent phù hợp

TTP_BY_DOMAIN = {
    "network_security": ["T1595", "T1190", "T1021.001", "T1021.002"],
    "appsec":           ["T1190", "T1059.001", "T1059.003", "T1566.001"],
    "endpoint_security":["T1059.001", "T1053.005", "T1003.001", "T1027"],
    "threat_intel":     ["T1566.001", "T1078", "T1041", "T1048"],
    "risk":             [],  # Risk group focus vào impact, không vào technique
}

class MitreReference:
    def get_ttp_context_for_agent(self, domain: str, persona: str) -> str:
        """
        Trả về mô tả TTP phù hợp với domain + persona.
        Offensive persona → nhấn mạnh cách exploit.
        Defensive persona → nhấn mạnh cách detect.
        Auditor persona  → nhấn mạnh compliance gap.
        """

    def get_relevant_ttps(self, asset: NetworkAsset, domain: str) -> List[str]:
        """TTP nào có thể áp dụng cho asset + domain này."""

    def get_detection_requirements(self, technique_id: str) -> List[str]:
        """Cần tool gì để detect technique này."""
```

**Kiểm tra xong khi**: `get_ttp_context_for_agent("network_security", "offensive")` khác với `get_ttp_context_for_agent("network_security", "defensive")`.

---

### Bước 1.3 — Network Topology Builder

**File cần tạo**: `backend/app/services/network_topology_builder.py`

Tương tự `graph_builder.py` của MiroFish nhưng với security schema. Reuse `TextProcessor`, `GraphBuilderService`, `TaskManager`.

```python
class NetworkTopologyBuilder:

    def build_from_text_async(self, text: str, graph_name: str) -> str:
        """Async: LLM extract NetworkAsset → lưu vào Zep KG."""

    def build_from_iac_async(self, iac_files: Dict[str, str],
                              extra_text: str, graph_name: str) -> str:
        """Parse Terraform/Docker Compose/K8s + enrich bằng text."""

    def _extract_assets_with_llm(self, text: str) -> List[NetworkAsset]:
        """LLM extract host, CVE, service, zone → JSON strict → NetworkAsset."""

    def _store_to_zep(self, graph_id: str, assets: List[NetworkAsset], text: str):
        """Reuse GraphBuilderService.set_ontology() + add_text_batches()."""
```

**Kiểm tra xong khi**: Upload text mô tả 5 host → Zep graph có đủ node và edge. Query "host nào ở DMZ" trả về đúng.

---

### Bước 1.4 — API Endpoints Phase 1

**File cần tạo**: `backend/app/api/cyber.py` — blueprint riêng, không sửa code cũ.

```
POST /api/cyber/setup
  Body: { text, iac_files, graph_name }
  Return: { task_id, mode }

GET  /api/cyber/task/<task_id>
  Return: { status, progress, result }

GET  /api/cyber/graph/<graph_id>/assets
  Return: { asset_count, assets[] }

GET  /api/cyber/graph/<graph_id>/attack-surface
  Return: { vulnerable_hosts[], risk_summary }
```

**Kiểm tra xong khi**: POST text → task completed → GET assets trả về đúng danh sách host.

---

## Phase 2 — Agent Matrix Core

### Mục tiêu
Có ma trận 13–15 agent với domain và persona khác nhau, sẵn sàng thảo luận trên OASIS Security Review Room theo cơ chế intra-group → cross-group.

---

### Bước 2.1 — Agent Matrix Profile Generator

**File cần tạo**: `backend/app/services/cyber_expert_profile_generator.py`

Tương tự `OasisProfileGenerator` nhưng tạo cả 2 tầng agent:

```python
AGENT_MATRIX = {
    "network_security": {
        "personas": ["offensive", "defensive", "architect"],
        "ttp_focus": ["T1595", "T1190", "T1021.001", "T1021.002"],
        "tools_known": ["ndr", "siem", "firewall"],
        "persona_prompts": {
            "offensive": "Tìm cách xâm nhập vào mạng. Focus vào reachability và exploit path.",
            "defensive": "Xem xét gì đang được bảo vệ tốt và chỗ nào còn gap.",
            "architect": "Đánh giá xem thiết kế network có logic flaw hoặc violation best practice không.",
        }
    },
    "appsec": {
        "personas": ["offensive", "defensive", "auditor"],
        "ttp_focus": ["T1190", "T1059.001", "T1059.003"],
        "tools_known": ["waf", "siem"],
        "persona_prompts": {
            "offensive": "Tìm CVE exploitable và service misconfiguration.",
            "defensive": "Xem xét WAF và input validation có đủ không.",
            "auditor":   "Đánh giá API security và authentication design.",
        }
    },
    "endpoint_security": {
        "personas": ["offensive", "defensive", "admin"],
        "ttp_focus": ["T1059.001", "T1053.005", "T1003.001"],
        "tools_known": ["edr", "av"],
        "persona_prompts": {
            "offensive": "Sau khi vào được 1 host, có thể lateral movement đi đâu?",
            "defensive": "EDR và AV coverage có gap ở host nào?",
            "admin":     "Patch management và hardening có lỗ hổng process không?",
        }
    },
    "threat_intel": {
        "personas": ["apt_analyst", "ir_analyst"],
        "ttp_focus": ["T1566.001", "T1078", "T1041", "T1048"],
        "tools_known": ["siem", "ndr"],
        "persona_prompts": {
            "apt_analyst": "APT group nào có thể target hạ tầng này và dùng vector gì?",
            "ir_analyst":  "Nếu bị tấn công, dấu hiệu nào cần monitor trước?",
        }
    },
    "risk": {
        "personas": ["ciso", "compliance"],
        "ttp_focus": [],
        "tools_known": [],
        "persona_prompts": {
            "ciso":       "Business impact là gì nếu asset critical bị compromise?",
            "compliance": "Vi phạm regulation nào (GDPR, ISO 27001) nếu data bị lộ?",
        }
    },
}

ATTACKER_PROFILES = {
    "opportunistic": {
        "name": "Opportunistic Attacker",
        "motivation": "Cơ hội, không có mục tiêu cụ thể, tìm low-hanging fruit",
        "skill_level": "low",
        "method": "Automated scanner, public exploit, default credential",
        "focus": "Tìm điểm yếu dễ khai thác nhất, nhanh nhất",
        "blind_spot": "Paths phức tạp nhiều bước, cần persistence",
        "prompt": """Bạn là kẻ tấn công cơ hội với kỹ năng thấp.
Bạn chỉ dùng công cụ tự động và public exploit có sẵn.
Nhìn vào hạ tầng này: điểm nào có thể exploit NGAY LẬP TỨC mà không cần kỹ năng cao?
Focus vào: default credential, unpatched CVE có public exploit, service exposed không cần thiết.""",
    },
    "apt": {
        "name": "APT / Nation State Actor",
        "motivation": "Data exfiltration, espionage, dài hạn, không muốn bị phát hiện",
        "skill_level": "expert",
        "method": "Stealth, living-off-the-land, lateral movement, patience",
        "focus": "Tìm path vào crown jewel mà không trigger alert",
        "blind_spot": "Quick wins gây noise — không quan tâm",
        "prompt": """Bạn là APT với nguồn lực cao và rất kiên nhẫn.
Mục tiêu: xâm nhập và TỒN TẠI trong mạng lâu dài mà không bị phát hiện.
Nhìn vào hạ tầng này: path nào đến crown jewel mà ít trigger alert nhất?
Focus vào: trust relationship, credential reuse, legitimate tool abuse, persistence mechanism.""",
    },
    "insider_threat": {
        "name": "Insider Threat",
        "motivation": "Tư lợi, bất mãn, hoặc bị ép buộc bởi bên ngoài",
        "skill_level": "medium",
        "method": "Dùng legitimate access, biết hạ tầng từ bên trong",
        "focus": "Tìm gì có thể làm với quyền hiện có, audit gap",
        "blind_spot": "External attack surface — đã ở trong rồi",
        "prompt": """Bạn là nhân viên nội bộ có legitimate access.
Bạn biết hạ tầng từ bên trong và muốn exfiltrate data hoặc gây hại.
Nhìn vào hạ tầng này: với quyền của một nhân viên thông thường, có thể làm gì?
Focus vào: overprivileged account, internal path không monitored, DLP gap, audit blind spot.""",
    },
    "ransomware": {
        "name": "Ransomware Group",
        "motivation": "Tài chính — nhanh, ồn ào, tối đa hóa thiệt hại",
        "skill_level": "medium-high",
        "method": "Speed > stealth, mass impact, double extortion",
        "focus": "Path đến domain admin nhanh nhất, backup exposure",
        "blind_spot": "Stealthy long-term paths — không cần thiết",
        "prompt": """Bạn là ransomware operator muốn maximize thiệt hại trong thời gian ngắn nhất.
Mục tiêu: encrypt toàn bộ mạng và exfiltrate data để double extortion.
Nhìn vào hạ tầng này: path nào đến Domain Admin / backup system nhanh nhất?
Focus vào: AD path, backup exposure, mass file access, Domain Controller reach.""",
    },
    "supply_chain": {
        "name": "Supply Chain Attacker",
        "motivation": "Tấn công nhiều nạn nhân qua 1 trusted third-party",
        "skill_level": "expert",
        "method": "Compromise vendor/dependency trước, sau đó pivot",
        "focus": "External dependency, vendor access, update mechanism",
        "blind_spot": "Direct attack path — không phải approach của mình",
        "prompt": """Bạn tấn công qua supply chain — compromise vendor hoặc software dependency trước.
Bạn đã có foothold qua một trusted third-party (IT vendor, SaaS tool, update server).
Nhìn vào hạ tầng này: từ vị trí vendor đó, có thể pivot vào đâu?
Focus vào: vendor access scope, update mechanism, trusted connection, 3rd-party integration.""",
    },
}

class CyberExpertProfileGenerator:

    def generate_all_profiles(self, network_summary: str, graph_id: Optional[str] = None) -> Dict:
        """
        Tạo toàn bộ 18 agents:
          - Tầng 1: 13 domain × mindset agents  → result["tier1"]
          - Tầng 2: 5 attacker profile agents    → result["tier2"]
          - Tất cả profiles                      → result["all"]
          - OASIS-compatible profiles             → result["oasis_profiles"]
        Reuse OASISProfileGenerator pattern — chỉ thay template.
        """

    def generate_attacker_profiles(self, network_context: str) -> List[Dict]:
        """
        Tạo 5 attacker profile agents.
        Inject network_context vào prompt để agents biết đang phân tích hạ tầng nào.
        Mỗi agent có: profile_type, motivation, network_context, system_prompt.
        """

    def _build_expert_prompt(self, domain: str, persona: str,
                              network_summary: str, ttp_context: str) -> str:
        """Prompt cho Tầng 1 — kết hợp domain knowledge + mindset + network context."""

    def _build_attacker_prompt(self, profile: str, network_summary: str) -> str:
        """
        Prompt cho Tầng 2 — kết hợp attacker motivation + method + network context.
        Không inject TTP context vì attacker không bị giới hạn bởi domain.
        """
```

**Kiểm tra xong khi**:
- Tầng 1: `network_security/offensive` và `network_security/defensive` có system prompt khác nhau rõ ràng
- Tầng 2: `apt` và `opportunistic` có prompt phản ánh đúng motivation và blind spot khác nhau
- Tổng cộng: 18 agent profiles được generate

---

### Bước 2.2 — OASIS Security Review Environment

**File cần tạo**: `backend/scripts/run_security_review.py`

Tương tự `run_twitter_simulation.py` nhưng environment là phòng review với 2-phase discussion:

```python
# Phase A: Intra-group (round 1–3)
#   Domain expert agents cùng group thảo luận nội bộ → tìm raw findings
#   Network/Offensive → Network/Defensive challenge → Network/Architect validate
#   Attacker agents: im lặng, chỉ đọc network context

# Phase B: Cross-group (round 4–7)
#   Tất cả Domain expert agents trên feed chung
#   Groups trình bày và challenge nhau
#   Attacker agents: vẫn im lặng, đọc findings của experts

# Phase C: Attacker Challenge (round 8–10)
#   5 Attacker Profile agents lên tiếng
#   Đọc toàn bộ findings từ Phase A+B → phản biện hoặc bổ sung
#   Góc nhìn: "kẻ tấn công thực tế có thật sự làm vậy không?"

SECURITY_REVIEW_ACTIONS = {
    # Phase A — Intra-group (Domain experts)
    "POST_FINDING":        "Đăng finding mới với evidence cụ thể",
    "CHALLENGE_FINDING":   "Phản biện finding của agent khác với lý do",
    "VALIDATE_FINDING":    "Xác nhận finding là đúng",
    "ADD_EVIDENCE":        "Bổ sung evidence cho finding có sẵn",
    "REFINE_SEVERITY":     "Điều chỉnh severity với justification",

    # Phase B — Cross-group (Domain experts)
    "CROSS_VALIDATE":      "Group khác xác nhận finding (weight cao hơn VALIDATE)",
    "CROSS_CHALLENGE":     "Group khác phản biện finding",
    "ESCALATE_TO_RISK":    "Yêu cầu Risk group đánh giá business impact",
    "REQUEST_INTEL":       "Yêu cầu Threat Intel confirm APT relevance",
    "CONCLUDE":            "Kết luận cuối cùng về finding",

    # Phase C — Attacker Challenge (Attacker Profile agents only)
    "ATTACKER_CONFIRM":    "Xác nhận: path/finding này realistic với profile của tôi",
    "ATTACKER_DISMISS":    "Bác bỏ: không ai thật sự làm vậy vì lý do X",
    "ATTACKER_ADD_PATH":   "Bổ sung: còn path này mà experts chưa thấy",
    "ATTACKER_ESCALATE":   "Nâng severity: dễ hơn experts nghĩ vì lý do X",
    "ATTACKER_DOWNGRADE":  "Hạ severity: khó hơn experts nghĩ vì lý do X",
}

# Confidence weight trong Consensus Engine:
# ATTACKER_CONFIRM   → bonus +0.15  (corroboration từ real-world perspective)
# ATTACKER_DISMISS   → penalty -0.20 (kẻ tấn công thật không làm vậy → likely FP)
# ATTACKER_ADD_PATH  → tạo finding mới, base confidence = 0.60
# ATTACKER_ESCALATE  → severity upgrade nếu ≥ 2 profiles đồng ý
# ATTACKER_DOWNGRADE → severity downgrade nếu ≥ 3 profiles đồng ý
```

**Kiểm tra xong khi**:
- Phase A: intra-group discussion có ít nhất 5 posts
- Phase B: ít nhất 3 cross-validate hoặc cross-challenge
- Phase C: ít nhất 3 attacker actions — có cả CONFIRM và DISMISS (attacker không đồng ý blindly)

---

## Phase 3 — Collaborative Analysis Session

### Mục tiêu
Orchestrate toàn bộ quá trình 2-phase review, collect findings, tính group-weighted consensus.

---

### Bước 3.1 — Review Session Orchestrator

**File**: `backend/app/services/cyber_session_orchestrator.py`

```python
class CyberSessionOrchestrator:

    def run_session_async(self, graph_id: str, network_summary: str, profiles: List[CyberAgentProfile]) -> str:
        """
        Phase A (round 1–3): Intra-group — Domain experts thảo luận nội bộ
          - Agents cùng group share feed riêng
          - Tìm raw findings, challenge nhau nội bộ
          - Attacker agents: im lặng, chỉ absorb network context

        Phase B (round 4–7): Cross-group — Domain experts challenge nhau
          - Tất cả domain agents trên feed chung
          - Groups trình bày và challenge nhau
          - Attacker agents: vẫn im lặng, đọc findings

        Phase C (round 8–10): Attacker Challenge
          - 5 Attacker Profile agents lên tiếng
          - Đọc toàn bộ findings → CONFIRM / DISMISS / ADD_PATH
          - Domain agents có thể phản hồi lại attacker comments

        Kết quả: findings từ cả 3 phase, tagged rõ nguồn gốc
        """

    def build_network_context_from_zep(self, graph_id: str) -> str:
        """
        Query Zep KG → tóm tắt hạ tầng inject vào tất cả agents:
          - Host, zone, CVE, service, security controls
          - Critical assets được đánh dấu rõ
        """

    def _parse_findings_from_feed(self, feed_history: List[Dict]) -> List[ExpertFinding]:
        """Parse feed → extract structured ExpertFinding với author_group, author_persona."""
```

---

### Bước 3.2 — Consensus Engine

**File cần tạo**: `backend/app/services/consensus_engine.py`

```python
class ConsensusEngine:
    """
    3-layer weighted confidence:

    Layer 1 — Intra-group agreement:
      % agents cùng group đồng ý
      Weight: 0.30

    Layer 2 — Cross-group validation:
      % domain groups KHÁC đã validate
      Weight: 0.45 (cao nhất — tránh group bias)

    Layer 3 — Attacker corroboration:
      % attacker profiles CONFIRM finding
      Weight: 0.25
      Bonus/penalty theo action type:
        ATTACKER_CONFIRM   → +0.15
        ATTACKER_DISMISS   → -0.20 (kẻ tấn công thật không làm vậy)
        ATTACKER_ESCALATE  → severity upgrade nếu ≥ 2 profiles
        ATTACKER_DOWNGRADE → severity downgrade nếu ≥ 3 profiles

    Final confidence = L1 × 0.30 + L2 × 0.45 + L3 × 0.25
    Filter: confidence < 0.35 → bỏ (likely FP)

    Ví dụ:
      Finding X: intra=0.8, cross=0.6, attacker=0 (bị 2 profiles DISMISS)
        → final = 0.8×0.30 + 0.6×0.45 + 0×0.25 = 0.51
        → Giữ nhưng note "attacker profiles không corroborate"

      Finding Y: intra=0.5, cross=0.3, attacker=0.9 (4/5 profiles CONFIRM)
        → final = 0.5×0.30 + 0.3×0.45 + 0.9×0.25 = 0.51
        → Giữ và note "high attacker relevance"

      Finding Z: intra=0.3, cross=0.2, attacker=0 (2 DISMISS)
        → final = 0.3×0.30 + 0.2×0.45 - 0.20 = 0.07 → loại
    """

    def compute_consensus(self, findings: List[ExpertFinding]) -> List[ConsensusVulnerability]:

    def _group_related_findings(self, findings: List[ExpertFinding]) -> List[List[ExpertFinding]]:
        """Group findings về cùng lỗ hổng theo asset + attack vector."""

    def _calc_three_layer_confidence(self, group: List[ExpertFinding]) -> float:
        """Tính confidence 3 layer: intra + cross + attacker corroboration."""

    def _apply_attacker_adjustments(self, vuln: ConsensusVulnerability,
                                     attacker_actions: List[ExpertFinding]) -> ConsensusVulnerability:
        """Apply ESCALATE/DOWNGRADE từ attacker profiles vào severity."""
```

**Kiểm tra xong khi**:
- Finding bị 2+ attacker profiles DISMISS → confidence giảm đáng kể
- Finding được 3+ attacker profiles CONFIRM → confidence tăng
- Finding chỉ có intra-group mà không có cross hoặc attacker → confidence thấp, gần filter threshold

---

## Phase 4 — Vulnerability Report & API

### Bước 4.1 — VulnReportAgent

**File cần tạo**: `backend/app/services/vuln_report_agent.py`

Extend `ReportAgent` từ MiroFish — reuse toàn bộ ReACT loop:

```python
class VulnReportAgent(ReportAgent):

    TOOLS = [
        "get_vulnerability_list",         # ConsensusVulnerability đã rank (3-layer confidence)
        "get_finding_detail",             # chi tiết finding + evidence + who challenged
        "get_group_disagreements",        # finding nào bị cross-group challenge nhiều nhất
        "get_attacker_profile_breakdown", # profile nào CONFIRM/DISMISS gì — realworld relevance
        "get_asset_risk_profile",         # host nào nguy hiểm nhất
        "get_tool_gap_analysis",          # thiếu tool nào → detection rate thấp
        "get_remediation_priority",       # thứ tự ưu tiên theo cost/impact
        "get_mitre_mapping",              # map finding → ATT&CK technique
        "get_persona_breakdown",          # offensive vs defensive tìm ra gì khác nhau
        "get_attacker_only_findings",     # findings do attacker ADD_PATH — experts bỏ sót
    ]

    SYSTEM_PROMPT = """
    Tổng hợp kết quả từ phiên multi-expert review (18 agents, 3 phases):
      1. Executive Summary: top 3 rủi ro nguy hiểm nhất
      2. Vulnerability Details: danh sách đầy đủ với evidence và 3-layer confidence
      3. Attacker Perspective: findings được attacker profiles corroborate
         và findings bị attacker dismiss (potential FP)
      4. Expert Disagreements: finding nào còn tranh cãi và tại sao
      5. Tool Gap Analysis: thiếu tool nào, ảnh hưởng thế nào
      6. Remediation Roadmap: thứ tự ưu tiên theo cost/impact

    Phân biệt rõ:
      - "High confidence" = cross-group validated + attacker confirmed
      - "Expert only" = domain experts đồng ý nhưng attacker chưa confirm
      - "Attacker surfaced" = attacker ADD_PATH, chưa có expert validate
    """
```

---

### Bước 4.2 — API Endpoints Phase 3–4

Thêm vào `backend/app/api/cyber.py`:

```
POST /api/cyber/session/start
  Body: { graph_id, network_summary, oasis_profiles }   ← oasis_profiles từ /agents/generate
  Return: { task_id, session_id }

GET  /api/cyber/review/<session_id>/status
  Return: { status, current_phase, current_round, finding_count, attacker_finding_count }

GET  /api/cyber/review/<session_id>/findings
  Query: phase, group, severity, type (expert|attacker|all)
  Return: { findings[], group_breakdown, cross_validated_count, attacker_count }

GET  /api/cyber/review/<session_id>/feed
  Query: phase, round_num, agent_id, limit, offset
  Return: { posts[], total, phase_breakdown }

GET  /api/cyber/network-context/<graph_id>
  Return: { graph_id, summary }   ← lấy network_summary khi dùng Zep graph

POST /api/cyber/report/generate
  Body: { session_id, expert_findings, attacker_findings, network_summary, graph_id }
  Return: { task_id }

GET  /api/cyber/report/<session_id>
  Return: { report, consensus_vulnerabilities[], coverage_gaps, stats }
```

---

## Phase 5 — Frontend & Evaluation

### Bước 5.1 — Frontend Components

```
Step1NetworkSetup.vue    → Upload hạ tầng, preview assets
Step2AgentSetup.vue      → Hiển thị agent matrix, toggle domain/persona
Step3ReviewSession.vue   → Live feed (tab: Intra-group / Cross-group)
                           Round counter, phase indicator, finding counter
Step4Findings.vue        → Danh sách finding với confidence badge,
                           group support indicator, evidence collapsible
Step5Report.vue          → Executive summary, disagreements highlight,
                           gap analysis, remediation roadmap
```

---

### Bước 5.2 — Experiment & Validation

Chạy 3 kịch bản cố định:

```
Kịch bản 1 — SME không có security tool:
  Input: 5 host, không có EDR/SIEM/WAF
  Expected: Nhiều finding, offensive personas active nhất,
            Risk group escalate impact cao

Kịch bản 2 — Doanh nghiệp vừa, có SIEM:
  Input: 15 host, có SIEM, không có EDR
  Expected: Defensive vs Offensive personas bất đồng về endpoint risk
            Cross-group challenge nhiều ở Endpoint findings

Kịch bản 3 — Enterprise với full stack security:
  Input: 30 host, SIEM + EDR + WAF + NDR
  Expected: Offensive personas focus vào logic flaw và design issue
            Auditor personas tìm được compliance gap mà kỹ thuật bỏ qua
```

**Validation metrics**:
- FP rate < 20% đối chiếu với known CVE database
- Cross-group validated findings có FP rate thấp hơn intra-group only
- Offensive personas tìm ra attack path mà defensive personas bỏ qua (và ngược lại)

---

## Rủi ro và Phương án dự phòng

| Rủi ro | Phương án |
|---|---|
| Intra-group groupthink | Offensive và Defensive persona trong cùng group có built-in tension |
| Cross-group không challenge đủ | Mỗi group bắt buộc có ít nhất 1 CROSS_CHALLENGE per session |
| FP cao vì assume worst case | ConsensusEngine penalize findings không có cross-group validation |
| 13–15 agents → LLM cost cao | Intra-group dùng lightweight model, cross-group dùng full model |
| Findings overlap nhiều | Group-weighted consensus tự nhiên dedup theo domain authority |

---

## Checklist tổng thể

```
Phase 1 — Network KG:
  [ ] cyber_models.py — ExpertFinding có author_group + author_persona
  [ ] mitre_reference.py — TTP context khác nhau theo domain + persona
  [ ] network_topology_builder.py — parse → Zep
  [ ] API /cyber/setup và /cyber/graph hoạt động

Phase 2 — Agent Matrix:
  [ ] cyber_expert_profile_generator.py — 13 domain×mindset + 5 attacker = 18 profiles
  [ ] Mỗi domain × persona có system prompt khác nhau rõ ràng
  [ ] Mỗi attacker profile có motivation và blind spot khác nhau rõ ràng
  [ ] OASIS Security Review Room — 3-phase discussion hoạt động
  [ ] Attacker agents im lặng Phase A+B, chỉ lên tiếng Phase C

Phase 3 — Analysis:
  [ ] review_session_orchestrator.py — Phase A, B, C chạy đúng thứ tự
  [ ] consensus_engine.py — 3-layer confidence (intra + cross + attacker)
  [ ] ATTACKER_DISMISS làm giảm confidence đáng kể
  [ ] ATTACKER_CONFIRM làm tăng confidence
  [ ] Finding bị 2+ profiles DISMISS → gần filter threshold

Phase 4 — Report:
  [ ] vuln_report_agent.py — 5 phần đầy đủ kể cả disagreements
  [ ] API endpoints đầy đủ

Phase 5 — Evaluate:
  [ ] 3 kịch bản reproducible
  [ ] Offensive vs Defensive persona findings khác nhau (chứng minh diversity)
  [ ] FP rate cross-validated < FP rate intra-only
  [ ] Validate với ít nhất 1 real incident report
```

---

## Research Questions cho luận án

```
RQ1: Domain Group × Mindset Persona matrix có tìm ra nhiều lỗ hổng đa dạng
     hơn single-role expert panel không?
     → So sánh: 5 generic experts vs 13-agent matrix trên cùng network

RQ2: Cross-group validation có làm giảm FP rate so với intra-group only không?
     → Đo FP ở findings chỉ có intra-group vs findings có cross-group validate

RQ3: Offensive và Defensive persona trong cùng domain có tìm ra
     các loại findings khác nhau không?
     → Phân tích overlap giữa offensive findings và defensive findings

RQ4: Group-weighted consensus có chính xác hơn simple majority vote không?
     → So sánh precision/recall của 2 consensus method
```

---

*Cập nhật: Thay đổi từ 5 expert đơn thuần sang Domain Group × Mindset Persona matrix (13–15 agents) để tận dụng đúng cơ chế emergent behavior của OASIS — tương tự cách MiroFish dùng role + persona cho social agents.*
