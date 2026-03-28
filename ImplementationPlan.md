# Kế hoạch Triển khai: MiroFish → CyberWar Simulation Engine

Tài liệu này mô tả từng bước cụ thể để biến MiroFish thành hệ thống CyberWar Simulation Engine (Plan A).

---

## Tổng quan tiến độ

```
Giai đoạn 1 — Nền tảng        (Tháng 1–3):   Schema, MITRE loader, Network graph
Giai đoạn 2 — Agent Core      (Tháng 4–6):   Red agent, Blue agent, OASIS feed
Giai đoạn 3 — Simulation Loop (Tháng 7–9):   Game loop, conflict resolver, metrics
Giai đoạn 4 — AAR & UI        (Tháng 10–12): AARAgent, frontend, integration test
Giai đoạn 5 — Evaluate        (Tháng 13–18): Validation, so sánh, viết luận án
```

---

## Giai đoạn 1 — Nền tảng (Tháng 1–3)

### Mục tiêu
Có được môi trường mạng ảo trong Zep graph và bộ TTP library. Chưa cần agent, chưa cần simulation.

---

### Bước 1.1 — Định nghĩa Data Schema

**File cần tạo**: `backend/app/models/cyber_models.py`

Định nghĩa các dataclass mới, không đụng vào model cũ của MiroFish:

```python
@dataclass
class NetworkAsset:
    host_id: str
    hostname: str
    ip: str
    zone: str                    # DMZ | Internal | Database | Management
    os: str
    services: List[str]          # ["Apache 2.4.49", "OpenSSH 7.4"]
    vulnerabilities: List[str]   # ["CVE-2021-41773", "CVE-2021-26855"]
    patch_status: str            # "patched" | "unpatched" | "partially_patched"
    status: str                  # "clean" | "compromised" | "detected" | "contained"
    controls: Dict[str, bool]    # {"edr": False, "siem": False, "av": True}

@dataclass
class TTP:
    technique_id: str            # "T1059.001"
    name: str                    # "PowerShell"
    tactic: str                  # "Execution"
    description: str
    prerequisites: List[str]     # điều kiện để dùng được technique này
    detection_difficulty: str    # "low" | "medium" | "high"
    noise_level: str             # "low" | "medium" | "high" (càng noise càng dễ detect)

@dataclass
class CyberEvent:
    round_num: int
    timestamp: str
    team: str                    # "red" | "blue"
    agent_id: str
    action_type: str             # "exploit" | "detect" | "contain" | "escalate"
    technique_id: Optional[str]  # MITRE ATT&CK ID nếu là Red action
    target_host: Optional[str]
    outcome: str                 # "success" | "failed" | "detected" | "missed"
    detail: str                  # mô tả chi tiết để hiển thị UI

@dataclass
class SimulationMetrics:
    simulation_id: str
    total_rounds: int
    red_objective_achieved: bool
    detection_rate: float        # % attack steps được detect
    mttd: float                  # Mean Time To Detect (rounds)
    mttr: float                  # Mean Time To Respond (rounds)
    kill_chain_progress: Dict    # {"recon": True, "initial_access": True, ...}
    missed_alerts: int
    false_positives: int
```

**Kiểm tra xong khi**: import được các class này, không có lỗi.

---

### Bước 1.2 — MITRE ATT&CK Loader

**File cần tạo**: `backend/app/services/mitre_attack_loader.py`

Pull data từ MITRE ATT&CK STIX/JSON (free, public):

```python
class MitreAttackLoader:
    MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    def load_techniques(self) -> List[TTP]:
        """
        Pull toàn bộ ATT&CK Enterprise techniques.
        Cache local để không pull mỗi lần chạy.
        Trả về subset top-50 phổ biến nhất (theo Navigator heatmap).
        """

    def get_techniques_by_tactic(self, tactic: str) -> List[TTP]:
        """Lọc TTP theo tactic phase — dùng trong game loop"""

    def get_techniques_for_target(self, asset: NetworkAsset) -> List[TTP]:
        """
        Lọc TTP phù hợp với target cụ thể.
        Ví dụ: Windows host → trả về Windows-specific techniques
        """
```

**Scope giới hạn** — chỉ implement top-20 TTP phổ biến nhất cho thesis:

| Phase | TTP implement |
|---|---|
| Reconnaissance | T1595, T1592, T1589 |
| Initial Access | T1190, T1566.001, T1078 |
| Execution | T1059.001, T1059.003 |
| Persistence | T1053, T1543 |
| Lateral Movement | T1021.001, T1078, T1550.002 |
| Exfiltration | T1041, T1048 |

**Kiểm tra xong khi**: `loader.get_techniques_by_tactic("Initial Access")` trả về list TTP đúng.

---

### Bước 1.3 — MITRE D3FEND Loader

**File cần tạo**: `backend/app/services/mitre_defend_loader.py`

```python
class MitreDefendLoader:
    def load_controls(self) -> Dict[str, List[str]]:
        """
        Map từ attack technique → defensive controls.
        Ví dụ: T1059.001 → ["Script Block Logging", "PowerShell Constrained Language Mode"]
        """

    def get_controls_for_technique(self, technique_id: str) -> List[str]:
        """Dùng trong Blue agent để biết có thể detect/block technique nào"""
```

**Kiểm tra xong khi**: `loader.get_controls_for_technique("T1059.001")` trả về list controls đúng.

---

### Bước 1.4 — Network Topology Builder

**File cần tạo**: `backend/app/services/network_topology_builder.py`

Thay thế `graph_builder.py` cho flow CyberWar. Reuse `TextProcessor` từ MiroFish:

```python
class NetworkTopologyBuilder:
    """
    Nhận input (văn bản hoặc IaC) → nạp NetworkAsset vào Zep graph
    """

    def build_from_text(self, text: str) -> str:
        """
        Dùng LLM extract network entities từ văn bản mô tả.
        Tương tự graph_builder.py nhưng với schema NetworkAsset.
        Trả về graph_id.
        """

    def build_from_iac(self, files: Dict[str, str]) -> str:
        """
        [Optional] Parse Terraform/K8s files trực tiếp.
        Không dùng LLM — parse code syntax.
        Kết hợp với build_from_text cho human factor.
        """

    def _extract_assets_with_llm(self, text: str) -> List[NetworkAsset]:
        """
        Prompt LLM để extract danh sách host, service, CVE, zone.
        Output: List[NetworkAsset] dạng JSON.
        """

    def _store_to_zep(self, graph_id: str, assets: List[NetworkAsset]):
        """
        Nạp assets vào Zep với quan hệ:
          Host → inZone → Zone
          Host → hasService → Service
          Host → hasVuln → CVE
          Zone → connectsTo → Zone
        """
```

**Kiểm tra xong khi**: Upload text mô tả hạ tầng → Zep graph có đủ node và edge, query được `"host nào có CVE CVSS > 8?"`.

---

### Bước 1.5 — API Endpoint Giai đoạn 1

**File cần sửa**: `backend/app/api/simulation.py` — thêm endpoint mới, không xóa endpoint cũ.

```python
# POST /api/cyber/setup
# Body: { "text": "...", "iac_files": {...} }
# Return: { "graph_id": "...", "asset_count": 12, "vuln_count": 5 }

# GET /api/cyber/graph/<graph_id>/assets
# Return: danh sách NetworkAsset đã parse được

# GET /api/cyber/graph/<graph_id>/attack-surface
# Return: danh sách host có vulnerability, sorted by CVSS
```

**Kiểm tra xong khi**: Có thể POST text → nhận graph_id → GET assets → thấy danh sách host đúng.

---

## Giai đoạn 2 — Agent Core (Tháng 4–6)

### Mục tiêu
Có Red agent và Blue agent hoạt động độc lập. OASIS feed cho giao tiếp nội bộ mỗi team.

---

### Bước 2.1 — Cyber Actor Profile Generator

**File cần tạo**: `backend/app/services/cyber_actor_profile_generator.py`

Tương tự `OASISProfileGenerator` nhưng tạo persona bảo mật:

```python
class CyberActorProfileGenerator:

    def generate_red_profiles(self, actor_type: str, count: int) -> List[RedAgentProfile]:
        """
        actor_type: "script_kiddie" | "APT" | "nation_state"

        APT profile:
          skill_level: "expert"
          patience: "high"          # ảnh hưởng tốc độ tấn công
          stealth_priority: "high"  # ưu tiên ít noise
          known_ttps: ["T1190", "T1078", "T1059.001", ...]
          motivation: "data_exfiltration"

        Script kiddie:
          skill_level: "basic"
          patience: "low"
          stealth_priority: "low"
          known_ttps: ["T1190", "T1059.001"]  # subset nhỏ
        """

    def generate_blue_profiles(self, soc_config: dict) -> List[BlueAgentProfile]:
        """
        soc_config: { analyst_count, tier_mix, tools_available, shift_schedule }

        Tier1 profile:
          tier: 1
          attention_capacity: 5     # max alert xử lý đồng thời
          fatigue_threshold: 20     # rounds trước khi performance giảm
          tools: ["SIEM"] hoặc []
          shift: "8x5"             # không làm ngoài giờ

        Tier2 profile:
          tier: 2
          investigation_depth: "high"
          can_hunt: True           # chủ động threat hunting
        """
```

**Kiểm tra xong khi**: Generate ra JSON profiles đúng format, có đủ attributes.

---

### Bước 2.2 — Red Agent Engine

**File cần tạo**: `backend/app/services/red_agent.py`

Đây là LLM agent với structured reasoning:

```python
class RedAgent:
    """
    Một Red agent với role cụ thể (Recon, Exploit, Lateral, Exfil).
    Mỗi round: nhận network state → reasoning → chọn action.
    """

    def __init__(self, profile: RedAgentProfile, role: str, llm_client: LLMClient):
        self.profile = profile
        self.role = role          # "recon" | "exploit" | "lateral" | "exfil"
        self.memory = []          # lịch sử action của agent này

    def decide_action(self, network_state: dict, round_num: int) -> RedAction:
        """
        Core method — gọi LLM với:
          1. System prompt: persona + role + skill level
          2. Context: network state hiện tại (từ Zep)
          3. Memory: những gì đã làm các round trước
          4. Available TTPs: list technique phù hợp với target

        LLM output (JSON có structure):
          {
            "technique_id": "T1059.001",
            "target_host": "WKSTN-042",
            "reasoning": "Host này không có EDR, PowerShell unrestricted",
            "expected_outcome": "code execution",
            "stealth_assessment": "medium noise, có thể bị AV flag"
          }
        """

    def _build_system_prompt(self) -> str:
        """
        Prompt khác nhau theo role:
          Recon: "Bạn là chuyên gia OSINT và scanning..."
          Exploit: "Bạn là exploit developer, chọn kỹ thuật phù hợp..."
          Lateral: "Bạn chuyên về pivot và credential abuse..."
        """

    def update_memory(self, action: RedAction, outcome: str):
        """Ghi lại kết quả để inform quyết định round sau"""
```

**Lưu ý quan trọng**: Output của LLM phải là JSON có schema cố định. Dùng `response_format={"type": "json_object"}` nếu model hỗ trợ, hoặc parse + validate thủ công.

**Kiểm tra xong khi**: `red_agent.decide_action(network_state, round=1)` trả về `RedAction` hợp lệ với technique_id tồn tại trong TTP library.

---

### Bước 2.3 — Blue Agent Engine

**File cần tạo**: `backend/app/services/blue_agent.py`

```python
class BlueAgent:
    """
    Một Blue agent với tier cụ thể.
    Mỗi round: nhận alert queue + team feed → reasoning → quyết định response.
    """

    def __init__(self, profile: BlueAgentProfile, llm_client: LLMClient):
        self.profile = profile
        self.current_workload = 0    # số alert đang xử lý
        self.fatigue_level = 0       # tăng theo round, ảnh hưởng accuracy
        self.is_on_shift = True      # False ngoài giờ làm

    def process_alerts(self, alert_queue: List[Alert], round_num: int) -> List[BlueAction]:
        """
        Nhận list alert → quyết định:
          - Triage từng alert (priority: low/medium/high/critical)
          - Investigate alert đáng ngờ
          - Escalate nếu vượt scope
          - Bỏ qua nếu overload (workload > attention_capacity)

        Tool capability check:
          Nếu tools_available=[] → chỉ detect qua manual log review (slow, inaccurate)
          Nếu tools_available=["SIEM"] → SIEM correlate tự động, alert rõ ràng hơn
          Nếu tools_available=["EDR"] → endpoint-level detection, catch fileless attack
        """

    def _can_detect(self, technique_id: str) -> float:
        """
        Tính xác suất detect technique dựa trên tools có sẵn.
        T1059.001 + có EDR → 0.85
        T1059.001 + không có EDR → 0.20
        """

    def _apply_fatigue(self, base_accuracy: float) -> float:
        """
        Giảm accuracy theo fatigue.
        Round 1-10: 100% base accuracy
        Round 11-20: 85% (bắt đầu mệt)
        Round 21+: 70% nếu không có nghỉ
        """

    def escalate_to(self, action: BlueAction, target_tier: int):
        """Escalate lên Tier cao hơn — kết nối với OASIS Blue feed"""
```

**Kiểm tra xong khi**: Tạo Blue agent với `tools_available=[]`, cho alert về PowerShell execution → phải có xác suất detect thấp (~20%). Tạo agent với `tools_available=["EDR"]` → xác suất detect cao (~85%).

---

### Bước 2.4 — OASIS Feed cho Team Communication

**Tái sử dụng OASIS từ MiroFish** — chỉ cần thêm 2 "environment" mới (Red war room + Blue SOC feed). Không sửa core OASIS code.

```python
# backend/scripts/run_red_team_feed.py
# Tương tự run_twitter_simulation.py nhưng:
#   - Environment: "red_war_room" thay vì Twitter
#   - Actions: "post_intel", "propose_ttp", "vote_plan" thay vì CREATE_POST/LIKE
#   - Agents: RedAgent profiles

# backend/scripts/run_blue_team_feed.py
# Environment: "blue_soc_feed"
# Actions: "post_alert", "add_analysis", "escalate", "close_alert"
# Agents: BlueAgent profiles + SIEM-bot
```

**SIEM-bot** — agent đặc biệt không dùng LLM, chỉ đơn giản là post alert từ Simulation Engine lên feed:

```python
class SIEMBot:
    """Không phải LLM agent — chỉ bridge từ Engine → Blue feed"""

    def post_alert(self, event: CyberEvent, blue_feed):
        if event.should_trigger_alert():
            blue_feed.post({
                "type": "alert",
                "content": f"[{event.severity}] {event.detail}",
                "source": "SIEM",
                "raw_event": event.to_dict()
            })
```

**Kiểm tra xong khi**: Chạy Blue feed riêng → 3 Tier1 agent thảo luận về 1 alert giả → Tier2 escalate → SOCManager ra quyết định. Log cho thấy đúng chuỗi interaction.

---

## Giai đoạn 3 — Simulation Loop (Tháng 7–9)

### Mục tiêu
Có game loop hoàn chỉnh: Red attack → Engine resolve → Blue respond → state update → round tiếp theo.

---

### Bước 3.1 — Simulation Engine (phần quan trọng nhất)

**File cần tạo**: `backend/app/services/cyber_simulation_engine.py`

Đây là phần khác biệt lớn nhất so với MiroFish và cần xây từ đầu:

```python
class CyberSimulationEngine:
    """
    Game loop chính: orchestrate Red vs Blue, resolve conflict, update state.
    """

    def __init__(self, config: SimulationConfig, graph_id: str):
        self.config = config
        self.graph_id = graph_id
        self.network_state = {}      # in-memory cache, sync Zep sau mỗi round
        self.events = []             # log toàn bộ CyberEvent
        self.round_num = 0

    def run(self):
        """Main loop"""
        self._initialize_state()

        while not self._is_finished():
            self.round_num += 1
            self._run_round()

        return self._compile_results()

    def _run_round(self):
        """
        Thứ tự xử lý trong 1 round — BẮT BUỘC tuần tự:

        1. Red team thảo luận trên feed → consensus action
        2. Engine execute Red action → tính outcome
        3. Engine generate alerts từ outcome
        4. Blue team nhận alert qua feed → thảo luận → response
        5. Engine process Blue response → update state
        6. Sync network state vào Zep
        7. Log tất cả events → stream về UI qua IPC
        """

        # Bước 1: Red action
        red_action = self._get_red_consensus_action()

        # Bước 2: Resolve outcome
        outcome = self._resolve_red_action(red_action)

        # Bước 3: Generate alerts
        alerts = self._generate_alerts(red_action, outcome)

        # Bước 4: Blue response
        blue_responses = self._get_blue_responses(alerts)

        # Bước 5: Apply Blue response
        self._apply_blue_responses(blue_responses)

        # Bước 6: Sync state
        self._sync_to_zep()

        # Bước 7: Stream
        self._stream_events_to_ui()

    def _resolve_red_action(self, action: RedAction) -> str:
        """
        Conflict resolution — trái tim của simulation.

        Factors:
          - CVE có trên target không?
          - Target đã patch chưa?
          - Controls nào đang active?
          - Red agent skill level?
          - Noise level của technique?

        Output: "success" | "failed" | "partial"
        """
        target = self.network_state[action.target_host]
        technique = self.ttp_library[action.technique_id]

        # Check prerequisite
        if not self._check_prerequisites(technique, target):
            return "failed"

        # Check defensive controls
        detection_probability = self._calc_detection_probability(technique, target)

        # Apply skill modifier
        success_probability = self._calc_success_probability(
            technique, target, self.red_skill_level
        )

        return self._roll_outcome(success_probability, detection_probability)

    def _generate_alerts(self, action: RedAction, outcome: str) -> List[Alert]:
        """
        Quyết định alert nào được tạo ra dựa trên:
          - Technique noise level
          - Tools Blue có sẵn
          - Outcome của action (success noise khác failed noise)

        Ví dụ:
          T1059.001 + EDR present → Alert: "Suspicious PowerShell execution"
          T1059.001 + no EDR → Alert: None (silent)
          T1078 + SIEM + login anomaly detection → Alert: "Unusual auth outside hours"
          T1078 + no SIEM → Alert: None
        """

    def _is_finished(self) -> bool:
        """
        Kết thúc khi:
          - Red đạt objective (exfiltrate database)
          - Hết số round
          - Blue successfully contain toàn bộ Red foothold
        """
```

**Kiểm tra xong khi**: Chạy 5 round với hardcoded action → event log đúng thứ tự, state update đúng, không có race condition.

---

### Bước 3.2 — Metrics Collector

**File cần tạo**: `backend/app/services/metrics_collector.py`

```python
class MetricsCollector:

    def calculate(self, events: List[CyberEvent]) -> SimulationMetrics:
        return SimulationMetrics(
            detection_rate=self._calc_detection_rate(events),
            mttd=self._calc_mttd(events),
            mttr=self._calc_mttr(events),
            kill_chain_progress=self._analyze_kill_chain(events),
            missed_alerts=self._count_missed(events),
            false_positives=self._count_fp(events)
        )

    def _calc_mttd(self, events) -> float:
        """
        Với mỗi attack step được detect:
          MTTD = round detect - round attack xảy ra
        Trả về trung bình.
        """

    def _calc_detection_rate(self, events) -> float:
        """
        # attack steps detected / # total attack steps
        """
```

**Kiểm tra xong khi**: Cho vào list event giả → metrics output đúng.

---

### Bước 3.3 — Tích hợp với SimulationRunner hiện tại

**File cần sửa**: `backend/app/services/simulation_runner.py`

KHÔNG xóa code cũ — thêm nhánh mới cho CyberWar mode:

```python
class SimulationRunner:

    @classmethod
    def start_simulation(cls, simulation_id, config, mode="social"):
        if mode == "social":
            # Code cũ của MiroFish — giữ nguyên
            cls._start_oasis_simulation(simulation_id, config)
        elif mode == "cyberwar":
            # Code mới
            cls._start_cyberwar_simulation(simulation_id, config)

    @classmethod
    def _start_cyberwar_simulation(cls, simulation_id, config):
        """
        Chạy CyberSimulationEngine trong subprocess riêng.
        Tương tự cách MiroFish chạy OASIS script.
        Stream event qua IPC về UI.
        """
```

**Kiểm tra xong khi**: POST `/api/cyber/simulation/start` → task created → poll status → simulation chạy → events stream về.

---

## Giai đoạn 4 — AAR Agent & Frontend (Tháng 10–12)

### Mục tiêu
Có After-Action Review tự động và UI hoàn chỉnh.

---

### Bước 4.1 — AAR Agent

**File cần tạo**: `backend/app/services/aar_agent.py`

Extend `ReportAgent` từ MiroFish — reuse toàn bộ ReACT loop, chỉ thay tools và prompts:

```python
class AARAgent(ReportAgent):
    """
    Thay vì phân tích social simulation, phân tích CyberWar simulation.
    Reuse ReACT loop từ ReportAgent hoàn toàn.
    """

    # Tools mới thay thế ZepTools
    TOOLS = [
        "get_attack_timeline",       # timeline đầy đủ Red actions
        "get_detection_gaps",        # attack steps không bị detect
        "get_blue_decisions",        # quyết định của từng Blue agent
        "get_kill_chain_analysis",   # tiến trình kill chain
        "get_metrics_summary",       # MTTD, MTTR, detection rate
        "compare_with_benchmark",    # so sánh với industry benchmark
        "get_mitre_recommendations", # suggest D3FEND controls cho gaps
    ]

    SYSTEM_PROMPT = """
    Bạn là chuyên gia After-Action Review với kinh nghiệm phân tích
    kết quả diễn tập Red Team / Blue Team.

    Nhiệm vụ: Phân tích kết quả simulation và đưa ra:
    1. Những attack steps nào Blue miss và tại sao
    2. Khoảng trống trong detection capability
    3. Quyết định nào của Blue agent là sai và nguyên nhân
    4. Khuyến nghị cụ thể ưu tiên theo MITRE D3FEND

    Mọi kết luận phải dựa trên data từ simulation, không phỏng đoán.
    """
```

**Kiểm tra xong khi**: Cho vào simulation result → AAR agent tạo ra report có đủ 4 phần, tool calls hợp lệ, không hallucinate.

---

### Bước 4.2 — Frontend Components

Thay thế 5 Step component của MiroFish. Reuse router, store, axios wrapper — chỉ thay nội dung:

**Step1NetworkSetup.vue** — thay Step1GraphBuild:
```
- Upload zone: text area + file upload (PDF, TXT, IaC files)
- Preview: hiển thị NetworkAsset list sau parse
- Validate: check có đủ host, zone, CVE chưa
```

**Step2ActorSetup.vue** — thay Step2EnvSetup:
```
- Red team config: actor_type, motivation, stealth_level
- Blue team config: analyst_count, tier_mix, tools, shift
- Scenario name + rounds + success criteria
```

**Step3CyberSimulation.vue** — thay Step3Simulation:
```
- Event feed: stream realtime từ IPC (reuse cơ chế cũ)
- NetworkTopologyMap.vue: D3.js graph với nodes đổi màu
    clean=xanh, compromised=đỏ, detected=vàng, contained=xám
- Team feed panels: Red feed + Blue feed song song
- Round counter + progress bar
```

**Step4AAR.vue** — thay Step4Report:
```
- Executive summary: detection rate, MTTD, MTTR dạng số
- Kill chain heatmap: matrix MITRE phase × detected/missed
- Gap analysis list với recommendations
- Markdown render (reuse từ MiroFish)
```

**Step5Debrief.vue** — thay Step5Interaction:
```
- Chat interface (reuse từ MiroFish)
- Dropdown chọn agent để chat
- Context: agent biết lịch sử quyết định của mình
```

**Kiểm tra xong khi**: End-to-end flow từ Step1 đến Step5 không có lỗi UI, data flow đúng.

---

### Bước 4.3 — API Endpoints hoàn chỉnh

```python
# Giai đoạn 1
POST   /api/cyber/setup                    # nhập hạ tầng → graph_id
GET    /api/cyber/graph/<id>/assets        # xem assets đã parse
GET    /api/cyber/graph/<id>/attack-surface # vuln summary

# Giai đoạn 2-3
POST   /api/cyber/simulation/start         # bắt đầu simulation
GET    /api/cyber/simulation/<id>/status   # poll status
GET    /api/cyber/simulation/<id>/events   # event feed (pagination)
POST   /api/cyber/simulation/<id>/stop     # dừng sớm

# Giai đoạn 4
POST   /api/cyber/report/generate          # tạo AAR report
GET    /api/cyber/report/<id>              # lấy report
POST   /api/cyber/report/<id>/chat         # chat với agent
```

---

## Giai đoạn 5 — Evaluation & Luận án (Tháng 13–18)

### Mục tiêu
Validate kết quả, so sánh với ground truth, viết luận án.

---

### Bước 5.1 — Thiết kế Experiment

Chạy 3 kịch bản cố định (reproducible với fixed seed):

```
Kịch bản 1 — Script Kiddie vs Minimal Blue:
  Red: script_kiddie, tools: public exploits only
  Blue: 1 Tier1 analyst, no SIEM, no EDR
  Expected: Red thắng dễ, detection rate thấp

Kịch bản 2 — APT vs Moderate Blue:
  Red: APT, high stealth
  Blue: 2 Tier1 + 1 Tier2, có SIEM, không EDR
  Expected: Kết quả mixed, phụ thuộc vào tool gap

Kịch bản 3 — APT vs Mature SOC:
  Red: APT, nation_state level
  Blue: 3 Tier1 + 2 Tier2, SIEM + EDR + NDR
  Expected: Blue detect được nhiều, Red có thể thua
```

Mỗi kịch bản chạy 5 lần (different random seed) → lấy mean + confidence interval.

---

### Bước 5.2 — Validation

**So sánh với case studies thật:**

| Case study | Nguồn | Dùng để validate |
|---|---|---|
| APT29 SolarWinds | Public incident report | MTTD, kill chain progression |
| Log4Shell exploitation | CISA advisory | Timeline từ CVE → exploitation |
| Colonial Pipeline | Public report | Lateral movement, detection gaps |

**Metric so sánh:**
```
Simulation output:  MTTD = X rounds, detection rate = Y%
Ground truth:       MTTD = X' hours, detection rate = Y'%
Correlation:        Pearson r > 0.7 → simulation có predictive value
```

---

### Bước 5.3 — Research Questions cho luận án

```
RQ1: LLM-based adaptive agent có tạo ra attack paths đa dạng hơn
     script-based TTP execution (CALDERA) không?

RQ2: Multi-agent Blue team với OASIS feed có detection rate cao hơn
     single-agent Blue team không, và tại sao?

RQ3: Simulation output có tương quan với historical breach data
     (Verizon DBIR) theo ngành và loại threat actor không?
```

---

## Rủi ro và Phương án dự phòng

| Rủi ro | Khả năng | Phương án |
|---|---|---|
| LLM hallucinate TTP không tồn tại | Cao | Validate output với TTP library trước khi execute |
| Simulation không reproducible | Cao | Fixed random seed + temperature=0 cho LLM |
| Zep Cloud latency làm simulation chậm | Trung bình | In-memory state cache, sync Zep cuối round |
| Chi phí API quá cao khi experiment | Trung bình | Dùng Ollama local cho development, API chỉ cho final run |
| Validation không đủ mạnh | Trung bình | Focus vào ranking correctness, không cần số tuyệt đối |

---

## Checklist tổng thể

```
Giai đoạn 1:
  [ ] cyber_models.py — schema định nghĩa xong
  [ ] mitre_attack_loader.py — pull và cache top-20 TTP
  [ ] mitre_defend_loader.py — map TTP → controls
  [ ] network_topology_builder.py — parse text → Zep graph
  [ ] API endpoint giai đoạn 1 hoạt động

Giai đoạn 2:
  [ ] cyber_actor_profile_generator.py — Red/Blue profiles
  [ ] red_agent.py — decide_action() trả về valid TTP
  [ ] blue_agent.py — process_alerts() với tool capability check
  [ ] OASIS Blue feed — 3 agent thảo luận được về 1 alert

Giai đoạn 3:
  [ ] cyber_simulation_engine.py — game loop 10 rounds không crash
  [ ] _resolve_red_action() — conflict resolution logic đúng
  [ ] _generate_alerts() — alert generation theo tool availability
  [ ] metrics_collector.py — MTTD, MTTR, detection rate đúng
  [ ] Tích hợp vào SimulationRunner

Giai đoạn 4:
  [ ] aar_agent.py — AAR report đủ 4 phần, không hallucinate
  [ ] Step1–Step5 frontend — end-to-end flow không lỗi
  [ ] API endpoints đầy đủ

Giai đoạn 5:
  [ ] 3 kịch bản experiment chạy được, reproducible
  [ ] Validation với ít nhất 2 case study thật
  [ ] RQ1, RQ2, RQ3 có data để answer
```

---

*Tài liệu phản ánh kế hoạch triển khai tại thời điểm MiroFish commit `1536a79`. Cập nhật khi có thay đổi scope hoặc technical decision mới.*
