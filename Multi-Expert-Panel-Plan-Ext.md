# Multi-Expert Panel Extension — Kế hoạch Triển khai (Hướng C)

## Tổng quan

Hướng C xây trực tiếp trên nền Hướng B. Toàn bộ code Phase 1–4 của Hướng B được giữ nguyên — Hướng C thêm vào **2 layer mới**:

```
Hướng B:   Network KG → Expert Panel → Vuln Report
                         ↑
Hướng C:   Network KG → Attack Graph → Expert Panel (guided) → [Red/Blue validate] → Vuln Report
                ↑ thêm layer này          ↑ B có sẵn            ↑ optional
```

### Vấn đề Hướng B chưa giải quyết

Hướng B để các expert agent **tự do phân tích** — họ có thể bỏ sót attack path vì không ai nghĩ đến, hoặc tập trung quá vào một vùng mà bỏ qua vùng khác.

Hướng C giải quyết bằng **Attack Graph** — thuật toán đồ thị duyệt có hệ thống tất cả path từ Internet đến crown jewel. Sau đó Expert Panel không phân tích tự do nữa mà **validate từng path** mà graph đã tìm ra.

```
Không có Attack Graph:
  Agents phân tích → có thể miss path qua SMB → Finding không đầy đủ

Có Attack Graph:
  Graph tìm ra 23 path → Agents validate từng path → Coverage gần như 100%
```

### Giá trị gia tăng so với Hướng B

| | Hướng B | Hướng C |
|---|---|---|
| Coverage | Phụ thuộc expert creativity | Gần 100% — graph duyệt hết |
| Provable | Khó — dựa vào LLM reasoning | Có — graph theory backing |
| FP rate | Trung bình | Thấp — graph + expert double-check |
| Confidence claim | "Experts đồng ý" | "Tất cả path tìm được + experts validate" |
| Novelty | Cao | Rất cao — chưa tool nào làm đủ |
| Độ phức tạp | Trung bình | Cao hơn B (~2–3 tháng thêm) |

---

## Kiến trúc tổng thể Hướng C

```
Input: Mô tả hạ tầng
        ↓
[Phase 1] Network Knowledge Graph  ← GIỐNG HỆT Hướng B
  Zep KG: Host, Zone, CVE, Service, SecurityControl
        ↓
[Phase C1] Attack Graph Generation  ← MỚI
  Build graph từ Zep KG
  Node = (attacker_position, compromised_assets)
  Edge = TTP có thể thực hiện từ node đó
  Thuật toán: BFS tìm ALL paths từ External → Crown Jewel
  Output: Ranked attack path list
        ↓
[Phase C2] Graph-Guided Expert Panel  ← BIẾN THỂ CỦA Hướng B Phase 2–3
  Không tự do phân tích
  Mỗi agent validate 1 set path từ Attack Graph
  "Path này có thực sự khả thi với hạ tầng cụ thể không?"
        ↓
[Phase C3 — Optional] Red/Blue Validation  ← MỚI
  Lấy top 3 path nguy hiểm nhất (expert validated)
  Red agent thực hiện path đó trong simulation
  Blue agent cố phát hiện
  Đo: path nào Blue KHÔNG phát hiện được → ưu tiên fix
        ↓
[Phase 4] Vulnerability Report  ← GIỐNG HỆT Hướng B
  VulnReportAgent (ReACT) tổng hợp 3 layer kết quả
        ↓
Output: "23 paths tìm được → 8 paths khả thi → 3 paths nguy hiểm nhất →
         Blue chỉ detect được 1/3 → Fix theo thứ tự này"
```

---

## Tiến độ bổ sung (trên nền Hướng B)

```
Hướng B hoàn chỉnh      (Tháng 1–8): xem Multi-Expert-Panel-Plan.md
Phase C1 — Attack Graph  (Tháng 9–10): graph builder, path ranking
Phase C2 — Guided Panel  (Tháng 11):   thay free-form bằng path validation
Phase C3 — Red/Blue val  (Tháng 12):   optional simulation layer
Evaluate & Luận án       (Tháng 13–18)
```

---

## Phase C1 — Attack Graph Generation

### Mục tiêu
Dùng graph algorithm để tìm một cách có hệ thống TẤT CẢ các đường tấn công có thể từ Internet đến crown jewel assets.

---

### Bước C1.1 — Attack Graph Builder

**File cần tạo**: `backend/app/services/attack_graph_builder.py`

```python
@dataclass
class AttackNode:
    node_id: str
    attacker_zone: str          # Attacker đang ở zone nào
    compromised_hosts: List[str] # Đã compromise host nào
    available_credentials: List[str]  # Credential đã thu thập được
    kill_chain_phase: str       # Đang ở phase nào trong kill chain

@dataclass
class AttackEdge:
    from_node: str
    to_node: str
    technique_id: str           # TTP thực hiện để đi từ node này sang node kia
    target_host: str            # Host bị tấn công
    prerequisites_met: bool     # Điều kiện tiên quyết có thỏa mãn không
    difficulty: float           # 0.0–1.0, càng thấp càng dễ

@dataclass
class AttackPath:
    path_id: str
    nodes: List[AttackNode]
    edges: List[AttackEdge]
    total_steps: int
    difficulty_score: float     # trung bình difficulty của các edge
    reaches_crown_jewel: bool
    crown_jewels_reached: List[str]
    required_conditions: List[str]  # điều kiện tổng thể để path này khả thi

class AttackGraphBuilder:

    def build_graph(self, graph_id: str) -> nx.DiGraph:
        """
        Đọc NetworkAsset từ Zep KG → build directed graph.

        Node ban đầu: (zone=External, compromised=[], phase=Reconnaissance)
        Với mỗi node, tạo edge cho mỗi TTP có thể áp dụng:
          - Check prerequisites (foothold, admin_privilege, ...)
          - Check target asset có tồn tại trong zone reachable không
          - Tạo node mới (state sau khi TTP thành công)
        """

    def find_all_paths(self, graph: nx.DiGraph,
                       crown_jewels: List[str]) -> List[AttackPath]:
        """
        BFS từ External node → tìm tất cả path đến crown jewel.
        Giới hạn: max depth = 8 (7–8 bước là realistic cho APT).
        Cắt branch nếu:
          - Đã thăm trạng thái này (loop detection)
          - Depth > max_depth
          - Không có TTP nào áp dụng được từ node hiện tại
        """

    def rank_paths(self, paths: List[AttackPath]) -> List[AttackPath]:
        """
        Sort paths theo mức độ nguy hiểm:
          Score = (1 - difficulty_score) × severity_weight × reachability
        Paths dễ thực hiện + đến được crown jewel critical → score cao nhất.
        """

    def identify_crown_jewels(self, assets: List[NetworkAsset]) -> List[str]:
        """
        Crown jewel = host có is_critical=True HOẶC zone=Database.
        Đây là objective cuối cùng của attacker.
        """

    def _get_applicable_ttps(self, node: AttackNode,
                              assets: List[NetworkAsset]) -> List[Tuple[str, str]]:
        """
        Với trạng thái hiện tại (zone, compromised hosts, credentials):
        TTP nào có thể thực hiện và target host nào?
        Return: [(technique_id, target_host_id), ...]
        """

    def _check_prerequisites(self, technique_id: str,
                              node: AttackNode, target: NetworkAsset) -> bool:
        """
        Kiểm tra điều kiện tiên quyết:
          T1190 (exploit web): target phải có CVE và ở zone reachable
          T1021.001 (RDP): phải có foothold trong mạng trước
          T1003.001 (LSASS dump): phải có admin trên Windows host
        """
```

**Kiểm tra xong khi**: Với network 5 host (1 DMZ web server, 3 Internal, 1 Database) → tìm được ít nhất 3 distinct paths đến Database. Paths không có loop. Rank đúng (ít bước + CVE unpatched → score cao).

---

### Bước C1.2 — Attack Graph API

Thêm vào `backend/app/api/cyber.py`:

```
POST /api/cyber/graph/<graph_id>/attack-graph/build
  Body: { max_depth, crown_jewel_overrides }
  Return: { task_id }

GET  /api/cyber/graph/<graph_id>/attack-graph
  Return: {
    total_paths: 23,
    paths_to_crown_jewel: 8,
    ranked_paths: [
      { path_id, steps, difficulty, crown_jewels_reached, technique_sequence }
    ],
    graph_stats: { node_count, edge_count, max_depth_reached }
  }

GET  /api/cyber/graph/<graph_id>/attack-graph/path/<path_id>
  Return: chi tiết 1 path: từng bước, TTP, target host, prerequisite
```

**Kiểm tra xong khi**: Build graph → GET attack-graph → thấy ranked paths với difficulty score hợp lý.

---

## Phase C2 — Graph-Guided Expert Panel

### Mục tiêu
Thay vì expert tự do phân tích, mỗi expert được assign một set attack paths cụ thể để validate.

---

### Bước C2.1 — Guided Review Orchestrator

**File cần sửa**: `backend/app/services/review_session_orchestrator.py`

Thêm mode mới, không xóa free-form mode cũ:

```python
class ReviewSessionOrchestrator:

    def run_session(self, graph_id: str, config: ReviewConfig,
                    mode: str = "free") -> List[ExpertFinding]:
        if mode == "free":
            # Hướng B — tự do phân tích
            return self._run_free_session(graph_id, config)
        elif mode == "guided":
            # Hướng C — validate attack paths từ graph
            return self._run_guided_session(graph_id, config)

    def _run_guided_session(self, graph_id: str,
                             config: ReviewConfig) -> List[ExpertFinding]:
        """
        Khác với free session:
          1. Load ranked attack paths từ attack graph
          2. Assign paths cho experts theo domain:
               Network expert → validate network-level paths (RDP, SMB)
               AppSec expert  → validate exploit paths (T1190, T1059)
               Endpoint expert → validate post-exploitation paths
          3. Expert không POST_FINDING tự do
             → Thay bằng VALIDATE_PATH / REJECT_PATH / MODIFY_PATH
          4. Collect: path nào được validate → trở thành confirmed finding
        """

    def _assign_paths_to_experts(self, paths: List[AttackPath]) -> Dict[str, List[AttackPath]]:
        """
        Phân công path cho expert phù hợp:
          Path có T1190 (web exploit) → assign cho appsec expert
          Path có T1021.001 (RDP) → assign cho network_security
          Path có T1003.001 (LSASS) → assign cho endpoint_security
        Mỗi path được ít nhất 2 expert review (cross-validation).
        """
```

---

### Bước C2.2 — Path Validation Actions

Thêm actions mới vào OASIS Security Review environment:

```python
GUIDED_REVIEW_ACTIONS = {
    # Giữ lại từ Hướng B:
    "POST_FINDING": "...",
    "CHALLENGE_FINDING": "...",
    "VALIDATE_FINDING": "...",

    # Thêm mới cho Hướng C:
    "VALIDATE_PATH": "Xác nhận attack path này khả thi với hạ tầng hiện tại",
    "REJECT_PATH": "Path này không khả thi vì lý do cụ thể (evidence required)",
    "MODIFY_PATH": "Path khả thi nhưng cần điều chỉnh bước X vì Y",
    "FLAG_DETECTION_GAP": "Path này khả thi VÀ Blue team sẽ không detect được vì thiếu tool Z",
}
```

**Kiểm tra xong khi**: Guided session với 8 attack paths → mỗi path được ít nhất 2 expert review → output có VALIDATE/REJECT/MODIFY cho từng path.

---

## Phase C3 — Red/Blue Validation (Optional)

### Mục tiêu
Lấy top 3 attack path đã được expert validate → chạy simulation đơn giản → đo Blue team có phát hiện được không.

Đây là layer **thứ 3 của validation** — sau graph (toán học) và expert (LLM reasoning), simulation là bằng chứng thực nghiệm.

---

### Bước C3.1 — Path Executor

**File cần tạo**: `backend/app/services/path_executor.py`

```python
class PathExecutor:
    """
    Nhận 1 AttackPath đã validated → execute từng bước trong simulation.
    KHÔNG phải full Red/Blue adversarial — chỉ execute path và check detectability.
    """

    def execute_path(self, path: AttackPath,
                     network_state: Dict,
                     blue_controls: SecurityControls) -> PathExecutionResult:
        """
        Với mỗi edge trong path:
          1. Resolve outcome (success/fail dựa trên CVE, patch status, skill)
          2. Generate alert (nếu noise level cao và có tool detect)
          3. Check Blue detection (dùng D3FEND detection probability)
          4. Cập nhật network state

        Không cần LLM cho từng bước — dùng probability model từ mitre_reference.
        LLM chỉ dùng ở cuối để generate explanation.
        """

    def _check_step_detectable(self, technique_id: str,
                                controls: SecurityControls) -> Tuple[bool, float]:
        """
        Dùng D3FEND detection probability:
          T1059.001 + có EDR → 85% chance detect
          T1059.001 + không có EDR → 15% chance detect
        Roll dice → True/False.
        """
```

**Kiểm tra xong khi**: Execute 1 path qua 5 bước → event log rõ ràng, detection outcome hợp lý với controls có sẵn.

---

### Bước C3.2 — Tích hợp vào Report

Kết quả của Path Executor được thêm vào VulnReportAgent:

```python
# Tools mới trong VulnReportAgent (Hướng C):
"get_simulation_results",   # path nào executed, bước nào bị detect
"get_undetected_paths",     # paths mà Blue team KHÔNG phát hiện được
"get_detection_timeline",   # bao giờ thì Blue phát hiện ra (nếu có)
```

Output report Hướng C so với Hướng B:

```
Hướng B output:
  "8 vulnerabilities found, confidence 0.8, recommend EDR"

Hướng C output:
  "23 paths possible → 8 expert-validated → 3 simulated
   Blue team failed to detect path 2 and path 3
   Path 2: Exploit WEB-01 → Lateral via SMB → Database
   Undetected because: no NDR in Internal zone
   Recommend: NDR deployment → blocks 2/3 undetected paths"
```

---

## So sánh Output giữa Hướng B và C

| | Hướng B | Hướng C |
|---|---|---|
| Nguồn evidence | Expert opinion | Graph (toán học) + Expert + Simulation |
| Claim về coverage | "Experts đã phân tích" | "Tất cả paths được duyệt có hệ thống" |
| Prioritization | Severity × Confidence | Severity × Confidence × Detectability |
| Blue team insight | Không có | Có — path nào Blue KHÔNG phát hiện được |
| Defend thesis | "Nhiều chuyên gia đồng ý" | "Toán học + expert + thực nghiệm đồng nhất" |

---

## Không có xung đột với Hướng B

Toàn bộ code Hướng B được giữ nguyên:

```
Thêm vào, không sửa:
  attack_graph_builder.py      ← mới hoàn toàn
  path_executor.py             ← mới hoàn toàn

Sửa nhỏ (thêm mode, không xóa gì):
  review_session_orchestrator.py  ← thêm run_guided_session()
  vuln_report_agent.py            ← thêm 2 tools mới
  cyber.py (API)                  ← thêm 3 endpoint mới

Giữ nguyên hoàn toàn:
  cyber_models.py
  mitre_reference.py
  network_topology_builder.py
  cyber_expert_profile_generator.py
  consensus_engine.py
  Frontend (chỉ thêm Attack Graph visualization)
```

---

## Research Questions bổ sung (thêm vào RQ của Hướng B)

```
RQ4: Attack Graph có tìm ra attack path mà Expert Panel bỏ sót không?
     → So sánh findings của B và C trên cùng network

RQ5: Combination (Graph + Expert + Simulation) có FP rate thấp hơn
     từng layer riêng lẻ không?
     → Đo FP ở mỗi layer và sau khi kết hợp

RQ6: Thứ tự ưu tiên remediation từ Hướng C có khác Hướng B không,
     và cái nào cost-effective hơn?
```

---

## Checklist bổ sung (thêm vào checklist Hướng B)

```
Phase C1 — Attack Graph:
  [ ] attack_graph_builder.py — build graph từ Zep KG
  [ ] find_all_paths() — BFS không loop, depth-limited
  [ ] rank_paths() — difficulty score hợp lý
  [ ] API /attack-graph/build và /attack-graph hoạt động

Phase C2 — Guided Panel:
  [ ] run_guided_session() — path assignment đúng theo domain
  [ ] VALIDATE_PATH / REJECT_PATH actions hoạt động
  [ ] Mỗi path được ít nhất 2 expert review

Phase C3 — Simulation:
  [ ] path_executor.py — execute 5-step path không crash
  [ ] Detection check dùng đúng D3FEND probability
  [ ] Kết quả inject được vào VulnReportAgent

Integrate:
  [ ] Report Hướng C có thêm "undetected paths" section
  [ ] So sánh output B vs C trên cùng kịch bản
```

---

## Quyết định thực tế

Hướng C thêm **2–3 tháng** so với Hướng B. Gợi ý:

- Nếu thời gian còn **> 6 tháng**: Implement C đầy đủ
- Nếu thời gian còn **3–6 tháng**: Implement B + Phase C1 (Attack Graph không có simulation)
- Nếu thời gian còn **< 3 tháng**: Hoàn thiện B, mention C như future work

Phase C3 (Red/Blue simulation) là layer **có thể bỏ qua** mà không ảnh hưởng đến novelty claim — Attack Graph + Expert Panel đã đủ mạnh cho thesis.

---

*Tài liệu phản ánh extension plan tại thời điểm khởi động hướng C. Implement Hướng B hoàn chỉnh trước khi bắt đầu bất kỳ bước nào trong tài liệu này.*
