# Semantic Finding Track — Implementation Plan

> Phần 2 của Phase 5 evaluation. Prerequisite cho Phase 5d (Web3Bugs).
> Effort: ~5–6 ngày. Không xung đột SWC pipeline hiện tại.
>
> Trạng thái: ⬜ Pending (bắt đầu sau khi Phase 5c SmartBugs xong)

---

## Mục tiêu

Thêm **parallel pipeline** để capture **business logic / semantic vulnerabilities** — loại bug không có SWC ID, mà Slither/Mythril đạt 0% recall. Pipeline mới chạy **song song** với SWC pipeline hiện tại (không thay thế).

**Output mới**: `SEMANTIC_FINDING` block trong agent posts → `SemanticFinding` dataclass → section riêng trong audit report → đánh giá được Web3Bugs S-category.

**Evidence cho paper**: C5 — "MECAP detects semantic logic vulnerabilities that static tools miss entirely (0% recall)."

---

## Format block mới

```
SEMANTIC_FINDING: <title mô tả business logic bug>
CATEGORY: <price_oracle|flash_loan|governance_attack|incorrect_accounting|
           state_machine_bug|incentive_misalignment|other>
SEVERITY: <critical|high|medium|low>
FUNCTION: <function_name()>
EVIDENCE: <behavior cụ thể — state variable nào, calculation nào, call sequence nào>
ATTACK_PATH:
  1) Attacker làm gì
  2) Tại sao contract phản ứng sai
  3) Kết quả đạt được (fund loss / state corruption / privilege gain)
```

**Phân biệt với `FINDING` block**:
- `FINDING` → kèm `SWC: SWC-107` → pipeline SWC hiện tại xử lý
- `SEMANTIC_FINDING` → không có SWC → pipeline semantic mới xử lý
- Một agent post có thể chứa cả hai

---

## Tổng quan 6 bước

| Bước | File | Thay đổi | Effort |
|------|------|----------|--------|
| 1 | `models/contract_models.py` | Thêm `SemanticFinding` dataclass + field trong `ContractSessionState` | 30 phút |
| 2 | `services/contract_oasis_env.py` | `parse_semantic_finding_from_text()` + cập nhật 3 agent prompts | 2–3 giờ |
| 3 | `services/cyber_session_orchestrator.py` | `_process_semantic_response()` + `semantic_findings` list trong session state | 2–3 giờ |
| 4 | `services/consensus_engine.py` | `_cluster_semantic_findings()` + `SEMANTIC_ANCHOR_KEYWORDS` | 2 giờ |
| 5 | `services/contract_audit_agent.py` | Tool `get_semantic_findings()` + Section 5B trong report | 1–2 giờ |
| 6 | `scripts/evaluate_web3bugs.py` | L→SWC mapping + S-category keyword match | 3–4 giờ |

---

## Bước 1 — `SemanticFinding` dataclass

**File**: `backend/app/models/contract_models.py`

**Vị trí chèn**: Ngay sau `ContractFinding` dataclass.

```python
@dataclass
class SemanticFinding:
    """
    Business logic / semantic vulnerability — không có SWC ID tương ứng.
    Parallel track bên cạnh ContractFinding (SWC-based).
    """
    finding_id: str                  # "semantic_<author>_<round>_<seq>"
    author_domain: str               # "defi" | "smart_contract_economics" | "governance"
    author_persona: str              # "offensive" | "analyst" | "economist"
    title: str                       # "Price oracle manipulation in borrow()"
    category: str                    # Xem SEMANTIC_CATEGORIES bên dưới
    severity: str                    # "critical" | "high" | "medium" | "low"
    affected_functions: List[str]    # ["borrow()", "getPrice()"]
    evidence: str                    # Behavior cụ thể, không phải pattern regex
    attack_path: List[str]           # ["1) Flash loan 100 ETH", "2) ...", "3) ..."]
    phase: str                       # "A" | "B" | "C"
    round_number: int
    confidence: float = 0.55         # Default thấp hơn SWC (semantic less certain)
    validated_by: List[str] = field(default_factory=list)   # agent_ids đã validate
    challenged_by: List[str] = field(default_factory=list)
    is_exploitable: Optional[bool] = None
    is_attacker_surfaced: bool = False  # True nếu attacker ADD_PATH, không phải expert


SEMANTIC_CATEGORIES = {
    "price_oracle":           "Flash loan / spot price manipulation",
    "flash_loan":             "Flash loan exploit path (non-oracle)",
    "governance_attack":      "Governance manipulation / flash loan voting",
    "incorrect_accounting":   "Rounding error / precision loss / fee calculation bug",
    "state_machine_bug":      "Invalid state transition / unprotected phase change",
    "incentive_misalignment": "Tokenomics exploit / reward manipulation",
    "reentrancy_logic":       "Cross-function / read-only reentrancy (logic variant)",
    "other":                  "Logic bug không fit vào category trên",
}
```

**Cập nhật `ContractSessionState`** — thêm field `semantic_findings`:

```python
@dataclass
class ContractSessionState:
    # ... existing fields ...
    contract_findings: List[Dict] = field(default_factory=list)
    attacker_findings: List[Dict] = field(default_factory=list)
    semantic_findings: List[Dict] = field(default_factory=list)  # THÊM DÒNG NÀY
    # ... rest of fields ...
```

**Kiểm tra xong khi**: `from models.contract_models import SemanticFinding, SEMANTIC_CATEGORIES` không lỗi. `ContractSessionState()` có attribute `semantic_findings`.

---

## Bước 2 — Parser + Format + Agent Prompts

**File**: `backend/app/services/contract_oasis_env.py`

### 2a — Thêm constant `SEMANTIC_FINDING_FORMAT`

**Vị trí chèn**: Cạnh `CONTRACT_FINDING_FORMAT` (đã có), khoảng đầu file sau các action dicts.

```python
SEMANTIC_FINDING_FORMAT = """
SEMANTIC_FINDING: <title mô tả logic bug>
CATEGORY: <price_oracle|flash_loan|governance_attack|incorrect_accounting|state_machine_bug|incentive_misalignment|other>
SEVERITY: <critical|high|medium|low>
FUNCTION: <affected_function_name()>
EVIDENCE: <state variable / call sequence / calculation dẫn đến bug>
ATTACK_PATH:
  1) <Attacker hành động gì>
  2) <Contract phản ứng sai ra sao>
  3) <Kết quả: fund loss / state corruption / privilege gain>
"""

SEMANTIC_CATEGORIES_LIST = [
    "price_oracle", "flash_loan", "governance_attack",
    "incorrect_accounting", "state_machine_bug",
    "incentive_misalignment", "reentrancy_logic", "other",
]
```

### 2b — Thêm `parse_semantic_finding_from_text()`

**Vị trí chèn**: Ngay sau `parse_contract_finding_from_text()` function.

```python
def parse_semantic_finding_from_text(
    text: str,
    agent_profile: "ContractAgentProfile",
    round_num: int,
) -> Optional[Dict[str, Any]]:
    """
    Extract SEMANTIC_FINDING block từ agent post.
    Trả về dict hoặc None nếu không có block hợp lệ.
    """
    # Gate: block phải tồn tại
    if "SEMANTIC_FINDING:" not in text:
        return None

    lines = text.split("\n")
    in_block = False
    fields: Dict[str, str] = {}
    attack_path_lines: List[str] = []
    in_attack_path = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("SEMANTIC_FINDING:"):
            in_block = True
            in_attack_path = False
            fields["title"] = stripped[len("SEMANTIC_FINDING:"):].strip()
            continue
        if not in_block:
            continue

        if stripped.startswith("CATEGORY:"):
            fields["category"] = stripped[len("CATEGORY:"):].strip().lower()
            in_attack_path = False
        elif stripped.startswith("SEVERITY:"):
            fields["severity"] = stripped[len("SEVERITY:"):].strip().lower()
            in_attack_path = False
        elif stripped.startswith("FUNCTION:"):
            fields["function"] = stripped[len("FUNCTION:"):].strip()
            in_attack_path = False
        elif stripped.startswith("EVIDENCE:"):
            fields["evidence"] = stripped[len("EVIDENCE:"):].strip()
            in_attack_path = False
        elif stripped.startswith("ATTACK_PATH:"):
            in_attack_path = True
        elif in_attack_path and stripped and stripped[0].isdigit():
            attack_path_lines.append(stripped)
        elif stripped == "" and in_attack_path and attack_path_lines:
            # blank line ends ATTACK_PATH block
            in_attack_path = False
        elif stripped.startswith("FINDING:") or stripped.startswith("ANALYZED:"):
            # New block starts — stop parsing this semantic block
            break

    # Validate required fields
    title = fields.get("title", "").strip()
    if not title or len(title) < 5:
        return None

    category = fields.get("category", "other")
    if category not in SEMANTIC_CATEGORIES_LIST:
        category = "other"

    severity = fields.get("severity", "medium")
    if severity not in ("critical", "high", "medium", "low"):
        severity = "medium"

    # Extract function name — same filter as parse_contract_finding_from_text
    raw_fn = fields.get("function", "")
    fn_match = re.match(r"^([a-zA-Z_]\w*)\s*\(", raw_fn)
    affected_functions = [fn_match.group(1) + "()"] if fn_match else []

    evidence = fields.get("evidence", "").strip()
    if not evidence:
        return None  # Evidence required — prevent vacuous semantic claims

    import time, random
    finding_id = (
        f"semantic_{agent_profile.domain}_{round_num}_"
        f"{int(time.time()) % 10000}_{random.randint(0, 99):02d}"
    )

    return {
        "finding_id": finding_id,
        "author_domain": agent_profile.domain,
        "author_persona": agent_profile.persona,
        "title": title,
        "category": category,
        "severity": severity,
        "affected_functions": affected_functions,
        "evidence": evidence,
        "attack_path": attack_path_lines,
        "phase": "A" if round_num <= 3 else "B" if round_num <= 7 else "C",
        "round_number": round_num,
        "confidence": 0.55,
        "validated_by": [],
        "challenged_by": [],
        "is_exploitable": None,
        "is_attacker_surfaced": False,
    }
```

### 2c — Cập nhật agent system prompts

Ba domain cần emit `SEMANTIC_FINDING` theo mặc định:

**`defi` offensive/defensive** — Thêm vào cuối system prompt:

```python
# Thêm vào CONTRACT_AGENT_MATRIX["defi"]["persona_prompts"]["offensive"]:
"""
...existing prompt...

When you find DeFi-specific logic bugs (price oracle manipulation, flash loan 
attack paths, liquidity imbalance), use SEMANTIC_FINDING format:

SEMANTIC_FINDING: Flash loan price manipulation in borrow()
CATEGORY: price_oracle
SEVERITY: critical
FUNCTION: borrow()
EVIDENCE: getPrice() reads spot price from DEX pool — manipulable in same tx
ATTACK_PATH:
  1) Flash loan 10,000 ETH to manipulate pool spot price
  2) borrow() calls getPrice() which returns inflated collateral value
  3) Extract protocol funds at artificially high collateral ratio
"""
```

**`smart_contract_economics` economist/protocol_designer** — Thêm:

```python
"""
...existing prompt...

For tokenomics and incentive misalignment bugs, use SEMANTIC_FINDING format:

SEMANTIC_FINDING: Reward calculation inflation via deposit-withdraw loop
CATEGORY: incentive_misalignment
SEVERITY: high
FUNCTION: claimReward()
EVIDENCE: rewardPerToken() uses totalSupply snapshot taken at deposit — no cooldown
ATTACK_PATH:
  1) Deposit large amount to inflate reward rate
  2) Call claimReward() before others deposit
  3) Withdraw immediately — earned disproportionate rewards
"""
```

**`logic_exploiter` (Tier 2 attacker)** — Đây là Tier 2 profile trong `CONTRACT_ATTACKER_PROFILES`. Thêm vào `prompt` field:

```python
# Trong CONTRACT_ATTACKER_PROFILES["logic_exploiter"]["prompt"]:
"""
...existing prompt...

Khi tìm thấy logic bug, dùng SEMANTIC_FINDING thay FINDING:
SEMANTIC_FINDING: <title>
CATEGORY: <state_machine_bug|incorrect_accounting|incentive_misalignment|other>
...
"""
```

**Kiểm tra xong khi**:
- `parse_semantic_finding_from_text("SEMANTIC_FINDING: oracle manip\nCATEGORY: price_oracle\nSEVERITY: critical\nFUNCTION: borrow()\nEVIDENCE: spot price\nATTACK_PATH:\n  1) flash\n  2) drain\n  3) profit", mock_profile, 2)` → trả về dict với đủ fields.
- Post không có `SEMANTIC_FINDING:` → trả về `None`.

---

## Bước 3 — Session Orchestrator

**File**: `backend/app/services/cyber_session_orchestrator.py`

### 3a — Thêm `semantic_findings` vào session state dict

Tìm chỗ khởi tạo session state dict trong `_session_worker()` (khoảng sau khi tạo `ContractSessionState`):

```python
# Hiện tại có:
state = {
    "session_id": session_id,
    "expert_findings": [],
    "attacker_findings": [],
    # ...
}

# Thêm:
state = {
    "session_id": session_id,
    "expert_findings": [],
    "attacker_findings": [],
    "semantic_findings": [],   # THÊM DÒNG NÀY
    # ...
}
```

### 3b — Thêm `_process_semantic_response()`

**Vị trí**: Ngay sau `_process_expert_response()` method.

```python
def _process_semantic_response(
    self,
    text: str,
    profile: "CyberAgentProfile",
    round_num: int,
    session_state: dict,
) -> None:
    """
    Extract SEMANTIC_FINDING block từ agent post và append vào semantic_findings list.
    Gọi sau _process_expert_response() cho cùng post text.
    Chỉ chạy trong contract_audit mode.
    """
    mods = _get_contract_modules()
    parse_fn = mods["parse_semantic_finding_from_text"]

    finding = parse_fn(text, profile, round_num)
    if finding is None:
        return

    # Dedup: bỏ qua nếu title quá giống finding đã có (>80% token overlap)
    existing_titles = [f["title"].lower() for f in session_state.get("semantic_findings", [])]
    new_tokens = set(finding["title"].lower().split())
    for et in existing_titles:
        overlap = len(new_tokens & set(et.split())) / max(len(new_tokens), 1)
        if overlap > 0.8:
            return

    session_state.setdefault("semantic_findings", []).append(finding)
    logger.debug(
        f"[Semantic] {profile.agent_id} round {round_num}: "
        f"{finding['category']} — {finding['title'][:60]}"
    )
```

### 3c — Gọi trong `_process_expert_response()` và `_process_attacker_response()`

Trong `_process_expert_response()`, sau khi xử lý FINDING block, thêm:

```python
# Contract audit mode: cũng check SEMANTIC_FINDING trong cùng post
if mode == "contract_audit":
    self._process_semantic_response(text, profile, round_num, session_state)
```

Trong `_process_attacker_response()`, sau khi xử lý ADD_PATH logic, thêm:

```python
# Attacker có thể surface semantic bugs không có trong expert findings
if mode == "contract_audit":
    self._process_semantic_response(text, profile, round_num, session_state)
    # Mark attacker-surfaced findings
    new_semantic = session_state.get("semantic_findings", [])
    if new_semantic:
        last = new_semantic[-1]
        if last.get("author_domain") == profile.domain:
            last["is_attacker_surfaced"] = True
```

### 3d — Expose semantic_findings trong session save/load

Tìm chỗ `_save_session_state()` / `_load_session_state()` — thêm `semantic_findings` vào serialization (nếu dùng JSON dict, không cần thay đổi thêm vì dict serialize tự động).

**Kiểm tra xong khi**:
- Session run với contract có oracle → `session_state["semantic_findings"]` không empty.
- Network security mode (mode="network_security") → `_process_semantic_response()` không được gọi.

---

## Bước 4 — Consensus Clustering cho Semantic Findings

**File**: `backend/app/services/consensus_engine.py`

### 4a — Thêm `SEMANTIC_ANCHOR_KEYWORDS`

**Vị trí**: Cạnh `SWC_ANCHOR_KEYWORDS` (đã có):

```python
SEMANTIC_ANCHOR_KEYWORDS: Dict[str, List[str]] = {
    "price_oracle":           ["oracle", "price", "spot price", "TWAP", "getPrice", "manipulation"],
    "flash_loan":             ["flash loan", "flashloan", "flash", "single transaction", "atomic"],
    "governance_attack":      ["governance", "voting", "proposal", "timelock", "quorum", "token vote"],
    "incorrect_accounting":   ["rounding", "precision", "fee calculation", "truncation", "accounting"],
    "state_machine_bug":      ["state machine", "phase", "transition", "guard", "invariant"],
    "incentive_misalignment": ["reward", "incentive", "tokenomics", "staking", "yield", "emission"],
    "reentrancy_logic":       ["cross-function", "read-only reentrancy", "view reentrant", "callback"],
}
```

### 4b — Thêm `_cluster_semantic_findings()`

**Vị trí**: Ngay sau `_cluster_findings()` method.

```python
def _cluster_semantic_findings(
    self, semantic_findings: List[Dict]
) -> List[List[Dict]]:
    """
    Cluster semantic findings theo category + title similarity.
    Simpler than SWC clustering: category match = strong signal.
    """
    if not semantic_findings:
        return []

    clusters: List[List[Dict]] = []

    for finding in semantic_findings:
        placed = False
        for cluster in clusters:
            rep = cluster[0]
            # Same category = candidate for same cluster
            if rep["category"] == finding["category"]:
                # Additional check: title token overlap
                rep_tokens = set(rep["title"].lower().split())
                new_tokens = set(finding["title"].lower().split())
                overlap = len(rep_tokens & new_tokens) / max(len(rep_tokens | new_tokens), 1)
                if overlap > 0.3:
                    cluster.append(finding)
                    placed = True
                    break
            # Even different category: check SEMANTIC_ANCHOR keyword overlap
            elif self._shares_semantic_anchor(rep, finding):
                cluster.append(finding)
                placed = True
                break

        if not placed:
            clusters.append([finding])

    return clusters


def _shares_semantic_anchor(self, f1: Dict, f2: Dict) -> bool:
    """True nếu 2 semantic findings share anchor keyword."""
    text1 = (f1.get("title", "") + " " + f1.get("evidence", "")).lower()
    text2 = (f2.get("title", "") + " " + f2.get("evidence", "")).lower()
    for keywords in SEMANTIC_ANCHOR_KEYWORDS.values():
        if any(kw.lower() in text1 for kw in keywords) and \
           any(kw.lower() in text2 for kw in keywords):
            return True
    return False
```

### 4c — Thêm `_score_semantic_cluster()` và tích hợp vào `run()`

```python
def _score_semantic_cluster(self, cluster: List[Dict]) -> Optional[Dict]:
    """
    Score semantic cluster — tương tự _score_cluster() nhưng không cần SWC ID.
    Returns consolidated semantic finding dict, hoặc None nếu confidence < threshold.
    """
    if not cluster:
        return None

    domains = {f["author_domain"] for f in cluster}
    intra = len([f for f in cluster if f["author_domain"] == cluster[0]["author_domain"]]) / len(cluster)
    cross = min(len(domains) / 3.0, 1.0)  # 3+ domains = full cross-domain
    attacker = sum(1 for f in cluster if f.get("is_attacker_surfaced", False)) * 0.25

    confidence = (
        intra * WEIGHT_INTRA +
        cross * WEIGHT_CROSS +
        min(attacker, 1.0) * WEIGHT_ATTACK
    )

    if confidence < MIN_CONFIDENCE:
        return None

    rep = max(cluster, key=lambda f: f["confidence"])  # highest-confidence finding as rep
    return {
        "vuln_id": f"semantic_{rep['category']}_{rep['finding_id'][-4:]}",
        "title": rep["title"],
        "category": rep["category"],
        "severity": rep["severity"],
        "affected_functions": rep["affected_functions"],
        "evidence": rep["evidence"],
        "attack_path": rep["attack_path"],
        "confidence_score": round(confidence, 3),
        "supporting_domains": sorted(domains),
        "is_attacker_surfaced": any(f.get("is_attacker_surfaced") for f in cluster),
        "source_finding_ids": [f["finding_id"] for f in cluster],
    }
```

Trong method `run()` — sau khi xử lý SWC findings, thêm:

```python
def run(
    self,
    expert_findings_raw: List[Dict],
    attacker_findings_raw: List[Dict],
    semantic_findings_raw: List[Dict],   # THÊM PARAM (default=[])
    domain_group_count: int = 5,
    mode: str = "network_security",
) -> Tuple[List[ConsensusVulnerability], List[Dict]]:  # (swc_results, semantic_results)
    """
    Returns:
      - swc_results: List[ConsensusVulnerability] — hiện tại
      - semantic_results: List[Dict] — consolidated semantic findings (mới)
    """
    # ... existing SWC logic ...

    # NEW: Process semantic findings
    semantic_results = []
    if mode == "contract_audit" and semantic_findings_raw:
        clusters = self._cluster_semantic_findings(semantic_findings_raw)
        for cluster in clusters:
            result = self._score_semantic_cluster(cluster)
            if result:
                semantic_results.append(result)
        semantic_results.sort(key=lambda x: x["confidence_score"], reverse=True)

    return swc_results, semantic_results
```

> **Backward compat**: `run()` signature thay đổi — cần cập nhật tất cả caller.
> Caller chính là `contract_audit_agent.py` → cập nhật ở Bước 5.
> Network mode: `semantic_findings_raw=[]` → `semantic_results=[]` → không ảnh hưởng.

**Kiểm tra xong khi**:
- 3 semantic findings cùng `category="price_oracle"` → cluster thành 1 → `_score_semantic_cluster()` trả về result với `confidence > 0`.
- 1 semantic finding từ 1 domain → `confidence < MIN_CONFIDENCE` → filtered out.

---

## Bước 5 — Report Agent

**File**: `backend/app/services/contract_audit_agent.py`

### 5a — Thêm tool `get_semantic_findings`

Trong `_ContractToolContext`, thêm sau `_get_defi_specific_risks()`:

```python
def _get_semantic_findings(self, args: Dict) -> str:
    """
    Tool: get_semantic_findings
    Returns consolidated semantic/logic findings — Web3Bugs S-category equivalent.
    """
    semantic = self._report_data.get("semantic_results", [])
    if not semantic:
        return "No semantic/logic vulnerabilities detected in this audit."

    lines = [f"SEMANTIC FINDINGS ({len(semantic)} total):", ""]
    for item in semantic:
        lines.append(f"[{item['severity'].upper()}] {item['title']}")
        lines.append(f"  Category: {item['category']}")
        lines.append(f"  Functions: {', '.join(item.get('affected_functions', ['unknown']))}")
        lines.append(f"  Confidence: {item['confidence_score']:.3f}")
        lines.append(f"  Domains: {', '.join(item.get('supporting_domains', []))}")
        if item.get("is_attacker_surfaced"):
            lines.append("  [ATTACKER SURFACED]")
        lines.append(f"  Evidence: {item.get('evidence', '')[:150]}")
        path = item.get("attack_path", [])
        if path:
            lines.append("  Attack path:")
            for step in path:
                lines.append(f"    {step}")
        lines.append("")
    return "\n".join(lines)
```

Đăng ký trong tool dispatch dict:

```python
TOOL_DISPATCH = {
    # ... existing tools ...
    "get_semantic_findings": self._get_semantic_findings,
}
```

Thêm vào `CONTRACT_AUDIT_TOOLS` list:

```python
CONTRACT_AUDIT_TOOLS = [
    # ... existing 10 tools ...
    "get_semantic_findings",   # THÊM
]
```

### 5b — Thêm Section 5B vào report system prompt

Trong `CONTRACT_AUDIT_SYSTEM_PROMPT`, sau Section 5 (DEFI-SPECIFIC RISKS):

```
5B. SEMANTIC / LOGIC VULNERABILITIES
    (Bỏ qua section này nếu get_semantic_findings trả về "No semantic...")
    Với mỗi semantic finding:
    - Category + title
    - Affected function(s)
    - Confidence score + supporting domains
    - Attack path (numbered steps)
    - Why static tools miss this: "No SWC pattern — requires understanding of protocol intent"
    - Recommendation

    Ghi chú quan trọng cho paper: đây là vulnerabilities mà Slither và Mythril không thể detect.
```

### 5c — Cập nhật `generate_report_sync()`

```python
# Hiện tại gọi consensus engine:
swc_results = self.consensus_engine.run(
    expert_findings_raw=session_state["expert_findings"],
    attacker_findings_raw=session_state["attacker_findings"],
    mode="contract_audit",
)

# Cập nhật thành:
swc_results, semantic_results = self.consensus_engine.run(
    expert_findings_raw=session_state["expert_findings"],
    attacker_findings_raw=session_state["attacker_findings"],
    semantic_findings_raw=session_state.get("semantic_findings", []),
    mode="contract_audit",
)

# Thêm semantic_results vào report_data:
self._report_data = {
    "consensus_vulns": swc_results,
    "semantic_results": semantic_results,   # THÊM
    # ... rest ...
}

# Cập nhật stats:
stats = {
    "critical": ...,
    "high": ...,
    "semantic_count": len(semantic_results),   # THÊM
    "semantic_critical": sum(1 for s in semantic_results if s["severity"] == "critical"),
}
```

**Kiểm tra xong khi**:
- `get_semantic_findings({})` với mock `semantic_results` → trả về formatted string.
- `get_semantic_findings({})` với empty list → trả về "No semantic...".
- `generate_report_sync()` trả về dict có key `semantic_results`.

---

## Bước 6 — `evaluate_web3bugs.py`

**File**: `backend/scripts/evaluate_web3bugs.py`

### L-category → SWC mapping table

```python
L_TO_SWC = {
    "L1": "SWC-107",   # Reentrancy
    "L2": "SWC-101",   # Rounding / precision loss → arithmetic
    "L5": "SWC-112",   # Storage collision (proxy)
    "L6": "SWC-104",   # Arbitrary external call / unchecked send
    "L7": "SWC-101",   # Integer overflow / underflow
    "LB": "SWC-115",   # tx.origin usage
}

# S-category → semantic categories (cho keyword matching)
S_TO_SEMANTIC = {
    "S1": ["price_oracle", "flash_loan"],          # Price oracle manipulation
    "S3": ["state_machine_bug", "incorrect_accounting"],  # Wrong state update
    "S4": ["incentive_misalignment"],              # Reward/tokenomics bug
    "S6": ["incorrect_accounting", "state_machine_bug"],  # Bad accounting
    "SE": ["price_oracle", "flash_loan", "governance_attack"],  # Economic exploit
    "SC": ["state_machine_bug", "governance_attack"],  # Contract logic bug
}
```

### Script structure

```python
"""
evaluate_web3bugs.py — Phase 5d evaluation script.

Usage:
    python evaluate_web3bugs.py \
        --contracts ./web3bugs_subset/ \
        --bugs-csv /path/to/Web3Bugs/results/bugs.csv \
        --output ./results/phase5d/

Pipeline per contract:
    1. Load bugs.csv — filter to this contract's HIGH findings
    2. Split ground truth: L-category vs S-category
    3. Run MECAP audit (calls run_contract_audit.py pipeline)
    4. L-evaluation: found SWC IDs vs L→SWC mapped ground truth
    5. S-evaluation: SemanticFinding categories vs S-category keywords
    6. Save audit_report.json + metrics

Outputs:
    phase5d/
      <contract>/
        audit_report.json     — full audit results
      summary.json            — aggregated L-recall + S-recall + per-contract
      summary.csv
"""
```

### S-recall metric logic

```python
def compute_s_recall(semantic_results: List[Dict], s_ground_truth: List[str]) -> float:
    """
    Semantic recall: fraction of S-category ground truth bugs detected.
    
    Match logic:
    - Ground truth: S1/S3/S4/S6/SE/SC bugs for this contract
    - Prediction: SemanticFinding categories from MECAP
    - Match = any predicted category in S_TO_SEMANTIC[s_label] 
              AND affected_function overlaps (if function info available)
    
    Conservative: count each S-bug as matched only once.
    """
    if not s_ground_truth:
        return None  # N/A — no S-category bugs in this contract

    matched = 0
    predicted_categories = {sf["category"] for sf in semantic_results}

    for s_label in s_ground_truth:
        expected_categories = S_TO_SEMANTIC.get(s_label, ["other"])
        if any(cat in predicted_categories for cat in expected_categories):
            matched += 1

    return matched / len(s_ground_truth)
```

### Summary output format

```
================================================================================
Web3Bugs Phase 5d Evaluation — N contracts
================================================================================
                        N    L-TP  L-FP  L-FN    L-P    L-R   L-F1   S-TP  S-FN  S-Recall
  Contract A            1       1     0     0  1.000  1.000  1.000     1     0   1.000
  Contract B            1       0     1     2  0.000  0.000  0.000     0     1   0.000
  ...
--------------------------------------------------------------------------------
  TOTAL                10       X     Y     Z   P_L    R_L    F1_L    S_X   S_Z   S_R
================================================================================
Note: S-recall baseline (Slither/Mythril) = 0.000 — static tools cannot detect semantic bugs
================================================================================
```

**Kiểm tra xong khi**:
- `L_TO_SWC` coverage: tất cả L-labels trong bugs.csv đều có mapping.
- `compute_s_recall([], ["S1"])` → `None` (no predictions) không crash.
- `compute_s_recall([{"category": "price_oracle"}], ["S1"])` → `1.0`.

---

## Test checklist tổng thể

```
Bước 1 — SemanticFinding dataclass:
  [ ] Import không lỗi
  [ ] ContractSessionState có semantic_findings field
  [ ] SemanticFinding() instantiate với defaults đúng

Bước 2 — Parser + Prompts:
  [ ] parse_semantic_finding_from_text() — post có SEMANTIC_FINDING block → dict đủ fields
  [ ] parse_semantic_finding_from_text() — post không có block → None
  [ ] parse_semantic_finding_from_text() — thiếu EVIDENCE field → None
  [ ] category không hợp lệ → normalize về "other"
  [ ] FINDING block và SEMANTIC_FINDING block cùng post → cả 2 đều parse được (không interfere)
  [ ] defi agent system prompt chứa SEMANTIC_FINDING example
  [ ] logic_exploiter prompt chứa SEMANTIC_FINDING example

Bước 3 — Orchestrator:
  [ ] _process_semantic_response() append vào semantic_findings[]
  [ ] Duplicate title (>80% overlap) → skip
  [ ] Mode="network_security" → semantic_findings không được populate
  [ ] is_attacker_surfaced=True cho Tier 2 attacker posts

Bước 4 — Consensus:
  [ ] 3 findings cùng category, 3 domains → clustered → scored > 0
  [ ] 1 finding, 1 domain → confidence < MIN_CONFIDENCE → filtered
  [ ] _shares_semantic_anchor() → oracle keywords match
  [ ] run() backward compat: semantic_findings_raw=[] → semantic_results=[]

Bước 5 — Report Agent:
  [ ] get_semantic_findings() với mock data → formatted string
  [ ] get_semantic_findings() với [] → "No semantic..." string
  [ ] generate_report_sync() trả về dict có key "semantic_results"
  [ ] Stats có key "semantic_count"

Bước 6 — evaluate_web3bugs.py:
  [ ] L_TO_SWC coverage đầy đủ
  [ ] compute_s_recall() với empty predictions → None (not 0.0)
  [ ] compute_s_recall() với matching category → 1.0
  [ ] Script chạy với 1 contract test → output audit_report.json hợp lệ
```

---

## Backward compatibility

| Điều kiện | Behavior |
|-----------|----------|
| `mode="network_security"` | `semantic_findings` không được gọi, `run()` nhận `semantic_findings_raw=[]` → trả về `(swc_results, [])`. Không ảnh hưởng Hướng B. |
| Session state cũ (không có `semantic_findings` key) | `session_state.get("semantic_findings", [])` → empty list, không crash. |
| Report gen với agent không emit SEMANTIC_FINDING | `semantic_results=[]` → `get_semantic_findings()` trả về "No semantic..." → Section 5B bị skip trong report. |
| `evaluate_phase5a/5b/5c.py` | Không call `consensus_engine.run()` trực tiếp — không cần cập nhật. |

---

## Dependency order

```
Bước 1 (models)
    ↓
Bước 2 (parser/prompts)  ←── không phụ thuộc Bước 3/4/5
    ↓
Bước 3 (orchestrator)    ←── phụ thuộc Bước 1 + 2
    ↓
Bước 4 (consensus)       ←── phụ thuộc Bước 1 + 3
    ↓
Bước 5 (report agent)    ←── phụ thuộc Bước 4 (vì gọi consensus.run())
    ↓
Bước 6 (evaluate script) ←── phụ thuộc Bước 1–5 (full pipeline)
```

Có thể implement Bước 1 + 2 song song với nhau (không phụ thuộc lẫn nhau).
