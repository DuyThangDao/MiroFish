# Smart Contract Multi-Expert Audit — Kế hoạch Triển khai (Đề tài 10)

## Tổng quan

### Ý tưởng cốt lõi

Áp dụng kiến trúc Multi-Expert Panel của MiroFish (Hướng B) vào **kiểm toán lỗ hổng Smart Contract**, thay thế:

```
Hướng B                          Đề tài 10
─────────────────────────────    ─────────────────────────────────
NetworkAsset (host/CVE)     →    ContractEntity (function/state_var)
MITRE ATT&CK TTP library    →    SWC Registry (40 weakness types)
Network topology builder    →    Solidity contract parser + KG builder
Attacker profiles           →    Contract attacker profiles
  (APT, Ransomware...)            (Flash Loan, Reentrancy, Governance...)
Security Review Room        →    Contract Audit Room
3-phase session             →    Giữ nguyên hoàn toàn
Consensus Engine (3-layer)  →    Giữ nguyên hoàn toàn
VulnReportAgent             →    ContractAuditReportAgent + patch suggestion
```

### Đóng góp cho paper

```
C1 — Framework: Multi-Expert Contract Audit Panel (first in smart contract domain)
C2 — Grounding: Contract KG anchors agent reasoning, reduces hallucination
C3 — Exploitability: Attacker profiles validate "exists" vs "actually exploitable"
C4 — Consensus: 3-layer confidence reduces FP rate vs GPTScan baseline
C5 — Semantic track: Parallel SEMANTIC_FINDING pipeline detects business logic /
     semantic vulnerabilities (Web3Bugs S-category) — static tools achieve 0% recall
```

### Tiến độ tổng quan

```
Phase 1 — Data Layer          (Tuần 1–2):  Models, SWC Registry, Contract Parser, KG Builder  ✅
Phase 2 — Agent Layer         (Tuần 3–4):  Profile generator, OASIS audit environment          ✅
Phase 3 — Session & Consensus (Tuần 5):    Minimal changes từ Hướng B                         ✅
Phase 4 — Report & API        (Tuần 6–7):  ContractAuditReportAgent, patch tool, endpoints     ✅
Phase 5a/b — Eval debug/validate           SmartBugs samples + reentrancy category             ⬜ In progress
Phase 5 — Semantic Track      (Tuần N):    SemanticFinding + taxonomy normalization            ✅ Core done (2026-04)
Phase 5c — Full SmartBugs Eval             143 contracts, Recall per SWC type                  ⬜ Pending
Phase 5d — Web3Bugs Eval                   10 contests, L/S two-track + policies               ✅ Script + taxonomy (trials ongoing)
Phase 5 — Ablation Study                   V1–V5 variants                                      ⬜ Pending
Phase 6 — Paper Writing       (Tuần 11–14):Introduction → Methodology → Evaluation → Conclusion ⬜
```

---

## Reuse Map — File nào giữ, file nào sửa, file nào tạo mới

```
GIỮ NGUYÊN (không sửa):
  consensus_engine.py              ← 3-layer consensus, semantic clustering
  cyber_session_orchestrator.py    ← 3-phase session logic (chỉ đổi import)
  zep_tools.py                     ← Zep KG query tools
  zep_entity_reader.py             ← Zep entity reader
  zep_graph_memory_updater.py      ← Zep graph updater
  graph_builder.py                 ← Base graph builder (reuse build pattern)

SỬA NHỎ (thêm mode, không xóa gì):
  cyber_session_orchestrator.py    ← Thêm mode="contract_audit" song song mode hiện tại
  consensus_engine.py              ← Thêm SWC anchor types vào semantic clustering
  app/__init__.py                  ← Đăng ký contract_bp blueprint

TẠO MỚI HOÀN TOÀN:
  models/contract_models.py        ← ContractEntity, ContractFinding, AuditResult
  services/semantic_taxonomy.py    ← Canonical S-categories, aliases, SWC→semantic, gap→S rules
  services/swc_registry.py         ← SWC weakness library (thay mitre_reference.py)
  services/contract_parser.py      ← Solidity → ContractEntity list
  services/contract_kg_builder.py  ← Build Zep KG từ contract structure
  services/contract_profile_generator.py  ← 13+5 agent profiles cho contract domain
  services/contract_oasis_env.py   ← Contract Audit Room environment
  services/contract_audit_agent.py ← ContractAuditReportAgent + patch suggestion
  api/contract.py                  ← Blueprint riêng (không thêm vào api/cyber.py)
  scripts/run_contract_audit.py    ← End-to-end script tương tự run_security_review.py

FRONTEND (optional — không cần cho paper):
  Extend MiroFish frontend hiện tại (Vue 3) thêm 2 component nếu cần demo luận án:
  ContractFeed.vue      ← Xem trao đổi agent theo phase/round (reuse SimulationFeed.vue)
  ContractInterview.vue ← Chọn agent → hỏi → xem trả lời (reuse InteractionView.vue)
  → Ưu tiên sau Phase 5 (evaluation) — không block paper
```

---

## Phase 1 — Data Layer (Tuần 1–2)

### Mục tiêu
Có đầy đủ data schema, knowledge base, và parser để đưa Smart Contract vào Zep KG.

---

### Bước 1.1 — Contract Data Schema

**File cần tạo**: `backend/app/models/contract_models.py`

```python
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class SWCCategory(str, Enum):
    """Top-level SWC categories — dùng để assign domain expert."""
    REENTRANCY        = "reentrancy"          # AppSec + Blockchain domain
    ACCESS_CONTROL    = "access_control"      # AppSec + Governance domain
    ARITHMETIC        = "arithmetic"          # Cryptography domain
    UNCHECKED_CALLS   = "unchecked_calls"     # AppSec domain
    DENIAL_OF_SERVICE = "denial_of_service"  # Network domain
    LOGIC_ERROR       = "logic_error"         # All domains
    RANDOMNESS        = "randomness"          # Cryptography domain
    FRONT_RUNNING     = "front_running"       # DeFi/Blockchain domain
    TIMESTAMP         = "timestamp"           # Blockchain domain
    GOVERNANCE        = "governance"          # Governance/DeFi domain


@dataclass
class ContractFunction:
    """Một function trong smart contract."""
    name: str                          # "withdraw"
    visibility: str                    # "public" | "private" | "internal" | "external"
    modifiers: List[str]               # ["onlyOwner", "nonReentrant"]
    has_external_call: bool            # True nếu gọi external contract/address
    state_updates: List[str]           # state vars được modify
    external_call_before_state: bool   # True = reentrancy risk pattern
    sends_ether: bool                  # True nếu có .call{value} hoặc .transfer
    parameters: List[str]              # tên parameter
    return_types: List[str]
    swc_candidates: List[str]          # SWC IDs có thể liên quan (từ static pattern)
    source_lines: Optional[str]        # "45-67"


@dataclass
class ContractStateVar:
    """State variable của contract."""
    name: str                   # "balances"
    var_type: str               # "mapping(address => uint256)"
    visibility: str             # "public" | "private"
    is_critical: bool           # True nếu là balance mapping, owner, admin role
    modified_by: List[str]      # functions nào modify var này


@dataclass
class ContractEntity:
    """Toàn bộ thông tin về 1 smart contract — thay thế NetworkAsset."""
    contract_id: str            # "TokenVault"
    source_code: str            # Full Solidity source
    compiler_version: str       # "0.8.19"
    contract_type: str          # "ERC20" | "DeFi_Lending" | "Governance" | "Custom"
    functions: List[ContractFunction]
    state_vars: List[ContractStateVar]
    external_dependencies: List[str]  # contracts/interfaces được import/call
    has_reentrancy_guard: bool
    has_access_control: bool    # onlyOwner, Role-based
    has_pausable: bool
    uses_oracle: bool           # True nếu dùng price oracle
    uses_flash_loan: bool       # True nếu implements flash loan interface
    is_upgradeable: bool        # Proxy pattern
    swc_candidates: List[str]   # Static analysis preliminary findings
    raw_text: str               # Description thêm (nếu có)


@dataclass
class ContractFinding:
    """Finding từ một expert agent — thay thế ExpertFinding."""
    finding_id: str
    author_domain: str          # "appsec" | "blockchain" | "cryptography" | "defi" | "governance"
    author_persona: str         # "offensive" | "defensive" | "auditor"
    title: str
    description: str
    affected_functions: List[str]  # functions bị ảnh hưởng
    swc_id: str                    # "SWC-107"
    swc_name: str                  # "Reentrancy"
    severity: str
    confidence: float
    evidence: List[str]            # trích dẫn từ contract code/KG
    is_exploitable: Optional[bool] # None = chưa biết, True/False = attacker đã validate
    exploit_scenario: Optional[str]
    patch_suggestion: Optional[str]
    challenged_by: List[str]
    validated_by: List[str]
    cross_domain_validated: bool


@dataclass
class ContractAuditResult:
    """Kết quả cuối — thay thế ConsensusVulnerability."""
    vuln_id: str
    title: str
    description: str
    affected_functions: List[str]
    swc_id: str
    severity: str
    confidence_score: float
    intra_domain_agreement: float
    cross_domain_agreement: float
    attacker_corroboration: float
    supporting_domains: List[str]
    is_exploitable: bool
    exploit_scenario: Optional[str]
    patch_suggestion: str
    mitre_equivalent: Optional[str]   # mapping sang MITRE nếu có
```

**Kiểm tra xong khi**: Import không lỗi. `ContractEntity` có đủ field để parser populate.

---

### Bước 1.2 — SWC Registry

**File cần tạo**: `backend/app/services/swc_registry.py`

Thay thế `mitre_reference.py` — cùng pattern, đổi data source.

```python
# SWC Registry — Smart Contract Weakness Classification
# Source: https://swcregistry.io (40 entries)

SWC_REGISTRY = {
    "SWC-100": {
        "name": "Function Default Visibility",
        "description": "Functions without explicit visibility default to public",
        "category": "access_control",
        "domains": ["appsec", "blockchain"],
        "severity": "medium",
        "example_pattern": "function transfer() { ... }  # missing visibility",
        "mitigation": "Always declare function visibility explicitly",
        "known_exploits": [],
    },
    "SWC-101": {
        "name": "Integer Overflow and Underflow",
        "description": "Arithmetic without bounds checking leads to wrap-around",
        "category": "arithmetic",
        "domains": ["cryptography", "appsec"],
        "severity": "high",
        "example_pattern": "uint8 x = 255; x += 1;  // wraps to 0",
        "mitigation": "Use Solidity 0.8+ (auto-revert) or SafeMath",
        "known_exploits": ["BEC Token hack 2018 — $900M"],
    },
    "SWC-107": {
        "name": "Reentrancy",
        "description": "External call made before state update — attacker can re-enter",
        "category": "reentrancy",
        "domains": ["appsec", "blockchain"],
        "severity": "critical",
        "example_pattern": "msg.sender.call{value: amount}(''); balances[msg.sender] -= amount;",
        "mitigation": "Checks-Effects-Interactions pattern; ReentrancyGuard modifier",
        "known_exploits": ["The DAO 2016 — $60M", "Cream Finance 2021 — $130M"],
    },
    "SWC-115": {
        "name": "Authorization through tx.origin",
        "description": "tx.origin can be manipulated by phishing contracts",
        "category": "access_control",
        "domains": ["appsec"],
        "severity": "high",
        "example_pattern": "require(tx.origin == owner)",
        "mitigation": "Use msg.sender instead of tx.origin",
        "known_exploits": [],
    },
    # ... 36 entries còn lại (đầy đủ trong implementation)
}

# DeFi-specific attack patterns — KHÔNG có trong SWC nhưng critical
DEFI_ATTACK_PATTERNS = {
    "FLASH_LOAN_PRICE_MANIPULATION": {
        "name": "Flash Loan Price Oracle Manipulation",
        "description": "Attacker borrows large amount to manipulate spot price oracle",
        "category": "front_running",
        "domains": ["defi", "blockchain"],
        "severity": "critical",
        "prerequisite": "Contract uses spot price from DEX as oracle",
        "mitigation": "Use TWAP oracle (Uniswap v3) or Chainlink",
        "known_exploits": ["PancakeBunny 2021 — $45M", "Mango Markets 2022 — $117M"],
    },
    "GOVERNANCE_FLASH_LOAN": {
        "name": "Governance Attack via Flash Loan",
        "description": "Borrow governance tokens → pass malicious proposal → return tokens",
        "category": "governance",
        "domains": ["governance", "defi"],
        "severity": "critical",
        "prerequisite": "Governance uses token balance snapshot at vote time",
        "mitigation": "Voting delay after token acquisition; time-lock on proposals",
        "known_exploits": ["Beanstalk 2022 — $182M", "Build Finance 2022 — $470K"],
    },
    "SANDWICH_ATTACK": {
        "name": "Sandwich Attack (MEV)",
        "description": "Front-run victim transaction, manipulate price, back-run",
        "category": "front_running",
        "domains": ["defi"],
        "severity": "medium",
        "prerequisite": "AMM swap without slippage protection",
        "mitigation": "Slippage tolerance; private mempool (Flashbots)",
        "known_exploits": [],
    },
}


class SWCRegistry:
    """
    Smart Contract Weakness Classification Registry.
    Thay thế MitreReference trong Hướng B.
    """

    def get_swc_context_for_agent(self, domain: str, persona: str) -> str:
        """
        Inject SWC context vào agent dựa trên domain + persona.
        Offensive → focus exploit path + known exploits
        Defensive → focus mitigation + detection
        Auditor   → focus compliance + code quality
        """

    def get_swc_for_domain(self, domain: str) -> List[Dict]:
        """Trả về SWC entries relevant cho domain này."""

    def get_swc_by_id(self, swc_id: str) -> Optional[Dict]:
        """Tra cứu SWC entry theo ID."""

    def get_defi_patterns_for_contract(self, entity: ContractEntity) -> List[Dict]:
        """
        Với contract cụ thể, trả về DeFi attack patterns relevant:
          uses_oracle=True → FLASH_LOAN_PRICE_MANIPULATION
          has governance functions → GOVERNANCE_FLASH_LOAN
          is AMM → SANDWICH_ATTACK
        """
```

**Kiểm tra xong khi**: `get_swc_context_for_agent("appsec", "offensive")` khác với `("appsec", "defensive")`.

---

### Bước 1.3 — Solidity Contract Parser

**File cần tạo**: `backend/app/services/contract_parser.py`

```python
class ContractParser:
    """
    Parse Solidity source code → ContractEntity.
    Strategy: LLM-based extraction (không cần Solidity compiler).
    Lý do: LLM đủ tốt để extract structure, và không cần setup toolchain phức tạp.
    """

    def parse_from_source(self, source_code: str,
                           contract_name: str = "") -> ContractEntity:
        """
        Gửi source code cho LLM → extract structured ContractEntity.

        LLM prompt extract:
          - Tên functions + visibility + modifiers
          - State variables + types
          - External calls + order relative to state updates
          - Import/inheritance
          - Contract type (ERC20/DeFi/Governance/Custom)

        Sau đó: static pattern matching để populate swc_candidates:
          - Tìm msg.sender.call() trước state update → SWC-107 candidate
          - Tìm tx.origin → SWC-115 candidate
          - Tìm block.timestamp trong condition → SWC-116 candidate
        """

    def parse_from_text_description(self, description: str) -> ContractEntity:
        """
        Khi không có source code — chỉ có mô tả bằng text.
        LLM tạo ContractEntity từ description.
        Dùng cho testing với dataset không có full source.
        """

    def _static_swc_scan(self, source_code: str) -> List[str]:
        """
        Regex-based preliminary scan — không cần LLM, nhanh, deterministic.
        Tìm obvious patterns:
          re.search(r'\.call\{value', source) → SWC-107 candidate
          re.search(r'tx\.origin', source)    → SWC-115 candidate
          re.search(r'block\.timestamp', source) → SWC-116 candidate
        Return: list SWC IDs để inject vào agent context
        """

    def _detect_contract_type(self, source_code: str) -> str:
        """
        Heuristic detect:
          "IERC20" / "transfer" / "balanceOf" → "ERC20"
          "borrow" / "liquidate" / "oracle"   → "DeFi_Lending"
          "propose" / "vote" / "execute"      → "Governance"
          else                                → "Custom"
        """
```

**Kiểm tra xong khi**: Parse contract DAO hack (100 dòng Solidity) → ContractEntity có `has_external_call=True`, `external_call_before_state=True`, `swc_candidates=["SWC-107"]`.

---

### Bước 1.4 — Contract Knowledge Graph Builder

**File cần tạo**: `backend/app/services/contract_kg_builder.py`

Tương tự `network_topology_builder.py` — reuse `ZepGraphMemoryUpdater` và `TaskManager`.

```python
class ContractKGBuilder:
    """
    Build Zep KG từ ContractEntity.
    Thay thế NetworkTopologyBuilder trong Hướng B.
    """

    def build_from_source_async(self, source_code: str,
                                 graph_name: str) -> str:
        """
        Async: parse contract → build Zep KG.
        Returns task_id.

        KG structure:
          Node types: Contract, Function, StateVar, ExternalCall
          Edge types:
            function → CALLS → external_contract
            function → MODIFIES → state_var
            function → HAS_MODIFIER → modifier_name
            state_var → OWNED_BY → function (who sets it)

          Critical properties on edges:
            CALLS edge: { before_state_update: True/False }
            → Nếu True = reentrancy risk → agent nhận fact này
        """

    def build_context_summary(self, graph_id: str) -> str:
        """
        Query Zep KG → tóm tắt inject vào tất cả agents:
          "Contract: TokenVault
           Functions: withdraw() [public, sends ETH, NO reentrancy guard]
                      deposit() [public, payable]
                      owner() [view]
           State vars: balances [mapping, critical]
                       _owner [address, critical]
           Risk signals:
             - withdraw() has external call BEFORE state update ← SWC-107
             - No ReentrancyGuard modifier on withdraw()
             - Uses tx.origin in authorization ← SWC-115"
        """
```

**Kiểm tra xong khi**: Build KG từ DAO contract → `build_context_summary()` mention "external call before state update".

---

## Phase 2 — Agent Layer (Tuần 3–4)

### Mục tiêu
13+5 agent profiles với domain/persona phù hợp smart contract, sẵn sàng chạy Contract Audit Room.

---

### Bước 2.1 — Contract Expert Profile Generator

**File cần tạo**: `backend/app/services/contract_profile_generator.py`

Tương tự `CyberExpertProfileGenerator` — chỉ đổi AGENT_MATRIX và ATTACKER_PROFILES.

```python
CONTRACT_AGENT_MATRIX = {
    "appsec": {
        "display_name": "Application Security",
        "personas": ["offensive", "defensive", "auditor"],
        "swc_focus": ["SWC-107", "SWC-101", "SWC-115", "SWC-104"],
        "persona_prompts": {
            "offensive": (
                "You are an AppSec expert with offensive mindset. "
                "Find exploitable vulnerabilities: reentrancy, integer overflow, "
                "unchecked return values. Ask: 'How would I drain this contract?'"
            ),
            "defensive": (
                "You are an AppSec expert with defensive mindset. "
                "Find missing protections: reentrancy guards, input validation, "
                "return value checks. Ask: 'What security controls are absent?'"
            ),
            "auditor": (
                "You are a smart contract auditor. Evaluate code quality, "
                "adherence to ERC standards, and best practice compliance. "
                "Ask: 'Does this contract follow established security patterns?'"
            ),
        }
    },
    "blockchain": {
        "display_name": "Blockchain Security",
        "personas": ["offensive", "defensive", "auditor"],
        "swc_focus": ["SWC-107", "SWC-112", "SWC-116", "SWC-120"],
        "persona_prompts": {
            "offensive": (
                "You are a blockchain security expert targeting EVM-specific risks. "
                "Focus on: reentrancy cross-function, delegatecall abuse, "
                "storage collision in proxy contracts."
            ),
            "defensive": (
                "You are a blockchain defender. Check: upgrade mechanism safety, "
                "storage layout compatibility, proxy admin key management."
            ),
            "auditor": (
                "You audit blockchain-specific patterns: proxy correctness, "
                "storage slot conflicts, constructor logic in upgradeable contracts."
            ),
        }
    },
    "cryptography": {
        "display_name": "Cryptography & Randomness",
        "personas": ["offensive", "defensive", "auditor"],
        "swc_focus": ["SWC-120", "SWC-116", "SWC-121"],
        "persona_prompts": {
            "offensive": "Find weak randomness sources exploitable by miners or front-runners.",
            "defensive": "Check that randomness uses Chainlink VRF or commit-reveal scheme.",
            "auditor":   "Audit hash functions, signature verification, replay protection.",
        }
    },
    "defi": {
        "display_name": "DeFi Protocol Security",
        "personas": ["offensive", "defensive"],
        "swc_focus": [],  # dùng DEFI_ATTACK_PATTERNS thay SWC
        "persona_prompts": {
            "offensive": (
                "You are a DeFi hacker. Look for: price oracle manipulation, "
                "flash loan attack paths, sandwich attack opportunities, "
                "liquidity pool imbalance exploits."
            ),
            "defensive": (
                "You are a DeFi security defender. Check: TWAP vs spot price usage, "
                "slippage protection, liquidity constraints, re-entrancy in callbacks."
            ),
        }
    },
    "governance": {
        "display_name": "Governance & Access Control",
        "personas": ["offensive", "defensive"],
        "swc_focus": ["SWC-105", "SWC-106", "SWC-115"],
        "persona_prompts": {
            "offensive": (
                "You focus on governance attacks: flash loan voting, "
                "proposal frontrunning, admin key compromise paths, "
                "timelock bypass."
            ),
            "defensive": (
                "Check: voting delay adequacy, proposal execution timelock, "
                "multi-sig requirements, role separation."
            ),
        }
    },
}

CONTRACT_ATTACKER_PROFILES = {
    "reentrancy_exploiter": {
        "name": "Reentrancy Exploiter",
        "motivation": "Drain ETH balance bằng recursive call",
        "method": "Deploy malicious contract với fallback/receive reentering target",
        "focus": "External calls trước state update, missing ReentrancyGuard",
        "blind_spot": "Read-only reentrancy, cross-function reentrancy phức tạp",
        "prompt": """Bạn là attacker chuyên reentrancy.
Khi thấy external call trước state update: bạn deploy contract attacker,
gọi withdraw(), trong fallback() gọi lại withdraw() trước balance bị trừ.
Nhìn vào contract: path reentrancy nào khả thi? Cần bao nhiêu ETH để exploit?""",
    },
    "flash_loan_attacker": {
        "name": "Flash Loan Attacker",
        "motivation": "Tận dụng capital tạm thời để manipulate state/price",
        "method": "Aave/dYdX flash loan → manipulate → repay trong 1 tx",
        "focus": "Price oracle dùng spot price, governance voting bằng token balance",
        "blind_spot": "Contracts không interact với external DeFi protocols",
        "prompt": """Bạn là flash loan attacker với access đến Aave/dYdX.
Bạn có thể borrow hàng triệu USD trong 1 transaction, không cần collateral.
Nhìn vào contract: có price oracle nào dùng spot price không?
Có governance voting nào dùng balance tại thời điểm vote không?
Path nào có thể exploit với flash loan?""",
    },
    "governance_attacker": {
        "name": "Governance Attacker",
        "motivation": "Pass malicious proposal để drain treasury hoặc upgrade contract",
        "method": "Accumulate voting power → propose → vote → execute",
        "focus": "Voting mechanism, timelock duration, proposal threshold",
        "blind_spot": "Contracts không có governance mechanism",
        "prompt": """Bạn tấn công governance mechanism.
Mục tiêu: pass một proposal drain treasury hoặc set malicious implementation.
Nhìn vào contract: voting threshold bao nhiêu? Có timelock không?
Có thể flash loan để đạt threshold trong 1 block không?
Proposal execution có delay đủ lâu để community phản ứng không?""",
    },
    "access_control_exploiter": {
        "name": "Access Control Exploiter",
        "motivation": "Leo thang đặc quyền, trở thành owner hoặc admin",
        "method": "Tìm missing modifier, tx.origin bypass, constructor vulnerability",
        "focus": "Unprotected functions, weak ownership transfer, initialization bug",
        "blind_spot": "Contracts với multi-sig và time-delay trên admin operations",
        "prompt": """Bạn tìm cách trở thành owner hoặc bypass access control.
Nhìn vào contract: function nào thiếu onlyOwner/onlyAdmin modifier?
Có dùng tx.origin thay msg.sender không?
Contract có uninitialized state sau deployment không?
Ownership transfer có 2-step verification không?""",
    },
    "logic_exploiter": {
        "name": "Logic & Business Rule Exploiter",
        "motivation": "Tìm edge case trong business logic để lợi dụng",
        "method": "Đọc hiểu protocol rules, tìm inconsistency",
        "focus": "Rounding errors, state machine bugs, incentive misalignment",
        "blind_spot": "Lỗi cần deep domain knowledge về DeFi protocol cụ thể",
        "prompt": """Bạn tìm lỗi logic không phải code pattern.
Nhìn vào contract: có phép tính nào bị rounding error không?
State machine có transition nào không được protect không?
Reward/penalty calculation có thể bị manipulate không?
Có hành vi nào của contract mâu thuẫn với intent của protocol không?""",
    },
}
```

---

### Bước 2.2 — Contract Audit OASIS Environment

**File cần tạo**: `backend/app/services/contract_oasis_env.py`

Tương tự `cyber_oasis_env.py` — giữ nguyên phase structure, đổi action space và context format.

```python
CONTRACT_AUDIT_ACTIONS = {
    # Phase A — Intra-domain (giữ nguyên tên, đổi ý nghĩa)
    "POST_FINDING":      "Báo cáo vulnerability với SWC ID và evidence từ code",
    "CHALLENGE_FINDING": "Phản biện finding với lý do cụ thể từ contract code",
    "VALIDATE_FINDING":  "Xác nhận finding sau khi review code",
    "ADD_EVIDENCE":      "Bổ sung evidence: function name, line range, code snippet",
    "REFINE_SEVERITY":   "Điều chỉnh severity với justification",

    # Phase B — Cross-domain (giữ nguyên)
    "CROSS_VALIDATE":    "Domain khác xác nhận finding (weight cao hơn)",
    "CROSS_CHALLENGE":   "Domain khác phản biện finding",
    "ESCALATE_TO_DEFI":  "Yêu cầu DeFi expert đánh giá exploit path",
    "REQUEST_GOVERNANCE":"Yêu cầu Governance expert xem access control",
    "CONCLUDE":          "Kết luận về finding sau debate",

    # Phase C — Attacker profiles (thêm mới)
    "ATTACKER_CONFIRM":   "Xác nhận: vulnerability này exploitable với profile của tôi",
    "ATTACKER_DISMISS":   "Bác bỏ: không thực sự exploitable vì lý do cụ thể",
    "ATTACKER_ADD_PATH":  "Bổ sung attack path mà experts chưa thấy",
    "ATTACKER_ESCALATE":  "Nâng severity: dễ exploit hơn experts nghĩ",
    "ATTACKER_DOWNGRADE": "Hạ severity: khó exploit hơn (có mitigation ẩn)",
    "SUGGEST_PATCH":      "Attacker đề xuất patch (vì biết rõ vulnerability nhất)",
}

# Định dạng post của agent — chuẩn để parser extract findings
CONTRACT_FINDING_FORMAT = """
FINDING: <title>
SWC: <SWC-ID hoặc DEFI-pattern-name>
SEVERITY: <critical|high|medium|low>
FUNCTION: <function_name()>
EVIDENCE: <code snippet hoặc mô tả từ KG>
DESCRIPTION: <giải thích chi tiết>
PATCH: <patch suggestion nếu có>
GAP: <gì không thể đánh giá từ thông tin hiện có>
"""
```

---

## Phase 3 — Session & Consensus (Tuần 5)

### Mục tiêu
Adapt `CyberSessionOrchestrator` và `ConsensusEngine` cho contract domain.

---

### Bước 3.1 — Adapt Session Orchestrator

**File cần sửa**: `backend/app/services/cyber_session_orchestrator.py`

Thêm `mode="contract_audit"` — **không xóa mode hiện tại**:

```python
def run_session_async(
    self,
    graph_id: str,
    network_summary: str,    # = contract KG summary
    profiles: List[CyberAgentProfile],
    session_id: Optional[str] = None,
    mode: str = "network_security",  # THÊM THAM SỐ NÀY
) -> str:
    """
    mode="network_security" → behavior hiện tại (Hướng B)
    mode="contract_audit"   → dùng CONTRACT_AUDIT_ACTIONS,
                               parse ContractFinding thay ExpertFinding
    """
```

Phần thay đổi chính là `_parse_findings_from_feed()` — nhận biết SWC ID thay MITRE TTP, và `FUNCTION:` field thay `ASSET:` field.

---

### Bước 3.2 — Adapt Consensus Engine

**File cần sửa**: `backend/app/services/consensus_engine.py`

Thêm SWC anchor types vào semantic clustering:

```python
# Hiện tại: anchor từ SecurityControls fields (edr, siem, mfa...)
# Thêm: anchor từ SWC categories (reentrancy, access_control, arithmetic...)

SWC_ANCHOR_KEYWORDS = {
    "reentrancy", "reentrant", "reentrancy_guard",
    "overflow", "underflow", "arithmetic",
    "access_control", "onlyowner", "modifier",
    "flash_loan", "oracle", "price_manipulation",
    "governance", "voting", "timelock",
    "randomness", "entropy", "blockhash",
}
```

Thay đổi này nhỏ — chỉ extend `_extract_anchors()` function.

---

## Phase 4 — Report & API (Tuần 6–7)

### Bước 4.1 — ContractAuditReportAgent

**File cần tạo**: `backend/app/services/contract_audit_agent.py`

Extend `VulnReportAgent` — thêm patch suggestion tool:

```python
CONTRACT_AUDIT_TOOLS = [
    # Giữ từ VulnReportAgent:
    "get_top_vulnerabilities",
    "get_critical_findings",
    "get_attacker_profile_breakdown",
    "get_attacker_only_findings",
    "get_coverage_gaps",
    "get_findings_by_domain",
    "get_swc_mapping",           # thay get_mitre_mapping

    # Thêm mới:
    "get_exploitable_findings",  # findings được attacker CONFIRM là exploitable
    "get_patch_suggestions",     # patch suggestion cho từng vuln
    "get_defi_specific_risks",   # risks từ DEFI_ATTACK_PATTERNS
    "get_compliance_issues",     # ERC standard violations
]

CONTRACT_AUDIT_SYSTEM_PROMPT = """
Bạn là senior smart contract auditor tổng hợp kết quả từ multi-expert review.
Viết audit report đầy đủ gồm 6 phần:

1. EXECUTIVE SUMMARY
   - Tổng số vulnerability: X critical, Y high, Z medium
   - Risk level tổng thể: Critical/High/Medium/Low
   - Top 3 issues cần fix ngay

2. VULNERABILITY DETAILS
   Với mỗi vulnerability:
   - SWC ID + tên
   - Affected function(s)
   - Severity + confidence score (3-layer)
   - Evidence từ code
   - Exploitability assessment (attacker profile đã validate chưa)
   - Patch suggestion (code example nếu có)

3. ATTACKER PERSPECTIVE
   - Findings được attacker profiles xác nhận exploitable
   - Findings bị attacker dismiss (potential FP — chú thích lý do)
   - Attack paths mà attacker ADD nhưng experts bỏ sót

4. EXPERT DISAGREEMENTS
   - Findings còn tranh cãi giữa domains
   - Lý do bất đồng (offensive vs defensive perspective)
   - Recommendation dựa trên disagreement

5. DEFI-SPECIFIC RISKS (nếu applicable)
   - Flash loan attack paths
   - Oracle manipulation risk
   - Governance attack surface

6. REMEDIATION ROADMAP
   - Immediate (critical): fix trước deploy
   - Short-term (high): fix trong 2 tuần
   - Long-term (medium): fix trong 1 tháng
   Code example cho mỗi patch.

Phân biệt rõ:
  [CONFIRMED] = cross-domain + attacker validated
  [EXPERT ONLY] = domain experts đồng ý, attacker chưa validate
  [ATTACKER SURFACED] = attacker ADD_PATH, experts chưa validate
  [DISPUTED] = có cross-domain disagreement
"""
```

---

### Bước 4.2 — API Endpoints

**File tạo mới**: `backend/app/api/contract.py` — Blueprint riêng, đăng ký trong `app/__init__.py`:

```
POST /api/contract/upload
  Body: { source_code, graph_name }
  Return: { task_id }
  Task result: { graph_id, contract_id, contract_type, function_count,
                 state_var_count, swc_candidates, context_summary }

GET  /api/contract/task/<task_id>
  Return: { status, progress, message, result }

GET  /api/contract/<graph_id>/summary
  Return: { graph_id, summary }

POST /api/contract/<graph_id>/agents/generate
  Body: { contract_summary }
  Return: { tier1_count: 17, tier2_count: 5, total: 22, oasis_profiles }

POST /api/contract/session/start
  Body: { graph_id, contract_summary, oasis_profiles }
  Return: { task_id, session_id }

GET  /api/contract/review/<session_id>/status
  Return: { status, current_phase, current_round, finding_count, attacker_finding_count }

GET  /api/contract/review/<session_id>/findings
  Query: phase, domain, severity, swc_id, type (expert|attacker|all)
  Return: { findings[], domain_breakdown, swc_breakdown, cross_validated_count }

GET  /api/contract/review/<session_id>/feed
  Query: phase, round_num, agent_id, limit, offset
  Return: { posts[], total, phase_breakdown }

POST /api/contract/report/generate
  Body: { session_id, expert_findings, attacker_findings, contract_summary, graph_id }
  Return: { task_id }

GET  /api/contract/report/<session_id>
  Return: { report, consensus_vulns[], unvalidated_swc_gaps[], coverage_gaps, stats }

# Endpoint cần bổ sung (Phase 4 pending):
POST /api/contract/interview
  Body: { session_id, agent_id, question }
  → Load session context + system_prompt của agent đó
  → Gọi LLM với context → trả lời từ góc nhìn agent
  Return: { agent_id, answer, agent_domain, agent_persona }
  Dùng để: theo dõi reasoning và hỏi đáp với từng agent sau session
```

---

## Phase 5 — Evaluation (Tuần 8–10)

### Mục tiêu
Thu thập số liệu cho 5 đóng góp trong paper trên 2 tầng đánh giá.

### Dataset strategy (cập nhật 2026-04-21)

```
Tầng 1 — Recall per SWC type:
  SmartBugs Curated 143 contracts
  Citation: Durieux et al. ICSE 2020
  Metric: Recall per vulnerability type, so sánh Slither/Mythril

Tầng 2 — Multi-SWC + Semantic bug detection:
  Web3Bugs (Code4rena) 10 contests đã chọn (xem bảng bên dưới)
  Citation: ZhangZhuoSJTU/Web3Bugs + GPTScan ICSE 2024
  Metric: L-recall (SWC pattern) + S-recall (semantic/logic)
  Prerequisite: semantic finding track phải implemented trước

Datasets DROPPED:
  SolidiFI-bench — redundant với SmartBugs, cùng single-SWC per contract
  DeFiHackLabs  — 100% Foundry test files, không chạy standalone được
```

### Chi phí ước tính (Gemini 2.5 Flash)

| Run | Chi phí | Thời gian |
|-----|---------|-----------|
| SmartBugs 143 contracts | ~$8.5 | ~3 giờ |
| Web3Bugs 10 contests | ~$6 | ~5 giờ |
| Ablation V1–V5 | ~$6 | ~3 giờ |
| **Tổng Phase 5** | **~$21** | **~11 giờ** |

---

### Bước 5.1 — Setup Dataset

**SmartBugs Curated** (Tầng 1 — primary benchmark):
```bash
# Đã clone tại: /home/thangdd/repos/smartbugs-curated
ls smartbugs-curated/dataset/
# reentrancy/ access_control/ arithmetic/ unchecked_calls/ ...
# 143 contracts, single-SWC per contract, line-level annotations
```

**Web3Bugs** (Tầng 2 — multi-SWC + semantic):
```bash
# Đã clone tại: /home/thangdd/repos/web3bugs
# Ground truth: results/bugs.csv (492 HIGH findings across 104 contests)
# L-category (~17%): L1=reentrancy, L4=gas, L7=overflow, LB=tx.origin, ...
# S-category (~77%): S1=price oracle, S3=wrong state, S6=bad accounting, SE=unexpected flow
# O-category (~6%): out-of-scope — excluded from evaluation

# Pre-process: python scripts/flatten_contest.py /path/to/contracts/<id>
# → topological sort .sol files → strip pragma/SPDX/imports → single 260K-char string
```

**10 Contests đã chọn cho Phase 5d** (coverage tất cả 8 S-types, tổng ~114 L/S bugs):

| ID | Tên | Bugs (L/S) | .sol | S-types covered |
|----|-----|-----------|------|-----------------|
| 19 | Connext | 5 (1L/4S) | 6 | S2-1, S3-1, SC, SE-2 |
| 3 | Marginswap | 9 (3L/6S) | 19 | S1-1, S3-1, S6-2, S6-4, SC, SE-4 |
| 20 | Spartan Protocol | 10 (1L/9S) | 29 | S1-1, S1-2, S2-2, SC |
| 29 | Sushi Trident (ph2) | 11 (4L/7S) | 31 | S6-3, S6-4, SC |
| 51 | Boot Finance | 7 (1L/6S) | 23 | S2-1, S3-1, S6-3, S6-4, SE-3 |
| 62 | Streaming Protocol | 7 (1L/6S) | 15 | S3-1, S6-3, S6-4, SC, SE-4 |
| 71 | InsureDAO | 6 (1L/5S) | 21 | S2-1, S4-1, S5-2, S6-4, SE-2 |
| 78 | Behodler | 7 (0L/7S) | 40 | S1-1, S3-2, S4-1, S5-1, S6-3, SC |
| 83 | Concur Finance | 8 (0L/8S) | 15 | S1-1, S2-2, S3-1, S5-2, S6-1, SC, SE-3 |
| 14 | PoolTogether | 5 (2L/3S) | 10 | S3-2, S6-3 |

**Lý do chọn**:
- Contest 19 (Connext): **trial contest**, chạy đầu tiên để calibrate, size nhỏ (38K chars)
- Contest 3 (Marginswap): đa dạng type (S1+S3+S6+SE), size vừa
- Contest 20 (Spartan): price oracle focus (S1), 10 bugs
- Contest 83 (Concur Finance): pure S-bugs, size nhỏ (15 .sol), good signal
- Contest 14 (PoolTogether): nhỏ nhất (10 .sol), warm-up cho tầng 1 tool baseline
- Còn lại: coverage S4 (business atomicity), S5 (privilege), SE (unexpected flow)

**S-type coverage map** (tổng 10 contests):

| S-type | Description | # contests |
|--------|-------------|------------|
| S1 | Price oracle manipulation | 3 (20, 78, 83) |
| S2 | ID/resource violations | 4 (19, 51, 71, 83) |
| S3 | Erroneous state updates | 6 (3, 19, 51, 62, 78, 83) |
| S4 | Business-flow atomicity | 2 (71, 78) |
| S5 | Privilege escalation | 2 (71, 78) |
| S6 | Erroneous accounting | 6 (3, 29, 51, 62, 71, 83) |
| SE | Unexpected operations | 5 (3, 19, 51, 62, 71) |
| SC | Contract-specific | 5 (3, 19, 20, 29, 62) |

> **Scope limitation — SE/SC bugs**: Nhóm SE (unexpected external interaction) và SC (contract-specific cross-chain flow) yêu cầu kiến thức về cross-chain state và protocol intent không có trong source code. Tool không thể detect được chúng từ source-level analysis. Trong metric báo cáo:
> - **In-scope recall**: tính trên L + S1–S6 only (loại SE/SC khỏi denominator)
> - **Full recall**: tính trên toàn bộ GT (SE/SC tính là FN nếu không tìm được)
> - Nếu tool "tình cờ" match SE/SC (qua `other` category), vẫn đếm là TP

**Evaluation script**: `backend/scripts/evaluate_web3bugs.py`
- Track L: SWC match trên `consensus_vulns` + `unvalidated_swc_gaps`
- Track S: category match trên `semantic_results` (Policy A); tùy chọn Policy B (SWC→semantic từ consensus) và Policy Gap (`--policy-gap`: gap có `source_count` đủ và map được → S-pool) — xem `docs/web3bugs-evaluation-protocol.md`
- Taxonomy chuẩn: `backend/app/services/semantic_taxonomy.py` (đồng bộ parser, consensus vote, eval)
- Output: per-contest breakdown + aggregate (chạy bằng `python3`, không cần Flask)

---

### Bước 5.2 — Baseline Setup

**Static analysis tools** (pip install, không cần clone):
```bash
pip install slither-analyzer   # Trail of Bits — ~2–5s/contract
pip install mythril             # ConsenSys — ~30–120s/contract (symbolic execution)
```

**Single-LLM baseline (Option B)** — tự implement, KHÔNG dùng GPTScan:
```
Lý do chọn Option B:
  - Cùng LLM (Gemini 2.5 Flash) với hệ thống → so sánh architecture, không phải model
  - Kết quả chứng minh multi-agent architecture có giá trị độc lập với model
  - Không cần clone repo ngoài, không phụ thuộc OpenAI API

Config:
  - 1 agent duy nhất (appsec_auditor)
  - 1 pass qua contract (không debate, không consensus)
  - Prompt: full contract source + system_prompt của agent đó
  - Output: list of findings (SWC ID + severity + description)

So sánh với GPTScan (ICSE 2024): paper báo trên **Web3Bugs** recall ~83.33% và **F1 ~67.8%**
(trích từ bản PDF chính thức); dataset DefiHacks F1 ~80%. **Không** trích F1=0.88 trên SmartBugs —
đó là benchmark khác / có thể nhầm với số liệu tool khác. Khi viết paper: trích đúng bảng GPTScan
theo dataset (Web3Bugs vs SmartBugs vs Top200).
```

Tạo `scripts/run_baselines.py`:
```python
# Chạy Slither + Mythril + Single-LLM trên SmartBugs dataset
# Lưu kết quả: { contract_id, tool, findings[], tp, fp, fn }
```

---

### Bước 5.3 — Chiến lược chạy

Chạy từ nhỏ đến lớn — chỉ mở rộng khi kết quả đã ổn:

```
Phase 5a — Debug (~$0.10, ~30 phút):       ✅ Scripts done (evaluate_phase5a.py)
  3 contracts: dao + erc20 + defi_vault (built-in samples)
  Tiêu chí: pipeline không crash, ≥1 expected SWC per sample

Phase 5b — Validate (~$3, ~2 giờ):         ✅ Scripts done (evaluate_phase5b.py)
  20 contracts: smartbugs-curated/dataset/reentrancy/
  Tiêu chí: Recall ≥ 0.80 → tiến 5c

Phase 5c — Full SmartBugs (~$8.5, ~3 giờ): ⬜ Pending
  143 contracts: toàn bộ SmartBugs Curated
  Metric: Recall per SWC type, macro Recall, so sánh Slither/Mythril
  Dùng: scripts/run_cohort_b.sh (batch runner đã có)

Phase 5 — Semantic Track:                   ✅ Core (parser + consensus + taxonomy + prompts)
  Chi tiết: `semantic_taxonomy.py`, `contract_oasis_env.py`, `consensus_engine.py`, `contract_profile_generator.py`
  Xem: docs/smart-contract-audit-progress.md

Phase 5d — Web3Bugs (~$3, ~1.5 giờ):       ✅ Script sẵn; chạy cohort 10 contest theo tiến độ
  Pre-process: flatten contest .sol
  Metric: L-recall (SWC) + S-recall (semantic categories; Policy A/B/Gap)
  Tiêu chí: L-recall ≥ 0.60, S-recall > 0% (calibrate trên contest 19 trước)
```

```bash
# Phase 5c — full SmartBugs
bash scripts/run_cohort_b.sh   # batch runner có sẵn

# Phase 5d — Web3Bugs (từ backend/)
python3 scripts/evaluate_web3bugs.py \
    --results results/web3bugs_trial/ \
    --bugs-csv /path/to/web3bugs/results/bugs.csv \
    [--contest 19] [--policy-b] [--policy-gap] [--verbose]
```

Scripts còn lại (optional):
- `scripts/run_baselines.py` — Slither + Mythril + Single-LLM Option B
- `scripts/ablation_study.py` — V1–V5 variants
- `scripts/evaluate_web3bugs.py` — Web3Bugs L+S (đã có)

---

### Bước 5.4 — Ablation Study (chứng minh từng component đóng góp)

```
V1 — Single agent, no KG:
  1 agent (appsec_auditor), không KG, 1 pass
  Baseline LLM thuần → Đo FP/FN

V2 — Single agent + KG:
  1 agent + Zep KG context
  Chứng minh C2: KG grounding giảm hallucination → Đo FP/FN

V3 — Multi-agent Phase A only, no KG:
  17 Tier-1 agents, chỉ Phase A (intra-domain), không KG
  Chứng minh multi-agent value độc lập → Đo FP/FN

V4 — Multi-agent + KG, no Phase C:
  17 Tier-1 agents, Phase A + B, có KG, không attacker profiles
  Chứng minh C3: Phase C (attackers) đóng góp gì → Đo FP/FN

V5 — Full system (Phase A + B + C + KG):
  22 agents (17 Tier-1 + 5 Tier-2), Phase A+B+C, có KG
  Full framework → Đo FP/FN

Expected: V1 < V2 < V3 < V4 < V5 (mỗi component thêm đều cải thiện F1)
```

---

### Bước 5.5 — Metrics

```python
# Với mỗi contract trong SmartBugs:
# Ground truth: known_vulns = ["SWC-107", "SWC-101"] (từ dataset label)
# Prediction:   found_vulns = output của hệ thống

TP = len(set(found_vulns) & set(known_vulns))  # tìm đúng
FP = len(set(found_vulns) - set(known_vulns))  # báo sai
FN = len(set(known_vulns) - set(found_vulns))  # bỏ sót

Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 * Precision * Recall / (Precision + Recall)

# Aggregate: macro-F1 trên 143 contracts
# Per-SWC-type: F1 riêng cho reentrancy, access_control, arithmetic...

# Với Web3Bugs (Tầng 2):
# L-recall = TP_L / (TP_L + FN_L)   — SWC-mappable bugs (L-category)
# S-recall = TP_S / (TP_S + FN_S)   — Semantic/logic bugs (S-category)
# TP_S = SEMANTIC_FINDING của hệ thống khớp với S-finding trong bugs.csv
#         (keyword match trên function name + description)
# Exploitability Precision = [CONFIRMED EXPLOITABLE] matches real exploit
#                            / total [CONFIRMED EXPLOITABLE] findings
```

---

## Phase 6 — Viết Paper (Tuần 11–14)

### Cấu trúc paper đề xuất (8–10 trang, IEEE format)

```
Abstract (150 words)
  - Problem: manual audit expensive, single-LLM high FP rate
  - Solution: multi-expert panel + contract KG grounding
  - Result: F1 = X, FP rate = Y% vs GPTScan Z%

1. Introduction (1 trang)
   1.1 Problem statement + motivation (DAO hack, $X billion lost)
   1.2 Limitation of existing tools (Slither: miss logic; GPTScan: 28% FP)
   1.3 Our approach (multi-expert + KG grounding)
   1.4 Contributions (C1–C5, bulleted)

2. Background (0.5 trang)
   2.1 Smart contract vulnerabilities + SWC Registry
   2.2 Multi-agent LLM systems
   2.3 Knowledge graph grounding

3. System Design (2.5 trang)
   3.1 Overall architecture (figure)
   3.2 Contract Knowledge Graph Builder
   3.3 Agent Matrix (Domain × Persona + Attacker profiles)
   3.4 3-phase Audit Session
   3.5 3-layer Consensus Engine

4. Evaluation (3 trang)
   4.1 Experimental setup (datasets, baselines, metrics)
   4.2 RQ1: Overall performance vs baselines (Table)
   4.3 RQ2: Ablation study (mỗi component đóng góp bao nhiêu)
   4.4 RQ3: Semantic/logic bug detection on Web3Bugs S-category
   4.5 RQ4: Exploitability validation + L-recall (Web3Bugs)

5. Related Work (0.5 trang)
   Slither, Mythril, GPTScan (ICSE 2024), LLM-SmartAudit (TSE 2025),
   SmartInv (S&P 2024), iAudit (ICSE 2025), multi-agent audit

6. Conclusion (0.3 trang)
   Contributions tóm tắt + future work (Attack Graph cho contracts)
```

---

## Checklist tổng thể

```
Phase 1 — Data Layer:
  [ ] contract_models.py — ContractEntity, ContractFinding đủ fields
  [ ] swc_registry.py — 40 SWC entries + DeFi patterns
  [ ] contract_parser.py — parse DAO contract → đúng SWC-107 candidate
  [ ] contract_kg_builder.py — build_context_summary() mention reentrancy risk

Phase 2 — Agent Layer:
  [ ] contract_profile_generator.py — 13+5 profiles, prompts khác nhau rõ
  [ ] contract_oasis_env.py — 3 phase actions, CONTRACT_FINDING_FORMAT

Phase 3 — Session & Consensus:
  [ ] cyber_session_orchestrator.py — mode="contract_audit" không break mode cũ
  [ ] consensus_engine.py — SWC anchor keywords hoạt động

Phase 4 — Report & API:
  [x] contract_audit_agent.py — 6-section report, patch suggestion (31 tests passed)
  [x] api/contract.py — 11 endpoints hoạt động (Blueprint riêng, kể cả /interview)
  [x] POST /api/contract/interview — agent interview endpoint (22/22 agent_ids parse đúng)

Phase 5 — Evaluation:
  [ ] Phase 5a: debug 3 built-in samples (dao/erc20/defi_vault) end-to-end
  [ ] Phase 5b: validate trên 20 reentrancy contracts → F1 ≥ 0.75
  [ ] Slither + Mythril baseline chạy được (scripts/run_baselines.py)
  [ ] Single-LLM baseline Option B (scripts/run_baselines.py)
  [ ] Phase 5c: full SmartBugs 143 contracts (chỉ sau khi 5b tốt)
  [ ] Ablation study 5 variants V1–V5 (scripts/ablation_study.py)
  [ ] Metrics: Precision/Recall/F1 per SWC type + macro (scripts/evaluate_smartbugs.py)
  [ ] Semantic Track: SemanticFinding dataclass + agent prompt + orchestrator + consensus + report tool
  [ ] Phase 5d: Web3Bugs 15–20 contracts — L-recall ≥ 0.60, S-recall > 0% (scripts/evaluate_web3bugs.py)

Phase 6 — Paper:
  [ ] Abstract + Introduction
  [ ] System Design với architecture figure
  [ ] Evaluation tables
  [ ] Submit draft
```

---

## Timeline gợi ý

```
Tuần 1–2  : Phase 1 — Data layer (models + SWC + parser + KG)
Tuần 3–4  : Phase 2 — Agent layer (profiles + audit environment)
Tuần 5    : Phase 3 — Adapt orchestrator + consensus
Tuần 6–7  : Phase 4 — Report agent + API endpoints
Tuần 8    : Phase 5.1–5.3 — Dataset setup + chạy hệ thống
Tuần 9    : Phase 5.4–5.5 — Ablation study + collect metrics
Tuần 10   : Fix issues từ evaluation, rerun nếu cần
Tuần 11   : Paper Introduction + Background + System Design
Tuần 12   : Paper Evaluation section (số liệu đã có)
Tuần 13   : Paper Related Work + Conclusion + revision
Tuần 14   : Proofreading + submit
```

---

## Research Questions cho paper

```
RQ1: Multi-Expert Panel có Precision/Recall/F1 cao hơn
     Slither, Mythril, và single-LLM baseline không?
     → So sánh trên SmartBugs 143 contracts

RQ2: Mỗi component trong kiến trúc đóng góp bao nhiêu?
     → Ablation study 5 variants

RQ3: MECAP có phát hiện được semantic/logic bugs mà static tools bỏ qua không?
     → Web3Bugs S-category: so sánh S-recall của MECAP vs Slither (0%) vs Mythril (0%)
     → MECAP phải > 0% để đây là đóng góp có ý nghĩa (C5)

RQ4: Attacker profile validation có cải thiện
     exploitability precision không?
     → Web3Bugs L-category: [CONFIRMED EXPLOITABLE] vs ground truth
     → So sánh V4 (no Phase C) vs V5 (full) trên L-category bugs

RQ5: Contract KG grounding có giảm FP rate
     so với agent không có KG context không?
     → Variant 2 (single agent + KG) vs Variant 1 (no KG) trong ablation study
```

---

*Plan này phản ánh trạng thái thiết kế tại thời điểm khởi động Đề tài 10.*
*Implement Phase 1–2 trước khi bắt đầu Phase 3 trở đi.*
*Paper submission target: IEEE ICBC hoặc Financial Cryptography.*
