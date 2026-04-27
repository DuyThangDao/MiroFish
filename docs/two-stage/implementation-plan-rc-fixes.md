# Implementation Plan — Fix G-RC-1 đến G-RC-4

> Thứ tự triển khai: S1a → S2a+1b → S3a+S3b → S5  
> Tham chiếu root cause: [contest35-fn-root-cause.md](contest35-fn-root-cause.md)

---

## Trạng thái hiện tại

| Solution | RC | Trạng thái |
|----------|----|-----------|
| S1a | RC-1 | ✅ **Done** — đã inject vào Phase A + B `stage1_instruction` |
| S2a + 1b (graph / Slither) | RC-2 | ⬜ Chưa làm |
| S3a + S3b | RC-3 | ⬜ Chưa làm |
| S5 | RC-4 | ⬜ Chưa làm |

---

## 1. S1a — SWC Tagging Rules ✅ (đã xong)

**File đã sửa:** `backend/app/services/contract_oasis_env.py`

**Thay đổi:** Thêm block `⚠️ SWC TAGGING RULES` vào Phase A (`stage1_instruction`, line ~87) và Phase B (`stage1_instruction`, line ~149). Block buộc agents gán SWC-101 cho explicit casts, SWC-107 cho external call trước state update, SWC-124 cho delegatecall, SWC-128 cho unbounded loop.

**Lưu ý sau khi deploy:** Chạy lại C35 → kiểm tra `audit_report.json` → đếm `swc_candidates` có SWC-101 không. Nếu không tăng → cân nhắc S1b (post-processing re-tagger).

---

## 2. S2a + Bước 1b — Contract Manifest + Dependency Graph + Focus Directive

### 2.1 Bước 1 — Contract Manifest trong `flatten_contest.py`

**File:** `backend/scripts/flatten_contest.py`

**Mục tiêu:** Sau khi build dep graph + topo sort, tính thêm `ContractManifest` để biết contract nào là primary/secondary.

**Thay đổi cần làm:**

*Thêm hàm `_compute_manifest()`* sau hàm `_topo_sort()`:

```python
# Class name patterns → ưu tiên cao (likely core logic)
_CORE_NAME_RE = re.compile(
    r'\b(Pool|Vault|Core|Engine|Logic|Manager|Strategy|Market|Exchange|Pair|AMM|Farm)\b',
    re.IGNORECASE
)
# Patterns → ưu tiên thấp (likely infrastructure/peripheral)
_INFRA_NAME_RE = re.compile(
    r'\b(Router|Helper|Deployer|Factory|Registry|Proxy|Base|Abstract|Interface|Mock)\b',
    re.IGNORECASE
)

def _compute_manifest(
    order: List[str],
    sources: Dict[str, str],
    graph: Dict[str, List[str]],
    contest_dir: str,
) -> dict:
    """
    Tính ContractManifest từ: LOC, class name pattern, import in-degree.
    Trả về dict với primary (str), secondary (list[str]), metadata.
    """
    base = Path(contest_dir)

    # Build reverse graph: dep → [files that import dep]  (in-degree signal)
    in_degree: Dict[str, int] = {k: 0 for k in order}
    for node, deps in graph.items():
        for d in deps:
            if d in in_degree:
                in_degree[d] += 1

    scores: Dict[str, float] = {}
    contract_names: Dict[str, str] = {}  # file_key → primary contract/library name

    for key in order:
        src = sources.get(key, "")
        if not src.strip():
            continue

        rel = str(Path(key).relative_to(base))
        loc = src.count('\n') + 1

        # Extract contract/library name from source
        m = _CONTRACT_RE.search(src)
        contract_name = m.group(0).split()[-1] if m else Path(key).stem
        contract_names[key] = contract_name

        # Base score = LOC (normalized later)
        score = loc

        # Bonus: core name pattern
        if _CORE_NAME_RE.search(contract_name):
            score *= 1.5
        # Penalty: infra/peripheral name pattern
        if _INFRA_NAME_RE.search(contract_name):
            score *= 0.6
        # Bonus: high in-degree (nhiều contract phụ thuộc vào nó → likely core)
        score += in_degree.get(key, 0) * 500
        # Penalty: interface-only file
        if _is_interface_only(src):
            score *= 0.1

        scores[key] = score

    if not scores:
        return {"primary": None, "secondary": [], "total_contracts": 0, "total_chars": 0}

    sorted_keys = sorted(scores, key=lambda k: scores[k], reverse=True)
    primary_key = sorted_keys[0]
    secondary_keys = sorted_keys[1:4]  # top 3 tiếp theo

    return {
        "primary": contract_names.get(primary_key),
        "primary_file": str(Path(primary_key).relative_to(base)),
        "secondary": [contract_names.get(k) for k in secondary_keys],
        "total_contracts": len(scores),
        "total_chars": sum(len(sources.get(k, "")) for k in order),
        # Cho phép manual override: caller set manifest["primary"] = "ActualCoreContract"
    }
```

*Sửa signature `flatten_contest_dir()`* để trả về manifest kèm theo:

```python
def flatten_contest_dir(
    contest_dir: str,
    max_chars: int = 260_000,
    verbose: bool = False,
    emit_manifest: bool = False,       # ← thêm param này
) -> str | tuple[str, dict]:           # tuple khi emit_manifest=True
    ...
    # Sau bước build output (cuối hàm), trước return:
    if emit_manifest:
        manifest = _compute_manifest(order, sources, graph, contest_dir)
        if verbose:
            print(f"  Manifest: primary={manifest['primary']}, "
                  f"secondary={manifest['secondary']}")
        return result, manifest
    return result
```

**Lưu ý:**
- `emit_manifest=False` mặc định → backward compatible, không vỡ code cũ
- Heuristic score có thể sai với repo cực kỳ non-standard → cần manual override option (xem Bước 2)
- In-degree signal đặc biệt quan trọng với AMM protocols (pool contract thường bị import nhiều)

---

### 2.2 Bước 1b — Slither + Memgraph Dependency Graph

**File mới:** `backend/app/services/contract_dep_graph.py`

**Mục tiêu:** Dùng Slither Python API để extract (function, state_variable, READ|WRITE) edges, lưu vào Memgraph, query summary để inject cùng manifest vào context.

#### 2.2.1 Dependencies cần thêm

Trong `backend/pyproject.toml`, thêm vào `[project.optional-dependencies]`:

```toml
[project.optional-dependencies]
...
graph = [
    "slither-analyzer>=0.10.0",   # Slither static analysis
    "mgclient>=1.3.0",             # Memgraph Python client
]
```

Cài bằng: `uv add --optional graph slither-analyzer mgclient`

> **Lưu ý:** `slither-analyzer` yêu cầu `solc` (Solidity compiler) được cài sẵn. Cách nhanh nhất: `pip install solc-select && solc-select install 0.8.x && solc-select use 0.8.x`. Nếu contest dùng nhiều version khác nhau, cần `solc-select use <version>` trước khi chạy Slither.

#### 2.2.2 Memgraph service trong docker-compose

Thêm vào `docker-compose.yml`:

```yaml
services:
  ...
  memgraph:
    image: memgraph/memgraph:latest
    container_name: mirofish_memgraph
    ports:
      - "7687:7687"   # Bolt protocol (Cypher queries)
      - "7444:7444"   # Memgraph Lab (web UI)
    volumes:
      - memgraph_data:/var/lib/memgraph
    restart: unless-stopped

volumes:
  memgraph_data:
```

Biến môi trường thêm vào `.env.example`:
```
MEMGRAPH_HOST=localhost
MEMGRAPH_PORT=7687
MEMGRAPH_ENABLED=false   # false = dùng in-memory fallback (NetworkX)
```

> **Lưu ý:** Khi `MEMGRAPH_ENABLED=false`, toàn bộ graph vẫn được build nhưng lưu in-memory (dict + NetworkX). Memgraph chỉ bật khi cần persistent storage / Cypher queries phức tạp. Điều này cho phép dev/test không cần Docker Memgraph.

#### 2.2.3 Nội dung `contract_dep_graph.py`

```python
"""
ContractDepGraph — Static dependency graph via Slither.

Extracts (Function) -[READS/WRITES]-> (StateVar) edges.
Stores in Memgraph (when MEMGRAPH_ENABLED=true) or in-memory dict.
Provides summary text for injection into agent context.
"""

import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from ..utils.logger import get_logger
logger = get_logger("mirofish.dep_graph")


@dataclass
class DepGraphSummary:
    """Summary suitable for prompt injection."""
    primary_contract: str
    top_writers: List[str]   # functions that write the most state vars
    top_readers: List[str]   # functions that read the most state vars
    critical_vars: List[str] # state vars with most writers (high-risk)
    text: str                # formatted string for prompt injection


class ContractDepGraph:
    """
    Build data-flow graph from Slither analysis.
    
    Usage:
        graph = ContractDepGraph()
        summary = graph.build_and_summarize(source_code, contract_name)
        # summary.text → inject into context_summary
    """

    def __init__(self):
        self._memgraph_enabled = os.getenv("MEMGRAPH_ENABLED", "false").lower() == "true"
        self._mg_host = os.getenv("MEMGRAPH_HOST", "localhost")
        self._mg_port = int(os.getenv("MEMGRAPH_PORT", "7687"))

    def build_and_summarize(
        self,
        source_path: str,          # path tới .sol file (Slither cần file, không nhận string)
        contract_name: str,
        top_n: int = 7,            # số functions/vars giữ lại trong summary
    ) -> Optional[DepGraphSummary]:
        """
        Chạy Slither, extract READ/WRITE edges, trả về DepGraphSummary.
        Trả về None nếu Slither không available hoặc compile lỗi.
        """
        try:
            from slither import Slither
        except ImportError:
            logger.warning("slither-analyzer không được cài — bỏ qua dep graph")
            return None

        try:
            sl = Slither(source_path)
        except Exception as e:
            logger.warning(f"Slither compile lỗi cho {contract_name}: {e}")
            return None

        # Extract edges
        write_map: Dict[str, List[str]] = {}  # func_qualified → [state_var_name]
        read_map:  Dict[str, List[str]] = {}
        var_writers: Dict[str, List[str]] = {}  # var_name → [func_qualified]

        for contract in sl.contracts:
            for func in contract.functions_and_modifiers:
                qname = f"{contract.name}::{func.name}"
                writes = [v.name for v in func.state_variables_written]
                reads  = [v.name for v in func.state_variables_read]
                if writes:
                    write_map[qname] = writes
                    for v in writes:
                        var_writers.setdefault(v, []).append(qname)
                if reads:
                    read_map[qname] = reads

        if self._memgraph_enabled:
            self._persist_to_memgraph(contract_name, write_map, read_map)

        # Build summary
        top_writers = sorted(write_map, key=lambda f: len(write_map[f]), reverse=True)[:top_n]
        top_readers = sorted(read_map,  key=lambda f: len(read_map[f]),  reverse=True)[:top_n]
        critical_vars = sorted(var_writers, key=lambda v: len(var_writers[v]), reverse=True)[:5]

        lines = [f"DATA-FLOW GRAPH — {contract_name} (top {top_n}):"]
        lines.append("  Critical state vars (most writers):")
        for v in critical_vars:
            writers = ", ".join(var_writers[v][:3])
            lines.append(f"    {v}: written by {writers}")
        lines.append("  Top writer functions:")
        for f in top_writers:
            lines.append(f"    {f} → writes [{', '.join(write_map[f][:4])}]")

        return DepGraphSummary(
            primary_contract=contract_name,
            top_writers=top_writers,
            top_readers=top_readers,
            critical_vars=critical_vars,
            text="\n".join(lines),
        )

    def _persist_to_memgraph(
        self,
        contract_name: str,
        write_map: Dict[str, List[str]],
        read_map:  Dict[str, List[str]],
    ) -> None:
        """MERGE nodes + edges vào Memgraph."""
        try:
            import mgclient
            conn = mgclient.connect(host=self._mg_host, port=self._mg_port)
            cursor = conn.cursor()

            for func_q, vars_ in write_map.items():
                for var in vars_:
                    cursor.execute(
                        "MERGE (f:Function {name: $func, contract: $c}) "
                        "MERGE (v:StateVar {name: $var, contract: $c}) "
                        "MERGE (f)-[:WRITES]->(v)",
                        {"func": func_q, "var": var, "c": contract_name}
                    )
            for func_q, vars_ in read_map.items():
                for var in vars_:
                    cursor.execute(
                        "MERGE (f:Function {name: $func, contract: $c}) "
                        "MERGE (v:StateVar {name: $var, contract: $c}) "
                        "MERGE (f)-[:READS]->(v)",
                        {"func": func_q, "var": var, "c": contract_name}
                    )
            conn.commit()
            logger.info(f"Memgraph: merged {len(write_map)} writers, {len(read_map)} readers for {contract_name}")
        except Exception as e:
            logger.warning(f"Memgraph persist lỗi: {e} — tiếp tục với in-memory")
```

**Lưu ý quan trọng:**
- Slither nhận **file path**, không nhận source string. Cần save temp file trước khi gọi.
- Nếu flat file dùng `pragma solidity` không khớp với `solc` version đang active → Slither compile lỗi. Cần detect pragma từ source và gọi `solc-select use <version>` trước.
- Slither có thể chậm (~10-30s) với large files. Nên chạy async hoặc with timeout.
- `MEMGRAPH_ENABLED=false` là default an toàn.

#### 2.2.4 Integration vào `run_contract_audit.py`

Thêm bước mới **Step 1.3** sau Step 1 (KG Build), trước Step 1.5 (Invariant Extract):

```python
# ── Step 1.3: Build dependency graph (Slither) ────────────────────────────
logger.info("\n[STEP 1.3/4] Building data-flow dependency graph (Slither)...")
dep_graph_summary = None
if sol_path:  # chỉ có path khi chạy từ file, không có với sample contracts
    from app.services.contract_dep_graph import ContractDepGraph
    dep_graph = ContractDepGraph()
    dep_graph_summary = dep_graph.build_and_summarize(
        source_path=sol_path,
        contract_name=contract_name,
    )
    if dep_graph_summary:
        # Inject vào contract_summary để enriched context cho invariant extractor
        contract_summary += f"\n\n{dep_graph_summary.text}"
        logger.info(f"  Dep graph: {len(dep_graph_summary.critical_vars)} critical vars")
    else:
        logger.info("  Dep graph: skipped (Slither not available or compile error)")
```

---

### 2.3 Bước 2 — Focus Directive trong `contract_oasis_env.py`

**File:** `backend/app/services/contract_oasis_env.py`

**Mục tiêu:** Khi manifest có primary contract và `total_chars > 100_000`, inject focus directive vào `stage1_instruction`.

**Thay đổi:** Tìm `ContractAuditEnvBuilder.__init__()` và các method build instruction — thêm support nhận `manifest: dict | None`:

```python
class ContractAuditEnvBuilder:
    def __init__(self, ..., manifest: Optional[dict] = None):
        ...
        self.manifest = manifest

    def _build_focus_directive(self) -> str:
        """Tạo focus directive nếu manifest có primary và file đủ lớn."""
        if not self.manifest:
            return ""
        primary = self.manifest.get("primary")
        secondary = self.manifest.get("secondary", [])
        total_chars = self.manifest.get("total_chars", 0)

        if not primary or total_chars < 100_000:
            return ""

        sec_str = ", ".join(secondary[:3]) if secondary else "none"
        return (
            f"\n⚠️ MULTI-CONTRACT AUDIT — Phân bổ attention:\n"
            f"  PRIMARY TARGET (≥50% findings phải về): {primary}\n"
            f"  Secondary: {sec_str}\n"
            f"  KHÔNG để infrastructure/utility patterns chiếm đa số findings.\n"
            f"  Infrastructure bugs vẫn report nhưng KHÔNG ưu tiên hơn {primary}.\n"
        )
```

Sau đó thêm `self._build_focus_directive()` vào cuối `stage1_instruction` của Phase A và Phase B (trước `GAP_FORMAT_INSTRUCTION`).

**Truyền manifest từ `run_contract_audit.py`:** Sau bước flatten + manifest generation, truyền manifest vào `orchestrator.run_session_async()`:

```python
# Trong run_contract_audit.py, khi gọi orchestrator:
task_id = orchestrator.run_session_async(
    graph_id=graph_id,
    ...
    manifest=manifest,   # ← thêm param
)
```

Xem thêm signature của `run_session_async()` trong `cyber_session_orchestrator.py` để add param tương ứng và forward xuống `ContractAuditEnvBuilder`.

**Lưu ý:**
- `manifest` cần được truyền qua chuỗi: `run_contract_audit.py` → `run_session_async()` → `ContractAuditEnvBuilder`  
- Cần kiểm tra tất cả caller của `run_session_async()` — nếu có caller khác không truyền manifest, đảm bảo `manifest=None` là default (focus directive không inject).

---

## 3. S3a + S3b — Cải thiện Invariant Extractor

**File:** `backend/app/services/contract_invariant_extractor.py`

### 3.1 S3a — Mở rộng `_SYSTEM_PROMPT`

**Thay đổi:** Trong `_SYSTEM_PROMPT`, thêm 4 loại mới sau 5 loại hiện có:

```python
_SYSTEM_PROMPT = """...
[5 loại hiện tại giữ nguyên: ACCESS_CONTROL, STATE_INTEGRITY, ECONOMIC, TEMPORAL, ATOMICITY]

6. ORDERING GAPS (mới)
   - Operations must happen in a specific sequence but can be called out-of-order
   - Pattern: "interest() must be called BEFORE liquidation check — but liquidate() doesn't enforce this"
   - Pattern: "fee must be accumulated BEFORE updating position — but update() skips accrueFee()"

7. ACCOUNTING INVARIANT VIOLATIONS (mới)
   - After operation X, a sum/total should equal expected value Y
   - Pattern: "After swap, reserve0 * reserve1 MUST >= k but no post-check exists"
   - Pattern: "shares/totalSupply must equal assets/totalAssets but mint() doesn't verify ratio"

8. BOUNDARY VIOLATIONS (mới)
   - Values must stay within [min, max] at all times but bounds not enforced
   - Pattern: "sqrtPrice must be in [MIN_SQRT_RATIO, MAX_SQRT_RATIO] but no clamp after update"
   - Pattern: "Liquidation only when collateralRatio < threshold — code uses <= (off-by-one)"

9. STATE TRANSITION VIOLATIONS (mới)
   - State machine with invalid transitions allowed
   - Pattern: "Position can be burned when liquidity > 0 — should require liquidity == 0 first"
   - Pattern: "cancel() callable when status == fulfilled — missing mutual exclusion"
...
"""
```

**Sửa `_parse_invariants()`:** Thêm các category mới vào `valid_cats`:

```python
valid_cats = {
    "access_control", "state_integrity", "economic", "temporal", "atomicity",
    "ordering", "accounting", "boundary", "state_transition",  # ← thêm
}
```

**Sửa `_build_invariant_section()`:** Update display label cho các category mới (tùy chọn, không bắt buộc).

### 3.2 S3b — Domain-Specific Invariant Templates

**Thay đổi:** Thêm dict `DOMAIN_INVARIANTS` và hàm `_detect_domain()` vào đầu file (sau imports):

```python
# ─── Domain detection + template invariants ──────────────────────────────────

_DOMAIN_KEYWORDS = {
    "amm_v3": ["sqrtPrice", "tick", "feeGrowth", "secondsPerLiquidity", "tickBitmap", "sqrtRatioX96"],
    "amm_v2": ["reserve0", "reserve1", "kLast", "MINIMUM_LIQUIDITY"],
    "lending": ["collateral", "liquidat", "interestRate", "borrowIndex", "healthFactor"],
    "erc4626": ["totalAssets", "totalSupply", "convertToShares", "convertToAssets"],
    "bridge": ["nonce", "relayer", "executeMessage", "xDomain", "domainSeparator"],
}

DOMAIN_INVARIANTS = {
    "amm_v3": [
        {
            "id": "TINV-AMM3-001",
            "category": "accounting",
            "statement": "feeGrowthInside = feeGrowthGlobal - feeGrowthBelow - feeGrowthAbove (unchecked subtraction intentional)",
            "functions": ["_updatePosition", "collect"],
            "violation_hint": "If feeGrowth subtraction is NOT unchecked{}, it will revert on wrap-around",
        },
        {
            "id": "TINV-AMM3-002",
            "category": "boundary",
            "statement": "sqrtPrice must stay within [MIN_SQRT_RATIO, MAX_SQRT_RATIO] at all times",
            "functions": ["swap", "initialize"],
            "violation_hint": "Check if sqrtPrice clamping exists after price update in swap()",
        },
        {
            "id": "TINV-AMM3-003",
            "category": "accounting",
            "statement": "pool.liquidity equals sum of liquidity of all positions active at current tick",
            "functions": ["mint", "burn", "_updatePosition"],
            "violation_hint": "Verify pool.liquidity is updated correctly in mint/burn — off-by-one in tick range check",
        },
    ],
    "amm_v2": [
        {
            "id": "TINV-AMM2-001",
            "category": "accounting",
            "statement": "reserve0 * reserve1 (k) must not decrease after swap (unless fee taken correctly)",
            "functions": ["swap"],
            "violation_hint": "Check k invariant assertion at end of swap() — missing or using wrong balance snapshot",
        },
    ],
    "lending": [
        {
            "id": "TINV-LEND-001",
            "category": "ordering",
            "statement": "Interest MUST be accrued before evaluating liquidation threshold",
            "functions": ["liquidate", "isLiquidatable"],
            "violation_hint": "Check if accrueInterest() is called before health factor check in liquidate()",
        },
        {
            "id": "TINV-LEND-002",
            "category": "boundary",
            "statement": "Liquidation only when collateralRatio STRICTLY less than threshold (< not <=)",
            "functions": ["liquidate", "isLiquidatable"],
            "violation_hint": "Check comparison operator: <= allows liquidation at exact threshold (off-by-one)",
        },
    ],
    "erc4626": [
        {
            "id": "TINV-4626-001",
            "category": "accounting",
            "statement": "shares/totalSupply must equal assets/totalAssets (ERC4626 share price invariant)",
            "functions": ["deposit", "withdraw", "mint", "redeem"],
            "violation_hint": "Check if totalAssets() and totalSupply stay in sync after each operation",
        },
    ],
}


def _detect_domain(source_code: str) -> Optional[str]:
    """Keyword scan để detect domain. Trả về domain key hoặc None."""
    sample = source_code[:50_000]  # chỉ scan 50K đầu để nhanh
    scores: Dict[str, int] = {}
    for domain, keywords in _DOMAIN_KEYWORDS.items():
        count = sum(sample.count(kw) for kw in keywords)
        if count > 0:
            scores[domain] = count
    if not scores:
        return None
    return max(scores, key=lambda d: scores[d])
```

**Sửa `ContractInvariantExtractor.extract()`:** Sau bước structural scan, thêm domain detection + template injection:

```python
def extract(self, source_code, context_summary, max_source_chars=40_000):
    # Layer 1: structural (hiện tại)
    structural_invs = _structural_ownership_scan(source_code)

    # Layer 1.5: domain template invariants (mới)  ← THÊM VÀO ĐÂY
    domain = _detect_domain(source_code)
    template_invs = []
    if domain and domain in DOMAIN_INVARIANTS:
        template_invs = [dict(inv, source="template") for inv in DOMAIN_INVARIANTS[domain]]
        logger.info(f"Domain detected: {domain} — injecting {len(template_invs)} template invariants")

    # Layer 2: LLM (hiện tại, không đổi)
    ...

    # Merge: structural + template + LLM
    invariants = structural_invs + template_invs + llm_invs  # ← sửa merge order
    ...
```

**Sửa `_build_invariant_section()`:** Thêm section riêng cho template invariants:

```python
template_invs = [i for i in invariants if i.get("source") == "template"]
# Hiển thị với label [DOMAIN TEMPLATE]
```

**Lưu ý:**
- Template invariants là **gợi ý** để guide agent reasoning, không phải bằng chứng có bug.
- LLM biết context nên kết quả LLM layer vẫn có thể override/contradict template — điều đó OK.
- Nếu domain detection sai (false positive keyword match), template vô hại nhưng tốn token → cần monitor.

---

## 4. S5 — Protocol Intent Extraction từ NatSpec

**File mới:** `backend/app/services/contract_intent_extractor.py`

**Mục tiêu:** Extract "protocol MUST" statements từ NatSpec + function signatures + README, inject vào agent context trước Stage 1.

### 4.1 Tạo `contract_intent_extractor.py`

```python
"""
ContractIntentExtractor — Step 1.1 of intent-aware audit.

Extracts protocol intent from:
  1. NatSpec @notice / @dev comments in source
  2. Function signatures + parameter names (inferred intent)
  3. Contest description / README if provided

Output: "PROTOCOL INTENT" section injected into context_summary.
"""

import re
from typing import List, Optional, Dict
from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger

logger = get_logger("mirofish.intent_extractor")


# ─── NatSpec regex ────────────────────────────────────────────────────────────
# Matches /** ... */ or /// comments before a function
_NATSPEC_BLOCK_RE = re.compile(
    r'(/\*\*.*?\*/|(?:///[^\n]*\n)+)\s*'
    r'function\s+(\w+)\s*\(',
    re.DOTALL
)

def _extract_natspec_hints(source_code: str) -> List[Dict[str, str]]:
    """
    Tìm NatSpec (@notice, @dev) trước mỗi function.
    Trả về list of {function: str, notice: str, dev: str}.
    """
    hints = []
    for m in _NATSPEC_BLOCK_RE.finditer(source_code[:80_000]):
        block = m.group(1)
        func  = m.group(2)
        notice = " ".join(re.findall(r'@notice\s+(.+?)(?=@|\*/|$)', block, re.DOTALL)).strip()
        dev    = " ".join(re.findall(r'@dev\s+(.+?)(?=@|\*/|$)', block, re.DOTALL)).strip()
        if notice or dev:
            hints.append({"function": func, "notice": notice, "dev": dev})
    return hints


# ─── LLM Prompt ──────────────────────────────────────────────────────────────

_INTENT_SYSTEM_PROMPT = """You are a smart contract protocol analyst.

Given Solidity source code (including NatSpec comments), extract PROTOCOL INTENT statements — things the protocol MUST do, MUST NOT do, or MUST maintain.

Focus on:
1. ORDERING: "X must happen BEFORE Y" — e.g., "interest must accrue before liquidation check"
2. BOUNDARY: "Value V must be strictly < threshold" vs "<=" — exact comparison matters
3. ACCOUNTING: "After operation X, invariant Y must hold" — e.g., "k must not decrease after swap"
4. STATE: "Function F can only be called when state S" — e.g., "burn requires liquidity == 0"
5. EFFECT: "Operation X MUST transfer tokens / update balance" — things that must have effect

Extract from:
- @notice and @dev NatSpec comments (highest priority)
- Function names and parameter names (infer intent)
- Require/revert messages (often describe what SHOULD be true)

Return JSON:
{
  "intent_statements": [
    {
      "type": "ORDERING|BOUNDARY|ACCOUNTING|STATE|EFFECT",
      "statement": "exact protocol must-statement",
      "function": "relevant function name",
      "source": "natspec|inferred"
    }
  ]
}

Max 10 statements. Prioritize HIGH-IMPACT ones (incorrect implementation = critical bug)."""


class ContractIntentExtractor:
    """
    Extracts protocol intent from NatSpec + function signatures.
    Result injected as "PROTOCOL INTENT" block into context_summary.
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or LLMClient()

    def extract(
        self,
        source_code: str,
        context_summary: str,
        readme: Optional[str] = None,
        max_source_chars: int = 50_000,
    ) -> Dict:
        """
        Returns {"intent_statements": [...], "enriched_summary": str}.
        Never raises.
        """
        # Layer 1: structural NatSpec extraction (no LLM)
        natspec_hints = _extract_natspec_hints(source_code)
        logger.info(f"NatSpec hints found: {len(natspec_hints)} functions with @notice/@dev")

        # Layer 2: LLM extraction
        truncated = source_code[:max_source_chars]
        if len(source_code) > max_source_chars:
            truncated += f"\n// ... [{len(source_code) - max_source_chars} chars truncated]"

        readme_section = f"\nCONTEST README:\n{readme[:3000]}" if readme else ""
        natspec_summary = ""
        if natspec_hints:
            natspec_summary = "\nNATSPEC EXTRACTED:\n" + "\n".join(
                f"  {h['function']}(): {h['notice']} {h['dev']}".strip()
                for h in natspec_hints[:15]
            )

        user_content = (
            f"CONTRACT SOURCE:\n```solidity\n{truncated}\n```"
            f"{readme_section}"
            f"{natspec_summary}\n\n"
            "Extract protocol intent statements as JSON."
        )

        intent_statements = []
        try:
            raw = self.llm.chat_json(
                messages=[
                    {"role": "system", "content": _INTENT_SYSTEM_PROMPT},
                    {"role": "user",   "content": user_content},
                ],
                temperature=0.2,
                max_tokens=2048,
            )
            if isinstance(raw, dict):
                intent_statements = raw.get("intent_statements", [])[:10]
        except Exception as e:
            logger.warning(f"Intent extraction LLM failed: {e}")

        if intent_statements:
            logger.info(
                f"Intent statements: {len(intent_statements)} — "
                + ", ".join(s.get("type", "?") for s in intent_statements[:5])
            )

        # Build injection section
        if intent_statements:
            lines = ["PROTOCOL INTENT (extracted from NatSpec + code analysis):"]
            for s in intent_statements:
                t = s.get("type", "INTENT")
                stmt = s.get("statement", "")
                func = s.get("function", "")
                func_str = f" [{func}()]" if func else ""
                lines.append(f"  [{t}]{func_str} {stmt}")
            intent_section = "\n".join(lines) + "\n"
            enriched = context_summary.rstrip() + "\n\n" + intent_section
        else:
            enriched = context_summary

        return {
            "intent_statements": intent_statements,
            "enriched_summary": enriched,
        }
```

### 4.2 Integration vào `run_contract_audit.py`

> **Tại sao Step 1.1 chạy SAU KG Build (Step 1), không phải trước?**  
> Intent extractor nhận `context_summary` từ KG làm enriched context cho LLM layer — KG summary chứa function list, state variable names, contract type đã được parse, giúp LLM suy luận intent chính xác hơn so với chỉ có raw source. Nếu chạy trước Step 1, LLM phải tự parse từ source thô và dễ bỏ sót context.  
> *(Song song với KG là possible nhưng cần refactor async pipeline — để sau.)*

Thêm bước **Step 1.1** — chạy TRƯỚC Step 1.5 (invariant extraction):

```python
from app.services.contract_intent_extractor import ContractIntentExtractor

intent_extractor = ContractIntentExtractor(llm_client=orchestrator.boost_llm)

# ── Step 1.1: Extract protocol intent from NatSpec ────────────────────────
logger.info("\n[STEP 1.1/4] Extracting protocol intent from NatSpec...")
intent_result = intent_extractor.extract(
    source_code=source_code,
    context_summary=contract_summary,
    readme=readme_text,  # None nếu không có; load từ contest README.md nếu có
)
contract_summary = intent_result["enriched_summary"]
logger.info(f"  Intent statements: {len(intent_result['intent_statements'])}")
_save_json(output_dir, "intent.json", {"intent": intent_result["intent_statements"]})
```

**Load README (nếu có):** Trước bước KG build, thêm logic load README:

```python
# Tìm README trong cùng thư mục với .sol file (nếu chạy từ contest dir)
readme_text = None
if args.sol:
    sol_dir = Path(args.sol).parent
    for readme_name in ["README.md", "readme.md", "README.txt"]:
        readme_path = sol_dir / readme_name
        if readme_path.exists():
            readme_text = readme_path.read_text(encoding="utf-8", errors="replace")[:5000]
            logger.info(f"  README found: {readme_path.name} ({len(readme_text)} chars)")
            break
```

**Lưu ý:**
- Intent extractor dùng **boost LLM** (same as invariant extractor) — chất lượng tốt hơn Flash model.
- NatSpec extraction (Layer 1) là deterministic, không tốn API call.
- LLM layer chỉ chạy nếu source có đủ NatSpec hoặc function signatures để suy luận.
- Intent statements được inject vào `contract_summary` → tự động lan truyền xuống invariant extractor (Step 1.5) và agent context — không cần pass riêng.
- **Dedup risk:** `ContractKGBuilder` ở Step 1 cũng đọc NatSpec khi build `context_summary`. Nếu KG builder đã extract một phần NatSpec content vào summary, Step 1.1 có thể tạo nội dung lặp → tốn token và tạo noise. Cách xử lý: trong `ContractIntentExtractor.extract()`, kiểm tra nhanh xem `context_summary` đã chứa `"@notice"` hoặc `"PROTOCOL INTENT"` hay chưa trước khi inject. Nếu có → chỉ append delta (intent statements mới), không inject lại phần đã có.

---

## 5. Thứ tự thay đổi và luồng dữ liệu sau khi xong

```
run_contract_audit.py:
  ├── [STEP 1]   KG Build → contract_summary
  ├── [STEP 1.1] Intent Extractor (S5)
  │              NatSpec + LLM → PROTOCOL INTENT → enriched contract_summary
  ├── [STEP 1.3] Dep Graph (1b)  [nếu sol_path / contest_dir có và slither available]
  │              Slither → READ/WRITE edges → DepGraphSummary → enriched contract_summary
  │              Optionally → Memgraph
  ├── [STEP 1.5] Invariant Extractor (S3a + S3b)
  │              structural scan + domain templates (S3b) + LLM (S3a extended)
  │              → MISSING ENFORCEMENT TARGETS → enriched contract_summary
  ├── [STEP 2]   Profile Generator  ← nhận enriched contract_summary
  └── [STEP 3]   Audit Session
                 ContractAuditEnvBuilder(manifest=manifest)  ← S2a Bước 2
                 stage1_instruction += SWC rules (S1a ✅) + focus directive (S2a)
```

---

## 6. Checklist triển khai

| # | Việc cần làm | File | Ưu tiên |
|---|-------------|------|--------|
| 1 | ✅ S1a: SWC tagging rules trong stage1 Phase A + B | `contract_oasis_env.py` | Done |
| 2 | S2a Bước 1: `_compute_manifest()` + `emit_manifest` param | `flatten_contest.py` | P1 |
| 3 | S2a Bước 2: `_build_focus_directive()` trong EnvBuilder | `contract_oasis_env.py` | P1 |
| 4 | S2a Bước 2: forward manifest qua `run_session_async()` | `run_contract_audit.py`, `cyber_session_orchestrator.py` | P1 |
| 5 | 1b: `contract_dep_graph.py` (Slither; Memgraph optional) | new file | P2 |
| 6 | 1b: thêm slither-analyzer + mgclient vào deps | `pyproject.toml` | P2 |
| 7 | 1b: Memgraph service vào docker-compose (optional nếu chỉ dùng in-memory) | `docker-compose.yml` | P2 |
| 8 | 1b: integrate dep graph vào run script | `run_contract_audit.py` | P2 |
| 9 | S3a: mở rộng `_SYSTEM_PROMPT` + `valid_cats` | `contract_invariant_extractor.py` | P2 |
| 10 | S3b: `DOMAIN_INVARIANTS` + `_detect_domain()` + template inject | `contract_invariant_extractor.py` | P2 |
| 11 | S5: tạo `contract_intent_extractor.py` | new file | P2 |
| 12 | S5: integrate intent extractor vào run script | `run_contract_audit.py` | P2 |

---

## 7. Lưu ý kiểm thử

- Sau mỗi giai đoạn, chạy lại **C35** (contest có nhiều FN nhất) để đo delta.
- Metric cần theo dõi: L F1, S F1, số SWC-101 findings, số S6 findings.
- Kết quả baseline: C35 L F1=0.000, S F1=0.154.
- Mục tiêu sau S1a + S2a: L F1 > 0.1 (SWC-101 tagging tăng), S F1 không giảm.
- Mục tiêu sau S3a + S5: S F1 > 0.3 (S6 recall tăng).
