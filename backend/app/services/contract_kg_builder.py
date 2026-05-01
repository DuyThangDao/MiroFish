"""
Contract Knowledge Graph Builder — Đề tài 10 (Smart Contract Audit).

Build Zep KG từ ContractEntity.
Thay thế NetworkTopologyBuilder trong Hướng B — reuse GraphBuilderService pattern.

KG structure:
  Node types: Contract, Function, StateVar, ExternalDep
  Edge types:
    function → CALLS_EXTERNAL → external_dep (with before_state_update property)
    function → MODIFIES → state_var
    function → HAS_MODIFIER → modifier
    state_var → CRITICAL_ASSET → contract
    contract → HAS_FUNCTION → function
    contract → HAS_STATE_VAR → state_var
"""

import os
import re
import time
import threading
import uuid
from typing import Callable, Dict, List, Any, Optional

_ENABLE_ZEP = os.getenv("ENABLE_ZEP", "false").lower() == "true"


def _zep_retry(fn: Callable, max_attempts: int = 8, retry_episode_limit: bool = True):
    """Retry a Zep API call on 429 / 403-episode-limit errors with exponential backoff.

    retry_episode_limit=False: fail immediately on monthly quota exceeded
    (useful for episode batch upload — caller handles graceful degradation).
    """
    import logging as _logging
    _log = _logging.getLogger("mirofish.contract_kg")
    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as e:
            s = str(e)
            is_rate = ("429" in s or "rate limit" in s.lower())
            is_episode_limit = ("403" in s and "episode" in s.lower())
            if is_episode_limit and not retry_episode_limit:
                raise  # fail fast — caller will degrade gracefully
            if (is_rate or is_episode_limit) and attempt < max_attempts - 1:
                m = re.search(r"retry-after['\": ]+(\d+)", s.lower())
                wait = int(m.group(1)) + 1 if m else min(15 * (2 ** attempt), 120)
                label = "403-episode-limit" if is_episode_limit else "429"
                _log.warning(f"Zep {label} (attempt {attempt+1}/{max_attempts}), waiting {wait}s")
                time.sleep(wait)
            else:
                raise

from ..utils.logger import get_logger
from ..models.task import TaskManager, TaskStatus
from ..models.contract_models import ContractEntity, ContractFunction
from .graph_builder import GraphBuilderService
from .contract_parser import ContractParser

logger = get_logger("mirofish.contract_kg")


# ─── Contract Audit Ontology for Zep ──────────────────────────────────────────

CONTRACT_AUDIT_ONTOLOGY: Dict[str, Any] = {
    "entity_types": [
        {
            "name": "SmartContract",
            "description": "A deployed or audited smart contract",
            "attributes": [
                {"name": "contract_id",         "description": "Unique contract identifier, e.g. TokenVault"},
                {"name": "contract_type",        "description": "ERC20 | ERC721 | DeFi_Lending | DeFi_AMM | Governance | Bridge | Vault | Custom"},
                {"name": "compiler_version",     "description": "Solidity compiler version, e.g. 0.8.19"},
                {"name": "has_reentrancy_guard", "description": "True if ReentrancyGuard or nonReentrant modifier is present"},
                {"name": "has_access_control",   "description": "True if onlyOwner or RBAC is present"},
                {"name": "uses_oracle",          "description": "True if contract uses a price oracle"},
                {"name": "uses_flash_loan",      "description": "True if contract implements flash loan"},
                {"name": "is_upgradeable",       "description": "True if proxy / upgradeable pattern is used"},
                {"name": "swc_candidates",       "description": "Comma-separated SWC IDs from static analysis"},
            ]
        },
        {
            "name": "ContractFunction",
            "description": "A function defined in a smart contract",
            "attributes": [
                {"name": "function_name",            "description": "Function name, e.g. withdraw"},
                {"name": "visibility",               "description": "public | private | internal | external"},
                {"name": "modifiers",                "description": "Comma-separated modifiers, e.g. onlyOwner,nonReentrant"},
                {"name": "has_external_call",        "description": "True if function calls external address"},
                {"name": "external_call_before_state","description": "True if external call happens before state update (reentrancy risk)"},
                {"name": "sends_ether",              "description": "True if function sends ETH"},
                {"name": "swc_candidates",           "description": "Comma-separated SWC IDs from static analysis of this function"},
                {"name": "source_lines",             "description": "Source line range, e.g. 45-67"},
            ]
        },
        {
            "name": "StateVariable",
            "description": "A state variable in a smart contract",
            "attributes": [
                {"name": "var_name",     "description": "Variable name, e.g. balances"},
                {"name": "var_type",     "description": "Solidity type, e.g. mapping(address => uint256)"},
                {"name": "visibility",   "description": "public | private | internal"},
                {"name": "is_critical",  "description": "True if this holds balances, owner, or admin roles"},
                {"name": "modified_by",  "description": "Comma-separated function names that modify this var"},
            ]
        },
        {
            "name": "ExternalDependency",
            "description": "External contract, interface, or library that this contract interacts with",
            "attributes": [
                {"name": "dep_name",  "description": "Dependency name, e.g. OpenZeppelin/IERC20"},
                {"name": "dep_type",  "description": "interface | library | contract"},
            ]
        },
    ],
    "edge_types": [
        {"name": "has_function",             "description": "Contract defines a function"},
        {"name": "has_state_var",            "description": "Contract defines a state variable"},
        {"name": "modifies",                 "description": "Function modifies a state variable"},
        {"name": "calls_external",           "description": "Function calls an external contract or address (with before_state_update property)"},
        {"name": "has_modifier",             "description": "Function has a modifier (e.g. onlyOwner)"},
        {"name": "depends_on",               "description": "Contract imports or inherits from external dependency"},
        {"name": "critical_reentrancy_path", "description": "Marks a function→external call path as reentrancy risk"},
    ]
}


class ContractKGBuilder:
    """
    Build Zep KG từ ContractEntity.
    Thay thế NetworkTopologyBuilder trong Hướng B.

    Workflow:
    1. ContractParser.parse_from_source() → ContractEntity
    2. _store_to_zep() — episodic text + structured facts → Zep graph
    3. build_context_summary() — query Zep → tóm tắt inject vào tất cả agents
    """

    def __init__(
        self,
        parser: Optional[ContractParser] = None,
        graph_service: Optional[GraphBuilderService] = None,
    ):
        self.parser = parser or ContractParser()
        self._zep_enabled = _ENABLE_ZEP
        self.graph_service = graph_service or (GraphBuilderService() if self._zep_enabled else None)
        self.task_manager = TaskManager()
        self._partial_graph_ids: dict = {}  # task_id -> graph_id, for cleanup on timeout

    # ─── Public async API ─────────────────────────────────────────────────────

    def build_from_source_async(self, source_code: str, graph_name: str, contract_name: str = "") -> str:
        """
        Async: parse Solidity source → build Zep KG.
        Returns task_id.
        """
        task_id = self.task_manager.create_task(
            task_type="contract_kg_build",
            metadata={"graph_name": graph_name, "source_length": len(source_code)}
        )
        thread = threading.Thread(
            target=self._build_worker,
            args=(task_id, source_code, graph_name, contract_name),
            daemon=True,
        )
        thread.start()
        return task_id

    def build_from_entity_async(self, entity: ContractEntity, graph_name: str) -> str:
        """
        Async: từ ContractEntity đã có → build Zep KG (bỏ qua parse step).
        Returns task_id.
        """
        task_id = self.task_manager.create_task(
            task_type="contract_kg_build",
            metadata={"graph_name": graph_name, "contract_id": entity.contract_id}
        )
        thread = threading.Thread(
            target=self._store_worker,
            args=(task_id, entity, graph_name),
            daemon=True,
        )
        thread.start()
        return task_id

    # ─── Context completeness helpers (Tầng 1 + Tầng 3) ─────────────────────────

    @staticmethod
    def _extract_function_snippets(
        source_code: str, func_names: list, max_body_lines: int = 3, max_line_chars: int = 90
    ) -> dict:
        """
        Tầng 1: extract first N statements from each function body.
        Returns {func_name: "stmt1 | stmt2 | stmt3"}.

        Agents see actual implementation → can verify safety patterns (SafeMath,
        require checks, CEI order) without hallucinating.
        """
        src_lines = source_code.split('\n')
        snippets: dict = {}

        for name in func_names:
            func_re = re.compile(rf'\bfunction\s+{re.escape(name)}\b')
            # Find ALL occurrences (flat files have interface stubs before implementations)
            all_starts = [i for i, ln in enumerate(src_lines) if func_re.search(ln)]
            if not all_starts:
                continue

            # Try occurrences in reverse order — implementation bodies come after stubs
            body: list = []
            for start in reversed(all_starts):
                # Scan forward to opening brace (may be on same or next few lines)
                brace_line = start
                found_brace = False
                for j in range(start, min(start + 6, len(src_lines))):
                    if '{' in src_lines[j]:
                        brace_line = j
                        found_brace = True
                        break
                if not found_brace:
                    continue

                # Collect meaningful body lines
                candidate: list = []
                for ln in src_lines[brace_line + 1: brace_line + 18]:
                    s = ln.strip()
                    if not s or s.startswith('//') or s.startswith('*'):
                        continue
                    if s == '}':
                        break
                    candidate.append(s[:max_line_chars])
                    if len(candidate) >= max_body_lines:
                        break
                if candidate:
                    body = candidate
                    break  # found an occurrence with actual body

            if body:
                snippets[name] = ' | '.join(body)

        return snippets

    @staticmethod
    def _detect_safety_patterns(source_code: str) -> list:
        """
        Tầng 3: detect safety/protection mechanisms in Solidity source.
        Returns list of human-readable signal strings for context_summary.

        Provides explicit ground-truth context so agents don't need to infer
        whether SafeMath, reentrancy guards, or access control are present.
        """
        signals: list = []

        # SafeMath — most common FP trigger for SWC-101
        # Handle both: 'using SafeMath for uint256' and 'using SafeMath for *'
        safemath_types = re.findall(r'using\s+SafeMath\s+for\s+(\w+|\*)', source_code)
        if safemath_types:
            types_str = "all types" if "*" in safemath_types else ", ".join(set(safemath_types))
            signals.append(
                f"SafeMath applied to {types_str} — "
                f"arithmetic overflow/underflow protection ACTIVE; SWC-101 likely mitigated"
            )
        elif re.search(r'\blibrary\s+SafeMath\b', source_code):
            signals.append(
                "SafeMath library defined — "
                "check for 'using SafeMath for' before reporting SWC-101"
            )

        # Solidity 0.8+ built-in overflow protection
        m = re.search(r'pragma\s+solidity\s+\^?([\d.]+)', source_code)
        if m:
            parts = m.group(1).split('.')
            major, minor = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
            if major == 0 and minor < 8:
                signals.append(
                    f"Compiler ^{m.group(1)}: pre-0.8 — NO built-in overflow protection; "
                    f"SafeMath or manual checks required for safe arithmetic"
                )
            else:
                signals.append(
                    f"Compiler ^{m.group(1)}: 0.8+ — arithmetic operators (+/-/*) revert on "
                    f"overflow/underflow; BUT explicit type casts (uint128(x), int256(y), uint256(int)) "
                    f"are NOT protected and silently truncate — SWC-101 still applicable via unsafe casting. "
                    f"Always check unchecked{{}} blocks and explicit casts."
                )

        # ReentrancyGuard
        if re.search(r'\bnonReentrant\b', source_code):
            nr_funcs = re.findall(
                r'function\s+(\w+)[^{]*\bnonReentrant\b', source_code
            )
            funcs_str = f" on: {', '.join(nr_funcs)}" if nr_funcs else ""
            signals.append(
                f"nonReentrant modifier present{funcs_str} — "
                f"reentrancy (SWC-107) mitigated on these functions"
            )

        # tx.origin
        if re.search(r'\btx\.origin\b', source_code):
            tx_funcs = re.findall(
                r'function\s+(\w+)[^{]*\{[^}]*\btx\.origin\b', source_code, re.DOTALL
            )
            funcs_str = f" in: {', '.join(tx_funcs[:3])}" if tx_funcs else ""
            signals.append(
                f"tx.origin used for authentication{funcs_str} — SWC-115 confirmed"
            )

        # Access control modifiers
        only_mods = list(set(re.findall(r'\bmodifier\s+(only\w+)\b', source_code)))
        if only_mods:
            signals.append(f"Access control modifiers defined: {', '.join(only_mods)}")

        # require() count as proxy for input validation density
        req_count = len(re.findall(r'\brequire\s*\(', source_code))
        if req_count:
            signals.append(f"Input validation: {req_count} require() checks in source")

        return signals

    @staticmethod
    def _extract_events_and_rules(source_code: str) -> str:
        """
        Extract events (state-transition signals) and require() messages (business rules)
        from Solidity source. Injected into context_summary AFTER parsing — never touches
        the KG builder's input so function names remain uncontaminated.
        """
        lines: List[str] = []

        # Events — tell agents what state transitions the protocol considers significant
        event_re = re.compile(
            r'^\s*event\s+(\w+)\s*\(([^)]*)\)\s*;',
            re.MULTILINE | re.DOTALL,
        )
        events = []
        for m in event_re.finditer(source_code):
            params = re.sub(r'\s+', ' ', m.group(2).replace('\n', ' ')).strip()
            events.append(f"{m.group(1)}({params})")
        if events:
            lines.append("PROTOCOL EVENTS (state-transition signals):")
            for ev in events[:20]:
                lines.append(f"  event {ev}")
            lines.append("")

        # require() messages — plain-English business rules embedded in code
        req_re = re.compile(
            r'require\s*\([^,)]+,\s*["\']([^"\']{4,80})["\']',
            re.MULTILINE,
        )
        msgs = list(dict.fromkeys(
            m.group(1).strip()
            for m in req_re.finditer(source_code)
            if len(m.group(1).strip()) > 5
        ))
        if msgs:
            lines.append("BUSINESS RULES (require messages):")
            for msg in msgs[:25]:
                lines.append(f'  "{msg}"')
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _build_call_graph_summary(source_code: str, known_functions: List[str]) -> str:
        """
        Build a per-function call-dependency summary using known_functions from the parsed
        entity. Only tracks calls to known functions — no hallucination from comment text.
        Falls back to regex extraction if entity parsing yielded no functions.
        Marks low-level / interface calls as [EXTERNAL].
        """
        if not known_functions:
            # Regex fallback: extract from source directly (only real function names)
            known_functions = list(set(re.findall(
                r'\bfunction\s+([a-zA-Z_]\w*)\s*\(', source_code
            )))
        if not known_functions:
            return ""

        fn_set = set(known_functions)
        LOW_LEVEL = {"call", "delegatecall", "staticcall", "transfer", "send"}

        fn_body_re = re.compile(
            r'function\s+(\w+)\s*\([^)]*\)[^{]*\{',
            re.MULTILINE,
        )
        call_re = re.compile(r'\b(\w+)\s*\(')

        matches = list(fn_body_re.finditer(source_code))
        if not matches:
            return ""

        lines: List[str] = ["CALL GRAPH:"]
        for i, m in enumerate(matches):
            fn_name = m.group(1)
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(source_code)
            body = source_code[start:end]

            called: set = set()
            ext_markers: set = set()

            for cm in call_re.finditer(body):
                callee = cm.group(1)
                if callee in fn_set and callee != fn_name:
                    called.add(callee)
                if callee in LOW_LEVEL:
                    ext_markers.add(callee)

            if re.search(r'\.(call|delegatecall|staticcall)\s*[({]', body):
                ext_markers.add("low-level-call")
            if re.search(r'I[A-Z]\w+\s*\(\s*\w+\s*\)\.', body):
                ext_markers.add("interface-call")

            parts: List[str] = []
            if called:
                parts.append("calls: " + ", ".join(sorted(called)))
            if ext_markers:
                parts.append("[EXTERNAL: " + ", ".join(sorted(ext_markers)) + "]")

            desc = " | ".join(parts) if parts else "(leaf)"
            lines.append(f"  {fn_name}() → {desc}")

        lines.append("")
        return "\n".join(lines)

    # ─── Context summary for agent injection ─────────────────────────────────

    def build_context_summary(self, entity: ContractEntity) -> str:
        """
        Build a structured text summary of ContractEntity to inject into all agents.
        Replaces build_attack_surface_context() from Hướng B.

        Format is designed to be concise and machine-readable for LLM agents.
        """
        lines: List[str] = []
        lines.append(f"=== Contract Audit Context: {entity.contract_id} ===")
        lines.append(f"Type: {entity.contract_type} | Compiler: {entity.compiler_version}")
        lines.append("")

        # Functions summary
        public_funcs = [f for f in entity.functions if f.visibility in ("public", "external")]
        if public_funcs:
            lines.append("PUBLIC/EXTERNAL FUNCTIONS:")
            for f in public_funcs:
                mods = f", mods=[{', '.join(f.modifiers)}]" if f.modifiers else ""
                eth_flag = " [SENDS ETH]" if f.sends_ether else ""
                lines.append(f"  - {f.name}(){mods}{eth_flag}")
                if f.swc_candidates:
                    lines.append(f"    Static SWC candidates: {', '.join(f.swc_candidates)}")
            lines.append("")
            # Tầng 1: inject function body snippets for public/external functions
            if entity.source_code:
                snippets = ContractKGBuilder._extract_function_snippets(
                    entity.source_code, [f.name for f in public_funcs[:20]]
                )
                if snippets:
                    lines.append("FUNCTION IMPLEMENTATIONS:")
                    for fname, snippet in snippets.items():
                        lines.append(f"  {fname}(): {snippet}")
                    lines.append("")
        elif entity.source_code:
            # RC-1 (2nd layer): static regex fallback when LLM extraction missed functions.
            # Gives agents a ground-truth function list so they don't hallucinate.
            static_funcs = sorted(set(re.findall(
                r'\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
                entity.source_code
            )))
            if static_funcs:
                # Tầng 1: show snippets instead of bare names for richer context
                snippets = ContractKGBuilder._extract_function_snippets(
                    entity.source_code, static_funcs[:20]
                )
                if snippets:
                    lines.append("FUNCTION IMPLEMENTATIONS:")
                    for fname, snippet in snippets.items():
                        lines.append(f"  {fname}(): {snippet}")
                else:
                    lines.append("DEFINED FUNCTIONS:")
                    lines.append(f"  {', '.join(static_funcs)}")
                lines.append("")

        # Critical state variables
        critical_vars = [v for v in entity.state_vars if v.is_critical]
        if critical_vars:
            lines.append("CRITICAL STATE VARIABLES:")
            for v in critical_vars:
                modified = f", modified_by=[{', '.join(v.modified_by)}]" if v.modified_by else ""
                lines.append(f"  - {v.name}: {v.var_type}{modified}")
            lines.append("")

        # Risk signals section
        risk = entity.risk_summary()
        lines.append("RISK SIGNALS:")

        if risk["reentrancy_risk_functions"]:
            lines.append(
                f"  ⚠ REENTRANCY: Functions with external call before state update: "
                f"{', '.join(risk['reentrancy_risk_functions'])}"
            )
        if risk["missing_reentrancy_guard"]:
            lines.append("  ⚠ NO ReentrancyGuard — SWC-107 risk confirmed")
        if risk["unprotected_ether_senders"]:
            lines.append(
                f"  ⚠ UNPROTECTED ETH SEND: {', '.join(risk['unprotected_ether_senders'])}"
            )
        if risk["missing_access_control"]:
            lines.append("  ⚠ NO access control detected (no onlyOwner / RBAC)")
        if risk["oracle_manipulation_risk"]:
            lines.append("  ⚠ ORACLE used without circuit breaker — flash loan price manipulation risk")
        if risk["flash_loan_risk"]:
            lines.append("  ⚠ FLASH LOAN interface — cross-contract reentrancy risk")
        if risk["upgrade_risk"]:
            lines.append("  ⚠ UPGRADEABLE proxy — verify upgrade admin is multi-sig + timelock")
        if risk["swc_candidates"]:
            lines.append(f"  Static SWC candidates: {', '.join(risk['swc_candidates'])}")

        if not any([
            risk["reentrancy_risk_functions"],
            risk["missing_reentrancy_guard"],
            risk["unprotected_ether_senders"],
            risk["missing_access_control"],
            risk["oracle_manipulation_risk"],
            risk["flash_loan_risk"],
            risk["upgrade_risk"],
            risk["swc_candidates"],
        ]):
            lines.append("  No static risk signals detected — deep semantic analysis required")

        lines.append("")

        # Security controls present
        controls_present = []
        if entity.has_reentrancy_guard:
            controls_present.append("ReentrancyGuard")
        if entity.has_access_control:
            controls_present.append("AccessControl")
        if entity.has_pausable:
            controls_present.append("Pausable")
        if controls_present:
            lines.append(f"SECURITY CONTROLS PRESENT: {', '.join(controls_present)}")

        # External dependencies
        if entity.external_dependencies:
            lines.append(f"EXTERNAL DEPENDENCIES: {', '.join(entity.external_dependencies[:10])}")

        # Tầng 3: safety patterns — explicit ground-truth about protections present
        if entity.source_code:
            safety = ContractKGBuilder._detect_safety_patterns(entity.source_code)
            if safety:
                lines.append("SAFETY PATTERNS DETECTED:")
                for s in safety:
                    lines.append(f"  • {s}")
                lines.append("")

        lines.append("NOTE: All agents must reference function names and state variables above when reporting findings.")
        lines.append("      Cite specific evidence from this context or contract source code.")

        # Inject events + business rules + call graph from source (after parse — no contamination)
        if entity.source_code:
            all_fn_names = [f.name for f in entity.functions]
            events_and_rules = ContractKGBuilder._extract_events_and_rules(entity.source_code)
            if events_and_rules:
                lines.append("")
                lines.append(events_and_rules)
            call_graph = ContractKGBuilder._build_call_graph_summary(
                entity.source_code, all_fn_names
            )
            if call_graph:
                lines.append(call_graph)

        return "\n".join(lines)

    # ─── Workers ──────────────────────────────────────────────────────────────

    def _build_worker(self, task_id: str, source_code: str, graph_name: str, contract_name: str = ""):
        """Full pipeline: parse source → (optional) store to Zep → build context summary."""
        try:
            self.task_manager.update_task(
                task_id, status=TaskStatus.PROCESSING,
                progress=5, message="Parsing Solidity source code..."
            )
            entity = self.parser.parse_from_source(source_code, contract_name=contract_name)

            graph_id = None
            if self._zep_enabled:
                self.task_manager.update_task(
                    task_id, progress=40,
                    message=f"Parsed {entity.contract_id}: {len(entity.functions)} functions. Building Zep KG..."
                )
                graph_id = self._store_to_zep(graph_name, entity, task_id=task_id)
            else:
                self.task_manager.update_task(
                    task_id, progress=40,
                    message=f"Parsed {entity.contract_id}: {len(entity.functions)} functions. Building context summary (Zep disabled)..."
                )

            context_summary = self.build_context_summary(entity)

            self._partial_graph_ids.pop(task_id, None)
            self.task_manager.complete_task(task_id, {
                "graph_id": graph_id,
                "contract_id": entity.contract_id,
                "contract_type": entity.contract_type,
                "function_count": len(entity.functions),
                "state_var_count": len(entity.state_vars),
                "swc_candidates": entity.swc_candidates,
                "context_summary": context_summary,
            })
        except Exception as e:
            import traceback
            self.task_manager.fail_task(task_id, f"{e}\n{traceback.format_exc()}")

    def _store_worker(self, task_id: str, entity: ContractEntity, graph_name: str):
        """Skip parse step — entity already available."""
        try:
            graph_id = None
            if self._zep_enabled:
                self.task_manager.update_task(
                    task_id, status=TaskStatus.PROCESSING,
                    progress=20, message=f"Building Zep KG for {entity.contract_id}..."
                )
                graph_id = self._store_to_zep(graph_name, entity)
            else:
                self.task_manager.update_task(
                    task_id, status=TaskStatus.PROCESSING,
                    progress=20, message=f"Building context summary for {entity.contract_id} (Zep disabled)..."
                )
            context_summary = self.build_context_summary(entity)

            self.task_manager.complete_task(task_id, {
                "graph_id": graph_id,
                "contract_id": entity.contract_id,
                "contract_type": entity.contract_type,
                "function_count": len(entity.functions),
                "state_var_count": len(entity.state_vars),
                "swc_candidates": entity.swc_candidates,
                "context_summary": context_summary,
            })
        except Exception as e:
            import traceback
            self.task_manager.fail_task(task_id, f"{e}\n{traceback.format_exc()}")

    # ─── Core Zep storage ─────────────────────────────────────────────────────

    def _store_to_zep(self, graph_name: str, entity: ContractEntity,
                      task_id: str = None) -> str:
        """
        Lưu ContractEntity vào Zep graph.

        1. Create graph + set CONTRACT_AUDIT_ONTOLOGY
        2. Add episodic text chunks:
           - entity.to_zep_text() (structured summary)
           - per-function descriptions
           - risk signal text
           - raw source (chunked, limited to ~8k chars)
        3. Wait for episode processing
        """
        graph_id = _zep_retry(lambda: self.graph_service.create_graph(graph_name))
        logger.info(f"Created Zep contract graph: {graph_id}")

        # Register immediately so run_audit can delete this graph even if poll times out
        if task_id:
            self._partial_graph_ids[task_id] = graph_id

        _zep_retry(lambda: self.graph_service.set_ontology(graph_id, CONTRACT_AUDIT_ONTOLOGY))
        logger.info("Set contract audit ontology on graph")

        chunks = self._build_episode_chunks(entity)
        logger.info(f"Sending {len(chunks)} episode chunks to Zep for {entity.contract_id}")

        try:
            episode_uuids = _zep_retry(
                lambda: self.graph_service.add_text_batches(
                    graph_id, chunks, batch_size=3,
                    progress_callback=lambda msg, _: logger.debug(msg)
                ),
                retry_episode_limit=False,  # fail fast so caller can degrade gracefully
            )
            self.graph_service._wait_for_episodes(
                episode_uuids,
                progress_callback=lambda msg, _: logger.debug(msg)
            )
        except Exception as e:
            if "403" in str(e) and "episode" in str(e).lower():
                logger.warning(
                    f"Zep monthly episode quota exceeded — continuing without KG episodes "
                    f"for {entity.contract_id}. context_summary will use local parse only."
                )
            else:
                raise
        return graph_id

    def _build_episode_chunks(self, entity: ContractEntity) -> List[str]:
        """
        Build list of text chunks to push as Zep episodes.
        Each chunk is meaningful, self-contained, and designed to surface
        as semantic context for agent queries.
        """
        from .text_processor import TextProcessor

        chunks: List[str] = []

        # 1. Overall contract summary
        chunks.append(entity.to_zep_text())

        # 2. Per-function detailed description
        for func in entity.functions:
            chunk = self._function_to_episode_text(entity.contract_id, func)
            chunks.append(chunk)

        # 3. State variables description
        if entity.state_vars:
            sv_lines = [
                f"Contract {entity.contract_id} state variables:"
            ]
            for v in entity.state_vars:
                critical_flag = " [CRITICAL]" if v.is_critical else ""
                modifiers_str = ", ".join(v.modified_by) if v.modified_by else "none"
                sv_lines.append(
                    f"  {v.visibility} {v.var_type} {v.name}{critical_flag} — modified by: {modifiers_str}"
                )
            chunks.append("\n".join(sv_lines))

        # 4. Risk signal summary (this is the most valuable for agents)
        risk_text = self._risk_signal_episode(entity)
        if risk_text:
            chunks.append(risk_text)

        # 5. Source code chunks (limited to first 8000 chars to avoid token overload)
        if entity.source_code:
            source_limited = entity.source_code[:8000]
            source_chunks = TextProcessor.split_text(source_limited, chunk_size=600, overlap=50)
            chunks.extend(source_chunks)

        return chunks

    def _function_to_episode_text(self, contract_id: str, func: ContractFunction) -> str:
        """Convert one ContractFunction to a rich text episode for Zep."""
        lines = [f"Function {func.name}() in contract {contract_id}:"]
        lines.append(f"  Visibility: {func.visibility}")

        if func.modifiers:
            lines.append(f"  Modifiers: {', '.join(func.modifiers)}")
        else:
            lines.append("  Modifiers: NONE")

        if func.parameters:
            lines.append(f"  Parameters: {', '.join(func.parameters)}")

        lines.append(f"  Sends ETH: {func.sends_ether}")
        lines.append(f"  Has external call: {func.has_external_call}")

        if func.external_call_before_state:
            lines.append(
                f"  WARNING: external_call_before_state_update=TRUE — "
                f"state vars [{', '.join(func.state_updates)}] are updated AFTER external call. "
                f"This is a reentrancy vulnerability pattern (SWC-107)."
            )
        elif func.has_external_call and func.state_updates:
            lines.append(
                f"  External call present, state updates: {', '.join(func.state_updates)} "
                f"(verify order: call AFTER state update = safe)"
            )

        if func.state_updates:
            lines.append(f"  Modifies state vars: {', '.join(func.state_updates)}")

        if func.swc_candidates:
            lines.append(f"  SWC candidates from static analysis: {', '.join(func.swc_candidates)}")

        if func.source_lines:
            lines.append(f"  Source lines: {func.source_lines}")

        return "\n".join(lines)

    def _risk_signal_episode(self, entity: ContractEntity) -> str:
        """Build a risk-focused episode that will be surfaced in agent context queries."""
        risk = entity.risk_summary()
        lines = [f"Security risk analysis for contract {entity.contract_id}:"]

        if risk["reentrancy_risk_functions"]:
            lines.append(
                f"REENTRANCY RISK: Functions with external call before state update: "
                f"{', '.join(risk['reentrancy_risk_functions'])}. "
                f"SWC-107 vulnerability pattern confirmed by static analysis."
            )
        if risk["missing_reentrancy_guard"]:
            lines.append(
                "MISSING PROTECTION: No ReentrancyGuard or nonReentrant modifier found. "
                "High reentrancy exploitability."
            )
        if risk["unprotected_ether_senders"]:
            lines.append(
                f"UNPROTECTED ETH TRANSFER: Functions sending ETH without access control: "
                f"{', '.join(risk['unprotected_ether_senders'])}. "
                f"SWC-105 vulnerability pattern."
            )
        if risk["missing_access_control"]:
            lines.append(
                "MISSING ACCESS CONTROL: No onlyOwner or role-based access control detected. "
                "Administrative functions may be publicly callable."
            )
        if risk["oracle_manipulation_risk"]:
            lines.append(
                "ORACLE MANIPULATION RISK: Contract uses price oracle without circuit breaker. "
                "Flash loan price manipulation attack possible (DeFi attack pattern)."
            )
        if risk["flash_loan_risk"]:
            lines.append(
                "FLASH LOAN INTERFACE: Contract implements flash loan. "
                "Cross-contract reentrancy and complex attack paths possible."
            )
        if risk["upgrade_risk"]:
            lines.append(
                "UPGRADE RISK: Contract is upgradeable (proxy pattern). "
                "Verify upgrade admin is multi-sig + timelock. Storage collision risk."
            )
        if risk["swc_candidates"]:
            lines.append(
                f"STATIC ANALYSIS FINDINGS: {', '.join(risk['swc_candidates'])} "
                f"patterns detected in source code."
            )

        if len(lines) == 1:
            # No risk signals
            return ""

        return "\n".join(lines)
