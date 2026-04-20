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

import re
import time
import threading
import uuid
from typing import Callable, Dict, List, Any, Optional


def _zep_retry(fn: Callable, max_attempts: int = 8):
    """Retry a Zep API call on 429 / 403-episode-limit errors with exponential backoff."""
    import logging as _logging
    _log = _logging.getLogger("mirofish.contract_kg")
    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as e:
            s = str(e)
            is_rate = ("429" in s or "rate limit" in s.lower())
            is_episode_limit = ("403" in s and "episode" in s.lower())
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
        self.graph_service = graph_service or GraphBuilderService()
        self.task_manager = TaskManager()
        self._partial_graph_ids: dict = {}  # task_id -> graph_id, for cleanup on timeout

    # ─── Public async API ─────────────────────────────────────────────────────

    def build_from_source_async(self, source_code: str, graph_name: str) -> str:
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
            args=(task_id, source_code, graph_name),
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

        lines.append("")
        lines.append("NOTE: All agents must reference function names and state variables above when reporting findings.")
        lines.append("      Cite specific evidence from this context or contract source code.")

        return "\n".join(lines)

    # ─── Workers ──────────────────────────────────────────────────────────────

    def _build_worker(self, task_id: str, source_code: str, graph_name: str):
        """Full pipeline: parse source → store to Zep."""
        try:
            self.task_manager.update_task(
                task_id, status=TaskStatus.PROCESSING,
                progress=5, message="Parsing Solidity source code..."
            )
            entity = self.parser.parse_from_source(source_code)

            self.task_manager.update_task(
                task_id, progress=40,
                message=f"Parsed {entity.contract_id}: {len(entity.functions)} functions. Building Zep KG..."
            )
            graph_id = self._store_to_zep(graph_name, entity, task_id=task_id)

            context_summary = self.build_context_summary(entity)

            self._partial_graph_ids.pop(task_id, None)  # no longer partial
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
            self.task_manager.update_task(
                task_id, status=TaskStatus.PROCESSING,
                progress=20, message=f"Building Zep KG for {entity.contract_id}..."
            )
            graph_id = self._store_to_zep(graph_name, entity)
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

        episode_uuids = _zep_retry(lambda: self.graph_service.add_text_batches(
            graph_id, chunks, batch_size=3,
            progress_callback=lambda msg, _: logger.debug(msg)
        ))
        self.graph_service._wait_for_episodes(
            episode_uuids,
            progress_callback=lambda msg, _: logger.debug(msg)
        )
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
