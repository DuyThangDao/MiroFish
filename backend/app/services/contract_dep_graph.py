"""
ContractDepGraph — Static data-flow dependency graph via Slither.

Extracts (Function) -[READS/WRITES]-> (StateVar) edges using Slither Python API:
  - function.state_variables_read  → set of StateVariable read by the function
  - function.state_variables_written → set of StateVariable written by the function

Stores in Memgraph (when MEMGRAPH_ENABLED=true) or in-memory dict (default).
Provides DepGraphSummary.text for injection into agent context_summary.

Integration point: called as Step 1.3 in run_contract_audit.py, after KG Build,
before Invariant Extraction. Requires contest_dir path (not flat source string)
because Slither needs a compilable project structure.
"""

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from ..utils.logger import get_logger

logger = get_logger("mirofish.dep_graph")


@dataclass
class DepGraphSummary:
    """Summary suitable for injection into agent context."""
    primary_contract: str
    top_writers: List[str]   # qualified function names that write the most state vars
    top_readers: List[str]   # qualified function names that read the most state vars
    critical_vars: List[str] # state vars with the most writers (highest-risk)
    text: str                # formatted string for prompt injection


class ContractDepGraph:
    """
    Build data-flow graph from Slither static analysis.

    Usage:
        graph = ContractDepGraph()
        summary = graph.build_and_summarize(source_path, contract_name)
        if summary:
            context_summary += summary.text
    """

    def __init__(self) -> None:
        self._memgraph_enabled = os.getenv("MEMGRAPH_ENABLED", "false").lower() == "true"
        self._mg_host = os.getenv("MEMGRAPH_HOST", "localhost")
        self._mg_port = int(os.getenv("MEMGRAPH_PORT", "7687"))

    def build_and_summarize(
        self,
        source_path: str,
        contract_name: str,
        top_n: int = 7,
    ) -> Optional[DepGraphSummary]:
        """
        Run Slither on source_path, extract READ/WRITE edges, return DepGraphSummary.
        Returns None if Slither is not installed or compilation fails.

        Args:
            source_path: absolute path to .sol file or contest directory.
                         Slither requires a file path, NOT a source string.
            contract_name: human-readable name for logging / summary header.
            top_n: number of top functions/vars to include in the summary text.
        """
        try:
            from slither import Slither  # type: ignore
        except ImportError:
            logger.warning("slither-analyzer not installed — skipping dep graph (pip install slither-analyzer)")
            return None

        try:
            sl = Slither(source_path)
        except Exception as e:
            logger.warning(f"Slither compile error for {contract_name}: {e}")
            return None

        write_map: Dict[str, List[str]] = {}   # qualified_func → [var_name, ...]
        read_map:  Dict[str, List[str]] = {}
        var_writers: Dict[str, List[str]] = {} # var_name → [qualified_func, ...]

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

        if not write_map and not read_map:
            logger.warning(f"Dep graph: no READ/WRITE edges found for {contract_name}")
            return None

        if self._memgraph_enabled:
            self._persist_to_memgraph(contract_name, write_map, read_map)

        top_writers   = sorted(write_map,   key=lambda f: len(write_map[f]),   reverse=True)[:top_n]
        top_readers   = sorted(read_map,    key=lambda f: len(read_map[f]),    reverse=True)[:top_n]
        critical_vars = sorted(var_writers, key=lambda v: len(var_writers[v]), reverse=True)[:5]

        lines = [f"DATA-FLOW GRAPH — {contract_name} (top {top_n}):"]
        if critical_vars:
            lines.append("  Critical state vars (most writers):")
            for v in critical_vars:
                writers_str = ", ".join(var_writers[v][:3])
                suffix = f" (+{len(var_writers[v])-3} more)" if len(var_writers[v]) > 3 else ""
                lines.append(f"    {v}: written by {writers_str}{suffix}")
        if top_writers:
            lines.append("  Top writer functions:")
            for f in top_writers:
                vars_str = ", ".join(write_map[f][:4])
                lines.append(f"    {f} → [{vars_str}]")

        logger.info(
            f"Dep graph: {len(write_map)} writers, {len(read_map)} readers, "
            f"{len(var_writers)} state vars for {contract_name}"
        )

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
        """MERGE nodes + edges into Memgraph. Falls back silently on error."""
        try:
            import mgclient  # type: ignore
            conn   = mgclient.connect(host=self._mg_host, port=self._mg_port)
            cursor = conn.cursor()

            for func_q, vars_ in write_map.items():
                for var in vars_:
                    cursor.execute(
                        "MERGE (f:Function {name: $func, contract: $c}) "
                        "MERGE (v:StateVar  {name: $var,  contract: $c}) "
                        "MERGE (f)-[:WRITES]->(v)",
                        {"func": func_q, "var": var, "c": contract_name},
                    )
            for func_q, vars_ in read_map.items():
                for var in vars_:
                    cursor.execute(
                        "MERGE (f:Function {name: $func, contract: $c}) "
                        "MERGE (v:StateVar  {name: $var,  contract: $c}) "
                        "MERGE (f)-[:READS]->(v)",
                        {"func": func_q, "var": var, "c": contract_name},
                    )
            conn.commit()
            logger.info(
                f"Memgraph: merged {len(write_map)} writers, "
                f"{len(read_map)} readers for {contract_name}"
            )
        except Exception as e:
            logger.warning(f"Memgraph persist error (non-fatal): {e}")
