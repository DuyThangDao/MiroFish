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

Directory resolution strategy (when source_path is a directory):
  1. Look for pre-flattened .sol files in flat/ subdirectories whose name
     contains the contract_name (case-insensitive).
  2. Fall back to any .sol file in flat/ (largest file wins).
  3. Detect pragma solidity version from the chosen file and switch solc
     automatically via solc-select.
  4. If no compilable target found, skip gracefully.

Compilation framework projects (Hardhat/Foundry) require `npx` or `forge`
respectively. If neither is available the directory fallback is used instead.
"""

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..utils.logger import get_logger

logger = get_logger("mirofish.dep_graph")

_PRAGMA_VERSION_RE = re.compile(
    r'pragma\s+solidity\s+(?:[>=^~<]+\s*)?([\d]+\.[\d]+(?:\.[\d]+)?)'
)


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

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _detect_pragma(sol_path: str) -> Optional[str]:
        """Extract the first pragma solidity version string from a file."""
        try:
            text = Path(sol_path).read_text(encoding="utf-8", errors="ignore")
            m = _PRAGMA_VERSION_RE.search(text)
            return m.group(1) if m else None
        except Exception:
            return None

    @staticmethod
    def _set_solc_version(version: str) -> bool:
        """Switch solc via solc-select. Returns True on success."""
        try:
            # Install if missing, then use
            subprocess.run(
                ["solc-select", "install", version],
                capture_output=True, timeout=60,
            )
            result = subprocess.run(
                ["solc-select", "use", version],
                capture_output=True, timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _find_flat_sol(source_dir: str, contract_name: str) -> Optional[str]:
        """
        Search source_dir recursively for pre-flattened .sol files.
        Prefer files whose name contains contract_name; fall back to largest file.
        Returns None if no flat/ directories found.
        """
        base = Path(source_dir)
        candidates: List[Path] = []

        for flat_dir in base.rglob("flat"):
            if flat_dir.is_dir():
                candidates.extend(flat_dir.glob("*.sol"))

        if not candidates:
            return None

        # Prefer match on contract name
        name_lower = contract_name.lower()
        named = [p for p in candidates if name_lower in p.stem.lower()]
        if named:
            return str(max(named, key=lambda p: p.stat().st_size))

        # Fall back: largest file
        return str(max(candidates, key=lambda p: p.stat().st_size))

    def _resolve_slither_target(
        self, source_path: str, contract_name: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Returns (slither_target, pragma_version) to pass to Slither.
        source_path may be a file or directory.
        """
        path = Path(source_path)

        if path.is_file():
            return str(path), self._detect_pragma(str(path))

        if not path.is_dir():
            return None, None

        # Directory: check if it has a compilation framework config
        has_foundry  = (path / "foundry.toml").exists() or any(path.rglob("foundry.toml"))
        has_hardhat  = any(path.rglob("hardhat.config.*"))

        if has_foundry:
            # Check forge in PATH and common install locations
            _forge_candidates = [
                "forge",
                str(Path.home() / ".foundry" / "bin" / "forge"),
                "/usr/local/bin/forge",
            ]
            forge_ok = False
            for _fc in _forge_candidates:
                try:
                    if subprocess.run([_fc, "--version"], capture_output=True, timeout=5).returncode == 0:
                        forge_ok = True
                        logger.debug(f"Dep graph: forge found at {_fc}")
                        break
                except Exception:
                    continue
            if forge_ok:
                return str(path), None  # Slither will use forge
            logger.debug("foundry.toml found but forge unavailable — trying flat file fallback")

        if has_hardhat:
            try:
                npx_ok = subprocess.run(
                    ["npx", "--version"], capture_output=True, timeout=5
                ).returncode == 0
            except Exception:
                npx_ok = False
            if npx_ok:
                return str(path), None  # Slither will use hardhat
            logger.debug("hardhat config found but npx unavailable — trying flat file fallback")

        # Fallback: pre-flattened .sol file
        flat_file = self._find_flat_sol(str(path), contract_name)
        if flat_file:
            pragma = self._detect_pragma(flat_file)
            logger.info(f"Dep graph: using pre-flattened file {Path(flat_file).name} "
                        f"(pragma {pragma}) for {contract_name}")
            return flat_file, pragma

        logger.warning(
            f"Dep graph: {source_path} is a directory with no compilable target "
            f"(no forge/npx available and no flat/ files found) — skipping"
        )
        return None, None

    # ── main entry point ──────────────────────────────────────────────────────

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
            contract_name: human-readable name for logging / summary header.
            top_n: number of top functions/vars to include in the summary text.
        """
        try:
            import os as _os, sys as _sys
            _venv_bin = _os.path.dirname(_sys.executable)
            _venv = _os.path.dirname(_venv_bin)
            # Fix 1: solc_select uses VIRTUAL_ENV to locate its artifacts dir;
            # a stale/system VIRTUAL_ENV causes PermissionError on module import.
            if not _os.environ.get("VIRTUAL_ENV", "").startswith(_venv):
                _os.environ["VIRTUAL_ENV"] = _venv
            # Fix 2: Slither spawns `solc` as a subprocess; if the venv bin dir
            # is not in PATH the binary is invisible even though it's installed.
            _path = _os.environ.get("PATH", "")
            if _venv_bin not in _path:
                _os.environ["PATH"] = _venv_bin + _os.pathsep + _path
            from slither import Slither  # type: ignore
        except Exception:
            logger.warning("slither-analyzer not available — skipping dep graph")
            return None

        target, pragma_ver = self._resolve_slither_target(source_path, contract_name)
        if not target:
            return None

        # Switch solc version if detected
        if pragma_ver:
            self._set_solc_version(pragma_ver)

        try:
            sl = Slither(target)
        except Exception as e:
            short = str(e).split("\n")[0][:120]
            logger.warning(f"Slither compile error for {contract_name}: {short}")
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
