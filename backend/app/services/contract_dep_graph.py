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
from typing import Dict, List, Optional, Set, Tuple

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
    def _setup_slither_env() -> None:
        """
        Ensure the current process's PATH includes:
          - the venv bin dir (so slither/solc-select are found)
          - the active nvm node bin dir (so npx/hardhat are found when Slither
            spawns subprocesses for compilation)

        Mutates os.environ in-place; safe to call multiple times.
        """
        import os as _os, sys as _sys
        _venv_bin = _os.path.dirname(_sys.executable)
        _venv     = _os.path.dirname(_venv_bin)

        if not _os.environ.get("VIRTUAL_ENV", "").startswith(_venv):
            _os.environ["VIRTUAL_ENV"] = _venv

        additions = [_venv_bin]

        # nvm node bin: check NVM_BIN env first, then scan ~/.nvm/versions/node/
        _nvm_bin = _os.environ.get("NVM_BIN", "")
        if _nvm_bin and Path(_nvm_bin).is_dir():
            additions.append(_nvm_bin)
        else:
            _nvm_base = Path.home() / ".nvm" / "versions" / "node"
            if _nvm_base.is_dir():
                # Pick the newest installed version that has npx
                for _ver_dir in sorted(_nvm_base.iterdir(), reverse=True):
                    _npx = _ver_dir / "bin" / "npx"
                    if _npx.exists():
                        additions.append(str(_ver_dir / "bin"))
                        break

        current_path = _os.environ.get("PATH", "")
        for entry in additions:
            if entry and entry not in current_path:
                _os.environ["PATH"] = entry + _os.pathsep + current_path
                current_path = _os.environ["PATH"]

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

        # Directory: check if it has a compilation framework config.
        # Use the ACTUAL project directory (where config lives), not just the root —
        # contests often nest the project in a subdirectory (e.g. root/trident/).
        _foundry_cfg = next(path.rglob("foundry.toml"), None)
        _hardhat_cfg = next(path.rglob("hardhat.config.*"), None)
        _project_dir = (_foundry_cfg or _hardhat_cfg)
        _project_dir = _project_dir.parent if _project_dir else path

        if _foundry_cfg:
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
                return str(_project_dir), None  # Slither will use forge
            logger.debug("foundry.toml found but forge unavailable — trying flat file fallback")

        if _hardhat_cfg:
            _npx_cmd = None
            for _nc in ["npx"]:
                try:
                    if subprocess.run([_nc, "--version"], capture_output=True, timeout=5).returncode == 0:
                        _npx_cmd = _nc
                        logger.debug(f"Dep graph: npx found at {_nc}")
                        break
                except Exception:
                    continue
            if _npx_cmd:
                return str(_project_dir), None  # Slither will use hardhat
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
            self._setup_slither_env()
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

    def get_callers_of_primary(
        self,
        source_path: str,
        contract_name: str,
    ) -> Optional[Set[str]]:
        """
        Find all contracts whose functions make high-level (external) calls into
        contract_name. Used by flatten_contest to identify consumer contracts
        (e.g. Manager, Position) that are not reachable via forward import BFS.

        Returns set of contract names, or None if Slither fails.
        None means "unknown" — caller should fall back to forward BFS only.
        """
        try:
            self._setup_slither_env()
            from slither import Slither  # type: ignore
        except Exception:
            logger.warning("slither-analyzer not available — skipping caller analysis")
            return None

        target, pragma_ver = self._resolve_slither_target(source_path, contract_name)
        if not target:
            return None

        if pragma_ver:
            self._set_solc_version(pragma_ver)

        try:
            sl = Slither(target)
        except Exception as e:
            short = str(e).split("\n")[0][:120]
            logger.warning(f"Slither compile error (caller analysis) for {contract_name}: {short}")
            return None

        primary_matches = sl.get_contract_from_name(contract_name)
        if not primary_matches:
            logger.warning(f"Slither: contract '{contract_name}' not found in compiled output")
            return None
        primary = primary_matches[0]

        # Build the set of types that represent "calling primary":
        #   1. The concrete contract itself
        #   2. Base classes / interfaces it explicitly inherits (via primary.inheritance)
        #   3. The companion interface following the Solidity IFoo convention (e.g.
        #      IConcentratedLiquidityPool for ConcentratedLiquidityPool) — Solidity
        #      allows contracts to satisfy an interface without explicit `is IFoo`
        #      declaration, so the interface won't appear in primary.inheritance.
        primary_and_bases: Set[object] = {primary} | set(getattr(primary, "inheritance", []))
        _companion_iface_name = "I" + primary.name
        for _c in sl.contracts:
            if _c.name == _companion_iface_name:
                primary_and_bases.add(_c)
                break

        callers: Set[str] = set()
        for contract in sl.contracts:
            if contract == primary:
                continue
            for func in contract.functions_and_modifiers:
                for target_c, _ in func.high_level_calls:
                    if target_c in primary_and_bases:
                        callers.add(contract.name)
                        break

        logger.info(
            f"Slither caller analysis: {len(callers)} contracts call {contract_name}"
            + (f": {', '.join(sorted(callers))}" if callers else "")
        )
        return callers

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


def extract_function_bodies(source: str, function_names: List[str], max_chars: int = 20000) -> str:
    """
    Extract full Solidity function bodies for the given function names.

    Names may be qualified ("Contract::swap") or plain ("swap").
    Only the simple name after "::" is used for matching in source.
    Skips Slither-internal names (slitherConstructorConstantVariables etc.).

    Returns a formatted block ready to append to contract_summary.
    Caps total output at max_chars to stay within context budget.
    """
    seen: set = set()
    simple_names: List[str] = []
    for qn in function_names:
        sn = qn.split("::")[-1].strip()
        if sn and sn not in seen and not sn.startswith("slither") and not sn.startswith("constructor"):
            seen.add(sn)
            simple_names.append(sn)

    if not simple_names:
        return ""

    blocks: List[str] = []
    total = 0

    for name in simple_names:
        pattern = re.compile(r'\bfunction\s+' + re.escape(name) + r'\s*\(', re.MULTILINE)
        match = pattern.search(source)
        if not match:
            continue

        brace_pos = source.find('{', match.start())
        if brace_pos == -1:
            continue

        depth = 0
        end_pos = brace_pos
        for i in range(brace_pos, len(source)):
            ch = source[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end_pos = i
                    break

        body = source[match.start(): end_pos + 1].strip()
        if not body:
            continue

        block = f"// --- function {name} ---\n{body}"
        if total + len(block) > max_chars:
            break
        blocks.append(block)
        total += len(block)

    if not blocks:
        return ""

    return (
        "=== CRITICAL FUNCTIONS — full source (most complex / most callers) ===\n"
        + "\n\n".join(blocks)
    )


def pick_critical_functions_from_summary(contract_summary: str, top_n: int = 6) -> List[str]:
    """
    Parse the CALL GRAPH section already present in contract_summary to find the
    top-N functions by number of callees. These are the most complex / risky functions
    in the primary contract, without needing to re-run Slither.

    Falls back to empty list if CALL GRAPH section is absent.
    """
    # Find CALL GRAPH block
    cg_match = re.search(r'CALL GRAPH:\s*\n(.*?)(?:\n\n|\Z)', contract_summary, re.DOTALL)
    if not cg_match:
        return []

    # Parse lines like: "  swap() → calls: _transfer, _updateFees, ..."
    callee_count: Dict[str, int] = {}
    leaf_pattern = re.compile(r'^\s+(\w+)\(\)\s*→\s*calls:\s*(.+)$')
    for line in cg_match.group(1).splitlines():
        m = leaf_pattern.match(line)
        if m:
            fn_name = m.group(1)
            callees = [c.strip() for c in m.group(2).split(',') if c.strip()]
            callee_count[fn_name] = len(callees)

    # Also include functions with external calls (→ [EXTERNAL: ...])
    ext_pattern = re.compile(r'^\s+(\w+)\(\)\s*→\s*\[EXTERNAL', re.MULTILINE)
    for m in ext_pattern.finditer(cg_match.group(1)):
        fn = m.group(1)
        callee_count[fn] = callee_count.get(fn, 0) + 10  # boost external-call functions

    # Sort by callee count descending, take top_n
    ranked = sorted(callee_count, key=lambda f: callee_count[f], reverse=True)
    return ranked[:top_n]
