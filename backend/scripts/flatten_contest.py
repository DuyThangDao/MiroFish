"""
flatten_contest.py — Flatten a Web3Bugs contest directory into a single .sol string.

Usage (standalone):
    python flatten_contest.py /path/to/web3bugs/contracts/42

Usage (as module):
    from flatten_contest import flatten_contest_dir
    source = flatten_contest_dir("/path/to/web3bugs/contracts/42")

Algorithm:
  1. Collect all .sol files under contest_dir (skip test/ mock/ migration/ scripts/)
  2. Separate: local files vs external npm imports (@openzeppelin, @uniswap, ...)
  3. Build dependency graph from local import statements
  4. Topological sort → include files in correct order (deps before dependents)
  5. Concatenate, stripping:
     - Duplicate pragma solidity (keep first only)
     - SPDX lines (keep one per file as comment, not directive)
     - Local import statements (file already inlined)
     - External import statements → replace with brief comment stub

Result: single self-contained .sol string for LLM audit.
Max size enforced: if total > max_chars, drop interface-only files first.
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# Directories to skip — tests, mocks, deployment scripts
_SKIP_DIRS = {
    "test", "tests", "mock", "mocks", "mocking",
    "migrations", "migration", "scripts", "deploy",
    "node_modules", "__pycache__", ".git",
}

# Known external package prefixes — will be stubbed
_EXTERNAL_PREFIXES = (
    "@openzeppelin/", "@uniswap/", "@chainlink/", "@aave/",
    "@compound/", "@sushiswap/", "@balancer/", "@mochifi/",
    "@yield-protocol/", "@api3/", "hardhat/", "@nomiclabs/",
)

_PRAGMA_RE   = re.compile(r'^\s*pragma\s+solidity[^;]+;', re.MULTILINE)
_SPDX_RE     = re.compile(r'^\s*//\s*SPDX-License-Identifier:.*$', re.MULTILINE)
_IMPORT_RE   = re.compile(r'''^\s*import\s+(?:[^"']*\s)?["']([^"']+)["'][^;]*;''', re.MULTILINE)
_IMPORT_LINE = re.compile(r'''^\s*import\s+[^;]+;''', re.MULTILINE)

# Files that are interface-only (all function bodies are empty / just signatures)
_INTERFACE_RE = re.compile(r'\binterface\s+\w+', re.MULTILINE)
_CONTRACT_RE  = re.compile(r'\b(contract|library|abstract\s+contract)\s+\w+', re.MULTILINE)


def _is_skip_dir(path: Path) -> bool:
    return any(part.lower() in _SKIP_DIRS for part in path.parts)


def _collect_sol_files(contest_dir: str) -> List[Path]:
    """Recursively collect .sol files, skipping test/mock/script dirs."""
    base = Path(contest_dir)
    result = []
    for p in base.rglob("*.sol"):
        if not _is_skip_dir(p.relative_to(base)):
            result.append(p)
    return sorted(result)


def _read_safe(path: Path) -> str:
    for enc in ("utf-8", "latin-1", "utf-8-sig"):
        try:
            return path.read_text(encoding=enc)
        except Exception:
            pass
    return ""


def _resolve_import(import_path: str, current_file: Path, all_files: Dict[str, Path]) -> Optional[Path]:
    """
    Resolve a local import path to an absolute Path.
    Tries relative resolution first, then basename lookup across all collected files.
    """
    if import_path.startswith(_EXTERNAL_PREFIXES):
        return None  # external — skip

    # Relative resolution
    candidate = (current_file.parent / import_path).resolve()
    if candidate in all_files.values():
        return candidate
    # Try by str key
    candidate_str = str(candidate)
    if candidate_str in all_files:
        return all_files[candidate_str]

    # Basename fallback — useful when import "../interfaces/IFoo.sol" but file is at
    # a different relative position in the tree
    basename = Path(import_path).name
    matches = [p for name, p in all_files.items() if Path(name).name == basename]
    if len(matches) == 1:
        return matches[0]

    return None  # unresolvable


def _build_dep_graph(files: List[Path]) -> Tuple[Dict[str, List[str]], Dict[str, Path]]:
    """
    Build adjacency list: file_key → [dep_file_key, ...]
    Returns (graph, key_to_path).
    """
    key_to_path = {str(p): p for p in files}
    all_files = key_to_path

    graph: Dict[str, List[str]] = {k: [] for k in key_to_path}

    for key, path in key_to_path.items():
        src = _read_safe(path)
        for m in _IMPORT_RE.finditer(src):
            imp = m.group(1)
            resolved = _resolve_import(imp, path, all_files)
            if resolved:
                dep_key = str(resolved)
                if dep_key in graph and dep_key not in graph[key]:
                    graph[key].append(dep_key)

    return graph, key_to_path


def _topo_sort(graph: Dict[str, List[str]]) -> List[str]:
    """Kahn's algorithm — returns topological order (deps first)."""
    from collections import deque

    in_degree = {k: 0 for k in graph}
    for node, deps in graph.items():
        for d in deps:
            in_degree[d] = in_degree.get(d, 0)  # ensure present
        # node depends on deps → edges: dep → node (dep must come first)

    # Re-build: edges mean "this node must come before that node"
    # dep → [node that imports dep]
    rev: Dict[str, List[str]] = {k: [] for k in graph}
    for node, deps in graph.items():
        for d in deps:
            if d in rev:
                rev[d].append(node)
            in_degree[node] += 0  # already counted

    # Recount in-degree properly: in_degree[node] = # of deps node has
    in_degree = {k: len(v) for k, v in graph.items()}

    queue = deque(k for k, d in in_degree.items() if d == 0)
    order = []
    while queue:
        node = queue.popleft()
        order.append(node)
        for consumer in rev.get(node, []):
            in_degree[consumer] -= 1
            if in_degree[consumer] == 0:
                queue.append(consumer)

    # Any remaining (cycles) — append in arbitrary order
    remaining = [k for k in graph if k not in order]
    order.extend(remaining)
    return order


def _strip_file(src: str, keep_pragma: bool, seen_externals: Set[str]) -> str:
    """
    Strip pragma (if not keep_pragma), SPDX, import lines from a file's source.
    External imports get a one-line stub comment.
    """
    lines = src.split("\n")
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # SPDX — drop (too noisy when repeated 50x)
        if _SPDX_RE.match(line):
            i += 1
            continue

        # pragma solidity
        if re.match(r'\s*pragma\s+solidity', line):
            if keep_pragma:
                out.append(line)
            i += 1
            continue

        # import statement — check if local or external
        if re.match(r'\s*import\s+', line):
            # Collect multi-line import
            import_block = line
            while not import_block.rstrip().endswith(";") and i + 1 < len(lines):
                i += 1
                import_block += "\n" + lines[i]

            # Extract path
            m = _IMPORT_RE.search(import_block)
            if m:
                imp_path = m.group(1)
                if any(imp_path.startswith(pfx) for pfx in _EXTERNAL_PREFIXES):
                    # Stub external import once per unique package
                    pkg = imp_path.split("/")[0] + "/" + imp_path.split("/")[1] if imp_path.count("/") >= 1 else imp_path
                    if pkg not in seen_externals:
                        seen_externals.add(pkg)
                        pkg_name = imp_path.split("/")[0]
                        out.append(f"// [external: {pkg_name}] — interface definitions omitted in flattened output")
                # Local import — omit (file already inlined)
            i += 1
            continue

        out.append(line)
        i += 1

    return "\n".join(out)


def _is_interface_only(src: str) -> bool:
    """True if file defines only interfaces (no contract/library bodies)."""
    has_interface = bool(_INTERFACE_RE.search(src))
    has_contract  = bool(_CONTRACT_RE.search(src))
    return has_interface and not has_contract


def flatten_contest_dir(
    contest_dir: str,
    max_chars: int = 260_000,
    verbose: bool = False,
) -> str:
    """
    Flatten all .sol files in contest_dir into a single source string.

    Args:
        contest_dir: path to Web3Bugs contracts/<id>/ directory
        max_chars:   soft limit; if exceeded, interface-only files are dropped
        verbose:     print progress info

    Returns:
        Flattened Solidity source as a single string.
    """
    files = _collect_sol_files(contest_dir)
    if not files:
        return ""

    if verbose:
        print(f"  Found {len(files)} .sol files in {contest_dir}")

    graph, key_to_path = _build_dep_graph(files)
    order = _topo_sort(graph)

    # Read all sources
    sources: Dict[str, str] = {k: _read_safe(p) for k, p in key_to_path.items()}

    # If total chars > max_chars, drop interface-only files
    total = sum(len(s) for s in sources.values())
    if total > max_chars:
        interface_keys = [k for k, s in sources.items() if _is_interface_only(s)]
        if verbose:
            print(f"  Total {total//1000}K > {max_chars//1000}K limit — "
                  f"dropping {len(interface_keys)} interface-only files")
        for k in interface_keys:
            sources.pop(k, None)
            order = [x for x in order if x != k]

    # Second pass: still too large → trim largest files from back
    total = sum(len(sources.get(k, "")) for k in order)
    if total > max_chars:
        trimmed_order = []
        running = 0
        for k in order:
            s = sources.get(k, "")
            if running + len(s) <= max_chars:
                trimmed_order.append(k)
                running += len(s)
        if verbose:
            dropped = len(order) - len(trimmed_order)
            print(f"  Still too large — dropping {dropped} more files to fit {max_chars//1000}K limit")
        order = trimmed_order

    # Build output
    pragma_emitted = False
    seen_externals: Set[str] = set()
    contest_name = Path(contest_dir).name
    parts = [f"// ═══ Web3Bugs Contest {contest_name} — Flattened Source ═══\n"]

    for key in order:
        if key not in sources:
            continue
        src = sources[key]
        if not src.strip():
            continue

        rel = str(Path(key).relative_to(Path(contest_dir)))
        parts.append(f"\n// ─── {rel} ───\n")

        keep_pragma = not pragma_emitted
        if keep_pragma and _PRAGMA_RE.search(src):
            pragma_emitted = True

        stripped = _strip_file(src, keep_pragma=keep_pragma, seen_externals=seen_externals)
        parts.append(stripped)

    result = "\n".join(parts)

    if verbose:
        print(f"  Flattened: {len(result):,} chars ({len(result)//1000}K) from {len(order)} files")

    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Flatten Web3Bugs contest directory")
    parser.add_argument("contest_dir", help="Path to contracts/<id>/ directory")
    parser.add_argument("--output", "-o", default=None,
                        help="Write output to file (default: print to stdout)")
    parser.add_argument("--max-chars", type=int, default=260_000,
                        help="Max chars in output (default: 260000)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    result = flatten_contest_dir(args.contest_dir, max_chars=args.max_chars, verbose=True)

    if args.output:
        Path(args.output).write_text(result, encoding="utf-8")
        print(f"Written to {args.output} ({len(result):,} chars)")
    else:
        print(result[:3000])
        print(f"\n... [{len(result):,} total chars, showing first 3000]")
