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
  5. Classify files as in-scope / out-of-scope via 3-tier strategy:
     Tier 1 — Import graph: files transitively imported by primary contract
     Tier 2 — README hints: parse "scope" / "focused on" patterns
     Tier 3 — Conservative: all files in-scope (no filtering)
  6. Concatenate:
     - In-scope files: full content (deduped pragma/SPDX/imports)
     - Out-of-scope files: function-signature stubs only (bodies replaced with {...})
     - Scope header injected at top for agent context

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

# Manifest: class name patterns for primary/secondary classification.
# No \b boundaries — match CamelCase suffixes (e.g. "Pool" in "ConcentratedLiquidityPool").
_CORE_NAME_RE = re.compile(
    r'Pool|Vault|Core|Engine|Logic|Manager|Strategy|Market|Exchange|Pair|AMM|Farm',
    re.IGNORECASE,
)
_INFRA_NAME_RE = re.compile(
    r'Router|Helper|Deployer|Factory|Registry|Proxy|Base|Abstract|Interface|Mock'
    r'|Math|Library|ERC20|ERC721|ERC1155',
    re.IGNORECASE,
)


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


_SOL_BLOCK_COMMENT_RE  = re.compile(r'/\*.*?\*/', re.DOTALL)
_SOL_LINE_COMMENT_RE   = re.compile(r'//[^\n]*')


def _strip_sol_comments(src: str) -> str:
    """Strip // line comments and /* */ block comments from Solidity source."""
    src = _SOL_BLOCK_COMMENT_RE.sub('', src)
    src = _SOL_LINE_COMMENT_RE.sub('', src)
    return src


def _get_reachable_set(start_key: str, graph: Dict[str, List[str]]) -> Set[str]:
    """BFS: return all file keys transitively imported by start_key (inclusive)."""
    visited: Set[str] = {start_key}
    queue = [start_key]
    while queue:
        node = queue.pop(0)
        for dep in graph.get(node, []):
            if dep not in visited:
                visited.add(dep)
                queue.append(dep)
    return visited


def _extract_scope_from_readme(contest_dir: str) -> List[str]:
    """
    Parse README.md for explicit scope hints.
    Returns list of path fragments (e.g. ["concentrated", "concentratedPool"]).
    """
    readme = Path(contest_dir) / "README.md"
    if not readme.exists():
        return []
    text = _read_safe(readme)
    hints: List[str] = []
    # "focused on X" → extract X
    m = re.search(r'focused\s+on\s+([A-Za-z0-9 /,_-]+)', text, re.IGNORECASE)
    if m:
        hints.append(m.group(1).strip().split()[0])  # first word of match
    # "contracts/X" path fragments in scope sections
    for m in re.finditer(r'contracts/([A-Za-z0-9_-]+)', text):
        frag = m.group(1)
        if frag not in hints:
            hints.append(frag)
    return hints


def _compress_to_stub(src: str) -> str:
    """
    Replace function/modifier/constructor bodies with { ... }, keeping all signatures.
    Preserves: pragma, contract/library/interface headers, state variables,
               function signatures, events, errors, structs, enums.

    Uses brace-depth tracking (depth 0 = top-level, 1 = inside contract,
    >=2 = inside a function body). Lines at depth >=2 are skipped.
    """
    lines = src.split('\n')
    result: List[str] = []
    depth = 0

    for line in lines:
        # Skip single-line // comments (keep NatSpec /// for signatures)
        stripped = line.strip()
        if stripped.startswith('//') and not stripped.startswith('///'):
            depth += line.count('{') - line.count('}')
            continue

        opens = line.count('{')
        closes = line.count('}')
        new_depth = depth + opens - closes

        if depth >= 2:
            # Inside a function body — skip entirely
            depth = new_depth
            continue

        if depth == 1 and opens > closes:
            # Line opens a function/modifier body (net +1 brace at contract level)
            # Truncate at last `{` and add stub marker
            sig = line[:line.rfind('{')].rstrip()
            if sig.strip():
                result.append(sig + ' { ... }')
            depth = new_depth
            continue

        result.append(line)
        depth = new_depth

    return '\n'.join(result)


def _classify_files(
    order: List[str],
    graph: Dict[str, List[str]],
    manifest: dict,
    contest_dir: str,
) -> Dict[str, object]:
    """
    Classify files as in-scope or out-of-scope using 3-tier fallback:
      Tier 1 — Import graph reachability from manifest.primary_key
      Tier 2 — README scope hints (folder/keyword matching)
      Tier 3 — Conservative: all files in-scope

    Returns dict with keys:
      in_scope:  List[str]  — file keys to include in full
      out_scope: List[str]  — file keys to compress to stubs
      method:    str        — which tier was used
    """
    base = Path(contest_dir)

    # Tier 1: import graph from primary
    primary_key = manifest.get("primary_key")
    if primary_key and primary_key in graph:
        reachable = _get_reachable_set(primary_key, graph)
        out_scope = [k for k in order if k not in reachable]
        if out_scope:
            return {
                "in_scope":  [k for k in order if k in reachable],
                "out_scope": out_scope,
                "method":    "import_graph",
            }

    # Tier 2: README scope hints
    hints = _extract_scope_from_readme(contest_dir)
    if hints:
        in_s, out_s = [], []
        for k in order:
            rel = str(Path(k).relative_to(base)).lower()
            if any(h.lower() in rel for h in hints):
                in_s.append(k)
            else:
                out_s.append(k)
        if out_s:
            return {"in_scope": in_s, "out_scope": out_s, "method": "readme"}

    # Tier 3: conservative — no filtering
    return {"in_scope": order, "out_scope": [], "method": "conservative"}


def _is_interface_only(src: str) -> bool:
    """True if file defines only interfaces (no contract/library bodies)."""
    stripped = _strip_sol_comments(src)
    has_interface = bool(_INTERFACE_RE.search(stripped))
    has_contract  = bool(_CONTRACT_RE.search(stripped))
    return has_interface and not has_contract


def _compute_manifest(
    order: List[str],
    sources: Dict[str, str],
    graph: Dict[str, List[str]],
    contest_dir: str,
) -> dict:
    """
    Compute ContractManifest from LOC, class name patterns, and import in-degree.
    Returns dict with primary (str), secondary (list[str]), and metadata.
    primary/secondary hold contract names (not file paths) for use in prompts.
    """
    base = Path(contest_dir)

    # in-degree: number of other files that import this file
    in_degree: Dict[str, int] = {k: 0 for k in order}
    for node, deps in graph.items():
        for d in deps:
            if d in in_degree:
                in_degree[d] += 1

    scores: Dict[str, float] = {}
    contract_names: Dict[str, str] = {}

    for key in order:
        src = sources.get(key, "")
        if not src.strip():
            continue

        stripped = _strip_sol_comments(src)
        loc = src.count('\n') + 1
        is_iface = _is_interface_only(src)

        # Extract contract name from comment-stripped source only
        m = _CONTRACT_RE.search(stripped)
        cname = m.group(0).split()[-1] if m else Path(key).stem
        contract_names[key] = cname

        score = float(loc)
        if _CORE_NAME_RE.search(cname):
            score *= 1.5
        if _INFRA_NAME_RE.search(cname):
            score *= 0.6
        # In-degree bonus only for real contracts — interfaces are imported widely
        # but that reflects dependency breadth, not implementation importance.
        # Weight 200 (not 500) so LOC+name pattern dominates over pure import count.
        if not is_iface:
            score += in_degree.get(key, 0) * 200
        if is_iface:
            score *= 0.1

        scores[key] = score

    if not scores:
        return {"primary": None, "secondary": [], "total_contracts": 0, "total_chars": 0}

    sorted_keys = sorted(scores, key=lambda k: scores[k], reverse=True)
    primary_key = sorted_keys[0]
    secondary_keys = sorted_keys[1:4]

    return {
        "primary":         contract_names.get(primary_key),
        "primary_file":    str(Path(primary_key).relative_to(base)),
        "primary_key":     primary_key,           # absolute path — used by _classify_files
        "secondary":       [contract_names.get(k) for k in secondary_keys],
        "secondary_keys":  secondary_keys,
        "total_contracts": len(scores),
        "total_chars":     sum(len(sources.get(k, "")) for k in order),
    }


def flatten_contest_dir(
    contest_dir: str,
    max_chars: int = 260_000,
    verbose: bool = False,
    emit_manifest: bool = False,
) -> "str | tuple[str, dict]":
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

    # Always compute manifest (needed for scope classification)
    manifest = _compute_manifest(order, sources, graph, contest_dir)

    # Classify files: in-scope (full) vs out-of-scope (stubs)
    classification = _classify_files(order, graph, manifest, contest_dir)
    in_scope_set  = set(classification["in_scope"])
    out_scope_set = set(classification["out_scope"])
    cls_method    = classification["method"]

    # Collect out-of-scope contract names for manifest + prompt
    base = Path(contest_dir)
    out_scope_names: List[str] = []
    for k in classification["out_scope"]:
        src = sources.get(k, "")
        stripped_src = _strip_sol_comments(src)
        m = _CONTRACT_RE.search(stripped_src)
        if m:
            out_scope_names.append(m.group(0).split()[-1])
    manifest["out_scope_contracts"] = out_scope_names
    manifest["scope_method"]        = cls_method

    if verbose and out_scope_set:
        print(f"  Scope ({cls_method}): {len(in_scope_set)} in-scope, "
              f"{len(out_scope_set)} out-of-scope → stubs")

    # Build scope header injected at top (agents see this first)
    primary   = manifest.get("primary", "unknown")
    secondary = [s for s in manifest.get("secondary", []) if s]
    scope_header_lines = [
        f"// ═══ Web3Bugs Contest {Path(contest_dir).name} — Flattened Source ═══",
        f"// AUDIT SCOPE: {primary}" + (f", {', '.join(secondary)}" if secondary else ""),
    ]
    if out_scope_names:
        scope_header_lines.append(
            f"// OUT-OF-SCOPE (stubs only — function bodies omitted): "
            f"{', '.join(out_scope_names[:8])}"
            + (" ..." if len(out_scope_names) > 8 else "")
        )
    scope_header_lines.append("")
    parts = ["\n".join(scope_header_lines)]

    # In-scope files: full content
    pragma_emitted = False
    seen_externals: Set[str] = set()
    inscope_parts = list(parts)  # copy scope header

    for key in order:
        if key not in sources or key not in in_scope_set:
            continue
        src = sources[key]
        if not src.strip():
            continue

        rel = str(Path(key).relative_to(base))
        file_header = f"\n// ─── {rel} ───\n"
        parts.append(file_header)
        inscope_parts.append(file_header)

        keep_pragma = not pragma_emitted
        if keep_pragma and _PRAGMA_RE.search(src):
            pragma_emitted = True

        stripped = _strip_file(src, keep_pragma=keep_pragma, seen_externals=seen_externals)
        parts.append(stripped)
        inscope_parts.append(stripped)

    # Out-of-scope files: compressed stubs (agents only — NOT in KG source)
    seen_externals_stubs: Set[str] = set(seen_externals)
    for key in order:
        if key not in sources or key not in out_scope_set:
            continue
        src = sources[key]
        if not src.strip():
            continue

        rel = str(Path(key).relative_to(base))
        parts.append(f"\n// ─── {rel} [OUT-OF-SCOPE — signatures only] ───\n")
        stub = _compress_to_stub(src)
        parts.append(_strip_file(stub, keep_pragma=False, seen_externals=seen_externals_stubs))

    result = "\n".join(parts)
    # Store in_scope_source in manifest so callers can pass only in-scope code to KG builder
    manifest["in_scope_source"] = "\n".join(inscope_parts)

    if verbose:
        print(f"  Flattened: {len(result):,} chars ({len(result)//1000}K) from {len(order)} files")

    if emit_manifest:
        if verbose:
            print(f"  Manifest: primary={manifest['primary']}, secondary={manifest['secondary']}")
        return result, manifest
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
