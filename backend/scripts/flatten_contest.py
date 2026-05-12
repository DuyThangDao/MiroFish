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
    "migrations", "migration", "scripts", "deploy", "deployer",
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
    r'Pool|Vault|Core|Engine|Logic|Manager|Strategy|Market|Exchange|Pair|AMM|Farm'
    r'|Reward|Treasury|Staking|Lending|Borrow',
    re.IGNORECASE,
)
# Soft infra penalty ×0.8 — utility/wiring, rarely contain core business logic,
# but NOT blacklisted outright since some (e.g. Oracle with price manipulation) can be primary.
_INFRA_NAME_RE = re.compile(
    r'Router|Helper|Deployer|Factory|Registry|Proxy|Base|Abstract|Interface|Mock'
    r'|Math|Library|ERC20|ERC721|ERC1155',
    re.IGNORECASE,
)
# Removed from _INFRA_NAME_RE: Adapter|Oracle|CSSR|Snapshot|PriceFeed|Aggregator|Verifier
# These can be primary audit targets (e.g. price manipulation in OracleAdapter).
# Demoted naturally by in_degree=0 — no regex penalty needed.

_VALUE_BEARING_RE = re.compile(
    r'\b(transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\('
    r'|IERC20\s*[(\(]'
    r'|msg\.value\b'
    r'|address\(this\)\.balance'
    r'|\.call\s*\{'
    r'|\bdelegatecall\b',
)

_PROXY_NAME_RE = re.compile(
    r'\b(Transparent|Beacon|UUPS|ERC1967|Minimal|Clones).*Proxy\b'
    r'|\bProxy\b'
    r'|\bUpgradeableProxy\b'
    r'|\bProxyAdmin\b',
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


_MODIFIER_BODY_RE = re.compile(r'\bmodifier\b')
_STRUCT_ENUM_BODY_RE = re.compile(r'\b(struct|enum)\b')


def _compress_to_stub(src: str) -> str:
    """
    Replace function/constructor bodies with { ... }, keeping all signatures.
    Preserves FULL BODY of: modifiers, structs, enums (critical for agent reasoning).
    Preserves at any depth: state variables, events, custom errors, NatSpec.

    Uses brace-depth tracking (depth 0 = top-level, 1 = inside contract,
    >=2 = inside a function/modifier/struct body).
    in_keepbody: True when inside a modifier/struct/enum whose body we want to keep.
    """
    lines = src.split('\n')
    result: List[str] = []
    depth = 0
    in_keepbody = False  # True inside modifier/struct/enum bodies

    for line in lines:
        stripped = line.strip()
        if stripped.startswith('//') and not stripped.startswith('///'):
            depth += line.count('{') - line.count('}')
            continue

        opens = line.count('{')
        closes = line.count('}')
        new_depth = depth + opens - closes

        if depth >= 2:
            if in_keepbody:
                result.append(line)
            if new_depth < 2:
                in_keepbody = False
            depth = new_depth
            continue

        if depth == 1 and opens > closes:
            # Opening a body at contract level — keep modifier/struct/enum, stub functions
            if _MODIFIER_BODY_RE.search(stripped) or _STRUCT_ENUM_BODY_RE.search(stripped):
                result.append(line)
                in_keepbody = True
            else:
                sig = line[:line.rfind('{')].rstrip()
                if sig.strip():
                    result.append(sig + ' { ... }')
                in_keepbody = False
            depth = new_depth
            continue

        result.append(line)
        depth = new_depth

    return '\n'.join(result)


def _build_reverse_graph(graph: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Build reverse import graph: for each file, list files that import it."""
    reverse: Dict[str, List[str]] = {k: [] for k in graph}
    for node, deps in graph.items():
        for dep in deps:
            if dep in reverse:
                reverse[dep].append(node)
    return reverse


def _is_infra_file(key: str) -> bool:
    """
    True if a file is likely infrastructure/boilerplate rather than auditable business logic.
    Only uses directory-level and well-established suffix patterns — no contest-specific keywords.
    """
    infra_dirs = {"test", "tests", "mock", "mocks", "deploy", "migration",
                  "migrations", "scripts", "examples", "flat", "deployer"}
    for part in Path(key).parts:
        if part.lower() in infra_dirs:
            return True
    stem = Path(key).stem.lower()
    infra_suffixes = ("mock", "test", "helper", "flat", "factory", "router",
                      "proxy", "base", "abstract", "deployer")
    return any(stem.endswith(s) for s in infra_suffixes)


def _is_mock_or_test(key: str) -> bool:
    """True if file is a mock, test, fixture, or deploy script — not auditable logic."""
    skip_dirs = {"test", "tests", "mock", "mocks", "scripts", "deploy",
                 "deployment", "deployments", "fixture", "fixtures"}
    for part in Path(key).parts:
        if part.lower() in skip_dirs:
            return True
    stem = Path(key).stem.lower()
    return stem.startswith(("mock", "test", "fixture", "deploy"))


def _classify_files(
    order: List[str],
    graph: Dict[str, List[str]],
    sources: Dict[str, str],
    manifest: dict,
    contest_dir: str,
    extra_scope_contracts: Optional[Set[str]] = None,
) -> Dict[str, object]:
    """
    Classify files as in-scope or out-of-scope using 3-tier fallback:
      Tier 1 — Forward import graph (BFS from primary) + optional Slither callers
               extra_scope_contracts: contract names identified by Slither as
               callers of primary (e.g. Manager, Position). These are added to
               the reachable set even if not reachable via forward BFS.
      Tier 2 — README scope hints (folder/keyword matching)
      Tier 3 — Conservative: all files in-scope

    Returns dict with keys:
      in_scope:  List[str]  — file keys to include in full
      out_scope: List[str]  — file keys to compress to stubs
      method:    str        — which tier was used
    """
    base = Path(contest_dir)

    # Identify all implementation contracts (non-mock, non-interface)
    all_impl_keys = [
        k for k in order
        if not _is_interface_only(sources.get(k, ""))
        and not _is_mock_or_test(k)
    ]
    if all_impl_keys:
        if extra_scope_contracts:
            # --- Skeletonization mode (Slither available) ---
            # Tier 1 (full): primary + Slither caller keys
            # Tier 2 (skeleton stubs): BFS deps of Tier 1 that are NOT in Tier 1
            # Tier 3 (dropped): mocks, interfaces, unreachable
            core_set: Set[str] = set()
            for pk in (manifest.get("primary_keys") or [manifest.get("primary_key")]):
                if pk:
                    core_set.add(pk)
            cnames: Dict[str, str] = manifest.get("contract_names_map", {})
            for key in order:
                cname = cnames.get(key, Path(key).stem)
                if cname in extra_scope_contracts:
                    core_set.add(key)

            full_reachable: Set[str] = set()
            for root_key in core_set:
                if root_key in graph:
                    full_reachable |= _get_reachable_set(root_key, graph)

            skeleton_set: Set[str] = {
                k for k in full_reachable - core_set
                if not _is_mock_or_test(k)
                and not _is_interface_only(sources.get(k, ""))
            }
            tier3_set = set(order) - core_set - skeleton_set

            return {
                "in_scope":  [k for k in order if k in core_set],
                "skeleton":  [k for k in order if k in skeleton_set],
                "out_scope": [k for k in order if k in tier3_set],
                "method":    "skeletonized_slither",
            }

        else:
            # --- Legacy multi-root BFS (no Slither) — unchanged from original ---
            reachable: Set[str] = set()
            for root_key in all_impl_keys:
                if root_key in graph:
                    reachable |= _get_reachable_set(root_key, graph)

            # Size cap: if full union > 300KB, use selective secondary roots
            total_chars = sum(len(sources.get(k, "")) for k in reachable)
            if total_chars > 300_000:
                primary_key = manifest.get("primary_key")
                if primary_key and primary_key in graph:
                    primary_reachable = _get_reachable_set(primary_key, graph)
                    unreached_impls = [k for k in all_impl_keys if k not in primary_reachable]
                    selective = set(primary_reachable)
                    running_chars = sum(len(sources.get(k, "")) for k in selective)
                    for root_key in unreached_impls:
                        new_contracts = (
                            (_get_reachable_set(root_key, graph) if root_key in graph else {root_key})
                            - primary_reachable
                        )
                        new_contracts.add(root_key)
                        added_chars = sum(len(sources.get(k, "")) for k in new_contracts - selective)
                        if running_chars + added_chars <= 300_000:
                            selective |= new_contracts
                            running_chars += added_chars
                    reachable = selective
                    method = "multi_root_bfs_selective"
                else:
                    method = "multi_root_bfs_capped"
            else:
                method = "multi_root_bfs"

            out_scope = [k for k in order if k not in reachable]
            if out_scope:
                return {
                    "in_scope":  [k for k in order if k in reachable],
                    "skeleton":  [],
                    "out_scope": out_scope,
                    "method":    method,
                }

    # Fallback: README scope hints
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
            return {"in_scope": in_s, "skeleton": [], "out_scope": out_s, "method": "readme"}

    # Conservative fallback — no filtering
    return {"in_scope": order, "skeleton": [], "out_scope": [], "method": "conservative"}


def _is_interface_only(src: str) -> bool:
    """True if file defines only interfaces (no contract/library bodies)."""
    stripped = _strip_sol_comments(src)
    has_interface = bool(_INTERFACE_RE.search(stripped))
    has_contract  = bool(_CONTRACT_RE.search(stripped))
    return has_interface and not has_contract


def _find_clusters(impl_keys: List[str], graph: Dict[str, List[str]]) -> List[List[str]]:
    """BFS connected components on undirected import graph, restricted to impl_keys only."""
    from collections import deque
    impl_set = set(impl_keys)
    undirected: Dict[str, Set[str]] = {k: set() for k in impl_keys}
    for node in impl_keys:
        for dep in graph.get(node, []):
            if dep in impl_set:
                undirected[node].add(dep)
                undirected[dep].add(node)
    visited: Set[str] = set()
    clusters: List[List[str]] = []
    for start in impl_keys:
        if start in visited:
            continue
        cluster: List[str] = []
        queue: deque = deque([start])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            cluster.append(node)
            for nb in undirected.get(node, set()):
                if nb not in visited:
                    queue.append(nb)
        clusters.append(cluster)
    return clusters


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
        # Solidity `library` keyword = utility code, rarely the primary audit target
        is_library = bool(m and m.group(1) == 'library')
        # Proxy wrapper contracts (OZ Transparent/Beacon/UUPS etc.) = no business logic
        is_proxy = bool(m and _PROXY_NAME_RE.search(cname))

        score = float(loc)
        if _CORE_NAME_RE.search(cname):
            score *= 1.1   # tie-breaker only — name is a weak signal
        if _INFRA_NAME_RE.search(cname):
            score *= 0.8   # soft penalty — Router/Helper/Factory rarely are primary
        if is_library:
            score *= 0.3
        if is_proxy:
            score *= 0.05
        # Value-bearing and entrypoint heuristics — only for real implementation contracts
        if not is_iface and not is_library and not is_proxy:
            if _VALUE_BEARING_RE.search(stripped):
                score *= 2.5   # strong behavioral signal — contracts that hold/move funds
                # Extra boost for value-bearing contracts with many state-changing entry points.
                # Intentionally NOT applied to non-VB contracts: a large oracle adapter with
                # many public getters is not a high-priority audit target.
                ext_count = len(re.findall(r'\b(?:external|public)\b(?!\s+(?:view|pure)\b)', stripped))
                if ext_count >= 5:
                    score *= 1.1
        # In-degree bonus only for real contracts — interfaces are imported widely
        # but that reflects dependency breadth, not implementation importance.
        # Weight 100 (not 200): prevents utility libs with high import count from
        # outscoring low-LOC core contracts (e.g. Rlp in contest 42).
        if not is_iface:
            score += in_degree.get(key, 0) * 100
        if is_iface:
            score *= 0.1

        scores[key] = score

    if not scores:
        return {"primary": None, "secondary": [], "primary_keys": [], "primary_names": [],
                "clusters": {}, "total_contracts": 0, "total_chars": 0}

    # --- Connected Components clustering ---
    # Cluster using ALL local files (including interfaces — they are the connective tissue
    # between contracts in Solidity). Exclude only external node_modules and mocks.
    all_local_keys = [
        k for k in order
        if k in scores
        and not _is_mock_or_test(k)
        and "node_modules" not in k
    ]
    raw_clusters = _find_clusters(all_local_keys, graph)

    # Within each cluster, candidates for primary = non-interface, non-library, non-proxy impls
    def _is_audit_candidate(k: str) -> bool:
        src = sources.get(k, "")
        stripped = _strip_sol_comments(src)
        m_c = _CONTRACT_RE.search(stripped)
        cname_c = m_c.group(0).split()[-1] if m_c else Path(k).stem
        return (
            not _is_interface_only(src)
            and not (m_c and m_c.group(1) == 'library')
            and not _PROXY_NAME_RE.search(cname_c)
        )

    # Filter out tiny clusters (total LOC < 100) — isolated utility contracts
    MIN_CLUSTER_LOC = 100
    sig_clusters = [
        c for c in raw_clusters
        if sum(sources.get(k, "").count('\n') + 1 for k in c) >= MIN_CLUSTER_LOC
    ]

    # Build cluster membership map for ToC and context
    cluster_map: Dict[str, List[str]] = {}
    for cluster in sig_clusters:
        candidates = [k for k in cluster if _is_audit_candidate(k) and k in scores]
        if not candidates:
            continue
        best = max(candidates, key=lambda k: scores.get(k, 0))
        cluster_map[best] = cluster  # representative → full cluster members

    # Primary selection: top-N globally ranked audit candidates (not constrained to 1/cluster).
    # Reason: protocols like Mochi connect all contracts through shared interfaces → single cluster,
    # but FeePoolV0/VestedRewardPool/MochiEngine each merit independent Slither analysis.
    MAX_PRIMARIES = 4
    all_candidates = [
        k for cluster in sig_clusters
        for k in cluster
        if _is_audit_candidate(k) and k in scores
    ]
    # Deduplicate (a key can appear in multiple sig_clusters if interface overlap caused merging)
    seen_cands: Set[str] = set()
    deduped_candidates: List[str] = []
    for k in all_candidates:
        if k not in seen_cands:
            seen_cands.add(k)
            deduped_candidates.append(k)

    cluster_primary_keys = sorted(
        deduped_candidates, key=lambda k: scores.get(k, 0), reverse=True
    )[:MAX_PRIMARIES]

    # Ensure cluster_map covers all chosen primaries
    # (some primaries may not be the best-score representative of their cluster)
    for pk in cluster_primary_keys:
        if pk not in cluster_map:
            # find which cluster this key belongs to and assign it
            for cluster in sig_clusters:
                if pk in cluster:
                    cluster_map[pk] = cluster
                    break

    # Fallback: if all keys were filtered out, fall back to global top scorer
    if not cluster_primary_keys:
        sorted_keys_fb = sorted(scores, key=lambda k: scores[k], reverse=True)
        cluster_primary_keys = [sorted_keys_fb[0]]
        cluster_map = {sorted_keys_fb[0]: sorted_keys_fb}

    primary_key = cluster_primary_keys[0]
    sorted_keys = sorted(scores, key=lambda k: scores[k], reverse=True)
    secondary_keys = [k for k in sorted_keys if k != primary_key]

    seen_names: Set[str] = set()
    tier1_impls: List[str] = []
    for k in sorted_keys:
        cn = contract_names.get(k, "")
        if cn and cn not in seen_names and k != primary_key:
            seen_names.add(cn)
            tier1_impls.append(cn)

    primary_names = [contract_names.get(pk, Path(pk).stem) for pk in cluster_primary_keys]
    return {
        # Backward-compatible single-primary fields
        "primary":            primary_names[0],
        "primary_file":       str(Path(primary_key).relative_to(base)),
        "primary_key":        primary_key,
        "secondary":          tier1_impls[:8],
        "secondary_keys":     secondary_keys,
        # Multi-primary fields
        "primary_keys":       cluster_primary_keys,
        "primary_names":      primary_names,
        "clusters":           {pk: cluster_map[pk] for pk in cluster_primary_keys},
        # Shared metadata
        "contract_names_map": contract_names,
        "total_contracts":    len(scores),
        "total_chars":        sum(len(sources.get(k, "")) for k in order),
    }


def flatten_contest_dir(
    contest_dir: str,
    max_chars: int = 200_000,
    verbose: bool = False,
    emit_manifest: bool = False,
    extra_scope_contracts: Optional[Set[str]] = None,
) -> "str | tuple[str, dict]":
    """
    Flatten all .sol files in contest_dir into a single source string.

    Args:
        contest_dir:           path to Web3Bugs contracts/<id>/ directory
        max_chars:             soft limit; if exceeded, interface-only files are dropped
        verbose:               print progress info
        extra_scope_contracts: contract names (e.g. from Slither caller analysis) to
                               force into in-scope even if not reachable via import BFS.

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

    # Step 1: Compute manifest and classify scope BEFORE any size trimming.
    # This ensures in-scope files (Manager, Position) are identified first and
    # protected from being dropped by the size budget.
    manifest = _compute_manifest(order, sources, graph, contest_dir)
    classification = _classify_files(order, graph, sources, manifest, contest_dir, extra_scope_contracts)
    in_scope_set  = set(classification["in_scope"])           # Tier 1: full source
    skeleton_set  = set(classification.get("skeleton", []))   # Tier 2: stub in in_scope_source
    out_scope_set = set(classification["out_scope"])           # Tier 3: dropped
    cls_method    = classification["method"]

    # Step 2: Size trimming
    base = Path(contest_dir)
    is_skeletonized = (cls_method == "skeletonized_slither")

    # 2a: Drop interface-only out-of-scope files first (cheapest drop for both modes)
    interface_oos = [k for k in out_scope_set if _is_interface_only(sources.get(k, ""))]
    if verbose and interface_oos:
        print(f"  Dropping {len(interface_oos)} interface-only out-of-scope files")
    for k in interface_oos:
        sources.pop(k, None)
        order = [x for x in order if x != k]
        out_scope_set.discard(k)

    if is_skeletonized:
        # 2b (skeletonized): Tier 1 is NEVER dropped — trim Tier 2 skeleton if over budget
        tier1_chars = sum(len(sources.get(k, "")) for k in in_scope_set if k in sources)
        tier2_chars = sum(len(_compress_to_stub(sources.get(k, ""))) for k in skeleton_set if k in sources)
        total_approx = tier1_chars + tier2_chars

        if total_approx > max_chars:
            remaining_budget = max_chars - tier1_chars
            kept_skeleton, running = [], 0
            for k in order:
                if k not in skeleton_set:
                    continue
                stub_size = len(_compress_to_stub(sources.get(k, "")))
                if running + stub_size <= remaining_budget:
                    kept_skeleton.append(k)
                    running += stub_size
            dropped_skeleton = skeleton_set - set(kept_skeleton)
            if verbose and dropped_skeleton:
                print(f"  Skeleton budget: dropping {len(dropped_skeleton)} Tier2 files "
                      f"to fit {max_chars//1000}K limit")
            for k in dropped_skeleton:
                skeleton_set.discard(k)
                out_scope_set.add(k)
    else:
        # 2b (legacy/no-Slither): drop out-of-scope stubs to fit budget, trim in-scope last resort
        total = sum(len(sources.get(k, "")) for k in order)
        if total > max_chars:
            in_scope_total = sum(len(sources.get(k, "")) for k in order if k in in_scope_set)
            remaining_budget = max_chars - in_scope_total
            kept_oos, running = [], 0
            for k in order:
                if k not in out_scope_set:
                    continue
                s = sources.get(k, "")
                if running + len(s) <= remaining_budget:
                    kept_oos.append(k)
                    running += len(s)
            dropped_oos = out_scope_set - set(kept_oos)
            if verbose and dropped_oos:
                print(f"  Still too large — dropping {len(dropped_oos)} out-of-scope files "
                      f"to fit {max_chars//1000}K limit")
            for k in dropped_oos:
                sources.pop(k, None)
            order = [k for k in order if k in sources]
            out_scope_set = set(kept_oos)

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
                print(f"  Still too large — dropping {len(order) - len(trimmed_order)} in-scope files (last resort)")
            dropped_keys = set(order) - set(trimmed_order)
            for k in dropped_keys:
                sources.pop(k, None)
                in_scope_set.discard(k)
                out_scope_set.discard(k)
            order = trimmed_order

    # Collect skeleton contract names for scope header
    skeleton_cnames: List[str] = []
    for k in [x for x in order if x in skeleton_set]:
        src = sources.get(k, "")
        m = _CONTRACT_RE.search(_strip_sol_comments(src))
        if m:
            skeleton_cnames.append(m.group(0).split()[-1])

    # Collect Tier 3 contract names for diagnostics
    out_scope_names: List[str] = []
    for k in classification["out_scope"]:
        src = sources.get(k, "")
        if not src:
            continue
        m = _CONTRACT_RE.search(_strip_sol_comments(src))
        if m:
            out_scope_names.append(m.group(0).split()[-1])
    manifest["out_scope_contracts"] = out_scope_names
    manifest["scope_method"]        = cls_method

    # Update secondary: only Tier 1 impl contracts (shown in AUDIT SCOPE header)
    cnames_map = manifest.get("contract_names_map", {})
    primary_key = manifest.get("primary_key")
    seen_names: set = set()
    tier1_impls = []
    for k in classification["in_scope"]:
        if k == primary_key or _is_interface_only(sources.get(k, "")):
            continue
        name = cnames_map.get(k, Path(k).stem)
        if name and name not in seen_names:
            seen_names.add(name)
            tier1_impls.append(name)
    manifest["secondary"]           = tier1_impls[:6]
    manifest["skeleton_contracts"]  = skeleton_cnames

    if verbose:
        print(f"  Scope ({cls_method}): {len(in_scope_set)} Tier1 full, "
              f"{len(skeleton_set)} Tier2 skeleton, {len(out_scope_set)} Tier3 dropped")

    # Build scope header injected at top (agents see this first)
    primary        = manifest.get("primary", "unknown")
    secondary      = [s for s in manifest.get("secondary", []) if s]
    primary_names_list = manifest.get("primary_names", [primary])
    clusters_info  = manifest.get("clusters", {})
    cnames_map_hdr = manifest.get("contract_names_map", {})

    if len(primary_names_list) > 1:
        # Multi-primary: generate Table of Contents to anchor LLM attention
        scope_header_lines = [
            f"// ═══ Web3Bugs Contest {Path(contest_dir).name} — Flattened Source ═══",
            f"// ⚠️  THIS PROTOCOL HAS {len(primary_names_list)} INDEPENDENT AUDIT TARGETS.",
            "// Analyze each target SEPARATELY. Only report cross-cluster bugs if state",
            "// is shared via direct external calls.",
            "//",
        ]
        pk_list = manifest.get("primary_keys", [])
        for i, (pk, pname) in enumerate(zip(pk_list, primary_names_list), 1):
            members = clusters_info.get(pk, [pk])
            member_names = [
                cnames_map_hdr.get(m, Path(m).stem) for m in members
                if m != pk and not _is_interface_only(sources.get(m, ""))
            ]
            scope_header_lines.append(f"// TARGET {i} — {pname} (primary)")
            if member_names:
                scope_header_lines.append(f"//   Related contracts: {', '.join(member_names[:6])}")
        if skeleton_cnames:
            scope_header_lines.append(
                f"// SKELETON DEPS: {', '.join(skeleton_cnames[:6])}"
                + (" ..." if len(skeleton_cnames) > 6 else "")
            )
        scope_header_lines.append("// " + "═" * 51)
    else:
        # Single-primary: existing compact header
        scope_header_lines = [
            f"// ═══ Web3Bugs Contest {Path(contest_dir).name} — Flattened Source ═══",
            f"// AUDIT SCOPE (full source): {primary}" + (f", {', '.join(secondary)}" if secondary else ""),
        ]
        if skeleton_cnames:
            scope_header_lines.append(
                f"// SKELETON CONTEXT (signatures/state vars only — function bodies omitted): "
                f"{', '.join(skeleton_cnames[:8])}"
                + (" ..." if len(skeleton_cnames) > 8 else "")
            )
    scope_header_lines.append("")
    parts = ["\n".join(scope_header_lines)]

    # Tier 1: full source — both in parts and inscope_parts
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

    # Tier 2: skeleton stubs — in BOTH parts and inscope_parts (KG + agents see signatures)
    seen_externals_skeleton: Set[str] = set(seen_externals)
    for key in order:
        if key not in sources or key not in skeleton_set:
            continue
        src = sources[key]
        if not src.strip():
            continue

        rel = str(Path(key).relative_to(base))
        file_header = f"\n// ─── {rel} [SKELETON — signatures only] ───\n"
        parts.append(file_header)
        inscope_parts.append(file_header)  # skeleton visible to KG builder

        stub = _compress_to_stub(src)
        stripped_stub = _strip_file(stub, keep_pragma=False, seen_externals=seen_externals_skeleton)
        parts.append(stripped_stub)
        inscope_parts.append(stripped_stub)  # skeleton visible to KG builder

    # Legacy out-of-scope stubs (agents only, NOT in inscope_parts) — only for non-skeletonized mode
    if not is_skeletonized:
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
    # Store in_scope_source: Tier 1 (full) + Tier 2 (skeleton) — used by KG builder and agents
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
    parser.add_argument("--max-chars", type=int, default=200_000,
                        help="Max chars in output (default: 200000)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    result = flatten_contest_dir(args.contest_dir, max_chars=args.max_chars, verbose=True)

    if args.output:
        Path(args.output).write_text(result, encoding="utf-8")
        print(f"Written to {args.output} ({len(result):,} chars)")
    else:
        print(result[:3000])
        print(f"\n... [{len(result):,} total chars, showing first 3000]")
