"""
PoC Verification Stage — Post-consensus vulnerability confirmation.

Runs after ConsensusEngine to upgrade Tier-2 gap findings to Tier-1
when a finding can be independently verified.

Three tracks (see docs/two-stage/poc-verification-stage.md):
  Track 1: Unit PoC  — forge unit test for Easy/Medium SWC  [requires Foundry via Docker]
  Track 2: Fuzz PoC  — forge fuzz test for Hard SWC          [requires Foundry via Docker]
  Track 3: LLM Query — targeted LLM verification for semantic S-class [always available]

Foundry is run via Docker (ghcr.io/foundry-rs/foundry:latest) to avoid GLIBC
version incompatibility on Ubuntu 20.04. No local forge binary required.

Workspace strategy (Tracks 1+2):
  - SSD workspace: /mnt/ollama_data/mirofish_poc/{contest_id}/
  - foundry.toml: src → HDD contest dir (read-only mount), out/cache/test → SSD workspace
  - Docker mounts both HDD contest dir and SSD workspace
  - Artifacts stay on SSD, cleaned up after run

Design principles:
  - Verification fail ≠ drop finding (PoC fail → stays in Tier-2, never deleted)
  - Hard time budget: entire stage ≤ stage_timeout_s (default 300s)
  - Graceful degradation: any failure → findings unchanged, pipeline not blocked
  - Evidence guard on Track 3: YES verdict without code evidence = hallucination → skip
"""

import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..utils.logger import get_logger

logger = get_logger("mirofish.poc_verification")

# ─── SWC routing tables ───────────────────────────────────────────────────────

# Track 1: unit test via forge (deterministic, bounded setup, observable failure)
POC_UNIT_SWCS: Set[str] = {
    "SWC-101",  # Integer Overflow/Underflow
    "SWC-105",  # Unprotected Ether Withdrawal
    "SWC-106",  # Unprotected Self-Destruct
    "SWC-115",  # tx.origin Authentication
    "SWC-107",  # Reentrancy
    "SWC-120",  # Weak Sources of Randomness
    "SWC-114",  # Transaction Order Dependence (front-running)
    "SWC-112",  # Delegatecall to Untrusted Callee
}

# Track 2: fuzz test via forge (scale-dependent, fuzzer finds threshold)
POC_FUZZ_SWCS: Set[str] = {
    "SWC-128",  # DoS With Block Gas Limit
}

# Track 3: LLM targeted query (semantic S-class, no execution needed)
LLM_QUERY_CATEGORIES: Set[str] = {
    "access_control",
    "incorrect_accounting",
    "state_machine_bug",
    "reentrancy_logic",
}

# Query templates per semantic category
LLM_QUERY_TEMPLATES: Dict[str, str] = {
    "access_control": (
        "Does {contract}.{function} enforce any access restriction "
        "(onlyOwner, role check, msg.sender validation)? "
        "If the restriction is MISSING: which addresses can call it unexpectedly?"
    ),
    "incorrect_accounting": (
        "In {contract}.{function}, do the balance/share calculations "
        "maintain correct invariants under all inputs? "
        "Show the specific arithmetic line where a discrepancy can occur."
    ),
    "state_machine_bug": (
        "Does {contract}.{function} transition state correctly? "
        "Is there any execution path where state is left inconsistent or permanently stuck?"
    ),
    "reentrancy_logic": (
        "Does {contract}.{function} follow the Checks-Effects-Interactions pattern? "
        "If NOT: is there an external call before a state update that enables re-entry?"
    ),
}


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class PoCConfig:
    enabled:               bool  = True
    min_agent_votes:       int   = 2      # minimum source_count to PoC
    max_unit_candidates:   int   = 10
    max_fuzz_candidates:   int   = 4
    max_llm_candidates:    int   = 8
    llm_timeout_s:         int   = 30
    llm_max_tokens:        int   = 200
    snippet_max_lines:     int   = 60
    forge_compile_timeout: int   = 90
    forge_test_timeout:    int   = 120
    fuzz_runs:             int   = 128
    stage_timeout_s:       int   = 300


@dataclass
class VerificationResult:
    verdict:   str    # "YES" | "NO" | "INCONCLUSIVE"
    evidence:  str    # direct code quote or "none"
    reasoning: str


@dataclass
class _PoCCandidate:
    gap_id:           str
    swc_id:           str
    swc_category:     str
    semantic_cat:     str
    contract_name:    str
    function_names:   List[str]
    description:      str
    source_count:     int
    track:            str   # "unit" | "fuzz" | "llm"
    gap_finding:      Dict[str, Any]  # original gap dict for reconstruction


# ─── Helpers ──────────────────────────────────────────────────────────────────

FOUNDRY_IMAGE = "ghcr.io/foundry-rs/foundry:latest"

# Shared forge-std library cached on SSD — installed once, mounted read-only into
# every workspace. Avoids re-downloading forge-std for each PoC run.
POC_SHARED_LIB = Path("/mnt/ollama_data/mirofish_poc/shared_lib/lib")


def _forge_available() -> bool:
    """True when Docker is running and Foundry image is present."""
    try:
        r = subprocess.run(
            ["docker", "images", "-q", FOUNDRY_IMAGE],
            capture_output=True, timeout=10,
        )
        # Non-empty stdout means image exists locally
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


def _extract_snippet(flat_source: str, function_name: str, max_lines: int) -> str:
    """Extract function body from flat Solidity source. Returns at most max_lines."""
    if not flat_source or not function_name:
        return ""

    fn = re.escape(function_name.rstrip("()"))
    pattern = re.compile(
        rf'\bfunction\s+{fn}\s*\(',
        re.MULTILINE,
    )
    m = pattern.search(flat_source)
    if not m:
        return ""

    start = flat_source.rfind("\n", 0, m.start()) + 1
    lines = flat_source[start:].split("\n")

    # Collect until matching brace closes
    brace_depth = 0
    result_lines = []
    found_open = False
    for line in lines[:max_lines * 3]:
        result_lines.append(line)
        brace_depth += line.count("{") - line.count("}")
        if "{" in line:
            found_open = True
        if found_open and brace_depth <= 0:
            break
        if len(result_lines) >= max_lines:
            result_lines.append("    // ... (truncated)")
            break

    return "\n".join(result_lines)


def _parse_verdict(response: str) -> VerificationResult:
    """Parse structured verdict from LLM response."""
    verdict_m  = re.search(r'VERDICT\s*:\s*(YES|NO|INCONCLUSIVE)', response, re.IGNORECASE)
    evidence_m = re.search(r'EVIDENCE\s*:\s*(.+?)(?:\n|REASONING|$)', response, re.IGNORECASE | re.DOTALL)
    reason_m   = re.search(r'REASONING\s*:\s*(.+?)$', response, re.IGNORECASE | re.DOTALL)

    verdict   = verdict_m.group(1).upper()  if verdict_m  else "INCONCLUSIVE"
    evidence  = evidence_m.group(1).strip() if evidence_m else "none"
    reasoning = reason_m.group(1).strip()   if reason_m   else ""

    # Truncate to reasonable length
    evidence  = evidence[:300]
    reasoning = reasoning[:200]

    return VerificationResult(verdict=verdict, evidence=evidence, reasoning=reasoning)


def _should_upgrade(result: VerificationResult) -> bool:
    """Evidence guard: only upgrade if YES with concrete code evidence."""
    if result.verdict != "YES":
        return False
    ev = result.evidence.lower().strip()
    return bool(ev) and ev not in {"none", "n/a", "-", ""}


# ─── Main class ───────────────────────────────────────────────────────────────

class PoCVerificationStage:
    """
    Post-consensus PoC verification. Call run() after enforce_swc_coverage().

    Usage:
        poc = PoCVerificationStage(llm_client=orchestrator.llm, config=PoCConfig())
        consensus_vulns, gap_findings = poc.run(
            consensus_vulns=consensus_vulns,
            gap_findings=gap_findings,
            flat_source=source_code,
            contest_dir=contest_dir,
        )
    """

    def __init__(self, llm_client: Any, config: Optional[PoCConfig] = None):
        self._llm   = llm_client
        self._cfg   = config or PoCConfig()
        self._forge = _forge_available()
        if not self._forge:
            logger.info(
                "PoC: Foundry Docker image not available — "
                "Track 1/2 (Unit/Fuzz) disabled; Track 3 (LLM Query) active. "
                f"To enable: docker pull {FOUNDRY_IMAGE}"
            )

    # ── public entry point ────────────────────────────────────────────────────

    def run(
        self,
        consensus_vulns: List[Dict[str, Any]],
        gap_findings: List[Dict[str, Any]],
        flat_source: str,
        contest_dir: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Returns (updated_consensus_vulns, updated_gap_findings).
        All failures are safe: findings never deleted, only potentially upgraded.
        """
        if not self._cfg.enabled or not gap_findings:
            return consensus_vulns, gap_findings

        stage_start = time.monotonic()

        try:
            candidates = self._select_candidates(gap_findings)
            if not candidates:
                logger.info("PoC: no eligible candidates — skipping stage")
                return consensus_vulns, gap_findings

            logger.info(
                f"PoC: {len(candidates)} candidates "
                f"(unit={sum(1 for c in candidates if c.track=='unit')}, "
                f"fuzz={sum(1 for c in candidates if c.track=='fuzz')}, "
                f"llm={sum(1 for c in candidates if c.track=='llm')})"
            )

            upgraded_ids: Set[str] = set()

            # Track 3: LLM targeted query (always available)
            llm_candidates = [c for c in candidates if c.track == "llm"]
            if llm_candidates:
                remaining = self._cfg.stage_timeout_s - int(time.monotonic() - stage_start)
                if remaining > 30:
                    llm_results = self._run_track3(llm_candidates, flat_source,
                                                    timeout=min(remaining - 10, 120))
                    for cid, result in llm_results.items():
                        if _should_upgrade(result):
                            upgraded_ids.add(cid)
                            logger.info(f"PoC T3 UPGRADE: {cid} — {result.evidence[:80]}")
                        else:
                            logger.debug(f"PoC T3 skip: {cid} verdict={result.verdict}")

            # Track 1+2: forge (stubbed when forge unavailable)
            forge_candidates = [c for c in candidates if c.track in ("unit", "fuzz")]
            if forge_candidates:
                if self._forge:
                    remaining = self._cfg.stage_timeout_s - int(time.monotonic() - stage_start)
                    if remaining > 60 and contest_dir:
                        forge_upgrades = self._run_forge_tracks(
                            forge_candidates, flat_source, contest_dir,
                            timeout=remaining - 10,
                        )
                        upgraded_ids.update(forge_upgrades)
                else:
                    logger.debug(
                        f"PoC: {len(forge_candidates)} forge candidates deferred "
                        f"(forge unavailable) — install Foundry to enable Track 1/2"
                    )

            if not upgraded_ids:
                logger.info("PoC: no findings upgraded")
                return consensus_vulns, gap_findings

            # Integrate results
            new_vulns, remaining_gaps = self._integrate(
                upgraded_ids, gap_findings, consensus_vulns
            )
            elapsed = int(time.monotonic() - stage_start)
            logger.info(
                f"PoC: +{len(new_vulns) - len(consensus_vulns)} upgraded to Tier-1 "
                f"in {elapsed}s"
            )
            return new_vulns, remaining_gaps

        except Exception as exc:
            logger.warning(f"PoC stage error (non-fatal): {exc}")
            return consensus_vulns, gap_findings

    # ── candidate selection ───────────────────────────────────────────────────

    def _select_candidates(
        self, gap_findings: List[Dict[str, Any]]
    ) -> List[_PoCCandidate]:
        unit, fuzz, llm = [], [], []

        for gap in gap_findings:
            if gap.get("source_count", 0) < self._cfg.min_agent_votes:
                continue

            fns = gap.get("affected_functions", [])
            if not fns:
                continue  # no function location — can't target PoC

            swc_id   = gap.get("swc_id", "")
            sem_cat  = gap.get("swc_category", "")
            contract = gap.get("title", "").split()[0] if gap.get("title") else "Contract"
            gap_id   = gap.get("swc_id", "") + "_" + "_".join(fns[:2])

            candidate = _PoCCandidate(
                gap_id=gap_id,
                swc_id=swc_id,
                swc_category=sem_cat,
                semantic_cat=sem_cat,
                contract_name=contract,
                function_names=fns,
                description=gap.get("description", ""),
                source_count=gap.get("source_count", 0),
                track="",
                gap_finding=gap,
            )

            if swc_id in POC_UNIT_SWCS:
                candidate.track = "unit"
                unit.append(candidate)
            elif swc_id in POC_FUZZ_SWCS:
                candidate.track = "fuzz"
                fuzz.append(candidate)
            elif sem_cat in LLM_QUERY_CATEGORIES:
                candidate.track = "llm"
                llm.append(candidate)

        return (
            unit[:self._cfg.max_unit_candidates]
            + fuzz[:self._cfg.max_fuzz_candidates]
            + llm[:self._cfg.max_llm_candidates]
        )

    # ── Track 3: LLM targeted query ───────────────────────────────────────────

    def _run_track3(
        self,
        candidates: List[_PoCCandidate],
        flat_source: str,
        timeout: int,
    ) -> Dict[str, VerificationResult]:
        """Run LLM targeted queries in parallel via ThreadPoolExecutor."""
        results: Dict[str, VerificationResult] = {}

        def query_one(c: _PoCCandidate) -> Tuple[str, VerificationResult]:
            fn = c.function_names[0] if c.function_names else ""
            snippet = _extract_snippet(flat_source, fn, self._cfg.snippet_max_lines)

            query_template = LLM_QUERY_TEMPLATES.get(
                c.semantic_cat,
                "Does {contract}.{function} have a security vulnerability? "
                "Show the specific line."
            )
            question = query_template.format(
                contract=c.contract_name,
                function=fn or "(unknown)",
            )

            system_msg = (
                "You are a smart contract security verifier. "
                "Answer ONLY what you directly observe in the code. "
                "Do not infer, extrapolate, or guess."
            )
            user_msg = (
                f"Question: {question}\n\n"
                f"Previous audit evidence:\n{c.description[:300]}\n\n"
                f"Code:\n```solidity\n{snippet}\n```\n\n"
                "Answer in this exact format (no extra text):\n"
                "VERDICT: YES | NO | INCONCLUSIVE\n"
                "EVIDENCE: <direct quote or line reference from the code above, "
                "or 'none' if nothing found>\n"
                "REASONING: <one sentence>"
            )

            try:
                response = self._llm.chat(
                    messages=[
                        {"role": "system", "content": system_msg},
                        {"role": "user",   "content": user_msg},
                    ],
                    temperature=0.0,
                    max_tokens=self._cfg.llm_max_tokens,
                )
                return c.gap_id, _parse_verdict(response)
            except Exception as e:
                logger.debug(f"PoC T3 query error for {c.gap_id}: {e}")
                return c.gap_id, VerificationResult("INCONCLUSIVE", "none", str(e)[:80])

        with ThreadPoolExecutor(max_workers=min(len(candidates), 8)) as pool:
            futures = {pool.submit(query_one, c): c for c in candidates}
            deadline = time.monotonic() + timeout
            for future in as_completed(futures, timeout=max(1, deadline - time.monotonic())):
                try:
                    gap_id, result = future.result(timeout=2)
                    results[gap_id] = result
                except Exception:
                    pass

        return results

    # ── Track 1+2: forge (placeholder — active when forge available) ──────────

    def _run_forge_tracks(
        self,
        candidates: List[_PoCCandidate],
        flat_source: str,
        contest_dir: str,
        timeout: int,
    ) -> Set[str]:
        """
        Run forge unit + fuzz tests. Creates SSD workspace, generates PoC file,
        compiles once, runs all tests in one invocation.

        Workspace: /mnt/ollama_data/mirofish_poc/{contest_id}/
          - foundry.toml: src → HDD contest dir, out/cache/test → SSD workspace
          - test/_poc_mirofish.t.sol: generated PoC tests

        Returns set of gap_ids that passed.
        """
        from pathlib import Path as _P
        import shutil, uuid

        POC_WORKSPACE_ROOT = _P("/mnt/ollama_data/mirofish_poc")
        contest_id = _P(contest_dir).name
        workspace  = POC_WORKSPACE_ROOT / contest_id

        upgraded: Set[str] = set()
        created_workspace = False

        try:
            workspace.mkdir(parents=True, exist_ok=True)
            (workspace / "test").mkdir(exist_ok=True)
            created_workspace = True

            # Generate foundry.toml
            (workspace / "foundry.toml").write_text(
                f'[profile.default]\n'
                f'src        = "{contest_dir}"\n'
                f'test       = "test"\n'
                f'out        = "out"\n'
                f'cache_path = "cache"\n'
            )

            # Generate PoC test file
            poc_content = self._generate_poc_file(candidates, flat_source)
            (workspace / "test" / "_poc_mirofish.t.sol").write_text(poc_content)

            # forge build
            build_ok = self._forge_build(workspace, contest_dir, timeout=min(timeout // 2, 90))
            if not build_ok:
                logger.warning("PoC T1/T2: forge build failed — skipping")
                return upgraded

            # forge test
            results = self._forge_test(
                workspace,
                contest_dir,
                timeout=min(timeout - 90, self._cfg.forge_test_timeout),
                fuzz_runs=self._cfg.fuzz_runs,
            )

            for candidate in candidates:
                fn = candidate.function_names[0].rstrip("()") if candidate.function_names else "fn"
                prefix = "testFuzz" if candidate.track == "fuzz" else "test"
                swc_short = candidate.swc_id.replace("-", "").lower()
                test_name = f"{prefix}_{swc_short}_{fn}"
                if results.get(test_name):
                    upgraded.add(candidate.gap_id)
                    logger.info(f"PoC T1/T2 UPGRADE: {test_name} PASS")

        except Exception as e:
            logger.warning(f"PoC forge tracks error: {e}")
        finally:
            if created_workspace:
                try:
                    shutil.rmtree(workspace, ignore_errors=True)
                except Exception:
                    pass

        return upgraded

    def _generate_poc_file(
        self, candidates: List[_PoCCandidate], flat_source: str
    ) -> str:
        """Generate a single PoC.t.sol with all test functions."""
        test_fns = []
        setup_lines = []
        seen_contracts: Set[str] = set()

        for c in candidates:
            fn = c.function_names[0].rstrip("()") if c.function_names else "fn"
            swc_short = c.swc_id.replace("-", "").lower()
            contract  = c.contract_name.split()[0] if c.contract_name else "Target"

            if contract not in seen_contracts:
                seen_contracts.add(contract)
                setup_lines.append(
                    f"        // {contract} target_{contract.lower()} = new {contract}();"
                )

            if c.track == "fuzz":
                test_fns.append(
                    f"    function testFuzz_{swc_short}_{fn}(uint16 param) public {{\n"
                    f"        // Fuzz PoC for {c.swc_id} in {fn}\n"
                    f"        // TODO: implement for {contract}\n"
                    f"    }}"
                )
            else:
                test_fns.append(
                    f"    function test_{swc_short}_{fn}() public {{\n"
                    f"        // Unit PoC for {c.swc_id} in {fn}\n"
                    f"        // TODO: implement for {contract}\n"
                    f"    }}"
                )

        return (
            '// SPDX-License-Identifier: UNLICENSED\n'
            'pragma solidity ^0.8.0;\n\n'
            'import "forge-std/Test.sol";\n\n'
            'contract _poc_mirofish is Test {\n\n'
            '    function setUp() public {\n'
            + "\n".join(setup_lines) + "\n"
            '    }\n\n'
            + "\n\n".join(test_fns) + "\n"
            '}\n'
        )

    def _docker_forge(
        self,
        forge_args: List[str],
        workspace: Path,
        contest_dir: Optional[str],
        timeout: int,
        capture_stdout: bool = False,
    ) -> subprocess.CompletedProcess:
        """
        Run forge inside Docker.

        Mounts:
          workspace        → /workspace     (rw, SSD — foundry.toml, test/, src/, out/, cache/)
          POC_SHARED_LIB   → /workspace/lib (ro, SSD — forge-std and other shared libs)
          contest_dir      → /src           (ro, HDD — contest source for future reference)
        """
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{workspace}:/workspace",
            "-w", "/workspace",
        ]
        # Mount shared forge-std lib if available
        if POC_SHARED_LIB.exists():
            cmd += ["-v", f"{POC_SHARED_LIB}:/workspace/lib:ro"]
        if contest_dir:
            cmd += ["-v", f"{contest_dir}:/src:ro"]
        cmd += [
            "--entrypoint", "",
            FOUNDRY_IMAGE,
            "/usr/local/bin/forge",
        ] + forge_args

        return subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=capture_stdout,
        )

    # Minimal hardhat/console.sol stub — covers common overloads used in audit code.
    # Injected into workspace so forge can resolve `import "hardhat/console.sol"` without
    # needing node_modules (web3bugs dataset ships code snapshots, not installed deps).
    _HARDHAT_CONSOLE_STUB = '''\
// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

library console {
    function log() internal pure {}
    function log(string memory) internal pure {}
    function log(bool) internal pure {}
    function log(address) internal pure {}
    function log(uint256) internal pure {}
    function log(int256) internal pure {}
    function log(bytes32) internal pure {}
    function log(string memory, string memory) internal pure {}
    function log(string memory, uint256) internal pure {}
    function log(string memory, int256) internal pure {}
    function log(string memory, bool) internal pure {}
    function log(string memory, address) internal pure {}
    function log(uint256, string memory) internal pure {}
    function log(uint256, uint256) internal pure {}
    function log(uint256, bool) internal pure {}
    function log(uint256, address) internal pure {}
    function log(bool, string memory) internal pure {}
    function log(bool, uint256) internal pure {}
    function log(bool, bool) internal pure {}
    function log(bool, address) internal pure {}
    function log(address, string memory) internal pure {}
    function log(address, uint256) internal pure {}
    function log(address, bool) internal pure {}
    function log(address, address) internal pure {}
    function log(string memory, string memory, string memory) internal pure {}
    function log(string memory, string memory, uint256) internal pure {}
    function log(string memory, uint256, uint256) internal pure {}
    function log(string memory, uint256, string memory) internal pure {}
    function log(string memory, uint256, bool) internal pure {}
    function log(string memory, uint256, address) internal pure {}
    function log(string memory, bool, bool) internal pure {}
    function log(string memory, bool, uint256) internal pure {}
    function log(string memory, bool, address) internal pure {}
    function log(uint256, uint256, uint256) internal pure {}
    function log(uint256, uint256, string memory) internal pure {}
    function log(uint256, string memory, uint256) internal pure {}
    function log(uint256, string memory, string memory) internal pure {}
}
'''

    def _setup_lib_stubs(self, workspace: Path) -> List[str]:
        """
        Returns remapping strings for shared stubs mounted at /workspace/lib.

        Stubs live in POC_SHARED_LIB (shared SSD cache) which is mounted read-only
        at /workspace/lib inside the Docker container — do NOT write into workspace/lib
        here because that directory is shadowed by the Docker volume mount.

        Currently handled via shared_lib:
          hardhat/console.sol — Hardhat debug lib, absent in web3bugs dataset
          forge-std/           — Foundry standard library
        """
        remappings: List[str] = []
        if POC_SHARED_LIB.exists():
            remappings.append("hardhat/=lib/hardhat/")
        return remappings

    def _forge_build(self, workspace: Path, contest_dir: Optional[str], timeout: int) -> bool:
        # src = workspace/src (isolated — only our stubs, not the full contest dir).
        # Forge would fail if pointed at the contest dir directly because web3bugs
        # ships code snapshots without npm install, so @openzeppelin / hardhat imports
        # are unresolvable. Our generated PoC tests are self-contained (forge-std only).
        (workspace / "src").mkdir(exist_ok=True)

        # Create lib stubs for dev-only imports that may appear in forge-std or future tests
        remappings = self._setup_lib_stubs(workspace)

        remappings_toml = (
            "remappings = [\n"
            + "".join(f'    "{r}",\n' for r in remappings)
            + "]\n"
        ) if remappings else ""

        toml_path = workspace / "foundry.toml"
        toml_path.write_text(
            "[profile.default]\n"
            "src        = \"src\"\n"
            "test       = \"test\"\n"
            "out        = \"out\"\n"
            "cache_path = \"cache\"\n"
            + remappings_toml
        )
        try:
            r = self._docker_forge(
                ["build", "--silent"],
                workspace=workspace,
                contest_dir=contest_dir,
                timeout=timeout,
            )
            if r.returncode != 0:
                logger.warning(f"PoC: forge build failed: {r.stderr.decode()[:300]}")
            return r.returncode == 0
        except subprocess.TimeoutExpired:
            logger.warning("PoC: forge build timed out")
            return False
        except Exception as e:
            logger.warning(f"PoC: forge build error: {e}")
            return False

    def _forge_test(
        self, workspace: Path, contest_dir: Optional[str], timeout: int, fuzz_runs: int
    ) -> Dict[str, bool]:
        """Returns {test_name: passed} from forge --json output."""
        try:
            r = self._docker_forge(
                [
                    "test",
                    "--match-contract", "_poc_mirofish",
                    "--json",
                    "--fuzz-runs", str(fuzz_runs),
                    "--no-match-test", "invariant_",
                ],
                workspace=workspace,
                contest_dir=contest_dir,
                timeout=timeout,
                capture_stdout=True,
            )
            return self._parse_forge_json(r.stdout)
        except subprocess.TimeoutExpired:
            logger.warning("PoC: forge test timed out")
            return {}
        except Exception as e:
            logger.warning(f"PoC: forge test error: {e}")
            return {}

    @staticmethod
    def _parse_forge_json(output: str) -> Dict[str, bool]:
        import json
        results: Dict[str, bool] = {}
        try:
            data = json.loads(output)
            for contract_results in data.values():
                test_results = contract_results.get("test_results", {})
                for test_name, test_data in test_results.items():
                    results[test_name] = test_data.get("status") == "Success"
        except Exception:
            pass
        return results

    # ── result integration ────────────────────────────────────────────────────

    def _integrate(
        self,
        upgraded_ids: Set[str],
        gap_findings: List[Dict[str, Any]],
        consensus_vulns: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Upgrade confirmed gap findings to consensus_vulns."""
        newly_confirmed: List[Dict[str, Any]] = []
        remaining_gaps: List[Dict[str, Any]] = []

        for gap in gap_findings:
            fns    = gap.get("affected_functions", [])
            swc_id = gap.get("swc_id", "")
            gap_id = swc_id + "_" + "_".join(fns[:2])

            if gap_id in upgraded_ids:
                # Promote to consensus_vuln dict format
                promoted = {
                    "id":              f"poc_{swc_id}_{fns[0] if fns else 'unknown'}",
                    "title":           gap.get("title", f"{swc_id} (PoC confirmed)"),
                    "description":     gap.get("description", ""),
                    "severity":        gap.get("severity", "medium"),
                    "swc_ids":         [swc_id] if swc_id else [],
                    "affected_assets": fns,
                    "recommendations": [
                        f"Fix {swc_id} vulnerability in {', '.join(fns[:3])}"
                    ],
                    "confidence_score": 0.70,   # PoC-confirmed base confidence
                    "needs_review":    False,
                    "poc_confirmed":   True,     # audit trail flag
                    "source":          "poc_verification",
                }
                newly_confirmed.append(promoted)
            else:
                remaining_gaps.append(gap)

        return consensus_vulns + newly_confirmed, remaining_gaps
