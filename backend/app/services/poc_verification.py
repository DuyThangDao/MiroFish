"""
PoC Verification Stage — Scenario-Driven Enrichment Layer.

Enriches confirmed findings from R2+R3 with poc_verified=True when a Forge test
derived from an attacker_verdict scenario passes.

Role: ENRICHMENT only — does NOT change confidence_score or confirmed/discarded status.

Flow:
  confirmed findings → _run_scenario_driven() per finding
    → CONFIRMED/PLAUSIBLE attacker_verdicts → SCENARIO_POC_PROMPT → Forge test
    → ≥1 test passes → poc_verified=True, poc_results populated

Skip conditions (non-fatal, pipeline not blocked):
  - Forge Docker image not available
  - Finding has no CONFIRMED/PLAUSIBLE attacker_verdicts
  - flat_source is empty
  - Stage timeout reached (stage_timeout_s, default 300s)
"""

import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..utils.logger import get_logger

logger = get_logger("mirofish.poc_verification")


# ─── Constants ────────────────────────────────────────────────────────────────

FOUNDRY_IMAGE  = "ghcr.io/foundry-rs/foundry:latest"

# Shared forge-std library cached on SSD — installed once, mounted read-only.
POC_SHARED_LIB = Path("/mnt/ollama_data/mirofish_poc/shared_lib/lib")

# Workspace root for per-finding temp directories
POC_WORKSPACE_ROOT = Path("/mnt/ollama_data/mirofish_poc")

SCENARIO_POC_PROMPT = """\
You are a smart contract security researcher writing a Foundry test to PROVE a vulnerability.

Target function source:
```solidity
{function_source}
```

Attack scenario:
  Entry point     : {entry_point}
  Pre-condition   : {pre_condition}
  Attack steps    : {attack_steps}
  Expected outcome: {expected_outcome}

Write ONLY the Solidity function body (statements inside curly braces) for a Forge test
that PASSES when this specific attack succeeds.
Rules:
- Use vm.deal, vm.prank, vm.expectRevert from forge-std when needed
- The test asserts the expected outcome (overflow, drain, revert, etc.)
- Max 30 lines. No comments. No imports. No function signature.\
"""


# ─── Config ───────────────────────────────────────────────────────────────────

@dataclass
class PoCConfig:
    enabled:               bool  = True
    stage_timeout_s:       int   = 300
    llm_timeout_s:         int   = 60
    llm_max_tokens:        int   = 512
    snippet_max_lines:     int   = 60
    forge_compile_timeout: int   = 90
    forge_test_timeout:    int   = 120


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _forge_available() -> bool:
    """True when Docker is running and Foundry image is present locally."""
    try:
        r = subprocess.run(
            ["docker", "images", "-q", FOUNDRY_IMAGE],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


def _extract_snippet(flat_source: str, function_name: str, max_lines: int) -> str:
    """Extract function body from flat Solidity source. Returns at most max_lines."""
    if not flat_source or not function_name:
        return ""

    fn = re.escape(function_name.rstrip("()"))
    pattern = re.compile(rf'\bfunction\s+{fn}\s*\(', re.MULTILINE)
    m = pattern.search(flat_source)
    if not m:
        return ""

    start = flat_source.rfind("\n", 0, m.start()) + 1
    lines = flat_source[start:].split("\n")

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


def _safe_test_name(pair_id: str, attacker_id: str) -> str:
    """Build a valid Solidity function identifier from pair_id + attacker_id."""
    raw = f"test_poc_{pair_id}_{attacker_id}"
    return re.sub(r"[^a-zA-Z0-9_]", "_", raw)[:64]


# ─── Main class ───────────────────────────────────────────────────────────────

class PoCVerificationStage:
    """
    Scenario-driven PoC enrichment for confirmed R2+R3 findings.

    Usage:
        poc = PoCVerificationStage(llm_client=orchestrator.llm)
        enriched = poc.run(confirmed_findings=all_confirmed, flat_source=source_code)
    """

    def __init__(self, llm_client: Any, config: Optional[PoCConfig] = None):
        self._llm   = llm_client
        self._cfg   = config or PoCConfig()
        self._forge = _forge_available()
        if not self._forge:
            logger.info(
                "PoC: Foundry Docker image not available — PoC stage will be skipped. "
                f"To enable: docker pull {FOUNDRY_IMAGE}"
            )

    # ── Public entry point ────────────────────────────────────────────────────

    def run(
        self,
        confirmed_findings: List[Dict[str, Any]],
        flat_source: str,
    ) -> List[Dict[str, Any]]:
        """
        Enrich each confirmed finding with poc_verified and poc_results.

        Returns the same list with poc_verified/poc_results populated.
        Findings without eligible attacker_verdicts are returned unchanged
        (poc_verified=False, poc_results=[] — already set by build_v2_output).
        """
        if not self._cfg.enabled or not flat_source or not confirmed_findings:
            logger.info("PoC: skipped (disabled or no input)")
            return confirmed_findings

        if not self._forge:
            logger.info("PoC: skipped (Forge not available)")
            return confirmed_findings

        stage_start = time.monotonic()
        enriched    = [dict(f) for f in confirmed_findings]  # shallow copy per finding
        verified_count = 0

        for i, finding in enumerate(enriched):
            elapsed = time.monotonic() - stage_start
            if elapsed > self._cfg.stage_timeout_s:
                logger.warning(
                    f"PoC: stage timeout ({self._cfg.stage_timeout_s}s) — "
                    f"{len(enriched) - i} findings not enriched"
                )
                break

            verdicts = finding.get("attacker_verdicts", {})
            has_eligible = any(
                v.get("verdict") in ("CONFIRMED", "PLAUSIBLE")
                for v in verdicts.values()
            )
            if not has_eligible:
                logger.debug(f"PoC: {finding.get('pair_id')} — no eligible verdicts, skipping")
                continue

            try:
                poc_verified, poc_results = self._run_scenario_driven(finding, flat_source)
                enriched[i]["poc_verified"] = poc_verified
                enriched[i]["poc_results"]  = poc_results
                if poc_verified:
                    verified_count += 1
                logger.info(
                    f"PoC: {finding.get('pair_id')} poc_verified={poc_verified} "
                    f"({sum(1 for r in poc_results if r.get('forge_pass'))}"
                    f"/{len(poc_results)} tests passed)"
                )
            except Exception as exc:
                logger.warning(f"PoC: error enriching {finding.get('pair_id')}: {exc}")

        logger.info(
            f"PoC: enrichment complete — {verified_count}/{len(enriched)} findings poc_verified "
            f"in {int(time.monotonic() - stage_start)}s"
        )
        return enriched

    # ── Scenario-driven core ──────────────────────────────────────────────────

    def _run_scenario_driven(
        self,
        finding: Dict[str, Any],
        flat_source: str,
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        For one confirmed finding:
          1. Collect CONFIRMED/PLAUSIBLE attacker_verdicts (priority order)
          2. Generate LLM Forge test body per verdict using SCENARIO_POC_PROMPT
          3. Batch all tests into one .t.sol, compile + run in a temp workspace
          4. Return (poc_verified, poc_results)
        """
        _VERDICT_PRIORITY = {"CONFIRMED": 2, "PLAUSIBLE": 1}

        verdicts  = finding.get("attacker_verdicts", {})
        pair_id   = finding.get("pair_id", "unknown")
        fn_name   = finding.get("function_name", "") or ""
        swc_id    = finding.get("swc_id", "")

        # Sort: CONFIRMED first, then PLAUSIBLE
        eligible = sorted(
            [(aid, v) for aid, v in verdicts.items()
             if v.get("verdict") in _VERDICT_PRIORITY],
            key=lambda x: _VERDICT_PRIORITY[x[1]["verdict"]],
            reverse=True,
        )

        fn_source = _extract_snippet(flat_source, fn_name, self._cfg.snippet_max_lines)

        # Build (test_name → scenario_summary) mapping alongside test bodies
        test_entries: List[Dict[str, Any]] = []  # {test_name, attacker_id, verdict, scenario_summary, body}

        for attacker_id, verdict_data in eligible:
            verdict         = verdict_data.get("verdict")
            entry_point     = verdict_data.get("entry_point", fn_name) or fn_name
            pre_condition   = verdict_data.get("pre_condition", "")
            attack_steps    = verdict_data.get("attack_steps", "")
            if isinstance(attack_steps, list):
                attack_steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(attack_steps))
            expected_outcome = verdict_data.get("expected_outcome", "")

            test_name        = _safe_test_name(pair_id, attacker_id)
            scenario_summary = f"{entry_point} → {expected_outcome}"[:120]

            body = self._llm_generate_scenario_test(
                fn_source        = fn_source,
                entry_point      = entry_point,
                pre_condition    = pre_condition,
                attack_steps     = attack_steps,
                expected_outcome = expected_outcome,
                swc_id           = swc_id,
            )

            test_entries.append({
                "test_name":        test_name,
                "attacker_id":      attacker_id,
                "verdict":          verdict,
                "scenario_summary": scenario_summary,
                "body":             body,  # None if LLM failed
            })

        if not test_entries:
            return False, []

        # Run all generated tests in one forge workspace
        forge_results = self._run_forge_batch(pair_id, test_entries, fn_source)

        poc_results  = []
        poc_verified = False

        for entry in test_entries:
            test_name = entry["test_name"]
            if entry["body"] is None:
                poc_results.append({
                    "attacker_id":      entry["attacker_id"],
                    "verdict":          entry["verdict"],
                    "forge_pass":       False,
                    "test_name":        test_name,
                    "scenario_summary": entry["scenario_summary"],
                    "skip_reason":      "llm_generation_failed",
                })
                continue

            forge_pass = forge_results.get(test_name, False)
            poc_results.append({
                "attacker_id":      entry["attacker_id"],
                "verdict":          entry["verdict"],
                "forge_pass":       forge_pass,
                "test_name":        test_name,
                "scenario_summary": entry["scenario_summary"],
            })
            if forge_pass:
                poc_verified = True

        return poc_verified, poc_results

    # ── LLM test generation ───────────────────────────────────────────────────

    def _llm_generate_scenario_test(
        self,
        fn_source:        str,
        entry_point:      str,
        pre_condition:    str,
        attack_steps:     str,
        expected_outcome: str,
        swc_id:           str,
    ) -> Optional[str]:
        """
        Call LLM with SCENARIO_POC_PROMPT to generate a Forge test body.
        Returns the raw body string (statements inside curly braces), or None on failure.
        """
        prompt = SCENARIO_POC_PROMPT.format(
            function_source  = fn_source or "(source unavailable)",
            entry_point      = entry_point,
            pre_condition    = pre_condition or "none",
            attack_steps     = attack_steps  or "not specified",
            expected_outcome = expected_outcome or "vulnerability triggered",
        )

        try:
            body = self._llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=self._cfg.llm_max_tokens,
            )
            # Strip markdown fences if LLM wraps output
            body = re.sub(r"^```[a-z]*\s*", "", body.strip(), flags=re.IGNORECASE)
            body = re.sub(r"\s*```$", "", body)
            # Sanity check: must contain at least one Solidity statement
            if not any(kw in body for kw in ("assert", "vm.", "require", "revert", "=")):
                logger.debug(f"PoC LLM body for {entry_point}/{swc_id} has no statements — skipping")
                return None
            return body.strip()
        except Exception as e:
            logger.debug(f"PoC LLM generation failed for {entry_point}/{swc_id}: {e}")
            return None

    # ── Forge batch runner ────────────────────────────────────────────────────

    def _run_forge_batch(
        self,
        pair_id:      str,
        test_entries: List[Dict[str, Any]],
        fn_source:    str,
    ) -> Dict[str, bool]:
        """
        Write all generated scenario tests into one .t.sol, compile + run,
        return {test_name: passed} map.
        """
        # Filter to only entries with a valid body
        runnable = [e for e in test_entries if e.get("body")]
        if not runnable:
            return {}

        safe_id   = re.sub(r"[^a-zA-Z0-9]", "_", pair_id)[:20]
        workspace = POC_WORKSPACE_ROOT / f"scenario_{safe_id}"

        try:
            workspace.mkdir(parents=True, exist_ok=True)
            (workspace / "test").mkdir(exist_ok=True)
            (workspace / "src").mkdir(exist_ok=True)

            # Write foundry.toml
            remappings = self._build_remappings()
            remappings_toml = (
                "remappings = [\n"
                + "".join(f'    "{r}",\n' for r in remappings)
                + "]\n"
            ) if remappings else ""

            (workspace / "foundry.toml").write_text(
                "[profile.default]\n"
                'src        = "src"\n'
                'test       = "test"\n'
                'out        = "out"\n'
                'cache_path = "cache"\n'
                + remappings_toml
            )

            # Write test file
            test_sol = self._build_test_file(safe_id, runnable)
            (workspace / "test" / f"_poc_{safe_id}.t.sol").write_text(test_sol)

            # Compile
            build_ok = self._forge_build(workspace, timeout=self._cfg.forge_compile_timeout)
            if not build_ok:
                logger.warning(f"PoC forge build failed for {pair_id}")
                return {}

            # Run tests
            contract_name = f"_poc_{safe_id}"
            return self._forge_test(
                workspace,
                contract_name,
                timeout=self._cfg.forge_test_timeout,
            )

        except Exception as e:
            logger.warning(f"PoC forge batch error for {pair_id}: {e}")
            return {}
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def _build_test_file(self, safe_id: str, entries: List[Dict[str, Any]]) -> str:
        """Assemble a .t.sol test contract with one function per entry."""
        test_fns = []
        for entry in entries:
            body_lines = "\n".join(f"        {ln}" for ln in entry["body"].splitlines())
            test_fns.append(
                f"    function {entry['test_name']}() public {{\n"
                f"{body_lines}\n"
                f"    }}"
            )
        return (
            "// SPDX-License-Identifier: UNLICENSED\n"
            "pragma solidity ^0.8.0;\n\n"
            'import "forge-std/Test.sol";\n\n'
            f"contract _poc_{safe_id} is Test {{\n\n"
            "    function setUp() public {}\n\n"
            + "\n\n".join(test_fns) + "\n"
            "}\n"
        )

    def _build_remappings(self) -> List[str]:
        remappings: List[str] = []
        if POC_SHARED_LIB.exists():
            remappings += [
                "forge-std/=lib/forge-std/src/",
                "hardhat/=lib/hardhat/",
            ]
        return remappings

    # ── Docker/Forge infrastructure ───────────────────────────────────────────

    def _docker_forge(
        self,
        forge_args: List[str],
        workspace:  Path,
        timeout:    int,
        capture_stdout: bool = False,
    ) -> subprocess.CompletedProcess:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{workspace}:/workspace",
            "-w", "/workspace",
        ]
        if POC_SHARED_LIB.exists():
            cmd += ["-v", f"{POC_SHARED_LIB}:/workspace/lib:ro"]
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

    def _forge_build(self, workspace: Path, timeout: int) -> bool:
        try:
            r = self._docker_forge(["build"], workspace=workspace, timeout=timeout)
            stdout = r.stdout.decode(errors="replace") if isinstance(r.stdout, bytes) else (r.stdout or "")
            stderr = r.stderr.decode(errors="replace") if isinstance(r.stderr, bytes) else (r.stderr or "")
            if r.returncode != 0:
                logger.warning(
                    f"PoC: forge build failed (exit={r.returncode})\n"
                    f"  STDOUT: {stdout[:300]}\n  STDERR: {stderr[:300]}"
                )
            return r.returncode == 0
        except subprocess.TimeoutExpired:
            logger.warning("PoC: forge build timed out")
            return False
        except Exception as e:
            logger.warning(f"PoC: forge build error: {e}")
            return False

    def _forge_test(
        self,
        workspace:     Path,
        contract_name: str,
        timeout:       int,
    ) -> Dict[str, bool]:
        """Returns {test_name: passed} from forge --json output."""
        try:
            r = self._docker_forge(
                [
                    "test",
                    "--match-contract", contract_name,
                    "--json",
                ],
                workspace=workspace,
                timeout=timeout,
                capture_stdout=True,
            )
            stderr = r.stderr.decode(errors="replace") if isinstance(r.stderr, bytes) else (r.stderr or "")
            if r.returncode != 0:
                logger.warning(f"PoC: forge test failed (exit={r.returncode}) stderr={stderr[:200]}")
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
                for test_name, test_data in contract_results.get("test_results", {}).items():
                    # forge JSON uses "functionName()" signatures; strip trailing "()"
                    normalized = test_name.rstrip("()")
                    results[normalized] = test_data.get("status") == "Success"
        except Exception:
            pass
        return results
