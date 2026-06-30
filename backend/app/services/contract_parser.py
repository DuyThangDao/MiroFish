"""
Solidity Contract Parser — Smart Contract Audit.

Parse Solidity source code → ContractEntity using LLM extraction + regex static scan.
Strategy: LLM-based extraction (no Solidity compiler or complex toolchain required).
"""

import re
import json
import uuid
from typing import List, Optional, Dict, Any

from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger
from ..models.contract_models import (
    ContractEntity,
    ContractFunction,
    ContractStateVar,
    ContractType,
    FunctionVisibility,
)

logger = get_logger("mirofish.contract_parser")


# ─── Static SWC patterns (regex-based, deterministic) ────────────────────────

_STATIC_PATTERNS: List[Dict[str, Any]] = [
    {
        "swc_id": "SWC-107",
        "name": "Reentrancy",
        # external call via .call{value / .call( before state update
        "regex": re.compile(r'\.call\s*\{?\s*value', re.IGNORECASE),
        "description": "External ETH transfer via low-level call (potential reentrancy)",
    },
    {
        "swc_id": "SWC-107",
        "name": "Reentrancy (transfer/send)",
        "regex": re.compile(r'\.\s*transfer\s*\(|\.\s*send\s*\(', re.IGNORECASE),
        "description": "Ether send via transfer/send (potential reentrancy if before state update)",
    },
    {
        "swc_id": "SWC-115",
        "name": "tx.origin Authorization",
        "regex": re.compile(r'\btx\s*\.\s*origin\b'),
        "description": "Authorization using tx.origin — phishing vulnerability",
    },
    {
        "swc_id": "SWC-116",
        "name": "Block Timestamp Dependence",
        "regex": re.compile(r'\bblock\s*\.\s*timestamp\b'),
        "description": "block.timestamp used in logic — miner-manipulable",
    },
    {
        "swc_id": "SWC-120",
        "name": "Weak Randomness",
        "regex": re.compile(r'\bblock\s*\.\s*(difficulty|prevrandao|number|blockhash)\b'),
        "description": "Chain attribute used as randomness source",
    },
    {
        "swc_id": "SWC-112",
        "name": "Delegatecall",
        "regex": re.compile(r'\bdelegatecall\b'),
        "description": "delegatecall detected — verify callee is trusted",
    },
    {
        "swc_id": "SWC-106",
        "name": "Selfdestruct",
        "regex": re.compile(r'\bselfdestruct\b|\bsuicide\b'),
        "description": "selfdestruct/suicide instruction — verify access control",
    },
    {
        "swc_id": "SWC-101",
        "name": "Potential Integer Overflow",
        "regex": re.compile(r'pragma\s+solidity\s+[^0-9]*0\.[0-7]', re.IGNORECASE),
        "description": "Pre-0.8 compiler: no automatic overflow protection",
    },
    {
        "swc_id": "SWC-133",
        "name": "ABI encodePacked Hash Collision",
        "regex": re.compile(r'abi\s*\.\s*encodePacked\s*\(', re.IGNORECASE),
        "description": "abi.encodePacked — verify no hash collision risk with multiple dynamic types",
    },
    {
        "swc_id": "SWC-121",
        "name": "Signature Without Nonce/ChainId",
        "regex": re.compile(r'\becrecover\b'),
        "description": "ecrecover found — verify nonce and chainId binding",
    },
]

# Contract type detection heuristics
_CONTRACT_TYPE_HINTS: List[Dict[str, Any]] = [
    {"keywords": ["IERC20", "ERC20", "balanceOf", "totalSupply", "allowance"],
     "type": ContractType.ERC20.value},
    {"keywords": ["IERC721", "ERC721", "ownerOf", "tokenURI", "safeTransferFrom"],
     "type": ContractType.ERC721.value},
    {"keywords": ["borrow", "liquidate", "collateral", "repay", "flashLoan"],
     "type": ContractType.DEFI_LENDING.value},
    {"keywords": ["swap", "addLiquidity", "removeLiquidity", "getAmountsOut", "getReserves"],
     "type": ContractType.DEFI_AMM.value},
    {"keywords": ["propose", "castVote", "queue", "execute", "timelock", "Governor"],
     "type": ContractType.GOVERNANCE.value},
    {"keywords": ["lockTokens", "bridge", "attestation", "deposit", "unlock", "crossChain"],
     "type": ContractType.BRIDGE.value},
    {"keywords": ["vault", "harvest", "strategy", "yield", "earnedTokens"],
     "type": ContractType.VAULT.value},
]


class ContractParser:
    """
    Parse Solidity source code → ContractEntity.

    Strategy:
    1. Static regex scan — fast, deterministic, extracts SWC candidates + boolean flags.
    2. LLM-based extraction — for structured ContractFunction + ContractStateVar.

    No Solidity compiler or solc toolchain needed — LLM is sufficient for structure extraction.
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or LLMClient()

    # ─── Public API ───────────────────────────────────────────────────────────

    def parse_from_source(
        self,
        source_code: str,
        contract_name: str = "",
    ) -> ContractEntity:
        """
        Parse Solidity source → ContractEntity.

        Step 1: Static scan (no LLM, instant)
        Step 2: LLM structural extraction
        Step 3: Merge + build ContractEntity
        """
        logger.info(f"Parsing contract: {contract_name or 'unnamed'} ({len(source_code)} chars)")

        # Step 1: Static scan
        static_candidates = self._static_swc_scan(source_code)
        contract_type = self._detect_contract_type(source_code)
        boolean_flags = self._detect_boolean_flags(source_code)
        compiler_version = self._extract_compiler_version(source_code)

        # Step 2: LLM extraction
        try:
            llm_data = self._extract_structure_with_llm(source_code, contract_name)
        except Exception as e:
            logger.warning(f"LLM extraction failed, using static-only: {e}")
            llm_data = {}

        # Step 3: Build ContractEntity
        # Validate LLM contract_name: reject if the name doesn't appear as an actual
        # 'contract Foo' declaration (guards against LLM hallucinating names from comments)
        llm_name = llm_data.get("contract_name", "")
        if llm_name and not re.search(rf'\bcontract\s+{re.escape(llm_name)}\b', source_code):
            llm_name = ""
        contract_id = (
            contract_name
            or llm_name
            or self._detect_contract_name(source_code)
            or f"Contract_{uuid.uuid4().hex[:6]}"
        )

        functions = self._build_functions(llm_data.get("functions", []), source_code)
        state_vars = self._build_state_vars(llm_data.get("state_vars", []))
        external_deps = llm_data.get("external_dependencies", self._detect_imports(source_code))

        # Merge SWC candidates from static scan + LLM
        llm_candidates = llm_data.get("swc_candidates", [])
        all_candidates = list(dict.fromkeys(static_candidates + llm_candidates))

        entity = ContractEntity(
            contract_id=contract_id,
            source_code=source_code,
            compiler_version=compiler_version,
            contract_type=llm_data.get("contract_type", contract_type),
            functions=functions,
            state_vars=state_vars,
            external_dependencies=external_deps,
            has_reentrancy_guard=boolean_flags["has_reentrancy_guard"],
            has_access_control=boolean_flags["has_access_control"],
            has_pausable=boolean_flags["has_pausable"],
            uses_oracle=boolean_flags["uses_oracle"],
            uses_flash_loan=boolean_flags["uses_flash_loan"],
            is_upgradeable=boolean_flags["is_upgradeable"],
            swc_candidates=all_candidates,
            raw_text=llm_data.get("notes", ""),
        )

        logger.info(
            f"Parsed: {contract_id} | type={entity.contract_type} | "
            f"funcs={len(functions)} | vars={len(state_vars)} | "
            f"SWC_candidates={all_candidates}"
        )
        return entity

    def parse_from_text_description(self, description: str) -> ContractEntity:
        """
        When no source code is available — only a text description.
        LLM creates a ContractEntity from the description.
        Used for testing with datasets that lack full source (e.g., SmartBugs text descriptions).
        """
        logger.info(f"Parsing from text description ({len(description)} chars)")

        prompt = f"""You are a smart contract security analyst.
Based on the following contract description, create a structured representation of the contract.

Return JSON with this structure:
{{
  "contract_name": "...",
  "compiler_version": "unknown",
  "contract_type": "Custom",
  "functions": [
    {{
      "name": "functionName",
      "visibility": "public|private|internal|external",
      "modifiers": [],
      "has_external_call": false,
      "state_updates": [],
      "external_call_before_state": false,
      "sends_ether": false,
      "parameters": [],
      "return_types": [],
      "swc_candidates": []
    }}
  ],
  "state_vars": [
    {{
      "name": "varName",
      "var_type": "uint256",
      "visibility": "private",
      "is_critical": false,
      "modified_by": []
    }}
  ],
  "external_dependencies": [],
  "has_reentrancy_guard": false,
  "has_access_control": false,
  "has_pausable": false,
  "uses_oracle": false,
  "uses_flash_loan": false,
  "is_upgradeable": false,
  "swc_candidates": [],
  "notes": "..."
}}

Contract description:
{description[:3000]}

Return ONLY valid JSON, no explanation."""

        raw = self.llm.chat(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=2000,
        )
        data = self._safe_json_parse(raw, {})

        return ContractEntity(
            contract_id=data.get("contract_name", f"Contract_{uuid.uuid4().hex[:6]}"),
            source_code="",
            compiler_version=data.get("compiler_version", "unknown"),
            contract_type=data.get("contract_type", "Custom"),
            functions=self._build_functions(data.get("functions", []), ""),
            state_vars=self._build_state_vars(data.get("state_vars", [])),
            external_dependencies=data.get("external_dependencies", []),
            has_reentrancy_guard=bool(data.get("has_reentrancy_guard", False)),
            has_access_control=bool(data.get("has_access_control", False)),
            has_pausable=bool(data.get("has_pausable", False)),
            uses_oracle=bool(data.get("uses_oracle", False)),
            uses_flash_loan=bool(data.get("uses_flash_loan", False)),
            is_upgradeable=bool(data.get("is_upgradeable", False)),
            swc_candidates=data.get("swc_candidates", []),
            raw_text=data.get("notes", description[:500]),
        )

    # ─── Static analysis (no LLM) ─────────────────────────────────────────────

    def _static_swc_scan(self, source_code: str) -> List[str]:
        """
        Regex-based preliminary scan — fast, deterministic, no LLM.
        Finds obvious SWC patterns and returns unique SWC IDs.
        """
        found: List[str] = []
        for pattern in _STATIC_PATTERNS:
            if pattern["regex"].search(source_code):
                swc_id = pattern["swc_id"]
                if swc_id not in found:
                    found.append(swc_id)
                    logger.debug(f"Static scan: {swc_id} — {pattern['name']}")
        return found

    def _detect_contract_type(self, source_code: str) -> str:
        """Heuristic detection of contract type from keywords."""
        for hint in _CONTRACT_TYPE_HINTS:
            if any(kw in source_code for kw in hint["keywords"]):
                return hint["type"]
        return ContractType.CUSTOM.value

    def _detect_boolean_flags(self, source_code: str) -> Dict[str, bool]:
        """
        Detect security flags via keyword search.
        Returns dict matching ContractEntity boolean fields.
        """
        src_lower = source_code.lower()
        return {
            "has_reentrancy_guard": bool(re.search(
                r'nonreentrant|reentrancyguard|_not_entered|_entered', src_lower
            )),
            "has_access_control": bool(re.search(
                r'onlyowner|onlyrole|accesscontrol|hasrole|msg\.sender\s*==\s*owner', src_lower
            )),
            "has_pausable": bool(re.search(
                r'whennotpaused|paused\b|_pause\b|pausable', src_lower
            )),
            "uses_oracle": bool(re.search(
                r'chainlink|ioracle|pricefeed|latestrounddata|oracle\b|twap|aggregator', src_lower
            )),
            "uses_flash_loan": bool(re.search(
                r'flashloan|flash_loan|executeflash|onflashlen|receiveraddress\b|iflashloan', src_lower
            )),
            "is_upgradeable": bool(re.search(
                r'upgradeable|uups|transparentproxy|delegatecall.*implementation|_implementation\b', src_lower
            )),
        }

    def _extract_compiler_version(self, source_code: str) -> str:
        """Extract pragma solidity version."""
        m = re.search(r'pragma\s+solidity\s+([^;]+);', source_code)
        if m:
            return m.group(1).strip()
        return "unknown"

    def _detect_contract_name(self, source_code: str) -> str:
        """Extract contract name from 'contract Foo {' declaration."""
        m = re.search(r'\bcontract\s+(\w+)', source_code)
        return m.group(1) if m else ""

    def _detect_imports(self, source_code: str) -> List[str]:
        """Extract import statements as external dependencies."""
        return re.findall(r'import\s+["\']([^"\']+)["\']', source_code)

    # ─── LLM extraction ───────────────────────────────────────────────────────

    def _extract_structure_with_llm(
        self,
        source_code: str,
        contract_name: str,
    ) -> Dict[str, Any]:
        """
        Send source code to LLM → extract structured data.
        Returns raw dict (functions, state_vars, type, etc.)
        """
        # For multi-contract flat files, focus on the last 'contract Foo' declaration
        # (implementations appear after interfaces/libraries in topological order)
        code_snippet = source_code
        if len(source_code) > 6000:
            last_contract = None
            for m in re.finditer(r'\bcontract\s+\w+', source_code):
                last_contract = m
            if last_contract:
                code_snippet = source_code[last_contract.start():][:8000]
            else:
                code_snippet = source_code[:6000]
        name_hint = f" The contract is named '{contract_name}'." if contract_name else ""

        prompt = f"""You are a Solidity smart contract security analyzer.{name_hint}
Analyze this Solidity source code and extract its structure for security auditing.

Return JSON with this exact structure:
{{
  "contract_name": "ContractName",
  "contract_type": "ERC20|ERC721|DeFi_Lending|DeFi_AMM|Governance|Bridge|Vault|Custom",
  "functions": [
    {{
      "name": "withdraw",
      "visibility": "public",
      "modifiers": ["onlyOwner"],
      "has_external_call": true,
      "state_updates": ["balances"],
      "external_call_before_state": true,
      "sends_ether": true,
      "parameters": ["uint256 amount"],
      "return_types": [],
      "swc_candidates": ["SWC-107"],
      "source_lines": "45-67"
    }}
  ],
  "state_vars": [
    {{
      "name": "balances",
      "var_type": "mapping(address => uint256)",
      "visibility": "private",
      "is_critical": true,
      "modified_by": ["deposit", "withdraw"]
    }}
  ],
  "external_dependencies": ["OpenZeppelin/Ownable", "IERC20"],
  "swc_candidates": ["SWC-107", "SWC-115"],
  "notes": "Any relevant security observations"
}}

Rules:
- external_call_before_state: true if an external call (call/transfer/send/delegatecall) happens BEFORE state variable updates in same function
- is_critical state var: true for balance mappings, owner, admin roles, token addresses
- swc_candidates: only include IDs you are highly confident about from the code
- For functions that send ETH, set sends_ether=true

Solidity source:
```solidity
{code_snippet}
```

Return ONLY valid JSON, no explanation, no markdown."""

        raw = self.llm.chat(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=3000,
        )
        return self._safe_json_parse(raw, {})

    # ─── Data builders ────────────────────────────────────────────────────────

    def _build_functions(
        self,
        raw_functions: List[Dict[str, Any]],
        source_code: str,
    ) -> List[ContractFunction]:
        """Convert raw LLM dict list → List[ContractFunction]."""
        result = []
        for f in raw_functions:
            if not isinstance(f, dict):
                continue
            name = f.get("name", "")
            if not name:
                continue

            visibility = f.get("visibility", "public")
            if visibility not in ("public", "private", "internal", "external"):
                visibility = "public"

            # Per-function static scan if we have source
            per_func_candidates = list(f.get("swc_candidates", []))
            if source_code and name:
                func_block = self._extract_function_block(source_code, name)
                if func_block:
                    extra = self._static_swc_scan(func_block)
                    for swc in extra:
                        if swc not in per_func_candidates:
                            per_func_candidates.append(swc)

            result.append(ContractFunction(
                name=name,
                visibility=visibility,
                modifiers=f.get("modifiers", []),
                has_external_call=bool(f.get("has_external_call", False)),
                state_updates=f.get("state_updates", []),
                external_call_before_state=bool(f.get("external_call_before_state", False)),
                sends_ether=bool(f.get("sends_ether", False)),
                parameters=f.get("parameters", []),
                return_types=f.get("return_types", []),
                swc_candidates=per_func_candidates,
                source_lines=f.get("source_lines"),
            ))
        return result

    def _build_state_vars(self, raw_vars: List[Dict[str, Any]]) -> List[ContractStateVar]:
        """Convert raw LLM dict list → List[ContractStateVar]."""
        result = []
        for v in raw_vars:
            if not isinstance(v, dict):
                continue
            name = v.get("name", "")
            if not name:
                continue
            visibility = v.get("visibility", "private")
            if visibility not in ("public", "private", "internal", "external"):
                visibility = "private"
            result.append(ContractStateVar(
                name=name,
                var_type=v.get("var_type", "unknown"),
                visibility=visibility,
                is_critical=bool(v.get("is_critical", False)),
                modified_by=v.get("modified_by", []),
            ))
        return result

    def _extract_function_block(self, source_code: str, func_name: str) -> str:
        """
        Extract the source block of a specific function by name.
        Simple brace-counting approach — not a full parser but sufficient for static scan.
        """
        pattern = re.compile(
            r'\bfunction\s+' + re.escape(func_name) + r'\b[^{]*\{',
            re.DOTALL
        )
        m = pattern.search(source_code)
        if not m:
            return ""

        start = m.start()
        brace_count = 0
        for i, ch in enumerate(source_code[m.start():], start=m.start()):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    return source_code[start:i + 1]
        return source_code[start:start + 500]

    # ─── JSON parsing ─────────────────────────────────────────────────────────

    def _safe_json_parse(self, raw: str, fallback: Any) -> Any:
        """
        Parse JSON from LLM response.
        Strips markdown code fences and think tags before parsing.
        """
        if not raw:
            return fallback

        # Strip <think>...</think> blocks (reasoning models)
        raw = re.sub(r'<think>.*?</think>', '', raw, flags=re.DOTALL).strip()

        # Strip markdown code fences
        raw = re.sub(r'^```(?:json)?\s*', '', raw.strip(), flags=re.MULTILINE)
        raw = re.sub(r'\s*```$', '', raw.strip(), flags=re.MULTILINE)

        # Extract first {...} block
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            raw = m.group(0)

        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse failed: {e}. Raw snippet: {raw[:200]}")
            return fallback
