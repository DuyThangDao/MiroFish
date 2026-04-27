"""
ContractInvariantExtractor — Step 1.5 of invariant-driven adversarial audit.

Two-layer approach:
  Layer 1 (structural): deterministic regex scan — ownership pattern check,
    finds functions writing to mapping[addrParam] without require(msg.sender==addrParam)
  Layer 2 (LLM): missing-enforcement framing — asks "what SHOULD be enforced but ISN'T"
    rather than the old "what IS enforced" approach

Combined output injected into context_summary for:
  - Expert agents: know what to verify
  - Attacker agents: receive concrete violation objectives (Phase C)
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger

logger = get_logger("mirofish.invariant_extractor")

# ─── LLM Prompt — missing enforcement framing ────────────────────────────────

_SYSTEM_PROMPT = """You are a smart contract vulnerability analyst specializing in MISSING enforcement detection.

Your goal is NOT to describe what the contract already enforces (existing require() checks).
Your goal is to identify invariants the protocol INTENDS to maintain but the CODE FAILS to enforce.

Focus on these "absent check" patterns:

1. ACCESS_CONTROL GAPS
   - Functions that modify per-user state (mapping[router][asset], mapping[user][...])
     without requiring msg.sender == that user/router
   - Functions that should be admin-only but have no onlyOwner or equivalent check
   - Pattern: "addLiquidity(router) writes routerBalances[router] but never checks msg.sender == router"

2. STATE_INTEGRITY GAPS
   - State transitions that can be bypassed or left in an inconsistent intermediate state
   - A record can be both active AND completed due to missing mutual exclusion check
   - Pattern: "fulfill() can be called on an already-cancelled tx — no require(status == prepared)"

3. ECONOMIC GAPS
   - Accounting manipulation: balance updated without a corresponding verified transfer
   - ERC20 approval left non-zero after an operation that should clean it up
   - Pattern: "approve(helper, amount) called but never reset to 0 if helper reverts"

4. TEMPORAL GAPS
   - Operations that should have ordering but don't
   - A later-phase function callable before the earlier phase completes
   - Pattern: "cancel() can be called before expiry — no require(block.timestamp > expiry)"

5. ATOMICITY GAPS
   - Multi-step operations where an intermediate state is exploitable by another caller
   - Pattern: "between step 1 (state update) and step 2 (token transfer), reentrancy is possible"

6. ORDERING GAPS (S3a)
   - Operations that MUST happen in a specific sequence but can be called out-of-order
   - Pattern: "interest() must be called BEFORE liquidation check — but liquidate() doesn't enforce this"
   - Pattern: "fee must be accumulated BEFORE updating position — but update() skips accrueFee()"

7. ACCOUNTING INVARIANT VIOLATIONS (S3a)
   - After operation X, a sum/total MUST equal expected value Y — but no post-check exists
   - Pattern: "After swap, reserve0 * reserve1 MUST >= k but no assertion exists"
   - Pattern: "shares/totalSupply must equal assets/totalAssets but mint() doesn't verify ratio"

8. BOUNDARY VIOLATIONS (S3a)
   - Values must stay within [min, max] at all times but bounds not enforced
   - Pattern: "sqrtPrice must be in [MIN_SQRT_RATIO, MAX_SQRT_RATIO] but no clamp after update"
   - Pattern: "Liquidation only when collateralRatio < threshold — code uses <= (off-by-one)"

9. STATE TRANSITION VIOLATIONS (S3a)
   - State machine allows invalid transitions
   - Pattern: "Position can be burned when liquidity > 0 — should require liquidity == 0 first"
   - Pattern: "cancel() callable when status == fulfilled — missing mutual exclusion"

CRITICAL RULES:
- Only report things the code DOES NOT currently have a require() or modifier for
- If you see require(msg.sender == X) already in the code — that one is COVERED, skip it
- violation_hint must be the MISSING line (e.g., "addLiquidity() has no require(msg.sender == router)")
- Maximum 10 invariants — prioritize HIGH-IMPACT missing checks only
- Reference actual function names and state variable names from the source

Return ONLY a JSON object:
{
  "invariants": [
    {
      "id": "INV-001",
      "category": "access_control",
      "statement": "Only the router itself should be able to add or remove its own liquidity",
      "functions": ["addLiquidity", "removeLiquidity"],
      "violation_hint": "addLiquidity(amount, assetId, router) writes routerBalances[router] but has no require(msg.sender == router)"
    }
  ]
}"""


# ─── Domain detection + template invariants (S3b) ────────────────────────────

_DOMAIN_KEYWORDS: Dict[str, List[str]] = {
    "amm_v3": ["sqrtPrice", "tick", "feeGrowth", "secondsPerLiquidity", "tickBitmap", "sqrtRatioX96"],
    "amm_v2": ["reserve0", "reserve1", "kLast", "MINIMUM_LIQUIDITY"],
    "lending": ["collateral", "liquidat", "interestRate", "borrowIndex", "healthFactor"],
    "erc4626": ["totalAssets", "convertToShares", "convertToAssets", "previewDeposit"],
    "bridge":  ["relayer", "executeMessage", "xDomain", "domainSeparator", "nonce"],
}

_DOMAIN_INVARIANTS: Dict[str, List[Dict[str, Any]]] = {
    "amm_v3": [
        {
            "id": "TINV-AMM3-001", "category": "accounting",
            "statement": "feeGrowthInside = feeGrowthGlobal - feeGrowthBelow - feeGrowthAbove (unchecked subtraction intentional for wrap-around)",
            "functions": ["_updatePosition", "collect"],
            "violation_hint": "If feeGrowth subtraction is NOT unchecked{}, it will revert on wrap-around — check all feeGrowth arithmetic",
        },
        {
            "id": "TINV-AMM3-002", "category": "boundary",
            "statement": "sqrtPrice must stay within [MIN_SQRT_RATIO, MAX_SQRT_RATIO] at all times",
            "functions": ["swap", "initialize"],
            "violation_hint": "Check if sqrtPrice clamping exists after price update in swap() — missing clamp = out-of-range price",
        },
        {
            "id": "TINV-AMM3-003", "category": "accounting",
            "statement": "pool.liquidity must equal sum of liquidity of all positions active at current tick",
            "functions": ["mint", "burn", "_updatePosition"],
            "violation_hint": "Verify pool.liquidity is updated correctly in mint/burn — off-by-one in tick range check causes drift",
        },
    ],
    "amm_v2": [
        {
            "id": "TINV-AMM2-001", "category": "accounting",
            "statement": "reserve0 * reserve1 (k) must not decrease after swap (unless fee taken correctly)",
            "functions": ["swap"],
            "violation_hint": "Check k-invariant assertion at end of swap() — missing or using wrong balance snapshot",
        },
    ],
    "lending": [
        {
            "id": "TINV-LEND-001", "category": "ordering",
            "statement": "Interest MUST be accrued before evaluating liquidation threshold",
            "functions": ["liquidate", "isLiquidatable"],
            "violation_hint": "Check if accrueInterest() is called before health factor check in liquidate()",
        },
        {
            "id": "TINV-LEND-002", "category": "boundary",
            "statement": "Liquidation only when collateralRatio STRICTLY less than threshold (< not <=)",
            "functions": ["liquidate", "isLiquidatable"],
            "violation_hint": "Check comparison operator: <= allows liquidation at exact threshold (off-by-one boundary bug)",
        },
    ],
    "erc4626": [
        {
            "id": "TINV-4626-001", "category": "accounting",
            "statement": "shares/totalSupply must equal assets/totalAssets (ERC4626 share price invariant)",
            "functions": ["deposit", "withdraw", "mint", "redeem"],
            "violation_hint": "Check if totalAssets() and totalSupply stay in sync after each operation — inflation attack vector",
        },
    ],
}


def _detect_domain(source_code: str) -> Optional[str]:
    """Keyword-scan first 50K chars to detect protocol domain. Returns domain key or None."""
    sample = source_code[:50_000]
    scores: Dict[str, int] = {}
    for domain, keywords in _DOMAIN_KEYWORDS.items():
        count = sum(sample.count(kw) for kw in keywords)
        if count > 0:
            scores[domain] = count
    if not scores:
        return None
    return max(scores, key=lambda d: scores[d])


# ─── Structural scan helpers ─────────────────────────────────────────────────

# Match: function name(params) [modifiers...] {
_FUNC_SIG_RE = re.compile(
    r'function\s+(\w+)\s*\(([^)]*)\)'
    r'(?:\s+(?:external|public|internal|private|payable|view|pure|virtual|override'
    r'|returns\s*\([^)]*\)|\w+))*\s*\{',
    re.IGNORECASE,
)

# Match: require(msg.sender == <ident> or <ident> == msg.sender)
_SENDER_CHECK_RE = re.compile(
    r'require\s*\(\s*(?:msg\.sender\s*==\s*(\w+)|(\w+)\s*==\s*msg\.sender)',
    re.IGNORECASE,
)

# Match modifier calls that are common ownership guards
_OWNERSHIP_MODIFIER_RE = re.compile(
    r'\b(onlyOwner|onlyAdmin|onlyRouter|onlyRole|isAuthorized|_checkOwner)\b',
    re.IGNORECASE,
)


def _extract_body(source: str, open_brace_pos: int, max_chars: int = 3000) -> str:
    """Return function body text by counting braces from opening {."""
    depth = 0
    for i in range(open_brace_pos, min(open_brace_pos + max_chars, len(source))):
        ch = source[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return source[open_brace_pos: i + 1]
    return source[open_brace_pos: open_brace_pos + max_chars]


def _structural_ownership_scan(source_code: str) -> List[Dict[str, Any]]:
    """
    Deterministic Layer-1 scan.

    Finds functions that:
      1. Accept an address parameter  (e.g., address router)
      2. Write to a mapping keyed by that parameter (e.g., routerBalances[router] = ...)
      3. Have NO require(msg.sender == router) or ownership modifier

    Returns list of invariant dicts (same schema as LLM output, with source="structural").
    """
    findings: List[Dict[str, Any]] = []
    seen: set = set()

    for m in _FUNC_SIG_RE.finditer(source_code):
        func_name = m.group(1)
        params_str = m.group(2)

        # Skip view/pure (no state mutation)
        pre_brace = source_code[m.start(): m.end()]
        if re.search(r'\b(view|pure)\b', pre_brace):
            continue

        # Collect address-typed parameter names
        addr_params = re.findall(r'\baddress\s+(\w+)', params_str)
        if not addr_params:
            continue

        body = _extract_body(source_code, m.end() - 1)

        # Check for ownership modifiers in signature
        sig_has_guard = bool(_OWNERSHIP_MODIFIER_RE.search(pre_brace))

        for addr_param in addr_params:
            key = (func_name, addr_param)
            if key in seen:
                continue

            # Does the body write to mapping[addr_param]?
            mapping_write = bool(re.search(
                rf'\b\w+\[{re.escape(addr_param)}\](?:\[\w+\])?\s*[+\-]?=',
                body,
            ))
            if not mapping_write:
                continue

            # Does the function have a msg.sender check for this param?
            sender_checks = _SENDER_CHECK_RE.findall(body)
            checked_idents = {g for pair in sender_checks for g in pair if g}
            has_sender_guard = addr_param in checked_idents or sig_has_guard

            if not has_sender_guard:
                seen.add(key)
                findings.append({
                    "id":             f"SINV-{len(findings)+1:03d}",
                    "category":       "access_control",
                    "statement":      (
                        f"Only the address passed as `{addr_param}` should be able to "
                        f"modify its own state via `{func_name}()`"
                    ),
                    "functions":      [func_name],
                    "violation_hint": (
                        f"`{func_name}()` writes to a mapping keyed by `{addr_param}` "
                        f"but has no `require(msg.sender == {addr_param})`"
                    ),
                    "source":         "structural",
                })

    if findings:
        logger.info(
            f"Structural scan: {len(findings)} ownership gap(s): "
            + ", ".join(f"{f['functions'][0]}({f['id']})" for f in findings)
        )
    else:
        logger.info("Structural scan: no ownership gaps found")

    return findings


# ─── Shared helpers ───────────────────────────────────────────────────────────

def _parse_invariants(raw: Any) -> List[Dict[str, Any]]:
    """Validate and normalise LLM output."""
    if isinstance(raw, dict):
        items = raw.get("invariants", [])
    elif isinstance(raw, list):
        items = raw
    else:
        return []

    valid_cats = {
        "access_control", "state_integrity", "economic", "temporal", "atomicity",
        "ordering", "accounting", "boundary", "state_transition",  # S3a additions
    }
    result = []
    for i, item in enumerate(items[:10]):
        if not isinstance(item, dict):
            continue
        inv_id = item.get("id") or f"INV-{i+1:03d}"
        cat    = item.get("category", "state_integrity").lower()
        if cat not in valid_cats:
            cat = "state_integrity"
        stmt = str(item.get("statement", "")).strip()
        if not stmt:
            continue
        funcs = item.get("functions") or []
        if not isinstance(funcs, list):
            funcs = [str(funcs)]
        hint = str(item.get("violation_hint", "")).strip()
        result.append({
            "id":             inv_id,
            "category":       cat,
            "statement":      stmt,
            "functions":      [str(f) for f in funcs],
            "violation_hint": hint,
        })
    return result


def _build_invariant_section(invariants: List[Dict[str, Any]]) -> str:
    """Format invariants for injection into context_summary."""
    if not invariants:
        return ""
    structural = [i for i in invariants if i.get("source") == "structural"]
    templates  = [i for i in invariants if i.get("source") == "template"]
    llm_based  = [i for i in invariants if i.get("source") not in ("structural", "template")]

    lines = ["MISSING ENFORCEMENT TARGETS (verify each — these checks are ABSENT from code):"]

    if structural:
        lines.append("  [STRUCTURAL — deterministic scan]")
        for inv in structural:
            funcs_str = ", ".join(inv["functions"]) if inv["functions"] else "—"
            lines.append(
                f"  [{inv['id']}] {inv['category']}: {inv['statement']}\n"
                f"            functions: {funcs_str}\n"
                f"            MISSING CHECK: {inv['violation_hint']}"
            )

    if templates:
        lines.append("  [DOMAIN TEMPLATE — protocol-class invariants]")
        for inv in templates:
            funcs_str = ", ".join(inv["functions"]) if inv["functions"] else "—"
            hint_str  = f"\n            CHECK: {inv['violation_hint']}" if inv.get("violation_hint") else ""
            lines.append(
                f"  [{inv['id']}] {inv['category']}: {inv['statement']}\n"
                f"            functions: {funcs_str}{hint_str}"
            )

    if llm_based:
        lines.append("  [LLM-DERIVED — semantic analysis]")
        for inv in llm_based:
            funcs_str = ", ".join(inv["functions"]) if inv["functions"] else "—"
            hint_str  = f"\n            MISSING CHECK: {inv['violation_hint']}" if inv["violation_hint"] else ""
            lines.append(
                f"  [{inv['id']}] {inv['category']}: {inv['statement']}\n"
                f"            functions: {funcs_str}{hint_str}"
            )

    lines.append("")
    return "\n".join(lines)


# ─── Extractor class ──────────────────────────────────────────────────────────

class ContractInvariantExtractor:
    """
    Two-layer invariant extractor.

    Layer 1 (structural): deterministic ownership-gap scan — no LLM needed.
    Layer 2 (LLM):        missing-enforcement framing — "what SHOULD be checked but isn't".

    Both layers use the same output schema and are merged before injection.

    Usage:
        extractor = ContractInvariantExtractor()
        result = extractor.extract(source_code=src, context_summary=summary)
        invariants       = result["invariants"]        # list[dict]
        enriched_summary = result["enriched_summary"]  # context_summary + missing-checks section
    """

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or LLMClient()

    def extract(
        self,
        source_code: str,
        context_summary: str,
        max_source_chars: int = 40_000,
    ) -> Dict[str, Any]:
        """
        Extract missing enforcements. Never raises — returns empty on failure.
        Structural scan always runs; LLM layer falls back to [] on error.
        """
        # ── Layer 1: structural ──────────────────────────────────────────────
        structural_invs = _structural_ownership_scan(source_code)

        # ── Layer 1.5: domain template invariants (S3b) ──────────────────────
        domain = _detect_domain(source_code)
        template_invs: List[Dict[str, Any]] = []
        if domain and domain in _DOMAIN_INVARIANTS:
            template_invs = [dict(inv, source="template") for inv in _DOMAIN_INVARIANTS[domain]]
            logger.info(f"Domain detected: {domain} — injecting {len(template_invs)} template invariants")

        # ── Layer 2: LLM (missing-enforcement framing) ───────────────────────
        truncated_src = source_code[:max_source_chars]
        if len(source_code) > max_source_chars:
            truncated_src += f"\n// ... [{len(source_code) - max_source_chars} chars truncated]"

        # Tell LLM what structural scan already found so it doesn't duplicate
        structural_note = ""
        if structural_invs:
            funcs_found = ", ".join(
                f"{i['functions'][0]}({i['id']})" for i in structural_invs
            )
            structural_note = (
                f"\n\nNOTE: Structural scan already found these ownership gaps: {funcs_found}. "
                "Do NOT duplicate these. Focus on STATE_INTEGRITY, ECONOMIC, TEMPORAL, ATOMICITY gaps instead."
            )

        user_content = (
            f"CONTRACT SOURCE:\n```solidity\n{truncated_src}\n```\n\n"
            f"CONTEXT SUMMARY:\n{context_summary[:5000]}\n"
            f"{structural_note}\n\n"
            "Identify missing enforcement patterns as JSON. "
            "Only report things NOT already enforced by existing require() statements."
        )

        llm_invs: List[Dict[str, Any]] = []
        try:
            raw = self.llm.chat_json(
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": user_content},
                ],
                temperature=0.2,
                max_tokens=4096,
            )
            llm_invs = _parse_invariants(raw)
        except Exception as e:
            err_str = str(e)
            if "JSON" in err_str or "json" in err_str:
                repaired = self._repair_truncated_json(err_str)
                if repaired:
                    llm_invs = _parse_invariants(repaired)
                    if llm_invs:
                        logger.info(f"JSON repair: recovered {len(llm_invs)} LLM invariants")
            if not llm_invs:
                logger.warning(f"LLM invariant extraction failed: {e}")

        if llm_invs:
            logger.info(
                f"LLM invariants ({len(llm_invs)}): "
                + ", ".join(f"{i['id']}({i['category']})" for i in llm_invs)
            )

        # ── Merge: structural → domain templates → LLM ───────────────────────
        invariants = structural_invs + template_invs + llm_invs

        if invariants:
            logger.info(
                f"Total invariants: {len(invariants)} "
                f"({len(structural_invs)} structural + {len(llm_invs)} LLM)"
            )
        else:
            logger.info("No invariants extracted — open-ended scan only")

        inv_section      = _build_invariant_section(invariants)
        enriched_summary = (
            context_summary.rstrip() + "\n\n" + inv_section
            if inv_section
            else context_summary
        )

        return {
            "invariants":       invariants,
            "enriched_summary": enriched_summary,
        }

    @staticmethod
    def _repair_truncated_json(error_str: str) -> Optional[Dict[str, Any]]:
        """Repair truncated JSON from a ValueError message (max_tokens cutoff)."""
        brace_idx = error_str.find("{")
        if brace_idx == -1:
            return None
        fragment = error_str[brace_idx:]
        for suffix in [" — proceeding without invariants", " — proceeding"]:
            if suffix in fragment:
                fragment = fragment[:fragment.index(suffix)]
        for closing in ["]}", "\n  }\n  ]\n}", "\n  }\n]}"]:
            try:
                return json.loads(fragment + closing)
            except json.JSONDecodeError:
                pass
        last_close = fragment.rfind("}")
        if last_close > 0:
            truncated = fragment[:last_close + 1]
            for closing in ["]}", "\n]}"]:
                try:
                    return json.loads(truncated + closing)
                except json.JSONDecodeError:
                    pass
        return None
