"""
ContractIntentExtractor — Step 1.1 of intent-aware audit (S5).

Extracts "protocol MUST" statements from:
  1. NatSpec @notice / @dev comments (deterministic, no LLM)
  2. Function signatures + require messages (LLM-inferred)
  3. Contest README if provided

Output: "PROTOCOL INTENT" section injected into context_summary.
Runs after KG Build (Step 1) so LLM receives KG-enriched summary as context.

Dedup guard: checks for existing "PROTOCOL INTENT" marker in context_summary
before injecting, to avoid duplication when KG builder also parses NatSpec.
"""

import re
from typing import Dict, List, Optional

from ..utils.llm_client import LLMClient
from ..utils.logger import get_logger

logger = get_logger("mirofish.intent_extractor")


# ─── NatSpec extraction (deterministic, no LLM) ──────────────────────────────

# Matches /** ... */ or consecutive /// lines immediately before a function
_NATSPEC_BLOCK_RE = re.compile(
    r'(/\*\*.*?\*/|(?:///[^\n]*\n)+)\s*function\s+(\w+)\s*\(',
    re.DOTALL,
)


def _extract_natspec_hints(source_code: str) -> List[Dict[str, str]]:
    """
    Parse @notice and @dev tags from NatSpec blocks before function definitions.
    Returns list of {function, notice, dev} dicts.
    """
    hints = []
    for m in _NATSPEC_BLOCK_RE.finditer(source_code[:80_000]):
        block = m.group(1)
        func  = m.group(2)
        notice = " ".join(re.findall(r'@notice\s+(.+?)(?=@|\*/|$)', block, re.DOTALL)).strip()
        dev    = " ".join(re.findall(r'@dev\s+(.+?)(?=@|\*/|$)', block, re.DOTALL)).strip()
        if notice or dev:
            hints.append({"function": func, "notice": notice, "dev": dev})
    return hints


# ─── LLM Prompt ──────────────────────────────────────────────────────────────

_INTENT_SYSTEM_PROMPT = """You are a smart contract protocol analyst.

Given Solidity source code (with NatSpec comments), extract PROTOCOL INTENT statements —
things the protocol MUST do, MUST NOT do, or MUST maintain. These represent design intent
that, if violated in the implementation, would constitute a critical bug.

Focus on:
1. ORDERING: "X must happen BEFORE Y" — e.g., "interest must accrue before liquidation check"
2. BOUNDARY: "Value V must be strictly < threshold" (< vs <= matters) — e.g., "liquidation only when ratio < min"
3. ACCOUNTING: "After operation X, invariant Y must hold" — e.g., "k must not decrease after swap"
4. STATE: "Function F can only be called when state S" — e.g., "burn requires liquidity == 0 first"
5. EFFECT: "Operation X MUST have side-effect Y" — e.g., "withdraw must decrease totalAssets by exact amount"

Extract from (in priority order):
- @notice and @dev NatSpec comments
- require() / revert messages (often describe what SHOULD be true)
- Function and parameter names (infer intent)

Return JSON:
{
  "intent_statements": [
    {
      "type": "ORDERING|BOUNDARY|ACCOUNTING|STATE|EFFECT",
      "statement": "concise protocol must-statement",
      "function": "relevant function name",
      "source": "natspec|inferred"
    }
  ]
}

Max 10 statements. Prioritize HIGH-IMPACT ones where a wrong implementation = critical bug.
Do NOT include statements already guaranteed by Solidity (e.g. integer overflow in 0.8 without unchecked)."""


class ContractIntentExtractor:
    """
    Extracts protocol intent from NatSpec + function signatures.
    Result injected as PROTOCOL INTENT block into context_summary.

    Usage:
        extractor = ContractIntentExtractor(llm_client=boost_llm)
        result = extractor.extract(source_code, context_summary, readme)
        contract_summary = result["enriched_summary"]
    """

    def __init__(self, llm_client: Optional[LLMClient] = None) -> None:
        self.llm = llm_client or LLMClient()

    def extract(
        self,
        source_code: str,
        context_summary: str,
        readme: Optional[str] = None,
        max_source_chars: int = 50_000,
    ) -> Dict:
        """
        Returns {"intent_statements": [...], "enriched_summary": str}.
        Never raises — falls back gracefully on LLM error.

        Dedup guard: if context_summary already contains "PROTOCOL INTENT",
        skips injection to avoid duplicating NatSpec content that KG builder
        may have already included.
        """
        # Dedup guard: skip if already injected
        if "PROTOCOL INTENT" in context_summary:
            logger.info("Intent extractor: PROTOCOL INTENT already present in summary — skipping")
            return {"intent_statements": [], "enriched_summary": context_summary}

        # Layer 1: deterministic NatSpec extraction (no LLM cost)
        natspec_hints = _extract_natspec_hints(source_code)
        logger.info(f"NatSpec hints: {len(natspec_hints)} functions with @notice/@dev")

        # Layer 2: LLM extraction
        truncated = source_code[:max_source_chars]
        if len(source_code) > max_source_chars:
            truncated += f"\n// ... [{len(source_code) - max_source_chars} chars truncated]"

        readme_section = f"\nCONTEST README:\n{readme[:3000]}\n" if readme else ""
        natspec_section = ""
        if natspec_hints:
            natspec_section = "\nNATSPEC EXTRACTED:\n" + "\n".join(
                f"  {h['function']}(): {(h['notice'] + ' ' + h['dev']).strip()}"
                for h in natspec_hints[:15]
            ) + "\n"

        user_content = (
            f"CONTRACT SOURCE:\n```solidity\n{truncated}\n```"
            f"{readme_section}"
            f"{natspec_section}"
            f"\nKG CONTEXT SUMMARY (first 3000 chars):\n{context_summary[:3000]}\n\n"
            "Extract protocol intent statements as JSON."
        )

        intent_statements: List[Dict] = []
        try:
            raw = self.llm.chat_json(
                messages=[
                    {"role": "system", "content": _INTENT_SYSTEM_PROMPT},
                    {"role": "user",   "content": user_content},
                ],
                temperature=0.2,
                max_tokens=2048,
            )
            if isinstance(raw, dict):
                intent_statements = raw.get("intent_statements", [])[:10]
        except Exception as e:
            logger.warning(f"Intent extraction LLM failed: {e}")

        if intent_statements:
            logger.info(
                f"Intent statements: {len(intent_statements)} — "
                + ", ".join(s.get("type", "?") for s in intent_statements[:5])
            )

        # Build injection section
        enriched = context_summary
        if intent_statements:
            lines = ["PROTOCOL INTENT (extracted from NatSpec + code analysis):"]
            for s in intent_statements:
                t        = s.get("type", "INTENT")
                stmt     = s.get("statement", "")
                func     = s.get("function", "")
                func_str = f" [{func}()]" if func else ""
                lines.append(f"  [{t}]{func_str} {stmt}")
            enriched = context_summary.rstrip() + "\n\n" + "\n".join(lines) + "\n"

        return {
            "intent_statements": intent_statements,
            "enriched_summary":  enriched,
        }
