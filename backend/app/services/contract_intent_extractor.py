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

Prompt strategy: sends only NatSpec + function signatures + require messages + README.
Raw source is NOT sent to avoid prompt overflow (~55K chars → LLM truncation).
"""

import json
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

_FUNC_SIG_RE = re.compile(
    r'function\s+(\w+)\s*\(([^)]*)\)\s*((?:(?:external|public|internal|private|pure|view|payable|virtual|override)\s*)*(?:returns\s*\([^)]*\))?)',
    re.MULTILINE,
)

_REQUIRE_MSG_RE = re.compile(r'require\s*\([^,)]+,\s*"([^"]{5,120})"')
_REVERT_MSG_RE  = re.compile(r'revert\s*\(\s*"([^"]{5,120})"\s*\)')


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


def _extract_function_signatures(source_code: str) -> List[str]:
    """Extract public/external function signatures (name + visibility) without body."""
    sigs = []
    seen = set()
    for m in _FUNC_SIG_RE.finditer(source_code[:80_000]):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        params    = re.sub(r'\s+', ' ', m.group(2).strip())
        modifiers = re.sub(r'\s+', ' ', m.group(3).strip())
        sig = f"function {name}({params})"
        if modifiers:
            sig += f" {modifiers}"
        sigs.append(sig.strip())
    return sigs[:50]


def _extract_require_messages(source_code: str) -> List[str]:
    """Extract require/revert string literals that describe protocol invariants."""
    msgs = []
    seen = set()
    for pattern in (_REQUIRE_MSG_RE, _REVERT_MSG_RE):
        for m in pattern.finditer(source_code[:80_000]):
            msg = m.group(1).strip()
            if msg not in seen:
                seen.add(msg)
                msgs.append(msg)
    return msgs[:30]


# ─── Resilient JSON parsing (Layer 2) ────────────────────────────────────────

def _robust_parse_json(text: str) -> Dict:
    """
    3-step JSON parsing with increasing tolerance.

    Step 1: strip markdown fences → json.loads (strict, fastest)
    Step 2: json_repair (handles truncated / unclosed brackets from LLM cutoff)
    Step 3: regex extract outermost {...} block → json.loads (last resort)
    """
    cleaned = re.sub(r'^```(?:json)?\s*\n?', '', text.strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r'\n?```\s*$', '', cleaned).strip()

    # Step 1 — standard
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Step 2 — json_repair
    try:
        from json_repair import repair_json  # optional dep, fail gracefully
        repaired = repair_json(cleaned, return_objects=True)
        if isinstance(repaired, dict):
            return repaired
    except Exception:
        pass

    # Step 3 — extract outermost {...}
    m = re.search(r'\{[\s\S]*\}', cleaned)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Cannot parse JSON ({len(text)} chars): {text[:120]}…")


def _natspec_to_intent(hints: List[Dict[str, str]]) -> List[Dict]:
    """
    Deterministic fallback (Layer 3): convert NatSpec hints → intent_statements.
    No LLM required — guaranteed non-empty when NatSpec exists.
    """
    statements = []
    for h in hints[:10]:
        text = (h.get("notice", "") + " " + h.get("dev", "")).strip()
        if len(text) >= 20:
            statements.append({
                "type":      "EFFECT",
                "statement": text,
                "function":  h["function"],
                "source":    "natspec",
            })
    return statements


# ─── LLM Prompt ──────────────────────────────────────────────────────────────

_INTENT_SYSTEM_PROMPT = """You are a smart contract protocol analyst.

Given structured contract metadata (NatSpec comments, function signatures, require messages),
extract PROTOCOL INTENT statements — things the protocol MUST do, MUST NOT do, or MUST maintain.
These represent design intent that, if violated, would constitute a critical bug.

Focus on:
1. ORDERING: "X must happen BEFORE Y" — e.g., "interest must accrue before liquidation check"
2. BOUNDARY: "Value V must be strictly < threshold" (< vs <= matters)
3. ACCOUNTING: "After operation X, invariant Y must hold" — e.g., "k must not decrease after swap"
4. STATE: "Function F can only be called when state S"
5. EFFECT: "Operation X MUST have side-effect Y" — e.g., "withdraw must decrease totalAssets by exact amount"

Extract from (in priority order):
- @notice and @dev NatSpec comments
- require() / revert messages (describe what SHOULD be true)
- Function signatures (infer intent from names and parameters)

Return JSON:
{
  "intent_statements": [
    {
      "type": "ORDERING|BOUNDARY|ACCOUNTING|STATE|EFFECT",
      "statement": "concise protocol must-statement",
      "function": "relevant function name",
      "source": "natspec|require|inferred"
    }
  ]
}

Max 10 statements. Prioritize HIGH-IMPACT ones where a wrong implementation = critical bug."""


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
        max_source_chars: int = 50_000,  # kept for API compatibility, no longer used
    ) -> Dict:
        """
        Returns {"intent_statements": [...], "enriched_summary": str}.
        Never raises — falls back gracefully on LLM error.

        Dedup guard: if context_summary already contains "PROTOCOL INTENT",
        skips injection to avoid duplicating NatSpec content that KG builder
        may have already included.

        Prompt strategy: raw source is NOT sent. Only structured extracts are used:
          - NatSpec @notice/@dev (deterministic regex)
          - Function signatures (regex)
          - require/revert messages (regex)
          - README excerpt
          - KG context summary
        This keeps prompt under ~8K chars, preventing LLM truncation of JSON output.
        """
        # Dedup guard: skip if already injected
        if "PROTOCOL INTENT" in context_summary:
            logger.info("Intent extractor: PROTOCOL INTENT already present in summary — skipping")
            return {"intent_statements": [], "enriched_summary": context_summary}

        # Deterministic extractions (no LLM cost)
        natspec_hints = _extract_natspec_hints(source_code)
        func_sigs     = _extract_function_signatures(source_code)
        require_msgs  = _extract_require_messages(source_code)
        logger.info(
            f"Intent extractor: natspec={len(natspec_hints)}, "
            f"sigs={len(func_sigs)}, requires={len(require_msgs)}"
        )

        # Build compact sections (total target: <8K chars)
        readme_section = f"\nCONTEST README:\n{readme[:3000]}\n" if readme else ""

        natspec_section = ""
        if natspec_hints:
            natspec_section = "\nNATSPEC (@notice/@dev):\n" + "\n".join(
                f"  {h['function']}(): {(h['notice'] + ' ' + h['dev']).strip()}"
                for h in natspec_hints[:20]
            ) + "\n"

        sigs_section = ""
        if func_sigs:
            sigs_section = "\nFUNCTION SIGNATURES:\n" + "\n".join(
                f"  {s}" for s in func_sigs
            ) + "\n"

        require_section = ""
        if require_msgs:
            require_section = "\nREQUIRE/REVERT MESSAGES:\n" + "\n".join(
                f"  - {msg}" for msg in require_msgs
            ) + "\n"

        user_content = (
            f"{readme_section}"
            f"{natspec_section}"
            f"{sigs_section}"
            f"{require_section}"
            f"\nKG CONTEXT SUMMARY (first 3000 chars):\n{context_summary[:3000]}\n\n"
            "Extract protocol intent statements as JSON."
        )
        logger.debug(f"Intent extractor prompt size: {len(user_content)} chars")

        intent_statements: List[Dict] = []

        # ── Layer 2+3: Attempt 1 — full structured prompt ────────────────────
        try:
            raw = self.llm.chat(
                messages=[
                    {"role": "system", "content": _INTENT_SYSTEM_PROMPT},
                    {"role": "user",   "content": user_content},
                ],
                temperature=0.2,
                max_tokens=2048,
            )
            raw_stmts = _robust_parse_json(raw).get("intent_statements", [])
            intent_statements = [s for s in raw_stmts if isinstance(s, dict)][:10]
            logger.info(f"Intent extraction attempt 1 OK: {len(intent_statements)} statements")
        except Exception as e:
            logger.warning(f"Intent extraction attempt 1 failed: {e}")

            # ── Layer 3: Attempt 2 — minimal NatSpec-only prompt ─────────────
            if natspec_hints:
                try:
                    minimal_content = (
                        "NATSPEC (@notice/@dev):\n"
                        + "\n".join(
                            f"  {h['function']}(): {(h['notice'] + ' ' + h['dev']).strip()}"
                            for h in natspec_hints[:10]
                        )
                        + "\n\nExtract up to 5 protocol intent statements as JSON."
                    )
                    raw = self.llm.chat(
                        messages=[
                            {"role": "system", "content": _INTENT_SYSTEM_PROMPT},
                            {"role": "user",   "content": minimal_content},
                        ],
                        temperature=0.2,
                        max_tokens=1024,
                    )
                    raw_stmts2 = _robust_parse_json(raw).get("intent_statements", [])
                    intent_statements = [s for s in raw_stmts2 if isinstance(s, dict)][:5]
                    logger.info(f"Intent extraction attempt 2 (minimal) OK: {len(intent_statements)} statements")
                except Exception as e2:
                    logger.warning(f"Intent extraction attempt 2 failed: {e2}")

            # ── Layer 3: Deterministic fallback — NatSpec → intent (no LLM) ─
            if not intent_statements and natspec_hints:
                intent_statements = _natspec_to_intent(natspec_hints)
                logger.info(f"Intent extraction: deterministic NatSpec fallback, {len(intent_statements)} statements")

        if intent_statements:
            logger.info(
                "Intent statements: "
                + f"{len(intent_statements)} — "
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
