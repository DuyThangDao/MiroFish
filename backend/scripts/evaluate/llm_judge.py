"""
LLM judge for semantic matching (Web3Bugs) and SWC classification (SmartBugs).

Uses the project's LLMClient (supports Vertex AI key file, AI Studio API key, etc.)
by importing from backend/app/utils/llm_client.py via sys.path injection.
Env vars: same as the main pipeline (LLM_VERTEX_AI_KEY_FILE, LLM_BASE_URL, etc.)
"""

import os
import re
import sys
import hashlib
import json
from typing import Tuple, Dict

# Allow importing project modules when running from scripts/evaluate/
_BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, os.path.abspath(_BACKEND_DIR))

# Load .env from repo root so LLM_VERTEX_AI_KEY_FILE etc. are available
try:
    from dotenv import load_dotenv as _load_dotenv
    for _env in (
        os.path.join(_BACKEND_DIR, "..", ".env"),
        os.path.join(_BACKEND_DIR, ".env"),
    ):
        if os.path.exists(_env):
            _load_dotenv(_env, override=False)
            break
except ImportError:
    pass

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # type: ignore


_SWC_NAMES: Dict[str, str] = {
    "SWC-100": "Function Default Visibility",
    "SWC-101": "Integer Overflow and Underflow",
    "SWC-102": "Outdated Compiler Version",
    "SWC-103": "Floating Pragma",
    "SWC-104": "Unchecked Call Return Value",
    "SWC-105": "Unprotected Ether Withdrawal",
    "SWC-106": "Unprotected SELFDESTRUCT Instruction",
    "SWC-107": "Reentrancy",
    "SWC-108": "State Variable Default Visibility",
    "SWC-110": "Assert Violation",
    "SWC-111": "Use of Deprecated Solidity Functions",
    "SWC-112": "Delegatecall to Untrusted Callee",
    "SWC-113": "DoS with Failed Call",
    "SWC-114": "Transaction Order Dependence",
    "SWC-115": "Authorization through tx.origin",
    "SWC-116": "Block values as a proxy for time",
    "SWC-120": "Weak Sources of Randomness",
    "SWC-121": "Missing Protection against Signature Replay Attacks",
    "SWC-122": "Lack of Proper Signature Verification",
    "SWC-123": "Requirement Violation",
    "SWC-124": "Write to Arbitrary Storage Location",
    "SWC-125": "Incorrect Inheritance Order",
    "SWC-126": "Insufficient Gas Griefing",
    "SWC-127": "Arbitrary Jump with Function Type Variable",
    "SWC-128": "DoS With Block Gas Limit",
    "SWC-129": "Typographical Error",
    "SWC-130": "Right-To-Left-Override control character (U+202E)",
    "SWC-131": "Presence of unused variables",
    "SWC-132": "Unexpected Ether balance",
    "SWC-133": "Hash Collisions With Multiple Variable Length Arguments",
    "SWC-134": "Message call with hardcoded gas amount",
    "SWC-135": "Code With No Effects",
    "SWC-136": "Unencrypted Private Data On-Chain",
}

_cache: Dict[str, Tuple[bool, str]] = {}


def _extract_visible(text: str) -> str:
    """Strip <think> blocks; if nothing remains, fall back to content inside <think>."""
    if not text:
        return ""
    visible = re.sub(r'<think>[\s\S]*?</think>', '', text).strip()
    if visible:
        return visible
    # Model put everything inside <think> — extract the inner content
    m = re.search(r'<think>([\s\S]*?)</think>', text)
    return m.group(1).strip() if m else text.strip()


def _get_llm_client():
    """Return LLMClient, preferring LLM2 key/base_url if set (avoids rate limit on main key)."""
    from app.utils.llm_client import LLMClient
    key2 = os.environ.get("LLM2_VERTEX_AI_KEY_FILE")
    url2 = os.environ.get("LLM2_BASE_URL")
    if key2 and url2:
        return LLMClient(vertex_key_file=key2, base_url=url2)
    return LLMClient()


def _model() -> str:
    from app.config import Config
    return Config.LLM_MODEL_NAME or os.environ.get("LLM_MODEL", "gpt-4o-mini")


def _cache_key(*parts) -> str:
    return hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()


def judge_match(gt_bug: dict, predicted: dict) -> Tuple[bool, str]:
    """
    Determine if a predicted finding matches a GT H bug.

    gt_bug:    {h_id, title, description, function_name, contract_name}
    predicted: {title, description, attack_path, function_name, contract_name, ...}

    Returns (is_match, reason).
    """
    key = _cache_key(
        gt_bug.get("h_id", ""), gt_bug.get("description", ""),
        predicted.get("title", ""), predicted.get("description", "")
    )
    if key in _cache:
        return _cache[key]

    prompt = f"""You are a security audit evaluator.

GROUND TRUTH BUG:
Function: {gt_bug.get('function_name', '?')} in {gt_bug.get('contract_name', '?')}
Description: {gt_bug.get('description', '')}

PREDICTED FINDING:
Function: {predicted.get('function_name', '?')} in {predicted.get('contract_name', '?')}
Title: {predicted.get('title', '')}
Description: {predicted.get('description', '')}
Attack path: {predicted.get('attack_path', '')}

Does the predicted finding identify the same vulnerability as the ground truth?
Answer: YES or NO
Reason: (one sentence)"""

    client = _get_llm_client()
    text = client.chat(
        messages=[{"role": "user", "content": prompt}],
        max_tokens=2000,
        temperature=0,
        strip_think=False,
    )
    text = _extract_visible(text)
    is_match = bool(re.search(r'\bYES\b', text.upper()[:100]))
    reason = text.split("\n", 1)[1].strip() if "\n" in text else text
    result = (is_match, reason)
    _cache[key] = result
    return result


def classify_swc(swc_id: str, predicted: dict) -> Tuple[bool, str]:
    """
    Classify whether a predicted finding describes a specific SWC vulnerability.

    swc_id:    e.g. "SWC-101"
    predicted: {title, description, attack_path, ...}

    Returns (is_match, reason).
    """
    key = _cache_key(swc_id, predicted.get("title", ""), predicted.get("description", ""))
    if key in _cache:
        return _cache[key]

    swc_name = _SWC_NAMES.get(swc_id, swc_id)
    prompt = f"""You are a smart contract security expert.

SWC VULNERABILITY TYPE:
{swc_id}: {swc_name}

PREDICTED FINDING:
Title: {predicted.get('title', '')}
Description: {predicted.get('description', '')}
Attack path: {predicted.get('attack_path', '')}

Does this predicted finding describe a "{swc_name}" vulnerability ({swc_id})?
Answer: YES or NO
Reason: (one sentence)"""

    client = _get_llm_client()
    text = client.chat(
        messages=[{"role": "user", "content": prompt}],
        max_tokens=2000,
        temperature=0,
        strip_think=False,
    )
    text = _extract_visible(text)
    is_match = bool(re.search(r'\bYES\b', text.upper()[:100]))
    reason = text.split("\n", 1)[1].strip() if "\n" in text else text
    result = (is_match, reason)
    _cache[key] = result
    return result
