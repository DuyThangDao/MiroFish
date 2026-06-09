#!/usr/bin/env python3
"""
simulate_tracks.py — Mô phỏng CODE track + OP track cho 1 GT function từ contest 35.

Không cần ChromaDB — dùng token overlap (Jaccard) làm proxy cho cosine similarity.
Mục đích: validate rằng queries được generate sẽ match đúng findings trong RAG DB.

Usage:
    python scripts/rag/simulate_tracks.py
"""
import json, re, os, sys, time
from pathlib import Path
from collections import Counter
import httpx
from openai import OpenAI

SCRIPT_DIR  = Path(__file__).parent.resolve()
REPO_ROOT   = SCRIPT_DIR.parent.parent.parent
CACHE_PATH  = SCRIPT_DIR / "rag_sections_cache.json"

SOL_KW = {
    "abstract","anonymous","assembly","break","catch","constant","constructor",
    "continue","contract","delete","do","else","enum","event","external",
    "fallback","false","final","for","from","function","if","immutable",
    "import","indexed","interface","internal","is","library","mapping",
    "modifier","new","override","payable","pragma","private","public",
    "pure","receive","return","returns","revert","storage","struct",
    "super","this","throw","true","try","type","unchecked","using",
    "view","virtual","while","calldata","memory",
    "address","bool","bytes","string","tuple","int","uint",
    "bytes1","bytes2","bytes4","bytes8","bytes16","bytes32",
    "uint8","uint16","uint32","uint64","uint96","uint128","uint160","uint256",
    "int8","int16","int32","int64","int128","int256",
    "abi","block","tx","msg","now","gasleft","blockhash",
    "keccak256","sha256","ripemd160","ecrecover","addmod","mulmod","selfdestruct",
    "require","assert","emit","transfer","send","call","delegatecall","staticcall",
    "encode","decode","encodePacked","encodeWithSelector","encodeWithSignature","encodeCall",
    "seconds","minutes","hours","days","weeks","years",
    "wei","gwei","ether","szabo","finney","fixed","ufixed","var","byte",
}

# ── GT function: ConcentratedLiquidityPool.burn (H-01 contest 35) ──────────────
BURN_FN = """
function burn(bytes calldata data) public override lock returns (IPool.TokenAmount[] memory withdrawnAmounts) {
    (int24 lower, int24 upper, uint128 amount, address recipient, bool unwrapBento) = abi.decode(
        data, (int24, int24, uint128, address, bool)
    );
    uint160 priceLower = TickMath.getSqrtRatioAtTick(lower);
    uint160 priceUpper = TickMath.getSqrtRatioAtTick(upper);
    uint160 currentPrice = price;
    unchecked {
        if (priceLower < currentPrice && currentPrice < priceUpper) liquidity -= amount;
    }
    (uint256 amount0, uint256 amount1) = _getAmountsForLiquidity(
        uint256(priceLower), uint256(priceUpper), uint256(currentPrice), uint256(amount)
    );
    (uint256 amount0fees, uint256 amount1fees) = _updatePosition(msg.sender, lower, upper, -int128(amount));
    unchecked {
        amount0 += amount0fees;
        amount1 += amount1fees;
    }
    unchecked {
        reserve0 -= uint128(amount0fees);
        reserve1 -= uint128(amount1fees);
    }
    _transferBothTokens(recipient, amount0, amount1, unwrapBento);
    nearestTick = Ticks.remove(ticks, lower, upper, amount, nearestTick);
    emit Burn(msg.sender, amount0, amount1, recipient);
}
""".strip()


# ── Normalize ──────────────────────────────────────────────────────────────────
def normalize_code(code: str) -> str:
    code = re.sub(r"(?m)^\s*\d+\s*:\s*", "", code)
    code = re.sub(r"//[^\n]*", "", code)
    code = re.sub(r"/\*[\s\S]*?\*/", "", code)
    code = re.sub(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
        lambda m: m.group(0) if m.group(0) in SOL_KW else "_VAR", code)
    code = re.sub(r"[\s]+", " ", code)
    return code.strip()


# ── Token sets for Jaccard ─────────────────────────────────────────────────────
def tokenize(text: str) -> set:
    return set(re.findall(r"[a-zA-Z0-9_]{2,}", text.lower()))


def jaccard(a: set, b: set) -> float:
    if not a or not b: return 0.0
    return len(a & b) / len(a | b)


def containment(needle: set, haystack: set) -> float:
    """Fraction of needle tokens present in haystack."""
    if not needle: return 0.0
    return len(needle & haystack) / len(needle)


# ── LLM setup ─────────────────────────────────────────────────────────────────
def build_client():
    env_path = REPO_ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k, _, v = line.partition("=")
            if k.strip() not in os.environ:
                os.environ[k.strip()] = v.strip().strip('"').strip("'")

    # W2 — tested working
    key_file = str(REPO_ROOT / "vertex-ai-2.json")
    base_url = "https://aiplatform.googleapis.com/v1/projects/learned-surge-498101-t0/locations/global/endpoints/openapi"
    from google.oauth2 import service_account
    import google.auth.transport.requests
    creds = service_account.Credentials.from_service_account_file(
        key_file, scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    class _Auth(httpx.Auth):
        def auth_flow(self, request):
            if not creds.valid:
                creds.refresh(google.auth.transport.requests.Request())
            request.headers["Authorization"] = f"Bearer {creds.token}"
            yield request
    return OpenAI(
        api_key="vertex-ai", base_url=base_url,
        http_client=httpx.Client(auth=_Auth(), timeout=120), max_retries=0,
    )

MODEL    = "google/gemini-3-flash-preview"
THINKING = {"google": {"thinking_config": {"thinking_level": "low"}}}

def call_llm(client, prompt: str) -> str:
    # max_tokens=4096: thinking_level=low dùng thinking tokens trước,
    # nếu max_tokens quá nhỏ thì content=None
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0, max_tokens=4096,
        extra_body=THINKING,
    )
    msg = resp.choices[0].message if resp.choices else None
    return (msg.content or "").strip() if msg else ""


# ── OP query generation (HIST-INV style) ──────────────────────────────────────
OP_QUERY_PROMPT = """\
You are a Solidity code analyst.

Function: burn()
Body:
{fn_body}

Generate search queries to find historical vulnerability findings related to this function.
Each query must target a DIFFERENT operation or pattern in this function.
List ALL distinct operations — do not merge or skip any.
Focus on: type casts, arithmetic operations, state updates, unchecked blocks.
Be specific about data types (uint128, int128, uint256) and operations.
Do NOT describe business purpose. Do NOT add 'vulnerability' keyword.

Format: one query per line, max 15 words each.
Output ONLY the queries, nothing else.\
"""

# ── OP description generation (solodit_op style — cho finding đã biết) ─────────
OP_DESC_PROMPT = """\
You are a Solidity code analyst.

Vulnerable code:
{raw_code}

Vulnerability context (for reference only):
{vul}

Enumerate the distinct mechanical operations in the code above.
Focus on: type casts, arithmetic (add, sub, mul, div, overflow), storage reads/writes, \
external calls, unchecked blocks, state update ordering.

Rules:
- One operation per line, 5-15 words each.
- 3 to 7 lines total.
- Each line will be indexed as a standalone search document — include enough context \
to be self-contained (mention the type, variable role, function context).
- Be specific about exact Solidity types when visible (uint128, uint256, int24, etc.).
- Use active verb phrases matching audit query style.
- Do NOT add judgment words like "incorrectly", "unsafely", "missing", "wrong".
- Output ONLY the operation lines. No numbering. No explanation. No markdown.\
"""


def sep(title=""):
    print("\n" + "="*70)
    if title: print(f"  {title}")
    print("="*70)


def main():
    print("Loading cache...")
    cache = json.load(open(CACHE_PATH))
    findings = cache["findings"]
    print(f"Total findings: {len(findings)}")

    # ── 1. CODE QUERY ──────────────────────────────────────────────────────────
    sep("STEP 1 — CODE TRACK: Normalize burn() → CODE query")
    code_query_norm = normalize_code(BURN_FN)
    print("CODE query (normalized):")
    print(code_query_norm[:400], "...")
    q_tokens = tokenize(code_query_norm)
    print(f"\nUnique tokens in query: {len(q_tokens)}")
    print("Sample tokens:", sorted(q_tokens)[:20])

    # ── 2. CODE TRACK: search sections.code dùng text-embedding-004 (production model) ──
    sep("STEP 2 — CODE TRACK: Search sections.code (text-embedding-004 cosine)")
    import vertexai
    from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput
    import numpy as np

    key_file = str(REPO_ROOT / "vertex-ai-2.json")
    project_id = json.load(open(key_file))["project_id"]
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = key_file
    vertexai.init(project=project_id)
    emb_model = TextEmbeddingModel.from_pretrained("text-embedding-004")

    def embed_texts(texts: list, task_type: str = "RETRIEVAL_DOCUMENT") -> np.ndarray:
        """Embed batch, trả về (N, dim) numpy array. Batch=40 để tránh token limit."""
        BATCH = 40
        all_embs = []
        for i in range(0, len(texts), BATCH):
            batch = texts[i:i+BATCH]
            inputs = [TextEmbeddingInput(t[:1200], task_type) for t in batch]  # truncate ~300 tokens
            embs = emb_model.get_embeddings(inputs)
            all_embs.extend([e.values for e in embs])
            if i + BATCH < len(texts):
                time.sleep(0.5)
        arr = np.array(all_embs, dtype=np.float32)
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        return arr / (norms + 1e-9)

    # Embed CODE query (task_type=RETRIEVAL_QUERY như production)
    print("Embedding CODE query (truncated to 1200 chars)...")
    q_emb = embed_texts([code_query_norm[:1200]], task_type="RETRIEVAL_QUERY")[0]

    # Embed tất cả sections.code
    has_code = [(f["slug"], f.get("title","")[:70], f["sections"]["code"], f["sections"].get("vul","")[:120])
                for f in findings if f["sections"].get("code")]
    print(f"Embedding {len(has_code)} sections.code (batch=40, ~{len(has_code)//40+1} calls)...")
    doc_embs = embed_texts([x[2] for x in has_code], task_type="RETRIEVAL_DOCUMENT")

    # Cosine similarity
    sims = doc_embs @ q_emb
    top_idx = np.argsort(sims)[::-1][:15]

    print(f"\nTop 15 by cosine similarity:\n")
    print(f"{'Rank':<5} {'Cosine':>8}  Title")
    print("-"*80)
    for rank, idx in enumerate(top_idx, 1):
        slug, title, _, _ = has_code[idx]
        print(f"{rank:<5} {sims[idx]:>8.4f}  {title}")

    print(f"\n--- Rank 1 vul preview ---")
    print(has_code[top_idx[0]][3])

    # ── 3. OP QUERIES (HIST-INV style) ─────────────────────────────────────────
    sep("STEP 3 — OP TRACK: Generate HIST-INV OP queries for burn()")
    print("Calling LLM to generate OP queries...")
    client = build_client()
    op_queries_raw = call_llm(client, OP_QUERY_PROMPT.format(fn_body=BURN_FN))
    op_queries = [ln.strip().lstrip("0123456789.-) ").strip()
                  for ln in op_queries_raw.split("\n") if ln.strip()]
    print(f"\nGenerated {len(op_queries)} OP queries:")
    for i, q in enumerate(op_queries, 1):
        print(f"  {i:2}. {q}")

    # ── 4. OP TRACK: generate op descriptions for 3 GT-similar findings ───────
    sep("STEP 4 — OP TRACK: Generate op descriptions for sample findings")
    # Lấy 3 findings từ cache có vul liên quan đến cast/overflow/reserve
    keywords = {"cast", "uint128", "overflow", "reserve", "truncat", "unsafe"}
    candidates = []
    for f in findings:
        vul = (f["sections"].get("vul") or "").lower()
        raw = f["sections"].get("raw_code") or ""
        if any(k in vul for k in keywords) and raw:
            candidates.append(f)
        if len(candidates) >= 5:
            break

    print(f"Selected {len(candidates)} candidate findings with cast/overflow/reserve keywords\n")
    sample_ops = []
    for f in candidates:
        print(f"  Generating op for: {f['slug'][:65]}")
        prompt = OP_DESC_PROMPT.format(
            raw_code=(f["sections"].get("raw_code") or "")[:1000],
            vul=(f["sections"].get("vul") or "")[:800],
        )
        op_text = call_llm(client, prompt)
        op_lines = [ln.strip().lstrip("0123456789.-) ").strip()
                    for ln in op_text.split("\n") if ln.strip() and len(ln.strip()) >= 5]
        sample_ops.append({
            "slug": f["slug"],
            "title": f.get("title","")[:70],
            "op_lines": op_lines,
        })
        print(f"    → {len(op_lines)} ops: {op_lines[:2]}")
        time.sleep(2)

    # ── 5. OP TRACK: match OP queries vs sample op descriptions ───────────────
    sep("STEP 5 — OP TRACK: Match queries vs generated op descriptions")
    print(f"\n{'Query':<55} {'Best match doc (containment)':>10}")
    print("-"*80)
    for q in op_queries:
        q_tok = tokenize(q)
        best_score = 0.0
        best_title = "(none)"
        best_op    = ""
        for doc in sample_ops:
            for op_line in doc["op_lines"]:
                score = containment(q_tok, tokenize(op_line))
                if score > best_score:
                    best_score = score
                    best_title = doc["title"][:50]
                    best_op    = op_line[:60]
        marker = "✓" if best_score >= 0.4 else ("~" if best_score >= 0.2 else "✗")
        print(f"  {marker} [{best_score:.2f}] Q: {q[:50]:<52}")
        if best_score > 0:
            print(f"          → matched op: {best_op}")

    # ── 6. OP TRACK — tìm finding thực sự tương tự H-01 trong RAG DB ──────────
    sep("STEP 6 — OP TRACK: Validate với findings thực sự tương tự H-01")
    # Tìm findings có vul chứa "uint128" và ("cast" hoặc "overflow" hoặc "truncat")
    similar_kw = {"uint128", "overflow", "truncat", "downcast", "cast"}
    similar = [
        f for f in findings
        if f["sections"].get("raw_code")
        and any(k in (f["sections"].get("vul") or "").lower() for k in similar_kw)
        and any(k in (f["sections"].get("raw_code") or "").lower() for k in {"uint128", "uint256"})
    ][:5]
    print(f"Found {len(similar)} findings with uint128/cast/overflow in vul+raw_code\n")

    similar_ops = []
    for f in similar:
        print(f"  Generating op for: {f['slug'][:65]}")
        prompt = OP_DESC_PROMPT.format(
            raw_code=(f["sections"].get("raw_code") or "")[:1000],
            vul=(f["sections"].get("vul") or "")[:800],
        )
        op_text = call_llm(client, prompt)
        op_lines = [ln.strip().lstrip("0123456789.-) ").strip()
                    for ln in op_text.split("\n") if ln.strip() and len(ln.strip()) >= 5]
        similar_ops.append({"slug": f["slug"], "title": f.get("title","")[:70], "op_lines": op_lines})
        print(f"    vul: {(f['sections'].get('vul') or '')[:80]}")
        print(f"    ops: {op_lines[:2]}")
        time.sleep(2)

    print(f"\n--- Match OP queries vs uint128/cast-related findings ---\n")
    for q in op_queries:
        q_tok = tokenize(q)
        best_score, best_title, best_op = 0.0, "(none)", ""
        for doc in similar_ops:
            for op_line in doc["op_lines"]:
                s = containment(q_tok, tokenize(op_line))
                if s > best_score:
                    best_score, best_title, best_op = s, doc["title"][:50], op_line[:60]
        marker = "✓" if best_score >= 0.4 else ("~" if best_score >= 0.2 else "✗")
        print(f"  {marker} [{best_score:.2f}] Q: {q[:55]}")
        if best_score > 0:
            print(f"          → {best_op}")

    # ── 7. Summary ──────────────────────────────────────────────────────────────
    sep("SUMMARY")
    print(f"CODE track — top-1 với text-embedding-004:")
    print(f"  {has_code[top_idx[0]][1]}")
    print(f"  cosine={sims[top_idx[0]]:.4f}  (range top15: {sims[top_idx[14]]:.4f}–{sims[top_idx[0]]:.4f})")
    spread = sims[top_idx[0]] - sims[top_idx[14]]
    print(f"  Spread top1–top15: {spread:.4f}  {'← GOOD discrimination' if spread > 0.05 else '← POOR discrimination (too narrow)'}")
    print(f"\nOP track: {len(op_queries)} queries generated")
    relevant = [q for q in op_queries if any(k in q.lower() for k in ["uint128","unchecked","cast","reserve","downcast"])]
    print(f"Queries liên quan đến H-01 pattern: {len(relevant)}/{len(op_queries)}")
    for q in relevant:
        print(f"  → {q}")


if __name__ == "__main__":
    main()
