"""
Test hypothesis-first RAG approach vs current approach.
Target: H-06 (claimRewardAsMochi) — ReferralFeePoolV0
3 conditions: no_rag | rag_findings (blob) | rag_unified (structured)
New prompt: agent must state hypothesis BEFORE each RAG call.
"""
import sys, os, json, time, re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pysqlite3; sys.modules['sqlite3'] = pysqlite3

import chromadb
from chromadb import EmbeddingFunction, Documents, Embeddings
from openai import OpenAI
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))

KEY_FILE = os.getenv('LLM_VERTEX_AI_KEY_FILE', '')
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = KEY_FILE
BASE_URL = os.getenv('LLM_BASE_URL', '')
MODEL    = os.getenv('LLM_MODEL_NAME', 'google/gemini-3-flash-preview')

import google.auth.transport.requests
from google.oauth2 import service_account
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput

creds = service_account.Credentials.from_service_account_file(
    KEY_FILE, scopes=['https://www.googleapis.com/auth/cloud-platform'])
creds.refresh(google.auth.transport.requests.Request())
token = creds.token
llm = OpenAI(api_key=token, base_url=BASE_URL)

def _strip(t): return re.sub(r'<think>.*?</think>', '', t or '', flags=re.DOTALL).strip()

# ─── RAG setup ────────────────────────────────────────────────────────────────
class VertexEmbed(EmbeddingFunction):
    def __init__(self):
        self._model = TextEmbeddingModel.from_pretrained("text-embedding-004")
    def __call__(self, input: Documents) -> Embeddings:
        ins = [TextEmbeddingInput(t, "RETRIEVAL_QUERY") for t in input]
        return [e.values for e in self._model.get_embeddings(ins)]

_embed = VertexEmbed()
_chroma = chromadb.PersistentClient(
    path=os.path.join(os.path.dirname(__file__), '../data/rag_db/chroma'))

_col_findings = _chroma.get_collection('solodit_findings', embedding_function=_embed)
_col_unified  = _chroma.get_collection('solodit_unified',  embedding_function=_embed)
print(f"[RAG] solodit_findings: {_col_findings.count()} | solodit_unified: {_col_unified.count()}")

def search(col, query: str, n=3) -> str:
    res = col.query(query_texts=[query], n_results=n*2,
                    include=['documents','metadatas','distances'])
    seen, out = set(), []
    for doc, meta, dist in zip(res['documents'][0], res['metadatas'][0], res['distances'][0]):
        slug = meta.get('slug','')
        if slug in seen: continue
        seen.add(slug)
        score = round(1 - dist, 3)
        title = meta.get('title','')
        protocol = meta.get('protocol', meta.get('protocol_name',''))
        firm = meta.get('firm','')
        # findings: truncate blob; unified: show full structured doc
        content = doc if col.name == 'solodit_unified' else doc[:800]
        out.append(f"[score={score}] {title}\nFIRM: {firm} | PROTOCOL: {protocol}\nSLUG: {slug}\n{content}\n")
        if len(out) >= n: break
    return "\n---\n".join(out) if out else "No results."

# ─── LLM ──────────────────────────────────────────────────────────────────────
def llm_call(messages, tools=None):
    for attempt in range(3):
        try:
            kwargs = dict(model=MODEL, messages=messages, temperature=0.3, max_tokens=3000,
                          extra_body={"google": {"thinking_config": {"thinking_budget": 0}}})
            if tools: kwargs['tools'] = tools
            return llm.chat.completions.create(**kwargs).choices[0].message
        except Exception as e:
            if '429' in str(e) or 'rate' in str(e).lower():
                wait = 20*(attempt+1); print(f"  [rate {wait}s]"); time.sleep(wait)
            else:
                raise
    raise RuntimeError("LLM failed after retries")

def run_agent(prompt: str, col, tool_name: str) -> tuple[str, int, list]:
    """Returns (full_text, rag_call_count, queries_made)."""
    tools = None
    if col:
        tools = [{
            "type": "function",
            "function": {
                "name": tool_name,
                "description": (
                    "Search historical smart contract audit findings. "
                    "Each result shows vulnerability description, violated invariant, operations involved. "
                    "RULE: Before calling this tool, state your hypothesis in the query itself. "
                    "Format: 'I suspect [mechanism] because [code observation]'. "
                    "If you cannot articulate a specific hypothesis yet, continue reading code first."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string",
                                  "description": "Your specific hypothesis + code evidence (max 20 words)."}
                    },
                    "required": ["query"]
                }
            }
        }]

    messages = [{"role": "user", "content": prompt}]
    all_text, rag_n, queries = "", 0, []

    for _ in range(6):
        msg = llm_call(messages, tools=tools)
        text = _strip(msg.content)
        all_text += text + "\n"
        messages.append({"role": "assistant", "content": msg.content,
                          "tool_calls": msg.tool_calls})
        if msg.tool_calls and col:
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments)
                q = args.get("query", "")
                queries.append(q)
                print(f"      RAG[{rag_n+1}]: '{q[:80]}'", flush=True)
                result = search(col, q)
                rag_n += 1
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
            time.sleep(4)
            continue
        break
    return all_text, rag_n, queries

# ─── Contract source ──────────────────────────────────────────────────────────
SOURCE = open("/home/thangdd/repos/web3bugs/contracts/42/projects/mochi-core/contracts/feePool/ReferralFeePoolV0.sol").read()

SYSTEM = (
    "You are a formal methods engineer who reads smart contracts as finite state machines. "
    "You look for invalid state transitions, dead-end states, and states where safety invariants "
    "are permanently broken. Key patterns: missing transitions that leave funds permanently locked, "
    "state inconsistency between storage variables after failed or partial operations, and update "
    "ordering bugs. TRACK C: Identify storage variables written by more than one function. "
    "For each shared variable: Is there an ordering where function A partially updates and function B reads stale state?"
)

OUTPUT_FMT = """
OUTPUT FORMAT:
  FINDING: <title>
  CONTRACT: <name>
  FUNCTION: <name>
  SEVERITY: high|medium|low
  EVIDENCE: CODE: <snippet> | MISSING: <what> AT: <fn()> | INV: <invariant> VIOLATED_AT: <fn()>
  ATTACK_PATH: ACTOR / CALL / STATE_CHANGE / OUTCOME
  DESCRIPTION: <why>
  PATCH: <fix>

Write NO FINDING if nothing found. Do not hallucinate.
"""

def make_prompt(rag_mode: str) -> str:
    rag_block = ""
    if rag_mode == "findings":
        rag_block = (
            "\n=== MEMORY TOOL ===\n"
            "You have search_historical_findings(query) — thousands of real audit findings.\n"
            "Call it freely when you suspect a pattern.\n"
            "Multiple calls encouraged — each with a different angle.\n"
        )
    elif rag_mode == "unified":
        rag_block = (
            "\n=== MEMORY TOOL ===\n"
            "You have search_audit_memory(query) — structured audit findings (vulnerability + invariant + operations).\n"
            "RULE: Complete STEP 1 before any RAG call.\n"
            "RULE: Each query must encode your hypothesis. Example:\n"
            "  'reward balance not reset before external call, can claim repeatedly'\n"
            "  'storage variable not updated before transfer, reentrancy or double-claim possible'\n"
            "If you cannot state a specific hypothesis yet, continue reading code first.\n"
        )
    return f"""=== ROUND 1 — INDEPENDENT DISCOVERY ===
You are a state_machine_analyst.
{SYSTEM}
{rag_block}
=== CONTRACT: ReferralFeePoolV0 ===
```solidity
{SOURCE}
```

=== EPISTEMIC LENS ===
Can this contract enter a state from which recovery is impossible, or where safety invariants are permanently broken?
Is there any function that writes storage without first verifying the prior state is valid?
Can any call sequence leave a storage variable permanently incorrect?

STEP 1 — LIST INVARIANTS (3-6, protocol-specific):
  ✓ "reward[user] must be set to 0 before/after transferring tokens to user"
  ✓ "rewards global tracker must equal sum of all reward[user]"
  ✗ Generic: "no reentrancy", "no overflow"

TRACK A — ADVERSARIAL INPUTS: test 0, max_uint, address(0), repeated calls.
TRACK B: apply your domain expertise (see system prompt).

STEP 2 — FIND VIOLATIONS: For each invariant, check if any execution path violates it.
{OUTPUT_FMT}"""

# ─── Detection ────────────────────────────────────────────────────────────────
KEYWORDS = [r"reward.*not.*reset|drain|re.?enter|balance.*not.*zero|missing.*reset|claim.*again|reward\[.*\].*not.*clear"]

def detect(response: str) -> bool:
    return "FINDING:" in response and any(
        re.search(kw, response, re.IGNORECASE) for kw in KEYWORDS)

# ─── Main ──────────────────────────────────────────────────────────────────────
OUT_DIR = "/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/42/sim_hypothesis"
os.makedirs(OUT_DIR, exist_ok=True)

CONDITIONS = [
    ("no_rag",   None,           None,       "—"),
    ("findings", _col_findings,  "search_historical_findings", "solodit_findings (blob)"),
    ("unified",  _col_unified,   "search_audit_memory",        "solodit_unified (structured)"),
]

print("\n" + "="*80)
print("H-06: claimRewardAsMochi — hypothesis-first RAG test")
print("="*80)
print(f"\n{'Condition':<12} {'Found':^6}  {'RAG calls':^10}  First FINDING")
print("─"*70)

results = []
for label, col, tool_name, desc in CONDITIONS:
    print(f"\n[{label}] running...", flush=True)
    prompt = make_prompt("unified" if label == "unified" else ("findings" if label == "findings" else "none"))
    time.sleep(4)
    resp, rag_n, queries = run_agent(prompt, col, tool_name)
    found = detect(resp)
    mark = "✅" if found else "❌"
    snippet = ""
    m = re.search(r'FINDING: (.{0,60})', resp)
    if m: snippet = m.group(1)
    print(f"  {label:<12} {mark:^6}  {rag_n:^10}  {snippet[:50]}")

    out_file = os.path.join(OUT_DIR, f"h06_{label}.txt")
    with open(out_file, 'w') as f:
        f.write(f"Condition: {label} ({desc})\nRAG calls: {rag_n}\nFound: {found}\n")
        if queries:
            f.write(f"Queries:\n" + "\n".join(f"  {i+1}. {q}" for i,q in enumerate(queries)) + "\n")
        f.write("\n" + "="*60 + "\n")
        f.write(resp)

    results.append({"label": label, "desc": desc, "found": found, "rag_n": rag_n, "queries": queries})
    time.sleep(3)

print("\n" + "="*80)
print("SUMMARY")
print("="*80)
for r in results:
    mark = "✅" if r["found"] else "❌"
    print(f"  {r['label']:<12} {mark}  ({r['desc']})")
    for i, q in enumerate(r["queries"]):
        print(f"    Query {i+1}: {q[:80]}")

with open(os.path.join(OUT_DIR, "summary.json"), 'w') as f:
    json.dump(results, f, indent=2)
print(f"\nResponses saved to: {OUT_DIR}/")
