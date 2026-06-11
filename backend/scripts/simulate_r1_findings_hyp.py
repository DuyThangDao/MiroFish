"""
Simulation với source code THẬT từ contest 42 — dùng solodit_findings + hypothesis-first prompt.
Mục đích: tách biệt xem improvement đến từ collection (unified) hay prompt (hypothesis-first).
So sánh với simulate_r1_unified.py (unified + hyp) và simulate_r1_real.py (findings, no hyp).
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
_col = _chroma.get_collection('solodit_findings', embedding_function=_embed)
print(f"[RAG] solodit_findings: {_col.count()} docs loaded")

RAG_TOOL = [{
    "type": "function",
    "function": {
        "name": "search_historical_findings",
        "description": (
            "Search historical smart contract audit findings. "
            "RULE: Each query must encode your specific hypothesis derived from code evidence. "
            "Format: '[mechanism you suspect] because [specific code observation]'. "
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

def search_rag(query: str) -> str:
    results = _col.query(query_texts=[query], n_results=8,
                         include=['documents','metadatas','distances'])
    docs, metas, dists = results['documents'][0], results['metadatas'][0], results['distances'][0]
    seen, out = set(), []
    for doc, meta, dist in zip(docs, metas, dists):
        slug = meta.get('slug','')
        if slug in seen: continue
        seen.add(slug)
        score = round(1 - dist, 3)
        title = meta.get('title','')
        protocol = meta.get('protocol_name','')
        out.append(f"[score={score}] {title} ({protocol})\nSLUG: {slug}\n{doc[:800]}\n")
        if len(out) >= 3: break
    return "\n---\n".join(out) if out else "No results."

def llm_call(messages, tools=None):
    for attempt in range(3):
        try:
            kwargs = dict(
                model=MODEL, messages=messages, temperature=0.3, max_tokens=3000,
                extra_body={"google": {"thinking_config": {"thinking_budget": 0}}}
            )
            if tools:
                kwargs['tools'] = tools
            resp = llm.chat.completions.create(**kwargs)
            return resp.choices[0].message
        except Exception as e:
            if '429' in str(e) or 'rate' in str(e).lower():
                wait = 20*(attempt+1); print(f"  [rate {wait}s]"); time.sleep(wait)
            else:
                raise
    raise RuntimeError("failed")

def run_agent(prompt: str, with_rag: bool) -> tuple[str, int]:
    """Returns (full_response_text, rag_call_count)."""
    messages = [{"role": "user", "content": prompt}]
    all_text = ""
    rag_n = 0
    for _ in range(6):  # max turns
        msg = llm_call(messages, tools=RAG_TOOL if with_rag else None)
        text = _strip(msg.content)
        all_text += text + "\n"
        messages.append({"role": "assistant", "content": msg.content,
                          "tool_calls": msg.tool_calls})
        if msg.tool_calls and with_rag:
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments)
                q = args.get("query", "")
                fn_name = tc.function.name
                print(f"      RAG[{rag_n+1}] {fn_name}: '{q[:70]}'", flush=True)
                result = search_rag(q)
                rag_n += 1
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
            time.sleep(4)
            continue
        break
    return all_text, rag_n

# ─── Real source loader ───────────────────────────────────────────────────────
BASE = "/home/thangdd/repos/web3bugs/contracts/42/projects/mochi-core/contracts"
def load(path): return open(path).read()

SOURCES = {
    "MochiVault":        load(f"{BASE}/vault/MochiVault.sol"),
    "MochiProfileV0":    load(f"{BASE}/profile/MochiProfileV0.sol"),
    "FeePoolV0":         load(f"{BASE}/feePool/FeePoolV0.sol"),
    "ReferralFeePoolV0": load(f"{BASE}/feePool/ReferralFeePoolV0.sol"),
    "MochiEngine":       load(f"{BASE}/MochiEngine.sol"),
    "VestedRewardPool":  load(f"{BASE}/emission/VestedRewardPool.sol"),
    "MochiTreasuryV0":   load(f"{BASE}/treasury/MochiTreasuryV0.sol"),
}

# ─── Exact agent prompts ──────────────────────────────────────────────────────
AGENTS = {
    "logic_exploiter": {
        "system": "You are a business logic specialist who finds gaps between intended behavior and actual implementation at a semantic level — not syntax bugs, but protocol design bugs. You look for: state ordering bugs, rounding asymmetry, cross-function state inconsistency where two functions each look correct but their interaction creates a bug, griefing vectors, and semantic gaps between what the spec says should happen and what the code actually does. When you identify a suspicious design choice, write a FINDING first. Do not use inability to prove the full attack path as a reason to stay silent.",
        "cq": "For each accumulator, reference variable, or operation ordering in this contract: is this the correct choice for the intended invariant? If the answer is 'possibly not', write a FINDING.",
    },
    "state_machine_analyst": {
        "system": "You are a formal methods engineer who reads smart contracts as finite state machines. You look for invalid state transitions, dead-end states, and states where safety invariants are permanently broken. Key patterns: missing transitions that leave funds permanently locked, state inconsistency between storage variables after failed or partial operations, and update ordering bugs. TRACK C: Identify storage variables written by more than one function. For each shared variable: Is there an ordering where function A partially updates and function B reads stale state?",
        "cq": "Can this contract enter a state from which recovery is impossible, or where safety invariants are permanently broken? Is there any function that writes storage without first verifying the prior state is valid? Can any call sequence leave a storage variable permanently incorrect?",
    },
    "invariant_breaker": {
        "system": "You are a formal methods adversary who specializes in breaking mathematical invariants. You look for boundary conditions, off-by-one errors, domain restrictions not enforced by the caller, and invariants that hold for typical inputs but fail at extreme values. ACCUMULATOR UPDATE ORDER: for every function that changes a denominator state variable (debts, shares, supply, balance), verify the global tracker is updated consistently with individual position trackers.",
        "cq": "What is the set of inputs that causes any mathematical invariant in this contract to fail? For every accounting variable: does it remain correct across all valid call sequences? Specifically: is the global/cumulative value always equal to the sum of individual values after every operation?",
    },
    "math_precision": {
        "system": "You are a quantitative analyst who reads smart contract code as a mathematical system. You know that integer arithmetic in Solidity has specific rounding behavior that attackers can exploit: division truncates toward zero, fixed-point operations accumulate precision loss. You trace every arithmetic operation to determine if accumulated error can be extracted.",
        "cq": "Are there inputs or sequences of operations that cause this mathematical system to diverge from its intended behavior in a way that favors an attacker? Test edge cases: zero values, max values, repeated operations.",
    },
    "defi_attacker": {
        "system": "You are a DeFi exploit developer with access to flash loans and MEV infrastructure. You treat protocols as capital extraction machines: route capital to extract more than you deposit in atomic transactions. You look for price oracle manipulation, sandwich attacks, stale oracle exploitation.",
        "cq": "How do I route capital through this protocol — using flash loans, DEX primitives — to extract more than I deposit? Which functions are permissionless and interact with external price sources or token swaps?",
    },
    "access_escalator": {
        "system": "You are a privilege escalation specialist. You look for unprotected functions, missing access control on sensitive operations, caller-controlled parameters that should be restricted, and functions that affect other users' funds without their authorization.",
        "cq": "What is the path of least resistance to gaining control of this protocol or affecting other users' funds without authorization? Which sensitive functions lack proper caller validation?",
    },
}

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

STEP1 = """STEP 1 — LIST INVARIANTS (3-6, protocol-specific):
  ✓ "after borrow(), debts[asset] must equal sum of all borrowInfo[asset][user].debt"
  ✓ "registerAsset() must not reduce collateral factor for already-registered asset"
  ✓ "treasuryShare must only be reset after transferring to treasury"
  ✗ Generic: "no reentrancy", "no overflow"
"""

TRACKS = """
TRACK A — ADVERSARIAL INPUTS: test 0, max_uint, address(0), repeated calls.
TRACK B: apply your domain expertise (see system prompt).
"""

def make_prompt(agent_id, contract, source, with_rag: bool):
    a = AGENTS[agent_id]
    rag_block = ""
    if with_rag:
        rag_block = (
            "\n=== MEMORY TOOL ===\n"
            "You have search_historical_findings(query) — thousands of real audit findings.\n"
            "RULE 1: Complete STEP 1 (list invariants) before any RAG call.\n"
            "RULE 2: Each query must state a specific mechanism hypothesis, not a function name.\n"
            "  Format: '[what breaks mechanically] + [specific variable or code detail you observed]'\n"
            "  Good: 'cToken exchange rate read before accrueInterest called, stale rate used in mint'\n"
            "  Good: 'LP shares burned but pool reserves not updated atomically, imbalance possible'\n"
            "  Good: 'governance timelock bypassed when proposer is also executor, instant execution'\n"
            "  Good: 'fee recipient mapping deleted but balance not transferred first, funds locked'\n"
            "  Bad:  'vulnerability in transfer()' — names a function, states no mechanism\n"
            "  Bad:  'reentrancy bug' — names a category, not a specific observable hypothesis\n"
            "RULE 3: If you cannot state a concrete mechanism yet, keep reading code first.\n"
            "Multiple calls encouraged — each targeting a different suspected invariant.\n"
        )
    return f"""=== ROUND 1 — INDEPENDENT DISCOVERY ===
You are {agent_id}.
{a['system']}
{rag_block}
=== CONTRACT: {contract} ===
```solidity
{source}
```

=== EPISTEMIC LENS ===
{a['cq']}

{STEP1}
{TRACKS}

STEP 2 — FIND VIOLATIONS: For each invariant, check if any execution path violates it.
{OUTPUT_FMT}"""

# ─── 13 GT tasks (contract, function, agent, detection keywords) ──────────────
TASKS = [
    # H-01/H-05 same function same bug: test separately but same contract
    ("H-01", "MochiVault",        "borrow",              "invariant_breaker",
     [r"global.*debt.*fee|debts\[.*fee|fee.*not.*add.*debts|undercount.*borrow"]),
    ("H-02", "FeePoolV0",         "distributeMochi",     "state_machine_analyst",
     [r"treasury.*overwrite|overwrite.*treasury|shareMochi.*reset|treasury.*lost|_shareMochi.*reset"]),
    ("H-03", "ReferralFeePoolV0", "claimRewardAsMochi",  "logic_exploiter",
     [r"array.*bound|out.of.bound|index.*exceed|array.*too.small|length.*miss"]),
    ("H-04", "MochiProfileV0",    "registerAsset",       "logic_exploiter",
     [r"overwrite|existing.*class|downgrad|re.?register.*class|already.*register"]),
    ("H-05", "MochiVault",        "borrow",              "invariant_breaker",
     [r"global.*debt|fee.*miss|debt.*fee|accumulator.*fee|debts.*less"]),
    ("H-06", "ReferralFeePoolV0", "claimRewardAsMochi",  "state_machine_analyst",
     [r"reward.*not.*reset|drain|re.?enter|balance.*not.*zero|missing.*reset|claim.*again"]),
    ("H-07", "MochiVault",        "liquidate",           "math_precision",
     [r"underflow|liquidat.*revert|debts.*underflow|discount.*underflow|subtraction.*fail"]),
    ("H-08", "MochiVault",        "deposit",             "logic_exploiter",
     [r"timer.*reset|withdrawal.*reset|griefing|zero.*deposit.*reset|deposit.*zero.*delay"]),
    ("H-09", "MochiTreasuryV0",   "veCRVlock",           "defi_attacker",
     [r"sandwich|slippage.*0|amountOutMin.*0|no.*slippage|front.?run.*swap"]),
    ("H-10", "MochiEngine",       "changeNFT",           "state_machine_analyst",
     [r"break.*protocol|existing.*vault|NFT.*break|position.*lost|orphan|vault.*invalid"]),
    ("H-11", "FeePoolV0",         "_shareMochi",         "state_machine_analyst",
     [r"treasury.*overwrite|overwrite.*treasury|treasury.*lost|reset.*treasury|treasury.*0.*without"]),
    ("H-12", "FeePoolV0",         "distributeMochi",     "defi_attacker",
     [r"sandwich|slippage.*0|amountOutMin.*0|no.*slippage|MEV"]),
    ("H-13", "VestedRewardPool",  "vest",                "access_escalator",
     [r"frontrun|front.?run|account.*control|caller.*recipient|steal.*vest|safeTransferFrom|access.control"]),
]

def detect(response: str, keywords: list) -> bool:
    """Strict: must have FINDING block AND keyword match."""
    return "FINDING:" in response and any(
        re.search(kw, response, re.IGNORECASE) for kw in keywords)

def main():
    out_dir = "/home/thangdd/repos/MiroFish/benchmark/web3bugs/agent-redesign/42/sim_findings_hyp_crossprotocol"
    os.makedirs(out_dir, exist_ok=True)

    summary = []
    hdr = f"{'GT':>5} {'Contract':<20} {'Fn':<22} {'No-RAG':>7} {'RAG':>6} {'RAG-calls':>10}  First FINDING snippet"
    print(f"\n{hdr}")
    print("─" * 100)

    for h_id, contract, fn, agent_id, keywords in TASKS:
        src = SOURCES[contract]

        results = {}
        for with_rag in [False, True]:
            label = "rag" if with_rag else "no_rag"
            prompt = make_prompt(agent_id, contract, src, with_rag)
            print(f"  [{h_id}] {label} ...", flush=True)
            time.sleep(4)
            try:
                resp, rag_n = run_agent(prompt, with_rag)
            except Exception as e:
                print(f"    ERROR: {e}")
                resp, rag_n = f"ERROR: {e}", 0
            found = detect(resp, keywords)
            results[label] = {"found": found, "rag_n": rag_n, "resp": resp}

            # Save full response
            out_file = os.path.join(out_dir, f"{h_id}_{label}_{fn}.txt")
            with open(out_file, 'w') as f:
                f.write(f"GT: {h_id} — {contract}.{fn}\nAgent: {agent_id}\nRAG: {with_rag}\n\n")
                f.write(resp)

        a = results["no_rag"]
        b = results["rag"]
        mark_a = "✅" if a["found"] else "❌"
        mark_b = "✅" if b["found"] else "❌"

        snippet = ""
        for resp in [a["resp"], b["resp"]]:
            m = re.search(r'FINDING: (.{0,60})', resp)
            if m: snippet = m.group(1); break

        print(f"  {h_id:>5} {contract:<20} {fn:<22} {mark_a:>7} {mark_b:>6} {b['rag_n']:>10}  {snippet[:55]}")
        summary.append({
            "id": h_id, "contract": contract, "fn": fn, "agent": agent_id,
            "no_rag": a["found"], "with_rag": b["found"], "rag_calls": b["rag_n"],
        })
        time.sleep(3)

    no_rag_tp  = sum(1 for r in summary if r["no_rag"])
    with_rag_tp = sum(1 for r in summary if r["with_rag"])
    improved = [r["id"] for r in summary if r["with_rag"] and not r["no_rag"]]
    regressed = [r["id"] for r in summary if r["no_rag"] and not r["with_rag"]]

    print(f"\n{'='*70}")
    print(f"No-RAG  TP = {no_rag_tp}/13  ({no_rag_tp/13*100:.1f}%)")
    print(f"With-RAG TP = {with_rag_tp}/13  ({with_rag_tp/13*100:.1f}%)")
    print(f"RAG improved: {improved if improved else 'none'}")
    print(f"RAG regressed: {regressed if regressed else 'none'}")
    print(f"Responses saved to: {out_dir}/")

    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

if __name__ == "__main__":
    main()
