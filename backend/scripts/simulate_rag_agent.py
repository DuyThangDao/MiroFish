"""
Simulation: R1 agent với agentic RAG (solodit_findings collection).
Không có HIST-INV pre-injection. Agent tự query RAG trong lúc reasoning.
Target: registerAsset (H-04) của contest 42.
"""

import sys, os, json, time, re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

# pysqlite3 workaround
import pysqlite3
sys.modules['sqlite3'] = pysqlite3

import chromadb
from chromadb import EmbeddingFunction, Documents, Embeddings
from openai import OpenAI
from dotenv import load_dotenv
import vertexai
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput

load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))

# ─── Vertex AI embedding (same as collection build) ──────────────────────────
KEY_FILE = os.getenv('LLM_VERTEX_AI_KEY_FILE', '')
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = KEY_FILE

class VertexEmbedding(EmbeddingFunction):
    def __init__(self):
        self._model = TextEmbeddingModel.from_pretrained("text-embedding-004")
    def __call__(self, input: Documents) -> Embeddings:
        inputs = [TextEmbeddingInput(t, "RETRIEVAL_QUERY") for t in input]
        return [e.values for e in self._model.get_embeddings(inputs)]

embed_fn = VertexEmbedding()

# ─── Setup ChromaDB ───────────────────────────────────────────────────────────
CHROMA_PATH = os.path.join(os.path.dirname(__file__), '../data/rag_db/chroma')
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
col = chroma_client.get_collection('solodit_findings', embedding_function=embed_fn)
print(f"[RAG] solodit_findings: {col.count()} docs loaded")

def search_historical_findings(query: str, n_results: int = 4) -> str:
    """Query solodit_findings ChromaDB. Returns formatted findings for agent."""
    results = col.query(
        query_texts=[query],
        n_results=min(n_results * 2, 10),  # over-fetch for dedup by slug
        include=['documents', 'metadatas', 'distances']
    )
    docs = results['documents'][0]
    metas = results['metadatas'][0]
    dists = results['distances'][0]

    out = []
    seen_slugs = set()
    for doc, meta, dist in zip(docs, metas, dists):
        slug = meta.get('slug', '')
        if slug in seen_slugs:
            continue
        seen_slugs.add(slug)
        impact = meta.get('impact', '')
        title = meta.get('title', '')
        protocol = meta.get('protocol_name', '')
        score = 1 - dist  # cosine similarity

        out.append(
            f"--- FINDING (score={score:.3f}) ---\n"
            f"SLUG: {slug}\n"
            f"TITLE: {title}\n"
            f"IMPACT: {impact} | PROTOCOL: {protocol}\n"
            f"CONTENT:\n{doc[:1200]}\n"
        )
        if len(out) >= 3:
            break

    return "\n".join(out) if out else "No relevant findings."

# ─── LLM Setup ───────────────────────────────────────────────────────────────
api_key_file = os.getenv('LLM_VERTEX_AI_KEY_FILE', '')
base_url = os.getenv('LLM_BASE_URL', '')
model = os.getenv('LLM_MODEL_NAME', 'google/gemini-3-flash-preview')

# Load Vertex AI key
token = None
if api_key_file and os.path.exists(api_key_file):
    import google.auth
    import google.auth.transport.requests
    from google.oauth2 import service_account
    creds = service_account.Credentials.from_service_account_file(
        api_key_file,
        scopes=['https://www.googleapis.com/auth/cloud-platform']
    )
    req = google.auth.transport.requests.Request()
    creds.refresh(req)
    token = creds.token

llm = OpenAI(api_key=token or "dummy", base_url=base_url)

def llm_call(messages, tools=None, tool_choice=None):
    """Single LLM call with optional tools."""
    kwargs = dict(
        model=model,
        messages=messages,
        temperature=0.3,
        max_tokens=3000,
        extra_body={"google": {"thinking_config": {"thinking_budget": 0}}}
    )
    if tools:
        kwargs['tools'] = tools
        if tool_choice:
            kwargs['tool_choice'] = tool_choice
    resp = llm.chat.completions.create(**kwargs)
    return resp

# ─── Contract Source ──────────────────────────────────────────────────────────
CONTRACT_SOURCE = """
// MochiProfileV0.sol — relevant excerpt

enum AssetClass { Stable, Alpha, Gamma, Delta, Zeta, Sigma }

contract MochiProfileV0 is IMochiProfile {
    IMochiEngine public immutable engine;
    uint256 public override liquidityRequirement;
    uint256 public override minimumDebt;
    mapping(address => AssetClass) internal _assetClass;
    mapping(address => uint256) public override creditCap;

    function assetClass(address _asset) public view override returns (AssetClass) {
        return _assetClass[_asset];
    }

    // Anyone can call this to register any asset as Sigma class
    function registerAsset(address _asset) external {
        uint256 liq = engine.cssr().getLiquidity(_asset);
        require(liq >= liquidityRequirement, "<liquidity");
        _register(_asset, AssetClass.Sigma);
    }

    // Only governance can register with specific class
    function registerAssetByGov(
        address[] calldata _asset,
        AssetClass[] calldata _classes
    ) external onlyGov {
        for (uint256 i = 0; i < _asset.length; i++) {
            _register(_asset[i], _classes[i]);
            engine.vaultFactory().deployVault(_asset[i]);
        }
    }

    function _register(address _asset, AssetClass _class) internal {
        _assetClass[_asset] = _class;
    }

    function changeAssetClass(
        address[] calldata _assets,
        AssetClass[] calldata _classes
    ) external override onlyGov {
        for (uint256 i = 0; i < _assets.length; i++) {
            _assetClass[_assets[i]] = _classes[i];
        }
    }

    // Asset class determines liquidation factor:
    // Stable=95%, Alpha=85%, Gamma=80%, Delta=75%, Zeta=65%, Sigma=50%
    function liquidationFactor(address _asset) public view override returns (float memory) {
        AssetClass class = assetClass(_asset);
        // ... returns factor based on class
        // Sigma class → lowest collateral factor
    }
}
"""

# ─── Tool Definition ──────────────────────────────────────────────────────────
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_historical_findings",
            "description": (
                "Search historical smart contract audit findings from Solodit database. "
                "Use this to recall similar past vulnerabilities that match patterns you observe. "
                "Call multiple times with different queries as your analysis deepens. "
                "Returns real audit findings with vulnerability descriptions and code examples."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Natural language description of the vulnerability pattern you suspect. Be specific about the mechanism."
                    },
                    "n_results": {
                        "type": "integer",
                        "description": "Number of results (default 4, max 6)",
                        "default": 4
                    }
                },
                "required": ["query"]
            }
        }
    }
]

# ─── Agent System Prompt ──────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert Solidity smart contract security auditor.

You have access to `search_historical_findings(query)` — a database of thousands of real audit findings from Solodit.
Use it freely during your analysis whenever you suspect a vulnerability pattern:
- Query when you notice a suspicious code pattern
- Query to recall how similar bugs were exploited in past protocols
- Query multiple times with different angles as your understanding deepens
- Use retrieved findings to deepen your analysis and validate hypotheses

Your task: Perform a thorough security audit of the given contract function.
Think step by step. Identify vulnerabilities. For each finding provide:
FINDING: <title>
FUNCTION: <function name>
SEVERITY: HIGH | MEDIUM | LOW
DESCRIPTION: <detailed explanation>
IMPACT: <what can attacker do>
POC: <step-by-step attack>
"""

# ─── Simulation ───────────────────────────────────────────────────────────────
def run_simulation():
    print("\n" + "="*70)
    print("SIMULATION: Agentic RAG Agent — registerAsset (H-04 target)")
    print("="*70)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": (
            "Audit the following Solidity contract for security vulnerabilities. "
            "Focus on `registerAsset()` and related functions. "
            "Use search_historical_findings to recall relevant past audit findings.\n\n"
            f"CONTRACT SOURCE:\n```solidity\n{CONTRACT_SOURCE}\n```"
        )}
    ]

    turn = 0
    max_turns = 8
    rag_calls = 0

    while turn < max_turns:
        turn += 1
        print(f"\n--- Turn {turn} ---")

        resp = llm_call(messages, tools=TOOLS)
        choice = resp.choices[0]
        msg = choice.message

        # Add assistant message
        messages.append({"role": "assistant", "content": msg.content, "tool_calls": msg.tool_calls})

        # Print assistant text
        if msg.content:
            # Strip think tags
            text = re.sub(r'<think>.*?</think>', '', msg.content or '', flags=re.DOTALL).strip()
            print(f"[Agent]: {text[:1000]}")

        # Handle tool calls
        if msg.tool_calls:
            for tc in msg.tool_calls:
                fn_name = tc.function.name
                args = json.loads(tc.function.arguments)
                query = args.get('query', '')
                n = args.get('n_results', 4)

                print(f"\n[RAG QUERY #{rag_calls+1}]: '{query}'")
                rag_result = search_historical_findings(query, n)
                rag_calls += 1

                # Show what was retrieved
                slugs = re.findall(r'SLUG: ([^\n]+)', rag_result)
                print(f"[RAG RESULT]: Retrieved slugs: {slugs}")

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": rag_result
                })

            time.sleep(3)  # rate limit
            continue

        # No tool calls — agent finished
        print(f"\n[Agent finished after {turn} turns, {rag_calls} RAG queries]")
        break

    print("\n" + "="*70)
    print("FINAL ANSWER:")
    print("="*70)
    final = messages[-1].get('content', '') or ''
    final = re.sub(r'<think>.*?</think>', '', final, flags=re.DOTALL).strip()
    print(final[:3000])

    # Check if H-04 was found
    h04_keywords = ['overwrite', 'already registered', 'existing', 'cannot overwrite',
                    're-register', 'downgrade', 'class.*overwritten', 'sigma.*overwrite']
    found_h04 = any(re.search(kw, final, re.IGNORECASE) for kw in h04_keywords)
    print(f"\n{'='*70}")
    print(f"H-04 FOUND: {'✅ YES' if found_h04 else '❌ NO'}")
    print(f"RAG calls made: {rag_calls}")
    print(f"{'='*70}")

if __name__ == '__main__':
    run_simulation()
