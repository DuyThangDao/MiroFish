"""
Simulation: 13 GT bugs × 2 conditions (no_rag vs with_rag)
- Sử dụng exact prompts từ R1 pipeline
- Agent persona được chọn phù hợp với từng GT
- Condition A: pure agent reasoning, no RAG
- Condition B: agent có search_historical_findings tool (solodit_findings collection)
"""

import sys, os, json, time, re, textwrap
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pysqlite3; sys.modules['sqlite3'] = pysqlite3

import chromadb
from chromadb import EmbeddingFunction, Documents, Embeddings
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))

# ─── Vertex AI embed ──────────────────────────────────────────────────────────
KEY_FILE = os.getenv('LLM_VERTEX_AI_KEY_FILE', '')
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = KEY_FILE

from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput

class VertexEmbed(EmbeddingFunction):
    def __init__(self):
        self._model = TextEmbeddingModel.from_pretrained("text-embedding-004")
    def __call__(self, input: Documents) -> Embeddings:
        ins = [TextEmbeddingInput(t, "RETRIEVAL_QUERY") for t in input]
        return [e.values for e in self._model.get_embeddings(ins)]

embed_fn = VertexEmbed()
CHROMA = chromadb.PersistentClient(path=os.path.join(os.path.dirname(__file__), '../data/rag_db/chroma'))
col = CHROMA.get_collection('solodit_findings', embedding_function=embed_fn)
print(f"[RAG] solodit_findings: {col.count()} docs")

# ─── LLM ──────────────────────────────────────────────────────────────────────
BASE_URL = os.getenv('LLM_BASE_URL', '')
MODEL    = os.getenv('LLM_MODEL_NAME', 'google/gemini-3-flash-preview')
token = None
if KEY_FILE and os.path.exists(KEY_FILE):
    import google.auth.transport.requests
    from google.oauth2 import service_account
    creds = service_account.Credentials.from_service_account_file(
        KEY_FILE, scopes=['https://www.googleapis.com/auth/cloud-platform'])
    creds.refresh(google.auth.transport.requests.Request())
    token = creds.token

llm = OpenAI(api_key=token or "dummy", base_url=BASE_URL)

def _strip_think(text: str) -> str:
    return re.sub(r'<think>.*?</think>', '', text or '', flags=re.DOTALL).strip()

def llm_call(messages, tools=None):
    for attempt in range(3):
        try:
            kwargs = dict(
                model=MODEL, messages=messages, temperature=0.3, max_tokens=3500,
                extra_body={"google": {"thinking_config": {"thinking_budget": 0}}}
            )
            if tools:
                kwargs['tools'] = tools
            resp = llm.chat.completions.create(**kwargs)
            return resp
        except Exception as e:
            if '429' in str(e) or 'rate' in str(e).lower():
                wait = 20 * (attempt + 1)
                print(f"  [rate limit, wait {wait}s]", flush=True)
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("LLM call failed after retries")

# ─── RAG Tool ─────────────────────────────────────────────────────────────────
RAG_TOOL = [{
    "type": "function",
    "function": {
        "name": "search_historical_findings",
        "description": (
            "Search thousands of real smart contract audit findings (Solodit). "
            "Call freely when you suspect a vulnerability — recall past bugs from similar protocols. "
            "Query with the specific mechanism you observe (e.g. 'storage mapping overwrite missing guard'). "
            "Call multiple times with different angles."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Describe the vulnerability pattern you suspect."}
            },
            "required": ["query"]
        }
    }
}]

def search_rag(query: str) -> str:
    results = col.query(query_texts=[query], n_results=8, include=['documents','metadatas','distances'])
    docs, metas, dists = results['documents'][0], results['metadatas'][0], results['distances'][0]
    seen, out = set(), []
    for doc, meta, dist in zip(docs, metas, dists):
        slug = meta.get('slug','')
        if slug in seen: continue
        seen.add(slug)
        title = meta.get('title','')
        protocol = meta.get('protocol_name','')
        score = round(1 - dist, 3)
        out.append(f"[score={score}] {title} (Protocol: {protocol})\nSLUG: {slug}\n{doc[:900]}\n")
        if len(out) >= 3: break
    return "\n---\n".join(out) if out else "No results."

# ─── Exact R1 prompt constants (from contract_oasis_env.py) ──────────────────
_STEP1_BLOCK = """STEP 1 — LIST INVARIANTS:
  Read the full contract source and list 3–6 PROTOCOL-SPECIFIC invariants.
  Format: INV-1: <invariant statement>, INV-2: ..., ...

  Invariants MUST be protocol-specific — NOT acceptable:
    ✗ Generic: "no reentrancy", "no overflow", "onlyOwner"
    ✓ Specific: "after borrow(), global_debts must increase by exactly amount + fee"
    ✓ Specific: "distribute() must only decrease mochiShare, never reset treasuryShare"
    ✓ Specific: "registerAsset() must not overwrite an existing non-default _assetClass"

  Look for: state vars named "total"/"global"/"cumulative", require() messages, NatSpec invariants."""

_TRACKS_BLOCK = """
INDEPENDENT REASONING TRACKS:

TRACK A — ADVERSARIAL INPUTS:
  For the 2-3 most complex functions: test numeric bounds (0, max_uint),
  address(0), empty arrays, cross-function call sequences.
  Any input that corrupts state without reverting = FINDING candidate.

TRACK B/C/D: apply per your domain expertise (see your system prompt).
"""

OUTPUT_FORMAT = """
OUTPUT FORMAT — use ONLY the FINDING format:

  FINDING: <concise title>
  CONTRACT: <contract name>
  FUNCTION: <function name>
  SEVERITY: high|medium|low
  EVIDENCE: CODE: <snippet> | or MISSING: <what> AT: <fn()> | or INV: <invariant> | VIOLATED_AT: <fn()>
  ATTACK_PATH: ACTOR / CALL / STATE_CHANGE / OUTCOME
  DESCRIPTION: <why exploitable>
  PATCH: <fix>

Write NO FINDING if you find nothing. Do not hallucinate vulnerabilities.
"""

def build_r1_prompt(agent_id: str, system_prompt: str, core_question: str,
                    contract_source: str, with_rag: bool) -> str:
    rag_section = ""
    if with_rag:
        rag_section = """
=== MEMORY TOOL ===
You have access to search_historical_findings(query).
Call it when you suspect a pattern — e.g. "storage overwrite without existence check",
"transfer without resetting balance", "array allocation smaller than usage".
Use retrieved findings to deepen your analysis. Call multiple times with different angles.
"""
    return f"""\
=== ROUND 1 — INDEPENDENT DISCOVERY ===
You are {agent_id}.
{system_prompt}

⚠ Use ONLY FINDING blocks. No CLAIM, VALIDATE, CHALLENGE, CONFIRM, or DISMISS.
{rag_section}
=== CONTRACT UNDER REVIEW ===
{contract_source}

=== INSTRUCTIONS ===
Perform an independent security analysis.

=== YOUR EPISTEMIC LENS ===
{core_question}

{_STEP1_BLOCK}

{_TRACKS_BLOCK}

STEP 2 — FIND VIOLATIONS:
  For each invariant, ask:
  Q1: Is there any execution path that makes this invariant false?
  Q2: Can an attacker control that path?
  Q3: If violated, what is the impact?

{OUTPUT_FORMAT}"""

# ─── Agent definitions (exact from CONTRACT_AGENT_MATRIX) ────────────────────
AGENTS = {
    "logic_exploiter": {
        "system": (
            "You are a business logic specialist who finds gaps between intended behavior and actual implementation "
            "at a semantic level — not syntax bugs, but protocol design bugs. "
            "You look for: state ordering bugs (A computed before B updated, but should be after), "
            "rounding asymmetry that consistently favors the attacker, "
            "cross-function state inconsistency where two functions each look correct but their interaction creates a bug, "
            "griefing vectors that let an attacker permanently harm other users at low cost, "
            "and semantic gaps between what the spec says should happen and what the code actually does. "
            "When you identify a suspicious design choice, write a FINDING first, then articulate "
            "the worst-case scenario — even if speculative. "
            "Do not use inability to prove the full attack path as a reason to stay silent."
        ),
        "cq": (
            "For each accumulator, reference variable, or operation ordering in this contract: "
            "is this the correct choice for the intended invariant? "
            "If the answer is 'possibly not', write a FINDING first, then articulate the worst-case scenario."
        ),
    },
    "state_machine_analyst": {
        "system": (
            "You are a formal methods engineer who reads smart contracts as finite state machines. "
            "You look for invalid state transitions, dead-end states from which recovery is impossible, "
            "and states where safety invariants are permanently broken. "
            "Key patterns: missing transitions that leave funds permanently locked, "
            "state inconsistency between storage variables after failed or partial operations, "
            "and update ordering bugs where Variable A is read before B is updated — but should be after. "
            "TRACK C — STATE CONSISTENCY: Identify storage variables written by more than one function. "
            "For each shared variable: Is there an ordering where function A partially updates and function B reads stale state? "
            "Focus on: cumulative totals, balance mappings, index variables. "
            "If inconsistent state is reachable → FINDING with the exact call sequence."
        ),
        "cq": (
            "Can this contract enter a state from which recovery is impossible, "
            "or where safety invariants are permanently broken? "
            "Is there any function that writes storage without first verifying the prior state is valid? "
            "Can any call sequence leave a storage variable permanently incorrect?"
        ),
    },
    "invariant_breaker": {
        "system": (
            "You are a formal methods adversary who specializes in breaking mathematical invariants. "
            "You look for boundary conditions, off-by-one errors, domain restrictions not enforced by the caller, "
            "and invariants that hold for typical inputs but fail at extreme values (zero, max uint, boundary). "
            "ACCUMULATOR UPDATE ORDER: for every function that changes a denominator state variable "
            "(debts, shares, supply, balance) — verify the accumulator is computed BEFORE the denominator changes."
        ),
        "cq": (
            "What is the set of inputs that causes any mathematical invariant in this contract to fail? "
            "For every accounting variable: does it remain correct across all valid call sequences? "
            "Specifically: is the global/cumulative value always equal to the sum of individual values?"
        ),
    },
    "math_precision": {
        "system": (
            "You are a quantitative analyst who reads smart contract code as a mathematical system. "
            "You know that integer arithmetic in Solidity has specific rounding behavior that attackers can exploit: "
            "division truncates toward zero, fixed-point operations accumulate precision loss, "
            "and share inflation via first-deposit is a classic ERC4626 bug. "
            "You trace every arithmetic operation to determine if accumulated error can be extracted."
        ),
        "cq": (
            "Are there inputs or sequences of operations that cause this mathematical system "
            "to diverge from its intended behavior in a way that favors an attacker? "
            "Test edge cases: zero values, max values, repeated operations over time."
        ),
    },
    "defi_attacker": {
        "system": (
            "You are a DeFi exploit developer with access to flash loans and MEV infrastructure. "
            "You treat protocols as capital extraction machines: your job is to route capital through "
            "the protocol — using flash loans, DEX primitives, and arbitrary call sequences — "
            "to extract more than you deposit in atomic or near-atomic transactions. "
            "You look for price oracle manipulation via spot DEX, sandwich attacks, "
            "stale oracle exploitation, and cross-contract reentrancy."
        ),
        "cq": (
            "How do I route capital through this protocol — using flash loans, DEX primitives, "
            "and arbitrary call sequences — to extract more than I deposit? "
            "Which functions are permissionless and interact with external price sources or token swaps?"
        ),
    },
    "access_escalator": {
        "system": (
            "You are a privilege escalation specialist. Every contract has admin or owner privileges — "
            "your job is to find the shortest path to acquiring them or bypassing them. "
            "You look for unprotected functions, missing access control on sensitive operations, "
            "caller-controlled parameters that should be restricted, "
            "and functions that affect other users' funds without their authorization."
        ),
        "cq": (
            "What is the path of least resistance to gaining control of this protocol or "
            "affecting other users' funds without authorization? "
            "Which functions lack proper caller validation?"
        ),
    },
}

# ─── GT Bug Definitions ───────────────────────────────────────────────────────
# Keywords để detect nếu agent tìm ra đúng GT bug
GT_BUGS = [
    {
        "id": "H-01", "function": "borrow", "contract": "MochiVault",
        "title": "Vault fails to track debt correctly — global debts < sum of individual debts",
        "agent": "invariant_breaker",
        "keywords": ["global.*debt|debts.*global", "fee.*not.*add|not.*add.*fee", "borrow.*fee.*miss|miss.*fee", "undercount|accumulator.*wrong|global.*less"],
        "source": """
contract MochiVault {
    // global debt tracker across all positions
    mapping(address => uint256) public debts; // asset → total debt
    mapping(address => mapping(address => BorrowInfo)) public borrowInfo; // asset → user → info

    // debtIndex tracks cumulative interest per asset
    mapping(address => uint256) public debtIndex; // asset → cumulative index

    modifier updateDebt(address _asset) {
        // accrues interest, updates debtIndex
        _accrueDebt(_asset);
        _;
    }

    function borrow(address _asset, uint256 _amount, address _recipient)
        external
        updateDebt(_asset)
    {
        // fee is applied to individual borrow position
        uint256 fee = (_amount * stabilityFee) / 1e18;

        // individual position: stored with fee included
        borrowInfo[_asset][msg.sender].debt += _amount + fee;

        // global debt tracker: updated WITHOUT fee (only base amount)
        debts[_asset] += _amount;

        // mint USDM to recipient
        usdm().mint(_recipient, _amount);
    }

    function repay(address _asset, address _payer, uint256 _amount)
        external
        updateDebt(_asset)
    {
        uint256 amount = _min(_amount, borrowInfo[_asset][_payer].debt);
        borrowInfo[_asset][_payer].debt -= amount;
        debts[_asset] -= amount; // global reduced by repay amount
        usdm().burn(_payer, amount);
    }

    // stabilityFee: fraction of borrow amount charged as fee (e.g. 0.5% = 5e15)
    uint256 public stabilityFee;
}"""
    },
    {
        "id": "H-02", "function": "distributeMochi", "contract": "FeePoolV0",
        "title": "distributeMochi() flushes treasuryShare without transferring it",
        "agent": "state_machine_analyst",
        "keywords": ["treasuryShare.*reset|reset.*treasury", "flush|zero.*without.*transfer|reset.*without", "treasury.*lost|treasuryShare.*overwrite"],
        "source": """
contract FeePoolV0 {
    uint256 public treasuryShare;
    uint256 public mochiShare;

    function _shareMochi(uint256 _amount) internal {
        // splits incoming amount between treasury and mochi
        treasuryShare = (_amount * treasuryRatio) / 1e18;
        mochiShare = _amount - treasuryShare;
    }

    function distributeMochi() external {
        // converts fees to mochi via swap
        uint256 amount = _swapToMochi();

        // BUG: _shareMochi overwrites treasuryShare with new value
        // Any previously accumulated treasuryShare is LOST (never transferred to treasury)
        _shareMochi(amount);

        // distribute mochiShare to stakers
        _distributeToStakers(mochiShare);
        mochiShare = 0;
        // NOTE: treasuryShare is NOT transferred here — it accumulates for later claim
    }

    function sendToTreasury() external {
        uint256 amount = treasuryShare;
        treasuryShare = 0;
        mochi.transfer(treasury, amount);
    }
}"""
    },
    {
        "id": "H-03", "function": "claimRewardAsMochi", "contract": "ReferralFeePoolV0",
        "title": "Array out-of-bounds: memory array allocated smaller than needed",
        "agent": "logic_exploiter",
        "keywords": ["array.*bound|out.of.bound|index.*length", "array.*length|alloc.*too.small|memory.*array"],
        "source": """
contract ReferralFeePoolV0 {
    // referrals[user] = list of referred addresses
    mapping(address => address[]) public referrals;
    mapping(address => uint256) public referralWeight; // weight per referral
    mapping(address => uint256) public totalWeight;    // total weight per referrer

    function claimRewardAsMochi(address _referrer) external {
        address[] memory referred = referrals[_referrer];
        uint256 n = referred.length;

        // Allocate arrays for swap parameters
        // BUG: only allocates n slots but loop assigns n items using different indexing
        address[] memory path = new address[](n);
        uint256[] memory amounts = new uint256[](n);

        uint256 totalReward = rewardOf(_referrer);
        for (uint256 i = 0; i < n; i++) {
            address ref = referred[i];
            uint256 weight = referralWeight[ref];
            uint256 share = (totalReward * weight) / totalWeight[_referrer];

            // When totalWeight[_referrer] is 0 but referrals exist: division by zero
            // OR: if array length calculation is wrong → index out of bounds
            path[i] = ref;          // Uses index i: fine if n correct
            amounts[i] = share;
        }
        // call external with arrays
        engine.claimReward(_referrer, path, amounts);
        rewardBalance[_referrer] = 0;
    }
}"""
    },
    {
        "id": "H-04", "function": "registerAsset", "contract": "MochiProfileV0",
        "title": "registerAsset() can overwrite existing _assetClass set by governance",
        "agent": "logic_exploiter",
        "keywords": ["overwrite|override.*class|downgrad", "existing.*class|already.*register|class.*reset", "sigma.*replace|re.register|class.*change"],
        "source": """
contract MochiProfileV0 {
    // AssetClass determines liquidation factor:
    // Stable=95%, Alpha=85%, Gamma=80%, Delta=75%, Zeta=65%, Sigma=50%
    enum AssetClass { Stable, Alpha, Gamma, Delta, Zeta, Sigma }

    mapping(address => AssetClass) internal _assetClass;
    uint256 public liquidityRequirement;

    // Governance can register asset with specific class
    function registerAssetByGov(address[] calldata _asset, AssetClass[] calldata _classes)
        external onlyGov
    {
        for (uint256 i = 0; i < _asset.length; i++) {
            _register(_asset[i], _classes[i]);
        }
    }

    // Anyone can register an asset as Sigma class (lowest collateral factor)
    function registerAsset(address _asset) external {
        uint256 liq = engine.cssr().getLiquidity(_asset);
        require(liq >= liquidityRequirement, "<liquidity");
        // BUG: No check whether _asset is already registered with a better class
        // An asset registered as Alpha (85%) can be downgraded to Sigma (50%) by anyone
        _register(_asset, AssetClass.Sigma);
    }

    function _register(address _asset, AssetClass _class) internal {
        _assetClass[_asset] = _class; // unconditional overwrite
    }

    function assetClass(address _asset) public view returns (AssetClass) {
        return _assetClass[_asset];
    }
}"""
    },
    {
        "id": "H-05", "function": "borrow", "contract": "MochiVault",
        "title": "debts[] global accumulator not updated by borrow fee → bad debt",
        "agent": "invariant_breaker",
        "keywords": ["global.*debt|debts.*fee|fee.*global", "undercount|borrow.*fee.*miss|accumulator"],
        "source": """// Same as H-01 — same function, same bug""" + """
contract MochiVault {
    mapping(address => uint256) public debts; // GLOBAL debt per asset
    mapping(address => mapping(address => BorrowInfo)) public borrowInfo; // per-user

    function borrow(address _asset, uint256 _amount, address _recipient)
        external updateDebt(_asset)
    {
        uint256 fee = (_amount * stabilityFee) / 1e18;

        // Individual position includes fee
        borrowInfo[_asset][msg.sender].debt += _amount + fee;

        // Global debts does NOT include fee
        debts[_asset] += _amount;  // Missing: + fee

        usdm().mint(_recipient, _amount);
    }

    function liquidate(address _asset, address _owner, address _recipient)
        external updateDebt(_asset)
    {
        uint256 debt = borrowInfo[_asset][_owner].debt;
        // When protocol tries to reduce global debts by debt amount:
        // debts[_asset] -= debt  → can UNDERFLOW because debt > debts[_asset]
        // (individual debt grew with fees, global tracker didn't)
        _repayAndLiquidate(_asset, _owner, debt, _recipient);
    }
}"""
    },
    {
        "id": "H-06", "function": "claimRewardAsMochi", "contract": "ReferralFeePoolV0",
        "title": "Referrer can drain pool: reward balance not reset before transfer",
        "agent": "state_machine_analyst",
        "keywords": ["drain|re.entr|reward.*reset|balance.*not.*reset|claim.*again", "missing.*zero|reward.*before.*transfer|reentr"],
        "source": """
contract ReferralFeePoolV0 {
    mapping(address => uint256) public rewardBalance; // accumulated reward per referrer

    function claimRewardAsMochi(address _referrer) external {
        uint256 reward = rewardBalance[_referrer];
        require(reward > 0, "no reward");

        // Convert reward to mochi via engine
        uint256 mochiAmount = engine.getMochiAmount(reward);

        // BUG: rewardBalance NOT reset before external call
        // External call could re-enter claimRewardAsMochi again
        engine.claimMochi(_referrer, mochiAmount);  // external call

        // Reset happens AFTER external call — too late if re-entrant
        // rewardBalance[_referrer] = 0;  ← this line is MISSING entirely in buggy version
        // The reward is transferred but never deducted from storage

        emit ClaimReward(_referrer, reward);
    }
}"""
    },
    {
        "id": "H-07", "function": "liquidate", "contract": "MochiVault",
        "title": "Liquidation reverts due to underflow when discount > 0",
        "agent": "math_precision",
        "keywords": ["underflow|liquidat.*revert|discount.*underflow", "debts.*underflow|subtraction.*revert|cannot.*liquidat"],
        "source": """
contract MochiVault {
    mapping(address => uint256) public debts; // global per asset

    modifier updateDebt(address _asset) {
        _accrueDebt(_asset); // increases debts[_asset] by accumulated interest
        _;
    }

    function liquidate(address _asset, address _owner, address _recipient)
        external updateDebt(_asset)
    {
        uint256 debt = borrowInfo[_asset][_owner].debt;
        uint256 discountFactor = profile.discountProfile(_asset); // e.g. 95% = 95e16

        // Liquidation with discount: protocol pays liquidator bonus
        // The amount subtracted from global debts uses the FULL debt
        // But because debts[] was not incremented with fees (H-01/H-05 bug),
        // debts[_asset] < sum of individual debts
        // When discount is non-zero, extra deductions cause underflow

        uint256 liquidationAmount = (debt * discountFactor) / 1e18;

        // This can underflow: debts[_asset] might be less than liquidationAmount
        debts[_asset] -= liquidationAmount;  // UNDERFLOW if discountFactor > debts ratio
        borrowInfo[_asset][_owner].debt = 0;

        // Transfer collateral to liquidator at discounted price
        _settleWithDiscount(_asset, _owner, _recipient, liquidationAmount);
    }
}"""
    },
    {
        "id": "H-08", "function": "deposit", "contract": "MochiVault",
        "title": "Anyone can extend withdrawal wait period by depositing zero collateral",
        "agent": "logic_exploiter",
        "keywords": ["withdrawal.*timer|timer.*reset|griefing|delay.*reset|zero.*deposit|deposit.*zero"],
        "source": """
contract MochiVault {
    mapping(address => mapping(address => uint256)) public lastDeposit; // asset → user → timestamp

    // Withdrawal has a delay after last deposit (anti-flash-loan)
    uint256 public withdrawDelay; // e.g. 3 minutes

    function deposit(address _asset, uint256 _amount, address _depositor)
        external
    {
        // Transfer collateral from depositor
        IERC20(_asset).transferFrom(msg.sender, address(this), _amount);

        // BUG: lastDeposit updated even when _amount == 0
        // Attacker calls deposit(asset, 0, victim) to reset victim's withdrawal timer
        lastDeposit[_asset][_depositor] = block.timestamp;

        _addCollateral(_asset, _depositor, _amount);
    }

    function withdraw(address _asset, uint256 _amount)
        external
    {
        // Must wait withdrawDelay since last deposit
        require(
            block.timestamp >= lastDeposit[_asset][msg.sender] + withdrawDelay,
            "too early"
        );
        _removeCollateral(_asset, msg.sender, _amount);
    }
}"""
    },
    {
        "id": "H-09", "function": "veCRVlock", "contract": "MochiTreasuryV0",
        "title": "Treasury sandwich attack via permissionless veCRVlock()",
        "agent": "defi_attacker",
        "keywords": ["sandwich|front.run|MEV|slippage.*0|amountOutMin.*0|swap.*no.*slippage"],
        "source": """
contract MochiTreasuryV0 {
    ICurveGauge public curveGauge;
    address public crvPool; // Uniswap/Sushi pool for CRV→MOCHI

    // Anyone can call — converts treasury CRV to veCRV or MOCHI
    function veCRVlock(uint256 _amount) external {
        uint256 crvBalance = crv.balanceOf(address(this));
        require(crvBalance >= _amount, "!balance");

        // Swap CRV to MOCHI via Uniswap — NO slippage protection
        address[] memory path = new address[](2);
        path[0] = address(crv);
        path[1] = address(mochi);

        // amountOutMin = 0 → accepts any price → sandwich attack target
        router.swapExactTokensForTokens(
            _amount,
            0,          // BUG: no minimum output
            path,
            address(this),
            block.timestamp
        );
    }
}"""
    },
    {
        "id": "H-10", "function": "changeNFT", "contract": "MochiEngine",
        "title": "Changing NFT contract address breaks all existing vault positions",
        "agent": "state_machine_analyst",
        "keywords": ["NFT.*break|existing.*position|vault.*break|ownership.*invalid", "change.*nft.*break|protocol.*break|collateral.*lost"],
        "source": """
contract MochiEngine {
    IMochiNFT public nft; // NFT contract representing vault ownership

    // Governance can change the NFT contract
    function changeNFT(address _nft) external onlyGov {
        // BUG: overwrites nft address with no migration
        // All existing vault positions are keyed to the OLD nft contract
        // After this change:
        // - existing NFT holders can no longer access their vaults
        // - ownerOf() calls return addresses from old contract
        // - all debt and collateral positions become orphaned
        nft = IMochiNFT(_nft);
    }

    // Vault ownership check uses nft.ownerOf()
    function vaultOwner(uint256 _id) external view returns (address) {
        return nft.ownerOf(_id); // uses current nft address
    }

    // All vault operations check vault ownership via nft
    function borrow(uint256 _vaultId, uint256 _amount) external {
        require(nft.ownerOf(_vaultId) == msg.sender, "!owner");
        // ... borrow logic
    }
}"""
    },
    {
        "id": "H-11", "function": "_shareMochi", "contract": "FeePoolV0",
        "title": "treasuryShare overwritten by _shareMochi without prior transfer",
        "agent": "state_machine_analyst",
        "keywords": ["treasuryShare.*overwrite|overwrite.*treasury", "treasury.*lost|reset.*treasury|treasury.*0.*without"],
        "source": """
contract FeePoolV0 {
    uint256 public treasuryShare;  // accumulated fees owed to treasury
    uint256 public mochiShare;

    function _shareMochi(uint256 _amount) internal {
        // BUG: overwrites treasuryShare unconditionally
        // If treasuryShare was 100 before this call, and _amount = 200:
        // New treasuryShare = 200 * ratio, old 100 is LOST
        treasuryShare = (_amount * treasuryRatio) / 1e18;  // OVERWRITE, not +=
        mochiShare = _amount - treasuryShare;
    }

    // Called from updateReserve() periodically
    function updateReserve(address _asset) external {
        uint256 fees = _collectFees(_asset);
        if (fees > 0) {
            _shareMochi(fees); // This overwrites existing treasuryShare
        }
    }

    // Treasury can claim its accumulated share
    function sendToTreasury() external {
        uint256 amount = treasuryShare;
        require(amount > 0, "!amount");
        treasuryShare = 0;
        mochi.transfer(treasury, amount);
    }
}"""
    },
    {
        "id": "H-12", "function": "distributeMochi", "contract": "FeePoolV0",
        "title": "distributeMochi() Uniswap swap has no slippage protection — sandwich",
        "agent": "defi_attacker",
        "keywords": ["sandwich|slippage.*0|amountOutMin.*0|front.run|MEV|no.*slippage"],
        "source": """
contract FeePoolV0 {
    IUniswapV2Router public router;
    address public mochi;

    function distributeMochi() external {
        uint256 balance = baseToken.balanceOf(address(this));
        if (balance == 0) return;

        address[] memory path = new address[](2);
        path[0] = address(baseToken);
        path[1] = mochi;

        // BUG: amountOutMin = 0 → no slippage protection
        // Any caller can sandwich this transaction:
        // 1. Front-run: dump mochi price in pool
        // 2. distributeMochi executes → gets very few mochi
        // 3. Back-run: profit from price recovery
        router.swapExactTokensForTokens(
            balance,
            0,              // no minimum output
            path,
            address(this),
            block.timestamp
        );
        _shareMochi(mochi.balanceOf(address(this)));
    }
}"""
    },
    {
        "id": "H-13", "function": "vest", "contract": "VestedRewardPool",
        "title": "vest() can be frontrun: no safeTransferFrom, recipient controlled by caller",
        "agent": "access_escalator",
        "keywords": ["frontrun|front.run|safeTransferFrom|recipient.*control|caller.*recipient", "steal.*vest|account.*param|access.*control.*vest"],
        "source": """
contract VestedRewardPool {
    struct Vesting {
        uint256 amount;
        uint256 timestamp;
    }
    mapping(address => Vesting) public vestings;
    IERC20 public mochi;

    // Anyone can call vest() for any account
    // BUG: 'account' parameter is fully caller-controlled — no check that caller == account
    function vest(address account, uint256 amount) external {
        require(amount > 0, "!amount");
        _update(account);  // update vesting state

        // Transfers FROM msg.sender (the caller), assigns vesting TO account
        // Attacker scenario: victim approves this contract for mochi
        // Attacker calls vest(victimAddress, victimBalance) → frontrun victim's own vest()
        // The mochi tokens are vested to victimAddress but at a time controlled by attacker
        // OR: attacker calls vest(attackerAddress, X) while victim's vest() is in mempool
        //     to capture the tokens before victim's transaction

        // Uses transfer (not safeTransferFrom), so failed transfers are silent
        mochi.transferFrom(msg.sender, address(this), amount);
        vestings[account].amount += amount;
        vestings[account].timestamp = block.timestamp;

        emit Vested(account, amount);
    }
}"""
    },
]

# ─── Run simulation ───────────────────────────────────────────────────────────
def run_one(gt: dict, with_rag: bool) -> dict:
    agent_id = gt["agent"]
    agent = AGENTS[agent_id]
    prompt = build_r1_prompt(agent_id, agent["system"], agent["cq"], gt["source"], with_rag)

    messages = [{"role": "user", "content": prompt}]
    rag_calls = 0
    all_text = ""

    for turn in range(6):
        resp = llm_call(messages, tools=RAG_TOOL if with_rag else None)
        msg = resp.choices[0].message
        text = _strip_think(msg.content)
        all_text += text + "\n"
        messages.append({"role": "assistant", "content": msg.content,
                          "tool_calls": msg.tool_calls})

        if msg.tool_calls and with_rag:
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments)
                query = args.get("query", "")
                print(f"      RAG[{rag_calls+1}]: '{query[:70]}'", flush=True)
                result = search_rag(query)
                rag_calls += 1
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
            time.sleep(4)
            continue

        break  # no tool calls → done

    # Detect GT hit
    found = any(re.search(kw, all_text, re.IGNORECASE) for kw in gt["keywords"])
    return {"found": found, "rag_calls": rag_calls, "response_len": len(all_text)}

def main():
    results = []
    print(f"\n{'='*72}")
    print(f"{'GT-ID':<7} {'Function':<22} {'Agent':<22} {'No-RAG':>7} {'With-RAG':>9} {'RAG-calls':>10}")
    print(f"{'-'*72}")

    for gt in GT_BUGS:
        gid = gt["id"]
        fn  = gt["function"]
        ag  = gt["agent"]

        # Condition A: no RAG
        print(f"  [{gid}] no_rag ...", flush=True)
        time.sleep(3)
        try:
            res_a = run_one(gt, with_rag=False)
        except Exception as e:
            print(f"    ERROR: {e}")
            res_a = {"found": False, "rag_calls": 0, "response_len": 0}

        # Condition B: with RAG
        print(f"  [{gid}] with_rag ...", flush=True)
        time.sleep(5)
        try:
            res_b = run_one(gt, with_rag=True)
        except Exception as e:
            print(f"    ERROR: {e}")
            res_b = {"found": False, "rag_calls": 0, "response_len": 0}

        a = "✅" if res_a["found"] else "❌"
        b = "✅" if res_b["found"] else "❌"
        print(f"  {gid:<7} {fn:<22} {ag:<22} {a:>7} {b:>9} {res_b['rag_calls']:>10}", flush=True)

        results.append({
            "id": gid, "function": fn, "agent": ag,
            "no_rag": res_a["found"],
            "with_rag": res_b["found"],
            "rag_calls": res_b["rag_calls"],
        })

        time.sleep(5)

    # Summary
    no_rag_tp  = sum(1 for r in results if r["no_rag"])
    with_rag_tp = sum(1 for r in results if r["with_rag"])
    print(f"\n{'='*72}")
    print(f"RESULTS: No-RAG TP={no_rag_tp}/13  |  With-RAG TP={with_rag_tp}/13")
    print(f"RAG improvement: +{with_rag_tp - no_rag_tp} findings")
    print(f"{'='*72}")

    # Save
    out_path = os.path.join(os.path.dirname(__file__), '../..', 'benchmark/web3bugs/agent-redesign/42/sim_rag_vs_norag.json')
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Saved: {out_path}")

if __name__ == '__main__':
    main()
