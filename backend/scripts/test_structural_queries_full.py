"""
Full test: structural property queries vs operation queries — contest 35 & 42, all H bugs.
"""
import os, sys, json, re, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scripts'))

import pysqlite3
sys.modules['sqlite3'] = pysqlite3

os.environ.setdefault(
    'GOOGLE_APPLICATION_CREDENTIALS',
    '/home/thangdd/repos/MiroFish/vertex-ai-2.json'
)

# Load .env
for line in open('/home/thangdd/repos/MiroFish/.env'):
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, _, v = line.partition('=')
        os.environ[k.strip()] = v.strip().split('  #')[0].strip()

from scripts.rag.rag_retriever import SolodirRetriever
from app.utils.llm_client import LLMClient

# ── File paths ────────────────────────────────────────────────────────────────
_C35  = "/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/pool/concentrated/"
_C35_CLP  = _C35 + "ConcentratedLiquidityPool.sol"
_C35_CLPM = _C35 + "ConcentratedLiquidityPoolManager.sol"
_C35_CLPP = _C35 + "ConcentratedLiquidityPosition.sol"
_C35_TICKS = "/home/thangdd/repos/web3bugs/contracts/35/trident/contracts/libraries/concentratedPool/Ticks.sol"

_C42 = "/home/thangdd/repos/web3bugs/contracts/42/projects/mochi-core/contracts/"
_C42_VAULT   = _C42 + "vault/MochiVault.sol"
_C42_PROFILE = _C42 + "profile/MochiProfileV0.sol"
_C42_FEE     = _C42 + "feePool/FeePoolV0.sol"
_C42_REFFEE  = _C42 + "feePool/ReferralFeePoolV0.sol"
_C42_TREASURY= _C42 + "treasury/MochiTreasuryV0.sol"
_C42_ENGINE  = _C42 + "MochiEngine.sol"
_C42_VEST    = _C42 + "emission/VestedRewardPool.sol"

TARGETS = [
    # ── Contest 42 (13 H bugs) ────────────────────────────────────────────────
    dict(contest=42, h_id="H-01", fn="borrow",           file=_C42_VAULT,    expected="Vault fails to track debt correctly that leads to bad debt"),
    dict(contest=42, h_id="H-02", fn="distributeMochi",  file=_C42_FEE,      expected="FeePoolV0.distributeMochi() will unexpectedly flush treasury"),
    dict(contest=42, h_id="H-03", fn="claimRewardAsMochi", file=_C42_REFFEE, expected="ReferralFeePoolV0.claimRewardAsMochi() Array out of bound exception"),
    dict(contest=42, h_id="H-04", fn="registerAsset",    file=_C42_PROFILE,  expected="registerAsset() can overwrite _assetClass value"),
    dict(contest=42, h_id="H-05", fn="borrow",           file=_C42_VAULT,    expected="debts calculation is not accurate"),
    dict(contest=42, h_id="H-06", fn="claimRewardAsMochi", file=_C42_REFFEE, expected="Referrer can drain ReferralFeePoolV0"),
    dict(contest=42, h_id="H-07", fn="liquidate",        file=_C42_VAULT,    expected="Liquidation will never work with non-zero discounts"),
    dict(contest=42, h_id="H-08", fn="deposit",          file=_C42_VAULT,    expected="Anyone can extend withdraw wait period by depositing zero collateral"),
    dict(contest=42, h_id="H-09", fn="veCRVlock",        file=_C42_TREASURY, expected="treasury is vulnerable to sandwich attack"),
    dict(contest=42, h_id="H-10", fn="changeNFT",        file=_C42_ENGINE,   expected="Changing NFT contract in the MochiEngine would break the protocol"),
    dict(contest=42, h_id="H-11", fn="_shareMochi",      file=_C42_FEE,      expected="treasuryShare is Overwritten in FeePoolV0._shareMochi()"),
    dict(contest=42, h_id="H-12", fn="distributeMochi",  file=_C42_FEE,      expected="feePool is vulnerable to sandwich attack"),
    dict(contest=42, h_id="H-13", fn="vest",             file=_C42_VEST,     expected="Tokens Can Be Stolen By Frontrunning VestedRewardPool.vest()"),
    # ── Contest 35 (17 H bugs) ────────────────────────────────────────────────
    dict(contest=35, h_id="H-01", fn="burn",                   file=_C35_CLP,  expected="Unsafe cast in ConcentratedLiquidityPool.burn leads to attack"),
    dict(contest=35, h_id="H-02", fn="subscribe",              file=_C35_CLPM, expected="Wrong usage of positionId in ConcentratedLiquidityPoolManager.subscribe"),
    dict(contest=35, h_id="H-03", fn="reclaimIncentive",       file=_C35_CLPM, expected="ConcentratedLiquidityPoolManager incentives can be stolen"),
    dict(contest=35, h_id="H-04", fn="mint",                   file=_C35_CLP,  expected="Overflow in the mint function of ConcentratedLiquidityPool"),
    dict(contest=35, h_id="H-05", fn="_getAmountsForLiquidity", file=_C35_CLP, expected="Incorrect usage of typecasting in _getAmountsForLiquidity"),
    dict(contest=35, h_id="H-06", fn="collect",                file=_C35_CLPP, expected="Users may get double the amount of yield when they call collect"),
    dict(contest=35, h_id="H-07", fn="burn",                   file=_C35_CLPP, expected="ConcentratedLiquidityPosition.burn() wrong implementation"),
    dict(contest=35, h_id="H-08", fn="mint",                   file=_C35_CLP,  expected="Wrong inequality when adding/removing liquidity in current price range"),
    dict(contest=35, h_id="H-09", fn="rangeFeeGrowth",         file=_C35_CLP,  expected="rangeFeeGrowth underflow causes pool to become permanently broken"),
    dict(contest=35, h_id="H-10", fn="burn",                   file=_C35_CLP,  expected="ConcentratedLiquidityPool.burn() wrong reserve update"),
    dict(contest=35, h_id="H-11", fn="cross",                  file=_C35_TICKS,expected="ConcentratedLiquidityPool: incorrect feeGrowthGlobal accounting"),
    dict(contest=35, h_id="H-12", fn="mint",                   file=_C35_CLP,  expected="secondsPerLiquidity should be updated before liquidity changes"),
    dict(contest=35, h_id="H-13", fn="burn",                   file=_C35_CLP,  expected="Burning does not update reserves correctly"),
    dict(contest=35, h_id="H-14", fn="rangeFeeGrowth",         file=_C35_CLP,  expected="rangeFeeGrowth and secondsPerLiquidity calculation errors"),
    dict(contest=35, h_id="H-15", fn="setPrice",               file=_C35_CLP,  expected="initialPrice not validated against sqrtPriceLimits"),
    dict(contest=35, h_id="H-16", fn="claimReward",            file=_C35_CLPM, expected="Possible JIT liquidity attack on secondsPerLiquidity reward"),
    dict(contest=35, h_id="H-17", fn="rangeFeeGrowth",         file=_C35_CLP,  expected="nearestTick is unsuitable as reference point for fee growth"),
]

SCORE_THRESHOLD = 0.65
LLM_DELAY = 5
LLM_MAX_TOKENS = 8192


# ── Helpers ───────────────────────────────────────────────────────────────────

def extract_fn_body(filepath: str, fn_name: str) -> str:
    try:
        src = open(filepath).read()
    except Exception as e:
        return f"<file error: {e}>"
    pattern = re.compile(r'function\s+' + re.escape(fn_name) + r'\s*\(', re.MULTILINE)
    m = pattern.search(src)
    if not m:
        return f"<{fn_name} not found>"
    start = m.start()
    depth, i = 0, start
    while i < len(src):
        if src[i] == '{': depth += 1
        elif src[i] == '}':
            depth -= 1
            if depth == 0:
                return src[start:i+1]
        i += 1
    return src[start:start+3000]


def _llm_call(client, prompt: str) -> list[str]:
    for attempt in range(2):
        try:
            raw = client.chat(
                [{"role": "user", "content": prompt}],
                temperature=0, max_tokens=LLM_MAX_TOKENS
            ).strip()
            if raw:
                lines = [ln.strip().lstrip('0123456789.-) ').strip()
                         for ln in raw.split('\n') if ln.strip()
                         and not ln.strip().startswith('```')]
                lines = [l for l in lines if l]
                if lines:
                    return lines
            if attempt == 0:
                print(f"    [LLM empty, retry after {LLM_DELAY}s]")
                time.sleep(LLM_DELAY)
        except Exception as e:
            print(f"    [LLM error attempt {attempt}] {str(e)[:80]}")
            time.sleep(LLM_DELAY)
    return []


def llm_operation_queries(fn_name: str, fn_body: str, client) -> list[str]:
    prompt = (
        "You are a Solidity code analyst.\n\n"
        f"Function: {fn_name}()\nBody:\n{fn_body.strip()[:2500]}\n\n"
        "Generate search queries to find historical vulnerability findings related to this function.\n"
        "Each query must target a DIFFERENT operation or pattern in this function.\n"
        "List ALL distinct operations — do not merge or skip any.\n"
        "Focus on: type casts, arithmetic operations, state updates, unchecked blocks, external calls.\n"
        "Be specific about data types (uint128, int128, uint256) and operations.\n"
        "Do NOT describe business purpose. Do NOT add 'vulnerability' keyword.\n"
        "Format: one query per line, max 15 words each.\n"
        "Output ONLY the queries, nothing else."
    )
    time.sleep(LLM_DELAY)
    return _llm_call(client, prompt)


def llm_structural_queries(fn_name: str, fn_body: str, client) -> list[str]:
    prompt = (
        "You are a smart contract security auditor.\n\n"
        f"Function: {fn_name}()\nBody:\n{fn_body.strip()[:2500]}\n\n"
        "Analyze this function for structural vulnerability properties.\n"
        "For each property present, write ONE query describing WHAT GOES WRONG — "
        "using the language of audit report finding titles.\n\n"
        "Check ONLY for properties actually visible in this code:\n"
        "- State written to mapping/storage WITHOUT checking existing value first\n"
        "- State mutation that executes unconditionally regardless of input amount (zero, max)\n"
        "- Arithmetic that can underflow/overflow for specific input range\n"
        "- External call without slippage/deadline/minOutput protection\n"
        "- Missing access control: state-changing function callable by anyone\n"
        "- Token balance assumption that breaks with fee-on-transfer tokens\n"
        "- Array/index access that can exceed bounds\n"
        "- Missing state reset after token transfer or claim\n\n"
        "Use phrasing like audit finding titles: 'X causes Y', 'missing Z allows W'.\n"
        "Format: one query per line, max 15 words each.\n"
        "Only output queries for properties you actually find. Output ONLY queries, nothing else."
    )
    time.sleep(LLM_DELAY)
    return _llm_call(client, prompt)


def query_rag(retriever, queries: list[str], delay=1.5) -> dict:
    best_score, best_title, best_query = 0.0, "", ""
    all_results = []
    for q in queries[:15]:
        try:
            docs = retriever.query(q, n_results=3)
            for d in docs:
                all_results.append({"query": q, "score": d["score"], "title": d["title"]})
                if d["score"] > best_score:
                    best_score, best_title, best_query = d["score"], d["title"], q
            time.sleep(delay)
        except Exception as e:
            if "429" in str(e):
                print(f"    [RAG 429, wait 10s]")
                time.sleep(10)
    passed = [r for r in all_results if r["score"] >= SCORE_THRESHOLD]
    return {
        "best_score": best_score,
        "best_title": best_title[:80],
        "best_query": best_query,
        "passed": len(passed),
        "top3": sorted(all_results, key=lambda x: -x["score"])[:3],
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("Initializing...")
    client = LLMClient()
    retriever = SolodirRetriever()
    print(f"Ready. Testing {len(TARGETS)} H bugs.\n")

    results = []
    errors = []

    for i, t in enumerate(TARGETS):
        label = f"{t['contest']}/{t['h_id']} {t['fn']}"
        print(f"[{i+1}/{len(TARGETS)}] {label}")

        fn_body = extract_fn_body(t["file"], t["fn"])
        if fn_body.startswith("<"):
            print(f"  ERROR: {fn_body}")
            errors.append(label)
            results.append({**t, "error": fn_body})
            continue

        print(f"  body={len(fn_body)}c  ", end="", flush=True)

        # Track 1: operation
        print("op...", end="", flush=True)
        op_q = llm_operation_queries(t["fn"], fn_body, client)
        print(f"{len(op_q)}q  ", end="", flush=True)

        # Track 2: structural
        print("struct...", end="", flush=True)
        st_q = llm_structural_queries(t["fn"], fn_body, client)
        print(f"{len(st_q)}q  ", end="", flush=True)

        # RAG
        print("rag...", end="", flush=True)
        op_rag = query_rag(retriever, op_q)
        st_rag = query_rag(retriever, st_q)
        print("done")

        op_mark = "✅" if op_rag["best_score"] >= SCORE_THRESHOLD else "❌"
        st_mark = "✅" if st_rag["best_score"] >= SCORE_THRESHOLD else "❌"
        winner = ""
        if st_rag["best_score"] > op_rag["best_score"] + 0.005:
            winner = " ← STRUCT"
        elif op_rag["best_score"] > st_rag["best_score"] + 0.005:
            winner = " ← OP"

        print(f"  OP     {op_mark} {op_rag['best_score']:.3f} pass={op_rag['passed']:2d} | {op_rag['best_title'][:65]}")
        print(f"  STRUCT {st_mark} {st_rag['best_score']:.3f} pass={st_rag['passed']:2d} | {st_rag['best_title'][:65]}{winner}")
        print()

        results.append({
            **t,
            "op_queries": op_q,
            "st_queries": st_q,
            "op": op_rag,
            "st": st_rag,
        })

    # Save
    out = "/tmp/full_structural_test_results.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"Results saved → {out}")

    # Summary
    print("\n" + "="*80)
    print(f"FULL SUMMARY  (threshold={SCORE_THRESHOLD})")
    print(f"{'Bug':<14} {'Expected':<45} {'OP':>7} {'ST':>7} {'Winner'}")
    print("-"*80)

    op_wins = st_wins = ties = op_only = st_only = both = neither = 0
    for r in results:
        if "error" in r:
            print(f"  {r['contest']}/{r['h_id']:<10} ERROR: {r['error']}")
            continue
        op, st = r["op"], r["st"]
        op_pass = op["best_score"] >= SCORE_THRESHOLD
        st_pass = st["best_score"] >= SCORE_THRESHOLD

        if op_pass and st_pass:    both += 1
        elif op_pass:              op_only += 1
        elif st_pass:              st_only += 1
        else:                      neither += 1

        if st["best_score"] > op["best_score"] + 0.005:
            w = "STRUCT"; st_wins += 1
        elif op["best_score"] > st["best_score"] + 0.005:
            w = "OP    "; op_wins += 1
        else:
            w = "TIE   "; ties += 1

        om = "✅" if op_pass else "❌"
        sm = "✅" if st_pass else "❌"
        print(f"  {r['contest']}/{r['h_id']:<10} {r['expected'][:44]:<44} {om}{op['best_score']:.3f} {sm}{st['best_score']:.3f} {w}")

    valid = len([r for r in results if "error" not in r])
    print("-"*80)
    print(f"  Valid={valid}  Errors={len(errors)}")
    print(f"  Score winner: OP={op_wins} STRUCT={st_wins} TIE={ties}")
    print(f"  Pass (≥{SCORE_THRESHOLD}): both={both} op_only={op_only} st_only={st_only} neither={neither}")
    print(f"  ST coverage gain: +{st_only} bugs (struct passes, op fails)")
    print(f"  ST coverage loss: -{op_only} bugs (op passes, struct fails)")
    if errors:
        print(f"  Errors: {errors}")


if __name__ == "__main__":
    main()
