#!/usr/bin/env python3
"""
fill_raw_code_llm.py — Dùng LLM extract raw_code từ parents.json content
cho các finding đã có sections.code nhưng thiếu raw_code (code_block miss).

Flow: parents.json content → extract code blocks → LLM pick+return relevant snippet
Workers: 2 Vertex AI, 18 RPM mỗi cái.

Usage:
    python scripts/rag/fill_raw_code_llm.py [--limit N] [--workers 1|2]
"""
import sys, os, json, re, time, threading, queue, logging, argparse, fcntl
from pathlib import Path
import httpx
from openai import OpenAI

SCRIPT_DIR   = Path(__file__).parent.resolve()
REPO_ROOT    = SCRIPT_DIR.parent.parent.parent
CACHE_PATH   = SCRIPT_DIR / "rag_sections_cache.json"
PARENTS_PATH = SCRIPT_DIR.parent.parent / "data/rag_db/parents.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(SCRIPT_DIR / "fill_raw_code_llm.log", mode="a"),
    ],
)
log = logging.getLogger("fill_raw_llm")

WORKER_CFGS = [
    {
        "key_file": str(REPO_ROOT / "vertex-ai-1.json"),
        "base_url": os.environ.get(
            "LLM_BASE_URL",
            "https://aiplatform.googleapis.com/v1/projects/sigma-comfort-498803-f9/locations/global/endpoints/openapi",
        ),
        "rpm_file": "/tmp/audit_fillraw_w1.json",
        "rpm_lock": "/tmp/audit_fillraw_w1.lock",
    },
    {
        "key_file": str(REPO_ROOT / "vertex-ai-2.json"),
        "base_url": os.environ.get(
            "LLM2_BASE_URL",
            "https://aiplatform.googleapis.com/v1/projects/learned-surge-498101-t0/locations/global/endpoints/openapi",
        ),
        "rpm_file": "/tmp/audit_fillraw_w2.json",
        "rpm_lock": "/tmp/audit_fillraw_w2.lock",
    },
]

MODEL    = os.environ.get("LLM_MODEL_NAME", "google/gemini-3-flash-preview")
THINKING = {"google": {"thinking_config": {"thinking_level": "low"}}}
RPM_LIMIT = 18

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

def normalize_code(code: str) -> str:
    if not code: return code
    code = re.sub(r"(?m)^\s*\d+\s*:\s*", "", code)
    code = re.sub(r"//[^\n]*", "", code)
    code = re.sub(r"/\*[\s\S]*?\*/", "", code)
    code = re.sub(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
        lambda m: m.group(0) if m.group(0) in SOL_KW else "_VAR", code)
    code = re.sub(r"[\s]+", " ", code)
    return code.strip()


def is_solidity(block: str) -> bool:
    if any(kw in block for kw in ("func ", "let mut ", "def ", "require.Equal", "println!")):
        return False
    sol_hits = sum(1 for kw in ("function ", "contract ", "mapping(", "uint256", "address",
                                "require(", "emit ", "modifier ", "pragma solidity",
                                "external", "public ", "returns (", "=> ") if kw in block)
    return sol_hits >= 1


def extract_sol_blocks(text: str) -> list[str]:
    fenced = re.findall(r"```(?:solidity|sol)?\s*\n([\s\S]*?)```", text, re.IGNORECASE)
    blocks = [b.strip() for b in fenced if b.strip() and is_solidity(b)]
    if not blocks:
        all_fenced = re.findall(r"```[^\n]*\n([\s\S]*?)```", text)
        blocks = [b.strip() for b in all_fenced if b.strip() and is_solidity(b)]
    return blocks


def build_vertex_client(key_file: str, base_url: str) -> OpenAI:
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


def acquire_slot(rpm_file: str, rpm_lock: str, limit: int = RPM_LIMIT) -> None:
    while True:
        wait = 0.0
        with open(rpm_lock, "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                now = time.time()
                cutoff = now - 60.0
                try:
                    data = json.load(open(rpm_file))
                    ts = [t for t in data.get("ts", []) if t > cutoff]
                except (FileNotFoundError, ValueError):
                    ts = []
                if len(ts) < limit:
                    ts.append(now)
                    with open(rpm_file, "w") as f:
                        json.dump({"ts": ts}, f)
                else:
                    wait = 60.0 - (now - min(ts)) + 0.5
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)
        if wait <= 0: return
        time.sleep(min(wait, 5.0))


def call_llm(client, prompt: str, rpm_file: str, rpm_lock: str,
             max_tokens: int = 4096, retries: int = 4) -> str:
    for attempt in range(retries + 1):
        acquire_slot(rpm_file, rpm_lock)
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0, max_tokens=max_tokens,
                extra_body=THINKING,
            )
            msg = resp.choices[0].message if resp.choices else None
            content = msg.content if msg is not None else None
            if content is None:
                log.warning(f"Empty LLM response (message/content=None), retrying")
                if attempt < retries:
                    time.sleep(5)
                continue
            return content.strip()
        except Exception as e:
            if "429" in str(e):
                delay = 15 * (2 ** attempt)
                log.warning(f"429 retry {attempt+1} in {delay}s")
                time.sleep(delay)
            else:
                log.error(f"LLM error: {e}")
                if attempt < retries: time.sleep(5)
    return ""


def strip_fences(text: str) -> str:
    text = re.sub(r"^```(?:solidity)?\s*\n?", "", text.strip(), flags=re.IGNORECASE)
    text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


_SAVE_LOCK = threading.Lock()

def save_cache(cache: dict, path: Path) -> None:
    with _SAVE_LOCK:
        tmp = str(path) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)


def worker_fn(worker_id, cfg, work_q, cache, idx_map, stats, save_every):
    client   = build_vertex_client(cfg["key_file"], cfg["base_url"])
    rpm_file = cfg["rpm_file"]
    rpm_lock = cfg["rpm_lock"]
    pending  = 0

    log.info(f"[W{worker_id}] started")

    while True:
        try:
            item = work_q.get(timeout=5)
        except queue.Empty:
            break

        slug    = item["slug"]
        vul     = item["vul"]
        content = item["content"]

        try:
            mode = item.get("mode", "blocks")  # "blocks", "inline", "hint"

            if mode == "hint":
                code_norm = item.get("code_norm", "")
                prompt = (
                    "You are a smart contract security expert.\n\n"
                    f"Vulnerability:\n{vul}\n\n"
                    "The vulnerable code, when normalized (identifiers replaced with _VAR), looks like:\n"
                    f"{code_norm}\n\n"
                    "Audit finding report content:\n"
                    f"{content[:8000]}\n\n"
                    "Find the actual raw source code (with real variable/function/contract names) "
                    "that corresponds to the normalized structure above.\n"
                    "Look in: code blocks, inline backtick references, or described function implementations.\n"
                    "Rules:\n"
                    "- Return ONLY code that appears in or is clearly described in the report.\n"
                    "- Do NOT invent code that is not present or implied in the report.\n"
                    "- Do NOT add placeholder comments like '// ...' or '// logic'.\n"
                    "- Return the minimal snippet (1-20 lines) showing the vulnerability.\n"
                    "- If you cannot find real code, output exactly: NONE\n"
                    "Return ONLY the raw code with real identifiers. No explanation. No markdown fences."
                )
            elif mode in ("inline", "inline_dnc"):
                # Inline mode: pass full content, LLM tìm code trong prose
                prompt = (
                    "You are a smart contract security expert.\n\n"
                    f"Vulnerability:\n{vul}\n\n"
                    "Audit finding report content:\n"
                    f"{content[:8000]}\n\n"
                    "The vulnerable Solidity code may be embedded inline in the text (not in code fences).\n"
                    "Extract ONLY the minimal Solidity code snippet (1-20 lines) from the CONTRACT SOURCE "
                    "that directly shows the vulnerability. Do NOT return test code or PoC code.\n"
                    "If no contract source code is identifiable, output exactly: NONE\n"
                    "Return ONLY the raw Solidity code. No explanation. No markdown fences."
                )
            else:
                # Blocks mode: extract fenced code blocks first
                blocks = extract_sol_blocks(content)
                if not blocks:
                    log.warning(f"[W{worker_id}] [NO_BLOCKS] {slug[:50]}")
                    stats["miss"] = stats.get("miss", 0) + 1
                    work_q.task_done()
                    continue

                combined = "\n\n---\n\n".join(blocks)[:4000]
                prompt = (
                    "You are a smart contract security expert.\n\n"
                    f"Vulnerability:\n{vul}\n\n"
                    "The following Solidity code blocks were extracted VERBATIM from the audit report:\n"
                    f"```solidity\n{combined}\n```\n\n"
                    "Select the single block (or minimal contiguous lines from one block) that best shows the vulnerability.\n"
                    "Rules:\n"
                    "- Return ONLY lines that appear VERBATIM in the blocks above. Do NOT add, invent, or paraphrase any code.\n"
                    "- Do NOT add comments like '// ...' or '// logic here' or any placeholder text.\n"
                    "- Do NOT combine unrelated blocks or add scaffolding code.\n"
                    "- If no block clearly shows the vulnerability, output exactly: NONE\n"
                    "Return ONLY the raw Solidity code with real variable/function names. No explanation. No markdown fences."
                )

            raw_text = call_llm(client, prompt, rpm_file, rpm_lock)
            raw_code = strip_fences(raw_text)

            if not raw_code or raw_code.upper() == "NONE" or len(raw_code) < 10:
                log.warning(f"[W{worker_id}] [EMPTY_LLM] {slug[:50]}")
                stats["miss"] = stats.get("miss", 0) + 1
                work_q.task_done()
                continue

            entry = cache["findings"][idx_map[slug]]
            entry["sections"]["raw_code"] = raw_code

            # inline_dnc: cũng điền sections.code và đổi status
            if mode == "inline_dnc":
                entry["sections"]["code"] = normalize_code(raw_code)
                entry["status"]           = "done"
                entry["code_source"]      = "llm_inline"

            n = stats.get("done", 0) + 1
            stats["done"] = n
            pending += 1

            log.info(f"[W{worker_id}] [{n}] {slug[:48]} raw={len(raw_code)}c")

            if pending >= save_every:
                save_cache(cache, CACHE_PATH)
                pending = 0
                log.info(f"[W{worker_id}] [SAVE] done={stats.get('done',0)} miss={stats.get('miss',0)}")

        except Exception as e:
            log.error(f"[W{worker_id}] exception {slug}: {e}", exc_info=True)
            stats["miss"] = stats.get("miss", 0) + 1

        work_q.task_done()

    if pending:
        save_cache(cache, CACHE_PATH)
    log.info(f"[W{worker_id}] finished")


def main():
    env_path = REPO_ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k, _, v = line.partition("=")
            if k.strip() not in os.environ:
                os.environ[k.strip()] = v.strip().strip('"').strip("'")

    parser = argparse.ArgumentParser()
    parser.add_argument("--limit",      type=int, default=0)
    parser.add_argument("--workers",    type=int, default=2, choices=[1, 2])
    parser.add_argument("--save-every", type=int, default=20)
    parser.add_argument("--source",     default="code_block",
                        choices=["code_block", "none", "dnc_none", "code_block_refix", "hint"],
                        help="code_block=fenced blocks miss; none=done inline prose; dnc_none=done_no_code inline; code_block_refix=replace hallucinated raw_code; hint=use normalized code as hint to find raw in content")
    args = parser.parse_args()

    log.info("Loading cache and parents.json...")
    cache   = json.load(open(CACHE_PATH))
    parents = json.load(open(PARENTS_PATH))

    idx_map = {f["slug"]: i for i, f in enumerate(cache["findings"])}

    HALLUC_MARKERS = ["// ...", "// External call", "/* ...", "// logic", "// NOTE:", "// TODO", "// pair.", "// process"]

    if args.source == "dnc_none":
        # done_no_code + code_source=None: Gemini failed to extract, inline code in prose
        targets = [
            f for f in cache["findings"]
            if f["status"] == "done_no_code"
            and not f["sections"].get("code")
            and f.get("code_source") is None
        ]
        mode = "inline_dnc"
    elif args.source == "code_block_refix":
        # Re-extract raw_code for findings where LLM previously hallucinated
        targets = [
            f for f in cache["findings"]
            if f["sections"].get("raw_code")
            and any(m in f["sections"]["raw_code"] for m in HALLUC_MARKERS)
        ]
        mode = "blocks"
    elif args.source == "hint":
        # done + có sections.code (normalized) + không có raw_code
        # Dùng sections.code làm hint cho LLM tìm raw code trong content
        targets = [
            f for f in cache["findings"]
            if f["status"] == "done"
            and f["sections"].get("code")
            and not f["sections"].get("raw_code")
        ]
        mode = "hint"
    elif args.source == "none":
        # done + code_source=None: code embedded inline in prose
        targets = [
            f for f in cache["findings"]
            if f["status"] == "done"
            and f["sections"].get("code")
            and not f["sections"].get("raw_code")
            and f.get("code_source") is None
        ]
        mode = "inline"
    else:
        # code_block findings: có fenced blocks nhưng similarity miss
        targets = [
            f for f in cache["findings"]
            if f["status"] == "done"
            and f["sections"].get("code")
            and not f["sections"].get("raw_code")
            and f.get("code_source") == "code_block"
        ]
        mode = "blocks"

    log.info(f"Targets ({args.source}): {len(targets)}  mode={mode}")
    if args.limit:
        targets = targets[:args.limit]

    work_q = queue.Queue()
    for f in targets:
        content = parents.get(f["slug"], "")
        if isinstance(content, dict):
            content = content.get("content", "")
        work_q.put({
            "slug":      f["slug"],
            "vul":       f["sections"].get("vul") or "",
            "content":   content,
            "mode":      mode,
            "code_norm": f["sections"].get("code") or "",
        })

    stats = {}
    threads = []
    for i in range(min(args.workers, len(WORKER_CFGS))):
        t = threading.Thread(
            target=worker_fn,
            args=(i+1, WORKER_CFGS[i], work_q, cache, idx_map, stats, args.save_every),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    save_cache(cache, CACHE_PATH)
    log.info(f"COMPLETE. done={stats.get('done',0)} miss={stats.get('miss',0)}")

    has_raw = sum(1 for f in cache["findings"] if f["sections"].get("raw_code"))
    log.info(f"Cache has_raw_code: {has_raw}")


if __name__ == "__main__":
    main()
