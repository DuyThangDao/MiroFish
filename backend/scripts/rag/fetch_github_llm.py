#!/usr/bin/env python3
"""
fetch_github_llm.py — Fetch raw Solidity from GitHub + LLM-extract precise snippet.

Phase A: done_no_code findings with github_links (#L anchors) → fetch file → LLM extract → raw_code + code
Phase B: done findings with raw_code (old 30-line window) → LLM refine → replace raw_code + code

Workers: 2 Vertex AI workers (sigma + learned-surge), each with separate RPM file.
RPM: 18/min per worker → ~36/min total.

Usage (from MiroFish/backend/ with venv activated):
    python scripts/rag/fetch_github_llm.py [--phase a|b|ab] [--limit N] [--workers 1|2]
"""
import sys, os, json, re, time, threading, queue, logging, argparse, fcntl
from pathlib import Path
import httpx
from openai import OpenAI

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
CACHE_PATH = SCRIPT_DIR / "rag_sections_cache.json"
WQ_PATH    = SCRIPT_DIR / "work_queue.json"
TODAY      = "2026-06-09"

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(SCRIPT_DIR / "fetch_github_llm.log", mode="a"),
    ],
)
log = logging.getLogger("fetch_llm")

# ── Vertex AI worker configs ───────────────────────────────────────────────────
REPO_ROOT = SCRIPT_DIR.parent.parent.parent  # MiroFish/
WORKER_CFGS = [
    {
        "key_file": str(REPO_ROOT / "vertex-ai-1.json"),
        "base_url": os.environ.get(
            "LLM_BASE_URL",
            "https://aiplatform.googleapis.com/v1/projects/sigma-comfort-498803-f9/locations/global/endpoints/openapi",
        ),
        "rpm_file": "/tmp/mirofish_fetch_llm_w1.json",
        "rpm_lock": "/tmp/mirofish_fetch_llm_w1.lock",
    },
    {
        "key_file": str(REPO_ROOT / "vertex-ai-2.json"),
        "base_url": os.environ.get(
            "LLM2_BASE_URL",
            "https://aiplatform.googleapis.com/v1/projects/learned-surge-498101-t0/locations/global/endpoints/openapi",
        ),
        "rpm_file": "/tmp/mirofish_fetch_llm_w2.json",
        "rpm_lock": "/tmp/mirofish_fetch_llm_w2.lock",
    },
]

MODEL      = os.environ.get("LLM_MODEL_NAME", "google/gemini-3-flash-preview")
RPM_LIMIT  = 18
THINKING   = {"google": {"thinking_config": {"thinking_level": "low"}}}

# ── Normalization ──────────────────────────────────────────────────────────────
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
    code = re.sub(
        r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
        lambda m: m.group(0) if m.group(0) in SOL_KW else "_VAR",
        code,
    )
    code = re.sub(r"[\s]+", " ", code)
    return code.strip()


# ── Vertex AI client builder ───────────────────────────────────────────────────
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
        api_key="vertex-ai",
        base_url=base_url,
        http_client=httpx.Client(auth=_Auth(), timeout=120),
        max_retries=0,
    )


# ── Per-worker RPM limiter ─────────────────────────────────────────────────────
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
                    oldest = min(ts)
                    wait = 60.0 - (now - oldest) + 0.5
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)
        if wait <= 0:
            return
        time.sleep(min(wait, 5.0))


# ── LLM call ──────────────────────────────────────────────────────────────────
def call_llm(client: OpenAI, prompt: str,
             rpm_file: str, rpm_lock: str,
             max_tokens: int = 4096,
             retries: int = 4) -> str:
    base_delay = 15
    for attempt in range(retries + 1):
        acquire_slot(rpm_file, rpm_lock)
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=max_tokens,
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
                delay = base_delay * (2 ** attempt)
                log.warning(f"429 rate limit, retry {attempt+1}/{retries} in {delay}s")
                time.sleep(delay)
            else:
                log.error(f"LLM error: {e}")
                if attempt < retries:
                    time.sleep(5)
    return ""


# ── GitHub fetch helpers ───────────────────────────────────────────────────────
_FILE_CACHE: dict = {}
_FILE_CACHE_LOCK = threading.Lock()

def parse_github_url(url: str):
    url = url.rstrip("-").strip()
    m = re.match(
        r"https://github\.com/([^/]+/[^/]+)/blob/([^/?#]+)/([^#]+)(?:#(.*))?$", url
    )
    if not m: return None
    owner_repo, ref, path, anchor = m.groups()
    raw_url = f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{path}"
    start = end = None
    if anchor:
        rm = re.match(r"L(\d+)(?:-L(\d+))?", anchor)
        if rm:
            start = int(rm.group(1))
            end   = int(rm.group(2)) if rm.group(2) else None
    return raw_url, start, end


def fetch_raw_file(http: httpx.Client, raw_url: str) -> str | None:
    with _FILE_CACHE_LOCK:
        if raw_url in _FILE_CACHE:
            return _FILE_CACHE[raw_url]

    content = None
    for attempt in range(3):
        try:
            resp = http.get(raw_url, timeout=20, follow_redirects=True)
            if resp.status_code == 200:
                content = resp.text
                break
            if resp.status_code in (404, 403, 451):
                break
            time.sleep(2)
        except Exception as e:
            log.warning(f"Fetch error attempt {attempt+1}: {e}")
            if attempt < 2: time.sleep(2)

    with _FILE_CACHE_LOCK:
        _FILE_CACHE[raw_url] = content
    return content


def url_score(url: str) -> int:
    if re.search(r"#L\d+-L\d+", url):  return 4
    if re.search(r"#L\d+$", url):      return 3
    if re.search(r"#L\d+-$", url):     return 2
    return 0


def extract_lines(content: str, start: int, end=None,
                  ctx_before: int = 10, max_lines: int = 60) -> str:
    lines = content.splitlines()
    lo = max(0, start - 1 - ctx_before)
    hi = min(len(lines), (end or start) + max_lines) if end else min(len(lines), start - 1 + max_lines)
    return "\n".join(lines[lo:hi])


def strip_fences(text: str) -> str:
    text = re.sub(r"^```(?:solidity)?\s*\n?", "", text.strip(), flags=re.IGNORECASE)
    text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


# ── LLM prompt builder ────────────────────────────────────────────────────────
def make_prompt(vul: str, window: str) -> str:
    return (
        "You are a smart contract security expert.\n\n"
        f"Vulnerability:\n{vul}\n\n"
        "Solidity code from the vulnerable file (around the reported line):\n"
        f"```solidity\n{window[:3000]}\n```\n\n"
        "Extract ONLY the minimal code snippet (5-30 lines) that directly shows the vulnerability.\n"
        "Include surrounding context if needed to understand the bug (e.g., function signature, relevant state reads).\n"
        "Return ONLY the raw Solidity code with real variable/function names. No explanation. No markdown fences."
    )


# ── Cache save ────────────────────────────────────────────────────────────────
_SAVE_LOCK = threading.Lock()

def save_cache(cache: dict, path: Path) -> None:
    with _SAVE_LOCK:
        tmp = str(path) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)


# ── Worker thread ─────────────────────────────────────────────────────────────
def worker_fn(
    worker_id: int,
    cfg: dict,
    work_q: queue.Queue,
    cache: dict,
    idx_map: dict,
    stats: dict,
    save_every: int,
    fetch_errors: dict,
):
    client = build_vertex_client(cfg["key_file"], cfg["base_url"])
    rpm_file = cfg["rpm_file"]
    rpm_lock = cfg["rpm_lock"]
    http = httpx.Client(headers={"User-Agent": "MiroFish-RAG/1.0"})
    pending = 0

    log.info(f"[W{worker_id}] started | key={cfg['key_file']} | endpoint={cfg['base_url'][:70]}")

    while True:
        try:
            item = work_q.get(timeout=5)
        except queue.Empty:
            break

        slug   = item["slug"]
        phase  = item["phase"]  # "a" or "b"
        vul    = item["vul"]
        links  = item.get("links", [])

        try:
            # Both phases: fetch from GitHub (same logic)
            window = None
            for url in links:
                parsed = parse_github_url(url)
                if not parsed: continue
                raw_url, start, end = parsed
                if raw_url in (fetch_errors or {}):
                    continue
                content = fetch_raw_file(http, raw_url)
                if content is None:
                    fetch_errors[f"{slug}||{raw_url}"] = {
                        "url": url, "reason": "http_error", "attempted_at": TODAY
                    }
                    continue
                window = extract_lines(content, start or 1, end)
                break

            if not window or not window.strip():
                log.warning(f"[W{worker_id}] [NOFETCH] {slug[:50]}")
                stats["fail"] = stats.get("fail", 0) + 1
                work_q.task_done()
                continue

            # LLM extract
            prompt   = make_prompt(vul, window)
            raw_text = call_llm(client, prompt, rpm_file, rpm_lock)
            raw_code = strip_fences(raw_text)

            if not raw_code or len(raw_code) < 30:
                log.warning(f"[W{worker_id}] [EMPTY_LLM] {slug[:50]}")
                stats["fail"] = stats.get("fail", 0) + 1
                work_q.task_done()
                continue

            normalized = normalize_code(raw_code)
            entry = cache["findings"][idx_map[slug]]
            entry["sections"]["raw_code"] = raw_code
            entry["sections"]["code"]     = normalized
            if phase == "a":
                entry["status"]            = "done"
                entry["code_source"]       = "github_llm"
            elif phase in ("e", "f"):
                entry["code_source"]       = "github_llm"
            # phase B/C/D: status stays "done", code_source stays

            n = stats.get("done", 0) + 1
            stats["done"] = n
            pending += 1

            log.info(
                f"[W{worker_id}] [{'A' if phase=='a' else 'B'}|{n}] {slug[:45]} "
                f"raw={len(raw_code)}c norm={len(normalized)}c"
            )

            if pending >= save_every:
                save_cache(cache, CACHE_PATH)
                pending = 0
                log.info(f"[W{worker_id}] [SAVE] done={stats.get('done',0)} fail={stats.get('fail',0)}")

        except Exception as e:
            log.error(f"[W{worker_id}] exception on {slug}: {e}", exc_info=True)
            stats["fail"] = stats.get("fail", 0) + 1

        work_q.task_done()

    if pending:
        save_cache(cache, CACHE_PATH)
    http.close()
    log.info(f"[W{worker_id}] finished")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    # Load .env manually
    env_path = REPO_ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            k, _, v = line.partition("=")
            if k.strip() not in os.environ:
                os.environ[k.strip()] = v.strip().strip('"').strip("'")

    parser = argparse.ArgumentParser()
    parser.add_argument("--phase",      default="ab", choices=["a","b","c","d","e","f","ab","abc","abcd","ef","abcdef","ac","bc","cd","abd","abcde","abcdef"], help="a=done_no_code, b=refine raw_code, c=github_url no_raw, d=rel_path reconstruct, e=secondary github_links, f=secondary rel_paths")
    parser.add_argument("--limit",      type=int, default=0, help="Max items total (0=all)")
    parser.add_argument("--workers",    type=int, default=2, choices=[1,2])
    parser.add_argument("--save-every", type=int, default=20)
    args = parser.parse_args()

    cache  = json.load(open(CACHE_PATH))
    wq_map = {f["slug"]: f for f in json.load(open(WQ_PATH))["findings"]}

    idx_map      = {f["slug"]: i for i, f in enumerate(cache["findings"])}
    fetch_errors = cache.setdefault("fetch_errors", {})

    work_items = []

    # Phase A: done_no_code + github_links with #L
    if "a" in args.phase:
        for f in cache["findings"]:
            if f["status"] != "done_no_code": continue
            if f["sections"].get("raw_code"): continue  # already has raw_code
            wq_f  = wq_map.get(f["slug"], {})
            links = sorted(
                [u for u in wq_f.get("github_links", []) if url_score(u) > 0],
                key=url_score, reverse=True
            )
            if not links: continue
            work_items.append({
                "slug":  f["slug"],
                "phase": "a",
                "vul":   f["sections"].get("vul") or "",
                "links": links[:3],
            })

    # Phase B: done + has raw_code (old window method) → re-fetch GitHub + LLM refine
    if "b" in args.phase:
        for f in cache["findings"]:
            if f["status"] != "done": continue
            if not f["sections"].get("raw_code"): continue
            wq_f  = wq_map.get(f["slug"], {})
            links = sorted(
                [u for u in wq_f.get("github_links", []) if url_score(u) > 0],
                key=url_score, reverse=True
            )
            if not links: continue
            work_items.append({
                "slug":  f["slug"],
                "phase": "b",
                "vul":   f["sections"].get("vul") or "",
                "links": links[:3],
            })

    # Phase D: done + code_source=rel_path + no raw_code → reconstruct GitHub URL + fetch + LLM
    if "d" in args.phase:
        for f in cache["findings"]:
            if f["status"] != "done": continue
            if f["sections"].get("raw_code"): continue
            if f.get("code_source") != "rel_path": continue
            source_link = f.get("source_link", "")

            # Chỉ xử lý code4rena (có thể reconstruct repo URL)
            m = re.match(r"https://code4rena\.com/reports/(.+)", source_link)
            if not m: continue
            contest = m.group(1).rstrip("/")
            repo    = f"https://github.com/code-423n4/{contest}"

            wq_f     = wq_map.get(f["slug"], {})
            rel_paths = wq_f.get("rel_paths", [])
            if not rel_paths: continue

            # Tạo full GitHub URLs từ rel_paths, thử main và master
            links = []
            for rp in rel_paths[:3]:
                rp = rp.strip()
                # Tách anchor (#L42 hoặc #L42-)
                if "#" in rp:
                    path, anchor = rp.split("#", 1)
                    anchor = anchor.rstrip("-")  # bỏ trailing dash
                else:
                    path, anchor = rp, ""
                for branch in ["main", "master"]:
                    url = f"{repo}/blob/{branch}/{path.lstrip('/')}"
                    if anchor:
                        url += f"#{anchor}"
                    links.append(url)

            if not links: continue
            work_items.append({
                "slug":  f["slug"],
                "phase": "d",
                "vul":   f["sections"].get("vul") or "",
                "links": links,
            })

    # Phase C: done + code_source=github_url + no raw_code → fetch + LLM (bị bỏ sót trước đó)
    if "c" in args.phase:
        for f in cache["findings"]:
            if f["status"] != "done": continue
            if f["sections"].get("raw_code"): continue  # đã có rồi
            if f.get("code_source") != "github_url": continue
            wq_f  = wq_map.get(f["slug"], {})
            links = sorted(
                [u for u in wq_f.get("github_links", []) if url_score(u) > 0],
                key=url_score, reverse=True
            )
            if not links: continue
            work_items.append({
                "slug":  f["slug"],
                "phase": "c",
                "vul":   f["sections"].get("vul") or "",
                "links": links[:3],
            })

    # Phase E: done + no raw_code + code_source != github_url + has secondary github_links
    if "e" in args.phase:
        for f in cache["findings"]:
            if f["status"] != "done": continue
            if f["sections"].get("raw_code"): continue
            if f.get("code_source") == "github_url": continue  # already tried by Phase C
            wq_f  = wq_map.get(f["slug"], {})
            links = sorted(
                [u for u in wq_f.get("github_links", []) if url_score(u) > 0],
                key=url_score, reverse=True
            )
            if not links: continue
            work_items.append({
                "slug":  f["slug"],
                "phase": "e",
                "vul":   f["sections"].get("vul") or "",
                "links": links[:3],
            })

    # Phase F: done + no raw_code + code_source != rel_path + has rel_paths + code4rena source
    if "f" in args.phase:
        for f in cache["findings"]:
            if f["status"] != "done": continue
            if f["sections"].get("raw_code"): continue
            if f.get("code_source") == "rel_path": continue  # already tried by Phase D
            source_link = f.get("source_link", "")
            m = re.match(r"https://code4rena\.com/reports/(.+)", source_link)
            if not m: continue
            contest  = m.group(1).rstrip("/")
            repo     = f"https://github.com/code-423n4/{contest}"
            wq_f     = wq_map.get(f["slug"], {})
            rel_paths = wq_f.get("rel_paths", [])
            if not rel_paths: continue
            links = []
            for rp in rel_paths[:3]:
                rp = rp.strip()
                if "#" in rp:
                    path, anchor = rp.split("#", 1)
                    anchor = anchor.rstrip("-")
                else:
                    path, anchor = rp, ""
                for branch in ["main", "master"]:
                    url = f"{repo}/blob/{branch}/{path.lstrip('/')}"
                    if anchor: url += f"#{anchor}"
                    links.append(url)
            if not links: continue
            work_items.append({
                "slug":  f["slug"],
                "phase": "f",
                "vul":   f["sections"].get("vul") or "",
                "links": links,
            })

    for ph in "abcdef":
        n = sum(1 for x in work_items if x["phase"] == ph)
        if n: log.info(f"Phase {ph.upper()}: {n} items")
    log.info(f"Total:   {len(work_items)} items | workers={args.workers}")

    if args.limit:
        work_items = work_items[:args.limit]
        log.info(f"Limited to {args.limit}")

    if not work_items:
        log.info("Nothing to do.")
        return

    work_q = queue.Queue()
    for item in work_items:
        work_q.put(item)

    stats = {}
    n_workers = min(args.workers, len(WORKER_CFGS))
    threads = []
    for i in range(n_workers):
        t = threading.Thread(
            target=worker_fn,
            args=(i+1, WORKER_CFGS[i], work_q, cache, idx_map, stats, args.save_every, fetch_errors),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    save_cache(cache, CACHE_PATH)
    log.info(f"COMPLETE. done={stats.get('done',0)} fail={stats.get('fail',0)}")

    # Summary
    done_cnt = sum(1 for f in cache["findings"] if f["status"]=="done")
    dnc_cnt  = sum(1 for f in cache["findings"] if f["status"]=="done_no_code")
    raw_cnt  = sum(1 for f in cache["findings"] if f["sections"].get("raw_code"))
    log.info(f"Cache: done={done_cnt} done_no_code={dnc_cnt} has_raw_code={raw_cnt}")


if __name__ == "__main__":
    main()
