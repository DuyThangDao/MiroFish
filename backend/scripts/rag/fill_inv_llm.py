#!/usr/bin/env python3
"""
fill_inv_llm.py — Generate sections.inv cho mỗi finding trong rag_sections_cache.json.

inv = 1-3 abstract, checkable invariants mô tả điều kiện PHẢI đúng để code an toàn.
Dùng để inject vào [HIST-INV] annotations trên source code khi HIST-INV build match finding.

Khác với sections.op (mô tả code LÀM GÌ), sections.inv mô tả code PHẢI ĐÁP ỨNG ĐIỀU KIỆN GÌ.

Input: sections.op (abstract mechanics) + sections.vul (bug class)
Không dùng raw_code — tránh leak variable/function names từ finding cũ vào annotation.

Invariants phải abstract (không chứa tên biến cụ thể) để agent R1 có thể check trên
bất kỳ contract tương tự, không phụ thuộc vào naming của finding gốc.

Workers: 2 Vertex AI, 18 RPM mỗi cái (~36 RPM tổng, ~93 phút cho 3366 findings).

Usage:
    python scripts/rag/fill_inv_llm.py [--limit N] [--workers 1|2]
"""
import sys, os, json, re, time, threading, queue, logging, argparse, fcntl
from pathlib import Path
import httpx
from openai import OpenAI

SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT   = SCRIPT_DIR.parent.parent.parent
CACHE_PATH  = SCRIPT_DIR / "rag_sections_cache.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(SCRIPT_DIR / "fill_inv_llm.log", mode="a"),
    ],
)
log = logging.getLogger("fill_inv")

WORKER_CFGS = [
    {
        "key_file": str(REPO_ROOT / "vertex-ai-1.json"),
        "base_url": "https://aiplatform.googleapis.com/v1/projects/sigma-comfort-498803-f9/locations/global/endpoints/openapi",
        "rpm_file": "/tmp/audit_fillinv_w1.json",
        "rpm_lock": "/tmp/audit_fillinv_w1.lock",
    },
    {
        "key_file": str(REPO_ROOT / "vertex-ai-2.json"),
        "base_url": "https://aiplatform.googleapis.com/v1/projects/learned-surge-498101-t0/locations/global/endpoints/openapi",
        "rpm_file": "/tmp/audit_fillinv_w2.json",
        "rpm_lock": "/tmp/audit_fillinv_w2.lock",
    },
]

MODEL    = os.environ.get("LLM_MODEL_NAME", "google/gemini-3-flash-preview")
THINKING = {"google": {"thinking_config": {"thinking_level": "low"}}}
RPM_LIMIT = 18

# Invariant phải:
# 1. Abstract — không chứa tên biến/hàm cụ thể từ finding gốc
# 2. Checkable — agent đọc code bất kỳ → trả lời yes/no
# 3. Expressed bằng: Solidity type names, operation patterns, ordering words
# 4. Format: "[subject] must [condition]" — 8-20 words
PROMPT = """\
You are a smart contract security auditor.

Vulnerability class:
{vul}

Mechanical operations that cause this bug:
{op}

Write 1 to 3 invariants that MUST hold for this code pattern to be safe.

Rules:
- Each invariant is a condition an auditor can verify by reading ANY contract with similar mechanics.
- Do NOT use variable names, function names, or contract names — they belong to a specific finding, \
not to the pattern.
- Use only: Solidity type names (uint128, uint256, int24, bytes32, etc.), \
operation patterns (cast, arithmetic, storage write, external call, unchecked block), \
and ordering words (before, after, prior to, following).
- Format: one invariant per line, 8-20 words, starting with a noun phrase.
- Express the NECESSARY SAFETY CONDITION, not the bug description.
- Good examples:
    "uint256 value must fit within uint128 bounds before any narrowing cast"
    "storage balance must be zeroed before any external transfer call in the same function"
    "cumulative reward index must be updated before computing any user-proportional delta"
    "fee amount subtracted from reserve must not exceed total reserve balance"
- Output ONLY the invariant lines. No numbering. No explanation. No markdown.\
"""


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
                log.warning("Empty LLM response (content=None), retrying")
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


def parse_inv_lines(text: str) -> list:
    """Strip markdown, numbering, empty lines. Return list of clean invariant strings."""
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        line = re.sub(r"^[\d]+[.)]\s*", "", line)
        line = re.sub(r"^[-*•]\s*", "", line)
        line = re.sub(r"\*+", "", line)
        line = line.strip()
        if line and len(line) >= 10:
            lines.append(line)
    # Cap at 3 invariants
    return lines[:3]


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

        slug = item["slug"]
        vul  = item["vul"]
        op   = item["op"]  # list[str]

        try:
            op_text = "\n".join(f"- {line}" for line in op)
            prompt = PROMPT.format(
                vul=vul[:1500],
                op=op_text[:1500],
            )

            raw_text  = call_llm(client, prompt, rpm_file, rpm_lock)
            inv_lines = parse_inv_lines(raw_text)

            if not inv_lines:
                log.warning(f"[W{worker_id}] [EMPTY] {slug[:50]}")
                stats["miss"] = stats.get("miss", 0) + 1
                work_q.task_done()
                continue

            cache["findings"][idx_map[slug]]["sections"]["inv"] = inv_lines

            n = stats.get("done", 0) + 1
            stats["done"] = n
            pending += 1

            log.info(f"[W{worker_id}] [{n}] {slug[:50]}  inv={len(inv_lines)}")

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
    args = parser.parse_args()

    log.info("Loading cache...")
    cache = json.load(open(CACHE_PATH))

    idx_map = {f["slug"]: i for i, f in enumerate(cache["findings"])}

    # Target: has op + has vul, but no inv yet
    targets = [
        f for f in cache["findings"]
        if not f["sections"].get("inv")
        and isinstance(f["sections"].get("op"), list) and f["sections"]["op"]
        and f["sections"].get("vul")
    ]

    log.info(f"Targets: {len(targets)}")
    if args.limit:
        targets = targets[:args.limit]

    work_q = queue.Queue()
    for f in targets:
        work_q.put({
            "slug": f["slug"],
            "vul":  f["sections"].get("vul") or "",
            "op":   f["sections"].get("op") or [],
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

    has_inv = sum(1 for f in cache["findings"] if f["sections"].get("inv"))
    log.info(f"Cache has_inv: {has_inv}/{len(cache['findings'])} findings")


if __name__ == "__main__":
    main()
