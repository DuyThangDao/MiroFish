#!/usr/bin/env python3
"""
fill_op_llm.py — Generate sections.op cho mỗi finding trong rag_sections_cache.json.

op = danh sách mechanical operations mô tả cụ thể những gì code làm dẫn đến lỗi.
Dùng để embed vào ChromaDB collection solodit_op, query bằng OP track của HIST-INV.

Input chính: raw_code + vul
Fallback (không có raw_code): vul only

Workers: 2 Vertex AI, 18 RPM mỗi cái (~36 RPM tổng, ~93 phút cho 3366 findings).

Usage:
    python scripts/rag/fill_op_llm.py [--limit N] [--workers 1|2] [--source all|with_raw|no_raw]
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
        logging.FileHandler(SCRIPT_DIR / "fill_op_llm.log", mode="a"),
    ],
)
log = logging.getLogger("fill_op")

WORKER_CFGS = [
    {
        "key_file": str(REPO_ROOT / "vertex-ai-1.json"),
        "base_url": "https://aiplatform.googleapis.com/v1/projects/sigma-comfort-498803-f9/locations/global/endpoints/openapi",
        "rpm_file": "/tmp/audit_fillop_w1.json",
        "rpm_lock": "/tmp/audit_fillop_w1.lock",
    },
    {
        "key_file": str(REPO_ROOT / "vertex-ai-2.json"),
        "base_url": "https://aiplatform.googleapis.com/v1/projects/learned-surge-498101-t0/locations/global/endpoints/openapi",
        "rpm_file": "/tmp/audit_fillop_w2.json",
        "rpm_lock": "/tmp/audit_fillop_w2.lock",
    },
]

MODEL    = os.environ.get("LLM_MODEL_NAME", "google/gemini-3-flash-preview")
THINKING = {"google": {"thinking_config": {"thinking_level": "low"}}}
RPM_LIMIT = 18

# Prompt khi có raw_code — input đủ để mô tả operation cụ thể
# raw_code đặt trước vul để LLM derive operations từ code, không từ prose
PROMPT_WITH_CODE = """\
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
to be self-contained (e.g. mention the type, the variable role, the function context).
- Be specific about exact Solidity types when visible (uint128, uint256, int24, etc.).
- Use active verb phrases matching audit query style: \
"cast uint256 to uint128 in reserve balance update", \
"subtract uint128 fee from balance mapping before external call", \
"call transfer to recipient before zeroing allowance state variable".
- Describe what the code does mechanically. Do NOT add judgment words like \
"incorrectly", "unsafely", "missing", "wrong".
- Output ONLY the operation lines. No numbering. No explanation. No markdown.\
"""

# Prompt fallback khi không có raw_code — dùng vul prose suy ra operations
PROMPT_NO_CODE = """\
You are a Solidity code analyst.

Vulnerability context:
{vul}

Based on the vulnerability description, enumerate the mechanical operations that cause this bug.
Focus on: type casts, arithmetic (add, sub, mul, div, overflow), storage reads/writes, \
external calls, unchecked blocks, state update ordering.

Rules:
- One operation per line, 5-15 words each.
- 3 to 7 lines total.
- Each line will be indexed as a standalone search document — include enough context \
to be self-contained (mention type, variable role, function context when available).
- Be specific about Solidity types when mentioned (uint128, uint256, int24, etc.).
- Use active verb phrases: "cast uint256 to uint128 in reserve balance update", \
"subtract fee from balance mapping before external call".
- Describe operations mechanically. Do NOT add judgment words like \
"incorrectly", "unsafely", "missing", "wrong".
- Output ONLY the operation lines. No numbering. No explanation. No markdown.\
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
                log.warning("Empty LLM response (message/content=None), retrying")
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


def parse_op_lines(text: str) -> list:
    """Strip markdown, numbering, empty lines. Return list of clean operation strings.
    Each item is a standalone document for per-operation ChromaDB embedding."""
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Strip leading numbering: "1." "1)" "-" "*"
        line = re.sub(r"^[\d]+[.)]\s*", "", line)
        line = re.sub(r"^[-*•]\s*", "", line)
        # Strip markdown bold/italic
        line = re.sub(r"\*+", "", line)
        line = line.strip()
        if line and len(line) >= 5:
            lines.append(line)
    return lines


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

        slug     = item["slug"]
        vul      = item["vul"]
        raw_code = item.get("raw_code") or ""

        try:
            if raw_code:
                prompt = PROMPT_WITH_CODE.format(
                    vul=vul[:1500],
                    raw_code=raw_code[:1500],
                )
            else:
                prompt = PROMPT_NO_CODE.format(vul=vul[:2000])

            raw_text = call_llm(client, prompt, rpm_file, rpm_lock)
            op_lines = parse_op_lines(raw_text)

            if not op_lines:
                log.warning(f"[W{worker_id}] [EMPTY] {slug[:50]}")
                stats["miss"] = stats.get("miss", 0) + 1
                work_q.task_done()
                continue

            # Lưu dạng list — mỗi item là 1 standalone document cho per-operation embedding
            cache["findings"][idx_map[slug]]["sections"]["op"] = op_lines

            n = stats.get("done", 0) + 1
            stats["done"] = n
            pending += 1

            has_code = "+" if raw_code else "-"
            log.info(f"[W{worker_id}] [{n}] [{has_code}raw] {slug[:48]}  ops={len(op_lines)}")

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
    parser.add_argument("--source",     default="all",
                        choices=["all", "with_raw", "no_raw"],
                        help=(
                            "all=tất cả findings chưa có op; "
                            "with_raw=chỉ findings có raw_code (chất lượng cao hơn); "
                            "no_raw=chỉ findings không có raw_code (fallback vul only)"
                        ))
    args = parser.parse_args()

    log.info("Loading cache...")
    cache = json.load(open(CACHE_PATH))

    idx_map = {f["slug"]: i for i, f in enumerate(cache["findings"])}

    all_findings = cache["findings"]

    if args.source == "with_raw":
        targets = [f for f in all_findings if not f["sections"].get("op") and f["sections"].get("raw_code")]
    elif args.source == "no_raw":
        targets = [f for f in all_findings if not f["sections"].get("op") and not f["sections"].get("raw_code") and f["sections"].get("vul")]
    else:  # all
        targets = [f for f in all_findings if not f["sections"].get("op") and f["sections"].get("vul")]

    log.info(f"Targets ({args.source}): {len(targets)}")
    if args.limit:
        targets = targets[:args.limit]

    work_q = queue.Queue()
    for f in targets:
        work_q.put({
            "slug":     f["slug"],
            "vul":      f["sections"].get("vul") or "",
            "raw_code": f["sections"].get("raw_code") or "",
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

    has_op = sum(1 for f in cache["findings"] if f["sections"].get("op"))
    total_ops = sum(len(f["sections"]["op"]) for f in cache["findings"] if isinstance(f["sections"].get("op"), list))
    log.info(f"Cache has_op: {has_op} findings, {total_ops} total operation documents")


if __name__ == "__main__":
    main()
