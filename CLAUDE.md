# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

MiroFish is a multi-agent swarm intelligence engine for predictive simulation. It orchestrates LLM-powered agents (via OASIS/CAMEL-AI) across simulated social platforms (Twitter/Reddit) to model how information spreads and predict outcomes. It uses Zep Cloud as a knowledge graph backend for entity memory and relationships.

## Commands

### Setup
```bash
cp .env.example .env          # fill in LLM_API_KEY and ZEP_API_KEY at minimum
npm run setup:all             # installs Node deps + creates Python venv + installs Python deps
```

### Development
```bash
npm run dev                   # starts both frontend (port 3000) and backend (port 5001) concurrently
npm run backend               # Flask only
npm run frontend              # Vite only
```

### Build & Docker
```bash
npm run build                 # builds frontend for production
docker compose up -d          # runs full stack in Docker
```

### Backend (Python) — run inside `backend/` with venv activated
```bash
source .venv/bin/activate
python run.py                 # starts Flask server directly
uv add <package>              # add a dependency (uses uv, not pip)
```

## Required Environment Variables

| Variable | Purpose |
|----------|---------|
| `LLM_API_KEY` | Primary LLM API key (OpenAI or compatible) |
| `ZEP_API_KEY` | Zep Cloud API key for knowledge graph |
| `LLM_BASE_URL` | Optional: custom endpoint for OpenAI-compatible APIs |
| `LLM_MODEL` | Optional: model name override |
| `BOOST_*` | Optional: second LLM config for expensive/long-running steps |

The app fails fast on startup if `LLM_API_KEY` or `ZEP_API_KEY` are missing.

## Architecture

### 5-Step Workflow Pipeline
1. **Graph Building** — Upload seed documents (PDF/TXT/MD) → extract ontology → build Zep knowledge graph
2. **Environment Setup** — Filter entities → generate OASIS agent profiles (personalities, behaviors)
3. **Simulation** — Run parallel multi-platform OASIS simulations as subprocess with IPC
4. **Report Generation** — ReportAgent (ReACT pattern) queries graph and generates analysis
5. **Interaction** — User interviews simulated agents; dialogue with ReportAgent

### Backend Structure (`backend/app/`)
- **`api/`** — Three Flask blueprints: `graph.py` (project/file management), `simulation.py` (agent profiles, sim control), `report.py` (reports, interviews)
- **`services/`** — Core logic; the heavy files are:
  - `simulation_runner.py` (1763 LOC) — manages OASIS subprocess, IPC, state machine
  - `report_agent.py` (2571 LOC) — multi-tool ReACT agent for report generation
  - `zep_tools.py` (1735 LOC) — tool suite wrapping Zep graph queries
  - `oasis_profile_generator.py` (1200 LOC) — generates agent social profiles
- **`models/`** — `Project` and `Task` dataclasses; state persisted as JSON in `backend/uploads/`
- **No database**: All persistence is file-based in `backend/uploads/`; Zep Cloud is the graph store

### Frontend Structure (`frontend/src/`)
- Vue 3 + Vite; Vite proxies `/api/*` to backend at port 5001
- **`views/`** — Page-level components mapped to routes
- **`api/`** — Axios-based API clients
- Routes: `/` → home, `/process/:projectId` → workflow, `/simulation/:simulationId/*` → sim setup/run, `/report/:reportId` → report, `/interaction/:reportId` → agent interview

### LLM Integration
- Uses the OpenAI SDK but works with any OpenAI-compatible endpoint (configured via `LLM_BASE_URL`)
- Reasoning models (e.g., MiniMax/GLM) may emit `<think>` tags and markdown code fences in the `content` field — the app strips these before parsing JSON responses (see recent fix in `985f89f`)

### Subprocess Simulation
OASIS simulations run as a separate subprocess to avoid Python GIL contention. Communication happens via IPC (pipes/queues). `atexit` hooks clean up processes on shutdown.

## Cyber / Audit Mode Notes

### Benchmark Audit (cách chuẩn — dùng cho mọi lần chạy mới)

Kết quả được lưu vào `benchmark/web3bugs/agent-redesign/<contest_id>/run-N/`.
Mỗi lần chạy mới tạo thêm `run-N` tiếp theo (run-1, run-2, ...).
Sau khi xong, output dir tự có: `dedup_findings.json`, `audit_report_dedup.json`, `run.log`.

```bash
cd /home/thangdd/repos/MiroFish/backend

# Chạy foreground (có progress output):
bash scripts/run_benchmark.sh \
  /home/thangdd/repos/web3bugs/contracts/<contest_id> \
  ../benchmark/web3bugs/agent-redesign/<contest_id>/run-N

# Chạy background:
nohup bash scripts/run_benchmark.sh \
  /home/thangdd/repos/web3bugs/contracts/<contest_id> \
  ../benchmark/web3bugs/agent-redesign/<contest_id>/run-N \
  > /tmp/benchmark_<contest_id>_runN.log 2>&1 &
```

**Eval sau khi xong (kết quả tự động lưu vào run dir):**
```bash
cd backend/scripts/evaluate
RUN_DIR=../../benchmark/web3bugs/agent-redesign/<contest_id>/run-N
REPORT=$RUN_DIR/<id>_*/audit_report_dedup.json
python3 web3bugs_eval.py gt/gt_<contest_id>.json "$REPORT" --verbose \
  | tee $RUN_DIR/eval_result.txt
```

Sau khi chạy eval, **bắt buộc lưu kết quả** vào `eval_result.txt` trong run dir bằng `tee` như trên.
File `eval_result.txt` chứa toàn bộ output verbose (matched/missed H bugs + TP/FP/FN/Precision/Recall/F1).

Flags đặt cứng trong script: `STOP_AFTER_DEDUP=true`, `RAG_ENABLED=true`.
Đây là cách dùng chuẩn trong giai đoạn tăng recall (focus R1, bỏ R2 voting).

**HIST-INV cache — KHÔNG xóa trừ khi user xác nhận rõ ràng:**
Cache nằm tại `benchmark/web3bugs/agent-redesign/<contest_id>/hist_inv_cache.json`.
Cache này lưu kết quả LLM query cho từng function — deterministic, dùng lại được giữa các runs cùng contest.
Chỉ xóa khi: thay đổi code HIST-INV, thay đổi prompt, hoặc user nói rõ "xóa cache".

**Quan trọng — luôn hỏi trước khi xóa, kể cả khi prompt vừa thay đổi.**
Lý do: cache có thể có 180+ entries — xóa toàn bộ tốn nhiều thời gian rebuild.
Thay vào đó, đề xuất xóa **selective** (chỉ xóa entries của các function cần test lại):
```python
import json
cache = json.load(open('hist_inv_cache.json'))
entries = cache.get('entries', {})
# Xóa chỉ các fn cần rebuild (ví dụ: GT functions)
target_fns = {'borrow', 'liquidate', 'registerAsset'}
cache['entries'] = {k: v for k, v in entries.items()
                    if v.get('fn_name','') not in target_fns}
json.dump(cache, open('hist_inv_cache.json','w'), indent=2)
```
Hỏi user: "Xóa toàn bộ cache hay chỉ các function [danh sách]?"

---

### Running a Contest Audit (background, with logging)

Tất cả contest source nằm ở `~/repos/web3bugs/contracts/<contest_id>/`.
Output nằm ở `backend/results/web3bugs_trial/contest_<label>/`.

```bash
# Chạy background — log ra /tmp/web3bugs_<id>_<label>.log
cd /home/thangdd/repos/MiroFish/backend

LOG=/tmp/web3bugs_35_nl_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
  source .venv/bin/activate
  exec python scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/35 \
    --output      ./results/web3bugs_trial/contest_35_nl \
    --timeout     21600 \
    --verbose
' >> "$LOG" 2>&1 &
echo "PID=$!  LOG=$LOG"
```

Thay `35` / `contest_35_nl` bằng contest_id / label muốn dùng.

**Theo dõi log:**
```bash
tail -f /tmp/web3bugs_35_nl_*.log          # stream log
grep -E "STEP|DONE|FAILED|ERROR|findings" /tmp/web3bugs_35_nl_*.log   # tóm tắt nhanh
ps aux | grep run_contract_audit           # kiểm tra process còn sống không
```

**Kiểm tra output sau khi xong:**
```bash
# Output nằm trong thư mục con có timestamp, e.g.:
ls results/web3bugs_trial/contest_35_nl/35_20260502_162342/
# audit_report.json  audit_report.md  session_result.json  profiles.json  ...

# Verify NL format (new arch): có findings[], không có swc_ids
python3 -c "
import json, glob, sys
f = sorted(glob.glob('results/web3bugs_trial/contest_35_nl/*/audit_report.json'))[-1]
d = json.load(open(f))
print('findings:', len(d.get('findings',[])), '| consensus_vulns:', len(d.get('consensus_vulns',[])))
k = list((d.get('findings') or d.get('consensus_vulns') or [{}])[0].keys())
print('keys:', k[:8])
"
```

**Env vars liên quan (từ .env):**
- `AUDIT_PIPELINE_VERSION=v2` — dùng v2 architecture (3-round: discovery/voting/attacker)
- `LLM_MODEL_NAME` — model chính cho agents
- `BOOST_MODEL_NAME` — model nặng hơn cho KG build / invariant extraction

### Running Evaluation (Web3Bugs H-bug F1)

GT files nằm ở `backend/scripts/evaluate/gt/gt_<contest_id>.json`.
Chạy sau khi có `audit_report.json`:

```bash
cd backend/scripts/evaluate

# Lấy đường dẫn audit_report.json của run mới nhất
REPORT=$(ls -td ../../results/web3bugs_trial/contest_35_nl/*/audit_report.json | head -1)

python web3bugs_eval.py gt/gt_35.json "$REPORT" --verbose
# In ra: TP= FP= FN= Precision= Recall= F1= và danh sách H bug matched
```

Cần `LLM_API_KEY` trong env để LLM judge chạy (dùng `gpt-4o-mini` mặc định,
override bằng `LLM_MODEL=...`).

### Web3Bugs GT Extraction (one-time manual step)
Khi cần build ground truth data cho Web3Bugs evaluation, đọc trực tiếp từ
`../web3bugs/reports/{contest_id}.md`. Mỗi H bug là 1 markdown section:
```
## [[H-01] Title with `Contract.function`](url)
_Submitted by ..._
Full description text...
```
Extract ra JSON file đặt tên theo contest (e.g. `gt_35.json`), mỗi item gồm:
```json
{
  "h_id": "H-01",
  "title": "Unsafe cast in ConcentratedLiquidityPool.burn leads to attack",
  "description": "The ConcentratedLiquidityPool.burn function performs...",
  "function_name": "burn",
  "contract_name": "ConcentratedLiquidityPool"
}
```
- `h_id` + `title`: từ `## [[H-XX] ...]` header
- `description`: full section text đến H tiếp theo
- `function_name` + `contract_name`: từ title (pattern `Contract.function`)
  hoặc đoạn đầu description (`` `function` of `Contract` ``)
**Đây là bước làm 1 lần bên ngoài evaluate module** — không tích hợp vào pipeline.
Metric tính theo H bug (không phân label L/S). Mỗi contest = 1 file JSON.

**Chuẩn bị trước khi chạy audit (làm song song với tạo GT):**
1. Kiểm tra contest có `hardhat.config*` không và ở đâu (root hay subdir).
2. Nếu có hardhat config → install deps:
   - Thử `npm install` trước; nếu lỗi `EUNSUPPORTEDPROTOCOL` (yarn: protocol) → dùng `yarn install` với path đầy đủ `/home/thangdd/.nvm/versions/node/v24.12.0/bin/yarn install`
   - Với multi-hardhat-config (subdir): install trong từng subdir riêng
3. **Sau khi contest đã chạy xong**, xóa `node_modules` ngay để tránh đầy đĩa:
   ```bash
   rm -rf /home/thangdd/repos/web3bugs/contracts/<id>/node_modules          # root
   rm -rf /home/thangdd/repos/web3bugs/contracts/<id>/*/node_modules        # subdir
   ```
4. Disk quota: `/dev/mapper/ubuntu--vg-ubuntu--lv` 218G tổng, thường gần đầy.
   Kiểm tra trước khi install: `df -h /` — nếu < 3G trống thì xóa node_modules contest cũ trước.

**Phân loại contests theo Slither compatibility:**
- `root_config` (hardhat.config ở root, count=1) → Slither khả năng cao chạy được
- `subdir_only` → Slither thường fail, pipeline dùng forward BFS fallback
- `no_hardhat` → Slither không chạy, dùng regex fallback
Lưu ý: root_config vẫn có thể fail nếu config cũ dùng syntax không tương thích
(e.g. `forking.blockNumber: null` gây HH8 error với hardhat v2 hiện tại).

## RAG Migration — 4-Section Architecture

### Tổng quan

Đang migration `solodit_findings` (ChromaDB blob) → 4 collections riêng biệt để cải thiện retrieval precision.
Tài liệu đầy đủ: `docs/good-techniques/rag-4section-architecture.md` và `docs/good-techniques/rag-migration-plan.md`.

### 4 Collections mới

| Collection | Query track | Nội dung |
|-----------|------------|---------|
| `solodit_vul` | ST queries | Vulnerability description (prose mô tả lỗi) |
| `solodit_code` | CODE queries | Normalized Solidity code (`_VAR` thay identifiers) |
| `solodit_op` | OP queries | Mechanical operations description (LLM-generated, Phase 3) |
| `solodit_inv` | — | Invariant description (LLM-generated, Phase 3) |

Collection cũ `solodit_findings` **giữ nguyên** — OP track vẫn dùng blob trong khi chờ `solodit_op`.

### Quy trình Migration (Claude trực tiếp xử lý)

**Claude** (người đang chat) đọc từng finding từ `parents.json` và extract/generate 4 sections — không cần script LLM API riêng. Kết quả ghi vào `rag_sections_cache.json` theo batch (checkpoint để resume qua nhiều session).

```
parents.json → Claude đọc + extract → rag_sections_cache.json → embed script → 4 collections
```

### Output JSON format

File: `backend/scripts/rag/rag_sections_cache.json`
Template tham khảo: `backend/scripts/rag/rag_sections_template.json`

**QUAN TRỌNG: KHÔNG lưu `content` hay `full_text`** — `parents.json` là source of truth, tra theo slug khi cần.

```json
{
  "_meta": {
    "total_findings": 3366,
    "processed_count": 0,
    "last_processed_slug": null
  },
  "fetch_errors": {
    "some-slug": { "url": "https://github.com/...", "reason": "404", "attempted_at": "2026-06-08" }
  },
  "findings": [
    {
      "slug": "h-01-...",
      "status": "done",
      "title": "...",
      "firm": "Sherlock",
      "protocol": "...",
      "impact": "HIGH",
      "source_link": "https://...",
      "content_source": "api_excerpt",
      "code_source": "code_block",
      "sections": {
        "vul":  "prose mô tả lỗi...",
        "code": "_VAR -= uint128(_VAR);",
        "op":   "cast uint256 to uint128; subtract from reserve slot...",
        "inv":  "function X must ensure Y before Z"
      }
    }
  ]
}
```

**`status`** ∈ `["done", "done_no_code", "failed"]`:
- `done` — tất cả sections extract thành công
- `done_no_code` — sections.code = null (prose_only hoặc GitHub fetch fail)
- `failed` — exception không recover được

`sections.code` = `null` khi không có code (prose_only hoặc fetch fail).
`code_source` ∈ `["code_block", "audit_marker", "inline_linenum", "inline_sol", "github_url", "rel_path", null]`.
- `inline_sol` — Solidity type declaration/assignment embedded in prose (no fences, no line numbers)

### Phân loại findings theo code availability

| Category | Count | Cách xử lý |
|----------|-------|-----------|
| ` ```solidity``` ` block inline | 1706 (50%) | Extract trực tiếp |
| GitHub URL permalink | 1116 (33%) | **WebFetch** blob URL → extract lines từ `#L42-L58` |
| Relative path (`File.sol#L123`) | 133 (4%) | Reconstruct URL từ `source_link` metadata → WebFetch |
| Inline marker (`//@audit`, `@>`) | 49 (1%) | Extract ± 3 dòng, detokenize |
| Prose only | 306 (9%) | `sections.code = null` |

**Fetch GitHub code**: dùng `WebFetch(github_blob_url, "extract Solidity code at lines L42-L58")` — không cần GITHUB_TOKEN. Fallback: `sections.code = null` nếu repo xóa/private.

**Relative path reconstruct**:
```
source_link: https://code4rena.com/reports/2022-09-biconomy
→ repo:       https://github.com/code-423n4/2022-09-biconomy
→ full URL:   https://github.com/code-423n4/2022-09-biconomy/blob/main/{rel_path}
```
Thử branch `main` → fallback `master` → skip nếu cả 2 fail.

### Normalize code

Trước khi ghi vào `sections.code`, normalize để code-to-code matching độc lập với variable names:
```python
# Thay tất cả user-defined identifiers bằng _VAR, giữ Solidity keywords/types
re.sub(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b",
       lambda m: m.group(0) if m.group(0) in SOLIDITY_KEYWORDS else "_VAR", code)
```

### Checkpoint & Resume

`rag_sections_cache.json` ghi sau mỗi batch. Resume logic:

```python
done_slugs     = {f["slug"] for f in cache.get("findings", [])}   # đã xử lý (kể cả failed)
failed_fetches = set(cache.get("fetch_errors", {}).keys())        # GitHub fetch fail → KHÔNG retry
remaining      = [m for m in all_metas if m["slug"] not in done_slugs]
```

**Nguyên tắc**: slug trong `done_slugs` → skip hoàn toàn. URL trong `fetch_errors` → skip GitHub fetch, `sections.code = null`. Không bao giờ re-fetch URL đã fail.

Sau mỗi batch ghi vào cache: tăng `_meta.processed_count`, cập nhật `_meta.last_processed_slug`.

### Trạng thái hiện tại

- **Phase 1 (vul)**: Chưa bắt đầu
- **Phase 2 (code)**: Chưa bắt đầu
- **Phase 3 (op + inv)**: Để sau Phase 1+2 validate xong
- **Sample files**: `backend/scripts/rag/samples/` — 7 files × 10 findings mỗi firm để kiểm tra

### Key files RAG

```
backend/
  data/rag_db/
    chroma/                     ← ChromaDB (collection solodit_findings hiện tại)
    parents.json                ← 3366 full-text findings (key: slug)
  scripts/rag/
    samples/                    ← 7 sample files (10 findings/firm) để phân tích
    rag_sections_template.json  ← Template output format
    rag_sections_cache.json     ← Output của migration (tạo dần)
    inject_custom_findings.py   ← Inject self-crafted entries vào ChromaDB
    self_crafted_35.json        ← 4 self-crafted entries cho contest 35 GT functions
docs/good-techniques/
  rag-4section-architecture.md  ← Thiết kế kiến trúc
  rag-migration-plan.md         ← Kế hoạch migration chi tiết
  code-normalize-rag.md         ← CODE normalize track design
```

---

## Key Patterns

- **Task tracking**: Long-running operations create a `Task` object with progress state. Frontend polls the task endpoint.
- **File encoding**: Multi-fallback chain (UTF-8 → charset_normalizer → chardet → UTF-8 with replace).
- **Report tool calls**: ReportAgent validates tool call format strictly; malformed LLM outputs are retried.
- **JSON output**: Flask is configured with `JSON_ENSURE_ASCII=False` so Chinese characters render directly.
