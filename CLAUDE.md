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

## Key Patterns

- **Task tracking**: Long-running operations create a `Task` object with progress state. Frontend polls the task endpoint.
- **File encoding**: Multi-fallback chain (UTF-8 → charset_normalizer → chardet → UTF-8 with replace).
- **Report tool calls**: ReportAgent validates tool call format strictly; malformed LLM outputs are retried.
- **JSON output**: Flask is configured with `JSON_ENSURE_ASCII=False` so Chinese characters render directly.
