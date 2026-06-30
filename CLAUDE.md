# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

MiroFish is a **multi-agent smart contract audit engine**. It orchestrates LLM-powered agents to analyze Solidity contracts, discover vulnerabilities, and produce structured audit findings. Agents run in parallel across (domain × contract) chunks using a T1→T2→T3 discovery flow.

## Setup

```bash
cp .env.example .env          # điền LLM_VERTEX_AI_KEY_FILE, LLM_BASE_URL, LLM_MODEL_NAME
cd backend && uv sync         # install Python deps vào .venv
source .venv/bin/activate
```

Biến bắt buộc trong `.env`:

| Variable | Mục đích |
|----------|---------|
| `LLM_VERTEX_AI_KEY_FILE` | Path tới service account JSON của Vertex AI |
| `LLM_BASE_URL` | Vertex AI endpoint (global openapi) |
| `LLM_MODEL_NAME` | Model name, vd: `google/gemini-3-flash-preview` |
| `ZEP_API_KEY` | Zep Cloud API key (dùng cho KG build) |

Pool LLM: cấu hình thêm `LLM2_*` ... `LLM5_*` để tăng throughput (round-robin).

## Entry Point

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate
python main.py --help
```

**Hướng dẫn đầy đủ:** `docs/operations/how-to-run.md`
**Workflow chi tiết:** `docs/overview/pipeline-workflow.md`

## Chạy Audit Contest

**Tra cứu contest metadata trước:**

```python
import json
contests = json.load(open('benchmark/benchmark_contests.json'))['contests']
entry = next(x for x in contests if x['contest_id'] == '<id>')
# entry['contracts_dir']  → --contracts-dir
# entry['gt_contracts']   → --gt-contracts
# contest_dir luôn là /home/thangdd/repos/web3bugs/contracts/<id>
```

**Chạy (cách chuẩn — background):**

```bash
cd /home/thangdd/repos/MiroFish/backend
LOG=/tmp/sim_e2e_<id>_<label>_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
source .venv/bin/activate
exec python main.py \
  --contest-id <id> \
  --contest-dir /home/thangdd/repos/web3bugs/contracts/<id> \
  --contracts-dir <contracts_dir> \
  --gt-contracts <gt_contracts> \
  --workers 5 \
  --out-dir ../benchmark/web3bugs/agent-redesign/<id>/<label>
' > "$LOG" 2>&1 &
echo "PID=$!  LOG=$LOG"
```

**Theo dõi:**
```bash
tail -f "$LOG"
grep "→ .* raw findings" "$LOG" | wc -l   # chunks xong
```

**Flags quan trọng:**

| Flag | Mặc định | Tác dụng |
|------|----------|---------|
| `--workers N` | 1 | Parallel workers |
| `--dedup` | off | Per-chunk dedup (không dùng trừ khi user yêu cầu) |
| `--no-inv` | off | Tắt HIST-INV injection |
| `--swc` | off | Inject SWC knowledge base vào agent prompts |
| `--rt` | off | Bật red-team attacker agents |
| `--kg-file PATH` | auto | Dùng KG đã build sẵn |

**RT: tắt theo mặc định.** Chỉ thêm `--rt` khi user yêu cầu rõ ràng.
**Dedup: tắt theo mặc định.** Không pass `--dedup` trừ khi user yêu cầu rõ ràng.
**KG: tự build và cache.** Script tự detect `kg_result_auto.json` và reuse — không cần flag.

## HIST-INV Cache

Cache lưu kết quả LLM synthesis cho từng function — reuse giữa các runs cùng contest.
Path: `benchmark/web3bugs/agent-redesign/<id>/hist_inv_cache.json`

**KHÔNG xóa trừ khi user xác nhận rõ ràng.** Cache có thể có 180+ entries.
Nếu cần rebuild selective:

```python
import json
cache = json.load(open('benchmark/web3bugs/agent-redesign/<id>/hist_inv_cache.json'))
target_fns = {'borrow', 'liquidate'}
cache['entries'] = {k: v for k, v in cache.get('entries', {}).items()
                    if v.get('fn_name', '') not in target_fns}
json.dump(cache, open('benchmark/web3bugs/agent-redesign/<id>/hist_inv_cache.json', 'w'), indent=2)
```

Hỏi user: "Xóa toàn bộ cache hay chỉ các function [danh sách]?"

## Eval

```bash
cd backend/scripts/evaluate
python web3bugs_eval.py \
  gt/gt_<id>.json \
  ../../benchmark/web3bugs/agent-redesign/<id>/<label>/audit_report_<id>_raw.json \
  --verbose | tee ../../benchmark/web3bugs/agent-redesign/<id>/<label>/eval_result.txt
```

**Manual eval:** theo hướng dẫn `docs/operations/eval-manual-matching-guide.md`

## Architecture

### Backend (`backend/`)

```
main.py                          ← Entry point (audit pipeline)
app/
  services/
    cyber_session_orchestrator.py  ← Core orchestrator, _run_contract_audit_v2()
    contract_oasis_env.py          ← Prompt builders (build_round1_prompt, build_t3_prompt, ...)
    contract_kg_builder.py         ← Zep KG builder
    contract_hist_inv_cache.py     ← HIST-INV cache manager
    contract_parser.py             ← Solidity parser
    contract_profile_generator.py  ← 19 Tier-1 agent profiles
    contract_dep_graph.py          ← Dependency graph
    cyber_oasis_env.py             ← Cyber mode env builder
    cyber_expert_profile_generator.py ← Cyber expert profiles
    graph_builder.py               ← Zep graph build service
    text_processor.py              ← Text utilities
    swc_registry.py                ← SWC knowledge base
    mitre_reference.py             ← MITRE ATT&CK reference
    semantic_taxonomy.py           ← Semantic vuln categories
  models/
    task.py                        ← TaskManager (async task tracking)
    cyber_models.py                ← Audit finding dataclasses
    contract_models.py             ← Contract entity dataclasses
  utils/                           ← LLM client, logger, helpers
scripts/
  hist_inv/
    populate_hist_inv_cache.py     ← Build HIST-INV cache (Giai đoạn 2)
  evaluate/
    web3bugs_eval.py               ← LLM-judge eval (H-bug F1)
    gt/                            ← Ground truth JSON files per contest
  dedup/
    dedup_report.py                ← LLM-based semantic dedup (offline)
  baselines/
    run_gptscan_benchmark.py       ← GPTScan baseline
    run_slither_benchmark.py       ← Slither baseline
    run_llmsmartaudit_benchmark.py ← LLMSmartAudit baseline
  rag/
    rag_sections_cache.json        ← RAG data (3366/3366 findings, hoàn tất)
```

### Pipeline Flow (main.py)

```
[1] Setup LLM pool (LLM1..5 round-robin)
[2] discover_contracts() → .sol files
[3] Build/load KG → kg_result_auto.json (auto-cache)
[4] Load HIST-INV cache → INV_MAP (fn → invariants)
[5] Generate 19 agent profiles (Tier 1)
[6] Build aux map (contract dependencies)
[7] build_chunks() → (domain × contract) groups
[8] Annotate source với HIST-INV comments
[9] Run agents (ThreadPoolExecutor, --workers)
    Per agent: T1 (invariants) → T2 (findings) → T3 (CoT sweep)
[10] Merge → audit_report_<id>_raw.json
```

### Docs

```
docs/
  operations/        ← Hướng dẫn vận hành
    how-to-run.md          ← Hướng dẫn chạy (3 giai đoạn)
    eval-manual-matching-guide.md
    eval-*.md              ← Eval guides cho các baseline tools
  overview/          ← Tài liệu tổng quan
    pipeline-workflow.md   ← Workflow chi tiết step-by-step
```

## RAG (HIST-INV Data)

RAG sections cache (`backend/scripts/rag/rag_sections_cache.json`) đã hoàn tất: 3366/3366 findings.
ChromaDB tại `backend/data/rag_db/chroma/` — collection `solodit_findings`.
Không cần rebuild trừ khi Solodit DB cập nhật thêm findings mới.

## Benchmark Data

```
benchmark/
  benchmark_contests.json          ← Registry các contests (contest_id, contracts_dir, gt_contracts)
  web3bugs/agent-redesign/
    <contest_id>/
      hist_inv_cache.json          ← HIST-INV cache per contest
      kg_result_auto.json          ← KG cache (auto-saved)
      <run_label>/
        audit_report_<id>_raw.json ← Raw findings (input cho eval)
        audit_report_dedup.json    ← Sau dedup_report.py
        eval_result.txt            ← Kết quả eval (tee từ web3bugs_eval.py)
```
