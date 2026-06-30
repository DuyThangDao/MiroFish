# Pipeline: `simulate_e2e.py` — Luồng Hoạt Động

## Tổng quan

Pipeline chia làm **2 giai đoạn**:

- **Giai đoạn 1 — Chuẩn bị** (làm một lần per contest): đăng ký contest vào registry, build HIST-INV cache offline.
- **Giai đoạn 2 — Chạy audit** (`simulate_e2e.py`): dùng cache đã build, chạy agents, sinh report.

```
═══════════════════════════════════════════════════════════
GIAI ĐOẠN 1 — CHUẨN BỊ (một lần per contest)
═══════════════════════════════════════════════════════════

benchmark_contests.json  ←  thêm entry contest mới
        │
        ▼
populate_hist_inv_cache.py
  ├─ flatten_contest_dir()       → combined source
  ├─ ContractParser.parse()      → entity (functions list)
  └─ _build_call_graph_with_hist_inv()
       ├─ RAG search per function (OP + ST tracks)
       └─ LLM synthesis → INV-N statements
                │
                ▼
        hist_inv_cache.json   (reused across all runs)

═══════════════════════════════════════════════════════════
GIAI ĐOẠN 2 — CHẠY AUDIT (simulate_e2e.py)
═══════════════════════════════════════════════════════════

Contest source  +  hist_inv_cache.json (từ Giai đoạn 1)
    │
    ▼
[2] Discover contracts  ──→  discover_contracts()
    │
    ▼
[3] Build KG (Zep)      ──→  _build_kg_pipeline()  →  kg_result_auto.json
    │
    ▼
[4] Generate profiles   ──→  ContractExpertProfileGenerator  →  profiles_map
    │
    ▼
[5] Build chunks        ──→  build_chunks()  →  list of (domain × contract) groups
    │
    ▼
[6] Run agents          ──→  ThreadPoolExecutor  →  T1→T2→T3 per agent per chunk
    │
    ▼
[7] (Optional) Dedup    ──→  dedup_pipeline()  →  chunk_dedup.json
    │
    ▼
[8] Save reports        ──→  audit_report_<id>_raw.json
```

---

## Giai đoạn 1 — Chuẩn bị

### Bước 1.0 — Build RAG Sections Cache (global, một lần toàn dự án)

`backend/scripts/rag/rag_sections_cache.json` là nguồn dữ liệu RAG cho toàn bộ hệ thống HIST-INV. File này được build **một lần duy nhất** cho toàn dự án (không phải per-contest) và reuse mãi mãi. Khi đã đầy đủ (3366/3366 findings), **không cần chạy lại** trừ khi Solodit DB cập nhật thêm findings mới.

**Trạng thái hiện tại:** `processed_count = 3366 / 3366` — đã hoàn tất.

#### Cấu trúc file

```json
{
  "_meta": {
    "total_findings": 3366,
    "processed_count": 3366,
    "last_processed_slug": "..."
  },
  "fetch_errors": { "some-slug": { "url": "...", "reason": "404" } },
  "findings": [
    {
      "slug": "h-01-...",
      "status": "done",
      "sections": {
        "vul":  "prose mô tả lỗi (bug class, impact)",
        "code": "_VAR -= uint128(_VAR);   ← normalized Solidity",
        "op":   "subtract from reserve; cast uint256→uint128 ...",
        "inv":  "function X must ensure Y before Z"
      }
    }
  ]
}
```

Source of truth là `backend/data/rag_db/parents.json` (3366 full-text findings). `rag_sections_cache.json` KHÔNG lưu `content` — tra theo `slug` từ `parents.json` khi cần.

#### Pipeline build (nếu cần rebuild từ đầu)

```
parents.json  (3366 findings — Solodit API, build bằng build_rag_db.py)
    │
    ├─ [Static extract] fill_raw_code_static.py
    │    → sections.vul  (từ finding text)
    │    → sections.code (code block / audit marker / inline Solidity)
    │
    ├─ [GitHub fetch]   fetch_github_code.py  →  sections.code cho GitHub URL findings
    │                   fetch_github_llm.py   →  LLM-assisted fetch khi parse thất bại
    │
    ├─ [LLM fill]       fill_raw_code_llm.py  →  sections.code cho remaining cases
    │
    ├─ [LLM generate]   fill_op_llm.py        →  sections.op  (input: raw_code + vul)
    │                   fill_inv_llm.py        →  sections.inv (input: op + vul)
    │
    └─ [Embed]          embed_solodit_unified.py
                            → ChromaDB collection solodit_unified
                               1 doc per finding = vul + inv + op concatenated
```

Tất cả scripts chạy từ `backend/` với venv activated. Mỗi script **idempotent** — skip findings đã có trong cache (checkpoint tự động sau mỗi batch).

#### Phân loại findings theo code availability

| Category | Count | Script xử lý |
|----------|-------|--------------|
| ` ```solidity``` ` block | 1621 (48%) | `fill_raw_code_static.py` |
| GitHub URL permalink | 921 (27%) | `fetch_github_code.py` / `fetch_github_llm.py` |
| LLM-assisted GitHub | 280 (8%) | `fetch_github_llm.py` |
| LLM inline extraction | 102 (3%) | `fill_raw_code_llm.py` |
| Relative path | 122 (4%) | `fill_raw_code_static.py` |
| Prose only (no code) | 252 (7%) | → `sections.code = null` |

#### Quan hệ với HIST-INV

`populate_hist_inv_cache.py` (Bước 1.2) đọc `inv` sections từ file này để inject vào agents. Nếu `rag_sections_cache.json` thiếu hoặc `sections.inv` trống, HIST-INV annotations sẽ không có invariant hints.

ChromaDB `solodit_unified` (từ `embed_solodit_unified.py`) được dùng bởi `_build_call_graph_with_hist_inv()` để RAG search — tìm findings tương tự cho từng function.

---

### Bước 1.1 — Đăng ký contest vào `benchmark/benchmark_contests.json`

File này là **registry trung tâm** cho toàn bộ contests. Mọi script đều tra cứu từ đây để lấy `contracts_dir` và `gt_contracts` — không hardcode path tùy tiện.

Thêm một entry vào mảng `contests`:

```json
{
  "contest_id": "<id>",
  "name": "<tên protocol>",
  "contracts_dir": "/home/thangdd/repos/web3bugs/contracts/<id>/<subdir>/contracts",
  "gt_file": "backend/scripts/evaluate/gt/gt_<id>.json",
  "gt_contracts": ["ContractA", "ContractB", "..."],
  "gt_by_contract": {
    "ContractA": ["H-01", "H-03"],
    "ContractB": ["H-02"]
  }
}
```

**Quan trọng về `contracts_dir`:**
- Lấy từ `benchmark_contests.json` — **không tự đoán path**
- Mỗi contest có thể có cấu trúc thư mục khác nhau
- Ví dụ contest 104: GT contracts nằm rải rác trong 3 subdirs → dùng root `104/` làm `contracts_dir`
- Tra cứu bằng Python:

```python
import json
contests = json.load(open('benchmark/benchmark_contests.json'))['contests']
entry = next(x for x in contests if x['contest_id'] == '<id>')
# entry['contracts_dir']  → dùng cho --contracts-dir
# entry['gt_contracts']   → dùng cho --gt-contracts
```

### Bước 1.2 — Build HIST-INV Cache (`populate_hist_inv_cache.py`)

Cache lưu kết quả RAG search + LLM synthesis cho từng function của contest. Được reuse giữa các runs — **không rebuild lại trừ khi prompt hoặc RAG DB thay đổi**.

**Luồng của script:**

```
flatten_contest_dir(contest_dir)
    │  → combined source (với file section headers)
    │    section headers giúp contract_name extract đúng → cache keys đúng
    ▼
ContractParser.parse_from_source(combined_source)
    │  → ContractEntity (danh sách tất cả functions)
    ▼
ContractKGBuilder._build_call_graph_with_hist_inv(
    source, fn_names, cache=hc, llm_clients=clients)
    │
    ├─ Với mỗi function:
    │    ├─ RAG search (OP track + ST track) → matched slugs
    │    ├─ Lookup inv statements từ rag_sections_cache.json
    │    └─ LLM synthesis → INV-N: ... lines
    │
    └─ Parallel: HIST_INV_WORKERS threads (env var)
    ▼
hc.save()  →  hist_inv_cache.json
```

**Chạy:**

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

LOG=/tmp/hist_inv_<id>_$(date +%Y%m%d_%H%M%S).log
nohup python scripts/populate_hist_inv_cache.py \
  --contest-id   <id> \
  --contest-dir  /home/thangdd/repos/web3bugs/contracts/<id> \
  --contracts-dir <contracts_dir từ benchmark_contests.json> \
  --gt-contracts  <gt_contracts từ benchmark_contests.json> \
  --workers 4 \
> "$LOG" 2>&1 & echo "PID=$!  LOG=$LOG"
```

Theo dõi:
```bash
tail -f "$LOG"
grep -E "DONE|functions annotated|Cache saved" "$LOG"
```

**Output:** `benchmark/web3bugs/agent-redesign/<id>/hist_inv_cache.json`

**Kiểm tra kết quả:**
```bash
python3 -c "
import json
cache = json.load(open('benchmark/web3bugs/agent-redesign/<id>/hist_inv_cache.json'))
entries = cache.get('entries', {})
print('Total entries:', len(entries))
# Kiểm tra GT contracts có được annotate không
gt = {'ContractA', 'ContractB'}
hits = {k: v for k, v in entries.items() if v.get('contract_name') in gt}
print('GT contract entries:', len(hits))
"
```

**Chính sách cache — KHÔNG xóa tùy tiện:**
- Cache có thể có 180+ entries — rebuild tốn nhiều thời gian
- Chỉ xóa khi: thay đổi HIST-INV prompt, thay đổi RAG DB, hoặc user nói rõ
- Nếu cần rebuild một phần, xóa **selective** theo `fn_name`:

```python
import json
cache = json.load(open('hist_inv_cache.json'))
entries = cache.get('entries', {})
target_fns = {'borrow', 'liquidate'}  # chỉ các fn cần rebuild
cache['entries'] = {k: v for k, v in entries.items()
                    if v.get('fn_name', '') not in target_fns}
json.dump(cache, open('hist_inv_cache.json', 'w'), indent=2)
```

### Khi nào cần chạy lại Giai đoạn 1

| Tình huống | Cần làm gì |
|-----------|-----------|
| Contest mới | Thêm entry vào `benchmark_contests.json` + chạy `populate_hist_inv_cache.py` |
| Đổi HIST-INV prompt | Xóa cache (selective nếu có thể) + chạy lại |
| RAG DB update (`rag_sections_cache.json`) | Xóa cache + chạy lại |
| Thêm GT contract mới vào contest đã có | Chỉ cần chạy lại (cache merge, không ghi đè entries cũ) |
| Chạy thêm run mới của cùng contest | **Không cần** — cache reuse tự động |

---

## Giai đoạn 2 — Chạy Audit (`simulate_e2e.py`)

### Bước 2 — Discover Contracts

`discover_contracts()` walk toàn bộ `--contracts-dir`, đọc tất cả `.sol` files, bỏ qua:
```
interfaces/  test/  workInProgress/  flat/  mocks/  mock/  node_modules/  artifacts/
```

Fallback: nếu GT contracts không tìm thấy trong `contracts-dir`, tìm tiếp trong `contest-dir`.

Output: `dict[contract_name → (path, source_code)]`

---

## Bước 3 — Build Knowledge Graph

**Priority order** (dừng tại bước đầu tiên thành công):

1. `--kg-result <path>` được pass → load trực tiếp
2. `kg_result_auto.json` tồn tại trong bench dir → reuse
3. Không có → chạy `_build_kg_pipeline()`:
   - Nếu `--contest-dir` có: flatten toàn bộ contest (`flatten_contest_dir()`) → lấy `in_scope_source`
   - Ngược lại: concat toàn bộ `--contracts-dir` files
   - Submit lên `ContractKGBuilder.build_from_source_async()` → poll đến khi `completed`
   - Lưu kết quả vào `kg_result_auto.json` (reuse lần sau)

Output: `_context_summary` — chuỗi text chứa CALL GRAPH của tất cả contracts.

---

## Bước 4 — Generate Agent Profiles

`ContractExpertProfileGenerator.generate_tier1_profiles(primary_src)` sinh 19 agent profiles.

Primary contract được auto-detect: GT contract đầu tiên theo alphabet.

Output: `profiles_map = {agent_id → ContractAgentProfile}`

Mỗi profile có: `agent_id`, `persona`, `system_prompt` (expert identity + worldview + core question).

---

## Bước 5 — Build Chunks

### 4a. Group functions theo domain

`build_chunks()` quét toàn bộ GT contracts, dùng `FN_NAME_RULES` để map từng function sang 1 trong 7 domains:

| Domain | Pattern ví dụ | Agents |
|--------|--------------|--------|
| `clmm_semantic` | tick, fee_growth, sqrt_ratio | quant_analyst, invariant_mathematician, ... |
| `liquidity_mutation` | burn, mint, add/removeLiquidity | quant_analyst, numerical_analyst, ... (14 agents) |
| `math_cast` | swap, calc*, getAmounts | quant_analyst, numerical_analyst, ... (11 agents) |
| `access_reward` | claim, reward, stake, deposit | token_flow_expert, accounting_auditor, ... |
| `economic` | flash, oracle, twap, buyback | defi_security_researcher, economic_exploiter, ... |
| `state_ordering` | initialize, init, callback, sync | program_logician, state_analyst, ... |
| `admin_gov` | changeX, setOwner, proposal, lockUnit | threat_modeler, state_analyst, ... |
| `general` | (fallback) | broad coverage |

### 4b. Xác định aux contracts

`build_aux_map()`: với mỗi GT contract, parse `import` statements → tìm deps trong GT contracts (direct match + interface `IName → Name` heuristic).

`_find_parent_sources()`: tìm parent contracts kế thừa (`is X`) trong cùng directory, filter:
- Không phải interfaces
- Không phải GT contracts
- File < 200 lines

### 4c. Build source cho chunk

Với mỗi `(domain, contract)` group:

- **Nhỏ (< 30k chars, không có aux)** → dùng full source
- **Lớn hoặc có aux** → `build_chunk_source()`:
  ```
  contract header (state vars, events, errors — bỏ function bodies)
  + target functions (extracted by name)
  + modifier bodies inline (dạng comment [MODIFIER name]: ...)
  + aux contracts (full source hoặc chỉ called functions tùy --no-full-aux)
  ```

- **HIST-INV annotation**: inject `// [HIST-INV] INV-N: ...` inline vào source trước khi chạy agents (từ RAG cache)
- **Call graph block**: prepend `CALL GRAPH: [ContractName]\n  fn → callee ...` từ `_context_summary`

Nếu `--max-fns-per-chunk N` → split thành sub-chunks (grp 1/N, 2/N, ...).

---

## Bước 6 — Run Agents

`ThreadPoolExecutor(max_workers=WORKERS)` chạy tất cả agent tasks song song.

### Defender agents (mặc định)

Mỗi agent chạy **3 rounds tuần tự**:

```
T1 — Invariant extraction
     build_round1_prompt(..., invariant_only=True)
     → LLM trả về INV-N: ... lines
     → clean_inv() giữ lại chỉ các dòng bắt đầu bằng "INV-N:"

T2 — Standard finding (dùng T1 invariants làm context)
     build_round1_prompt(..., injected_invariants=t1_clean)
     → LLM trả về FINDING blocks
     → parse_findings() → list of findings

T3 — Chain-of-thought sweep (độc lập, không dùng T1/T2)
     build_t3_prompt(...)
     → LLM viết TRACE blocks trước, sau đó FINDING blocks chỉ cho VERDICT=BUG
     → parse_findings()
```

### Attacker agents (RT — chỉ khi `--rt`)

Agent IDs: `arithmetic_exploiter`, `flash_loan_attacker`, `state_hijacker`, `timing_manipulator`, `trusted_insider`

```
RT1 — Attack surface scan
      SURFACE [fn]: INPUT / WORST_CASE / ASSUMPTION_BROKEN / PRE_STATE / CALLBACKS

RT2 — Exploit construction (dùng RT1 surfaces làm context)
      FINDING blocks chỉ cho surfaces có real exploit

RT3 — Adversarial backward trace (độc lập)
      ATTACK_TRACE [fn]: GOAL / PRECONDITION / SEQUENCE / OUTCOME / FEASIBILITY=EXPLOIT
      → FINDING blocks chỉ cho EXPLOIT traces
```

RT agents **không nhận HIST-INV** (annotations bị strip trước khi tạo prompt).

### Resume logic

Nếu output file `<chunk>_<agent_id>.txt` đã tồn tại → parse lại, **bỏ qua LLM call**. Cho phép resume khi bị interrupt.

### Staggering

Agent `idx` sleep `idx * 2s` (parallel mode) hoặc `2 + idx * 3s` (sequential) trước khi call LLM — tránh burst rate limit.

### LLM pool

Round-robin qua `llm_pool` (LLM1..LLM5 từ env). Retry tối đa 5 lần khi gặp 429 / connection error.

### Contract filter

Sau khi parse findings, `_filter_to_chunk_contract()` drop findings có `contract_name` không thuộc primary hoặc aux contracts của chunk — ngăn hallucination về contracts không có trong source.

---

## Bước 7 — Per-chunk Dedup (chỉ khi `--dedup`)

Triggered khi agent cuối cùng của chunk hoàn thành. Chạy async trong cùng executor.

`dedup_pipeline()` gọi 3 bước của orchestrator:
```
_dedup_pre_r2()          — rule-based pre-filter (code anchor exact match)
_semi_static_anchor_dedup()  — anchor-based clustering
_llm_anchor_dedup()      — LLM-based semantic merge
```

Output: `<chunk>_chunk_dedup.json`

---

## Bước 8 — Save Reports

Merge findings từ tất cả chunks:

```
audit_report_<id>_raw.json    — tất cả T2+T3 findings, không dedup
```

Format:
```json
{
  "contest_id": "5",
  "config": "T2+T3_merged_no_dedup",
  "total_findings": 1234,
  "wall_time_s": 3600,
  "findings": [
    {
      "title": "...",
      "description": "...",
      "attack_path": "...",
      "contract_name": "Pools",
      "function_name": "swap",
      "severity": "high",
      "code_anchor": "...",
      "evidence": "...",
      "source": "T2",
      "agent_id": "quant_analyst"
    }
  ]
}
```

---

## Giai đoạn 3 — Post-processing

### Bước 3.1 — Semantic Dedup (`dedup_report.py`)

Giai đoạn 2 sinh ra `audit_report_<id>_raw.json` thường có hàng trăm đến hàng nghìn findings do nhiều agents báo cùng một bug. `dedup_report.py` gom nhóm và loại trùng bằng LLM để giảm noise trước khi eval.

**Khi nào dùng:**
- Mặc định: **không** dùng `--dedup` trong `simulate_e2e.py` → dedup offline bằng script này
- Lợi thế: có thể thử nhiều mức dedup khác nhau mà không cần chạy lại agents

#### Luồng dedup

```
audit_report_<id>_raw.json
    │
    ▼
Bước 1-2: Load + Group by (normalize_fn, contract)
           normalize_fn = fn.split('(')[0].strip()
    │
    ▼
Bước 3: Cluster mỗi group (parallel, --workers threads)
    │
    ├─ Singleton (1 finding) → pass through
    │
    ├─ Small group (≤ batch-size) → 1 LLM call (Merge Prompt)
    │    default = giữ tất cả; merge CHỈ khi 100% chắc cùng bug
    │    3 điều kiện bắt buộc: same buggy line + same mechanism + same fix
    │
    └─ Large group (> batch-size) → 2-pass:
         Pass 1: split batches ≤ batch-size → LLM cluster mỗi batch
         Pass 2: 1 LLM call cluster survivors của Pass 1
    │
    ▼
Bước 4: Cross-group dedup (sequential)
    │
    ├─ Pattern C — Misattribution check (deterministic):
    │    Tìm singletons có description nhắc đến function X
    │    nhưng metadata ghi function Y (X ≠ Y)
    │    → nếu X đã có representative → drop singleton
    │
    └─ Pattern D — Same vuln across N functions (per contract):
         Chỉ check contracts có ≥ 5 dedup findings
         1 LLM call per contract: "có cặp nào cùng root cause, cùng fix không?"
         → nếu có: drop duplicates
    │
    ▼
Bước 5: Write audit_report_dedup.json
```

**Framing quan trọng của Merge Prompt:** "default = giữ tất cả, chỉ merge khi chắc chắn" — tránh sai hướng từ "cluster thành nhóm" sang "tìm duplicate". Missed merge (giữ duplicate) chấp nhận được; wrong merge (drop TP) phá eval.

#### Chạy

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

RUN_DIR=../benchmark/web3bugs/agent-redesign/<id>/<run_label>

python scripts/dedup_report.py \
  --input   $RUN_DIR/audit_report_<id>_raw.json \
  --output  $RUN_DIR/audit_report_dedup.json \
  --workers 3 \
  --batch-size 20
```

Flags tùy chọn:
```
--skip-cross    # Bỏ Bước 4 (Pattern C/D) — chỉ group-level dedup
--workers N     # Parallel threads cho group clustering (default: 3)
--batch-size N  # Max findings per LLM call trong 1 group (default: 20)
```

#### Output format

```json
{
  "findings": [
    {
      "title": "...",
      "contract_name": "Pools",
      "function_name": "swap",
      "_raw_idx": 103,
      "_dedup_note": "Representative of 32 findings in swap/Pools (merged raw[45]: same access control bug)"
    }
  ],
  "_dedup_meta": {
    "raw_count":   1760,
    "dedup_count": 426,
    "date":        "2026-06-30",
    "source_file": "audit_report_5_raw.json"
  }
}
```

#### Kiểm tra nhanh kết quả

```bash
python3 -c "
import json
d = json.load(open('$RUN_DIR/audit_report_dedup.json'))
m = d['_dedup_meta']
reduction = round((1 - m['dedup_count'] / m['raw_count']) * 100, 1)
print(f'raw={m[\"raw_count\"]}  dedup={m[\"dedup_count\"]}  reduction={reduction}%')
"
```

---

### Bước 3.2 — Evaluation (`web3bugs_eval.py`)

Đánh giá recall so với Ground Truth H-bugs. Chạy eval trên **cả raw và dedup** — raw trước để có baseline, dedup sau.

#### Cách hoạt động

```
gt_<id>.json  +  audit_report_*.json
    │
    ▼
Với mỗi GT bug:

  Tier-1 (T1): Tìm findings có function_name == gt_fn AND contract_name == gt_con
       → LLM judge (batch 10) → is_match?  →  MATCH nếu YES

  Tier-2 (T2): Nếu T1 miss → tìm findings mà description/attack_path
               nhắc đến gt_fn + gt_con (agent báo đúng bug nhưng sai function attribution)
       → LLM judge → MATCH nếu YES
    │
    ▼
TP = số GT bugs có MATCH (mỗi bug tính tối đa 1 lần)
FN = số GT bugs không có MATCH
FP = số findings không match bất kỳ GT bug nào
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 * P * R / (P + R)
```

**Staggering:** worker `i` sleep `i×15s` trước call đầu tiên — tránh burst rate limit khi start.

#### Chạy

```bash
cd /home/thangdd/repos/MiroFish/backend/scripts/evaluate

RUN_DIR=../../benchmark/web3bugs/agent-redesign/<id>/<run_label>

# Eval raw (chạy trước)
python web3bugs_eval.py gt/gt_<id>.json \
  $RUN_DIR/audit_report_<id>_raw.json \
  --verbose 2>&1 | tee $RUN_DIR/eval_result_raw.txt

# Eval dedup (chạy sau — không song song)
python web3bugs_eval.py gt/gt_<id>.json \
  $RUN_DIR/audit_report_dedup.json \
  --verbose 2>&1 | tee $RUN_DIR/eval_result_dedup.txt
```

**Quan trọng:** chạy raw trước, dedup sau — **không song song** (cùng dùng LLM pool, tránh rate limit).

#### Output mẫu

```
=== Web3Bugs Evaluation ===
TP=18  (T1=12 T2=6)  FP=0  FN=6
Precision=1.000  Recall=0.750  F1=0.857

Matched H bugs:
  H-01 [T1] ← finding 'Unhandled return value in transferOut'
  H-07 [T2] ← finding 'Wrong asymmetric share formula'
  ...
```

#### Lưu ý: Lỗi Regex parse function_name

`web3bugs_eval.py` dùng `function_name` để match T1. Nếu `function_name = None` (do `parse_log()` regex miss khi description dùng dạng `` `funcName` `` không có `(` ngay sau), finding bị skip T1, và T2 có thể cũng miss.

Sau khi chạy eval, kiểm tra GT bugs bị "no match" xem có phải do regex miss không:

```python
import json
data  = json.load(open('findings_all.json'))        # hoặc audit_report_raw.json
gt_fn = 'calcLiquidityUnits'
hits  = [f for f in data['findings']
         if f.get('function_name') is None
         and gt_fn in (f.get('description') or '')]
for f in hits:
    print(f['vulnerability_name'])
    print(f['description'][:300])
```

Nếu tìm được: áp 3-câu checklist và ghi nhận manual correction (xem `docs/eval-manual-matching-guide.md`).

#### Lưu kết quả bắt buộc

```bash
# Bắt buộc dùng tee để lưu kết quả
python web3bugs_eval.py gt/gt_<id>.json $REPORT --verbose \
  | tee $RUN_DIR/eval_result.txt
```

File `eval_result.txt` chứa toàn bộ verbose output (matched/missed H bugs + TP/FP/FN/Precision/Recall/F1).

---

## Các File Liên Quan

### Scripts — Giai đoạn 1 (Chuẩn bị RAG)

| File | Mô tả |
|------|-------|
| `backend/scripts/rag/build_rag_db.py` | Fetch 3366 findings từ Solodit API → `parents.json` + ChromaDB ban đầu |
| `backend/scripts/rag/fill_raw_code_static.py` | Extract `sections.vul` + `sections.code` bằng regex (code block / audit marker / inline) |
| `backend/scripts/rag/fetch_github_code.py` | Fetch code từ GitHub permalink URLs → `sections.code` |
| `backend/scripts/rag/fetch_github_llm.py` | LLM-assisted GitHub fetch khi parse thất bại |
| `backend/scripts/rag/fill_raw_code_llm.py` | LLM fill `sections.code` cho các trường hợp còn lại |
| `backend/scripts/rag/fill_op_llm.py` | Generate `sections.op` (mechanical operations) bằng LLM |
| `backend/scripts/rag/fill_inv_llm.py` | Generate `sections.inv` (abstract invariants) bằng LLM |
| `backend/scripts/rag/embed_solodit_unified.py` | Embed vul+inv+op vào ChromaDB collection `solodit_unified` |
| `backend/scripts/populate_hist_inv_cache.py` | Build `hist_inv_cache.json` cho một contest (RAG search + LLM synthesis) |

**RAG helpers** (không chạy trực tiếp, dùng gián tiếp hoặc one-off):

| File | Mô tả |
|------|-------|
| `backend/scripts/rag/process_sections_gemini.py` | Automated extraction vul/code qua Vertex AI Gemini (dùng khi build lần đầu) |
| `backend/scripts/rag/rag_retriever.py` | RAG search helper — được import bởi `cyber_session_orchestrator._get_rag_retriever()` |
| `backend/scripts/rag/inject_custom_findings.py` | Inject self-crafted entries vào ChromaDB (dùng khi cần thêm custom GT findings) |
| `backend/scripts/rag/embed_solodit_op.py` | Embed riêng OP track → collection `solodit_op` (bổ sung bên cạnh `solodit_unified`) |
| `backend/scripts/rag/cache_writer.py` | Helper ghi checkpoint vào `rag_sections_cache.json` (thread-safe) |
| `backend/scripts/rag/build_work_queue.py` | Build `work_queue.json` — danh sách slugs cần process cho `process_sections_gemini.py` |

**HIST-INV utilities** (dùng khi cần rebuild/debug một phần cache, không chạy trong flow chính):

| File | Mô tả |
|------|-------|
| `backend/scripts/hist_inv/backfill_hist_inv_stmts.py` | Backfill `hist_inv_stmts.json` từ cache có sẵn — tái dùng HIST titles, không cần chạy lại KG |
| `backend/scripts/hist_inv/build_hist_for_fns.py` | Build HIST-INV cache cho một danh sách functions cụ thể (debug/test GT functions) |
| `backend/scripts/hist_inv/rebuild_hist_inv_cache.py` | Rebuild `hist_inv_cache.json` chỉ cho GT contracts của một contest |

### Scripts — Giai đoạn 2 (Chạy Audit)

| File | Mô tả |
|------|-------|
| `backend/scripts/simulate_e2e.py` | **Main pipeline** — discover → KG → profiles → chunks → agents → report |
| `backend/scripts/flatten_contest.py` | Flatten toàn bộ contest dir thành combined source (dùng cho KG build) |

### Scripts — Giai đoạn 3 (Post-processing)

| File | Mô tả |
|------|-------|
| `backend/scripts/dedup_report.py` | LLM-based semantic dedup: group by fn → merge prompt → Pattern C/D |
| `backend/scripts/evaluate/web3bugs_eval.py` | Đánh giá recall: T1 (exact fn match) + T2 (semantic) so với GT H-bugs |
| `backend/scripts/evaluate/llm_judge.py` | LLM judge helper — so sánh 1 finding với 1 GT bug |
| `backend/scripts/evaluate/metrics.py` | Tính TP/FP/FN/Precision/Recall/F1 |

### Services (được gọi bởi pipeline)

| File | Mô tả |
|------|-------|
| `backend/app/services/contract_kg_builder.py` | Build Zep KG + `_build_call_graph_with_hist_inv()` (RAG search per function) |
| `backend/app/services/contract_parser.py` | Parse Solidity source → `ContractEntity` (functions list) |
| `backend/app/services/contract_hist_inv_cache.py` | Cache manager cho HIST-INV results (`HistInvCache`, `HistInvStmtsCache`) |
| `backend/app/services/contract_profile_generator.py` | Generate 19 Tier-1 agent profiles (Epistemic Lens) |
| `backend/app/services/contract_oasis_env.py` | OASIS env config + `build_round1_prompt()` + `build_t3_prompt()` |
| `backend/app/services/cyber_session_orchestrator.py` | Dedup pipeline + `_annotate_source_with_hist_inv()` + `_get_rag_retriever()` |

### Data Files — Static (không thay đổi giữa các runs)

| File | Mô tả |
|------|-------|
| `benchmark/benchmark_contests.json` | Contest registry — `contracts_dir`, `gt_contracts`, `gt_by_contract` |
| `backend/data/rag_db/parents.json` | 3366 full-text findings từ Solodit — source of truth, không sửa |
| `backend/data/rag_db/chroma/` | ChromaDB directory — chứa collection `solodit_unified` (và `solodit_op`) |
| `backend/scripts/rag/rag_sections_cache.json` | 4-section cache: vul/code/op/inv cho 3366 findings |
| `backend/scripts/evaluate/gt/gt_<id>.json` | Ground truth H-bugs per contest |

### Data Files — Per-Contest (generated)

```
benchmark/web3bugs/agent-redesign/<contest_id>/
  hist_inv_cache.json          ← Giai đoạn 1.2 — reused giữa mọi runs cùng contest
  kg_result_auto.json          ← Giai đoạn 2 bước 3 — reused nếu source không đổi

  <run_label>/
    audit_report_<id>_raw.json      ← Giai đoạn 2 output (main)
    audit_report_dedup.json         ← Giai đoạn 3.1 output
    eval_result_raw.txt             ← Giai đoạn 3.2 (eval trên raw)
    eval_result_dedup.txt           ← Giai đoạn 3.2 (eval trên dedup)
    chunk_timings.jsonl             ← Elapsed time per chunk
    <domain>_<contract>_<agent>.txt      ← Raw T1/T2/T3 LLM response
    <domain>_<contract>_chunk_raw.json   ← Merged findings per chunk
    <domain>_<contract>_chunk_dedup.json ← Per-chunk dedup (nếu --dedup trong e2e)
```

### Tài liệu Liên Quan

| File | Mô tả |
|------|-------|
| `docs/simulate-e2e-pipeline.md` | File này — tổng quan toàn bộ pipeline |
| `docs/eval-manual-matching-guide.md` | Hướng dẫn manual eval + sửa false negative do regex miss |
| `docs/eval-llmsmartaudit-ta-matching-guide.md` | Guide eval LLMSmartAudit TA output (41 detectors) |

### Không thuộc Pipeline Hiện Tại

Các file sau tồn tại trong repo nhưng **không được dùng** trong 3 giai đoạn trên:

| File | Trạng thái | Ghi chú |
|------|-----------|---------|
| `backend/scripts/run_contract_audit.py` | Deprecated | Pipeline cũ (full 5-step Flask-based). Theo CLAUDE.md: dùng `simulate_e2e.py` thay thế |
| `backend/scripts/evaluate_web3bugs.py` | Cũ | Eval theo track L/S/SWC ID — không dùng cho H-bug benchmark |
| `backend/scripts/evaluate_phase5a.py` | Cũ | Eval Phase 5a (cũ) |
| `backend/scripts/evaluate_phase5b.py` | Cũ | Eval Phase 5b (cũ) |
| `backend/scripts/baselines/run_gptscan_benchmark.py` | Baseline | Chạy GPTScan (baseline tool, không phải pipeline chính) |
| `backend/scripts/baselines/run_llmsmartaudit_benchmark.py` | Baseline | Chạy LLMSmartAudit TA/BA (baseline tool) |
| `backend/scripts/baselines/run_slither_benchmark.py` | Baseline | Chạy Slither (baseline tool) |
| `backend/scripts/action_logger.py` | Utility | Log agent actions (không dùng trong e2e) |
| `backend/scripts/simulate_h17_inv_test.py` | Test | One-off test script cho H-17 invariant |
| `backend/app/services/contract_audit_agent.py` | Unused | ReACT report agent — thuộc pipeline cũ, không gọi từ `simulate_e2e.py` |
| `backend/app/services/contract_dep_graph.py` | Unused | Slither-based dependency graph — không gọi từ pipeline hiện tại |
| `backend/app/services/contract_intent_extractor.py` | Unused | Intent extractor — không gọi từ pipeline hiện tại |
| `backend/app/services/contract_invariant_extractor.py` | Unused | Invariant extractor riêng — không gọi từ pipeline hiện tại |
| `backend/app/services/cyber_expert_profile_generator.py` | Khác pipeline | Dùng cho Cyber/Security direction (không phải Contract Audit) |
| `backend/app/services/cyber_oasis_env.py` | Khác pipeline | Dùng cho Cyber/Security direction (không phải Contract Audit) |

---

## FINDING Format (trong LLM response)

```
FINDING: <title>
CONTRACT: <contract_name>
FUNCTION: <function_name>
SEVERITY: high | medium | low
DESCRIPTION: <what's wrong and why it's exploitable>
CODE_ANCHOR: <exact line from source — no paraphrasing>
ATTACK_PATH: <attacker call sequence>
```

**FUNCTION attribution rule**: nếu bug nằm trong private/internal helper được gọi từ target function → dùng tên helper, không dùng tên caller.

---

## CLI Reference

```bash
python scripts/simulate_e2e.py \
  --contest-id   <id>          # Contest ID, dùng cho output dir và file names
  --contest-dir  <path>        # Full contest dir cho KG build (khác contracts-dir OK)
  --contracts-dir <path>       # Root dir chứa Solidity files cần scan
  --gt-contracts A B C ...     # GT contract names (không .sol)
  [--kg-result <path>]         # Skip KG build, dùng file có sẵn
  [--cache-path <path>]        # Override hist_inv_cache.json path
  [--workers N]                # Parallel agent workers (default: 1)
  [--dedup]                    # Enable per-chunk dedup sau khi agents xong
  [--rt]                       # Enable attacker agents (default: off)
  [--no-inv]                   # Disable HIST-INV injection
  [--max-fns-per-chunk N]      # Split chunks lớn thành sub-chunks
  [--no-full-aux]              # Chỉ inject called fns của aux (default: full aux)
  [--single-agent <id>]        # Ablation: chạy đúng 1 agent cho mọi chunk
  [--out-dir <path>]           # Override output directory
```

---

## Output Directory Structure

```
benchmark/web3bugs/agent-redesign/<contest_id>/
  hist_inv_cache.json                     ← (bench dir — reused across runs)
  kg_result_auto.json                     ← (bench dir — reused across runs)
  <run_label>/
    audit_report_<id>_raw.json            ← Giai đoạn 2 output
    audit_report_dedup.json               ← Giai đoạn 3.1 output
    eval_result_raw.txt                   ← Giai đoạn 3.2 (raw)
    eval_result_dedup.txt                 ← Giai đoạn 3.2 (dedup)
    chunk_timings.jsonl                   ← elapsed time per chunk
    <domain>_<contract>_<agent>.txt       ← raw T1/T2/T3 response per agent
    <domain>_<contract>_chunk_raw.json    ← merged findings per chunk
    <domain>_<contract>_chunk_dedup.json  ← per-chunk dedup (nếu --dedup trong e2e)
```
