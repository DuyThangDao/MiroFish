# Pipeline Workflow — `backend/main.py`

Mô tả luồng hoạt động từng bước khi chạy `python main.py`.

---

## Tổng quan

```
[1] Setup LLM pool
[2] Discover contracts
[3] Build / load KG (call graph)
[4] Load HIST-INV cache → INV_MAP
[5] Generate agent profiles
[6] Build aux map (dependencies)
[7] Build chunks (domain × contract)
[8] Prepare chunk states (annotate source)
[9] Run agents (parallel) → per-chunk raw findings
[10] Merge all chunks → audit_report_<id>_raw.json
```

---

## Bước 1 — Setup LLM pool

Đọc `.env`, khởi tạo pool LLM clients từ `LLM_VERTEX_AI_KEY_FILE` + `LLM2..5_*`. Pool dùng round-robin: mỗi agent task nhận 1 client theo thứ tự.

```
[setup] llm_pool = 5 client(s)
```

---

## Bước 2 — Discover contracts

`discover_contracts()` quét `--contracts-dir` để tìm tất cả `.sol` files. GT contracts bắt buộc phải có — nếu thiếu, tự động tìm trong `--contest-dir` (fallback).

```
[discover] GT contract outside contracts_dir: Ticks → .../Ticks.sol
Contracts discovered: 12
```

**Output:** `contracts: dict[name → (path, source)]`

---

## Bước 3 — Build / load KG

Call graph cần thiết để build `focus_directive` cho mỗi agent (biết function nào gọi function nào).

**Priority:**
1. `--kg-result <path>` — dùng file có sẵn
2. `benchmark/.../kg_result_auto.json` — auto-saved từ lần chạy trước
3. Build mới qua `ContractKGBuilder` (flatten → KG pipeline → save auto)

```
[kg] loaded from auto-saved: .../kg_result_auto.json
```
hoặc:
```
[kg] flattening full contest dir: ...
[kg] building KG ... 45% ...
[kg] done — context_summary 12,345 chars
[kg] saved → .../kg_result_auto.json
```

---

## Bước 4 — Load HIST-INV cache → INV_MAP

`HistInvCache` đọc `hist_inv_cache.json` (từ Giai đoạn 2 chuẩn bị). Build `INV_MAP: dict[fn_name → inv_text]` — ánh xạ từng function tới các invariants đã được synthesize sẵn.

```
[INV_MAP] 182 functions annotated (no custom slugs)
```

Nếu `--no-inv`: bỏ qua bước này, agents tự suy luận từ code.

---

## Bước 5 — Generate agent profiles

`ContractExpertProfileGenerator` đọc source của **primary contract** (GT contract lớn nhất, auto-detect) → tạo 19 agent profiles (Tier 1).

Mỗi profile gồm:
- `agent_id`, `domain_group`, `persona`
- `system_prompt` — worldview + guidelines (+ SWC context nếu `--swc`)
- `core_question` (CQ) — câu hỏi hướng dẫn T1 và T3

```
[profiles] auto-detected primary contract: ConcentratedLiquidityPool
```

---

## Bước 6 — Build aux map

`build_aux_map()` phân tích import statements trong các GT contracts để tìm dependency. Aux contracts được inject vào source của chunk để agent có đủ context.

```
Aux contracts (auto-detected):
  ConcentratedLiquidityPool → ['Ticks', 'DyDxMath', 'SwapLib']
```

---

## Bước 7 — Build chunks

`build_chunks()` nhóm functions thành các **chunk (domain × contract)**:

```
chunk = {
  domain:        "general",
  contract_name: "ConcentratedLiquidityPool",
  fn_names:      ["mint", "burn", "swap", ...],
  agents:        ["state_analyst", "program_logician", ...],  # 3-4 agents/chunk
  source:        "<flattened sol source + aux contracts>",
  aux_names:     ["Ticks", "DyDxMath"],
}
```

Mỗi domain có bộ agents riêng (từ `DOMAIN_AGENTS` map). Chỉ GT contracts mới được chunk — aux contracts chỉ xuất hiện như context.

```
Chunks to simulate (10 total — GT contracts only):
  [general] ConcentratedLiquidityPool: [mint, burn, swap, ...]
  [liquidity_mutation] ConcentratedLiquidityPool: [mint, burn, ...]
  ...
```

---

## Bước 8 — Prepare chunk states

Với mỗi chunk, `_prepare_chunk_state()`:
1. Inject **HIST-INV annotations** vào source: `_annotate_source_with_hist_inv(source, INV_MAP)` → thêm `// [HIST-INV] INV-1: ...` comments vào từng function
2. Prepend **call graph block** (`_get_call_graph_block`) — danh sách caller/callee relationships

**Output per chunk:** `ChunkState` với `ann_src` = source đã annotate đầy đủ.

---

## Bước 9 — Run agents (parallel)

`ThreadPoolExecutor(max_workers=WORKERS)` chạy song song tất cả `(chunk × agent)` tasks.

### Per-agent flow (defender):

```
T1 — Invariant Extraction (build_round1_prompt, invariant_only=True)
  → Agent đọc source + HIST-INV annotations + CQ
  → Output: danh sách INV-1, INV-2, ... (không viết FINDING)

T2 — Violation Scan (build_round1_prompt, injected_invariants=t1_clean)
  → Agent nhận invariants từ T1, scan code tìm violations
  → Output: FINDING blocks (nguồn findings chính)

T3 — CoT Independent Sweep (build_t3_prompt)
  → Agent scan độc lập, viết TRACE [fn]: OP → CHAIN → INVARIANT → VERDICT
  → Chỉ viết FINDING khi VERDICT=BUG
  → Cross-check, bắt những gì T2 bỏ sót
```

### Per-agent flow (red-team, `--rt` only):

```
RT1 — Attack Surface Inventory  → liệt kê entry points có thể exploit
RT2 — Exploit Construction      → xây exploit cụ thể từ RT1 surfaces
RT3 — Backward Trace            → scan ngược độc lập
```

### Per-chunk aggregation:

Khi tất cả agents của 1 chunk xong:
- Gộp T2 + T3 findings → `cs.findings`
- Lưu `<chunk_label>_chunk_raw.json`
- Nếu `--dedup`: chạy `dedup_pipeline()` → `<chunk_label>_chunk_dedup.json`

```
[general/ConcentratedLiquidityPool] → 55 raw findings | 189s → ...chunk_raw.json
```

---

## Bước 10 — Merge & save report

Sau khi tất cả chunks xong:
- Gộp findings từ tất cả `ChunkState` → `all_raw`
- Lưu `audit_report_<id>_raw.json`

```
audit_report_<id>_raw.json
├── contest_id
├── config
├── total_findings
├── wall_time_s
└── findings: [...]       ← tất cả T2+T3 findings từ mọi chunk
```

In summary + eval commands:
```
DONE — raw=539  |  497s  |  workers=5
```

---

## Checkpoints & Resume

KG được auto-save tại `kg_result_auto.json` → reuse tự động lần sau.

Per-agent resume: nếu `<chunk_label>/<agent_id>.txt` đã tồn tại trong `OUT_DIR`, agent được skip và findings được load lại từ file.

---

## Output files

```
benchmark/web3bugs/agent-redesign/<id>/<run_label>/
├── audit_report_<id>_raw.json          ← tất cả raw findings (input cho eval)
├── audit_report_<id>_dedup.json        ← sau dedup_report.py (optional)
├── kg_result_auto.json                 ← KG cache (auto-saved, reused)
├── hist_inv_cache.json                 ← HIST-INV cache (từ giai đoạn 2)
├── general_CLP_chunk_raw.json          ← per-chunk raw
├── general_CLP_chunk_dedup.json        ← per-chunk dedup (nếu --dedup)
└── general_CLP/<agent_id>.txt          ← per-agent raw response (resume cache)
```
