# Phase 4 — Full Map-Reduce Audit

## 1. Vấn đề hiện tại

### 1.1 Attention Dilution (Phase 3 — Light)

Phase 3 đưa nhiều primaries vào **1 session duy nhất**. 19 agents đọc toàn bộ flattened source (~150–200KB) gồm tất cả clusters. Kết quả thực tế với contest 42:

```
Session 1 (Phase 3 — 200KB):
  MochiVault (375 LOC)          ← agents tập trung ở đây
  DutchAuctionLiquidator        ← agents đọc kỹ
  FeePoolV0 (102 LOC)           ← agents "thấy" nhưng không đào sâu
  MochiTreasuryV0               ← tương tự
  VestedRewardPool (73 LOC)     ← agents bỏ qua gần như hoàn toàn

Kết quả: TP=3, Recall=23%
Miss: H-02, H-03, H-06, H-09, H-11, H-12, H-13 (7/13 bugs)
→ Tất cả 7 bugs này nằm ở FeePoolV0, ReferralFeePoolV0, Treasury, VestedRewardPool
```

**Root cause**: LLM có hiện tượng "Lost in the Middle" — thông tin ở giữa context dài bị underweight. MochiVault lớn hơn, đứng đầu file → agents focus vào đó. FeePoolV0 nhỏ hơn, đứng giữa → bị bỏ qua dù đã trong scope.

### 1.2 Không phải vấn đề của R2/R3

R2/R3 là **FP filter** (voting + attacker gate), không generate findings mới. Tăng R1 rounds hay tune R2/R3 không giải quyết được miss ở FeePoolV0. Vấn đề nằm ở **R1 agents không được đọc FeePoolV0 với đủ attention**.

### 1.3 Cross-cluster bug risk

Một số H bugs là **cross-cluster**: exploit path đi qua nhiều contracts ở nhiều clusters. Ví dụ H-02 (FeePoolV0 flush treasury) có trigger từ MochiVault.mintFeeToPool(). Phase 3 lý thuyết có thể tìm loại này vì tất cả trong 1 session — nhưng thực tế vẫn miss do attention dilution.

---

## 2. Kiến trúc Phase 4 — Full Map-Reduce

```
Contest dir
     │
     ▼
[Phase 1+2: Connected Components + Scoring]
     │
     ▼
primary_keys = [MochiVault, FeePoolV0, MochiTreasuryV0, VestedRewardPool]
     │
     ├─────────────────────────────────────────────────────────────────┐
     │                                                                 │
     ▼                                                                 ▼
[MAP — chạy song song N sessions]                              [chạy độc lập]
     │
     ├─ Session 1: flatten(cluster=MochiVault)    → R1→dedup → findings_1.json
     ├─ Session 2: flatten(cluster=FeePoolV0)     → R1→dedup → findings_2.json
     ├─ Session 3: flatten(cluster=MochiTreasury) → R1→dedup → findings_3.json
     └─ Session 4: flatten(cluster=VestedReward)  → R1→dedup → findings_4.json
                                │
                                ▼
                    [REDUCE — Cross-Cluster Merge]
                    1. Static dedup (exact anchor match across sessions)
                    2. LLM dedup (semantic match across sessions)
                    3. Cross-cluster chain detection
                       (finding A ở session 1 + finding B ở session 2
                        → có chung root cause? → merge thành 1 cross-cluster bug)
                                │
                                ▼
                    [Report Generation]
                    merged_findings.json → audit_report.md
```

**Mỗi session** dùng nguyên kiến trúc hiện tại (19 agents, R1→dedup), chỉ khác ở input:
- Source code nhỏ hơn (~40–80KB thay vì 200KB)
- Prompt chỉ đề cập 1 primary
- Agents không bị distract bởi contracts của cluster khác

---

## 3. Files cần sửa / tạo mới

| File | Thay đổi |
|---|---|
| `backend/scripts/flatten_contest.py` | Thêm param `target_cluster_key` để flatten 1 cluster |
| `backend/scripts/run_contract_audit.py` | Thêm `--multi-primary` flag, orchestrator loop, merge step |
| `backend/scripts/merge_cluster_findings.py` | **Mới** — Cross-cluster dedup + chain detection |

---

## 4. Chi tiết triển khai

### 4.1 flatten_contest.py — Single-cluster flatten

Thêm optional param `target_cluster_key` vào `flatten_contest_dir()`:

```python
def flatten_contest_dir(
    contest_dir: str,
    ...,
    target_cluster_key: Optional[str] = None,   # NEW: chỉ flatten 1 cluster
) -> Tuple[str, dict]:
```

Khi `target_cluster_key` được set:
- Tier 1 (full source): chỉ `target_cluster_key` + các contracts trong `manifest["clusters"][target_cluster_key]`
- Tier 2 (skeleton): contracts được import bởi Tier 1 nhưng không thuộc cluster này (cross-cluster deps)
- Tier 3: bỏ qua

Header của flattened source:
```solidity
// ═══ Web3Bugs Contest 42 — Cluster 2/4: FeePoolV0 ═══
// AUDIT SCOPE: FeePoolV0, ReferralFeePoolV0
// Cross-cluster deps (skeleton only): MochiEngine, USDM
// NOTE: Audit FeePoolV0 independently. Flag any finding that requires
//       state from MochiVault for cross-cluster review.
```

### 4.2 run_contract_audit.py — Orchestrator loop

Thêm CLI flag:
```bash
python scripts/run_contract_audit.py \
  --contest-dir /path/to/42 \
  --output ./results/contest_42_phase4 \
  --multi-primary           # kích hoạt Phase 4
  --timeout 14400
```

Flow khi `--multi-primary`:

```python
def run_multi_primary_audit(contest_dir, output_dir, ...):
    # 1. Flatten toàn bộ để lấy manifest + primary_keys
    _, manifest = flatten_contest_dir(contest_dir, emit_manifest=True)
    primary_keys = manifest.get("primary_keys", [])

    # 2. STEP 0: Slither callers cho tất cả primaries (giống Phase 3)
    all_callers = run_multi_slither(manifest, contest_dir)

    # 3. MAP — chạy N sessions (sequential hoặc parallel)
    cluster_results = {}
    for i, pk in enumerate(primary_keys):
        cluster_name = manifest["primary_names"][i]
        try:
            logger.info(f"\n[CLUSTER {i+1}/{len(primary_keys)}] Auditing {cluster_name}...")
            result = run_single_cluster_session(
                contest_dir=contest_dir,
                target_cluster_key=pk,
                manifest=manifest,
                output_dir=output_dir / f"cluster_{cluster_name}",
                ...
            )
            cluster_results[cluster_name] = result
            # Fail-safe: lưu partial ngay sau khi mỗi cluster xong
            _save_partial_results(output_dir, cluster_results)
        except Exception as e:
            logger.error(f"[Cluster {i+1}] {cluster_name} FAILED: {e}")
            cluster_results[cluster_name] = {"error": str(e), "findings": []}
            continue   # KHÔNG raise — tiếp tục cluster tiếp theo

    # 4. REDUCE — merge findings từ tất cả sessions
    merged = merge_cluster_findings(cluster_results, manifest)

    # 5. Report generation từ merged findings
    generate_report(merged, output_dir)
```

### 4.3 run_single_cluster_session()

Hàm này đóng gói toàn bộ STEP 1→3 của pipeline hiện tại, nhưng với source của 1 cluster:

```python
def run_single_cluster_session(
    contest_dir: str,
    target_cluster_key: str,
    manifest: dict,
    output_dir: Path,
    ...
) -> dict:
    # Flatten chỉ cluster này
    source_code, cluster_manifest = flatten_contest_dir(
        contest_dir,
        emit_manifest=True,
        target_cluster_key=target_cluster_key,
        extra_scope_contracts=all_callers,
    )

    # STEP 1.1: NatSpec intent (chỉ cho cluster này)
    # STEP 1.3: Slither dep graph (chỉ cho primary của cluster này)
    # STEP 2: Profiles (dùng lại profiles từ main session nếu đã generate)
    # STEP 3: R1 → STOP_AFTER_DEDUP → trả về dedup findings
    ...
    return {"findings": dedup_findings, "cluster": cluster_name}
```

### 4.4 merge_cluster_findings.py — Cross-cluster merge

```python
def merge_cluster_findings(
    cluster_results: Dict[str, dict],
    manifest: dict,
) -> List[dict]:

    all_findings = []
    for cluster_name, result in cluster_results.items():
        for f in result.get("findings", []):
            f["source_cluster"] = cluster_name   # tag nguồn gốc
            all_findings.append(f)

    # Bước 1: Static dedup — exact anchor match
    deduped = static_dedup(all_findings)

    # Bước 2: LLM dedup — semantic match (dùng cơ chế hiện tại)
    deduped = llm_dedup(deduped)

    # Bước 3: Cross-cluster chain detection
    # Tìm pairs (finding_A từ cluster X, finding_B từ cluster Y) có thể
    # kết hợp thành 1 exploit chain
    chains = detect_cross_cluster_chains(deduped)
    for chain in chains:
        # Merge thành 1 finding mới, giữ lại cả 2 findings gốc như evidence
        merged_finding = {
            **chain["primary_finding"],
            "cross_cluster": True,
            "clusters_involved": chain["clusters"],
            "chain_description": chain["description"],
            "evidence": chain["findings"],
        }
        deduped.append(merged_finding)

    return deduped
```

**`detect_cross_cluster_chains()`** dùng Gemini Flash (model nhẹ, không cần reasoning sâu):

```
Prompt: "Given these findings from different contract clusters, identify pairs where
finding A (cluster X) enables or amplifies finding B (cluster Y). Look for:
- Price oracle manipulation leading to vault exploit
- Fee accounting error in one cluster draining another
- Access control gap in cluster A used as attack vector into cluster B
Return JSON pairs with exploit_chain_description."
```

---

## 5. Trade-offs

| Khía cạnh | Phase 3 (Light) | Phase 4 (Map-Reduce) |
|---|---|---|
| **LLM Cost** | 1× | N× (với contest 42: ~4×) |
| **Wall time** | ~20 phút | ~20 phút (parallel) / ~80 phút (sequential) |
| **Attention** | Diluted — 19 agents đọc 200KB | Focused — 19 agents đọc 40–80KB/session |
| **Cross-cluster bugs** | Có thể tìm (1 session) nhưng thực tế miss do dilution | Cần merge step riêng, risk miss nếu chain phức tạp |
| **Recall dự kiến** | ~20–30% | ~50–70% |
| **Implementation complexity** | Đã xong | Cao — orchestrator loop + single-cluster flatten + merge |
| **Failure mode** | 1 API crash = mất toàn bộ | 1 cluster crash = mất 1/N, partial results vẫn lưu |
| **Dedup complexity** | 1 dedup pass | 2 passes (per-cluster + cross-cluster) |

### Khi nào dùng Phase 3 vs Phase 4

```
Protocol size < 150KB và ≤ 2 clusters  →  Phase 3 đủ
Protocol size > 150KB hoặc ≥ 3 clusters →  Phase 4
Recall requirement > 50%               →  Phase 4 bắt buộc
Budget hạn chế                         →  Phase 3 (chấp nhận Recall thấp hơn)
```

---

## 6. Rủi ro & Giảm thiểu

| Rủi ro | Giảm thiểu |
|---|---|
| API timeout giữa chừng (Gemini 503) | `try/except` + `_save_partial_results()` sau mỗi cluster |
| Cross-cluster chain bị miss ở merge step | Giữ lại tất cả findings gốc của từng cluster trong output — auditor human review |
| Cost explosion với protocol lớn (10+ clusters) | Cap MAX_CLUSTERS=4 ở Phase 1+2; Phase 4 chỉ chạy top-4 clusters theo score |
| Dedup nhầm findings từ 2 clusters (cùng function name khác contract) | Static dedup phải dùng `(contract_name, function_name, anchor)` tuple, không chỉ anchor |
| Profile generation N lần (tốn token) | Generate profiles 1 lần từ contract_summary tổng hợp, tái sử dụng cho tất cả sessions |
| Session 2 không biết context của session 1 | Đúng — đây là by design (isolation). Cross-cluster context được inject qua Tier 2 skeleton deps trong flatten |

---

## 7. Thứ tự triển khai

```
Bước 1: flatten_contest.py — thêm target_cluster_key param
  └─ Smoke test: flatten contest 42 cluster FeePoolV0, verify chỉ có FeePoolV0 source + skeleton deps

Bước 2: run_contract_audit.py — extract run_single_cluster_session()
  └─ Refactor: tách STEP 1→3 thành hàm riêng, không thay đổi behavior hiện tại

Bước 3: run_contract_audit.py — thêm --multi-primary flag + orchestrator loop
  └─ Test: chạy contest 42 với --multi-primary, verify 4 sessions chạy tuần tự

Bước 4: merge_cluster_findings.py — static dedup + LLM dedup
  └─ Test: merge findings từ 4 sessions contest 42, verify không có duplicate

Bước 5: detect_cross_cluster_chains() — Gemini Flash call
  └─ Test: verify H-02 (FeePoolV0 + MochiVault chain) được detect

Bước 6: Full eval contest 42 với Phase 4
  └─ Target: Recall > 50%
```

---

## 8. Verification

```bash
# Bước 1: Smoke test single-cluster flatten
python3 - << 'EOF'
from scripts.flatten_contest import flatten_contest_dir, _compute_manifest, _build_dep_graph, _collect_sol_files, _topo_sort, _read_safe
d = "/home/thangdd/repos/web3bugs/contracts/42"
_, manifest = flatten_contest_dir(d, emit_manifest=True)
feepool_pk = next(k for k in manifest["primary_keys"] if "FeePool" in manifest["contract_names_map"].get(k, ""))
source, _ = flatten_contest_dir(d, emit_manifest=True, target_cluster_key=feepool_pk)
assert "FeePoolV0" in source
assert "MochiVault" not in source or "skeleton" in source.lower()   # MochiVault chỉ là skeleton dep
print(f"FeePoolV0 cluster size: {len(source)//1024}KB")
assert len(source) < 80_000, "Single cluster should be < 80KB"
print("PASS")
EOF

# Bước 6: Full Phase 4 audit contest 42
LOG=/tmp/web3bugs_42_phase4_$(date +%Y%m%d_%H%M%S).log
nohup bash -c "
  source /home/thangdd/repos/MiroFish/backend/.venv/bin/activate
  exec python scripts/run_contract_audit.py \
    --contest-dir /home/thangdd/repos/web3bugs/contracts/42 \
    --output ./results/web3bugs_trial/contest_42_phase4 \
    --multi-primary \
    --timeout 14400 --verbose
" >> "$LOG" 2>&1 &
echo "PID=$! LOG=$LOG"

# Eval
python3 scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_42.json \
  ./results/web3bugs_trial/contest_42_phase4/merged_findings.json --verbose
# Target: Recall > 50% (so với 23% Phase 3)
```
