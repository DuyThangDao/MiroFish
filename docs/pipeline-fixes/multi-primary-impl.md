# Multi-Primary Protocol Audit — Kế hoạch Triển khai Chi tiết

> **Status**: Phase 1 + 2 + 3 (light) đã implement. Phase 4 (Full Map-Reduce) defer.
> **Implementation note**: Một số điểm trong spec được điều chỉnh trong quá trình triển khai — xem mục 10.

## 1. Bối cảnh & Vấn đề

### Vấn đề hiện tại
Pipeline hiện tại chọn **1 primary contract** duy nhất (contract có score cao nhất) rồi dùng Slither caller graph để mở rộng scope. Cách này hiệu quả với protocol đơn cluster (contest 35 — ConcentratedLiquidityPool là trung tâm), nhưng thất bại với **multi-primary protocol** (contest 42 — Mochi).

**Ví dụ contest 42:**
- Pipeline chọn `MochiVault` → scope: MochiVault + DutchAuctionLiquidator + MinterV0 + MochiProfileV0
- 11/13 H bugs nằm ở `FeePoolV0`, `MochiEngine`, `ReferralFeePoolV0`, `MochiTreasuryV0`, `VestedRewardPool` — **hoàn toàn ngoài scope**
- Recall = 15%, TP = 2

### Kiến trúc protocol Mochi — thực tế trong import graph
Spec ban đầu dự đoán 3 clusters độc lập. Thực tế: tất cả contracts connect qua shared interfaces (IFeePool, IReferralFeePool, IMochiVault...) → **1 cluster lớn**. Giải pháp: top-N global scoring thay vì 1/cluster (xem mục 10.2).

### Mục tiêu sau khi implement
- Tự động chọn top-4 contracts quan trọng nhất từ protocol
- STEP 0 chạy Slither cho tất cả 4 primaries → scope cover FeePoolV0, Treasury, Engine
- Dự kiến Recall contest 42: từ 15% lên 50–70%

---

## 2. Tổng quan 3 Phase

```
Phase 1 — Connected Components     Phase 2 — Value-bearing Heuristics     Phase 3 — Multi-Primary Session
─────────────────────────────────   ───────────────────────────────────     ──────────────────────────────
flatten_contest.py:                 flatten_contest.py:                     run_contract_audit.py:
  _compute_manifest()                 scoring trong _compute_manifest()       Loop qua primary_keys
  → trả primary_keys: List[str]       → FeePool-style được boost              Merge findings cuối
```

Phase 1 và 2 là **nền móng** — Phase 3 không làm được nếu chưa có list primaries.

---

## 3. Phase 1 — Connected Components trong `_compute_manifest()`

### Mục tiêu
Thay vì trả `{"primary": "MochiVault"}`, trả `{"primary_keys": ["path/MochiVault.sol", "path/FeePoolV0.sol", "path/VestedRewardPool.sol"]}`.

### File cần sửa
`backend/scripts/flatten_contest.py` — hàm `_compute_manifest()`.

### Thuật toán

**Bước 1: Build undirected graph từ directed import graph**
```python
# _build_dep_graph() trả về directed graph: A → B nghĩa là A import B
# Chuyển thành undirected: thêm edge B → A
undirected = defaultdict(set)
for node, deps in directed_graph.items():
    for dep in deps:
        undirected[node].add(dep)
        undirected[dep].add(node)
```

**Bước 2: Lọc trước khi cluster**

Chỉ cluster các "real implementation contracts" — loại:
- Interfaces (`is_interface_only()` trả True)
- Libraries (`is_library = True` từ fix trước)
- Contracts nằm trong `node_modules/` (external dependencies)
- Mocks/Tests (tên chứa `Mock`, `Test`, `Stub`, `Fake`)
- **Proxy wrapper contracts** — tên contract (từ `_CONTRACT_RE`) khớp:
  ```python
  _PROXY_NAME_RE = re.compile(
      r'\b(Transparent|Beacon|UUPS|ERC1967|Minimal|Clones)'
      r'.*Proxy\b'
      r'|\bProxy\b'                    # generic Proxy
      r'|\bUpgradeableProxy\b'
      r'|\bProxyAdmin\b',
      re.IGNORECASE
  )
  ```
  Lưu ý: dùng **contract name** (từ `_CONTRACT_RE.search()`), không dùng filename, vì tên file có thể khác (e.g., `deploy/Vault.sol` chứa `contract TransparentUpgradeableProxy`).

Lý do: OZ SafeMath, IERC20, IUniswap được import ở khắp nơi → nếu không lọc, tất cả clusters sẽ bị merge thành 1 cục qua các shared dependencies. Proxy contracts bị loại vì: (1) chứa `delegatecall` → value-bearing regex boost sai, (2) logic business nằm ở implementation contract, (3) audit proxy OZ chuẩn không tìm được bug thực.

**Bước 3: BFS Connected Components**
```python
def _find_clusters(keys: List[str], graph: Dict) -> List[List[str]]:
    visited = set()
    clusters = []
    for start in keys:
        if start in visited:
            continue
        cluster = []
        queue = deque([start])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            cluster.append(node)
            for neighbor in graph.get(node, []):
                if neighbor in keys and neighbor not in visited:
                    queue.append(neighbor)
        clusters.append(cluster)
    return clusters
```

**Bước 4: Chọn primary của mỗi cluster**

Dùng scoring hiện tại (LOC × pattern multiplier + in-degree × 100) **trong phạm vi cluster**. Contract có score cao nhất trong cluster = primary của cluster đó.

**Bước 5: Filter clusters nhỏ**

Bỏ qua clusters có tổng LOC < 100 (thường là isolated utility contracts không đáng audit riêng). Threshold có thể tune.

### Output mới của `_compute_manifest()`
```python
{
    "primary": "MochiVault",           # primary[0] — backward compat
    "primary_key": "path/MochiVault.sol",
    "primary_keys": [                  # NEW — list tất cả cluster primaries
        "path/MochiVault.sol",
        "path/FeePoolV0.sol",
        "path/VestedRewardPool.sol"
    ],
    "primary_names": ["MochiVault", "FeePoolV0", "VestedRewardPool"],
    "clusters": {                      # NEW — debug info
        "path/MochiVault.sol": ["path/MochiVault.sol", "path/DutchAuctionLiquidator.sol", ...],
        "path/FeePoolV0.sol": ["path/FeePoolV0.sol", "path/ReferralFeePoolV0.sol", ...],
    },
    "secondary": [...],                # giữ nguyên — secondary của primary[0]
    ...
}
```

### Lưu ý triển khai
- Backward compatibility: giữ `"primary"` và `"primary_key"` (string, = primary_keys[0]) để không break các caller cũ
- Max clusters: giới hạn `primary_keys` tối đa 4–5 clusters để tránh cost explosion ở Phase 3. Nếu > 5 clusters → merge các cluster nhỏ vào cluster lớn nhất gần nhất
- Import graph vs call graph: clustering dùng import graph (không cần Slither). Không chính xác bằng call graph nhưng đủ tốt và nhanh. Slither caller analysis (STEP 0) vẫn chạy riêng cho từng primary ở Phase 3

---

## 4. Phase 2 — Value-bearing Heuristics

### Vấn đề
`FeePoolV0`, `ReferralFeePoolV0` không có tên khớp `_CORE_NAME_RE` ("Pool" có thể match, nhưng "FeePool" là distribute-pool, không phải LP pool). Scoring thuần LOC có thể không đủ để boost chúng lên làm primary của cluster.

### Heuristic bổ sung: value-bearing check

Một contract được coi là "value-bearing" nếu source code chứa ít nhất 1 trong các pattern:

```python
_VALUE_BEARING_RE = re.compile(
    r'\b(transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\('
    r'|IERC20\s*[(\(]'
    r'|msg\.value\b'
    r'|address\(this\)\.balance'
    r'|\.call\s*\{'          # low-level ETH send: .call{value: x}("") — phổ biến hơn transfer() sau EIP-1884
    r'|\bdelegatecall\b'     # proxy/upgradeable logic — cực kỳ nguy hiểm nếu không dùng đúng cách
)

# Trong scoring loop:
if _VALUE_BEARING_RE.search(stripped):
    score *= 1.3   # boost nhẹ, không lấn át LOC
```

> **Lý do thêm `.call{` và `delegatecall`**: Sau EIP-1884 (Istanbul), `transfer()` bị giới hạn 2300 gas không còn đủ cho nhiều use case, dev chuyển sang `.call{value: x}("")`. Đây là vector reentrancy phổ biến nhất hiện nay. `delegatecall` xuất hiện trong proxy/upgradeable contracts — nơi có rủi ro storage collision và uninitialized implementation.

> **Cảnh báo**: Thêm `delegatecall` vào regex BẮT BUỘC phải đi kèm với **Anti-Proxy filter** (xem mục 4.3 bên dưới). Không thì `TransparentUpgradeableProxy.sol` sẽ được boost score và trở thành primary — đây là contract OZ chuẩn, không có logic business, audit sẽ không tìm được gì.

### Heuristic bổ sung: external function density

Contract có nhiều `external`/`public` functions = entry point cho user → khả năng cao là primary của cluster:
```python
ext_count = len(re.findall(r'\b(external|public)\b(?!\s+view\b)(?!\s+pure\b)', stripped))
if ext_count >= 5:
    score *= 1.1
```

### Lưu ý triển khai
- Hai heuristic này chỉ áp dụng cho contracts **không phải interface, không phải library**
- `_VALUE_BEARING_RE` tìm trên comment-stripped source để tránh false positive từ comments
- Multiplier nhỏ (1.1–1.3) — không được lấn át LOC vì LOC vẫn là signal chính xác nhất

---

## 5. Phase 3 — Multi-Primary Session (Light Version)

### Mục tiêu
Mở rộng scope của **1 audit session** để cover tất cả cluster primaries, thay vì chỉ primary[0].

### Cách hoạt động

**STEP 0 (Slither callers)** — chạy cho từng primary trong `primary_keys`:
```python
all_callers = set()
for pk in manifest["primary_keys"]:
    callers = run_slither_caller_analysis(pk, contest_dir)
    all_callers.update(callers)
# Re-flatten với toàn bộ callers của tất cả primaries
```

**STEP 1 (Flatten)** — scope = union của tất cả clusters:
- Tier 1 (full source): tất cả cluster primaries + callers của chúng từ Slither
- Tier 2 (skeleton): contracts kết nối với bất kỳ Tier 1 nào
- Tier 3: còn lại

**Size budget — Greedy Fit + Hard Signal:**

```python
# Tính Tier 1 size của từng cluster (primary full source + Slither callers)
cluster_sizes = {pk: compute_tier1_size(pk) for pk in primary_keys}

# Greedy fit: sort giảm dần theo size, include cho đến khi vượt 200KB
sorted_clusters = sorted(primary_keys, key=lambda k: cluster_sizes[k], reverse=True)
included, pending, budget_used = [], [], 0
for pk in sorted_clusters:
    if budget_used + cluster_sizes[pk] <= MAX_CHARS:
        included.append(pk)
        budget_used += cluster_sizes[pk]
    else:
        pending.append(pk)

if pending:
    logger.warning(
        f"[Phase 3] Budget exceeded — {len(pending)} cluster(s) DROPPED: "
        f"{[manifest['primary_names'][primary_keys.index(pk)] for pk in pending]}. "
        f"Consider switching to Phase 4 (--multi-primary) for full coverage."
    )
    # Lưu vào manifest để orchestrator biết còn clusters chưa được audit
    manifest["pending_clusters"] = pending
```

> **Tại sao không skeleton-ize cluster primary khi vượt budget**: Skeleton primary = LLM thấy function signatures nhưng không thấy logic → không tìm được access control gap, arithmetic error, state machine bug → toàn bộ token bị lãng phí và LLM có ảo giác "đã đọc" cluster đó. **Drop hẳn + warning** trung thực hơn và tiết kiệm token hơn.

> **Tại sao greedy fit thay vì "drop cluster nhỏ nhất"**: Cluster nhỏ nhất (về LOC) chưa chắc kém quan trọng — `VestedRewardPool` ít dòng nhưng chứa H-13. Greedy fit tối đa hóa coverage trong ngân sách mà không phán xét tầm quan trọng.

**STEP 1.3 (Dep graph)** — chạy Slither dep graph cho `primary_names` (list):
```python
# Hiện tại: target = manifest["primary"] (1 contract)
# Sau fix: target = manifest["primary_names"] (list) → Slither chạy cho từng contract
# Merge critical_vars từ tất cả dep graphs
```

**STEP 1 (Flatten — Table of Contents header)** — khi `len(primary_keys) > 1`, generate ToC ngay đầu flattened source trong `flatten_contest_dir()`:

```solidity
// ═══ Web3Bugs Contest 42 — Flattened Source ═══
// ⚠️ THIS PROTOCOL HAS 3 INDEPENDENT CLUSTERS. Analyze each cluster separately.
// Only report cross-cluster bugs if state is shared via direct external calls.
//
// CLUSTER 1 — MochiVault (primary)
//   Full source: MochiVault, DutchAuctionLiquidator, MinterV0, MochiProfileV0
//   Skeleton deps: Rlp, MerklePatriciaVerifier
//   Critical vars: totalDebt, collateral, liquidationFee
//
// CLUSTER 2 — FeePoolV0 (primary)
//   Full source: FeePoolV0, ReferralFeePoolV0
//   Skeleton deps: MochiEngine
//
// CLUSTER 3 — VestedRewardPool (primary)
//   Full source: VestedRewardPool
// ═══════════════════════════════════════════════
```

> **Lý do**: "Lost in the Middle" là hiện tượng được ghi nhận — LLM bỏ sót thông tin nằm ở giữa context window dài. ToC ở đầu file đóng vai trò "system prompt thu nhỏ", neo giữ attention của model vào cấu trúc trước khi đọc hàng ngàn dòng code. Critical vars (từ Slither dep graph) trong ToC giúp model biết ngay đâu là state quan trọng nhất.

**STEP 3 (Audit session)** — agents nhận source code rộng hơn, có thể tìm bugs ở tất cả clusters trong 1 session.

**Audit prompt** — cần cập nhật để agents biết có nhiều primary:
```
CONTRACT UNDER AUDIT: MochiVault (primary cluster 1), FeePoolV0 (primary cluster 2)
These are independent clusters — analyze each separately but flag cross-cluster interactions.
```

### Trade-off Light vs Full Map-Reduce

| | Light (Phase 3) | Full Map-Reduce |
|--|---|---|
| Sessions | 1 | N |
| LLM cost | 1× | N× |
| Attention | Diluted (context chia cho N clusters) | Tập trung (mỗi session 1 cluster) |
| Context size | Có thể > 200KB với nhiều clusters | Kiểm soát được (~100–150KB/session) |
| Complexity | Trung bình | Cao (cần orchestrator loop + cross-dedup) |
| Nên dùng khi | ≤ 3 clusters nhỏ | ≥ 3 clusters lớn hoặc cần Recall tối đa |

### Lưu ý triển khai
- `network_summary` (đầu vào của audit session) cần tổng hợp intent/invariants của tất cả primaries
- Profiles (22 experts) được generate 1 lần dựa trên `contract_summary` tổng hợp — không cần N bộ profiles
- Dedup sau R1 vẫn dùng cơ chế hiện tại — findings từ nhiều clusters sẽ có anchor khác nhau nên static dedup không nhầm

---

## 6. Phase 4 (Dài hạn) — Full Map-Reduce

### Khi nào cần
- Protocol > 5 clusters, mỗi cluster > 100KB
- Recall requirement cao (> 80%)
- Budget cho phép N× LLM cost

### Kiến trúc

```
Contest dir
    │
    ▼
[Connected Components] → [primary_keys: N clusters]
    │
    ├─ Session 1: flatten(primary=cluster1) → STOP_AFTER_DEDUP → dedup1.json
    ├─ Session 2: flatten(primary=cluster2) → STOP_AFTER_DEDUP → dedup2.json
    └─ Session N: flatten(primary=clusterN) → STOP_AFTER_DEDUP → dedupN.json
                                                      │
                                              [Cross-Cluster Merge]
                                              dedup1 + dedup2 + ... + dedupN
                                                      │
                                              [Global Dedup Agent]
                                              - Remove duplicates across sessions
                                              - Flag cross-cluster exploit chains
                                                      │
                                              [Report Generation]
```

### Cross-Cluster Dedup
Findings từ N sessions có thể trùng lặp nếu 2 clusters import cùng 1 contract. Cần:
1. Static dedup: exact anchor match across sessions
2. LLM dedup: dùng cơ chế hiện tại, nhưng input là findings từ tất cả sessions
3. Cross-cluster annotation: finding A (session 1) + finding B (session 2) cùng root cause → merge, note cả 2 contracts

### Lưu ý triển khai
- Sessions có thể chạy **song song** (async) — không phụ thuộc nhau
- STOP_AFTER_DEDUP=true cho tất cả sessions để tránh N× R2/R3 cost trước khi merge
- `run_contract_audit.py` cần thêm `--multi-primary` flag để kích hoạt chế độ này
- Cross-dedup agent nên dùng model nhẹ (gemini-flash) — không cần reasoning sâu, chỉ cần so sánh

### Fail-safe bắt buộc cho vòng lặp cluster

Vertex AI / Gemini API có thể timeout hoặc trả `503 Service Unavailable` / `blocked by safety filter` một cách ngẫu nhiên. Vòng lặp qua `primary_keys` **BẮT BUỘC** bọc trong try/except:

```python
cluster_results = {}
for i, pk in enumerate(manifest["primary_keys"]):
    cluster_name = manifest["primary_names"][i]
    try:
        result = run_single_cluster_audit(pk, contest_dir, ...)
        cluster_results[cluster_name] = result
        # Lưu partial results ngay sau khi mỗi cluster xong
        _save_partial_results(output_dir, cluster_results)
    except Exception as e:
        logger.error(f"[Cluster {i+1}/{n}] {cluster_name} FAILED: {e}")
        cluster_results[cluster_name] = {"error": str(e), "findings": []}
        # TIẾP TỤC cluster tiếp theo — không raise, không crash
        continue

# Sau vòng lặp: merge tất cả cluster_results (kể cả cluster bị lỗi → 0 findings)
merged = merge_cluster_findings(cluster_results)
```

> **Lý do `_save_partial_results()` sau mỗi cluster**: Nếu N=3 và cluster 3 crash sau 40 phút, kết quả của cluster 1+2 vẫn được lưu. Không có cơ chế này, toàn bộ run bị mất. Partial results lưu vào `output_dir/partial_cluster_{name}.json`.

---

## 7. Thứ tự triển khai & Dependencies

```
Phase 1: Connected Components trong _compute_manifest()
    └─ Required by: Phase 2, Phase 3, Phase 4
    └─ Files: backend/scripts/flatten_contest.py

Phase 2: Value-bearing heuristics trong _compute_manifest()
    └─ Required by: không có (độc lập)
    └─ Files: backend/scripts/flatten_contest.py

Phase 3: Multi-Primary Session trong run_contract_audit.py
    └─ Required by: Phase 4
    └─ Requires: Phase 1 done
    └─ Files: backend/scripts/run_contract_audit.py

Phase 4: Full Map-Reduce
    └─ Requires: Phase 1, Phase 3 done
    └─ Files: run_contract_audit.py + new merge_findings.py script
```

**Khuyến nghị**: Implement Phase 1 + 2 trước, chạy smoke test trên contest 42 để xác nhận đúng 3 clusters. Sau đó mới implement Phase 3.

---

## 8. Smoke Tests & Verification

### Test Phase 1 (Connected Components)
```python
# Contest 42: expect 3 clusters
manifest = _compute_manifest(order, sources, graph, contest_dir_42)
assert len(manifest["primary_keys"]) == 3
assert "MochiVault" in manifest["primary_names"]
assert any("FeePool" in n for n in manifest["primary_names"])

# Contest 35: expect 1 cluster (ConcentratedLiquidityPool là trung tâm)
manifest = _compute_manifest(order, sources, graph, contest_dir_35)
assert len(manifest["primary_keys"]) == 1
assert manifest["primary"] == "ConcentratedLiquidityPool"
```

### Test Phase 2 (Heuristics)
```python
# FeePoolV0 phải có score cao hơn MerklePatriciaVerifier trong cluster của nó
scores_42 = _debug_scores(contest_dir_42)
assert scores_42["FeePoolV0"] > scores_42["MerklePatriciaVerifier"]
```

### Test Phase 3 (Multi-Primary Session)
```bash
# Chạy contest 42 với Phase 3, STOP_AFTER_DEDUP=true
# Expect: dedup findings có anchor từ cả MochiVault functions VÀ FeePoolV0 functions
python3 scripts/run_contract_audit.py \
  --contest-dir /home/thangdd/repos/web3bugs/contracts/42 \
  --output ./results/web3bugs_trial/contest_42_multi \
  --timeout 7200 --verbose

# Eval: expect Recall > 50% (so với 15% hiện tại)
python3 scripts/evaluate/web3bugs_eval.py \
  scripts/evaluate/gt/gt_42.json \
  /tmp/dedup_42_multi_*.json --verbose
```

---

## 9. Rủi ro & Giảm thiểu

| Rủi ro | Khả năng | Giảm thiểu |
|--------|----------|------------|
| Tất cả contracts bị merge thành 1 cluster (do shared OZ imports) | Cao nếu không lọc interfaces/libs | Lọc interfaces + libraries + node_modules trước khi cluster |
| Quá nhiều clusters (> 5), tăng cost | Trung bình với protocol lớn | Cap tối đa 4 clusters; merge clusters nhỏ (LOC < 100) vào cluster lớn gần nhất |
| Context size > 200KB với Phase 3 (nhiều Tier 1) | Trung bình | Greedy fit: include clusters cho đến hết budget, DROP (không skeleton-ize) phần còn lại + log `pending_clusters` → hard signal chuyển Phase 4 |
| FP tăng vì scope rộng hơn (nhiều contracts = nhiều false alarms) | Cao | Giữ nguyên R2 voting + attacker gate; không bypass consensus |
| Contest 35 bị break (ConcentratedLiquidityPool không còn là sole primary) | Thấp | Test regression ngay sau Phase 1; add assert trong CI |
| Cross-session dedup bỏ sót duplicate | Trung bình | Static dedup (exact anchor) đủ cho phần lớn; LLM dedup cho edge cases |

---

## 10. Implementation Notes & Deviations

Phần này ghi lại những điểm spec ban đầu (mục 3–5) đã được **điều chỉnh trong quá trình triển khai** — lý do thực tế và tác động.

---

### 10.1 Clustering input: `all_local_keys` thay vì `impl_keys`

**Spec nói**: Chỉ cluster "real implementation contracts" — lọc bỏ interfaces, libraries, proxies trước khi BFS.

**Thực tế triển khai**: Dùng `all_local_keys` (bao gồm cả interfaces) cho bước BFS, sau đó lọc khi **chọn primary** trong mỗi cluster.

**Lý do**: Solidity protocol dùng shared interfaces (IFeePool, IReferralFeePool, IMochiVault...) làm "keo dán" giữa các subsystems. Nếu lọc interfaces ra khỏi BFS, tất cả contracts bị tách thành singletons — không có cluster nào. Interfaces không chứa business logic nhưng **là cạnh kết nối** trong undirected graph.

**Tác động**: BFS vẫn hoạt động đúng. Khác biệt duy nhất là graph có nhiều node hơn nhưng primary selection vẫn filter `_is_audit_candidate()` → kết quả primaries không đổi.

---

### 10.2 Primary selection: top-N global thay vì 1/cluster

**Spec nói**: Chọn 1 primary/cluster (contract score cao nhất trong cluster đó). Với 3 clusters → 3 primaries.

**Thực tế triển khai**: Chọn top-4 candidates toàn cục (MAX_PRIMARIES=4), không quan tâm cluster boundary.

```python
all_candidates = [k for cluster in sig_clusters
                  for k in cluster if _is_audit_candidate(k) and k in scores]
cluster_primary_keys = sorted(deduped, key=lambda k: scores[k], reverse=True)[:MAX_PRIMARIES]
```

**Lý do**: Contest 42 — tất cả Mochi contracts kết nối qua shared interfaces → **1 cluster lớn duy nhất**. Spec "1/cluster" chỉ cho ra MochiVault. Top-N global lấy được MochiVault, FeePoolV0, MochiEngine, VestedRewardPool cùng lúc.

**Tác động**: Với protocol thực sự nhiều clusters (ví dụ 2 independent sub-protocols trong 1 repo), top-N global vẫn chọn đúng vì score của primary mỗi cluster tự nhiên cao hơn secondary của cluster đó. Trường hợp suy biến: 2 clusters có size tương đương → chọn đúng top-2 trong 2 clusters.

---

### 10.3 Pattern additions trong `_CORE_NAME_RE` và `_INFRA_NAME_RE`

**Spec nói**: Không đề cập cụ thể — dùng patterns sẵn có.

**Thực tế triển khai**: Thêm các patterns domain-specific:

```python
# _CORE_NAME_RE — boost ×1.5
# Thêm: Reward | Treasury | Staking | Lending | Borrow

# _INFRA_NAME_RE — penalty ×0.6
# Thêm: Adapter | Oracle | CSSR | Snapshot | PriceFeed | Aggregator | Verifier
```

**Lý do**: UniswapV2CSSR (249 LOC) và SushiswapV2CSSR bị scoring cao hơn FeePoolV0 (102 LOC) do LOC lớn hơn. CSSR = Custom Spot/Storage Rate oracle adapter — không có business logic của protocol. Thêm `CSSR|Oracle|Aggregator` vào infra list để penalty xuống, nhường chỗ cho FeePoolV0.

**Tác động**: Contest-specific pattern matching — có thể miss nếu oracle contract dùng tên khác. Cần monitor trên các contests tiếp theo.

> **⚠️ Tech-Debt: Overfitting Risk + Hardcoded Heuristics**
>
> Các pattern hiện tại được thêm vào để fix Contest 42 (Mochi/Sushi). Rủi ro:
> - `Oracle|Aggregator|CSSR` trong blacklist → một contest khác có thể có `OracleAdapter` chứa **logic thao túng giá (price manipulation)** cốt lõi — contract đó sẽ bị penalty score và không được chọn làm primary.
> - Tương tự, `Reward|Treasury` trong whitelist boost có thể không đúng với mọi protocol.
>
> **Giải pháp dài hạn**: Tách regex + weights ra `heuristics_config.json`:
> ```json
> {
>   "core_patterns": [
>     {"pattern": "Pool|Vault|Engine|Market", "multiplier": 1.5},
>     {"pattern": "Reward|Treasury|Staking", "multiplier": 1.5}
>   ],
>   "infra_patterns": [
>     {"pattern": "Oracle|CSSR|Aggregator|Verifier", "multiplier": 0.6},
>     {"pattern": "Router|Helper|Deployer|Factory", "multiplier": 0.6}
>   ],
>   "value_bearing_multiplier": 1.3,
>   "proxy_multiplier": 0.05,
>   "library_multiplier": 0.3
> }
> ```
> Khi có dữ liệu từ 50–100 contests với ground truth, có thể chạy grid search / logistic regression để auto-tune multipliers thay vì điều chỉnh bằng tay. Hiện tại **giữ nguyên hardcode**, đây là tech-debt đã biết.

---

### 10.4 ToC header thiếu "Critical vars" field

**Spec nói** (mục 5, phần ToC):
```solidity
// CLUSTER 1 — MochiVault (primary)
//   Critical vars: totalDebt, collateral, liquidationFee    ← từ Slither dep graph
```

**Thực tế triển khai**: ToC header được generate trong `flatten_contest_dir()`, chạy TRƯỚC STEP 1.3 (Slither dep graph). Tại thời điểm generate ToC, chưa có `critical_vars`.

**Gap hiện tại**: ToC chỉ có cluster name và related contracts — không có critical vars.

```solidity
// TARGET 1 — MochiVault (primary)
//   Related contracts: DutchAuctionLiquidator, MinterV0, MochiProfileV0
```

**Giải pháp tương lai**: Patch ToC sau khi STEP 1.3 xong — đọc lại flattened source, prepend updated ToC, ghi đè file. Hoặc đưa critical vars vào system prompt của agents thay vì ToC.

---

### 10.5 Greedy fit nằm ở STEP 0 trong `run_contract_audit.py`, không phải trong `flatten_contest_dir()`

**Spec nói**: Greedy fit tính Tier 1 size của từng cluster, include cho đến hết budget, set `manifest["pending_clusters"]`.

**Thực tế triển khai**: Logic greedy fit **chưa được implement đầy đủ**. STEP 0 hiện tại:
1. Chạy Slither caller analysis cho tất cả primaries → merge `_all_callers`
2. Re-flatten 1 lần với toàn bộ callers
3. Log warning nếu `manifest["pending_clusters"]` tồn tại

Nhưng `flatten_contest_dir()` **không tự set `pending_clusters`** — field này sẽ chỉ được set nếu orchestrator bên ngoài tính budget và gọi lại flatten với danh sách primaries đã được cắt bớt.

**Tác động**: Budget overflow chưa được handle — nếu tổng Tier 1 của 4 primaries vượt 200KB, vẫn flatten đủ (Tier 2/3 tự động bị truncate bởi logic hiện tại), nhưng không có `pending_clusters` signal để biết cluster nào bị bỏ.

**Việc cần làm** (Phase 3 hoàn chỉnh): Thêm greedy fit loop vào STEP 0 trước khi gọi `flatten_contest_dir()` — tính size ước lượng của mỗi cluster, chọn subset fit budget, pass vào manifest trước khi flatten.
