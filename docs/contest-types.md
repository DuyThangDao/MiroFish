# Web3Bugs Contest Types

Phân loại dựa trên vị trí của `hardhat.config.*` trong thư mục contest.
Loại contest quyết định pipeline path — từ Slither caller analysis đến scope method.

---

## Phân bố (102 contests)

| Loại | Số lượng | % |
|---|---|---|
| `subdir_only` | 40 | 39.2% |
| `root_config` | 37 | 36.3% |
| `no_hardhat` | 25 | 24.5% |

Theo size (quyết định size gate vs Slither BFS):
- ≤ 200KB total sol chars → **size gate** (full audit): 51 contests (50%)
- > 200KB → **Slither BFS** hoặc fallback: 51 contests (50%)

---

## 1. `root_config`

**Dấu hiệu:** `hardhat.config.ts` (hoặc `.js`) nằm ngay tại root của contest dir.

```
contest/45/
  hardhat.config.ts   ← ở root
  contracts/
    MyProtocol.sol
    Vault.sol
  package.json
  node_modules/
```

**Pipeline:**
- Slither compile từ root → **thành công cao** (cấu trúc chuẩn)
- Step 0: `Slither caller analysis` → tìm được contract nào call primary contract
- Scope: `skeletonized_slither` — Tier 1 (full source) = primary + callers; Tier 2 (skeleton stub) = deps BFS

**Điểm mạnh:** Caller graph chính xác nhất; scope sát với reality nhất.

**Rủi ro:**
- `node_modules` phải được install trước (`npm install` hoặc `yarn install`)
- Một số config cũ dùng syntax không tương thích hardhat v2 hiện tại (e.g. `forking.blockNumber: null` gây HH8 error)
- Nếu compile fail → fallback về forward BFS (giống subdir_only)

**Ví dụ:** Contest 5, 13, 17, 21, 25, 26, 28, 30, 37, 45, 47, 56, 61...

### Root_config contests theo số H bugs

| Contest | H bugs | Impl size | Scope method khi chạy |
|---|---|---|---|
| **5** (Vader Protocol) | **24** | 106KB | full_audit_size_gate |
| 71 | 13 | 129KB | full_audit_size_gate |
| 83 | 11 | 44KB | full_audit_size_gate |
| **61** | **11** | 280KB | multi_root_bfs |
| 192 | 11 | 132KB | full_audit_size_gate |
| 30 | 10 | 149KB | full_audit_size_gate |
| 107 | 9 | 121KB | full_audit_size_gate |
| 78 | 7 | 272KB | multi_root_bfs |
| 100 | 3 | 35KB | full_audit_size_gate |

**Insight quan trọng:** Phần lớn root_config contests < 200KB impl → đi `full_audit_size_gate`, KHÔNG đi `skeletonized_slither`. Slither vẫn chạy ở STEP 0 để tìm callers, nhưng nếu tổng impl chars ≤ 200KB thì scope method vẫn là size_gate (tất cả contracts đều được include anyway).

**Contest 5 (Vader Protocol)** — candidate được chọn để test:
- 24 H bugs (nhiều nhất trong root_config) → F1 ổn định
- GT đã có: `backend/scripts/evaluate/gt/gt_5.json`
- Cần: install node_modules, kiểm tra hardhat compile thành công

---

## 2. `subdir_only`

**Dấu hiệu:** Không có `hardhat.config.*` ở root; chỉ có trong các subdirectory.

```
contest/42/
  mochi-core/
    hardhat.config.ts   ← trong subdir
    contracts/
      MochiEngine.sol
  mochi-usm/
    hardhat.config.ts
    contracts/
      USSD.sol
  mochi-library/
    contracts/
      Beacon.sol
```

**Pipeline:**
- Slither chạy từng subdir riêng → phức tạp, **thường fail** (cross-subdir imports)
- Step 0: Nếu Slither fail → fallback "No callers found"
- Scope: **forward BFS trên import graph** (ai import ai) thay vì call graph thực
- Size gate (< 200KB): full audit tất cả packages — bypass BFS hoàn toàn

**Điểm mạnh:** Size gate cover toàn bộ scope khi contest nhỏ.

**Rủi ro:**
- Khi Slither fail + contest > 200KB: forward BFS có thể bỏ sót contracts không được import trực tiếp nhưng được call at runtime
- Size gate fix (2026-06-03): đã bỏ prefix filter → tất cả packages đều trong scope

**Ví dụ đã test:** Contest 35 (Trident CLP), 42 (Mochi), 104 (Core/Splitter/RoyaltyVault)

---

## 3. `no_hardhat`

**Dấu hiệu:** Không có `hardhat.config.*` ở bất kỳ đâu trong contest dir.

```
contest/3/
  contracts/
    Protocol.sol
    Library.sol
  README.md
```

**Pipeline:**
- Slither **không thể chạy** (không có hardhat project để compile)
- Step 0: Skip hoàn toàn
- Scope: **regex fallback** — phân tích `import "..."` statements và `interface`/`contract` declarations thuần text
- Caller graph: không có; chỉ dựa vào forward import BFS
- Size gate (< 200KB): vẫn áp dụng → full audit nếu nhỏ

**Điểm mạnh:** Đơn giản, không cần dependency. Hoạt động với bất kỳ contest nào.

**Rủi ro:**
- Scope kém chính xác nhất — regex không hiểu runtime calls
- Interface-only contracts có thể bị lọc sai
- Không phân biệt được `call` vs `delegatecall` vs `import`

**Ví dụ:** Contest 3, 6, 7, 14, 18, 19, 20, 23, 31, 32, 49, 52...

---

## Pipeline Decision Tree

```
contest dir
    │
    ├─ total_sol_chars ≤ 200KB?
    │       │
    │       YES → full_audit_size_gate (tất cả packages, bỏ qua Slither)
    │       │     scope_method = "full_audit_size_gate"
    │       │
    │      NO ↓
    │
    ├─ hardhat.config ở root? → root_config
    │       │
    │       ├─ node_modules installed? → Slither compile SUCCESS
    │       │       → scope_method = "skeletonized_slither"
    │       │
    │       └─ compile fail → fallback forward BFS
    │               → scope_method = "legacy_bfs" (hoặc tương đương)
    │
    ├─ hardhat.config trong subdir? → subdir_only
    │       │
    │       ├─ Slither per-subdir SUCCESS (hiếm)
    │       │       → scope_method = "skeletonized_slither"
    │       │
    │       └─ Slither fail (thường) → forward BFS
    │               → scope_method = "legacy_bfs"
    │
    └─ không có hardhat → no_hardhat
            → forward BFS + regex
            → scope_method = "legacy_bfs"
```

---

## Coverage hiện tại của chúng ta

| Contest | Loại | Impl chars | Scope method | H bugs | TP | F1 |
|---|---|---|---|---|---|---|
| 42 (Mochi) | subdir_only | 128KB | full_audit_size_gate | 13 | 9 | 0.273 |
| 104 (Core/Split/Royalty) | subdir_only | 58KB | full_audit_size_gate | 9 | 8 | 0.314 |
| 35 (Trident CLP) | subdir_only | 303KB | multi_root_bfs_selective | 17 | 13 | 0.295 |
| **5 (Vader Protocol)** | **root_config** | **106KB** | **full_audit_size_gate** | **24** | TBD | TBD |

> **Impl chars** = sau khi lọc node_modules, interfaces, mocks — không phải tổng `.sol` thô.
> Contest 35 tổng `.sol` thô ~1MB; sau lọc còn 105 files / 532KB; sau lọc impl-only còn 303KB → vượt 200KB, đi BFS.

**Đã cover:**
- `full_audit_size_gate` (size ≤ 200KB): contest 42, 104, và 5 (pending)
- `multi_root_bfs_selective` (size > 200KB, BFS không Slither): contest 35

**Chưa test:**
- `skeletonized_slither` (Slither thành công + caller graph thực): cần contest root_config > 200KB impl + node_modules
- `no_hardhat`: 25 contests — cần ít nhất 1 để verify regex fallback path

**Lưu ý về `skeletonized_slither`:** Phần lớn root_config contests < 200KB impl nên tự đi size_gate. Contest 61 (280KB) hoặc 78 (272KB) là candidates cho `skeletonized_slither`, nhưng chưa có GT.
