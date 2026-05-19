# Vấn đề: Peripheral Contract Coverage Gap

## Tóm tắt

Agents không generate findings cho các **sibling/peripheral contracts** trong cùng contest, dù chúng được include đầy đủ trong flattened source. Root cause là agent attention bị dẫn dắt bởi manifest `primary/secondary` — chỉ cover contracts mà primary contract tham chiếu trực tiếp.

**Quan sát từ contest 42 (MochiVault):**
- Miss: H-03, H-06 (`ReferralFeePoolV0`) — array OOB + reward drain
- Miss: H-13 (`VestedRewardPool`) — frontrunning
- Miss: H-10 (`MochiEngine.changeNFT`) — governance risk
- Cover tốt: `FeePoolV0`, `MochiTreasuryV0` — vì MochiVault gọi trực tiếp

---

## Root Cause

### Manifest chỉ bao gồm direct dependencies

BFS từ primary contract (`MochiVault`) tìm ra secondary = các adapter/interface mà MochiVault import:

```
primary  = MochiVault
secondary = [AggregatorV3Interface, MochiCSSRv0, ChainlinkAdapter, SushiswapV2LPAdapter, ...]
```

Các sibling contracts (`ReferralFeePoolV0`, `VestedRewardPool`) được deploy cùng contest nhưng **không phải là dependency của MochiVault** → không xuất hiện trong manifest → không có focus directive → agents bỏ qua khi generate invariants (Turn 1).

### Agent attention bị lệch bởi manifest focus

Turn 1 prompt inject `focus_directive`:
```
⚠️ AUDIT SCOPE — Tập trung đúng contract:
  IN-SCOPE PRIMARY  : MochiVault
  IN-SCOPE SECONDARY: AggregatorV3Interface, MochiCSSRv0, ChainlinkAdapter, ...
```

Khi agent đọc 136K source với 134 files và derive 6-8 invariants, nó tự nhiên tập trung vào PRIMARY và các contract xuất hiện nhiều lần qua cross-reference → peripheral contracts không được derive invariant → không có RAG query → không có Turn 2 hint.

### FeePoolV0 được cover vì lý do khác

`FeePoolV0` không trong manifest secondary nhưng vẫn được cover vì MochiVault gọi `engine.feePool()` trực tiếp → nó xuất hiện trong call graph → agents tự nhiên đọc nó.

```
MochiVault → engine.feePool() → FeePoolV0   ✅ covered
MochiVault → (không gọi)     → ReferralFeePoolV0  ❌ missed
MochiVault → (không gọi)     → VestedRewardPool   ❌ missed
```

---

## Phân loại contracts bị miss

| Loại | Ví dụ | Tại sao miss |
|------|-------|-------------|
| **Sibling pool** | ReferralFeePoolV0 | Không phải dep của primary, không được gọi |
| **Emission/vesting** | VestedRewardPool | Peripheral, không liên quan trực tiếp vault logic |
| **Governance admin** | MochiEngine.changeNFT | Admin function, agents focus exploit paths |

---

## Hướng fix đề xuất

### Option 1 — Mở rộng manifest secondary (đơn giản nhất)

Thay vì chỉ BFS từ primary, nhận diện tất cả **business logic contracts** trong scope bằng heuristic:
- Contract có `state variables` + `write functions` → business logic
- Contract là pure adapter/interface → utility (skip)

Thêm tất cả business logic contracts vào secondary, kể cả khi không phải direct dependency.

**File cần sửa:** `backend/app/services/contract_oasis_env.py` — hàm build manifest

### Option 2 — Agent chuyên peripheral (phức tạp hơn)

Thêm 1 agent profile `peripheral_auditor` với `focus_directive` trỏ đến tất cả contracts KHÔNG phải primary. Agent này chuyên review các contracts ít được chú ý.

**Ưu:** Coverage tốt hơn  
**Nhược:** Thêm 1 LLM call/contest, cần design profile

### Option 3 — Multi-root BFS (cân bằng)

Thay vì BFS từ 1 primary, chọn 2-3 roots từ các contract lớn nhất (by LOC hoặc function count) và merge manifest secondary.

**File cần sửa:** `backend/app/services/contract_flattener.py` (hoặc tương đương)

---

## Ưu tiên triển khai

Option 1 là đơn giản nhất và ít rủi ro nhất. Chỉ cần extend manifest building để bao gồm tất cả in-scope contracts có business logic, không chỉ direct deps của primary.

Option 3 cũng khả thi nếu codebase đã có multi-root BFS (contest 35 dùng `multi_root_bfs_selective`).

---

## Liên quan

- Contest 42 missed H-03, H-06, H-10, H-13 do vấn đề này
- Contest 35 (AMM) ít bị ảnh hưởng hơn vì `ConcentratedLiquidityPool` là contract duy nhất chứa hầu hết logic
- Contest 104 (NFT) — chưa phân tích coverage gap riêng
