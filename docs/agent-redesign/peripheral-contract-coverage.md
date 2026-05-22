# Vấn đề: Peripheral Contract Coverage

## Tóm tắt

Pipeline hiện tại dùng BFS từ primary contracts để xác định `in_scope_source`. Các contracts
không được import trực tiếp (chỉ được gọi qua interface) bị drop hoàn toàn khỏi context agents.

## Bằng chứng

Contest 42 — context agents nhận (46K chars) chỉ gồm 6 contracts:
`FeePoolV0`, `DutchAuctionLiquidator`, `MinterV0`, `MochiProfileV0`, `MochiTreasuryV0`, `MochiVault`

Bị drop hoàn toàn (không có stub, không có gì):
- `ReferralFeePoolV0` — H-03 (array OOB), H-06 (drain) → 2 TP miss
- `VestedRewardPool` — H-13 (frontrunning vest()) → 1 TP miss
- `MochiEngine` — H-10 (changeNFT breaks protocol) → 1 TP miss

**4/6 FN của contest 42 trực tiếp do peripheral contract bị drop.**

Nguyên nhân gốc: primary contracts import `IReferralFeePool` (interface), không import
`ReferralFeePoolV0` (concrete). BFS chỉ follow `import` statements → concrete implementation
không reachable.

## Trade-off

| Approach | Context size | Coverage | Rủi ro |
|----------|-------------|----------|--------|
| BFS hiện tại | 33K (focused) | Bỏ sót peripheral | Miss 4-5 TP/contest |
| Full source | 136K (diluted) | Đủ contracts | TP primary có thể giảm |
| Per-contract pass | +N×focused | Đủ contracts | Cost/time tăng ~30-50% |
| Interface mapping | +5-10K | Chỉ contracts được call | Cần implement logic mapping |

## Các options đã xem xét

### Option A — Protocol sweep (bị loại)
Sau BFS, add lại tất cả non-OZ contracts vào context. Về bản chất là full source trừ OZ libs
(~100K) — không khác gì Pass 1 flatten, mất đi lý do tồn tại của BFS filtering.

### Option B — Interface-to-implementation mapping
Với mỗi interface được reference trong primary contracts (`IReferralFeePool` → `ReferralFeePoolV0`),
tìm concrete implementation trong codebase và add vào scope dưới dạng compressed summary (~5-10K thêm).
- Ưu: chính xác, context tăng nhẹ, agents aware về peripheral contracts
- Nhược: cần viết logic mapping interface → implementation
- Phù hợp nếu muốn fix nhẹ mà không thay đổi nhiều pipeline

### Option C — Per-peripheral mini-audit (preferred)
Sau R1 main, identify peripheral contracts bị drop, chạy 3-5 agents riêng cho mỗi contract
với context tập trung. Merge findings vào dedup pool chung.
- Ưu: peripheral contracts được cover đầy đủ, không ảnh hưởng TP primary
- Nhược: cost và thời gian tăng ~30-50%
- Phù hợp khi muốn tăng Recall đáng kể và sẵn sàng trả thêm cost

## Độ ưu tiên

Hiện tại ở giai đoạn tăng recall — vấn đề này gây 4-5 TP miss/contest, xử lý sau khi
đã fix các vấn đề higher ROI hơn (BOOST model fix đã xong).

Trước khi implement cần benchmark: chạy lại contest 42 sau BOOST fix để đo baseline mới,
sau đó mới đánh giá ROI của peripheral coverage fix.
