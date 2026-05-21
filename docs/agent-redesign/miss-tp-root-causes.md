# Phân tích nguyên nhân Miss TP — 3 Contests (35, 42, 104)

**Kiến trúc đánh giá**: Epistemic Lens — 19 Tier-1 agents, STOP_AFTER_DEDUP (Round 1 only)
**Kết quả tổng hợp**:

| Contest | Protocol | GT | TP | FN | Recall |
|---------|----------|----|----|-----|--------|
| 35 | Sushi Trident CLP | 17 | 10 | 7 | 58.8% |
| 42 | Mochi Protocol | 13 | 7 | 6 | 53.8% |
| 104 | Core/Splitter/RoyaltyVault | 9 | 5 | 4 | 55.6% |
| **Average** | | **39** | **22** | **17** | **56.4%** |

---

## Nguyên nhân 1: Scope Selection bỏ sót Peripheral Contracts

### Mô tả

Pipeline xác định primary audit targets thông qua BFS traversal từ hardhat config và Slither output, giữ lại tối đa 4–5 contracts "nặng nhất". Source code của các contracts nằm ngoài top-N này không được inject vào context của agents. Agents chỉ thấy tên các contracts đó trong comment (`// Related contracts: ...`) nhưng không có code để phân tích.

### Biểu hiện cụ thể

| Contest | H bug bị miss | Contract bị bỏ sót |
|---------|--------------|---------------------|
| 42 | H-03, H-06 | `ReferralFeePoolV0.claimRewardAsMochi` |
| 42 | H-10 | `MochiEngine.changeNFT` |
| 42 | H-13 | `VestedRewardPool.vest` |

Eval output xác nhận: tất cả 4 bugs này có `0 T1 candidates` — không một agent nào generate finding ở contracts đó.

### Root cause kỹ thuật

`multi_root_bfs_selective` trong pipeline chọn primary targets dựa trên số lượng external calls và state variables. `ReferralFeePoolV0`, `MochiEngine`, `VestedRewardPool` là peripheral contracts ít được reference hơn → không vào top-4 → source code không được flatten vào `contract_summary.txt`.

### Phân loại

**Pipeline-level bug** — không liên quan đến agent prompts hay kiến trúc multi-agent. Fix cần thay đổi ở bước scope selection, không phải ở agents.

---

## Nguyên nhân 2: Coverage Gap — Thiếu độ rộng và độ sâu phân tích

### Mô tả

Agent không tìm được vulnerability cụ thể, thể hiện qua hai failure mode khác nhau — nhưng cả hai đều quy về cùng một nguyên nhân: agent chưa đủ khả năng để phân tích đủ sâu hoặc quét đủ rộng trong phạm vi code được cấp.

**Failure mode A — Partial pattern coverage** (thiếu độ rộng): Agent nhận ra đúng bug class và tìm được một instance trong contract, nhưng bỏ sót instance khác của cùng pattern ở function khác.

**Failure mode B — Wrong attack vector** (thiếu độ sâu): Agent tìm đúng function nhưng dừng lại ở một attack vector bề mặt, không trace đủ sâu để nhận ra attack vector thật sự của H bug.

**Failure mode C — Cross-contract và library** (thiếu độ rộng cross-boundary): Bug nằm ở library function hoặc peripheral position contract — agent có source nhưng không trace đủ sâu qua call chain.

### Biểu hiện cụ thể

| Contest | H bug | Failure mode | Chi tiết |
|---------|-------|--------------|----------|
| 42 | H-09 (sandwich veCRVlock) | A — partial coverage | Agents tìm sandwich tại `_buyMochi`/`_buyCRV` (= H-12, TP), nhưng miss instance riêng tại `veCRVlock` |
| 42 | H-08 (zero-deposit griefing) | B — wrong attack vector | Agents tìm `deposit` + fee-on-transfer, nhưng H-08 là timer reset attack — 2 bugs độc lập trong cùng function |
| 35 | H-07 (Position.burn wrong) | B — single-pass depth | `ConcentratedLiquidityPosition.burn` IN scope (có trong contract_summary). Full multi-round tìm được (T2 match); STOP_AFTER_DEDUP single-pass không generate finding |
| 35 | H-06 (double yield) | C — cross-contract | `ConcentratedLiquidityPosition.collect` — cross-contract interaction giữa Position và Pool không được trace |
| 35 | H-11 (feeGrowthGlobal) | C — library | `Ticks.cross` (library) — agents tìm bug ở main contract, không trace vào tick crossing logic |

### Root cause kỹ thuật

Cả ba failure mode đều xuất phát từ kiến trúc **single-pass, single-context**:
- Failure mode A: Agent dừng lại sau khi tìm được một finding thỏa mãn bug class, không có mechanism để enforce "kiểm tra tất cả functions có thể có cùng pattern"
- Failure mode B: Agent không có second-pass để verify attack vector của finding đã tìm được
- Failure mode C: `library_auditor` có giới hạn về scope — cần biết rõ "library nào / function nào cần đào" và không có cross-contract call chain reasoning

### Phân loại

**Coverage gap** — agent có code, có knowledge, nhưng không trace đủ rộng/sâu. Partially addressable bằng per-function coverage directive (mode A) và mở rộng `library_auditor` scope (mode C).

---

## Nguyên nhân 3: Agent Worldview Tradeoff (evm_hardener)

### Mô tả

Quyết định đổi `evm_hardener` từ "deployment/proxy safety" sang "arithmetic/cast safety" giúp cải thiện contest 35 (tìm được H-01, H-05) nhưng tạo ra regression cho contest 104 (miss H-04, H-06).

### So sánh trực tiếp

| H bug | Contest | Nội dung | Epistemic run | Ghi chú |
|-------|---------|----------|---------------|---------|
| H-01 (unsafe cast burn) | 35 | uint128 cast overflow | ✅ Found | evm_hardener mới cover |
| H-04 (reinitialization) | 104 | Missing initializer guard | ❌ Miss | evm_hardener cũ cover |
| H-06 (storage collision) | 104 | Proxy storage layout collision | ❌ Miss | evm_hardener cũ cover |

### Root cause kỹ thuật

Proxy/initialization bugs (SWC-112, SWC-119, SWC-125) và arithmetic cast bugs (SWC-101, SWC-130) là hai domain khác nhau. Một single agent không thể cover cả hai tốt — buộc phải chọn một. Contest 35 là AMM (không có proxy) → arithmetic focus wins. Contest 104 là NFT với proxy pattern → proxy focus wins.

Giải pháp lý tưởng là **tách thành 2 agents**: một cho arithmetic safety, một cho proxy/initialization safety. Tuy nhiên điều này tăng số agents từ 19 lên 20, cần đánh giá cost/benefit.

### Phân loại

**Architecture tradeoff** — không có single worldview nào cover tất cả contract types. Đây là hệ quả tất yếu của fixed 19-agent pool trên diverse contest types.

---

## Nguyên nhân 4: Agent Pool Coverage Gap — Thiếu Domain Cover

### Mô tả

19 agents hiện tại cover 6 domain groups nhưng không có agent nào có worldview cho 4 sub-domain cần thiết để tìm các H bugs này. Eval data xác nhận **0 T1 + 0 T2 candidates** trong tất cả runs kể cả full multi-round — agents không tiếp cận được các bugs này từ đầu.

### Biểu hiện cụ thể

| Contest | H bug | Sub-domain thiếu | Agent gần nhất | Vì sao không cover |
|---------|-------|-----------------|----------------|-------------------|
| 35 | H-15 (initialPrice validation) | Absence detection | Tất cả agents | Agents tìm thứ *sai* trong code, không có agent systematically tìm thứ *bị thiếu* |
| 35 | H-16 (JIT liquidity attack) | MEV/block-level economics | `defi_economics` | Focus vào slippage/sandwich, không phải block-level timing attack |
| 35 | H-17 (nearestTick design flaw) | Protocol design correctness | Không có | Không có agent hỏi "semantic của invariant này có đúng với protocol intent không" |
| 104 | H-05 (centralization risk) | Owner-as-adversary | `governance_specialist` | Treat owner là legitimate actor, chỉ tìm "bypass access control", không tìm "owner lạm dụng privilege" |

### Root cause kỹ thuật

Agent pool thiếu 4 worldview:
1. **Absence detection**: "Function/constraint nào *nên có* nhưng không có?" — ngược với adversarial mindset hiện tại
2. **MEV/block-level**: "Ai có thể thao túng transaction ordering để exploit contract này?" — cần knowledge về block builder behavior ngoài code
3. **Protocol design correctness**: "Invariant này có đúng với semantic của protocol không?" — cần đọc spec/design intent, không chỉ code
4. **Owner-as-adversary**: "Nếu owner là attacker, họ có thể làm gì với các privileged functions?" — trust model khác với standard access control audit

### Phân loại

**Agent pool coverage gap** — addressable bằng cách thêm hoặc điều chỉnh worldview cho 4 sub-domain trên. Không phải fundamental limitation, nhưng cost cao hơn RC1/RC2: cần thêm agents hoặc rewrite worldview của agents hiện có.

---

## Tổng hợp

| # | Nguyên nhân | Bugs bị ảnh hưởng | Khả năng fix | Layer |
|---|-------------|-------------------|--------------|-------|
| 1 | Scope selection bỏ sót peripheral contracts | 42: H-03,H-06,H-10,H-13 | **Cao** — sửa BFS scope | Pipeline |
| 2 | Coverage gap (độ rộng + độ sâu + cross-contract) | 42: H-08,H-09; 35: H-06,H-07,H-11 | **Trung bình** — per-function directive, library scope | Prompt + Architecture |
| 3 | Agent worldview tradeoff | 104: H-04,H-06 | **Thấp** — cần thêm agent hoặc dynamic worldview | Architecture |
| 4 | Agent pool coverage gap (MEV, absence detection, protocol design, owner-adversary) | 35: H-15,H-16,H-17; 104: H-05 | **Trung bình** — thêm/rewrite worldview cho 4 sub-domain | Architecture (Agent Worldview) |

**Quick wins** (impact cao, fix dễ): Nguyên nhân 1 (scope selection) — sửa pipeline để inject source code của tất cả contracts được reference, không chỉ top-N primary targets. Ước tính có thể phục hồi 3–4 TP trên contest 42.

**Long-term**: Nguyên nhân 2, 3, 4 đều là inherent limitations của kiến trúc single-pass, single-context, fixed-agent-pool. Nguyên nhân 2 (H-07 cụ thể) có thể cải thiện bằng full multi-round thay vì STOP_AFTER_DEDUP. Nguyên nhân 4 cần external domain knowledge không derivable từ code.
