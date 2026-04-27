# Root Cause Analysis — Điểm yếu hệ thống của MiroFish Audit Engine

> Được xác định qua 3 contests: C19 (Connext/Bridge), C03 (Marginswap/Dexes), C35 (Sushi Trident/AMM)  
> Tập trung vào các vấn đề **xảy ra chung trên nhiều contest và thực tế**, không phải C35-specific.

---

## Phân biệt L-track vs S-track (nền tảng để hiểu root causes)

| | L-track | S-track |
|-|---------|---------|
| Match bằng | **SWC code** trong `consensus_vulns` / `swc_gaps` | **Semantic category** trong `semantic_results` |
| Ví dụ | L1=SWC-107 (reentrancy), L4=SWC-128 (DoS), L7=SWC-101 (overflow) | S1=price_oracle, S3=state, S6=incorrect_accounting |
| Đặc điểm | Bug có *pattern SWC recognizable* | Bug cần hiểu *ý định thiết kế* của protocol |
| Phân biệt | **Có SWC code hay không** — không phải đơn giản/phức tạp | Logic errors, business flow bugs, accounting errors |

---

## G-RC-1 — Agents gán sai/thiếu SWC code cho patterns không quen thuộc

### Vấn đề

L-track evaluation match bằng SWC code. Nếu agent không gán đúng SWC cho một finding, bug tương ứng sẽ không được count là TP — bất kể agent có "thấy" bug đó hay không.

Vấn đề không phải SWC taxonomy thiếu, mà là **agents không apply SWC codes đúng** khi gặp variant patterns hoặc context mới:

**Trường hợp phổ biến nhất — SWC-101 và Solidity 0.8 assumption:**
```
Code:    uint128 liquidity = uint128(amount);   ← explicit cast, có thể truncate
Agent:   "Solidity 0.8 có overflow protection → không cần tag SWC-101"
Reality: 0.8 bảo vệ phép tính (+, -, *) NHƯNG KHÔNG bảo vệ explicit cast
Result:  Không có SWC-101 finding → L7 bugs miss hoàn toàn
```

**Pattern tổng quát hơn** — xảy ra với nhiều SWC:

| SWC | Pattern quen thuộc (agents tag được) | Variant (agents thường bỏ qua) |
|-----|--------------------------------------|-------------------------------|
| SWC-101 | `a + b` overflow (Solidity <0.8) | Explicit cast `uint128(x)`, `unchecked{}` block |
| SWC-107 | `call()` trước `balances[msg.sender] = 0` | Reentrancy qua callback/hook ở tầng sâu hơn |
| SWC-124 | `delegatecall` trực tiếp | Delegatecall qua proxy pattern, `batch()` function |
| SWC-128 | Loop duyệt array không giới hạn | Indirect unbounded growth qua mapping + index |

**Bằng chứng xuyên contest:**
- C35: 54 findings, chỉ 1 SWC-101 (là code smell, không phải vulnerability thật) → 6 L7 bugs miss
- C19: SWC-128 chỉ được tag sau khi có P-L1 checklist nhắc nhở — không tự nhiên xuất hiện
- C03: Một số SWC-128 findings về DoS xuất hiện nhưng không đủ để cover H-11

### Giải pháp

**S1a — SWC explicit tagging obligation trong stage1_instruction (ngắn hạn, ~30 phút):**

Thêm vào `contract_oasis_env.py` stage1_instruction một block bắt buộc:

```
⚠️ SWC TAGGING RULES — BẮT BUỘC gán SWC khi thấy pattern sau:
  SWC-101: Bất kỳ explicit cast nào (uint128(x), int24(y), uint160(z), int256(uint256_var))
           Bất kỳ unchecked{} block nào — verify intentional hay không
           → Solidity 0.8 KHÔNG bảo vệ explicit casts, chỉ bảo vệ phép tính thuần túy
  SWC-107: Bất kỳ external call nào TRƯỚC state update, kể cả qua callback/hook/onFlashLoan
  SWC-124: Bất kỳ delegatecall nào, kể cả ẩn trong batch() hay proxy pattern
  SWC-128: Bất kỳ loop nào duyệt qua array/mapping có thể grow unbounded
```

**S1b — Post-processing SWC re-tagging (trung hạn, ~2 giờ):**

Sau khi collect tất cả findings từ agents, chạy một pass re-tagging: scan `description` + `evidence` của mỗi finding, nếu phát hiện pattern keyword → gán SWC tương ứng nếu còn thiếu. Tương tự spell-check nhưng cho SWC codes.

**Tác động:** Áp dụng cho mọi contest và mọi domain — không chỉ AMM. Rủi ro tăng FP ở contract ít pattern (bridge/simple lending) là thấp nhưng cần đo lại sau khi implement.

---

## G-RC-2 — Flat file không có context prioritization: attention dilution

### Vấn đề

Khi nhiều contracts được flatten thành một file duy nhất, agents không được hướng dẫn phân bổ attention. Kết quả: **agents tự nhiên gravitate về contracts có pattern bugs quen thuộc**, bất kể đó có phải là audit target chính hay không.

**Cơ chế xảy ra:**

```
Flat file gồm 5 contracts:
  ├── InfraContract (reentrancy, delegatecall, signature replay patterns rõ ràng)
  ├── CoreContract (domain-specific math bugs, ít pattern surface)
  ├── HelperA, HelperB, HelperC (utility, ít bugs)

Agent behavior:
  → InfraContract: quen thuộc, dễ nhận diện → agents generate nhiều findings
  → CoreContract: cần domain knowledge → agents bỏ qua hoặc tạo generic findings
  → Kết quả: 40-50% findings về InfraContract, <5% về CoreContract
```

**Tại sao đây là vấn đề hệ thống, không phải C35-specific:**

Bất kỳ multi-contract codebase nào cũng có sự phân hóa này:
- DeFi protocol: vault/core logic bị bỏ qua vì peripheral contracts có nhiều "visible" patterns hơn
- Lending protocol: interest rate math bị bỏ qua vì access control patterns rõ ràng hơn
- Bridge protocol: cross-chain accounting bị bỏ qua vì signature validation patterns chiếm attention

**Bằng chứng xuyên contest:**
- C35: BentoBox infrastructure chiếm ~39% findings (keyword estimate), ConcentratedLiquidityPool ~0%
- C03: 20 invariants, phần lớn là access_control từ peripheral contracts — core lending math ít được cover
- Pattern này sẽ xuất hiện ở bất kỳ flat file nào có >3 contracts với độ phức tạp khác nhau

**Vấn đề sâu hơn — agents không biết "contract nào quan trọng":**

Hiện tại agents nhận toàn bộ flat file mà không có thông tin nào về:
- Contract nào là audit target chính
- Contract nào là infrastructure/boilerplate
- Phân bổ attention nên như thế nào

→ Agents mặc định dùng "pattern familiarity" làm proxy cho "importance" — và đây là proxy sai.

### Giải pháp

**S2a — Contract manifest + focus directive (trung hạn, ~2-3 giờ):**

*Bước 1:* Mở rộng `flatten_contest.py` để emit contract manifest sau khi flatten:

```python
ContractManifest = {
    "primary": "CoreContract",       # heuristic: không phải interface/library + LOC cao
                                     # + class name priority: *Core*, *Pool*, *Vault*, *Logic*
                                     # + manual override nếu heuristic sai
    "secondary": ["InfraContract", "HelperA"],
    "total_contracts": 5,
    "total_chars": 248342
}
```

> Heuristic "primary = LOC lớn nhất" không đủ — infrastructure contracts có thể lớn hơn core.  
> Cần kết hợp: (1) LOC, (2) class name pattern matching, (3) exclude interfaces/libraries, (4) manual override option.

*Bước 1b — Đồ thị / bản đồ dự án (khuyến nghị gắn với S2a):*

Dùng tool hoặc script (dependency graph, call graph, import cluster) để **bổ sung tín hiệu cấu trúc** — không thay thế manifest nhưng làm **chọn `primary` / `secondary` ổn định hơn** so với chỉ đếm LOC:

| Tín hiệu từ graph | Cách dùng |
|-------------------|-----------|
| In-degree / hub / cluster | Ưu tiên contract **trung tâm** (vault, pool, engine) thay vì file to nhưng chỉ là infra |
| Cạnh phụ thuộc | Phân loại **core → periphery** để gắn nhãn secondary hợp lý |
| Text tóm tắt (vd. Mermaid nhỏ hoặc bullet) | Inject thêm vào context cùng manifest: agent thấy **ai gọi ai**, giảm đoán mò |

*Hạ tầng tùy chọn (dài hạn):* ngoài **call/import graph**, có thể dựng **đồ thị phụ thuộc dữ liệu** tĩnh (hàm nào **đọc/ghi** biến trạng thái quan trọng — ví dụ `reserve0`/`reserve1`) từ **Slither/SlithIR**, rồi xuất sang **property graph (Memgraph)** để hỏi bằng **Cypher**; phục vụ chọn `primary`/`secondary` và thứ tự reasoning (invariant/ordering) sâu hơn so với chỉ dựa hub theo in-degree, **vẫn** là nâng cấp S2a — không thay thế focus directive. Giới hạn: phân tích tĩnh; xem tài liệu riêng: [slither-memgraph-state-lifecycle.md](slither-memgraph-state-lifecycle.md).

**Tác động L/S (một dòng):** Chỉ **gián tiếp** (đúng module → dễ có finding khớp SWC/semantic hơn); **không** sửa eval. **G-RC-1** vẫn cần **S1**; AMM sâu vẫn cần **S3**.

**Giới hạn:** (1) Graph tĩnh có thể **sai** với proxy / `delegatecall` / factory — dùng **gợi ý + override tay**. (2) **Token / noise:** toàn bộ graph lớn (vd. >~20 node) nếu nhét cả vào prompt sẽ **tốn context và thêm nhiễu**; nên chỉ inject **summary** — vd. **top 5–7** contract theo in-degree (hoặc trọng số hub) + cạnh nối trực tiếp, hoặc vài dòng bullet; tránh Mermaid full graph. (3) **Bắt buộc** vẫn kèm **focus directive** (Bước 2), không “chỉ vẽ graph là đủ”.

*Bước 2:* Inject vào `contract_oasis_env.py` stage1_instruction khi `total_chars > 100_000`:

```
⚠️ MULTI-CONTRACT AUDIT — Phân bổ attention:
  PRIMARY TARGET (≥50% findings): {primary_contract}
  Secondary: {secondary_contracts}
  KHÔNG để infrastructure/utility patterns chiếm đa số findings.
  Infrastructure bugs (reentrancy, signature) vẫn report nhưng không ưu tiên hơn PRIMARY.
```

**S2b — Sub-audit pipeline (dài hạn, ~1-2 ngày):**

Giải pháp triệt để hơn: thay vì 1 flat file lớn, tách thành N sub-audits theo contract group, sau đó merge findings:

```
Input: multi-contract repo
       ↓
[Contract Splitter] → group theo dependency
       ├── sub_audit_1: CoreContract (~80K chars)
       ├── sub_audit_2: InfraContract (~90K chars)
       └── sub_audit_3: Periphery (~78K chars)
       ↓
[N parallel audit runs]
       ↓
[Finding Merger] — dedup + cross-reference
       ↓
Output: merged audit_report.json
```

| | Sub-audit | Flat file |
|-|-----------|-----------|
| Attention quality | ✓ Tập trung tối đa | ✗ Diluted |
| Thời gian | ✗ N× | ✓ 1× |
| Chi phí API | ✗ N× | ✓ 1× |
| Cross-contract bugs | ✗ Có thể bỏ sót | ✓ Agents thấy toàn bộ |

**Khuyến nghị:** Implement S2a trước (Manifest + Bước 2); tích hợp **Bước 1b (graph)** khi có pipeline build graph ổn định — coi graph là **phần nâng cấp của S2a**, không thay S2b. Chỉ implement S2b nếu S2a (+ graph) vẫn chưa đủ sau ≥3 contests.

---

## G-RC-3 — Invariant extractor chỉ capture structural invariants, bỏ qua protocol invariants

### Vấn đề

Invariants được extract và inject vào agent context để hướng dẫn reasoning. Nhưng hiện tại extractor chỉ tạo được một loại invariant:

```
Loại được extract:   "Only owner can call function X"  (access_control)
                     "Balance sau withdraw ≤ balance trước" (economic, generic)

Loại bị bỏ qua:     "Interest phải được apply TRƯỚC khi tính liquidation ratio"
                     "Fee phải được accumulate TRƯỚC khi update position"  
                     "Slippage check phải xảy ra SAU khi swap, không phải trước"
```

**Tại sao quan trọng:** Khi agents có invariants đúng, họ có thể dùng chúng để CHALLENGE findings ("Finding này vi phạm invariant X") và VALIDATE ("Finding này thật vì vi phạm invariant Y"). Không có protocol invariants → Stage 2 CHALLENGE/VALIDATE thiếu cơ sở logic → consensus quality thấp.

**Bằng chứng xuyên contest:**
- C19: 3 invariants, đều là access_control (ownership gaps)
- C03: 20 invariants, phần lớn là access_control — không có invariant nào về lending math (interest rate, liquidation order)
- C35: 10 invariants, toàn access_control — không có AMM fee growth, liquidity accounting

→ Pattern nhất quán: **không contest nào có protocol-level invariants thực sự**, bất kể domain.

### Giải pháp

**S3a — Cải thiện invariant extraction prompt (ngắn hạn, ~1 giờ):**

Thêm vào invariant extraction prompt các câu hỏi hướng LLM extract protocol invariants:

```
Ngoài access_control invariants, hãy extract:
1. ORDERING invariants: "A phải xảy ra TRƯỚC B" (ví dụ: interest phải apply trước liquidation check)
2. ACCOUNTING invariants: "Sau operation X, tổng Y phải bằng Z"
3. STATE TRANSITION invariants: "State S1 chỉ có thể chuyển sang S2 khi điều kiện C thỏa mãn"
4. BOUNDARY invariants: "Giá trị V phải nằm trong [min, max]"
```

**S3b — Domain-specific invariant templates (trung hạn, ~3-4 giờ):**

Detect domain từ keyword scan, inject pre-defined template invariants phù hợp:

```python
DOMAIN_INVARIANTS = {
    "amm_v3": [  # detect: sqrtPrice, tick, feeGrowth, secondsPerLiquidity
        "feeGrowthInside = global - below - above (subtraction dùng unchecked{})",
        "sqrtPrice ∈ [MIN_SQRT_RATIO, MAX_SQRT_RATIO] tại mọi thời điểm",
        "pool.liquidity = Σ liquidity của positions active tại current tick",
    ],
    "lending": [  # detect: collateral, liquidation, interestRate, borrowIndex
        "Interest phải được accrued trước khi check liquidation threshold",
        "Collateral ratio sau borrow phải ≥ min_collateral_ratio",
    ],
    "erc20_vault": [  # detect: totalSupply, totalAssets, shares
        "shares/totalSupply = assets/totalAssets (ERC4626 invariant)",
        "totalAssets không giảm sau deposit (trừ fee)",
    ],
}
```

> *Templates là đơn giản hóa để hướng dẫn agent, không dùng cho formal verification.*

---

## G-RC-4 — S6 logic bugs bị miss hệ thống: agents không biết protocol intent

### Vấn đề

S6 là loại "implementation logic error" — code làm *đúng về mặt syntax* nhưng *sai về mặt ý định*:

```
Ví dụ S6-4 (C03 H-05):
  Intent:  "Liquidation chỉ xảy ra khi collateral ratio < threshold"
  Code:    if (collateralRatio <= threshold)   ← dùng <= thay vì <
  Bug:     Cho phép liquidation khi ratio = threshold (boundary case sai)
  
  Agent thấy: "Code này syntactically valid, không có pattern bug rõ ràng"
  Agent không biết: "Protocol PHẢI dùng < không phải <="
```

**Tại sao agents không thể detect S6 tự nhiên:**

Agents giỏi tìm *"code làm gì sai so với pattern chuẩn"* (reentrancy, overflow). Nhưng S6 yêu cầu biết *"protocol phải làm gì"* — thông tin này không có trong code, chỉ có trong:
- NatSpec comments (`@notice`, `@dev`)
- Contest description / README
- Whitepaper / spec document
- Implicit từ naming convention và context

**Bằng chứng xuyên contest — S6 bị miss nhất quán:**
- C03: H-04 (S6-2 `applyInterest`), H-05 (S6-4 liquidation) → miss
- C35: H-08 (S6-4 range check), H-10 (S6-3 burn), H-11 (S6-4 fee accounting), H-12 (S6-1 secondsPerLiquidity) → miss
- Pattern: S6 bị miss ở **mọi contest**, bất kể domain

### Giải pháp

**S5 — Protocol intent extraction trước Stage 1 (trung hạn, ~3-4 giờ):**

Thêm bước pre-audit trước Stage 1: LLM đọc NatSpec, function names, contest description và extract "protocol MUST" statements, inject vào agent context:

*Input sources (theo thứ tự ưu tiên):*
1. NatSpec `@notice` và `@dev` comments trong code
2. Contest description / README (nếu có)
3. Inferred từ function signatures và variable names

*Output format được inject vào context:*
```
PROTOCOL INTENT (extracted):
  [ORDERING]  Interest PHẢI được accrued trước khi evaluate liquidation
  [BOUNDARY]  Liquidation chỉ xảy ra khi collateralRatio STRICTLY < threshold (dùng <, không <=)
  [ACCOUNTING] Sau mỗi swap, reserve0 * reserve1 PHẢI ≥ k (constant product invariant)
  [STATE]     Position chỉ được burn khi liquidity = 0
```

Khi agents có context này, Stage 2 CHALLENGE/VALIDATE sẽ có cơ sở để phát hiện S6 violations.

---

## Tổng hợp — Prioritized roadmap

| # | Root Cause | Impact | Solution | Effort | Ưu tiên |
|---|-----------|--------|---------|--------|--------|
| **G-RC-1** | Agents gán sai SWC code (Solidity 0.8 assumption, variant patterns) | L-track FN cao | S1a: SWC tagging rules trong prompt | 30 min | **P0** |
| **G-RC-2** | Attention dilution trong multi-contract flat file | L+S-track FN cao với codebase lớn | S2a: manifest + focus directive | 2–3h | **P1** |
| **G-RC-3** | Invariant extractor bỏ qua protocol invariants | CHALLENGE/VALIDATE thiếu cơ sở, S6 FN | S3a: mở rộng prompt + S3b: domain templates | 1–4h | **P2** |
| **G-RC-4** | Agents không biết protocol intent → S6 miss hệ thống | S-track FN cao ở mọi contest | S5: pre-audit intent extraction từ NatSpec | 3–4h | **P2** |
| *(hạ tầng)* | Đồ thị phụ thuộc dữ liệu tĩnh (hàm đọc/ghi state quan trọng) từ Slither/SlithIR | Cấu trúc rõ hơn cho S2a; **không** thay focus directive | [slither-memgraph-state-lifecycle](slither-memgraph-state-lifecycle.md) + tích hợp pipeline tùy contest | (tùy) | **P3** |
| *(hạ tầng)* | Attention dilution không giải quyết được bằng prompt | Mọi multi-contract repo lớn | S2b: sub-audit pipeline | 1–2 ngày | **P3** |

```
Giai đoạn 1: S1a → chạy lại C35 + C19 → đo delta SWC tagging
Giai đoạn 2: S2a + S3a → chạy C35 + C104/C14 → đo tổng hợp L+S
Giai đoạn 3: S3b + S5 → đo S6 recall improvement
Giai đoạn 4: S2b nếu S2a vẫn chưa đủ sau ≥5 contests
```
