# Two-Stage Round — Vấn đề và Đề xuất Giải pháp

**Ngày cập nhật:** 2026-04-25 (sau khi run contest 19 hoàn thành)  
**Context:** Phân tích đầy đủ sau run `cyber_4ff463a5cd7c` (contest 19, Connext TransactionManager, 38K chars, 10 rounds).  
**Trạng thái:** Run hoàn thành lúc 16:28:45 UTC — tất cả số liệu dưới đây là kết quả thực tế.

---

## Kết quả đo thực tế (run hoàn chỉnh)

| Metric | Baseline (single-stage) | Two-stage (đo thực tế) | Kỳ vọng |
|--------|------------------------|------------------------|---------|
| CLAIMs/round | 0 (không có) | **49–56 ✓** (R1=54, R2=49, R3=50, R4=54, R5=56, R6=54, R7=54) | ≥ 10 |
| VALIDATE → finding | N/A | **0/60 VALIDATE** ✗ (60/60 → claim) | > 50% |
| VALIDATE → claim | N/A | **60/60** (vô hiệu do không có confidence) | — |
| CHALLENGE tổng | N/A | **2/119 Stage 2 agents** ✗ (1 → finding, 1 → claim) | ≥ 10% |
| expert_findings với validated_by ≠ [] | N/A | **0/19** ✗ | > 50% |
| Stage 2 avg latency (normal) | ~800 chars equiv | **8.9s** (~235 chars visible) ✗ | ≥ 600 chars equiv |
| Expert findings | 35 | **19** ✓ (ít FP hơn) | — |
| Round duration | ~15 min | **~13 min** ✓ | — |
| 429 incidents | ~8 | **9** (tương đương) | — |

### F1 score so sánh (contest 19 — 3 bugs in-scope)

| Track | Baseline | Two-Stage | Δ |
|-------|----------|-----------|---|
| **L-track** (SWC matching) | 0.222 (P=0.125, R=1.000) | **0.333** (P=0.200, R=1.000) | **+0.111** ✓ |
| **S-track** (semantic category) | 0.667 (P=1.000, R=0.500) | **0.500** (P=0.500, R=0.500) | **−0.167** ✗ |
| **Combined F1** | 0.333 | **0.400** | **+0.067** ✓ |

Ground truth contest 19: H-01 (access_control), H-02 (SWC-128 DoS), H-05 (state_machine_bug).
- ✅ H-01 detected qua S-track (category=access_control)
- ✅ H-02 detected qua L-track (SWC-128, `removeUserActiveBlocks()`)
- ❌ H-05 missed (approval not reset on IFulfillHelper failure — state machine bug)

**Kết luận:** Combined F1 tăng +0.067 nhờ **ít FP hơn** trong L-track (19 vs 35 findings → consensus 5 vs 8), không phải từ VALIDATE/CHALLENGE feedback loop (vẫn broken). S-track regression nhỏ do thêm 1 FP semantic finding.

---

## Vấn đề 1 — VALIDATE không propagate lên expert_findings

**Mức độ:** Critical — block toàn bộ confidence calibration  
**Trạng thái:** ✅ **CONFIRMED** bởi daily log (debug level)

### Hiện tượng (đo thực tế)

- **60/60 VALIDATE** trong Phase B (7 rounds × 119 Stage 2 agents) đều target `→ claim`
- **0/60 VALIDATE** target `→ finding`
- 19/19 `expert_findings` có `validated_by = []` sau khi run xong
- Confidence cao (0.82–0.87) đến từ **Phase C attacker corroboration** (+0.03 × 4 attackers), không phải VALIDATE

### Root cause

`_find_target()` trong `_parse_challenge_validate()` (orchestrator.py:1332–1342):

```python
# Priority 1: Stage 1 CLAIMs (same round)  ← agents luôn chọn đây
if stage1_claims:
    for c in stage1_claims:
        if frag in _normalize(c["title"]):
            return ("claim", c)
# Priority 2: expert_findings round cũ
for f in session_state.expert_findings:
    if f.get("round_number", 0) < round_num and frag in _normalize(f.get("title", "")):
        return ("finding", f)
```

Confidence boost và `cross_domain_validated` **chỉ áp dụng khi `kind == "finding"`**. Khi target là CLAIM, `validated_by` được ghi vào CLAIM dict nhưng không có expert_finding nào thay đổi.

Agents ưu tiên target CLAIMs cùng round vì feed context hiển thị chúng nổi bật hơn prior_context.

### Giải pháp đề xuất

**Option A — Fuzzy link CLAIM → expert_finding sau khi match (recommended)**

Sau khi `_find_target` trả về `kind="claim"`, tìm tiếp expert_finding cùng round có title overlap cao nhất:

```python
if kind == "claim":
    best_match, best_score = None, 0
    claim_tokens = set(_normalize(target["title"]).split())
    for f in session_state.expert_findings:
        if f.get("round_number") == round_num:
            finding_tokens = set(_normalize(f["title"]).split())
            overlap = len(claim_tokens & finding_tokens)
            if overlap > best_score:
                best_score, best_match = overlap, f

    # Ngưỡng thích nghi: title ngắn cần Jaccard cao hơn đếm tuyệt đối
    min_overlap = 3 if len(claim_tokens) < 8 else 2
    jaccard = best_score / len(claim_tokens | set(_normalize(best_match["title"]).split())) if best_match else 0
    if best_match and best_score >= min_overlap and jaccard >= 0.15:
        kind, target = "finding", best_match
```

> **Lưu ý 1 — Parallel Stage 2:** Stage 2 chạy song song — khi `_parse_challenge_validate` được gọi, expert_findings từ cùng batch Stage 2 có thể chưa được commit. Chỉ link tới findings đã có trong `session_state` tại thời điểm gọi.

> **Lưu ý 2 — VALIDATE semantic misuse (Vấn đề 6):** Guard phát hiện CLAIM âm phải đặt **trước** bước link. Xem Vấn đề 6 để biết chi tiết cách detect negation trong mệnh đề "because...".

**Option B — Bỏ điều kiện `round_number < round_num`**

Cho phép VALIDATE target same-round expert_findings. Rủi ro: circular validation trong cùng batch — không khuyến khích.

**Effort:** ~30 dòng trong `_parse_challenge_validate()`

---

## Vấn đề 2 — Stage 2 bị truncation, FINDING blocks không đầy đủ

**Mức độ:** High — giảm evidence quality, block VALIDATE/CHALLENGE multi-line  
**Trạng thái:** ✅ **CONFIRMED** — Stage 2 normal latency **8.9s avg** (116/119 agents), pattern nhất quán với ~235 chars visible

### Hiện tượng (đo thực tế)

- Stage 2 avg latency bình thường: **8.9s** (116 agents; 3 outliers do 429: 622s, 623s, 354s)
- Regex `_VALIDATE_RE` yêu cầu `DOMAIN_EVIDENCE:` trên dòng riêng — multi-line format không vừa trong 235 chars
- Regex `_CHALLENGE_RE` yêu cầu `REASON:` trên dòng riêng — tương tự
- Hệ quả: VALIDATE thành công chỉ khi agent viết format cực ngắn, không có evidence thực sự

### Root cause

`_run_stage2` gọi `_call_agent` không truyền `max_tokens` (orchestrator.py:906–912), dùng mặc định:

```python
max_tok = max_tokens if max_tokens is not None else (4096 if is_attacker_phase_c else 1500)
```

`gemini-2.5-flash` là thinking model — token budget dành cho `<think>` block chiếm phần lớn `max_tokens`. Tỷ lệ ~96% thinking là ước tính thực nghiệm từ các run, không được cố định trong code.

### Giải pháp đề xuất

**Option A — Tăng `STAGE2_MAX_TOKENS` qua env var**

```
STAGE2_MAX_TOKENS=8192
```

Sửa `_run_stage2` truyền `max_tokens=self._STAGE2_MAX_TOKENS` vào `_call_agent`.

**Rủi ro:** Token consumption tăng ~5× → 429s nhiều hơn. Tăng `max_tokens` đơn lẻ mà không điều chỉnh rate-limit strategy là patch một chiều:
- Cần tính lại `LLM_SUBMIT_DELAY_S` riêng cho Stage 2 (hiện tại 8s toàn bộ — Stage 2 với 8192 tokens cần delay dài hơn hoặc giảm concurrent workers tạm thời).
- **Cách validate:** chạy cùng một contest trước/sau thay đổi, so sánh số lượng 429 và tổng thời gian run để có baseline trước khi tune thêm.

**Option B — Disable thinking cho Stage 2 (recommended nếu endpoint hỗ trợ)**

Stage 2 cần structured output, không cần deep reasoning:
```python
# Trong _call_agent khi stage=2:
extra_body = {"google": {"thinking_config": {"thinking_budget": 0}}}
```
Cần verify Vertex AI OpenAI-compatible endpoint có nhận `extra_body` không — chưa được kiểm chứng trong repo.

**Option C — Single-line format cho Stage 2**

Tương tự fix Stage 1 (CLAIM-only), đổi sang format ngắn:
```
FINDING: <title> | SWC: <id> | SEVERITY: <level>
VALIDATE: <claim-or-finding-title>
CHALLENGE: <title> | REASON: <one sentence>
```
**Tradeoff:** Mất `EVIDENCE:` block trong FINDING → giảm khả năng filter FP ở consensus engine, nhưng khả thi nhất.

---

## Vấn đề 3 — CHALLENGE gần như không xảy ra

**Mức độ:** Medium — FP reduction mechanism không hoạt động  
**Trạng thái:** ✅ **CONFIRMED** — 2 CHALLENGE trên toàn bộ 119 Stage 2 invocations Phase B

### Hiện tượng (đo thực tế)

- Phase B: 60 VALIDATE, **2 CHALLENGE** (1 → finding với penalty, 1 → claim không hiệu lực)
- Ratio VALIDATE:CHALLENGE = 30:1
- Không có FP nào bị penalize confidence đáng kể

### Root cause

1. **Social bias của LLM**: Thinking model thiên về đồng thuận
2. **Truncation** (Vấn đề 2): `CHALLENGE_FINDING:` + `REASON:` multi-line không vừa ~235 chars

### Giải pháp đề xuất

**Option A — Designated skeptic: 1 agent/round role cố định (recommended)**

Thay vì áp instruction cho tất cả `offensive` agents (dẫn đến CHALLENGE giả hàng loạt), chỉ định 1 agent/round làm adversarial reviewer:

```python
# Chọn 1 offensive agent ngẫu nhiên từ domain khác làm skeptic
skeptic = next((p for p in active_profiles
                if p.persona == "offensive" and p.domain_group != prev_round_dominant_domain), None)
if skeptic:
    skeptic_instruction = (
        "\nYour role this round is SKEPTIC. Your PRIMARY task is to challenge at least 2 CLAIMs "
        "or findings you believe are incorrect or overstated. Write CHALLENGE_FINDING blocks FIRST, "
        "then any new FINDING you believe the group missed."
    )
    # Chỉ áp cho skeptic, 16 agents còn lại giữ instruction gốc
```

Ưu điểm: không làm loãng output 16 agents còn lại; designated skeptic có full mandate để CHALLENGE mà không cần "giả vờ" như per-quota approach.

**Option B — Persona-based instruction cho tất cả offensive**

```python
if profile.persona == "offensive":
    phase_instruction += "\nPRIORITY: Challenge at least 1 CLAIM you believe is incorrect."
```

Rủi ro cao hơn Option A: tất cả offensive agents tạo CHALLENGE giả để tuân thủ, làm tăng noise thay vì signal.

> **Fix Vấn đề 2 (truncation) là điều kiện tiên quyết.** CHALLENGE multi-line sẽ không hoàn chỉnh khi Stage 2 chỉ có ~235 chars visible — designated skeptic cũng bị ảnh hưởng.

**Effort:** ~15 dòng

---

## Vấn đề 4 — Non-standard SWC bị drop, không vào pipeline nào

**Mức độ:** High — miss TP trực tiếp với DeFi contests  
**Trạng thái:** ⚠️ **Chưa phát sinh** trong contest 19 (bridge contract dùng toàn SWC-1xx chuẩn); sẽ phát sinh với DeFi contests (flash loan, oracle)

### Hiện tượng

Agents hay tạo SWC ID tùy chế: `DEFI-FLASH_LOAN`, `FLASH_LOAN_PRICE_MANIPULATION`, `DEFI-ORACLE`.

Những findings này **bị drop hoàn toàn** bởi RC-5 validation (contract_oasis_env.py:836–842):

```python
if swc_id and not _VALID_SWC_RE.match(swc_id):
    logger.debug(f"RC-5: invalid SWC tag '{swc_id}' → dropped '{title[:60]}'")
    return None
```

Với `DEFI-*` IDs hợp lệ theo regex, finding vào expert_findings (H-track) nhưng không vào semantic_results (S-track).

### Giải pháp đề xuất

**Dual-write sang semantic_findings (recommended — không mất H-track)**

```python
NON_STANDARD_SWC_TO_SEMANTIC = {
    "FLASH_LOAN_PRICE_MANIPULATION": "price_manipulation",
    "DEFI-FLASH_LOAN":               "price_manipulation",
    "DEFI-PRICE_ORACLE":             "price_manipulation",
    "PRICE_ORACLE_STALENESS":        "price_manipulation",
    "DEFI-COMPOSABILITY":            "defi_integration_error",
    "DEFI-LIQUIDATION":              "defi_liquidation_error",
    "DEFI-ORACLE":                   "price_manipulation",
    "DEFI-FRONT_RUNNING":            "front_running",
}

if swc_id in NON_STANDARD_SWC_TO_SEMANTIC:
    session_state.semantic_findings.append({
        "category": NON_STANDARD_SWC_TO_SEMANTIC[swc_id],
        "title": finding.title,
        "evidence": finding.evidence,
        "source_finding_id": finding.finding_id,
    })
    # Finding vẫn được append vào expert_findings như bình thường
```

**Hard requirement:** Mapping table phải import trực tiếp từ `semantic_taxonomy` đã dùng trong `evaluate_web3bugs.py` — single source of truth, không maintain hai bảng song song. Nếu `evaluate_web3bugs.py` thêm category mới, dual-write tự động được hưởng lợi; nếu dùng bảng riêng, sẽ lệch silent và gây FP/FN không giải thích được.

```python
# Đúng — import từ evaluate script để đảm bảo nhất quán:
from backend.app.services.evaluate_web3bugs import SWC_TO_SEMANTIC, SEMANTIC_TAXONOMY
NON_STANDARD_SWC_TO_SEMANTIC = {k: v for k, v in SWC_TO_SEMANTIC.items()
                                  if not k.startswith("SWC-")}
```

**Effort:** ~25 dòng  
**Expected impact:** Contest 3 S-track F1: 0 → ~0.25 (H-03 near-miss → TP)

---

## Vấn đề 5 — Prior context thiếu evidence

**Mức độ:** Medium — agents không thể build on nhau's reasoning  
**Trạng thái:** Chưa đo trực tiếp, đúng về nguyên tắc

### Hiện tượng

Prior context (orchestrator.py:1510–1527) chỉ chứa titles + severity + confidence:
```
[CRITICAL] Reentrancy via transferAsset in fulfill() (by apps/offensive, confidence: 0.70)
```

### Giải pháp đề xuất

```python
# Trong _build_prior_context():
top3 = sorted(windowed, key=lambda f: f["confidence"], reverse=True)[:3]
for f in top3:
    lines.append(f"=== HIGH-CONFIDENCE FINDING ===")
    lines.append(f"[{f['severity'].upper()}] {f['title']}")
    evidence = (f.get('evidence') or [''])[0]
    if evidence:
        lines.append(f"Evidence: {evidence[:400]}")
```

**Token impact:** +~800 tokens/request  
**Effort:** ~15 dòng

---

## Vấn đề 6 — VALIDATE semantic misuse (mới phát hiện)

**Mức độ:** Medium — gây poisoning khi Vấn đề 1 được fix  
**Trạng thái:** 🆕 **Phát hiện trong run thực tế**

### Hiện tượng

Một số agents VALIDATE các CLAIM **âm** (phủ định):

```
VALIDATE [apps_auditor] → claim '`removeUserActiveBlocks()` is not vulnerable to SWC-113 beca...'
VALIDATE [apps_auditor] → claim '`removeUserActiveBlocks()` is miscategorized as SWC-113 beca...'
```

Semantics sai: VALIDATE trên claim nói "không có bug" = xác nhận không có rủi ro. Hiện tại vô hại (target là claim, không có confidence). **Nguy hiểm khi Vấn đề 1 được fix:** nếu CLAIM âm được fuzzy-link sang expert_finding dương, VALIDATE sẽ boost confidence cho finding đúng theo nghĩa ngược lại.

### Giải pháp đề xuất

Guard đặt **trước** bước fuzzy link trong Option A của Vấn đề 1. Keyword matching đơn thuần trên tiêu đề dễ false positive/negative với paraphrase ("this poses no real risk", "the guard prevents"). Hướng đáng tin cậy hơn: phát hiện negation trong mệnh đề "because..." của CLAIM thay vì toàn bộ title:

```python
def _claim_is_negative(claim: dict) -> bool:
    """True nếu CLAIM phủ định vulnerability (không nên propagate sang finding)."""
    text = _normalize(claim.get("title", "") + " " + claim.get("content", ""))

    # Pattern 1: negation trực tiếp trong title
    TITLE_NEGATIONS = ("not vulnerable", "no risk", "is safe", "is not exploitable",
                       "cannot be exploited", "miscategorized", "false positive")
    if any(s in text for s in TITLE_NEGATIONS):
        return True

    # Pattern 2: mệnh đề "because" bắt đầu bằng negation
    # CLAIM format: "<func> may be vulnerable because <reason>"
    because_idx = text.find(" because ")
    if because_idx != -1:
        reason = text[because_idx + 9:].strip()
        REASON_NEGATIONS = ("it does not", "there is no", "the guard", "already protected",
                            "not possible", "no way", "impossible")
        if any(reason.startswith(s) for s in REASON_NEGATIONS):
            return True
    return False

# Trong fuzzy link loop, trước khi gán kind/target:
if _claim_is_negative(target):
    continue
```

**Tradeoff:** Vẫn có thể bỏ sót negation phức tạp ("the reentrancy guard makes this unfeasible"). Nếu cần độ chính xác cao hơn, ghi log những trường hợp bị skip để review thủ công.

**Effort:** ~15 dòng, gắn liền với fix Vấn đề 1

---

## Vấn đề 7 — S-track FP tăng sau two-stage (mới phát hiện)

**Mức độ:** Medium — S-track F1 regression: 0.667 → 0.500  
**Trạng thái:** 🆕 **Phát hiện qua so sánh kết quả**

### Hiện tượng

| | Baseline | Two-Stage |
|--|---------|-----------|
| Raw semantic findings | ~2 | **5** |
| Semantic results trong report | 1 (P=1.000) | 2 (P=0.500) |
| Extra FP | 0 | 1 ("Bank Run Risk", category=other) |

5 raw semantic findings từ state: 2 `other` (Bank Run Risk), 2 `access_control`, 1 `business_flow` — sau deduplication report chỉ giữ 2.

### Root cause

Chưa xác định rõ. Hypothesis: CLAIM mechanism khuyến khích agents explore rộng hơn → nhiều findings đa dạng hơn → nhiều semantic findings hơn → thêm FP vào S-pool. Category `other` không mapped với bug nào trong ground truth.

### Giải pháp đề xuất

**Option A — Giữ `other` trong report nhưng exclude khỏi F1 pool (recommended)**

Drop toàn cục `other` mất thông tin có giá trị cho auditor người. Thay vào đó, đánh nhãn và exclude khỏi eval:

```python
EVAL_CATEGORIES = {"access_control", "price_manipulation", "reentrancy",
                   "front_running", "business_flow", "state_machine_bug",
                   "defi_integration_error", "defi_liquidation_error"}

for r in semantic_results:
    r["exclude_from_eval"] = r["category"] not in EVAL_CATEGORIES
    if r["exclude_from_eval"]:
        r["display_label"] = "[UNCLASSIFIED]"  # hiển thị rõ trong report
```

F1 calculation chỉ tính những entries có `exclude_from_eval = False`. Auditor người vẫn thấy `[UNCLASSIFIED]` findings trong report.

**Option B — Tăng confidence threshold cho semantic_results**

Chỉ đưa vào report semantic findings có confidence ≥ threshold. Hiện tại confidence=0.00 cho tất cả semantic findings — cần fix confidence assignment trước, nên là giải pháp dài hạn hơn.

**Effort:** ~8 dòng (cả eval filter + report label)  
**Expected impact:** S-track F1: 0.500 → ~0.667 (khôi phục baseline) mà không mất thông tin

---

## Vấn đề 8 — Attacker CONFIRM quá dễ dãi, không filter FP

**Mức độ:** Low–Medium — Phase C không phân biệt được TP/FP  
**Trạng thái:** 🆕 **Phát hiện qua phân tích attacker_corroborations**

### Hiện tượng

Tất cả 4 reentrancy findings (SWC-107) đều nhận CONFIRM từ 4 attackers (delta +0.03 mỗi) → confidence 0.82–0.87. Nhưng SWC-107 reentrancy không có trong ground truth contest 19 (là FP thực sự).

Attacker phase hiện tại không phân biệt TP/FP — tất cả reentrancy đều được confirm, không có discriminant.

### Liên hệ với FP Reduction Plan

Đây là biểu hiện cụ thể của vấn đề đã nhận diện trong `project_fp_reduction_plan.md`: attacker gate multiplier cần có threshold để penalize findings bị DISMISS bởi majority, thay vì chỉ cộng dồn delta flat.

### Giải pháp đề xuất

Data thực tế cho thấy vấn đề phức tạp hơn: `logic_exploiter` vừa CONFIRM (+0.03) vừa DISMISS (−0.20) cùng một finding trong cùng session. Flat delta cộng dồn → net effect phụ thuộc thứ tự và số lần vote, không phản ánh consensus thực.

**Weighted gate dựa trên net vote ratio:**

```python
# Sau Phase C, trước khi finalize confidence — áp dụng 1 lần per finding:
def _apply_attacker_gate(finding: dict, n_attackers: int = 5):
    corrs = finding.get("attacker_corroborations", [])
    if not corrs:
        return

    # Dedup: mỗi attacker chỉ tính vote cuối cùng
    last_vote = {}
    for c in corrs:
        last_vote[c["profile_id"]] = c["action"]

    confirms = sum(1 for a in last_vote.values() if "CONFIRM" in a)
    dismisses = sum(1 for a in last_vote.values() if "DISMISS" in a)
    net_ratio = (confirms - dismisses) / n_attackers  # range [-1, 1]

    if net_ratio <= -0.4:          # majority DISMISS
        finding["confidence"] = max(0.1, finding["confidence"] * 0.70)
    elif net_ratio >= 0.6:         # strong CONFIRM
        finding["confidence"] = min(0.95, finding["confidence"] * 1.15)
    # Neutral zone: không thay đổi
```

**Lý do dùng last_vote thay vì tổng:** nếu cùng attacker CONFIRM ở round 8 rồi DISMISS ở round 9, vote cuối (DISMISS) phản ánh đánh giá cuối cùng sau khi có thêm context — cộng dồn cả hai sẽ cancel nhau sai.

**Effort:** ~25 dòng trong `_attach_corroboration()` hoặc thêm `_finalize_attacker_gate()` gọi sau Phase C

---

## Kế hoạch hành động (cập nhật sau run thực tế)

| Priority | Vấn đề | Action | Effort | Expected Impact |
|----------|--------|--------|--------|-----------------|
| **P1** | VALIDATE propagation (#1) + semantic guard (#6) | Fuzzy link với ngưỡng Jaccard + negation detection trong "because" clause | ~45 dòng | Confidence calibration thực sự |
| **P2** | Stage 2 truncation (#2) | `STAGE2_MAX_TOKENS=8192` kèm điều chỉnh `SUBMIT_DELAY_S` Stage 2; benchmark 429 before/after | ~15 dòng + tuning | Evidence quality, unblocks CHALLENGE |
| **P3** | S-track FP (#7) | Giữ `other` với nhãn `[UNCLASSIFIED]`, exclude khỏi F1 pool qua `exclude_from_eval` | ~8 dòng | S-track F1: 0.500 → 0.667, không mất thông tin |
| **P4** | CHALLENGE quá ít (#3) | Designated skeptic: 1 agent/round có full mandate CHALLENGE | ~15 dòng | FP reduction (phụ thuộc P2) |
| **P5** | Non-standard SWC (#4) | Dual-write từ `SWC_TO_SEMANTIC` của evaluate script (single source of truth) | ~25 dòng | S-track TP cho DeFi contests |
| **P6** | Attacker gate (#8) | Net vote ratio (last_vote dedup) + multiplier gate | ~25 dòng | FP reduction Phase C |
| **P7** | Prior context (#5) | Top-3 full evidence in context | ~15 dòng | TP coverage |

> **P2 là điều kiện tiên quyết cho P4:** CHALLENGE multi-line không hoàn chỉnh khi Stage 2 bị truncate — designated skeptic cũng bị ảnh hưởng.  
> **P3 là quick win độc lập:** không có dependency, khôi phục S-track regression ngay.  
> **P1 + P6 cần phối hợp:** khi VALIDATE propagation hoạt động, attacker gate cần calibrate lại để hai cơ chế không conflict.

**Không nên làm:** Migrate sang true OASIS library — phân tích chi tiết trong `docs/oasis-communication-analysis.md` §3.

---

## Ghi chú về thiết kế two-stage

Two-stage giải quyết đúng vấn đề **ordering trap**. CLAIMs hoạt động (~50/round, ổn định qua 7 rounds). Vấn đề cốt lõi là **feedback loop** chưa close: 100% VALIDATE target CLAIMs (không có confidence), 0% target expert_findings.

Cải thiện Combined F1 (+0.067) trong run này đến từ **ít findings hơn** (19 vs 35) chứ không từ cơ chế VALIDATE/CHALLENGE. Đây là tín hiệu tốt về chất lượng Stage 1 filtering, nhưng chưa validate được thiết kế two-stage.

**Fix tối thiểu để two-stage có giá trị đo được:** P1 (VALIDATE propagation) + P2 (Stage 2 tokens) + P3 (S-track filter).
