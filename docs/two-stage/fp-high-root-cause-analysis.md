# High FP Root Cause: Cross-Validation Không Có Tác Dụng

**Ngày**: 2026-04-26 · **Cập nhật**: 2026-04-26 (làm rõ số liệu validate, H-01, tách L-track, liên kết doc)  
**Contest**: Web3Bugs Contest 19 — Option A run  
**Vấn đề**: FP = 8 với 3 consensus_vulns + 5 swc_gaps, dù agents có thể đọc và phản hồi nhau

---

## 1. Kỳ vọng vs Thực tế

**Kỳ vọng**: Multi-agent với Stage 2 CHALLENGE/VALIDATE + Phase C attacker review → FP bị loại bỏ dần qua các round.

**Thực tế** — dữ liệu từ run `20260425_200440` (19 expert findings, 10 rounds):

```
Findings với challenge_count > 0:  1 / 19  (5%)
Findings với validate_count > 0:   5 / 19  (26%)
Findings với cross_domain_validated: 0 / 19  (0%)
```

Chỉ 1 finding được challenge (là finding conf=0.30 — đã thấp sẵn). 13/19 findings không có bất kỳ signal nào từ Stage 2. Sau 10 round, FP vẫn là 8.

**Ghi chú số liệu:** `validated_by` trên `expert_finding` chỉ tăng khi VALIDATE/CHALLENGE **target một finding** (không phải CLAIM). Trong cơ chế two-stage, phần lớn VALIDATE trỏ **CLAIM** → `cross_domain_validated` trên expert có thể = 0 dù nhiều bài VALIDATE. `validate_count` trên từng **expert_finding** cần đối chiếu script thống kê; không tự suy từ log DEBUG alone.

---

## 2. Nguyên nhân gốc rễ

### 2.1 [CRITICAL] ConsensusEngine KHÔNG sử dụng challenge/validate signals

Đây là bug kiến trúc quan trọng nhất.

`_parse_challenge_validate()` ghi `challenged_by` và `validated_by` vào từng `expert_finding`. Nhưng khi `ConsensusEngine._score_cluster()` tính confidence, nó **hoàn toàn bỏ qua** hai trường này:

```python
# ConsensusEngine._score_cluster() — toàn bộ logic tính confidence:
intra_score  = groups_with_multiple / total_groups_in_cluster  # đếm author_domain
cross_score  = len(unique_groups) / domain_group_count          # đếm unique author_domain
attacker_score = self._calc_attacker_score(all_corr)            # attacker_corroborations

expert_confidence = intra_score * WEIGHT_INTRA + cross_score * WEIGHT_CROSS
confidence = expert_confidence * gate  # gate từ attacker
```

`challenged_by`, `validated_by`, `cross_domain_validated` — **không có dòng nào đọc các field này**.

ConsensusEngine tính confidence **từ đầu** dựa trên số lượng agents report cùng finding (clustering). Việc agents challenge hay validate trong Stage 2 **không có bất kỳ tác động nào** lên final confidence score trong consensus.

**Hệ quả**: Nếu 3/7 domain groups đều report cùng một FP (vì họ cùng bị mislead bởi contract code), confidence = 0*0.40 + (3/7)*0.60 = 0.257... thực ra không đủ. Nhưng nếu 4/7 groups: 0 + (4/7)*0.60 = 0.343 ≈ MIN_CONFIDENCE. Dù 10 agents challenge finding đó, nó vẫn vào consensus.

### 2.2 [HIGH] Delta confidence trong orchestrator không đến được ConsensusEngine

`_parse_challenge_validate()` có thực hiện delta:

```python
# VALIDATE → +0.08 trên individual finding
target["confidence"] = min(0.95, target.get("confidence", 0.5) + 0.08)

# CHALLENGE → -0.10 trên individual finding  
target["confidence"] = max(0.1, target.get("confidence", 0.5) - 0.10)
```

Nhưng `ConsensusEngine` **không đọc `confidence` từ raw expert_finding**. Nó tự tính lại từ intra/cross score. Delta này chỉ tồn tại trong `session_result.json` nhưng không feed vào `audit_report.json`.

### 2.2b [MEDIUM] `_apply_attacker_gate()` (P8) trong orchestrator — chỉ khi đã có vote

Hàm `cyber_session_orchestrator._apply_attacker_gate()` lặp từng `expert_finding` và **bỏ qua** (`continue`) nếu `attacker_corroborations` rỗng. Nghĩa là: **không** có cơ hội hạ/ tăng confidence sau Phase C nếu finding chưa hề nhận bất kỳ hành động attacker nào. Nó bổ sung (không mâu thuẫn) mục 2.3: gate trung tính trong `ConsensusEngine` + không chỉnh post-hoc trên session khi zero corroboration.

### 2.3 [HIGH] Attacker gate = NEUTRAL cho findings không được review

```python
ATTACKER_GATE_NEUTRAL = 1.00   # không bị phạt gì khi attacker không review
```

Phase C có 5 attacker profiles. Mỗi attacker xử lý toàn bộ finding list bằng cách target theo SWC ID. Trong run này:

- **Attacker findings**: 0 (không có finding nào được attackers tạo mới)
- **Attacker corroborations trên expert_findings**: không được log

Tức là nếu attacker không explicitly target một finding → `all_corr = []` → `gate = ATTACKER_GATE_NEUTRAL = 1.00` → finding tồn tại với full confidence. Không có penalty cho việc "không được verify".

### 2.4 [MEDIUM] Stage 2 agents viết FINDING mới thay vì CHALLENGE/VALIDATE

Nhìn vào prompt Stage 2:

```
"Now write your structured output:
  - FINDING / SEMANTIC_FINDING: new vulnerabilities from YOUR domain
  - VALIDATE_FINDING: confirm a Stage 1 CLAIM or prior-round finding
  - CHALLENGE_FINDING: dispute a Stage 1 CLAIM or prior-round finding"
```

Thứ tự ưu tiên trong prompt là FINDING trước, CHALLENGE/VALIDATE sau. Agents có xu hướng viết thêm FINDING thay vì review CLAIMs của peer. Kết quả: Stage 2 tạo ra thêm FP thay vì loại bỏ FP.

### 2.5 [MEDIUM] CHALLENGE/VALIDATE link rate thấp do title matching strict

`_find_target()` dùng substring match:
```python
if frag in _normalize(c["title"]):  # exact substring
```

Nếu agent viết `CHALLENGE_FINDING: ERC20 approve race` nhưng CLAIM title là `ERC20 approve() race condition within fulfill()` → không match (`race` không phải substring của `race condition within fulfill()`). Finding không bị challenge dù agent có cố gắng.

### 2.6 [LOW] Attacker gate trong orchestrator (P8) — ngưỡng cao, và chỉ chạy khi có `corrs`

Xem 2.2b: cần **ít nhất một** bản ghi trong `attacker_corroborations` thì mới tính `net_ratio` và áp hệ số. `_apply_attacker_gate()`:
```python
net_ratio = (confirms - dismisses) / n_attackers
if net_ratio <= -0.4:   # cần ≥3/5 attackers dismiss
    confidence *= 0.70
elif net_ratio >= 0.6:  # cần ≥4/5 attackers confirm
    confidence *= 1.15
```

Threshold ≥40% dismiss để penalize là khá cao. Trong thực tế, attacker focus vào SWC-107 (reentrancy) và bỏ qua các FP về SWC-102/SWC-105 → không đủ dismisses để kích hoạt penalty. Run `200440` còn có **0** attacker output đáng kể lên nhiều finding → tầng này gần như không tác động.

### 2.7 [INFO] Tách biệt với L-track miss (FN H-02 / SWC-128)

**Nhiễu L-pool (nhiều FP, peer review vô hiệu)** và **mất TP trên L** (không có `SWC-128` trên `consensus_vulns` ∪ `unvalidated_swc_gaps` theo `evaluate_web3bugs.py`) là **hai trục độc lập**.

- Sửa Fix-CV1…CV4 (giảm FP, đưa CHALLENGE/VALIDATE vào engine) **không** tự đảm bảo có bản ghi L4 = SWC-128 nếu agent không tạo finding/gap đúng nhãn.
- Phân tích chi tiết **FN L / thiếu SWC-128** xem [`l-track-miss-analysis.md`](l-track-miss-analysis.md); phân tích **chất lượng báo cáo** run tương tự: [`contest19-report-quality-latest-run.md`](contest19-report-quality-latest-run.md).

---

## 3. Pipeline thực tế vs Pipeline kỳ vọng

```
                    PIPELINE HIỆN TẠI
─────────────────────────────────────────────────────────────────────
Stage 1 (17 agents)  →  CLAIMs
Stage 2 (17 agents)  →  FINDINGs mới + CHALLENGE/VALIDATE
                          ↓              ↓
                     expert_findings  challenged_by/validated_by
                          ↓              ↓
                     ConsensusEngine  [IGNORED ❌]
                          ↓
                     consensus_vulns (intra+cross score only)
                          ↓
                     Attacker gate (NEUTRAL nếu không review = 1.0x)
                          ↓
                     audit_report (FP vẫn cao)
─────────────────────────────────────────────────────────────────────

                    PIPELINE KỲ VỌNG
─────────────────────────────────────────────────────────────────────
Stage 2 CHALLENGE  →  giảm confidence finding bị challenge
Stage 2 VALIDATE   →  tăng confidence finding được validate
ConsensusEngine    →  đọc challenge_count, validate_count trong scoring
Attacker gate      →  penalty cho findings không được attacker review
                       (NEUTRAL ≠ 1.0, nên là ~0.8 hoặc 0.75)
─────────────────────────────────────────────────────────────────────
```

---

## 4. Minh chứng định lượng

| Finding / hướng | conf | challenged | validated | Vào report? | Ghi chú (GT contest 19) |
|---------|------|-----------|----------|----------------|----------------|
| `ERC20 approve() race…` (ví dụ) | 0.70 | 0 | 2* | ✓ consensus (SWC-114) | FP trên **track L** (in-scope L = H-02 / 128) |
| `address(0)` / ecrecover | 0.70 | 0 | 0 | ✓ (SWC-122) | FP (L) |
| `OZ dependency` / pragma | 0.50 / 0.30 | 0 / **1** | … | gap / consensus | FP (L) |
| Hướng **H-01** — access / `prepare()` (semantic `access_control`, không dùng SWC cho S eval theo Policy A) | — | — | — | `semantic_results` | **TP (S2-1 / H-01)**, *khác* track L |

\*Số lần validate trên **finding**; có thể khác tổng số bài VALIDATE (nhiều cái trỏ **CLAIM**).

Dòng bị challenge rõ thường là finding điển hình kiểu **Floating pragma** (conf thấp) — 1 lần CHALLENGE thường **không** đủ kéo cluster xuống dưới `MIN_CONFIDENCE` nếu `ConsensusEngine` vẫn bỏ qua peer signal.

**Tránh nhầm nhãn H-01:** H-01 (Web3Bugs) tương ứng **S2-1 / access_control** (vd. thiếu ràng buộc caller trên `prepare()`), **không** nên tóm tắt bằng *“reentrancy in prepare”* nếu ground truth và `bugs.csv` không gắn reentrancy — bảng trên dùng “hướng H-01” thay vì thuộc tính kỹ thuật sai tên.

---

## 5. Đề xuất giải pháp

### Fix-CV1: Đưa challenge/validate signals vào ConsensusEngine *(P0 — critical)*

Thêm Layer 4 (peer review) vào scoring formula:

```python
# Trong _score_cluster():
challenge_count = sum(len(f.get("challenged_by", [])) for f in cluster)
validate_count  = sum(len(f.get("validated_by", []))   for f in cluster)

# Peer review adjustment
peer_delta = min(validate_count, 5) * 0.03 - min(challenge_count, 5) * 0.05

# Final confidence với peer signal
confidence = (expert_confidence + peer_delta) * gate
confidence = max(0.0, min(1.0, confidence))
```

Tác dụng:
- 3 challenges trên 1 finding → −0.15 → finding conf=0.50 giảm xuống 0.35 = MIN_CONFIDENCE → bị lọc ra
- 5 validates → +0.15 → tăng confidence genuine finding

### Fix-CV2: Hạ ATTACKER_GATE_NEUTRAL xuống 0.75 *(P1)*

Findings không được attacker review nên bị giảm confidence 25%:

```python
ATTACKER_GATE_NEUTRAL = 0.75   # thay vì 1.00
```

Tác dụng: Finding chỉ dựa vào expert agreement (cross_score=0.60) nhưng không được attacker verify → max confidence = 0.60 * 0.75 = 0.45. Vẫn qua MIN_CONFIDENCE=0.35, nhưng chỉ 1 finding attacker DISMISS sẽ kéo xuống 0.45*0.40=0.18 → bị lọc.

**Rủi ro**: Giảm recall nếu attacker Phase C coverage thấp → cần benchmark trên nhiều contest.

**Mâu thuẫn thiết kế hiện tại:** Trong `consensus_engine.py`, `ATTACKER_GATE_NEUTRAL = 1.0` **có chủ ý** (chú thích: tránh lọc quá mạnh khi Phase C ít tương tác). Hạ xuống 0.75 **đi ngược** mặc định đó; cần A/B nhiều contest và cân nhắc **chỉ hạ NEUTRAL** khi `stats.total_attacker_findings` / coverage đảm bảo tối thiểu.

### Fix-CV3: Đảo thứ tự prompt Stage 2 — CHALLENGE trước FINDING *(P1)*

Thay:
```
"- FINDING / SEMANTIC_FINDING: new vulnerabilities...
 - VALIDATE_FINDING: confirm...
 - CHALLENGE_FINDING: dispute..."
```

Thành:
```
"Priority 1 — CHALLENGE_FINDING hoặc VALIDATE_FINDING (bắt buộc ít nhất 1):
   ...
Priority 2 — Chỉ viết FINDING mới nếu không có gì để challenge/validate."
```

Tác dụng: Challenge rate tăng từ 5% lên ước tính 40–60%.

### Fix-CV4: Fuzzy title matching trong _find_target() *(P1)*

Thay substring exact match bằng Jaccard token overlap:

```python
def _find_target(title_fragment: str):
    frag_tokens = set(_normalize(title_fragment).split())
    best, best_score = None, 0
    for c in stage1_claims:
        claim_tokens = set(_normalize(c["title"]).split())
        overlap = len(frag_tokens & claim_tokens) / max(len(frag_tokens | claim_tokens), 1)
        if overlap > best_score:
            best, best_score = c, overlap
    if best_score >= 0.30:  # Jaccard ≥ 0.30
        return ("claim", best)
    ...
```

Tác dụng: Link rate tăng từ ~26% lên ước tính 60–70%.

### Fix-CV5: Mandatory CHALLENGE quota cho Skeptic *(P2)*

Skeptic agent hiện có instruction nhưng không có enforcement. Thêm parser check:

```python
if profile.agent_id == skeptic_id:
    challenge_count = len(re.findall(r'(?i)^CHALLENGE_FINDING\s*:', response, re.MULTILINE))
    if challenge_count < 2:
        logger.warning(f"Skeptic {profile.agent_id} wrote only {challenge_count} challenges")
        # Option: retry với stricter instruction
```

### Fix-CV6: Attacker review coverage gate *(P2)*

Nếu một finding có confidence > 0.60 nhưng **zero attacker corroboration** sau Phase C → downgrade severity một bậc (high → medium):

```python
for v in consensus_vulns:
    if v.confidence_score > 0.60 and not v.supporting_attackers and not v.dismissing_attackers:
        v.needs_review = True
        v.severity = downgrade_severity(v.severity)  # high → medium
```

---

## 6. Thứ tự ưu tiên

| # | Fix | Impact FP | Effort | Rủi ro recall |
|---|-----|-----------|--------|---------------|
| P0 | **Fix-CV1**: challenge/validate → ConsensusEngine | Cao | Trung bình | Thấp |
| P1 | **Fix-CV3**: đảo thứ tự prompt Stage 2 | Trung bình | Thấp | Không có |
| P1 | **Fix-CV4**: fuzzy title matching | Trung bình | Thấp | Không có |
| P2 | **Fix-CV2**: ATTACKER_GATE_NEUTRAL = 0.75 | Cao | Thấp | Trung bình |
| P2 | **Fix-CV5**: Skeptic enforcement | Thấp | Thấp | Không có |
| P3 | **Fix-CV6**: Attacker coverage gate | Thấp | Thấp | Trung bình |

---

## 7. Kết luận

**Agents đọc được nhau nhưng phản hồi peer review (CHALLENGE/VALIDATE) không vào công thức `ConsensusEngine._score_cluster()`** — tương đương “/dev/null” với tầng consensus.

Cụ thể:
- `challenged_by` / `validated_by` trên `expert_finding` **không** tham gia tính `confidence_score` cluster; thống kê này khiến **L-pool** dễ dày **FP** (nhiễu SWC) khi nhiều domain đồng thuận nhầm.
- `ATTACKER_GATE_NEUTRAL = 1.0` + run thiếu corroboration → **không** giảm giả định expert khi Phase C rỗng; `_apply_attacker_gate` còn **không chạy** nếu `attacker_corroborations` rỗng.
- Prompt Stage 2 ưu tiên FINDING mới so với review → dễ **thêm** hạt giả, không lọc FP ở tầng agent.

**Liên hệ với mất recall L (H-02 / SWC-128):** Giảm FP (Fix-CV1…) **không** thay thế việc agent phải sinh bản ghi khớp **L-pool theo eval**; xem [`l-track-miss-analysis.md`](l-track-miss-analysis.md).

Ba fix (Fix-CV1, Fix-CV3, Fix-CV4) ước tính giảm số mục nhiễu trong L-pool / cải thiện **precision**; **recall L** cần theo dõi riêng sau khi sửa (và không được suy từ FP paper một chiều).
