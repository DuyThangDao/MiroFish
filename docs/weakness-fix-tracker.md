# Weakness Fix Tracker

> Tracking tiến độ khắc phục các điểm yếu trong [coverage-gaps-analysis.md](coverage-gaps-analysis.md)
> Scenario tham chiếu: `sme_no_tools`, 10 rounds, 13 domain expert agents

---

## Tổng quan

| # | Điểm yếu | Status | Priority |
|---|-----------|--------|----------|
| 1 | [CVE Attention Bias](#1-cve-attention-bias) | ✅ Partial (control gaps fixed) | High |
| 2 | [Consensus Threshold Lọc Mất Control-Gap Findings](#2-consensus-threshold) | ✅ Fixed (B-dynamic + D enforcement) | Medium |
| 3 | [Host Blind Spots](#3-host-blind-spots) | ✅ Fixed (bởi cơ chế GAP) | High |
| 4 | [Duplicate Findings Inflate Count](#4-duplicate-findings) | ✅ Fixed (Published Registry) | High |
| 5 | [MITRE Techniques Không Được Populate](#5-mitre-techniques) | ✅ Đã giải quyết | Medium |

---

## 1. CVE Attention Bias

**Mô tả:** Agents tập trung vào CVE nổi bật nhất, bỏ qua missing controls và hosts không có CVE.

**Sub-problems:**

| Sub | Vấn đề | Status |
|-----|--------|--------|
| 1a | Host blind spots — MAIL-01, FW-01 nhận 0 findings | ✅ Đã giải quyết (bởi GAP routing) |
| 1b | Control gap blind spots — SIEM, MFA, DLP, NDR = 0 findings | ✅ Đã giải quyết (bởi GAP routing) |
| 1c | CVE over-representation — tỉ lệ findings cùng 1 CVE cao | ⬜ Chưa giải quyết |

**Giải pháp đã triển khai (cho 1a + 1b):**

**Delphi-Inspired GAP Declaration Mechanism** — Mỗi Tier-1 agent bắt buộc khai báo `ANALYZED: <host/control>` và `GAP: <lý do không thể đánh giá>` cuối mỗi bài post. Các GAP được parse, routing theo từ khóa sang domain group phù hợp, và inject vào context của agent nhận trong round tiếp theo.

Kết quả trên `test_gap_v2`:
- Control gap coverage: **3/7 → 7/7** ✅
- MFA findings: 0 → 11, SIEM: 0 → 14, DLP: 0 → 3, NDR: 0 → 10
- GAP declarations generated: **127**

→ Tài liệu chi tiết: [docs/contributions/delphi-gap-declaration.md](contributions/delphi-gap-declaration.md)

**Còn lại (1c — CVE over-representation):**

Chưa triển khai. Các phương án đề xuất (từ `coverage-gaps-analysis.md`):
- **A.** Structured Coverage Checklist trong system prompt (per-host checklist)
- **B.** Per-host assignment — assign cứng host cho từng agent trong Phase A
- **C.** Diversity penalty trong ConsensusEngine scoring

---

## 2. Consensus Threshold

**Mô tả:** ConsensusEngine yêu cầu `cross_group_score` cao, penalize các "absence of X" findings chỉ được 1 domain group phát hiện.

**Status:** ✅ Đã giải quyết

**Giải pháp đã triển khai:** **B-dynamic Semantic Anchor Clustering (both-title rule) + D Post-consensus Enforcement**

- B: cluster findings chia sẻ control keyword (siem, mfa…) hoặc host ID trong **cả hai titles** (both-title rule), anchors derive tự động từ `SecurityControls` dataclass + `affected_assets`
- D: sau consensus, collect standard controls chưa được cover vào section `unvalidated_control_gaps`

Kết quả `test_gap_v4`: 13 consensus vulns (tốt nhất), 7/7 control coverage, DLP bắt bởi D section, report 22,212 chars. Over-clustering (v3) đã được fix bằng both-title rule.

→ Tài liệu: [docs/contributions/semantic-clustering-coverage.md](contributions/semantic-clustering-coverage.md)

**Giải pháp đề xuất thêm (chưa làm):**
- **A.** Phân loại `finding_type: "control_gap" | "vulnerability"` + công thức scoring riêng cho từng loại
- **C.** Attacker boost cho control-gap findings được Phase C confirm

---

## 3. Host Blind Spots

**Mô tả:** Hosts không có CVE cụ thể (MAIL-01, FW-01) nhận 0 findings dù là hạ tầng quan trọng.

**Status:** ✅ Đã giải quyết

**Giải pháp đã triển khai:** Giải quyết đồng thời bởi GAP Declaration Mechanism (xem Điểm yếu 1).

`appsec` declare `GAP: Cannot assess MAIL-01 Postfix` → routed đến `network_security` → phân tích MAIL-01 như attack surface.

→ Tài liệu: [docs/contributions/delphi-gap-declaration.md §4.2](contributions/delphi-gap-declaration.md)

---

## 4. Duplicate Findings

**Mô tả:** ~50% raw findings là near-duplicates. Wasted LLM calls, biased consensus.

**Status:** ✅ Đã giải quyết

**Giải pháp đã triển khai:** **Published Finding Registry**

Sau mỗi round, inject vào context của mỗi agent danh sách unique finding titles đã được report (tối đa 20 entries). Agents được hướng dẫn CHALLENGE hoặc EXPAND thay vì duplicate.

Thực trạng v4 trước fix: 33 duplicate pairs (Jaccard ≥ 0.5), 76% là intra-group. Solution B (pre-scoring dedup) bị loại vì risk drop thông tin quan trọng.

→ Tài liệu: [docs/contributions/published-registry.md](contributions/published-registry.md)

**Giải pháp không chọn:**
- **B** (pre-scoring dedup) — risk mất thông tin, không giảm chi phí LLM thực sự
- **C** (CROSS_VALIDATE tag) — effort cao, để dành cho sau

---

## 5. MITRE Techniques

**Mô tả:** Tất cả consensus vulnerabilities có `mitre_techniques: []`. MITRE ATT&CK mapping bị mất hoàn toàn.

**Status:** ✅ Đã giải quyết

**Root cause thực sự (hai lớp bug):**
1. `parse_expert_finding_from_text()` thiếu case parse `MITRE:` field — v6 fix
2. `_process_expert_response()` hardcode `mitre_techniques=[]` bỏ qua output của parser — v7 fix
3. Agents KHÔNG viết `MITRE:` dạng field riêng — họ nhúng inline trong prose ("aligns with T1190") — v8 fix

**Giải pháp đã triển khai (v6+v7+v8):**
```python
# v6: Thêm MITRE: field parser
elif stripped.lower().startswith("mitre:"):
    mitre_raw = stripped.split(":", 1)[1].strip()
    mitre_techniques = re.findall(r'T\d{4}(?:\.\d{3})?', mitre_raw)

# v8: Fallback full-text scan khi không có MITRE: field
if not mitre_techniques:
    mitre_techniques = list(dict.fromkeys(re.findall(r'\bT\d{4}(?:\.\d{3})?\b', text)))
```

**Kết quả v7 (patched):** 12/13 consensus vulns có MITRE, 19 unique techniques

**Giải pháp không chọn:**
- **Fallback keyword mapping** — hardcode dễ sai context, cần maintain

---

## Lịch sử thay đổi

| Ngày | Thay đổi |
|------|----------|
| 2026-04-07 | Baseline test (`test_paid`): 36 findings, CVE 47%, control 3/7, report 550 chars |
| 2026-04-07 | v1 test (`test_gap_v1`): GAP format thêm vào PHASE_CONFIG nhưng chưa wire code |
| 2026-04-07 | v2 test (`test_gap_v2`): GAP mechanism đầy đủ — control 7/7, 127 declarations, report 16,575 chars |
| 2026-04-07 | Switch LLM từ AI Studio → Vertex AI (service account JSON, auto token refresh) |
| 2026-04-07 | B+D triển khai: semantic anchor clustering + post-consensus enforcement |
| 2026-04-07 | v3 test (`test_gap_v3`): B+D OR-title rule — over-clustering (12→4 vulns), avg conf 0.74. |
| 2026-04-07 | Fix both-title rule trong `_shares_anchor` — ngăn compound findings làm hub. |
| 2026-04-07 | v4 test (`test_gap_v4`): B+D both-title — 13 consensus vulns, 7/7 controls, DLP in D section, report 22,212 chars. ✅ |
| 2026-04-07 | Published Registry triển khai — inject unique finding titles vào agent context, hướng dẫn CHALLENGE/EXPAND thay vì duplicate |
| 2026-04-07 | v5 test (`test_gap_v5`): Registry active — dups ≥0.5 giảm 79% (33→7), findings 81→64 (-21%), consensus 11 vulns, D catches MFA+DLP. ✅ |
| 2026-04-07 | MITRE parser fix (v6) — thêm case `MITRE:` vào `parse_expert_finding_from_text()`. Root cause: missing parser case. |
| 2026-04-07 | v7 test (`test_gap_v7`): 13 consensus vulns, F1=0.93. MITRE vẫn 0 do orchestrator hardcode `mitre_techniques=[]`. |
| 2026-04-07 | Fix orchestrator bug — `_process_expert_response()` dùng `finding_raw.get("mitre_techniques", [])` thay vì `[]`. |
| 2026-04-07 | Fix MITRE fallback scan — agents không viết `MITRE:` field, viết inline trong prose. Thêm `re.findall` trên full finding text. |
| 2026-04-07 | v7 patched (re-consensus): 12/13 vulns có MITRE, 19 unique techniques. ✅ |
| 2026-04-07 | v8 test (`test_gap_v8`): 14 consensus vulns, F1=0.96 (best), R=1.00, P=0.93. 13/14 vulns có MITRE, 20 unique techniques. ✅ |
