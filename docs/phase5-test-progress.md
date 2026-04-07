# Phase 5 — Test Progress

> Cập nhật lần cuối: 2026-04-07

---

## Tổng quan

```
✅ Test 1 — TTP Library
✅ Test 2 — TTP Context Diversity
✅ Test 3 — Build Network Graph
✅ Test 4 — Generate 18 Agent Profiles
✅ Test 5 — Full Pipeline (script)
✅ Test 6 — Verify Output Quality
```

**Phase 5 HOÀN THÀNH** ✅

---

## Test 1 — TTP Library ✅

**Endpoint**: `GET /api/cyber/ttp-library`

| Check | Kết quả |
|-------|---------|
| Tổng số TTPs | 20 ✅ |
| Filter theo domain (`network_security`) | 7 TTPs ✅ |
| Detail lookup (`/ttp-library/T1190`) | name, tactic, required_detection_tools đúng ✅ |

---

## Test 2 — TTP Context Diversity ✅

**Endpoint**: `POST /api/cyber/ttp-library/context`

| Check | Kết quả |
|-------|---------|
| `network_security / offensive` | Có "Attack angle" ✅ |
| `network_security / defensive` | Có "Defense focus" ✅ |
| Hai context KHÁC nhau | ✅ |

---

## Test 3 — Build Network Graph ✅

**Endpoint**: `POST /api/cyber/setup`

| Check | Kết quả |
|-------|---------|
| Task completed | ✅ |
| asset_count | 2 (WEB-01 DMZ, DB-01 Database) ✅ |
| `/graph/<id>/assets` | trả về đúng ✅ |
| `/graph/<id>/attack-surface` | 2 hosts (missing_edr_or_siem) ✅ |

**graph_id test**: `mirofish_12d1c00abd734af7`

**Bugs phát hiện và đã fix**:
1. `network_topology_builder.py:417` — `chunk_overlap=50` → `overlap=50` (wrong kwarg)
2. `network_topology_builder.py:247` — `node.uuid` không có guard → thêm `hasattr` check
3. `network_topology_builder.py:248` — `controls_str` có thể là `None` → thêm `or ""`

---

## Test 4 — Generate 18 Agent Profiles ✅

**Endpoint**: `POST /api/cyber/agents/generate`

| Check | Kết quả |
|-------|---------|
| tier1_count | 13 ✅ |
| tier2_count | 5 ✅ |
| total | 18 ✅ |
| Tier-1 sample | `netw_offensive`, `netw_defensive` ✅ |
| Tier-2 (5 profiles) | opportunistic, apt, insider_threat, ransomware, supply_chain ✅ |

---

## Test 5 — Full Pipeline via Script ✅

**Model**: Gemini 2.5 Flash (paid tier, GCP $300 credit)
**Config**: `LLM_MAX_WORKERS=5`, `LLM_RPM_LIMIT=0`
**Scenario**: `sme_no_tools`
**Output**: `backend/results/test_paid/`

| Check | Kết quả |
|-------|---------|
| 10/10 rounds hoàn thành | ✅ |
| Phase A → B → C đầy đủ | ✅ |
| 145 feed posts (13×3 + 13×4 + 18×3) | ✅ |
| 36 expert findings được parse | ✅ |
| Checkpoint saved/removed đúng | ✅ |
| Tổng thời gian | ~3 phút (5 luồng song song) ✅ |
| Không có unhandled error | ✅ |

**Cấu hình chạy thực nghiệm**:
```bash
cd backend
source .venv/bin/activate
python scripts/run_security_review.py \
    --scenario sme_no_tools \
    --output ./results/run1/
# Resume nếu bị ngắt:
python scripts/run_security_review.py --output ./results/run1/ --resume
```

---

## Test 6 — Verify Output Quality ✅

**File**: `backend/results/test_paid/report.json`

| Check | Kết quả |
|-------|---------|
| ≥3 findings trong consensus | 6 findings ✅ |
| Findings đúng với scenario (CVE, host names) | CVE-2021-41773 WEB-01, credential dump WIN-01 ✅ |
| Tất cả domain groups có đóng góp | `silent_domain_groups: []` ✅ |
| Consensus engine chạy đúng | 36 findings → 6 consensus vulns ✅ |
| Report JSON đầy đủ fields | session_id, report, consensus_vulnerabilities, coverage_gaps, stats ✅ |

**Consensus Vulnerabilities (6 CRITICAL)**:
1. Critical Vulnerability in Public-Facing Web Server (WEB-01 Apache 2.4.49)
2. Lack of EDR and Vulnerable Windows Server — Credential Dumping & Lateral Movement
3. Lack of Network Segmentation Between Internal and Database Zones
4. Apache HTTP Server Path Traversal and File Disclosure (CVE-2021-41773)
5. Unpatched Apache on WEB-01 allows RCE and initial access
6. Complete absence of EDR across all hosts

**Known issues**:
- `attacker_findings: 0` — Phase C attacker format chưa được parse đúng → cần investigate
- `report.md` bị truncate (550 chars) — `VulnReportAgent` cần tăng `max_tokens` cho step generate report

---

## Bugs đã phát hiện và fix (Phase 5)

| File | Bug | Fix |
|------|-----|-----|
| `network_topology_builder.py:417` | `chunk_overlap=` sai tên param | đổi thành `overlap=` |
| `network_topology_builder.py:247` | `node.uuid` không có guard | thêm `hasattr` check |
| `network_topology_builder.py:248` | `controls` attribute là `None` | thêm `or ""` |
| `llm_client.py` | SDK tự retry không đọc `retry-after` header | thêm `max_retries=0` |
| `run_security_review.py` | Không xử lý 429 rate limit | thêm retry-with-backoff đọc `retryDelay` |

---

## Remaining issues (đã fix)

| Issue | Mức độ | Fix |
|-------|--------|-----|
| `attacker_findings: 0` | N/A | Không phải bug — 15/15 corroborations gắn đúng vào `expert_findings[n]["attacker_corroborations"]`. `attacker_findings` chỉ nhận `ATTACKER_ADD_PATH` actions. |
| Report truncated (550 chars) | Fixed | `vuln_report_agent.py:223,253` max_tokens 3000/4000 → 8192. Gemini 2.5 Flash (thinking model) dùng phần lớn budget cho reasoning, để lại ít cho output. |
| Agent response truncated mid-sentence | Fixed | `run_security_review.py` max_tokens 800 → 1500 cho `_call_agent()`. |
