# Implementation Roadmap — Multi-Expert Panel

## Tổng quan tiến độ

```
✅ Phase 1 — Network KG Foundation      (HOÀN THÀNH)
✅ Phase 2 — Agent Matrix Core          (HOÀN THÀNH)
✅ Phase 3 — Collaborative Analysis     (HOÀN THÀNH)
✅ Phase 4 — Report & API               (HOÀN THÀNH)
🔲 Phase 5 — Verify & Test              (TIẾP THEO)
🔲 Phase 6 — Frontend                  (SAU ĐÓ)
🔲 Phase 7 — Experiment & Validation   (CUỐI)
🔲 Phase 8 — Viết luận án              (CUỐI)
```

---

## Phase 5 — Verify & Test Backend ← LÀM NGAY

> Mục tiêu: Xác nhận toàn bộ pipeline chạy không lỗi trước khi làm frontend.

### Bước 5.1 — Cài đặt môi trường

```bash
# 1. Clone / vào thư mục dự án
cd MiroFish

# 2. Copy env
cp .env.example .env

# 3. Cài Node deps + Python venv
npm run setup:all

# 4. Kích hoạt venv
cd backend
source .venv/bin/activate
```

Cấu hình `.env`:
```env
LLM_API_KEY=ollama
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL_NAME=qwen2.5:32b

BOOST_API_KEY=ollama
BOOST_BASE_URL=http://localhost:11434/v1
BOOST_MODEL_NAME=qwen2.5:32b

ZEP_API_KEY=<your_zep_cloud_key>
```

---

### Bước 5.2 — Cài Ollama + model

```bash
# Cài Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Cấu hình tối ưu
sudo systemctl edit ollama
# Paste vào:
# [Service]
# Environment="OLLAMA_KEEP_ALIVE=24h"
# Environment="OLLAMA_NUM_THREAD=20"
# Environment="OLLAMA_NUM_PARALLEL=1"

sudo systemctl daemon-reload && sudo systemctl restart ollama

# Pull model
ollama pull qwen2.5:32b

# Verify
curl http://localhost:11434/v1/models
```

---

### Bước 5.3 — Khởi động backend

```bash
cd MiroFish
npm run backend
# Flask chạy tại http://localhost:5001
```

Kiểm tra blueprint cyber đã đăng ký:
```bash
curl http://localhost:5001/api/cyber/ttp-library | python3 -m json.tool
```

Kết quả mong đợi: JSON có `techniques` list với 20 TTP entries.

---

### Bước 5.4 — Test từng API endpoint

**Test 1: TTP Library**
```bash
curl "http://localhost:5001/api/cyber/ttp-library?domain=network_security"
curl "http://localhost:5001/api/cyber/ttp-library/T1190"
```

**Test 2: TTP Context (kiểm tra diversity giữa personas)**
```bash
# Offensive persona
curl -X POST http://localhost:5001/api/cyber/ttp-library/context \
  -H "Content-Type: application/json" \
  -d '{"domain": "network_security", "persona": "offensive"}'

# Defensive persona — prompt phải KHÁC với offensive
curl -X POST http://localhost:5001/api/cyber/ttp-library/context \
  -H "Content-Type: application/json" \
  -d '{"domain": "network_security", "persona": "defensive"}'
```

**Test 2b: Network context từ Zep (optional — khi dùng graph_id thay vì text)**
```bash
# Chỉ cần test nếu đã build graph trước
curl http://localhost:5001/api/cyber/network-context/<graph_id>
# Kết quả mong đợi: JSON có "summary" text mô tả hạ tầng
```

**Test 3: Build network graph**
```bash
curl -X POST http://localhost:5001/api/cyber/setup \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Web server Apache 2.4.49 in DMZ zone, IP 10.0.1.10, unpatched, CVE-2021-41773. Database server MySQL 8.0 in Database zone, critical asset, no EDR.",
    "graph_name": "Test Network"
  }'
# Lưu lại task_id

# Poll task
curl http://localhost:5001/api/cyber/task/<task_id>
```

**Test 4: Generate 18 agent profiles**
```bash
curl -X POST http://localhost:5001/api/cyber/agents/generate \
  -H "Content-Type: application/json" \
  -d '{
    "network_summary": "2 hosts: Apache 2.4.49 DMZ (CVE-2021-41773, unpatched), MySQL Database (critical, no EDR)",
    "graph_id": "test"
  }'
# Kết quả mong đợi: tier1_count=13, tier2_count=5, total=18
# Lưu lại oasis_profiles từ response để dùng ở Test 5
```

**Test 5: Khởi động session (cần oasis_profiles từ Test 4)**
```bash
curl -X POST http://localhost:5001/api/cyber/session/start \
  -H "Content-Type: application/json" \
  -d '{
    "graph_id": "test",
    "network_summary": "2 hosts: Apache 2.4.49 DMZ (CVE-2021-41773, unpatched), MySQL Database (critical, no EDR)",
    "oasis_profiles": <oasis_profiles từ Test 4>
  }'
# Kết quả mong đợi: { task_id, session_id }

# Poll session status
curl http://localhost:5001/api/cyber/review/<session_id>/status
```

---

### Bước 5.5 — Chạy full pipeline qua script

Đây là bước quan trọng nhất — chạy end-to-end với rounds nhỏ để test nhanh:

```bash
cd backend
source .venv/bin/activate

# Test nhanh với 3 rounds (thay vì 10)
python scripts/run_security_review.py \
    --scenario sme_no_tools \
    --output ./results/test_quick/ \
    --rounds 3 \
    --verbose
```

Kiểm tra output:
```bash
ls ./results/test_quick/
# Phải có:
#   agent_profiles.json   → 18 profiles
#   feed.jsonl            → posts từ mỗi agent mỗi round
#   session_state.json    → findings từ session
#   report.json           → consensus vulns + report text
#   report.md             → human-readable report
```

Đọc report:
```bash
cat ./results/test_quick/report.md
```

---

### Bước 5.6 — Kiểm tra chất lượng output

Sau khi có `report.md`, verify các điểm sau:

```
✅ Có ít nhất 3 findings trong report
✅ Severity có cả critical/high/medium (không phải tất cả cùng level)
✅ Offensive agent và Defensive agent có findings KHÁC nhau
✅ Ít nhất 1 attacker profile đã CONFIRM hoặc DISMISS finding nào đó
✅ Report có Executive Summary + Recommendations
✅ Confidence score range từ 0.35 đến 0.9 (không phải tất cả giống nhau)
```

Nếu có vấn đề → fix bug → quay lại bước 5.5.

---

## Phase 6 — Frontend ← SAU KHI BACKEND VERIFIED

> Mục tiêu: Giao diện để demo cho hội đồng và chạy experiment.

### Bước 6.1 — Step1NetworkSetup.vue

```
Chức năng:
  - Text area nhập mô tả hạ tầng mạng
  - Upload IaC file (Terraform, Docker Compose)
  - Gọi POST /api/cyber/setup
  - Progress bar poll task status
  - Khi xong → hiện tóm tắt: X hosts, Y CVEs detected
  - Nút "Continue to Agent Setup"
```

---

### Bước 6.2 — Step2AgentSetup.vue

```
Chức năng:
  - Gọi POST /api/cyber/agents/generate
  - Hiển thị ma trận 13 Tier-1 agents dạng table:
      | Domain          | Offensive | Defensive | Auditor |
      | Network Sec     |    ✅     |    ✅     |   ✅    |
      | AppSec          |    ✅     |    ✅     |   ✅    |
      ...
  - Hiển thị 5 Tier-2 attacker profiles dạng card:
      [APT] [Ransomware] [Insider] [Opportunistic] [Supply Chain]
  - Click vào mỗi agent → xem system prompt preview
  - Nút "Start Analysis Session"
```

---

### Bước 6.3 — Step3ReviewSession.vue

```
Chức năng:
  - Gọi POST /api/cyber/session/start
  - Hiển thị live feed bằng cách poll GET /api/cyber/review/<id>/feed
  - Tab layout:
      [Phase A: Intra-group] [Phase B: Cross-group] [Phase C: Attacker]
  - Mỗi post hiện dạng chat bubble:
      Avatar + tên agent + domain tag + nội dung
      [FINDING] badge nếu post chứa finding
  - Round counter: Round 3/10 | Phase B
  - Finding counter: 12 findings so far
  - Khi done → nút "View Findings"
```

---

### Bước 6.4 — Step4Findings.vue

```
Chức năng:
  - Gọi GET /api/cyber/review/<id>/findings
  - Danh sách findings dạng card:
      [CRITICAL] RDP Exposed to DMZ
      Confidence: ████████░░ 0.82
      Groups: network_security, endpoint_security, threat_intel
      Attackers confirm: apt, ransomware
      [expand] Evidence / Recommendations
  - Filter bar: phase / domain / severity
  - Group breakdown chart: pie chart số findings theo domain
  - Nút "Generate Report"
```

---

### Bước 6.5 — Step5Report.vue

```
Chức năng:
  - Gọi POST /api/cyber/report/generate → poll task
  - Sau khi xong gọi GET /api/cyber/report/<session_id>
  - Hiển thị:
      Executive Summary (highlight box)
      Top Vulnerabilities table (sortable theo confidence/severity)
      Attacker Profile Breakdown:
        APT confirmed: X findings | dismissed: Y
        Ransomware confirmed: X | ...
      Coverage Gap Analysis:
        Silent groups: [...]
        Low cross-validation: [...]
        Attacker-only paths: [...]
      Recommendations (timeline: immediate / 30d / 90d)
  - Nút Export PDF / Export JSON
```

---

## Phase 7 — Experiment & Validation ← SONG SONG VỚI FRONTEND

> Mục tiêu: Thu thập số liệu cho Research Questions trong luận án.

### Bước 7.1 — Chạy 3 scenarios đầy đủ (10 rounds)

```bash
# Scenario 1
python scripts/run_security_review.py \
    --scenario sme_no_tools \
    --output ./results/scenario1/ \
    --rounds 10

# Scenario 2
python scripts/run_security_review.py \
    --scenario mid_siem \
    --output ./results/scenario2/ \
    --rounds 10

# Scenario 3
python scripts/run_security_review.py \
    --scenario enterprise_full_stack \
    --output ./results/scenario3/ \
    --rounds 10
```

---

### Bước 7.2 — Chạy baseline để so sánh

Tạo baseline: single-agent (không có multi-expert panel):

```bash
# Chạy single agent với cùng network description
# Gọi LLM 1 lần duy nhất, không có consensus
python scripts/run_security_review.py \
    --scenario sme_no_tools \
    --output ./results/baseline1/ \
    --rounds 1    # 1 round = gần single agent nhất
```

---

### Bước 7.3 — Đo metrics cho từng Research Question

**RQ1 — Diversity (số lượng findings)**
```
Đo: Tổng findings của 13-agent panel vs 5 generic experts
So sánh: unique findings theo domain group
Expected: Panel tìm ra nhiều loại findings hơn (network + app + endpoint + ...)
```

**RQ2 — FP Rate (cross-validation)**
```
Đo: Findings có cross_group_score > 0.5 vs < 0.5
Verify thủ công: mỗi finding có thật sự là lỗ hổng không?
Expected: FP rate của cross-validated findings < intra-only findings
```

**RQ3 — Offensive vs Defensive diversity**
```
Đo: Findings từ offensive personas vs defensive personas
Overlap analysis: bao nhiêu % findings trùng nhau?
Expected: < 50% overlap → chứng minh mindset diversity có giá trị
```

**RQ4 — Weighted consensus vs simple majority**
```
Đo: Re-rank findings bằng simple majority (không dùng weight)
So sánh: rank order có khác 3-layer weighted không?
Expected: Weighted rank chính xác hơn khi verified thủ công
```

**RQ bổ sung — Hallucination rate**
```
Đo: Findings trong report không có evidence thật (false positive)
So sánh: Panel vs single-agent baseline
Expected: Panel FP rate < single-agent FP rate
```

---

### Bước 7.4 — Validate với real case

Tìm 1 incident report công khai (CISA advisory, CVE writeup, HackTheBox writeup) và:

```
1. Dùng infrastructure description từ incident đó làm input
2. Chạy panel → xem hệ thống có detect ra vulnerability đó không
3. So sánh findings với actual attack path trong writeup
4. Document: hệ thống detect được X/Y vulnerabilities trong real case
```

Nguồn tốt để tìm:
- CISA Known Exploited Vulnerabilities: cisa.gov/known-exploited-vulnerabilities-catalog
- HackTheBox writeups (sau khi machine retired)
- VulnHub machine descriptions

---

## Phase 8 — Viết Luận án ← CUỐI CÙNG

### Cấu trúc chương đề xuất

```
Chương 1 — Giới thiệu
  1.1 Bối cảnh: Vulnerability discovery hiện tại và giới hạn
  1.2 Vấn đề: LLM single-agent và hallucination
  1.3 Đề xuất: Multi-Expert Panel với 3-layer consensus
  1.4 Research Questions (RQ1–RQ4 + RQ hallucination)
  1.5 Cấu trúc luận án

Chương 2 — Cơ sở lý thuyết
  2.1 Large Language Model và hallucination
  2.2 Multi-agent systems và emergent behavior
  2.3 OASIS framework (CAMEL-AI)
  2.4 MITRE ATT&CK và D3FEND
  2.5 Delphi method và structured expert elicitation
  2.6 Các nghiên cứu liên quan (PentestGPT, AutoPT, AutoGen...)

Chương 3 — Thiết kế hệ thống
  3.1 Kiến trúc tổng thể (5-phase pipeline)
  3.2 Domain Group × Mindset Persona matrix
  3.3 Attacker Profile Agents
  3.4 3-phase OASIS session
  3.5 3-layer Consensus Engine
  3.6 Hallucination mitigation mechanisms

Chương 4 — Cài đặt
  4.1 Stack kỹ thuật (MiroFish + Zep + Ollama)
  4.2 Các module chính (mô tả file, không cần toàn bộ code)
  4.3 API endpoints
  4.4 Self-hosted LLM deployment

Chương 5 — Thực nghiệm và Đánh giá
  5.1 Môi trường thực nghiệm
  5.2 3 scenarios (SME / Mid / Enterprise)
  5.3 Kết quả RQ1: Diversity
  5.4 Kết quả RQ2: FP Rate
  5.5 Kết quả RQ3: Offensive vs Defensive
  5.6 Kết quả RQ4: Weighted vs Majority
  5.7 Kết quả RQ5: Hallucination mitigation
  5.8 Real case validation

Chương 6 — Kết luận
  6.1 Tóm tắt đóng góp
  6.2 Giới hạn
  6.3 Hướng phát triển (Direction C: Attack Graph)
```

---

## Checklist tổng thể

```
Backend:
  ✅ cyber_models.py
  ✅ mitre_reference.py
  ✅ network_topology_builder.py
  ✅ cyber_expert_profile_generator.py
  ✅ cyber_oasis_env.py
  ✅ cyber_session_orchestrator.py
  ✅ consensus_engine.py
  ✅ vuln_report_agent.py
  ✅ api/cyber.py (đầy đủ endpoints)
  ✅ scripts/run_security_review.py
  ✅ docs/hallucination-mitigation.md

Verify & Test:
  🔲 Ollama + qwen2.5:32b chạy được
  🔲 Flask khởi động không lỗi (cyber_bp registered)
  🔲 /api/cyber/ttp-library trả về đúng (20 techniques)
  🔲 /api/cyber/agents/generate trả về tier1=13, tier2=5
  🔲 /api/cyber/session/start khởi động không lỗi
  🔲 Pipeline end-to-end ra report.md

Frontend:
  🔲 Step1NetworkSetup.vue
  🔲 Step2AgentSetup.vue
  🔲 Step3ReviewSession.vue
  🔲 Step4Findings.vue
  🔲 Step5Report.vue

Experiment:
  🔲 Scenario 1 (sme_no_tools) — 10 rounds
  🔲 Scenario 2 (mid_siem) — 10 rounds
  🔲 Scenario 3 (enterprise_full_stack) — 10 rounds
  🔲 Baseline single-agent
  🔲 Metrics RQ1–RQ5 đo xong
  🔲 Real case validation

Luận án:
  🔲 Chương 1–2 (lý thuyết)
  🔲 Chương 3–4 (thiết kế + cài đặt)
  🔲 Chương 5 (thực nghiệm)
  🔲 Chương 6 (kết luận)
```

---

## Timeline gợi ý

```
Tuần 1–2  : Phase 5 — Verify backend, fix bug nếu có
Tuần 3–5  : Phase 6 — Frontend 5 components
Tuần 4–6  : Phase 7 — Chạy experiment song song với frontend
             (script chạy overnight, không cần giám sát)
Tuần 7–10 : Phase 8 — Viết luận án
             Chương 1–2: tuần 7
             Chương 3–4: tuần 8
             Chương 5:   tuần 9
             Chương 6 + review: tuần 10
```

---

*Roadmap này phản ánh trạng thái dự án tại thời điểm backend hoàn thành.*
*Cập nhật checklist khi hoàn thành từng bước.*
