# Smart Contract Audit — Tổng hợp tiến độ & vấn đề

> Cập nhật: 2026-04-24

---

## 1. Tổng quan hệ thống

MiroFish được pivot sang hướng **Cybersecurity Vulnerability Assessment** (Hướng B), sử dụng multi-agent LLM panel để phân tích lỗ hổng smart contract. Kiến trúc gồm 3 tầng chính:

```
Solidity source
      ↓
[KG Build]  →  Zep Knowledge Graph (ontology + invariants)
      ↓
[22 Agents]  →  17 Tier-1 (domain × mindset) + 5 Tier-2 (attacker profiles)
      ↓
[10-Round Session]  →  Phase A (intra-domain) → B (cross-domain) → C (attacker challenge)
      ↓
[Consensus Engine]  →  L1/L2/L3 weighting → consensus_vulns + semantic_results
      ↓
[Output JSON]  →  consensus_vulns[], unvalidated_swc_gaps[], semantic_results[]
```

**Semantic taxonomy (2026-04):** `backend/app/services/semantic_taxonomy.py` là single source cho tập category chuẩn, alias → bucket, `SWC_TO_SEMANTIC`, map `swc_category` trên gap → semantic (Policy Gap trong eval), few-shot prompt text, và ngưỡng `source_count` tối thiểu cho gap vào S-pool.

---

## 2. Đã triển khai

### 2.1 Backend Pipeline (Phase 1–4) — HOÀN THÀNH

| Component | Mô tả | Trạng thái |
|---|---|---|
| `contract_profile_generator.py` | Sinh 22 agent profile (domain × mindset × SWC focus) | ✅ Done |
| `cyber_session_orchestrator.py` | Điều phối 10-round session tuần tự/song song | ✅ Done |
| `consensus_engine.py` | 3-layer consensus + semantic clustering + vote category chuẩn hóa | ✅ Done |
| `contract_oasis_env.py` | SEMANTIC_FINDING parser (normalize category) | ✅ Done |
| `semantic_taxonomy.py` | Enum category + alias + SWC/gap mapping + few-shot | ✅ Done |
| `swc_registry.py` | SWC knowledge base phân domain | ✅ Done |

### 2.2 Các fix đã áp dụng (Phase 5)

#### Fix lỗi backend ban đầu (test_gap_v1–v8)

| Lỗi | Giải pháp | Kết quả |
|---|---|---|
| Host blind spots (MAIL-01, FW-01 = 0 findings) | Delphi GAP Declaration — agent khai báo `ANALYZED:` / `GAP:` cuối mỗi post | Coverage 3/7 → 7/7 |
| Consensus threshold lọc mất control-gap findings | Semantic Anchor Clustering + both-title rule + post-consensus enforcement | ✅ |
| Duplicate findings ~50% | Published Finding Registry — inject title đã report vào context | Giảm 79% |
| MITRE techniques = [] | 3-layer bug fix + inline text fallback scan regex | ✅ |
| **CVE over-representation** (~47% findings cùng CVE) | **Chưa fix** — xem §4.2 | ⬜ |

**Kết quả sau v8:** F1=0.96, Recall=1.00, Precision=0.93 (trên test_gap scenario)

#### Fix cho Web3Bugs evaluation + semantic alignment (2026-04)

| Hạng mục | Giải pháp |
|---|---|
| Category enum thiếu / lệch parser | `semantic_taxonomy.CANONICAL_SEMANTIC_CATEGORIES` + `normalize_semantic_category()` trong parser và consensus |
| Agent dùng từ tự do (`incentive_misalignment`, `oracle`, …) | `ALIAS_TO_CANONICAL` map vào bucket Web3Bugs (vd. incentive → `access_control`, oracle → `price_oracle`) |
| Prompt / format lệch nhau | `SEMANTIC_CATEGORY_PIPE_STRING` + `SEMANTIC_CATEGORY_FEW_SHOT` nhúng vào `contract_profile_generator` và `SEMANTIC_FINDING_FORMAT` trong `contract_oasis_env` |
| Policy A bỏ lỡ S khi chỉ có signal trên gap có SWC | Eval: `--policy-gap` — gap có `source_count` ≥ `GAP_MIN_SOURCE_COUNT_FOR_S` và map được → đưa vào S-pool (chỉ sensitivity / appendix) |
| SWC→semantic trùng hai nơi | `evaluate_web3bugs.py` import động `semantic_taxonomy.py` (importlib, không load Flask) |
| Thiếu SWC-128 trong appsec, appsec không SEMANTIC | Đã có từ trước: SWC-128 + `_SEMANTIC_DOMAINS` |
| Sort report sai thư mục | `st_mtime` trong `find_latest_report` |

---

## 3. Evaluation Protocol — Web3Bugs

### 3.1 Hai track độc lập

| Track | Ground Truth | Tool Output | Metric |
|---|---|---|---|
| **Track L** | Bug label L\* → SWC mapping | `consensus_vulns[].mitre_techniques` + gaps | P/R/F1_L |
| **Track S** | Bug label S1–S6 → semantic category | `semantic_results[].category` (+ optional B / Gap) | P/R/F1_S |
| Loại khỏi GT chính | SE\*, SC, O\* | — | (báo cáo phụ) |

### 3.2 Ba policy (track S)

- **Policy A** (paper-safe): chỉ `semantic_results` đã chuẩn hóa category
- **Policy B** (sensitivity): thêm consensus nếu SWC ∈ `SWC_TO_SEMANTIC`
- **Policy Gap** (`--policy-gap`): thêm `unvalidated_swc_gaps` khi `semantic_category_from_gap()` trả về bucket (có ngưỡng `source_count`)

Chi tiết: `docs/web3bugs-evaluation-protocol.md`

### 3.3 Contest 19 — trạng thái mới nhất

- **Contract:** TransactionManager (Connext). Ground truth trong `bugs.csv`: 5 bugs (1 L, 2 S in-scope, 2 OOS).
- **Run đầy đủ 10 rounds:** `backend/results/web3bugs_trial/contest_19/TransactionManager_20260424_054640/audit_report.json` (2026-04-24).
- **Run timeout cũ (2026-04-23):** chỉ tới ~round 3 — giữ làm lịch sử; không dùng cho metric chính.

**Số liệu `evaluate_web3bugs.py` trên report 2026-04-24** (micro, contest 19):

| Policy | F1_L | F1_S | Ghi chú |
|--------|------|------|---------|
| A | ~0.20 | ~0.67 | S-pool=1; 1/2 S bugs khớp category |
| B+gap | ~0.20 | ~0.25 | S-pool lớn hơn → FP_S tăng (sensitivity) |

F1_L thấp chủ yếu do định nghĩa FP script-style: `FP_L = |L-pool| − TP_L` với nhiều finding trong pool nhưng chỉ 1 bug L.

---

## 4. Vấn đề hiện tại

### 4.1 Tốc độ & timeout (đã phần nào giải quyết bằng run 2026-04-24)

**Triệu chứng cũ:** Round ~40–50 phút; `timeout_session=7200s` cắt sớm.

**Vẫn cần theo dõi:** prompt dài, 429 Vertex, cooldown — xem bảng trong phiên bản trước của doc này; khuyến nghị: tăng delay/cooldown/timeout theo `.env` và `run_contract_audit.py` nếu tái diễn.

### 4.2 CVE Over-representation (lỗi backend mở từ v8)

Chưa đổi kiến trúc L3 — xem kế hoạch multiplicative attacker gate trong các bản progress cũ.

### 4.3 So sánh baseline GPTScan

Paper GPTScan (ICSE 2024) báo **Web3Bugs** khoảng **F1 ~67.8%** (và recall ~83.33%), không phải F1=0.88 trên SmartBugs. Khi viết luận văn, trích đúng dataset từ bảng trong paper.

---

## 5. Pending — Việc cần làm tiếp

| # | Việc | Ưu tiên |
|---|---|---|
| 1 | Chạy cohort 10 contest Web3Bugs + aggregate metrics | 🔴 Cao |
| 2 | Tune timeout / prompt size nếu 429 tái diễn | 🟡 Trung bình |
| 3 | Attacker gate multiplicative (CVE over-representation) | 🟡 Trung bình |
| 4 | Frontend (5 Vue components) | 🟢 Thấp |
| 5 | Thesis experiment scenarios | 🟢 Thấp |

---

## 6. Config hiện tại (`.env`)

```env
LLM_MODEL_NAME=google/gemini-2.5-flash
LLM_MAX_WORKERS=1          # sequential mode
LLM_RPM_LIMIT=20
LLM_SUBMIT_DELAY_S=3       # delay giữa các agent trong 1 round
LLM_ROUND_COOLDOWN_S=15    # delay giữa các round
BOOST_MODEL_NAME=google/gemini-2.5-pro
```

(Có thể tăng delay/cooldown theo §4.1 nếu cần.)
