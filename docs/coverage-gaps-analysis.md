# Coverage Gaps Analysis — Phase 5 Test Results

> Ngày phân tích: 2026-04-07
> Dựa trên kết quả chạy scenario `sme_no_tools`, 10 rounds, Gemini 2.5 Flash paid tier

---

## Tóm tắt

| Metric | Kết quả |
|--------|---------|
| Ground truth issues | 13 |
| Covered trong raw findings | 8/13 (62%) |
| Covered trong consensus | 4–5/13 (31–38%) |
| Raw findings tổng | 36 |
| Duplicate/near-duplicate findings | ~18/36 (50%) |
| Consensus vulns | 6 (thực chất 4 distinct) |

**Kết luận ngắn:** Tool bắt tốt CVE rõ ràng và structural issues (network segmentation, attack paths), nhưng bỏ sót nhiều control-gap findings (MFA, SIEM, DLP) và không phân tích các host không có CVE cụ thể (MAIL-01, FW-01).

---

## Điểm yếu 1 — CVE Attention Bias

### Mô tả

Khi scenario có 1 CVE nổi bật (CVE-2021-41773 trên WEB-01), các agents tập trung toàn bộ vào đó và bỏ qua phần còn lại.

**Bằng chứng từ test:**
- 15/36 raw findings (42%) nói về cùng 1 CVE
- SIEM, MFA, DLP không xuất hiện trong bất kỳ finding nào dù được liệt kê rõ trong prompt
- MAIL-01, FW-01 không có finding nào

**Root cause:**

Prompt hiện tại yêu cầu agents "identify vulnerabilities" — không có cơ chế bắt buộc phân tích từng host hay từng control domain riêng biệt. Agents follow the path of least resistance: viết nhiều lần về lỗ hổng dễ nhìn thấy nhất.

### Phương án giải quyết

**A. Structured Coverage Checklist trong system prompt**

Thêm vào `_build_tier1_system_prompt` một checklist cứng mà agent phải address trước khi kết thúc analysis:

```
For each round, ensure your analysis covers at minimum:
1. All hosts listed in the infrastructure (generate at least 1 finding per host)
2. All security controls explicitly listed as absent/present
3. Your domain-specific perspective on network architecture
```

**B. Per-host assignment trong Phase A**

Phân công cứng: mỗi agent trong intra-group phase được assign 1-2 hosts cụ thể để phân tích thay vì tự chọn. Implement trong `cyber_oasis_env.py` bằng cách rotate host list theo `agent_index % len(hosts)`.

**C. Diversity penalty trong scoring**

Trong `ConsensusEngine`, giảm weight của findings có title similarity > 80% với findings đã có trong pool. Dùng simple token overlap: nếu `len(intersection(title_A_tokens, title_B_tokens)) / len(union) > 0.6` thì mark là duplicate candidate.

---

## Điểm yếu 2 — Consensus Threshold Lọc Mất Control-Gap Findings

### Mô tả

`ConsensusEngine` yêu cầu findings phải có `cross_group_score` cao (validated bởi nhiều domain groups). Các "absence of X" findings (WAF, AV, NDR) thường chỉ được 1 group phát hiện → bị lọc ra khỏi consensus dù là lỗ hổng thực sự.

**Bằng chứng từ test:**

| Finding | Groups phát hiện | cross_group_score | Vào consensus? |
|---------|-----------------|-------------------|----------------|
| No WAF | appsec (1 group) | thấp | ❌ |
| No AV | endpoint_security (1 group) | thấp | ❌ |
| No NIDS | network_security (1 group) | thấp | ❌ |
| DMZ internet exposure | network_security (1 group) | thấp | ❌ |
| No segmentation | risk + network_security (2 groups) | trung bình | ✅ |

**Root cause:**

`ConsensusEngine.run()` dùng công thức `confidence_score = 0.4 * intra + 0.35 * cross + 0.25 * attacker`. Findings chỉ có 1 group support → `cross_group_score` ≈ 0.2 → `confidence_score` ≈ 0.45–0.50 → thường dưới ngưỡng lọc.

Control-gap findings (absence of a security tool) theo đặc thù chỉ thuộc về 1 domain — WAF là vấn đề của appsec, không phải của endpoint hay network. Công thức hiện tại penalize những findings kiểu này không công bằng.

### Phương án giải quyết

**A. Phân loại finding type — "control-gap" vs "vulnerability"**

Thêm field `finding_type: "control_gap" | "vulnerability" | "architecture"` vào finding schema. Agents phân loại khi generate. ConsensusEngine dùng công thức khác nhau:

```python
if finding.finding_type == "control_gap":
    # Single-domain findings — chỉ cần intra-group consensus
    confidence = 0.6 * intra_score + 0.15 * cross_score + 0.25 * attacker_score
    threshold = 0.45  # thấp hơn
else:
    # Vulnerability / architecture — cần cross-domain validation
    confidence = 0.4 * intra_score + 0.35 * cross_score + 0.25 * attacker_score
    threshold = 0.50
```

**B. Minimum coverage rule**

Sau khi chạy consensus, kiểm tra các "standard security controls" đã được cover chưa. Nếu chưa, tự động add vào report dưới section "Control Gaps Not Validated by Consensus":

```python
STANDARD_CONTROLS = ["EDR", "SIEM", "AV", "WAF", "NDR", "MFA", "DLP", "patch management"]

for control in STANDARD_CONTROLS:
    if any(control.lower() in f["title"].lower() for f in all_findings):
        if not any(control.lower() in v.title.lower() for v in consensus_vulns):
            coverage_gaps["unvalidated_control_gaps"].append(control)
```

**C. Attacker boost cho control-gap findings**

Trong Phase C, nếu attacker confirm một control-gap finding (e.g., `ATTACKER_CONFIRM` trên "No WAF"), tăng `attacker_score` lên 0.8 thay vì 0.5. Lý do: attacker xác nhận khai thác được → finding xứng đáng vào consensus dù chỉ 1 expert group phát hiện.

---

## Điểm yếu 3 — Host Blind Spots (MAIL-01, FW-01)

### Mô tả

Các host không có CVE cụ thể được gắn nhãn trong prompt không có finding nào trong toàn bộ 36 raw findings. MAIL-01 và FW-01 bị ignore hoàn toàn.

**Bằng chứng từ test:**
- `mail-01`, `postfix` → 0 keyword hits trong 36 findings
- `fw-01`, `pfsense` → 0 keyword hits trong 36 findings
- Finding duy nhất đề cập MAIL-01 là finding #16 (DMZ exposure) — assets list, không phải vuln trên MAIL-01

**Root cause:**

Agents không có incentive để phân tích host "nhàm" khi có CVE nổi bật hơn. Postfix 3.5 và pfSense 2.5 không có CVE được mention → agents bỏ qua.

Thực tế security-wise, đây là blind spot nguy hiểm:
- MAIL-01 trong DMZ với Postfix 3.5: có thể có open relay, header injection, hoặc là bước pivot
- FW-01 (pfSense 2.5): is_critical, nếu bị compromise → toàn bộ network topology bị mất

### Phương án giải quyết

**A. Per-host rotation trong Phase A**

Trong `cyber_oasis_env.py`, thêm `[ASSIGNED HOST]` vào instruction_addition của Phase A:

```python
host_list = extract_hosts_from_summary(network_summary)  # parse từ network text
assigned_host = host_list[agent_index % len(host_list)]

instruction_addition = f"""
In this phase, you MUST generate at least one finding specifically about:
  Assigned host: {assigned_host}

After addressing your assigned host, you may discuss other infrastructure issues.
"""
```

**B. Host coverage check trong ConsensusEngine**

```python
def get_coverage_gaps(self, vulns, network_summary):
    hosts = extract_hosts(network_summary)  # ["WEB-01", "DB-01", "FW-01", "WIN-01", "MAIL-01"]
    covered_hosts = set()
    for v in vulns:
        for asset in v.affected_assets:
            for host in hosts:
                if host.lower() in asset.lower():
                    covered_hosts.add(host)
    gaps["uncovered_hosts"] = [h for h in hosts if h not in covered_hosts]
```

**C. Threat-model driven prompting**

Thay vì để agents tự do, cung cấp per-host threat model nhỏ trong context. Ví dụ:

```
MAIL-01 (Postfix 3.5, DMZ): Consider: open relay, SMTP smuggling, email as pivot point, 
                              credential harvesting via phishing infrastructure.
FW-01 (pfSense 2.5, Management, is_critical): Consider: management interface exposure, 
                              firewall rule misconfigurations, admin credential attacks.
```

---

## Điểm yếu 4 — Duplicate Findings Inflate Count

### Mô tả

50% raw findings là near-duplicates của nhau. 15/36 findings đều về CVE-2021-41773. Điều này:
1. Waste LLM calls (và tiền)
2. Bias consensus về phía CVE, làm giảm weight của findings khác
3. Report trông "full" nhưng thực ra thin

**Bằng chứng từ test:**

```
[1]  Critical Vulnerability in Public-Facing Web Server
[2]  Unpatched Public-Facing Web Server Vulnerable to RCE        ← duplicate of [1]
[3]  Exposed and Vulnerable Apache Web Server (RCE via Path Traversal)  ← dup
[4]  Apache HTTP Server Path Traversal and File Disclosure (CVE-2021-41773)  ← dup
[5]  Critical Vulnerability in Public-Facing Web Server (CVE-2021-41773)  ← dup
[6]  Critical Public-Facing Web Server Vulnerability (CVE-2021-41773)  ← dup
...  (9 more)
```

**Root cause:**

Không có "memory" giữa agents về những gì đã được report. Agent A viết finding về CVE-2021-41773, agent B không biết → viết lại.

### Phương án giải quyết

**A. Shared finding registry (đơn giản nhất)**

Trong `CyberOasisEnvBuilder`, maintain một `published_findings_summary` được append vào context của mỗi agent sau mỗi round:

```
Already reported findings (do not duplicate):
- CVE-2021-41773 on WEB-01 [reported by netw_offensive, appsec_offensive]
- Missing EDR on all hosts [reported by endpoint_defensive]
```

Agent nhìn vào list này và được hướng dẫn: "Nếu topic đã được report, hãy CHALLENGE hoặc EXPAND thay vì report lại."

**B. Intra-round dedup trong ConsensusEngine**

Trước khi score, cluster findings theo semantic similarity. Dùng simple heuristic:
- Nếu 2 findings cùng `author_group` và title overlap > 60% → giữ cái có `confidence` cao hơn, discard cái còn lại
- Nếu 2 findings khác group nhưng title overlap > 80% → merge vào 1 finding với `supporting_groups` từ cả hai

**C. Diversity instruction trong Phase B**

Phase B hiện tại prompt agents "read and challenge findings from other groups." Thêm: "Do NOT re-report findings that have already been identified. If you agree with a finding, use `[CROSS_VALIDATE]` tag instead of writing a new finding."

---

## Điểm yếu 5 — MITRE Techniques Không Được Populate

### Mô tả

Tất cả 6 consensus vulnerabilities có `mitre_techniques: []`. Mất đi một trong những giá trị cốt lõi của tool (mapping to MITRE ATT&CK).

**Root cause (đã xác định):**

`max_tokens=800` trong `_call_agent()` cắt agent responses trước khi chúng có thể hoàn thành JSON với MITRE fields. Khi response bị truncate mid-sentence, parser không đọc được `mitre_techniques` → default về `[]`.

**Trạng thái fix:**

Đã tăng `max_tokens: 800 → 1500` trong [run_security_review.py](../backend/scripts/run_security_review.py). Cần verify lại trong run tiếp theo.

### Phương án giải quyết bổ sung

**A. Fallback MITRE mapping trong ConsensusEngine**

Nếu `mitre_techniques` của finding là empty, dùng keyword → MITRE lookup table:

```python
KEYWORD_MITRE_MAP = {
    "path traversal":     ["T1190"],
    "rce":                ["T1190", "T1059"],
    "credential dump":    ["T1003"],
    "lateral movement":   ["T1021"],
    "rdp":                ["T1021.001"],
    "no edr":             ["T1562.001"],
    "no siem":            ["T1562"],
    "network segment":    ["T1599"],
}
```

**B. Explicit MITRE instruction trong system prompt**

Thêm vào agent system prompt: "For each finding, you MUST include at least 1 MITRE ATT&CK technique ID (format: T####). Use the TTP catalog provided."

---

## Ưu tiên fix

| # | Fix | Impact | Effort | Priority |
|---|-----|--------|--------|----------|
| 1 | Tăng `max_tokens` 800 → 1500 (đã done) | MITRE, truncation | Thấp | ✅ Done |
| 2 | Tăng VulnReportAgent `max_tokens` 3000 → 8192 (đã done) | Report quality | Thấp | ✅ Done |
| 3 | Shared finding registry (Điểm yếu 4A) | -50% duplicates | Thấp | 🔴 High |
| 4 | Per-host assignment Phase A (Điểm yếu 3A) | Host coverage | Trung bình | 🔴 High |
| 5 | `finding_type` + split threshold (Điểm yếu 2A) | Control gap coverage | Trung bình | 🟡 Medium |
| 6 | Fallback MITRE mapping (Điểm yếu 5A) | MITRE completeness | Thấp | 🟡 Medium |
| 7 | Host coverage check in ConsensusEngine (Điểm yếu 3B) | Gap visibility | Thấp | 🟡 Medium |
| 8 | Minimum control coverage rule (Điểm yếu 2B) | Control gap visibility | Thấp | 🟡 Medium |
| 9 | `finding_type` per-host diversity instruction (Điểm yếu 1A) | Agent diversity | Thấp | 🟢 Low |
| 10 | Tăng rounds lên 15 (thực nghiệm) | Overall coverage | Zero-code | 🟢 Low |

---

## Kết quả kỳ vọng sau khi fix

Với các fix **High priority** (shared registry + per-host assignment):

| Metric | Hiện tại | Kỳ vọng |
|--------|---------|---------|
| CVE-finding ratio | 42% (15/36) | < 25% |
| Unique distinct findings | ~18/36 (50%) | > 28/36 (78%) |
| Host coverage | 3/5 hosts | 5/5 hosts |
| Control gap coverage (raw) | 5/9 (56%) | 7–8/9 (78–89%) |
| Consensus coverage | 4–5/13 (31–38%) | 7–9/13 (54–69%) |
| MITRE populated | 0/6 (0%) | > 4/6 (67%) |
