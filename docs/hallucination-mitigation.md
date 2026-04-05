# LLM Hallucination Mitigation trong Multi-Expert Panel

## Tóm tắt

Một trong những hạn chế cốt lõi của Large Language Model (LLM) khi áp dụng vào lĩnh vực an toàn thông tin là **hallucination** — hiện tượng model tự tin đưa ra thông tin sai lệch, đặc biệt với các factual knowledge như CVE ID, version số, hoặc chi tiết kỹ thuật cụ thể. Thay vì xem đây là rào cản, hệ thống **Multi-Expert Panel** được thiết kế để giảm thiểu hallucination một cách có hệ thống thông qua 3 cơ chế độc lập, không phụ thuộc vào độ chính xác của bất kỳ model đơn lẻ nào.

---

## 1. Vấn đề — LLM Hallucination trong Security Context

### 1.1 Minh họa thực tế

Khi được hỏi về CVE-2021-41773 mà không có context, `qwen2.5:32b` trả lời:

> *"CVE-2021-41773 is a remote code execution vulnerability in **VMware products**..."*

Đây là thông tin **hoàn toàn sai**. CVE-2021-41773 là lỗ hổng path traversal trên **Apache HTTP Server 2.4.49**, không liên quan đến VMware.

### 1.2 Tại sao hallucination đặc biệt nguy hiểm trong security

```
Lĩnh vực khác:
  Hallucination về lịch sử, văn học → sai nhưng ít hậu quả nghiêm trọng

Lĩnh vực security:
  Hallucination về CVE → false positive → lãng phí nguồn lực remediation
  Hallucination về attack path → bỏ sót lỗ hổng thật → false negative
  Hallucination về tool requirement → đề xuất sai giải pháp phòng thủ
  → Hậu quả: tổ chức bị tấn công vào điểm mù mà AI không phát hiện
```

### 1.3 Giới hạn của giải pháp hiện tại trên thị trường

Các sản phẩm AI security hiện tại (Microsoft Security Copilot, CrowdStrike Charlotte AI) đều dùng **single-agent paradigm**:

```
User query → Single LLM → Output
```

Không có cơ chế nào để phát hiện khi chính LLM đó đang hallucinate.

---

## 2. Giải pháp — 3 Cơ chế Độc lập

### Cơ chế 1: Context Injection (Không phụ thuộc memory của model)

**Vấn đề gốc:** Model phải tự nhớ CVE ID, version số, TTP detail → hallucinate.

**Giải pháp:** Inject toàn bộ factual knowledge vào prompt — model chỉ cần reasoning, không cần recall.

#### 1a. MITRE ATT&CK TTP Injection (`mitre_reference.py`)

Thay vì hỏi model "T1190 là gì?", hệ thống inject thẳng:

```
[T1190] Exploit Public-Facing Application (Initial Access)
  Overview: Khai thác lỗ hổng trong web app, API, VPN gateway đối ngoại.
  Attack angle: Tìm CVE exploitable và service misconfiguration.
  Defense focus: WAF + patch management + input validation là 3 lớp bảo vệ chính.
  Detection tools: waf, siem
  Common indicators: Anomalous HTTP payload, SQL injection pattern, Path traversal
```

Model không cần biết T1190 là gì — nó được cung cấp đầy đủ để reasoning.

#### 1b. Network Topology Injection (`network_topology_builder.py`)

CVE ID được inject từ infrastructure description, không để model tự nhớ:

```
Host: WEB-01 [CRITICAL]
  IP: 10.0.1.10, Zone: DMZ
  Services: Apache 2.4.49, OpenSSH 8.9
  CVEs: CVE-2021-41773          ← inject thẳng, không hỏi model
  Patch status: unpatched
  Security controls: none
```

**Kết quả:** Model nhìn thấy "CVE-2021-41773 trên Apache 2.4.49" trong context → reasoning về impact và exploit path đúng, dù trước đó không biết CVE này là gì.

#### 1c. Output Format Constraint (`cyber_expert_profile_generator.py`)

System prompt buộc agent dùng format có cấu trúc:

```
[FINDING] Tiêu đề mô tả vulnerability class
Severity: critical|high|medium|low
Affected: [host/service từ context]         ← phải tham chiếu context thật
Evidence: [lý do cụ thể từ hạ tầng]        ← không được tự bịa
Detail: [mô tả chi tiết]
Recommendation: [hành động cụ thể]
```

Field `Evidence` và `Affected` buộc model phải **dẫn chứng từ context được cung cấp**, không thể tự bịa ra host hoặc CVE không tồn tại trong input.

---

### Cơ chế 2: Multi-Agent Cross-Validation (Hallucination bị challenge)

**Vấn đề gốc:** Single agent hallucinate → không ai phát hiện.

**Giải pháp:** 18 agent đọc và challenge lẫn nhau. Hallucination từ 1 agent bị expose khi agent khác có domain knowledge khác nhau.

#### Phase A — Intra-group challenge

```
Network/Offensive agent: "Apache 2.4.48 có thể bị exploit bằng CVE-2021-41773"
                                          ↑ sai version
Network/Defensive agent: "CVE-2021-41773 chỉ ảnh hưởng 2.4.49, không phải 2.4.48.
                          Finding này cần verify lại version chính xác."
Network/Architect agent: "Đồng ý với Defensive — version mismatch làm giảm
                          confidence của finding này."
→ challenged_by ghi nhận, confidence giảm
```

#### Phase B — Cross-group challenge

```
AppSec/Offensive: "SQL injection trên API endpoint /login"
                  (hallucinate — không có evidence nào trong network description)

Network/Architect: "CROSS_CHALLENGE: Không thấy API /login được đề cập
                   trong infrastructure description. Cần evidence cụ thể."

Risk/CISO: "CROSS_CHALLENGE: Finding này thiếu affected asset cụ thể.
            Không thể đánh giá business impact nếu không rõ host nào."
→ cross_group_validated = False → cross_group_score thấp → confidence thấp
```

#### Phase C — Attacker corroboration

Đây là cơ chế độc đáo nhất. Attacker profile agent đọc toàn bộ findings và phán xét từ góc nhìn **"tôi có thật sự exploit được không?"**:

```
Expert finding: "Default credential trên RDP là lỗ hổng nghiêm trọng"

Opportunistic attacker:  ATTACKER_CONFIRM  → +0.15 confidence
                         "Đây là target đầu tiên tôi sẽ thử"

APT attacker:            ATTACKER_CONFIRM  → +0.15 confidence
                         "Valid — dùng để establish initial foothold"

Insider Threat:          ATTACKER_DISMISS  → -0.20 confidence
                         "Không liên quan với tôi — đã có legitimate access rồi"

→ Net: +0.15 + 0.15 - 0.20 = +0.10 → confidence tăng nhẹ, giữ finding
```

```
Expert finding: "Firewall rule X tạo attack path từ DMZ vào Database"
(thực ra là hallucination — không có evidence trong input)

Opportunistic:  ATTACKER_DISMISS  "Không thấy path này trong scan"
APT:            ATTACKER_DISMISS  "Trust relationship không tồn tại theo mô tả"
Ransomware:     ATTACKER_DISMISS  "Không có route nào đến backup từ DMZ"

→ 3 DISMISS → net delta = -0.60 → confidence = 0.12 → bị filter (< 0.35)
→ Hallucination bị loại trước khi vào report
```

---

### Cơ chế 3: Weighted Consensus Filter (Hallucination không qua được threshold)

**Vấn đề gốc:** Ngay cả sau challenge, vẫn có thể còn finding sai.

**Giải pháp:** 3-layer confidence score — finding phải vượt qua cả 3 lớp để đi vào report.

```
Final confidence = L1 × 0.30 + L2 × 0.45 + L3 × 0.25

Layer 1 — Intra-group agreement (0.30):
  % agents trong cùng domain group đồng ý
  Hallucination thường chỉ được 1 agent nêu → intra_score thấp

Layer 2 — Cross-group validation (0.45) ← trọng số cao nhất:
  % domain groups KHÁC đã validate finding
  Hallucination ít khi được nhiều domain khác nhau xác nhận
  → cross_score là bộ lọc hiệu quả nhất

Layer 3 — Attacker corroboration (0.25):
  Net score từ 5 attacker profiles
  Hallucination về exploit path → attacker DISMISS → score giảm

Filter: confidence < 0.35 → loại (likely false positive)
```

#### Ví dụ số liệu

```
Finding thật (RDP exposed, evidence rõ ràng):
  L1 (intra):   0.80  → 2/3 agents trong network group đồng ý
  L2 (cross):   0.80  → 4/5 domain groups validate
  L3 (attack):  0.85  → 4/5 attacker profiles confirm
  Final = 0.80×0.30 + 0.80×0.45 + 0.85×0.25 = 0.817 ✅ đưa vào report

Finding hallucinated (attack path không có evidence):
  L1 (intra):   0.33  → chỉ 1/3 agents đồng ý (người nêu ra)
  L2 (cross):   0.20  → chỉ 1/5 groups xác nhận
  L3 (attack):  0.10  → 3/5 attacker DISMISS
  Final = 0.33×0.30 + 0.20×0.45 + 0.10×0.25 = 0.214 ❌ bị filter
```

---

## 3. Tại sao Kiến trúc này Robust hơn Single-Agent

### So sánh trực tiếp

| Tình huống | Single-Agent System | Multi-Expert Panel |
|---|---|---|
| 1 agent hallucinate CVE ID | Đi thẳng vào output | 17 agent có thể challenge |
| Agent bịa attack path | Không ai phát hiện | Cross-group: "Không có evidence" |
| Finding chỉ 1 người nêu | Đi vào report | L1 score thấp → confidence thấp |
| Không group nào validate | Không áp dụng | L2 = 0 → confidence < threshold |
| Attacker không thể exploit | Không áp dụng | ATTACKER_DISMISS → confidence giảm |

### Redundancy by design

```
Để 1 hallucinated finding lọt vào report cuối, nó phải:
  1. Vượt qua intra-group challenge    (Phase A)
  2. Vượt qua cross-group challenge    (Phase B)
  3. Vượt qua attacker DISMISS         (Phase C)
  4. Vượt qua threshold 0.35          (ConsensusEngine)

Xác suất vượt qua cả 4 lớp << xác suất lọt qua single-agent check
```

---

## 4. Giới hạn và Thành thật

Hệ thống **không loại bỏ hoàn toàn** hallucination:

```
Vẫn có thể xảy ra khi:
  - Tất cả agents cùng hallucinate về 1 vấn đề
    (do cùng training data bias)
  - Finding được nhiều agents đồng thuận nhưng đều sai
    (systematic bias, không phải random hallucination)
  - Context injection bị sai ngay từ đầu
    (network description input không chính xác)
```

Đây là lý do tại sao:
1. **Attacker profiles** được thiết kế với motivation khác nhau — giảm systematic bias
2. **Output nên được human review** với findings có confidence 0.35–0.60
3. Hệ thống không thay thế penetration tester — nó là **lớp pre-screening** giúp tập trung effort vào đúng chỗ

---

## 5. Đóng góp cho Luận án

### Novelty rõ ràng

Không có paper hoặc sản phẩm nào hiện tại sử dụng **attacker profile corroboration** như một cơ chế giảm hallucination trong vulnerability discovery. Đây là đóng góp kỹ thuật mới có thể trình bày rõ ràng.

### Research Question đề xuất

```
RQ (bổ sung): "Kiến trúc Multi-Expert Panel với 3-layer consensus
               có làm giảm hallucination rate so với single-agent LLM
               trong vulnerability discovery không?"

Đo lường:
  - False Positive rate: findings trong report không có trong
    actual vulnerability list của target system
  - So sánh: Single LLM vs Multi-Expert Panel trên cùng 3 scenarios
  - Expected result: FP rate của Panel < FP rate của single agent
    vì consensus filter loại hallucinated findings
```

### Argument cho thesis

> *"Thay vì cố gắng dùng model chính xác hơn — vốn đòi hỏi compute cao và vẫn không loại bỏ được hallucination — hệ thống này áp dụng nguyên lý fault tolerance: mỗi agent có thể sai, nhưng hệ thống được thiết kế để phát hiện và filter những sai lầm đó thông qua structured multi-agent deliberation. Đây là cách tiếp cận thực tế hơn cho deployment trong môi trường production, nơi không thể kiểm soát được model quality."*

---

*Document này mô tả thiết kế hallucination mitigation trong hệ thống Multi-Expert Panel — một phần của luận án Thạc sĩ An toàn thông tin.*
