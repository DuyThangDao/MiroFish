# Tài liệu kế hoạch: Vulnerability Exploit Race Simulation

Dựa trên nền tảng MiroFish — **Hướng C**

## 1. Ý tưởng

Khi một CVE được công bố, hai phe bắt đầu cuộc đua ngầm:

- **Red side**: Threat actor phát triển/mua exploit → tấn công trước khi patch được apply
- **Blue side**: Vendor release patch → CERT phát advisory → Tổ chức test và deploy patch

Kết quả cuộc đua phụ thuộc vào độ phức tạp của CVE, skill của threat actor, và patch cycle của từng tổ chức. **Không ai biết kết quả trước** — và đây là bài toán MiroFish phù hợp để mô phỏng.

**Core output**: "Với đặc điểm cụ thể của tổ chức X, họ có patch kịp trước khi bị khai thác không, và còn bao nhiêu ngày?"

## 2. Mapping với MiroFish

| MiroFish gốc | Hướng C |
|---|---|
| Tài liệu xã hội (PDF/TXT) | CVE report + Threat Intel report |
| Entity: người, tổ chức | Entity: CVE, software, org, threat actor |
| Agent: nhà báo, influencer | Agent: ThreatActor, DefenderOrg, CERT, Vendor |
| post/retweet/like | share_advisory / release_patch / develop_exploit / apply_patch |
| Thông tin lan truyền qua feed | Intel lan truyền qua security community |
| Dự đoán sentiment | Dự đoán exploit window, xác suất tổ chức bị tấn công |

Reuse ước tính: **~90%** kiến trúc MiroFish.

## 3. Phần cần xây mới

```text
backend/app/services/
├── nvd_loader.py              # Pull CVE data từ NVD API (free, structured)
├── exploit_race_engine.py     # Game loop: resolve exploit dev vs patch deployment
└── vuln_metrics_collector.py  # Exploit window, patch deadline, risk probability
```

Frontend: thay D3 visualization từ network map → timeline race chart.

## 4. Input / Output

**Input:**
```json
{
  "cve_id": "CVE-2024-XXXX",
  "org_profile": {
    "software_inventory": ["Apache Log4j 2.x", "Windows Server 2019"],
    "patch_cycle_days": 30,
    "security_team_size": 2
  }
}
```

**Output:**
```
Exploit Window:        8 ngày (APT) / 11 ngày (Script Kiddie)
Org patch deadline:    30 ngày
Kết quả dự báo:        SẼ BỊ TẤN CÔNG trong window ngày 8–30
Khuyến nghị:          Cần rút patch cycle xuống <8 ngày cho CVE này
```

## 5. Giới hạn thật sự (cần nhìn nhận)

- **Chỉ có value cao khi CVE mới ra** — CVE cũ đã biết exploit window từ thực tế
- **EPSS đã tồn tại** (USENIX 2022) — dùng ML trên historical data, miễn phí, tích hợp vào NVD
- **Commercial case yếu hơn kỳ vọng** — Tenable/Qualys đã tích hợp EPSS + asset inventory

## 6. Research Question cho luận án

> "Agent-based simulation có dự đoán exploit window và tổ chức at-risk chính xác hơn EPSS-based scoring không, và trong trường hợp nào?"

**Validation**: So sánh prediction với ExploitDB timestamp + Shodan historical data cho các CVE đã xảy ra.

**Publication**: RAID, Computers & Security journal — phù hợp hơn USENIX nếu kết quả không vượt trội EPSS rõ ràng.

---

*Hướng C có research value nhưng commercial case hạn chế do EPSS đã cover phần lớn use case. Xem Hướng D cho option thị trường tốt hơn.*
