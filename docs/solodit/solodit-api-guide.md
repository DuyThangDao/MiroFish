# Solodit API — Hướng dẫn truy vấn Findings

**Platform:** [solodit.cyfrin.io](https://solodit.cyfrin.io)  
**Tài liệu chính thức:** [docs.solodit.cyfrin.io](https://docs.solodit.cyfrin.io)

---

## 1. Xác thực (Authentication)

Tạo account tại `solodit.cyfrin.io` → Dashboard dropdown → **API Keys** → Generate.

```bash
# API key lưu trong .env
SOLODIT_API_KEY=sk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Mọi request đều cần header:
```
X-Cyfrin-API-Key: <your_key>
```

---

## 2. Endpoint duy nhất cho Findings

```
POST https://solodit.cyfrin.io/api/v1/solodit/findings
Content-Type: application/json
X-Cyfrin-API-Key: <your_key>
```

**Rate limit:** 20 requests / 60 giây (trả về trong response header `rateLimit`).

---

## 3. Request Body Schema

```json
{
  "page": 1,
  "pageSize": 20,
  "filters": {
    "keywords":      "string — từ khóa tìm kiếm tự do",
    "impact":        ["HIGH", "MEDIUM", "LOW", "GAS", "INFORMATIONAL"],
    "firms":         [{"value": "Code4rena"}, {"value": "Sherlock"}],
    "sortField":     "Quality | Recency | Rarity",
    "sortDirection": "Asc | Desc"
  }
}
```

### Các giá trị hợp lệ

| Field | Kiểu | Giá trị chấp nhận |
|---|---|---|
| `page` | number | ≥ 1 |
| `pageSize` | number | 1–100 |
| `filters.impact` | string[] | `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"GAS"`, `"INFORMATIONAL"` (uppercase) |
| `filters.firms` | object[] | `{"value": "<tên firm>"}` — xem danh sách bên dưới |
| `filters.keywords` | string | Bất kỳ text nào |
| `filters.sortField` | string | `"Quality"`, `"Recency"`, `"Rarity"` |
| `filters.sortDirection` | string | `"Asc"`, `"Desc"` |

### Firms phổ biến

```
Code4rena   Sherlock    Spearbit    Trail of Bits
Cyfrin      OpenZeppelin    Cantina     Pashov Audit Group
```

---

## 4. Response Schema

```json
{
  "findings": [
    {
      "id":               "64869",
      "kind":             "GIT | PDF",
      "auditfirm_id":     "2",
      "impact":           "HIGH",
      "finders_count":    26,
      "protocol_id":      "3313",
      "title":            "[H-01] ...",
      "content":          "Full markdown write-up với code snippets và PoC",
      "summary":          "AI-generated tóm tắt ngắn (~2-3 câu)",
      "report_date":      {},
      "contest_prize_txt":"63250",
      "contest_link":     "https://code4rena.com/reports/...",
      "contest_id":       "514",
      "sponsor_name":     "GTE",
      "quality_score":    5,
      "general_score":    3.0,
      "source_link":      "https://...",
      "github_link":      "https://...",
      "slug":             "h-01-...-code4rena-gte-git",
      "firm_name":        "Code4rena",
      "protocol_name":    "GTE",
      "auditfirms_auditfirm": { "name": "Code4rena" },
      "protocols_protocol": { "name": "GTE" },
      "issues_issue_finders": [{ "wardens_warden": { "handle": "volodya" } }],
      "issues_issuetagscore": []
    }
  ],
  "metadata": {
    "totalResults": 1669,
    "currentPage":  1,
    "pageSize":     3,
    "totalPages":   557,
    "elapsed":      0.31
  },
  "rateLimit": {
    "limit":     20,
    "remaining": 19,
    "reset":     1778726460
  }
}
```

### Các field quan trọng nhất cho RAG

| Field | Dùng cho |
|---|---|
| `summary` | **Embed chính** — AI summary có sẵn, không cần gọi thêm LLM |
| `content` | Full write-up nếu cần context sâu hơn |
| `title` | Tiêu đề finding |
| `impact` | Severity filter / metadata |
| `firm_name` | Nguồn (Code4rena / Sherlock...) |
| `protocol_name` | Protocol bị ảnh hưởng |
| `contest_id` | Blacklist eval contests tránh data leakage |
| `quality_score` | Filter findings chất lượng (0–5, ưu tiên ≥ 4) |
| `slug` | Document ID duy nhất cho ChromaDB |

---

## 5. Ví dụ thực tế — 3 High Findings từ Code4rena

Đây là lệnh đã được verify hoạt động (2026-05-14):

```bash
curl -X POST "https://solodit.cyfrin.io/api/v1/solodit/findings" \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $SOLODIT_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 3,
    "filters": {
      "impact": ["HIGH"],
      "firms": [{"value": "Code4rena"}],
      "sortField": "Quality",
      "sortDirection": "Desc"
    }
  }'
```

**Kết quả:** `totalResults: 1669` findings HIGH từ Code4rena, sorted by quality.

Raw data response → xem `sample-findings.json` trong cùng thư mục.

---

## 6. Ví dụ Python cho Phase 2 Extractor

```python
import os, requests, time

SOLODIT_API_URL = "https://solodit.cyfrin.io/api/v1/solodit/findings"
API_KEY = os.environ["SOLODIT_API_KEY"]

# Blacklist contest IDs đang dùng làm benchmark — tránh data leakage
EVAL_CONTEST_IDS = {"35", "42", "104"}

def fetch_findings(
    impact: list[str] = ["HIGH", "MEDIUM"],
    firms: list[str] = ["Code4rena", "Sherlock"],
    min_quality: float = 4.0,
    max_pages: int = 100,
) -> list[dict]:
    headers = {
        "Content-Type": "application/json",
        "X-Cyfrin-API-Key": API_KEY,
    }
    all_findings = []

    for page in range(1, max_pages + 1):
        payload = {
            "page": page,
            "pageSize": 100,
            "filters": {
                "impact": impact,
                "firms": [{"value": f} for f in firms],
                "sortField": "Quality",
                "sortDirection": "Desc",
            },
        }
        resp = requests.post(SOLODIT_API_URL, json=payload, headers=headers)
        data = resp.json()

        findings = data.get("findings", [])
        if not findings:
            break

        for f in findings:
            # Bỏ qua findings từ eval contests
            if str(f.get("contest_id", "")) in EVAL_CONTEST_IDS:
                continue
            # Chỉ lấy findings chất lượng cao
            if (f.get("quality_score") or 0) < min_quality:
                continue
            all_findings.append(f)

        meta = data.get("metadata", {})
        print(f"Page {page}/{meta.get('totalPages', '?')} — collected {len(all_findings)}")

        # Nếu đã hết trang
        if page >= meta.get("totalPages", 1):
            break

        # Rate limit: 20 req/60s → sleep ~3.5s giữa các request
        rate = data.get("rateLimit", {})
        if rate.get("remaining", 20) < 3:
            reset_in = rate["reset"] - time.time()
            print(f"Rate limit sắp hết, chờ {reset_in:.0f}s...")
            time.sleep(max(reset_in + 1, 0))
        else:
            time.sleep(3.5)

    return all_findings


def finding_to_rag_doc(f: dict) -> dict:
    """Convert Solodit finding → ChromaDB document dict."""
    return {
        "id": f"solodit_{f['slug']}",
        "content": f["summary"] or f["title"],   # summary đã AI-generated
        "metadata": {
            "source":        "solodit",
            "firm_name":     f.get("firm_name", ""),
            "protocol_name": f.get("protocol_name", ""),
            "impact":        f.get("impact", ""),
            "quality_score": str(f.get("quality_score", 0)),
            "contest_id":    str(f.get("contest_id", "")),
            "title":         f.get("title", ""),
        },
    }
```

---

## 7. Lưu ý quan trọng

### `summary` thay thế LLM call
Khác với DeFiHackLabs (cần LLM summarize code), Solodit trả về `summary` field đã được
AI-generate sẵn. Dùng thẳng `summary` làm content để embed → **không tốn thêm chi phí LLM**.

### Blacklist eval contests
Solodit chứa cả findings từ Code4rena contests đang dùng làm benchmark (35, 42, 104...).
Bắt buộc filter theo `contest_id` trước khi upsert vào ChromaDB.

### `firms` field là `object[]` không phải `string[]`
```python
# ❌ Sai — trả về lỗi InvalidArgument
"firms": ["Code4rena"]

# ✅ Đúng
"firms": [{"value": "Code4rena"}]
```

### `impact` phải uppercase
```python
# ❌ Sai
"impact": ["High"]

# ✅ Đúng
"impact": ["HIGH"]
```

---

## 8. Lấy content từ `source_link` (Code4rena)

`source_link` trỏ đến trang Next.js SPA — browser render được nhưng curl chỉ nhận HTML shell,
không có nội dung vì content được load bằng JavaScript.

**Tuy nhiên**, Code4rena nhúng toàn bộ report vào HTML dưới dạng **Next.js RSC payload**
(`__next_f.push(...)`) — có thể parse mà không cần headless browser.

> **Lưu ý thực tế:** Field `content` từ Solodit API đã chứa đầy đủ write-up.
> Chỉ cần scrape `source_link` khi muốn lấy **toàn bộ report** (nhiều findings trong 1 contest)
> thay vì từng finding riêng lẻ.

### Scraper (đã verify hoạt động 2026-05-14)

```python
import urllib.request, re, html

def scrape_code4rena_report(source_link: str) -> str:
    """
    Fetch full report text từ code4rena.com/reports/<slug>.
    Parse Next.js RSC payload inline trong HTML — không cần Playwright hay headless browser.
    Trả về plain text đã strip HTML tags.
    """
    req = urllib.request.Request(
        source_link,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read().decode("utf-8", errors="replace")

    # Extract tất cả RSC chunks từ __next_f.push([1, "..."])
    chunks = re.findall(r'self\.__next_f\.push\(\[1,\"(.*?)\"\]\)', raw, re.DOTALL)
    combined = "".join(chunks)

    # Decode unicode escapes và newlines
    decoded = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), combined)
    decoded = decoded.replace('\\n', '\n').replace('\\t', '\t')

    # Strip HTML tags → plain text
    text = re.sub(r'<[^>]+>', ' ', decoded)
    text = html.unescape(text)
    text = re.sub(r' {2,}', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()
```

### Ví dụ sử dụng

```python
# Lấy full report contest GTE (finding 1 trong sample-findings.json)
text = scrape_code4rena_report(
    "https://code4rena.com/reports/2025-07-gte-spot-clob-and-router"
)

# Cắt từ phần High Risk Findings
start = text.find("High Risk Findings")
print(text[start:start + 5000])
```

**Kết quả:** Plain text toàn bộ report gồm H-01, H-02, H-03... với đầy đủ
description, code snippets, impact, mitigation. Xem file `scraped-report.md` làm mẫu.

### So sánh 3 cách

| Cách | Yêu cầu | Tốc độ | Độ bền |
|---|---|---|---|
| **RSC payload parse** (trên) | Chỉ `urllib` + `re` | ~1–2s/page | Tốt — RSC là chuẩn Next.js |
| **Playwright headless** | `uv add playwright` + Chromium 150MB | ~5–10s/page | Cao nhất |
| **Solodit `content` field** | Đã có sẵn trong API response | 0s | Tốt nhất — không cần crawl |
