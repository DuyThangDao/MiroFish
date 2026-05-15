# RAG Implementation Plan v2 — Nguồn dữ liệu: Solodit API

**Ngày tạo:** 2026-05-14  
**Thay thế:** `rag-implementation-plan.md` (dùng DeFiHackLabs — đã loại bỏ)  
**Nguồn dữ liệu duy nhất:** [solodit.cyfrin.io](https://solodit.cyfrin.io)

---

## Tổng quan

Solodit là nền tảng tổng hợp audit reports từ Code4rena, Sherlock, Cyfrin, Spearbit...
Mỗi finding đã có:
- `content`: full write-up dạng markdown (description, code snippet, impact, mitigation)
- `summary`: AI-generated tóm tắt (~2–3 câu)
- `quality_score` (0–5): filter chất lượng
- `slug`: ID duy nhất

**Kết quả:** Không cần LLM để summarize — dùng thẳng `content` làm văn bản embed.
Toàn bộ pipeline chạy hoàn toàn offline sau bước fetch.

### Pipeline tổng thể (streaming batch)

```
Solodit API (page N)
    │ 20 findings
    ▼
[Step 1] Fetch & Deduplicate
    │ lọc slug đã thấy
    ▼
[Step 2] Preprocess & Blacklist
    │ lọc web3bugs benchmark
    ▼
[Step 3] Schema → Document
    │ dict chuẩn
    ▼
[Step 4] Ingest → ChromaDB
    │ upsert batch
    ▼
Fetch page N+1 → lặp lại
```

---

## Step 1 — Fetch từ Solodit

### 1.1 Cấu hình fetch

Mục tiêu: lấy **HIGH** findings, ngôn ngữ **Solidity**, nguồn **Code4rena**, sort by Quality Desc.

```python
FETCH_CONFIG = {
    "impact":     ["HIGH"],
    "firms":      [{"value": "Code4rena"}],
    "languages":  [{"value": "Solidity"}],
    "sortField":  "Quality",
    "sortDirection": "Desc",
    "pageSize":   20,
}
```

> Verified 2026-05-14: filter này trả về **1605 findings** (so với 1669 khi không filter language).
> `languages` nhận cùng format `[{"value": "..."}]` như `firms`.
> Sau khi ổn định có thể mở rộng thêm MEDIUM hoặc các nguồn Cyfrin, Spearbit.

### 1.2 Rate limit handling

Giới hạn: **20 requests / 60 giây** (trả về trong response header `rateLimit`).

Chiến lược:
- Sleep **3.5s** giữa mỗi page (~ an toàn với 20 req/60s)
- Nếu `rateLimit.remaining < 3` → sleep đến `rateLimit.reset` + 1s

```python
rate = data.get("rateLimit", {})
if rate.get("remaining", 20) < 3:
    wait = rate["reset"] - time.time()
    time.sleep(max(wait + 1, 0))
else:
    time.sleep(3.5)
```

### 1.3 Duplicate prevention — `seen_slugs.json`

Mỗi finding có field `slug` (dạng `h-01-...-code4rena-gte-git`) là **ID duy nhất toàn cục**.

`seen_slugs.json` theo dõi các slug đã được ingest vào ChromaDB để:
- Bỏ qua bước preprocess + ingest (tiết kiệm CPU)
- Vẫn **FETCH tất cả các trang** từ 1 đến `totalPages` (không bỏ qua page nào)

```python
SEEN_SLUGS_PATH = Path("data/rag_db/seen_slugs.json")

def load_seen_slugs() -> set[str]:
    if SEEN_SLUGS_PATH.exists():
        return set(json.loads(SEEN_SLUGS_PATH.read_text()))
    return set()

def save_seen_slugs(slugs: set[str]):
    SEEN_SLUGS_PATH.write_text(json.dumps(sorted(slugs), indent=2))
```

### 1.4 Pagination strategy — tại sao luôn phải duyệt hết tất cả trang

**Vấn đề với offset pagination:** Solodit dùng `page`/`pageSize` (offset-based).
Nếu dataset thay đổi giữa 2 lần chạy (finding mới được thêm vào với quality cao →
đẩy các finding cũ xuống trang sau), cùng một `page=5` sẽ trả về findings khác nhau.

**Kết quả:** Trên incremental run, trang đầu có thể trùng 15/20, trang tiếp theo 17/20...
Nhưng điều này KHÔNG làm mất finding nào vì:
- Script luôn chạy từ `page=1` đến `page=totalPages`
- Finding mới (ở trang đầu) sẽ được bắt gặp ngay lần đầu tiên
- Finding cũ (đã có trong `seen_slugs`) chỉ bị bỏ qua ở bước ingest, không bỏ qua ở bước fetch

**Cái thực sự cần tránh:** early-stop dựa trên "trang này toàn duplicate → dừng".
Pattern đó MỚI gây mất finding.

### 1.5 Terminate condition — khi nào fetch xong

**Cách 1 — `totalPages` từ API (primary, luôn dùng):**

API trả về `metadata.totalPages` trong mỗi response. Dừng khi `page >= totalPages`.
Đây là nguồn sự thật duy nhất về số trang — luôn phản ánh dataset hiện tại.

```python
meta = data.get("metadata", {})
if page >= meta.get("totalPages", 1):
    break
```

**Cách 2 — Early-exit cho incremental run (optimization):**

Trước khi bắt đầu vòng lặp, fetch page 1 để lấy `totalResults`. So sánh với `len(seen_slugs)`:

```python
# Lấy totalResults từ page 1
resp = requests.post(SOLODIT_URL, json={**payload, "page": 1}, headers=headers)
total_in_api = resp.json()["metadata"]["totalResults"]
new_count = total_in_api - len(seen_slugs)  # ước tính số finding mới (trừ blacklist)

if new_count <= 0:
    print(f"DB đã up-to-date: {len(seen_slugs)}/{total_in_api} findings. Bỏ qua.")
    return
print(f"Cần fetch ~{new_count} findings mới từ {total_in_api} tổng")
```

> `new_count` là **ước tính** — có thể dương nhưng thực tế sau blacklist không còn gì mới.
> Đây chỉ là optimization để tránh 81 API calls khi DB đã đầy, không phải điều kiện dừng chính xác.

**Tóm tắt logic terminate:**

```
totalResults từ API = 1605
seen_slugs (đã ingest) = 1200
→ Có thể còn ~405 finding mới → chạy full paginate

totalResults từ API = 1605
seen_slugs (đã ingest) = 1605
→ Không cần chạy → exit sớm
```

```python
SEEN_SLUGS_PATH = Path("data/rag_db/seen_slugs.json")

def load_seen_slugs() -> set[str]:
    if SEEN_SLUGS_PATH.exists():
        return set(json.loads(SEEN_SLUGS_PATH.read_text()))
    return set()

def save_seen_slugs(slugs: set[str]):
    SEEN_SLUGS_PATH.write_text(json.dumps(sorted(slugs), indent=2))
```

Pipeline incremental: chạy lại script sẽ **bỏ qua ingest** findings đã có trong DB,
nhưng vẫn duyệt hết `totalPages` trang để bắt findings mới ở bất kỳ trang nào.

---

## Step 2 — Preprocess & Blacklist

### 2.1 Blacklist web3bugs benchmark contests

**Vấn đề:** Solodit chứa findings từ các Code4rena contests đang dùng làm benchmark
(web3bugs). Nếu đưa vào RAG → data leakage → F1 score sẽ bị inflate.

**Lưu ý quan trọng về `contest_id`:**
Field `contest_id` **có tồn tại** trong Solodit response nhưng là **ID nội bộ của Solodit**
(ví dụ: `514` cho GTE, `525` cho Sequence). Đây KHÔNG phải ID của web3bugs (35, 42, 104) —
hai hệ thống dùng ID riêng biệt, không thể map trực tiếp.

→ **Không thể blacklist bằng `contest_id`** từ Solodit data.

**Cách duy nhất đáng tin cậy — Title matching với web3bugs reports:**

Hai nguồn dữ liệu dùng format title khác nhau:

| Nguồn | Format title | Ví dụ |
|---|---|---|
| web3bugs report (`.md`) | `## [[H-01] Title](url)` | `## [[H-01] Unsafe cast in burn](https://...)` |
| Solodit API (`title` field) | `[H-01] Title` | `[H-01] Unsafe cast in burn` |

→ Chỉ cần so sánh phần **Title text** sau khi strip prefix `[H-xx]` từ cả hai.
URL trong web3bugs header không liên quan đến việc matching.

Web3bugs reports nằm tại `/home/thangdd/repos/web3bugs/reports/*.md`.

```python
import re
from pathlib import Path

def build_web3bugs_title_set() -> set[str]:
    """Extract tất cả H-bug titles từ web3bugs reports.
    Header format trong .md: ## [[H-01] Title text](url)
    Regex lấy phần 'Title text' — bỏ số H-xx và URL.
    """
    titles = set()
    for path in Path("/home/thangdd/repos/web3bugs/reports").glob("*.md"):
        text = path.read_text(errors="replace")
        for m in re.finditer(r'##\s+\[\[H-\d+\]\s+(.+?)\]', text):
            titles.add(m.group(1).strip().lower())
    return titles

def is_blacklisted_by_title(finding: dict, web3bugs_titles: set[str]) -> bool:
    # Solodit title: "[H-01] Title text" → strip prefix → "title text"
    title = re.sub(r'^\[h-\d+\]\s*', '', finding.get("title", "").lower())
    return title in web3bugs_titles
```

```python
def should_skip(finding: dict, seen_slugs: set, web3bugs_titles: set) -> bool:
    if finding.get("slug") in seen_slugs:
        return True
    if is_blacklisted_by_title(finding, web3bugs_titles):
        return True
    return False
```

### 2.2 Không filter theo quality_score

Findings đã được filter `impact=HIGH` từ Code4rena — đây là tín hiệu đủ mạnh vì finding
đã qua review của judge và được công nhận là lỗ hổng thực.

`quality_score` của Solodit đo chất lượng **write-up** (có POC không, code snippet đầy đủ
không), không phải độ nghiêm trọng. Với RAG, ta cần coverage rộng về vulnerability
patterns — một finding quality_score thấp vẫn chứa đủ signal semantic để embed và retrieve.

→ Lấy tất cả 1605 findings, không filter theo `quality_score`.

### 2.3 Scrape source_link — BẮT BUỘC

**Vấn đề với `content` field:** Solodit API truncate `content` không nhất quán — một số
findings chỉ còn phần intro (1–2 đoạn), mất hoàn toàn code snippet, description đầy đủ,
và PoC. Ví dụ verified: finding "Partial signature replay" có `content` chỉ 1172 chars,
trong khi nội dung thực trên report là 13280 chars (thiếu 11.3x).

→ **Luôn scrape `source_link`** để lấy nội dung đầy đủ thay thế `content` field.

#### Bước 1 — Scrape full report từ source_link

Code4rena dùng Next.js SPA — nội dung nhúng trong RSC payload của HTML (không cần headless browser):

```python
import urllib.request, re, html as html_module

def scrape_full_report(source_link: str) -> str:
    """Scrape toàn bộ contest report từ source_link (Code4rena Next.js RSC payload)."""
    req = urllib.request.Request(
        source_link,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read().decode("utf-8", errors="replace")
    chunks = re.findall(r'self\.__next_f\.push\(\[1,"(.*?)"\]\)', raw, re.DOTALL)
    combined = "".join(chunks)
    decoded = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), combined)
    decoded = decoded.replace('\\n', '\n').replace('\\t', '\t')
    text = re.sub(r'<[^>]+>', ' ', decoded)
    text = html_module.unescape(text)
    text = re.sub(r' {2,}', ' ', text)
    return re.sub(r'\n{3,}', '\n\n', text).strip()
```

#### Bước 2 — Extract section của finding cụ thể

`source_link` của một finding trỏ đến **toàn bộ contest report** — chứa H-01, H-02, H-03,
M-01... của cùng một dự án. Cần tách đúng phần của finding cần lấy.

**Cơ chế extraction:**
1. Dùng title text (bỏ prefix `[H-xx]`) để tìm vị trí bắt đầu của finding trong report
2. Tìm vị trí bắt đầu của finding **tiếp theo** bằng pattern `[H-xx]`, `[M-xx]`, `[L-xx]`
3. Cắt đoạn text giữa hai vị trí đó

```python
# Pattern nhận biết ranh giới giữa các findings
FINDING_BOUNDARY = re.compile(r'\[(?:H|M|L|G|I)-\d+\]')

# Pattern nhận biết section header của report (nằm sau finding cuối cùng của nhóm)
# Dùng để cắt khi finding là cuối cùng trong nhóm H/M/L nhưng vẫn còn nhóm khác phía sau
SECTION_HEADER = re.compile(
    r'(?:Medium|Low|Gas|Informational|Non[-\s]?Critical)\s+Risk\s+Findings'
    r'|Assessed\s+type'       # footer thường gặp trên Code4rena
    r'|Audit\s+Analysis',
    re.IGNORECASE
)

def extract_finding_section(full_report: str, finding_title: str) -> str:
    """
    Tách section của 1 finding từ full contest report.

    finding_title: title từ Solodit, ví dụ "[H-01] Order double-linked list..."
    full_report  : toàn bộ text đã scrape từ source_link

    Trả về text từ đầu finding đến trước finding tiếp theo.

    Edge cases được xử lý:
    - Finding ở giữa: cắt tại [H-xx]/[M-xx] tiếp theo
    - Finding cuối nhóm H (còn nhóm M sau): cắt tại "Medium Risk Findings"
    - Finding cuối toàn bộ report: cắt tại section footer, hoặc lấy đến hết
    """
    # Strip prefix [H-xx] / [M-xx] để lấy core title
    core_title = re.sub(r'^\[(?:H|M|L|G|I)-\d+\]\s*', '', finding_title).strip()

    # Tìm vị trí bắt đầu của finding này trong report
    start = full_report.find(core_title)
    if start == -1:
        return ""  # không tìm thấy → fallback về content field

    # Lùi lại để bao gồm cả prefix [H-xx] nếu có ngay trước core_title
    prefix_search = full_report.rfind('[', max(0, start - 10), start)
    if prefix_search != -1 and FINDING_BOUNDARY.match(full_report[prefix_search:start + 5]):
        start = prefix_search

    remainder = full_report[start + len(core_title):]

    # Ưu tiên 1: finding tiếp theo [H-xx] / [M-xx] / ...
    next_finding = FINDING_BOUNDARY.search(remainder)

    # Ưu tiên 2: section header tiếp theo (e.g. "Medium Risk Findings")
    next_section = SECTION_HEADER.search(remainder)

    if next_finding and next_section:
        # Lấy cái nào gần hơn
        boundary = min(next_finding.start(), next_section.start())
    elif next_finding:
        boundary = next_finding.start()
    elif next_section:
        # Finding cuối nhóm H, sau đó là "Medium Risk Findings..."
        boundary = next_section.start()
    else:
        # Finding cuối cùng toàn bộ report — lấy hết đến cuối, không giới hạn.
        # An toàn vì đã check FINDING_BOUNDARY + SECTION_HEADER ở trên rồi.
        # Một finding phức tạp có PoC có thể dài 13000+ chars — không nên cắt.
        boundary = len(remainder)

    end = start + len(core_title) + boundary
    return full_report[start:end].strip()
```

**Ví dụ các trường hợp:**

| Tình huống | Cơ chế dừng |
|---|---|
| Finding giữa report (H-01, còn H-02 sau) | Dừng tại `[H-02]` |
| Finding cuối nhóm H (H-03, tiếp theo là M-01) | Dừng tại `[M-01]` |
| Finding cuối nhóm H (H-03, tiếp theo là "Medium Risk Findings" header) | Dừng tại section header |
| Finding cuối toàn bộ report (không còn gì sau) | Lấy hết đến cuối — không giới hạn |

#### Bước 3 — Cache per source_link

Nhiều findings trong cùng 1 contest dùng chung `source_link` → scrape 1 lần, dùng nhiều lần:

```python
_report_cache: dict[str, str] = {}  # in-memory cache trong 1 run

def get_finding_content(finding: dict) -> str:
    """Lấy full content của finding: scrape source_link + extract section."""
    source_link = finding.get("source_link", "")
    if not source_link:
        return finding.get("content", "") or finding.get("title", "")

    # Cache lookup
    if source_link not in _report_cache:
        try:
            _report_cache[source_link] = scrape_full_report(source_link)
        except Exception as e:
            print(f"  [WARN] scrape failed {source_link}: {e} — fallback to content field")
            return finding.get("content", "") or finding.get("title", "")

    full_report = _report_cache[source_link]
    section = extract_finding_section(full_report, finding.get("title", ""))

    if not section:
        # Fallback: core_title không tìm thấy trong report (hiếm gặp)
        return finding.get("content", "") or finding.get("title", "")

    return section
```

> **Rate limit khi scrape:** Mỗi `source_link` duy nhất = 1 HTTP request tới Code4rena.
> Với ~1600 findings nhưng chỉ ~500–600 contest reports khác nhau (mỗi contest nhiều findings),
> số lượng request thực tế ít hơn số findings. Thêm `time.sleep(1)` sau mỗi scrape mới
> (không áp dụng cho cache hit).

**Fallback chain:**
```
source_link scrape + extract → (nếu fail) content field → (nếu rỗng) title
```

---

## Step 3 — Schema Document

### 3.1 Luồng dữ liệu → ChromaDB

```
Solodit API response (finding dict)
    │
    ├─ slug          ──────────────────────────→ id       (ChromaDB document ID)
    │
    ├─ title, impact, protocol_name             │
    ├─ summary                                  ├──→ document  (text được embed)
    └─ source_link → [Step 2.3 scrape+extract] ─┘
         scraped_content                        │
                                                └──→ metadata  (filter & display)
    ├─ firm_name, protocol_name, impact
    ├─ quality_score, contest_id
    ├─ title, slug, source_link
```

Mỗi document ChromaDB gồm 3 phần:

```
{
  "id":       slug,                          # "solodit_h-01-...-code4rena-gte-git"
  "document": build_document_text(...),      # text được embed — xem 3.2
  "metadata": build_metadata(...),           # dict filter — xem 3.3
}
```

### 3.2 Field `document` — nơi scraped_content được lưu

`document` là field ChromaDB dùng để **embed + trả về khi query**. Đây là nơi
`scraped_content` từ Step 2.3 được lưu vào.

**Tại sao không dùng `content` field của Solodit:** Bị truncate không nhất quán
(verified: finding "Partial signature replay" chỉ có 1172 chars thay vì 13280 chars đầy đủ).

```python
def build_document_text(f: dict, scraped_content: str) -> str:
    """
    f              : finding dict từ Solodit API
    scraped_content: kết quả từ get_finding_content(f) — full section từ source_link

    Output → field 'document' trong ChromaDB upsert call.
    """
    parts = [
        f"Title: {f.get('title', '')}",
        f"Impact: {f.get('impact', '')}",
        f"Protocol: {f.get('protocol_name', '')}",
        f"\n{scraped_content}",
    ]
    return "\n".join(parts)
```

Ví dụ document thực tế cho finding H-01 GTE:
```
Title: [H-01] Order double-linked list is broken because order.prevOrderId is not persisted
Impact: HIGH
Protocol: GTE

[H-01] Order double-linked list is broken...
Submitted by montecristo, also found by...
order.prevOrderId is updated only in memory and not saved to storage...
Description: Orders are stored as a double-linked list...
File: contracts/clob/types/Book.sol
150: function addOrderToBook(...)
...
Impact: Order adding/removal will be affected...
Recommended Mitigation: ...
```

> `summary` không cần thiết — `scraped_content` đã mở đầu bằng mô tả ngắn gọn của finding
> (brief description ngay sau title trong Code4rena report). Thêm summary chỉ tạo redundancy.

### 3.3 Chunking strategy — 1 Finding = N Vectors (Parent-Child)

#### Vấn đề: Silent Truncation của Vertex AI

`text-embedding-004` có context window **2048 tokens (~6000–8000 ký tự)**.
Khi input vượt giới hạn, API **không báo lỗi** — tự động cắt bỏ phần thừa.

Hậu quả với finding dài như H-02 Sequence (13.280 ký tự):
- Phần đầu (description, code snippet đầu): được embed ✅
- Phần cuối (PoC đầy đủ, mitigation): bị cắt mất → không có trong vector ❌

Vector thu được chỉ đại diện cho ~50% nội dung finding — retrieval sẽ bỏ sót
hoặc rank sai những findings có PoC phức tạp ở nửa sau.

#### Giải pháp: Semantic Chunking + Parent-Child Retrieval

**Nguyên lý:** 1 finding = N chunks nhỏ (embed) + 1 parent document đầy đủ (lưu riêng).

```
build_document_text() output (13.280 chars)
    │
    ▼ chunk_text(chunk_size=3000, overlap=600)
    ├─ Chunk 0: chars 0–3000       → embed → ChromaDB id: solodit_{slug}_chunk_0
    ├─ Chunk 1: chars 2400–5400    → embed → ChromaDB id: solodit_{slug}_chunk_1
    ├─ Chunk 2: chars 4800–7800    → embed → ChromaDB id: solodit_{slug}_chunk_2
    ├─ Chunk 3: chars 7200–10200   → embed → ChromaDB id: solodit_{slug}_chunk_3
    └─ Chunk 4: chars 9600–12600   → embed → ChromaDB id: solodit_{slug}_chunk_4

Full text (13.280 chars) → parents.json: { slug: full_text }
```

**Overlap 600 chars (20%):** Tránh cắt đôi hàm Solidity — Chunk 1 lặp lại
600 chars cuối của Chunk 0, đảm bảo không có đoạn code nào bị chia nửa.

#### Chunking function — dùng RecursiveCharacterTextSplitter

**Tại sao không tự viết vòng lặp `text[start:start+3000]`:**
Cắt cứng theo index sẽ cắt vô điều kiện tại ký tự thứ 3000 — có thể rơi đúng giữa
một khai báo hàm Solidity:

```
Chunk 1: "...function transferFrom(address sender, ad"
Chunk 2: "dress recipient, uint256 amount) public {"
```

Hai nửa "từ vỡ" này trở thành token vô nghĩa trong không gian embedding — vector
của đoạn code đó bị hỏng hoàn toàn.

**`RecursiveCharacterTextSplitter`** cắt theo thứ tự ưu tiên:
1. `\n\n` — ranh giới giữa 2 hàm / 2 đoạn văn (lý tưởng nhất)
2. `\n` — xuống dòng
3. `" "` — dấu cách (ranh giới từ)
4. `""` — ký tự đơn (fallback, chỉ khi từ dài hơn chunk_size — không xảy ra trong thực tế)

Luôn tìm ranh giới tự nhiên gần nhất trước khi chạm chunk_size → không bao giờ cắt giữa từ.

```python
from langchain_text_splitters import RecursiveCharacterTextSplitter

CHUNK_SIZE    = 3000   # ~800 tokens — an toàn với 2048 token limit của text-embedding-004
CHUNK_OVERLAP = 600    # 20% overlap — chunk sau lặp lại 600 chars cuối chunk trước

_splitter = RecursiveCharacterTextSplitter(
    chunk_size=CHUNK_SIZE,
    chunk_overlap=CHUNK_OVERLAP,
    separators=["\n\n", "\n", " ", ""],
)

def chunk_text(text: str) -> list[str]:
    return _splitter.split_text(text)
```

#### Parent store — parents.json

```python
PARENTS_PATH = Path("data/rag_db/parents.json")

def load_parents() -> dict[str, str]:
    if PARENTS_PATH.exists():
        return json.loads(PARENTS_PATH.read_text())
    return {}

def save_parents(parents: dict[str, str]):
    PARENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    PARENTS_PATH.write_text(json.dumps(parents, ensure_ascii=False, indent=2))
```

`parents.json` lưu `{ slug: build_document_text() output }` — full text bao gồm
cả header `Title/Impact/Protocol` để agent đọc được ngữ cảnh đầy đủ ngay khi nhận.

#### Luồng retrieval với Parent-Child

```
Agent query → ChromaDB tìm chunk khớp nhất
                │
                ▼
           chunk metadata chứa slug
                │
                ▼ dedup theo slug (giữ chunk similarity cao nhất)
           parents.json[slug] → full 13.280 chars
                │
                ▼
           Agent nhận full content (Gemini Flash đọc 13k chars = ~0.013 cents)
```

**Tại sao không trả chunk thô cho agent:** Agent nhận "chunk giữa" thiếu context
(ví dụ: đoạn code PoC không có phần Description phía trước) → hiểu sai severity.
Trả full parent giải quyết hoàn toàn vấn đề này.

### 3.4 Metadata schema

```python
def build_metadata(f: dict) -> dict:
    return {
        "source":        "solodit",
        "firm_name":     f.get("firm_name", ""),          # "Code4rena" | "Sherlock"...
        "protocol_name": f.get("protocol_name", ""),      # "GTE" | "Uniswap"...
        "impact":        f.get("impact", ""),             # "HIGH" | "MEDIUM"
        "quality_score": str(f.get("quality_score", 0)), # "5" | "4" (ChromaDB chỉ nhận str)
        "contest_id":    str(f.get("contest_id", "")),    # dùng khi audit cần exclude
        "title":         f.get("title", ""),              # hiển thị trong kết quả
        "slug":          f.get("slug", ""),               # key tra cứu parents.json
        "source_link":   f.get("source_link", ""),        # link full report
        # chunk_index và total_chunks được thêm lúc ingest (xem Step 4)
    }
```

> **Lưu ý ChromaDB:** metadata values phải là `str | int | float | bool`.
> `quality_score` convert sang `str` để an toàn.
> Mỗi chunk lưu cùng metadata của parent + thêm `chunk_index` (int) và `total_chunks` (int).
> `slug` trong metadata là khóa tra cứu `parents.json` khi retrieval.

### 3.5 Có cần LLM không?

**Không.** Solodit cung cấp human-written `content` field đầy đủ.
Không cần call LLM thêm bất kỳ bước nào trong pipeline này.

So sánh với DeFiHackLabs:

| Nguồn | Content có sẵn | Cần LLM | Chi phí |
|---|---|---|---|
| DeFiHackLabs | PoC Solidity code only | ✅ (summarize code) | ~$5–10/1000 docs |
| **Solodit** | Full markdown write-up | ❌ | $0 |

---

## Step 4 — Ingest vào ChromaDB

### 4.1 Setup ChromaDB với monkey-patch SQLite

```python
# PHẢI đặt trước mọi import chromadb
import sys
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import os, chromadb
from chromadb import EmbeddingFunction, Documents, Embeddings
```

> Ubuntu 20.04 có SQLite 3.31.1 < 3.35.0 (yêu cầu của ChromaDB 1.5.9).
> Monkey-patch thay thế sqlite3 bằng pysqlite3-binary (3.46+).

### 4.2 Vertex AI Embedding Function

Dùng `text-embedding-004` từ Vertex AI thay vì `all-MiniLM-L6-v2` để hiểu
Solidity code trong findings tốt hơn (768 dims vs 384, trained trên diverse data gồm code).

**Task type:**
- Build DB (upsert documents): `RETRIEVAL_DOCUMENT`
- Query lúc audit: `RETRIEVAL_QUERY`

Hai task type khác nhau → embedding được tối ưu riêng cho từng vai trò, cải thiện
retrieval quality so với dùng cùng 1 task type cho cả hai.

```python
import time, vertexai
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput
from google.api_core.exceptions import ResourceExhausted  # HTTP 429 từ Vertex AI

class VertexEmbedding(EmbeddingFunction):
    """ChromaDB-compatible embedding function dùng Vertex AI text-embedding-004."""

    def __init__(self, task_type: str = "RETRIEVAL_DOCUMENT"):
        # Đọc credentials từ env (set từ LLM_VERTEX_AI_KEY_FILE trong .env)
        key_file = os.environ.get("LLM_VERTEX_AI_KEY_FILE", "")
        if key_file:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = key_file
        vertexai.init()
        self._model = TextEmbeddingModel.from_pretrained("text-embedding-004")
        self._task_type = task_type

    def __call__(self, input: Documents) -> Embeddings:
        inputs = [TextEmbeddingInput(text, self._task_type) for text in input]
        max_retries = 5
        for attempt in range(max_retries):
            try:
                return [e.values for e in self._model.get_embeddings(inputs)]
            except ResourceExhausted:
                if attempt == max_retries - 1:
                    raise
                wait = 2 ** attempt  # exponential backoff: 1, 2, 4, 8, 16s
                print(f"  [WARN] Vertex AI 429 — chờ {wait}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait)
```

> **Exponential backoff:** Retry 1 sau 1s, retry 2 sau 2s, ..., retry 5 sau 16s.
> Sau 5 lần thất bại liên tiếp mới raise — đủ để qua được spike tạm thời của Vertex AI.
> Quota bình thường là 1500 req/phút, backoff chỉ kích hoạt khi thực sự quá tải.

### 4.3 Khởi tạo collection

```python
CHROMA_PATH = "data/rag_db/chroma"
COLLECTION_NAME = "solodit_findings"  # ≥ 3 ký tự (yêu cầu ChromaDB 1.5.9)

def get_collection():
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    embed_fn = VertexEmbedding(task_type="RETRIEVAL_DOCUMENT")
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"},
    )
```

### 4.4 Chunk upsert — 1 finding → N chunks vào ChromaDB

Mỗi finding được split thành chunks trước khi upsert. `seen_slugs` vẫn track theo
**parent slug** (không phải chunk ID) — nếu slug đã seen nghĩa là tất cả chunks đã được ingest.

```python
def ingest_finding(col, f: dict, parents: dict, seen: set) -> tuple[int, int]:
    """
    Ingest 1 finding thành N chunks. Trả về (số chunk đã upsert, 1 nếu finding mới).
    Cập nhật parents dict và seen set in-place.
    """
    slug = f["slug"]
    full_text = build_document_text(f, get_finding_content(f))
    parents[slug] = full_text  # lưu toàn văn vào parent store

    chunks = chunk_text(full_text)
    base_meta = build_metadata(f)

    ids   = [f"solodit_{slug}_chunk_{i}" for i in range(len(chunks))]
    docs  = chunks
    metas = [{**base_meta, "chunk_index": i, "total_chunks": len(chunks)}
             for i in range(len(chunks))]

    col.upsert(ids=ids, documents=docs, metadatas=metas)
    seen.add(slug)
    return len(chunks), 1
```

> Dùng `upsert` → idempotent: chạy lại không bị lỗi duplicate.
> ID chunk dạng `solodit_{slug}_chunk_{i}` — unique vì slug đã unique toàn cục.

### 4.5 Script pipeline hoàn chỉnh

File: `backend/scripts/rag/build_rag_db.py`

```python
#!/usr/bin/env python3
"""
Build RAG database từ Solodit API (Parent-Child chunking).
Chạy: python -m scripts.rag.build_rag_db
"""
import sys
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import json, os, time, re, html as html_module
import urllib.request
from pathlib import Path
import requests, chromadb
from chromadb import EmbeddingFunction, Documents, Embeddings
import vertexai
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput
from langchain_text_splitters import RecursiveCharacterTextSplitter
from google.api_core.exceptions import ResourceExhausted

class VertexEmbedding(EmbeddingFunction):
    def __init__(self, task_type: str = "RETRIEVAL_DOCUMENT"):
        key_file = os.environ.get("LLM_VERTEX_AI_KEY_FILE", "")
        if key_file:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = key_file
        vertexai.init()
        self._model = TextEmbeddingModel.from_pretrained("text-embedding-004")
        self._task_type = task_type

    def __call__(self, input: Documents) -> Embeddings:
        inputs = [TextEmbeddingInput(text, self._task_type) for text in input]
        max_retries = 5
        for attempt in range(max_retries):
            try:
                return [e.values for e in self._model.get_embeddings(inputs)]
            except ResourceExhausted:
                if attempt == max_retries - 1:
                    raise
                wait = 2 ** attempt  # 1, 2, 4, 8, 16s
                print(f"  [WARN] Vertex AI 429 — chờ {wait}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait)

SOLODIT_URL   = "https://solodit.cyfrin.io/api/v1/solodit/findings"
API_KEY       = os.environ["SOLODIT_API_KEY"]
CHROMA_PATH   = Path("data/rag_db/chroma")
SLUGS_PATH    = Path("data/rag_db/seen_slugs.json")
PARENTS_PATH  = Path("data/rag_db/parents.json")
WEB3BUGS_DIR  = Path("/home/thangdd/repos/web3bugs/reports")
CHUNK_SIZE    = 3000
CHUNK_OVERLAP = 600

_splitter = RecursiveCharacterTextSplitter(
    chunk_size=CHUNK_SIZE,
    chunk_overlap=CHUNK_OVERLAP,
    separators=["\n\n", "\n", " ", ""],
)

# ── Persistence helpers ────────────────────────────────────────────────────────

def load_seen_slugs() -> set[str]:
    if SLUGS_PATH.exists():
        return set(json.loads(SLUGS_PATH.read_text()))
    return set()

def save_seen_slugs(slugs: set[str]):
    SLUGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SLUGS_PATH.write_text(json.dumps(sorted(slugs), indent=2))

def load_parents() -> dict[str, str]:
    if PARENTS_PATH.exists():
        return json.loads(PARENTS_PATH.read_text())
    return {}

def save_parents(parents: dict[str, str]):
    PARENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    PARENTS_PATH.write_text(json.dumps(parents, ensure_ascii=False, indent=2))

# ── Chunking ───────────────────────────────────────────────────────────────────

def chunk_text(text: str) -> list[str]:
    """Split text tại ranh giới tự nhiên (\n\n → \n → space), không cắt giữa từ."""
    return _splitter.split_text(text)

# ── Blacklist ──────────────────────────────────────────────────────────────────

def build_web3bugs_titles() -> set[str]:
    titles = set()
    for path in WEB3BUGS_DIR.glob("*.md"):
        text = path.read_text(errors="replace")
        for m in re.finditer(r'##\s+\[\[H-\d+\]\s+(.+?)\]', text):
            titles.add(m.group(1).strip().lower())
    return titles

def should_skip(f: dict, seen: set, wb_titles: set) -> bool:
    if f.get("slug") in seen:
        return True
    # contest_id của Solodit là ID nội bộ — không map được với web3bugs IDs
    title = re.sub(r'^\[h-\d+\]\s*', '', f.get("title", "").lower())
    return title in wb_titles

# ── Scraping ───────────────────────────────────────────────────────────────────

FINDING_BOUNDARY = re.compile(r'\[(?:H|M|L|G|I)-\d+\]')
SECTION_HEADER   = re.compile(
    r'(?:Medium|Low|Gas|Informational|Non[-\s]?Critical)\s+Risk\s+Findings'
    r'|Assessed\s+type|Audit\s+Analysis',
    re.IGNORECASE
)
_report_cache: dict[str, str] = {}

def scrape_full_report(source_link: str) -> str:
    req = urllib.request.Request(
        source_link,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read().decode("utf-8", errors="replace")
    chunks = re.findall(r'self\.__next_f\.push\(\[1,"(.*?)"\]\)', raw, re.DOTALL)
    combined = "".join(chunks)
    decoded = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), combined)
    decoded = decoded.replace('\\n', '\n').replace('\\t', '\t')
    text = re.sub(r'<[^>]+>', ' ', decoded)
    return re.sub(r' {2,}', ' ', html_module.unescape(text)).strip()

def extract_finding_section(full_report: str, finding_title: str) -> str:
    core_title = re.sub(r'^\[(?:H|M|L|G|I)-\d+\]\s*', '', finding_title).strip()
    start = full_report.find(core_title)
    if start == -1:
        return ""
    prefix_search = full_report.rfind('[', max(0, start - 10), start)
    if prefix_search != -1 and FINDING_BOUNDARY.match(full_report[prefix_search:start + 5]):
        start = prefix_search
    remainder = full_report[start + len(core_title):]
    next_finding = FINDING_BOUNDARY.search(remainder)
    next_section  = SECTION_HEADER.search(remainder)
    if next_finding and next_section:
        boundary = min(next_finding.start(), next_section.start())
    elif next_finding:
        boundary = next_finding.start()
    elif next_section:
        boundary = next_section.start()
    else:
        boundary = len(remainder)  # finding cuối report — lấy hết, không giới hạn
    return full_report[start:start + len(core_title) + boundary].strip()

def get_finding_content(finding: dict) -> str:
    source_link = finding.get("source_link", "")
    if not source_link:
        return finding.get("content", "") or finding.get("title", "")
    if source_link not in _report_cache:
        try:
            _report_cache[source_link] = scrape_full_report(source_link)
            time.sleep(1)
        except Exception as e:
            print(f"  [WARN] scrape failed: {e}")
            return finding.get("content", "") or finding.get("title", "")
    section = extract_finding_section(_report_cache[source_link], finding.get("title", ""))
    return section or finding.get("content", "") or finding.get("title", "")

# ── Document builders ──────────────────────────────────────────────────────────

def build_document_text(f: dict, scraped_content: str) -> str:
    return "\n".join([
        f"Title: {f.get('title', '')}",
        f"Impact: {f.get('impact', '')}",
        f"Protocol: {f.get('protocol_name', '')}",
        f"\n{scraped_content}",
    ])

def build_metadata(f: dict) -> dict:
    return {
        "source":        "solodit",
        "firm_name":     f.get("firm_name", ""),
        "protocol_name": f.get("protocol_name", ""),
        "impact":        f.get("impact", ""),
        "quality_score": str(f.get("quality_score", 0)),
        "contest_id":    str(f.get("contest_id", "")),
        "title":         f.get("title", ""),
        "slug":          f.get("slug", ""),
        "source_link":   f.get("source_link", ""),
    }

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    CHROMA_PATH.mkdir(parents=True, exist_ok=True)
    seen     = load_seen_slugs()
    parents  = load_parents()
    wb_titles = build_web3bugs_titles()
    print(f"Loaded {len(seen)} seen slugs | {len(wb_titles)} web3bugs titles to blacklist")

    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    embed_fn = VertexEmbedding(task_type="RETRIEVAL_DOCUMENT")
    col = client.get_or_create_collection(
        "solodit_findings",
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"},
    )

    headers = {"Content-Type": "application/json", "X-Cyfrin-API-Key": API_KEY}
    base_filters = {
        "impact":    ["HIGH"],
        "firms":     [{"value": "Code4rena"}],
        "languages": [{"value": "Solidity"}],
        "sortField": "Quality", "sortDirection": "Desc",
    }

    # Early-exit: kiểm tra totalResults trước khi chạy full paginate
    probe = requests.post(SOLODIT_URL, json={"page": 1, "pageSize": 1, "filters": base_filters}, headers=headers)
    total_in_api = probe.json()["metadata"]["totalResults"]
    if len(seen) >= total_in_api:
        print(f"DB đã up-to-date: {len(seen)}/{total_in_api} findings. Không cần fetch.")
        return
    print(f"Cần fetch: seen={len(seen)}, totalResults={total_in_api}, ước tính mới ~{total_in_api - len(seen)}")
    time.sleep(3.5)

    total_findings = 0
    page = 1

    while True:
        payload = {"page": page, "pageSize": 20, "filters": base_filters}
        resp = requests.post(SOLODIT_URL, json=payload, headers=headers)
        data = resp.json()
        findings = data.get("findings", [])
        if not findings:
            break

        to_ingest = [f for f in findings if not should_skip(f, seen, wb_titles)]
        all_ids, all_docs, all_metas = [], [], []

        for f in to_ingest:
            slug      = f["slug"]
            full_text = build_document_text(f, get_finding_content(f))
            parents[slug] = full_text  # lưu toàn văn vào parent store

            chunks    = chunk_text(full_text)
            base_meta = build_metadata(f)
            for i, chunk in enumerate(chunks):
                all_ids.append(f"solodit_{slug}_chunk_{i}")
                all_docs.append(chunk)
                all_metas.append({**base_meta, "chunk_index": i, "total_chunks": len(chunks)})

            seen.add(slug)
            total_findings += 1

        if all_ids:
            col.upsert(ids=all_ids, documents=all_docs, metadatas=all_metas)
            save_parents(parents)
            save_seen_slugs(seen)

        meta    = data.get("metadata", {})
        skipped = len(findings) - len(to_ingest)
        print(
            f"Page {page}/{meta.get('totalPages', '?')} — "
            f"ingested {len(to_ingest)} findings ({len(all_ids)} chunks), "
            f"skipped {skipped} | total findings: {total_findings} | DB chunks: {col.count()}"
        )

        if page >= meta.get("totalPages", 1):
            break

        rate = data.get("rateLimit", {})
        if rate.get("remaining", 20) < 3:
            wait = rate["reset"] - time.time()
            print(f"Rate limit — chờ {wait:.0f}s...")
            time.sleep(max(wait + 1, 0))
        else:
            time.sleep(3.5)
        page += 1

    print(f"\nDone. Total findings: {total_findings} | DB chunks: {col.count()}")

if __name__ == "__main__":
    main()
```

**Chạy:**
```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate
python -m scripts.rag.build_rag_db
```

---

## Step 5 — Agent Retrieval & Tích hợp Audit Pipeline

### 5.1 RAG Retriever module

File: `backend/scripts/rag/rag_retriever.py`

```python
import sys
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import json, os, time, chromadb
import numpy as np
from chromadb import EmbeddingFunction, Documents, Embeddings
from pathlib import Path
from typing import Optional
import vertexai
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput
from google.api_core.exceptions import ResourceExhausted

CHROMA_PATH  = Path("data/rag_db/chroma")
PARENTS_PATH = CHROMA_PATH.parent / "parents.json"

class VertexEmbedding(EmbeddingFunction):
    def __init__(self, task_type: str = "RETRIEVAL_QUERY"):
        key_file = os.environ.get("LLM_VERTEX_AI_KEY_FILE", "")
        if key_file:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = key_file
        vertexai.init()
        self._model = TextEmbeddingModel.from_pretrained("text-embedding-004")
        self._task_type = task_type

    def __call__(self, input: Documents) -> Embeddings:
        inputs = [TextEmbeddingInput(text, self._task_type) for text in input]
        max_retries = 5
        for attempt in range(max_retries):
            try:
                return [e.values for e in self._model.get_embeddings(inputs)]
            except ResourceExhausted:
                if attempt == max_retries - 1:
                    raise
                wait = 2 ** attempt  # 1, 2, 4, 8, 16s
                print(f"  [WARN] Vertex AI 429 — chờ {wait}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait)


def _cosine(a: list[float], b: list[float]) -> float:
    a, b = np.array(a), np.array(b)
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))


def mmr_select(
    candidates: list[dict],
    query_embedding: list[float],
    n: int = 5,
    lambda_: float = 0.5,
) -> list[dict]:
    """
    Maximal Marginal Relevance: chọn n candidates đa dạng nhất.
    Mỗi candidate phải có field 'score' (cosine similarity với query)
    và 'embedding' (vector của chunk đại diện).

    lambda_=0.5: cân bằng relevance và diversity (recommended).
    lambda_=1.0: pure cosine similarity (bỏ qua diversity).
    """
    selected, remaining = [], list(candidates)
    while len(selected) < n and remaining:
        if not selected:
            best = max(remaining, key=lambda c: c["score"])
        else:
            best = max(
                remaining,
                key=lambda c: (
                    lambda_ * c["score"]
                    - (1 - lambda_) * max(
                        _cosine(c["embedding"], s["embedding"]) for s in selected
                    )
                ),
            )
        selected.append(best)
        remaining.remove(best)
    return selected


class SolodirRetriever:
    def __init__(self):
        client = chromadb.PersistentClient(path=str(CHROMA_PATH))
        # Lưu embed_fn để embed query riêng lấy query_embedding cho MMR
        self._embed_fn = VertexEmbedding(task_type="RETRIEVAL_QUERY")
        self._col = client.get_collection("solodit_findings", embedding_function=self._embed_fn)
        # Load parent store — full build_document_text() output cho mỗi finding
        self._parents: dict[str, str] = (
            json.loads(PARENTS_PATH.read_text()) if PARENTS_PATH.exists() else {}
        )

    def query(
        self,
        query_text: str,
        n_results: int = 5,
        impact: Optional[list[str]] = None,
        lambda_: float = 0.5,
    ) -> list[dict]:
        where = {"impact": {"$in": impact}} if impact else None

        # Embed query riêng để dùng làm query_embedding cho MMR
        query_embedding = self._embed_fn([query_text])[0]

        # Fetch n_results*4 chunks, bao gồm embeddings để tính MMR diversity
        raw = self._col.query(
            query_texts=[query_text],
            n_results=n_results * 4,
            where=where,
            include=["metadatas", "distances", "embeddings"],
        )

        # Dedup theo slug — giữ chunk có similarity cao nhất (distance nhỏ nhất)
        # Lưu embedding của chunk đại diện để dùng trong MMR
        best: dict[str, dict] = {}
        for meta, dist, emb in zip(
            raw["metadatas"][0],
            raw["distances"][0],
            raw["embeddings"][0],
        ):
            slug = meta.get("slug", "")
            if slug not in best or dist < best[slug]["distance"]:
                best[slug] = {
                    "meta":      meta,
                    "distance":  dist,
                    "score":     round(1 - dist, 4),
                    "embedding": emb,   # vector chunk đại diện — dùng cho MMR
                }

        # MMR: chọn top-n_results đa dạng, tránh trả về 5 findings cùng pattern
        selected = mmr_select(list(best.values()), query_embedding, n=n_results, lambda_=lambda_)

        results = []
        for item in selected:
            meta = item["meta"]
            slug = meta.get("slug", "")
            results.append({
                "score":    item["score"],
                "title":    meta.get("title", ""),
                "impact":   meta.get("impact", ""),
                "firm":     meta.get("firm_name", ""),
                "protocol": meta.get("protocol_name", ""),
                "quality":  meta.get("quality_score", ""),
                "source":   meta.get("source_link", ""),
                # Full parent document (toàn văn 13k+ chars) — agent đọc được đầy đủ context
                "content":  self._parents.get(slug, ""),
            })
        return results
```

### 5.2 Tích hợp vào Audit Agent

Trong `audit_agent.py` hoặc `report_agent.py`, thêm RAG tool:

```python
from scripts.rag.rag_retriever import SolodirRetriever

retriever = SolodirRetriever()

def rag_search(query: str, impact: list[str] = None) -> str:
    """
    Tool: tìm kiếm audit findings tương tự từ Solodit RAG DB.
    Dùng khi cần example về vulnerability pattern tương tự.
    """
    results = retriever.query(query, n_results=5, impact=impact)
    if not results:
        return "Không tìm thấy findings liên quan."

    lines = [f"[RAG] Tìm thấy {len(results)} findings tương tự từ Solodit:\n"]
    for i, r in enumerate(results, 1):
        lines.append(
            f"--- Finding {i} (similarity: {r['score']:.3f}) ---\n"
            f"Title:    {r['title']}\n"
            f"Protocol: {r['protocol']} | Firm: {r['firm']} | Quality: {r['quality']}/5\n"
            f"Source:   {r['source']}\n"
            f"\n{r['content']}\n"
        )
    return "\n".join(lines)
```

### 5.3 Cơ chế chọn top-K — MMR thay vì pure cosine similarity

Nếu query trả về 20 findings, top-5 theo cosine similarity thuần có thể là 5 biến thể
rất giống nhau (ví dụ: 5 reentrancy bugs từ 5 protocol khác nhau nhưng pattern giống hệt).
Agent không học thêm được gì từ finding thứ 2 đến thứ 5.

**MMR (Maximal Marginal Relevance)** cân bằng giữa relevance và diversity:

```
score(finding) = λ × similarity(finding, query)
               − (1−λ) × max_similarity(finding, các_finding_đã_chọn)
```

- `λ = 1.0` → pure relevance (giống cosine thuần)
- `λ = 0.5` → cân bằng relevance và diversity (recommended)

**Luồng đầy đủ trong `query()`:**

```
ChromaDB.query(n_results=20, include=["embeddings"])
    │
    ▼ dedup theo slug → candidates (mỗi cái có score + embedding của chunk tốt nhất)
    │
    ▼ embed(query_text) → query_embedding (1 Vertex AI call riêng)
    │
    ▼ mmr_select(candidates, query_embedding, n=5, lambda_=0.5)
    │
    ▼ top-5 diverse findings → load parent → trả cho agent
```

`mmr_select` và toàn bộ logic trên đã được tích hợp trực tiếp vào `rag_retriever.py`
(xem Mục 5.1) — không phải code riêng lẻ.

**Lưu ý chi phí:** `query()` thực hiện **2 lần Vertex AI call**:
1. `self._embed_fn([query_text])` — lấy `query_embedding` cho MMR
2. `self._col.query(query_texts=[query_text])` — ChromaDB tự gọi embed_fn nội bộ

Cả hai đều embed cùng `query_text`. Nếu muốn tránh gọi 2 lần, có thể embed 1 lần,
dùng kết quả cho cả ChromaDB query (via `query_embeddings=`) lẫn MMR — nhưng cần
thêm code và lợi ích nhỏ (~200ms) nên giữ đơn giản.

### 5.4 Vị trí RAG trong luồng audit — không thay thế discovery

RAG chỉ được gọi **sau khi** agent tự phát hiện điểm nghi ngờ từ phân tích code.
Luồng đúng:

```
Đọc code → Tự phát hiện pattern nghi ngờ → Query RAG để xác nhận + làm giàu context
```

Nếu RAG không tìm thấy finding tương tự (similarity thấp), agent vẫn có thể report
finding đó dựa trên phân tích độc lập — đây có thể là lỗ hổng mới chưa có trong database.
RAG là bước **optional enrichment**, không phải bước discovery bắt buộc.

**Rủi ro cần tránh:** Thiết kế sai khi agent chỉ tìm những gì RAG biết → bị bias
về các pattern cũ, bỏ sót zero-day vulnerabilities.

### 5.5 RAG và Invariant — hai tầng độc lập

Hai cơ chế hoạt động ở tầng khác nhau và không được chạm vào nhau:

| | Invariant | RAG |
|---|---|---|
| **Nguồn** | Code của protocol đang audit | Database findings từ các protocol khác |
| **Mục tiêu** | Tìm vi phạm tính chất nội tại | Cung cấp context từ kinh nghiệm lịch sử |
| **Câu hỏi** | "Điều này có luôn đúng trong protocol này không?" | "Pattern này đã bị exploit như thế nào ở nơi khác?" |

**Xung đột xảy ra khi:** agent dùng invariant của protocol B (từ RAG) để suy luận về
protocol A đang audit — hai protocol khác nhau, invariant khác nhau hoàn toàn.

**Cách tránh:** Invariant extraction là bước **hoàn toàn nội bộ** (chỉ đọc code hiện tại,
không tham khảo RAG). RAG chỉ được gọi sau khi đã có finding từ invariant violation,
để làm rõ mức độ severity và cách exploit thực tế.

**RAG bổ trợ invariant:** Khi agent tìm thấy một invariant bị vi phạm, RAG cho biết
*cách attacker đã khai thác vi phạm tương tự trong quá khứ* → giúp đánh giá severity
chính xác hơn và viết PoC có chiều sâu hơn.

### 5.6 Performance optimization

#### Embedding speed
`text-embedding-004` là Vertex AI API call — query latency ~200–400ms mỗi request.
Không cần GPU local; cần credentials Vertex AI và kết nối internet.

#### HNSW index
ChromaDB tự động build HNSW index khi collection có > 100 docs.
Cosine similarity → `metadata={"hnsw:space": "cosine"}` (set khi create collection).

#### Lazy loading
`SolodirRetriever` nên là **singleton** (khởi tạo 1 lần khi app start) vì:
- Init Vertex AI client mất ~1s lần đầu
- Mỗi query sau đó là 1 API call (~200ms), không có local cache

```python
# app.py hoặc __init__.py
_retriever: SolodirRetriever = None

def get_retriever() -> SolodirRetriever:
    global _retriever
    if _retriever is None:
        _retriever = SolodirRetriever()
    return _retriever
```

#### Query caching (optional)
Nếu cùng 1 code snippet được query nhiều lần → cache kết quả với `functools.lru_cache`
hoặc `dict` in-memory (TTL 5 phút).

---

## Files tạo mới

| File | Mục đích |
|---|---|
| `backend/scripts/rag/build_rag_db.py` | Script build ChromaDB từ Solodit |
| `backend/scripts/rag/rag_retriever.py` | Retriever module cho audit agent |
| `backend/data/rag_db/chroma/` | ChromaDB persistent storage — chứa chunk vectors (auto-created) |
| `backend/data/rag_db/seen_slugs.json` | Dedup tracking theo parent slug (auto-created) |
| `backend/data/rag_db/parents.json` | Parent store — full `build_document_text()` output, key = slug (auto-created) |

## Dependencies

```bash
# Đã cài:
pysqlite3-binary        # SQLite monkey-patch
chromadb                # vector DB

# Cần cài thêm:
google-cloud-aiplatform # Vertex AI SDK (bao gồm vertexai + TextEmbeddingModel)
langchain-text-splitters # RecursiveCharacterTextSplitter — KHÔNG cần full langchain
```

```bash
cd backend && uv add google-cloud-aiplatform langchain-text-splitters
```

> `langchain-text-splitters` là package nhỏ, độc lập — không kéo theo toàn bộ LangChain.
> Chỉ chứa các text splitter utilities (~50KB), không có LLM/chain/agent dependencies.

**Credentials:** Script đọc `LLM_VERTEX_AI_KEY_FILE` từ `.env` và set
`GOOGLE_APPLICATION_CREDENTIALS` tự động — không cần config thêm.

> `sentence-transformers` không còn dùng cho embedding, có thể giữ lại nếu
> các phần khác của project vẫn cần.

---

## Checklist chạy lần đầu

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

# 1. Verify dependencies
python -c "
import sys; __import__('pysqlite3'); sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
import sqlite3, chromadb, os
import vertexai
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput
key_file = os.environ.get('LLM_VERTEX_AI_KEY_FILE', '')
if key_file:
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = key_file
vertexai.init()
model = TextEmbeddingModel.from_pretrained('text-embedding-004')
result = model.get_embeddings([TextEmbeddingInput('test embedding', 'RETRIEVAL_DOCUMENT')])
print('sqlite3:', sqlite3.sqlite_version)       # expect >= 3.35
print('chromadb:', chromadb.__version__)        # expect 1.5.x
print('embedding dims:', len(result[0].values)) # expect 768
print('ALL OK')
"

# 2. Build DB (background, ~30 phút cho toàn bộ Code4rena HIGH+MEDIUM)
SOLODIT_API_KEY=... python -m scripts.rag.build_rag_db

# 3. Verify DB
python -c "
import sys; __import__('pysqlite3'); sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
import os, chromadb
from chromadb import EmbeddingFunction, Documents, Embeddings
import vertexai
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput

class VertexEmbedding(EmbeddingFunction):
    def __init__(self, task_type='RETRIEVAL_QUERY'):
        key_file = os.environ.get('LLM_VERTEX_AI_KEY_FILE', '')
        if key_file:
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = key_file
        vertexai.init()
        self._model = TextEmbeddingModel.from_pretrained('text-embedding-004')
        self._task_type = task_type
    def __call__(self, input):
        return [e.values for e in self._model.get_embeddings(
            [TextEmbeddingInput(t, self._task_type) for t in input])]

c = chromadb.PersistentClient('data/rag_db/chroma')
col = c.get_collection('solodit_findings', embedding_function=VertexEmbedding())
print('Total docs:', col.count())
res = col.query(query_texts=['reentrancy attack in withdraw'], n_results=3)
for t in res['metadatas'][0]:
    print(' -', t['title'][:60])
"
```

---

## Ước tính dữ liệu

| Nguồn | Impact | Language | Số findings (verified) | Sau blacklist web3bugs |
|---|---|---|---|---|
| Code4rena | HIGH | Solidity | **1605** | ~1580–1600 |

~1590 findings × avg 2KB content/finding ≈ **~3MB raw text** → ChromaDB size ~30–50MB với embeddings.
