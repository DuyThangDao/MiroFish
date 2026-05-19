# Plan: Spearbit PDF Scraper cho RAG DB

## Vấn đề hiện tại

Toàn bộ 342 Spearbit findings đang lưu dạng `api_excerpt` (trích xuất ngắn từ Solodit API) thay vì full content, vì scraper hiện tại chỉ xử lý HTML (Next.js SSR payload) trong khi Spearbit source link là PDF trên GitHub.

**Hệ quả**: Embedding thiếu context → score RAG thấp → ít findings được inject vào agent → giảm hiệu quả Phase 5 invariant RAG.

---

## Cấu trúc PDF Spearbit (đã phân tích)

PDF được parse bằng `pymupdf` (fitz) cho ra plain text với cấu trúc nhất quán:

```
5.2.1
No price scaling in SMAOracle
Severity: High Risk
Context: SMAOracle.sol#L82-L96, ChainlinkOracleWrapper.sol#L36-L60
Description: The update() function ...
...code snippet...
Recommendation: ...
Tracer: Valid. Fixed in commit 669a61a.
Spearbit: Acknowledged.
5.2.2
Two different invariantCheck variables used in PoolFactory.deployPool()
Severity: High Risk
...
```

**Boundary pattern**:
- **Finding start**: `\n\d+\.\d+\.\d+\n{title}\nSeverity:`
- **Finding end**: next `\n\d+\.\d+(\.\d+)?\n` (finding tiếp theo hoặc section header như `5.3\nMedium Risk`)

**URL transform**:
```
blob:  https://github.com/spearbit/portfolio/blob/master/pdfs/Foo.pdf
raw:   https://raw.githubusercontent.com/spearbit/portfolio/master/pdfs/Foo.pdf
```

---

## Dependency

```bash
cd backend
uv add pymupdf   # package name: pymupdf, import: fitz
```

`pymupdf` đã có trong venv (import `fitz` đang hoạt động).

---

## Files cần sửa

| File | Thay đổi |
|------|----------|
| `backend/scripts/rag/build_rag_db.py` | Thêm `scrape_spearbit_pdf()`, sửa `get_finding_content()` |
| `backend/data/rag_db/seen_slugs.json` | Reset Spearbit slugs để re-ingest |

---

## Chi tiết implementation

### 1. Thêm PDF scraper vào `build_rag_db.py`

**Sau `_report_cache: dict[str, str] = {}`**, thêm:

```python
import fitz  # pymupdf

_PDF_BLOB_RE = re.compile(
    r'github\.com/([^/]+/[^/]+)/blob/([^/]+)/(.+\.pdf)',
    re.IGNORECASE,
)

def _blob_to_raw(url: str) -> str:
    """Transform GitHub blob URL → raw.githubusercontent.com URL."""
    m = _PDF_BLOB_RE.search(url)
    if not m:
        return url
    repo, ref, path = m.group(1), m.group(2), m.group(3)
    return f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"


_FINDING_SECTION_RE = re.compile(
    r'\n\d+\.\d+\.\d+\n(.+?)\nSeverity:',
    re.DOTALL,
)
_SECTION_BOUNDARY_RE = re.compile(r'\n\d+\.\d+(\.\d+)?\n')


def scrape_spearbit_pdf(pdf_url: str) -> str:
    """Download PDF từ raw GitHub URL và trả về full text."""
    raw_url = _blob_to_raw(pdf_url)
    req = urllib.request.Request(
        raw_url,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        pdf_bytes = r.read()
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    return "\n".join(page.get_text() for page in doc)


def extract_spearbit_section(full_text: str, finding_title: str) -> str:
    """Tìm section của finding trong PDF text bằng title matching."""
    # Normalize title: PDF text có thể thêm khoảng trắng/newline
    core = re.sub(r'\s+', ' ', finding_title).strip().lower()

    # Tìm tất cả finding boundaries
    for m in _FINDING_SECTION_RE.finditer(full_text):
        pdf_title = re.sub(r'\s+', ' ', m.group(1)).strip().lower()
        # Fuzzy match: PDF title chứa ≥80% words của API title
        api_words = set(core.split())
        pdf_words = set(pdf_title.split())
        overlap = len(api_words & pdf_words) / max(len(api_words), 1)
        if overlap >= 0.8:
            start = m.start()
            # Tìm boundary tiếp theo
            next_boundary = _SECTION_BOUNDARY_RE.search(full_text, m.end())
            end = next_boundary.start() if next_boundary else len(full_text)
            return full_text[start:end].strip()

    return ""
```

### 2. Sửa `get_finding_content()`

Thay logic hiện tại để nhận diện PDF và dùng scraper riêng:

```python
def get_finding_content(finding: dict) -> tuple[str, str]:
    source_link = finding.get("source_link", "")
    if not source_link:
        excerpt = finding.get("content", "")
        return (excerpt, "api_excerpt") if excerpt else (finding.get("title", ""), "title_only")

    is_pdf = source_link.lower().endswith(".pdf")

    if source_link not in _report_cache:
        try:
            if is_pdf:
                _report_cache[source_link] = scrape_spearbit_pdf(source_link)
            else:
                _report_cache[source_link] = scrape_full_report(source_link)
            time.sleep(1)
        except Exception as e:
            print(f"  [WARN] scrape failed ({source_link}): {e}")
            excerpt = finding.get("content", "")
            return (excerpt, "api_excerpt") if excerpt else (finding.get("title", ""), "title_only")

    full_text = _report_cache[source_link]
    if is_pdf:
        section = extract_spearbit_section(full_text, finding.get("title", ""))
    else:
        section = extract_finding_section(full_text, finding.get("title", ""))

    if section:
        return section, "scraped"
    excerpt = finding.get("content", "")
    return (excerpt, "api_excerpt") if excerpt else (finding.get("title", ""), "title_only")
```

---

## Re-ingest Spearbit

### Bước 1: Reset Spearbit slugs khỏi `seen_slugs.json`

```bash
cd backend
source .venv/bin/activate
python << 'EOF'
import sys, json
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
import chromadb
from pathlib import Path

# Lấy danh sách slug Spearbit từ ChromaDB
client = chromadb.PersistentClient(path='data/rag_db/chroma')
col = client.get_or_create_collection('solodit_findings')
total = col.count()
spearbit_slugs = set()
for offset in range(0, total, 500):
    res = col.get(limit=500, offset=offset, include=['metadatas'])
    for m in res['metadatas']:
        if m.get('firm_name') == 'Spearbit':
            spearbit_slugs.add(m['slug'])

# Xóa khỏi seen_slugs
slugs_path = Path('data/rag_db/seen_slugs.json')
seen = set(json.loads(slugs_path.read_text()))
before = len(seen)
seen -= spearbit_slugs
slugs_path.write_text(json.dumps(sorted(seen), indent=2))
print(f"Removed {before - len(seen)} Spearbit slugs. Remaining: {len(seen)}")

# Xóa Spearbit chunks khỏi ChromaDB
res_all = col.get(include=['metadatas'])
ids_to_delete = [
    res_all['ids'][i]
    for i, m in enumerate(res_all['metadatas'])
    if m.get('firm_name') == 'Spearbit'
]
if ids_to_delete:
    col.delete(ids=ids_to_delete)
print(f"Deleted {len(ids_to_delete)} Spearbit chunks from ChromaDB. New total: {col.count()}")
EOF
```

### Bước 2: Chạy lại ingest

```bash
cd /home/thangdd/repos/MiroFish/backend
LOG=/tmp/rag_spearbit_pdf_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
  set -a; source /home/thangdd/repos/MiroFish/.env; set +a
  source .venv/bin/activate
  exec python -u -m scripts.rag.build_rag_db
' >> "$LOG" 2>&1 &
echo "PID=$!  LOG=$LOG"
```

### Bước 3: Theo dõi

```bash
# Kiểm tra tiến độ
tail -f "$LOG"

# Tỉ lệ scraped vs api_excerpt
grep "scraped\|api_excerpt" "$LOG" | tail -20
```

---

## Verification sau khi xong

```bash
source .venv/bin/activate
python << 'EOF'
import sys, json
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
import chromadb
from collections import Counter

client = chromadb.PersistentClient(path='data/rag_db/chroma')
col = client.get_or_create_collection('solodit_findings')
total = col.count()

all_metas = []
for offset in range(0, total, 500):
    res = col.get(limit=500, offset=offset, include=['metadatas'])
    all_metas.extend(res['metadatas'])

firm_chunks   = Counter(m.get('firm_name') for m in all_metas)
firm_findings = Counter(m.get('firm_name') for m in all_metas if m.get('chunk_index') == 0)
spb_sources   = Counter(m.get('content_source') for m in all_metas if m.get('firm_name') == 'Spearbit')

print("Total chunks:", total)
print("Chunks by firm:", dict(firm_chunks))
print("Findings by firm:", dict(firm_findings))
print("Spearbit content_source:", dict(spb_sources))
# Target: scraped >> api_excerpt cho Spearbit
EOF
```

**Target**: `scraped` chiếm ≥70% Spearbit chunks (thay vì 0% hiện tại).

---

## Rủi ro & fallback

| Rủi ro | Xác suất | Xử lý |
|--------|----------|-------|
| PDF bị password-protect | Thấp | `fitz` trả về empty text → fallback api_excerpt |
| PDF scan (image-only) | Rất thấp | `fitz.get_text()` trả về empty → fallback |
| Title matching thất bại (overlap < 0.8) | Trung bình | Fallback api_excerpt; có thể tune threshold xuống 0.7 |
| Raw GitHub URL đổi format | Thấp | Log WARN, fallback api_excerpt |
| Rate limit GitHub raw CDN | Rất thấp | Thêm `time.sleep(0.5)` sau mỗi PDF nếu cần |

---

## Ước tính thời gian chạy

- 342 findings từ ~30-40 PDF khác nhau (nhiều findings/PDF)
- Mỗi PDF download ~1-2s, parse ~0.5s → ~30-40 PDF × 2s = ~1 phút download
- PDF được cache per-URL → chỉ download 1 lần/PDF
- Embedding không đổi — vẫn ~3.5s/page × 18 pages = ~60s embed
- **Tổng ước tính**: 15-20 phút (nhanh hơn lần đầu vì chỉ re-ingest Spearbit)
