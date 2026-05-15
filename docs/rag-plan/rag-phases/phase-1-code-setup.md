# Phase 1 — Hoàn thiện code chuẩn bị xây dựng RAG

**Mục tiêu:** Cài đặt dependencies, tạo file structure, viết toàn bộ code.
Sau phase này, `python -m scripts.rag.build_rag_db` có thể chạy được (chưa cần API key thật).

**Tham chiếu:** [rag-implementing-plan-2.md](../rag-implementing-plan-2.md)

---

## Checklist

- [ ] 1. Cài dependencies
- [ ] 2. Tạo file structure
- [ ] 3. Viết `build_rag_db.py`
- [ ] 4. Viết `rag_retriever.py`
- [ ] 5. Thêm `.gitignore`
- [ ] 6. Verify imports

---

## Bước 1 — Cài dependencies

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

uv add google-cloud-aiplatform langchain-text-splitters
```

**Packages đã có sẵn (không cần cài lại):**
- `pysqlite3-binary` — SQLite monkey-patch cho ChromaDB trên Ubuntu 20.04
- `chromadb` — vector DB
- `requests` — HTTP client

**Verify sau khi cài:**
```bash
python -c "
from langchain_text_splitters import RecursiveCharacterTextSplitter
from google.api_core.exceptions import ResourceExhausted
import vertexai
from vertexai.language_models import TextEmbeddingModel
print('imports OK')
"
```

---

## Bước 2 — Tạo file structure

```bash
cd /home/thangdd/repos/MiroFish/backend

# Package init files
touch scripts/rag/__init__.py
touch scripts/rag/extractors/__init__.py   # nếu chưa có

# Data dir (tự tạo khi chạy script, nhưng tạo trước để .gitignore hoạt động)
mkdir -p data/rag_db
```

Cấu trúc sau khi hoàn thành:
```
backend/
├── scripts/
│   └── rag/
│       ├── __init__.py
│       ├── build_rag_db.py        ← Phase 1
│       └── rag_retriever.py       ← Phase 1
└── data/
    └── rag_db/
        ├── chroma/                ← auto-created khi build (Phase 2)
        ├── seen_slugs.json        ← auto-created khi build (Phase 2)
        └── parents.json           ← auto-created khi build (Phase 2)
```

---

## Bước 3 — Viết `build_rag_db.py`

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

# ── Embedding ──────────────────────────────────────────────────────────────────

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

# ── Constants ──────────────────────────────────────────────────────────────────

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
    # contest_id của Solodit là ID nội bộ — không map được với web3bugs IDs (35, 42, 104)
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
    seen      = load_seen_slugs()
    parents   = load_parents()
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
    probe = requests.post(
        SOLODIT_URL,
        json={"page": 1, "pageSize": 1, "filters": base_filters},
        headers=headers,
    )
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

---

## Bước 4 — Viết `rag_retriever.py`

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
    Mỗi candidate cần có 'score' (cosine similarity) và 'embedding' (chunk vector).
    lambda_=0.5: cân bằng relevance và diversity.
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
        self._embed_fn = VertexEmbedding(task_type="RETRIEVAL_QUERY")
        self._col = client.get_collection("solodit_findings", embedding_function=self._embed_fn)
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
                    "embedding": emb,
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
                "content":  self._parents.get(slug, ""),  # full parent document
            })
        return results
```

---

## Bước 5 — Thêm `.gitignore`

File: `backend/.gitignore`

```gitignore
# RAG vector database — build locally, không commit
data/rag_db/

# Python
__pycache__/
*.pyc
.env
```

---

## Bước 6 — Verify imports (không cần API key thật)

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

python -c "
import sys
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import sqlite3, chromadb
from langchain_text_splitters import RecursiveCharacterTextSplitter
from google.api_core.exceptions import ResourceExhausted

# Verify chunker hoạt động
splitter = RecursiveCharacterTextSplitter(chunk_size=3000, chunk_overlap=600)
chunks = splitter.split_text('hello world ' * 500)
print(f'sqlite3:  {sqlite3.sqlite_version}')   # expect >= 3.35
print(f'chromadb: {chromadb.__version__}')     # expect 1.5.x
print(f'chunks:   {len(chunks)} từ 6000 chars')
print('Phase 1 imports OK')
"
```

**Kết quả mong đợi:**
```
sqlite3:  3.46.x
chromadb: 1.5.9
chunks:   3 từ 6000 chars
Phase 1 imports OK
```

---

## Kết thúc Phase 1

Sau khi hoàn thành, các file sau đã tồn tại:
- `backend/scripts/rag/__init__.py`
- `backend/scripts/rag/build_rag_db.py`
- `backend/scripts/rag/rag_retriever.py`
- `backend/.gitignore` (có entry `data/rag_db/`)

**Chuyển sang** → [Phase 2: Thu thập dữ liệu và build RAG](phase-2-data-build.md)
