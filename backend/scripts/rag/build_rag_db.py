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
from google.api_core.exceptions import ResourceExhausted, TooManyRequests

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
        max_retries = 8
        for attempt in range(max_retries):
            try:
                return [e.values for e in self._model.get_embeddings(inputs)]
            except (ResourceExhausted, TooManyRequests):
                if attempt == max_retries - 1:
                    raise
                wait = min(60, 2 ** attempt)
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
EMBED_BATCH   = 15   # max chunks per upsert — 15 × ~750 tokens ≈ 11250 < 20000 limit

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
    title = re.sub(r'^\[h-\d+\]\s*', '', f.get("title", "").lower()).strip()
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

def get_finding_content(finding: dict) -> tuple[str, str]:
    """Returns (content, content_source) where content_source is one of:
    'scraped', 'api_excerpt', 'title_only'."""
    source_link = finding.get("source_link", "")
    if not source_link:
        excerpt = finding.get("content", "")
        if excerpt:
            return excerpt, "api_excerpt"
        return finding.get("title", ""), "title_only"
    if source_link not in _report_cache:
        try:
            _report_cache[source_link] = scrape_full_report(source_link)
            time.sleep(1)
        except Exception as e:
            print(f"  [WARN] scrape failed: {e}")
            excerpt = finding.get("content", "")
            if excerpt:
                return excerpt, "api_excerpt"
            return finding.get("title", ""), "title_only"
    section = extract_finding_section(_report_cache[source_link], finding.get("title", ""))
    if section:
        return section, "scraped"
    excerpt = finding.get("content", "")
    if excerpt:
        return excerpt, "api_excerpt"
    return finding.get("title", ""), "title_only"

# ── Document builders ──────────────────────────────────────────────────────────

def build_document_text(f: dict, scraped_content: str) -> str:
    return "\n".join([
        f"Title: {f.get('title', '')}",
        f"Impact: {f.get('impact', '')}",
        f"Protocol: {f.get('protocol_name', '')}",
        f"\n{scraped_content}",
    ])

def build_metadata(f: dict, content_source: str = "scraped") -> dict:
    return {
        "source":         "solodit",
        "firm_name":      f.get("firm_name", ""),
        "protocol_name":  f.get("protocol_name", ""),
        "impact":         f.get("impact", ""),
        "quality_score":  str(f.get("quality_score", 0)),
        "contest_id":     str(f.get("contest_id", "")),
        "title":          f.get("title", ""),
        "slug":           f.get("slug", ""),
        "source_link":    f.get("source_link", ""),
        "content_source": content_source,
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
        "firms":     [{"value": "Cyfrin"}],
        "languages": [{"value": "Solidity"}],
        "sortField": "Quality", "sortDirection": "Desc",
    }

    # Probe: lấy tổng số findings theo filter hiện tại
    probe = requests.post(
        SOLODIT_URL,
        json={"page": 1, "pageSize": 1, "filters": base_filters},
        headers=headers,
    )
    total_in_api = probe.json()["metadata"]["totalResults"]
    print(f"Fetching: totalResults={total_in_api} (seen_slugs global={len(seen)})")
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
        n_chunks_page = 0

        for f in to_ingest:
            slug             = f["slug"]
            scraped, src     = get_finding_content(f)
            full_text        = build_document_text(f, scraped)
            parents[slug]    = full_text

            chunks    = chunk_text(full_text)
            base_meta = build_metadata(f, content_source=src)
            ids   = [f"solodit_{slug}_chunk_{i}" for i in range(len(chunks))]
            metas = [{**base_meta, "chunk_index": i, "total_chunks": len(chunks)}
                     for i in range(len(chunks))]

            for b in range(0, len(chunks), EMBED_BATCH):
                col.upsert(
                    ids=ids[b:b + EMBED_BATCH],
                    documents=chunks[b:b + EMBED_BATCH],
                    metadatas=metas[b:b + EMBED_BATCH],
                )
            seen.add(slug)
            total_findings += 1
            n_chunks_page += len(chunks)

        if to_ingest:
            save_parents(parents)
            save_seen_slugs(seen)

        meta    = data.get("metadata", {})
        skipped = len(findings) - len(to_ingest)
        print(
            f"Page {page}/{meta.get('totalPages', '?')} — "
            f"ingested {len(to_ingest)} findings ({n_chunks_page} chunks), "
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
