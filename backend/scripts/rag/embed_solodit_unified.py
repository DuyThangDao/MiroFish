#!/usr/bin/env python3
"""
Build solodit_unified ChromaDB collection.

Mỗi finding trong rag_sections_cache.json → 1 document:
    [VULNERABILITY]
    {vul}

    [INVARIANT]
    {inv}

    [OPERATIONS]
    {op}

avg ~1213 chars, không truncate. Dùng cho agentic RAG (search_audit_memory tool)
thay thế solodit_findings (raw report blob, avg 4911 chars).

Chạy:
    cd backend && source .venv/bin/activate
    python scripts/rag/embed_solodit_unified.py

Idempotent: skip findings đã indexed (dựa vào slug id).
"""
import sys
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import json, os, time
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[3] / ".env")

import chromadb
from chromadb import EmbeddingFunction, Documents, Embeddings
import vertexai
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput
from google.api_core.exceptions import ResourceExhausted

CHROMA_PATH  = Path("data/rag_db/chroma")
CACHE_PATH   = Path("scripts/rag/rag_sections_cache.json")
COLLECTION   = "solodit_unified"
UPSERT_BATCH = 40    # docs per ChromaDB upsert — Vertex AI limit ~20k tokens/batch


# ─── Helpers ─────────────────────────────────────────────────────────────────

def to_str(v) -> str:
    """Sections may be stored as list or string."""
    if isinstance(v, list):
        return " ".join(str(x) for x in v if x)
    return v or ""


def build_document(f: dict) -> str:
    s = f.get("sections") or {}
    vul = to_str(s.get("vul")).strip()
    inv = to_str(s.get("inv")).strip()
    op  = to_str(s.get("op")).strip()

    parts = []
    if vul:
        parts.append(f"[VULNERABILITY]\n{vul}")
    if inv:
        parts.append(f"[INVARIANT]\n{inv}")
    if op:
        parts.append(f"[OPERATIONS]\n{op}")
    return "\n\n".join(parts)


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


# ─── Vertex AI Embedding ──────────────────────────────────────────────────────

class VertexEmbedding(EmbeddingFunction):
    def __init__(self):
        key_file = (
            os.environ.get("LLM2_VERTEX_AI_KEY_FILE")
            or os.environ.get("LLM_VERTEX_AI_KEY_FILE", "")
        )
        if key_file:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = key_file
            project_id = json.load(open(key_file)).get("project_id", "")
        else:
            project_id = ""
        vertexai.init(project=project_id or None)
        self._model = TextEmbeddingModel.from_pretrained("text-embedding-004")

    def __call__(self, input: Documents) -> Embeddings:
        inputs = [TextEmbeddingInput(text, "RETRIEVAL_DOCUMENT") for text in input]
        max_retries = 8
        for attempt in range(max_retries):
            try:
                return [e.values for e in self._model.get_embeddings(inputs)]
            except ResourceExhausted:
                if attempt == max_retries - 1:
                    raise
                wait = min(60, 2 ** attempt)
                print(f"  [WARN] Vertex AI 429 — chờ {wait}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    if not CACHE_PATH.exists():
        print(f"ERROR: {CACHE_PATH} not found.")
        return

    print("Loading rag_sections_cache.json ...")
    cache = json.loads(CACHE_PATH.read_text())
    findings = cache.get("findings", [])
    print(f"  {len(findings)} findings loaded")

    # Build doc list — skip findings with no usable content
    all_docs = []
    skipped = 0
    for f in findings:
        slug = f.get("slug", "")
        if not slug:
            skipped += 1
            continue

        doc_text = build_document(f)
        if not doc_text.strip():
            skipped += 1
            continue

        all_docs.append({
            "id":       slug,
            "document": doc_text,
            "metadata": {
                "slug":           slug,
                "title":          f.get("title", "")[:200],
                "firm":           f.get("firm", ""),
                "protocol":       f.get("protocol", ""),
                "impact":         f.get("impact", ""),
                "source_link":    f.get("source_link", "")[:300],
                "content_source": f.get("content_source", ""),
            },
        })

    total = len(all_docs)
    print(f"  {total} docs to embed  ({skipped} skipped — no content)")

    if total == 0:
        print("Nothing to embed.")
        return

    # Quick sanity check on doc lengths
    lens = [len(d["document"]) for d in all_docs]
    avg_len = sum(lens) // len(lens)
    print(f"  Doc length: avg={avg_len}, min={min(lens)}, max={max(lens)}")

    # Connect ChromaDB
    embed_fn = VertexEmbedding()
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    col = client.get_or_create_collection(
        COLLECTION,
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"},
    )

    existing = col.count()
    if existing >= total:
        print(f"\nsolodit_unified already built ({existing} docs >= {total} expected). Skip.")
        print("To rebuild: delete the collection first.")
        return

    print(f"\nExisting: {existing} / {total}. Embedding remaining ...")

    # Skip already-indexed slugs
    if existing > 0:
        existing_ids = set(col.get(include=[])["ids"])
    else:
        existing_ids = set()

    to_embed = [d for d in all_docs if d["id"] not in existing_ids]
    print(f"To embed: {len(to_embed)} docs\n")

    done = 0
    t0 = time.time()
    for batch in chunks(to_embed, UPSERT_BATCH):
        col.upsert(
            ids=[d["id"] for d in batch],
            documents=[d["document"] for d in batch],
            metadatas=[d["metadata"] for d in batch],
        )
        done += len(batch)
        elapsed = time.time() - t0
        rate = done / elapsed if elapsed > 0 else 0
        eta = (len(to_embed) - done) / rate if rate > 0 else 0
        print(f"  {done}/{len(to_embed)} ({done / len(to_embed) * 100:.1f}%)"
              f"  {rate:.1f} docs/s  ETA {eta / 60:.1f}min")

    final_count = col.count()
    print(f"\nDone. solodit_unified: {final_count} docs.")


if __name__ == "__main__":
    main()
