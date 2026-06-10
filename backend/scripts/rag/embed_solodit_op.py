#!/usr/bin/env python3
"""
Embed solodit_op collection — mỗi op line trong sections.op → 1 ChromaDB doc.

Chạy SAU KHI fill_op_llm.py và fill_inv_llm.py hoàn thành:
    cd backend && source .venv/bin/activate
    python scripts/rag/embed_solodit_op.py

Idempotent: nếu collection đã build đủ số docs → skip.
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

CHROMA_PATH = Path("data/rag_db/chroma")
CACHE_PATH  = Path("scripts/rag/rag_sections_cache.json")
COLLECTION  = "solodit_op"
EMBED_BATCH = 40   # docs per embedding call (op lines are short)
UPSERT_BATCH = 40  # docs per ChromaDB upsert


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


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def main():
    if not CACHE_PATH.exists():
        print(f"ERROR: {CACHE_PATH} not found. Run fill_op_llm.py first.")
        return

    print("Loading rag_sections_cache.json ...")
    cache = json.loads(CACHE_PATH.read_text())
    findings = cache.get("findings", [])

    # Build flat list of all op docs
    all_docs = []
    for f in findings:
        slug = f["slug"]
        ops = (f.get("sections") or {}).get("op") or []
        impact = f.get("impact", "")
        firm = f.get("firm", "")
        for i, op in enumerate(ops):
            if not op or not op.strip():
                continue
            all_docs.append({
                "id":       f"{slug}::op::{i}",
                "document": op.strip()[:1200],
                "metadata": {"slug": slug, "impact": impact, "firm": firm},
            })

    total_expected = len(all_docs)
    print(f"Total op docs: {total_expected}")

    # Connect ChromaDB
    embed_fn = VertexEmbedding()
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    col = client.get_or_create_collection(
        COLLECTION,
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"},
    )

    existing = col.count()
    if existing >= total_expected:
        print(f"solodit_op already built ({existing} docs >= {total_expected} expected). Skip.")
        return

    print(f"Existing: {existing} / {total_expected}. Embedding remaining ...")

    # Get already-indexed ids to skip
    if existing > 0:
        all_existing = col.get(include=[])["ids"]
        existing_ids = set(all_existing)
    else:
        existing_ids = set()

    to_embed = [d for d in all_docs if d["id"] not in existing_ids]
    print(f"To embed: {len(to_embed)} docs")

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
        remaining = (len(to_embed) - done) / rate if rate > 0 else 0
        print(f"  {done}/{len(to_embed)} ({done/len(to_embed)*100:.1f}%) "
              f"— {rate:.1f} docs/s — ETA {remaining/60:.1f} min")

    final_count = col.count()
    print(f"\nDone. solodit_op collection: {final_count} docs.")


if __name__ == "__main__":
    main()
