"""
Inject self-crafted findings vào ChromaDB RAG DB.
Chạy: cd backend && source .venv/bin/activate && python -m scripts.rag.inject_custom_findings
"""
import sys, json, os
from pathlib import Path

__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import chromadb
import vertexai
from chromadb import EmbeddingFunction, Documents, Embeddings
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput
from google.api_core.exceptions import ResourceExhausted
import time

CHROMA_PATH   = Path("data/rag_db/chroma")
PARENTS_PATH  = CHROMA_PATH.parent / "parents.json"
INPUT_FILE    = Path("scripts/rag/self_crafted_35.json")


class VertexEmbeddingDoc(EmbeddingFunction):
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
        inputs = [TextEmbeddingInput(t, "RETRIEVAL_DOCUMENT") for t in input]
        for attempt in range(5):
            try:
                return [e.values for e in self._model.get_embeddings(inputs)]
            except ResourceExhausted:
                wait = 2 ** attempt
                print(f"  [429] chờ {wait}s...")
                time.sleep(wait)
        raise RuntimeError("Embedding failed after retries")


def main():
    findings = json.loads(INPUT_FILE.read_text())
    print(f"Loaded {len(findings)} custom findings from {INPUT_FILE}")

    embed_fn = VertexEmbeddingDoc()
    client   = chromadb.PersistentClient(path=str(CHROMA_PATH))
    col      = client.get_collection("solodit_findings", embedding_function=embed_fn)
    print(f"DB hiện tại: {col.count()} chunks")

    parents = json.loads(PARENTS_PATH.read_text()) if PARENTS_PATH.exists() else {}

    for f in findings:
        slug    = f["slug"]
        title   = f["title"]
        impact  = f["impact"]
        content = f["content"]

        # Document text = gì được embed (cùng format build_rag_db)
        doc_text = f"Title: {title}\nImpact: {impact}\nProtocol: {f.get('protocol','')}\n\n{content}"

        metadata = {
            "source":        "self-crafted",
            "firm_name":     f.get("firm", "self-crafted"),
            "protocol_name": f.get("protocol", ""),
            "impact":        impact,
            "quality_score": str(f.get("quality_score", "5")),
            "contest_id":    str(f.get("contest_id", "35")),
            "title":         title,
            "slug":          slug,
            "source_link":   f.get("source_link", ""),
            "content_source": f.get("content_source", "self-crafted"),
            "chunk_index":   0,
            "total_chunks":  1,
        }

        col.upsert(
            ids=[f"custom_{slug}_chunk_0"],
            documents=[doc_text],
            metadatas=[metadata],
        )
        parents[slug] = doc_text
        print(f"  ✓ upserted: {slug}")

    PARENTS_PATH.write_text(json.dumps(parents, ensure_ascii=False, indent=2))
    print(f"\nDone. DB: {col.count()} chunks | parents.json updated")


if __name__ == "__main__":
    main()
