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
