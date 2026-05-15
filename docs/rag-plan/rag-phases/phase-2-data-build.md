# Phase 2 — Thu thập dữ liệu và Build RAG

**Mục tiêu:** Cấu hình credentials, chạy `build_rag_db.py` để fetch ~1605 findings từ Solodit,
scrape full content từ Code4rena, embed bằng Vertex AI, lưu vào ChromaDB.
Sau phase này, `data/rag_db/` chứa đầy đủ vector DB và `parents.json`.

**Tham chiếu:** [rag-implementing-plan-2.md](../rag-implementing-plan-2.md) — Step 1, 2, 3, 4

**Ước tính thời gian:** ~2–3 giờ (1605 findings × scrape + embed)

---

## Checklist

- [ ] 1. Chuẩn bị credentials (Solodit API key + Vertex AI)
- [ ] 2. Verify Vertex AI kết nối được
- [ ] 3. Chạy build script (background)
- [ ] 4. Theo dõi tiến trình
- [ ] 5. Verify DB sau khi build xong

---

## Bước 1 — Chuẩn bị credentials

### 1.1 Solodit API Key

Thêm vào `backend/.env`:
```bash
SOLODIT_API_KEY=<key từ solodit.cyfrin.io>
```

Hoặc export tạm thời khi chạy:
```bash
export SOLODIT_API_KEY=<key>
```

### 1.2 Vertex AI credentials

Cần một trong hai cách:

**Cách A — Service account key file (recommended cho local):**
```bash
# Đặt path vào .env
LLM_VERTEX_AI_KEY_FILE=/path/to/service-account-key.json
```

Script tự đọc `LLM_VERTEX_AI_KEY_FILE` từ env và set `GOOGLE_APPLICATION_CREDENTIALS`.

**Cách B — Application Default Credentials:**
```bash
gcloud auth application-default login
# Sau đó không cần LLM_VERTEX_AI_KEY_FILE
```

---

## Bước 2 — Verify Vertex AI kết nối được

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

python -c "
import sys
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import os, sqlite3, chromadb
import vertexai
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput

key_file = os.environ.get('LLM_VERTEX_AI_KEY_FILE', '')
if key_file:
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = key_file

vertexai.init()
model = TextEmbeddingModel.from_pretrained('text-embedding-004')
result = model.get_embeddings([TextEmbeddingInput('test smart contract reentrancy', 'RETRIEVAL_DOCUMENT')])

print('sqlite3 version:', sqlite3.sqlite_version)       # expect >= 3.35.0
print('chromadb version:', chromadb.__version__)        # expect 1.5.x
print('embedding dims:', len(result[0].values))         # expect 768
print('ALL OK — sẵn sàng build DB')
"
```

**Nếu lỗi `DefaultCredentialsError`:** chưa set credentials → kiểm tra lại Bước 1.
**Nếu lỗi `sqlite3.sqlite_version` < 3.35:** monkey-patch chưa đúng → kiểm tra lại import order.

---

## Bước 3 — Chạy build script

### 3.1 Chạy foreground (theo dõi trực tiếp)

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

SOLODIT_API_KEY=<key> python -m scripts.rag.build_rag_db
```

### 3.2 Chạy background với log (recommended vì ~2-3 giờ)

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

LOG=/tmp/rag_build_$(date +%Y%m%d_%H%M%S).log
nohup bash -c '
  source .venv/bin/activate
  exec python -m scripts.rag.build_rag_db
' >> "$LOG" 2>&1 &

echo "PID=$!  LOG=$LOG"
```

---

## Bước 4 — Theo dõi tiến trình

```bash
# Stream log
tail -f /tmp/rag_build_*.log

# Tóm tắt nhanh
grep -E "Page|WARN|Done|Rate limit" /tmp/rag_build_*.log | tail -20

# Kiểm tra process còn sống không
ps aux | grep build_rag_db

# Xem DB đang có bao nhiêu chunks
python -c "
import sys; __import__('pysqlite3'); sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
import chromadb
c = chromadb.PersistentClient('data/rag_db/chroma')
print('DB chunks hiện tại:', c.get_collection('solodit_findings').count())
"
```

### Output mẫu khi đang chạy bình thường:
```
Loaded 0 seen slugs | 847 web3bugs titles to blacklist
Cần fetch: seen=0, totalResults=1605, ước tính mới ~1605
Page 1/81 — ingested 18 findings (42 chunks), skipped 2 | total findings: 18 | DB chunks: 42
Page 2/81 — ingested 20 findings (51 chunks), skipped 0 | total findings: 38 | DB chunks: 93
...
```

### Xử lý các warning thường gặp:

| Warning | Nguyên nhân | Hành động |
|---|---|---|
| `[WARN] scrape failed: HTTP 403` | Code4rena block IP tạm thời | Bỏ qua, fallback về `content` field |
| `[WARN] scrape failed: timeout` | Code4rena slow | Bỏ qua, fallback về `content` field |
| `[WARN] Vertex AI 429` | Rate limit spike | Script tự retry với backoff, không cần can thiệp |

---

## Bước 5 — Verify DB sau khi build xong

```bash
cd /home/thangdd/repos/MiroFish/backend
source .venv/bin/activate

python -c "
import sys, json
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import os, chromadb
from chromadb import EmbeddingFunction, Documents, Embeddings
from pathlib import Path
import vertexai
from vertexai.language_models import TextEmbeddingModel, TextEmbeddingInput
from google.api_core.exceptions import ResourceExhausted

class VertexEmbedding(EmbeddingFunction):
    def __init__(self, task_type='RETRIEVAL_QUERY'):
        key_file = os.environ.get('LLM_VERTEX_AI_KEY_FILE', '')
        if key_file:
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = key_file
        vertexai.init()
        self._model = TextEmbeddingModel.from_pretrained('text-embedding-004')
        self._task_type = task_type
    def __call__(self, input):
        import time
        for attempt in range(5):
            try:
                return [e.values for e in self._model.get_embeddings(
                    [TextEmbeddingInput(t, self._task_type) for t in input])]
            except ResourceExhausted:
                if attempt == 4: raise
                time.sleep(2 ** attempt)

# 1. Kiểm tra ChromaDB
c = chromadb.PersistentClient('data/rag_db/chroma')
col = c.get_collection('solodit_findings', embedding_function=VertexEmbedding())
print(f'[ChromaDB] Total chunks: {col.count()}')

# 2. Kiểm tra parents.json
parents = json.loads(Path('data/rag_db/parents.json').read_text())
print(f'[Parents]  Total findings: {len(parents)}')

# 3. Kiểm tra seen_slugs.json
slugs = json.loads(Path('data/rag_db/seen_slugs.json').read_text())
print(f'[Slugs]    Seen slugs: {len(slugs)}')

# 4. Thử query
res = col.query(query_texts=['reentrancy attack in withdraw function'], n_results=3,
                include=['metadatas', 'distances'])
print(f'[Query]    Top 3 kết quả cho reentrancy:')
for meta, dist in zip(res['metadatas'][0], res['distances'][0]):
    print(f'  [{round(1-dist, 3)}] {meta[\"title\"][:70]}')
"
```

**Kết quả mong đợi:**
```
[ChromaDB] Total chunks: ~3500–5000  (1590 findings × avg 2.5 chunks)
[Parents]  Total findings: ~1590
[Slugs]    Seen slugs: ~1590
[Query]    Top 3 kết quả cho reentrancy:
  [0.872] [H-01] Reentrancy in withdraw allows attacker to drain funds
  [0.841] [H-03] Missing reentrancy guard in claim()
  [0.829] [H-02] Cross-function reentrancy via callback
```

---

## Ước tính kích thước output

| File | Kích thước ước tính |
|---|---|
| `data/rag_db/chroma/` | ~100–200MB (vectors 768 dims × ~4000 chunks) |
| `data/rag_db/parents.json` | ~50–100MB (full text ~1590 findings) |
| `data/rag_db/seen_slugs.json` | ~100KB |

---

## Incremental run (lần 2 trở đi)

Khi chạy lại sau khi DB đã có dữ liệu:
```bash
SOLODIT_API_KEY=<key> python -m scripts.rag.build_rag_db
```

Script tự động:
1. Load `seen_slugs.json` → biết slug nào đã ingest
2. Probe API để lấy `totalResults` → nếu `len(seen) >= total` thì exit sớm
3. Nếu có findings mới → chỉ ingest phần mới, bỏ qua phần cũ

---

## Kết thúc Phase 2

Sau khi hoàn thành, các file sau đã tồn tại và có dữ liệu:
- `data/rag_db/chroma/` — ChromaDB với ~4000 chunk vectors
- `data/rag_db/parents.json` — ~1590 full finding documents
- `data/rag_db/seen_slugs.json` — danh sách slugs đã ingest

**Chuyển sang** → [Phase 3: Chạy thử với Tools sau khi tích hợp](phase-3-integration-test.md)
