# RAG Database Build — Thống kê và Xác minh

**Ngày build:** 2026-05-15  
**Script:** `backend/scripts/rag/build_rag_db.py`  
**Working dir:** `backend/`

---

## 1. Nguồn dữ liệu

| Nguồn | Số liệu |
|---|---|
| Solodit API — tổng findings trả về | 1605 |
| Filter áp dụng | `impact=HIGH`, `firm=Code4rena`, `language=Solidity` |
| Web3bugs H-findings (104 contest files) | 487 |
| Web3bugs unique titles (dùng làm blacklist) | 483 *(4 titles trùng giữa các contests)* |

---

## 2. Kết quả DB

| Metric | Số liệu |
|---|---|
| Findings trong ChromaDB | **1137** |
| Chunks trong ChromaDB | **3495** |
| Entries trong `parents.json` | 1137 |
| Entries trong `seen_slugs.json` | 1137 |

---

## 3. Phân tích skipped findings

```
Solodit API trả về:            1605
Web3bugs blacklisted:          -468   (matched với 483 unique titles)
─────────────────────────────────────
Findings trong DB:             1137
Kiểm tra:  468 + 1137 = 1605 ✓
```

**19 web3bugs H-findings không có trong Solodit** — có thể Solodit chưa index hoặc
bị loại bởi filter (impact/firm/language không khớp).

---

## 4. Tính toàn vẹn dữ liệu

Cross-check 3 nguồn sau khi build:

| Kiểm tra | Kết quả |
|---|---|
| seen_slugs == parents | ✅ 1137 = 1137 |
| seen_slugs == unique slugs trong ChromaDB | ✅ 1137 = 1137 |
| Findings trong seen nhưng KHÔNG có trong ChromaDB | ✅ 0 missing |
| Findings trong ChromaDB nhưng KHÔNG có trong seen | ✅ 0 orphan |

---

## 5. Chất lượng content (`content_source`)

Content của mỗi finding được lấy theo 3 cấp:

| Cấp | `content_source` | Mô tả |
|---|---|---|
| 1 | `scraped` | Scrape trực tiếp từ Code4rena report → extract đúng section |
| 2 | `api_excerpt` | Scrape thành công nhưng extract thất bại → fallback Solodit excerpt |
| 3 | `title_only` | Scrape thất bại hoàn toàn → chỉ có title |

Sample kiểm tra 10 findings ngẫu nhiên: **10/10 = `scraped`**, có code snippet Solidity,
kích thước 1036–8409 chars — không có finding nào bị thin hoặc mất content.

---

## 6. Quá trình build

Build chạy qua **3 lần restart** do lỗi Vertex AI token limit:

| Lần | Lỗi | Fix |
|---|---|---|
| 1 | 94321 tokens/request (batch toàn page) | Chuyển sang upsert per-finding |
| 2 | 25545 tokens/request (finding cuối report rất dài) | Thêm `EMBED_BATCH=15` (sub-batch chunks) |
| 3 | ✅ Thành công | — |

**Tham số embedding:**
- Model: `text-embedding-004` (Vertex AI), 768 dims
- `CHUNK_SIZE=3000` chars, `CHUNK_OVERLAP=600` chars
- `EMBED_BATCH=15` chunks/request (~11250 tokens, dưới giới hạn 20000)
- Task type: `RETRIEVAL_DOCUMENT` (build), `RETRIEVAL_QUERY` (query)

---

## 7. Hậu kiểm web3bugs

Script `backend/scripts/rag/audit_wb.py` (chưa tạo) có thể chạy sau build để
phát hiện web3bugs findings lọt vào DB do title matching thất bại:

```bash
cd backend
.venv/bin/python scripts/rag/audit_wb.py
# → Found 0 web3bugs findings (expected nếu exact match hoạt động đúng)
```
