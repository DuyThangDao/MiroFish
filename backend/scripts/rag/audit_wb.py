#!/usr/bin/env python3
"""
Kiểm tra xem có web3bugs H-findings nào lọt vào ChromaDB không.
Chạy: python -m scripts.rag.audit_wb
"""
import sys
__import__('pysqlite3')
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import json, re
from pathlib import Path
import chromadb

CHROMA_PATH   = Path("data/rag_db/chroma")
SLUGS_PATH    = Path("data/rag_db/seen_slugs.json")
PARENTS_PATH  = Path("data/rag_db/parents.json")
WEB3BUGS_DIR  = Path("/home/thangdd/repos/web3bugs/reports")


def build_web3bugs_titles() -> set[str]:
    titles = set()
    for path in WEB3BUGS_DIR.glob("*.md"):
        text = path.read_text(errors="replace")
        for m in re.finditer(r'##\s+\[\[H-\d+\]\s+(.+?)\]', text):
            titles.add(m.group(1).strip().lower())
    return titles


def normalize(title: str) -> str:
    return re.sub(r'^\[(?:h|m|l|g|i)-\d+\]\s*', '', title.lower()).strip()


def main():
    print("=== Web3bugs Audit ===\n")

    wb_titles = build_web3bugs_titles()
    print(f"Web3bugs blacklist: {len(wb_titles)} unique H-titles\n")

    client  = chromadb.PersistentClient(path=str(CHROMA_PATH))
    col     = client.get_collection("solodit_findings")
    parents = json.loads(PARENTS_PATH.read_text())
    seen    = set(json.loads(SLUGS_PATH.read_text()))

    all_data = col.get(include=["metadatas"])
    # Dedup: chỉ xét 1 entry per slug
    seen_slugs_checked = set()
    candidates = []
    for meta in all_data["metadatas"]:
        slug = meta.get("slug", "")
        if slug in seen_slugs_checked:
            continue
        seen_slugs_checked.add(slug)
        candidates.append(meta)

    print(f"Findings trong DB: {len(candidates)}\n")

    leaked = []
    for meta in candidates:
        title_norm = normalize(meta.get("title", ""))
        if title_norm in wb_titles:
            leaked.append(meta)

    if not leaked:
        print("✅ Không có finding nào lọt — DB sạch.")
        return

    print(f"⚠️  Tìm thấy {len(leaked)} web3bugs finding lọt vào DB:\n")
    for i, meta in enumerate(leaked, 1):
        print(f"[{i:02d}] {meta.get('title', '')}")
        print(f"      slug:     {meta.get('slug', '')}")
        print(f"      protocol: {meta.get('protocol_name', '')}")
        print(f"      source:   {meta.get('source_link', '')}")
        print()

    answer = input(f"Xóa {len(leaked)} findings này khỏi DB? (y/n): ").strip().lower()
    if answer != 'y':
        print("Hủy. Không thay đổi gì.")
        return

    # Thu thập tất cả chunk IDs cần xóa
    slugs_to_delete = {m["slug"] for m in leaked}
    all_ids_raw = col.get()["ids"]
    ids_to_delete = [
        doc_id for doc_id in all_ids_raw
        if any(doc_id.startswith(f"solodit_{s}_") for s in slugs_to_delete)
    ]

    col.delete(ids=ids_to_delete)

    for slug in slugs_to_delete:
        parents.pop(slug, None)
        seen.discard(slug)

    PARENTS_PATH.write_text(json.dumps(parents, ensure_ascii=False, indent=2))
    SLUGS_PATH.write_text(json.dumps(sorted(seen), indent=2))

    print(f"\n✅ Đã xóa {len(leaked)} findings ({len(ids_to_delete)} chunks).")
    print(f"   DB còn lại: {col.count()} chunks | {len(seen)} findings")


if __name__ == "__main__":
    main()
