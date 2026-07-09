#!/usr/bin/env python3
"""
rag_ingest.py — CLI tool to ingest text/markdown/PDF documents into ShieldScan's ChromaDB.

Usage:
    python rag_ingest.py docs/                    # ingest all .txt/.md/.pdf in folder
    python rag_ingest.py docs/cis_aws_v3.pdf      # ingest single file
    python rag_ingest.py --status                 # show collection size
    python rag_ingest.py --reset                  # wipe and re-seed from scratch

Teammates can use this to add their own research documents to the RAG knowledge base.
The chunk size is set to 800 chars with 100-char overlap for good retrieval quality.
"""

import os
import sys
import argparse
import hashlib
from pathlib import Path
from typing import List, Dict

# Ensure backend modules are importable
sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

CHROMA_PERSIST_DIR = os.path.join(os.path.dirname(__file__), "chroma_db")
COLLECTION_NAME = "shieldscan_knowledge"
CHUNK_SIZE = 800       # characters per chunk
CHUNK_OVERLAP = 100    # overlap between consecutive chunks


def _get_collection():
    import chromadb
    from chromadb.utils import embedding_functions

    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
    ef = embedding_functions.DefaultEmbeddingFunction()
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )


def chunk_text(text: str, source_name: str) -> List[Dict]:
    """Split text into overlapping chunks and return list of {id, content, metadata}."""
    text = text.strip()
    chunks = []
    start = 0
    chunk_index = 0

    while start < len(text):
        end = start + CHUNK_SIZE
        chunk_text = text[start:end].strip()
        if not chunk_text:
            break

        # Stable ID from content hash (idempotent — re-ingesting same file won't duplicate)
        chunk_hash = hashlib.md5(chunk_text.encode()).hexdigest()[:8]
        chunk_id = f"ingest-{Path(source_name).stem}-{chunk_index}-{chunk_hash}"

        chunks.append({
            "id": chunk_id,
            "content": chunk_text,
            "metadata": {
                "source": source_name,
                "chunk_index": chunk_index,
                "category": "Ingested",
                "severity": "INFO",
            }
        })
        chunk_index += 1
        start += CHUNK_SIZE - CHUNK_OVERLAP

    return chunks


def read_txt(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def read_md(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    # Strip markdown syntax for cleaner embeddings
    import re
    content = re.sub(r"#{1,6}\s+", "", content)       # headers
    content = re.sub(r"\*\*(.+?)\*\*", r"\1", content) # bold
    content = re.sub(r"\*(.+?)\*", r"\1", content)     # italic
    content = re.sub(r"`{1,3}[^`]*`{1,3}", "", content)# code blocks
    content = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", content)  # links
    return content


def read_pdf(path: str) -> str:
    try:
        import pdfplumber
        text_parts = []
        with pdfplumber.open(path) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    text_parts.append(text)
        return "\n\n".join(text_parts)
    except ImportError:
        print("  [!] pdfplumber not installed. Run: pip install pdfplumber --break-system-packages")
        return ""
    except Exception as e:
        print(f"  [!] PDF read error: {e}")
        return ""


def ingest_file(path: str, collection) -> int:
    """Ingest a single file into the collection. Returns number of chunks added."""
    path = str(path)
    ext = Path(path).suffix.lower()
    source_name = Path(path).name

    print(f"  Reading {source_name}...")

    if ext == ".txt":
        text = read_txt(path)
    elif ext == ".md":
        text = read_md(path)
    elif ext == ".pdf":
        text = read_pdf(path)
    else:
        print(f"  [!] Skipping unsupported file type: {ext}")
        return 0

    if not text.strip():
        print(f"  [!] Empty content in {source_name}")
        return 0

    chunks = chunk_text(text, source_name)
    if not chunks:
        return 0

    collection.upsert(
        ids=[c["id"] for c in chunks],
        documents=[c["content"] for c in chunks],
        metadatas=[c["metadata"] for c in chunks],
    )
    print(f"  ✓ {source_name} — {len(chunks)} chunks ingested")
    return len(chunks)


def ingest_path(target: str):
    """Ingest a file or all supported files in a directory."""
    collection = _get_collection()
    target_path = Path(target)

    if not target_path.exists():
        print(f"Error: path not found: {target}")
        sys.exit(1)

    total_chunks = 0
    total_files = 0

    if target_path.is_file():
        total_chunks += ingest_file(str(target_path), collection)
        total_files = 1
    else:
        # Directory: recursively find all supported files
        supported_exts = {".txt", ".md", ".pdf"}
        files = sorted([
            f for f in target_path.rglob("*")
            if f.suffix.lower() in supported_exts and f.is_file()
        ])
        if not files:
            print(f"No .txt, .md, or .pdf files found in {target}")
            return
        for f in files:
            total_chunks += ingest_file(str(f), collection)
            total_files += 1

    print(f"\nDone: {total_files} file(s), {total_chunks} chunks added.")
    print(f"Total knowledge base size: {collection.count()} documents")


def show_status():
    """Show current collection size."""
    collection = _get_collection()
    count = collection.count()
    print(f"ShieldScan knowledge base: {count} documents in ChromaDB")
    print(f"Location: {CHROMA_PERSIST_DIR}")


def reset_collection():
    """Wipe the collection and re-seed from rag_module defaults."""
    import chromadb
    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
    try:
        client.delete_collection(COLLECTION_NAME)
        print("Collection deleted.")
    except Exception:
        pass

    # Re-import rag_module to trigger re-seed on next _get_collection() call
    # Clear module cache so _collection is None
    import rag_module
    rag_module._client = None
    rag_module._collection = None
    collection = rag_module._get_collection()
    print(f"Re-seeded: {collection.count()} base documents loaded.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ingest documents into ShieldScan's ChromaDB RAG knowledge base"
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="File or directory to ingest (.txt, .md, .pdf)"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show current knowledge base size"
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Wipe collection and re-seed from rag_module defaults"
    )

    args = parser.parse_args()

    if args.status:
        show_status()
    elif args.reset:
        confirm = input("This will delete all ingested documents. Type 'yes' to confirm: ")
        if confirm.strip().lower() == "yes":
            reset_collection()
        else:
            print("Aborted.")
    elif args.path:
        ingest_path(args.path)
    else:
        parser.print_help()
