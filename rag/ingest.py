"""
Orchestrates RAG ingestion pipeline: loads JSON KB 
documents → generates nomic-embed-text embeddings → stores in persistent ChromaDB. 
orchestrate_ingestion() is the main entry point, supporting automatic sample pattern 
creation when no documents exist. 
Uses LangChain's Chroma.from_documents() for vector storage. 
Key methods: load_pattern_documents(), orchestrate_ingestion().
"""

import json
from pathlib import Path
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from langchain_core.documents import Document

# Path configurations matching SentinelX structure
KNOWLEDGE_BASE_DIR = Path("./knowledge_base")
CHROMA_DB_DIR = Path("./knowledge_base/chroma_db")
COLLECTION_NAME = "sentinelx_patterns"
EMBEDDING_MODEL = "nomic-embed-text"


def load_pattern_documents(knowledge_dir: Path) -> list[Document]:
    """Loads network packet patterns, threat signatures, and security metadata files."""
    documents = []

    if not knowledge_dir.exists():
        knowledge_dir.mkdir(parents=True, exist_ok=True)
        print(f"Created knowledge directory at: {knowledge_dir}")
        return documents

    for file_path in knowledge_dir.glob("**/*"):
        if file_path.is_file() and not str(file_path).startswith(str(CHROMA_DB_DIR)):
            if file_path.suffix == ".json":
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    items = data if isinstance(data, list) else [data]
                    for idx, item in enumerate(items):
                        content = item.get("description") or item.get("pattern_text") or json.dumps(item)
                        metadata = {
                            "source": file_path.name,
                            "pattern_id": str(item.get("id", f"{file_path.stem}_{idx}")),
                            "protocol": str(item.get("protocol", "unknown")),
                            "severity": str(item.get("severity", "info")),
                            "attack_type": str(item.get("attack_type", "general"))
                        }
                        documents.append(Document(page_content=content, metadata=metadata))

            elif file_path.suffix in [".txt", ".md"]:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    metadata = {
                        "source": file_path.name,
                        "file_type": file_path.suffix[1:]
                    }
                    documents.append(Document(page_content=content, metadata=metadata))

    return documents


def orchestrate_ingestion():
    """Converts documents to searchable text, generates Nomic embeddings, and stores in persistent ChromaDB."""
    print("Step 1: Ingesting pattern documents from knowledge base...")
    docs = load_pattern_documents(KNOWLEDGE_BASE_DIR)

    if not docs:
        print("No documents found in knowledge_base/. Adding sample packet pattern document...")
        sample_doc = Document(
            page_content="TCP SYN Flood Anomaly: Unusually high rate of TCP SYN packets targeting HTTP/HTTPS ports without completing handshake.",
            metadata={
                "source": "sample_patterns.json",
                "pattern_id": "RULE-TCP-001",
                "protocol": "TCP",
                "severity": "high",
                "attack_type": "DoS"
            }
        )
        docs.append(sample_doc)

    print(f"Loaded {len(docs)} document chunk(s) for embedding.")

    print(f"Step 2: Initializing embedding generator using '{EMBEDDING_MODEL}'...")
    embeddings = OllamaEmbeddings(model=EMBEDDING_MODEL)

    print(f"Step 3: Storing vectors in persistent Chroma collection at '{CHROMA_DB_DIR}'...")
    vectorstore = Chroma.from_documents(
        documents=docs,
        embedding=embeddings,
        collection_name=COLLECTION_NAME,
        persist_directory=str(CHROMA_DB_DIR)
    )

    count = vectorstore._collection.count()
    print(f"Ingestion successful! Persistent collection '{COLLECTION_NAME}' now contains {count} vector entries.")


if __name__ == "__main__":
    orchestrate_ingestion()