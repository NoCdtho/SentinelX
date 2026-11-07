"""
Standalone test script that creates sample attack pattern JSON files 
(SQLi, SYN Flood, DNS Tunneling) and runs the ingestion pipeline to populate 
ChromaDB. Requires Ollama with nomic-embed-text model. Outputs ingestion confirmation 
with vector count. Key functions: create_sample_patterns(), run_test_ingestion().
"""
import os
import json
from pathlib import Path
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from langchain_core.documents import Document

KNOWLEDGE_BASE_DIR = Path("./knowledge_base")
CHROMA_DB_DIR = Path("./knowledge_base/chroma_db")
COLLECTION_NAME = "sentinelx_patterns"
EMBEDDING_MODEL = "nomic-embed-text"


def create_sample_patterns():
    """Creates sample pattern files in knowledge_base/ for testing ingestion."""
    KNOWLEDGE_BASE_DIR.mkdir(parents=True, exist_ok=True)

    sample_data = [
        {
            "id": "RULE-HTTP-001",
            "protocol": "HTTP",
            "severity": "critical",
            "attack_type": "SQL Injection",
            "description": "SQL injection pattern detected in HTTP GET parameter with UNION SELECT syntax attempting database enumeration."
        },
        {
            "id": "RULE-TCP-002",
            "protocol": "TCP",
            "severity": "high",
            "attack_type": "SYN Flood",
            "description": "TCP SYN Flood pattern with excessive SYN packets sent from single IP without ACK handshake completion."
        },
        {
            "id": "RULE-DNS-003",
            "protocol": "DNS",
            "severity": "medium",
            "attack_type": "DNS Tunneling",
            "description": "High entropy TXT record query frequencies indicative of outbound DNS tunneling data exfiltration."
        }
    ]

    sample_file = KNOWLEDGE_BASE_DIR / "sample_attack_patterns.json"
    with open(sample_file, "w", encoding="utf-8") as f:
        json.dump(sample_data, f, indent=2)
    print(f"[+] Created test pattern dataset at: {sample_file}")


def run_test_ingestion():
    """Runs test ingestion pipeline using nomic-embed-text and Chroma vector store."""
    create_sample_patterns()

    print("[*] Loading pattern files from knowledge base...")
    documents = []
    for file_path in KNOWLEDGE_BASE_DIR.glob("*.json"):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            items = data if isinstance(data, list) else [data]
            for item in items:
                doc = Document(
                    page_content=item["description"],
                    metadata={
                        "pattern_id": item["id"],
                        "protocol": item["protocol"],
                        "severity": item["severity"],
                        "attack_type": item["attack_type"],
                        "source": file_path.name
                    }
                )
                documents.append(doc)

    print(f"[*] Loaded {len(documents)} document chunk(s) for ingestion.")

    print(f"[*] Initializing embedding generator using model '{EMBEDDING_MODEL}'...")
    embeddings = OllamaEmbeddings(model=EMBEDDING_MODEL)

    print(f"[*] Persisting vectors into Chroma collection '{COLLECTION_NAME}'...")
    vectorstore = Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        collection_name=COLLECTION_NAME,
        persist_directory=str(CHROMA_DB_DIR)
    )

    print(f"[+] Ingestion complete! Total entries in collection: {vectorstore._collection.count()}")


if __name__ == "__main__":
    run_test_ingestion()