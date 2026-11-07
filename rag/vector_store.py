# rag/vector_store.py
# Persistent ChromaDB vector database manager for SentinelX threat knowledge
# Persistent ChromaDB vector database manager for SentinelX threat knowledge
import logging
import math
from pathlib import Path
from typing import List, Dict, Any, cast
import chromadb
from rag.chunker import Chunk

logger = logging.getLogger("SentinelX.VectorStore")


class ChromaVectorStore:
    """
    Persistent ChromaDB vector database manager for SentinelX.
    Handles upserts, semantic retrieval, metadata queries, and document updates/deletions.
    """

    def __init__(self, persist_dir: str = "./chroma_db", collection_name: str = "sentinelx_knowledge_base"):
        """
        :param persist_dir: Local directory path on disk for database persistence.
        :param collection_name: Name of the target ChromaDB collection.
        """
        self.persist_dir = Path(persist_dir)
        self.collection_name = collection_name

        # Ensure persistence directory exists on disk
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        # Initialize persistent client
        self.client = chromadb.PersistentClient(path=str(self.persist_dir))
        
        # Create or fetch collection using Cosine distance metric
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"}
        )
        logger.info(
            f"Initialized ChromaDB PersistentClient at '{self.persist_dir}' "
            f"| Collection: '{self.collection_name}' ({self.get_count()} existing vectors)"
        )

    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensures metadata values are valid ChromaDB primitives (str, int, float, bool).
        """
        clean_meta = {}
        for key, value in metadata.items():
            if value is None:
                continue
            clean_key = str(key)
            if isinstance(value, (str, int, float, bool)):
                clean_meta[clean_key] = value
            else:
                clean_meta[clean_key] = str(value)
        return clean_meta

    def _validate_upsert_inputs(self, chunks: List[Chunk], embeddings: List[List[float]]) -> None:
        if len(chunks) != len(embeddings):
            raise ValueError(
                f"Mismatch between number of chunks ({len(chunks)}) and embeddings ({len(embeddings)})."
            )

        embedding_dimensions = set()
        for embedding in embeddings:
            if not isinstance(embedding, list) or not embedding:
                raise ValueError("Embeddings must be non-empty lists of numbers.")
            if any(not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) for value in embedding):
                raise ValueError("Embeddings must contain only finite numeric values.")
            embedding_dimensions.add(len(embedding))
        if len(embedding_dimensions) > 1:
            raise ValueError("All embeddings must have the same dimension.")

        if any(not isinstance(chunk, Chunk) for chunk in chunks):
            raise TypeError("chunks must contain Chunk instances.")
        if any(not chunk.chunk_id or not chunk.text.strip() for chunk in chunks):
            raise ValueError("Chunk IDs and text must be non-empty.")

    def upsert_chunks(self, chunks: List[Chunk], embeddings: List[List[float]]) -> int:
        """
        Stores document chunks, embeddings, and metadata.
        Implements duplicate prevention: Existing chunk IDs are overwritten/updated,
        preventing duplicate entries when ingestion is executed multiple times.
        """
        if not chunks and not embeddings:
            logger.warning("No chunks or embeddings provided for storage.")
            return 0

        self._validate_upsert_inputs(chunks, embeddings)

        ids = [c.chunk_id for c in chunks]
        documents = [c.text for c in chunks]
        metadatas = [self._sanitize_metadata(c.metadata) for c in chunks]

        # ChromaDB upsert overwrites existing chunk_ids, preventing duplicate indexing
        self.collection.upsert(
            ids=ids,
            embeddings=cast(Any, embeddings),
            documents=documents,
            metadatas=cast(Any, metadatas)
        )

        logger.info(f"Successfully upserted {len(chunks)} chunks into ChromaDB.")
        return len(chunks)

    def delete_by_doc_id(self, doc_id: str) -> int:
        """
        Deletes all chunks associated with a given parent document ID (`doc_id` or `parent_doc_id`).
        """
        if not isinstance(doc_id, str) or not doc_id.strip():
            raise ValueError("doc_id must be a non-empty string.")
        doc_id = doc_id.strip()

        # Search for all chunk entries where metadata parent_doc_id or doc_id matches target
        results = self.collection.get(
            where={"parent_doc_id": doc_id}
        )

        matching_ids = list(results.get("ids", []))

        # Some chunks may carry doc_id metadata instead of parent_doc_id.
        results = self.collection.get(where={"doc_id": doc_id})
        matching_ids.extend(results.get("ids", []))

        matching_ids = list(dict.fromkeys(chunk_id for chunk_id in matching_ids if isinstance(chunk_id, str)))
        if matching_ids:
            self.collection.delete(ids=matching_ids)
            logger.info(f"Deleted {len(matching_ids)} chunks associated with Document ID '{doc_id}'.")
            return len(matching_ids)
        
        logger.warning(f"No existing vector records found for Document ID '{doc_id}'.")
        return 0

    def update_document(
        self, 
        doc_id: str, 
        new_chunks: List[Chunk], 
        new_embeddings: List[List[float]]
    ) -> int:
        """
        Updates an existing document by purging old chunks and inserting newly updated chunks.
        """
        self._validate_upsert_inputs(new_chunks, new_embeddings)

        logger.info(f"Updating Document ID '{doc_id}'...")
        self.delete_by_doc_id(doc_id)
        return self.upsert_chunks(new_chunks, new_embeddings)

    def search_similar(self, query_embedding: List[float], top_k: int = 5) -> Dict[str, Any]:
        """
        Retrieves top-k relevant document chunks using vector similarity search.
        """
        if not isinstance(top_k, int) or isinstance(top_k, bool) or top_k <= 0:
            raise ValueError("top_k must be a positive integer.")
        if not isinstance(query_embedding, list) or not query_embedding:
            raise ValueError("query_embedding must be a non-empty list of numbers.")
        if any(not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) for value in query_embedding):
            raise ValueError("query_embedding must contain only finite numeric values.")

        return cast(Dict[str, Any], self.collection.query(
            query_embeddings=cast(Any, [query_embedding]),
            n_results=top_k,
            include=["documents", "metadatas", "distances"]
        ))

    def get_count(self) -> int:
        """Returns total vector count in the collection."""
        return self.collection.count()

    def reset_collection(self):
        """Purges all records inside the current collection."""
        self.client.delete_collection(name=self.collection_name)
        self.collection = self.client.create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"}
        )
        logger.info(f"Reset collection '{self.collection_name}'. Vector count: 0")