"""
This file implements a document chunking module for a cybersecurity knowledge base. Its job is to take large text documents and split them into smaller, 
overlapping pieces ("chunks") that can later be embedded into a vector database for retrieval-augmented generation (RAG) or semantic search.
"""

import logging
from typing import List, Dict, Any
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

logger = logging.getLogger("SentinelX.DocumentChunker")



@dataclass
class Document:
    """Represents an un-chunked knowledge base document."""
    doc_id: str
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Chunk:
    """Represents a discrete text chunk prepared for embedding and storage."""
    chunk_id: str
    parent_doc_id: str
    text: str
    chunk_index: int
    total_chunks: int
    metadata: Dict[str, Any] = field(default_factory=dict)


class DocumentChunker:
    """
    Handles chunking of cybersecurity knowledge documents with configurable 
    sizes, overlaps, record sorting, and metadata preservation.
    """

    def __init__(self, chunk_size: int = 500, chunk_overlap: int = 50):
        """
        :param chunk_size: Maximum character length for a single chunk.
        :param chunk_overlap: Character overlap between consecutive chunks.
        """
        if chunk_overlap >= chunk_size:
            raise ValueError("chunk_overlap must be strictly less than chunk_size.")

        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def _split_text_with_overlap(self, text: str) -> List[str]:
        """
        Splits text into windows of `chunk_size` with `chunk_overlap`.
        Attempts to break at line or space boundaries to avoid cutting words.
        """
        if len(text) <= self.chunk_size:
            return [text]

        chunks = []
        start = 0
        text_length = len(text)

        while start < text_length:
            end = start + self.chunk_size

            # If we are not at the end of text, attempt to break at word boundary
            if end < text_length:
                # Look for space or newline near the end boundary
                last_space = text.rfind(" ", start, end)
                last_newline = text.rfind("\n", start, end)
                boundary = max(last_space, last_newline)

                # Only snap to boundary if it's within a reasonable window
                if boundary > start + (self.chunk_size // 2):
                    end = boundary

            chunk_str = text[start:end].strip()
            if chunk_str:
                chunks.append(chunk_str)

            # Advance start pointer considering overlap
            start = end - self.chunk_overlap if end < text_length else text_length

        return chunks

    def chunk_document(self, doc: Document) -> List[Chunk]:
        """
        Chunks a single Document object:
        - Avoids splitting if text length fits within chunk_size.
        - Preserves all metadata and attaches chunk sequence metrics.
        - Generates unique chunk IDs (e.g., 'TI-01_c0', 'TI-01_c1').
        """
        text = doc.text.strip()
        if not text:
            logger.warning(f"Skipping empty document '{doc.doc_id}'.")
            return []

        # Avoid unnecessary splitting for short records
        raw_chunks = self._split_text_with_overlap(text)
        total_chunks = len(raw_chunks)
        chunk_objects: List[Chunk] = []

        for idx, chunk_text in enumerate(raw_chunks):
            # Requirement: Generate unique chunk ID
            chunk_id = f"{doc.doc_id}_c{idx}"

            # Requirement: Preserve document IDs and metadata
            chunk_meta: Dict[str, Any] = doc.metadata.copy()
            chunk_meta.update({
                "chunk_id": chunk_id,
                "parent_doc_id": doc.doc_id,
                "chunk_index": idx,
                "total_chunks": total_chunks,
                "char_length": len(chunk_text)
            })

            chunk_objects.append(
                Chunk(
                    chunk_id=chunk_id,
                    parent_doc_id=doc.doc_id,
                    text=chunk_text,
                    chunk_index=idx,
                    total_chunks=total_chunks,
                    metadata=chunk_meta
                )
            )

        return chunk_objects

    def chunk_documents(self, documents: List[Document], sort_records: bool = True) -> List[Chunk]:
        """
        Processes a list of documents into chunks.
        
        :param documents: List of Document objects.
        :param sort_records: Sorts documents deterministically before chunking.
        """
        if sort_records:
            # Sort by category first, then by doc_id to ensure deterministic ingestion
            documents = sorted(
                documents, 
                key=lambda d: (str(d.metadata.get("category", "")), str(d.doc_id))
            )

        all_chunks: List[Chunk] = []
        for doc in documents:
            chunks = self.chunk_document(doc)
            all_chunks.extend(chunks)

        logger.info(
            f"Chunked {len(documents)} documents into {len(all_chunks)} chunks "
            f"(chunk_size={self.chunk_size}, overlap={self.chunk_overlap})."
        )
        return all_chunks