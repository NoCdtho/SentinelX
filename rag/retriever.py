"""
This test script is used to exercise and benchmark the 
vector-search + context-assembly part without running any 
local LLM inference — useful for validating that 
packet-to-knowledge-base lookups behave correctly in isolation.
"""


import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma

# Base configurations matching SentinelX architecture
CHROMA_DB_DIR = Path("./knowledge_base/chroma_db")
COLLECTION_NAME = "sentinelx_patterns"
EMBEDDING_MODEL = "nomic-embed-text"

# Default similarity distance threshold (Chroma L2 distance: lower = closer match)
# Matches with distance <= DEFAULT_SIMILARITY_THRESHOLD are deemed relevant.
DEFAULT_SIMILARITY_THRESHOLD = 1.10

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class SentinelRetriever:
    """Retriever engine that queries ChromaDB, enforces similarity score thresholds,
    and returns standardized MATCH_FOUND or NO_RELEVANT_MATCH responses.
    """

    def __init__(
        self,
        db_dir: Path = CHROMA_DB_DIR,
        collection_name: str = COLLECTION_NAME,
        model_name: str = EMBEDDING_MODEL,
        similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
    ):
        self.db_dir = db_dir
        self.collection_name = collection_name
        self.model_name = model_name
        self.similarity_threshold = similarity_threshold
        
        self.embeddings = OllamaEmbeddings(model=self.model_name)
        self._vectorstore: Optional[Chroma] = None

    def _get_vectorstore(self) -> Chroma:
        """Lazy-loads and connects to the persistent ChromaDB collection."""
        if self._vectorstore is None:
            if not self.db_dir.exists():
                raise FileNotFoundError(
                    f"Chroma DB directory '{self.db_dir}' not found. "
                    "Run 'rag/ingest.py' or 'rag/test_ingest.py' first."
                )
            self._vectorstore = Chroma(
                collection_name=self.collection_name,
                embedding_function=self.embeddings,
                persist_directory=str(self.db_dir),
            )
        return self._vectorstore

    def search_top_patterns(
        self,
        query_text: str,
        top_k: int = 3,
        protocol_filter: Optional[str] = None,
    ) -> List[Tuple[Any, float]]:
        """1. Search ChromaDB for the top relevant patterns with distance scores.

        Args:
            query_text: Plaintext query or preprocessed feature string.
            top_k: Maximum number of candidate vectors to retrieve.
            protocol_filter: Optional protocol metadata constraint (e.g. 'TCP', 'HTTP').

        Returns:
            List of tuples containing (Document, distance_score).
        """
        if not isinstance(query_text, str) or not query_text.strip():
            raise ValueError("query_text must be a non-empty string.")
        if not isinstance(top_k, int) or isinstance(top_k, bool) or top_k <= 0:
            raise ValueError("top_k must be a positive integer.")

        vectorstore = self._get_vectorstore()

        filter_dict: Dict[str, str] = {}
        if isinstance(protocol_filter, str):
            normalized_protocol = protocol_filter.strip().upper()
            if normalized_protocol in ["TCP", "UDP", "HTTP", "DNS"]:
                filter_dict["protocol"] = normalized_protocol

        logging.info(f"Searching ChromaDB for: '{query_text}' (k={top_k}, filter={filter_dict})")
        if filter_dict:
            results = vectorstore.similarity_search_with_score(
                query_text,
                k=top_k,
                filter=filter_dict,
            )
        else:
            results = vectorstore.similarity_search_with_score(query_text, k=top_k)
        return results

    def retrieve_with_threshold(
        self,
        query_text: str,
        top_k: int = 3,
        custom_threshold: Optional[float] = None,
        protocol_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """2 & 3. Configures similarity threshold and returns MATCH_FOUND or NO_RELEVANT_MATCH.

        Args:
            query_text: Search query string.
            top_k: Max patterns to retrieve.
            custom_threshold: Overrides default distance threshold for testing/tuning.
            protocol_filter: Optional metadata protocol filter.

        Returns:
            Structured dictionary response with status code, matched patterns, and score metrics.
        """
        threshold = custom_threshold if custom_threshold is not None else self.similarity_threshold
        raw_results = self.search_top_patterns(query_text, top_k=top_k, protocol_filter=protocol_filter)

        matched_patterns = []
        filtered_out_count = 0

        for doc, distance in raw_results:
            # Distance <= Threshold indicates high semantic similarity
            if distance <= threshold:
                matched_patterns.append({
                    "pattern_id": doc.metadata.get("pattern_id", "UNKNOWN"),
                    "attack_type": doc.metadata.get("attack_type", "N/A"),
                    "severity": doc.metadata.get("severity", "N/A"),
                    "protocol": doc.metadata.get("protocol", "N/A"),
                    "description": doc.page_content,
                    "distance_score": round(float(distance), 4),
                })
            else:
                filtered_out_count += 1

        # Determine output status signal
        if matched_patterns:
            status = "MATCH_FOUND"
        else:
            status = "NO_RELEVANT_MATCH"

        return {
            "status": status,
            "threshold_used": threshold,
            "total_candidates_found": len(raw_results),
            "matches_accepted": len(matched_patterns),
            "matches_rejected": filtered_out_count,
            "patterns": matched_patterns,
        }

    def format_llm_injection_context(self, retrieval_response: Dict[str, Any]) -> str:
        """Formats the retrieval response object into a context string for main agent prompts."""
        status = retrieval_response["status"]
        
        if status == "NO_RELEVANT_MATCH":
            return (
                f"[RAG Status: NO_RELEVANT_MATCH]\n"
                f"No known threat signatures matched the target criteria within threshold ({retrieval_response['threshold_used']})."
            )

        context_lines = [
            f"[RAG Status: MATCH_FOUND | Retrived {retrieval_response['matches_accepted']} relevant signature(s)]",
            "=== SENTINELX THREAT KNOWLEDGE MATCHES ==="
        ]
        
        for idx, pattern in enumerate(retrieval_response["patterns"], start=1):
            context_lines.append(
                f"[{idx}] ID: {pattern['pattern_id']} | Type: {pattern['attack_type']} | "
                f"Severity: {pattern['severity']} | Distance: {pattern['distance_score']}"
            )
            context_lines.append(f"    Details: {pattern['description']}")

        context_lines.append("==========================================")
        return "\n".join(context_lines)


# =============================================================================
# Test & Threshold Validation Harness
# =============================================================================
if __name__ == "__main__":
    print("--- SentinelX RAG Retriever Test Suite ---")
    retriever = SentinelRetriever(similarity_threshold=1.10)

    # Test Query 1: Close match for SQL Injection
    query_sqli = "Protocol: HTTP | Method: GET | Payload Snippet: UNION SELECT username, password FROM users--"
    res_sqli = retriever.retrieve_with_threshold(query_sqli, top_k=2)

    print(f"\nQuery 1: SQL Injection Attempt")
    print(f"Status        : {res_sqli['status']}")
    print(f"Accepted      : {res_sqli['matches_accepted']} / {res_sqli['total_candidates_found']}")
    print(retriever.format_llm_injection_context(res_sqli))

    # Test Query 2: Irrelevant benign query expected to trigger NO_RELEVANT_MATCH under strict threshold
    query_benign = "Protocol: UDP | Port 123 Network Time Protocol synchronization pulse"
    res_benign = retriever.retrieve_with_threshold(query_benign, top_k=2, custom_threshold=0.50)

    print(f"\nQuery 2: Benign NTP Traffic (Strict Threshold: 0.50)")
    print(f"Status        : {res_benign['status']}")
    print(f"Accepted      : {res_benign['matches_accepted']} / {res_benign['total_candidates_found']}")
    print(retriever.format_llm_injection_context(res_benign))