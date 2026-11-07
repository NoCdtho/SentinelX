# Manages vector embedding generation using Ollama's `nomic-embed-text` model

import logging
import requests
from typing import List, Tuple, Optional
from rag.chunker import Chunk

logger = logging.getLogger("SentinelX.EmbeddingManager")


class OllamaEmbeddingManager:
    """
    Manages vector embedding generation using Ollama's `nomic-embed-text`.
    Provides dimension verification, failure isolation, and unified query/chunk processing.
    """

    DEFAULT_DIMENSION = 768  # Nominal dimension output for nomic-embed-text

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model_name: str = "nomic-embed-text",
        timeout: int = 30,
        expected_dimension: Optional[int] = DEFAULT_DIMENSION,
    ):
        """
        :param base_url: Ollama server endpoint.
        :param model_name: Name of embedding model pulled in Ollama.
        :param timeout: Request timeout in seconds.
        :param expected_dimension: Expected dimension length (768 for nomic-embed-text).
        """
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.timeout = timeout
        self.expected_dimension = expected_dimension
        self._verified_once = False

    def _request_embedding(self, text: str) -> List[float]:
        """
        Issues POST request to Ollama embedding API with failure handling.
        """
        clean_text = text.strip()
        if not clean_text:
            raise ValueError("Cannot generate embedding for empty or whitespace-only text.")

        url = f"{self.base_url}/api/embeddings"
        payload = {
            "model": self.model_name,
            "prompt": clean_text
        }

        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.Timeout as exc:
            logger.error(f"Ollama API request timed out ({self.timeout}s): {exc}")
            raise RuntimeError(f"Embedding API timed out for model '{self.model_name}'.") from exc
        except requests.exceptions.RequestException as exc:
            logger.error(f"Ollama connection error ({self.base_url}): {exc}")
            raise RuntimeError(f"Failed to connect to Ollama embedding service: {exc}") from exc
        except ValueError as exc:
            logger.error(f"Malformed JSON returned from Ollama API: {exc}")
            raise RuntimeError("Ollama returned unparseable response body.") from exc

        embedding = data.get("embedding")
        if not embedding or not isinstance(embedding, list):
            raise RuntimeError(f"Response missing valid 'embedding' float list: {data}")

        return embedding

    def verify_embedding_format(self, embedding: List[float]) -> bool:
        """
        Verifies vector structure, non-emptiness, element data types, and dimensionality.
        """
        if not isinstance(embedding, list) or len(embedding) == 0:
            logger.error("Validation Error: Embedding output is empty or not a list.")
            return False

        # Validate elements are float/int
        if not all(isinstance(val, (int, float)) for val in embedding):
            logger.error("Validation Error: Embedding contains non-numeric values.")
            return False

        # Check vector dimensionality
        actual_dim = len(embedding)
        if self.expected_dimension and actual_dim != self.expected_dimension:
            logger.warning(
                f"Dimension Mismatch: Model returned {actual_dim} dimensions; "
                f"expected {self.expected_dimension} for '{self.model_name}'."
            )

        return True

    def get_embedding(self, text: str) -> List[float]:
        """
        Generates and validates an embedding vector for a single text input.
        """
        vec = self._request_embedding(text)

        if not self.verify_embedding_format(vec):
            raise ValueError("Generated embedding failed structural validation checks.")

        if not self._verified_once:
            logger.info(
                f"Successfully connected to Ollama model '{self.model_name}' "
                f"(Verified Dimension: {len(vec)})."
            )
            self._verified_once = True

        return vec

    def get_query_embedding(self, query: str) -> List[float]:
        """
        Generates vector embeddings for user queries using the exact same model & rules.
        """
        logger.debug(f"Generating query vector for string: '{query[:60]}...'")
        return self.get_embedding(query)

    def embed_chunks(self, chunks: List[Chunk]) -> Tuple[List[Chunk], List[List[float]]]:
        """
        Converts document Chunk objects into vector embeddings.
        Isolates individual chunk failures to prevent whole-batch pipeline aborts.
        
        :return: Tuple containing (valid_chunks, generated_embeddings)
        """
        valid_chunks: List[Chunk] = []
        embeddings: List[List[float]] = []

        for chunk in chunks:
            try:
                vector = self.get_embedding(chunk.text)
                valid_chunks.append(chunk)
                embeddings.append(vector)
            except Exception as exc:
                logger.error(
                    f"Skipping Chunk '{chunk.chunk_id}' (Parent Doc: '{chunk.parent_doc_id}') "
                    f"due to embedding failure: {exc}"
                )

        logger.info(
            f"Embedding complete: {len(valid_chunks)}/{len(chunks)} chunks "
            f"processed successfully via '{self.model_name}'."
        )
        return valid_chunks, embeddings