import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma

# Default configuration paths matching SentinelX architecture
CHROMA_DB_DIR = Path("./knowledge_base/chroma_db")
COLLECTION_NAME = "sentinelx_patterns"
EMBEDDING_MODEL = "nomic-embed-text"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class SentinelQueryBuilder:
    """Runtime Query Builder and Vector Retrieval Engine for SentinelX.
    
    Handles preprocessed packet normalization, HTTP payload parsing, HTTPS encrypted 
    traffic heuristics, vector embedding generation, and Chroma DB similarity retrieval.
    """

    def __init__(
        self,
        db_dir: Path = CHROMA_DB_DIR,
        collection_name: str = COLLECTION_NAME,
        model_name: str = EMBEDDING_MODEL,
    ):
        self.db_dir = db_dir
        self.collection_name = collection_name
        self.model_name = model_name
        
        # Step 3 Core: Initialize nomic-embed-text embedding engine
        self.embeddings = OllamaEmbeddings(model=self.model_name)
        self._vectorstore: Optional[Chroma] = None

    def _get_vectorstore(self) -> Chroma:
        """Lazy-loads and connects to the persistent ChromaDB collection."""
        if self._vectorstore is None:
            if not self.db_dir.exists():
                raise FileNotFoundError(
                    f"Chroma DB directory '{self.db_dir}' not found. "
                    "Execute 'rag/ingest.py' or 'rag/test_ingest.py' first."
                )
            self._vectorstore = Chroma(
                collection_name=self.collection_name,
                embedding_function=self.embeddings,
                persist_directory=str(self.db_dir),
            )
        return self._vectorstore

    # =========================================================================
    # PART 1 & PART 2: Packet Preprocessing & HTTP / HTTPS Inspection
    # =========================================================================

    def _extract_http_query(self, packet: Dict[str, Any]) -> str:
        """Extracts plaintext L7 HTTP parameters (Method, URI, Host, Headers, Payload Snippet)."""
        http_data = packet.get("http", {})
        method = http_data.get("method", "UNKNOWN")
        uri = http_data.get("uri", "/")
        host = http_data.get("host", "unknown-host")
        user_agent = http_data.get("user_agent", "")
        payload = http_data.get("payload_snippet", "")
        status_code = http_data.get("status_code", "")

        query_tokens = [
            f"Protocol: HTTP",
            f"HTTP Method: {method}",
            f"Target URI: {uri}",
            f"Host: {host}",
        ]
        
        if status_code:
            query_tokens.append(f"Status Code: {status_code}")
        if user_agent:
            query_tokens.append(f"User-Agent: {user_agent}")
        if payload:
            query_tokens.append(f"Payload Snippet: {payload}")

        return " | ".join(query_tokens)

    def _extract_https_query(self, packet: Dict[str, Any]) -> str:
        """Handles HTTPS/TLS encrypted traffic visibility constraints.
        
        Note: Layer-7 HTTP URI, headers, and body are encrypted. Fallback to 
        TLS Handshake metadata (SNI, Cipher Suites, JA3/JA4), packet length, 
        port 443 signals, and entropy analysis.
        """
        tls_data = packet.get("tls", {})
        sni = tls_data.get("sni") or tls_data.get("server_name", "Unknown-SNI")
        cipher_suite = tls_data.get("cipher_suite", "Unknown-Cipher")
        tls_version = tls_data.get("version", "TLS1.2/1.3")
        ja3_hash = tls_data.get("ja3_fingerprint", "")
        payload_entropy = packet.get("entropy", None)
        pkt_len = packet.get("length", 0)

        query_tokens = [
            "Protocol: HTTPS/TLS (Encrypted Payload - L7 Content Inaccessible)",
            f"SNI Target: {sni}",
            f"TLS Version: {tls_version}",
            f"Cipher Suite: {cipher_suite}",
            f"Packet Size: {pkt_len} bytes",
        ]

        if ja3_hash:
            query_tokens.append(f"JA3 Signature: {ja3_hash}")
        if payload_entropy is not None:
            query_tokens.append(f"Payload Entropy: {payload_entropy:.2f}")

        # Heuristic anomaly tagging for encrypted channels
        if payload_entropy and payload_entropy > 7.5:
            query_tokens.append("Anomaly: High entropy encrypted payload (possible data exfiltration or malware C2)")

        return " | ".join(query_tokens)

    def build_query_string(self, preprocessed_packet: Dict[str, Any]) -> str:
        """Constructs a domain-rich semantic query from preprocessed packet data.
        
        Args:
            preprocessed_packet: Structured feature map output by parser.py/analyzer.py.
        """
        proto = str(preprocessed_packet.get("protocol", "")).upper()
        dest_port = preprocessed_packet.get("dest_port", 0)

        # Route 1: Handle HTTP (Plaintext inspection)
        if proto == "HTTP" or dest_port == 80:
            query_body = self._extract_http_query(preprocessed_packet)

        # Route 2: Handle HTTPS / TLS (Encrypted payload constraints)
        elif proto in ["HTTPS", "TLS", "SSL"] or dest_port == 443:
            query_body = self._extract_https_query(preprocessed_packet)

        # Route 3: Generic TCP / UDP / ICMP Packet fallback
        else:
            tcp_flags = preprocessed_packet.get("tcp_flags", "")
            src_ip = preprocessed_packet.get("src_ip", "")
            dest_ip = preprocessed_packet.get("dest_ip", "")
            raw_desc = preprocessed_packet.get("description", "")

            tokens = [f"Protocol: {proto}"]
            if dest_port:
                tokens.append(f"Destination Port: {dest_port}")
            if tcp_flags:
                tokens.append(f"TCP Flags: {tcp_flags}")
            if src_ip and dest_ip:
                tokens.append(f"Flow: {src_ip}:{preprocessed_packet.get('src_port', '')} -> {dest_ip}:{dest_port}")
            if raw_desc:
                tokens.append(f"Anomaly Detail: {raw_desc}")

            query_body = " | ".join(tokens)

        # Append explicit threat tags if identified during preprocessing
        if "attack_type" in preprocessed_packet:
            query_body += f" | Suspected Attack: {preprocessed_packet['attack_type']}"

        return query_body

    # =========================================================================
    # PART 3: Embedding Generation & Runtime Retrieval
    # =========================================================================

    def generate_query_embedding(self, query_string: str) -> List[float]:
        """Generates a dense vector embedding using the local nomic-embed-text model.

        Args:
            query_string: The formatted search query text.

        Returns:
            Vector embedding float array.
        """
        logging.info(f"Generating query embedding with model: '{self.model_name}'")
        return self.embeddings.embed_query(query_string)

    def retrieve_threat_context(
        self,
        preprocessed_packet: Dict[str, Any],
        top_k: int = 3,
        score_threshold: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Builds query string, generates embeddings, and queries ChromaDB.

        Args:
            preprocessed_packet: Extracted features from live traffic frame.
            top_k: Number of matching security context documents to return.
            score_threshold: Optional similarity distance threshold filter.
        """
        # Step 1: Prepare query string from packet features
        query_str = self.build_query_string(preprocessed_packet)
        logging.info(f"Built Retrieval Query: {query_str}")

        # Step 2: Query ChromaDB using nomic-embed-text vector embeddings
        vectorstore = self._get_vectorstore()
        
        # Apply protocol metadata filter if present
        proto_filter = preprocessed_packet.get("protocol")
        filter_kwargs = {}
        if proto_filter and proto_filter.upper() in ["TCP", "UDP", "HTTP", "DNS"]:
            filter_kwargs["filter"] = {"protocol": proto_filter.upper()}

        raw_results = vectorstore.similarity_search_with_score(
            query_str,
            k=top_k,
            **filter_kwargs
        )

        matched_records = []
        for doc, score in raw_results:
            if score_threshold is not None and score > score_threshold:
                continue
            matched_records.append({
                "content": doc.page_content,
                "metadata": doc.metadata,
                "similarity_score": round(float(score), 4),
            })

        return matched_records

    def format_llm_context(self, preprocessed_packet: Dict[str, Any], top_k: int = 3) -> str:
        """Formats retrieved vector matches into a clean prompt context block for the LLM."""
        records = self.retrieve_threat_context(preprocessed_packet, top_k=top_k)

        if not records:
            return "No relevant threat signatures or CVE context found in Chroma knowledge base."

        context_lines = ["=== SENTINELX RETRIEVED THREAT KNOWLEDGE ==="]
        for idx, rec in enumerate(records, start=1):
            meta = rec["metadata"]
            pid = meta.get("pattern_id", "N/A")
            attack = meta.get("attack_type", "N/A")
            severity = meta.get("severity", "N/A")

            context_lines.append(
                f"[{idx}] ID: {pid} | Attack Type: {attack} | Severity: {severity} (Score: {rec['similarity_score']})"
            )
            context_lines.append(f"    Description: {rec['content']}\n")

        context_lines.append("=============================================")
        return "\n".join(context_lines)


if __name__ == "__main__":
    # Test harness simulating live packet processing
    builder = SentinelQueryBuilder()

    # Case A: Plaintext HTTP Packet (SQLi payload)
    http_packet = {
        "protocol": "HTTP",
        "dest_port": 80,
        "http": {
            "method": "GET",
            "uri": "/api/users?id=1' UNION SELECT username, password FROM users--",
            "host": "prime-motorx.local",
            "user_agent": "sqlmap/1.5.2#stable",
            "payload_snippet": "UNION SELECT username, password",
        },
        "attack_type": "SQL Injection",
    }

    # Case B: Encrypted HTTPS Packet (SNI + High Entropy)
    https_packet = {
        "protocol": "HTTPS",
        "dest_port": 443,
        "length": 1420,
        "entropy": 7.85,
        "tls": {
            "sni": "c2-malicious-node.xyz",
            "version": "TLS 1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "ja3_fingerprint": "7710,4865-4866-4867,0-23-65281,29-23-24,0",
        },
    }

    print("--- Testing HTTP Query Building ---")
    http_q = builder.build_query_string(http_packet)
    print(f"HTTP Query: {http_q}\n")

    print("--- Testing HTTPS Visibility Fallback ---")
    https_q = builder.build_query_string(https_packet)
    print(f"HTTPS Query: {https_q}\n")

    print("--- Testing Nomic Embedding Generation ---")
    vector = builder.generate_query_embedding(http_q)
    print(f"Embedding Vector Dim: {len(vector)} (Model: nomic-embed-text)")