"""
This file formats the network packet data and retrival results into structured prompts for local llm
"""

import json
import logging
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class SentinelContextBuilder:
    """Formats retrieved vector matches, threat metadata, and packet signals 
    into clean, structured prompt context blocks for the local LLM agent.
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def format_pattern_record(self, record: Dict[str, Any], index: int, concise: bool = False) -> str:
        """Formats an individual retrieved threat pattern record into Markdown.

        Args:
            record: Dictionary containing pattern_id, attack_type, severity, protocol, content, distance_score.
            index: Numerical index for ordering in the prompt context.
            concise: If True, uses a compact single-line format to save prompt tokens.
        """
        pid = record.get("pattern_id", "N/A")
        attack_type = record.get("attack_type", "N/A")
        severity = record.get("severity", "N/A").upper()
        protocol = record.get("protocol", "N/A").upper()
        score = record.get("distance_score", record.get("similarity_score", 0.0))
        content = record.get("description", record.get("content", ""))

        if concise:
            return f"[{index}] ID:{pid} | Type:{attack_type} | Sev:{severity} | Proto:{protocol} | Score:{score:.4f} -> {content}"

        lines = [
            f"### Match #{index}: [{pid}] {attack_type}",
            f"- **Protocol:** {protocol}",
            f"- **Severity Level:** {severity}",
            f"- **Vector Distance Score:** {score:.4f}",
            f"- **Pattern Description:** {content}",
        ]
        return "\n".join(lines)

    def build_rag_context_block(
        self,
        retrieval_response: Dict[str, Any],
        max_matches: Optional[int] = None,
        concise_mode: bool = False,
    ) -> str:
        """Converts raw RAG retrieval results into a structured prompt context block.

        Args:
            retrieval_response: Output dictionary from SentinelRetriever or SentinelQueryBuilder.
            max_matches: Limit the number of pattern records included in the context.
            concise_mode: If True, uses compact text representation for token optimization.

        Returns:
            Formatted string block ready for injection into LLM prompt template.
        """
        status = retrieval_response.get("status", "UNKNOWN")
        patterns = retrieval_response.get("patterns", [])
        threshold = retrieval_response.get("threshold_used", "N/A")

        if max_matches is not None and max_matches > 0:
            patterns = patterns[:max_matches]

        if status == "NO_RELEVANT_MATCH" or not patterns:
            return (
                "=== SENTINELX THREAT INTELLIGENCE CONTEXT ===\n"
                "[RAG Status: NO_RELEVANT_MATCH]\n"
                f"No known attack signatures matched the evaluated packet vector within threshold ({threshold}).\n"
                "Note: Treat current traffic frame against baseline anomaly heuristics."
            )

        context_header = (
            "=== SENTINELX THREAT INTELLIGENCE CONTEXT ===\n"
            f"[RAG Status: MATCH_FOUND | {len(patterns)} Signature Match(es) Retrived]\n"
        )

        formatted_records = []
        for idx, pattern in enumerate(patterns, start=1):
            formatted_records.append(self.format_pattern_record(pattern, idx, concise=concise_mode))

        divider = "\n" + ("-" * 45) + "\n" if not concise_mode else "\n"
        records_body = divider.join(formatted_records)
        context_footer = "\n=================================================="

        return f"{context_header}\n{records_body}{context_footer}"

    def inject_llm_prompt(
        self,
        system_instruction: str,
        packet_features: Dict[str, Any],
        retrieval_response: Dict[str, Any],
        concise_rag: bool = False,
    ) -> List[Dict[str, str]]:
        """Constructs full chat messages payload (System + User Prompt) for local LLM inference.

        Args:
            system_instruction: Core directive for the local LLM security agent.
            packet_features: Extracted features from parser.py/analyzer.py.
            retrieval_response: RAG matches output dictionary from retriever.py.
            concise_rag: Enables token-efficient RAG context rendering.

        Returns:
            List of message dicts formatted for OpenAI/Ollama API (`[{'role': 'system', ...}, ...]`).
        """
        rag_context = self.build_rag_context_block(retrieval_response, concise_mode=concise_rag)

        user_content = [
            "### LIVE EVALUATION TARGET (Network Packet Signals)",
            "```json",
            json.dumps(packet_features, indent=2),
            "```\n",
            rag_context,
            "\n### INSTRUCTION FOR AGENT",
            "Synthesize the packet signals with the retrieved threat intelligence context above.",
            "Explain if this packet represents malicious activity or benign traffic, update internal notion, and decide whether to inspect more frames or STOP.",
        ]

        messages = [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": "\n".join(user_content)},
        ]

        return messages



if __name__ == "__main__":
    builder = SentinelContextBuilder()

    # Mock live packet features extracted by parser.py/analyzer.py
    sample_packet_data = {
        "frame_id": 1042,
        "src_ip": "192.168.1.105",
        "dest_ip": "10.0.0.12",
        "protocol": "HTTP",
        "dest_port": 80,
        "http": {
            "method": "GET",
            "uri": "/admin/config.php?id=1' UNION SELECT 1,username,password FROM users--",
            "user_agent": "sqlmap/1.6.4#stable",
        },
    }

    # Mock retrieval output from rag/retriever.py
    mock_retrieval_match = {
        "status": "MATCH_FOUND",
        "threshold_used": 1.10,
        "total_candidates_found": 1,
        "matches_accepted": 1,
        "patterns": [
            {
                "pattern_id": "RULE-HTTP-001",
                "attack_type": "SQL Injection (SQLi)",
                "severity": "critical",
                "protocol": "HTTP",
                "description": "SQL injection pattern detected in HTTP GET parameters using UNION SELECT syntax to extract database user credentials.",
                "distance_score": 0.2415,
            }
        ],
    }

    print("--- 1. Testing Standard Markdown Context Building ---")
    markdown_context = builder.build_rag_context_block(mock_retrieval_match, concise_mode=False)
    print(markdown_context)

    print("\n--- 2. Testing Concise Token-Efficient Context Building ---")
    concise_context = builder.build_rag_context_block(mock_retrieval_match, concise_mode=True)
    print(concise_context)

    print("\n--- 3. Testing Full LLM Prompt Payload Generation ---")
    system_prompt = "You are SentinelX, an automated agentic IIoT network security analyst."
    llm_payload = builder.inject_llm_prompt(system_prompt, sample_packet_data, mock_retrieval_match)
    print(json.dumps(llm_payload, indent=2))