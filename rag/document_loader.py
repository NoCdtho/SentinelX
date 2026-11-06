# Converts JSON knowledge base records into searchable Document objects with metadata 

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from rag.chunker import Document

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("SentinelX.DocumentLoader")

class DocumentLoader:
    """Loads, validates, cleans, and extracts metadata from SentinelX JSON knowledge bases."""

    def __init__(self):
        self._seen_ids: set[str] = set()

    def _assign_unique_id(self, raw_id: Optional[str], category: str, index: int) -> str:
        """
        Assigns a guaranteed unique document ID, resolving missing values or collisions.
        (Requirement 4: Assign unique IDs to documents)
        """
        # Fallback to category + index if raw_id is missing or invalid
        if isinstance(raw_id, (str, int, float)) and not isinstance(raw_id, bool):
            raw_id_text = str(raw_id).strip()
        else:
            raw_id_text = ""
        base_id = raw_id_text if raw_id_text else f"{category}_{index}"
        
        # Collision resolution loop
        unique_id = base_id
        counter = 1
        while unique_id in self._seen_ids:
            unique_id = f"{base_id}_{counter}"
            counter += 1

        self._seen_ids.add(unique_id)
        return unique_id

    def load_json_file(self, file_path: str | Path, category: str) -> List[Document]:
        """
        Loads a single JSON file, validates entries, and extracts content & metadata separately.
        (Requirement 1: Load JSON files & Requirement 5: Handle invalid/missing fields)
        """
        path = Path(file_path)
        if not path.exists():
            logger.error(f"Knowledge base file not found: {path}")
            return []

        try:
            with open(path, "r", encoding="utf-8") as f:
                records = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Malformed JSON format in {path.name} at line {e.lineno}: {e.msg}")
            return []
        except (OSError, UnicodeDecodeError) as e:
            logger.error(f"Unable to read knowledge base file {path}: {e}")
            return []

        if not isinstance(records, list):
            logger.warning(f"Skipping {path.name}: Root JSON element must be an array [].")
            return []

        documents: List[Document] = []
        for index, record in enumerate(records):
            # Skip invalid non-dictionary records
            if not isinstance(record, dict):
                logger.warning(f"Skipping record at index {index} in {path.name}: Not a JSON object.")
                continue

            # Requirement 5: Handle missing or invalid fields with defensive defaults
            raw_id = record.get("id")

            title = next(
                (
                    value.strip() for value in (
                        record.get("threat_name"),
                        record.get("title"),
                        record.get("name")
                    ) if isinstance(value, str) and value.strip()
                ),
                f"Untitled_{category}_{index}"
            )
            description_value = record.get("description")
            description = description_value.strip() if isinstance(description_value, str) else ""
            instructions_value = record.get("instructions")
            instructions = instructions_value.strip() if isinstance(instructions_value, str) else ""

            severity_value = record.get("severity") or record.get("severity_trigger")
            severity = severity_value.strip().upper() if isinstance(severity_value, str) and severity_value.strip() else "MEDIUM"
            source_value = record.get("source")
            source = source_value.strip() if isinstance(source_value, str) and source_value.strip() else "Unknown Source"

            # Skip records with no searchable text content
            if not description and not instructions:
                logger.warning(f"Skipping record '{raw_id or index}' in {path.name}: Lacks description or instructions.")
                continue

            # Requirement 4: Assign unique ID
            doc_id = self._assign_unique_id(raw_id, category, index)

            # Requirement 3: Extract document content (for vector embedding)
            protocol_value = record.get("protocol")
            protocol = protocol_value.strip() if isinstance(protocol_value, str) and protocol_value.strip() else ""

            content_parts = [f"Title: {title}"]
            if description:
                content_parts.append(f"Description: {description}")
            if instructions:
                content_parts.append(f"Instructions: {instructions}")
            if protocol:
                content_parts.append(f"Protocol: {protocol}")

            text_content = "\n".join(content_parts)

            # Requirement 3: Extract metadata (for ChromaDB filtering & citation)
            metadata: Dict[str, Any] = {
                "category": category,
                "doc_id": doc_id,
                "source": source,
                "title": title,
                "severity": severity,
                "original_id": str(raw_id) if raw_id else doc_id
            }

            # Optional metadata attributes
            if isinstance(record.get("framework_ref"), str) and record["framework_ref"].strip():
                metadata["framework_ref"] = record["framework_ref"].strip()
            if protocol:
                metadata["protocol"] = protocol
            if "requires_human_approval" in record:
                metadata["requires_human_approval"] = bool(record["requires_human_approval"])

            # Requirement 2: Convert record into Document object
            documents.append(Document(doc_id=doc_id, text=text_content, metadata=metadata))

        logger.info(f"Loaded {len(documents)} valid documents from {path.name} [{category}]")
        return documents

    def load_all_categories(
        self, 
        threat_intel_path: str | Path, 
        attack_patterns_path: str | Path, 
        response_playbooks_path: str | Path
    ) -> List[Document]:
        """
        Requirement 1 & 2: Main entrypoint to load all 3 JSON files into a unified Document collection.
        """
        self._seen_ids.clear()
        all_docs: List[Document] = []

        all_docs.extend(self.load_json_file(threat_intel_path, "threat_intelligence"))
        all_docs.extend(self.load_json_file(attack_patterns_path, "attack_patterns"))
        all_docs.extend(self.load_json_file(response_playbooks_path, "response_playbooks"))

        logger.info(f"Successfully loaded {len(all_docs)} total knowledge-base documents.")
        return all_docs