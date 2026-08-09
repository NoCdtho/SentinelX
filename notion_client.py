import json
from datetime import datetime, timezone
import requests
from config import NOTION_API_KEY, NOTION_API_URL, NOTION_PARENT_PAGE_ID, NOTION_VERSION


def notion_headers() -> dict:
    return {
        "Authorization": f"Bearer {NOTION_API_KEY}",
        "Content-Type": "application/json",
        "Notion-Version": NOTION_VERSION
    }


def notion_text(text) -> dict:
    return {
        "type": "text",
        "text": {"content": str(text or "")[:1900]}
    }


def paragraph_block(text: str) -> dict:
    return {
        "object": "block",
        "type": "paragraph",
        "paragraph": {"rich_text": [notion_text(text)]}
    }


def heading_block(text: str, level: int = 2) -> dict:
    block_type = f"heading_{level}"
    return {
        "object": "block",
        "type": block_type,
        block_type: {"rich_text": [notion_text(text)]}
    }


def bullet_block(text: str) -> dict:
    return {
        "object": "block",
        "type": "bulleted_list_item",
        "bulleted_list_item": {"rich_text": [notion_text(text)]}
    }


def code_block(code: str, language: str = "json") -> dict:
    return {
        "object": "block",
        "type": "code",
        "code": {
            "rich_text": [notion_text(code)],
            "language": language
        }
    }


def build_packet_blocks(item: dict) -> list:
    """Build Notion blocks for a single analyzed packet."""
    packet = item["packet"]
    analysis = item["analysis"]
    number = packet["packet_number"]

    suspicious = analysis.get("suspicious_indicators", [])
    suspicious_text = ", ".join(str(x) for x in suspicious) if isinstance(suspicious, list) else str(suspicious)

    return [
        heading_block(f"Packet {number}", level=2),
        paragraph_block(f"Protocol: {packet['protocol_stack']}"),
        paragraph_block(f"Source: {packet['source_ip']}"),
        paragraph_block(f"Destination: {packet['destination_ip']}"),
        paragraph_block(f"Length: {packet['length']} bytes"),
        heading_block("LLM Security Analysis", level=3),
        bullet_block(f"Summary: {analysis.get('summary', 'N/A')}"),
        bullet_block(f"Protocol analysis: {analysis.get('protocol_analysis', 'N/A')}"),
        bullet_block(f"Security assessment: {analysis.get('security_assessment', 'N/A')}"),
        bullet_block(f"Risk level: {analysis.get('risk_level', 'Unknown')}"),
        bullet_block(f"Suspicious indicators: {suspicious_text or 'None identified'}"),
        bullet_block(f"Possible attack: {analysis.get('possible_attack', 'Unknown')}"),
        bullet_block(f"MITRE ATT&CK technique: {analysis.get('mitre_attack_technique', 'Unknown')}"),
        bullet_block(f"Recommended action: {analysis.get('recommended_action', 'N/A')}"),
        heading_block("Packet Data", level=3),
        code_block(json.dumps(packet, indent=2))
    ]


def create_notion_page(packets: list) -> dict:
    """Publish the full packet analysis report to Notion."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    title = f"Network Packet Analysis - {timestamp}"

    children = [
        heading_block("Network Packet Analysis", level=1),
        paragraph_block(f"Analysis generated at {timestamp}."),
        paragraph_block(f"Packets analyzed: {len(packets)}")
    ]

    for item in packets:
        children.extend(build_packet_blocks(item))

    payload = {
        "parent": {"page_id": NOTION_PARENT_PAGE_ID},
        "properties": {
            "title": {
                "title": [{"text": {"content": title}}]
            }
        },
        "children": children
    }

    try:
        response = requests.post(NOTION_API_URL, headers=notion_headers(), json=payload, timeout=60)
        response.raise_for_status()

        result = response.json()
        print()
        print("=" * 60)
        print("Notion page created successfully")
        print("=" * 60)
        print(f"Page ID : {result.get('id')}")
        print(f"Page URL: {result.get('url', 'Not available')}")
        return result

    except requests.RequestException as exc:
        print(f"\nNotion API error: {exc}")
        if hasattr(exc, "response") and exc.response is not None:
            print(exc.response.text)
        return None #type:ignore