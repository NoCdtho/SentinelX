import json
import requests
from config import LLM_API_KEY, LLM_MODEL

SYSTEM_PROMPT = """
You are a network security analyst.

Analyze the supplied network packet metadata.

Do NOT invent information that is not present in the packet.

Return valid JSON with exactly these fields:

{
  "summary": "...",
  "protocol_analysis": "...",
  "security_assessment": "...",
  "risk_level": "Low|Medium|High|Critical|Unknown",
  "suspicious_indicators": [],
  "possible_attack": "...",
  "mitre_attack_technique": "...",
  "recommended_action": "..."
}

Important:
- A single packet does not automatically prove an attack.
- Clearly distinguish observation from inference.
- If there is insufficient information to identify an attack, say so.
- Do not claim that a packet is malicious without evidence.
"""


def _default_error_response(message: str) -> dict:
    return {
        "summary": message,
        "protocol_analysis": "",
        "security_assessment": "",
        "risk_level": "Unknown",
        "suspicious_indicators": [],
        "possible_attack": "Unknown",
        "mitre_attack_technique": "Unknown",
        "recommended_action": "Manual analysis required."
    }


def analyze_packet_with_llm(packet: dict) -> dict:
    """Send structured packet metadata to the LLM API for analysis."""
    user_prompt = f"Analyze this network packet:\n\n{json.dumps(packet, indent=2)}\n\nProvide the result as JSON only."

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT.strip()},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"}
    }

    try:
        response = requests.post(LLM_API_URL, headers=headers, json=payload, timeout=90) #type:ignore
        response.raise_for_status()

        result = response.json()
        content = result.get("choices", [{}])[0].get("message", {}).get("content", "")

        if not content:
            return _default_error_response("LLM returned no analysis.")

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            res = _default_error_response("LLM output could not be parsed as JSON.")
            res["summary"] = content
            return res

    except requests.RequestException as exc:
        print(f"LLM API error: {exc}")
        return _default_error_response("LLM analysis failed due to network error.")