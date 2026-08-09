import json
import requests
from config import gemini_client, LLM_MODEL
from google.genai import types 

system_prompt = """
    You are an expert network security analyst.

    You are analyzing metadata extracted from a network packet
    using TShark.

    Your job is to:
    1. Explain what the packet represents.
    2. Identify the protocol behavior.
    3. Look for suspicious indicators.
    4. Estimate the security risk.
    5. Identify a possible attack only when there is evidence.
    6. Suggest an appropriate defensive action.

    IMPORTANT:
    - Do not invent information.
    - Do not assume a packet is malicious simply because
    it uses a particular port.
    - A single packet usually cannot prove an attack.
    - Clearly distinguish observed facts from security inference.
    - If there is insufficient information, say so.

    Return ONLY valid JSON.

    Use exactly this structure:

    {
        "summary": "Short explanation",
        "protocol_analysis": "Protocol-level explanation",
        "security_assessment": "Security interpretation",
        "risk_level": "Low|Medium|High|Critical|Unknown",
        "suspicious_indicators": [],
        "possible_attack": "None identified or possible attack",
        "mitre_attack_technique": "Technique or Not enough evidence",
        "recommended_action": "Recommended defensive action"
    }
    """

def default_error_response(message: str) -> dict:
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

# Remove markdown JSON fences if Gemini returns them.
def clean_json_response(response_text: str) -> str: #type: ignore
    
    
    if response_text.startswith("```json"):
        response_text = response_text[7:]
    
    if response_text.startswith("```"):
        response_text = response_text[3:]
    
    if response_text.endswith("```"):
        response_text = response_text[:-3]
    
    response_text = response_text.strip()


def validate_analysis(result: dict) -> dict:
    """
    Make sure the LLM returned the fields required by the application.
    """

    required_fields = {
        "summary": "",
        "protocol_analysis": "",
        "security_assessment": "",
        "risk_level": "Unknown",
        "suspicious_indicators": [],
        "possible_attack": "Unknown",
        "mitre_attack_technique": "Unknown",
        "recommended_action": "Manual analysis required."
    }

    for field, default_value in required_fields.items():

        if field not in result:
            result[field] = default_value

    # Make sure risk_level contains an expected value.
    valid_risk_levels = {
        "Low",
        "Medium",
        "High",
        "Critical",
        "Unknown"
    }

    if result["risk_level"] not in valid_risk_levels:
        result["risk_level"] = "Unknown"

    # suspicious_indicators should be a list.
    if not isinstance(
        result["suspicious_indicators"],
        list
    ):
        result["suspicious_indicators"] = [
            str(result["suspicious_indicators"])
        ]

    return result



# Analyze one structured network packet using Gemini.
def analyze_packet_with_llm(packet: dict) -> dict:

    packet_json = json.dumps(
        packet,
        indent=2
    )

    prompt = f"""
        {system_prompt}

        Analyze the following network packet:

        {packet_json}

        Return JSON only.
        """

    try:

        response = gemini_client.models.generate_content(
            model=LLM_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json"
            )
        )

        # text only returns the text part and ignore the non text part
        response_text = response.text 

        if not response_text:
            return  default_error_response(
                "Gemini is not responding"
            )

        response_text = clean_json_response(
            response_text
        )

        try:
            result = json.loads(
                response_text
            )

        except json.JSONDecodeError as exc:

            print(
                "Gemini returned invalid JSON"
            )

            print(exc)

            return default_error_response(
            "Gemini returned invalid JSON."
            )

        if not isinstance(result, dict):

            return default_error_response(
                "Gemini response was not a JSON object."
            )

        return validate_analysis(result)

    except Exception as exc:

        print(
            f"Gemini API error: {exc}"
        )

        return default_error_response(
            "Gemini analysis failed."
        )

