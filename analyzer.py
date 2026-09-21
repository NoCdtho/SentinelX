import json
import ollama
from config import gemini_client, LLM_MODEL, LOCAL_LLM_MODEL
from google.genai import types 
import traceback

system_prompt = """
    You are a network security analyst.
    You have access to two tools:
    1. **fetch_tshark_packets**: Fetches additional network packets for further analysis.
    2. **document_to_notion**: Saves the current analysis to Notion.

    Decide which tool you need to use next.

    - If you choose **fetch_tshark_packets**, respond with a JSON object containing exactly two fields:
    - "tool_name": "fetch_tshark_packets"
    - "explanation": A brief explanation of why you need more packets.

    - If you choose **document_to_notion**, respond with a JSON object containing the full analysis in exactly this structure:
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

    Return only the JSON object, without any additional text or markdown fences.
    """


# Remove markdown JSON fences if Gemini returns them.
def clean_json_response(response_text: str) -> str: #type: ignore
    
    
    if response_text.startswith("```json"):
        response_text = response_text[7:]
    
    if response_text.startswith("```"):
        response_text = response_text[3:]
    
    if response_text.endswith("```"):
        response_text = response_text[:-3]
    
    response_text = response_text.strip()

    return response_text


# Analyze structured packet using qwen 
def analyze_packet_with_local_llm(packet: dict)-> dict:

    # Converts python object to json formatted String
    packet_json = json.dumps(packet, indent=2)

    # Structure prompt
    prompt = f"""  
    Analyze this network packet:
    {packet_json}
    """

    try:
        response = ollama.chat(
            model=LOCAL_LLM_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            format="json"
        )

        responses= response["message"]["content"]
        role = response["messages"]["role"]
        print(f"This was asked by {role}")
        print(f"This is the response: {responses}")
        if not responses:
            raise RuntimeError(
                "Local LLM return a empty response."
            )

        result = json.loads(responses) # Convert JSON formated string into python object
        return result

    except Exception as e:
        print("Local LLM error: {exc}")
        return {
            "Summary" : "There is empty response from qwen",
            "Description": "Qwen analysis failed."
        }

