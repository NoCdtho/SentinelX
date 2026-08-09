import json
import requests
from config import gemini_client, LLM_MODEL
from google.genai import types 
import traceback

system_prompt = """
    You are an expert network security analyst.
    Analyze the meta data using structure
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


# Analyze one structured network packet using Gemini.
def analyze_packet_with_llm(packet: dict) -> dict:

    print("DEBUG: Packet type:", type(packet))
    print("DEBUG: Packet:", packet)

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

        print("DEBUG: Gemini response text:", repr(response_text))

        if not response_text:
            return  {
                "Summary" : "There is empty response from gemini" 
            }

        response_text = clean_json_response(response_text)

        try:
            result = json.loads(
                response_text
            )

        except json.JSONDecodeError as exc:

            print(exc)

            return {
                "Summary" : "There is empty response from gemini",
                "Description": "Gemini returned invalid JSON."
            }

        if not isinstance(result, dict):
            return {
                "Summary" : "There is empty response from gemini",
                "Description": "Gemini response was not a JSON object."
            }
        
        return result

    except Exception as exc:

        traceback.print_exc()

        return {
                "Summary" : "There is empty response from gemini",
                "Description": "Gemini analysis failed."
            }
            

