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

# Analyze one structured network packet using Gemini.
def analyze_packet_with_llm(packet: dict) -> dict:

    print("DEBUG: Packet type:", type(packet))
    print("DEBUG: Packet:", packet)

    # Here the packets dictionary are converted into JSON text string.
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
        # The response is being is stored in the form JSON as well below is API call being made 
        response = gemini_client.models.generate_content(
            model=LLM_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json"
            )
        )

        # Below attribute pulls the raw string out of the API's response object.
        response_text = response.text 

        # print("DEBUG: Gemini response text:", repr(response_text))
        if not response_text:
            return  {
                "Summary" : "There is empty response from gemini" 
            }

        response_text = clean_json_response(response_text)

        try:
            # This function converts the json object in python dictionary
            result = json.loads(response_text)

        except json.JSONDecodeError as exc:
            print(exc)
            return {
                "Summary" : "There is empty response from gemini",
                "Description": "Gemini returned invalid JSON."
            }
        
        # Check if the result is a disctionary or not type checking
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

# Analyze structured packet using qwen 
def analyze_packet_with_local_llm(packet: dict)-> dict:

    # Converts python object to json formatted String
    packet_json = json.dumps(packet, indent=2)

    # Structure prompt
    prompt = f""" 
    {system_prompt} 
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

        response_text = response["message"]["content"]

        if not response_text:
            raise RuntimeError(
                "Local LLM return a empty response."
            )

        result = json.loads(response_text) # Convert JSON formated string into python object
        return result

    except Exception as e:
        print("Local LLM error: {exc}")
        return {
            "Summary" : "There is empty response from qwen",
            "Description": "Qwen analysis failed."
        }

