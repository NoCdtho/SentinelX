import os
import sys
from dotenv import load_dotenv
from google import genai

load_dotenv()

# Capture Settings
MAX_PACKETS = 1
TSHARK_INTERFACE = os.getenv("TSHARK_INTERFACE", "WI-FI")

# LLM API Settings
LLM_API_KEY = os.getenv("GEMINI_API_KEY")

if not LLM_API_KEY:
    print("key not found")
    sys.exit(1)

gemini_client = genai.Client(
    api_key=LLM_API_KEY
)

LLM_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
LOCAL_LLM_MODEL = os.getenv("QWEN_MODEL","qwen3:8b")

# Notion API Settings
NOTION_API_KEY = os.getenv("NOTION_API_KEY")
NOTION_PARENT_PAGE_ID = os.getenv("NOTION_PARENT_PAGE_ID")
NOTION_VERSION = "2022-06-28"
NOTION_API_URL = "https://api.notion.com/v1/pages"


def validate_configuration():
    """Ensure all required environment variables are set."""
    required_variables = {
        "LLM_API_KEY": LLM_API_KEY,
        "LLM_MODEL": LLM_MODEL,
        "NOTION_API_KEY": NOTION_API_KEY,
        "NOTION_PARENT_PAGE_ID": NOTION_PARENT_PAGE_ID,
    }

    missing = [name for name, value in required_variables.items() if not value]

    if missing:
        print("\nMissing environment variables:")
        for item in missing:
            print(f"  - {item}")
        print("\nPlease configure your .env file.")
        sys.exit(1)