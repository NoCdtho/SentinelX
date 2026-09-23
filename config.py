import os
from dotenv import load_dotenv

load_dotenv()

# Capture Settings
MAX_PACKETS = 1
TSHARK_INTERFACE = os.getenv("TSHARK_INTERFACE", "WI-FI")
MAX_PACKETS_LIMIT = 10


LOCAL_LLM_MODEL = os.getenv("QWEN_MODEL", "qwen3:8b")

# Notion API Settings
NOTION_API_KEY = os.getenv("NOTION_API_KEY")
NOTION_PARENT_PAGE_ID = os.getenv("NOTION_PARENT_PAGE_ID")
NOTION_VERSION = "2022-06-28"
NOTION_API_URL = "https://api.notion.com/v1/pages"


def validate_configuration() -> bool:
    """Ensure all required environment variables are set."""
    required_variables = {
        "NOTION_API_KEY": NOTION_API_KEY,
        "NOTION_PARENT_PAGE_ID": NOTION_PARENT_PAGE_ID,
    }

    missing = [name for name, value in required_variables.items() if not value]

    if missing:
        print("\nMissing environment variables:")
        for item in missing:
            print(f"  - {item}")
        print("\nPlease configure your .env file.")
        return False
    return True