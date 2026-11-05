import os
from dotenv import load_dotenv
from pathlib import Path
from dataclasses import dataclass 

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

chroma_db_dir: str = os.getenv("CHROMA_DB_DIR", str(BASE_DIR / "chroma_db"))
collection_name: str = os.getenv("CHROMA_COLLECTION", "sentinelx_knowledge_base")
# Relational Database (PostgreSQL / pgvector) Configuration
db_host: str = os.getenv("DB_HOST", "localhost")
db_port: int = int(os.getenv("DB_PORT", "5432"))
db_name: str = os.getenv("DB_NAME", "sentinelx")
db_user: str = os.getenv("DB_USER", "postgres")
db_password: str = os.getenv("DB_PASSWORD", "")

def postgres_connection_uri() -> str:
        return f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"


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