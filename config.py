import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
REQUEST_TIMEOUT = 30
CACHE_DIR = BASE_DIR / "cache"
OUTPUT_DIR = BASE_DIR / "output"
CLASSES_FILE = BASE_DIR / "data" / "malware_classes.json"
