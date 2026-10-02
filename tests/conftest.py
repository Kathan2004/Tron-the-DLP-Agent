import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Test configuration: never touch a real .env, bot or LLM.
os.environ["TRON_ENV_FILE"] = os.devnull
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "000000:test-token")
os.environ.setdefault("GCP_PROJECT_ID", "test-project")
os.environ.setdefault("APP_AUTH_SECRET", "test-secret-not-for-production")
os.environ.setdefault("APP_ADMIN_PASSWORD", "Test-Admin-Pass-123!")
os.environ.pop("GOOGLE_GENAI_API_KEY", None)
