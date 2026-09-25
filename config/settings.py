import os
from dotenv import load_dotenv
from pathlib import Path

# Load .env from the project root
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=env_path, override=True)

class Config:
    # Telegram
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    _chat_id = os.getenv("SECURITY_CHAT_ID", "").strip()
    SECURITY_CHAT_ID = int(_chat_id) if _chat_id else 0
    
    # Google Cloud
    GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
    GCP_CREDENTIALS_PATH = os.getenv("GCP_CREDENTIALS_PATH", "./config/service-account.json")
    GCP_REGION = "us-central1"
    
    # Google Generative AI (Gemini)
    GOOGLE_GENAI_API_KEY = os.getenv("GOOGLE_GENAI_API_KEY")
    
    # Slack
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
    
    # Jira
    JIRA_SERVER = os.getenv("JIRA_SERVER")
    JIRA_USER = os.getenv("JIRA_USER")
    JIRA_TOKEN = os.getenv("JIRA_TOKEN")
    
    # Flask
    FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))
    FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    
    # Redis
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    # DLP Rules
    FP_AUTO_CLOSE_THRESHOLD = 0.85  # Close if FP prob > 85%
    INCIDENT_TRIGGER_THRESHOLD = 3  # Trigger AI analysis after N alerts
    INCIDENT_TIME_WINDOW = 30 * 60  # 30 minutes in seconds
    
    # Vertex AI Model
    VERTEX_AI_MODEL = "gemini-1.5-flash"  # Using Gemini on Vertex AI
    MAX_TOKENS = 500
    TEMPERATURE = 0.3
