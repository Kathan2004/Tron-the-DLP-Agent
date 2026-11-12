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


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_process_state(monkeypatch):
    """Rate-limit counters and cached ciphers are process-wide; reset them per test."""
    from src import crypto, security
    security.limiter.reset()
    crypto.reset_cipher_cache()
    for var in ("TRON_AGENT_TOKEN", "TRON_AGENT_AUTH", "TRON_DATA_KEY", "TRON_METRICS_TOKEN",
                "TRON_ENCRYPT_AT_REST"):
        monkeypatch.delenv(var, raising=False)
    yield
    security.limiter.reset()
    crypto.reset_cipher_cache()


@pytest.fixture()
def client(tmp_path):
    """Flask test client wired to a fresh database in tmp_path."""
    from src import api
    from src.ai_analyzer import FalsePositiveClassifier, VertexAIAnalyzer
    from src.database import Database
    from src.event_processor import EscalationEngine, EventProcessor
    from src.incident_store import IncidentStore
    from src.rules_engine import RulesEngine
    from src.telegram_bot import DLPTelegramBot

    db = Database(str(tmp_path / "test.db"))
    store = IncidentStore(db=db)
    rules = RulesEngine()
    rules.db = db
    processor = EventProcessor(rules, store)
    bot = DLPTelegramBot(store)
    analyzer = VertexAIAnalyzer()
    api.init_components(store, rules, processor, EscalationEngine(), analyzer,
                        FalsePositiveClassifier(analyzer), bot, db)
    api.app.config["TESTING"] = True
    with api.app.test_client() as c:
        c.db = db
        yield c


ADMIN = {"email": "admin@tron.local", "password": "Test-Admin-Pass-123!"}


@pytest.fixture()
def admin_token(client):
    r = client.post("/api/auth/login", json=ADMIN)
    assert r.status_code == 200, r.json
    return r.json["token"]


@pytest.fixture()
def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}
