#!/usr/bin/env python3
"""
TRON THE DLP AGENT System v2.0 — Main Entry Point
Real AI-Powered Data Loss Prevention with persistent storage.
"""

import asyncio
import sys
from config.settings import Config
from src.database import Database
from src.incident_store import IncidentStore
from src.rules_engine import RulesEngine
from src.ai_analyzer import VertexAIAnalyzer, FalsePositiveClassifier
from src.event_processor import EventProcessor, EscalationEngine
from src.telegram_bot import DLPTelegramBot, scrub_token
from src.api import app, init_components
import threading


def main():
    """Main application entry point"""

    print("""
    ╔════════════════════════════════════════════════════════╗
    ║   🛡️  TRON THE DLP AGENT SYSTEM v2.0                         ║
    ║   Real AI-Powered Data Loss Prevention                 ║
    ║   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
    ║   Storage:  SQLite (Persistent)                        ║
    ║   Scanning: Real file content analysis                 ║
    ║   Network:  Real connection monitoring                 ║
    ╚════════════════════════════════════════════════════════╝
    """)

    # Check configuration
    if not Config.TELEGRAM_BOT_TOKEN:
        print("❌ TELEGRAM_BOT_TOKEN not configured")
        sys.exit(1)

    if not Config.GCP_PROJECT_ID:
        print("❌ GCP_PROJECT_ID not configured")
        sys.exit(1)

    # Initialize persistent database
    database = Database()
    print(f"  ✅ Database: SQLite (persistent)")

    # Initialize components with database
    incident_store = IncidentStore(db=database)
    rules_engine = RulesEngine()
    rules_engine.db = database
    event_processor = EventProcessor(rules_engine, incident_store)
    escalation_engine = EscalationEngine()
    ai_analyzer = VertexAIAnalyzer()
    fp_classifier = FalsePositiveClassifier(ai_analyzer)

    # Initialize Telegram bot
    telegram_bot = DLPTelegramBot(incident_store)
    telegram_bot.escalation_engine = escalation_engine

    # Set cross-references
    event_processor.escalation_engine = escalation_engine
    event_processor.telegram_bot = telegram_bot
    event_processor.ai_analyzer = ai_analyzer

    # Print component status
    print(f"  ✅ Telegram Bot: Configured")
    print(f"  ✅ GCP Project: {Config.GCP_PROJECT_ID}")
    print(f"  ✅ AI Model: Gemini 2.0 Flash")
    print(f"  ✅ Slack: {'Configured' if Config.SLACK_WEBHOOK_URL else 'Not configured'}")
    print(f"  ✅ API Server: {Config.FLASK_HOST}:{Config.FLASK_PORT}")

    # Database stats
    stats = database.stats()
    if stats['total_incidents'] > 0 or stats['total_events'] > 0:
        print(f"\n  📊 Loaded from DB:")
        print(f"     Incidents: {stats['total_incidents']} ({stats['open']} open)")
        print(f"     Events: {stats['total_events']}")
        print(f"     Scans: {stats['total_scans']}")

    print()

    # Share components with API
    init_components(
        incident_store,
        rules_engine,
        event_processor,
        escalation_engine,
        ai_analyzer,
        fp_classifier,
        telegram_bot,
        database
    )

    # ===========================
    # FIXED TELEGRAM SECTION
    # ===========================

    def run_telegram():
        """Run Telegram bot safely in separate thread (PTB v20+)"""
        try:
            import os
            # Prevent Telegram from routing itself through our mitmproxy
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"]:
                os.environ.pop(var, None)
            os.environ["NO_PROXY"] = "*"
            os.environ["no_proxy"] = "*"

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            telegram_bot.loop = loop
            telegram_bot.run()
        except Exception as e:
            print(f"  ❌ Telegram bot error: {scrub_token(e)}")

    telegram_thread = threading.Thread(
        target=run_telegram,
        daemon=True
    )
    telegram_thread.start()

    # ===========================

    print("  🚀 Starting DLP System...")
    print()
    print("  📡 API Endpoints:")
    print(f"     POST /api/events          — Ingest events from agents")
    print(f"     GET  /api/events          — List events")
    print(f"     GET  /api/incidents       — List incidents")
    print(f"     POST /api/scan/file       — Scan file/directory")
    print(f"     POST /api/scan/text       — Scan text content")
    print(f"     POST /api/scan/clipboard  — Scan clipboard")
    print(f"     GET  /api/scans           — Scan results")
    print(f"     GET  /api/audit           — Audit log")
    print(f"     GET  /api/stats           — Dashboard stats")
    print(f"     GET  /api/health          — Health check")
    print()

    # Start Flask API server
    try:
        app.run(
            host=Config.FLASK_HOST,
            port=Config.FLASK_PORT,
            debug=Config.DEBUG,
            use_reloader=False
        )
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down DLP System...")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {scrub_token(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()