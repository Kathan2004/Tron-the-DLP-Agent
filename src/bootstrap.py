"""
Application assembly: build the components, attach them to the Flask app and start the
background services. Used by wsgi.py (production) and main.py (local development).
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading

from src import logging_setup

log = logging.getLogger("tron.bootstrap")
_started = threading.Lock()
_app = None


def _config_warnings() -> None:
    from src import agent_auth
    if not os.getenv("APP_AUTH_SECRET", "").strip():
        log.warning("APP_AUTH_SECRET is unset: console sessions will not survive a restart")
    if agent_auth.auth_mode() == "open":
        log.warning("agent ingest is unauthenticated: set TRON_AGENT_TOKEN (and TRON_AGENT_AUTH=strict "
                    "once agents are enrolled)")
    if not os.getenv("TRON_DATA_KEY", "").strip():
        log.warning("TRON_DATA_KEY is unset: the data key is stored next to the database; set it from a "
                    "secret manager so database copies are unreadable on their own")
    if os.getenv("DEBUG", "false").lower() == "true":
        log.warning("DEBUG is enabled: do not expose this process to a network")


def _start_telegram(bot) -> None:
    """Run the Telegram bot's polling loop on its own thread and event loop."""
    from src.telegram_bot import scrub_token

    def run():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            bot.loop = loop
            bot.run()
        except Exception as exc:
            log.error("Telegram bot stopped: %s", scrub_token(exc))

    threading.Thread(target=run, name="tron-telegram", daemon=True).start()


def create_app(start_services: bool = True):
    """Build (once per process) and return the configured Flask app."""
    global _app
    with _started:
        if _app is not None:
            return _app
        logging_setup.configure()

        from config.settings import Config
        from src import api
        from src.ai_analyzer import FalsePositiveClassifier, VertexAIAnalyzer
        from src.database import Database
        from src.event_processor import EscalationEngine, EventProcessor
        from src.incident_store import IncidentStore
        from src.rules_engine import RulesEngine
        from src.telegram_bot import DLPTelegramBot

        database = Database()
        incident_store = IncidentStore(db=database)
        rules_engine = RulesEngine()
        rules_engine.db = database
        event_processor = EventProcessor(rules_engine, incident_store)
        escalation_engine = EscalationEngine()
        ai_analyzer = VertexAIAnalyzer()
        fp_classifier = FalsePositiveClassifier(ai_analyzer)
        telegram_bot = DLPTelegramBot(incident_store)
        telegram_bot.escalation_engine = escalation_engine
        event_processor.escalation_engine = escalation_engine
        event_processor.telegram_bot = telegram_bot
        event_processor.ai_analyzer = ai_analyzer

        api.init_components(incident_store, rules_engine, event_processor, escalation_engine,
                            ai_analyzer, fp_classifier, telegram_bot, database)

        stats = database.stats() or {}
        log.info("Tron DLP %s ready: %s incidents (%s open), %s events, encryption at rest %s",
                 api.APP_VERSION, stats.get("total_incidents", 0), stats.get("open", 0),
                 stats.get("total_events", 0), "on" if database.cipher.enabled else "OFF")
        log.info("integrations: telegram=%s llm_triage=%s slack=%s jira=%s",
                 "on" if Config.TELEGRAM_BOT_TOKEN else "off",
                 "on" if ai_analyzer.api_key else "off",
                 "on" if Config.SLACK_WEBHOOK_URL else "off",
                 "on" if Config.JIRA_SERVER else "off")
        _config_warnings()

        if start_services:
            api.start_background_workers()
            if Config.TELEGRAM_BOT_TOKEN:
                _start_telegram(telegram_bot)
        _app = api.app
        return _app
