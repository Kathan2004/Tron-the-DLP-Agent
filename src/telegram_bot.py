"""
TRON THE DLP AGENT — Telegram Bot
Real-time incident alerts and management through Telegram.
"""

# pyright: reportOptionalMemberAccess=false, reportOptionalSubscript=false

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
from config.settings import Config
from src.incident_store import IncidentStore
import asyncio
import re
import traceback
from typing import Any


def scrub_token(text: object) -> str:
    """Remove the bot token from error text before it is printed (API errors can embed it)."""
    out = str(text)
    token = Config.TELEGRAM_BOT_TOKEN or ""
    if token:
        out = out.replace(token, "<redacted-bot-token>")
    return out


class DLPTelegramBot:
    """Telegram bot for DLP incident alerts and commands"""

    def __init__(self, incident_store: IncidentStore):
        self.incident_store = incident_store
        self.bot_token = Config.TELEGRAM_BOT_TOKEN or ""
        self.chat_id = Config.SECURITY_CHAT_ID
        self.app: Any = None
        self.loop: Any = None
        self._escalation_engine = None  # Set from main.py

    @property
    def escalation_engine(self):
        return self._escalation_engine

    @escalation_engine.setter
    def escalation_engine(self, engine):
        self._escalation_engine = engine

    @staticmethod
    def escape_md(text: str) -> str:
        """Escape Markdown V1 special chars for Telegram."""
        if not text:
            return ""
        text = str(text)
        for ch in ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']:
            text = text.replace(ch, '\\' + ch)
        return text

    # ==================== COMMANDS ====================

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /start command"""
        await update.message.reply_text(
            "🛡️ *TRON THE DLP AGENT Bot v2.0*\n"
            "Real-Time Data Loss Prevention\n\n"
            "Commands:\n"
            "/status — System dashboard\n"
            "/incidents — Open incidents with actions\n"
            "/summary — 24h summary\n"
            "/scan <text> — Scan text for sensitive data\n"
            "/close <id> — Close incident\n"
            "/escalate <id> — Escalate to Slack\n"
            "/getchatid — Get your chat ID\n"
            "/help — Full help",
            
        )

    async def status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /status command"""
        stats = self.incident_store.stats()

        msg = (
            "📊 *TRON THE DLP AGENT — Dashboard*\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔴 Open Incidents: {stats.get('open', 0)}\n"
            f"🚨 Escalated: {stats.get('escalated', 0)}\n"
            f"✅ Closed: {stats.get('closed', stats.get('auto_closed', 0))}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📡 Total Events: {stats.get('total_events', 0)}\n"
            f"🔍 Total Scans: {stats.get('total_scans', 0)}\n"
            f"📈 Avg Risk: {stats.get('avg_risk', 0)}/100\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📅 Events (24h): {stats.get('events_24h', 0)}\n"
            f"📅 Scans (24h): {stats.get('scans_24h', 0)}"
        )

        await update.message.reply_text(msg)

    async def summary(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /summary command"""
        incidents = self.incident_store.get_all_incidents()

        if not incidents:
            await update.message.reply_text("✅ No incidents recorded. All clear!")
            return

        msg = f"📋 *Incident Summary* — {len(incidents)} total\n\n"

        for inc in incidents[:5]:
            if inc.verdict == "LIKELY_THREAT":
                emoji = "🔴"
            elif inc.verdict == "LIKELY_FP":
                emoji = "🟢"
            else:
                emoji = "🟡"

            msg += (
                f"{emoji} `{inc.incident_id}`\n"
                f"   User: {inc.user}\n"
                f"   Pattern: {inc.pattern}\n"
                f"   Risk: {inc.risk}/100 | Status: {inc.status}\n\n"
            )

        if len(incidents) > 5:
            msg += f"... and {len(incidents) - 5} more"

        await update.message.reply_text(msg)

    async def incidents(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /incidents command — list open incidents with inline buttons"""
        open_incidents = self.incident_store.get_all_incidents(status="OPEN")

        if not open_incidents:
            await update.message.reply_text("✅ No open incidents.")
            return

        msg = f"🔴 *{len(open_incidents)} Open Incidents*\n\n"

        for inc in open_incidents[:10]:
            msg += (
                f"📋 `{inc.incident_id}`\n"
                f"   👤 {inc.user}\n"
                f"   🖥️ {inc.host} | 📡 {inc.channel}\n"
                f"   🎯 {inc.pattern}\n"
                f"   📊 Risk: {inc.risk}% | FP: {inc.fp}%\n\n"
            )

        # Action buttons for each incident
        keyboard = []
        for inc in open_incidents[:3]:
            iid = inc.incident_id
            keyboard.append([
                InlineKeyboardButton(f"✅ Close {iid}", callback_data=f"close_{iid}"),
                InlineKeyboardButton(f"🚨 Escalate {iid}", callback_data=f"escalate_{iid}")
            ])
            keyboard.append([
                InlineKeyboardButton(f"🤖 Analyze {iid}", callback_data=f"analyze_{iid}"),
                InlineKeyboardButton(f"📋 Details {iid}", callback_data=f"details_{iid}")
            ])

        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(msg, reply_markup=reply_markup)

    async def close_incident_cmd(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /close <id> command"""
        if not context.args:
            await update.message.reply_text("Usage: /close <incident_id>")
            return

        incident_id = context.args[0]
        incident = self.incident_store.close_incident(incident_id)

        if incident:
            await update.message.reply_text(
                f"✅ *Closed* `{incident_id}`\n"
                f"Status: {incident.status}",
                
            )
        else:
            await update.message.reply_text(f"❌ Incident `{incident_id}` not found")

    async def escalate_incident_cmd(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /escalate <id> command"""
        if not context.args:
            await update.message.reply_text("Usage: /escalate <incident_id>")
            return

        incident_id = context.args[0]
        incident = self.incident_store.escalate_incident(incident_id)

        if incident:
            # Escalate to Slack
            slack_sent = False
            if self._escalation_engine:
                slack_sent = self._escalation_engine.escalate_to_slack(incident.to_dict())

            await update.message.reply_text(
                f"🚨 *Escalated* `{incident_id}`\n"
                f"Status: {incident.status}\n"
                f"Slack: {'✅ Sent' if slack_sent else '⚠️ Not sent'}",
                
            )
        else:
            await update.message.reply_text(f"❌ Incident `{incident_id}` not found")

    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /scan <text> — scan text for sensitive data"""
        if not context.args:
            await update.message.reply_text("Usage: /scan <text to check>")
            return

        text = " ".join(context.args)

        try:
            from src.file_scanner import FileContentScanner
            scanner = FileContentScanner()
            findings = scanner.scan_text(text, "telegram_scan")

            if not findings:
                await update.message.reply_text("✅ No sensitive data found.")
                return

            msg = f"🚨 *{len(findings)} patterns detected*\n\n"
            for f in findings[:10]:
                msg += f"  [{f.severity.upper()}] {f.pattern_name}: `{f.matched_text}`\n"

            await update.message.reply_text(msg)

        except Exception as e:
            await update.message.reply_text(f"⚠️ Scan error: {e}")

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /help command"""
        await update.message.reply_text(
            "🛡️ *TRON THE DLP AGENT Bot v2.0*\n\n"
            "*Commands:*\n"
            "/start — Welcome\n"
            "/status — Dashboard stats\n"
            "/summary — Incident summary\n"
            "/incidents — Open incidents with actions\n"
            "/scan <text> — Scan text for sensitive data\n"
            "/close <id> — Close as false positive\n"
            "/escalate <id> — Escalate to Slack\n"
            "/getchatid — Get chat ID for setup\n"
            "/help — This message\n\n"
            "*Inline Buttons:*\n"
            "✅ Close — Close incident as FP\n"
            "🚨 Escalate — Send to Slack\n"
            "🤖 Analyze — Run AI analysis\n"
            "📋 Details — View full details",
            
        )

    async def get_chat_id(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /getchatid command"""
        chat_id = update.effective_chat.id
        await update.message.reply_text(
            f"📱 *Your Chat ID:*\n\n`{chat_id}`\n\n"
            f"Add to .env:\n`SECURITY_CHAT_ID={chat_id}`",
            
        )

    # ==================== INLINE BUTTON HANDLER ====================

    async def button_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle ALL inline keyboard button presses"""
        query = update.callback_query

        try:
            # Always answer the callback first to stop the loading spinner
            await query.answer()

            data = query.data
            # Split on first underscore: "close_INC-XXXX" -> ["close", "INC-XXXX"]
            parts = data.split("_", 1)

            if len(parts) != 2:
                await query.edit_message_text(text=f"⚠️ Invalid action: {data}")
                return

            action, incident_id = parts

            if action == "close":
                incident = self.incident_store.close_incident(incident_id)
                if incident:
                    await query.edit_message_text(
                        text=(
                            f"✅ Incident Closed\n\n"
                            f"ID: {incident_id}\n"
                            f"Status: {incident.status}\n"
                            f"User: {incident.user}\n"
                            f"Pattern: {incident.pattern}"
                        )
                    )
                else:
                    await query.edit_message_text(text=f"❌ Incident `{incident_id}` not found")

            elif action == "escalate":
                incident = self.incident_store.escalate_incident(incident_id)
                if incident:
                    # Actually send to Slack
                    slack_sent = False
                    jira_ticket = None
                    if self._escalation_engine:
                        slack_sent = self._escalation_engine.escalate_to_slack(incident.to_dict())
                        jira_ticket = self._escalation_engine.escalate_to_jira(incident.to_dict())

                    await query.edit_message_text(
                        text=(
                            f"🚨 Incident Escalated\n\n"
                            f"ID: {incident_id}\n"
                            f"Status: {incident.status}\n"
                            f"User: {incident.user}\n"
                            f"Risk: {incident.risk}/100\n"
                            f"━━━━━━━━━━━━━━━━━━━━━━\n"
                            f"Slack: {'✅ Sent' if slack_sent else '⚠️ Failed'}\n"
                            f"Jira: {jira_ticket if jira_ticket else '⚠️ N/A'}"
                        )
                    )
                else:
                    await query.edit_message_text(text=f"❌ Incident `{incident_id}` not found")

            elif action == "analyze":
                # Trigger AI analysis
                await query.edit_message_text(
                    text=f"🤖 Analyzing `{incident_id}`... Please wait.",
                    
                )

                try:
                    import requests
                    session = requests.Session()
                    session.trust_env = False
                    session.proxies = {}

                    resp = session.post(
                        f"http://localhost:5001/api/incidents/{incident_id}/analyze",
                        timeout=30
                    )

                    if resp.status_code == 200:
                        result = resp.json()
                        verdict = result.get("verdict", "UNKNOWN")

                        if verdict == "LIKELY_THREAT":
                            emoji = "🔴"
                        elif verdict == "LIKELY_FP":
                            emoji = "🟢"
                        else:
                            emoji = "🟡"

                        reasoning = result.get("reasoning", "N/A")
                        if len(reasoning) > 300:
                            reasoning = reasoning[:300] + "..."

                        await query.edit_message_text(
                            text=(
                                f"{emoji} AI Analysis Complete\n\n"
                                f"ID: {incident_id}\n"
                                f"Verdict: {verdict}\n"
                                f"Risk: {result.get('risk_score', 'N/A')}/100\n"
                                f"FP Probability: {result.get('false_positive_probability', 'N/A')}%\n"
                                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                                f"Reasoning: {reasoning}"
                            )
                        )
                    else:
                        await query.edit_message_text(
                            text=f"⚠️ Analysis failed (HTTP {resp.status_code})"
                        )
                except Exception as e:
                    await query.edit_message_text(text=f"⚠️ Analysis error: {str(e)[:100]}")

            elif action == "details":
                incident = self.incident_store.get_incident(incident_id)
                if incident:
                    # Build detailed view
                    ai = incident.ai_analysis
                    ai_section = ""
                    if ai and isinstance(ai, dict):
                        ai_section = (
                            f"\n🤖 *AI Analysis:*\n"
                            f"  Verdict: {ai.get('verdict', 'N/A')}\n"
                            f"  Risk: {ai.get('risk_score', 'N/A')}/100\n"
                            f"  FP: {ai.get('false_positive_probability', 'N/A')}%\n"
                            f"  Reasoning: {str(ai.get('reasoning', 'N/A'))[:200]}"
                        )

                    events_str = ", ".join(incident.events[:5]) if incident.events else "None"

                    await query.edit_message_text(
                        text=(
                            f"📋 Incident Details\n\n"
                            f"ID: {incident_id}\n"
                            f"Status: {incident.status}\n"
                            f"Created: {incident.created_at}\n"
                            f"━━━━━━━━━━━━━━━━━━━━━━\n"
                            f"👤 User: {incident.user}\n"
                            f"🖥️ Host: {incident.host}\n"
                            f"📡 Channel: {incident.channel}\n"
                            f"🎯 Pattern: {incident.pattern}\n"
                            f"📊 Risk: {incident.risk}/100\n"
                            f"🔄 Alerts: {incident.alert_count}\n"
                            f"🔁 Repeats: {incident.repeat_count}\n"
                            f"━━━━━━━━━━━━━━━━━━━━━━\n"
                            f"Events: {events_str}\n"
                            f"{ai_section.replace('*', '')}"
                        )
                    )
                else:
                    await query.edit_message_text(text=f"❌ Incident `{incident_id}` not found")

            elif action == "monitor":
                # "Keep Open" button — just acknowledge
                await query.edit_message_text(
                    text=f"👁️ Monitoring `{incident_id}` — no action taken.\nUse /incidents to see current status.",
                    
                )

            elif action == "ticket":
                # Raise Jira ticket
                incident = self.incident_store.get_incident(incident_id)
                if incident and self._escalation_engine:
                    jira_ticket = self._escalation_engine.escalate_to_jira(incident.to_dict())
                    await query.edit_message_text(
                        text=(
                            f"🎫 Ticket Raised\n\n"
                            f"ID: {incident_id}\n"
                            f"Jira: {jira_ticket if jira_ticket else '⚠️ Jira not configured'}"
                        )
                    )
                else:
                    await query.edit_message_text(text=f"⚠️ Could not raise ticket for `{incident_id}`")

            else:
                await query.edit_message_text(text=f"⚠️ Unknown action: {action}")

        except Exception as e:
            print(f"⚠️ Button handler error: {scrub_token(e)}")
            traceback.print_exc()
            try:
                await query.edit_message_text(text=f"⚠️ Error: {str(e)[:100]}")
            except Exception:
                pass

    # ==================== ALERT SENDING ====================

    async def send_alert(self, incident_id: str, summary: str, verdictcolor: str = "🔴") -> None:
        """Send incident alert to security chat with action buttons"""
        if not self.chat_id or not self.app:
            print(f"⚠️ Cannot send alert: chat_id={self.chat_id}, app={bool(self.app)}")
            return

        incident = self.incident_store.get_incident(incident_id)
        if not incident:
            return

        # Build alert message (use plain text to avoid escaping issues)
        message = (
            f"{verdictcolor} DLP INCIDENT ALERT\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📋 ID: {incident_id}\n"
            f"👤 User: {incident.user}\n"
            f"🖥️ Host: {incident.host}\n"
            f"📡 Channel: {incident.channel}\n"
            f"⏰ Alerts: {incident.alert_count}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🤖 Verdict: {incident.verdict}\n"
            f"📊 Risk: {incident.risk}/100 | FP: {incident.fp}%\n"
            f"🎯 Pattern: {incident.pattern}\n"
        )

        # AI reasoning if available
        if incident.ai_analysis and isinstance(incident.ai_analysis, dict):
            reasoning = incident.ai_analysis.get("reasoning", "")
            if reasoning:
                short = reasoning[:150] + "..." if len(reasoning) > 150 else reasoning
                message += f"━━━━━━━━━━━━━━━━━━━━━━\n💡 {short}\n"

        # Action buttons
        keyboard = [
            [
                InlineKeyboardButton("✅ Close — FP", callback_data=f"close_{incident_id}"),
                InlineKeyboardButton("👁️ Monitor", callback_data=f"monitor_{incident_id}")
            ],
            [
                InlineKeyboardButton("🚨 Escalate", callback_data=f"escalate_{incident_id}"),
                InlineKeyboardButton("🤖 Analyze", callback_data=f"analyze_{incident_id}")
            ],
            [
                InlineKeyboardButton("📋 Details", callback_data=f"details_{incident_id}"),
                InlineKeyboardButton("🎫 Raise Ticket", callback_data=f"ticket_{incident_id}")
            ]
        ]

        reply_markup = InlineKeyboardMarkup(keyboard)

        try:
            await self.app.bot.send_message(
                chat_id=self.chat_id,
                text=message,
                reply_markup=reply_markup,
                
            )
            print(f"📱 Telegram alert sent: {incident_id}")
        except Exception as e:
            print(f"⚠️ Telegram send failed: {scrub_token(e)}")
            # Try again without markdown if formatting failed
            try:
                plain_msg = message.replace("*", "").replace("`", "")
                await self.app.bot.send_message(
                    chat_id=self.chat_id,
                    text=plain_msg,
                    reply_markup=reply_markup,
                )
                print(f"📱 Telegram alert sent (plain): {incident_id}")
            except Exception as e2:
                print(f"⚠️ Telegram send failed (plain): {scrub_token(e2)}")

    # ==================== INITIALIZATION ====================

    async def error_handler(self, update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Log Errors caused by Updates quietly to avoid huge tracebacks in console"""
        import traceback
        
        # Format the error message
        error_msg = scrub_token(context.error)
        
        if "terminated by other getUpdates request" in error_msg:
            print("  ⚠️ Telegram Warning: Another instance is using this bot token.")
            print("     (Alerts will be sent via API, but receiving commands might flap)")
        elif "timed out" in error_msg.lower():
            pass  # Ignore common timeouts
        else:
            print(f"  ⚠️ Telegram Error: {error_msg}")

    def setup_handlers(self):
        """Register command and callback handlers"""
        self.app.add_handler(CommandHandler("start", self.start))
        self.app.add_handler(CommandHandler("status", self.status))
        self.app.add_handler(CommandHandler("summary", self.summary))
        self.app.add_handler(CommandHandler("incidents", self.incidents))
        self.app.add_handler(CommandHandler("close", self.close_incident_cmd))
        self.app.add_handler(CommandHandler("escalate", self.escalate_incident_cmd))
        self.app.add_handler(CommandHandler("scan", self.scan_command))
        self.app.add_handler(CommandHandler("getchatid", self.get_chat_id))
        self.app.add_handler(CommandHandler("help", self.help_command))
        self.app.add_handler(CallbackQueryHandler(self.button_handler))
        
        # Add error handler
        self.app.add_error_handler(self.error_handler)

    async def initialize(self):
        """Initialize the bot application for sending messages async via other scripts"""
        if not self.app:
            self.app = Application.builder().token(self.bot_token).build()
        await self.app.initialize()
        self.setup_handlers()

    def run(self):
        if not self.app:
            self.app = Application.builder().token(self.bot_token).build()
            self.setup_handlers()

        print("  ✅ Telegram bot polling started")
        self.app.run_polling(drop_pending_updates=True, stop_signals=None)
