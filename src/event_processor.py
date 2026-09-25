import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Optional, Any
from src.rules_engine import RulesEngine
from src.incident_store import IncidentStore, Event
from src.telegram_bot import scrub_token

class EventProcessor:
    """Process incoming DLP events and trigger incident creation"""
    
    def __init__(self, rules_engine: RulesEngine, incident_store: IncidentStore):
        self.rules_engine = rules_engine
        self.incident_store = incident_store
        self.escalation_engine: Optional[Any] = None  # Will be set from main.py
        self.telegram_bot: Optional[Any] = None  # Will be set from main.py
        self.ai_analyzer: Optional[Any] = None  # Will be set from main.py
    
    def process_event(
        self,
        agent_type: str,
        source_host: str,
        user: str,
        channel: str,
        payload: str,
        geo: Optional[dict] = None
    ) -> Optional[str]:
        """Process incoming event and return event_id"""
        
        # Calculate payload hash
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()
        
        # Detect patterns
        detections = self.rules_engine.detect_patterns(payload)
        
        if not detections:
            return None  # No matches, ignore
        
        # Get matched rule names
        matched_rules = [d.rule_name for d in detections]
        
        # Evaluate severity
        severity, risk_score = self.rules_engine.evaluate_severity(detections)
        
        # Create event
        event = Event(
            event_id=f"EVT-{hashlib.md5(payload_hash.encode()).hexdigest()[:8].upper()}",
            timestamp=datetime.now().isoformat(),
            agent_type=agent_type,
            source_host=source_host,
            user=user,
            channel=channel,
            payload_hash=payload_hash,
            payload_sample=payload[:500],
            matched_rules=matched_rules,
            severity=severity,
            geo=geo or {}
        )
        
        # Store event
        self.incident_store.add_event(event)
        
        # Check against rule thresholds
        should_escalate = False
        trigger_reasons = []
        active_rules = self.rules_engine.get_all_rules()
        
        # Max window we'll need to look back
        max_window = max([r.get('window', 60) for r in active_rules.values()] + [60])
        recent_events = self.incident_store.get_recent_events(user, minutes=max_window)
        
        for rule_name in matched_rules:
            rule_config = active_rules.get(rule_name, {})
            threshold = rule_config.get('threshold', 1)
            window = rule_config.get('window', 60)
            cutoff = datetime.now() - timedelta(minutes=window)

            def in_rule_window(evt: Event) -> bool:
                ts_raw = str(getattr(evt, 'timestamp', '') or '').strip()
                if not ts_raw:
                    return False
                try:
                    ts = datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
                except Exception:
                    return False
                # Normalize timezone-aware timestamps to naive local comparison baseline.
                if ts.tzinfo is not None:
                    ts = ts.astimezone().replace(tzinfo=None)
                return ts >= cutoff
            
            # Count occurrences of this specific rule in the window
            # (including the event we just added, which is now in recent_events but 
            # might not be returned immediately if get_recent_events hits cache/replica latency,
            # though locally SQLite is instant. We'll count manually to be safe.)
            
            trigger_events = [e for e in recent_events 
                              if hasattr(e, 'matched_rules') and rule_name in e.matched_rules and in_rule_window(e)]
            
            # If the current event is not in trigger_events, add it implicitly for counting
            # (Actually since we just inserted it, it should be there, but let's just count safely)
            count = len(trigger_events)
            
            if count >= threshold:
                should_escalate = True
                trigger_reasons.append(f"{rule_name} ({count}/{threshold})")
        
        if should_escalate:
            print(f"Threshold met for {user}: {', '.join(trigger_reasons)}")
            incident = self._create_or_update_incident(user, source_host, recent_events)
            
            # Check if this is a REPEAT attempt (auto-escalate on repeats)
            self._check_and_escalate_repeats(incident)
        
        return event.event_id
    
    def _create_or_update_incident(self, user: str, host: str, events: List[Event]):
        """Create incident or update existing one (for repeats)"""
        
        # Check if incident already exists for this user/host (within 60 minutes to avoid duplicates)
        existing_incident = None
        for incident in self.incident_store.incidents.values():
            if incident.user == user and incident.host == host and incident.status == "OPEN":
                created_time = datetime.fromisoformat(incident.created_at)
                if datetime.now() - created_time < timedelta(minutes=60):
                    existing_incident = incident
                    break
        
        if existing_incident:
            # This is a REPEAT attempt - update existing incident
            existing_incident.alert_count += len(events)
            existing_incident.repeat_count += 1
            existing_incident.risk = min(100, existing_incident.risk + 15)  # Increase risk for each repeat
            existing_incident.events.extend([e.event_id for e in events])
            
            # Save to Database
            self.incident_store.update_incident(
                existing_incident.incident_id,
                alert_count=existing_incident.alert_count,
                repeat_count=existing_incident.repeat_count,
                risk=existing_incident.risk,
                events=existing_incident.events
            )
            
            print(f"⚠️ REPEAT EXFILTRATION: User {user} attempted {existing_incident.repeat_count + 1}x in 24h")
            return existing_incident
        else:
            # New incident
            channels = set(e.channel for e in events)
            channel_str = " → ".join(list(channels)[:2])
            
            all_rules = set()
            for e in events:
                all_rules.update(e.matched_rules)
            pattern_str = ", ".join(list(all_rules)[:2])
            
            avg_risk = int(sum(80 if e.severity == "critical" else 60 if e.severity == "high" else 40 for e in events) / len(events))
            dedup_key = f"stream:{str(user).strip().lower()}|{str(host).strip().lower()}|{str(pattern_str).strip().lower()}"
            
            incident = self.incident_store.create_incident(
                user=user,
                host=host,
                channel=channel_str,
                pattern=pattern_str,
                risk=avg_risk,
                events=events,
                dedup_key=dedup_key,
            )
            
            print(f"🚨 NEW INCIDENT: {incident.incident_id} - User {user} attempted to exfiltrate {pattern_str}")
            
            # Send initial Telegram alert
            self._send_telegram_alert(incident, f"NEW EXFILTRATION: {incident.user}")
            
            return incident
    
    def _send_telegram_alert(self, incident, summary_text: str):
        """Helper to send telegram alert thread-safely."""
        if self.telegram_bot and getattr(self.telegram_bot, 'loop', None):
            try:
                import asyncio
                loop = self.telegram_bot.loop
                if loop and loop.is_running():
                    # Safely schedule the coro on the bot's own dedicated Event Loop
                    asyncio.run_coroutine_threadsafe(
                        self.telegram_bot.send_alert(
                            incident_id=incident.incident_id,
                            summary=summary_text,
                            verdictcolor="🔴"
                        ),
                        loop
                    )
                    print(f"📱 TELEGRAM ALERT QUEUED: {incident.incident_id}")
                else:
                    print(f"⚠️ Telegram loop not running, could not send to {incident.incident_id}")
            except Exception as e:
                print(f"⚠️ Telegram alert failed: {scrub_token(e)}")
                
    def _check_and_escalate_repeats(self, incident):
        """Auto-escalate repeated exfiltration attempts"""
        
        if incident.repeat_count >= 1:
            # Send Telegram alert on EVERY repeat
            self._send_telegram_alert(incident, f"REPEAT EXFILTRATION: {incident.user}")
            
            # Auto-escalate to Slack on first repeat
            if not incident.auto_escalated:
                incident.auto_escalated = True
                incident.status = "ESCALATED"
                
                # Update in DB
                if hasattr(self.incident_store, 'db') and self.incident_store.db:
                    self.incident_store.db.update_incident(
                        incident.incident_id,
                        status="ESCALATED",
                        auto_escalated=True
                    )
                
                # Send to Slack immediately
                if self.escalation_engine:
                    self.escalation_engine.escalate_to_slack(incident.to_dict())
                    print(f"🚨 AUTO-ESCALATED TO SLACK: {incident.incident_id}")
            
            return True
        
        
        return False


class EscalationEngine:
    """Handle incident escalation to Slack and Jira"""
    
    def __init__(self):
        from config.settings import Config
        self.slack_webhook = Config.SLACK_WEBHOOK_URL
        self.jira_server = Config.JIRA_SERVER
        self.jira_user = Config.JIRA_USER
        self.jira_token = Config.JIRA_TOKEN
    
    def escalate_to_slack(self, incident_dict: dict) -> bool:
        """Post incident to Slack"""
        
        if not self.slack_webhook:
            print("Slack webhook not configured")
            return False
        
        try:
            # Get AI analysis safely
            ai_analysis = incident_dict.get('ai_analysis')
            reasoning = "N/A"
            if isinstance(ai_analysis, dict):
                reasoning = ai_analysis.get('reasoning', 'N/A')
            
            # Format for Slack
            payload = {
                "text": f"🚨 DLP Incident Escalation — {incident_dict['incident_id']}",
                "attachments": [
                    {
                        "color": "danger" if incident_dict.get('verdict') == "LIKELY_THREAT" else "warning",
                        "fields": [
                            {"title": "User", "value": str(incident_dict.get('user', 'N/A')), "short": True},
                            {"title": "Host", "value": str(incident_dict.get('host', 'N/A')), "short": True},
                            {"title": "Channel", "value": str(incident_dict.get('channel', 'N/A')), "short": True},
                            {"title": "Pattern", "value": str(incident_dict.get('pattern', 'N/A')), "short": True},
                            {"title": "Risk Score", "value": f"{incident_dict.get('risk', 0)}/100", "short": True},
                            {"title": "AI Verdict", "value": str(incident_dict.get('verdict', 'N/A')), "short": True},
                            {"title": "Evidence", "value": str(reasoning), "short": False}
                        ]
                    }
                ]
            }
            
            import requests
            response = requests.post(self.slack_webhook, json=payload, timeout=10)
            print(f"✅ Escalated to Slack: {response.status_code}")
            return response.status_code == 200
        except Exception as e:
            print(f"Slack escalation error: {e}")
            return False
            return False
    
    def escalate_to_jira(self, incident_dict: dict):
        """Create Jira ticket"""
        
        if not all([self.jira_server, self.jira_user, self.jira_token]):
            print("ℹ️ Jira credentials not configured - skipping ticket creation")
            return None
        
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            payload = {
                "fields": {
                    "project": {"key": "SEC"},
                    "issuetype": {"name": "Security Incident"},
                    "summary": f"DLP: {incident_dict.get('pattern', 'UNKNOWN')} — {incident_dict.get('user', 'UNKNOWN')}",
                    "description": f"""Incident ID: {incident_dict.get('incident_id', 'N/A')}
User: {incident_dict.get('user', 'N/A')}
Host: {incident_dict.get('host', 'N/A')}
Channel: {incident_dict.get('channel', 'N/A')}
Risk Score: {incident_dict.get('risk', 0)}/100
AI Verdict: {incident_dict.get('verdict', 'N/A')}
FP Probability: {incident_dict.get('fp', 0)}%""",
                    "priority": {"name": "High" if incident_dict.get('risk', 0) > 70 else "Medium"},
                    "labels": ["dlp", "ai-flagged"]
                }
            }
            
            url = f"{self.jira_server}/rest/api/2/issue"
            response = requests.post(
                url,
                json=payload,
                auth=HTTPBasicAuth(self.jira_user or "", self.jira_token or ""),
                timeout=10
            )
            
            if response.status_code == 201:
                ticket = response.json()
                print(f"✅ Jira ticket created: {ticket.get('key', 'N/A')}")
                return ticket.get('key')
            else:
                print(f"⚠️ Jira error: {response.status_code}")
                return None
        except Exception as e:
            print(f"Jira escalation error: {e}")
            return None
