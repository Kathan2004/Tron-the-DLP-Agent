"""
Persistent Incident Store — TRON THE DLP AGENT
Wraps the SQLite database with the same interface used by the rest of the system.
Drop-in replacement for the original in-memory IncidentStore.
"""

import json
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from src.database import Database


class IncidentStatus(Enum):
    OPEN = "OPEN"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"
    TICKET_RAISED = "TICKET_RAISED"


class Verdict(Enum):
    LIKELY_THREAT = "LIKELY_THREAT"
    LIKELY_FP = "LIKELY_FP"
    NEEDS_REVIEW = "NEEDS_REVIEW"


@dataclass
class Event:
    event_id: str
    timestamp: str
    agent_type: str
    source_host: str
    user: str
    channel: str
    payload_hash: str
    payload_sample: str
    matched_rules: List[str]
    severity: str
    geo: Dict

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> 'Event':
        return cls(
            event_id=d.get('event_id', ''),
            timestamp=d.get('timestamp', ''),
            agent_type=d.get('agent_type', ''),
            source_host=d.get('source_host', ''),
            user=d.get('user', ''),
            channel=d.get('channel', ''),
            payload_hash=d.get('payload_hash', ''),
            payload_sample=d.get('payload_sample', ''),
            matched_rules=d.get('matched_rules', []),
            severity=d.get('severity', 'low'),
            geo=d.get('geo', {}),
        )


class Incident:
    """Incident object that wraps a dict from the database."""

    def __init__(self, data: Dict):
        self._data = data

    @property
    def incident_id(self) -> str:
        return self._data.get('incident_id', '')

    @property
    def user(self) -> str:
        return self._data.get('user', '')

    @property
    def host(self) -> str:
        return self._data.get('host', '')

    @property
    def channel(self) -> str:
        return self._data.get('channel', '')

    @property
    def pattern(self) -> str:
        return self._data.get('pattern', '')

    @property
    def risk(self) -> int:
        return self._data.get('risk', 50)

    @risk.setter
    def risk(self, value: int):
        self._data['risk'] = value

    @property
    def verdict(self) -> str:
        return self._data.get('verdict', 'NEEDS_REVIEW')

    @verdict.setter
    def verdict(self, value: str):
        self._data['verdict'] = value

    @property
    def fp(self) -> int:
        return self._data.get('fp', 50)

    @fp.setter
    def fp(self, value: int):
        self._data['fp'] = value

    @property
    def status(self) -> str:
        return self._data.get('status', 'OPEN')

    @status.setter
    def status(self, value: str):
        self._data['status'] = value

    @property
    def created_at(self) -> str:
        return self._data.get('created_at', '')

    @property
    def alert_count(self) -> int:
        return self._data.get('alert_count', 0)

    @alert_count.setter
    def alert_count(self, value: int):
        self._data['alert_count'] = value

    @property
    def events(self) -> List[str]:
        return self._data.get('events', [])

    @events.setter
    def events(self, value: List[str]):
        self._data['events'] = value

    @property
    def ai_analysis(self) -> Optional[Dict]:
        return self._data.get('ai_analysis')

    @ai_analysis.setter
    def ai_analysis(self, value: Optional[Dict]):
        self._data['ai_analysis'] = value

    @property
    def repeat_count(self) -> int:
        return self._data.get('repeat_count', 0)

    @repeat_count.setter
    def repeat_count(self, value: int):
        self._data['repeat_count'] = value

    @property
    def auto_escalated(self) -> bool:
        return bool(self._data.get('auto_escalated', False))

    @auto_escalated.setter
    def auto_escalated(self, value: bool):
        self._data['auto_escalated'] = value

    def to_dict(self) -> Dict:
        return dict(self._data)


class IncidentStore:
    """Persistent incident store backed by SQLite.
    
    Drop-in replacement for the old in-memory IncidentStore.
    All data survives restarts. Full audit trail.
    """

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        # Keep legacy in-memory caches for hot path compatibility
        self.incidents: Dict[str, Incident] = {}
        self.events: Dict[str, Event] = {}
        self.alert_buffer: Dict[str, List[Event]] = {}
        # Load existing data from DB
        self._load_cache()

    def _load_cache(self):
        """Load recent data into memory cache."""
        # Load recent incidents
        for inc_dict in self.db.get_all_incidents(limit=1000):
            inc = Incident(inc_dict)
            self.incidents[inc.incident_id] = inc

        # Load recent events
        for evt_dict in self.db.get_all_events(limit=500):
            evt = Event.from_dict(evt_dict)
            self.events[evt.event_id] = evt
            # Rebuild alert buffer
            if evt.user not in self.alert_buffer:
                self.alert_buffer[evt.user] = []
            self.alert_buffer[evt.user].append(evt)

        if self.incidents:
            print(f"  📂 Loaded {len(self.incidents)} incidents from database")
        if self.events:
            print(f"  📂 Loaded {len(self.events)} events from database")

    def add_event(self, event: Event) -> None:
        """Store event in database and memory."""
        # Persist to DB
        self.db.add_event(
            event_id=event.event_id,
            timestamp=event.timestamp,
            agent_type=event.agent_type,
            source_host=event.source_host,
            user=event.user,
            channel=event.channel,
            payload_hash=event.payload_hash,
            payload_sample=event.payload_sample,
            matched_rules=event.matched_rules,
            severity=event.severity,
            geo=event.geo
        )

        # In-memory cache
        self.events[event.event_id] = event

        if event.user not in self.alert_buffer:
            self.alert_buffer[event.user] = []
        self.alert_buffer[event.user].append(event)

    def get_recent_events(self, user: str, minutes: int = 30) -> List[Event]:
        """Get user's events in last N minutes from DB."""
        events_dicts = self.db.get_recent_events(user, minutes)
        return [Event.from_dict(d) for d in events_dicts]

    def create_incident(
        self,
        user: str,
        host: str,
        channel: str,
        pattern: str,
        risk: int,
        events: List[Event],
        dedup_key: Optional[str] = None,
    ) -> Incident:
        """Create new incident in database."""
        event_ids = [e.event_id for e in events]

        inc_dict = self.db.create_incident(
            user=user,
            host=host,
            channel=channel,
            pattern=pattern,
            risk=risk,
            events=event_ids,
            dedup_key=dedup_key,
        )

        if not inc_dict or not isinstance(inc_dict, dict):
            raise RuntimeError("Failed to create incident")

        incident = Incident(inc_dict)
        self.incidents[incident.incident_id] = incident
        return incident

    def update_incident(
        self,
        incident_id: str,
        verdict: Optional[str] = None,
        fp_probability: Optional[int] = None,
        risk_score: Optional[int] = None,
        ai_analysis: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Optional[Incident]:
        """Update incident with AI analysis results."""
        update_fields = {}
        if verdict is not None:
            update_fields['verdict'] = verdict
        if fp_probability is not None:
            update_fields['fp'] = fp_probability
        if risk_score is not None:
            update_fields['risk'] = risk_score
        if ai_analysis is not None:
            update_fields['ai_analysis'] = ai_analysis
        update_fields.update(kwargs)

        if not update_fields:
            return self.get_incident(incident_id)

        updated = self.db.update_incident(incident_id, **update_fields)
        if updated:
            incident = Incident(updated)
            self.incidents[incident_id] = incident

            # Auto-close logic
            fp = updated.get('fp', 0)
            risk = updated.get('risk', 100)
            if fp > 85 and risk < 50:
                self.db.update_incident(incident_id, status="CLOSED")
                incident.status = "CLOSED"

            return incident
        return None

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Fetch incident by ID."""
        # Check cache first
        if incident_id in self.incidents:
            return self.incidents[incident_id]

        # Fall back to DB
        inc_dict = self.db.get_incident(incident_id)
        if inc_dict:
            incident = Incident(inc_dict)
            self.incidents[incident_id] = incident
            return incident
        return None

    def get_all_incidents(self, status: Optional[str] = None) -> List[Incident]:
        """Fetch all incidents from DB."""
        if status is None:
            inc_dicts = self.db.get_all_incidents()
        else:
            inc_dicts = self.db.get_all_incidents(status=status)
        incidents = [Incident(d) for d in inc_dicts]

        # Update cache
        for inc in incidents:
            self.incidents[inc.incident_id] = inc

        return incidents

    def close_incident(self, incident_id: str, reason: str = "user_closed") -> Optional[Incident]:
        """Close incident in DB."""
        updated = self.db.close_incident(incident_id, reason)
        if updated:
            incident = Incident(updated)
            self.incidents[incident_id] = incident
            return incident
        return None

    def escalate_incident(self, incident_id: str) -> Optional[Incident]:
        """Escalate incident in DB."""
        updated = self.db.escalate_incident(incident_id)
        if updated:
            incident = Incident(updated)
            self.incidents[incident_id] = incident
            return incident
        return None

    def raise_ticket(self, incident_id: str, actor: str = "secops_analyst") -> Optional[Incident]:
        """Raise ticket for incident in DB."""
        updated = self.db.raise_ticket(incident_id, actor=actor)
        if updated:
            incident = Incident(updated)
            self.incidents[incident_id] = incident
            return incident
        return None

    def reopen_incident(self, incident_id: str, actor: str = "secops_analyst") -> Optional[Incident]:
        """Reopen incident in DB."""
        updated = self.db.reopen_incident(incident_id, actor=actor)
        if updated:
            incident = Incident(updated)
            self.incidents[incident_id] = incident
            return incident
        return None

    def create_manual_incident(self,
                               user: str,
                               host: str,
                               channel: str,
                               pattern: str,
                               risk: int = 50) -> Optional[Incident]:
        """Create incident without linked events (analyst-created)."""
        inc_dict = self.db.create_incident(
            user=user,
            host=host,
            channel=channel,
            pattern=pattern,
            risk=risk,
            events=[]
        )
        if not inc_dict or not isinstance(inc_dict, dict):
            return None
        incident = Incident(inc_dict)
        self.incidents[incident.incident_id] = incident
        return incident

    def delete_incident(self, incident_id: str) -> bool:
        """Delete a single incident."""
        ok = self.db.delete_incident(incident_id)
        if ok and incident_id in self.incidents:
            del self.incidents[incident_id]
        return ok

    def delete_incidents(self, incident_ids: List[str]) -> int:
        """Delete multiple incidents."""
        count = self.db.delete_incidents(incident_ids)
        for incident_id in incident_ids or []:
            self.incidents.pop(str(incident_id), None)
        return count

    def stats(self) -> Dict:
        """Get dashboard statistics from DB."""
        return self.db.stats() or {}
