import React, { useEffect, useMemo, useState } from 'react';

const EventRecordDetail = ({ eventId, apiBase, onBack }) => {
    const [eventData, setEventData] = useState(null);
    const [relatedIncidents, setRelatedIncidents] = useState([]);
    const [relatedEvents, setRelatedEvents] = useState([]);
    const [allEvents, setAllEvents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('details');

    useEffect(() => {
        const load = async () => {
            setLoading(true);
            try {
                const [res, incRes, evtRes] = await Promise.all([
                    fetch(`${apiBase}/events/${encodeURIComponent(eventId)}`),
                    fetch(`${apiBase}/incidents?limit=500`),
                    fetch(`${apiBase}/events?limit=500`),
                ]);
                const data = await res.json();
                const incidentsData = await incRes.json();
                const eventsData = await evtRes.json();
                const eventList = Array.isArray(eventsData.events) ? eventsData.events : [];
                setAllEvents(eventList);

                const eventObj = res.ok ? data : null;
                setEventData(eventObj);

                if (eventObj) {
                    const user = (eventObj.user || '').toLowerCase();
                    const host = (eventObj.source_host || eventObj.host || '').toLowerCase();

                    const relInc = (incidentsData.incidents || []).filter((inc) =>
                        (user && (inc.user || '').toLowerCase() === user) ||
                        (host && (inc.host || '').toLowerCase() === host)
                    ).slice(0, 8);
                    setRelatedIncidents(relInc);

                    const relEvt = eventList.filter((e) => {
                        if (!e || e.event_id === eventObj.event_id) return false;
                        return (user && (e.user || '').toLowerCase() === user) ||
                               (host && ((e.source_host || e.host || '').toLowerCase() === host));
                    }).slice(0, 10);
                    setRelatedEvents(relEvt);
                } else {
                    setRelatedIncidents([]);
                    setRelatedEvents([]);
                }
            } catch (_) {
                setEventData(null);
                setRelatedIncidents([]);
                setRelatedEvents([]);
                setAllEvents([]);
            }
            setLoading(false);
        };
        load();
    }, [eventId, apiBase]);

    const parseJson = (val) => {
        if (!val) return val;
        if (typeof val === 'object') return val;
        try { return JSON.parse(val); } catch { return val; }
    };

    const geo = useMemo(() => parseJson(eventData?.geo) || {}, [eventData]);
    const matchedRules = useMemo(() => parseJson(eventData?.matched_rules) || [], [eventData]);
    const findings = useMemo(() => parseJson(eventData?.findings) || geo.findings || [], [eventData, geo]);

    const formatTimestamp = (ts) => {
        if (!ts) return '—';
        const d = new Date(ts);
        if (Number.isNaN(d.getTime())) return String(ts);
        return d.toLocaleString();
    };

    const toMillis = (evt) => {
        if (!evt) return null;
        const candidate = evt.timestamp || evt.created_at || evt.detected_at;
        if (!candidate) return null;
        const ms = new Date(candidate).getTime();
        return Number.isFinite(ms) ? ms : null;
    };

    const currentMillis = useMemo(() => toMillis(eventData), [eventData]);

    const comparableEvents = useMemo(() => {
        if (!eventData) return [];
        const user = (eventData.user || '').toLowerCase();
        const host = (eventData.source_host || eventData.host || '').toLowerCase();

        return (allEvents || []).filter((e) => {
            if (!e || !e.event_id) return false;
            const sameUser = user && (e.user || '').toLowerCase() === user;
            const sameHost = host && ((e.source_host || e.host || '').toLowerCase() === host);
            return sameUser || sameHost;
        });
    }, [allEvents, eventData]);

    const previousComparableEvent = useMemo(() => {
        if (!eventData || !currentMillis) return null;
        let prev = null;
        let bestTs = -Infinity;

        for (const evt of comparableEvents) {
            if (!evt || evt.event_id === eventData.event_id) continue;
            const ts = toMillis(evt);
            if (!ts || ts >= currentMillis) continue;
            if (ts > bestTs) {
                bestTs = ts;
                prev = evt;
            }
        }
        return prev;
    }, [comparableEvents, currentMillis, eventData]);

    const timelineEvents = useMemo(() => {
        if (!currentMillis) return [];
        const windowMs = 30 * 60 * 1000;
        const start = currentMillis - windowMs;
        const end = currentMillis + windowMs;

        return comparableEvents
            .filter((e) => {
                const ts = toMillis(e);
                return ts && ts >= start && ts <= end;
            })
            .sort((a, b) => (toMillis(a) || 0) - (toMillis(b) || 0))
            .slice(0, 40);
    }, [comparableEvents, currentMillis]);

    const eventDeltaSummary = useMemo(() => {
        if (!eventData || !previousComparableEvent) return [];

        const prevRules = JSON.stringify(parseJson(previousComparableEvent.matched_rules) || []);
        const curRules = JSON.stringify(parseJson(eventData.matched_rules) || []);
        const prevFindings = (Array.isArray(parseJson(previousComparableEvent.findings)) ? parseJson(previousComparableEvent.findings) : []).length;
        const curFindings = (Array.isArray(parseJson(eventData.findings)) ? parseJson(eventData.findings) : []).length;

        const rows = [
            ['Severity', (previousComparableEvent.severity || 'low').toUpperCase(), (eventData.severity || 'low').toUpperCase()],
            ['Channel', previousComparableEvent.channel || 'unknown', eventData.channel || 'unknown'],
            ['Action', previousComparableEvent.action_taken || 'n/a', eventData.action_taken || 'n/a'],
            ['Rules', prevRules, curRules],
            ['Findings Count', String(prevFindings), String(curFindings)],
        ];

        return rows
            .filter(([_, before, after]) => before !== after)
            .map(([label, before, after]) => ({ label, before, after }));
    }, [eventData, previousComparableEvent]);

    const severityColor = (sev) => {
        const s = String(sev || '').toLowerCase();
        if (s === 'critical') return '#f85149';
        if (s === 'high') return '#ff7b72';
        if (s === 'medium') return '#d29922';
        return 'var(--accent)';
    };

    if (loading) {
        return <div style={{ color: 'var(--text-muted)', padding: '30px' }}>Loading event detail...</div>;
    }

    if (!eventData) {
        return (
            <div style={{ color: 'var(--text-muted)', padding: '30px' }}>
                <div>Event not found.</div>
                <button className="btn" onClick={onBack} style={{ marginTop: '12px' }}>Back</button>
            </div>
        );
    }

    return (
        <div>
            <div style={{ marginBottom: '18px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <button className="btn" onClick={onBack}>Back to Event Log</button>
                <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Event</span>
                <span style={{ color: 'var(--accent)', fontFamily: 'monospace', fontSize: '12px' }}>{eventData.event_id}</span>
                <button className="btn" style={{ marginLeft: 'auto' }} onClick={() => navigator.clipboard.writeText(eventData.event_id || '')}>Copy ID</button>
                <button className="btn" onClick={() => navigator.clipboard.writeText(JSON.stringify(eventData, null, 2))}>Copy JSON</button>
            </div>

            <div style={{ marginBottom: '14px', paddingBottom: '10px', borderBottom: '1px solid var(--border-color)' }}>
                <h3 style={{ marginTop: 0 }}>Event Overview</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '8px', fontSize: '12px' }}>
                    <div><span style={{ color: 'var(--text-muted)' }}>Time:</span> {formatTimestamp(eventData.timestamp || eventData.created_at)}</div>
                    <div><span style={{ color: 'var(--text-muted)' }}>Agent:</span> {eventData.agent_type || 'unknown'}</div>
                    <div><span style={{ color: 'var(--text-muted)' }}>User:</span> {eventData.user || 'unknown'}</div>
                    <div><span style={{ color: 'var(--text-muted)' }}>Host:</span> {eventData.source_host || eventData.host || 'unknown'}</div>
                    <div><span style={{ color: 'var(--text-muted)' }}>Channel:</span> {eventData.channel || 'unknown'}</div>
                    <div><span style={{ color: 'var(--text-muted)' }}>Severity:</span> {(eventData.severity || 'low').toUpperCase()}</div>
                </div>
            </div>

            <div style={{ marginBottom: '14px', paddingBottom: '10px', borderBottom: '1px solid var(--border-color)' }}>
                <h3 style={{ marginTop: 0 }}>Timeline (±30 minutes)</h3>
                {timelineEvents.length === 0 ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No related activity in the selected time window.</div>
                ) : (
                    <div style={{ display: 'flex', alignItems: 'stretch', gap: '4px', overflowX: 'auto', paddingBottom: '6px' }}>
                        {timelineEvents.map((evt) => {
                            const isCurrent = evt.event_id === eventData.event_id;
                            const ts = formatTimestamp(evt.timestamp || evt.created_at);
                            return (
                                <a
                                    key={evt.event_id}
                                    href={`#/event/${encodeURIComponent(evt.event_id)}`}
                                    title={`${evt.event_id} • ${ts} • ${(evt.severity || 'low').toUpperCase()}${isCurrent ? ' • CURRENT' : ''}`}
                                    style={{
                                        minWidth: isCurrent ? '22px' : '14px',
                                        height: isCurrent ? '34px' : '24px',
                                        borderRadius: '4px',
                                        background: isCurrent ? 'var(--accent)' : severityColor(evt.severity),
                                        border: isCurrent ? '2px solid var(--text-strong)' : '1px solid var(--border-color)',
                                        display: 'inline-block',
                                        textDecoration: 'none',
                                        opacity: isCurrent ? 1 : 0.85,
                                        marginTop: isCurrent ? '0' : '5px',
                                    }}
                                />
                            );
                        })}
                    </div>
                )}
                <div style={{ marginTop: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
                    Each bar is a related event for the same user/host. Taller highlighted bar is the current event.
                </div>
            </div>

            <div style={{ marginBottom: '14px', paddingBottom: '10px', borderBottom: '1px solid var(--border-color)' }}>
                <h3 style={{ marginTop: 0 }}>Change vs Previous Related Event</h3>
                {!previousComparableEvent ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No previous event found for the same user/host.</div>
                ) : (
                    <>
                        <div style={{ fontSize: '12px', marginBottom: '8px' }}>
                            Previous: <a href={`#/event/${encodeURIComponent(previousComparableEvent.event_id)}`} style={{ color: 'var(--accent)', textDecoration: 'none' }}>{previousComparableEvent.event_id}</a> · {formatTimestamp(previousComparableEvent.timestamp || previousComparableEvent.created_at)}
                        </div>
                        {eventDeltaSummary.length === 0 ? (
                            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No significant field changes detected.</div>
                        ) : (
                            <div style={{ display: 'grid', gap: '6px' }}>
                                {eventDeltaSummary.map((row) => (
                                    <div key={row.label} style={{ display: 'grid', gridTemplateColumns: '160px 1fr 1fr', gap: '8px', fontSize: '11px', borderBottom: '1px solid var(--border-color)', paddingBottom: '6px' }}>
                                        <div style={{ color: 'var(--text-muted)' }}>{row.label}</div>
                                        <div style={{ color: 'var(--text-main)', wordBreak: 'break-word' }}>{row.before}</div>
                                        <div style={{ color: 'var(--success-text)', wordBreak: 'break-word' }}>{row.after}</div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </>
                )}
            </div>

            <div style={{ display: 'flex', gap: '6px', marginBottom: '10px' }}>
                {['details', 'json'].map(tab => (
                    <button key={tab} className="btn" onClick={() => setActiveTab(tab)} style={{ opacity: activeTab === tab ? 1 : 0.7 }}>
                        {tab === 'details' ? 'Details' : 'JSON'}
                    </button>
                ))}
            </div>

            {activeTab === 'details' && (
                <div>
                    <h3 style={{ marginTop: 0 }}>Event Data</h3>

                    <div style={{ marginBottom: '10px' }}>
                        <div style={{ color: 'var(--text-strong)', fontSize: '12px', marginBottom: '4px' }}>Matched Rules</div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                            {(Array.isArray(matchedRules) ? matchedRules : [matchedRules]).filter(Boolean).map((r, i) => (
                                <span key={i} style={{ background: 'var(--chip-accent-bg)', color: 'var(--link-soft)', padding: '2px 8px', borderRadius: '4px', fontSize: '11px' }}>{String(r)}</span>
                            ))}
                        </div>
                    </div>

                    {Array.isArray(findings) && findings.length > 0 && (
                        <div style={{ marginBottom: '10px' }}>
                            <div style={{ color: 'var(--text-strong)', fontSize: '12px', marginBottom: '4px' }}>Findings</div>
                            <div style={{ display: 'grid', gap: '6px' }}>
                                {findings.slice(0, 20).map((f, i) => (
                                    <div key={i} style={{ borderBottom: '1px solid var(--border-color)', padding: '8px 0', fontSize: '11px' }}>
                                        <div style={{ color: 'var(--warning-text)' }}>{f.pattern_name || f.description || f.category || 'match'}</div>
                                        <div style={{ marginTop: '2px', color: 'var(--text-main)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{f.matched_text || ''}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {eventData.payload_sample && (
                        <div>
                            <div style={{ color: 'var(--text-strong)', fontSize: '12px', marginBottom: '4px' }}>Payload Sample</div>
                            <pre style={{ margin: 0, background: 'transparent', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '8px', color: 'var(--text-main)', fontSize: '11px', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{eventData.payload_sample}</pre>
                        </div>
                    )}

                    <div style={{ marginTop: '16px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                        <div>
                            <h4 style={{ marginTop: 0 }}>Related Incidents</h4>
                            {relatedIncidents.length === 0 ? (
                                <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No related incidents found.</div>
                            ) : relatedIncidents.map((inc) => (
                                <div key={inc.incident_id} style={{ padding: '6px 0', borderBottom: '1px solid var(--border-color)' }}>
                                    <a href={`#/incident/${encodeURIComponent(inc.incident_id)}`} style={{ color: 'var(--accent)', textDecoration: 'none', fontSize: '12px' }}>{inc.incident_id}</a>
                                    <div style={{ color: 'var(--text-main)', fontSize: '11px' }}>{inc.pattern}</div>
                                </div>
                            ))}
                        </div>
                        <div>
                            <h4 style={{ marginTop: 0 }}>Nearby Events</h4>
                            {relatedEvents.length === 0 ? (
                                <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No nearby events found.</div>
                            ) : relatedEvents.map((evt) => (
                                <div key={evt.event_id} style={{ padding: '6px 0', borderBottom: '1px solid var(--border-color)' }}>
                                    <a href={`#/event/${encodeURIComponent(evt.event_id)}`} style={{ color: 'var(--accent)', textDecoration: 'none', fontSize: '12px' }}>{evt.event_id}</a>
                                    <div style={{ color: 'var(--text-main)', fontSize: '11px' }}>{evt.channel} • {(evt.severity || 'low').toUpperCase()}</div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            {activeTab === 'json' && (
                <div>
                    <h3 style={{ marginTop: 0 }}>Event JSON</h3>
                    <pre style={{ margin: 0, background: 'transparent', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '10px', color: 'var(--success-text)', fontSize: '11px', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: '65vh', overflow: 'auto' }}>
                        {JSON.stringify({ ...eventData, geo }, null, 2)}
                    </pre>
                </div>
            )}
        </div>
    );
};

export default EventRecordDetail;
