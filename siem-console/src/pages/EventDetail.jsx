import React, { useState, useEffect } from 'react';

const EventDetail = ({ incidentId, apiBase, onBack }) => {
    const [incident, setIncident] = useState(null);
    const [events, setEvents] = useState([]);
    const [artifacts, setArtifacts] = useState([]);
    const [userAnalytics, setUserAnalytics] = useState(null);
    const [loadingUserAnalytics, setLoadingUserAnalytics] = useState(false);
    const [artifactContent, setArtifactContent] = useState({});
    const [artifactLoading, setArtifactLoading] = useState({});
    const [loading, setLoading] = useState(true);
    const [activeSection, setActiveSection] = useState('overview');
    const [actionLoading, setActionLoading] = useState(null);
    const [securityTeam, setSecurityTeam] = useState([]);
    const [workflowLoading, setWorkflowLoading] = useState(false);
    const [workflowMessage, setWorkflowMessage] = useState('');
    const [assignedTo, setAssignedTo] = useState('');
    const [classification, setClassification] = useState('TRUE_POSITIVE');
    const [initialStatement, setInitialStatement] = useState('');
    const [finalStatement, setFinalStatement] = useState('');
    const [logStage, setLogStage] = useState('comment');
    const [logNote, setLogNote] = useState('');
    const [activityLogs, setActivityLogs] = useState([]);
    const [isCompactLayout, setIsCompactLayout] = useState(false);
    const [showActionsPanel, setShowActionsPanel] = useState(false);
    const [backendConnected, setBackendConnected] = useState(true);
    const actionsPanelRef = React.useRef(null);

    useEffect(() => {
        fetchIncidentDetail();
    }, [incidentId]);

    useEffect(() => {
        const applyLayoutMode = () => {
            const compact = window.innerWidth < 1280;
            setIsCompactLayout(compact);
            if (!compact) {
                setShowActionsPanel(true);
            }
        };

        applyLayoutMode();
        window.addEventListener('resize', applyLayoutMode);
        return () => window.removeEventListener('resize', applyLayoutMode);
    }, []);

    useEffect(() => {
        const loadSecurityTeam = async () => {
            try {
                const res = await fetch(`${apiBase}/security-team`);
                const data = await res.json();
                if (!res.ok) throw new Error(data?.error || 'Failed to load security team');
                setSecurityTeam(data.members || []);
                setBackendConnected(true);
            } catch {
                setSecurityTeam([]);
                setBackendConnected(false);
            }
        };
        loadSecurityTeam();
    }, [apiBase]);

    const focusActionsPanel = () => {
        setShowActionsPanel(true);
        setTimeout(() => {
            actionsPanelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 40);
    };

    const fetchIncidentDetail = async () => {
        setLoading(true);
        setLoadingUserAnalytics(true);
        try {
            const res = await fetch(`${apiBase}/incidents/${incidentId}`);
            const data = await res.json();
            setIncident(data);
            setActivityLogs(Array.isArray(data.activity_logs) ? data.activity_logs : []);
            setAssignedTo(data.assigned_to || '');
            setClassification(data.classification || 'TRUE_POSITIVE');

            const [artRes, analyticsRes] = await Promise.all([
                fetch(`${apiBase}/incidents/${incidentId}/artifacts`),
                fetch(`${apiBase}/incidents/${incidentId}/user-analytics`),
            ]);
            const artData = await artRes.json();
            const analyticsData = await analyticsRes.json();
            setArtifacts(artData.artifacts || []);
            setUserAnalytics(analyticsData || null);

            if (Array.isArray(data.resolved_events) && data.resolved_events.length > 0) {
                setEvents(data.resolved_events);
                setLoadingUserAnalytics(false);
                setLoading(false);
                return;
            }

            // Fetch related events
            const evtRes = await fetch(`${apiBase}/events?limit=200`);
            const evtData = await evtRes.json();
            const allEvents = evtData.events || [];

            // Filter events tied to this incident
            const eventIds = data.events || [];
            const related = allEvents.filter(e => eventIds.includes(e.event_id));
            // If no linked events, show events matching same user+pattern
            if (related.length === 0) {
                const fallback = allEvents.filter(e =>
                    e.user === data.user || e.source_host === data.host
                ).slice(0, 10);
                setEvents(fallback);
            } else {
                setEvents(related);
            }
        } catch (err) {
            console.error("Failed to load incident detail:", err);
            setUserAnalytics(null);
        }
        setLoadingUserAnalytics(false);
        setLoading(false);
    };

    const handleAction = async (action) => {
        setActionLoading(action);
        try {
            if (action === 'close') {
                focusActionsPanel();
                await handleCloseWorkflow();
                setActionLoading(null);
                return;
            }

            const endpoint = action === 'escalate'
                ? `${apiBase}/incidents/${incidentId}/escalate`
                : action === 'raise_ticket'
                    ? `${apiBase}/incidents/${incidentId}/raise-ticket`
                    : `${apiBase}/incidents/${incidentId}/reopen`;
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    actor: assignedTo || incident?.assigned_to || 'secops_analyst',
                    note: action === 'raise_ticket' ? 'Ticket raised from incident detail.' : action === 'reopen' ? 'Incident reopened from incident detail.' : 'Incident escalated from incident detail.',
                }),
            });
            if (res.ok) {
                setWorkflowMessage(action === 'reopen' ? 'Incident reopened.' : action === 'raise_ticket' ? 'Ticket raised.' : 'Incident escalated.');
                await fetchIncidentDetail();
            } else {
                const data = await res.json().catch(() => ({}));
                setWorkflowMessage(data?.error || `Failed to ${action}.`);
            }
        } catch (err) {
            console.error(`Failed to ${action}:`, err);
            setWorkflowMessage(`Failed to ${action}.`);
        }
        setActionLoading(null);
    };

    const handleAssign = async () => {
        if (!assignedTo) return;
        setWorkflowLoading(true);
        setWorkflowMessage('');
        try {
            const res = await fetch(`${apiBase}/incidents/${incidentId}/assign`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    assignee: assignedTo,
                    actor: assignedTo || 'secops_analyst',
                    note: 'Assignment updated from incident detail page.',
                }),
            });
            const data = await res.json();
            if (!res.ok) {
                setWorkflowMessage(data.error || 'Assignment failed.');
            } else {
                setWorkflowMessage(`Assigned to ${assignedTo}.`);
                await fetchIncidentDetail();
            }
        } catch {
            setWorkflowMessage('Assignment failed.');
        }
        setWorkflowLoading(false);
    };

    const handleAddActivityLog = async () => {
        if (!logNote.trim()) {
            setWorkflowMessage('Activity note is required.');
            return;
        }
        setWorkflowLoading(true);
        setWorkflowMessage('');
        try {
            const res = await fetch(`${apiBase}/incidents/${incidentId}/activity-log`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    stage: logStage,
                    actor: assignedTo || incident?.assigned_to || 'secops_analyst',
                    note: logNote.trim(),
                    tags: [classification],
                }),
            });
            const data = await res.json();
            if (!res.ok) {
                setWorkflowMessage(data.error || 'Failed to add activity log.');
            } else {
                setLogNote('');
                setActivityLogs(data.logs || []);
                setWorkflowMessage('Activity log added.');
                await fetchIncidentDetail();
            }
        } catch {
            setWorkflowMessage('Failed to add activity log.');
        }
        setWorkflowLoading(false);
    };

    const handleCloseWorkflow = async () => {
        if (!classification || !initialStatement.trim() || !finalStatement.trim()) {
            setWorkflowMessage('Classification + initial + final statements are required.');
            focusActionsPanel();
            return;
        }

        setWorkflowLoading(true);
        setWorkflowMessage('');
        try {
            const res = await fetch(`${apiBase}/incidents/${incidentId}/close`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    actor: assignedTo || incident?.assigned_to || 'secops_analyst',
                    classification,
                    initial_statement: initialStatement.trim(),
                    final_statement: finalStatement.trim(),
                    tags: [classification],
                }),
            });
            const data = await res.json();
            if (!res.ok) {
                setWorkflowMessage(data.error || 'Failed to close incident.');
                focusActionsPanel();
            } else {
                setWorkflowMessage('Incident closed successfully.');
                await fetchIncidentDetail();
            }
        } catch {
            setWorkflowMessage('Failed to close incident.');
            focusActionsPanel();
        }
        setWorkflowLoading(false);
    };

    const severityConfig = {
        critical: { color: 'var(--danger)', bg: 'var(--surface-subtle)', icon: 'C', label: 'CRITICAL' },
        high: { color: 'var(--warning)', bg: 'var(--surface-subtle)', icon: 'H', label: 'HIGH' },
        medium: { color: 'var(--accent)', bg: 'var(--surface-subtle)', icon: 'M', label: 'MEDIUM' },
        low: { color: 'var(--text-muted)', bg: 'var(--surface-subtle)', icon: 'L', label: 'LOW' },
    };

    const loadArtifactContent = async (artifactId) => {
        if (!artifactId) return;
        if (artifactContent[artifactId]) {
            setArtifactContent(prev => ({ ...prev, [artifactId]: null }));
            return;
        }

        setArtifactLoading(prev => ({ ...prev, [artifactId]: true }));
        try {
            const res = await fetch(`${apiBase}/fleet/artifacts/${encodeURIComponent(artifactId)}/content`);
            const data = await res.json();
            setArtifactContent(prev => ({ ...prev, [artifactId]: data }));
        } catch (err) {
            setArtifactContent(prev => ({ ...prev, [artifactId]: { error: 'Failed to load content' } }));
        }
        setArtifactLoading(prev => ({ ...prev, [artifactId]: false }));
    };

    const statusConfig = {
        OPEN: { color: 'var(--warning)', bg: 'var(--surface-subtle)' },
        ESCALATED: { color: 'var(--danger)', bg: 'var(--surface-subtle)' },
        CLOSED: { color: 'var(--text-muted)', bg: 'var(--surface-subtle)' },
        'AUTO-CLOSED': { color: 'var(--text-muted)', bg: 'var(--surface-subtle)' },
        TICKET_RAISED: { color: 'var(--accent)', bg: 'var(--surface-subtle)' },
    };

    const formatTimestamp = (ts) => {
        if (!ts) return '—';
        let raw = String(ts).trim();
        // SQLite datetime('now') returns "YYYY-MM-DD HH:MM:SS" in UTC.
        // Convert explicitly so UI shows local time correctly.
        if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(raw)) {
            raw = raw.replace(' ', 'T') + 'Z';
        }
        const d = new Date(raw);
        if (Number.isNaN(d.getTime())) return String(ts);
        return d.toLocaleString('en-US', {
            year: 'numeric', month: 'short', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            hour12: false
        });
    };

    const riskLevel = (risk) => {
        if (risk >= 80) return { label: 'CRITICAL', color: 'var(--danger)' };
        if (risk >= 60) return { label: 'HIGH', color: 'var(--warning)' };
        if (risk >= 40) return { label: 'MEDIUM', color: 'var(--accent)' };
        return { label: 'LOW', color: 'var(--success)' };
    };

    if (loading) {
        return (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '400px', color: 'var(--text-muted)' }}>
                <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '36px', marginBottom: '12px', animation: 'pulse 1.5s infinite' }}>...</div>
                    <div>Loading forensic data...</div>
                </div>
            </div>
        );
    }

    if (!incident) {
        return (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                <div style={{ fontSize: '48px', marginBottom: '12px' }}>--</div>
                <h3>Incident Not Found</h3>
                <p>Incident {incidentId} does not exist in the database.</p>
                <button className="btn" onClick={onBack} style={{ marginTop: '20px' }}>← Back to Command Center</button>
            </div>
        );
    }

    const riskInfo = riskLevel(incident.risk || 0);
    const displayStatus = String(incident.status || '').toUpperCase() === 'AUTO-CLOSED' ? 'CLOSED' : incident.status;
    const sConf = statusConfig[displayStatus] || statusConfig[incident.status] || statusConfig.OPEN;
    const ai = incident.ai_analysis;
    const parsedAi = typeof ai === 'string' ? (() => { try { return JSON.parse(ai); } catch { return null; } })() : ai;

    const sectionTabs = [
        { id: 'overview', label: 'Overview', icon: '' },
        { id: 'user_analytics', label: 'User Analytics', icon: '' },
        { id: 'timeline', label: 'Event Timeline', icon: '' },
        { id: 'evidence', label: 'Evidence', icon: '' },
        { id: 'raw', label: '{ } Raw Log', icon: '' },
    ];
    if (parsedAi) sectionTabs.splice(2, 0, { id: 'ai', label: 'AI Analysis', icon: '' });

    const sectionCardStyle = {
        background: 'var(--panel-bg)',
        border: '1px solid var(--border-color)',
        borderRadius: '12px',
        padding: '16px 18px',
        boxShadow: 'var(--card-shadow)',
        minWidth: 0,
        maxWidth: '100%',
        overflowX: 'auto',
    };

    return (
        <div>
            {/* Breadcrumb & Back */}
            <div style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '12px' }}>
                <button onClick={onBack} style={{
                    background: 'transparent', border: '1px solid var(--border-color)', color: 'var(--text-muted)',
                    borderRadius: '6px', padding: '6px 14px', cursor: 'pointer', fontSize: '13px', transition: 'all 0.2s'
                }}
                    onMouseOver={e => e.currentTarget.style.borderColor = 'var(--accent)'}
                    onMouseOut={e => e.currentTarget.style.borderColor = 'var(--border-color)'}
                >← Back</button>
                <span style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Command Center</span>
                <span style={{ color: 'var(--text-muted)', fontSize: '13px' }}>/</span>
                <span style={{ color: 'var(--accent)', fontSize: '13px', fontWeight: 600 }}>{incident.incident_id}</span>
            </div>

            {/* ── Header Card ── */}
            <div style={{
                background: 'var(--panel-bg)',
                border: '1px solid var(--border-color)',
                borderRadius: '12px',
                boxShadow: 'var(--card-shadow)',
                padding: '16px 18px', marginBottom: '20px',
                borderLeft: `3px solid ${riskInfo.color}`,
                paddingLeft: '14px'
            }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '20px' }}>
                    <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                            <h2 style={{ color: 'var(--text-strong)', fontSize: '22px', fontWeight: 700, margin: 0 }}>
                                Incident {incident.incident_id}
                            </h2>
                            <span style={{
                                padding: '3px 10px', borderRadius: '12px', fontSize: '11px', fontWeight: 700,
                                background: sConf.bg, color: sConf.color, textTransform: 'uppercase', letterSpacing: '0.5px'
                            }}>{displayStatus}</span>
                        </div>
                        <p style={{ color: 'var(--text-muted)', fontSize: '13px', margin: 0 }}>
                            Opened {formatTimestamp(incident.created_at)} • Last updated {formatTimestamp(incident.updated_at || incident.created_at)}
                        </p>
                    </div>

                    {/* Action Buttons */}
                    <div style={{ display: 'flex', gap: '10px' }}>
                        {isCompactLayout && (
                            <button
                                className="btn"
                                onClick={() => setShowActionsPanel((v) => !v)}
                                style={{ background: 'var(--surface-subtle)', color: 'var(--accent)', border: '1px solid var(--accent)' }}
                            >
                                {showActionsPanel ? 'Hide Actions' : 'Show Actions'}
                            </button>
                        )}
                        {(incident.status === 'OPEN' || incident.status === 'ESCALATED') && (
                            <>
                                {incident.status === 'OPEN' && (
                                    <button className="btn" onClick={() => handleAction('escalate')} disabled={!!actionLoading}
                                        style={{ background: 'var(--surface-subtle)', color: 'var(--danger)', border: '1px solid var(--danger)' }}>
                                        {actionLoading === 'escalate' ? '...' : 'Escalate'}
                                    </button>
                                )}
                                <button className="btn" onClick={() => handleAction('raise_ticket')} disabled={!!actionLoading}
                                    style={{ background: 'var(--surface-subtle)', color: 'var(--accent)', border: '1px solid var(--accent)' }}>
                                    {actionLoading === 'raise_ticket' ? '...' : 'Raise Ticket'}
                                </button>
                                <button className="btn" onClick={() => handleAction('close')} disabled={!!actionLoading}
                                    style={{ background: 'var(--surface-subtle)', color: 'var(--success)', border: '1px solid var(--success)' }}>
                                    {actionLoading === 'close' ? '...' : '✓ Close (with logs)'}
                                </button>
                            </>
                        )}
                        {(incident.status === 'CLOSED' || incident.status === 'AUTO-CLOSED' || incident.status === 'TICKET_RAISED') && (
                            <button className="btn" onClick={() => handleAction('reopen')} disabled={!!actionLoading}
                                style={{ background: 'var(--surface-subtle)', color: 'var(--warning)', border: '1px solid var(--warning)' }}>
                                {actionLoading === 'reopen' ? '...' : 'Reopen'}
                            </button>
                        )}
                    </div>
                </div>
            </div>

            {/* ── Key Metrics Row ── */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '14px', marginBottom: '20px' }}>
                {[
                    { label: 'AI RISK SCORE', value: `${incident.risk || 0} / 100`, accent: riskInfo.color },
                    { label: 'VERDICT', value: incident.verdict || 'NEEDS_REVIEW', accent: 'var(--warning)' },
                    { label: 'FP PROBABILITY', value: `${incident.fp ?? 50}%`, accent: incident.fp > 70 ? 'var(--success)' : 'var(--danger)' },
                    { label: 'MATCHED PATTERN', value: incident.pattern || '—', accent: 'var(--accent)' },
                    { label: 'SOURCE HOST', value: incident.host || '—', accent: 'var(--text-main)' },
                    { label: 'USER', value: incident.user || '—', accent: 'var(--text-main)' },
                    { label: 'CHANNEL', value: incident.channel || '—', accent: 'var(--text-main)' },
                    { label: 'ALERT COUNT', value: incident.alert_count || 0, accent: 'var(--warning)' },
                ].map((m, i) => (
                    <div key={i} style={{
                        background: 'var(--panel-bg)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '10px',
                        padding: '12px 12px',
                        borderTop: `2px solid ${m.accent}`,
                        boxShadow: 'var(--card-shadow)',
                    }}>
                        <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 600, letterSpacing: '1px', textTransform: 'uppercase', marginBottom: '6px' }}>{m.label}</div>
                        <div style={{ color: m.accent, fontSize: '16px', fontWeight: 700, fontFamily: "'Inter', monospace", wordBreak: 'break-word', overflowWrap: 'anywhere' }}>{m.value}</div>
                    </div>
                ))}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: isCompactLayout ? '1fr' : 'minmax(0, 1fr) minmax(360px, 420px)', gap: '16px', alignItems: 'start' }}>
                <div style={{ order: isCompactLayout ? 2 : 1, minWidth: 0, overflowX: 'hidden' }}>
                    {/* ── Section Tabs ── */}
                    <div style={{ display: 'flex', gap: '4px', marginBottom: '20px', borderBottom: '1px solid var(--border-color)', paddingBottom: '0', overflowX: 'auto' }}>
                        {sectionTabs.map(t => (
                            <button key={t.id} onClick={() => setActiveSection(t.id)} style={{
                                background: activeSection === t.id ? 'var(--panel-bg)' : 'transparent',
                                border: activeSection === t.id ? '1px solid var(--border-color)' : '1px solid transparent',
                                borderBottom: activeSection === t.id ? '1px solid var(--panel-bg)' : '1px solid transparent',
                                borderRadius: '8px 8px 0 0', padding: '10px 18px', cursor: 'pointer',
                                color: activeSection === t.id ? 'var(--text-strong)' : 'var(--text-muted)', fontSize: '13px', fontWeight: 500,
                                marginBottom: '-1px', transition: 'all 0.2s', whiteSpace: 'nowrap',
                                boxShadow: activeSection === t.id ? 'var(--card-shadow)' : 'none'
                            }}>
                                {t.label}
                            </button>
                        ))}
                    </div>

            {/* ── OVERVIEW SECTION ── */}
            {activeSection === 'overview' && (
                <div style={sectionCardStyle}>
                    <h3 style={{ color: 'var(--text-strong)', marginBottom: '20px', fontSize: '16px' }}>Incident Summary</h3>

                    <div style={{ marginBottom: '18px', padding: '10px 0', borderBottom: '1px solid var(--border-color)' }}>
                        <div style={{ color: 'var(--text-strong)', fontSize: '12px', fontWeight: 700, marginBottom: '8px' }}>EXACT PATTERN MATCHES</div>
                        {(incident.pattern_matches || []).length === 0 ? (
                            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No extracted pattern names yet for this incident.</div>
                        ) : (
                            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                                {incident.pattern_matches.map((p, i) => (
                                    <span key={`${p}-${i}`} style={{
                                        background: 'var(--chip-accent-bg)', color: 'var(--link-soft)',
                                        padding: '3px 8px', borderRadius: '4px', fontSize: '11px',
                                        border: '1px solid var(--border-color)', fontFamily: 'monospace'
                                    }}>{p}</span>
                                ))}
                            </div>
                        )}
                    </div>

                    <div style={{ marginBottom: '18px', padding: '10px 0', borderBottom: '1px solid var(--border-color)' }}>
                        <div style={{ color: 'var(--text-strong)', fontSize: '12px', fontWeight: 700, marginBottom: '8px' }}>MATCHED TEXT SAMPLES</div>
                        {(incident.exact_findings || []).length === 0 ? (
                            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No matched text samples available for this incident.</div>
                        ) : (
                            <div style={{ maxHeight: '180px', overflow: 'auto', display: 'grid', gap: '8px' }}>
                                {incident.exact_findings.slice(0, 20).map((f, i) => (
                                    <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border-color)' }}>
                                        <div style={{ color: 'var(--warning-text)', fontSize: '11px', fontWeight: 700 }}>{f.pattern_name || 'match'} {f.severity ? `• ${String(f.severity).toUpperCase()}` : ''}</div>
                                        <div style={{ color: 'var(--text-main)', fontSize: '11px', marginTop: '4px', fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                                            {f.matched_text || '(empty)'}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    <table>
                        <tbody>
                            {[
                                ['Incident ID', incident.incident_id],
                                ['Status', incident.status],
                                ['User', incident.user],
                                ['Source Host', incident.host],
                                ['Channel', incident.channel],
                                ['Matched Pattern', incident.pattern],
                                ['Risk Score', `${incident.risk || 0} / 100`],
                                ['Verdict', incident.verdict || 'NEEDS_REVIEW'],
                                ['False Positive %', `${incident.fp ?? 50}%`],
                                ['Alert Count', incident.alert_count || 0],
                                ['Repeat Count', incident.repeat_count || 0],
                                ['Auto-Escalated', incident.auto_escalated ? 'Yes' : 'No'],
                                ['Owner', incident.assigned_to || 'UNASSIGNED'],
                                ['Assigned At', formatTimestamp(incident.assigned_at)],
                                ['Classification', incident.classification || 'NOT_SET'],
                                ['Closed By', incident.closed_by || '—'],
                                ['Closed At', formatTimestamp(incident.closed_at)],
                                ['Created At', formatTimestamp(incident.created_at)],
                                ['Updated At', formatTimestamp(incident.updated_at)],
                                ['Linked Events', (incident.events || []).length],
                            ].map(([label, val], i) => (
                                <tr key={i}>
                                    <td style={{ color: 'var(--text-muted)', fontWeight: 500, width: '200px', fontSize: '13px', borderBottom: '1px solid var(--border-color)' }}>{label}</td>
                                    <td style={{ color: 'var(--text-strong)', fontFamily: "'Inter', monospace", fontSize: '13px', borderBottom: '1px solid var(--border-color)' }}>{String(val)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* ── USER ANALYTICS SECTION ── */}
            {activeSection === 'user_analytics' && (
                <div style={sectionCardStyle}>
                    <h3 style={{ color: 'var(--text-strong)', marginBottom: '20px', fontSize: '16px' }}>User Investigation Analytics</h3>

                    {loadingUserAnalytics ? (
                        <div style={{ color: 'var(--text-muted)' }}>Loading analytics...</div>
                    ) : !userAnalytics ? (
                        <div style={{ color: 'var(--text-muted)' }}>No analytics available for this incident context.</div>
                    ) : (
                        <>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px', marginBottom: '16px' }}>
                                {[
                                    ['TOTAL RELATED INCIDENTS', userAnalytics.summary?.total_related_incidents ?? 0, 'var(--accent)'],
                                    ['OPEN INCIDENTS', userAnalytics.summary?.open_incidents ?? 0, 'var(--warning)'],
                                    ['ESCALATED INCIDENTS', userAnalytics.summary?.escalated_incidents ?? 0, 'var(--danger)'],
                                    ['SAME POLICY REPEATS', userAnalytics.summary?.same_pattern_incidents ?? 0, 'var(--warning-text)'],
                                    ['SAME HOST INCIDENTS', userAnalytics.summary?.same_host_incidents ?? 0, 'var(--success-text)'],
                                    ['TOTAL RELATED EVENTS', userAnalytics.summary?.event_count ?? 0, 'var(--link-soft)'],
                                ].map(([label, value, color], i) => (
                                    <div key={i} style={{ borderBottom: '1px solid var(--border-color)', borderLeft: `2px solid ${color}`, padding: '8px 0 8px 10px' }}>
                                        <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 600 }}>{label}</div>
                                        <div style={{ color, fontSize: '22px', fontWeight: 700 }}>{value}</div>
                                    </div>
                                ))}
                            </div>

                            <div style={{ marginBottom: '14px', color: 'var(--text-muted)', fontSize: '12px' }}>
                                First seen: {formatTimestamp(userAnalytics.summary?.first_seen)} | Last seen: {formatTimestamp(userAnalytics.summary?.last_seen)}
                            </div>

                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
                                <div style={{ borderBottom: '1px solid var(--border-color)', padding: '8px 0' }}>
                                    <div style={{ color: 'var(--text-strong)', marginBottom: '10px', fontSize: '13px', fontWeight: 600 }}>Top Repeated Policies</div>
                                    {(userAnalytics.frequent_patterns || []).slice(0, 8).map((p, i) => {
                                        const max = Math.max(...(userAnalytics.frequent_patterns || []).map(x => x.count || 0), 1);
                                        const w = ((p.count || 0) / max) * 100;
                                        return (
                                            <div key={i} style={{ marginBottom: '8px' }}>
                                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                                                    <span style={{ color: 'var(--text-main)', maxWidth: '75%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.pattern}</span>
                                                    <span style={{ color: 'var(--accent)' }}>{p.count}</span>
                                                </div>
                                                <div style={{ height: '4px', background: 'var(--surface-subtle)', marginTop: '3px' }}>
                                                    <div style={{ height: '4px', width: `${w}%`, background: 'var(--accent)' }} />
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>

                                <div style={{ borderBottom: '1px solid var(--border-color)', padding: '8px 0' }}>
                                    <div style={{ color: 'var(--text-strong)', marginBottom: '10px', fontSize: '13px', fontWeight: 600 }}>Severity Distribution</div>
                                    {(userAnalytics.severity_distribution || []).map((s, i) => {
                                        const max = Math.max(...(userAnalytics.severity_distribution || []).map(x => x.count || 0), 1);
                                        const w = ((s.count || 0) / max) * 100;
                                        const color = s.severity === 'critical' ? 'var(--danger)' : s.severity === 'high' ? 'var(--warning)' : s.severity === 'medium' ? 'var(--accent)' : 'var(--text-muted)';
                                        return (
                                            <div key={i} style={{ marginBottom: '8px' }}>
                                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                                                    <span style={{ color: 'var(--text-main)', textTransform: 'uppercase' }}>{s.severity}</span>
                                                    <span style={{ color }}>{s.count}</span>
                                                </div>
                                                <div style={{ height: '4px', background: 'var(--surface-subtle)', marginTop: '3px' }}>
                                                    <div style={{ height: '4px', width: `${w}%`, background: color }} />
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>

                            <div style={{ borderBottom: '1px solid var(--border-color)', padding: '8px 0', marginBottom: '16px' }}>
                                <div style={{ color: 'var(--text-strong)', marginBottom: '10px', fontSize: '13px', fontWeight: 600 }}>Incident Trend (Recent Days)</div>
                                <div style={{ display: 'flex', alignItems: 'flex-end', gap: '6px', minHeight: '120px' }}>
                                    {(userAnalytics.daily_incidents || []).slice(-14).map((d, i) => {
                                        const max = Math.max(...(userAnalytics.daily_incidents || []).map(x => x.count || 0), 1);
                                        const h = Math.max(8, ((d.count || 0) / max) * 90);
                                        return (
                                            <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px', flex: 1 }}>
                                                <div style={{ width: '100%', maxWidth: '18px', height: `${h}px`, background: 'var(--accent)' }} title={`${d.day}: ${d.count}`} />
                                                <div style={{ color: 'var(--text-muted)', fontSize: '9px' }}>{(d.day || '').slice(5)}</div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>

                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
                                <div style={{ borderBottom: '1px solid var(--border-color)', padding: '8px 0' }}>
                                    <div style={{ color: 'var(--text-strong)', marginBottom: '10px', fontSize: '13px', fontWeight: 600 }}>Channel Distribution</div>
                                    {(userAnalytics.channel_distribution || []).slice(0, 8).map((c, i) => {
                                        const max = Math.max(...(userAnalytics.channel_distribution || []).map(x => x.count || 0), 1);
                                        const w = ((c.count || 0) / max) * 100;
                                        return (
                                            <div key={i} style={{ marginBottom: '8px' }}>
                                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                                                    <span style={{ color: 'var(--text-main)', maxWidth: '75%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.channel}</span>
                                                    <span style={{ color: 'var(--success-text)' }}>{c.count}</span>
                                                </div>
                                                <div style={{ height: '4px', background: 'var(--surface-subtle)', marginTop: '3px' }}>
                                                    <div style={{ height: '4px', width: `${w}%`, background: 'var(--success-text)' }} />
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>

                                <div style={{ borderBottom: '1px solid var(--border-color)', padding: '8px 0' }}>
                                    <div style={{ color: 'var(--text-strong)', marginBottom: '10px', fontSize: '13px', fontWeight: 600 }}>Hourly Activity</div>
                                    {(userAnalytics.hourly_activity || []).slice(0, 12).map((h, i) => {
                                        const max = Math.max(...(userAnalytics.hourly_activity || []).map(x => x.count || 0), 1);
                                        const w = ((h.count || 0) / max) * 100;
                                        return (
                                            <div key={i} style={{ marginBottom: '8px' }}>
                                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                                                    <span style={{ color: 'var(--text-main)' }}>{h.hour}</span>
                                                    <span style={{ color: 'var(--link-soft)' }}>{h.count}</span>
                                                </div>
                                                <div style={{ height: '4px', background: 'var(--surface-subtle)', marginTop: '3px' }}>
                                                    <div style={{ height: '4px', width: `${w}%`, background: 'var(--link-soft)' }} />
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>

                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                                <div style={{ borderBottom: '1px solid var(--border-color)', padding: '8px 0' }}>
                                    <div style={{ color: 'var(--text-strong)', marginBottom: '10px', fontSize: '13px', fontWeight: 600 }}>Past Incidents (Same User/Host)</div>
                                    {(userAnalytics.recent_incidents || []).length === 0 ? (
                                        <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No prior incidents found.</div>
                                    ) : (
                                        <div style={{ maxHeight: '260px', overflow: 'auto' }}>
                                            {(userAnalytics.recent_incidents || []).map((r, i) => (
                                                <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border-color)' }}>
                                                    <a href={`#/incident/${encodeURIComponent(r.incident_id)}`} style={{ color: 'var(--accent)', textDecoration: 'none', fontSize: '12px', fontWeight: 600 }}>{r.incident_id}</a>
                                                    <div style={{ color: 'var(--text-main)', fontSize: '11px', marginTop: '2px' }}>{r.pattern}</div>
                                                    <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>{formatTimestamp(r.created_at)} • Risk {r.risk} • {r.status}</div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>

                                <div style={{ borderBottom: '1px solid var(--border-color)', padding: '8px 0' }}>
                                    <div style={{ color: 'var(--text-strong)', marginBottom: '10px', fontSize: '13px', fontWeight: 600 }}>Same Policy Violation History</div>
                                    {(userAnalytics.same_pattern_history || []).length === 0 ? (
                                        <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No repeated incidents with this policy pattern yet.</div>
                                    ) : (
                                        <div style={{ maxHeight: '260px', overflow: 'auto' }}>
                                            {(userAnalytics.same_pattern_history || []).map((r, i) => (
                                                <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border-color)' }}>
                                                    <a href={`#/incident/${encodeURIComponent(r.incident_id)}`} style={{ color: 'var(--warning-text)', textDecoration: 'none', fontSize: '12px', fontWeight: 600 }}>{r.incident_id}</a>
                                                    <div style={{ color: 'var(--text-main)', fontSize: '11px', marginTop: '2px' }}>{r.pattern}</div>
                                                    <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>{formatTimestamp(r.created_at)} • Risk {r.risk} • {r.status}</div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </>
                    )}
                </div>
            )}

            {/* ── EVENT TIMELINE SECTION ── */}
            {activeSection === 'timeline' && (
                <div style={sectionCardStyle}>
                    <h3 style={{ color: 'var(--text-strong)', marginBottom: '20px', fontSize: '16px' }}>Correlated Event Timeline</h3>
                    {events.length === 0 ? (
                        <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)', border: '1px dashed var(--border-color)', borderRadius: '8px' }}>
                            No correlated events found for this incident.
                        </div>
                    ) : (
                        <div style={{ position: 'relative' }}>
                            {/* Vertical timeline line */}
                            <div style={{ position: 'absolute', left: '18px', top: '10px', bottom: '10px', width: '2px', background: 'var(--border-color)' }} />
                            {events.map((evt, i) => {
                                const sev = (evt.severity || 'low').toLowerCase();
                                const sevConf = severityConfig[sev] || severityConfig.low;
                                let matchedRules = evt.matched_rules;
                                if (typeof matchedRules === 'string') {
                                    try { matchedRules = JSON.parse(matchedRules); } catch { matchedRules = [matchedRules]; }
                                }
                                matchedRules = (matchedRules || []).flatMap(r => typeof r === 'string' ? r.split(',').map(x => x.trim()).filter(Boolean) : []);
                                let geo = evt.geo;
                                if (typeof geo === 'string') {
                                    try { geo = JSON.parse(geo); } catch { geo = {}; }
                                }
                                return (
                                    <div key={evt.event_id || i} style={{ display: 'flex', gap: '20px', marginBottom: '20px', paddingLeft: '4px' }}>
                                        {/* Dot */}
                                        <div style={{
                                            width: '30px', height: '30px', borderRadius: '50%', flexShrink: 0,
                                            background: sevConf.bg, border: `2px solid ${sevConf.color}`,
                                            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', zIndex: 1
                                        }}>{sevConf.icon}</div>
                                        {/* Card */}
                                        <div style={{
                                            flex: 1, padding: '10px 0 12px 12px', borderBottom: '1px solid var(--border-color)', borderLeft: `2px solid ${sevConf.color}`
                                        }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
                                                <span style={{ color: 'var(--accent)', fontFamily: 'monospace', fontSize: '12px', fontWeight: 600 }}>{evt.event_id}</span>
                                                <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{formatTimestamp(evt.timestamp || evt.created_at)}</span>
                                            </div>
                                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '8px', fontSize: '12px' }}>
                                                <div><span style={{ color: 'var(--text-muted)' }}>Agent: </span><span style={{ color: 'var(--text-strong)' }}>{evt.agent_type}</span></div>
                                                <div><span style={{ color: 'var(--text-muted)' }}>Host: </span><span style={{ color: 'var(--text-strong)' }}>{evt.source_host}</span></div>
                                                <div><span style={{ color: 'var(--text-muted)' }}>User: </span><span style={{ color: 'var(--text-strong)' }}>{evt.user}</span></div>
                                                <div><span style={{ color: 'var(--text-muted)' }}>Channel: </span><span style={{ color: 'var(--text-strong)' }}>{evt.channel}</span></div>
                                                <div><span style={{ color: 'var(--text-muted)' }}>Severity: </span><span style={{ color: sevConf.color, fontWeight: 600 }}>{sevConf.label}</span></div>
                                            </div>
                                            {/* Matched Rules */}
                                            {matchedRules && matchedRules.length > 0 && (
                                                <div style={{ marginTop: '10px' }}>
                                                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 600, marginBottom: '4px', letterSpacing: '0.5px' }}>MATCHED RULES</div>
                                                    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                                                        {matchedRules.map((r, ri) => (
                                                            <span key={ri} style={{
                                                                background: 'var(--chip-accent-bg)', color: 'var(--accent)',
                                                                padding: '2px 8px', borderRadius: '4px', fontSize: '11px',
                                                                fontFamily: 'monospace', border: '1px solid var(--border-color)'
                                                            }}>{r}</span>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                            {Array.isArray(geo?.findings) && geo.findings.length > 0 && (
                                                <div style={{ marginTop: '10px' }}>
                                                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 600, marginBottom: '4px', letterSpacing: '0.5px' }}>EXACT MATCHES</div>
                                                    <div style={{ display: 'grid', gap: '6px' }}>
                                                        {geo.findings.slice(0, 10).map((f, fi) => (
                                                            <div key={fi} style={{ borderBottom: '1px solid var(--border-color)', padding: '8px 0' }}>
                                                                <div style={{ color: 'var(--warning-text)', fontSize: '11px', fontWeight: 700 }}>{f.pattern_name || f.category || 'match'}</div>
                                                                <div style={{ color: 'var(--text-main)', fontSize: '11px', marginTop: '3px', fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{f.matched_text || ''}</div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                            {/* Payload Sample */}
                                            {evt.payload_sample && (
                                                <div style={{ marginTop: '10px' }}>
                                                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 600, marginBottom: '4px', letterSpacing: '0.5px' }}>PAYLOAD SAMPLE</div>
                                                    <pre style={{
                                                        background: 'var(--code-bg)', border: '1px solid var(--border-color)',
                                                        borderRadius: '6px', padding: '10px', fontSize: '11px',
                                                        color: 'var(--code-text)', fontFamily: "'Fira Code', 'JetBrains Mono', monospace",
                                                        whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowWrap: 'anywhere', maxHeight: '120px', overflow: 'auto'
                                                    }}>{evt.payload_sample}</pre>
                                                </div>
                                            )}
                                            {/* Geo/Meta */}
                                            {geo && Object.keys(geo).length > 0 && (
                                                <div style={{ marginTop: '10px' }}>
                                                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 600, marginBottom: '4px', letterSpacing: '0.5px' }}>METADATA</div>
                                                    <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', fontSize: '11px' }}>
                                                        {Object.entries(geo).map(([k, v]) => (
                                                            <span key={k}>
                                                                <span style={{ color: 'var(--text-muted)' }}>{k}: </span>
                                                                <span style={{ color: 'var(--text-main)' }}>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                                                            </span>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            )}

            {/* ── EVIDENCE SECTION ── */}
            {activeSection === 'evidence' && (
                <div style={sectionCardStyle}>
                    <h3 style={{ color: 'var(--text-strong)', marginBottom: '20px', fontSize: '16px' }}>Incident Evidence</h3>
                    {artifacts.length === 0 ? (
                        <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)', border: '1px dashed var(--border-color)', borderRadius: '8px' }}>
                            No downloadable flagged files linked to this incident yet.
                        </div>
                    ) : (
                        <div style={{ display: 'grid', gap: '10px' }}>
                            {artifacts.map((a, i) => (
                                <div key={a.artifact_id || i} style={{ borderBottom: '1px solid var(--border-color)', padding: '12px 0' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px', marginBottom: '4px' }}>
                                        <div style={{ color: 'var(--warning-text)', fontWeight: 700, fontSize: '13px' }}>{a.file_name || 'artifact.bin'}</div>
                                        <div style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{formatTimestamp(a.created_at)}</div>
                                    </div>
                                    <div style={{ color: 'var(--text-main)', fontSize: '12px' }}>
                                        Severity: {a.severity || 'unknown'} • Action: {a.action || 'review'} • Match: {a.match_reason || 'linked'}
                                    </div>
                                    <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '4px' }}>
                                        {(Array.isArray(a.findings) && a.findings.length)
                                            ? `Patterns: ${a.findings.map(f => f.pattern_name || f.description || f.category || 'match').slice(0, 6).join(', ')}`
                                            : 'No finding list'}
                                    </div>
                                    {Array.isArray(a.findings) && a.findings.some(f => (f.matched_text || '').trim()) && (
                                        <div style={{ marginTop: '8px', borderLeft: '2px solid var(--accent)', paddingLeft: '8px' }}>
                                            <div style={{ color: 'var(--link-soft)', fontSize: '11px', fontWeight: 700, marginBottom: '4px' }}>Exact Data Found</div>
                                            <div style={{ display: 'grid', gap: '6px' }}>
                                                {a.findings.filter(f => (f.matched_text || '').trim()).slice(0, 10).map((f, idx) => (
                                                    <div key={idx} style={{ fontSize: '11px', borderBottom: '1px solid var(--border-color)', paddingBottom: '4px' }}>
                                                        <div style={{ color: 'var(--warning-text)' }}>{f.pattern_name || f.description || f.category || 'match'}</div>
                                                        <div style={{ color: 'var(--text-main)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{f.matched_text}</div>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                    <div style={{ marginTop: '8px' }}>
                                        {a.is_virtual ? (
                                            <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                                                Clipboard evidence (inline matched text only)
                                            </span>
                                        ) : (
                                            <>
                                                <a
                                                    href={`${apiBase.replace(/\/api$/, '')}${a.download_url || `/api/fleet/artifacts/${encodeURIComponent(a.artifact_id)}/download`}`}
                                                    target="_blank"
                                                    rel="noreferrer"
                                                    style={{ color: 'var(--accent)', textDecoration: 'none', fontSize: '12px' }}
                                                >
                                                    Download flagged file ↗
                                                </a>
                                                <a
                                                    href={`${apiBase.replace(/\/api$/, '')}/api/fleet/artifacts/${encodeURIComponent(a.artifact_id)}/view`}
                                                    target="_blank"
                                                    rel="noreferrer"
                                                    style={{ color: 'var(--link-soft)', textDecoration: 'none', fontSize: '12px', marginLeft: '10px' }}
                                                >
                                                    Open inline ↗
                                                </a>
                                                <button
                                                    className="btn"
                                                    onClick={() => loadArtifactContent(a.artifact_id)}
                                                    style={{ marginLeft: '10px', fontSize: '11px', padding: '4px 10px' }}
                                                >
                                                    {artifactLoading[a.artifact_id] ? 'Loading...' : (artifactContent[a.artifact_id] ? 'Hide Content' : 'View Exact Content')}
                                                </button>
                                            </>
                                        )}
                                    </div>
                                    {artifactContent[a.artifact_id] && (
                                        <div style={{ marginTop: '8px' }}>
                                            {artifactContent[a.artifact_id].error ? (
                                                <div style={{ color: 'var(--danger)', fontSize: '12px' }}>{artifactContent[a.artifact_id].error}</div>
                                            ) : artifactContent[a.artifact_id].is_text ? (
                                                <pre style={{
                                                    background: 'var(--code-bg)', border: '1px solid var(--border-color)', borderRadius: '6px',
                                                    padding: '10px', fontSize: '11px', color: 'var(--code-text)', fontFamily: "'Fira Code', monospace",
                                                    whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: '260px', overflow: 'auto'
                                                }}>{artifactContent[a.artifact_id].content || ''}</pre>
                                            ) : (
                                                <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{artifactContent[a.artifact_id].message || 'Binary file. Download to inspect exact bytes.'}</div>
                                            )}
                                            {artifactContent[a.artifact_id].truncated && (
                                                <div style={{ color: 'var(--warning)', fontSize: '11px', marginTop: '4px' }}>Preview truncated. Download for full content.</div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* ── AI ANALYSIS SECTION ── */}
            {activeSection === 'ai' && parsedAi && (
                <div style={sectionCardStyle}>
                    <h3 style={{ color: 'var(--text-strong)', marginBottom: '20px', fontSize: '16px' }}>AI Threat Intelligence</h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px', marginBottom: '20px' }}>
                        {parsedAi.risk_score !== undefined && (
                            <div style={{ padding: '10px 0', borderBottom: '1px solid var(--border-color)', borderTop: '2px solid var(--danger)' }}>
                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 600, letterSpacing: '1px', marginBottom: '4px' }}>AI RISK SCORE</div>
                                <div style={{ color: riskLevel(parsedAi.risk_score).color, fontSize: '28px', fontWeight: 700 }}>{parsedAi.risk_score}<span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>/100</span></div>
                            </div>
                        )}
                        {parsedAi.recommendation && (
                            <div style={{ padding: '10px 0', borderBottom: '1px solid var(--border-color)', borderTop: '2px solid var(--accent)' }}>
                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 600, letterSpacing: '1px', marginBottom: '4px' }}>AI RECOMMENDATION</div>
                                <div style={{ color: 'var(--accent)', fontSize: '16px', fontWeight: 700, textTransform: 'uppercase' }}>{parsedAi.recommendation}</div>
                            </div>
                        )}
                        {parsedAi.verdict && (
                            <div style={{ padding: '10px 0', borderBottom: '1px solid var(--border-color)', borderTop: '2px solid var(--warning)' }}>
                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 600, letterSpacing: '1px', marginBottom: '4px' }}>AI VERDICT</div>
                                <div style={{ color: 'var(--warning)', fontSize: '16px', fontWeight: 700 }}>{parsedAi.verdict}</div>
                            </div>
                        )}
                    </div>
                    {parsedAi.reasoning && (
                        <div style={{ marginBottom: '16px' }}>
                            <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 600, letterSpacing: '0.5px', marginBottom: '6px' }}>REASONING</div>
                            <div style={{
                                borderBottom: '1px solid var(--border-color)',
                                padding: '14px', color: 'var(--text-main)', fontSize: '13px', lineHeight: '1.6'
                            }}>{parsedAi.reasoning}</div>
                        </div>
                    )}
                    {/* Render any other AI fields */}
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 600, letterSpacing: '0.5px', marginBottom: '6px' }}>FULL AI RESPONSE</div>
                    <pre style={{
                        background: 'var(--code-bg)', border: '1px solid var(--border-color)', borderRadius: '6px',
                        padding: '12px', fontSize: '11px', color: 'var(--code-text)', fontFamily: "'Fira Code', monospace",
                        whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowWrap: 'anywhere', maxHeight: '300px', overflow: 'auto'
                    }}>{JSON.stringify(parsedAi, null, 2)}</pre>
                </div>
            )}

                    {/* ── RAW LOG SECTION ── */}
                    {activeSection === 'raw' && (
                        <div style={sectionCardStyle}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                        <h3 style={{ color: 'var(--text-strong)', fontSize: '16px', margin: 0 }}>{'{ }'} Raw Incident Log</h3>
                        <button className="btn" style={{ fontSize: '12px', padding: '4px 12px' }}
                            onClick={() => { navigator.clipboard.writeText(JSON.stringify(incident, null, 2)); }}>
                            Copy JSON
                        </button>
                    </div>
                    <pre style={{
                        background: 'var(--code-bg)', border: '1px solid var(--border-color)', borderRadius: '8px',
                        padding: '16px', fontSize: '12px', color: 'var(--code-text)',
                        fontFamily: "'Fira Code', 'JetBrains Mono', 'Courier New', monospace",
                        whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowWrap: 'anywhere', maxHeight: '500px', overflow: 'auto',
                        lineHeight: '1.6'
                    }}>{JSON.stringify(incident, null, 2)}</pre>

                    {events.length > 0 && (
                        <>
                            <h4 style={{ color: 'var(--text-strong)', fontSize: '14px', marginTop: '24px', marginBottom: '12px' }}>Linked Event Logs ({events.length})</h4>
                            {events.map((evt, i) => (
                                <div key={evt.event_id || i} style={{ marginBottom: '12px' }}>
                                    <div style={{ color: 'var(--accent)', fontSize: '12px', fontFamily: 'monospace', marginBottom: '4px' }}>{evt.event_id}</div>
                                    <pre style={{
                                        background: 'var(--code-bg)', border: '1px solid var(--border-color)', borderRadius: '6px',
                                        padding: '12px', fontSize: '11px', color: 'var(--code-text)',
                                        fontFamily: "'Fira Code', monospace", whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowWrap: 'anywhere',
                                        maxHeight: '200px', overflow: 'auto'
                                    }}>{JSON.stringify(evt, null, 2)}</pre>
                                </div>
                            ))}
                        </>
                    )}
                        </div>
                    )}
                </div>

                <div ref={actionsPanelRef} style={{ order: isCompactLayout ? 1 : 2, minWidth: 0, position: isCompactLayout ? 'static' : 'sticky', top: isCompactLayout ? 'auto' : '12px', alignSelf: 'start', zIndex: 1 }}>
                    <div style={sectionCardStyle}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                            <h3 style={{ color: 'var(--text-strong)', margin: 0, fontSize: '16px' }}>Incident Actions</h3>
                            {isCompactLayout && (
                                <button
                                    className="btn"
                                    onClick={() => setShowActionsPanel((v) => !v)}
                                    style={{ fontSize: '11px', padding: '4px 10px' }}
                                >
                                    {showActionsPanel ? 'Collapse' : 'Expand'}
                                </button>
                            )}
                        </div>

                        {!backendConnected && (
                            <div style={{ color: 'var(--danger)', fontSize: '12px', marginBottom: '10px' }}>
                                Backend action API unavailable. Verify server is running on {apiBase}.
                            </div>
                        )}

                        {(!isCompactLayout || showActionsPanel) && (
                            <div style={{ maxHeight: isCompactLayout ? 'none' : 'calc(100vh - 180px)', overflowY: isCompactLayout ? 'visible' : 'auto', paddingRight: isCompactLayout ? 0 : '4px' }}>

                        <div style={{ display: 'grid', gap: '8px', marginBottom: '12px', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
                            <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700 }}>Status</div>
                            <div style={{ color: 'var(--text-strong)', fontSize: '13px' }}>{incident.status}</div>
                            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Opened {formatTimestamp(incident.created_at)}</div>
                            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Owner: {incident.assigned_to || 'UNASSIGNED'}</div>
                        </div>

                        <div style={{ marginBottom: '12px' }}>
                            <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, marginBottom: '6px' }}>Assign owner</div>
                            <div style={{ display: 'grid', gap: '6px' }}>
                                <select value={assignedTo} onChange={(e) => setAssignedTo(e.target.value)} style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }}>
                                    <option value="">Choose security team member</option>
                                    {securityTeam.map(m => (
                                        <option key={m.member_id} value={m.email}>{m.display_name} ({m.email})</option>
                                    ))}
                                </select>
                                <button className="btn" onClick={handleAssign} disabled={workflowLoading || !assignedTo}>Assign</button>
                            </div>
                        </div>

                        <div style={{ marginBottom: '12px' }}>
                            <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, marginBottom: '6px' }}>Close workflow</div>
                            <div style={{ display: 'grid', gap: '6px' }}>
                                <select value={classification} onChange={(e) => setClassification(e.target.value)} style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }}>
                                    <option value="TRUE_POSITIVE">TRUE_POSITIVE</option>
                                    <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                                    <option value="FALSE_NEGATIVE">FALSE_NEGATIVE</option>
                                    <option value="BENIGN_POSITIVE">BENIGN_POSITIVE</option>
                                </select>
                                <textarea
                                    value={initialStatement}
                                    onChange={(e) => setInitialStatement(e.target.value)}
                                    placeholder="Initial statement (required)"
                                    style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '6px', fontSize: '12px', padding: '8px', minHeight: '60px' }}
                                />
                                <textarea
                                    value={finalStatement}
                                    onChange={(e) => setFinalStatement(e.target.value)}
                                    placeholder="Final closure statement (required)"
                                    style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '6px', fontSize: '12px', padding: '8px', minHeight: '60px' }}
                                />
                                <button className="btn" onClick={handleCloseWorkflow} disabled={workflowLoading || incident.status !== 'OPEN'} style={{ background: 'var(--surface-subtle)', color: 'var(--success)', border: '1px solid var(--success)' }}>
                                    {workflowLoading ? 'Processing...' : 'Close Incident'}
                                </button>
                            </div>
                        </div>

                        <div style={{ marginBottom: '12px' }}>
                            <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, marginBottom: '6px' }}>Add activity log</div>
                            <div style={{ display: 'grid', gap: '6px' }}>
                                <select value={logStage} onChange={(e) => setLogStage(e.target.value)} style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }}>
                                    <option value="comment">comment</option>
                                    <option value="initial">initial</option>
                                    <option value="final">final</option>
                                    <option value="update">update</option>
                                    <option value="assignment">assignment</option>
                                </select>
                                <textarea
                                    value={logNote}
                                    onChange={(e) => setLogNote(e.target.value)}
                                    placeholder="Activity log note"
                                    style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '6px', fontSize: '12px', padding: '8px', minHeight: '60px' }}
                                />
                                <button className="btn" onClick={handleAddActivityLog} disabled={workflowLoading || !logNote.trim()}>Add Log</button>
                            </div>
                        </div>

                        {workflowMessage && <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '10px' }}>{workflowMessage}</div>}

                        <div>
                            <div style={{ color: 'var(--text-strong)', fontSize: '13px', fontWeight: 600, marginBottom: '8px' }}>Activity Timeline</div>
                            {activityLogs.length === 0 ? (
                                <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>No activity logs yet.</div>
                            ) : (
                                <div style={{ display: 'grid', gap: '8px', maxHeight: '280px', overflow: 'auto' }}>
                                    {activityLogs.map((log, idx) => (
                                        <div key={`${log.id || idx}`} style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px' }}>
                                                <div style={{ color: 'var(--link-soft)', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase' }}>{log.stage || 'update'}</div>
                                                <div style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{formatTimestamp(log.created_at)}</div>
                                            </div>
                                            <div style={{ color: 'var(--text-main)', fontSize: '12px', marginTop: '4px', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{log.note}</div>
                                            <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '2px' }}>{log.actor || 'system'}</div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default EventDetail;
