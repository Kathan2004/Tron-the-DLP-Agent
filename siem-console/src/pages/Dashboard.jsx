import React from 'react';

const Dashboard = ({ stats, incidents, onSelectIncident, apiBase, onIncidentsChanged, currentUser }) => {
    const [currentPage, setCurrentPage] = React.useState(1);
    const [pageSize, setPageSize] = React.useState(10);
    const [autoPageSize, setAutoPageSize] = React.useState(true);
    const [timeFilter, setTimeFilter] = React.useState('all');
    const [statusFilter, setStatusFilter] = React.useState('all');
    const [riskFilter, setRiskFilter] = React.useState('all');
    const [userFilter, setUserFilter] = React.useState('');
    const [hostFilter, setHostFilter] = React.useState('');
    const [selectedIds, setSelectedIds] = React.useState([]);
    const [securityTeam, setSecurityTeam] = React.useState([]);
    const [assignee, setAssignee] = React.useState('');
    const [actor, setActor] = React.useState(currentUser?.email || 'soc.analyst1@tron.local');
    const [classification, setClassification] = React.useState('TRUE_POSITIVE');
    const [initialStatement, setInitialStatement] = React.useState('');
    const [finalStatement, setFinalStatement] = React.useState('');
    const [bulkLoading, setBulkLoading] = React.useState(false);
    const [bulkMessage, setBulkMessage] = React.useState('');
    const [showQueueSidebar, setShowQueueSidebar] = React.useState(false);
    const [sortKey, setSortKey] = React.useState('created_at');
    const [sortDirection, setSortDirection] = React.useState('desc');
    const tableViewportRef = React.useRef(null);
    const role = String(currentUser?.role || 'VIEWER').toUpperCase();
    const canAssign = role === 'SUPER_ADMIN' || role === 'SECURITY_ADMIN' || role === 'SOC_ANALYST';
    const canEscalate = role === 'SUPER_ADMIN' || role === 'SECURITY_ADMIN' || role === 'SOC_ANALYST';
    const canRaiseTicket = role === 'SUPER_ADMIN' || role === 'SECURITY_ADMIN' || role === 'SOC_ANALYST';
    const canClose = role === 'SUPER_ADMIN' || role === 'SECURITY_ADMIN' || role === 'SOC_ANALYST';
    const canReopen = role === 'SUPER_ADMIN' || role === 'SECURITY_ADMIN' || role === 'SOC_ANALYST';
    
    const inTimeWindow = (ts) => {
        if (timeFilter === 'all') return true;
        const dt = new Date(ts);
        if (Number.isNaN(dt.getTime())) return false;
        const now = Date.now();
        const diff = now - dt.getTime();
        if (timeFilter === '1h') return diff <= 60 * 60 * 1000;
        if (timeFilter === '24h') return diff <= 24 * 60 * 60 * 1000;
        if (timeFilter === '7d') return diff <= 7 * 24 * 60 * 60 * 1000;
        if (timeFilter === '30d') return diff <= 30 * 24 * 60 * 60 * 1000;
        return true;
    };

    const getIncidentSeverity = (inc) => {
        const sev = String(inc.severity || '').toUpperCase();
        if (sev === 'CRITICAL' || sev === 'HIGH' || sev === 'MEDIUM' || sev === 'LOW') return sev;
        const risk = Number(inc.risk || 0);
        if (risk >= 80) return 'CRITICAL';
        if (risk >= 60) return 'HIGH';
        if (risk >= 40) return 'MEDIUM';
        return 'LOW';
    };

    const filteredIncidents = incidents.filter((inc) => {
        if (!inTimeWindow(inc.created_at)) return false;
        if (statusFilter !== 'all') {
            const st = String(inc.status || '').toUpperCase();
            const normalized = st === 'AUTO-CLOSED' ? 'CLOSED' : st;
            if (normalized !== statusFilter) return false;
        }
        if (riskFilter !== 'all') {
            const sev = getIncidentSeverity(inc).toLowerCase();
            if (sev !== riskFilter) return false;
        }
        if (userFilter && !(inc.user || '').toLowerCase().includes(userFilter.toLowerCase())) return false;
        if (hostFilter && !(inc.host || '').toLowerCase().includes(hostFilter.toLowerCase())) return false;
        return true;
    });

    const parseSortableTime = (value) => {
        if (!value) return 0;
        const raw = String(value);
        const normalized = raw.includes('T') ? raw : raw.replace(' ', 'T') + 'Z';
        const ts = new Date(normalized).getTime();
        return Number.isNaN(ts) ? 0 : ts;
    };

    const sortedIncidents = React.useMemo(() => {
        const list = [...filteredIncidents];
        const direction = sortDirection === 'asc' ? 1 : -1;
        const severityRank = (inc) => ({ LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[getIncidentSeverity(inc)] || 1);

        list.sort((a, b) => {
            let av;
            let bv;

            switch (sortKey) {
                case 'incident_id':
                    av = String(a.incident_id || '');
                    bv = String(b.incident_id || '');
                    break;
                case 'host':
                    av = String(a.host || '').toLowerCase();
                    bv = String(b.host || '').toLowerCase();
                    break;
                case 'user':
                    av = String(a.user || '').toLowerCase();
                    bv = String(b.user || '').toLowerCase();
                    break;
                case 'pattern':
                    av = String(a.pattern || '').toLowerCase();
                    bv = String(b.pattern || '').toLowerCase();
                    break;
                case 'risk':
                    av = severityRank(a) * 1000 + Number(a.risk || 0);
                    bv = severityRank(b) * 1000 + Number(b.risk || 0);
                    break;
                case 'severity':
                    av = severityRank(a);
                    bv = severityRank(b);
                    break;
                case 'status':
                    av = String(a.status || '').toUpperCase();
                    bv = String(b.status || '').toUpperCase();
                    break;
                case 'assigned_to':
                    av = String(a.assigned_to || '').toLowerCase();
                    bv = String(b.assigned_to || '').toLowerCase();
                    break;
                case 'classification':
                    av = String(a.classification || 'NOT_SET').toUpperCase();
                    bv = String(b.classification || 'NOT_SET').toUpperCase();
                    break;
                case 'updated_at':
                    av = parseSortableTime(a.updated_at || a.created_at);
                    bv = parseSortableTime(b.updated_at || b.created_at);
                    break;
                case 'created_at':
                default:
                    av = parseSortableTime(a.created_at);
                    bv = parseSortableTime(b.created_at);
                    break;
            }

            if (av < bv) return -1 * direction;
            if (av > bv) return 1 * direction;
            return 0;
        });

        return list;
    }, [filteredIncidents, sortDirection, sortKey]);

    const handleSort = (key) => {
        setCurrentPage(1);
        if (sortKey === key) {
            setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
            return;
        }
        setSortKey(key);
        setSortDirection(key === 'created_at' || key === 'updated_at' || key === 'risk' ? 'desc' : 'asc');
    };

    const sortIndicator = (key) => {
        if (sortKey !== key) return '↕';
        return sortDirection === 'asc' ? '↑' : '↓';
    };

    const totalPages = Math.ceil(sortedIncidents.length / pageSize);
    const startIndex = (currentPage - 1) * pageSize;
    const pagedIncidents = sortedIncidents.slice(startIndex, startIndex + pageSize);
    const visibleIds = React.useMemo(() => pagedIncidents.map(i => i.incident_id), [pagedIncidents]);
    const allVisibleSelected = visibleIds.length > 0 && visibleIds.every(id => selectedIds.includes(id));
    const selectedIncidents = React.useMemo(() => {
        const set = new Set(selectedIds);
        return incidents.filter(i => set.has(i.incident_id));
    }, [incidents, selectedIds]);
    const selectedStatuses = React.useMemo(() => new Set(selectedIncidents.map(i => String(i.status || '').trim().toUpperCase())), [selectedIncidents]);
    const closeEligibleIds = React.useMemo(
        () => selectedIncidents
            .filter(i => {
                const s = String(i.status || '').trim().toUpperCase();
                return s === 'OPEN' || s === 'ESCALATED';
            })
            .map(i => i.incident_id),
        [selectedIncidents]
    );
    const escalateEligibleIds = React.useMemo(
        () => selectedIncidents
            .filter(i => {
                const s = String(i.status || '').trim().toUpperCase();
                return s === 'OPEN';
            })
            .map(i => i.incident_id),
        [selectedIncidents]
    );
    const ticketEligibleIds = React.useMemo(
        () => selectedIncidents
            .filter(i => {
                const s = String(i.status || '').trim().toUpperCase();
                return s === 'OPEN' || s === 'ESCALATED';
            })
            .map(i => i.incident_id),
        [selectedIncidents]
    );
    const reopenEligibleIds = React.useMemo(
        () => selectedIncidents
            .filter(i => {
                const s = String(i.status || '').trim().toUpperCase();
                return s === 'CLOSED' || s === 'AUTO-CLOSED' || s === 'TICKET_RAISED';
            })
            .map(i => i.incident_id),
        [selectedIncidents]
    );
    const canReopenSelection = reopenEligibleIds.length > 0;
    const canEscalateSelection = escalateEligibleIds.length > 0;
    const canRaiseTicketSelection = ticketEligibleIds.length > 0;
    const canCloseSelection = closeEligibleIds.length > 0;
    const selectedCount = selectedIds.length;

    const fmt = (ts) => {
        if (!ts) return '—';
        const d = new Date(String(ts).replace(' ', 'T') + (String(ts).includes('T') ? '' : 'Z'));
        if (Number.isNaN(d.getTime())) return String(ts);
        return d.toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
    };

    const isInteractiveRowTarget = (target) => {
        if (!target || typeof target.closest !== 'function') return false;
        return !!target.closest('a, button, input, select, textarea, label, [role="button"], [data-row-ignore-click="true"]');
    };

    const incidentHref = (incidentId) => `${window.location.pathname}#/incident/${encodeURIComponent(incidentId)}`;

    const openIncidentInNewTab = (incidentId) => {
        window.open(incidentHref(incidentId), '_blank', 'noopener,noreferrer');
    };

    const handleIncidentRowClick = (e, incidentId) => {
        if (!incidentId || isInteractiveRowTarget(e.target)) return;
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
            e.preventDefault();
            openIncidentInNewTab(incidentId);
            return;
        }
        onSelectIncident && onSelectIncident(incidentId);
    };

    const handleIncidentRowAuxClick = (e, incidentId) => {
        if (!incidentId || e.button !== 1 || isInteractiveRowTarget(e.target)) return;
        e.preventDefault();
        openIncidentInNewTab(incidentId);
    };

    React.useEffect(() => {
        setActor(currentUser?.email || 'soc.analyst1@tron.local');
    }, [currentUser?.email]);

    React.useEffect(() => {
        const loadSecurityTeam = async () => {
            if (!apiBase) return;
            try {
                const res = await fetch(`${apiBase}/security-team`);
                const data = await res.json();
                const members = data.members || [];
                setSecurityTeam(members);
                if (!assignee && members.length > 0) setAssignee(members[0].email || '');
            } catch {
                setSecurityTeam([]);
            }
        };
        loadSecurityTeam();
    }, [apiBase]);

    React.useEffect(() => {
        if (!autoPageSize) return;

        const computeFitSize = () => {
            const el = tableViewportRef.current;
            if (!el) return;

            const viewportHeight = el.clientHeight || 0;
            const headerAllowance = 44; // sticky header row
            const rowHeight = 52; // incident row average
            const fit = Math.max(5, Math.floor((viewportHeight - headerAllowance) / rowHeight));
            if (fit > 0) {
                setPageSize(prev => (prev === fit ? prev : fit));
            }
        };

        computeFitSize();
        window.addEventListener('resize', computeFitSize);
        return () => window.removeEventListener('resize', computeFitSize);
    }, [autoPageSize, incidents.length]);

    React.useEffect(() => {
        const safeTotal = Math.max(1, totalPages || 1);
        setCurrentPage(prev => Math.min(prev, safeTotal));
    }, [totalPages]);

    React.useEffect(() => {
        setCurrentPage(1);
    }, [timeFilter, statusFilter, riskFilter, userFilter, hostFilter]);

    React.useEffect(() => {
        const valid = new Set(incidents.map(i => i.incident_id));
        setSelectedIds(prev => prev.filter(id => valid.has(id)));
    }, [incidents]);

    React.useEffect(() => {
        setBulkMessage('');
    }, [selectedIds]);

    const toggleSelectAllVisible = () => {
        if (allVisibleSelected) {
            setSelectedIds(prev => prev.filter(id => !visibleIds.includes(id)));
            return;
        }
        setSelectedIds(prev => Array.from(new Set([...prev, ...visibleIds])));
    };

    const toggleOne = (id) => {
        setSelectedIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
    };

    const runBulkAction = async (payload, targetIds = selectedIds) => {
        if (!apiBase || !targetIds || targetIds.length === 0) {
            setBulkMessage('No eligible incidents selected for this action.');
            return;
        }
        setBulkLoading(true);
        setBulkMessage('');
        try {
            const res = await fetch(`${apiBase}/incidents/bulk-action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ incident_ids: targetIds, actor, ...payload }),
            });
            const data = await res.json();
            if (!res.ok) {
                setBulkMessage(data.error || 'Bulk action failed.');
            } else {
                const failed = Array.isArray(data.failed) ? data.failed : [];
                const failedPreview = failed.slice(0, 2).map(f => `${f.incident_id}: ${f.error}`).join(' | ');
                const integ = data.integrations || {};
                const integBits = [];
                if (typeof integ.slack_sent === 'number' && typeof integ.slack_failed === 'number' && typeof integ.slack_unconfigured === 'number') {
                    integBits.push(`Slack sent:${integ.slack_sent} failed:${integ.slack_failed} unconfigured:${integ.slack_unconfigured}`);
                }
                if (typeof integ.jira_created === 'number' && typeof integ.jira_failed === 'number' && typeof integ.jira_unconfigured === 'number') {
                    integBits.push(`Jira created:${integ.jira_created} failed:${integ.jira_failed} unconfigured:${integ.jira_unconfigured}`);
                }
                setBulkMessage(
                    `${data.updated_count || 0} updated, ${data.failed_count || 0} failed.` +
                    (failedPreview ? ` ${failedPreview}` : '') +
                    (integBits.length ? ` ${integBits.join(' | ')}` : '')
                );
                setSelectedIds([]);
                setShowQueueSidebar(false);
                setAssignee('');
                setInitialStatement('');
                setFinalStatement('');
                if (typeof onIncidentsChanged === 'function') await onIncidentsChanged();
            }
        } catch {
            setBulkMessage('Bulk action failed.');
        }
        setBulkLoading(false);
    };

    if (!stats) return <div style={{ padding: '40px', color: 'var(--text-muted)' }}>Initializing command center...</div>;

    return (
        <>
        <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 120px)' }}>
            <div className="stats-grid" style={{ marginBottom: '24px', flexShrink: 0 }}>
                <div className="stat-card" style={{ borderTop: '3px solid var(--danger)', padding: '20px' }}>
                    <div className="stat-title">CRITICAL INCIDENTS</div>
                    <div className="stat-value">{stats.total_incidents}</div>
                </div>
                <div className="stat-card" style={{ borderTop: '3px solid var(--warning)', padding: '20px' }}>
                    <div className="stat-title">ESCALATED</div>
                    <div className="stat-value">{stats.escalated}</div>
                </div>
                <div className="stat-card" style={{ borderTop: '3px solid var(--accent)', padding: '20px' }}>
                    <div className="stat-title">EVENTS SCANNED (24H)</div>
                    <div className="stat-value">{stats.events_24h}</div>
                </div>
                <div className="stat-card" style={{ borderTop: '3px solid var(--success)', padding: '20px' }}>
                    <div className="stat-title">AVG RISK SCORE</div>
                    <div className="stat-value">{stats.avg_risk} / 100</div>
                </div>
            </div>

            {/* Clean flat table without nested borders */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-strong)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span>[ ]</span> Incidents Log
                    </h2>
                    <span style={{ fontSize: '12px', color: 'var(--accent)', fontWeight: 600 }}>{sortedIncidents.length} Filtered / {incidents.length} Total</span>
                </div>

                <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                    <select value={timeFilter} onChange={(e) => setTimeFilter(e.target.value)} style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }}>
                        <option value="all">Time: All</option>
                        <option value="1h">Last 1 hour</option>
                        <option value="24h">Last 24 hours</option>
                        <option value="7d">Last 7 days</option>
                        <option value="30d">Last 30 days</option>
                    </select>
                    <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }}>
                        <option value="all">Status: All</option>
                        <option value="OPEN">OPEN</option>
                        <option value="ESCALATED">ESCALATED</option>
                        <option value="CLOSED">CLOSED</option>
                        <option value="TICKET_RAISED">TICKET_RAISED</option>
                    </select>
                    <select value={riskFilter} onChange={(e) => setRiskFilter(e.target.value)} style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }}>
                        <option value="all">Risk: All</option>
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                    </select>
                    <input value={userFilter} onChange={(e) => setUserFilter(e.target.value)} placeholder="Filter user" style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }} />
                    <input value={hostFilter} onChange={(e) => setHostFilter(e.target.value)} placeholder="Filter host" style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }} />
                </div>

                <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Selected incidents: <span style={{ color: 'var(--text-strong)', fontWeight: 700 }}>{selectedIds.length}</span></div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                        <button className="btn" onClick={() => setShowQueueSidebar(true)} disabled={selectedIds.length === 0}>Queue Actions</button>
                        <button className="btn" onClick={() => setSelectedIds([])} disabled={selectedIds.length === 0}>Clear</button>
                    </div>
                </div>

                {/* Clean table without extra container styling */}
                <div ref={tableViewportRef} style={{ flex: 1, overflowY: 'auto', overflowX: 'auto' }}>
                    <table style={{ borderCollapse: 'separate', borderSpacing: 0, width: '100%', background: 'var(--table-bg)' }}>
                        <thead style={{ position: 'sticky', top: 0, zIndex: 1, background: 'var(--table-head-bg)' }}>
                            <tr>
                                <th style={{ padding: '12px 10px', borderBottom: '1px solid var(--border-color)', textAlign: 'center' }}><input type="checkbox" checked={allVisibleSelected} onChange={toggleSelectAllVisible} /></th>
                                <th onClick={() => handleSort('incident_id')} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', textAlign: 'left', fontWeight: 500, cursor: 'pointer', userSelect: 'none' }}>ID {sortIndicator('incident_id')}</th>
                                <th onClick={() => handleSort('host')} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', textAlign: 'left', fontWeight: 500, cursor: 'pointer', userSelect: 'none' }}>Host {sortIndicator('host')}</th>
                                <th onClick={() => handleSort('user')} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', textAlign: 'left', fontWeight: 500, cursor: 'pointer', userSelect: 'none' }}>User {sortIndicator('user')}</th>
                                <th onClick={() => handleSort('pattern')} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', textAlign: 'left', width: '30%', fontWeight: 500, cursor: 'pointer', userSelect: 'none' }}>Violation Details {sortIndicator('pattern')}</th>
                                <th onClick={() => handleSort('risk')} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', textAlign: 'center', fontWeight: 500, cursor: 'pointer', userSelect: 'none' }}>AI Risk {sortIndicator('risk')}</th>
                                <th onClick={() => handleSort('severity')} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', textAlign: 'left', fontWeight: 500, cursor: 'pointer', userSelect: 'none' }}>Severity {sortIndicator('severity')}</th>
                                <th onClick={() => handleSort('status')} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', textAlign: 'left', fontWeight: 500, cursor: 'pointer', userSelect: 'none' }}>Status {sortIndicator('status')}</th>
                                <th onClick={() => handleSort('assigned_to')} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', textAlign: 'left', fontWeight: 500, cursor: 'pointer', userSelect: 'none' }}>Assignee {sortIndicator('assigned_to')}</th>
                                <th onClick={() => handleSort('classification')} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', textAlign: 'left', fontWeight: 500, cursor: 'pointer', userSelect: 'none' }}>Classification {sortIndicator('classification')}</th>
                                <th onClick={() => handleSort('created_at')} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', textAlign: 'left', fontWeight: 500, cursor: 'pointer', userSelect: 'none' }}>Created {sortIndicator('created_at')}</th>
                                <th onClick={() => handleSort('updated_at')} style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', textAlign: 'left', fontWeight: 500, cursor: 'pointer', userSelect: 'none' }}>Updated {sortIndicator('updated_at')}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {pagedIncidents.map((inc) => (
                                <tr
                                    key={inc.incident_id}
                                    style={{ transition: 'background 0.15s', borderBottom: '1px solid var(--table-row-border)', cursor: 'pointer' }}
                                    onClick={(e) => handleIncidentRowClick(e, inc.incident_id)}
                                    onAuxClick={(e) => handleIncidentRowAuxClick(e, inc.incident_id)}
                                    onMouseOver={(e) => { e.currentTarget.style.background = 'var(--surface-subtle)'; }}
                                    onMouseOut={(e) => { e.currentTarget.style.background = 'transparent'; }}
                                >
                                    <td style={{ padding: '12px 10px', textAlign: 'center' }}>
                                        <input
                                            type="checkbox"
                                            checked={selectedIds.includes(inc.incident_id)}
                                            onClick={(e) => e.stopPropagation()}
                                            onChange={() => toggleOne(inc.incident_id)}
                                        />
                                    </td>
                                    <td style={{ padding: '12px 16px' }}>
                                        <a
                                            href={incidentHref(inc.incident_id)}
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                // Keep SPA behavior on normal left click.
                                                if (e.button === 0 && !(e.metaKey || e.ctrlKey || e.shiftKey || e.altKey)) {
                                                    e.preventDefault();
                                                    onSelectIncident && onSelectIncident(inc.incident_id);
                                                }
                                            }}
                                            style={{
                                                color: 'var(--accent)', fontWeight: 600, cursor: 'pointer', textDecoration: 'none',
                                                fontSize: '12px', padding: '4px 9px', background: 'var(--id-chip-bg)', borderRadius: '4px', border: '1px solid var(--id-chip-border)'
                                            }}
                                            onMouseOver={e => e.currentTarget.style.background = 'var(--chip-accent-bg-hover)'}
                                            onMouseOut={e => e.currentTarget.style.background = 'var(--id-chip-bg)'}
                                        >
                                            {inc.incident_id.replace('INC-', '')}
                                        </a>
                                    </td>
                                    <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--table-row-border)', color: 'var(--text-main)', fontSize: '12px' }}>{inc.host}</td>
                                    <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--table-row-border)', color: 'var(--text-main)', fontSize: '12px' }}>{inc.user}</td>
                                    <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--table-row-border)', fontSize: '12px', wordBreak: 'break-all', color: 'var(--text-main)', lineHeight: '1.45' }}>
                                        {inc.pattern}
                                    </td>
                                    <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--table-row-border)', textAlign: 'center' }}>
                                        <span style={{ 
                                            padding: '4px 10px', borderRadius: '4px', fontSize: '10px', fontWeight: 700,
                                            background: inc.risk > 80 ? 'rgba(248, 81, 73, 0.15)' : 'rgba(88, 166, 255, 0.15)',
                                            color: inc.risk > 80 ? 'var(--danger)' : 'var(--accent)',
                                            display: 'inline-block'
                                        }}>{inc.risk} / 100</span>
                                    </td>
                                    <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--table-row-border)' }}>
                                        <span style={{
                                            fontSize: '11px',
                                            fontWeight: 700,
                                            color: getIncidentSeverity(inc) === 'CRITICAL' ? 'var(--danger)' : getIncidentSeverity(inc) === 'HIGH' ? 'var(--warning)' : getIncidentSeverity(inc) === 'MEDIUM' ? 'var(--accent)' : 'var(--text-muted)'
                                        }}>
                                            {getIncidentSeverity(inc)}
                                        </span>
                                    </td>
                                    <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--table-row-border)' }}>
                                        <span style={{ fontSize: '12px', fontWeight: 600, color: inc.status === 'ESCALATED' ? 'var(--danger)' : 'var(--text-main)' }}>
                                            {String(inc.status || '').toUpperCase() === 'AUTO-CLOSED' ? 'CLOSED' : inc.status}
                                        </span>
                                    </td>
                                    <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--table-row-border)', color: 'var(--text-main)', fontSize: '12px' }}>{inc.assigned_to || 'UNASSIGNED'}</td>
                                    <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--table-row-border)', color: 'var(--text-main)', fontSize: '12px' }}>{inc.classification || 'NOT_SET'}</td>
                                    <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--table-row-border)', color: 'var(--text-main)', fontSize: '12px', whiteSpace: 'nowrap' }}>{fmt(inc.created_at)}</td>
                                    <td style={{ padding: '12px 16px', borderBottom: '1px solid var(--table-row-border)', color: 'var(--text-main)', fontSize: '12px', whiteSpace: 'nowrap' }}>{fmt(inc.updated_at)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {sortedIncidents.length === 0 && <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>No incidents match current filters.</div>}
                </div>

                {/* Footer fixed to the bottom */}
                {sortedIncidents.length > 0 && (
                    <div style={{ flexShrink: 0, display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 20px', borderTop: '1px solid var(--border-color)' }}>
                        <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                            Showing {startIndex + 1}—{Math.min(startIndex + pageSize, sortedIncidents.length)} of {sortedIncidents.length}
                        </div>
                        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Rows:</span>
                                <select 
                                    value={pageSize} 
                                    onChange={(e) => {
                                        setAutoPageSize(false);
                                        setPageSize(Number(e.target.value));
                                        setCurrentPage(1);
                                    }}
                                    style={{
                                        background: 'var(--input-bg)', border: '1px solid var(--border-color)',
                                        color: 'var(--text-strong)', fontSize: '12px', borderRadius: '4px', padding: '4px 8px'
                                    }}
                                >
                                    {[10, 20, 50, 100].map(v => <option key={v} value={v}>{v}</option>)}
                                </select>
                            </div>
                            
                            <div style={{ display: 'flex', gap: '6px' }}>
                                <button 
                                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                                    disabled={currentPage === 1}
                                    style={{
                                        padding: '4px 10px', background: 'var(--input-bg)', border: '1px solid var(--border-color)',
                                        color: 'var(--text-strong)', borderRadius: '4px', cursor: currentPage === 1 ? 'not-allowed' : 'pointer', opacity: currentPage === 1 ? 0.4 : 1
                                    }}
                                >
                                    ‹
                                </button>
                                <span style={{ color: 'var(--text-strong)', fontSize: '13px', display: 'flex', alignItems: 'center', minWidth: '80px', justifyContent: 'center' }}>
                                    {currentPage} / {totalPages || 1}
                                </span>
                                <button 
                                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                                    disabled={currentPage === totalPages || totalPages === 0}
                                    style={{
                                        padding: '4px 10px', background: 'var(--input-bg)', border: '1px solid var(--border-color)',
                                        color: 'var(--text-strong)', borderRadius: '4px', cursor: (currentPage === totalPages || totalPages === 0) ? 'not-allowed' : 'pointer', opacity: (currentPage === totalPages || totalPages === 0) ? 0.4 : 1
                                    }}
                                >
                                    ›
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>

            {showQueueSidebar && (
                <>
                    <div
                        onClick={() => setShowQueueSidebar(false)}
                        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.35)', zIndex: 40 }}
                    />
                    <div style={{
                        position: 'fixed', top: 0, right: 0, height: '100vh', width: '380px', maxWidth: '92vw',
                        background: 'var(--panel-bg)', borderLeft: '1px solid var(--border-color)', zIndex: 41,
                        display: 'flex', flexDirection: 'column', boxShadow: '-6px 0 24px rgba(0,0,0,0.18)'
                    }}>
                        <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--surface-subtle)' }}>
                            <div>
                                <div style={{ color: 'var(--text-strong)', fontWeight: 700 }}>Queue Actions</div>
                                <div style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{selectedIds.length} selected</div>
                            </div>
                            <button className="btn" style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => setShowQueueSidebar(false)}>Close</button>
                        </div>
                        <div style={{ padding: '12px 16px', overflowY: 'auto', display: 'grid', gap: '10px' }}>
                            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Acting on {selectedCount} {selectedCount === 1 ? 'incident' : 'incidents'}</div>
                            <div style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Statuses: {selectedIncidents.length ? [...selectedStatuses].join(', ') : '—'}</div>
                            <input value={actor} onChange={(e) => setActor(e.target.value)} placeholder="actor" style={{ background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }} />

                            <div style={{ border: '1px solid var(--border-color)', borderRadius: '8px', padding: '10px' }}>
                                <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, marginBottom: '6px' }}>Ownership</div>
                                <select value={assignee} onChange={(e) => setAssignee(e.target.value)} style={{ width: '100%', background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px', marginBottom: '6px' }}>
                                    <option value="">Assign to...</option>
                                    {securityTeam.map(m => <option key={m.member_id} value={m.email}>{m.display_name} ({m.email})</option>)}
                                </select>
                                <button className="btn" disabled={!canAssign || bulkLoading || !assignee || selectedCount === 0} onClick={() => runBulkAction({ action: 'assign', assignee })}>Assign</button>
                            </div>

                            <div style={{ border: '1px solid var(--border-color)', borderRadius: '8px', padding: '10px' }}>
                                <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, marginBottom: '6px' }}>State Actions</div>
                                <div style={{ display: 'grid', gap: '6px' }}>
                                    {canEscalateSelection && (
                                        <button className="btn" disabled={!canEscalate || bulkLoading || escalateEligibleIds.length === 0} onClick={() => runBulkAction({ action: 'escalate' }, escalateEligibleIds)}>Escalate</button>
                                    )}
                                    {canRaiseTicketSelection && (
                                        <button className="btn" disabled={!canRaiseTicket || bulkLoading || ticketEligibleIds.length === 0} onClick={() => runBulkAction({ action: 'raise_ticket' }, ticketEligibleIds)}>Raise Ticket</button>
                                    )}
                                    {canReopenSelection && (
                                        <button className="btn" disabled={!canReopen || bulkLoading || reopenEligibleIds.length === 0} onClick={() => runBulkAction({ action: 'reopen' }, reopenEligibleIds)}>Reopen</button>
                                    )}
                                    {!canEscalateSelection && !canRaiseTicketSelection && !canReopenSelection && (
                                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Select incidents to see available state actions.</div>
                                    )}
                                </div>
                            </div>

                            <div style={{ border: '1px solid var(--border-color)', borderRadius: '8px', padding: '10px' }}>
                                <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, marginBottom: '6px' }}>Close Incidents</div>
                                <select value={classification} onChange={(e) => setClassification(e.target.value)} style={{ width: '100%', marginBottom: '6px', background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }}>
                                    <option value="TRUE_POSITIVE">TRUE_POSITIVE</option>
                                    <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                                    <option value="FALSE_NEGATIVE">FALSE_NEGATIVE</option>
                                    <option value="BENIGN_POSITIVE">BENIGN_POSITIVE</option>
                                </select>
                                <input value={initialStatement} onChange={(e) => setInitialStatement(e.target.value)} placeholder="Initial statement" style={{ width: '100%', marginBottom: '6px', background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }} />
                                <input value={finalStatement} onChange={(e) => setFinalStatement(e.target.value)} placeholder="Final closure statement" style={{ width: '100%', marginBottom: '6px', background: 'var(--input-bg)', color: 'var(--text-strong)', border: '1px solid var(--border-color)', borderRadius: '4px', fontSize: '12px', padding: '6px 8px' }} />
                                <button className="btn" disabled={!canClose || bulkLoading || selectedCount === 0 || !canCloseSelection || !initialStatement.trim() || !finalStatement.trim()} onClick={() => runBulkAction({ action: 'close', classification, initial_statement: initialStatement.trim(), final_statement: finalStatement.trim() }, closeEligibleIds)}>
                                    Close {selectedIds.length > 1 ? 'Selected' : 'Incident'}
                                </button>
                                {!canCloseSelection && <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '6px' }}>Close is only available for OPEN or ESCALATED incidents.</div>}
                            </div>

                            {bulkMessage && <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{bulkMessage}</div>}
                        </div>
                    </div>
                </>
            )}
            </>
    );
};

export default Dashboard;
