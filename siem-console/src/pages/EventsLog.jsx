import React, { useState, useEffect, useCallback, useRef } from 'react';

const EventsLog = ({ apiBase, onSelectEvent }) => {
    const [events, setEvents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [filterSeverity, setFilterSeverity] = useState('all');
    const [filterAgent, setFilterAgent] = useState('all');
    const [searchQuery, setSearchQuery] = useState('');
    const [autoRefresh, setAutoRefresh] = useState(true);

    const [currentPage, setCurrentPage] = useState(1);
    const [pageSize, setPageSize] = useState(15);
    const [autoPageSize, setAutoPageSize] = useState(true);
    const [timePreset, setTimePreset] = useState('all');
    const [fromTime, setFromTime] = useState('');
    const [toTime, setToTime] = useState('');
    const [sortKey, setSortKey] = useState('time');
    const [sortDirection, setSortDirection] = useState('desc');
    const tableViewportRef = useRef(null);

    const fetchEvents = useCallback(async () => {
        try {
            const res = await fetch(`${apiBase}/events?limit=1000`);
            const data = await res.json();
            setEvents(data.events || []);
        } catch (err) {
            console.error("Failed to load events:", err);
        }
        setLoading(false);
    }, [apiBase]);

    useEffect(() => {
        fetchEvents();
        let interval;
        if (autoRefresh) {
            interval = setInterval(fetchEvents, 5000);
        }
        return () => interval && clearInterval(interval);
    }, [fetchEvents, autoRefresh]);

    const severityConfig = {
        critical: { color: '#f85149', bg: 'rgba(248,81,73,0.1)', icon: 'C' },
        high: { color: '#d29922', bg: 'rgba(210,153,34,0.1)', icon: 'H' },
        medium: { color: '#58a6ff', bg: 'rgba(88,166,255,0.1)', icon: 'M' },
        low: { color: '#8b949e', bg: 'rgba(139,148,158,0.1)', icon: 'L' },
    };

    const formatTimestamp = (ts) => {
        if (!ts) return '—';
        const d = new Date(ts);
        return d.toLocaleTimeString([], { hour12: false });
    };

    const isInteractiveRowTarget = (target) => {
        if (!target || typeof target.closest !== 'function') return false;
        return !!target.closest('a, button, input, select, textarea, label, [role="button"], [data-row-ignore-click="true"]');
    };

    const eventHref = (eventId) => `${window.location.pathname}#/event/${encodeURIComponent(eventId || '')}`;

    const openEventInNewTab = (eventId) => {
        if (!eventId) return;
        window.open(eventHref(eventId), '_blank', 'noopener,noreferrer');
    };

    const handleEventRowClick = (e, eventId) => {
        if (!eventId || isInteractiveRowTarget(e.target)) return;
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
            e.preventDefault();
            openEventInNewTab(eventId);
            return;
        }
        onSelectEvent && onSelectEvent(eventId);
    };

    const handleEventRowAuxClick = (e, eventId) => {
        if (!eventId || e.button !== 1 || isInteractiveRowTarget(e.target)) return;
        e.preventDefault();
        openEventInNewTab(eventId);
    };

    const parseJson = (val) => {
        if (!val) return val;
        if (typeof val === 'object') return val;
        try { return JSON.parse(val); } catch { return val; }
    };

    const eventSearchBlob = (evt) => {
        const parts = [
            evt.event_id,
            evt.timestamp,
            evt.created_at,
            evt.user,
            evt.source_host,
            evt.host,
            evt.channel,
            evt.agent_type,
            evt.severity,
            evt.payload_sample,
            evt.payload_hash,
        ];

        const geo = parseJson(evt.geo);
        const matchedRules = parseJson(evt.matched_rules);
        const findings = parseJson(evt.findings);

        if (geo) parts.push(typeof geo === 'string' ? geo : JSON.stringify(geo));
        if (matchedRules) parts.push(typeof matchedRules === 'string' ? matchedRules : JSON.stringify(matchedRules));
        if (findings) parts.push(typeof findings === 'string' ? findings : JSON.stringify(findings));

        return parts.filter(Boolean).join(' ').toLowerCase();
    };

    const getEventDetailLabel = (evt) => {
        const geo = parseJson(evt?.geo);
        const base = String(evt?.channel || 'unknown');
        if (!geo || typeof geo !== 'object') return base;

        const tags = [];
        const batch = String(geo.upload_batch_id || '').trim();
        const exceptionApplied = !!geo.exception_applied
            || String(geo.reason || '').toLowerCase().startsWith('global_exception:')
            || String(geo.suppressed || '').toLowerCase() === 'policy_exception';

        if (batch) {
            tags.push(`batch:${batch.slice(0, 14)}`);
        }
        if (exceptionApplied) {
            tags.push('exception');
        }

        return tags.length > 0 ? `${base} • ${tags.join(' • ')}` : base;
    };

    const inTimeWindow = (ts) => {
        const dt = new Date(ts);
        if (Number.isNaN(dt.getTime())) return false;

        if (timePreset === 'custom') {
            if (fromTime) {
                const from = new Date(fromTime);
                if (!Number.isNaN(from.getTime()) && dt < from) return false;
            }
            if (toTime) {
                const to = new Date(toTime);
                if (!Number.isNaN(to.getTime()) && dt > to) return false;
            }
            return true;
        }

        if (timePreset === 'all') return true;
        const now = Date.now();
        const diff = now - dt.getTime();
        if (timePreset === '1h') return diff <= 60 * 60 * 1000;
        if (timePreset === '24h') return diff <= 24 * 60 * 60 * 1000;
        if (timePreset === '7d') return diff <= 7 * 24 * 60 * 60 * 1000;
        if (timePreset === '30d') return diff <= 30 * 24 * 60 * 60 * 1000;
        return true;
    };

    const filteredEvents = events.filter(evt => {
        const sev = (evt.severity || 'low').toLowerCase();
        if (filterSeverity !== 'all' && sev !== filterSeverity) return false;
        if (filterAgent !== 'all' && evt.agent_type !== filterAgent) return false;
        if (!inTimeWindow(evt.timestamp || evt.created_at)) return false;
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            const searchable = eventSearchBlob(evt);
            if (!searchable.includes(q)) return false;
        }
        return true;
    });

    const agentTypes = [...new Set(events.map(e => e.agent_type).filter(Boolean))];

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    events.forEach(e => {
        const s = (e.severity || 'low').toLowerCase();
        if (counts[s] !== undefined) counts[s]++;
    });

    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    const sortableTime = (evt) => {
        const raw = evt.timestamp || evt.created_at;
        if (!raw) return 0;
        const ts = new Date(raw).getTime();
        return Number.isNaN(ts) ? 0 : ts;
    };

    const sortedEvents = React.useMemo(() => {
        const list = [...filteredEvents];
        const direction = sortDirection === 'asc' ? 1 : -1;

        list.sort((a, b) => {
            let av;
            let bv;

            switch (sortKey) {
                case 'id':
                    av = String(a.event_id || '');
                    bv = String(b.event_id || '');
                    break;
                case 'agent':
                    av = String(a.agent_type || '').toLowerCase();
                    bv = String(b.agent_type || '').toLowerCase();
                    break;
                case 'user':
                    av = String(a.user || '').toLowerCase();
                    bv = String(b.user || '').toLowerCase();
                    break;
                case 'severity':
                    av = severityOrder[String(a.severity || 'low').toLowerCase()] || 0;
                    bv = severityOrder[String(b.severity || 'low').toLowerCase()] || 0;
                    break;
                case 'details':
                    av = getEventDetailLabel(a).toLowerCase();
                    bv = getEventDetailLabel(b).toLowerCase();
                    break;
                case 'time':
                default:
                    av = sortableTime(a);
                    bv = sortableTime(b);
                    break;
            }

            if (av < bv) return -1 * direction;
            if (av > bv) return 1 * direction;
            return 0;
        });

        return list;
    }, [filteredEvents, sortDirection, sortKey]);

    const handleSort = (key) => {
        setCurrentPage(1);
        if (sortKey === key) {
            setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
            return;
        }
        setSortKey(key);
        setSortDirection(key === 'time' || key === 'severity' ? 'desc' : 'asc');
    };

    const sortIndicator = (key) => {
        if (sortKey !== key) return '↕';
        return sortDirection === 'asc' ? '↑' : '↓';
    };

    const totalPages = Math.ceil(sortedEvents.length / pageSize);
    const startIndex = (currentPage - 1) * pageSize;
    const pagedEvents = sortedEvents.slice(startIndex, startIndex + pageSize);

    useEffect(() => {
        if (!autoPageSize) return;

        const computeFitSize = () => {
            const el = tableViewportRef.current;
            if (!el) return;

            const viewportHeight = el.clientHeight || 0;
            const headerAllowance = 44;
            const rowHeight = 46;
            const fit = Math.max(8, Math.floor((viewportHeight - headerAllowance) / rowHeight));
            if (fit > 0) {
                setPageSize(prev => (prev === fit ? prev : fit));
            }
        };

        computeFitSize();
        window.addEventListener('resize', computeFitSize);
        return () => window.removeEventListener('resize', computeFitSize);
    }, [autoPageSize, filteredEvents.length]);

    useEffect(() => {
        const safeTotal = Math.max(1, totalPages || 1);
        setCurrentPage(prev => Math.min(prev, safeTotal));
    }, [totalPages]);

    useEffect(() => {
        setCurrentPage(1);
    }, [filterSeverity, filterAgent, searchQuery, timePreset, fromTime, toTime]);

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 120px)' }}>
            {/* Flattened Severity Strips */}
            <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
                {Object.entries(counts).map(([sev, count]) => {
                    const conf = severityConfig[sev];
                    return (
                        <div key={sev} onClick={() => setFilterSeverity(filterSeverity === sev ? 'all' : sev)}
                            style={{
                                flex: 1, background: filterSeverity === sev ? conf.bg : 'var(--panel-bg)', 
                                border: `1px solid ${filterSeverity === sev ? conf.color : 'var(--border-color)'}`,
                                borderRadius: '8px', padding: '12px', cursor: 'pointer', transition: 'all 0.15s',
                                borderLeft: `4px solid ${conf.color}`
                            }}>
                            <div style={{ color: 'var(--text-muted)', fontSize: '10px', textTransform: 'uppercase', fontWeight: 700 }}>{sev}</div>
                            <div style={{ color: conf.color, fontSize: '20px', fontWeight: 800 }}>{count}</div>
                        </div>
                    );
                })}
            </div>

            {/* Flat Toolbar */}
            <div style={{
                display: 'flex', gap: '12px', marginBottom: '12px', alignItems: 'center',
                padding: '12px 0'
            }}>
                <div style={{ flex: 1 }}>
                    <input type="text" placeholder="Filter logs..." value={searchQuery}
                        onChange={e => setSearchQuery(e.target.value)}
                        style={{
                            width: '100%', padding: '6px 12px', background: 'var(--input-bg)', border: '1px solid var(--border-color)',
                            borderRadius: '4px', color: 'var(--text-strong)', fontSize: '13px'
                        }} />
                </div>
                <select value={filterAgent} onChange={e => setFilterAgent(e.target.value)} style={{
                    padding: '6px 10px', background: 'var(--input-bg)', border: '1px solid var(--border-color)',
                    borderRadius: '4px', color: 'var(--text-strong)', fontSize: '12px'
                }}>
                    <option value="all">All Agents</option>
                    {agentTypes.map(a => <option key={a} value={a}>{a}</option>)}
                </select>
                <select value={timePreset} onChange={e => setTimePreset(e.target.value)} style={{
                    padding: '6px 10px', background: 'var(--input-bg)', border: '1px solid var(--border-color)',
                    borderRadius: '4px', color: 'var(--text-strong)', fontSize: '12px'
                }}>
                    <option value="all">Time: All</option>
                    <option value="1h">Last 1 hour</option>
                    <option value="24h">Last 24 hours</option>
                    <option value="7d">Last 7 days</option>
                    <option value="30d">Last 30 days</option>
                    <option value="custom">Custom range</option>
                </select>
                {timePreset === 'custom' && (
                    <>
                        <input
                            type="datetime-local"
                            value={fromTime}
                            onChange={(e) => setFromTime(e.target.value)}
                            style={{ padding: '6px 8px', background: 'var(--input-bg)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-strong)', fontSize: '12px' }}
                        />
                        <input
                            type="datetime-local"
                            value={toTime}
                            onChange={(e) => setToTime(e.target.value)}
                            style={{ padding: '6px 8px', background: 'var(--input-bg)', border: '1px solid var(--border-color)', borderRadius: '4px', color: 'var(--text-strong)', fontSize: '12px' }}
                        />
                    </>
                )}
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-muted)', fontSize: '12px', cursor: 'pointer' }}>
                    <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} /> Live
                </label>
            </div>

            {/* Clean table without nested container */}
            <div ref={tableViewportRef} style={{ flex: 1, overflowY: 'auto', overflowX: 'auto' }}>
                <table style={{ borderCollapse: 'separate', borderSpacing: 0, width: '100%', fontSize: '13px', background: 'var(--table-bg)' }}>
                    <thead style={{ position: 'sticky', top: 0, zIndex: 1, background: 'var(--table-head-bg)' }}>
                        <tr>
                            <th onClick={() => handleSort('time')} style={{ padding: '14px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '11px', fontWeight: 600, letterSpacing: '0.5px', cursor: 'pointer', userSelect: 'none' }}>Time {sortIndicator('time')}</th>
                            <th onClick={() => handleSort('id')} style={{ padding: '14px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '11px', fontWeight: 600, letterSpacing: '0.5px', cursor: 'pointer', userSelect: 'none' }}>ID {sortIndicator('id')}</th>
                            <th onClick={() => handleSort('agent')} style={{ padding: '14px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '11px', fontWeight: 600, letterSpacing: '0.5px', cursor: 'pointer', userSelect: 'none' }}>Agent {sortIndicator('agent')}</th>
                            <th onClick={() => handleSort('user')} style={{ padding: '14px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '11px', fontWeight: 600, letterSpacing: '0.5px', cursor: 'pointer', userSelect: 'none' }}>User {sortIndicator('user')}</th>
                            <th onClick={() => handleSort('severity')} style={{ padding: '14px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '11px', fontWeight: 600, letterSpacing: '0.5px', cursor: 'pointer', userSelect: 'none' }}>Severity {sortIndicator('severity')}</th>
                            <th onClick={() => handleSort('details')} style={{ padding: '14px 16px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '11px', textAlign: 'left', fontWeight: 600, letterSpacing: '0.5px', cursor: 'pointer', userSelect: 'none' }}>Details {sortIndicator('details')}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {pagedEvents.map((evt, i) => {
                            const sev = (evt.severity || 'low').toLowerCase();
                            const conf = severityConfig[sev] || severityConfig.low;

                            return (
                                <React.Fragment key={evt.event_id || i}>
                                    <tr
                                        style={{ background: 'transparent', cursor: evt.event_id ? 'pointer' : 'default', borderBottom: '1px solid var(--table-row-border)' }}
                                        onClick={(e) => handleEventRowClick(e, evt.event_id)}
                                        onAuxClick={(e) => handleEventRowAuxClick(e, evt.event_id)}
                                        onMouseOver={(e) => { e.currentTarget.style.background = 'var(--surface-subtle)'; }}
                                        onMouseOut={(e) => { e.currentTarget.style.background = 'transparent'; }}
                                    >
                                        <td style={{ padding: '13px 16px', color: 'var(--text-main)', fontFamily: 'monospace', fontSize: '12px' }}>
                                            {formatTimestamp(evt.timestamp || evt.created_at)}
                                        </td>
                                        <td style={{ padding: '13px 16px', color: 'var(--link-soft)', fontFamily: 'monospace', fontSize: '12px', fontWeight: 600 }}>
                                            <a
                                                href={eventHref(evt.event_id)}
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    if (e.button === 0 && !(e.metaKey || e.ctrlKey || e.shiftKey || e.altKey)) {
                                                        e.preventDefault();
                                                        onSelectEvent && evt.event_id && onSelectEvent(evt.event_id);
                                                    }
                                                }}
                                                style={{ color: 'var(--link-soft)', textDecoration: 'none', fontWeight: 700 }}
                                            >
                                                {(evt.event_id || '').substring(0, 8)}
                                            </a>
                                        </td>
                                        <td style={{ padding: '13px 16px' }}>
                                            <span style={{ padding: '3px 8px', borderRadius: '4px', background: 'var(--chip-accent-bg)', color: 'var(--accent)', fontSize: '12px', fontWeight: 600 }}>{evt.agent_type}</span>
                                        </td>
                                        <td style={{ padding: '13px 16px', color: 'var(--text-strong)', fontSize: '13px', fontWeight: 500 }}>{evt.user}</td>
                                        <td style={{ padding: '13px 16px' }}>
                                            <span style={{ padding: '3px 10px', borderRadius: '12px', background: conf.bg, color: conf.color, fontSize: '11px', fontWeight: 700 }}>{sev}</span>
                                        </td>
                                        <td style={{ padding: '13px 16px', color: 'var(--text-main)', fontSize: '13px' }}>{getEventDetailLabel(evt)}</td>
                                    </tr>
                                </React.Fragment>
                            );
                        })}
                        </tbody>
                    </table>
                </div>

                {/* Clean footer without extra background */}
                <div style={{ flexShrink: 0, display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0', borderTop: '1px solid var(--border-color)' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                        Showing {startIndex + 1}—{Math.min(startIndex + pageSize, sortedEvents.length)} of {sortedEvents.length}
                    </div>
                    <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                        <select value={pageSize} onChange={e => { setAutoPageSize(false); setPageSize(Number(e.target.value)); setCurrentPage(1); }}
                            style={{ background: 'var(--input-bg)', border: '1px solid var(--border-color)', color: 'var(--text-strong)', fontSize: '12px', borderRadius: '4px', padding: '4px 8px' }}>
                            {[15, 30, 50, 100].map(v => <option key={v} value={v}>{v}</option>)}
                        </select>
                        <div style={{ display: 'flex', gap: '4px' }}>
                            <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1} 
                                style={{ padding: '2px 8px', background: 'var(--input-bg)', border: '1px solid var(--border-color)', color: 'var(--text-strong)', opacity: currentPage === 1 ? 0.3 : 1, cursor: 'pointer' }}>‹</button>
                            <span style={{ fontSize: '12px', color: 'var(--text-strong)' }}>{currentPage} / {totalPages || 1}</span>
                            <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} 
                                style={{ padding: '2px 8px', background: 'var(--input-bg)', border: '1px solid var(--border-color)', color: 'var(--text-strong)', opacity: currentPage === totalPages ? 0.3 : 1, cursor: 'pointer' }}>›</button>
                        </div>
                    </div>
                </div>
        </div>
    );
};

export default EventsLog;
