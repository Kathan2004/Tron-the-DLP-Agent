import React, { useState, useEffect, useMemo } from 'react';
import {
    Chart as ChartJS,
    CategoryScale, LinearScale, PointElement, LineElement,
    BarElement, ArcElement, Title, Tooltip, Legend, Filler
} from 'chart.js';
import { Line, Bar, Doughnut } from 'react-chartjs-2';

ChartJS.register(
    CategoryScale, LinearScale, PointElement, LineElement,
    BarElement, ArcElement, Title, Tooltip, Legend, Filler
);

// Shared chart defaults
const chartFont = { family: "'Inter', sans-serif" };

const Analytics = ({ apiBase, theme }) => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [lastUpdated, setLastUpdated] = useState(null);
    const [windowSize, setWindowSize] = useState('7d');
    const [cssVars, setCssVars] = useState({
        textMuted: '#8b949e',
        border: '#30363d',
        panel: '#161b22',
        textStrong: '#ffffff',
        accent: '#58a6ff',
        warning: '#d29922',
        danger: '#f85149',
        linkSoft: '#8ec7ff',
        chartGrid: '#30363d',
        success: '#16a34a',
    });

    // Update CSS variables whenever theme changes
    useEffect(() => {
        const updateCssVars = () => {
            if (typeof window === 'undefined') return;
            const styles = getComputedStyle(document.documentElement);
            setCssVars({
                textMuted: styles.getPropertyValue('--text-muted').trim() || '#8b949e',
                border: styles.getPropertyValue('--border-color').trim() || '#30363d',
                panel: styles.getPropertyValue('--panel-bg').trim() || '#161b22',
                textStrong: styles.getPropertyValue('--text-strong').trim() || '#ffffff',
                accent: styles.getPropertyValue('--accent').trim() || '#58a6ff',
                warning: styles.getPropertyValue('--warning').trim() || '#d29922',
                danger: styles.getPropertyValue('--danger').trim() || '#f85149',
                linkSoft: styles.getPropertyValue('--link-soft').trim() || '#8ec7ff',
                chartGrid: styles.getPropertyValue('--chart-grid').trim() || '#30363d',
                success: styles.getPropertyValue('--success').trim() || '#16a34a',
            });
        };
        updateCssVars();
        // Listen for theme attribute changes
        const observer = new MutationObserver(updateCssVars);
        observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
        return () => observer.disconnect();
    }, []);

    const gridColor = cssVars.chartGrid;
    const textColor = cssVars.textMuted;

    useEffect(() => {
        let mounted = true;

        const fetchAnalytics = async (isManual = false) => {
            if (isManual) setRefreshing(true);
            try {
                const res = await fetch(`${apiBase}/analytics?window=${encodeURIComponent(windowSize)}&t=${Date.now()}`);
                const d = await res.json();
                if (mounted) {
                    setData(d);
                    setLastUpdated(new Date());
                }
            } catch (err) {
                console.error("Analytics fetch failed:", err);
            }
            if (mounted) {
                setLoading(false);
                if (isManual) setRefreshing(false);
            }
        };

        fetchAnalytics();
        const interval = setInterval(() => fetchAnalytics(false), 5000);
        return () => {
            mounted = false;
            clearInterval(interval);
        };
    }, [apiBase, windowSize]);

    const handleManualRefresh = () => {
        setRefreshing(true);
        setData(null);
        const fetchAnalytics = async () => {
            try {
                const res = await fetch(`${apiBase}/analytics?window=${encodeURIComponent(windowSize)}&t=${Date.now()}`);
                const d = await res.json();
                setData(d);
                setLastUpdated(new Date());
            } catch (err) {
                console.error("Analytics fetch failed:", err);
            }
            setRefreshing(false);
        };
        fetchAnalytics();
    };

    const pctDelta = (cur, prev) => {
        const c = Number(cur || 0);
        const p = Number(prev || 0);
        if (p === 0 && c === 0) return '0%';
        if (p === 0) return '+100%';
        const d = ((c - p) / p) * 100;
        const rounded = Math.round(d * 10) / 10;
        return `${rounded > 0 ? '+' : ''}${rounded}%`;
    };

    const trendColor = (cur, prev, inverse = false) => {
        const c = Number(cur || 0);
        const p = Number(prev || 0);
        if (c === p) return 'var(--text-muted)';
        const upIsGood = inverse;
        const wentUp = c > p;
        const good = (wentUp && upIsGood) || (!wentUp && !upIsGood);
        return good ? 'var(--success)' : 'var(--danger)';
    };

    const incidentsLineData = useMemo(() => ({
        labels: (data?.incidents_over_time || []).map(d => {
            const raw = String(d.day || '');
            const normalized = raw.includes('T') ? raw : raw.replace(' ', 'T');
            const dt = new Date(normalized);
            if (Number.isNaN(dt.getTime())) return raw;
            if (windowSize === '24h') {
                return dt.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
            }
            return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        }),
        datasets: [{
            label: 'Incidents',
            data: (data?.incidents_over_time || []).map(d => d.count),
            borderColor: cssVars.danger,
            backgroundColor: 'rgba(248,81,73,0.12)',
            fill: true,
            tension: 0.35,
            pointBackgroundColor: cssVars.danger,
            pointRadius: 3,
        }]
    }), [data, cssVars.danger, windowSize]);

    const eventsHourlyData = useMemo(() => ({
        labels: (data?.events_hourly || []).map(d => d.label || (d.hour ? `${d.hour}:00` : '—')),
        datasets: [{
            label: 'Events',
            data: (data?.events_hourly || []).map(d => d.count),
            borderColor: cssVars.accent,
            backgroundColor: 'rgba(88,166,255,0.10)',
            fill: true,
            tension: 0.3,
            pointRadius: 2,
            pointBackgroundColor: cssVars.accent,
        }]
    }), [data, cssVars.accent]);

    const statusData = useMemo(() => {
        const rows = data?.status_breakdown || [];
        const statusColors = { OPEN: cssVars.warning, ESCALATED: cssVars.danger, CLOSED: cssVars.success, 'AUTO-CLOSED': cssVars.success, TICKET_RAISED: cssVars.accent };
        const normalizeStatus = (s) => (String(s || '').toUpperCase() === 'AUTO-CLOSED' ? 'CLOSED' : s);
        return {
            labels: rows.map(d => normalizeStatus(d.status)),
            datasets: [{
                data: rows.map(d => d.count),
                backgroundColor: rows.map(d => statusColors[normalizeStatus(d.status)] || cssVars.textMuted),
                borderColor: cssVars.panel,
                borderWidth: 2,
            }]
        };
    }, [data, cssVars.warning, cssVars.danger, cssVars.success, cssVars.accent, cssVars.panel]);

    const riskyUsersBar = useMemo(() => ({
        labels: (data?.risky_users || []).slice(0, 8).map(d => d.user),
        datasets: [{
            label: 'Avg Risk',
            data: (data?.risky_users || []).slice(0, 8).map(d => d.avg_risk),
            backgroundColor: 'rgba(248,81,73,0.55)',
            borderColor: cssVars.danger,
            borderWidth: 1,
        }]
    }), [data, cssVars.danger]);

    const assigneeWorkloadData = useMemo(() => {
        const rows = (data?.assignee_workload || []).slice(0, 10);
        return {
            labels: rows.map(r => r.assignee || 'UNASSIGNED'),
            datasets: [
                {
                    label: 'Open',
                    data: rows.map(r => Number(r.open_count || 0)),
                    backgroundColor: 'rgba(248,81,73,0.65)',
                    borderColor: cssVars.danger,
                    borderWidth: 1,
                },
                {
                    label: 'Escalated',
                    data: rows.map(r => Number(r.escalated_count || 0)),
                    backgroundColor: 'rgba(210,153,34,0.65)',
                    borderColor: cssVars.warning,
                    borderWidth: 1,
                },
                {
                    label: 'Resolved',
                    data: rows.map(r => Number(r.resolved_count || 0)),
                    backgroundColor: 'rgba(46,160,67,0.65)',
                    borderColor: cssVars.success,
                    borderWidth: 1,
                }
            ]
        };
    }, [data, cssVars.danger, cssVars.warning, cssVars.success]);

    const closureLeaderboardData = useMemo(() => {
        const rows = (data?.closure_leaderboard || []).slice(0, 10);
        return {
            labels: rows.map(r => r.analyst || 'UNKNOWN'),
            datasets: [{
                label: 'Closed Incidents',
                data: rows.map(r => Number(r.closed_count || 0)),
                backgroundColor: 'rgba(88,166,255,0.6)',
                borderColor: cssVars.accent,
                borderWidth: 1,
            }]
        };
    }, [data, cssVars.accent]);

    const lineOptions = {
        responsive: true, maintainAspectRatio: false,
        plugins: {
            legend: { display: false },
            tooltip: { titleFont: chartFont, bodyFont: chartFont, backgroundColor: cssVars.panel, borderColor: cssVars.border, borderWidth: 1, titleColor: cssVars.textStrong, bodyColor: cssVars.textStrong }
        },
        scales: {
            x: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 11 } } },
            y: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 11 }, precision: 0 }, beginAtZero: true }
        }
    };

    const barOptions = {
        responsive: true, maintainAspectRatio: false, indexAxis: 'y',
        plugins: {
            legend: { display: false },
            tooltip: { titleFont: chartFont, bodyFont: chartFont, backgroundColor: cssVars.panel, borderColor: cssVars.border, borderWidth: 1, titleColor: cssVars.textStrong, bodyColor: cssVars.textStrong }
        },
        scales: {
            x: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 11 }, precision: 0 }, beginAtZero: true },
            y: { grid: { display: false }, ticks: { color: textColor, font: { size: 11 } } }
        }
    };

    const stackedBarOptions = {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: {
            legend: {
                display: true,
                labels: { color: textColor, font: { size: 11, ...chartFont }, usePointStyle: true }
            },
            tooltip: { titleFont: chartFont, bodyFont: chartFont, backgroundColor: cssVars.panel, borderColor: cssVars.border, borderWidth: 1, titleColor: cssVars.textStrong, bodyColor: cssVars.textStrong }
        },
        scales: {
            x: { stacked: true, grid: { color: gridColor }, ticks: { color: textColor, font: { size: 11 }, precision: 0 }, beginAtZero: true },
            y: { stacked: true, grid: { display: false }, ticks: { color: textColor, font: { size: 11 } } }
        }
    };

    const doughnutOptions = {
        responsive: true, maintainAspectRatio: false, cutout: '66%',
        plugins: {
            legend: { position: 'bottom', labels: { color: textColor, font: { size: 12, ...chartFont }, padding: 16, usePointStyle: true, pointStyleWidth: 10 } },
            tooltip: { titleFont: chartFont, bodyFont: chartFont, backgroundColor: cssVars.panel, borderColor: cssVars.border, borderWidth: 1, titleColor: cssVars.textStrong, bodyColor: cssVars.textStrong }
        }
    };

    const kpi = data?.kpi || {};
    const throughput = data?.throughput || {};
    const windowLabel = (throughput.window_label || String(windowSize || '7d').toUpperCase());
    const incidentsWindow = throughput.incidents_window ?? throughput.incidents_24h ?? 0;
    const incidentsPrevWindow = throughput.incidents_prev_window ?? throughput.incidents_prev_24h ?? 0;
    const eventsWindow = throughput.events_window ?? throughput.events_24h ?? 0;
    const eventsPrevWindow = throughput.events_prev_window ?? throughput.events_prev_24h ?? 0;
    const incidentToEventRatioWindow = throughput.incident_to_event_ratio_window ?? throughput.incident_to_event_ratio_24h ?? 0;
    const assignmentsWindow = throughput.assignments_window ?? 0;

    const sectionCard = {
        background: 'var(--panel-bg)',
        border: '1px solid var(--border-color)',
        borderRadius: '12px',
        padding: '14px 16px',
        boxShadow: 'var(--card-shadow)'
    };

    const actionableSignals = useMemo(() => {
        const out = [];
        if ((kpi.critical_open_incidents || 0) > 0) out.push(`Critical open incidents require immediate triage: ${kpi.critical_open_incidents}.`);
        if ((kpi.stale_open_incidents || 0) > 0) out.push(`Open incidents older than 24h: ${kpi.stale_open_incidents}.`);
        if ((kpi.mttr_minutes || 0) > 240) out.push(`MTTR is high at ${Math.round(kpi.mttr_minutes)} minutes; review escalation workflow.`);
        if ((eventsWindow || 0) > 0 && (incidentToEventRatioWindow || 0) > 0.15) out.push(`High detection-to-incident ratio (${incidentToEventRatioWindow}); tune suppression and grouping.`);
        if ((kpi.avg_fp || 0) > 60) out.push(`Average false-positive score is high (${kpi.avg_fp}%). Prioritize policy precision updates.`);
        return out;
    }, [kpi, eventsWindow, incidentToEventRatioWindow]);

    if (loading || !data) {
        return (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '380px', color: 'var(--text-muted)' }}>
                Loading SOC analytics...
            </div>
        );
    }

    const Metric = ({ label, value, sub, valueColor = 'var(--text-strong)' }) => (
        <div style={{ borderBottom: '1px solid var(--border-color)', padding: '10px 0' }}>
            <div style={{ color: 'var(--text-muted)', fontSize: '11px', letterSpacing: '0.8px', fontWeight: 600 }}>{label}</div>
            <div style={{ color: valueColor, fontSize: '24px', fontWeight: 700, lineHeight: 1.2 }}>{value}</div>
            {sub && <div style={{ color: 'var(--text-main)', fontSize: '12px', marginTop: '2px' }}>{sub}</div>}
        </div>
    );

    return (
        <div>
            <div style={{ marginBottom: '14px', paddingBottom: '10px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2 style={{ margin: 0, fontSize: '18px', color: 'var(--text-strong)' }}>SOC Analytics</h2>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <select
                        className="form-control"
                        value={windowSize}
                        onChange={(e) => setWindowSize(e.target.value)}
                        style={{ width: '110px', fontSize: '12px', padding: '4px 8px' }}
                    >
                        <option value="24h">24h</option>
                        <option value="7d">7d</option>
                        <option value="30d">30d</option>
                    </select>
                    <button
                        onClick={handleManualRefresh}
                        disabled={refreshing}
                        style={{
                            padding: '4px 12px',
                            background: 'var(--input-bg)',
                            border: '1px solid var(--border-color)',
                            color: 'var(--text-strong)',
                            borderRadius: '4px',
                            cursor: refreshing ? 'not-allowed' : 'pointer',
                            fontSize: '12px',
                            opacity: refreshing ? 0.5 : 1,
                        }}
                    >
                        {refreshing ? '⟳ Refreshing...' : '↻ Refresh'}
                    </button>
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', whiteSpace: 'nowrap' }}>
                        {lastUpdated ? (
                            <>
                                <span style={{ display: 'block' }}>Updated: {lastUpdated.toLocaleTimeString()}</span>
                                <span style={{ display: 'block', fontSize: '10px', color: 'var(--success)' }}>Live (5s refresh)</span>
                            </>
                        ) : (
                            'Loading...'
                        )}
                    </div>
                </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(180px, 1fr))', gap: '12px', marginBottom: '18px' }}>
                <Metric label={`INCIDENTS (${windowLabel})`} value={incidentsWindow} sub={`${pctDelta(incidentsWindow, incidentsPrevWindow)} vs prev ${windowLabel}`} valueColor={trendColor(incidentsWindow, incidentsPrevWindow)} />
                <Metric label={`EVENTS (${windowLabel})`} value={eventsWindow} sub={`${pctDelta(eventsWindow, eventsPrevWindow)} vs prev ${windowLabel}`} valueColor={trendColor(eventsWindow, eventsPrevWindow)} />
                <Metric label="OPEN INCIDENTS" value={kpi.open_incidents || 0} sub={`${kpi.open_rate || 0}% of total`} valueColor={(kpi.open_incidents || 0) > 0 ? 'var(--warning)' : 'var(--success)'} />
                <Metric label="CRITICAL OPEN" value={kpi.critical_open_incidents || 0} sub="Immediate triage queue" valueColor={(kpi.critical_open_incidents || 0) > 0 ? 'var(--danger)' : 'var(--success)'} />
                <Metric label="MTTR" value={`${Math.round(kpi.mttr_minutes || 0)}m`} sub="Mean time to resolution" valueColor={(kpi.mttr_minutes || 0) > 240 ? 'var(--danger)' : 'var(--success)'} />
                <Metric label="P95 RISK" value={kpi.p95_risk || 0} sub={`Avg ${kpi.avg_risk || 0} • Max ${kpi.max_risk || 0}`} valueColor={(kpi.p95_risk || 0) >= 80 ? 'var(--danger)' : 'var(--accent)'} />
                <Metric label="CONTAINMENT RATE" value={`${kpi.containment_rate || 0}%`} sub="Closed or resolved incidents" valueColor={(kpi.containment_rate || 0) >= 70 ? 'var(--success)' : 'var(--warning)'} />
                <Metric label="FALSE POSITIVE AVG" value={`${Math.round(kpi.avg_fp || 0)}%`} sub="Lower is better" valueColor={(kpi.avg_fp || 0) > 60 ? 'var(--danger)' : 'var(--success)'} />
                <Metric label={`ASSIGNMENTS (${windowLabel})`} value={assignmentsWindow} sub="Incidents assigned to analysts" valueColor={assignmentsWindow > 0 ? 'var(--accent)' : 'var(--text-muted)'} />
            </div>

            <div style={{ ...sectionCard, marginBottom: '14px' }}>
                <div style={{ color: 'var(--text-strong)', fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>Actionable Signals</div>
                {actionableSignals.length === 0 ? (
                    <div style={{ color: 'var(--text-main)', fontSize: '13px' }}>No urgent anomalies detected from current metrics.</div>
                ) : (
                    <ul style={{ margin: 0, paddingLeft: '18px', color: 'var(--text-main)', fontSize: '13px', lineHeight: 1.65 }}>
                        {actionableSignals.map((s, i) => <li key={i}>{s}</li>)}
                    </ul>
                )}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1.5fr', gap: '14px', marginBottom: '14px' }}>
                <div style={{ ...sectionCard, minHeight: '260px' }}>
                    <div style={{ color: 'var(--text-strong)', fontSize: '14px', fontWeight: 600, marginBottom: '10px' }}>Incident Trend ({windowSize})</div>
                    <div style={{ height: '220px' }}><Line data={incidentsLineData} options={lineOptions} /></div>
                </div>
                <div style={{ ...sectionCard, minHeight: '260px' }}>
                    <div style={{ color: 'var(--text-strong)', fontSize: '14px', fontWeight: 600, marginBottom: '10px' }}>Event Throughput ({windowSize})</div>
                    <div style={{ height: '220px' }}><Line data={eventsHourlyData} options={lineOptions} /></div>
                </div>
                <div style={{ ...sectionCard, minHeight: '260px' }}>
                    <div style={{ color: 'var(--text-strong)', fontSize: '14px', fontWeight: 600, marginBottom: '10px' }}>Incident Status Mix</div>
                    <div style={{ height: '220px' }}><Doughnut data={statusData} options={doughnutOptions} /></div>
                </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: '14px', marginBottom: '14px' }}>
                <div style={sectionCard}>
                    <div style={{ color: 'var(--text-strong)', fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>High-Risk Users (avg risk)</div>
                    <div style={{ height: '220px' }}><Bar data={riskyUsersBar} options={barOptions} /></div>
                </div>

                <div style={sectionCard}>
                    <div style={{ color: 'var(--text-strong)', fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>Risky Hosts</div>
                    <div style={{ maxHeight: '240px', overflow: 'auto' }}>
                        {(data.risky_hosts || []).slice(0, 10).map((h, i) => (
                            <div key={`${h.host}-${i}`} style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', gap: '8px', borderBottom: '1px solid var(--border-color)', padding: '8px 0', fontSize: '12px' }}>
                                <span style={{ color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.host || 'unknown'}</span>
                                <span style={{ color: 'var(--accent)' }}>avg {h.avg_risk}</span>
                                <span style={{ color: 'var(--warning)' }}>open {h.open_count}</span>
                            </div>
                        ))}
                    </div>
                </div>

                <div style={sectionCard}>
                    <div style={{ color: 'var(--text-strong)', fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>Repeat Offenders (users)</div>
                    <div style={{ maxHeight: '240px', overflow: 'auto' }}>
                        {(data.repeat_offenders || []).length === 0 ? (
                            <div style={{ color: 'var(--text-main)', fontSize: '13px' }}>No repeat offenders ({'>='}3 incidents) in current dataset.</div>
                        ) : (data.repeat_offenders || []).map((r, i) => (
                            <div key={`${r.user}-${i}`} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '8px', borderBottom: '1px solid var(--border-color)', padding: '8px 0', fontSize: '12px' }}>
                                <span style={{ color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.user || 'unknown'}</span>
                                <span style={{ color: 'var(--danger)', fontWeight: 700 }}>{r.count}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '14px', marginBottom: '14px' }}>
                <div style={sectionCard}>
                    <div style={{ color: 'var(--text-strong)', fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>Assignee Workload ({windowLabel})</div>
                    {(data.assignee_workload || []).length === 0 ? (
                        <div style={{ color: 'var(--text-main)', fontSize: '13px' }}>No assignment activity found for this window.</div>
                    ) : (
                        <div style={{ height: '250px' }}><Bar data={assigneeWorkloadData} options={stackedBarOptions} /></div>
                    )}
                </div>

                <div style={sectionCard}>
                    <div style={{ color: 'var(--text-strong)', fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>Closure Leaderboard ({windowLabel})</div>
                    {(data.closure_leaderboard || []).length === 0 ? (
                        <div style={{ color: 'var(--text-main)', fontSize: '13px' }}>No closure activity in this window.</div>
                    ) : (
                        <>
                            <div style={{ height: '170px', marginBottom: '8px' }}><Bar data={closureLeaderboardData} options={barOptions} /></div>
                            <div style={{ maxHeight: '72px', overflow: 'auto' }}>
                                {(data.closure_leaderboard || []).slice(0, 5).map((r, i) => (
                                    <div key={`${r.analyst}-${i}`} style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', gap: '8px', borderBottom: '1px solid var(--border-color)', padding: '4px 0', fontSize: '12px' }}>
                                        <span style={{ color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.analyst || 'UNKNOWN'}</span>
                                        <span style={{ color: 'var(--accent)', fontWeight: 600 }}>{r.closed_count || 0} closed</span>
                                        <span style={{ color: 'var(--text-muted)' }}>{Math.round(Number(r.avg_resolution_minutes || 0))}m avg</span>
                                    </div>
                                ))}
                            </div>
                        </>
                    )}
                </div>
            </div>

            <div style={sectionCard}>
                <div style={{ color: 'var(--text-strong)', fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>Channel Pressure (events)</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px' }}>
                    {(data.events_by_channel || []).slice(0, 10).map((c, i) => {
                        const max = Math.max(...(data.events_by_channel || []).map(x => x.count || 0), 1);
                        const width = ((c.count || 0) / max) * 100;
                        return (
                            <div key={`${c.channel}-${i}`} style={{ borderBottom: '1px solid var(--border-color)', padding: '8px 0' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px', fontSize: '12px' }}>
                                    <span style={{ color: 'var(--text-main)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.channel || 'unknown'}</span>
                                    <span style={{ color: 'var(--link-soft)' }}>{c.count}</span>
                                </div>
                                <div style={{ height: '4px', background: 'rgba(142,199,255,0.2)', marginTop: '4px' }}>
                                    <div style={{ height: '4px', width: `${width}%`, background: 'var(--link-soft)' }} />
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
};

export default Analytics;
