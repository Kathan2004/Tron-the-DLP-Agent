import React, { useState, useEffect, useRef } from 'react';

const FleetView = ({ apiBase, notify }) => {
    const [fleet, setFleet] = useState(null);
    const [loading, setLoading] = useState(true);
    const [selectedAgent, setSelectedAgent] = useState(null);
    const [agentLogs, setAgentLogs] = useState([]);
    const [loadingLogs, setLoadingLogs] = useState(false);
    const [downloadHistory, setDownloadHistory] = useState([]);
    const [loadingDownloads, setLoadingDownloads] = useState(false);
    const [operationalLogs, setOperationalLogs] = useState([]);
    const [loadingOperational, setLoadingOperational] = useState(false);
    const [upgradeBusy, setUpgradeBusy] = useState(false);
    const [policyBusy, setPolicyBusy] = useState(false);
    const defaultManagedPolicy = {
        enabled: true,
        hardBlockAllUploads: false,
        blockMode: 'block',
        scanThreshold: 'medium',
        notifyOnDetection: true,
        reportToApi: true,
        strictInspection: true,
        silentMode: false,
        aiEnabled: true,
        aiScanMode: 'smart',
        allowedDomains: [],
        blockedDomains: [],
        highRiskDomains: [],
        maxFileSize: 10 * 1024 * 1024,
        settingsLocked: true,
    };
    const [agentPolicy, setAgentPolicy] = useState(defaultManagedPolicy);
    const [policyForm, setPolicyForm] = useState({
        blockMode: 'block',
        scanThreshold: 'medium',
        aiScanMode: 'smart',
        maxFileSizeMB: 10,
        allowedDomainsText: '',
        blockedDomainsText: '',
        highRiskDomainsText: '',
    });
    const [routeAgentId, setRouteAgentId] = useState(null);
    const [upgradeDialog, setUpgradeDialog] = useState({
        open: false,
        agent: null,
        download_url: '',
        install_command: '',
        target_version: '',
    });
    const lastLoadedAgentRef = useRef(null);

    useEffect(() => {
        fetchFleet();
        const interval = setInterval(fetchFleet, 5000);
        return () => clearInterval(interval);
    }, [apiBase]);

    const notifyUi = (message, severity = 'info') => {
        if (typeof notify === 'function') {
            notify(message, severity);
            return;
        }
        alert(message);
    };

    // Listen for URL hash changes only once.
    useEffect(() => {
        const parseHash = () => {
            const h = window.location.hash || '';
            const m = h.match(/^#\/fleet\/agent\/(.+)$/);
            if (m) {
                setRouteAgentId(decodeURIComponent(m[1]));
                return;
            }
            setRouteAgentId(null);
        };
        parseHash();
        window.addEventListener('hashchange', parseHash);
        return () => window.removeEventListener('hashchange', parseHash);
    }, []);

    // Resolve selected agent from route + load data exactly once per route id.
    useEffect(() => {
        if (!routeAgentId) {
            setSelectedAgent(null);
            return;
        }

        const agent = fleet?.agents?.find(a => a.agent_id === routeAgentId);
        if (agent) {
            setSelectedAgent(agent);
        } else {
            setSelectedAgent({ agent_id: routeAgentId, hostname: routeAgentId, meta: {} });
        }

        if (lastLoadedAgentRef.current !== routeAgentId) {
            lastLoadedAgentRef.current = routeAgentId;
            fetchAgentLogs(routeAgentId);
            fetchAgentDownloads(routeAgentId);
            fetchOperationalLogs(routeAgentId);
            fetchAgentPolicy(routeAgentId);
        }
    }, [routeAgentId, fleet]);

    // SSE live updates for selected agent
    useEffect(() => {
        if (!selectedAgent?.agent_id) return;
        let es;
        try {
            es = new EventSource(`${apiBase.replace(/\/api$/, '')}/api/stream`);
        } catch (e) {
            return;
        }

        es.onmessage = (ev) => {
            try {
                const data = JSON.parse(ev.data);
                if (!data || !data.type) return;

                // If it's an operational event for this agent, prepend to operational logs
                if (data.type === 'operational' && (data.agent_id === selectedAgent.agent_id || data.hostname === selectedAgent.hostname)) {
                    setOperationalLogs(prev => [{ ...data, timestamp: data.timestamp }, ...prev].slice(0, 200));
                }

                // If it's a scan_result for this agent or host, prepend to downloadHistory/agentLogs
                if (data.type === 'scan_result' && (data.agent_id === selectedAgent.agent_id || data.host === selectedAgent.hostname)) {
                    // Refresh downloads slice
                    setDownloadHistory(prev => [{ file_path: data.source || data.scan_type, timestamp: data.timestamp, severity: data.severity }, ...prev].slice(0, 200));
                    // Also append to agentLogs timeline
                    setAgentLogs(prev => [{ kind: 'scan', timestamp: data.timestamp, source: data.source || '', severity: data.severity, summary: data.scan_type }, ...prev].slice(0, 500));
                }

                // Incidents are broadcast as 'incident' type by server; if relevant to this agent, trigger a refresh
                if (data.type === 'incident' && (data.host === selectedAgent.hostname || data.agent_id === selectedAgent.agent_id)) {
                    fetchAgentLogs(selectedAgent.agent_id);
                }
            } catch (e) {}
        };

        es.onerror = () => {
            es.close();
        };

        return () => es.close();
    }, [selectedAgent?.agent_id, selectedAgent?.hostname, apiBase]);

    const fetchFleet = async () => {
        try {
            const res = await fetch(`${apiBase}/fleet/status`);
            const data = await res.json();
            setFleet(data);
        } catch (err) {
            console.error("Fleet fetch failed:", err);
        }
        setLoading(false);
    };

    const fetchAgentLogs = async (agentId) => {
        setLoadingLogs(true);
        try {
            const res = await fetch(`${apiBase}/fleet/agents/${agentId}/logs`);
            const data = await res.json();
            // Normalize and merge logs/events/incidents into a single timeline
            const merged = [];
            (data.logs || []).forEach(l => {
                merged.push({
                    kind: l.scan_type || 'scan',
                    timestamp: l.timestamp || l.scan_time || l.created_at,
                    source: l.file_path || l.source || l.host || '',
                    severity: l.severity || 'none',
                    summary: Array.isArray(l.findings) && l.findings.length ? (l.findings[0].pattern_name || l.findings[0].description || JSON.stringify(l.findings[0])) : '',
                });
            });
            (data.events || []).forEach(e => {
                const payload = e.payload_sample || e.payload || '';
                const lines = typeof payload === 'string' ? payload.split('\n') : [];
                const pick = (prefix) => {
                    const row = lines.find(l => l.startsWith(prefix));
                    return row ? row.slice(prefix.length).trim() : '';
                };
                const fileName = pick('File: ');
                const domain = pick('Domain: ') || e.geo?.domain || e.source_host || '';
                const evtAction = pick('Action: ') || e.geo?.action || '';
                const patterns = pick('Patterns: ') || (Array.isArray(e.matched_rules) ? e.matched_rules.join(', ') : '');

                merged.push({
                    kind: 'event',
                    eventId: e.event_id,
                    timestamp: e.timestamp || e.created_at,
                    source: `${e.user || 'unknown'} @ ${domain || e.source_host || 'unknown'}`,
                    severity: e.severity || e.geo?.severity || 'none',
                    summary: `${evtAction ? `[${evtAction.toUpperCase()}] ` : ''}${fileName || 'event'}${patterns ? ` • ${patterns}` : ''}`,
                    details: {
                        channel: e.channel,
                        event_id: e.event_id,
                        domain,
                        file_name: fileName,
                        patterns,
                        action: evtAction,
                        agent_type: e.agent_type,
                    }
                });
            });
            (data.incidents || []).forEach(i => {
                merged.push({
                    kind: 'incident',
                    eventId: i.incident_id,
                    timestamp: i.created_at || i.timestamp,
                    source: i.host || i.user || '',
                    severity: i.verdict || i.risk || 'none',
                    summary: `${i.pattern || i.channel || ''}`,
                    details: {
                        incident_id: i.incident_id,
                        risk: i.risk,
                        status: i.status,
                        verdict: i.verdict,
                    }
                });
            });

            // Sort by timestamp desc
            merged.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            setAgentLogs(merged);
        } catch (err) {
            console.error("Failed to fetch agent logs:", err);
            setAgentLogs([]);
        }
        setLoadingLogs(false);
    };

    const fetchAgentDownloads = async (agentId) => {
        setLoadingDownloads(true);
        try {
            const res = await fetch(`${apiBase}/fleet/agents/${agentId}/downloads`);
            const data = await res.json();
            setDownloadHistory(data.downloads || []);
        } catch (err) {
            console.error('Failed to fetch downloads:', err);
            setDownloadHistory([]);
        }
        setLoadingDownloads(false);
    };

    const fetchOperationalLogs = async (agentId) => {
        setLoadingOperational(true);
        try {
            const res = await fetch(`${apiBase}/fleet/agents/${agentId}/operational`);
            const data = await res.json();
            setOperationalLogs(data.logs || []);
        } catch (err) {
            console.error('Failed to fetch operational logs:', err);
            setOperationalLogs([]);
        }
        setLoadingOperational(false);
    };

    const fetchAgentPolicy = async (agentId) => {
        try {
            const res = await fetch(`${apiBase}/fleet/agents/${encodeURIComponent(agentId)}/policy`);
            const data = await res.json().catch(() => ({}));
            const managed = (data && data.managed_settings) || {};
            const merged = {
                ...defaultManagedPolicy,
                ...managed,
                hardBlockAllUploads: !!managed.hardBlockAllUploads,
                enabled: managed.enabled !== false,
                allowedDomains: Array.isArray(managed.allowedDomains) ? managed.allowedDomains : [],
                blockedDomains: Array.isArray(managed.blockedDomains) ? managed.blockedDomains : [],
                highRiskDomains: Array.isArray(managed.highRiskDomains) ? managed.highRiskDomains : [],
                maxFileSize: Number(managed.maxFileSize || defaultManagedPolicy.maxFileSize),
            };
            setAgentPolicy(merged);
            setPolicyForm({
                blockMode: merged.blockMode || 'block',
                scanThreshold: merged.scanThreshold || 'medium',
                aiScanMode: merged.aiScanMode || 'smart',
                maxFileSizeMB: Math.max(1, Math.round((Number(merged.maxFileSize) || (10 * 1024 * 1024)) / (1024 * 1024))),
                allowedDomainsText: (merged.allowedDomains || []).join(', '),
                blockedDomainsText: (merged.blockedDomains || []).join(', '),
                highRiskDomainsText: (merged.highRiskDomains || []).join(', '),
            });
        } catch (_) {
            setAgentPolicy(defaultManagedPolicy);
        }
    };

    const parseDomainList = (raw) => String(raw || '')
        .split(',')
        .map(x => x.trim())
        .filter(Boolean);

    const saveManagedSettings = async (agentId, partial) => {
        setPolicyBusy(true);
        try {
            const res = await fetch(`${apiBase}/fleet/agents/${encodeURIComponent(agentId)}/policy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ managed_settings: partial }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                notifyUi(data.error || 'Failed to update policy.', 'error');
                return null;
            }
            const managed = data?.managed_settings || {};
            const merged = {
                ...defaultManagedPolicy,
                ...managed,
                hardBlockAllUploads: !!managed.hardBlockAllUploads,
                enabled: managed.enabled !== false,
                allowedDomains: Array.isArray(managed.allowedDomains) ? managed.allowedDomains : [],
                blockedDomains: Array.isArray(managed.blockedDomains) ? managed.blockedDomains : [],
                highRiskDomains: Array.isArray(managed.highRiskDomains) ? managed.highRiskDomains : [],
                maxFileSize: Number(managed.maxFileSize || defaultManagedPolicy.maxFileSize),
            };
            setAgentPolicy(merged);
            setPolicyForm((prev) => ({
                ...prev,
                blockMode: merged.blockMode || 'block',
                scanThreshold: merged.scanThreshold || 'medium',
                aiScanMode: merged.aiScanMode || 'smart',
                maxFileSizeMB: Math.max(1, Math.round((Number(merged.maxFileSize) || (10 * 1024 * 1024)) / (1024 * 1024))),
                allowedDomainsText: (merged.allowedDomains || []).join(', '),
                blockedDomainsText: (merged.blockedDomains || []).join(', '),
                highRiskDomainsText: (merged.highRiskDomains || []).join(', '),
            }));
            return managed;
        } catch (_) {
            notifyUi('Failed to update policy.', 'error');
            return null;
        } finally {
            setPolicyBusy(false);
        }
    };

    const setHardBlock = async (agentId, enabled) => {
        const managed = await saveManagedSettings(agentId, { hardBlockAllUploads: !!enabled });
        if (managed) {
            notifyUi(`Hard block ${enabled ? 'enabled' : 'disabled'} for this agent.`, 'success');
        }
    };

    const setDlpEnabled = async (agentId, enabled) => {
        const managed = await saveManagedSettings(agentId, { enabled: !!enabled });
        if (managed) {
            notifyUi(`DLP ${enabled ? 'enabled' : 'disabled'} for this agent.`, 'success');
        }
    };

    const saveAdvancedPolicy = async (agentId) => {
        const payload = {
            blockMode: policyForm.blockMode,
            scanThreshold: policyForm.scanThreshold,
            aiScanMode: policyForm.aiScanMode,
            maxFileSize: Math.max(1, Number(policyForm.maxFileSizeMB || 10)) * 1024 * 1024,
            notifyOnDetection: !!agentPolicy.notifyOnDetection,
            reportToApi: !!agentPolicy.reportToApi,
            strictInspection: !!agentPolicy.strictInspection,
            silentMode: !!agentPolicy.silentMode,
            aiEnabled: !!agentPolicy.aiEnabled,
            allowedDomains: parseDomainList(policyForm.allowedDomainsText),
            blockedDomains: parseDomainList(policyForm.blockedDomainsText),
            highRiskDomains: parseDomainList(policyForm.highRiskDomainsText),
        };
        const managed = await saveManagedSettings(agentId, payload);
        if (managed) {
            notifyUi('Managed extension settings updated.', 'success');
        }
    };

    const pushUpgrade = async (agent) => {
        if (!agent?.agent_id) return;
        if (agent.agent_type === 'browser_extension') {
            notifyUi('Remote upgrade is not supported for browser extensions. Update via extension distribution/policy.', 'warning');
            return;
        }

        setUpgradeDialog({
            open: true,
            agent,
            download_url: '',
            install_command: '',
            target_version: '',
        });
    };

    const closeUpgradeDialog = () => {
        if (upgradeBusy) return;
        setUpgradeDialog({
            open: false,
            agent: null,
            download_url: '',
            install_command: '',
            target_version: '',
        });
    };

    const submitUpgrade = async (e) => {
        e.preventDefault();
        const agent = upgradeDialog.agent;
        if (!agent?.agent_id) return;

        const downloadUrl = String(upgradeDialog.download_url || '').trim();
        const installCommand = String(upgradeDialog.install_command || '').trim();
        const targetVersion = String(upgradeDialog.target_version || '').trim();

        if (!downloadUrl.trim() && !installCommand.trim()) {
            notifyUi('Provide either download URL or install command.', 'warning');
            return;
        }

        setUpgradeBusy(true);
        try {
            const res = await fetch(`${apiBase}/fleet/agents/${encodeURIComponent(agent.agent_id)}/upgrade`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    download_url: downloadUrl.trim(),
                    install_command: installCommand.trim(),
                    target_version: targetVersion.trim(),
                }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                notifyUi(data.error || data.message || 'Failed to queue upgrade command.', 'error');
                return;
            }
            notifyUi(`Upgrade queued for ${agent.hostname || agent.agent_id}. Command ID: ${data?.command?.command_id || 'N/A'}`, 'success');
            closeUpgradeDialog();
        } catch (err) {
            notifyUi('Failed to queue upgrade command.', 'error');
        } finally {
            setUpgradeBusy(false);
        }
    };

    const handleAgentClick = (agent) => {
        // Update URL to dedicated agent page
        const nextHash = `#/fleet/agent/${encodeURIComponent(agent.agent_id)}`;
        if (window.location.hash !== nextHash) {
            window.location.hash = nextHash;
        } else {
            // If same hash clicked, force immediate reload manually
            setSelectedAgent(agent);
            fetchAgentLogs(agent.agent_id);
            fetchAgentDownloads(agent.agent_id);
            fetchOperationalLogs(agent.agent_id);
            fetchAgentPolicy(agent.agent_id);
        }
    };

    const statusConfig = {
        online: { color: '#2ea043', bg: 'rgba(46,160,67,0.12)', icon: 'ON', label: 'ONLINE' },
        idle: { color: '#d29922', bg: 'rgba(210,153,34,0.12)', icon: 'ID', label: 'IDLE' },
        offline: { color: '#f85149', bg: 'rgba(248,81,73,0.12)', icon: 'OFF', label: 'OFFLINE' },
    };

    const agentIcons = {
        browser_extension: 'BR',
        endpoint_agent: 'EP',
        network_agent: 'NW',
        web_agent: 'WB',
        unknown: '--',
    };

    const formatLastSeen = (seconds) => {
        if (seconds < 60) return `${seconds}s ago`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        return `${Math.floor(seconds / 86400)}d ago`;
    };

    const formatTimestamp = (value) => {
        if (!value) return '—';

        // SQLite `datetime('now')` is UTC but stored without timezone.
        // Convert "YYYY-MM-DD HH:MM:SS" -> "YYYY-MM-DDTHH:MM:SSZ" so JS reads it as UTC,
        // then Intl formatting will display correct local timezone (e.g., IST).
        let normalized = value;
        if (typeof value === 'string') {
            const s = value.trim();
            const hasZone = /Z$|[+-]\d{2}:?\d{2}$/.test(s);
            const isSqliteUtc = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?$/.test(s);
            const isIsoNoZone = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(s);

            // IMPORTANT:
            // - SQLite default datetime('now') => "YYYY-MM-DD HH:MM:SS" in UTC (no zone)
            // - Python datetime.now().isoformat() => "YYYY-MM-DDTHH:MM:SS..." in local time (no zone)
            // So only SQLite-style timestamps should be forced to UTC with 'Z'.
            // ISO-without-zone stays local to avoid unwanted +5:30 shifts.
            if (isSqliteUtc && !hasZone) {
                normalized = `${s.replace(' ', 'T')}Z`;
            } else if (isIsoNoZone) {
                normalized = s;
            } else {
                normalized = s;
            }
        }

        const dt = new Date(normalized);
        if (Number.isNaN(dt.getTime())) return String(value);

        return new Intl.DateTimeFormat(undefined, {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false,
            timeZoneName: 'short',
        }).format(dt);
    };

    const compareSemver = (a, b) => {
        const pa = String(a || '0').split('.').map(n => parseInt(n, 10) || 0);
        const pb = String(b || '0').split('.').map(n => parseInt(n, 10) || 0);
        for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
            const da = pa[i] || 0;
            const db = pb[i] || 0;
            if (da > db) return 1;
            if (da < db) return -1;
        }
        return 0;
    };

    const toCoord = (v) => {
        const n = typeof v === 'string' ? parseFloat(v) : v;
        return Number.isFinite(n) ? n : null;
    };

    const selectedGeo = selectedAgent?.meta?.geo || {};
    const geoLat = toCoord(selectedGeo.latitude);
    const geoLng = toCoord(selectedGeo.longitude);
    const hasCoords = geoLat !== null && geoLng !== null;
    const approxLocation = [selectedGeo.city, selectedGeo.region, selectedGeo.country_name].filter(Boolean).join(', ')
        || selectedAgent?.meta?.location
        || 'Unknown';
    const gmapsUrl = hasCoords
        ? `https://www.google.com/maps?q=${encodeURIComponent(`${geoLat},${geoLng}`)}`
        : `https://www.google.com/maps?q=${encodeURIComponent(approxLocation)}`;
    const isDedicatedAgentPage = !!routeAgentId;
    const requiredBrowserVersion = '1.0.2';
    const selectedNeedsUpgrade = !!selectedAgent && selectedAgent.agent_type === 'browser_extension' && compareSemver(selectedAgent.version, requiredBrowserVersion) < 0;

    if (loading || !fleet) {
        return (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '400px', color: 'var(--text-muted)' }}>
                <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '36px', marginBottom: '12px' }}>...</div>
                    <div>Scanning fleet...</div>
                </div>
            </div>
        );
    }

    return (
        <div style={{ position: 'relative' }}>
            {/* Summit Cards */}
            {!isDedicatedAgentPage && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px', marginBottom: '24px' }}>
                <div style={{ background: 'var(--panel-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '20px', borderTop: '3px solid var(--accent)' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 600, letterSpacing: '1px', marginBottom: '6px' }}>TOTAL AGENTS</div>
                    <div style={{ color: 'var(--accent)', fontSize: '36px', fontWeight: 700 }}>{fleet.total}</div>
                </div>
                <div style={{ background: 'var(--panel-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '20px', borderTop: '3px solid #2ea043' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 600, letterSpacing: '1px', marginBottom: '6px' }}>ONLINE</div>
                    <div style={{ color: '#2ea043', fontSize: '36px', fontWeight: 700 }}>{fleet.online}</div>
                </div>
                <div style={{ background: 'var(--panel-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '20px', borderTop: '3px solid #d29922' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 600, letterSpacing: '1px', marginBottom: '6px' }}>IDLE</div>
                    <div style={{ color: '#d29922', fontSize: '36px', fontWeight: 700 }}>{fleet.idle}</div>
                </div>
                <div style={{ background: 'var(--panel-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '20px', borderTop: '3px solid #f85149' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 600, letterSpacing: '1px', marginBottom: '6px' }}>OFFLINE</div>
                    <div style={{ color: '#f85149', fontSize: '36px', fontWeight: 700 }}>{fleet.offline}</div>
                </div>
            </div>
            )}

            {/* Content Area */}
            <div style={{ display: 'flex', gap: '20px' }}>
                {!isDedicatedAgentPage && (
                <div style={{ flex: selectedAgent ? '0 0 65%' : '1' }}>
                    {/* Agent Grid */}
                    {fleet.agents.length === 0 ? (
                        <div className="panel" style={{ textAlign: 'center', padding: '60px 20px' }}>
                            <div style={{ fontSize: '48px', marginBottom: '16px' }}>...</div>
                            <h3 style={{ color: 'var(--text-strong)', marginBottom: '8px' }}>No Agents Connected</h3>
                            <p style={{ color: 'var(--text-muted)', maxWidth: '400px', margin: '0 auto' }}>
                                Deploy the Tron browser extension or endpoint agents to start fleet monitoring.
                                Agents will auto-register on first check-in.
                            </p>
                        </div>
                    ) : (
                        <div style={{ display: 'grid', gridTemplateColumns: selectedAgent ? '1fr' : 'repeat(auto-fill, minmax(340px, 1fr))', gap: '16px' }}>
                            {fleet.agents.map((agent) => {
                                const sConf = statusConfig[agent.status] || statusConfig.offline;
                                const icon = agentIcons[agent.agent_type] || agentIcons.unknown;
                                const isSelected = selectedAgent?.agent_id === agent.agent_id;

                                return (
                                    <div 
                                        key={agent.agent_id} 
                                        onClick={() => handleAgentClick(agent)}
                                        style={{
                                            background: 'var(--panel-bg)', 
                                            border: `1px solid ${isSelected ? 'var(--accent)' : (agent.status === 'online' ? 'rgba(46,160,67,0.3)' : 'var(--border-color)')}`,
                                            borderRadius: '12px', padding: '20px', transition: 'all 0.3s',
                                            borderLeft: `4px solid ${sConf.color}`,
                                            boxShadow: isSelected ? '0 0 15px rgba(88,166,255,0.2)' : (agent.status === 'online' ? `0 0 10px ${sConf.bg}` : 'none'),
                                            cursor: 'pointer'
                                        }}
                                    >
                                        {/* Header */}
                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                                <span style={{ fontSize: '24px' }}>{icon}</span>
                                                <div>
                                                    <div style={{ color: 'var(--text-strong)', fontSize: '15px', fontWeight: 600 }}>{agent.hostname}</div>
                                                    <div style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{agent.agent_type}</div>
                                                </div>
                                            </div>
                                            <span style={{
                                                padding: '3px 10px', borderRadius: '12px', fontSize: '10px', fontWeight: 700,
                                                background: sConf.bg, color: sConf.color, letterSpacing: '0.5px',
                                                display: 'flex', alignItems: 'center', gap: '4px'
                                            }}>
                                                {sConf.icon} {sConf.label}
                                            </span>
                                        </div>

                                        {/* Info Grid */}
                                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '12px' }}>
                                            <div>
                                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 600, letterSpacing: '0.5px' }}>IP ADDRESS</div>
                                                <div style={{ color: 'var(--text-main)', fontFamily: 'monospace' }}>{agent.ip}</div>
                                            </div>
                                            <div>
                                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 600, letterSpacing: '0.5px' }}>OS</div>
                                                <div style={{ color: 'var(--text-main)' }}>{agent.os}</div>
                                            </div>
                                            <div>
                                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 600, letterSpacing: '0.5px' }}>USER</div>
                                                <div style={{ color: 'var(--text-main)' }}>{agent.user}</div>
                                            </div>
                                            <div>
                                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 600, letterSpacing: '0.5px' }}>SCANS</div>
                                                <div style={{ color: 'var(--accent)', fontWeight: 600 }}>{agent.scans_reported}</div>
                                            </div>
                                        </div>

                                        {/* Footer */}
                                        <div style={{ marginTop: '14px', paddingTop: '12px', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                            <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                                                Last seen: <strong style={{ color: sConf.color }}>{formatLastSeen(agent.last_seen_ago)}</strong>
                                            </span>
                                            <div style={{ display: 'flex', gap: '8px' }}>
                                                <a
                                                    href={`#/fleet/agent/${encodeURIComponent(agent.agent_id)}`}
                                                    onClick={(e) => e.stopPropagation()}
                                                    style={{ color: 'var(--accent)', fontSize: '11px', textDecoration: 'none' }}
                                                >
                                                    Open
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
                )}

                {/* Detail Side Panel */}
                {selectedAgent && (
                    <div style={{ 
                        flex: isDedicatedAgentPage ? '1' : '1', 
                        background: 'var(--panel-bg)', 
                        border: '1px solid var(--border-color)', 
                        borderRadius: '12px',
                        padding: '24px',
                        height: 'fit-content',
                        position: isDedicatedAgentPage ? 'relative' : 'sticky',
                        top: isDedicatedAgentPage ? '0' : '20px',
                        animation: 'slideIn 0.3s ease-out'
                    }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                <span style={{ fontSize: '32px' }}>{agentIcons[selectedAgent.agent_type]}</span>
                                <div>
                                    <h2 style={{ margin: 0, color: 'var(--text-strong)', fontSize: '20px', border: 'none' }}>{selectedAgent.hostname}</h2>
                                    <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{selectedAgent.agent_id}</div>
                                </div>
                            </div>
                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                {isDedicatedAgentPage && (
                                    <button className="btn" onClick={() => { window.location.hash = '#/fleet'; }}>← Back to Fleet</button>
                                )}
                                {!isDedicatedAgentPage && (
                                    <button 
                                        onClick={() => {
                                            setSelectedAgent(null);
                                            setAgentLogs([]);
                                            setDownloadHistory([]);
                                            setOperationalLogs([]);
                                            lastLoadedAgentRef.current = null;
                                            window.location.hash = '#/fleet';
                                        }}
                                        style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '20px' }}
                                    >✕</button>
                                )}
                            </div>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '24px', padding: '16px', borderRadius: '8px', background: 'var(--surface-subtle)' }}>
                            <div>
                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 700, marginBottom: '4px' }}>LOCATION</div>
                                <div style={{ color: 'var(--text-strong)' }}>{approxLocation}</div>
                            </div>
                            <div>
                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 700, marginBottom: '4px' }}>CPU ARCH</div>
                                <div style={{ color: 'var(--text-strong)' }}>{selectedAgent.meta?.platform || 'Unknown'}</div>
                            </div>
                            <div>
                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 700, marginBottom: '4px' }}>SESSION ID</div>
                                <div style={{ color: 'var(--text-strong)', fontFamily: 'monospace' }}>{selectedAgent.meta?.session_id || 'N/A'}</div>
                            </div>
                            <div>
                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 700, marginBottom: '4px' }}>VERSION</div>
                                <div style={{ color: 'var(--text-strong)' }}>v{selectedAgent.version}</div>
                                {selectedNeedsUpgrade && (
                                    <div style={{ color: '#f85149', fontSize: '11px', marginTop: '4px' }}>
                                        Upgrade required (expected v{requiredBrowserVersion}+)
                                    </div>
                                )}
                            </div>
                            <div>
                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 700, marginBottom: '4px' }}>LATITUDE</div>
                                <div style={{ color: 'var(--text-strong)', fontFamily: 'monospace' }}>{hasCoords ? geoLat.toFixed(5) : 'N/A'}</div>
                            </div>
                            <div>
                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 700, marginBottom: '4px' }}>LONGITUDE</div>
                                <div style={{ color: 'var(--text-strong)', fontFamily: 'monospace' }}>{hasCoords ? geoLng.toFixed(5) : 'N/A'}</div>
                            </div>
                            <div style={{ gridColumn: '1 / -1' }}>
                                <div style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: 700, marginBottom: '4px' }}>APPROX MAP</div>
                                <a href={gmapsUrl} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)', textDecoration: 'none', fontSize: '12px' }}>
                                    Open approximate location in Google Maps ↗
                                </a>
                            </div>
                        </div>
                        <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
                            <button onClick={() => { fetchAgentLogs(selectedAgent.agent_id); fetchOperationalLogs(selectedAgent.agent_id); }} className="btn">Refresh Logs</button>
                            <button onClick={() => fetchAgentDownloads(selectedAgent.agent_id)} className="btn" disabled={loadingDownloads}>
                                {loadingDownloads ? 'Loading Downloads...' : 'Fetch Download History'}
                            </button>
                            <button onClick={() => fetchOperationalLogs(selectedAgent.agent_id)} className="btn" disabled={loadingOperational}>
                                {loadingOperational ? 'Loading...' : 'Fetch Operational Logs'}
                            </button>
                            <button onClick={() => pushUpgrade(selectedAgent)} className="btn" disabled={upgradeBusy}>
                                {upgradeBusy ? 'Queueing Upgrade...' : 'Push Upgrade'}
                            </button>
                            <span style={{ color: 'var(--text-muted)', fontSize: '12px', alignSelf: 'center' }}>
                                Extension runtime settings are centrally managed by SIEM defaults.
                            </span>
                        </div>

                        <h3 style={{ fontSize: '14px', color: 'var(--text-strong)', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            Operational Logs
                            {loadingLogs && <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 'normal' }}> (Loading...)</span>}
                        </h3>

                        <div style={{ maxHeight: '400px', overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '8px', background: 'var(--table-bg)' }}>
                            {agentLogs.length === 0 ? (
                                <div style={{ color: 'var(--text-muted)', fontSize: '12px', textAlign: 'center', padding: '40px 0' }}>
                                    No logs available for this agent period.
                                </div>
                            ) : (
                                agentLogs.map((log, i) => (
                                    <div key={i} style={{ 
                                        padding: '10px', 
                                        borderBottom: i === agentLogs.length - 1 ? 'none' : '1px solid var(--border-color)',
                                        fontSize: '11px'
                                    }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                                            <span style={{ 
                                                color: log.severity === 'critical' ? '#f85149' : (log.severity === 'high' ? '#ffa657' : '#58a6ff'),
                                                fontWeight: 700,
                                                fontSize: '10px'
                                            }}>[{(log.kind || 'scan').toUpperCase()}]</span>
                                            <span style={{ color: 'var(--text-muted)', fontSize: '10px' }}>{formatTimestamp(log.timestamp)}</span>
                                        </div>
                                        <div style={{ color: 'var(--text-main)', wordBreak: 'break-all', fontWeight: 600 }}>{(log.source || '').toString().substring(0, 120)}{(log.source || '').toString().length > 120 ? '...' : ''}</div>
                                        <div style={{ marginTop: '4px', fontSize: '11px', color: 'var(--link-soft)' }}>{(log.summary || '').toString().substring(0, 180)}{(log.summary || '').toString().length > 180 ? '...' : ''}</div>
                                        <div style={{ marginTop: '4px', fontSize: '11px', color: 'var(--text-muted)' }}>
                                            {log.eventId ? `ID: ${log.eventId} • ` : ''}{log.severity !== 'none' ? `Severity: ${log.severity}` : 'Clean scan'}
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>

                        {/* Download History */}
                        <h3 style={{ fontSize: '14px', color: 'var(--text-strong)', marginTop: '16px' }}>Download History</h3>
                        <div style={{ maxHeight: '240px', overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '8px', background: 'var(--table-bg)' }}>
                            {loadingDownloads ? (
                                <div style={{ color: 'var(--text-muted)', padding: '24px', textAlign: 'center' }}>Loading...</div>
                            ) : downloadHistory.length === 0 ? (
                                <div style={{ color: 'var(--text-muted)', padding: '24px', textAlign: 'center' }}>No download history for this agent.</div>
                            ) : (
                                downloadHistory.map((d, i) => (
                                    <div key={i} style={{ padding: '10px', borderBottom: i === downloadHistory.length - 1 ? 'none' : '1px solid var(--border-color)' }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <div style={{ color: 'var(--accent)', fontWeight: 700 }}>{d.file_path ? d.file_path.split('/').pop() : (d.source || 'unknown')}</div>
                                            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{formatTimestamp(d.timestamp)}</div>
                                        </div>
                                        <div style={{ color: 'var(--text-main)', fontSize: '12px', marginTop: '6px' }}>{d.severity ? `Severity: ${d.severity}` : ''} {d.file_size ? `• ${(d.file_size/1024).toFixed(1)} KB` : ''}</div>
                                        <div style={{ marginTop: '6px', fontSize: '12px', color: 'var(--text-muted)' }}>{d.findings && d.findings.length ? `Patterns: ${d.findings.map(f=>f.pattern_name||f.description||f.pattern||'').slice(0,3).join(', ')}` : 'No detected patterns'}</div>
                                    </div>
                                ))
                            )}
                        </div>

                        {/* Operational Logs */}
                        <h3 style={{ fontSize: '14px', color: 'var(--text-strong)', marginTop: '16px' }}>Operational Events</h3>
                        <div style={{ maxHeight: '240px', overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '8px', background: 'var(--table-bg)' }}>
                            {loadingOperational ? (
                                <div style={{ color: 'var(--text-muted)', padding: '24px', textAlign: 'center' }}>Loading...</div>
                            ) : operationalLogs.length === 0 ? (
                                <div style={{ color: 'var(--text-muted)', padding: '24px', textAlign: 'center' }}>No operational logs for this agent.</div>
                            ) : (
                                operationalLogs.map((o, i) => (
                                    <div key={i} style={{ padding: '10px', borderBottom: i === operationalLogs.length - 1 ? 'none' : '1px solid var(--border-color)' }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                            <div style={{ color: 'var(--accent)', fontWeight: 700 }}>{o.event_type}</div>
                                            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{formatTimestamp(o.timestamp)}</div>
                                        </div>
                                        <div style={{ color: 'var(--text-main)', fontSize: '12px', marginTop: '6px' }}>{o.message}</div>
                                        <div style={{ marginTop: '6px', fontSize: '12px', color: 'var(--text-muted)' }}>{o.details && Object.keys(o.details).length ? JSON.stringify(o.details) : ''}</div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                )}
            </div>
            
            <style dangerouslySetInnerHTML={{ __html: `
                @keyframes slideIn {
                    from { transform: translateX(20px); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            `}} />

            {upgradeDialog.open && (
                <div className="modal-backdrop" onClick={closeUpgradeDialog}>
                    <div className="modal-card" onClick={(evt) => evt.stopPropagation()}>
                        <h3 className="modal-title">Queue Agent Upgrade</h3>
                        <p className="modal-message" style={{ marginBottom: '12px' }}>
                            Target: <strong>{upgradeDialog.agent?.hostname || upgradeDialog.agent?.agent_id}</strong>
                        </p>
                        <form onSubmit={submitUpgrade}>
                            <div className="form-group">
                                <label>Upgrade package/script URL (download_url)</label>
                                <input
                                    className="form-control"
                                    value={upgradeDialog.download_url}
                                    onChange={(ev) => setUpgradeDialog(prev => ({ ...prev, download_url: ev.target.value }))}
                                    placeholder="https://example.com/agent-upgrade.sh"
                                />
                            </div>
                            <div className="form-group">
                                <label>Install command (optional)</label>
                                <input
                                    className="form-control"
                                    value={upgradeDialog.install_command}
                                    onChange={(ev) => setUpgradeDialog(prev => ({ ...prev, install_command: ev.target.value }))}
                                    placeholder="sudo bash /tmp/upgrade.sh"
                                />
                            </div>
                            <div className="form-group">
                                <label>Target version (optional)</label>
                                <input
                                    className="form-control"
                                    value={upgradeDialog.target_version}
                                    onChange={(ev) => setUpgradeDialog(prev => ({ ...prev, target_version: ev.target.value }))}
                                    placeholder="1.0.3"
                                />
                            </div>
                            <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '14px' }}>
                                Provide either download URL or install command.
                            </div>
                            <div className="modal-actions">
                                <button type="button" className="btn modal-btn-cancel" onClick={closeUpgradeDialog} disabled={upgradeBusy}>Cancel</button>
                                <button type="submit" className="btn" style={{ backgroundColor: 'var(--accent)', color: 'var(--text-inverse)' }} disabled={upgradeBusy}>
                                    {upgradeBusy ? 'Queueing...' : 'Queue Upgrade'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default FleetView;
