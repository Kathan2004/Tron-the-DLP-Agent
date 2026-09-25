import React, { useEffect, useMemo, useState } from 'react';

const emptyForm = {
    name: '',
    description: '',
    scope_type: 'global',
    policy_id: '',
    policy_ids: [],
    mode: 'allow_and_log',
    users: '',
    domains: '',
    expires_at: '',
    ticket_id: '',
    reason: '',
    is_active: true,
};

const Exceptions = ({ apiBase, notify, confirmAction }) => {
    const [exceptions, setExceptions] = useState([]);
    const [policies, setPolicies] = useState([]);
    const [fleetUsers, setFleetUsers] = useState([]);
    const [editingId, setEditingId] = useState(null);
    const [formData, setFormData] = useState(emptyForm);
    const [selectedFleetUser, setSelectedFleetUser] = useState('');
    const [policySearch, setPolicySearch] = useState('');

    const policyMap = useMemo(() => {
        const m = new Map();
        for (const p of policies) {
            m.set(p.policy_id, p.name);
        }
        return m;
    }, [policies]);

    const toList = (raw) => String(raw || '')
        .split(',')
        .map(x => x.trim())
        .filter(Boolean);

    const fromList = (arr) => Array.isArray(arr) ? arr.join(', ') : '';

    const formatExpiryForDisplay = (value) => {
        const s = String(value || '').trim();
        if (!s) return '';
        const d = new Date(s);
        if (Number.isNaN(d.getTime())) return s;
        const formatted = d.toLocaleString('en-IN', {
            year: 'numeric',
            month: 'short',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            hour12: false,
            timeZone: 'Asia/Kolkata',
        });
        return `${formatted} IST`;
    };

    const getExceptionStatusMeta = (ex) => {
        const enabled = !!ex?.is_active;
        const expiryRaw = String(ex?.expires_at || '').trim();
        const expiryMs = expiryRaw ? Date.parse(expiryRaw) : NaN;
        const hasValidExpiry = Number.isFinite(expiryMs);
        const isExpired = hasValidExpiry && expiryMs <= Date.now();

        if (!enabled) {
            return { label: 'DISABLED', badgeClass: 'critical', isEffectiveActive: false };
        }
        if (isExpired) {
            return { label: 'EXPIRED', badgeClass: 'high', isEffectiveActive: false };
        }
        return { label: 'ACTIVE', badgeClass: 'low', isEffectiveActive: true };
    };

    const isoToLocalDateTimeInput = (value) => {
        const s = String(value || '').trim();
        if (!s) return '';
        const normalized = s.endsWith('Z') ? s : s.replace(' ', 'T');
        const d = new Date(normalized);
        if (Number.isNaN(d.getTime())) return '';
        const pad = (n) => String(n).padStart(2, '0');
        const yyyy = d.getFullYear();
        const mm = pad(d.getMonth() + 1);
        const dd = pad(d.getDate());
        const hh = pad(d.getHours());
        const mi = pad(d.getMinutes());
        return `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
    };

    const localDateTimeInputToIso = (value) => {
        const s = String(value || '').trim();
        if (!s) return null;
        const d = new Date(s);
        if (Number.isNaN(d.getTime())) return null;
        return d.toISOString();
    };

    const parseJsonSafe = async (res, fallback) => {
        try {
            if (!res || !res.ok) return fallback;
            return await res.json();
        } catch (_) {
            return fallback;
        }
    };

    const mergeCsvValues = (...rawValues) => {
        const all = rawValues
            .flatMap(v => toList(v))
            .map(v => String(v || '').trim())
            .filter(Boolean);
        const seen = new Set();
        const out = [];
        for (const item of all) {
            const key = item.toLowerCase();
            if (seen.has(key)) continue;
            seen.add(key);
            out.push(item);
        }
        return out.join(', ');
    };

    const filteredPolicies = useMemo(() => {
        const activePolicies = policies.filter(p => p?.is_active === 1 || p?.is_active === true);
        const q = String(policySearch || '').trim().toLowerCase();
        if (!q) return activePolicies;
        return activePolicies.filter(p => {
            const name = String(p?.name || '').toLowerCase();
            const id = String(p?.policy_id || '').toLowerCase();
            return name.includes(q) || id.includes(q);
        });
    }, [policies, policySearch]);

    const activePolicyIds = useMemo(() => {
        return new Set(
            policies
                .filter(p => p?.is_active === 1 || p?.is_active === true)
                .map(p => p.policy_id)
                .filter(Boolean)
        );
    }, [policies]);

    const visibleExceptions = useMemo(() => {
        return exceptions.filter(ex => {
            if (String(ex?.scope_type || '').toLowerCase() !== 'policy') return true;
            const ids = Array.isArray(ex?.policy_ids) && ex.policy_ids.length > 0
                ? ex.policy_ids
                : (ex?.policy_id ? [ex.policy_id] : []);
            return ids.some(pid => activePolicyIds.has(pid));
        });
    }, [exceptions, activePolicyIds]);

    const selectedPolicyIds = Array.isArray(formData.policy_ids) ? formData.policy_ids : [];

    const togglePolicy = (policyId) => {
        const pid = String(policyId || '').trim();
        if (!pid) return;
        const next = selectedPolicyIds.includes(pid)
            ? selectedPolicyIds.filter(x => x !== pid)
            : [...selectedPolicyIds, pid];
        setFormData({ ...formData, policy_ids: next, policy_id: next[0] || '' });
    };

    const fetchData = async () => {
        try {
            const [exReq, polReq, fleetReq] = await Promise.allSettled([
                fetch(`${apiBase}/exceptions`),
                fetch(`${apiBase}/policies`),
                fetch(`${apiBase}/fleet/status`),
            ]);

            const exRes = exReq.status === 'fulfilled' ? exReq.value : null;
            const polRes = polReq.status === 'fulfilled' ? polReq.value : null;
            const fleetRes = fleetReq.status === 'fulfilled' ? fleetReq.value : null;

            const exData = await parseJsonSafe(exRes, { exceptions: [] });
            const polData = await parseJsonSafe(polRes, { policies: [] });
            const fleetData = await parseJsonSafe(fleetRes, { agents: [] });

            // Never blank out lists because of an unrelated endpoint hiccup.
            setExceptions(Array.isArray(exData?.exceptions) ? exData.exceptions : []);
            setPolicies(Array.isArray(polData?.policies) ? polData.policies : []);
            const users = Array.isArray(fleetData?.agents)
                ? fleetData.agents
                    .map(a => String(a?.user || '').trim())
                    .filter(Boolean)
                : [];
            setFleetUsers(Array.from(new Set(users)).sort((a, b) => a.localeCompare(b)));
        } catch (err) {
            console.error('Failed to load exceptions data', err);
        }
    };

    useEffect(() => {
        fetchData();
    }, [apiBase]);

    const notifyUi = (message, severity = 'info') => {
        if (typeof notify === 'function') {
            notify(message, severity);
            return;
        }
        alert(message);
    };

    const confirmUi = async (options) => {
        if (typeof confirmAction === 'function') {
            return !!(await confirmAction(options));
        }
        return window.confirm(options?.message || 'Are you sure?');
    };

    const resetForm = () => {
        setFormData(emptyForm);
        setEditingId(null);
        setSelectedFleetUser('');
        setPolicySearch('');
    };

    const buildPayload = () => ({
        name: formData.name,
        description: formData.description,
        scope_type: formData.scope_type,
        policy_id: formData.scope_type === 'policy' ? (formData.policy_ids?.[0] || formData.policy_id || null) : null,
        policy_ids: formData.scope_type === 'policy'
            ? (Array.isArray(formData.policy_ids) ? formData.policy_ids.filter(Boolean) : [])
            : [],
        mode: formData.mode,
        users: toList(formData.users),
        // Sender is auto-aligned with selected users for browser DLP flows.
        senders: toList(formData.users),
        recipients: [],
        domains: toList(formData.domains),
        expires_at: localDateTimeInputToIso(formData.expires_at),
        ticket_id: String(formData.ticket_id || '').trim(),
        reason: String(formData.reason || '').trim(),
        is_active: !!formData.is_active,
    });

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            if (formData.scope_type === 'policy') {
                const selected = Array.isArray(formData.policy_ids) ? formData.policy_ids.filter(Boolean) : [];
                if (selected.length === 0) {
                    notifyUi('Select at least one target policy.', 'warning');
                    return;
                }
            }
            const payload = buildPayload();
            const url = editingId ? `${apiBase}/exceptions/${editingId}` : `${apiBase}/exceptions`;
            const method = editingId ? 'PUT' : 'POST';
            const res = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                notifyUi(err.error || 'Failed to save exception', 'error');
                return;
            }
            notifyUi(editingId ? 'Exception updated' : 'Exception created', 'success');
            resetForm();
            fetchData();
        } catch (err) {
            console.error(err);
            notifyUi('Failed to save exception', 'error');
        }
    };

    const handleToggleActive = async (ex) => {
        const currentlyActive = !!ex?.is_active;
        const nextActive = currentlyActive ? 0 : 1;
        const confirmed = await confirmUi({
            title: currentlyActive ? 'Deactivate Exception' : 'Activate Exception',
            message: currentlyActive ? 'Deactivate this exception rule?' : 'Activate this exception rule?',
            confirmText: currentlyActive ? 'Deactivate' : 'Activate',
            tone: 'warning',
        });
        if (!confirmed) return;
        try {
            const res = await fetch(`${apiBase}/exceptions/${ex.exception_id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: ex.name,
                    description: ex.description || '',
                    scope_type: ex.scope_type || 'global',
                    policy_id: ex.policy_id || null,
                    policy_ids: Array.isArray(ex.policy_ids) ? ex.policy_ids : [],
                    mode: ex.mode || 'allow_and_log',
                    users: Array.isArray(ex.users) ? ex.users : [],
                    senders: Array.isArray(ex.senders) ? ex.senders : [],
                    recipients: Array.isArray(ex.recipients) ? ex.recipients : [],
                    domains: Array.isArray(ex.domains) ? ex.domains : [],
                    expires_at: ex.expires_at || null,
                    ticket_id: ex.ticket_id || '',
                    reason: ex.reason || '',
                    is_active: nextActive,
                })
            });
            if (res.ok) {
                fetchData();
                notifyUi(currentlyActive ? 'Exception deactivated' : 'Exception activated', 'success');
            }
        } catch (err) {
            console.error(err);
            notifyUi('Failed to update exception', 'error');
        }
    };

    const handleDelete = async (ex) => {
        const isActive = !!ex?.is_active;
        const confirmed = await confirmUi({
            title: 'Delete Exception',
            message: `${isActive ? 'This exception is ACTIVE. ' : ''}Delete permanently?\n\n${ex?.name || ''}`,
            confirmText: 'Delete',
            tone: 'danger',
        });
        if (!confirmed) return;
        try {
            const res = await fetch(`${apiBase}/exceptions/${ex.exception_id}`, { method: 'DELETE' });
            if (res.ok) {
                if (editingId === ex.exception_id) resetForm();
                fetchData();
                notifyUi(`Exception deleted: ${ex?.name || ex?.exception_id || ''}`, 'success');
            }
        } catch (err) {
            console.error(err);
            notifyUi('Failed to delete exception', 'error');
        }
    };

    const handleEdit = (ex) => {
        setEditingId(ex.exception_id);
        setSelectedFleetUser('');
        setPolicySearch('');
        const mergedUsers = mergeCsvValues(fromList(ex.users), fromList(ex.senders));
        setFormData({
            name: ex.name || '',
            description: ex.description || '',
            scope_type: ex.scope_type || 'global',
            policy_id: ex.policy_id || '',
            policy_ids: Array.isArray(ex.policy_ids) && ex.policy_ids.length > 0
                ? ex.policy_ids
                : (ex.policy_id ? [ex.policy_id] : []),
            mode: ex.mode || 'allow_and_log',
            users: mergedUsers,
            domains: fromList(ex.domains),
            expires_at: isoToLocalDateTimeInput(ex.expires_at),
            ticket_id: ex.ticket_id || '',
            reason: ex.reason || '',
            is_active: !!ex.is_active,
        });
        window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    return (
        <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(340px, 1fr) 2fr', gap: '20px', alignItems: 'flex-start' }}>
                <div style={{
                    background: 'var(--panel-bg)',
                    border: `1px solid ${editingId ? 'var(--warning)' : 'var(--border-color)'}`,
                    borderRadius: '12px',
                    padding: '18px',
                    boxShadow: 'var(--card-shadow)',
                }}>
                    <h3 style={{ marginBottom: '10px', color: 'var(--text-strong)', fontSize: '20px' }}>
                        {editingId ? 'Edit Exception Rule' : 'Create Exception Rule'}
                    </h3>
                    <p style={{ color: 'var(--text-main)', fontSize: '13px', marginBottom: '18px', lineHeight: 1.5 }}>
                        Global scope applies to all policies. Policy scope can target one or many policies.
                    </p>

                    <form onSubmit={handleSubmit}>
                        <div className="form-group">
                            <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Exception Name</label>
                            <input className="form-control" required value={formData.name} onChange={e => setFormData({ ...formData, name: e.target.value })} placeholder="e.g. Internal trusted domain allowlist" />
                        </div>

                        <div className="form-group">
                            <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Description</label>
                            <textarea className="form-control" rows={2} value={formData.description} onChange={e => setFormData({ ...formData, description: e.target.value })} />
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                            <div className="form-group">
                                <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Scope</label>
                                <select className="form-control" value={formData.scope_type} onChange={e => setFormData({ ...formData, scope_type: e.target.value, policy_id: '', policy_ids: [] })}>
                                    <option value="global">Global (all policies)</option>
                                    <option value="policy">Policy-specific</option>
                                </select>
                            </div>

                            {formData.scope_type === 'policy' ? (
                                <div className="form-group">
                                    <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Target Policies</label>
                                    <div style={{ border: '1px solid var(--border-color)', borderRadius: '8px', background: 'var(--panel-bg-alt)', padding: '10px' }}>
                                        <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                                            <input
                                                className="form-control"
                                                placeholder="Search Policies"
                                                value={policySearch}
                                                onChange={(e) => setPolicySearch(e.target.value)}
                                            />
                                            <button
                                                type="button"
                                                className="btn"
                                                style={{ backgroundColor: 'var(--panel-bg)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }}
                                                onClick={() => {
                                                    const all = policies
                                                        .filter(p => p?.is_active === 1 || p?.is_active === true)
                                                        .map(p => p.policy_id)
                                                        .filter(Boolean);
                                                    setFormData({ ...formData, policy_ids: all, policy_id: all[0] || '' });
                                                }}
                                            >
                                                All
                                            </button>
                                            <button
                                                type="button"
                                                className="btn"
                                                style={{ backgroundColor: 'var(--panel-bg)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }}
                                                onClick={() => setFormData({ ...formData, policy_ids: [], policy_id: '' })}
                                            >
                                                Clear
                                            </button>
                                        </div>

                                        <div style={{ maxHeight: '170px', overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '6px', background: 'var(--panel-bg)' }}>
                                            {filteredPolicies.length === 0 ? (
                                                <div style={{ color: 'var(--text-muted)', fontSize: '12px', padding: '8px' }}>No matching policies.</div>
                                            ) : filteredPolicies.map(p => {
                                                const checked = selectedPolicyIds.includes(p.policy_id);
                                                return (
                                                    <label key={p.policy_id} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', padding: '6px', cursor: 'pointer', borderRadius: '6px', background: checked ? 'var(--chip-accent-bg)' : 'transparent' }}>
                                                        <input
                                                            type="checkbox"
                                                            checked={checked}
                                                            onChange={() => togglePolicy(p.policy_id)}
                                                        />
                                                        <div>
                                                            <div style={{ color: 'var(--text-strong)', fontWeight: 600, fontSize: '12px' }}>{p.name}</div>
                                                            <div style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'monospace' }}>{p.policy_id}</div>
                                                        </div>
                                                    </label>
                                                );
                                            })}
                                        </div>

                                        <div style={{ marginTop: '8px', color: 'var(--text-muted)', fontSize: '11px' }}>
                                            {selectedPolicyIds.length} policy(s) selected
                                        </div>

                                        {selectedPolicyIds.length > 0 && (
                                            <div style={{ marginTop: '8px', display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                                                {selectedPolicyIds.map(pid => (
                                                    <span key={pid} style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '4px 8px', borderRadius: '999px', background: 'var(--chip-accent-bg)', color: 'var(--accent)', fontSize: '11px', border: '1px solid var(--accent)' }}>
                                                        {policyMap.get(pid) || pid}
                                                        <button
                                                            type="button"
                                                            onClick={() => togglePolicy(pid)}
                                                            style={{ border: 'none', background: 'transparent', color: 'var(--accent)', cursor: 'pointer', fontWeight: 700, lineHeight: 1 }}
                                                            aria-label={`Remove ${pid}`}
                                                        >
                                                            ×
                                                        </button>
                                                    </span>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ) : (
                                <div className="form-group">
                                    <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Mode</label>
                                    <select className="form-control" value={formData.mode} onChange={e => setFormData({ ...formData, mode: e.target.value })}>
                                        <option value="allow_and_log">Allow + Log</option>
                                        <option value="allow">Allow</option>
                                        <option value="monitor_only">Monitor Only</option>
                                    </select>
                                </div>
                            )}
                        </div>

                        <div style={{ marginTop: '6px', marginBottom: '12px', padding: '10px', border: '1px solid var(--border-color)', borderRadius: '8px', background: 'var(--panel-bg-alt)' }}>
                            <div style={{ color: 'var(--text-strong)', fontWeight: 700, fontSize: '12px', marginBottom: '8px' }}>Matching Conditions (blank means any)</div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                                <div className="form-group" style={{ marginBottom: 0 }}>
                                    <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Sender / User (from Fleet)</label>
                                    <input className="form-control" value={formData.users} onChange={e => setFormData({ ...formData, users: e.target.value })} placeholder="alice@corp.com, bob@corp.com" />
                                    <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
                                        <select className="form-control" value={selectedFleetUser} onChange={e => setSelectedFleetUser(e.target.value)}>
                                            <option value="">Select from Fleet users</option>
                                            {fleetUsers.map(u => (
                                                <option key={u} value={u}>{u}</option>
                                            ))}
                                        </select>
                                        <button
                                            type="button"
                                            className="btn"
                                            style={{ backgroundColor: 'var(--panel-bg)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }}
                                            onClick={() => {
                                                if (!selectedFleetUser) return;
                                                setFormData(prev => ({ ...prev, users: mergeCsvValues(prev.users, selectedFleetUser) }));
                                            }}
                                        >
                                            Add
                                        </button>
                                    </div>
                                </div>
                                <div className="form-group" style={{ marginBottom: 0 }}>
                                    <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Domains</label>
                                    <input className="form-control" value={formData.domains} onChange={e => setFormData({ ...formData, domains: e.target.value })} placeholder="internal.company.com" />
                                </div>
                            </div>
                            <div style={{ marginTop: '8px', color: 'var(--text-muted)', fontSize: '11px' }}>
                                Sender is auto-mapped from selected user(s). Domain is destination scope. Blank = applies to any.
                            </div>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                            <div className="form-group">
                                <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Expires At</label>
                                <div style={{ display: 'flex', gap: '8px' }}>
                                    <input
                                        type="datetime-local"
                                        className="form-control"
                                        value={formData.expires_at}
                                        onChange={e => setFormData({ ...formData, expires_at: e.target.value })}
                                    />
                                    <button
                                        type="button"
                                        className="btn"
                                        style={{ backgroundColor: 'var(--panel-bg)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }}
                                        onClick={() => setFormData({ ...formData, expires_at: '' })}
                                    >
                                        Clear
                                    </button>
                                </div>
                            </div>
                            <div className="form-group">
                                <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Ticket ID</label>
                                <input className="form-control" value={formData.ticket_id} onChange={e => setFormData({ ...formData, ticket_id: e.target.value })} placeholder="CHG-12345" />
                            </div>
                        </div>

                        <div className="form-group">
                            <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Reason</label>
                            <textarea className="form-control" rows={2} value={formData.reason} onChange={e => setFormData({ ...formData, reason: e.target.value })} />
                        </div>

                        <div className="form-group" style={{ marginBottom: '10px' }}>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-main)', fontWeight: 600 }}>
                                <input type="checkbox" checked={!!formData.is_active} onChange={e => setFormData({ ...formData, is_active: e.target.checked })} />
                                Active
                            </label>
                        </div>

                        <button type="submit" className="btn" style={{ width: '100%', backgroundColor: editingId ? 'var(--warning)' : 'var(--accent)', color: 'var(--text-inverse)' }}>
                            {editingId ? 'Update Exception' : 'Create Exception'}
                        </button>

                        {formData.scope_type === 'policy' && selectedPolicyIds.length === 0 && (
                            <div style={{ marginTop: '8px', color: 'var(--danger, #f85149)', fontSize: '12px' }}>
                                Select at least one policy.
                            </div>
                        )}

                        {editingId && (
                            <button type="button" className="btn" style={{ width: '100%', marginTop: '10px', backgroundColor: 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }} onClick={resetForm}>
                                Cancel Edit
                            </button>
                        )}
                    </form>
                </div>

                <div style={{
                    background: 'var(--panel-bg)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '12px',
                    padding: '18px',
                    boxShadow: 'var(--card-shadow)',
                }}>
                    <h3 style={{ marginBottom: '10px', color: 'var(--text-strong)', fontSize: '20px' }}>Exception Rules ({visibleExceptions.length})</h3>
                    {exceptions.length !== visibleExceptions.length && (
                        <div style={{ marginBottom: '12px', color: 'var(--text-muted)', fontSize: '12px' }}>
                            {exceptions.length - visibleExceptions.length} policy-scoped exception(s) hidden because all target policies are disabled.
                        </div>
                    )}

                    <div className="policy-list">
                        {visibleExceptions.map(ex => (
                            (() => {
                                const status = getExceptionStatusMeta(ex);
                                return (
                            <div key={ex.exception_id} className="policy-item" style={{ borderLeft: ex.exception_id === editingId ? '3px solid var(--warning)' : '3px solid transparent', background: 'var(--panel-bg-alt)' }}>
                                <div className="policy-info">
                                    <h4>{ex.name}</h4>
                                    <div className="policy-meta" style={{ marginTop: '6px', flexWrap: 'wrap', rowGap: '6px' }}>
                                        <span style={{ color: 'var(--text-main)' }}>Scope: <strong style={{ color: 'var(--text-strong)' }}>{ex.scope_type === 'policy' ? 'Policy' : 'Global'}</strong></span>
                                        {ex.scope_type === 'policy' && (
                                            <span style={{ color: 'var(--text-main)' }}>
                                                Policies: <strong style={{ color: 'var(--text-strong)' }}>
                                                    {(() => {
                                                        const ids = Array.isArray(ex.policy_ids) && ex.policy_ids.length > 0
                                                            ? ex.policy_ids
                                                            : (ex.policy_id ? [ex.policy_id] : []);
                                                        if (ids.length === 0) return '—';
                                                        return ids.map(pid => policyMap.get(pid) || pid).join(', ');
                                                    })()}
                                                </strong>
                                            </span>
                                        )}
                                        <span style={{ color: 'var(--text-main)' }}>Mode: <strong style={{ color: 'var(--text-strong)' }}>{String(ex.mode || 'allow_and_log').toUpperCase()}</strong></span>
                                        {ex.expires_at && (
                                            <span style={{ color: 'var(--text-main)' }} title={`UTC: ${ex.expires_at}`}>
                                                Expires: <strong style={{ color: 'var(--text-strong)' }}>{formatExpiryForDisplay(ex.expires_at)}</strong>
                                            </span>
                                        )}
                                    </div>
                                    <div style={{ marginTop: '8px', color: 'var(--text-main)', fontSize: '12px' }}>
                                        actors={mergeCsvValues(fromList(ex.users), fromList(ex.senders)) || 'ANY'} | domains={fromList(ex.domains) || 'ANY'}
                                    </div>
                                </div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
                                    <span className={`badge ${status.badgeClass}`}>{status.label}</span>
                                    <button onClick={() => handleEdit(ex)} className="btn" style={{ marginRight: '4px', backgroundColor: 'var(--panel-bg)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }}>Edit</button>
                                    <button
                                        onClick={() => handleToggleActive(ex)}
                                        className="btn"
                                        style={{
                                            backgroundColor: ex.is_active ? '#b45309' : 'var(--accent)',
                                            color: 'var(--text-inverse)'
                                        }}
                                    >
                                        {ex.is_active ? 'Deactivate' : 'Activate'}
                                    </button>
                                    <button
                                        onClick={() => handleDelete(ex)}
                                        className="btn"
                                        style={{ backgroundColor: '#b91c1c', color: 'var(--text-inverse)' }}
                                    >
                                        Delete
                                    </button>
                                </div>
                            </div>
                                );
                            })()
                        ))}

                        {visibleExceptions.length === 0 && (
                            <div style={{ padding: '30px', textAlign: 'center', border: '1px dashed var(--border-color)', borderRadius: '8px', color: 'var(--text-muted)' }}>
                                No exception rules configured.
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Exceptions;
