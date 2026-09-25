import React, { useState, useEffect } from 'react';

const Policies = ({ apiBase, notify, confirmAction }) => {
    const [policies, setPolicies] = useState([]);
    const [editingId, setEditingId] = useState(null);
    const [formData, setFormData] = useState({
        name: '',
        description: '',
        regex_pattern: '',
        rule_type: 'regex',
        action: 'block',
        severity: 'MEDIUM',
        threshold_count: 3,
        threshold_window_mins: 60,
    });

    const getPatternForEdit = (policy) => {
        if (policy?.regex_pattern) return policy.regex_pattern;

        const type = policy?.rule_type || 'regex';
        const rd = policy?.rule_data || {};

        if (type === 'regex') return rd.pattern || '';
        if (type === 'extension') return Array.isArray(rd.blocked_extensions) ? rd.blocked_extensions.join('|') : '';
        if (type === 'file_size') return rd.max_size_mb != null ? String(rd.max_size_mb) : '';
        if (type === 'network') return Array.isArray(rd.blocked_domains) ? rd.blocked_domains.join(',') : '';

        return '';
    };

    const buildRuleDataFromForm = (fd) => {
        const type = fd.rule_type || 'regex';
        const raw = (fd.regex_pattern || '').trim();

        if (type === 'extension') {
            const blocked_extensions = raw
                .split('|')
                .map(x => x.trim())
                .filter(Boolean)
                .map(x => (x.startsWith('.') ? x : `.${x}`));
            return { blocked_extensions };
        }

        if (type === 'file_size') {
            const max_size_mb = Number(raw) || 10;
            return { max_size_mb };
        }

        if (type === 'network') {
            const blocked_domains = raw
                .split(',')
                .map(x => x.trim())
                .filter(Boolean);
            return { blocked_domains };
        }

        return { pattern: raw };
    };

    const fetchPolicies = async () => {
        try {
            const res = await fetch(`${apiBase}/policies`);
            const data = await res.json();
            setPolicies(data.policies || []);
        } catch (err) {
            console.error("Failed to load policies", err);
        }
    };

    const isAiPolicy = (policy) => {
        const meta = policy?.rule_data?._meta || {};
        return meta?.source === 'ai_lab' || meta?.ai_generated === true || policy?.ai_generated === true;
    };

    const patternLabelByType = {
        regex: 'Regex Pattern',
        extension: 'Blocked Extensions (pipe-separated)',
        file_size: 'Max File Size (MB)',
        network: 'Blocked Domains (comma-separated)',
    };

    const patternPlaceholderByType = {
        regex: '\\bLORD-KATHAN-[A-Z0-9]{8}\\b',
        extension: '.exe|.bat|.scr',
        file_size: '10',
        network: 'dropbox.com, drive.google.com',
    };

    useEffect(() => {
        fetchPolicies();
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

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const payload = {
                name: formData.name,
                description: formData.description,
                rule_type: formData.rule_type || 'regex',
                rule_data: buildRuleDataFromForm(formData),
                regex_pattern: formData.regex_pattern,
                pattern: formData.regex_pattern,
                severity: formData.severity,
                action: formData.action,
                threshold_count: Number(formData.threshold_count),
                threshold_window_mins: Number(formData.threshold_window_mins)
            };

            if (editingId) {
                // UPDATE Existing
                const res = await fetch(`${apiBase}/policies/${editingId}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                if (res.ok) {
                    notifyUi('Policy updated across all fleet agents!', 'success');
                }
            } else {
                // CREATE New
                const res = await fetch(`${apiBase}/policies`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                if (res.ok) {
                    notifyUi('Policy deployed across all fleet agents!', 'success');
                }
            }

            setFormData({ name: '', description: '', regex_pattern: '', rule_type: 'regex', action: 'block', severity: 'MEDIUM', threshold_count: 3, threshold_window_mins: 60 });
            setEditingId(null);
            fetchPolicies();

        } catch (err) {
            console.error(err);
            notifyUi('Error saving policy', 'error');
        }
    };

    const handleToggleActive = async (policy) => {
        const nextActive = !(policy?.is_active === 1 || policy?.is_active === true);
        const confirmed = await confirmUi({
            title: nextActive ? 'Activate Policy' : 'Deactivate Policy',
            message: nextActive
                ? 'Activate this policy? It will be enforced on next sync.'
                : 'Deactivate this policy? It will stop enforcement on next sync.',
            confirmText: nextActive ? 'Activate' : 'Deactivate',
            tone: nextActive ? 'warning' : 'warning',
        });
        if (!confirmed) return;
        try {
            const res = await fetch(`${apiBase}/policies/${policy.policy_id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ is_active: nextActive ? 1 : 0 })
            });
            if (res.ok) fetchPolicies();
        } catch (err) {
            console.error(err);
        }
    };

    const handleDelete = async (policy) => {
        const isActive = policy?.is_active === 1 || policy?.is_active === true;
        const confirmed = await confirmUi({
            title: 'Delete Policy',
            message: `${isActive ? 'This policy is ACTIVE. ' : ''}Delete permanently?\n\n${policy?.name || ''}`,
            confirmText: 'Delete',
            tone: 'danger',
        });
        if (!confirmed) return;
        try {
            const res = await fetch(`${apiBase}/policies/${policy.policy_id}`, { method: 'DELETE' });
            if (res.ok) {
                if (editingId === policy.policy_id) handleCancelEdit();
                fetchPolicies();
                notifyUi(`Policy deleted: ${policy?.name || policy?.policy_id || ''}`, 'success');
            }
        } catch (err) {
            console.error(err);
            notifyUi('Failed to delete policy', 'error');
        }
    };

    const handleEdit = (policy) => {
        setFormData({
            name: policy.name,
            description: policy.description || '',
            regex_pattern: getPatternForEdit(policy),
            rule_type: policy.rule_type || 'regex',
            action: policy.action || 'block',
            severity: policy.severity,
            threshold_count: policy.threshold_count,
            threshold_window_mins: policy.threshold_window_mins,
        });
        setEditingId(policy.policy_id);
        window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    const handleCancelEdit = () => {
        setFormData({ name: '', description: '', regex_pattern: '', rule_type: 'regex', action: 'block', severity: 'MEDIUM', threshold_count: 3, threshold_window_mins: 60 });
        setEditingId(null);
    }

    return (
        <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(340px, 1fr) 2fr', gap: '20px', alignItems: 'flex-start' }}>

                {/* ADD / EDIT POLICY */}
                <div style={{
                    background: 'var(--panel-bg)',
                    border: `1px solid ${editingId ? 'var(--warning)' : 'var(--border-color)'}`,
                    borderRadius: '12px',
                    padding: '18px',
                    boxShadow: 'var(--card-shadow)'
                }}>
                    <h3 style={{ marginBottom: '10px', color: 'var(--text-strong)', fontSize: '20px' }}>
                        {editingId ? "Edit Config" : "Deploy Config Rule"}
                    </h3>
                    <p style={{ color: 'var(--text-main)', fontSize: '13px', marginBottom: '18px', lineHeight: 1.5 }}>
                        When deployed, this config pattern is instantly synced to all Tron browser and endpoint agents.
                    </p>

                    <form onSubmit={handleSubmit}>
                        <div className="form-group">
                            <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Config Name</label>
                            <input type="text" className="form-control" required value={formData.name} onChange={e => setFormData({ ...formData, name: e.target.value })} placeholder="e.g. Project Lord Kathan" />
                        </div>
                        <div className="form-group">
                            <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Description</label>
                            <textarea
                                className="form-control"
                                rows={3}
                                value={formData.description}
                                onChange={e => setFormData({ ...formData, description: e.target.value })}
                                placeholder="Policy purpose and expected enforcement behavior"
                            />
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                            <div className="form-group">
                                <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Rule Type</label>
                                <select
                                    className="form-control"
                                    value={formData.rule_type}
                                    onChange={e => setFormData({ ...formData, rule_type: e.target.value, regex_pattern: '' })}
                                >
                                    <option value="regex">Regex</option>
                                    <option value="extension">Extension</option>
                                    <option value="file_size">File Size</option>
                                    <option value="network">Network Domain</option>
                                </select>
                            </div>
                            <div className="form-group">
                                <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Action</label>
                                <select className="form-control" value={formData.action} onChange={e => setFormData({ ...formData, action: e.target.value })}>
                                    <option value="monitor">MONITOR</option>
                                    <option value="warn">WARN</option>
                                    <option value="block">BLOCK</option>
                                </select>
                            </div>
                        </div>

                        <div className="form-group">
                            <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>{patternLabelByType[formData.rule_type] || 'Pattern / Value'}</label>
                            <input
                                type={formData.rule_type === 'file_size' ? 'number' : 'text'}
                                className="form-control"
                                required
                                min={formData.rule_type === 'file_size' ? '1' : undefined}
                                value={formData.regex_pattern}
                                onChange={e => setFormData({ ...formData, regex_pattern: e.target.value })}
                                placeholder={patternPlaceholderByType[formData.rule_type] || 'Value'}
                            />
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                            <div className="form-group">
                                <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Threshold Hits</label>
                                <input type="number" className="form-control" required min="1" value={formData.threshold_count} onChange={e => setFormData({ ...formData, threshold_count: parseInt(e.target.value) })} />
                            </div>
                            <div className="form-group">
                                <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Time Window (Mins)</label>
                                <input type="number" className="form-control" required min="1" value={formData.threshold_window_mins} onChange={e => setFormData({ ...formData, threshold_window_mins: parseInt(e.target.value) })} />
                            </div>
                        </div>

                        <div className="form-group">
                            <label style={{ color: 'var(--text-main)', fontWeight: 600 }}>Severity</label>
                            <select className="form-control" value={formData.severity} onChange={e => setFormData({ ...formData, severity: e.target.value })}>
                                <option value="CRITICAL">CRITICAL</option>
                                <option value="HIGH">HIGH</option>
                                <option value="MEDIUM">MEDIUM</option>
                                <option value="LOW">LOW</option>
                            </select>
                        </div>

                        <button type="submit" className="btn" style={{ width: '100%', marginTop: '10px', backgroundColor: editingId ? 'var(--warning)' : 'var(--accent)', color: 'var(--text-inverse)' }}>
                            {editingId ? "Update Config in Fleet" : "Deploy Config to Fleet"}
                        </button>

                        {editingId && (
                            <button type="button" onClick={handleCancelEdit} className="btn" style={{ width: '100%', marginTop: '10px', backgroundColor: 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }}>
                                Cancel Edit
                            </button>
                        )}
                    </form>
                </div>

                {/* ACTIVE POLICIES */}
                <div style={{
                    background: 'var(--panel-bg)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '12px',
                    padding: '18px',
                    boxShadow: 'var(--card-shadow)'
                }}>
                    <h3 style={{ marginBottom: '16px', color: 'var(--text-strong)', fontSize: '20px' }}>Fleet Configurations ({policies.length})</h3>

                    <div className="policy-list">
                        {policies.map(p => (
                            <div className="policy-item" key={p.policy_id} style={{
                                borderLeft: p.policy_id === editingId ? '3px solid var(--warning)' : '3px solid transparent',
                                background: 'var(--panel-bg-alt)',
                                opacity: (p.is_active === 0 || p.is_active === false) ? 0.75 : 1,
                            }}>
                                <div className="policy-info">
                                    <h4 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                        {p.name}
                                        {isAiPolicy(p) && (
                                            <span style={{ fontSize: '10px', fontWeight: 700, color: 'var(--accent)', border: '1px solid var(--accent)', borderRadius: '999px', padding: '2px 7px' }}>
                                                AI
                                            </span>
                                        )}
                                    </h4>
                                    <div className="policy-meta" style={{ marginTop: '6px', flexWrap: 'wrap', rowGap: '6px' }}>
                                        <span style={{ color: 'var(--accent)', fontFamily: 'monospace' }}>
                                            {p.rule_type === 'regex' ? `/${p.regex || p.rule_data?.pattern || p.regex_pattern}/g` : 
                                             p.rule_type === 'extension' ? `EXT: ${p.rule_data?.blocked_extensions?.join(', ') || p.regex_pattern}` :
                                             `/${p.regex_pattern || '—'}/g`}
                                        </span>
                                        <span style={{ color: 'var(--text-main)' }}>Hits: <strong style={{ color: 'var(--text-strong)' }}>{p.threshold_count}</strong></span>
                                        <span style={{ color: 'var(--text-main)' }}>Window: <strong style={{ color: 'var(--text-strong)' }}>{p.threshold_window_mins}m</strong></span>
                                        <span style={{ color: 'var(--text-main)' }}>Action: <strong style={{ color: 'var(--text-strong)' }}>{String(p.action || 'block').toUpperCase()}</strong></span>
                                    </div>
                                </div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
                                    <span className={`badge ${(p.is_active === 0 || p.is_active === false) ? 'critical' : 'low'}`}>
                                        {(p.is_active === 0 || p.is_active === false) ? 'DISABLED' : 'ACTIVE'}
                                    </span>
                                    <span className={`badge ${p.severity.toLowerCase()}`} style={{ marginRight: '15px' }}>{p.severity}</span>
                                    <button onClick={() => handleEdit(p)} className="btn" style={{ marginRight: '4px', backgroundColor: 'var(--panel-bg)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }}>Edit</button>
                                    <button
                                        onClick={() => handleToggleActive(p)}
                                        className="btn"
                                        style={{
                                            backgroundColor: (p.is_active === 0 || p.is_active === false) ? 'var(--accent)' : '#b45309',
                                            color: 'var(--text-inverse)'
                                        }}
                                    >
                                        {(p.is_active === 0 || p.is_active === false) ? 'Activate' : 'Deactivate'}
                                    </button>
                                    <button
                                        onClick={() => handleDelete(p)}
                                        className="btn"
                                        style={{ backgroundColor: '#b91c1c', color: 'var(--text-inverse)' }}
                                    >
                                        Delete
                                    </button>
                                </div>
                            </div>
                        ))}

                        {policies.length === 0 && (
                            <div style={{ padding: '30px', textAlign: 'center', border: '1px dashed var(--border-color)', borderRadius: '8px', color: 'var(--text-muted)' }}>
                                No configs active. The agents are currently running pre-programmed ML algorithms and standard rules.
                            </div>
                        )}
                    </div>
                </div>

            </div>
        </div>
    );
};

export default Policies;
