import React, { useEffect, useMemo, useState } from 'react';

const emptyForm = {
    email: '',
    display_name: '',
    password: '',
    role: 'SOC_ANALYST',
    manager_email: '',
    is_active: true,
};

const Users = ({ apiBase, currentUser }) => {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [form, setForm] = useState(emptyForm);
    const [message, setMessage] = useState('');
    const [showCreatePassword, setShowCreatePassword] = useState(false);
    const [resetPasswords, setResetPasswords] = useState({});

    const canManage = String(currentUser?.role || '').toUpperCase() === 'SUPER_ADMIN';

    const getAuthHeaders = (extra = {}) => {
        const token = window.localStorage.getItem('siem-auth-token') || '';
        return token
            ? { Authorization: `Bearer ${token}`, ...extra }
            : { ...extra };
    };

    const loadUsers = async () => {
        setLoading(true);
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/users`, { headers: getAuthHeaders() });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to load users');
                setUsers([]);
            } else {
                setUsers(Array.isArray(data.users) ? data.users : []);
            }
        } catch (_) {
            setMessage('Failed to load users');
            setUsers([]);
        }
        setLoading(false);
    };

    useEffect(() => {
        if (canManage) loadUsers();
    }, [apiBase, canManage]);

    const managerOptions = useMemo(() => users.map(u => u.email).filter(Boolean), [users]);

    const createUser = async (e) => {
        e.preventDefault();
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/users`, {
                method: 'POST',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify(form),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || data.message || `Failed to create user (${res.status})`);
                return;
            }
            setForm(emptyForm);
            setMessage('User created');
            loadUsers();
        } catch (_) {
            setMessage('Failed to create user');
        }
    };

    const toggleActive = async (user) => {
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/users/${user.user_id}`, {
                method: 'PATCH',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ is_active: !user.is_active }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to update user');
                return;
            }
            loadUsers();
        } catch (_) {
            setMessage('Failed to update user');
        }
    };

    const updateRole = async (user, role) => {
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/users/${user.user_id}`, {
                method: 'PATCH',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ role }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to update role');
                return;
            }
            setMessage(`Updated role for ${user.display_name}`);
            loadUsers();
        } catch (_) {
            setMessage('Failed to update role');
        }
    };

    const resetUserPassword = async (user) => {
        const next = String(resetPasswords[user.user_id] || '');
        if (next.length < 8) {
            setMessage('Temporary password must be at least 8 characters');
            return;
        }
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/users/${user.user_id}/reset-password`, {
                method: 'POST',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ new_password: next }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to reset password');
                return;
            }
            setResetPasswords((prev) => ({ ...prev, [user.user_id]: '' }));
            setMessage(`Password reset for ${user.display_name}`);
        } catch (_) {
            setMessage('Failed to reset password');
        }
    };

    const revokeSessions = async (user) => {
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/users/${user.user_id}/revoke-sessions`, {
                method: 'POST',
                headers: getAuthHeaders(),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to revoke sessions');
                return;
            }
            setMessage(`Revoked ${data.count || 0} sessions for ${user.display_name}`);
        } catch (_) {
            setMessage('Failed to revoke sessions');
        }
    };

    if (!canManage) {
        return (
            <div className="panel">
                <h2>Users & Access</h2>
                <div style={{ color: 'var(--text-muted)' }}>Only SUPER_ADMIN can manage users.</div>
            </div>
        );
    }

    return (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(340px, 1fr) 2fr', gap: '20px', alignItems: 'flex-start' }}>
            <div className="panel" style={{ marginBottom: 0 }}>
                <h2>Create User</h2>
                <form onSubmit={createUser}>
                    <div className="form-group">
                        <label>Email</label>
                        <input className="form-control" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
                    </div>
                    <div className="form-group">
                        <label>Display Name</label>
                        <input className="form-control" required value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
                    </div>
                    <div className="form-group">
                        <label>Password</label>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <input className="form-control" type={showCreatePassword ? 'text' : 'password'} required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
                            <button
                                type="button"
                                className="btn"
                                style={{ background: 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }}
                                onClick={() => setShowCreatePassword(v => !v)}
                            >
                                {showCreatePassword ? 'Hide' : 'Show'}
                            </button>
                        </div>
                    </div>
                    <div className="form-group">
                        <label>Role</label>
                        <select className="form-control" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                            <option value="SUPER_ADMIN">SUPER_ADMIN</option>
                            <option value="SECURITY_ADMIN">SECURITY_ADMIN</option>
                            <option value="SOC_ANALYST">SOC_ANALYST</option>
                            <option value="VIEWER">VIEWER</option>
                        </select>
                    </div>
                    <div className="form-group">
                        <label>Manager Email (optional)</label>
                        <input list="user-manager-options" className="form-control" value={form.manager_email} onChange={(e) => setForm({ ...form, manager_email: e.target.value })} />
                        <datalist id="user-manager-options">
                            {managerOptions.map((email) => (<option key={email} value={email} />))}
                        </datalist>
                    </div>
                    <button className="btn" type="submit">Create User</button>
                </form>
            </div>

            <div className="panel" style={{ marginBottom: 0 }}>
                <h2>Users ({users.length})</h2>
                {message && <div style={{ color: 'var(--text-muted)', marginBottom: '10px' }}>{message}</div>}
                {loading ? (
                    <div style={{ color: 'var(--text-muted)' }}>Loading...</div>
                ) : users.length === 0 ? (
                    <div style={{ color: 'var(--text-muted)' }}>No users found.</div>
                ) : (
                    <div className="policy-list">
                        {users.map((u) => (
                            <div className="policy-item" key={u.user_id} style={{ alignItems: 'center' }}>
                                <div className="policy-info">
                                    <h4>{u.display_name}</h4>
                                    <div className="policy-meta" style={{ flexWrap: 'wrap' }}>
                                        <span>{u.email}</span>
                                        <span>
                                            Role:
                                            <select
                                                className="form-control"
                                                style={{ marginLeft: '8px', display: 'inline-block', width: '180px' }}
                                                value={u.role}
                                                onChange={(e) => updateRole(u, e.target.value)}
                                            >
                                                <option value="SUPER_ADMIN">SUPER_ADMIN</option>
                                                <option value="SECURITY_ADMIN">SECURITY_ADMIN</option>
                                                <option value="SOC_ANALYST">SOC_ANALYST</option>
                                                <option value="VIEWER">VIEWER</option>
                                            </select>
                                        </span>
                                        <span>Manager: <strong>{u.manager_email || '—'}</strong></span>
                                    </div>
                                    <div style={{ display: 'flex', gap: '8px', marginTop: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                                        <input
                                            className="form-control"
                                            style={{ width: '240px' }}
                                            type="password"
                                            placeholder="Temporary password"
                                            value={resetPasswords[u.user_id] || ''}
                                            onChange={(e) => setResetPasswords((prev) => ({ ...prev, [u.user_id]: e.target.value }))}
                                        />
                                        <button className="btn" onClick={() => resetUserPassword(u)}>Reset Password</button>
                                        <button className="btn" style={{ background: '#b45309' }} onClick={() => revokeSessions(u)}>Revoke Sessions</button>
                                    </div>
                                </div>
                                <button className="btn" onClick={() => toggleActive(u)} style={{ background: u.is_active ? '#b45309' : 'var(--accent)' }}>
                                    {u.is_active ? 'Deactivate' : 'Activate'}
                                </button>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default Users;
