import React, { useEffect, useMemo, useState } from 'react';

const Profile = ({ apiBase, currentUser, onUserUpdated, notify }) => {
    const [profile, setProfile] = useState({
        display_name: currentUser?.display_name || '',
        timezone: currentUser?.timezone || 'Asia/Kolkata',
        locale: currentUser?.locale || 'en-IN',
        theme_preference: currentUser?.theme_preference || 'light',
        notify_email: currentUser?.notify_email ?? true,
        notify_telegram: currentUser?.notify_telegram ?? true,
    });

    const [pw, setPw] = useState({ old_password: '', new_password: '', confirm: '' });
    const [pwShow, setPwShow] = useState({ old: false, next: false });
    const [savingProfile, setSavingProfile] = useState(false);
    const [savingPw, setSavingPw] = useState(false);
    const [msg, setMsg] = useState('');
    const [sessions, setSessions] = useState([]);
    const [loadingSessions, setLoadingSessions] = useState(false);

    useEffect(() => {
        setProfile({
            display_name: currentUser?.display_name || '',
            timezone: currentUser?.timezone || 'Asia/Kolkata',
            locale: currentUser?.locale || 'en-IN',
            theme_preference: currentUser?.theme_preference || 'light',
            notify_email: currentUser?.notify_email ?? true,
            notify_telegram: currentUser?.notify_telegram ?? true,
        });
    }, [
        currentUser?.display_name,
        currentUser?.timezone,
        currentUser?.locale,
        currentUser?.theme_preference,
        currentUser?.notify_email,
        currentUser?.notify_telegram,
    ]);

    const tzOptions = useMemo(() => [
        'Asia/Kolkata', 'UTC', 'America/New_York', 'Europe/London', 'Asia/Singapore'
    ], []);

    const notifyUi = (m, sev = 'info') => {
        if (typeof notify === 'function') notify(m, sev);
    };

    const loadSessions = async () => {
        setLoadingSessions(true);
        try {
            const res = await fetch(`${apiBase}/auth/sessions`);
            const data = await res.json().catch(() => ({}));
            if (res.ok) setSessions(Array.isArray(data.sessions) ? data.sessions : []);
        } catch (_) {
            // ignore
        }
        setLoadingSessions(false);
    };

    useEffect(() => {
        loadSessions();
    }, [apiBase]);

    const saveProfile = async (e) => {
        e.preventDefault();
        setSavingProfile(true);
        setMsg('');
        try {
            const res = await fetch(`${apiBase}/auth/profile`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(profile),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMsg(data.error || 'Failed to update profile');
            } else {
                setMsg('Profile updated');
                onUserUpdated && onUserUpdated(data.user);
                notifyUi('Profile updated', 'success');
            }
        } catch (_) {
            setMsg('Failed to update profile');
        }
        setSavingProfile(false);
    };

    const changePassword = async (e) => {
        e.preventDefault();
        setSavingPw(true);
        setMsg('');
        if (pw.new_password.length < 8) {
            setMsg('New password must be at least 8 characters');
            setSavingPw(false);
            return;
        }
        if (pw.new_password !== pw.confirm) {
            setMsg('New password and confirmation do not match');
            setSavingPw(false);
            return;
        }
        try {
            const res = await fetch(`${apiBase}/auth/change-password`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ old_password: pw.old_password, new_password: pw.new_password }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMsg(data.error || 'Failed to change password');
            } else {
                setPw({ old_password: '', new_password: '', confirm: '' });
                setMsg('Password updated');
                notifyUi('Password updated', 'success');
                loadSessions();
            }
        } catch (_) {
            setMsg('Failed to change password');
        }
        setSavingPw(false);
    };

    const revokeSession = async (sessionId) => {
        try {
            const res = await fetch(`${apiBase}/auth/sessions/revoke`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: sessionId }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMsg(data.error || 'Failed to revoke session');
                return;
            }
            notifyUi('Session revoked', 'success');
            loadSessions();
        } catch (_) {
            setMsg('Failed to revoke session');
        }
    };

    const revokeAllOtherSessions = async () => {
        try {
            const res = await fetch(`${apiBase}/auth/sessions/revoke`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ revoke_all: true }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMsg(data.error || 'Failed to revoke sessions');
                return;
            }
            notifyUi(`Revoked ${data.count || 0} sessions`, 'success');
            loadSessions();
        } catch (_) {
            setMsg('Failed to revoke sessions');
        }
    };

    return (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(340px, 1fr) 2fr', gap: '20px', alignItems: 'flex-start' }}>
            <div className="panel" style={{ marginBottom: 0 }}>
                <h2>Account</h2>
                <div style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '12px' }}>
                    <div>Email: <strong style={{ color: 'var(--text-strong)' }}>{currentUser?.email}</strong></div>
                    <div>Role: <strong style={{ color: 'var(--text-strong)' }}>{currentUser?.role}</strong></div>
                    <div>Manager: <strong style={{ color: 'var(--text-strong)' }}>{currentUser?.manager_email || '—'}</strong></div>
                </div>

                <form onSubmit={saveProfile}>
                    <div className="form-group">
                        <label>Display Name</label>
                        <input className="form-control" value={profile.display_name} onChange={(e) => setProfile({ ...profile, display_name: e.target.value })} />
                    </div>
                    <div className="form-group">
                        <label>Timezone</label>
                        <select className="form-control" value={profile.timezone} onChange={(e) => setProfile({ ...profile, timezone: e.target.value })}>
                            {tzOptions.map(tz => <option key={tz} value={tz}>{tz}</option>)}
                        </select>
                    </div>
                    <div className="form-group">
                        <label>Locale</label>
                        <input className="form-control" value={profile.locale} onChange={(e) => setProfile({ ...profile, locale: e.target.value })} />
                    </div>
                    <div className="form-group">
                        <label>Theme Preference</label>
                        <select className="form-control" value={profile.theme_preference} onChange={(e) => setProfile({ ...profile, theme_preference: e.target.value })}>
                            <option value="system">System</option>
                            <option value="light">Light</option>
                            <option value="dark">Dark</option>
                        </select>
                    </div>
                    <div className="form-group" style={{ display: 'flex', gap: '14px' }}>
                        <label style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                            <input type="checkbox" checked={!!profile.notify_email} onChange={(e) => setProfile({ ...profile, notify_email: e.target.checked })} />
                            Email notifications
                        </label>
                        <label style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                            <input type="checkbox" checked={!!profile.notify_telegram} onChange={(e) => setProfile({ ...profile, notify_telegram: e.target.checked })} />
                            Telegram notifications
                        </label>
                    </div>
                    <button className="btn" type="submit" disabled={savingProfile}>{savingProfile ? 'Saving...' : 'Save Profile'}</button>
                </form>
            </div>

            <div className="panel" style={{ marginBottom: 0 }}>
                <h2>Security</h2>
                <form onSubmit={changePassword}>
                    <div className="form-group">
                        <label>Current Password</label>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <input className="form-control" type={pwShow.old ? 'text' : 'password'} value={pw.old_password} onChange={(e) => setPw({ ...pw, old_password: e.target.value })} />
                            <button type="button" className="btn" style={{ background: 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }} onClick={() => setPwShow(s => ({ ...s, old: !s.old }))}>{pwShow.old ? 'Hide' : 'Show'}</button>
                        </div>
                    </div>
                    <div className="form-group">
                        <label>New Password</label>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <input className="form-control" type={pwShow.next ? 'text' : 'password'} value={pw.new_password} onChange={(e) => setPw({ ...pw, new_password: e.target.value })} />
                            <button type="button" className="btn" style={{ background: 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }} onClick={() => setPwShow(s => ({ ...s, next: !s.next }))}>{pwShow.next ? 'Hide' : 'Show'}</button>
                        </div>
                    </div>
                    <div className="form-group">
                        <label>Confirm New Password</label>
                        <input className="form-control" type={pwShow.next ? 'text' : 'password'} value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} />
                    </div>
                    <button className="btn" type="submit" disabled={savingPw}>{savingPw ? 'Updating...' : 'Update Password'}</button>
                </form>

                {msg && <div style={{ marginTop: '12px', color: 'var(--text-muted)' }}>{msg}</div>}

                <div style={{ marginTop: '22px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                        <h3 style={{ margin: 0, fontSize: '15px' }}>Active Sessions</h3>
                        <button className="btn" style={{ background: '#b45309' }} onClick={revokeAllOtherSessions}>Revoke Other Sessions</button>
                    </div>
                    {loadingSessions ? (
                        <div style={{ color: 'var(--text-muted)' }}>Loading sessions...</div>
                    ) : sessions.length === 0 ? (
                        <div style={{ color: 'var(--text-muted)' }}>No sessions found.</div>
                    ) : (
                        <div style={{ display: 'grid', gap: '8px' }}>
                            {sessions.map((s) => (
                                <div key={s.session_id} style={{ border: '1px solid var(--border-color)', borderRadius: '8px', padding: '8px 10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
                                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                                        <div style={{ color: 'var(--text-strong)' }}>{s.is_current ? 'Current session' : 'Session'}</div>
                                        <div>{s.ip_address || 'Unknown IP'} · {s.user_agent || 'Unknown client'}</div>
                                        <div>Issued: {s.issued_at || '—'}{s.revoked_at ? ` · Revoked: ${s.revoked_at}` : ''}</div>
                                    </div>
                                    {!s.is_current && !s.revoked_at && (
                                        <button className="btn" style={{ background: '#b45309' }} onClick={() => revokeSession(s.session_id)}>Revoke</button>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default Profile;
