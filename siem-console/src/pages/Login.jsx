import React, { useState } from 'react';

const Login = ({ apiBase, onLogin }) => {
    const [email, setEmail] = useState('admin@tron.local');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [showPassword, setShowPassword] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`${apiBase}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setError(data.error || 'Login failed');
                setLoading(false);
                return;
            }
            onLogin && onLogin(data);
        } catch (_) {
            setError('Login failed');
        }
        setLoading(false);
    };

    return (
        <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: 'var(--main-content-bg)', padding: '20px' }}>
            <div style={{ width: '100%', maxWidth: '420px', background: 'var(--panel-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '24px', boxShadow: 'var(--card-shadow)' }}>
                <h2 style={{ color: 'var(--text-strong)', marginBottom: '6px' }}>Tron SIEM Login</h2>
                <div style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '14px' }}>Local auth mode (enterprise SSO can be enabled later).</div>
                <form onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label>Email</label>
                        <input className="form-control" value={email} onChange={(e) => setEmail(e.target.value)} required />
                    </div>
                    <div className="form-group">
                        <label>Password</label>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <input className="form-control" type={showPassword ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} required />
                            <button
                                type="button"
                                className="btn"
                                style={{ background: 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }}
                                onClick={() => setShowPassword(v => !v)}
                            >
                                {showPassword ? 'Hide' : 'Show'}
                            </button>
                        </div>
                    </div>
                    {error && <div style={{ color: 'var(--danger)', marginBottom: '10px', fontSize: '13px' }}>{error}</div>}
                    <button className="btn" type="submit" disabled={loading} style={{ width: '100%' }}>
                        {loading ? 'Signing in...' : 'Sign In'}
                    </button>
                </form>
            </div>
        </div>
    );
};

export default Login;
