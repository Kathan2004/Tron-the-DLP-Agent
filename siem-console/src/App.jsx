import React, { useState, useEffect, useRef, useCallback } from 'react';
import './index.css';
import Dashboard from './pages/Dashboard';
import Policies from './pages/Policies';
import EventDetail from './pages/EventDetail';
import EventsLog from './pages/EventsLog';
import EventRecordDetail from './pages/EventRecordDetail';
import Analytics from './pages/Analytics';
import FleetView from './pages/FleetView';
import Lab from './pages/Lab';
import Exceptions from './pages/Exceptions';
import Login from './pages/Login';
import Profile from './pages/Profile';
import Governance from './pages/Governance';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:5001/api';

const LIGHT_THEME_VARS = {
  '--bg-color': '#ffffff',
  '--panel-bg': '#ffffff',
  '--panel-bg-alt': '#f7f8fb',
  '--text-main': '#1f2937',
  '--text-strong': '#111827',
  '--text-soft': '#0f172a',
  '--text-muted': '#2d3748',
  '--text-inverse': '#ffffff',
  '--accent': '#4f46e5',
  '--accent-hover': '#4338ca',
  '--border-color': '#e4e7ee',
  '--chip-accent-bg': '#eef0ff',
  '--surface-subtle': '#f7f7f9',
  '--surface-muted': '#f6f6f8',
  '--table-bg': '#ffffff',
  '--table-head-bg': '#f4f6fa',
  '--main-content-bg': '#ffffff',
  '--input-bg': '#ffffff',
};

const DARK_THEME_VARS = {
  '--bg-color': '#0d1117',
  '--panel-bg': '#161b22',
  '--panel-bg-alt': '#1c2128',
  '--text-main': '#c9d1d9',
  '--text-strong': '#ffffff',
  '--text-soft': '#e6edf3',
  '--text-muted': '#8b949e',
  '--text-inverse': '#ffffff',
  '--accent': '#58a6ff',
  '--accent-hover': '#3182ce',
  '--border-color': '#30363d',
  '--chip-accent-bg': 'rgba(88, 166, 255, 0.1)',
  '--surface-subtle': 'rgba(255, 255, 255, 0.02)',
  '--surface-muted': 'rgba(0, 0, 0, 0.3)',
  '--table-bg': '#0d1117',
  '--table-head-bg': '#1c2128',
  '--main-content-bg': 'radial-gradient(circle at top left, #1f2937 0%, transparent 40%), #0d1117',
  '--input-bg': '#0d1117',
};

const applyRuntimeThemeVars = (theme) => {
  const vars = theme === 'dark' ? DARK_THEME_VARS : LIGHT_THEME_VARS;
  try {
    const rootStyle = document.documentElement?.style;
    if (!rootStyle) return;
    Object.entries(vars).forEach(([k, v]) => rootStyle.setProperty(k, v));
  } catch (_) {
    // no-op
  }
};

class AppErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, message: '' };
  }

  static getDerivedStateFromError(error) {
    return {
      hasError: true,
      message: String(error?.message || 'Unexpected UI error'),
    };
  }

  componentDidCatch(error, info) {
    console.error('UI render error:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: 'var(--main-content-bg)', padding: '20px' }}>
          <div style={{ width: '100%', maxWidth: '720px', background: 'var(--panel-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '20px' }}>
            <h2 style={{ marginTop: 0, color: 'var(--text-strong)' }}>UI error detected</h2>
            <div style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '12px' }}>
              A rendering error occurred. The app did not crash silently.
            </div>
            <div style={{ color: 'var(--text-strong)', fontSize: '13px', marginBottom: '14px' }}>
              {this.state.message}
            </div>
            <button className="btn" onClick={() => window.location.reload()}>Reload</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function App() {
  const initialHash = (typeof window !== 'undefined' && window.location.hash) ? window.location.hash : '#/dashboard';
  const initialIncidentId = initialHash.startsWith('#/incident/') ? decodeURIComponent(initialHash.replace('#/incident/', '')) : null;
  const initialEventId = initialHash.startsWith('#/event/') ? decodeURIComponent(initialHash.replace('#/event/', '')) : null;
  const initialTab = (() => {
    if (initialHash.startsWith('#/event/')) return 'eventDetail';
    if (initialHash.startsWith('#/incident/')) return 'detail';
    if (initialHash.startsWith('#/fleet')) return 'fleet';
    if (initialHash === '#/analytics') return 'analytics';
    if (initialHash === '#/events') return 'events';
    if (initialHash === '#/policies') return 'policies';
    if (initialHash === '#/exceptions') return 'exceptions';
    if (initialHash === '#/profile') return 'profile';
    if (initialHash.startsWith('#/governance') || initialHash === '#/users') return 'admin';
    if (initialHash === '#/lab') return 'lab';
    return 'dashboard';
  })();

  const [activeTab, setActiveTab] = useState(initialTab);
  const [stats, setStats] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(initialIncidentId);
  const [selectedEventId, setSelectedEventId] = useState(initialEventId);
  const [toasts, setToasts] = useState([]);
  const [confirmDialog, setConfirmDialog] = useState({
    open: false,
    title: 'Confirm Action',
    message: '',
    confirmText: 'Confirm',
    cancelText: 'Cancel',
    tone: 'warning',
  });
  const [sseConnected, setSseConnected] = useState(false);
  const [authLoading, setAuthLoading] = useState(true);
  const [authToken, setAuthToken] = useState(() => (typeof window !== 'undefined' ? (window.localStorage.getItem('siem-auth-token') || '') : ''));
  const [authUser, setAuthUser] = useState(null);
  const [authPermissions, setAuthPermissions] = useState([]);
  const [pwOld, setPwOld] = useState('');
  const [pwNew, setPwNew] = useState('');
  const [pwMsg, setPwMsg] = useState('');
  const [pwBusy, setPwBusy] = useState(false);
  const [pwShowOld, setPwShowOld] = useState(false);
  const [pwShowNew, setPwShowNew] = useState(false);
  const [pwConfirm, setPwConfirm] = useState('');
  const [theme, setTheme] = useState(() => {
    const saved = typeof window !== 'undefined' ? window.localStorage.getItem('siem-theme') : null;
    return saved === 'light' || saved === 'dark' ? saved : 'light';
  });
  const toastIdRef = useRef(0);
  const confirmResolverRef = useRef(null);

  const severityColorMap = {
    critical: '#f85149',
    error: '#f85149',
    danger: '#f85149',
    high: '#d29922',
    warning: '#d29922',
    medium: '#58a6ff',
    info: '#58a6ff',
    success: '#2ea043',
    low: '#8b949e',
  };

  const pushToast = useCallback((message, severity = 'info', options = {}) => {
    const sev = String(severity || 'info').toLowerCase();
    const id = ++toastIdRef.current;
    const duration = Number(options.durationMs || 4500);
    const toast = {
      id,
      message: String(message || ''),
      severity: sev,
      color: severityColorMap[sev] || severityColorMap.info,
      incident_id: options.incident_id || null,
      timestamp: new Date().toLocaleTimeString(),
    };
    setToasts(prev => [toast, ...prev].slice(0, 5));
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, duration);
  }, []);

  const askConfirm = useCallback((options = {}) => {
    const title = String(options.title || 'Confirm Action');
    const message = String(options.message || 'Are you sure?');
    const confirmText = String(options.confirmText || 'Confirm');
    const cancelText = String(options.cancelText || 'Cancel');
    const tone = String(options.tone || 'warning').toLowerCase();

    setConfirmDialog({ open: true, title, message, confirmText, cancelText, tone });
    return new Promise((resolve) => {
      confirmResolverRef.current = resolve;
    });
  }, []);

  const closeConfirm = useCallback((result) => {
    if (confirmResolverRef.current) {
      confirmResolverRef.current(!!result);
      confirmResolverRef.current = null;
    }
    setConfirmDialog(prev => ({ ...prev, open: false }));
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.body?.setAttribute('data-theme', theme);
    applyRuntimeThemeVars(theme);
    window.localStorage.setItem('siem-theme', theme);
  }, [theme]);

  useEffect(() => {
    const expected = theme === 'dark' ? '#0d1117' : '#ffffff';
    const ensureTheme = () => {
      try {
        const current = getComputedStyle(document.documentElement).getPropertyValue('--bg-color').trim().toLowerCase();
        const normalized = current.replace(/\s+/g, '');
        if (normalized !== expected) {
          document.documentElement.setAttribute('data-theme', theme);
          document.body?.setAttribute('data-theme', theme);
          applyRuntimeThemeVars(theme);
        }
      } catch (_) {
        // no-op
      }
    };

    // Immediate + short startup window guard
    ensureTheme();
    const t1 = setTimeout(ensureTheme, 150);
    const t2 = setTimeout(ensureTheme, 700);
    const t3 = setTimeout(ensureTheme, 1500);

    const onFocus = () => ensureTheme();
    const onVisibility = () => {
      if (document.visibilityState === 'visible') ensureTheme();
    };
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [theme]);

  useEffect(() => {
    const onStorage = (e) => {
      if (e.key !== 'siem-theme') return;
      const next = String(e.newValue || '').toLowerCase();
      if (next === 'light' || next === 'dark') {
        setTheme(next);
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  const applyThemePreference = useCallback((user) => {
    const local = typeof window !== 'undefined' ? window.localStorage.getItem('siem-theme') : '';
    const resolved = (local === 'light' || local === 'dark') ? local : 'light';
    if (typeof window !== 'undefined' && local !== resolved) {
      window.localStorage.setItem('siem-theme', resolved);
    }
    setTheme(resolved);
  }, []);

  const fetchPermissions = useCallback(async (token) => {
    if (!token) {
      setAuthPermissions([]);
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/auth/permissions`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && Array.isArray(data?.permissions)) {
        setAuthPermissions(data.permissions);
      } else {
        setAuthPermissions([]);
      }
    } catch (_) {
      setAuthPermissions([]);
    }
  }, []);

  useEffect(() => {
    const token = (typeof window !== 'undefined' ? window.localStorage.getItem('siem-auth-token') : '') || '';
    if (!token) {
      setAuthUser(null);
      setAuthLoading(false);
      return;
    }
    const verify = async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data?.user) {
          window.localStorage.removeItem('siem-auth-token');
          setAuthToken('');
          setAuthUser(null);
          setAuthPermissions([]);
        } else {
          setAuthToken(token);
          setAuthUser(data.user);
          applyThemePreference(data.user);
          fetchPermissions(token);
        }
      } catch (_) {
        setAuthUser(null);
        setAuthPermissions([]);
      }
      setAuthLoading(false);
    };
    verify();
  }, [applyThemePreference, fetchPermissions]);

  useEffect(() => {
    const originalFetch = window.fetch.bind(window);
    window.fetch = (input, init = {}) => {
      try {
        const url = typeof input === 'string' ? input : (input?.url || '');
        const isApi = url.includes('/api/');
        const isLogin = url.endsWith('/api/auth/login');
        if (!authToken || !isApi || isLogin) {
          return originalFetch(input, init);
        }
        const headers = new Headers(init?.headers || (input instanceof Request ? input.headers : undefined));
        if (!headers.get('Authorization')) headers.set('Authorization', `Bearer ${authToken}`);
        return originalFetch(input, { ...init, headers });
      } catch (_) {
        return originalFetch(input, init);
      }
    };
    return () => {
      window.fetch = originalFetch;
    };
  }, [authToken]);

  const handleLogin = (data) => {
    const token = String(data?.token || '');
    const user = data?.user || null;
    if (!token || !user) return;
    window.localStorage.setItem('siem-auth-token', token);
    setAuthToken(token);
    setAuthUser(user);
    applyThemePreference(user);
    if (Array.isArray(data?.permissions)) setAuthPermissions(data.permissions);
    else fetchPermissions(token);
  };

  const handleLogout = async () => {
    try {
      if (authToken) {
        await fetch(`${API_BASE}/auth/logout`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${authToken}` },
        });
      }
    } catch (_) {
      // no-op
    }
    window.localStorage.removeItem('siem-auth-token');
    setAuthToken('');
    setAuthUser(null);
    setAuthPermissions([]);
    setSelectedIncidentId(null);
    setSelectedEventId(null);
    setActiveTab('dashboard');
  };

  const submitPasswordChange = async ({ oldPassword, newPassword }) => {
    const res = await fetch(`${API_BASE}/auth/change-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return { ok: false, error: data.error || 'Failed to change password' };

    const meRes = await fetch(`${API_BASE}/auth/me`, { headers: { Authorization: `Bearer ${authToken}` } });
    const meData = await meRes.json().catch(() => ({}));
    if (meRes.ok && meData?.user) setAuthUser(meData.user);
    return { ok: true };
  };

  const fetchDashboardData = useCallback(async () => {
    if (!authUser) return;
    try {
      const statsRes = await fetch(`${API_BASE}/stats`);
      const statsData = await statsRes.json();
      setStats(statsData);

      const incRes = await fetch(`${API_BASE}/incidents?limit=1000`);
      const incData = await incRes.json();
      setIncidents(incData.incidents || []);
    } catch (err) {
      console.error("Failed to fetch data:", err);
    }
  }, [authUser]);

  // Dashboard data
  useEffect(() => {
    if (!authUser) return;
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000);
    return () => clearInterval(interval);
  }, [fetchDashboardData, authUser]);

  // Real-time SSE connection
  useEffect(() => {
    if (!authUser) return;
    let eventSource;
    let retryTimeout;

    const connect = () => {
      eventSource = new EventSource(`${API_BASE}/stream`);

      eventSource.onopen = () => {
        setSseConnected(true);
      };

      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'heartbeat' || data.type === 'connected') return;

          if (data.type === 'incident') {
            pushToast(data.message || `New incident: ${data.incident_id}`, data.severity || 'high', {
              incident_id: data.incident_id,
              durationMs: 8000,
            });

            // Refresh dashboard data
            fetch(`${API_BASE}/incidents?limit=1000`)
              .then(r => r.json())
              .then(d => setIncidents(d.incidents || []));
            fetch(`${API_BASE}/stats`)
              .then(r => r.json())
              .then(d => setStats(d));
          }
        } catch (e) {
          // ignore parse errors
        }
      };

      eventSource.onerror = () => {
        setSseConnected(false);
        eventSource.close();
        retryTimeout = setTimeout(connect, 5000);
      };
    };

    connect();

    return () => {
      if (eventSource) eventSource.close();
      if (retryTimeout) clearTimeout(retryTimeout);
    };
  }, [pushToast, authUser]);

  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === 'Escape' && confirmDialog.open) {
        closeConfirm(false);
      }
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [confirmDialog.open, closeConfirm]);

  // Support direct linking to fleet agent pages via hash (#/fleet/agent/:id)
  useEffect(() => {
    const handleHash = () => {
      const h = window.location.hash || '';
      if (h.startsWith('#/fleet/agent/')) {
        setActiveTab('fleet');
        return;
      }
      if (h === '#/fleet') {
        setActiveTab('fleet');
        return;
      }
      if (h.startsWith('#/incident/')) {
        const id = decodeURIComponent(h.replace('#/incident/', ''));
        if (id) {
          setSelectedIncidentId(id);
          setActiveTab('detail');
        }
        return;
      }
      if (h.startsWith('#/event/')) {
        const id = decodeURIComponent(h.replace('#/event/', ''));
        if (id) {
          setSelectedEventId(id);
          setActiveTab('eventDetail');
        }
        return;
      }
      if (h.startsWith('#/governance')) {
        setSelectedIncidentId(null);
        setSelectedEventId(null);
        setActiveTab('admin');
        return;
      }
      const tabMap = {
        '#/dashboard': 'dashboard',
        '#/analytics': 'analytics',
        '#/events': 'events',
        '#/policies': 'policies',
        '#/exceptions': 'exceptions',
        '#/profile': 'profile',
        '#/governance': 'admin',
        '#/users': 'admin',
        '#/lab': 'lab',
      };
      if (tabMap[h]) {
        setSelectedIncidentId(null);
        setSelectedEventId(null);
        setActiveTab(tabMap[h]);
      }
    };
    handleHash();
    window.addEventListener('hashchange', handleHash);
    return () => window.removeEventListener('hashchange', handleHash);
  }, []);

  // Keep URL hash in sync with current view for deep-linking/new-tab support.
  useEffect(() => {
    const current = window.location.hash || '';
    let next = '#/dashboard';
    if (activeTab === 'detail' && selectedIncidentId) next = `#/incident/${encodeURIComponent(selectedIncidentId)}`;
    else if (activeTab === 'eventDetail' && selectedEventId) next = `#/event/${encodeURIComponent(selectedEventId)}`;
    else if (activeTab === 'fleet') {
      // keep current fleet agent deep link if already on one
      next = current.startsWith('#/fleet/agent/') ? current : '#/fleet';
    } else if (activeTab === 'analytics') next = '#/analytics';
    else if (activeTab === 'events') next = '#/events';
    else if (activeTab === 'policies') next = '#/policies';
    else if (activeTab === 'exceptions') next = '#/exceptions';
    else if (activeTab === 'profile') next = '#/profile';
    else if (activeTab === 'admin') next = current.startsWith('#/governance') ? current : '#/governance/overview';
    else if (activeTab === 'lab') next = '#/lab';

    if (next && current !== next) {
      window.history.replaceState(null, '', `${window.location.pathname}${next}`);
    }
  }, [activeTab, selectedIncidentId, selectedEventId]);

  const handleSelectIncident = (id) => {
    setSelectedIncidentId(id);
    setActiveTab('detail');
    window.location.hash = `#/incident/${encodeURIComponent(id)}`;
  };

  const handleBackFromDetail = () => {
    setSelectedIncidentId(null);
    setActiveTab('dashboard');
    window.location.hash = '#/dashboard';
  };

  const handleSelectEvent = (id) => {
    if (!id) return;
    setSelectedEventId(id);
    setActiveTab('eventDetail');
    window.location.hash = `#/event/${encodeURIComponent(id)}`;
  };

  const handleBackFromEventDetail = () => {
    setSelectedEventId(null);
    setActiveTab('events');
    window.location.hash = '#/events';
  };

  const pageTitle = () => {
    if (activeTab === 'detail') return `Incident ${selectedIncidentId}`;
    if (activeTab === 'eventDetail') return `Event ${selectedEventId}`;
    if (activeTab === 'events') return 'Event Log';
    if (activeTab === 'analytics') return 'Analytics';
    if (activeTab === 'fleet') return 'Fleet Monitor';
    if (activeTab === 'policies') return 'Policy Engine';
    if (activeTab === 'exceptions') return 'Exceptions';
    if (activeTab === 'profile') return 'Profile & Settings';
    if (activeTab === 'admin') return 'IAM & Governance';
    if (activeTab === 'lab') return 'AI Policy Lab';
    return 'Home';
  };

  const can = (permission) => authPermissions.includes(permission) || String(authUser?.role || '').toUpperCase() === 'SUPER_ADMIN';

  const isTabAllowed = (tabId) => {
    if (tabId === 'profile') return true;
    if (tabId === 'dashboard') return can('dashboard.view');
    if (tabId === 'analytics') return can('incidents.view');
    if (tabId === 'events') return can('events.view');
    if (tabId === 'fleet') return can('fleet.view');
    if (tabId === 'policies') return can('policies.view');
    if (tabId === 'exceptions') return can('exceptions.view');
    if (tabId === 'admin') return can('users.manage') || can('iam.manage');
    if (tabId === 'lab') return can('ai_lab.manage');
    return false;
  };

  const navItems = [
    ...(isTabAllowed('dashboard') ? [{ id: 'dashboard', icon: '', label: 'Home' }] : []),
    ...(isTabAllowed('analytics') ? [{ id: 'analytics', icon: '', label: 'Analytics' }] : []),
    ...(isTabAllowed('events') ? [{ id: 'events', icon: '', label: 'Event Log' }] : []),
    ...(isTabAllowed('fleet') ? [{ id: 'fleet', icon: '', label: 'Fleet Monitor' }] : []),
    ...(can('policies.view') ? [{ id: 'policies', icon: '', label: 'Policy Engine' }] : []),
    ...(can('exceptions.view') ? [{ id: 'exceptions', icon: '', label: 'Exceptions' }] : []),
    { id: 'profile', icon: '', label: 'Profile' },
    ...((can('users.manage') || can('iam.manage')) ? [{ id: 'admin', icon: '', label: 'Admin' }] : []),
    ...(can('ai_lab.manage') ? [{ id: 'lab', icon: '', label: 'AI Lab' }] : []),
  ];

  const hashForTab = (tabId) => {
    if (tabId === 'admin') return '#/governance/overview';
    if (tabId === 'dashboard') return '#/dashboard';
    if (tabId === 'analytics') return '#/analytics';
    if (tabId === 'events') return '#/events';
    if (tabId === 'fleet') return '#/fleet';
    if (tabId === 'policies') return '#/policies';
    if (tabId === 'exceptions') return '#/exceptions';
    if (tabId === 'profile') return '#/profile';
    if (tabId === 'lab') return '#/lab';
    return '#/dashboard';
  };

  useEffect(() => {
    if (!authUser) return;
    const allowedTabs = new Set(navItems.map((n) => n.id));
    if ((activeTab === 'detail' && selectedIncidentId) || (activeTab === 'eventDetail' && selectedEventId)) {
      return;
    }
    if (!allowedTabs.has(activeTab)) {
      const fallback = navItems[0]?.id || 'profile';
      setActiveTab(fallback);
      const nextHash = fallback === 'profile' ? '#/profile' : `#/${fallback}`;
      if ((window.location.hash || '') !== nextHash) window.location.hash = nextHash;
    }
  }, [authUser, activeTab, navItems, selectedIncidentId, selectedEventId]);

  if (authLoading) {
    return <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', color: 'var(--text-muted)' }}>Loading...</div>;
  }

  if (!authUser) {
    return <Login apiBase={API_BASE} onLogin={handleLogin} />;
  }

  if (authUser?.must_change_password) {
    return (
      <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: 'var(--main-content-bg)', padding: '20px' }}>
        <div style={{ width: '100%', maxWidth: '460px', background: 'var(--panel-bg)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '24px', boxShadow: 'var(--card-shadow)' }}>
          <h2 style={{ color: 'var(--text-strong)', marginBottom: '8px' }}>Change Password Required</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '14px' }}>You are already signed in. Update your password once to continue; after that you can change it any time from Profile settings.</p>
          <div className="form-group">
            <label>Current Password</label>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input className="form-control" type={pwShowOld ? 'text' : 'password'} value={pwOld} onChange={(e) => setPwOld(e.target.value)} />
              <button
                type="button"
                className="btn"
                style={{ background: 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }}
                onClick={() => setPwShowOld(v => !v)}
              >
                {pwShowOld ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>
          <div className="form-group">
            <label>New Password (min 8 chars)</label>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input className="form-control" type={pwShowNew ? 'text' : 'password'} value={pwNew} onChange={(e) => setPwNew(e.target.value)} />
              <button
                type="button"
                className="btn"
                style={{ background: 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }}
                onClick={() => setPwShowNew(v => !v)}
              >
                {pwShowNew ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>
          <div className="form-group">
            <label>Confirm New Password</label>
            <input className="form-control" type={pwShowNew ? 'text' : 'password'} value={pwConfirm} onChange={(e) => setPwConfirm(e.target.value)} />
          </div>
          {pwMsg && <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '10px' }}>{pwMsg}</div>}
          <button
            className="btn"
            disabled={pwBusy || !pwOld || pwNew.length < 8 || pwNew !== pwConfirm}
            onClick={async () => {
              setPwBusy(true);
              setPwMsg('');
              try {
                if (pwNew !== pwConfirm) {
                  setPwMsg('New password and confirmation do not match');
                } else {
                  const out = await submitPasswordChange({ oldPassword: pwOld, newPassword: pwNew });
                  if (!out.ok) {
                    setPwMsg(out.error);
                  } else {
                    setPwOld('');
                    setPwNew('');
                    setPwConfirm('');
                    setPwMsg('Password updated.');
                    pushToast('Password updated successfully', 'success');
                  }
                }
              } catch (_) {
                setPwMsg('Failed to change password');
              }
              setPwBusy(false);
            }}
            style={{ width: '100%' }}
          >
            {pwBusy ? 'Updating...' : 'Update Password'}
          </button>
          <button className="btn" style={{ width: '100%', marginTop: '10px', background: 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }} onClick={handleLogout}>Logout</button>
        </div>
      </div>
    );
  }

  return (
    <AppErrorBoundary>
    <div className="layout">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="brand">
          Tron SIEM
        </div>
        <nav>
          {navItems.map(item => (
            <a key={item.id}
              href={hashForTab(item.id)}
              className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
              style={{ textDecoration: 'none' }}
              onClick={() => { setActiveTab(item.id); if (item.id !== 'detail') setSelectedIncidentId(null); if (item.id !== 'eventDetail') setSelectedEventId(null); }}
            >
              {item.icon} {item.label}
            </a>
          ))}
        </nav>

        {/* SSE Status */}
        <div style={{
          marginTop: 'auto', padding: '16px 20px', borderTop: '1px solid var(--border-color)',
          fontSize: '12px', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '8px'
        }}>
          <div style={{
            width: '8px', height: '8px', borderRadius: '50%',
            background: sseConnected ? '#2ea043' : '#f85149',
            boxShadow: sseConnected ? '0 0 8px #2ea043' : '0 0 8px #f85149',
            animation: sseConnected ? 'pulse 2s infinite' : 'none',
          }} />
          {sseConnected ? 'Live Stream Connected' : 'Reconnecting...'}
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
          <h1 className="page-title">
            {pageTitle()}
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--text-muted)', fontSize: '14px' }}>
            <span style={{ fontSize: '12px' }}>{authUser.display_name} ({authUser.role})</span>
            <button className="btn" style={{ background: 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }} onClick={handleLogout}>Logout</button>
            <button
              className="theme-toggle"
              onClick={() => setTheme(prev => (prev === 'dark' ? 'light' : 'dark'))}
              aria-label="Toggle theme"
            >
              {theme === 'dark' ? 'Light' : 'Dark'}
            </button>
            <div className="pulse"></div> System Active — Syncing rules with endpoint agents
          </div>
        </header>

        {activeTab === 'dashboard' && (
          <Dashboard stats={stats} incidents={incidents} onSelectIncident={handleSelectIncident} apiBase={API_BASE} onIncidentsChanged={fetchDashboardData} currentUser={authUser} />
        )}
        {activeTab === 'detail' && selectedIncidentId && (
          <EventDetail incidentId={selectedIncidentId} apiBase={API_BASE} onBack={handleBackFromDetail} />
        )}
        {activeTab === 'analytics' && <Analytics apiBase={API_BASE} theme={theme} />}
        {activeTab === 'events' && (
          <EventsLog apiBase={API_BASE} onSelectEvent={handleSelectEvent} />
        )}
        {activeTab === 'eventDetail' && selectedEventId && (
          <EventRecordDetail eventId={selectedEventId} apiBase={API_BASE} onBack={handleBackFromEventDetail} />
        )}
        {activeTab === 'fleet' && <FleetView apiBase={API_BASE} notify={pushToast} confirmAction={askConfirm} />}
        {activeTab === 'policies' && <Policies apiBase={API_BASE} notify={pushToast} confirmAction={askConfirm} />}
        {activeTab === 'exceptions' && <Exceptions apiBase={API_BASE} notify={pushToast} confirmAction={askConfirm} />}
        {activeTab === 'profile' && (
          <Profile
            apiBase={API_BASE}
            currentUser={authUser}
            notify={pushToast}
            onUserUpdated={(u) => {
              if (u) {
                setAuthUser(u);
                applyThemePreference(u);
              }
            }}
          />
        )}
        {activeTab === 'admin' && <Governance apiBase={API_BASE} currentUser={authUser} notify={pushToast} confirmAction={askConfirm} />}
        {activeTab === 'lab' && <Lab apiBase={API_BASE} />}
      </main>

      {/* Toast Notifications Overlay */}
      <div style={{
        position: 'fixed', top: '20px', right: '20px', zIndex: 9999,
        display: 'flex', flexDirection: 'column', gap: '10px', maxWidth: '420px',
      }}>
        {toasts.map(toast => (
          <div key={toast.id} style={{
            background: 'var(--toast-bg)', border: `1px solid ${toast.color}`,
            borderLeft: `4px solid ${toast.color}`, borderRadius: '10px', padding: '14px 18px',
            backdropFilter: 'blur(12px)', boxShadow: `var(--toast-shadow), 0 0 15px ${toast.color}33`,
            animation: 'slideInRight 0.3s ease-out',
            cursor: 'pointer', transition: 'all 0.2s',
          }}
            onClick={() => {
              if (toast.incident_id) handleSelectIncident(toast.incident_id);
              setToasts(prev => prev.filter(t => t.id !== toast.id));
            }}
            onMouseOver={e => e.currentTarget.style.transform = 'translateX(-4px)'}
            onMouseOut={e => e.currentTarget.style.transform = 'none'}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
              <span style={{ color: toast.color, fontSize: '12px', fontWeight: 700, letterSpacing: '0.5px', textTransform: 'uppercase' }}>
                {toast.severity} ALERT
              </span>
              <span style={{ color: 'var(--text-muted)', fontSize: '10px' }}>{toast.timestamp}</span>
            </div>
            <div style={{ color: 'var(--text-soft)', fontSize: '13px', lineHeight: '1.4' }}>{toast.message}</div>
            <div style={{ color: 'var(--text-muted)', fontSize: '10px', marginTop: '4px' }}>Click to investigate →</div>
          </div>
        ))}
      </div>

      {confirmDialog.open && (
        <div className="modal-backdrop" onClick={() => closeConfirm(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <h3 className="modal-title">{confirmDialog.title}</h3>
            <p className="modal-message">{confirmDialog.message}</p>
            <div className="modal-actions">
              <button className="btn modal-btn-cancel" onClick={() => closeConfirm(false)}>{confirmDialog.cancelText}</button>
              <button
                className="btn"
                style={{ backgroundColor: confirmDialog.tone === 'danger' ? 'var(--danger)' : 'var(--warning)', color: 'var(--text-inverse)' }}
                onClick={() => closeConfirm(true)}
              >
                {confirmDialog.confirmText}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
    </AppErrorBoundary>
  );
}

export default App;
