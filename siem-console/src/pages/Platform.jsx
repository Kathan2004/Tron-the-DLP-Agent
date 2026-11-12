import { useCallback, useEffect, useState } from 'react';
import Icon from '../components/Icons';
import { runSoon } from '../utils';

const TABS = [
  { id: 'protection', label: 'Data protection' },
  { id: 'agents', label: 'Agent credentials' },
  { id: 'retention', label: 'Retention' },
  { id: 'siem', label: 'SIEM forwarding' },
];

const api = async (url, options = {}) => {
  const init = { ...options };
  if (init.body && typeof init.body !== 'string') {
    init.body = JSON.stringify(init.body);
    init.headers = { 'Content-Type': 'application/json', ...(init.headers || {}) };
  }
  const res = await fetch(url, init);
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
};

const fmtTime = (value) => {
  if (!value) return '-';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
};

const StatusRow = ({ ok, label, detail }) => (
  <tr>
    <td style={{ width: 110 }}>
      <span className={`chip ${ok ? 'chip-success' : 'chip-warning'}`}>{ok ? 'OK' : 'Action needed'}</span>
    </td>
    <td style={{ fontWeight: 600, color: 'var(--text-strong)' }}>{label}</td>
    <td className="field-hint">{detail}</td>
  </tr>
);

// ---------------------------------------------------------------- Data protection

const ProtectionTab = ({ apiBase }) => {
  const [state, setState] = useState(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    const { ok, body } = await api(`${apiBase}/settings/data-protection`);
    if (ok) { setState(body); setError(''); } else setError(body.error || 'Could not load status');
  }, [apiBase]);
  useEffect(() => runSoon(load), [load]);

  if (error) return <div className="notice notice-error">{error}</div>;
  if (!state) return <div className="empty-state">Loading...</div>;
  const chain = state.audit_chain || {};
  const mode = state.agent_auth_mode;

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Security posture</div>
          <div className="card-subtitle">Configuration that protects stored detections and the ingest API. Set through environment variables on the API host.</div>
        </div>
        <button className="btn btn-secondary btn-sm" onClick={load}><Icon name="refresh" size={13} /> Re-check</button>
      </div>
      <div className="table-wrap">
        <table className="data-table">
          <tbody>
            <StatusRow ok={state.encryption_at_rest} label="Encryption at rest"
              detail={state.encryption_at_rest
                ? 'Matched values, payload samples, captured files and screenshots are sealed with AES-256-GCM.'
                : 'Disabled (TRON_ENCRYPT_AT_REST=0). Findings are stored in plaintext.'} />
            <StatusRow ok={state.data_key_source === 'environment'} label="Data key location"
              detail={state.data_key_source === 'environment'
                ? 'Supplied through TRON_DATA_KEY, separate from the database.'
                : 'Stored in a key file next to the database. Set TRON_DATA_KEY from a secret manager so a copied database is unreadable on its own.'} />
            <StatusRow ok={mode === 'strict'} label="Agent authentication"
              detail={mode === 'strict' ? 'Every ingest request must carry a per-agent key.'
                : mode === 'token' ? 'Shared enrollment token is still accepted on ingest. Set TRON_AGENT_AUTH=strict once all agents hold a key.'
                  : 'Ingest endpoints are unauthenticated. Set TRON_AGENT_TOKEN.'} />
            <StatusRow ok={state.auth_secret_persistent} label="Session signing secret"
              detail={state.auth_secret_persistent ? 'APP_AUTH_SECRET is set.' : 'APP_AUTH_SECRET is unset; all console sessions end when the API restarts.'} />
            <StatusRow ok={chain.ok} label="Audit log integrity"
              detail={chain.ok
                ? `${chain.checked} chained entries verified${chain.unchained ? `, ${chain.unchained} older entries predate chaining` : ''}.`
                : `Hash chain broken at entry ${chain.first_bad_id}. The audit log was modified outside the application.`} />
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------- Agent credentials

const AgentsTab = ({ apiBase, notify, confirmAction }) => {
  const [data, setData] = useState({ credentials: [], auth_mode: '', enrollment_enabled: false });
  const [loading, setLoading] = useState(true);
  const [issueId, setIssueId] = useState('');
  const [issued, setIssued] = useState(null);

  const load = useCallback(async () => {
    const { ok, body } = await api(`${apiBase}/fleet/credentials`);
    if (ok) setData(body);
    setLoading(false);
  }, [apiBase]);
  useEffect(() => runSoon(load), [load]);

  const act = async (label, url, method, okMessage) => {
    const { ok, body } = await api(url, { method });
    if (!ok) { notify?.(body.message || body.error || `${label} failed`, 'high'); return null; }
    notify?.(okMessage, 'success');
    load();
    return body;
  };

  const revoke = async (c) => {
    const ok = await confirmAction?.({
      title: 'Revoke agent key', message: `${c.agent_id} will be rejected by the API until it is enrolled again.`,
      confirmText: 'Revoke', tone: 'danger',
    });
    if (ok) act('Revoke', `${apiBase}/fleet/agents/${encodeURIComponent(c.agent_id)}/key`, 'DELETE', 'Key revoked');
  };

  const issue = async () => {
    const id = issueId.trim();
    if (!id) return;
    const body = await act('Issue', `${apiBase}/fleet/agents/${encodeURIComponent(id)}/key`, 'POST', 'Key issued');
    if (body) { setIssued(body); setIssueId(''); }
  };

  return (
    <>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="stat-inline">
          <div><strong>{data.credentials.filter(c => !c.revoked_at).length}</strong>active keys</div>
          <div><strong>{data.credentials.filter(c => c.revoked_at).length}</strong>revoked</div>
          <div><strong>{String(data.auth_mode || '-').toUpperCase()}</strong>ingest auth mode</div>
          <div><strong>{data.enrollment_enabled ? 'ON' : 'OFF'}</strong>self-enrollment</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">Per-agent keys</div>
            <div className="card-subtitle">Agents enroll with the enrollment token and then use their own key. Only a hash of each key is stored.</div>
          </div>
        </div>
        <div className="toolbar">
          <input className="form-control mono" style={{ minWidth: 320 }} placeholder="Agent ID to pre-provision"
            value={issueId} onChange={e => setIssueId(e.target.value)} />
          <button className="btn" onClick={issue} disabled={!issueId.trim()}><Icon name="plus" size={14} /> Issue key</button>
        </div>
        {issued && (
          <div className="notice notice-success" style={{ marginBottom: 14 }}>
            <div style={{ fontWeight: 700, marginBottom: 6 }}>Key for {issued.agent_id}. Copy it now; it is not shown again.</div>
            <div className="highlight-box" style={{ userSelect: 'all' }}>{issued.agent_key}</div>
            <div className="btn-row" style={{ marginTop: 8 }}>
              <button className="btn btn-secondary btn-sm" onClick={() => navigator.clipboard?.writeText(issued.agent_key)}><Icon name="copy" size={13} /> Copy</button>
              <button className="btn btn-secondary btn-sm" onClick={() => setIssued(null)}>Dismiss</button>
            </div>
          </div>
        )}
        {loading ? <div className="empty-state">Loading...</div>
          : data.credentials.length === 0 ? (
            <div className="empty-state"><strong>No agent keys yet</strong>Set TRON_AGENT_TOKEN on the API and on the agents; each agent obtains its key on first contact.</div>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr><th>Agent</th><th>Key</th><th>Status</th><th>Enrolled</th><th>Rotated</th><th>Last used</th><th style={{ width: 190 }} /></tr>
                </thead>
                <tbody>
                  {data.credentials.map(c => (
                    <tr key={c.agent_id} className={c.revoked_at ? 'row-disabled' : ''}>
                      <td>
                        <div className="mono" style={{ fontWeight: 700, color: 'var(--text-strong)' }}>{c.agent_id}</div>
                        <div className="field-hint">{[c.agent_type, c.hostname].filter(Boolean).join(' on ') || '-'}</div>
                      </td>
                      <td className="mono">{c.key_prefix}...</td>
                      <td>{c.revoked_at
                        ? <span className="chip chip-danger" title={`by ${c.revoked_by || 'unknown'}`}>Revoked</span>
                        : <span className="chip chip-success">Active</span>}</td>
                      <td>{fmtTime(c.created_at)}<div className="field-hint">{c.created_by}</div></td>
                      <td>{fmtTime(c.rotated_at)}</td>
                      <td>{fmtTime(c.last_used_at)}<div className="field-hint mono">{c.last_ip}</div></td>
                      <td>
                        {!c.revoked_at && (
                          <div className="btn-row">
                            <button className="btn btn-secondary btn-sm"
                              onClick={() => act('Rotation', `${apiBase}/fleet/agents/${encodeURIComponent(c.agent_id)}/key/rotation`, 'POST', 'Rotation queued for next check-in')}>
                              Rotate
                            </button>
                            <button className="btn btn-danger-outline btn-sm" onClick={() => revoke(c)}>Revoke</button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </div>
    </>
  );
};

// ---------------------------------------------------------------- Retention

const RetentionTab = ({ apiBase, notify, confirmAction }) => {
  const [data, setData] = useState(null);
  const [draft, setDraft] = useState({});
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const { ok, body } = await api(`${apiBase}/settings/retention`);
    if (ok) { setData(body); setDraft(body.retention_days || {}); }
  }, [apiBase]);
  useEffect(() => runSoon(load), [load]);

  if (!data) return <div className="empty-state">Loading...</div>;

  const save = async () => {
    setBusy(true);
    const { ok, body } = await api(`${apiBase}/settings/retention`, { method: 'PUT', body: { retention_days: draft } });
    setBusy(false);
    if (!ok) { notify?.(body.error || 'Save failed', 'high'); return; }
    notify?.('Retention policy saved', 'success');
    load();
  };

  const runNow = async () => {
    const ok = await confirmAction?.({
      title: 'Apply retention now', message: 'Data older than the saved periods is deleted permanently.',
      confirmText: 'Delete expired data', tone: 'danger',
    });
    if (!ok) return;
    setBusy(true);
    const { ok: done, body } = await api(`${apiBase}/settings/retention/run`, { method: 'POST' });
    setBusy(false);
    if (!done) { notify?.(body.error || 'Run failed', 'high'); return; }
    const total = Object.values(body.deleted || {}).reduce((a, b) => a + Number(b || 0), 0);
    notify?.(total ? `Removed ${total} expired records` : 'Nothing was past its retention period', 'success');
    load();
  };

  const dirty = JSON.stringify(draft) !== JSON.stringify(data.retention_days);

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Retention periods</div>
          <div className="card-subtitle">Days to keep each class of data. 0 keeps it indefinitely. The job runs hourly. The audit log is never pruned.</div>
        </div>
        <div className="btn-row">
          <button className="btn btn-secondary" onClick={runNow} disabled={busy || dirty} title={dirty ? 'Save changes first' : ''}>Apply now</button>
          <button className="btn" onClick={save} disabled={busy || !dirty}>{busy ? 'Working...' : 'Save'}</button>
        </div>
      </div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Data class</th><th style={{ width: 160 }}>Keep for (days)</th><th style={{ width: 160 }}>Effect</th></tr></thead>
          <tbody>
            {Object.entries(data.data_classes || {}).map(([key, label]) => {
              const value = Number(draft[key] ?? 0);
              return (
                <tr key={key}>
                  <td><div style={{ fontWeight: 600, color: 'var(--text-strong)' }}>{label}</div><div className="field-hint mono">{key}</div></td>
                  <td>
                    <input className="form-control" type="number" min={0} max={data.max_days} value={value}
                      onChange={e => setDraft({ ...draft, [key]: Math.max(0, Math.min(data.max_days, parseInt(e.target.value || '0', 10) || 0)) })} />
                  </td>
                  <td>{value ? <span className="chip chip-warning">deleted after {value}d</span> : <span className="chip">kept indefinitely</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------- SIEM forwarding

const NEW_DEST = {
  syslog: { type: 'syslog', enabled: true, host: '', port: 6514, protocol: 'tls', format: 'cef', min_severity: 'low', ca_pem: '' },
  webhook: { type: 'webhook', enabled: true, url: '', format: 'json', min_severity: 'low', secret: '', auth_header: '', ca_pem: '' },
};

const SiemTab = ({ apiBase, notify }) => {
  const [data, setData] = useState(null);
  const [config, setConfig] = useState({ enabled: false, destinations: [] });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    const { ok, body } = await api(`${apiBase}/siem/config`);
    if (ok) { setData(body); setConfig(body.config); }
  }, [apiBase]);
  useEffect(() => runSoon(load), [load]);

  if (!data) return <div className="empty-state">Loading...</div>;
  const kinds = data.record_kinds || [];

  const update = (index, patch) => setConfig({
    ...config, destinations: config.destinations.map((d, i) => (i === index ? { ...d, ...patch } : d)),
  });
  const add = (type) => setConfig({
    ...config,
    destinations: [...config.destinations, { ...NEW_DEST[type], id: `${type}-${config.destinations.length + 1}`, record_kinds: [...kinds] }],
  });
  const remove = (index) => setConfig({ ...config, destinations: config.destinations.filter((_, i) => i !== index) });

  const save = async () => {
    setBusy(true); setError('');
    const { ok, body } = await api(`${apiBase}/siem/config`, { method: 'PUT', body: { config } });
    setBusy(false);
    if (!ok) { setError(body.error || 'Save failed'); return; }
    notify?.('Forwarding configuration saved', 'success');
    load();
  };

  const test = async (id) => {
    setBusy(true);
    const { ok, body } = await api(`${apiBase}/siem/test`, { method: 'POST', body: { destination_id: id } });
    setBusy(false);
    notify?.(ok ? `Test record delivered to ${id}` : `Delivery to ${id} failed: ${body.error || 'unknown error'}`, ok ? 'success' : 'high');
  };

  const saved = new Set((data.config.destinations || []).map(d => d.id));

  return (
    <>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="stat-inline">
          <div><strong>{data.outbox?.pending ?? 0}</strong>queued</div>
          <div><strong>{data.delivered ?? 0}</strong>delivered since start</div>
          <div><strong>{data.failed ?? 0}</strong>failed attempts</div>
        </div>
        {data.outbox?.last_error && <div className="notice notice-error" style={{ marginTop: 12 }}>Last delivery error: {data.outbox.last_error}</div>}
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">Destinations</div>
            <div className="card-subtitle">Incidents, detections and audit records are queued durably and delivered at least once. Matched values are never forwarded.</div>
          </div>
          <label className="switch" title="Enable forwarding">
            <input type="checkbox" checked={!!config.enabled} onChange={e => setConfig({ ...config, enabled: e.target.checked })} />
            <span />
          </label>
        </div>

        {config.destinations.length === 0 && (
          <div className="empty-state"><strong>No destinations</strong>Add a syslog collector or an HTTPS endpoint.</div>
        )}

        {config.destinations.map((d, i) => (
          <div key={i} className="card" style={{ marginBottom: 12, background: 'var(--surface-subtle)' }}>
            <div className="card-header">
              <div className="btn-row">
                <span className="chip chip-accent">{d.type}</span>
                <input className="form-control mono" style={{ width: 200 }} value={d.id} onChange={e => update(i, { id: e.target.value })} aria-label="Destination ID" />
              </div>
              <div className="btn-row">
                <label className="switch"><input type="checkbox" checked={d.enabled !== false} onChange={e => update(i, { enabled: e.target.checked })} /><span /></label>
                <button className="btn btn-secondary btn-sm" disabled={busy || !saved.has(d.id)} title={saved.has(d.id) ? '' : 'Save first'} onClick={() => test(d.id)}>Send test</button>
                <button className="btn btn-danger-outline btn-sm" onClick={() => remove(i)}>Remove</button>
              </div>
            </div>
            {d.type === 'syslog' ? (
              <div className="grid-3">
                <div className="form-group"><label>Host</label><input className="form-control" value={d.host || ''} onChange={e => update(i, { host: e.target.value })} placeholder="siem.example.com" /></div>
                <div className="form-group"><label>Port</label><input className="form-control" type="number" value={d.port || ''} onChange={e => update(i, { port: parseInt(e.target.value || '0', 10) })} /></div>
                <div className="form-group"><label>Transport</label>
                  <select className="form-control" value={d.protocol} onChange={e => update(i, { protocol: e.target.value })}>
                    <option value="tls">TLS</option><option value="tcp">TCP (unencrypted)</option><option value="udp">UDP (unencrypted)</option>
                  </select>
                </div>
                <div className="form-group"><label>Format</label>
                  <select className="form-control" value={d.format} onChange={e => update(i, { format: e.target.value })}>
                    <option value="cef">CEF</option><option value="json">JSON</option>
                  </select>
                </div>
              </div>
            ) : (
              <div className="grid-2">
                <div className="form-group"><label>URL</label><input className="form-control" value={d.url || ''} onChange={e => update(i, { url: e.target.value })} placeholder="https://collector.example.com/services/collector/event" /></div>
                <div className="form-group"><label>Format</label>
                  <select className="form-control" value={d.format} onChange={e => update(i, { format: e.target.value })}>
                    <option value="json">JSON batch</option><option value="splunk_hec">Splunk HEC</option>
                  </select>
                </div>
                <div className="form-group"><label>Authorization header {d.has_auth_header && <span className="chip chip-success">stored</span>}</label>
                  <input className="form-control" type="password" autoComplete="off" value={d.auth_header || ''} onChange={e => update(i, { auth_header: e.target.value })} placeholder={d.has_auth_header ? 'Leave blank to keep' : 'Splunk <token> / Bearer <token>'} />
                </div>
                <div className="form-group"><label>Signing secret (HMAC-SHA256) {d.has_secret && <span className="chip chip-success">stored</span>}</label>
                  <input className="form-control" type="password" autoComplete="off" value={d.secret || ''} onChange={e => update(i, { secret: e.target.value })} placeholder={d.has_secret ? 'Leave blank to keep' : 'Optional'} />
                </div>
              </div>
            )}
            <div className="grid-2">
              <div className="form-group"><label>Record kinds</label>
                <div className="btn-row">
                  {kinds.map(k => {
                    const on = (d.record_kinds || []).includes(k);
                    return (
                      <button key={k} type="button" className={`chip ${on ? 'chip-accent' : ''}`} style={{ cursor: 'pointer', border: '1px solid var(--border-color)' }}
                        onClick={() => update(i, { record_kinds: on ? d.record_kinds.filter(x => x !== k) : [...(d.record_kinds || []), k] })}>
                        {on && <Icon name="check" size={11} />}{k}
                      </button>
                    );
                  })}
                </div>
              </div>
              <div className="form-group"><label>Minimum severity (incidents and detections)</label>
                <select className="form-control" value={d.min_severity || 'low'} onChange={e => update(i, { min_severity: e.target.value })}>
                  {['low', 'medium', 'high', 'critical'].map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
            </div>
            {(d.type === 'webhook' || d.protocol === 'tls') && (
              <div className="form-group"><label>Private CA certificate (PEM) {d.has_ca_pem && <span className="chip chip-success">stored</span>}</label>
                <textarea className="form-control mono" rows={3} value={d.ca_pem || ''} onChange={e => update(i, { ca_pem: e.target.value })}
                  placeholder={d.has_ca_pem ? 'Leave blank to keep' : 'Only needed when the collector uses a private CA. Certificates are always verified.'} />
              </div>
            )}
          </div>
        ))}

        {error && <div className="notice notice-error" style={{ marginBottom: 12 }}>{error}</div>}
        <div className="btn-row" style={{ justifyContent: 'space-between' }}>
          <div className="btn-row">
            <button className="btn btn-secondary" onClick={() => add('syslog')}><Icon name="plus" size={14} /> Syslog</button>
            <button className="btn btn-secondary" onClick={() => add('webhook')}><Icon name="plus" size={14} /> HTTPS endpoint</button>
          </div>
          <button className="btn" onClick={save} disabled={busy}>{busy ? 'Working...' : 'Save configuration'}</button>
        </div>
      </div>
    </>
  );
};

const Platform = ({ apiBase, notify, confirmAction, canSettings, canFleet }) => {
  const visible = TABS.filter(t => (t.id === 'agents' ? canFleet : canSettings));
  const [tab, setTab] = useState(visible[0]?.id);

  return (
    <div className="fade-in">
      <div className="tabs" role="tablist">
        {visible.map(t => (
          <button key={t.id} role="tab" aria-selected={tab === t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>
      {tab === 'protection' && <ProtectionTab apiBase={apiBase} />}
      {tab === 'agents' && <AgentsTab apiBase={apiBase} notify={notify} confirmAction={confirmAction} />}
      {tab === 'retention' && <RetentionTab apiBase={apiBase} notify={notify} confirmAction={confirmAction} />}
      {tab === 'siem' && <SiemTab apiBase={apiBase} notify={notify} />}
    </div>
  );
};

export default Platform;
