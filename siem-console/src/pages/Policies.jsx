import { useEffect, useMemo, useState } from 'react';
import Icon from '../components/Icons';
import { runSoon } from '../utils';

const EMPTY_FORM = {
  name: '', description: '', rule_type: 'detector', detector: 'CREDIT_CARD', value: '',
  action: 'warn', severity: 'HIGH', threshold_count: 1, threshold_window_mins: 60,
};

const TYPE_LABEL = { detector: 'Detector', regex: 'Regex', extension: 'File type', file_size: 'File size', network: 'Destination' };
const VALUE_LABEL = {
  regex: 'Regular expression',
  extension: 'Blocked extensions (separate with |)',
  file_size: 'Maximum file size (MB)',
  network: 'Blocked domains (comma-separated)',
};
const VALUE_PLACEHOLDER = {
  regex: '\\bPROJECT[ -]FALCON\\b',
  extension: '.exe|.bat|.scr',
  file_size: '25',
  network: 'pastebin.com, transfer.sh',
};
const SEV_CHIP = { critical: 'chip-danger', high: 'chip-warning', medium: 'chip-accent', low: '' };

const policyKind = (p) => {
  const rd = p?.rule_data || {};
  if ((p?.rule_type || 'regex') === 'regex' && rd.detector) return 'detector';
  return p?.rule_type || 'regex';
};

const valueForEdit = (p) => {
  const rd = p?.rule_data || {};
  switch (p?.rule_type) {
    case 'extension': return Array.isArray(rd.blocked_extensions) ? rd.blocked_extensions.join('|') : '';
    case 'file_size': return rd.max_size_mb != null ? String(rd.max_size_mb) : '';
    case 'network': return Array.isArray(rd.blocked_domains) ? rd.blocked_domains.join(', ') : '';
    default: return rd.pattern || p?.regex || '';
  }
};

const buildRuleData = (form, existing) => {
  const raw = String(form.value || '').trim();
  const meta = existing?.rule_data?._meta ? { _meta: existing.rule_data._meta } : {};
  switch (form.rule_type) {
    case 'detector': return { ...meta, detector: form.detector, ...(existing?.rule_data?.pattern ? { pattern: existing.rule_data.pattern } : {}) };
    case 'extension': return { ...meta, blocked_extensions: raw.split('|').map(x => x.trim()).filter(Boolean).map(x => (x.startsWith('.') ? x : `.${x}`)) };
    case 'file_size': return { ...meta, max_size_mb: Number(raw) || 10 };
    case 'network': return { ...meta, blocked_domains: raw.split(',').map(x => x.trim()).filter(Boolean) };
    default: return { ...meta, pattern: raw };
  }
};

const Policies = ({ apiBase, notify, confirmAction }) => {
  const [policies, setPolicies] = useState([]);
  const [detectors, setDetectors] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [editing, setEditing] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');

  const load = async () => {
    try {
      const [pr, dr] = await Promise.all([fetch(`${apiBase}/policies`), fetch(`${apiBase}/detectors`)]);
      const pd = await pr.json();
      const dd = await dr.json().catch(() => ({}));
      setPolicies(pd.policies || []);
      setDetectors(dd.detectors || []);
    } catch (_) {
      setError('Could not load policies');
    }
  };

  useEffect(() => runSoon(load), [apiBase]); // eslint-disable-line react-hooks/exhaustive-deps

  const detectorByName = useMemo(() => Object.fromEntries(detectors.map(d => [d.name, d])), [detectors]);
  const groupedDetectors = useMemo(() => {
    const groups = {};
    detectors.forEach(d => { (groups[d.category] = groups[d.category] || []).push(d); });
    return Object.entries(groups).sort();
  }, [detectors]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return policies.filter(p => {
      if (typeFilter !== 'all' && policyKind(p) !== typeFilter) return false;
      if (!q) return true;
      return [p.name, p.description, p.rule_data?.detector, p.rule_data?.pattern].some(x => String(x || '').toLowerCase().includes(q));
    });
  }, [policies, query, typeFilter]);

  const reset = () => { setForm(EMPTY_FORM); setEditing(null); setError(''); };

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    const existing = editing ? policies.find(p => p.policy_id === editing) : null;
    const ruleType = form.rule_type === 'detector' ? 'regex' : form.rule_type;
    const payload = {
      name: form.name.trim(),
      description: form.description,
      rule_type: ruleType,
      rule_data: buildRuleData(form, existing),
      severity: form.severity,
      action: form.action,
      threshold_count: Number(form.threshold_count) || 1,
      threshold_window_mins: Number(form.threshold_window_mins) || 60,
    };
    if (form.rule_type === 'detector') payload.detector = form.detector;
    else payload.pattern = form.value;
    try {
      const res = await fetch(editing ? `${apiBase}/policies/${editing}` : `${apiBase}/policies`, {
        method: editing ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(body.error || 'Could not save policy');
      } else {
        notify?.(editing ? `Policy ${payload.name} updated` : `Policy ${payload.name} deployed`, 'success');
        reset();
        load();
      }
    } catch (_) {
      setError('Could not reach the API');
    }
    setBusy(false);
  };

  const edit = (p) => {
    const kind = policyKind(p);
    setForm({
      name: p.name, description: p.description || '', rule_type: kind,
      detector: p.rule_data?.detector || 'CREDIT_CARD', value: valueForEdit(p),
      action: p.action || 'warn', severity: String(p.severity || 'MEDIUM').toUpperCase(),
      threshold_count: p.threshold_count || 1, threshold_window_mins: p.threshold_window_mins || 60,
    });
    setEditing(p.policy_id);
    setError('');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const isActive = (p) => !(p.is_active === 0 || p.is_active === false);

  const toggle = async (p) => {
    const next = !isActive(p);
    const ok = await confirmAction?.({
      title: next ? 'Enable policy' : 'Disable policy',
      message: `${next ? 'Enable' : 'Disable'} ${p.name}? Agents pick up the change on their next sync.`,
      confirmText: next ? 'Enable' : 'Disable', tone: 'warning',
    });
    if (!ok) return;
    const res = await fetch(`${apiBase}/policies/${p.policy_id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ is_active: next ? 1 : 0 }),
    });
    if (res.ok) load();
  };

  const remove = async (p) => {
    const ok = await confirmAction?.({
      title: 'Delete policy',
      message: `${isActive(p) ? 'This policy is active. ' : ''}Delete ${p.name} permanently?`,
      confirmText: 'Delete', tone: 'danger',
    });
    if (!ok) return;
    const res = await fetch(`${apiBase}/policies/${p.policy_id}`, { method: 'DELETE' });
    if (res.ok) {
      if (editing === p.policy_id) reset();
      notify?.(`Policy ${p.name} deleted`, 'success');
      load();
    } else {
      const body = await res.json().catch(() => ({}));
      notify?.(body.error || 'Could not delete policy', 'error');
    }
  };

  const matchSummary = (p) => {
    const rd = p.rule_data || {};
    const kind = policyKind(p);
    if (kind === 'detector') {
      const d = detectorByName[rd.detector];
      return (
        <span className="btn-row" style={{ gap: '6px' }}>
          <span className="mono" style={{ fontWeight: 600 }}>{rd.detector}</span>
          {d?.validator && <span className="chip chip-success"><Icon name="check" size={11} />{d.validator}</span>}
          {d && d.enabled === false && <span className="chip chip-danger">detector disabled</span>}
          {!d && detectors.length > 0 && <span className="chip chip-danger">unknown detector</span>}
        </span>
      );
    }
    if (kind === 'extension') return <span className="mono">{(rd.blocked_extensions || []).join(' ')}</span>;
    if (kind === 'file_size') return <span>&gt; {rd.max_size_mb} MB</span>;
    if (kind === 'network') return <span className="mono">{(rd.blocked_domains || []).join(', ')}</span>;
    return <span className="mono" style={{ wordBreak: 'break-all' }}>/{rd.pattern || p.regex}/</span>;
  };

  const selected = detectorByName[form.detector];

  return (
    <div className="split fade-in">
      <form className="card" onSubmit={submit} style={{ borderColor: editing ? 'var(--warning)' : undefined }}>
        <div className="card-title">{editing ? 'Edit policy' : 'New policy'}</div>
        <div className="card-subtitle" style={{ marginBottom: '14px' }}>Policies sync to every endpoint agent and browser extension.</div>

        <div className="form-group">
          <label>Name</label>
          <input className="form-control" required value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="e.g. Payment card exfiltration" />
        </div>
        <div className="form-group">
          <label>Description</label>
          <textarea className="form-control" rows={2} value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Why this policy exists and who owns it" />
        </div>
        <div className="form-group">
          <label>Match on</label>
          <select className="form-control" value={form.rule_type} onChange={e => setForm({ ...form, rule_type: e.target.value, value: '' })}>
            <option value="detector">Detector from the library (validated)</option>
            <option value="regex">Custom regular expression</option>
            <option value="extension">File type</option>
            <option value="file_size">File size</option>
            <option value="network">Destination domain</option>
          </select>
        </div>

        {form.rule_type === 'detector' ? (
          <div className="form-group">
            <label>Detector</label>
            <select className="form-control" value={form.detector} onChange={e => setForm({ ...form, detector: e.target.value })}>
              {groupedDetectors.map(([cat, list]) => (
                <optgroup key={cat} label={cat}>
                  {list.map(d => <option key={d.name} value={d.name}>{d.name}{d.enabled === false ? ' (disabled)' : ''}</option>)}
                </optgroup>
              ))}
            </select>
            {selected && (
              <div className="field-hint">
                {selected.description}. {selected.validator ? `Checksum: ${selected.validator}. ` : ''}
                {(selected.keywords || []).length ? `Keywords${selected.require_keyword ? ' (required)' : ''}: ${selected.keywords.slice(0, 4).join(', ')}.` : ''}
              </div>
            )}
          </div>
        ) : (
          <div className="form-group">
            <label>{VALUE_LABEL[form.rule_type]}</label>
            <input className={`form-control ${form.rule_type === 'regex' ? 'mono' : ''}`} required type={form.rule_type === 'file_size' ? 'number' : 'text'}
              min={form.rule_type === 'file_size' ? 1 : undefined} value={form.value} onChange={e => setForm({ ...form, value: e.target.value })}
              placeholder={VALUE_PLACEHOLDER[form.rule_type]} />
            {form.rule_type === 'regex' && <div className="field-hint">Need a checksum or keyword context? Build a detector in the Detection Lab instead.</div>}
          </div>
        )}

        <div className="grid-2">
          <div className="form-group">
            <label>Action</label>
            <select className="form-control" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>
              <option value="monitor">Monitor</option><option value="warn">Warn</option><option value="block">Block</option>
            </select>
          </div>
          <div className="form-group">
            <label>Severity</label>
            <select className="form-control" value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label>Threshold (hits)</label>
            <input type="number" min="1" className="form-control" value={form.threshold_count} onChange={e => setForm({ ...form, threshold_count: e.target.value })} />
          </div>
          <div className="form-group">
            <label>Window (minutes)</label>
            <input type="number" min="1" className="form-control" value={form.threshold_window_mins} onChange={e => setForm({ ...form, threshold_window_mins: e.target.value })} />
          </div>
        </div>
        <div className="field-hint" style={{ marginTop: '-6px', marginBottom: '12px' }}>An incident opens when a user hits this policy {form.threshold_count || 1} time(s) within {form.threshold_window_mins || 60} minutes.</div>

        {error && <div className="notice notice-error" style={{ marginBottom: '12px' }}>{error}</div>}
        <div className="btn-row">
          <button type="submit" className="btn" disabled={busy} style={{ flex: 1 }}>{busy ? 'Saving...' : editing ? 'Save changes' : 'Deploy policy'}</button>
          {editing && <button type="button" className="btn btn-secondary" onClick={reset}>Cancel</button>}
        </div>
      </form>

      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">Policies ({policies.length})</div>
            <div className="card-subtitle">{policies.filter(isActive).length} active</div>
          </div>
        </div>
        <div className="toolbar">
          <input className="form-control" style={{ minWidth: '220px' }} placeholder="Search policies" value={query} onChange={e => setQuery(e.target.value)} />
          <select className="form-control" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
            <option value="all">All types</option>
            {Object.entries(TYPE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </div>
        {filtered.length === 0 ? (
          <div className="empty-state">
            <strong>{policies.length ? 'No policies match' : 'No policies yet'}</strong>
            {policies.length ? 'Adjust the search or filter.' : 'Without policies, detections are still logged but no incidents are opened.'}
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th style={{ width: 52 }}>On</th><th>Policy</th><th>Match</th><th>Trigger</th><th>Severity</th><th style={{ width: 160 }} /></tr></thead>
              <tbody>
                {filtered.map(p => (
                  <tr key={p.policy_id} className={`${isActive(p) ? '' : 'row-disabled'} ${editing === p.policy_id ? 'row-selected' : ''}`}>
                    <td><label className="switch"><input type="checkbox" checked={isActive(p)} onChange={() => toggle(p)} /><span /></label></td>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--text-strong)' }}>
                        {p.name} {(p.rule_data?._meta?.source === 'ai_lab') && <span className="chip chip-accent">Lab</span>}
                      </div>
                      {p.description && <div className="field-hint">{p.description}</div>}
                    </td>
                    <td><div className="field-hint" style={{ marginTop: 0 }}>{TYPE_LABEL[policyKind(p)]}</div>{matchSummary(p)}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <div style={{ fontWeight: 600 }}>{String(p.action || 'monitor').toUpperCase()}</div>
                      <div className="field-hint">{p.threshold_count}x / {p.threshold_window_mins} min</div>
                    </td>
                    <td><span className={`chip ${SEV_CHIP[String(p.severity).toLowerCase()] || ''}`}>{p.severity}</span></td>
                    <td>
                      <div className="btn-row" style={{ justifyContent: 'flex-end', flexWrap: 'nowrap' }}>
                        <button className="btn btn-secondary btn-sm" onClick={() => edit(p)}>Edit</button>
                        <button className="btn btn-danger-outline btn-sm" onClick={() => remove(p)}>Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default Policies;
