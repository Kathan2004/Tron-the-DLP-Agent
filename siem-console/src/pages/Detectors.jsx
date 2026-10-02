import { useEffect, useMemo, useState } from 'react';
import Icon from '../components/Icons';
import DetectorForm from '../components/DetectorForm';
import { cleanKeywords, runSoon } from '../utils';
import DetectorTester from '../components/DetectorTester';

const SEV_CHIP = { critical: 'chip-danger', high: 'chip-warning', medium: 'chip-accent', low: '' };
const EDITABLE = ['enabled', 'severity', 'confidence', 'keywords', 'require_keyword', 'pattern', 'validator', 'ignore_case'];
const EMPTY_CUSTOM = {
  name: '', description: '', category: 'Custom', pattern: '', group: 0, validator: null, keywords: [],
  require_keyword: false, ignore_case: false, severity: 'high', confidence: 0.85, enabled: true,
};

const Detectors = ({ apiBase, notify, confirmAction, canManage }) => {
  const [data, setData] = useState({ detectors: [], validators: [], categories: [] });
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('all');
  const [view, setView] = useState('all');
  const [editing, setEditing] = useState(null);   // { mode, original, draft }
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${apiBase}/detectors`);
      const body = await res.json();
      if (res.ok) setData({ detectors: body.detectors || [], validators: body.validators || [], categories: body.categories || [] });
    } catch (_) { /* surfaced by empty state */ }
    setLoading(false);
  };

  useEffect(() => runSoon(load), [apiBase]); // eslint-disable-line react-hooks/exhaustive-deps

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return data.detectors.filter(d => {
      if (category !== 'all' && d.category !== category) return false;
      if (view === 'builtin' && d.source !== 'builtin') return false;
      if (view === 'custom' && d.source !== 'custom') return false;
      if (view === 'modified' && !(d.overridden || []).length) return false;
      if (view === 'disabled' && d.enabled !== false) return false;
      if (!q) return true;
      return [d.name, d.description, d.validator, ...(d.keywords || [])].some(x => String(x || '').toLowerCase().includes(q));
    });
  }, [data.detectors, query, category, view]);

  const counts = useMemo(() => ({
    total: data.detectors.length,
    enabled: data.detectors.filter(d => d.enabled !== false).length,
    validated: data.detectors.filter(d => d.validator).length,
    custom: data.detectors.filter(d => d.source === 'custom').length,
    modified: data.detectors.filter(d => (d.overridden || []).length).length,
  }), [data.detectors]);

  const categories = useMemo(() => [...new Set(data.detectors.map(d => d.category))].sort(), [data.detectors]);

  const save = async (name, payload, isNew = false) => {
    setSaving(true);
    setFormError('');
    try {
      const res = await fetch(isNew ? `${apiBase}/detectors` : `${apiBase}/detectors/${encodeURIComponent(name)}`, {
        method: isNew ? 'POST' : 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setFormError(body.error || 'Save failed');
        setSaving(false);
        return false;
      }
      notify?.(isNew ? `Detector ${payload.name} created` : `Detector ${name} saved`, 'success');
      await load();
      setSaving(false);
      return true;
    } catch (_) {
      setFormError('Could not reach the API');
      setSaving(false);
      return false;
    }
  };

  const toggleEnabled = async (d) => {
    if (!canManage) return;
    const next = d.enabled === false;
    if (!next && (d.used_by_policies || []).length) {
      const ok = await confirmAction?.({
        title: 'Disable detector',
        message: `${d.name} is used by: ${d.used_by_policies.join(', ')}. Those policies stop matching while it is disabled. LLM redaction keeps masking these values.`,
        confirmText: 'Disable', tone: 'warning',
      });
      if (!ok) return;
    }
    await save(d.name, { enabled: next });
  };

  const openEdit = (d) => {
    setFormError('');
    const draft = { ...d, keywords: [...(d.keywords || [])] };
    setEditing({ mode: d.source === 'builtin' ? 'builtin' : 'custom-edit', original: d, draft });
  };

  const openNew = () => {
    setFormError('');
    setEditing({ mode: 'new', original: null, draft: { ...EMPTY_CUSTOM } });
  };

  const submitEdit = async () => {
    const { mode, original, draft } = editing;
    const d = { ...draft, keywords: cleanKeywords(draft.keywords) };
    let ok;
    if (mode === 'builtin') {
      const payload = {};
      EDITABLE.forEach(k => { payload[k] = d[k]; });
      ok = await save(original.name, payload);
    } else if (mode === 'custom-edit') {
      ok = await save(original.name, d);
    } else {
      ok = await save(d.name, d, true);
    }
    if (ok) setEditing(null);
  };

  const resetOrDelete = async () => {
    const { mode, original } = editing;
    const isBuiltin = mode === 'builtin';
    const ok = await confirmAction?.({
      title: isBuiltin ? 'Reset to defaults' : 'Delete detector',
      message: isBuiltin ? `Discard all changes to ${original.name}?` : `Delete ${original.name} permanently?`,
      confirmText: isBuiltin ? 'Reset' : 'Delete', tone: isBuiltin ? 'warning' : 'danger',
    });
    if (!ok) return;
    const res = await fetch(`${apiBase}/detectors/${encodeURIComponent(original.name)}`, { method: 'DELETE' });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { setFormError(body.error || 'Request failed'); return; }
    notify?.(isBuiltin ? `${original.name} reset to defaults` : `${original.name} deleted`, 'success');
    setEditing(null);
    load();
  };

  const draftDefinition = editing ? {
    ...editing.draft,
    name: editing.mode === 'builtin' ? `${editing.draft.name}_DRAFT` : (editing.draft.name || 'DRAFT'),
    keywords: cleanKeywords(editing.draft.keywords),
    category: editing.mode === 'builtin' ? 'Custom' : editing.draft.category,
  } : null;
  const generatorKind = editing ? (editing.original?.has_generator && editing.mode === 'builtin' ? editing.original.name : (data.validators.find(x => x.name === editing.draft.validator && x.generator) ? editing.draft.validator : null)) : null;

  return (
    <div className="fade-in">
      <div className="card" style={{ marginBottom: '16px' }}>
        <div className="stat-inline">
          <div><strong>{counts.total}</strong>detectors</div>
          <div><strong>{counts.enabled}</strong>enabled</div>
          <div><strong>{counts.validated}</strong>checksum-validated</div>
          <div><strong>{counts.custom}</strong>custom</div>
          <div><strong>{counts.modified}</strong>modified built-ins</div>
        </div>
      </div>

      <div className="card">
        <div className="toolbar">
          <input className="form-control" style={{ minWidth: '260px' }} placeholder="Search name, keyword or validator"
            value={query} onChange={e => setQuery(e.target.value)} />
          <select className="form-control" value={category} onChange={e => setCategory(e.target.value)}>
            <option value="all">All categories</option>
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          <select className="form-control" value={view} onChange={e => setView(e.target.value)}>
            <option value="all">All detectors</option>
            <option value="builtin">Built-in</option>
            <option value="custom">Custom</option>
            <option value="modified">Modified</option>
            <option value="disabled">Disabled</option>
          </select>
          <span style={{ flex: 1 }} />
          {canManage && (
            <button className="btn" onClick={openNew}><Icon name="plus" size={14} /> New detector</button>
          )}
        </div>

        {loading ? (
          <div className="empty-state">Loading detector library...</div>
        ) : filtered.length === 0 ? (
          <div className="empty-state"><strong>No detectors match</strong>Adjust the search or filters.</div>
        ) : (
          <div className="table-wrap" style={{ maxHeight: 'calc(100vh - 330px)' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 56 }}>On</th>
                  <th>Detector</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Validation</th>
                  <th>Context</th>
                  <th>Source</th>
                  <th style={{ width: 90 }} />
                </tr>
              </thead>
              <tbody>
                {filtered.map(d => (
                  <tr key={d.name} className={d.enabled === false ? 'row-disabled' : ''}>
                    <td>
                      <label className="switch" title={canManage ? 'Enable / disable' : 'Read only'}>
                        <input type="checkbox" checked={d.enabled !== false} disabled={!canManage} onChange={() => toggleEnabled(d)} />
                        <span />
                      </label>
                    </td>
                    <td>
                      <div className="mono" style={{ fontWeight: 700, color: 'var(--text-strong)' }}>{d.name}</div>
                      <div className="field-hint" style={{ marginTop: 2 }}>{d.description}</div>
                      {(d.used_by_policies || []).length > 0 && (
                        <div className="field-hint">Used by: {d.used_by_policies.join(', ')}</div>
                      )}
                    </td>
                    <td>{d.category}</td>
                    <td><span className={`chip ${SEV_CHIP[d.severity] || ''}`}>{String(d.severity).toUpperCase()}</span></td>
                    <td>{d.validator ? <span className="chip chip-success"><Icon name="check" size={11} />{d.validator}</span> : <span className="chip">pattern only</span>}</td>
                    <td>
                      {(d.keywords || []).length ? (
                        <span className={`chip ${d.require_keyword ? 'chip-warning' : ''}`} title={(d.keywords || []).join(', ')}>
                          {d.require_keyword ? 'required' : 'boost'}: {d.keywords.slice(0, 2).join(', ')}{d.keywords.length > 2 ? ` +${d.keywords.length - 2}` : ''}
                        </span>
                      ) : <span style={{ color: 'var(--text-muted)' }}>-</span>}
                    </td>
                    <td>
                      {d.source === 'custom' ? <span className="chip chip-accent">Custom</span>
                        : (d.overridden || []).length ? <span className="chip chip-warning" title={`Changed: ${d.overridden.join(', ')}`}>Modified</span>
                          : <span className="chip">Built-in</span>}
                    </td>
                    <td><button className="btn btn-secondary btn-sm" onClick={() => openEdit(d)}>{canManage ? 'Edit' : 'View'}</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {editing && (
        <>
          <div className="drawer-backdrop" onClick={() => setEditing(null)} />
          <aside className="drawer" role="dialog" aria-label="Edit detector">
            <div className="drawer-header">
              <div>
                <div className="card-title mono">{editing.mode === 'new' ? 'New detector' : editing.original.name}</div>
                <div className="card-subtitle">
                  {editing.mode === 'builtin' ? 'Built-in detector. Changes are stored as overrides and can be reset at any time.'
                    : editing.mode === 'new' ? 'Pattern + optional checksum validator + keyword context.'
                      : 'Custom detector.'}
                </div>
              </div>
              <button className="icon-btn" onClick={() => setEditing(null)} aria-label="Close"><Icon name="x" /></button>
            </div>
            <div className="drawer-body">
              <DetectorForm
                value={editing.draft}
                onChange={(draft) => setEditing({ ...editing, draft })}
                mode={editing.mode}
                validators={data.validators}
                categories={data.categories}
                defaults={editing.original?.defaults || {}}
                readOnly={!canManage}
              />
              {formError && <div className="notice notice-error" style={{ marginTop: '12px' }}>{formError}</div>}
              <div style={{ borderTop: '1px solid var(--border-color)', margin: '18px 0 14px' }} />
              <div className="card-title" style={{ fontSize: '14px', marginBottom: '8px' }}>Test this configuration</div>
              {draftDefinition?.pattern ? (
                <DetectorTester apiBase={apiBase} definition={draftDefinition} generatorKind={generatorKind}
                  keywordHint={cleanKeywords(editing.draft.keywords)[0] || ''} />
              ) : <div className="field-hint">Enter a pattern to test it.</div>}
            </div>
            <div className="drawer-footer">
              <div>
                {canManage && editing.mode === 'builtin' && (editing.original.overridden || []).length > 0 && (
                  <button className="btn btn-secondary" onClick={resetOrDelete}><Icon name="reset" size={14} /> Reset to defaults</button>
                )}
                {canManage && editing.mode === 'custom-edit' && (
                  <button className="btn btn-danger-outline" onClick={resetOrDelete}>Delete</button>
                )}
              </div>
              <div className="btn-row">
                <button className="btn btn-secondary" onClick={() => setEditing(null)}>Cancel</button>
                {canManage && (
                  <button className="btn" onClick={submitEdit} disabled={saving}>
                    {saving ? 'Saving...' : editing.mode === 'new' ? 'Create detector' : 'Save changes'}
                  </button>
                )}
              </div>
            </div>
          </aside>
        </>
      )}
    </div>
  );
};

export default Detectors;
