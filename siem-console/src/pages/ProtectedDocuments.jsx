import { useCallback, useEffect, useRef, useState } from 'react';
import Icon from '../components/Icons';
import { runSoon } from '../utils';

const SEV_CHIP = { CRITICAL: 'chip-danger', HIGH: 'chip-warning', MEDIUM: 'chip-accent', LOW: '' };

const fmtSize = (bytes) => {
  const n = Number(bytes || 0);
  if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} KB`;
  return `${n} B`;
};

const ProtectedDocuments = ({ apiBase, notify, confirmAction, canManage }) => {
  const [docs, setDocs] = useState([]);
  const [minWords, setMinWords] = useState(40);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ name: '', description: '', sensitivity: 'HIGH' });
  const [error, setError] = useState('');
  const [testText, setTestText] = useState('');
  const [testResult, setTestResult] = useState(null);
  const fileRef = useRef(null);
  const testFileRef = useRef(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch(`${apiBase}/idm/documents`);
      const body = await res.json();
      if (res.ok) { setDocs(body.documents || []); setMinWords(body.min_words || 40); }
    } catch (_) { /* empty state covers it */ }
    setLoading(false);
  }, [apiBase]);
  useEffect(() => runSoon(load), [load]);

  const register = async () => {
    const file = fileRef.current?.files?.[0];
    if (!file) { setError('Choose a document to protect.'); return; }
    setBusy(true); setError('');
    const fd = new FormData();
    fd.append('file', file);
    fd.append('name', form.name.trim() || file.name);
    fd.append('description', form.description);
    fd.append('sensitivity', form.sensitivity);
    const res = await fetch(`${apiBase}/idm/documents`, { method: 'POST', body: fd });
    const body = await res.json().catch(() => ({}));
    setBusy(false);
    if (!res.ok) { setError(body.message || body.error || 'Registration failed'); return; }
    notify?.(body.status === 'exists' ? 'This document is already registered' : `Registered ${body.document.name} (${body.document.fingerprint_count} fingerprints)`, 'success');
    setForm({ name: '', description: '', sensitivity: 'HIGH' });
    if (fileRef.current) fileRef.current.value = '';
    load();
  };

  const toggle = async (doc) => {
    await fetch(`${apiBase}/idm/documents/${doc.doc_id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ is_active: !doc.is_active }),
    });
    load();
  };

  const remove = async (doc) => {
    const ok = await confirmAction?.({
      title: 'Remove protected document', message: `"${doc.name}" will no longer be detected. Its fingerprints are deleted.`,
      confirmText: 'Remove', tone: 'danger',
    });
    if (!ok) return;
    const res = await fetch(`${apiBase}/idm/documents/${doc.doc_id}`, { method: 'DELETE' });
    if (res.ok) { notify?.('Document removed', 'success'); load(); }
  };

  const runTest = async () => {
    setBusy(true); setTestResult(null);
    const file = testFileRef.current?.files?.[0];
    let res;
    if (file) {
      const fd = new FormData();
      fd.append('file', file);
      res = await fetch(`${apiBase}/idm/match`, { method: 'POST', body: fd });
    } else {
      res = await fetch(`${apiBase}/idm/match`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: testText }),
      });
    }
    const body = await res.json().catch(() => ({}));
    setBusy(false);
    setTestResult(res.ok ? body.matches || [] : { error: body.error || 'Check failed' });
  };

  return (
    <div className="fade-in">
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="stat-inline">
          <div><strong>{docs.length}</strong>protected documents</div>
          <div><strong>{docs.filter(d => d.is_active).length}</strong>active</div>
          <div><strong>{docs.reduce((a, d) => a + Number(d.fingerprint_count || 0), 0).toLocaleString()}</strong>fingerprints</div>
        </div>
      </div>

      {canManage && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <div>
              <div className="card-title">Register a document</div>
              <div className="card-subtitle">
                The file is fingerprinted and discarded; only keyed hashes are stored. Copies, reformatted versions and excerpts of about 13 words or more are then detected in uploads and scans.
                Needs at least {minWords} words of extractable text.
              </div>
            </div>
          </div>
          <div className="grid-3">
            <div className="form-group"><label>Document</label><input ref={fileRef} className="form-control" type="file" /></div>
            <div className="form-group"><label>Name</label><input className="form-control" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Defaults to the file name" /></div>
            <div className="form-group"><label>Sensitivity</label>
              <select className="form-control" value={form.sensitivity} onChange={e => setForm({ ...form, sensitivity: e.target.value })}>
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <div className="form-group"><label>Description</label><input className="form-control" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Owner, classification, why it is protected" /></div>
          {error && <div className="notice notice-error" style={{ marginBottom: 12 }}>{error}</div>}
          <button className="btn" onClick={register} disabled={busy}><Icon name="plus" size={14} /> {busy ? 'Working...' : 'Register'}</button>
        </div>
      )}

      <div className="card" style={{ marginBottom: 16 }}>
        {loading ? <div className="empty-state">Loading...</div>
          : docs.length === 0 ? (
            <div className="empty-state"><strong>No protected documents</strong>Register confidential documents that contain no recognisable identifiers: contracts, source code, board papers, designs.</div>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead><tr><th style={{ width: 56 }}>On</th><th>Document</th><th>Sensitivity</th><th>Size</th><th>Fingerprints</th><th>Registered</th><th style={{ width: 90 }} /></tr></thead>
                <tbody>
                  {docs.map(d => (
                    <tr key={d.doc_id} className={d.is_active ? '' : 'row-disabled'}>
                      <td><label className="switch"><input type="checkbox" checked={!!d.is_active} disabled={!canManage} onChange={() => toggle(d)} /><span /></label></td>
                      <td>
                        <div style={{ fontWeight: 700, color: 'var(--text-strong)' }}>{d.name}</div>
                        <div className="field-hint">{d.description}</div>
                        <div className="field-hint mono">{d.doc_id} · sha256 {String(d.content_sha256).slice(0, 16)}...</div>
                      </td>
                      <td><span className={`chip ${SEV_CHIP[d.sensitivity] || ''}`}>{d.sensitivity}</span></td>
                      <td>{fmtSize(d.size_bytes)}<div className="field-hint">{Number(d.word_count).toLocaleString()} words</div></td>
                      <td>{Number(d.fingerprint_count).toLocaleString()}</td>
                      <td>{new Date(d.created_at).toLocaleDateString()}<div className="field-hint">{d.created_by}</div></td>
                      <td>{canManage && <button className="btn btn-danger-outline btn-sm" onClick={() => remove(d)}>Remove</button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </div>

      {canManage && (
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">Check content against the index</div>
              <div className="card-subtitle">Paste text or choose a file to see which protected documents it contains.</div>
            </div>
          </div>
          <div className="form-group"><textarea className="form-control" rows={5} value={testText} onChange={e => setTestText(e.target.value)} placeholder="Paste text to check" /></div>
          <div className="btn-row">
            <input ref={testFileRef} className="form-control" type="file" style={{ maxWidth: 320 }} />
            <button className="btn" onClick={runTest} disabled={busy}><Icon name="play" size={13} /> Check</button>
          </div>
          {testResult && (
            <div style={{ marginTop: 14 }}>
              {testResult.error ? <div className="notice notice-error">{testResult.error}</div>
                : testResult.length === 0 ? <div className="notice">No protected document found in this content.</div>
                  : testResult.map(m => (
                    <div key={m.doc_id} className="notice notice-error" style={{ marginBottom: 8 }}>
                      <strong>{m.name}</strong>: {Math.round(m.containment * 100)}% of the document is present ({m.matched} of {m.total} fingerprints)
                    </div>
                  ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ProtectedDocuments;
