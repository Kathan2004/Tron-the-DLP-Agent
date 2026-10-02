import { useEffect, useMemo, useState } from 'react';
import Icon from '../components/Icons';
import DetectorForm from '../components/DetectorForm';
import { cleanKeywords, runSoon } from '../utils';
import DetectorTester, { HighlightedText } from '../components/DetectorTester';

const TABS = [
  { id: 'builder', label: 'Rule builder' },
  { id: 'checksum', label: 'Checksum tools' },
  { id: 'scan', label: 'Library scan' },
  { id: 'history', label: 'History' },
];

const EXAMPLES = [
  'Block employee IDs like EMP-482913 that end with a Luhn check digit',
  'Alert when Aadhaar numbers are shared',
  'Warn on loyalty card numbers e.g. LC-0012345678 validated with mod 10',
  "Block anything mentioning 'Project Falcon'",
  'Block uploads larger than 25 MB',
];

const EMPTY_DETECTOR = {
  name: '', description: '', category: 'Custom', pattern: '', group: 0, validator: null, keywords: [],
  require_keyword: false, ignore_case: false, severity: 'high', confidence: 0.85, enabled: true,
};

const SEV_CHIP = { critical: 'chip-danger', high: 'chip-warning', medium: 'chip-accent', low: '' };

// ------------------------------------------------------------------ builder
const Builder = ({ apiBase, notify, canManage, meta, reloadHistory }) => {
  const [prompt, setPrompt] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [rule, setRule] = useState(null);          // generated rule (any kind)
  const [draft, setDraft] = useState({ ...EMPTY_DETECTOR });
  const [policy, setPolicy] = useState({ create: true, action: 'warn', severity: 'HIGH', threshold_count: 1, threshold_window_mins: 60 });
  const [simpleInput, setSimpleInput] = useState('');
  const [simpleResult, setSimpleResult] = useState(null);

  const kind = rule?.kind || 'detector';

  const generate = async (text) => {
    const p = (text ?? prompt).trim();
    if (!p) return;
    setPrompt(p);
    setBusy(true);
    setMessage(null);
    setSimpleResult(null);
    try {
      const res = await fetch(`${apiBase}/lab/generate_rule`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ prompt: p }),
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        setMessage({ type: 'error', text: data.error || 'Generation failed' });
      } else {
        setRule(data);
        setPolicy(prev => ({ ...prev, action: data.action || prev.action, severity: data.severity || prev.severity }));
        if (data.kind === 'detector' && data.detector_definition) setDraft({ ...EMPTY_DETECTOR, ...data.detector_definition });
        const src = data.source === 'ai' ? 'Gemini' : 'the offline rule builder (no LLM key configured or LLM output rejected)';
        setMessage({ type: 'success', text: `Rule drafted by ${src}. Review and test it before saving.` });
      }
    } catch (_) {
      setMessage({ type: 'error', text: 'Could not reach the API' });
    }
    setBusy(false);
  };

  const startBlank = () => {
    setRule({ kind: 'detector', name: '', description: '' });
    setDraft({ ...EMPTY_DETECTOR });
    setMessage(null);
  };

  const cloneBuiltin = (name) => {
    const d = meta.detectors.find(x => x.name === name);
    if (!d) return;
    setRule({ kind: 'detector', name: `${name}_CUSTOM` });
    setDraft({
      ...EMPTY_DETECTOR, name: `${name}_CUSTOM`, description: `Custom variant of ${name}`, pattern: d.pattern,
      group: d.group || 0, validator: d.validator || null, keywords: [...(d.keywords || [])],
      require_keyword: !!d.require_keyword, ignore_case: !!d.ignore_case, severity: d.severity, confidence: d.confidence,
      category: d.category,
    });
  };

  const save = async () => {
    setBusy(true);
    setMessage(null);
    try {
      let detectorName = null;
      if (kind === 'detector') {
        const def = { ...draft, keywords: cleanKeywords(draft.keywords) };
        const res = await fetch(`${apiBase}/detectors`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(def),
        });
        const data = await res.json();
        if (!res.ok) { setMessage({ type: 'error', text: data.error || 'Could not save detector' }); setBusy(false); return; }
        detectorName = def.name;
      } else if (kind === 'builtin') {
        detectorName = rule.rule_data?.detector;
      }
      if (policy.create || !detectorName) {
        const body = detectorName ? {
          name: kind === 'builtin' ? `${detectorName}_POLICY` : detectorName,
          description: rule?.description || draft.description || prompt,
          rule_type: 'regex', detector: detectorName, rule_data: { detector: detectorName },
        } : {
          name: rule.name, description: rule.description, rule_type: rule.rule_type, rule_data: rule.rule_data,
          pattern: rule.pattern,
        };
        Object.assign(body, {
          action: policy.action, severity: policy.severity,
          threshold_count: Number(policy.threshold_count) || 1, threshold_window_mins: Number(policy.threshold_window_mins) || 60,
          ai_generated: !!rule?.ai_generated, ai_prompt: prompt,
        });
        body.rule_data = { ...(body.rule_data || {}), _meta: { source: 'ai_lab', ai_generated: !!rule?.ai_generated, ai_prompt: prompt, generated_at: new Date().toISOString() } };
        const res = await fetch(`${apiBase}/policies`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { setMessage({ type: 'error', text: data.error || 'Could not create policy' }); setBusy(false); return; }
      }
      notify?.(detectorName && kind === 'detector' ? `Detector ${detectorName} saved${policy.create ? ' and policy deployed' : ''}` : 'Policy deployed', 'success');
      setMessage({ type: 'success', text: 'Saved. Agents and browser extensions pick it up on their next sync.' });
      setRule(null);
      setDraft({ ...EMPTY_DETECTOR });
      setPrompt('');
      reloadHistory?.();
    } catch (_) {
      setMessage({ type: 'error', text: 'Could not reach the API' });
    }
    setBusy(false);
  };

  const testSimple = async () => {
    try {
      const res = await fetch(`${apiBase}/lab/test_rule`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rule, input: simpleInput }),
      });
      setSimpleResult(await res.json());
    } catch (_) {
      setSimpleResult({ match: false, reason: 'Could not reach the API' });
    }
  };

  const validatorWithGenerator = meta.validators.find(v => v.name === draft.validator && v.generator);
  const builtinName = kind === 'builtin' ? rule?.rule_data?.detector : null;
  const builtin = builtinName ? meta.detectors.find(d => d.name === builtinName) : null;

  return (
    <div>
      <div className="card" style={{ marginBottom: '16px' }}>
        <div className="card-header">
          <div>
            <div className="card-title">Describe what to protect</div>
            <div className="card-subtitle">Plain language in, a testable rule out. With a Gemini key the LLM drafts it; otherwise the offline builder maps known identifiers and builds patterns from examples.</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <input className="form-control" value={prompt} onChange={e => setPrompt(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && generate()} placeholder="e.g. Block employee IDs like EMP-482913 with a Luhn check digit" />
          <button className="btn" onClick={() => generate()} disabled={busy || !prompt.trim()}>
            <Icon name="sparkle" size={14} /> {busy ? 'Drafting...' : 'Draft rule'}
          </button>
        </div>
        <div className="btn-row" style={{ marginTop: '10px' }}>
          {EXAMPLES.map(ex => (
            <button key={ex} className="chip" style={{ cursor: 'pointer' }} onClick={() => generate(ex)}>{ex}</button>
          ))}
        </div>
        <div className="btn-row" style={{ marginTop: '12px' }}>
          <button className="btn btn-secondary btn-sm" onClick={startBlank}><Icon name="plus" size={12} /> Blank detector</button>
          <select className="form-control" style={{ width: 'auto', fontSize: '12px', padding: '5px 8px' }} value=""
            onChange={e => e.target.value && cloneBuiltin(e.target.value)}>
            <option value="">Start from a built-in detector...</option>
            {meta.detectors.filter(d => d.source === 'builtin').map(d => <option key={d.name} value={d.name}>{d.name}</option>)}
          </select>
        </div>
        {message && <div className={`notice ${message.type === 'error' ? 'notice-error' : 'notice-success'}`} style={{ marginTop: '12px' }}>{message.text}</div>}
      </div>

      {rule && (
        <div className="grid-2" style={{ alignItems: 'start' }}>
          <div className="card">
            <div className="card-header">
              <div>
                <div className="card-title">
                  {kind === 'detector' ? 'Custom detector' : kind === 'builtin' ? 'Use a built-in detector' : 'Policy rule'}
                </div>
                <div className="card-subtitle">
                  {kind === 'detector' && 'Pattern, checksum validator and keyword context. Saved to the detector library.'}
                  {kind === 'builtin' && 'An existing validated detector already covers this. The policy references it, so checksums and context apply.'}
                  {!['detector', 'builtin'].includes(kind) && `A ${kind.replace('_', ' ')} rule.`}
                </div>
              </div>
              <span className="chip chip-accent">{rule.source === 'ai' ? 'Gemini' : rule.source === 'offline' ? 'offline builder' : 'manual'}</span>
            </div>

            {kind === 'detector' && (
              <DetectorForm value={draft} onChange={setDraft} mode="new" validators={meta.validators} categories={meta.categories} readOnly={!canManage} />
            )}
            {kind === 'builtin' && builtin && (
              <dl className="kv">
                <dt>Detector</dt><dd className="mono">{builtin.name}</dd>
                <dt>Description</dt><dd>{builtin.description}</dd>
                <dt>Validation</dt><dd>{builtin.validator || 'pattern only'}</dd>
                <dt>Keywords</dt><dd>{(builtin.keywords || []).join(', ') || '-'}{builtin.require_keyword ? ' (required)' : ''}</dd>
                <dt>Severity</dt><dd><span className={`chip ${SEV_CHIP[builtin.severity] || ''}`}>{String(builtin.severity).toUpperCase()}</span></dd>
              </dl>
            )}
            {!['detector', 'builtin'].includes(kind) && (
              <dl className="kv">
                <dt>Name</dt><dd className="mono">{rule.name}</dd>
                <dt>Type</dt><dd>{rule.rule_type}</dd>
                <dt>Value</dt><dd className="mono">{rule.pattern}</dd>
                <dt>Description</dt><dd>{rule.description}</dd>
              </dl>
            )}

            <div style={{ borderTop: '1px solid var(--border-color)', margin: '16px 0 12px' }} />
            <div className="card-title" style={{ fontSize: '14px', marginBottom: '10px' }}>Policy</div>
            {kind !== 'builtin' && kind === 'detector' && (
              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', marginBottom: '10px' }}>
                <span className="switch"><input type="checkbox" checked={policy.create} onChange={e => setPolicy({ ...policy, create: e.target.checked })} /><span /></span>
                Also create a policy that alerts or blocks on this detector
              </label>
            )}
            {(policy.create || kind !== 'detector') && (
              <div className="grid-2">
                <div className="form-group">
                  <label>Action</label>
                  <select className="form-control" value={policy.action} onChange={e => setPolicy({ ...policy, action: e.target.value })}>
                    <option value="monitor">Monitor</option><option value="warn">Warn</option><option value="block">Block</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Severity</label>
                  <select className="form-control" value={policy.severity} onChange={e => setPolicy({ ...policy, severity: e.target.value })}>
                    {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div className="form-group">
                  <label>Threshold (hits)</label>
                  <input type="number" min="1" className="form-control" value={policy.threshold_count} onChange={e => setPolicy({ ...policy, threshold_count: e.target.value })} />
                </div>
                <div className="form-group">
                  <label>Window (minutes)</label>
                  <input type="number" min="1" className="form-control" value={policy.threshold_window_mins} onChange={e => setPolicy({ ...policy, threshold_window_mins: e.target.value })} />
                </div>
              </div>
            )}
            {canManage ? (
              <button className="btn btn-success" style={{ width: '100%' }} onClick={save} disabled={busy || (kind === 'detector' && (!draft.name || !draft.pattern))}>
                {busy ? 'Saving...' : kind === 'detector' ? (policy.create ? 'Save detector and deploy policy' : 'Save detector') : 'Deploy policy'}
              </button>
            ) : <div className="field-hint">You need the policies.manage permission to save.</div>}
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <div className="card-title">Test before you deploy</div>
                <div className="card-subtitle">Every candidate is shown with its checksum result, nearby keyword and the final decision.</div>
              </div>
            </div>
            {kind === 'detector' && (draft.pattern ? (
              <DetectorTester key={draft.pattern + String(draft.validator)} apiBase={apiBase}
                definition={{ ...draft, name: draft.name || 'DRAFT', keywords: cleanKeywords(draft.keywords) }}
                generatorKind={validatorWithGenerator ? draft.validator : null} keywordHint={cleanKeywords(draft.keywords)[0] || ''} />
            ) : <div className="empty-state">Enter a pattern to start testing.</div>)}
            {kind === 'builtin' && builtin && (
              <DetectorTester key={builtin.name} apiBase={apiBase} detectorName={builtin.name}
                generatorKind={builtin.has_generator ? builtin.name : null} keywordHint={(builtin.keywords || [])[0] || ''} />
            )}
            {!['detector', 'builtin'].includes(kind) && (
              <div>
                <div className="form-group">
                  <label>{rule.rule_type === 'file_size' ? 'File size in MB' : rule.rule_type === 'extension' ? 'File name' : 'Sample text or URL'}</label>
                  <input className="form-control" value={simpleInput} onChange={e => setSimpleInput(e.target.value)} />
                </div>
                <button className="btn btn-sm" onClick={testSimple} disabled={!simpleInput}><Icon name="play" size={12} /> Run test</button>
                {simpleResult && (
                  <div className={`notice ${simpleResult.match ? 'notice-error' : 'notice-success'}`} style={{ marginTop: '12px' }}>
                    <strong>{simpleResult.match ? 'Match' : 'No match'}</strong>
                    <div style={{ fontSize: '12px', marginTop: '4px' }}>{simpleResult.reason}</div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

// ------------------------------------------------------------------ checksum tools
const ChecksumTools = ({ apiBase, meta }) => {
  const [value, setValue] = useState('4111 1111 1111 1111');
  const [check, setCheck] = useState(null);
  const [kind, setKind] = useState('payment_card');
  const [count, setCount] = useState(5);
  const [brand, setBrand] = useState('');
  const [country, setCountry] = useState('GB');
  const [values, setValues] = useState([]);
  const [error, setError] = useState('');

  const runCheck = async () => {
    setError('');
    const res = await fetch(`${apiBase}/detectors/check`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ value }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error || 'Check failed'); return; }
    setCheck(data);
  };

  const runGenerate = async () => {
    setError('');
    const options = {};
    if (kind === 'payment_card' && brand) options.brand = brand;
    if (kind === 'iban') options.country = country;
    const res = await fetch(`${apiBase}/detectors/generate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ kind, count, options }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error || 'Generation failed'); return; }
    setValues(data.values || []);
  };

  const kinds = useMemo(() => {
    const fromValidators = meta.validators.filter(v => v.generator).map(v => ({ id: v.name, label: `${v.name} (validator)` }));
    const fromDetectors = meta.detectors.filter(d => d.has_generator && d.source === 'builtin').map(d => ({ id: d.name, label: `${d.name} (detector)` }));
    return [...fromValidators, ...fromDetectors];
  }, [meta]);

  return (
    <div className="grid-2" style={{ alignItems: 'start' }}>
      <div className="card">
        <div className="card-title">Checksum checker</div>
        <div className="card-subtitle" style={{ marginBottom: '12px' }}>Which validators does a number pass? Useful for triaging a finding or confirming a test value.</div>
        <div style={{ display: 'flex', gap: '10px', marginBottom: '12px' }}>
          <input className="form-control mono" value={value} onChange={e => setValue(e.target.value)} onKeyDown={e => e.key === 'Enter' && runCheck()} />
          <button className="btn" onClick={runCheck} disabled={!value.trim()}><Icon name="hash" size={14} /> Check</button>
        </div>
        {check && (
          <div className="table-wrap" style={{ maxHeight: '420px' }}>
            <table className="data-table">
              <thead><tr><th>Validator</th><th>Result</th></tr></thead>
              <tbody>
                {check.results.map(r => (
                  <tr key={r.validator}>
                    <td><div className="mono" style={{ fontWeight: 600 }}>{r.validator}</div><div className="field-hint">{r.description}</div></td>
                    <td>{r.valid ? <span className="chip chip-success"><Icon name="check" size={11} />valid</span> : <span className="chip">invalid</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-title">Test data generator</div>
        <div className="card-subtitle" style={{ marginBottom: '12px' }}>Random values with correct check digits for testing policies end to end. They belong to no one.</div>
        <div className="grid-2">
          <div className="form-group">
            <label>Format</label>
            <select className="form-control" value={kind} onChange={e => setKind(e.target.value)}>
              {kinds.map(k => <option key={k.id} value={k.id}>{k.label}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label>Count</label>
            <input type="number" min="1" max="50" className="form-control" value={count} onChange={e => setCount(Number(e.target.value) || 1)} />
          </div>
          {kind === 'payment_card' && (
            <div className="form-group">
              <label>Card brand</label>
              <select className="form-control" value={brand} onChange={e => setBrand(e.target.value)}>
                <option value="">Any</option>
                {['visa', 'mastercard', 'amex', 'discover', 'jcb', 'diners', 'unionpay', 'rupay'].map(b => <option key={b} value={b}>{b}</option>)}
              </select>
            </div>
          )}
          {kind === 'iban' && (
            <div className="form-group">
              <label>Country</label>
              <select className="form-control" value={country} onChange={e => setCountry(e.target.value)}>
                {['GB', 'DE', 'FR', 'NL', 'ES', 'IT', 'CH', 'BE'].map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
          )}
        </div>
        <div className="btn-row" style={{ marginBottom: '12px' }}>
          <button className="btn" onClick={runGenerate}><Icon name="wand" size={14} /> Generate</button>
          {values.length > 0 && (
            <button className="btn btn-secondary" onClick={() => navigator.clipboard?.writeText(values.join('\n'))}><Icon name="copy" size={14} /> Copy all</button>
          )}
        </div>
        {values.length > 0 && <div className="code-block">{values.join('\n')}</div>}
      </div>
      {error && <div className="notice notice-error">{error}</div>}
    </div>
  );
};

// ------------------------------------------------------------------ library scan
const LibraryScan = ({ apiBase }) => {
  const [text, setText] = useState('Customer: Jane Doe, SSN 536-22-1234\nCard 4111 1111 1111 1111 exp 09/28\nOrder 1234567812345678 (not a card: fails Luhn)\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\nemail jane.doe@example.com');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const run = async () => {
    setError('');
    const res = await fetch(`${apiBase}/detectors/test`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error || 'Scan failed'); return; }
    setResult({ ...data, text });
  };
  return (
    <div className="card">
      <div className="card-title">Scan text with the live detector library</div>
      <div className="card-subtitle" style={{ marginBottom: '12px' }}>Uses the current configuration: disabled detectors are skipped, overrides and custom detectors apply.</div>
      <textarea className="form-control mono" rows={7} value={text} onChange={e => setText(e.target.value)} />
      <div className="btn-row" style={{ margin: '12px 0' }}>
        <button className="btn" onClick={run} disabled={!text.trim()}><Icon name="play" size={14} /> Scan</button>
        {result && <span className="chip">{result.findings.length} findings</span>}
      </div>
      {error && <div className="notice notice-error">{error}</div>}
      {result && (
        <>
          <HighlightedText text={result.text} spans={result.findings.map(f => ({ start: f.start, end: f.end, accepted: true, title: f.detector }))} />
          {result.findings.length > 0 && (
            <div className="table-wrap" style={{ marginTop: '10px' }}>
              <table className="data-table">
                <thead><tr><th>Detector</th><th>Value</th><th>Severity</th><th>Evidence</th></tr></thead>
                <tbody>
                  {result.findings.map((f, i) => (
                    <tr key={i}>
                      <td className="mono" style={{ fontWeight: 600 }}>{f.detector}</td>
                      <td className="mono">{f.value}</td>
                      <td><span className={`chip ${SEV_CHIP[f.severity] || ''}`}>{String(f.severity).toUpperCase()}</span></td>
                      <td className="btn-row">
                        {f.validated && <span className="chip chip-success">checksum</span>}
                        {f.keyword && <span className="chip chip-accent">keyword: {f.keyword}</span>}
                        {f.encoding && <span className="chip chip-warning">{f.encoding}</span>}
                        <span className="chip">conf {f.confidence}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
};

// ------------------------------------------------------------------ page
const Lab = ({ apiBase, notify, canManage = true }) => {
  const [tab, setTab] = useState('builder');
  const [meta, setMeta] = useState({ detectors: [], validators: [], categories: [] });
  const [history, setHistory] = useState([]);

  const loadMeta = async () => {
    try {
      const res = await fetch(`${apiBase}/detectors`);
      const data = await res.json();
      if (res.ok) setMeta({ detectors: data.detectors || [], validators: data.validators || [], categories: data.categories || [] });
    } catch (_) { /* empty */ }
  };

  const loadHistory = async () => {
    try {
      const res = await fetch(`${apiBase}/policies`);
      const data = await res.json();
      const rows = (Array.isArray(data.policies) ? data.policies : [])
        .filter(p => (p?.rule_data?._meta || {}).source === 'ai_lab' || p?.ai_generated === true)
        .sort((a, b) => new Date(b?.created_at || 0) - new Date(a?.created_at || 0));
      setHistory(rows);
    } catch (_) { setHistory([]); }
  };

  useEffect(() => runSoon(() => { loadMeta(); loadHistory(); }), [apiBase]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="fade-in">
      <div className="tabs">
        {TABS.map(t => (
          <button key={t.id} className={`tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>
      {tab === 'builder' && <Builder apiBase={apiBase} notify={notify} canManage={canManage} meta={meta} reloadHistory={() => { loadHistory(); loadMeta(); }} />}
      {tab === 'checksum' && <ChecksumTools apiBase={apiBase} meta={meta} />}
      {tab === 'scan' && <LibraryScan apiBase={apiBase} />}
      {tab === 'history' && (
        <div className="card">
          <div className="card-title" style={{ marginBottom: '12px' }}>Policies created in the Lab</div>
          {history.length === 0 ? (
            <div className="empty-state"><strong>Nothing deployed from the Lab yet</strong>Draft a rule in the builder and deploy it.</div>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead><tr><th>Policy</th><th>Uses</th><th>Action</th><th>Severity</th><th>Created</th></tr></thead>
                <tbody>
                  {history.map(p => (
                    <tr key={p.policy_id}>
                      <td><div style={{ fontWeight: 600 }}>{p.name}</div><div className="field-hint">{p.rule_data?._meta?.ai_prompt || p.description}</div></td>
                      <td className="mono">{p.rule_data?.detector || p.rule_type}</td>
                      <td>{String(p.action || '').toUpperCase()}</td>
                      <td><span className={`chip ${SEV_CHIP[String(p.severity).toLowerCase()] || ''}`}>{p.severity}</span></td>
                      <td>{p.created_at ? new Date(p.created_at).toLocaleString() : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Lab;
