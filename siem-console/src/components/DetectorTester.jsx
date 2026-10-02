import { useState } from 'react';
import Icon from './Icons';

export const HighlightedText = ({ text, spans }) => {
  const sorted = [...(spans || [])].sort((a, b) => a.start - b.start);
  const parts = [];
  let last = 0;
  sorted.forEach((s, i) => {
    if (s.start < last) return;
    if (s.start > last) parts.push(<span key={`t${i}`}>{text.slice(last, s.start)}</span>);
    parts.push(
      <mark key={`m${i}`} className={s.accepted === false ? 'hit-rejected' : 'hit'} title={s.title || ''}>
        {text.slice(s.start, s.end)}
      </mark>
    );
    last = s.end;
  });
  parts.push(<span key="tail">{text.slice(last)}</span>);
  return <div className="highlight-box">{parts}</div>;
};

/**
 * Runs sample text through one detector definition (draft or saved) and explains each candidate.
 * props: apiBase, definition (draft object) | detectorName, generatorKind (optional), keywordHint
 */
const DetectorTester = ({ apiBase, definition, detectorName, generatorKind, keywordHint, defaultText = '' }) => {
  const [text, setText] = useState(defaultText);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const run = async (override) => {
    const sample = override ?? text;
    if (!sample.trim()) return;
    setBusy(true);
    setError('');
    try {
      const body = definition ? { text: sample, definition } : { text: sample, detector: detectorName };
      const res = await fetch(`${apiBase}/detectors/test`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Test failed');
        setResult(null);
      } else {
        setResult({ ...data, text: sample });
      }
    } catch (_) {
      setError('Could not reach the API');
    }
    setBusy(false);
  };

  const generate = async () => {
    if (!generatorKind) return;
    try {
      const res = await fetch(`${apiBase}/detectors/generate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind: generatorKind, count: 3 }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || 'Generator failed'); return; }
      const prefix = keywordHint ? `${keywordHint} ` : '';
      const good = data.values || [];
      const bad = good.slice(0, 1).map(v => v.slice(0, -1) + (v.slice(-1) === '0' ? '1' : '0'));
      const sample = [
        ...good.map(v => `${prefix}${v}`),
        ...bad.map(v => `${prefix}${v}   <- check digit altered, should be rejected`),
      ].join('\n');
      setText(sample);
      run(sample);
    } catch (_) {
      setError('Could not reach the API');
    }
  };

  const candidates = result?.candidates || [];
  const accepted = candidates.filter(c => c.accepted).length;

  return (
    <div>
      <div className="form-group" style={{ marginBottom: '10px' }}>
        <label>Sample text</label>
        <textarea className="form-control mono" rows={5} value={text} onChange={e => setText(e.target.value)}
          placeholder="Paste text that should (and should not) match" />
      </div>
      <div className="btn-row" style={{ marginBottom: '12px' }}>
        <button type="button" className="btn btn-sm" onClick={() => run()} disabled={busy || !text.trim()}>
          <Icon name="play" size={12} /> {busy ? 'Testing...' : 'Run test'}
        </button>
        {generatorKind && (
          <button type="button" className="btn btn-secondary btn-sm" onClick={generate} disabled={busy}>
            <Icon name="wand" size={12} /> Generate valid samples
          </button>
        )}
        {result && (
          <span className="chip">{accepted} accepted / {candidates.length - accepted} rejected</span>
        )}
      </div>
      {error && <div className="notice notice-error" style={{ marginBottom: '10px' }}>{error}</div>}
      {result && (
        <>
          <HighlightedText text={result.text} spans={candidates.map(c => ({ ...c, title: c.reason }))} />
          {candidates.length > 0 ? (
            <div className="table-wrap" style={{ marginTop: '10px', maxHeight: '240px' }}>
              <table className="data-table">
                <thead><tr><th>Value</th><th>Checksum</th><th>Keyword</th><th>Decision</th></tr></thead>
                <tbody>
                  {candidates.map((c, i) => (
                    <tr key={i}>
                      <td className="mono">{c.value}</td>
                      <td>{c.validator ? (c.validator_passed ? <span className="chip chip-success">{c.validator} ok</span> : <span className="chip chip-danger">{c.validator} failed</span>) : <span className="chip">none</span>}</td>
                      <td>{c.keyword ? <span className="chip chip-accent">{c.keyword}</span> : <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                      <td>
                        <span className={`chip ${c.accepted ? 'chip-danger' : ''}`}>{c.accepted ? 'Detected' : 'Ignored'}</span>
                        <div className="field-hint">{c.reason}{c.accepted ? ` (confidence ${c.confidence})` : ''}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state" style={{ marginTop: '10px' }}>No candidates: the pattern does not match this text.</div>
          )}
        </>
      )}
    </div>
  );
};

export default DetectorTester;
