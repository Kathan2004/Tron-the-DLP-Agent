// Shared form for editing built-in detectors (overridable fields only) and custom detectors.
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

const Modified = ({ show, defaultValue }) => (show ? (
  <span className="chip chip-warning" style={{ marginLeft: '6px' }} title={`Default: ${defaultValue}`}>modified</span>
) : null);

const keywordsToText = (k) => (Array.isArray(k) ? k.join(', ') : (k || ''));

const DetectorForm = ({ value, onChange, mode = 'custom', validators = [], categories = [], defaults = {}, readOnly = false }) => {
  const v = value || {};
  const set = (patch) => onChange({ ...v, ...patch });
  const isBuiltin = mode === 'builtin';
  const changed = (key) => isBuiltin && defaults && JSON.stringify(defaults[key] ?? null) !== JSON.stringify(v[key] ?? null);
  const validatorInfo = validators.find(x => x.name === v.validator);

  return (
    <fieldset disabled={readOnly} style={{ border: 'none', padding: 0, margin: 0 }}>
      {!isBuiltin && (
        <div className="grid-2">
          <div className="form-group">
            <label>Name</label>
            <input className="form-control mono" value={v.name || ''} disabled={mode === 'custom-edit'}
              onChange={e => set({ name: e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, '_') })} placeholder="EMPLOYEE_ID" />
            <div className="field-hint">Uppercase letters, digits and underscores.</div>
          </div>
          <div className="form-group">
            <label>Category</label>
            <select className="form-control" value={v.category || 'Custom'} onChange={e => set({ category: e.target.value })}>
              {(categories.length ? categories : ['Custom']).map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
        </div>
      )}
      {!isBuiltin && (
        <div className="form-group">
          <label>Description</label>
          <input className="form-control" value={v.description || ''} onChange={e => set({ description: e.target.value })}
            placeholder="What this detector finds" />
        </div>
      )}

      <div className="form-group">
        <label>Pattern (regular expression) <Modified show={changed('pattern')} defaultValue={defaults.pattern} /></label>
        <textarea className="form-control mono" rows={2} value={v.pattern || ''} onChange={e => set({ pattern: e.target.value })}
          placeholder="\bEMP-\d{6}\b" />
        <div className="field-hint">Runs on the server and in the browser extension: no inline flags like (?i) and no named groups.</div>
      </div>

      <div className="grid-2">
        <div className="form-group">
          <label>Checksum validator <Modified show={changed('validator')} defaultValue={defaults.validator || 'none'} /></label>
          <select className="form-control" value={v.validator || ''} onChange={e => set({ validator: e.target.value || null })}>
            <option value="">None (pattern only)</option>
            {validators.map(x => <option key={x.name} value={x.name}>{x.name}</option>)}
          </select>
          {validatorInfo && <div className="field-hint">{validatorInfo.description}</div>}
        </div>
        {!isBuiltin ? (
          <div className="form-group">
            <label>Capture group</label>
            <input type="number" min="0" max="9" className="form-control" value={v.group ?? 0}
              onChange={e => set({ group: Number(e.target.value) })} />
            <div className="field-hint">0 = whole match. Use 1 to validate only the part inside the first ( ).</div>
          </div>
        ) : (
          <div className="form-group">
            <label>Severity <Modified show={changed('severity')} defaultValue={defaults.severity} /></label>
            <select className="form-control" value={v.severity || 'medium'} onChange={e => set({ severity: e.target.value })}>
              {SEVERITIES.map(sv => <option key={sv} value={sv}>{sv.toUpperCase()}</option>)}
            </select>
          </div>
        )}
      </div>

      <div className="form-group">
        <label>Context keywords <Modified show={changed('keywords')} defaultValue={keywordsToText(defaults.keywords)} /></label>
        <input className="form-control" value={keywordsToText(v.keywords)}
          onChange={e => set({ keywords: e.target.value.split(',').map(x => x.trimStart()) })}
          placeholder="employee, staff id, payroll" />
        <div className="field-hint">Looked up within 64 characters of a match. They raise confidence, or are mandatory when "require keyword" is on.</div>
      </div>

      <div className="grid-2">
        {!isBuiltin && (
          <div className="form-group">
            <label>Severity</label>
            <select className="form-control" value={v.severity || 'medium'} onChange={e => set({ severity: e.target.value })}>
              {SEVERITIES.map(sv => <option key={sv} value={sv}>{sv.toUpperCase()}</option>)}
            </select>
          </div>
        )}
        <div className="form-group">
          <label>Confidence <Modified show={changed('confidence')} defaultValue={defaults.confidence} /></label>
          <input type="number" step="0.01" min="0.05" max="0.99" className="form-control" value={v.confidence ?? 0.8}
            onChange={e => set({ confidence: e.target.value === '' ? '' : Number(e.target.value) })} />
        </div>
      </div>

      <div style={{ display: 'flex', gap: '22px', flexWrap: 'wrap', marginTop: '4px' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
          <span className="switch"><input type="checkbox" checked={!!v.require_keyword} onChange={e => set({ require_keyword: e.target.checked })} /><span /></span>
          Require keyword <Modified show={changed('require_keyword')} defaultValue={String(defaults.require_keyword || false)} />
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
          <span className="switch"><input type="checkbox" checked={!!v.ignore_case} onChange={e => set({ ignore_case: e.target.checked })} /><span /></span>
          Ignore case <Modified show={changed('ignore_case')} defaultValue={String(defaults.ignore_case || false)} />
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
          <span className="switch"><input type="checkbox" checked={v.enabled !== false} onChange={e => set({ enabled: e.target.checked })} /><span /></span>
          Enabled
        </label>
      </div>
    </fieldset>
  );
};

export default DetectorForm;
