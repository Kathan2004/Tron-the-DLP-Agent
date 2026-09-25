import { useEffect, useMemo, useState } from 'react';

const Lab = ({ apiBase }) => {
  const [prompt, setPrompt] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedRule, setGeneratedRule] = useState(null);
  const [testInput, setTestInput] = useState("");
  const [testResult, setTestResult] = useState(null);
  const [isTesting, setIsTesting] = useState(false);
  const [message, setMessage] = useState(null);
  const [policyHistory, setPolicyHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const loadPolicyHistory = async () => {
    if (!apiBase) return;
    setHistoryLoading(true);
    try {
      const res = await fetch(`${apiBase}/policies`);
      const data = await res.json();
      setPolicyHistory(Array.isArray(data.policies) ? data.policies : []);
    } catch {
      setPolicyHistory([]);
    }
    setHistoryLoading(false);
  };

  useEffect(() => {
    loadPolicyHistory();
  }, [apiBase]);

  const aiHistory = useMemo(() => {
    return (policyHistory || [])
      .filter((p) => {
        const meta = p?.rule_data?._meta || {};
        return meta?.source === 'ai_lab' || meta?.ai_generated === true || p?.ai_generated === true;
      })
      .sort((a, b) => new Date(b?.created_at || 0).getTime() - new Date(a?.created_at || 0).getTime());
  }, [policyHistory]);

  const handleGenerate = async () => {
    if (!prompt) return;
    setIsGenerating(true);
    setMessage(null);
    try {
      const res = await fetch(`${apiBase}/lab/generate_rule`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt })
      });
      const data = await res.json();
      if (data.error) {
        setMessage({ type: 'error', text: data.error });
        setGeneratedRule(null);
      } else {
        setGeneratedRule(data);
        setMessage({ type: 'success', text: "AI rule generation complete!" });
        setTestInput(data.rule_type === 'file_size' ? "5" : (data.rule_type === 'extension' ? "test.exe" : "Sample value..."));
      }
    } catch (err) { setMessage({ type: 'error', text: "Failed to connect to AI service" }); }
    setIsGenerating(false);
  };

  const handleTest = async () => {
    if (!generatedRule || !testInput) return;
    setIsTesting(true);
    try {
      const res = await fetch(`${apiBase}/lab/test_rule`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule: generatedRule, input: testInput })
      });
      const data = await res.json();
      setTestResult(data);
    } catch (err) { setMessage({ type: 'error', text: "Test failed" }); }
    setIsTesting(false);
  };

  const handleActivate = async () => {
    if (!generatedRule) return;
    try {
      const payload = {
        ...generatedRule,
        ai_generated: true,
        ai_prompt: prompt,
        rule_data: {
          ...(generatedRule.rule_data || {}),
          _meta: {
            source: 'ai_lab',
            ai_generated: true,
            ai_prompt: prompt,
            ai_model: generatedRule.ai_model || 'VertexAI',
            generated_at: new Date().toISOString(),
          }
        }
      };
      const res = await fetch(`${apiBase}/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        setMessage({ type: 'success', text: "Rule activated successfully! Fleet syncing..." });
        setGeneratedRule(null);
        setPrompt("");
        await loadPolicyHistory();
      } else {
        const d = await res.json();
        setMessage({ type: 'error', text: d.error || "Failed to activate rule" });
      }
    } catch (err) { setMessage({ type: 'error', text: "Connection error" }); }
  };

  return (
    <div className="analytics-container fade-in">
      <div className="panel" style={{ marginBottom: '24px' }}>
        <h2 style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          AI Policy Lab
          <span style={{ fontSize: '12px', background: 'var(--surface-subtle)', padding: '4px 10px', borderRadius: '12px', fontWeight: 500, color: 'var(--accent)' }}>EXPERIMENTAL</span>
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '14px', marginBottom: '20px' }}>
          Describe a security threat or a data protection requirement in plain English. 
          Our AI will generate the appropriate rule logic and let you test it before deployment.
        </p>

        <div style={{ display: 'flex', gap: '12px' }}>
          <input 
            type="text" 
            placeholder="e.g., Block all file uploads larger than 3 MB"
            className="search-input"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleGenerate()}
            style={{ flex: 1, padding: '12px 16px', background: 'var(--input-bg)', border: '1px solid var(--border-color)', borderRadius: '8px', color: 'var(--text-strong)', fontSize: '15px' }} />
          <button onClick={handleGenerate} disabled={isGenerating || !prompt}
            style={{ padding: '0 24px', background: 'var(--accent)', border: 'none', borderRadius: '8px', color: 'var(--text-inverse)', fontWeight: 600, cursor: 'pointer', opacity: (isGenerating || !prompt) ? 0.5 : 1 }}>
            {isGenerating ? 'Generating...' : 'Go'}
          </button>
        </div>
        {message && <div style={{ marginTop: '16px', padding: '10px 16px', borderRadius: '6px', background: message.type === 'error' ? 'rgba(248,81,73,0.1)' : 'rgba(46,160,67,0.1)', color: message.type === 'error' ? 'var(--danger)' : 'var(--success)', fontSize: '13px' }}>{message.text}</div>}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 1fr)', gap: '24px' }}>
        <div className="panel">
            <h3 style={{ color: 'var(--text-strong)', fontSize: '16px', marginBottom: '16px' }}>Rule Extraction</h3>
          {generatedRule ? (
              <div style={{ padding: '20px', background: 'var(--surface-subtle)', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                  <div style={{ color: 'var(--accent)', fontSize: '18px', fontWeight: 700, marginBottom: '8px' }}>{generatedRule.name}</div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '16px' }}>{generatedRule.description}</div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', fontSize: '12px' }}>
                  <div>Type: <span style={{ color: 'var(--text-strong)' }}>{generatedRule.rule_type}</span></div>
                      <div>Action: <span style={{ color: 'var(--accent)' }}>{generatedRule.action}</span></div>
                      <div>Severity: <span style={{ color: 'var(--warning)' }}>{generatedRule.severity}</span></div>
                  </div>
              </div>
          ) : <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '60px 0' }}>Rule definition will appear here.</div>}
        </div>

        <div className="panel">
           <h3 style={{ color: 'var(--text-strong)', fontSize: '16px', marginBottom: '16px' }}>Test & Deploy</h3>
           {generatedRule ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                 <input type="text" value={testInput} onChange={e => setTestInput(e.target.value)}
                        style={{ padding: '12px', background: 'var(--input-bg)', border: '1px solid var(--border-color)', borderRadius: '8px', color: 'var(--text-strong)', fontSize: '13px' }} placeholder="Test input..." />
                 <button onClick={handleTest} disabled={isTesting}
                         style={{ padding: '12px', background: 'var(--surface-subtle)', border: '1px solid var(--border-color)', borderRadius: '8px', color: 'var(--text-strong)', cursor: 'pointer' }}>
                   {isTesting ? 'Testing...' : 'Test Pattern'}
                 </button>
                 {testResult && (
                   <div style={{ padding: '16px', borderRadius: '8px', background: testResult.match ? 'rgba(248,81,73,0.1)' : 'rgba(46,160,67,0.1)', border: '1px solid var(--border-color)', textAlign: 'center' }}>
                       <div style={{ color: testResult.match ? 'var(--danger)' : 'var(--success)', fontWeight: 800, fontSize: '20px' }}>{testResult.match ? '⚠️ MATCH' : '✅ CLEAN'}</div>
                       <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>{testResult.reason}</div>
                   </div>
                 )}
                 <button onClick={handleActivate} style={{ width: '100%', padding: '16px', background: 'var(--success)', color: 'var(--text-inverse)', border: 'none', borderRadius: '8px', fontWeight: 700, cursor: 'pointer', marginTop: '10px' }}>Activate Rule</button>
              </div>
           ) : <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '60px 0' }}>Sandbox is inactive.</div>}
        </div>
      </div>

      <div className="panel" style={{ marginTop: '24px' }}>
        <h3 style={{ color: 'var(--text-strong)', fontSize: '16px', marginBottom: '12px' }}>AI Rule History</h3>
        {historyLoading ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Loading AI rule history...</div>
        ) : aiHistory.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No AI-generated rules deployed yet.</div>
        ) : (
          <div style={{ display: 'grid', gap: '8px' }}>
            {aiHistory.slice(0, 12).map((p) => (
              <div key={p.policy_id} style={{ border: '1px solid var(--border-color)', borderRadius: '8px', padding: '10px 12px', background: 'var(--surface-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px' }}>
                  <div style={{ color: 'var(--text-strong)', fontWeight: 700 }}>{p.name}</div>
                  <span style={{ fontSize: '10px', fontWeight: 700, color: 'var(--accent)', border: '1px solid var(--accent)', borderRadius: '999px', padding: '2px 8px' }}>AI</span>
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '4px' }}>{p.description || 'No description'}</div>
                <div style={{ color: 'var(--text-main)', fontSize: '11px', marginTop: '6px' }}>
                  {p.rule_type?.toUpperCase()} • {p.severity} • {p.created_at ? new Date(p.created_at).toLocaleString() : '—'}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default Lab;
