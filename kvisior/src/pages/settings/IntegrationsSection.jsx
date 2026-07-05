import { useEffect, useState } from 'react';
import { usePerms, actingHeaders } from '../../context/PermissionsContext';
import { INTEGRATION_DEFS } from './settingsConstants';
import { inputStyle, btnGhost, btnDanger } from './settingsUi';

function mergeWithStored(def, values, record) {
  const out = {};
  for (const f of def.fields) {
    const v = (values[f.key] ?? '').trim();
    if (v && v !== '***') {
      out[f.key] = v;
      continue;
    }
    if (f.secret && record?.config?.[f.key] === '***') {
      out[f.key] = '***';
    }
  }
  return out;
}

function IntegrationCard({ def, record, onSaved, toast }) {
  const { can } = usePerms();
  const initial = () => {
    const out = {};
    for (const f of def.fields) {
      const v = record?.config?.[f.key];
      out[f.key] = v == null ? '' : String(v);
    }
    return out;
  };
  const [values, setValues]   = useState(initial);
  const [enabled, setEnabled] = useState(!!record?.enabled);
  const [busy, setBusy]       = useState(null);

  useEffect(() => {
    setValues(initial());
    setEnabled(!!record?.enabled);
  }, [record?.updated_at, record?.enabled]);

  const buildConfig = () => {
    const out = {};
    for (const f of def.fields) {
      const v = (values[f.key] ?? '').trim();
      if (v === '' || v === '***') continue;
      out[f.key] = v;
    }
    return out;
  };

  const validateRequired = () => {
    for (const f of def.fields) {
      if (!f.required) continue;
      const v = (values[f.key] ?? '').trim();
      const stored = record?.config?.[f.key];
      const haveStored = f.secret ? stored === '***' : !!stored;
      if (!v && !haveStored) {
        toast('error', 'Missing field', `${f.label} is required`);
        return false;
      }
    }
    return true;
  };

  const save = async () => {
    if (!validateRequired()) return;
    setBusy('save');
    try {
      const cfg = mergeWithStored(def, values, record);
      const res = await fetch(`/anomaly/api/integrations/${def.kind}`, {
        method: 'PUT',
        headers: actingHeaders({ 'Content-Type': 'application/json' }),
        credentials: 'same-origin',
        body: JSON.stringify({ enabled, config: cfg }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
      toast('success', `${def.label} saved`, enabled ? 'Enabled' : 'Disabled');
      onSaved();
    } catch (e) {
      toast('error', `${def.label} save failed`, String(e.message || e));
    } finally {
      setBusy(null);
    }
  };

  const test = async () => {
    setBusy('test');
    try {
      const cfg = mergeWithStored(def, values, record);
      const res = await fetch(`/anomaly/api/integrations/${def.kind}/test`, {
        method: 'POST',
        headers: actingHeaders({ 'Content-Type': 'application/json' }),
        credentials: 'same-origin',
        body: JSON.stringify({ config: cfg }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
      toast('success', `${def.label} reachable`, 'Connection OK');
    } catch (e) {
      toast('error', `${def.label} test failed`, String(e.message || e));
    } finally {
      setBusy(null);
    }
  };

  const remove = async () => {
    setBusy('del');
    try {
      const res = await fetch(`/anomaly/api/integrations/${def.kind}`, {
        method: 'DELETE',
        headers: actingHeaders(),
        credentials: 'same-origin',
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      toast('warn', `${def.label} removed`, '');
      onSaved();
    } catch (e) {
      toast('error', 'Remove failed', String(e.message || e));
    } finally {
      setBusy(null);
    }
  };

  const isConfigured = !!record;
  const statusLabel = !isConfigured ? 'Not configured' : enabled ? 'Enabled' : 'Disabled';
  const statusColor = !isConfigured ? 'var(--text-muted)' : enabled ? 'var(--accent-3)' : 'var(--warning)';
  const writable = can('integrations.write');

  void buildConfig;

  return (
    <div className="card" style={{padding:24,border:'none',marginBottom:16}}>
      <div style={{display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:16,gap:16}}>
        <div>
          <div style={{fontSize:14,fontWeight:600,color:'var(--text-primary)',marginBottom:3}}>{def.label}</div>
          <div style={{fontSize:12,color:'var(--text-muted)',maxWidth:560}}>{def.desc}</div>
        </div>
        <label style={{display:'flex',alignItems:'center',gap:8,fontSize:12,color:statusColor,whiteSpace:'nowrap'}}>
          <input type="checkbox" checked={enabled} disabled={!writable} onChange={e => setEnabled(e.target.checked)} />
          {statusLabel}
        </label>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14,marginBottom:16}}>
        {def.fields.map(f => (
          <div key={f.key} style={f.key === 'webhook_url' || f.key === 'url' ? {gridColumn:'span 2'} : null}>
            <label style={{display:'block',fontSize:11,textTransform:'uppercase',letterSpacing:'.07em',color:'var(--text-muted)',marginBottom:6}}>
              {f.label}{f.required && <span style={{color:'var(--danger)'}}> *</span>}
            </label>
            <input
              type={f.secret ? 'password' : 'text'}
              placeholder={f.placeholder || ''}
              value={values[f.key] ?? ''}
              disabled={!writable}
              onChange={e => setValues(v => ({...v, [f.key]: e.target.value}))}
              style={inputStyle}
            />
          </div>
        ))}
      </div>

      <div style={{display:'flex',gap:8,alignItems:'center'}}>
        {writable && (
          <button className="btn btn-primary" disabled={!!busy} onClick={save}>
            {busy === 'save' ? 'Saving…' : 'Save'}
          </button>
        )}
        <button className="btn" disabled={!!busy} onClick={test} style={btnGhost}>
          {busy === 'test' ? 'Testing…' : 'Test connection'}
        </button>
        {isConfigured && writable && (
          <button disabled={!!busy} onClick={remove} style={{...btnDanger, marginLeft:'auto'}}>
            {busy === 'del' ? 'Removing…' : 'Remove'}
          </button>
        )}
      </div>

      {record?.updated_at && (
        <div style={{marginTop:10,fontSize:11,color:'var(--text-muted)'}}>
          Last updated {new Date(record.updated_at).toLocaleString()}
        </div>
      )}
    </div>
  );
}

export function IntegrationsSection({ toast }) {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);

  const reload = async () => {
    try {
      const res = await fetch('/anomaly/api/integrations', { headers: actingHeaders(), credentials: 'same-origin' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      const map = {};
      for (const it of body.items || []) map[it.kind] = it;
      setItems(map);
      setError(null);
    } catch (e) {
      setError(String(e.message || e));
    }
  };

  useEffect(() => { reload(); }, []);

  if (error) {
    return (
      <div className="card" style={{padding:24,border:'none'}}>
        <div style={{fontSize:13,color:'var(--danger)'}}>Failed to load integrations: {error}</div>
        <button className="btn" onClick={reload} style={{...btnGhost, marginTop:12}}>Retry</button>
      </div>
    );
  }
  if (items == null) {
    return <div className="card" style={{padding:24,border:'none',color:'var(--text-muted)',fontSize:13}}>Loading integrations…</div>;
  }

  return (
    <div>
      {INTEGRATION_DEFS.map(def => (
        <IntegrationCard key={def.kind} def={def} record={items[def.kind]} onSaved={reload} toast={toast} />
      ))}
    </div>
  );
}
