import { apiFetch } from '../../data/cluster';
import { useEffect, useState } from 'react';
import { usePerms, actingHeaders } from '../../context/PermissionsContext';
import { INTEGRATION_DEFS } from './settingsConstants';
import { AuditLogSourceCard } from './AuditLogSourceCard';
import { AuditRetentionCard } from './AuditRetentionCard';
import { Field, Switch, Notice } from '../../components/kit';

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
      const res = await apiFetch(`/anomaly/api/integrations/${def.kind}`, {
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
      const res = await apiFetch(`/anomaly/api/integrations/${def.kind}/test`, {
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
      const res = await apiFetch(`/anomaly/api/integrations/${def.kind}`, {
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
  const statusTone = !isConfigured ? 't-muted' : enabled ? 't-ok' : 't-warning';
  const writable = can('integrations.write');
  const wide = key => key === 'webhook_url' || key === 'url';

  return (
    <section className="pane settings-section">
      <div className="pane-head">
        <div className="grow">
          <div className="pane-title">{def.label}</div>
          <div className="pane-sub">{def.desc}</div>
        </div>
        <span className={`row t-sm ${statusTone}`}>
          <Switch checked={enabled} disabled={!writable} onChange={setEnabled} label={`${def.label} enabled`} />
          {statusLabel}
        </span>
      </div>
      <div className="pane-body">
        <div className="fields fields--2">
          {def.fields.map(f => (
            <Field key={f.key} className={wide(f.key) ? 'span-2' : undefined} htmlFor={`int-${def.kind}-${f.key}`}
              label={<>{f.label}{f.required && <span className="t-danger"> *</span>}</>}>
              <input id={`int-${def.kind}-${f.key}`} type={f.secret ? 'password' : 'text'} placeholder={f.placeholder || ''}
                value={values[f.key] ?? ''} disabled={!writable} className="input input--block"
                onChange={e => setValues(v => ({ ...v, [f.key]: e.target.value }))} />
            </Field>
          ))}
        </div>
        <div className="row">
          {writable && (
            <button type="button" className="btn btn-primary" disabled={!!busy} onClick={save}>{busy === 'save' ? 'Saving…' : 'Save'}</button>
          )}
          <button type="button" className="btn btn-ghost" disabled={!!busy} onClick={test}>{busy === 'test' ? 'Testing…' : 'Test connection'}</button>
          <span className="grow" />
          {isConfigured && writable && (
            <button type="button" disabled={!!busy} onClick={remove} className="btn btn-ghost btn-tone-danger">{busy === 'del' ? 'Removing…' : 'Remove'}</button>
          )}
        </div>
        {record?.updated_at && <div className="field-hint mt-8">Last updated {new Date(record.updated_at).toLocaleString()}</div>}
      </div>
    </section>
  );
}

export function IntegrationsSection({ toast }) {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);

  const reload = async () => {
    try {
      const res = await apiFetch('/anomaly/api/integrations', { headers: actingHeaders(), credentials: 'same-origin' });
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
      <div>
        <AuditLogSourceCard toast={toast} />
        <AuditRetentionCard toast={toast} />
        <Notice tone="danger" className="settings-section">
          <div>Failed to load integrations: {error}</div>
          <button type="button" className="btn btn-ghost btn-sm mt-8" onClick={reload}>Retry</button>
        </Notice>
      </div>
    );
  }
  if (items == null) {
    return <div className="pane empty-state empty-state--compact">Loading integrations…</div>;
  }

  return (
    <div>
      <AuditLogSourceCard toast={toast} />
      <AuditRetentionCard toast={toast} />
      {INTEGRATION_DEFS.map(def => (
        <IntegrationCard key={def.kind} def={def} record={items[def.kind]} onSaved={reload} toast={toast} />
      ))}
    </div>
  );
}
