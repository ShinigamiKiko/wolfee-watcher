import { apiFetch } from '../../data/cluster';
import { useEffect, useState } from 'react';
import { usePerms, actingHeaders } from '../../context/PermissionsContext';
import { INTEGRATION_DEFS } from './settingsConstants';
import { AuditLogSourceCard } from './AuditLogSourceCard';
import { AuditRetentionCard } from './AuditRetentionCard';
import { Field, Switch, Notice } from '../../components/kit';
import { SettingsGroup, SettingsRow, SettingsActions, SettingsToggle } from './settingsUi';

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
  const live = !!record?.enabled;
  const statusLabel = !isConfigured ? 'Not configured' : live ? 'Connected' : 'Disabled';
  const tone = !isConfigured ? 'muted' : live ? 'ok' : 'warning';
  const writable = can('integrations.write');
  const wide = key => key === 'webhook_url' || key === 'url';
  const summary = def.summary?.(record?.config || {});

  return (
    <SettingsRow icon={def.icon} title={def.label} desc={def.desc} summary={isConfigured ? summary : null} status={statusLabel} tone={tone}>
      <SettingsToggle label={def.toggle} hint={enabled === live ? null : 'Takes effect after Save'}>
        <Switch checked={enabled} disabled={!writable} onChange={setEnabled} label={`${def.label} enabled`} />
      </SettingsToggle>
      <div className="fields fields--2">
        {def.fields.map(f => (
          <Field key={f.key} className={wide(f.key) ? 'span-2' : undefined} htmlFor={`int-${def.kind}-${f.key}`}
            label={<>{f.label}{f.required && <span className="t-danger"> *</span>}</>}>
            <input id={`int-${def.kind}-${f.key}`} type={f.secret ? 'password' : 'text'} placeholder={f.placeholder || ''}
              value={values[f.key] ?? ''} disabled={!writable} className={`input input--block${f.secret || wide(f.key) ? ' input--mono' : ''}`}
              onChange={e => setValues(v => ({ ...v, [f.key]: e.target.value }))} />
          </Field>
        ))}
      </div>
      <SettingsActions aside={<>
        <button type="button" className="btn btn-outline" disabled={!!busy} onClick={test}>{busy === 'test' ? 'Testing…' : 'Test connection'}</button>
        {isConfigured && writable && (
          <button type="button" disabled={!!busy} onClick={remove} className="btn btn-ghost btn-tone-danger">{busy === 'del' ? 'Removing…' : 'Remove'}</button>
        )}
      </>}>
        {record?.updated_at && <span className="set-actions-note">Updated {new Date(record.updated_at).toLocaleString()}</span>}
        {writable && (
          <button type="button" className="btn btn-primary" disabled={!!busy} onClick={save}>{busy === 'save' ? 'Saving…' : 'Save'}</button>
        )}
      </SettingsActions>
    </SettingsRow>
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

  const audit = (
    <SettingsGroup title="Kubernetes audit" desc="Where audit events come from and how long they are kept.">
      <AuditLogSourceCard toast={toast} />
      <AuditRetentionCard toast={toast} />
    </SettingsGroup>
  );
  const rows = group => (items == null
    ? <div className="set-row-loading">Loading integrations…</div>
    : INTEGRATION_DEFS.filter(d => d.group === group).map(def => (
      <IntegrationCard key={def.kind} def={def} record={items[def.kind]} onSaved={reload} toast={toast} />
    )));

  return (
    <div className="set-stack">
      {audit}
      {error ? (
        <Notice tone="danger">
          <div>Failed to load integrations: {error}</div>
          <button type="button" className="btn btn-ghost btn-sm mt-8" onClick={reload}>Retry</button>
        </Notice>
      ) : (
        <>
          <SettingsGroup title="Alert destinations" desc="Where anomalies and alerts are delivered. Every enabled destination receives each alert.">
            {rows('alerts')}
          </SettingsGroup>
          <SettingsGroup title="Registries" desc="Credentials the scanner uses to pull images.">
            {rows('registry')}
          </SettingsGroup>
        </>
      )}
    </div>
  );
}
