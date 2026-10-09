import { useEffect, useState } from 'react';
import { usePerms } from '../../context/PermissionsContext';
import { apiJSON } from './settingsApi';
import { Field } from '../../components/kit';
import { SettingsRow, SettingsActions } from './settingsUi';

const CHOICES = [1, 3, 7, 14, 21, 30];

const request = (method, body) =>
  apiJSON('/api/audit/retention', { method, body: body ? JSON.stringify(body) : undefined });

const days = hours => Math.round(hours / 24);

export function AuditRetentionCard({ toast }) {
  const { isAdmin } = usePerms();
  const [view, setView] = useState(null);
  const [error, setError] = useState('');
  const [choice, setChoice] = useState(14);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    request('GET')
      .then(data => { if (alive) { setView(data); setChoice(days(data.hours)); } })
      .catch(e => alive && setError(String(e.message || e)));
    return () => { alive = false; };
  }, []);

  if (!view) {
    return (
      <SettingsRow icon="clock" title="Audit log retention" desc="How long audit events, silenced events and rollups are kept."
        status={error ? 'Unavailable' : 'Loading…'} tone={error ? 'danger' : 'muted'}>
        <p className={`set-lead ${error ? 't-danger' : ''}`}>{error ? `Failed to load the audit log retention: ${error}` : 'Loading the audit log retention…'}</p>
      </SettingsRow>
    );
  }

  const current = days(view.hours);
  const options = [...new Set([...CHOICES, current])]
    .filter(d => d * 24 >= view.minHours && d * 24 <= view.maxHours)
    .sort((a, b) => a - b);
  const editable = isAdmin && view.editable;

  const save = async () => {
    if (choice < current && !window.confirm(
      `Audit events older than ${choice} ${choice === 1 ? 'day' : 'days'} will be deleted for every cluster within the next hour. This cannot be undone. Continue?`)) {
      return;
    }
    setBusy(true);
    try {
      const data = await request('PUT', { hours: choice * 24 });
      setView(data);
      setChoice(days(data.hours));
      toast('success', 'Audit log retention saved', `Every cluster keeps ${days(data.hours)} days of audit events`);
    } catch (e) {
      toast('error', 'Audit log retention was not saved', String(e.message || e));
    } finally {
      setBusy(false);
    }
  };

  const note = !view.editable
    ? 'Set on the hub. This kvisior reads the shared value and cannot change it.'
    : view.updatedAt
      ? `Last changed by ${view.updatedBy || 'unknown'} on ${new Date(view.updatedAt).toLocaleString()}`
      : 'Taken from AUDIT_RETENTION_HOURS when the hub first started';

  return (
    <SettingsRow icon="clock" title="Audit log retention" desc="How long audit events, silenced events and rollups are kept."
      summary={`${current} ${current === 1 ? 'day' : 'days'}`}
      status={view.synced ? (view.editable ? null : 'Set on the hub') : 'Waiting for the hub'} tone={view.synced ? 'muted' : 'warning'}>
      <p className="set-lead">One value applies to every cluster that shares the database. Shortening it deletes older events within the next hour.</p>
      <Field label="Keep audit events for" htmlFor="audit-retention" className="set-narrow">
        <select id="audit-retention" className="input input--block" value={choice} disabled={!editable || busy}
          onChange={e => setChoice(Number(e.target.value))}>
          {options.map(d => <option key={d} value={d}>{d} {d === 1 ? 'day' : 'days'}</option>)}
        </select>
      </Field>
      <SettingsActions aside={<span className={`set-actions-note ${view.synced ? '' : 't-warning'}`}>{view.synced ? note : 'Waiting for the hub value: nothing is deleted until it is read.'}</span>}>
        {editable && (
          <button type="button" className="btn btn-primary" disabled={busy || choice === current} onClick={save}>{busy ? 'Saving…' : 'Save'}</button>
        )}
      </SettingsActions>
    </SettingsRow>
  );
}
