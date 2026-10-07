import { useEffect, useRef, useState } from 'react';
import { useApp } from '../../context/AppContext';
import { createSilence, deleteSilence, endSilence } from './api';
import { KINDS, fmtDate, num } from './shared';
import { DataWindow } from '../../components/DataWindow';
import { Pager } from '../../components/Pager';
import { usePaged } from '../../hooks/usePaged';

const DURATIONS = [[60, '1 hour'], [8 * 60, '8 hours'], [24 * 60, '24 hours'], [7 * 24 * 60, '7 days'], [0, 'Until removed']];
const BLANK = { action: '', object: '', user: '', sourceIP: '', reason: '', minutes: 8 * 60 };

export function silenceObject(ev) {
  return [ev.resource, ev.ns, ev.name].filter(Boolean).join('/');
}

export function describeSilence(s) {
  const parts = [s.action || 'any action', s.object || 'any object'];
  if (s.user) parts.push(`by ${s.user}`);
  if (s.sourceIP) parts.push(`from ${s.sourceIP}`);
  return parts.join(' ');
}

function remaining(s, now) {
  if (!s.active) return null;
  if (!s.expiresAt) return 'until removed';
  const m = Math.max(1, Math.ceil((new Date(s.expiresAt).getTime() - now) / 60000));
  if (m < 60) return `${m} min left`;
  const h = Math.floor(m / 60);
  return h < 48 ? `${h} h ${m % 60} min left` : `${Math.floor(h / 24)} d ${h % 24} h left`;
}

function validate(s) {
  const found = {};
  if (!(s.action || s.object.trim() || s.user.trim() || s.sourceIP.trim())) found.match = 'Fill in at least one of action, object, user or source IP.';
  const ip = s.sourceIP.trim();
  if (ip) {
    const [base, bits, extra] = ip.split('/');
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(base);
    const okBase = base.includes(':') || (v4 && v4.slice(1).every(o => +o <= 255));
    if (extra !== undefined || !okBase || (bits !== undefined && !/^\d{1,3}$/.test(bits))) {
      found.sourceIP = 'Enter an address or a CIDR range, for example 10.0.0.0/8.';
    }
  }
  return found;
}

function SilenceForm({ initial, onSave, onCancel }) {
  const [s, setS] = useState(initial);
  const [errors, setErrors] = useState({});
  const [saving, setSaving] = useState(false);
  const firstRef = useRef(null);

  useEffect(() => { setS(initial); setErrors({}); firstRef.current?.focus(); }, [initial]);

  const set = (key, value) => setS(prev => ({ ...prev, [key]: value }));

  const submit = async e => {
    e.preventDefault();
    const found = validate(s);
    setErrors(found);
    if (Object.keys(found).length) return;
    setSaving(true);
    try {
      await onSave({
        action: s.action, object: s.object.trim(), user: s.user.trim(), sourceIP: s.sourceIP.trim(),
        reason: s.reason.trim(), minutes: s.minutes,
      });
    } catch (err) {
      setErrors({ save: err.status === 403 ? 'Only administrators can silence events.' : err.message });
    } finally {
      setSaving(false);
    }
  };

  return (
    <form className="aul-form" onSubmit={submit} noValidate>
      <h2>New silence</h2>
      <fieldset>
        <legend>Events to silence</legend>
        <div className="aul-grid">
          <label>Action
            <select ref={firstRef} className="aul-input" value={s.action} onChange={e => set('action', e.target.value)}>
              <option value="">Any action</option>
              {KINDS.map(k => <option key={k} value={k}>{k}</option>)}
            </select>
          </label>
          <label>Object
            <input className="aul-input aul-mono" value={s.object} maxLength={512} onChange={e => set('object', e.target.value)} placeholder="configmaps/default/*" />
          </label>
          <label>User
            <input className="aul-input aul-mono" value={s.user} maxLength={512} onChange={e => set('user', e.target.value)} placeholder="system:serviceaccount:ci:*" />
          </label>
          <label>Source IP
            <input className={`aul-input aul-mono${errors.sourceIP ? ' invalid' : ''}`} value={s.sourceIP} maxLength={64}
                   onChange={e => set('sourceIP', e.target.value)} placeholder="10.0.0.0/8" />
            {errors.sourceIP && <span className="aul-err">{errors.sourceIP}</span>}
          </label>
        </div>
        {errors.match && <p className="aul-err aul-gap">{errors.match}</p>}
        <p className="aul-hint aul-gap">An event is silenced when it matches every field that is filled in. Object is <span className="aul-mono">resource/namespace/name</span>; Object and User accept <span className="aul-mono">*</span>.</p>
      </fieldset>
      <fieldset>
        <legend>For how long</legend>
        <div className="aul-chips" role="group" aria-label="Duration">
          {DURATIONS.map(([value, label]) => (
            <button key={value} type="button" className="aul-chip" aria-pressed={s.minutes === value} onClick={() => set('minutes', value)}>{label}</button>
          ))}
        </div>
        <div className="aul-grid aul-gap">
          <label>Reason
            <input className="aul-input" value={s.reason} maxLength={500} onChange={e => set('reason', e.target.value)} placeholder="Why these events are expected, for the next person on duty" />
          </label>
        </div>
      </fieldset>
      {errors.save && <p className="aul-err">Could not save the silence: {errors.save}</p>}
      <div className="aul-actions">
        <button className="btn btn-primary aul-btn" type="submit" disabled={saving}>{saving ? 'Saving…' : 'Silence events'}</button>
        <button className="btn btn-outline aul-btn" type="button" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

export function Silent({ silences, loadError, canEdit, reload, draft, onDraftUsed }) {
  const { toast } = useApp();
  const [form, setForm] = useState(null);
  const [confirm, setConfirm] = useState(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (!draft) return;
    setForm({ ...BLANK, ...draft });
    onDraftUsed();
  }, [draft, onDraftUsed]);

  const run = async (action, done) => {
    try {
      await action();
      await reload();
      if (done) toast('success', done);
    } catch (e) {
      toast('error', 'The change was not saved', e.status === 403 ? 'Only administrators can change silences.' : e.message);
    }
  };

  const save = async body => {
    await createSilence(body);
    await reload();
    setForm(null);
    toast('success', 'Silence saved', 'New matching events no longer appear in Monitoring and Investigation.');
  };

  const { pageItems: pageSilences, pager } = usePaged(silences, 'audit.silences');
  const active = silences.filter(s => s.active).length;

  return (
    <div>
      <div className="aul-toolbar">
        {canEdit && <button className="btn btn-primary aul-btn" onClick={() => setForm({ ...BLANK })}>New silence</button>}
      </div>
      <p className="aul-hint aul-note">
        {silences.length} silences, {active} active. Silenced events leave Monitoring and Investigation; Hidden shows how many each silence caught. Rules, violations and alerts still work for them.
        Ending a silence keeps those events hidden; deleting it returns them to the other tabs.
        {!canEdit && ' Only administrators can change silences.'}
      </p>
      {loadError && <p className="aul-err">Could not load the silences: {loadError}</p>}
      {form && <SilenceForm initial={form} onSave={save} onCancel={() => setForm(null)} />}
      <DataWindow label="Silences" deps={[!!form, !!loadError]} footer={<Pager {...pager} noun="silences" />}>
        <table className="data-table aul-silences">
          <thead><tr><th>Silences</th><th>Reason</th><th>Created</th><th>Expires</th><th>Hidden</th><th /></tr></thead>
          <tbody>
            {silences.length === 0 && (
              <tr className="aul-norow"><td colSpan={6}><div className="aul-blank">
                No silences. Select an event in Monitoring or Investigation and choose “Silence events like this”, or add one here.
              </div></td></tr>
            )}
            {pageSilences.map(s => (
              <tr key={s.id} className={s.active ? '' : 'aul-ended'}>
                <td className="aul-rulecell"><div className="aul-mono">{describeSilence(s)}</div></td>
                <td className="aul-reason">{s.reason || <span className="aul-empty">no reason given</span>}</td>
                <td className="aul-mono">{fmtDate(s.createdAt)}{s.createdBy && <div className="aul-dim">by {s.createdBy}</div>}</td>
                <td className="aul-mono">{s.active
                  ? <span className={s.expiresAt ? 'aul-left' : ''}>{remaining(s, now)}</span>
                  : <span className="aul-dim">ended {fmtDate(s.expiresAt)}</span>}</td>
                <td className="aul-mono">{num(s.hits)}{s.lastHitAt && <div className="aul-dim">last {fmtDate(s.lastHitAt)}</div>}</td>
                <td>
                  {canEdit && (
                    <div className="aul-rowactions">
                      {confirm === s.id ? (
                        <>
                          <button className="btn btn-danger aul-btn-sm" onClick={() => { setConfirm(null); run(() => deleteSilence(s.id), 'Silence deleted, its events are back in Monitoring and Investigation'); }}>Delete silence</button>
                          <button className="btn btn-outline aul-btn-sm" onClick={() => setConfirm(null)}>Keep</button>
                        </>
                      ) : (
                        <>
                          {s.active && <button className="btn btn-outline aul-btn-sm" onClick={() => run(() => endSilence(s.id), 'Silence ended')}>End now</button>}
                          <button className="btn btn-outline aul-btn-sm" onClick={() => setConfirm(s.id)}>Delete</button>
                        </>
                      )}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataWindow>
    </div>
  );
}
