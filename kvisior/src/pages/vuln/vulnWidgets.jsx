import { useState } from 'react';
import { Icon } from '../../components/Icon';
import { Field, Seg, Switch, Notice } from '../../components/kit';

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

export function ScheduleModal({ schedule, onSave, onClose }) {
  const [form, setForm] = useState({
    enabled:   schedule?.enabled   ?? false,
    frequency: schedule?.frequency ?? 'daily',
    timeOfDay: schedule?.timeOfDay ?? '02:00',
    dayOfWeek: schedule?.dayOfWeek ?? 1,
  });
  const [saving, setSaving] = useState(false);
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleSave = async () => {
    setSaving(true);
    try { await onSave(form); onClose(); } finally { setSaving(false); }
  };

  const fmtNextRun = () => {
    if (!form.enabled) return 'Disabled';
    const now = new Date();
    const [h, m] = form.timeOfDay.split(':').map(Number);
    let next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), h, m));
    if (form.frequency === 'daily') {
      if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
    } else {
      let d = 0;
      while (d <= 7) {
        const c = new Date(next); c.setUTCDate(next.getUTCDate() + d);
        if (c.getUTCDay() === form.dayOfWeek && c > now) { next = c; break; }
        d++;
      }
    }
    return next.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
  };

  return (
    <div className="modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal modal--sm" role="dialog" aria-modal="true" aria-labelledby="scan-schedule-title">
        <div className="modal-header">
          <div>
            <div className="modal-title row" id="scan-schedule-title"><Icon name="clock" /> Scan Schedule</div>
            <div className="modal-sub">Auto-scan all cluster images</div>
          </div>
          <button type="button" className="modal-close" aria-label="Close" onClick={onClose}><Icon name="x" /></button>
        </div>

        <div className="item-card row row--between mb-16">
          <div>
            <div className="t-md t-medium t-primary">Scheduled scanning</div>
            <div className="t-xs t-muted mt-4">{form.enabled ? 'Active' : 'Disabled — scans only run manually'}</div>
          </div>
          <Switch checked={form.enabled} onChange={v => set('enabled', v)} label="Scheduled scanning" />
        </div>

        {form.enabled && <>
          <Field label="Frequency">
            <Seg value={form.frequency} onChange={v => set('frequency', v)} label="Frequency"
              options={[{ value: 'daily', label: 'Daily', icon: 'calendar' }, { value: 'weekly', label: 'Weekly', icon: 'calendar' }]} />
          </Field>

          {form.frequency === 'weekly' && (
            <Field label="Day of week">
              <Seg value={form.dayOfWeek} onChange={v => set('dayOfWeek', v)} label="Day of week"
                options={DAYS.map((d, i) => ({ value: i, label: d }))} />
            </Field>
          )}

          <Field label="Time (UTC)" htmlFor="scan-schedule-time">
            <input id="scan-schedule-time" type="time" className="input input--mono input--narrow"
              value={form.timeOfDay} onChange={e => set('timeOfDay', e.target.value)} />
          </Field>

          <Notice icon="clock" className="mb-0">
            <span className="t-muted">Next run: </span><span className="mono t-accent">{fmtNextRun()}</span>
          </Notice>
        </>}

        <div className="modal-footer">
          <button type="button" className="btn btn-outline" onClick={onClose}>Cancel</button>
          <button type="button" className="btn btn-primary" onClick={handleSave} disabled={saving}>
            {saving ? <><Icon name="loader" /> Saving…</> : <><Icon name="check" /> Save Schedule</>}
          </button>
        </div>
      </div>
    </div>
  );
}
