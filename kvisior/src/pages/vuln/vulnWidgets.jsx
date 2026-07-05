import { useState } from 'react';

function CvePills({ c = 0, h = 0, m = 0, l = 0 }) {
  const items = [
    [c, 'rgba(239,68,68,.15)',   'var(--danger)',    'C'],
    [h, 'rgba(245,158,11,.12)', 'var(--warning)',   'H'],
    [m, 'rgba(99,102,241,.10)', '#a78bfa',          'M'],
    [l, 'rgba(255,255,255,.05)', 'var(--text-muted)', 'L'],
  ].filter(([v]) => v > 0);
  if (!items.length) return <span style={{ color: 'var(--accent-3)', fontSize: 11 }}>Clean</span>;
  return (
    <div style={{ display: 'flex', gap: 3 }}>
      {items.map(([v, bg, color, lbl]) => (
        <span key={lbl} style={{ fontSize: 11, background: bg, color, padding: '2px 6px', borderRadius: 4, fontFamily: 'JetBrains Mono,monospace' }}>
          {lbl}:{v}
        </span>
      ))}
    </div>
  );
}

const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

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
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.6)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 12, padding: 28, width: 420, maxWidth: '95vw', boxShadow: '0 20px 60px rgba(0,0,0,.5)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>⏱ Scan Schedule</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Auto-scan all cluster images</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 18, padding: '2px 6px' }}>✕</button>
        </div>

        {}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 14px', background: 'var(--bg-card)', borderRadius: 8, border: '1px solid var(--border)', marginBottom: 16 }}>
          <div>
            <div style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>Scheduled scanning</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{form.enabled ? 'Active' : 'Disabled — scans only run manually'}</div>
          </div>
          <div onClick={() => set('enabled', !form.enabled)}
            style={{ width: 44, height: 24, borderRadius: 12, cursor: 'pointer', transition: 'background .2s', background: form.enabled ? 'var(--accent)' : 'rgba(255,255,255,.1)', position: 'relative', flexShrink: 0 }}>
            <div style={{ position: 'absolute', top: 3, width: 18, height: 18, borderRadius: '50%', background: '#fff', transition: 'left .2s', left: form.enabled ? '23px' : '3px', boxShadow: '0 1px 3px rgba(0,0,0,.3)' }} />
          </div>
        </div>

        {form.enabled && <>
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.06em', color: 'var(--text-muted)', marginBottom: 8 }}>Frequency</div>
            <div style={{ display: 'flex', gap: 8 }}>
              {['daily', 'weekly'].map(f => (
                <button key={f} onClick={() => set('frequency', f)}
                  style={{ flex: 1, padding: '9px 0', borderRadius: 8, cursor: 'pointer', fontSize: 13, fontWeight: form.frequency === f ? 600 : 400,
                    background: form.frequency === f ? 'var(--accent)' : 'var(--bg-card)',
                    border: `1px solid ${form.frequency === f ? 'var(--accent)' : 'var(--border)'}`,
                    color: form.frequency === f ? '#000' : 'var(--text-primary)', textTransform: 'capitalize', transition: 'all .15s' }}>
                  {f === 'daily' ? '📅 Daily' : '🗓 Weekly'}
                </button>
              ))}
            </div>
          </div>

          {form.frequency === 'weekly' && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.06em', color: 'var(--text-muted)', marginBottom: 8 }}>Day of Week</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7,1fr)', gap: 4 }}>
                {DAY_NAMES.map((d, i) => (
                  <button key={i} onClick={() => set('dayOfWeek', i)}
                    style={{ padding: '6px 2px', borderRadius: 6, cursor: 'pointer', fontSize: 10,
                      background: form.dayOfWeek === i ? 'var(--accent)' : 'var(--bg-card)',
                      border: `1px solid ${form.dayOfWeek === i ? 'var(--accent)' : 'var(--border)'}`,
                      color: form.dayOfWeek === i ? '#000' : 'var(--text-muted)', transition: 'all .15s' }}>
                    {d.slice(0, 3)}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.06em', color: 'var(--text-muted)', marginBottom: 8 }}>Time (UTC)</div>
            <input type="time" value={form.timeOfDay} onChange={e => set('timeOfDay', e.target.value)}
              style={{ width: '100%', padding: '9px 12px', borderRadius: 8, fontSize: 14, background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-primary)', outline: 'none', fontFamily: 'JetBrains Mono,monospace', boxSizing: 'border-box' }} />
          </div>

          <div style={{ marginBottom: 20, padding: '10px 12px', background: 'rgba(0,200,255,.06)', border: '1px solid rgba(0,200,255,.15)', borderRadius: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Next run: </span>
            <span style={{ fontSize: 11, color: 'var(--accent)', fontFamily: 'JetBrains Mono,monospace' }}>{fmtNextRun()}</span>
          </div>
        </>}

        <div style={{ display: 'flex', gap: 10 }}>
          <button onClick={onClose} style={{ flex: 1, padding: 10, borderRadius: 8, cursor: 'pointer', background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontSize: 13 }}>Cancel</button>
          <button onClick={handleSave} disabled={saving}
            style={{ flex: 2, padding: 10, borderRadius: 8, cursor: 'pointer', background: 'var(--accent)', border: 'none', color: '#000', fontSize: 13, fontWeight: 600, opacity: saving ? .7 : 1 }}>
            {saving ? 'Saving…' : '✓ Save Schedule'}
          </button>
        </div>
      </div>
    </div>
  );
}
