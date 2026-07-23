
import { useEffect, useRef, useState, useMemo } from 'react';
import { SevBadge } from '../../components/ui';

const MAX_KEEP   = 5000;
const POLL_EVERY = 5000;

const SOURCE_LABEL = {
  'tracee-bridge':    'Runtime',
  'sentry-audit':     'Audit',
  'scanner-agent':    'Build',
  'sensor':           'Deploy',
  'anomaly-detector': 'Anomaly',
};

export function AlertLog() {
  const [items, setItems] = useState([]);
  const [error, setError] = useState(null);
  const [detFilter, setDetFilter] = useState('All');
  const lastIdRef = useRef('0');
  const aliveRef  = useRef(true);

  const clearAll = () => {
    setItems([]);
    lastIdRef.current = '0';
  };

  const deleteItem = (id) => setItems(prev => prev.filter(a => a.id !== id));

  useEffect(() => {
    aliveRef.current = true;
    const poll = async () => {
      try {
        const url = `/api/alerts?since=${encodeURIComponent(lastIdRef.current)}&limit=200`;
        const r = await fetch(url, { credentials: 'same-origin' });
        if (!r.ok) {
          if (r.status !== 503) setError(`HTTP ${r.status}`);
          return;
        }
        setError(null);
        const data = await r.json();
        const fresh = Array.isArray(data.alerts) ? data.alerts : [];
        if (fresh.length === 0) return;
        if (data.lastId) {
          lastIdRef.current = data.lastId;
        } else {
          const cmp = (a, b) => {
            const na = Number(a), nb = Number(b);
            if (Number.isFinite(na) && Number.isFinite(nb)) return na - nb;
            return a > b ? 1 : a < b ? -1 : 0;
          };
          const maxId = fresh.reduce((m, a) => {
            const id = a.id != null ? String(a.id) : null;
            return id && cmp(id, m) > 0 ? id : m;
          }, lastIdRef.current);
          lastIdRef.current = maxId;
        }
        if (!aliveRef.current) return;
        setItems(prev => {
          const byId = new Map(prev.map(a => [a.id ?? a.ts, a]));
          for (const a of fresh) byId.set(a.id ?? a.ts, a);
          const merged = [...byId.values()].sort((a, b) => new Date(b.ts) - new Date(a.ts));
          return merged.length > MAX_KEEP ? merged.slice(0, MAX_KEEP) : merged;
        });
      } catch (e) {
        setError(e.message || String(e));
      }
    };
    poll();
    const t = setInterval(poll, POLL_EVERY);
    return () => { aliveRef.current = false; clearInterval(t); };
  }, []);

  const filtered = useMemo(() => {
    if (detFilter === 'All') return items;
    return items.filter(it => it.detType === detFilter);
  }, [items, detFilter]);

  const detTypes = useMemo(() => {
    const s = new Set(items.map(it => it.detType).filter(Boolean));
    return ['All', ...[...s].sort()];
  }, [items]);

  return (
    <div className="page active">
      <div className="page-header">
        <div>
          <div className="page-title">Alert Log</div>
          <div className="page-subtitle">
            <span style={{ color: 'var(--accent-3)' }}>{items.length}</span> recent ·
            {' '}<span style={{ color: 'var(--text-muted)' }}>polling backend every {POLL_EVERY / 1000}s</span>
            {error && <span style={{ color: 'var(--danger)', marginLeft: 12 }}>· {error}</span>}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          {detTypes.map(t => (
            <button key={t}
              className={`btn ${detFilter === t ? 'btn-primary' : 'btn-outline'}`}
              style={{ padding: '4px 10px', fontSize: 11 }}
              onClick={() => setDetFilter(t)}>{t}</button>
          ))}
          {items.length > 0 && (
            <button
              className="btn btn-outline"
              style={{ padding: '4px 10px', fontSize: 11, color: 'var(--danger)', borderColor: 'var(--danger)', marginLeft: 8 }}
              onClick={() => { if (confirm('Очистить весь журнал алертов?')) clearAll(); }}
            >Clear all</button>
          )}
        </div>
      </div>

      <div className="card">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Rule</th>
                <th>Namespace / Target</th>
                <th>Syscall</th>
                <th>Detail</th>
                <th style={{ textAlign: 'center' }} title="Delivered to an external webhook">Sent</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>
                    {items.length === 0
                      ? 'No alerts yet — waiting for rule matches (or set the Alert checkbox on a policy).'
                      : `No alerts matching "${detFilter}".`}
                  </td>
                </tr>
              ) : filtered.map(a => (
                <tr key={a.id}>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {fmtTime(a.ts)}
                  </td>
                  <td style={{ fontSize: 12 }}>{SOURCE_LABEL[a.source] || a.source}</td>
                  <td style={{ fontSize: 12 }}>{a.detType}</td>
                  <td><SevBadge sev={(a.severity || '').toUpperCase() || 'LOW'} /></td>
                  <td className="td-primary" style={{ fontSize: 12 }}>{a.ruleName || a.ruleId || '—'}</td>
                  <td style={{ fontSize: 12 }}>
                    <span style={{ color: 'var(--text-muted)' }}>{a.namespace || '—'}</span>
                    {a.target && <> / <span>{a.target}</span></>}
                  </td>
                  <td style={{ fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: 'var(--accent)' }}>
                    {a.syscall || '—'}
                  </td>
                  <td style={{ fontSize: 11, color: 'var(--text-secondary)', maxWidth: 320,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                      title={a.detail}>
                    {a.detail || '—'}
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    {a.deliveredAt
                      ? <span style={{ color: 'var(--accent-3)', fontSize: 13 }} title={a.deliveredAt}>✓</span>
                      : <span style={{ color: 'var(--text-muted)', fontSize: 13, opacity: 0.3 }} title="Pending delivery">·</span>}
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <button
                      title="Удалить"
                      onClick={() => deleteItem(a.id)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 13, padding: '0 4px', lineHeight: 1 }}
                    >✕</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function fmtTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
