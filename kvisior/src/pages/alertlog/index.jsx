import { apiFetch } from '../../data/cluster';

import { useEffect, useRef, useState, useMemo } from 'react';
import { SevBadge } from '../../components/ui';
import { Icon } from '../../components/Icon';
import { DataWindow } from '../../components/DataWindow';
import { Pager } from '../../components/Pager';
import { usePaged } from '../../hooks/usePaged';
import { PageHeader, Seg, EmptyRow } from '../../components/kit';

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
        const r = await apiFetch(url, { credentials: 'same-origin' });
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
  const { pageItems, pager } = usePaged(filtered, 'alertlog', [detFilter]);

  const detTypes = useMemo(() => {
    const s = new Set(items.map(it => it.detType).filter(Boolean));
    return ['All', ...[...s].sort()];
  }, [items]);

  return (
    <div className="page active">
      <PageHeader
        title="Alert Log"
        subtitle={<>
          <span className="t-ok">{items.length}</span> recent · <span className="t-muted">polling backend every {POLL_EVERY / 1000}s</span>
          {error && <span className="t-danger"> · {error}</span>}
        </>}
        actions={<>
          <Seg label="Detection type" value={detFilter} onChange={setDetFilter} options={detTypes} />
          {items.length > 0 && (
            <button type="button" className="btn btn-outline btn-sm btn-tone-danger" title="Hide every alert from this view; nothing is deleted on the server"
              onClick={() => { if (confirm('Hide every alert from this view? Nothing is deleted on the server.')) clearAll(); }}>Clear view</button>
          )}
        </>}
      />

      <DataWindow label="Alert log" deps={[detFilter]} footer={<Pager {...pager} noun="alerts" />}>
        <table className="data-table data-table--static">
          <thead>
            <tr>
              <th>Time</th><th>Source</th><th>Type</th><th>Severity</th><th>Rule</th><th>Namespace / Target</th>
              <th>Syscall</th><th>User</th><th>Action</th>
              <th className="t-center" title="Delivered to an external webhook">Sent</th>
              <th aria-label="Hide" />
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <EmptyRow cols={11}>
                {items.length === 0
                  ? 'No alerts yet — waiting for rule matches (or set the Alert checkbox on a policy).'
                  : `No alerts matching "${detFilter}".`}
              </EmptyRow>
            ) : pageItems.map(a => (
              <tr key={a.id}>
                <td className="t-xs t-muted">{fmtTime(a.ts)}</td>
                <td className="t-sm">{SOURCE_LABEL[a.source] || a.source}</td>
                <td className="t-sm">{a.detType}</td>
                <td><SevBadge sev={(a.severity || '').toUpperCase() || 'LOW'} /></td>
                <td className="td-primary t-sm">{a.ruleName || a.ruleId || '—'}</td>
                <td className="t-sm"><span className="t-muted">{a.namespace || '—'}</span>{a.target && <> / <span>{a.target}</span></>}</td>
                <td className="mono t-xs t-accent">{a.syscall || '—'}</td>
                <td className="t-sm clip clip--md" title={a.user || ''}>{a.user || ''}</td>
                <td className="t-xs clip clip--lg" title={a.action ?? a.detail}>{(a.action ?? a.detail) || '—'}</td>
                <td className="t-center">
                  {a.deliveredAt
                    ? <span className="t-ok" title={a.deliveredAt}><Icon name="check" /></span>
                    : <span className="t-muted" title="Pending delivery">·</span>}
                </td>
                <td className="row-actions-cell">
                  <button type="button" className="btn-icon btn-icon--sm" title="Hide from this view" aria-label="Hide from this view" onClick={() => deleteItem(a.id)}>
                    <Icon name="x" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataWindow>
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
