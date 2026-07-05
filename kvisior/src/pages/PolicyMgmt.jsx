import { useState, useMemo, useEffect, useCallback } from 'react';
import { useApp }    from '../context/AppContext';
import { useBridge } from '../context/BridgeContext';
import { SevBadge, Tabs } from '../components/ui';
import { SYSCALLS, matchesRule, saveRuntimeRules, fetchRulesFromAPI } from '../data/syscalls';
import { PolicyModal } from './policy/PolicyModal';

const TABS = [
  { id: 'policies', label: 'Policies'       },
  { id: 'catalog',  label: 'Syscall Catalog' },
  { id: 'live',     label: 'Live Hits'      },
];

export function PolicyMgmt() {
  const { toast, showModal, closeModal } = useApp();
  const { ruleHits, auditHits, events, rulesVersion } = useBridge();

  const [rules,   setRules]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab,     setTab]     = useState('policies');
  const [search,  setSearch]  = useState('');

  useEffect(() => {
    let alive = true;
    const load = async () => {
      const r = await fetchRulesFromAPI();
      if (!alive) return;
      if (r !== null) {
        setRules(r);
        setLoading(false);
      } else {
        setTimeout(load, 3000);
      }
    };
    load();
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    const h = (ev) => toast('error', 'Policy save failed', ev.detail?.error || 'backend unreachable — change was rolled back');
    window.addEventListener('sw-rules-save-failed', h);
    return () => window.removeEventListener('sw-rules-save-failed', h);
  }, [toast]);

  const persist = useCallback((computeNext) => {
    let prev, next;
    setRules(p => { prev = p; next = computeNext(p); return next; });
    Promise.resolve().then(() =>
      saveRuntimeRules(next).then(ok => { if (!ok) setRules(prev); })
    );
  }, []);

  const addOrUpdate = useCallback((rule) => {
    const isEdit = rules.some(r => r.id === rule.id);
    persist(prev => {
      const idx = prev.findIndex(r => r.id === rule.id);
      return idx >= 0 ? prev.map((r, i) => i === idx ? rule : r) : [...prev, rule];
    });
    toast('success', isEdit ? 'Policy updated' : 'Policy created', rule.name);
  }, [rules, persist, toast]);

  const deleteRule = useCallback((id) => {
    persist(prev => prev.filter(r => r.id !== id));
    toast('warn', 'Policy deleted', '');
  }, [persist, toast]);

  const toggleRule = useCallback((id) => {
    persist(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  }, [persist]);

  const toggleAlert = useCallback((id) => {
    persist(prev => prev.map(r => r.id === id ? { ...r, alertOnly: !r.alertOnly } : r));
  }, [persist]);

  const deleteAll = useCallback(() => {
    persist(() => []);
    toast('warn', 'All policies deleted', '');
  }, [persist, toast]);

  const openCreate = () => showModal(<PolicyModal onSave={addOrUpdate} onClose={closeModal} />);
  const openEdit   = (rule) => showModal(<PolicyModal initial={rule} onSave={addOrUpdate} onClose={closeModal} />);

  const liveHits = useMemo(() => {
    if (!events.length) return [];
    const syscallRules = rules.filter(r => r.enabled !== false &&
      r.detType !== 'Audit' && r.detType !== 'Build' && r.detType !== 'Deploy');
    return events.filter(e => syscallRules.some(r => matchesRule(e._raw || e, r))).slice(-100).reverse();
  }, [events, rules]);

  const filtered = rules.filter(p =>
    !search || p.name.toLowerCase().includes(search.toLowerCase()) || (p.syscall || '').toLowerCase().includes(search.toLowerCase())
  );

  if (loading) {
    return (
      <div className="page active" id="page-policies">
        <div className="page-header">
          <div className="page-title">Policy Management</div>
        </div>
        <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 14 }}>
          Loading policies…
        </div>
      </div>
    );
  }

  return (
    <div className="page active" id="page-policies">
      <div className="page-header">
        <div>
          <div className="page-title">Policy Management</div>
          <div className="page-subtitle">
            <span style={{ color: 'var(--accent-3)' }}>{rules.filter(r => r.enabled !== false).length}</span> active ·{' '}
            <span style={{ color: 'var(--text-muted)' }}>{rules.length}</span> total
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {rules.length > 0 && (
            <button className="btn btn-outline" style={{ fontSize: 12, color: 'var(--danger)', borderColor: 'rgba(239,68,68,.3)' }}
              onClick={() => { if (window.confirm('Delete all custom policies?')) deleteAll(); }}>
              🗑 Delete all
            </button>
          )}
          <button className="btn btn-primary" onClick={openCreate}>+ Create policy</button>
        </div>
      </div>

      <Tabs tabs={TABS} active={tab} onSwitch={setTab} />

      {tab === 'policies' && <>
        <div className="page-search">
          <input type="text" placeholder="Search policies…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <div className="card">
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Policy</th><th>Status</th><th>Origin</th><th>Severity</th><th>Match</th><th>Hits</th><th>Alert</th><th></th></tr></thead>
              <tbody>
                {filtered.map(p => (
                  <tr key={p.id} style={{ opacity: p.enabled === false ? .5 : 1 }}>
                    <td className="td-primary">{p.name}</td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12,
                        color: p.enabled !== false ? 'var(--accent-3)' : 'var(--text-muted)' }}>
                        {p.enabled !== false ? '✓' : '—'}
                        <span style={{ fontSize: 11 }}>{p.enabled !== false ? 'Enabled' : 'Disabled'}</span>
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{p.origin || 'Custom'}</td>
                    <td><SevBadge sev={p.sev} /></td>
                    <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, color: 'var(--accent)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {p.detType === 'Binary' ? `$ ${p.processFilter}${p.pathFilter ? ' ' + p.pathFilter : ''}` : (p.syscall || '*')}
                    </td>
                    <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 12, color: (p.detType === 'Audit' ? auditHits?.[p.id] : ruleHits?.[p.id]) > 0 ? 'var(--accent-3)' : 'var(--text-muted)' }}>
                      {p.detType === 'Audit' ? (auditHits?.[p.id] ?? 0) : p.detType === 'Build' || p.detType === 'Deploy' ? '—' : (ruleHits?.[p.id] ?? 0)}
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      {p.alertOnly
                        ? <span style={{ fontSize: 13, color: 'var(--accent)' }}>✓</span>
                        : <span style={{ fontSize: 13, color: 'var(--text-muted)', opacity: 0.3 }}>—</span>}
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn btn-outline" style={{ padding: '3px 8px', fontSize: 11 }} onClick={e => { e.stopPropagation(); openEdit(p); }}>✏️</button>
                        <button className="btn btn-outline"
                          style={{ padding: '3px 10px', fontSize: 11,
                            color: p.enabled !== false ? 'var(--warning)' : 'var(--accent-3)',
                            borderColor: p.enabled !== false ? 'rgba(245,158,11,.35)' : 'rgba(52,211,153,.35)' }}
                          onClick={e => { e.stopPropagation(); toggleRule(p.id); }}
                          title={p.enabled !== false ? 'Stop rule' : 'Run rule'}>
                          {p.enabled !== false ? 'Stop' : 'Run'}
                        </button>
                        <button className="btn btn-outline" style={{ padding: '3px 8px', fontSize: 11, color: 'var(--danger)', borderColor: 'rgba(239,68,68,.3)' }} onClick={e => { e.stopPropagation(); deleteRule(p.id); }}>🗑</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </>}

      {tab === 'catalog' && (
        <div className="card">
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Syscall</th><th>Category</th><th>Severity</th><th>Description</th><th>Live Events</th></tr></thead>
              <tbody>
                {SYSCALLS.map(s => (
                  <tr key={s.name}>
                    <td className="td-primary" style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 12 }}>{s.name}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{s.cat}</td>
                    <td><SevBadge sev={s.sev?.toUpperCase()} /></td>
                    <td style={{ fontSize: 12, maxWidth: 300, whiteSpace: 'normal' }}>{s.desc}</td>
                    <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 12, color: (ruleHits?.[`sys-${s.name}`] || 0) > 0 ? 'var(--accent-3)' : 'var(--text-muted)' }}>
                      {ruleHits?.[`sys-${s.name}`] ?? 0}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'live' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Live Rule Hits</div>
            <span className="live-dot">Live</span>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Syscall</th><th>Severity</th><th>Process</th><th>Pod</th><th>Namespace</th><th>Time</th></tr></thead>
              <tbody>
                {liveHits.length === 0
                  ? <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>No rule hits yet — waiting for events</td></tr>
                  : liveHits.map((e, i) => (
                      <tr key={i}>
                        <td className="td-primary" style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 12 }}>{e.syscall || e.name || '—'}</td>
                        <td><SevBadge sev={(e.severity || '').toUpperCase()} /></td>
                        <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, color: 'var(--text-secondary)' }}>{e.process || e._raw?.process || '—'}</td>
                        <td style={{ fontSize: 12 }}>{e.pod || '—'}</td>
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{e.namespace || '—'}</td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{e.ts ? new Date(e.ts).toLocaleTimeString() : '—'}</td>
                      </tr>
                    ))
                }
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
