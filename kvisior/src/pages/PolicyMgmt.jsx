import { useState, useMemo, useEffect, useCallback } from 'react';
import { useApp }    from '../context/AppContext';
import { useBridge } from '../context/BridgeContext';
import { SevBadge, Tabs } from '../components/ui';
import { SYSCALLS, saveRuntimeRules, fetchRulesFromAPI } from '../data/syscalls';
import { PolicyModal } from './policy/PolicyModal';
import { DataWindow } from '../components/DataWindow';
import { Icon } from '../components/Icon';
import { Pager } from '../components/Pager';
import { usePaged } from '../hooks/usePaged';

const TABS = [
  { id: 'policies', label: 'Policies'       },
  { id: 'catalog',  label: 'Syscall Catalog' },
  { id: 'live',     label: 'Live Hits'      },
];

export function PolicyMgmt() {
  const { toast, showModal, closeModal } = useApp();
  const { ruleHits, auditHits, violations, rulesVersion } = useBridge();

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
    const runtime = new Set(rules.filter(r => r.enabled !== false &&
      r.detType !== 'Audit' && r.detType !== 'Build' && r.detType !== 'Deploy').map(r => r.id));
    return violations.filter(v => runtime.has(v._ruleId)).slice(-1000).reverse();
  }, [violations, rules]);

  const filtered = rules.filter(p =>
    !search || p.name.toLowerCase().includes(search.toLowerCase()) || (p.syscall || '').toLowerCase().includes(search.toLowerCase())
  );
  const policyPage = usePaged(filtered, 'policies', [search]);
  const syscallPage = usePaged(SYSCALLS, 'policies.syscalls');
  const hitsPage = usePaged(liveHits, 'policies.hits');

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
            <button className="btn btn-outline btn-tone-danger"
              onClick={() => { if (window.confirm('Delete all custom policies?')) deleteAll(); }}>
              <Icon name="trash" /> Delete all
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
        <DataWindow label="Policies" deps={[tab]} footer={<Pager {...policyPage.pager} noun="policies" />}>
            <table className="data-table">
              <thead><tr><th>Policy</th><th>Status</th><th>Origin</th><th>Severity</th><th>Match</th><th>Hits</th><th>Alert</th><th></th></tr></thead>
              <tbody>
                {policyPage.pageItems.map(p => (
                  <tr key={p.id} style={{ opacity: p.enabled === false ? .5 : 1 }}>
                    <td className="td-primary">{p.name}</td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12,
                        color: p.enabled !== false ? 'var(--accent-3)' : 'var(--text-muted)' }}>
                        {p.enabled !== false ? <Icon name="check" /> : '—'}
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
                        ? <Icon name="check" style={{ color: 'var(--accent)' }} />
                        : <span style={{ fontSize: 13, color: 'var(--text-muted)', opacity: 0.3 }}>—</span>}
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn btn-outline btn-sm" onClick={e => { e.stopPropagation(); openEdit(p); }} title="Edit"><Icon name="edit" /></button>
                        <button className={`btn btn-outline btn-sm ${p.enabled !== false ? 'btn-tone-warning' : 'btn-tone-ok'}`}
                          onClick={e => { e.stopPropagation(); toggleRule(p.id); }}
                          title={p.enabled !== false ? 'Stop rule' : 'Run rule'}>
                          {p.enabled !== false ? 'Stop' : 'Run'}
                        </button>
                        <button className="btn btn-outline btn-sm btn-tone-danger" onClick={e => { e.stopPropagation(); deleteRule(p.id); }} title="Delete"><Icon name="trash" /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
        </DataWindow>
      </>}

      {tab === 'catalog' && (
        <DataWindow label="Syscall catalog" deps={[tab]} footer={<Pager {...syscallPage.pager} noun="syscalls" />}>
            <table className="data-table">
              <thead><tr><th>Syscall</th><th>Category</th><th>Severity</th><th>Description</th><th>Live Events</th></tr></thead>
              <tbody>
                {syscallPage.pageItems.map(s => (
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
        </DataWindow>
      )}

      {tab === 'live' && (
        <>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 2px 10px' }}>
            <div className="card-title">Live Rule Hits</div>
            <span className="live-dot">Live</span>
          </div>
          <DataWindow label="Live rule hits" deps={[tab]} footer={<Pager {...hitsPage.pager} noun="hits" />}>
            <table className="data-table">
              <thead><tr><th>Syscall</th><th>Rule</th><th>Severity</th><th>Process</th><th>Pod</th><th>Namespace</th><th>Time</th></tr></thead>
              <tbody>
                {liveHits.length === 0
                  ? <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>No rule hits yet — waiting for events</td></tr>
                  : hitsPage.pageItems.map((e, i) => (
                      <tr key={e._fp || i}>
                        <td className="td-primary" style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 12 }}>{e.syscall || e.name || '—'}</td>
                        <td style={{ fontSize: 12 }}>{e._ruleName || '—'}</td>
                        <td><SevBadge sev={(e.sev || e.severity || '').toUpperCase()} /></td>
                        <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, color: 'var(--text-secondary)' }}>{e.process || e._raw?.process || '—'}</td>
                        <td style={{ fontSize: 12 }}>{e.pod || '—'}</td>
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{e.namespace || '—'}</td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{e.ts ? new Date(e.ts).toLocaleTimeString() : '—'}</td>
                      </tr>
                    ))
                }
              </tbody>
            </table>
          </DataWindow>
        </>
      )}
    </div>
  );
}
