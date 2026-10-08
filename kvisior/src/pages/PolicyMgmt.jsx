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
import { PageHeader, SearchInput, EmptyRow, cx } from '../components/kit';

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
        <PageHeader title="Policy Management" />
        <div className="page-loading">Loading policies…</div>
      </div>
    );
  }

  const hitsOf = p => (p.detType === 'Audit' ? auditHits?.[p.id] : ruleHits?.[p.id]) || 0;

  return (
    <div className="page active" id="page-policies">
      <PageHeader
        title="Policy Management"
        subtitle={<><span className="t-ok">{rules.filter(r => r.enabled !== false).length}</span> active · <span className="t-muted">{rules.length}</span> total</>}
        actions={<>
          {rules.length > 0 && (
            <button type="button" className="btn btn-outline btn-tone-danger" onClick={() => { if (window.confirm('Delete all custom policies?')) deleteAll(); }}>
              <Icon name="trash" /> Delete all
            </button>
          )}
          <button type="button" className="btn btn-primary" onClick={openCreate}>+ Create policy</button>
        </>}
      />

      <Tabs tabs={TABS} active={tab} onSwitch={setTab} />

      {tab === 'policies' && <>
        <div className="toolbar">
          <SearchInput value={search} onChange={setSearch} placeholder="Search policies…" />
        </div>
        <DataWindow label="Policies" deps={[tab]} footer={<Pager {...policyPage.pager} noun="policies" />}>
          <table className="data-table data-table--static">
            <thead><tr><th>Policy</th><th>Status</th><th>Origin</th><th>Severity</th><th>Match</th><th>Hits</th><th className="t-center">Alert</th><th aria-label="Actions" /></tr></thead>
            <tbody>
              {policyPage.pageItems.map(p => {
                const on = p.enabled !== false;
                return (
                  <tr key={p.id} className={on ? undefined : 'is-off'}>
                    <td className="td-primary">{p.name}</td>
                    <td className={cx('t-xs', on ? 't-ok' : 't-muted')}>
                      <span className="ic-label">{on ? <Icon name="check" /> : '—'}{on ? 'Enabled' : 'Disabled'}</span>
                    </td>
                    <td className="t-sm t-muted">{p.origin || 'Custom'}</td>
                    <td><SevBadge sev={p.sev} /></td>
                    <td className="mono t-xs t-accent clip clip--md">
                      {p.detType === 'Binary' ? `$ ${p.processFilter}${p.pathFilter ? ' ' + p.pathFilter : ''}` : (p.syscall || '*')}
                    </td>
                    <td className={cx('mono t-sm', hitsOf(p) > 0 ? 't-ok' : 't-muted')}>
                      {p.detType === 'Audit' ? (auditHits?.[p.id] ?? 0) : p.detType === 'Build' || p.detType === 'Deploy' ? '—' : (ruleHits?.[p.id] ?? 0)}
                    </td>
                    <td className="t-center">{p.alertOnly ? <span className="t-accent"><Icon name="check" /></span> : <span className="t-muted">—</span>}</td>
                    <td className="row-actions-cell">
                      <span className="row-actions">
                        <button type="button" className="btn btn-outline btn-sm" onClick={() => openEdit(p)} title="Edit" aria-label={`Edit ${p.name}`}><Icon name="edit" /></button>
                        <button type="button" className={`btn btn-outline btn-sm ${on ? 'btn-tone-warning' : 'btn-tone-ok'}`} onClick={() => toggleRule(p.id)}
                          title={on ? 'Stop rule' : 'Run rule'}>{on ? 'Stop' : 'Run'}</button>
                        <button type="button" className="btn btn-outline btn-sm btn-tone-danger" onClick={() => deleteRule(p.id)} title="Delete" aria-label={`Delete ${p.name}`}><Icon name="trash" /></button>
                      </span>
                    </td>
                  </tr>
                );
              })}
              {filtered.length === 0 && <EmptyRow cols={8}>{rules.length === 0 ? 'No policies yet — create one to start detecting' : 'No policies match the search'}</EmptyRow>}
            </tbody>
          </table>
        </DataWindow>
      </>}

      {tab === 'catalog' && (
        <DataWindow label="Syscall catalog" deps={[tab]} footer={<Pager {...syscallPage.pager} noun="syscalls" />}>
          <table className="data-table data-table--static">
            <thead><tr><th>Syscall</th><th>Category</th><th>Severity</th><th>Description</th><th>Live Events</th></tr></thead>
            <tbody>
              {syscallPage.pageItems.map(s => {
                const hits = ruleHits?.[`sys-${s.name}`] ?? 0;
                return (
                  <tr key={s.name}>
                    <td className="td-primary mono t-sm">{s.name}</td>
                    <td className="t-sm t-muted">{s.cat}</td>
                    <td><SevBadge sev={s.sev?.toUpperCase()} /></td>
                    <td className="t-sm wrap desc-cell">{s.desc}</td>
                    <td className={cx('mono t-sm', hits > 0 ? 't-ok' : 't-muted')}>{hits}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </DataWindow>
      )}

      {tab === 'live' && (
        <>
          <div className="section-head">
            <div className="section-title">Live Rule Hits</div>
            <span className="live-dot">Live</span>
          </div>
          <DataWindow label="Live rule hits" deps={[tab]} footer={<Pager {...hitsPage.pager} noun="hits" />}>
            <table className="data-table data-table--static">
              <thead><tr><th>Syscall</th><th>Rule</th><th>Severity</th><th>Process</th><th>Pod</th><th>Namespace</th><th>Time</th></tr></thead>
              <tbody>
                {liveHits.length === 0
                  ? <EmptyRow cols={7}>No rule hits yet — waiting for events</EmptyRow>
                  : hitsPage.pageItems.map((e, i) => (
                      <tr key={e._fp || i}>
                        <td className="td-primary mono t-sm">{e.syscall || e.name || '—'}</td>
                        <td className="t-sm">{e._ruleName || '—'}</td>
                        <td><SevBadge sev={(e.sev || e.severity || '').toUpperCase()} /></td>
                        <td className="mono t-xs">{e.process || e._raw?.process || '—'}</td>
                        <td className="t-sm">{e.pod || '—'}</td>
                        <td className="t-sm t-muted">{e.namespace || '—'}</td>
                        <td className="t-xs t-muted">{e.ts ? new Date(e.ts).toLocaleTimeString() : '—'}</td>
                      </tr>
                    ))}
              </tbody>
            </table>
          </DataWindow>
        </>
      )}
    </div>
  );
}
