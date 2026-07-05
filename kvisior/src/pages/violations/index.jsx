import { useState, useMemo, useEffect, useRef } from 'react';
import { useNavigate }  from 'react-router-dom';
import { useBridge }   from '../../context/BridgeContext';
import { usePerms }    from '../../context/PermissionsContext';
import { useScanner }  from '../../context/ScannerContext';
import { useSensor }   from '../../context/SensorContext';
import { SevBadge }    from '../../components/ui';
import { CheckboxDD }  from '../../components/CheckboxDD';
import { SyscallDetail } from './SyscallDetail';
import { BuildDetail }   from './BuildDetail';
import { DeployDetail }  from './DeployDetail';
import { AuditDetail }   from './AuditDetail';
import { evalBuildViolations, evalDeployViolations } from './evaluators';

import { OUTER_TABS, RUNTIME_TABS, KIND_COLOR, ackKey, fpKey } from './violationsConstants';
import { Pagination } from './Pagination';
import { SilentFpButtons } from './SilentFpButtons';
import { SilencedPanel } from './SilencedPanel';
import { LSM_NAMES } from '../lsm/lsmCatalog';
import { TRACEPOINT_NAMES } from '../tracepoints/tracepointsCatalog';

const LSM_SET = new Set(LSM_NAMES);
const TP_SET  = new Set(TRACEPOINT_NAMES);

export function Violations() {
  const { violations, auditViolations, connected, getMatchedRules, rulesVersion, removeViolation, removeAuditViolation } = useBridge();
  const { clusterImages, histories } = useScanner();
  const { workloads, snapshot } = useSensor();
  const { isAdmin } = usePerms();
  const navigate = useNavigate();

  const [outerTab,     setOuterTab]     = useState('Syscalls');
  const [selected,     setSelected]     = useState(null);
  const [search,       setSearch]       = useState('');
  const [sevChecked,   setSevChecked]   = useState(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
  const [sortDir,      setSortDir]      = useState('desc');
  const [sortCol,      setSortCol]      = useState('time');
  const [showSilenced, setShowSilenced] = useState(false);
  const [pageSize,     setPageSize]     = useState(40);
  const [page,         setPage2]        = useState(1);

  const [silenced, setSilenced] = useState(new Map());

  const [suppressedRows, setSuppressedRows] = useState(new Map());
  const dismissedFps = useMemo(() => {
    const s = new Set();
    for (const [fp, e] of suppressedRows) if (e.state === 'DISMISSED') s.add(fp);
    return s;
  }, [suppressedRows]);

  const loadCategoryAcks = () => {
    fetch('/api/acks', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!Array.isArray(data?.items)) return;
        const m = new Map();
        const now = Date.now();
        for (const { key, type, expiresAt } of data.items) {
          if (type !== 'silent') continue;
          if (expiresAt !== null && expiresAt !== undefined && expiresAt <= now) continue;
          m.set(key, { type, expiresAt: expiresAt ?? null });
        }
        setSilenced(m);
      })
      .catch(() => {});
  };
  const loadSuppressedRows = () => {
    fetch('/v1/violations?state=suppressed&limit=1000', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        const sup = new Map();
        for (const row of data?.violations || []) {
          if (!row.fingerprint) continue;
          sup.set(row.fingerprint, {
            state:     row.state,
            expiresAt: row.stateExpiresAt ? Date.parse(row.stateExpiresAt) : null,
            row,
          });
        }
        setSuppressedRows(sup);
      })
      .catch(() => {});
  };
  useEffect(() => {
    const refresh = () => { loadCategoryAcks(); loadSuppressedRows(); };
    refresh();
    const onFocus = () => { if (!document.hidden) refresh(); };
    document.addEventListener('visibilitychange', onFocus);
    const id = setInterval(refresh, 60_000);
    return () => { clearInterval(id); document.removeEventListener('visibilitychange', onFocus); };
  }, []);

  useEffect(() => { setPage2(1); }, [outerTab, search, sevChecked, sortDir, sortCol]);

  const postState = (fp, state) =>
    fetch(`/v1/violations?fp=${encodeURIComponent(fp)}&state=${state}`,
      { method: 'POST', credentials: 'same-origin' });

  const doSilent = (v, tab) => {
    const key = ackKey(v, tab);
    const expiresAt = Date.now() + 60 * 24 * 3600 * 1000;
    setSilenced(prev => new Map([...prev, [key, { type: 'silent', expiresAt }]]));
    fetch('/api/acks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ key, type: 'silent', expiresAt }),
    }).catch(() => {});
    if (selected === v) setSelected(null);
  };

  const doFp = (v, tab) => {
    const fp = v._fp || fpKey(v, tab);
    if (!fp) return;
    const expiresAt = Date.now() + 7 * 24 * 3600 * 1000;
    setSuppressedRows(prev => new Map(prev).set(fp, {
      state: 'FP', expiresAt, row: { ...v, vtype: tab.toLowerCase(), fingerprint: fp },
    }));
    postState(fp, 'FP').catch(() => {});
    if (selected === v) setSelected(null);
  };

  const dismiss = (v, tab) => {
    const fp = v._fp || fpKey(v, tab);
    if (selected === v) setSelected(null);
    if (RUNTIME_TABS.includes(tab) && fp) removeViolation(fp);
    if (tab === 'Audit'             && fp) removeAuditViolation(fp);
    if (fp) {
      const expiresAt = Date.now() + 25 * 3600 * 1000;
      setSuppressedRows(prev => new Map(prev).set(fp, {
        state: 'DISMISSED', expiresAt,
        row: { ...v, vtype: tab.toLowerCase(), fingerprint: fp },
      }));
      fetch(`/v1/violations?fp=${encodeURIComponent(fp)}`,
        { method: 'DELETE', credentials: 'same-origin' }).catch(() => {});
    }
  };
  const doResolve = dismiss;

  const doUnsilent = (key) => {
    setSilenced(prev => { const m = new Map(prev); m.delete(key); return m; });
    setSuppressedRows(prev => { const m = new Map(prev); m.delete(key); return m; });
    const isCategoryKey = /^(sc|tp|lsm|bld|dep|aud)::/.test(key);
    if (isCategoryKey) {
      fetch(`/api/acks?key=${encodeURIComponent(key)}`, { method: 'DELETE', credentials: 'same-origin' }).catch(() => {});
    } else {
      postState(key, 'ACTIVE').catch(() => {});
    }
  };

  const isSilenced = (v, tab) => {
    const entry = silenced.get(ackKey(v, tab));
    if (entry?.type !== 'silent') return false;
    return entry.expiresAt === null || entry.expiresAt > Date.now();
  };

  const isFp = (v) => {
    const entry = suppressedRows.get(v._fp);
    return entry?.state === 'FP' || entry?.state === 'ACK';
  };
  const isDismissed = (v) => dismissedFps.has(v._fp);

  const recordedRef = useRef(new Set());
  const recordBuildDeploy = (v, tab) => {
    if (!isAdmin) return;
    if (!v._fp || recordedRef.current.has(v._fp)) return;
    if (recordedRef.current.size > 5_000) recordedRef.current.clear();
    recordedRef.current.add(v._fp);
    const vtype = tab === 'Build' ? 'build' : 'deploy';
    fetch('/v1/violations/record', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        vtype,
        ruleId:   v._policyId || '',
        ruleName: v.policy    || '',
        sev:      v.sev       || '',
        ns:       v.ns || v.namespace || '',
        pod:      v.image || v.workload || '',
        fingerprint: v._fp,
        data: v,
      }),
    }).catch(() => {});
  };

  const [apiRules, setApiRules] = useState([]);
  const [rulesLoaded, setRulesLoaded] = useState(false);
  useEffect(() => {
    fetch('/api/policies', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (Array.isArray(data?.policies)) setApiRules(data.policies); })
      .catch(() => {})
      .finally(() => setRulesLoaded(true));
  }, [rulesVersion]);

  const buildRules  = useMemo(() => apiRules.filter(r => r.enabled !== false && r.detType === 'Build'),  [apiRules]);
  const deployRules = useMemo(() => apiRules.filter(r => r.enabled !== false && r.detType === 'Deploy'), [apiRules]);

  const syscallViolations = violations;

  const ruleDetType = useMemo(() => {
    const m = new Map();
    for (const r of apiRules) m.set(r.id, r.detType || 'Syscall');
    return m;
  }, [apiRules]);

  const byFamily = useMemo(() => {
    const m = { 'Syscalls': [], 'Tracepoints': [], 'LSM Hooks': [] };
    for (const v of violations) {
      const dt = ruleDetType.get(v._ruleId);
      const fam =
        dt === 'LSM'        ? 'LSM Hooks'   :
        dt === 'Tracepoint' ? 'Tracepoints' :
        dt                  ? 'Syscalls'    :
        LSM_SET.has(v.syscall) ? 'LSM Hooks' :
        TP_SET.has(v.syscall)  ? 'Tracepoints' : 'Syscalls';
      m[fam].push(v);
    }
    return m;
  }, [violations, ruleDetType]);
  const buildViolations   = useMemo(() => evalBuildViolations(buildRules, clusterImages, histories),  [buildRules, clusterImages, histories]);
  const deployViolations  = useMemo(() => evalDeployViolations(deployRules, workloads, snapshot), [deployRules, workloads, snapshot]);

  useEffect(() => {
    for (const v of buildViolations)  recordBuildDeploy(v, 'Build');
    for (const v of deployViolations) recordBuildDeploy(v, 'Deploy');
  }, [buildViolations, deployViolations]);

  const q = search.toLowerCase();
  const bySev = v => sevChecked.includes(v.sev);

  const sevRank = (s) => ({ critical: 4, high: 3, medium: 2, low: 1 }[String(s || '').toLowerCase()] ?? 0);
  const toggleSort = (col) => {
    if (col === sortCol) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir(col === 'time' ? 'desc' : 'asc'); }
  };
  const sortRows = (rows, cols, timeOf) => {
    const col = sortCol === 'time' ? null : cols.find(c => c.key === sortCol);
    const get = col ? col.val : timeOf;
    return [...rows].sort((a, b) => {
      const va = get(a), vb = get(b);
      const cmp = (typeof va === 'number' && typeof vb === 'number') ? va - vb : String(va).localeCompare(String(vb));
      return sortDir === 'asc' ? cmp : -cmp;
    });
  };
  const sortTh = (col) => (
    <th key={col.key} onClick={() => toggleSort(col.key)}
      style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }}>
      {col.label}{sortCol === col.key ? (sortDir === 'asc' ? ' ↑' : ' ↓') : ''}
    </th>
  );
  const buildDeployTimeOf = v => v._detectedAt || 0;
  const auditTimeOf = v => v.timestamp ? new Date(v.timestamp).getTime() : 0;
  const buildCols = [
    { key: 'policy', label: 'Policy',   val: v => v.policy || '' },
    { key: 'sev',    label: 'Severity', val: v => sevRank(v.sev) },
    { key: 'image',  label: 'Image',    val: v => v.image || '' },
    { key: 'detail', label: 'Detail',   val: v => v.detail || '' },
    { key: 'action', label: 'Action',   val: v => v.action || 'alert' },
  ];
  const deployCols = [
    { key: 'policy',   label: 'Policy',    val: v => v.policy || '' },
    { key: 'sev',      label: 'Severity',  val: v => sevRank(v.sev) },
    { key: 'workload', label: 'Workload',  val: v => v.workload || '' },
    { key: 'kind',     label: 'Kind',      val: v => v.kind || '' },
    { key: 'ns',       label: 'Namespace', val: v => v.ns || '' },
    { key: 'detail',   label: 'Detail',    val: v => v.detail || '' },
    { key: 'action',   label: 'Action',    val: v => v.action || 'alert' },
  ];
  const auditCols = [
    { key: 'time',     label: 'Time',      val: auditTimeOf },
    { key: 'policy',   label: 'Policy',    val: v => v.policy || '' },
    { key: 'sev',      label: 'Severity',  val: v => sevRank(v.sev) },
    { key: 'kind',     label: 'Action',    val: v => v.kind || '' },
    { key: 'resource', label: 'Resource',  val: v => v.resource || '' },
    { key: 'name',     label: 'Name',      val: v => v.name || '' },
    { key: 'ns',       label: 'Namespace', val: v => v.ns || '' },
    { key: 'user',     label: 'User',      val: v => v.user || '' },
  ];

  const sortByTime = (arr, getTime) =>
    [...arr].sort((a, b) => {
      const ta = getTime(a) || 0, tb = getTime(b) || 0;
      return sortDir === 'desc' ? tb - ta : ta - tb;
    });

  const filterRuntime = (list, tab) => sortByTime(
    list.filter(v =>
      !isSilenced(v,tab) && !isFp(v) && bySev(v) &&
      (!q || (v.syscall||'').toLowerCase().includes(q) || (v.pod||'').toLowerCase().includes(q)
        || (v.namespace||'').toLowerCase().includes(q) || (v.process||'').toLowerCase().includes(q))),
    v => v.ts ? new Date(v.ts).getTime() : (v._detectedAt || 0)
  );

  const filteredSyscalls = useMemo(() => filterRuntime(byFamily['Syscalls'], 'Syscalls'),
    [byFamily, sevChecked, q, sortDir, silenced, suppressedRows]);
  const filteredTracepoints = useMemo(() => filterRuntime(byFamily['Tracepoints'], 'Tracepoints'),
    [byFamily, sevChecked, q, sortDir, silenced, suppressedRows]);
  const filteredLsm = useMemo(() => filterRuntime(byFamily['LSM Hooks'], 'LSM Hooks'),
    [byFamily, sevChecked, q, sortDir, silenced, suppressedRows]);

  const filteredBuild = useMemo(() => sortByTime(
    buildViolations.filter(v =>
      !isSilenced(v,'Build') && !isFp(v) && !isDismissed(v) && bySev(v) &&
      (!q || (v.policy||'').toLowerCase().includes(q) || (v.image||'').toLowerCase().includes(q))),
    v => v._detectedAt || 0
  ), [buildViolations, sevChecked, q, sortDir, silenced, suppressedRows, dismissedFps]);

  const filteredDeploy = useMemo(() => sortByTime(
    deployViolations.filter(v =>
      !isSilenced(v,'Deploy') && !isFp(v) && !isDismissed(v) && bySev(v) &&
      (!q || (v.policy||'').toLowerCase().includes(q) || (v.workload||'').toLowerCase().includes(q) || (v.ns||'').toLowerCase().includes(q))),
    v => v._detectedAt || 0
  ), [deployViolations, sevChecked, q, sortDir, silenced, suppressedRows, dismissedFps]);

  const filteredAudit = useMemo(() => sortByTime(
    auditViolations.filter(v =>
      !isSilenced(v,'Audit') && !isFp(v) && bySev(v) &&
      (!q || (v.policy||'').toLowerCase().includes(q) || (v.resource||'').toLowerCase().includes(q)
        || (v.ns||'').toLowerCase().includes(q) || (v.kind||'').toLowerCase().includes(q)
        || (v.user||'').toLowerCase().includes(q) || (v.name||'').toLowerCase().includes(q))),
    v => v.timestamp ? new Date(v.timestamp).getTime() : 0
  ), [auditViolations, sevChecked, q, sortDir, silenced]);

  const paginate = arr => {
    if (pageSize === 0) return arr;
    const start = (page - 1) * pageSize;
    return arr.slice(start, start + pageSize);
  };

  const toggleSev = s => setSevChecked(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s]);
  useEffect(() => { setSelected(null); setSortCol('time'); }, [outerTab]);

  const silencedCount = silenced.size + suppressedRows.size;

  const runtimeEmptyText = (tab) => {
    if (!connected)   return '⚠ Bridge disconnected';
    if (!rulesLoaded) return 'Loading policies…';
    const enabled = apiRules.filter(r => r.enabled !== false);
    if (tab === 'Tracepoints') {
      return enabled.some(r => r.detType === 'Tracepoint')
        ? 'No tracepoint violations'
        : 'No Tracepoint policies — create one in Policy Management';
    }
    if (tab === 'LSM Hooks') {
      return enabled.some(r => r.detType === 'LSM')
        ? 'No LSM hook violations'
        : 'No LSM policies — create one in Policy Management';
    }
    return enabled.some(r => !['Build', 'Deploy', 'Audit', 'LSM', 'Tracepoint'].includes(r.detType))
      ? 'No syscall violations'
      : 'No runtime policies — create one in Policy Management';
  };

  const renderRuntimeTab = (tab, rows, eventLabel) => {
    const timeOf = v => v.ts ? new Date(v.ts).getTime() : (v._detectedAt || 0);
    const cols = [
      { key: 'time',      label: 'Time',      val: timeOf },
      { key: 'pod',       label: 'Pod',       val: v => v.pod || '' },
      { key: 'namespace', label: 'Namespace', val: v => v.namespace || '' },
      { key: 'binary',    label: 'Binary',    val: v => v.process || '' },
      { key: 'cmdline',   label: 'Cmdline',   val: v => v.cmdline || '' },
      { key: 'uid',       label: 'UID',       val: v => (v.uid != null ? v.uid : -1) },
      { key: 'event',     label: eventLabel,  val: v => v.syscall || '' },
      { key: 'sev',       label: 'Severity',  val: v => sevRank(v.sev) },
      { key: 'rule',      label: 'Rule',      val: v => v._matchedRule?.name || v.syscall || '' },
    ];
    return (
    <div className="card" style={{ marginRight: selected ? 0 : 24, display: 'flex', flexDirection: 'column' }}>
      <div className="table-wrap" style={{ flex: 1 }}>
        <table className="data-table">
          <thead>
            <tr>
              {cols.map(sortTh)}
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0
              ? <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>
                  {runtimeEmptyText(tab)}
                </td></tr>
              : paginate(sortRows(rows, cols, timeOf)).map((v, i) => (
                  <tr key={i} className={selected === v ? 'selected' : ''} style={{ cursor: 'pointer' }} onClick={() => setSelected(selected === v ? null : v)}>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {v.ts ? (<><div>{new Date(v.ts).toLocaleDateString('ru-RU')}</div><div>{new Date(v.ts).toLocaleTimeString()}</div></>) : v.time || '—'}
                    </td>
                    <td style={{ fontSize: 12 }}>{v.pod}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v.namespace}</td>
                    <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, color: 'var(--text-secondary)' }}>{v.process || '—'}</td>
                    <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, color: 'var(--accent)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.cmdline || <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                    <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, color: 'var(--text-muted)' }}>{v.uid != null ? v.uid : '—'}</td>
                    <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, color: 'var(--accent)' }}>{v.syscall}</td>
                    <td><SevBadge sev={v.sev} /></td>
                    <td className="td-primary" style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 12 }}>{v._matchedRule?.name || v.syscall}</td>
                    <td onClick={e => e.stopPropagation()} style={{ whiteSpace: 'nowrap' }}>
                      <SilentFpButtons onSilent={() => doSilent(v,tab)} onFp={() => doFp(v,tab)} />
                      <DismissBtn onClick={() => dismiss(v,tab)} />
                    </td>
                  </tr>
                ))
            }
          </tbody>
        </table>
      </div>
      <Pagination total={rows.length} pageSize={pageSize} page={page}
        onPageChange={setPage2} onPageSizeChange={setPageSize} />
    </div>
    );
  };

  return (
    <div className="page active flex-page" id="page-violations" style={{ flexDirection: 'column', padding: 0 }}>
      <div style={{ padding: '20px 24px 0', flexShrink: 0 }}>
        <div className="page-header" style={{ marginBottom: 14 }}>
          <div>
            <div className="page-title">Violations</div>
            <div className="page-subtitle">
              {apiRules.length > 0
                ? <><span style={{ color: 'var(--accent)' }}>{apiRules.filter(r => r.enabled !== false).length}</span> {apiRules.length === 1 ? 'policy' : 'policies'} active{' · '}<span style={{ color: 'var(--accent-3)' }}>{syscallViolations.length + buildViolations.length + deployViolations.length + auditViolations.length}</span> total violations</>
                : <span style={{ color: 'var(--text-muted)' }}>No policies configured.{' '}<span style={{ cursor: 'pointer', textDecoration: 'underline', color: 'var(--accent)' }} onClick={() => navigate('/policymgmt')}>Create policy →</span></span>
              }
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 0, marginBottom: 16, borderBottom: '1px solid var(--border)' }}>
          {OUTER_TABS.map(t => (
            <div key={t} onClick={() => setOuterTab(t)}
              style={{ padding: '8px 18px', cursor: 'pointer', fontSize: 13, fontWeight: 500,
                color: outerTab === t ? 'var(--accent)' : 'var(--text-muted)',
                borderBottom: outerTab === t ? '2px solid var(--accent)' : '2px solid transparent',
                marginBottom: -1, transition: 'color .15s', display: 'flex', alignItems: 'center', gap: 6 }}>
              {t}
            </div>
          ))}
        </div>

        <div className="page-search" style={{ marginBottom: 14 }}>
          <input type="text"
            placeholder={
              outerTab === 'Syscalls'      ? 'Filter by syscall, pod, process…'
              : outerTab === 'Tracepoints' ? 'Filter by tracepoint, pod, process…'
              : outerTab === 'LSM Hooks'   ? 'Filter by hook, pod, process…'
              : outerTab === 'Build'       ? 'Filter by policy, image…'
              : outerTab === 'Deploy'      ? 'Filter by policy, workload, namespace…'
              :                             'Filter by policy, resource, kind, namespace…'
            }
            value={search} onChange={e => setSearch(e.target.value)} style={{ minWidth: 220 }} />
          <CheckboxDD label="Severity" options={['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']} checked={sevChecked} onChange={toggleSev} />
          <button
            onClick={() => setSortDir(d => d === 'desc' ? 'asc' : 'desc')}
            title={sortDir === 'desc' ? 'Newest first — click for oldest first' : 'Oldest first — click for newest first'}
            style={{
              padding: '4px 10px', fontSize: 11, cursor: 'pointer',
              background: 'var(--color-background-secondary)',
              border: '0.5px solid var(--color-border-secondary)',
              borderRadius: 'var(--border-radius-md)',
              color: 'var(--color-text-secondary)',
              display: 'flex', alignItems: 'center', gap: 4, whiteSpace: 'nowrap',
            }}>
            {sortDir === 'desc' ? '↓ Newest' : '↑ Oldest'}
          </button>
          <button onClick={() => setShowSilenced(s => !s)} style={{
            padding: '4px 10px', fontSize: 11, cursor: 'pointer',
            background: showSilenced ? 'rgba(251,191,36,.12)' : silencedCount > 0 ? 'var(--color-background-secondary)' : 'rgba(99,179,237,.06)',
            border: showSilenced ? '0.5px solid rgba(251,191,36,.4)' : silencedCount > 0 ? '0.5px solid rgba(251,191,36,.4)' : '0.5px solid rgba(99,179,237,.4)',
            borderRadius: 'var(--border-radius-md)',
            color: showSilenced ? 'var(--warning)' : silencedCount > 0 ? 'var(--warning)' : 'var(--accent)',
            display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap',
          }}>
            Silent
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto', padding: '0 0 24px 24px', minWidth: 0 }}>

          {}
          {showSilenced && (
            <SilencedPanel
              silenced={silenced}
              doUnsilent={doUnsilent}
              syscallViolations={byFamily['Syscalls']}
              tracepointViolations={byFamily['Tracepoints']}
              lsmViolations={byFamily['LSM Hooks']}
              buildViolations={buildViolations}
              deployViolations={deployViolations}
              auditViolations={auditViolations}
            />
          )}

          {}
          {!showSilenced && outerTab === 'Syscalls'    && renderRuntimeTab('Syscalls',    filteredSyscalls,    'Syscall')}
          {!showSilenced && outerTab === 'Tracepoints' && renderRuntimeTab('Tracepoints', filteredTracepoints, 'Tracepoint')}
          {!showSilenced && outerTab === 'LSM Hooks'   && renderRuntimeTab('LSM Hooks',   filteredLsm,         'LSM Hook')}

          {}
          {!showSilenced && outerTab === 'Build' && (
            <div className="card" style={{ marginRight: selected ? 0 : 24, display: 'flex', flexDirection: 'column' }}>
              <div className="table-wrap" style={{ flex: 1 }}>
                <table className="data-table">
                  <thead><tr>{buildCols.map(sortTh)}<th></th></tr></thead>
                  <tbody>
                    {filteredBuild.length === 0
                      ? <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>{buildRules.length === 0 ? 'No Build policies — create one in Policy Management' : 'No build violations detected in scanned images'}</td></tr>
                      : paginate(sortRows(filteredBuild, buildCols, buildDeployTimeOf)).map((v, i) => (
                          <tr key={i} className={selected === v ? 'selected' : ''} style={{ cursor: 'pointer' }} onClick={() => setSelected(selected === v ? null : v)}>
                            <td className="td-primary">{v.policy}</td>
                            <td><SevBadge sev={v.sev} /></td>
                            <td className="mono" style={{ fontSize: 11, color: 'var(--accent)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={v.image}>{v.image}</td>
                            <td style={{ fontSize: 12, color: 'var(--text-muted)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.detail}</td>
                            <td style={{ fontSize: 11, color: 'var(--warning)' }}>{v.action || 'alert'}</td>
                            <td onClick={e => e.stopPropagation()} style={{ whiteSpace: 'nowrap' }}>
                              <SilentFpButtons onSilent={() => doSilent(v,'Build')} onFp={() => doFp(v,'Build')} />
                              <DismissBtn onClick={() => dismiss(v,'Build')} />
                            </td>
                          </tr>
                        ))
                    }
                  </tbody>
                </table>
              </div>
              <Pagination total={filteredBuild.length} pageSize={pageSize} page={page}
                onPageChange={setPage2} onPageSizeChange={setPageSize} />
            </div>
          )}

          {}
          {!showSilenced && outerTab === 'Deploy' && (
            <div className="card" style={{ marginRight: selected ? 0 : 24, display: 'flex', flexDirection: 'column' }}>
              <div className="table-wrap" style={{ flex: 1 }}>
                <table className="data-table">
                  <thead><tr>{deployCols.map(sortTh)}<th></th></tr></thead>
                  <tbody>
                    {filteredDeploy.length === 0
                      ? <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>{deployRules.length === 0 ? 'No Deploy policies — create one in Policy Management' : 'No deploy violations in current workloads'}</td></tr>
                      : paginate(sortRows(filteredDeploy, deployCols, buildDeployTimeOf)).map((v, i) => (
                          <tr key={i} className={selected === v ? 'selected' : ''} style={{ cursor: 'pointer' }} onClick={() => setSelected(selected === v ? null : v)}>
                            <td className="td-primary">{v.policy}</td>
                            <td><SevBadge sev={v.sev} /></td>
                            <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 12 }}>{v.workload}</td>
                            <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{v.kind}</td>
                            <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v.ns}</td>
                            <td style={{ fontSize: 12, color: 'var(--text-muted)', maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.detail}</td>
                            <td style={{ fontSize: 11, color: 'var(--warning)' }}>{v.action || 'alert'}</td>
                            <td onClick={e => e.stopPropagation()} style={{ whiteSpace: 'nowrap' }}>
                              <SilentFpButtons onSilent={() => doSilent(v,'Deploy')} onFp={() => doFp(v,'Deploy')} />
                              <DismissBtn onClick={() => dismiss(v,'Deploy')} />
                            </td>
                          </tr>
                        ))
                    }
                  </tbody>
                </table>
              </div>
              <Pagination total={filteredDeploy.length} pageSize={pageSize} page={page}
                onPageChange={setPage2} onPageSizeChange={setPageSize} />
            </div>
          )}

          {}
          {!showSilenced && outerTab === 'Audit' && (
            <div className="card" style={{ marginRight: selected ? 0 : 24, display: 'flex', flexDirection: 'column' }}>
              <div className="table-wrap" style={{ flex: 1 }}>
                <table className="data-table">
                  <thead><tr>{auditCols.map(sortTh)}<th></th></tr></thead>
                  <tbody>
                    {filteredAudit.length === 0
                      ? <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>
                          {apiRules.filter(r => r.enabled !== false && r.detType === 'Audit').length === 0 ? 'No Audit policies — create one in Policy Management' : 'Waiting for events from sentry-audit…'}
                        </td></tr>
                      : paginate(sortRows(filteredAudit, auditCols, auditTimeOf)).map((v, i) => (
                          <tr key={v._eventId ? `${v._eventId}-${v.check}` : i}
                            className={selected === v ? 'selected' : ''}
                            style={{ cursor: 'pointer' }}
                            onClick={() => setSelected(selected === v ? null : v)}>
                            <td style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                              {v.timestamp ? (<><div>{new Date(v.timestamp).toLocaleDateString('ru-RU')}</div><div>{new Date(v.timestamp).toLocaleTimeString()}</div></>) : '—'}
                            </td>
                            <td className="td-primary">{v.policy}</td>
                            <td><SevBadge sev={v.sev} /></td>
                            <td>
                              <span style={{ fontSize: 11, padding: '2px 7px', borderRadius: 5,
                                background: `${KIND_COLOR[v.kind] || '#94a3b8'}22`,
                                color: KIND_COLOR[v.kind] || 'var(--text-muted)',
                                border: `1px solid ${KIND_COLOR[v.kind] || '#94a3b8'}44`,
                                fontFamily: 'JetBrains Mono,monospace' }}>
                                {v.kind}
                              </span>
                            </td>
                            <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, color: 'var(--accent)' }}>{v.resource}</td>
                            <td style={{ fontFamily: 'JetBrains Mono,monospace', fontSize: 11, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.name || '—'}</td>
                            <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{v.ns}</td>
                            <td style={{ fontSize: 12, color: 'var(--text-muted)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.user || '—'}</td>
                            <td onClick={e => e.stopPropagation()} style={{ whiteSpace: 'nowrap' }}>
                              <SilentFpButtons onSilent={() => doSilent(v,'Audit')} onFp={() => doFp(v,'Audit')} />
                              <DismissBtn onClick={() => dismiss(v,'Audit')} />
                            </td>
                          </tr>
                        ))
                    }
                  </tbody>
                </table>
              </div>
              <Pagination total={filteredAudit.length} pageSize={pageSize} page={page}
                onPageChange={setPage2} onPageSizeChange={setPageSize} />
            </div>
          )}
        </div>

        {RUNTIME_TABS.includes(outerTab) && <SyscallDetail v={selected} onClose={() => setSelected(null)} onFp={() => doFp(selected, outerTab)} onResolve={() => doResolve(selected, outerTab)} getMatchedRules={getMatchedRules} rulesVersion={rulesVersion} />}
        {outerTab === 'Build'    && <BuildDetail   v={selected} onClose={() => setSelected(null)} />}
        {outerTab === 'Deploy'   && <DeployDetail  v={selected} onClose={() => setSelected(null)} />}
        {outerTab === 'Audit'    && <AuditDetail   v={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  );
}

function DismissBtn({ onClick }) {
  return (
    <button
      onClick={onClick}
      title="Dismiss"
      style={{
        marginLeft: 4, background: 'none', border: 'none', cursor: 'pointer',
        color: 'var(--text-muted)', fontSize: 15, lineHeight: 1,
        padding: '1px 4px', borderRadius: 4, verticalAlign: 'middle',
        transition: 'color .15s',
      }}
      onMouseEnter={e => { e.currentTarget.style.color = 'var(--danger)'; }}
      onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; }}
    >×</button>
  );
}
