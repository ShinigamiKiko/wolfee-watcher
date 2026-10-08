import { apiFetch } from '../../data/cluster';
import { useState, useMemo, useEffect, useRef } from 'react';
import { useNavigate }  from 'react-router-dom';
import { useBridge }   from '../../context/BridgeContext';
import { usePerms }    from '../../context/PermissionsContext';
import { useScanner }  from '../../context/ScannerContext';
import { useSensor }   from '../../context/SensorContext';
import { SevBadge, Tabs } from '../../components/ui';
import { PageHeader, SearchInput, SortTh, EmptyRow, ActionBadge, cx } from '../../components/kit';
import { CheckboxDD }  from '../../components/CheckboxDD';
import { SyscallDetail } from './SyscallDetail';
import { BuildDetail }   from './BuildDetail';
import { DeployDetail }  from './DeployDetail';
import { AuditDetail }   from './AuditDetail';
import { evalBuildViolations, evalDeployViolations } from './evaluators';

import { OUTER_TABS, RUNTIME_TABS, ackKey, fpKey } from './violationsConstants';
import { Pager } from '../../components/Pager';
import { usePageSize } from '../../hooks/usePaged';
import { DataWindow } from '../../components/DataWindow';
import { SilentFpButtons } from './SilentFpButtons';
import { SilencedPanel } from './SilencedPanel';
import { LSM_NAMES } from '../lsm/lsmCatalog';
import { TRACEPOINT_NAMES } from '../tracepoints/tracepointsCatalog';
import { Icon } from '../../components/Icon';

const POSTURE_REFRESH_MS = 60_000;

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
  const [pageSize,     setPageSize]     = usePageSize('violations');
  const [page,         setPage2]        = useState(1);

  const [silenced, setSilenced] = useState(new Map());

  const [suppressedRows, setSuppressedRows] = useState(new Map());
  const dismissedFps = useMemo(() => {
    const s = new Set();
    for (const [fp, e] of suppressedRows) if (e.state === 'DISMISSED') s.add(fp);
    return s;
  }, [suppressedRows]);

  const loadCategoryAcks = () => {
    apiFetch('/api/acks', { credentials: 'same-origin' })
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
    apiFetch('/v1/violations?state=suppressed&limit=1000', { credentials: 'same-origin' })
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
    apiFetch(`/v1/violations?fp=${encodeURIComponent(fp)}&state=${state}`,
      { method: 'POST', credentials: 'same-origin' });

  const doSilent = (v, tab) => {
    const key = ackKey(v, tab);
    const expiresAt = Date.now() + 60 * 24 * 3600 * 1000;
    setSilenced(prev => new Map([...prev, [key, { type: 'silent', expiresAt }]]));
    apiFetch('/api/acks', {
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
      apiFetch(`/v1/violations?fp=${encodeURIComponent(fp)}`,
        { method: 'DELETE', credentials: 'same-origin' }).catch(() => {});
    }
  };
  const doResolve = dismiss;

  const doUnsilent = (key) => {
    setSilenced(prev => { const m = new Map(prev); m.delete(key); return m; });
    setSuppressedRows(prev => { const m = new Map(prev); m.delete(key); return m; });
    const isCategoryKey = /^(sc|tp|lsm|bld|dep|aud)::/.test(key);
    if (isCategoryKey) {
      apiFetch(`/api/acks?key=${encodeURIComponent(key)}`, { method: 'DELETE', credentials: 'same-origin' }).catch(() => {});
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
    apiFetch('/v1/violations/record', {
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
    apiFetch('/api/policies', { credentials: 'same-origin' })
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
  const [posture, setPosture] = useState({ build: null, deploy: null, unavailable: false });
  const postureSeen = useRef({ build: undefined, deploy: undefined });
  useEffect(() => {
    let alive = true;
    postureSeen.current = { build: undefined, deploy: undefined };
    const load = () => Promise.all(['build', 'deploy'].map(type =>
      apiFetch(`/v1/posture?type=${type}`, { credentials: 'same-origin' }).then(r => r.ok ? r.json() : null).catch(() => null)))
      .then(([build, deploy]) => {
        if (!alive) return;
        if (build?.unavailable || deploy?.unavailable) {
          setPosture(prev => prev.unavailable ? prev : { build: null, deploy: null, unavailable: true });
          return;
        }
        const fresh = (type, res) => Array.isArray(res?.findings) && res.evaluatedAt !== postureSeen.current[type];
        const nextBuild = fresh('build', build), nextDeploy = fresh('deploy', deploy);
        if (!nextBuild && !nextDeploy) return;
        if (nextBuild) postureSeen.current.build = build.evaluatedAt;
        if (nextDeploy) postureSeen.current.deploy = deploy.evaluatedAt;
        setPosture(prev => ({
          build:  nextBuild  ? build.findings  : prev.build,
          deploy: nextDeploy ? deploy.findings : prev.deploy,
          unavailable: false,
        }));
      });
    load();
    const t = setInterval(load, POSTURE_REFRESH_MS);
    return () => { alive = false; clearInterval(t); };
  }, [rulesVersion]);

  const localPosture = posture.unavailable;
  const buildViolations   = useMemo(() => localPosture ? evalBuildViolations(buildRules, clusterImages, histories) : (posture.build || []),
    [localPosture, posture.build, buildRules, clusterImages, histories]);
  const deployViolations  = useMemo(() => localPosture ? evalDeployViolations(deployRules, workloads, snapshot) : (posture.deploy || []),
    [localPosture, posture.deploy, deployRules, workloads, snapshot]);

  useEffect(() => {
    if (!localPosture) return;
    for (const v of buildViolations)  recordBuildDeploy(v, 'Build');
    for (const v of deployViolations) recordBuildDeploy(v, 'Deploy');
  }, [localPosture, buildViolations, deployViolations]);

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
  const sortTh = col => <SortTh key={col.key} col={col.key} label={col.label} sort={sortCol} dir={sortDir} onSort={toggleSort} />;
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
     { key: 'webhookType', label: 'Webhook type', val: v => v.webhookType || '' },
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
    const start = (page - 1) * pageSize;
    return arr.slice(start, start + pageSize);
  };

  const toggleSev = s => setSevChecked(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s]);
  useEffect(() => { setSelected(null); setSortCol('time'); }, [outerTab]);

  const silencedCount = silenced.size + suppressedRows.size;

  const runtimeEmptyText = (tab) => {
    if (!connected)   return 'Bridge disconnected';
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

  const pager = total => (
    <Pager total={total} pageSize={pageSize} page={page} onPage={setPage2} onPageSize={n => { setPageSize(n); setPage2(1); }} />
  );
  const rowProps = v => ({ className: selected === v ? 'selected' : '', onClick: () => setSelected(selected === v ? null : v) });
  const actions = (v, tab) => (
    <td className="row-actions-cell" onClick={e => e.stopPropagation()}>
      <span className="row row--tight">
        <SilentFpButtons onSilent={() => doSilent(v, tab)} onFp={() => doFp(v, tab)} />
        <DismissBtn onClick={() => dismiss(v, tab)} />
      </span>
    </td>
  );
  const when = iso => (iso
    ? <><div>{new Date(iso).toLocaleDateString('ru-RU')}</div><div>{new Date(iso).toLocaleTimeString()}</div></>
    : '—');

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
      <DataWindow label="Runtime violations" deps={[outerTab, showSilenced, !!selected]} footer={pager(rows.length)}>
        <table className="data-table">
          <thead><tr>{cols.map(sortTh)}<th aria-label="Actions" /></tr></thead>
          <tbody>
            {rows.length === 0
              ? <EmptyRow cols={10}>{runtimeEmptyText(tab)}</EmptyRow>
              : paginate(sortRows(rows, cols, timeOf)).map((v, i) => (
                  <tr key={i} {...rowProps(v)}>
                    <td className="t-xs t-muted">{v.ts ? when(v.ts) : v.time || '—'}</td>
                    <td className="t-sm">{v.pod}</td>
                    <td className="t-sm t-muted">{v.namespace}</td>
                    <td className="mono t-xs">{v.process || '—'}</td>
                    <td className="mono t-xs t-accent clip clip--md">{v.cmdline || <span className="t-muted">—</span>}</td>
                    <td className="mono t-xs t-muted">{v.uid != null ? v.uid : '—'}</td>
                    <td className="mono t-xs t-accent">{v.syscall}</td>
                    <td><SevBadge sev={v.sev} /></td>
                    <td className="td-primary mono t-sm">{v._matchedRule?.name || v.syscall}</td>
                    {actions(v, tab)}
                  </tr>
                ))}
          </tbody>
        </table>
      </DataWindow>
    );
  };

  const placeholder = {
    Syscalls: 'Filter by syscall, pod, process…',
    Tracepoints: 'Filter by tracepoint, pod, process…',
    'LSM Hooks': 'Filter by hook, pod, process…',
    Build: 'Filter by policy, image…',
    Deploy: 'Filter by policy, workload, namespace…',
  }[outerTab] || 'Filter by policy, resource, kind, namespace…';
  const activePolicies = apiRules.filter(r => r.enabled !== false).length;
  const totalViolations = syscallViolations.length + buildViolations.length + deployViolations.length + auditViolations.length;

  return (
    <div className="page active flex-page split-page" id="page-violations">
      <div className="split-head">
        <PageHeader
          className="mb-12"
          title="Violations"
          subtitle={apiRules.length > 0
            ? <><span className="t-accent">{activePolicies}</span> {apiRules.length === 1 ? 'policy' : 'policies'} active · <span className="t-ok">{totalViolations}</span> total violations</>
            : <>No policies configured. <button type="button" className="link-btn" onClick={() => navigate('/policymgmt')}>Create policy →</button></>}
        />

        <Tabs tabs={OUTER_TABS.map(t => ({ id: t, label: t }))} active={outerTab} onSwitch={setOuterTab} />

        <div className="toolbar">
          <SearchInput value={search} onChange={setSearch} placeholder={placeholder} />
          <CheckboxDD label="Severity" options={['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']} checked={sevChecked} onChange={toggleSev} />
          <button type="button" className="btn btn-outline btn-sm" onClick={() => setSortDir(d => d === 'desc' ? 'asc' : 'desc')}
            title={sortDir === 'desc' ? 'Newest first — click for oldest first' : 'Oldest first — click for newest first'}>
            <Icon name={sortDir === 'desc' ? 'arrow-down' : 'arrow-up'} /> {sortDir === 'desc' ? 'Newest' : 'Oldest'}
          </button>
          <button type="button" className={cx('chip', silencedCount > 0 && 'chip--warning')} aria-pressed={showSilenced} onClick={() => setShowSilenced(s => !s)}>
            Silent{silencedCount > 0 && <span className="mono">{silencedCount}</span>}
          </button>
        </div>
      </div>

      <div className="split-body">
        <div className="split-main">
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

          {!showSilenced && outerTab === 'Syscalls'    && renderRuntimeTab('Syscalls',    filteredSyscalls,    'Syscall')}
          {!showSilenced && outerTab === 'Tracepoints' && renderRuntimeTab('Tracepoints', filteredTracepoints, 'Tracepoint')}
          {!showSilenced && outerTab === 'LSM Hooks'   && renderRuntimeTab('LSM Hooks',   filteredLsm,         'LSM Hook')}

          {!showSilenced && outerTab === 'Build' && (
            <DataWindow label="Build violations" deps={[outerTab, showSilenced, !!selected]} footer={pager(filteredBuild.length)}>
              <table className="data-table">
                <thead><tr>{buildCols.map(sortTh)}<th aria-label="Actions" /></tr></thead>
                <tbody>
                  {filteredBuild.length === 0
                    ? <EmptyRow cols={6}>{buildRules.length === 0 ? 'No Build policies — create one in Policy Management' : 'No build violations detected in scanned images'}</EmptyRow>
                    : paginate(sortRows(filteredBuild, buildCols, buildDeployTimeOf)).map((v, i) => (
                        <tr key={i} {...rowProps(v)}>
                          <td className="td-primary">{v.policy}</td>
                          <td><SevBadge sev={v.sev} /></td>
                          <td className="mono t-xs t-accent clip clip--md" title={v.image}>{v.image}</td>
                          <td className="t-sm t-muted clip clip--lg">{v.detail}</td>
                          <td className="t-xs t-warning">{v.action || 'alert'}</td>
                          {actions(v, 'Build')}
                        </tr>
                      ))}
                </tbody>
              </table>
            </DataWindow>
          )}

          {!showSilenced && outerTab === 'Deploy' && (
            <DataWindow label="Deploy violations" deps={[outerTab, showSilenced, !!selected]} footer={pager(filteredDeploy.length)}>
              <table className="data-table">
                <thead><tr>{deployCols.map(sortTh)}<th aria-label="Actions" /></tr></thead>
                <tbody>
                  {filteredDeploy.length === 0
                    ? <EmptyRow cols={8}>{deployRules.length === 0 ? 'No Deploy policies — create one in Policy Management' : 'No deploy violations in current workloads'}</EmptyRow>
                    : paginate(sortRows(filteredDeploy, deployCols, buildDeployTimeOf)).map((v, i) => (
                        <tr key={i} {...rowProps(v)}>
                          <td className="td-primary">{v.policy}</td>
                          <td><SevBadge sev={v.sev} /></td>
                          <td className="mono t-sm">{v.workload}</td>
                          <td className="t-xs t-muted">{v.kind}</td>
                          <td className="t-sm t-muted">{v.ns}</td>
                          <td className="t-sm t-muted clip clip--lg">{v.detail}</td>
                          <td className="t-xs t-warning">{v.action || 'alert'}</td>
                          {actions(v, 'Deploy')}
                        </tr>
                      ))}
                </tbody>
              </table>
            </DataWindow>
          )}

          {!showSilenced && outerTab === 'Audit' && (
            <DataWindow label="Audit violations" deps={[outerTab, showSilenced, !!selected]} footer={pager(filteredAudit.length)}>
              <table className="data-table">
                <thead><tr>{auditCols.map(sortTh)}<th aria-label="Actions" /></tr></thead>
                <tbody>
                  {filteredAudit.length === 0
                    ? <EmptyRow cols={10}>No audit violations. Audit rules are managed in Audit logs, on the Rules tab.</EmptyRow>
                    : paginate(sortRows(filteredAudit, auditCols, auditTimeOf)).map((v, i) => (
                        <tr key={v._eventId ? `${v._eventId}-${v.check}` : i} {...rowProps(v)}>
                          <td className="t-xs t-muted">{when(v.timestamp)}</td>
                          <td className="td-primary">{v.policy}</td>
                          <td><SevBadge sev={v.sev} /></td>
                          <td><ActionBadge kind={v.kind} /></td>
                          <td className="t-xs t-muted clip clip--md">{v.webhookType || '—'}</td>
                          <td className="mono t-xs t-accent">{v.resource}</td>
                          <td className="mono t-xs clip clip--md">{v.name || '—'}</td>
                          <td className="t-sm t-muted">{v.ns}</td>
                          <td className="t-sm t-muted clip clip--sm">{v.user || '—'}</td>
                          {actions(v, 'Audit')}
                        </tr>
                      ))}
                </tbody>
              </table>
            </DataWindow>
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
    <button type="button" className="btn-icon btn-icon--sm btn-icon--danger" title="Dismiss" aria-label="Dismiss" onClick={onClick}>
      <Icon name="x" />
    </button>
  );
}
