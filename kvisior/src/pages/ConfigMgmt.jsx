import { useState, useMemo } from 'react';
import { useBridge }  from '../context/BridgeContext';
import { useScanner } from '../context/ScannerContext';
import { useSensor }  from '../context/SensorContext';
import { YamlPanel }  from './config/YamlPanel';
import { nodeRole, nodeReady, workloadReady, workloadImages, bindingsFor, SYS_NS, SYS_NAMES } from './config/cfgHelpers';
import { ClustersTab, NamespacesTab, NodesTab, WorkloadsTab } from './config/tabs1';
import { ServiceAccountsTab, RolesTab, SecretsTab, CrdsTab, StaticPodsTab, WebhooksTab } from './config/tabs2';

const TABS = ['Clusters','Namespaces','Nodes','Deployments','Service Accounts','Roles','Secrets','CRDs','Static Pods','MWH','VWH'];
const CONTROLLER_KINDS = new Set(['ReplicaSet','StatefulSet','DaemonSet','Job','CronJob','ReplicationController']);

export function ConfigMgmt() {
  const { nodeStats, events, connected }          = useBridge();
  const { clusterImages, agentInfo }              = useScanner();
  const { sensorOnline, lastUpdated, nodes, pods, workloads, namespaces,
          serviceAccounts, secrets, allRoles, allBindings, crds,
          mutatingWebhooks, validatingWebhooks }  = useSensor();

  const [tab,      setTab]      = useState('Clusters');
  const [search,   setSearch]   = useState('');
  const [selected, setSelected] = useState(null);
  const [nsDrill,     setNsDrill]     = useState(null);
  const [showSystem,  setShowSystem]  = useState(false);
  const q = search.toLowerCase();

  const nsRows = useMemo(() => {
    const evCount = {}, podsByNs = {};
    events.forEach(e => { if (e.namespace) evCount[e.namespace] = (evCount[e.namespace] || 0) + 1; });
    pods.forEach(p => { const ns = p.metadata?.namespace; if (ns) { if (!podsByNs[ns]) podsByNs[ns] = []; podsByNs[ns].push(p); } });
    return namespaces.filter(ns => showSystem || !SYS_NS.has(ns.metadata?.name))
      .map(ns => ({ name: ns.metadata?.name || '', raw: ns, events: evCount[ns.metadata?.name] || 0, pods: podsByNs[ns.metadata?.name] || [] }))
      .sort((a, b) => b.events - a.events);
  }, [namespaces, pods, events, showSystem]);

  const nodeRows = useMemo(() => nodes.map(n => {
    const name = n.metadata?.name || '', info = n.status?.nodeInfo || {}, cap = n.status?.capacity || {};
    return { name, role: nodeRole(n), st: nodeReady(n), info, cpu: cap.cpu || '—', mem: cap.memory ? (parseInt(cap.memory) / 1048576).toFixed(0) + 'Gi' : '—', events: nodeStats?.[name] || 0, raw: n };
  }).sort((a, b) => b.events - a.events), [nodes, nodeStats]);

  const workloadRows = useMemo(() => workloads.filter(w => showSystem || !SYS_NS.has(w.metadata?.namespace))
    .map(w => ({ name: w.metadata?.name || '', ns: w.metadata?.namespace || '', kind: w._kind, images: workloadImages(w), ready: workloadReady(w), raw: w }))
    .sort((a, b) => a.ns.localeCompare(b.ns) || a.name.localeCompare(b.name)), [workloads, showSystem]);

  const saRows = useMemo(() => serviceAccounts.filter(sa => showSystem || !SYS_NS.has(sa.metadata?.namespace))
    .map(sa => {
      const name = sa.metadata?.name || '', ns = sa.metadata?.namespace || '';
      const binds = bindingsFor(name, 'sa', ns, allBindings);
      return { name, ns, automount: sa.automountServiceAccountToken !== false, bindings: binds.length, raw: sa };
    }).sort((a, b) => a.ns.localeCompare(b.ns) || a.name.localeCompare(b.name)), [serviceAccounts, allBindings, showSystem]);

  const roleRows = useMemo(() => allRoles.filter(r => showSystem || !SYS_NAMES.some(p => r.metadata?.name?.startsWith(p)))
    .map(r => {
      const name = r.metadata?.name || '', ns = r.metadata?.namespace || '—';
      const hasWildcard = (r.rules || []).some(ru => ru.verbs?.includes('*') || ru.resources?.includes('*') || ru.apiGroups?.includes('*'));
      const binds = bindingsFor(name, 'role', ns, allBindings);
      const subjectSet = new Map();
      binds.forEach(b => (b.subjects || []).forEach(s => { const k = `${s.kind}/${s.name}`; if (!subjectSet.has(k)) subjectSet.set(k, s); }));
      return { name, ns, kind: r._kind, rules: r.rules?.length || 0, hasWildcard, bindings: binds.length, subjects: [...subjectSet.values()], raw: r };
    }).sort((a, b) => (b.hasWildcard ? 1 : 0) - (a.hasWildcard ? 1 : 0) || a.name.localeCompare(b.name)), [allRoles, allBindings, showSystem]);

  const staticPods = useMemo(() => pods.filter(p => {
    const owners = p.metadata?.ownerReferences || [];
    return owners.length === 0 || owners.every(o => !CONTROLLER_KINDS.has(o.kind));
  }).sort((a, b) => {
    const aS = (a.metadata?.ownerReferences || []).some(o => o.kind === 'Node');
    const bS = (b.metadata?.ownerReferences || []).some(o => o.kind === 'Node');
    if (aS !== bS) return aS ? -1 : 1;
    return (a.metadata?.name || '').localeCompare(b.metadata?.name || '');
  }), [pods]);

  const switchTab = t => { setTab(t); setSelected(null); setSearch(''); setNsDrill(null); };
  const sharedProps = { q, search, setSearch, sensorOnline, selected, setSelected };

  return (
    <div className="page active flex-page" id="page-configmgmt" style={{ flexDirection: 'column', padding: 0 }}>
      <div style={{ padding: '20px 24px 0', flexShrink: 0 }}>
        <div className="page-header" style={{ marginBottom: 14 }}>
          <div>
            <div className="page-title">Configuration Management</div>
            <div className="page-subtitle" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              Kubernetes object configuration and security posture
              <span className={`status-dot status-${connected ? 'active' : 'warn'}`}>{connected ? 'Live data' : 'Bridge offline'}</span>
              {sensorOnline && <span style={{ fontSize: 11, color: 'var(--accent-3)' }}>● sensor online</span>}
              {lastUpdated  && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>· {lastUpdated.toLocaleTimeString()}</span>}
            </div>
            <button onClick={() => setShowSystem(s => !s)} style={{
              marginTop: 6, padding: '4px 12px', borderRadius: 7, fontSize: 11, fontWeight: 500,
              cursor: 'pointer', border: '1px solid var(--border)', fontFamily: 'DM Sans, sans-serif',
              background: showSystem ? 'rgba(0,200,255,.15)' : 'var(--bg-elevated)',
              color: showSystem ? 'var(--accent)' : 'var(--text-muted)',
              transition: 'all .15s',
            }}>
              {showSystem ? '⊙ System NS: on' : '⊙ System NS: off'}
            </button>
          </div>
        </div>
        <div className="tabs">
          {TABS.map(t => <div key={t} className={`tab${tab === t ? ' active' : ''}`} onClick={() => switchTab(t)}>{t}</div>)}
        </div>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto', padding: '0 0 24px 24px', minWidth: 0 }}>
          {tab === 'Clusters'         && <ClustersTab         {...sharedProps} nodeRows={nodeRows} nsRows={nsRows} workloadRows={workloadRows} clusterImages={clusterImages} agentInfo={agentInfo} connected={connected} />}
          {tab === 'Namespaces'       && <NamespacesTab       {...sharedProps} nsRows={nsRows} nsDrill={nsDrill} setNsDrill={setNsDrill} />}
          {tab === 'Nodes'            && <NodesTab            {...sharedProps} nodeRows={nodeRows} pods={pods} />}
          {tab === 'Deployments'      && <WorkloadsTab        {...sharedProps} workloadRows={workloadRows} />}
          {tab === 'Service Accounts' && <ServiceAccountsTab  {...sharedProps} saRows={saRows} />}
          {tab === 'Roles'            && <RolesTab            {...sharedProps} roleRows={roleRows} />}
          {tab === 'Secrets'          && <SecretsTab          {...sharedProps} secrets={secrets} SYS_NS={SYS_NS} />}
          {tab === 'CRDs'             && <CrdsTab             {...sharedProps} crds={crds} />}
          {tab === 'Static Pods'      && <StaticPodsTab       {...sharedProps} staticPods={staticPods} />}
          {tab === 'MWH'              && <WebhooksTab         {...sharedProps} isMut={true}  items={mutatingWebhooks} />}
          {tab === 'VWH'              && <WebhooksTab         {...sharedProps} isMut={false} items={validatingWebhooks} />}
        </div>
        <YamlPanel item={selected} onClose={() => setSelected(null)} />
      </div>
    </div>
  );
}
