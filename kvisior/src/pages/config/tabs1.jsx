import { StatusDot } from '../../components/ui';
import { Stat, Crumbs, cx } from '../../components/kit';
import { KindBadge, FilterInput, EmptyRow } from './cfgHelpers';
import { Icon } from '../../components/Icon';
import { PagedWindow } from '../../components/PagedWindow';

const Open = () => <td className="t-muted"><Icon name="chevron-right" /></td>;

export function ClustersTab({ nodeRows, nsRows, workloadRows, clusterImages, agentInfo, sensorOnline, connected, selected, setSelected }) {
  const clusterName = agentInfo?.clusterName || 'wolfee-watcher';
  const k8sVersion  = nodeRows[0]?.info?.kubeletVersion || agentInfo?.k8sVersion || '—';
  const sel = () => setSelected({ title: clusterName, sub: 'Cluster overview', raw: { apiVersion: 'v1', kind: 'Cluster', metadata: { name: clusterName }, status: { nodes: nodeRows.length, namespaces: nsRows.length, k8sVersion } } });

  return (<>
    <div className="stats-grid stats-grid--4">
      <Stat label="Nodes" value={nodeRows.length || '—'} tone="accent" />
      <Stat label="Namespaces" value={nsRows.length || '—'} tone="accent" />
      <Stat label="Workloads" value={workloadRows.length || '—'} tone="accent" />
      <Stat label="Images" value={clusterImages.length || '—'} tone="warning" />
    </div>
    <div className="card">
      <div className="card-header"><div className="card-title">Clusters</div></div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Cluster</th><th>Nodes</th><th>Namespaces</th><th>K8s Version</th><th>Sensor</th><th>Bridge</th></tr></thead>
          <tbody>
            <tr className={selected?.title === clusterName ? 'selected' : ''} onClick={sel}>
              <td className="td-primary">{clusterName}</td>
              <td>{nodeRows.length || '—'}</td><td>{nsRows.length || '—'}</td>
              <td className="mono t-xs">{k8sVersion}</td>
              <td><StatusDot type={sensorOnline ? 'active' : 'error'} label={sensorOnline ? 'Online' : 'Offline'} /></td>
              <td><StatusDot type={connected ? 'active' : 'warn'} label={connected ? 'Online' : 'Offline'} /></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </>);
}

export function NamespacesTab({ nsRows, q, search, setSearch, sensorOnline, selected, setSelected, nsDrill, setNsDrill }) {
  const sel = (title, sub, raw) => setSelected({ title, sub, raw });
  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          {nsDrill
            ? <Crumbs items={[{ label: 'Namespaces', onClick: () => setNsDrill(null) }, { label: nsDrill.name }]} meta={`${nsDrill.pods.length} pods`} />
            : <>Namespaces <span className="card-sub">({nsRows.length})</span></>}
        </div>
        {!nsDrill && <FilterInput value={search} onChange={setSearch} />}
        {nsDrill && <button type="button" onClick={() => setNsDrill(null)} className="btn btn-outline btn-sm"><Icon name="arrow-left" /> Back</button>}
      </div>
      <PagedWindow items={nsDrill ? nsDrill.pods : nsRows.filter(r => !q || r.name.includes(q))} storageKey="config.namespaces" label="Namespaces" noun="rows" resetKey={`${nsDrill?.name || ''}|${q}`}>{rows => (
        !nsDrill ? (
          <table className="data-table">
            <thead><tr><th>Namespace</th><th>Status</th><th>Pods</th><th>Live Events</th><th aria-label="Open" /></tr></thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.name} onClick={() => setNsDrill(r)}>
                  <td className="td-primary">{r.name}</td>
                  <td><StatusDot type="active" label="Active" /></td>
                  <td className={cx('t-sm', r.pods.length > 0 ? 't-primary' : 't-muted')}>{r.pods.length}</td>
                  <td className={cx('mono t-sm', r.events > 0 ? 't-accent' : 't-muted')}>{r.events || '—'}</td>
                  <Open />
                </tr>
              ))}
              {!nsRows.length && <EmptyRow cols={5} msg="No namespaces" sensorOnline={sensorOnline} />}
            </tbody>
          </table>
        ) : (
          <table className="data-table">
            <thead><tr><th>Pod</th><th>Node</th><th>Images</th><th>Status</th><th aria-label="Open" /></tr></thead>
            <tbody>
              {nsDrill.pods.length === 0
                ? <EmptyRow cols={5} msg="No pods in this namespace" />
                : rows.map((p, i) => {
                    const phase  = p.status?.phase || 'Unknown';
                    const stType = phase === 'Running' ? 'active' : phase === 'Pending' ? 'warn' : 'error';
                    const images = (p.spec?.containers || []).map(c => c.image).filter(Boolean);
                    return (
                      <tr key={i} className={selected?.title === p.metadata?.name ? 'selected' : ''}
                        onClick={() => sel(p.metadata?.name, `Pod · ${nsDrill.name}`, p)}>
                        <td className="td-primary mono t-sm">{p.metadata?.name}</td>
                        <td className="t-sm t-muted">{p.spec?.nodeName || '—'}</td>
                        <td className="mono t-xs t-muted clip clip--md">{images.join(', ') || '—'}</td>
                        <td><StatusDot type={stType} label={phase} /></td>
                        <Open />
                      </tr>
                    );
                  })}
            </tbody>
          </table>
        )
      )}</PagedWindow>
    </div>
  );
}

export function NodesTab({ nodeRows, pods, q, search, setSearch, sensorOnline, selected, setSelected }) {
  const podsByNode = pods.reduce((acc, p) => { const n = p.spec?.nodeName; if (n) acc[n] = (acc[n] || 0) + 1; return acc; }, {});
  return (
    <div className="card">
      <div className="card-header"><div className="card-title">Nodes <span className="card-sub">({nodeRows.length})</span></div><FilterInput value={search} onChange={setSearch} /></div>
      <PagedWindow items={nodeRows.filter(n => !q || n.name.includes(q))} storageKey="config.nodes" label="Nodes" noun="nodes" resetKey={q}>{rows => (
        <table className="data-table">
          <thead><tr><th>Node</th><th>Role</th><th>OS</th><th>Kernel</th><th>CPU</th><th>Memory</th><th>Pods</th><th>Live Events</th><th>Status</th></tr></thead>
          <tbody>
            {rows.map(n => (
              <tr key={n.name} className={selected?.title === n.name ? 'selected' : ''}
                onClick={() => setSelected({ title: n.name, sub: `Node · ${n.info.operatingSystem || 'linux'}`, raw: Object.assign({ apiVersion: 'v1', kind: 'Node' }, n.raw) })}>
                <td className="td-primary">{n.name}</td>
                <td><KindBadge kind={n.role === 'control-plane' ? 'ClusterRole' : 'Role'} /></td>
                <td className="t-sm">{n.info.osImage || '—'}</td>
                <td className="mono t-xs t-muted">{n.info.kernelVersion || '—'}</td>
                <td className="t-sm">{n.cpu}</td>
                <td className="t-sm">{n.mem}</td>
                <td className="mono t-sm t-primary">{podsByNode[n.name] || 0}</td>
                <td className={cx('mono t-sm', n.events > 0 ? 't-accent' : 't-muted')}>{n.events || '—'}</td>
                <td><StatusDot type={n.st.type} label={n.st.label} /></td>
              </tr>
            ))}
            {!nodeRows.length && <EmptyRow cols={9} msg="No nodes found" sensorOnline={sensorOnline} />}
          </tbody>
        </table>
      )}</PagedWindow>
    </div>
  );
}

export function WorkloadsTab({ workloadRows, q, search, setSearch, sensorOnline, selected, setSelected }) {
  return (
    <div className="card">
      <div className="card-header"><div className="card-title">Workloads <span className="card-sub">({workloadRows.length})</span></div><FilterInput value={search} onChange={setSearch} /></div>
      <PagedWindow items={workloadRows.filter(w => !q || w.name.includes(q) || w.ns.includes(q) || w.kind.toLowerCase().includes(q))} storageKey="config.workloads" label="Workloads" noun="workloads" resetKey={q}>{rows => (
        <table className="data-table">
          <thead><tr><th>Name</th><th>Kind</th><th>Namespace</th><th>Images</th><th>Ready</th><th aria-label="Open" /></tr></thead>
          <tbody>
            {rows.map((w, i) => (
              <tr key={i} className={selected?.title === w.name ? 'selected' : ''}
                onClick={() => setSelected({ title: w.name, sub: `${w.kind} · ${w.ns}`, raw: Object.assign({ apiVersion: 'apps/v1', kind: w.kind }, w.raw) })}>
                <td className="td-primary">{w.name}</td>
                <td><KindBadge kind={w.kind} /></td>
                <td className="t-sm">{w.ns}</td>
                <td className="mono t-xs t-muted clip clip--md">{w.images.join(', ') || '—'}</td>
                <td className="mono t-sm">{w.ready}</td>
                <Open />
              </tr>
            ))}
            {!workloadRows.length && <EmptyRow cols={6} msg="No workloads found" sensorOnline={sensorOnline} />}
          </tbody>
        </table>
      )}</PagedWindow>
    </div>
  );
}
