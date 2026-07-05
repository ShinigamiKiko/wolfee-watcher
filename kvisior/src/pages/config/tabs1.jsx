import { StatusDot } from '../../components/ui';
import { KindBadge, FilterInput, EmptyRow } from './cfgHelpers';

export function ClustersTab({ nodeRows, nsRows, workloadRows, clusterImages, agentInfo, sensorOnline, connected, selected, setSelected }) {
  const clusterName = agentInfo?.clusterName || 'wolfee-watcher';
  const k8sVersion  = nodeRows[0]?.info?.kubeletVersion || agentInfo?.k8sVersion || '—';
  const sel = () => setSelected({ title: clusterName, sub: 'Cluster overview', raw: { apiVersion: 'v1', kind: 'Cluster', metadata: { name: clusterName }, status: { nodes: nodeRows.length, namespaces: nsRows.length, k8sVersion } } });

  return (<>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12, margin: '16px 24px 16px 0' }}>
      {[['Nodes', nodeRows.length, 'info'], ['Namespaces', nsRows.length, 'info'], ['Workloads', workloadRows.length, 'info'], ['Images', clusterImages.length, 'warn']].map(([l, v, c]) => (
        <div key={l} className="stat-card"><div className="stat-label">{l}</div><div className={`stat-value ${c}`}>{v || '—'}</div></div>
      ))}
    </div>
    <div className="card" style={{ marginRight: selected ? 0 : 24 }}>
      <div className="card-header"><div className="card-title">Clusters</div></div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Cluster</th><th>Nodes</th><th>Namespaces</th><th>K8s Version</th><th>Sensor</th><th>Bridge</th></tr></thead>
          <tbody>
            <tr style={{ cursor: 'pointer' }} className={selected?.title === clusterName ? 'selected' : ''} onClick={sel}>
              <td className="td-primary">{clusterName}</td>
              <td>{nodeRows.length || '—'}</td><td>{nsRows.length || '—'}</td>
              <td className="mono" style={{ fontSize: 11 }}>{k8sVersion}</td>
              <td><StatusDot type={sensorOnline ? 'active' : 'error'} label={sensorOnline ? 'Online' : 'Offline'} /></td>
              <td><StatusDot type={connected ? 'active' : 'warn'}     label={connected ? 'Online' : 'Offline'} /></td>
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
    <div className="card" style={{ marginTop: 16, marginRight: selected ? 0 : 24 }}>
      <div className="card-header">
        <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {nsDrill
            ? <><span style={{ color: 'var(--text-muted)', cursor: 'pointer' }} onClick={() => setNsDrill(null)}>Namespaces</span>
                <span style={{ color: 'var(--text-muted)' }}>›</span>
                <span>{nsDrill.name}</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400 }}>({nsDrill.pods.length} pods)</span></>
            : <>Namespaces ({nsRows.length})</>
          }
        </div>
        {!nsDrill && <FilterInput value={search} onChange={setSearch} />}
        {nsDrill  && <button onClick={() => setNsDrill(null)} style={{ fontSize: 11, padding: '3px 10px', borderRadius: 5, cursor: 'pointer', background: 'var(--bg-elevated)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}>← Back</button>}
      </div>
      <div className="table-wrap">
        {!nsDrill ? (
          <table className="data-table">
            <thead><tr><th>Namespace</th><th>Status</th><th>Pods</th><th>Live Events</th><th></th></tr></thead>
            <tbody>
              {nsRows.filter(r => !q || r.name.includes(q)).map(r => (
                <tr key={r.name} style={{ cursor: 'pointer' }} onClick={() => setNsDrill(r)}>
                  <td className="td-primary">{r.name}</td>
                  <td><StatusDot type="active" label="Active" /></td>
                  <td style={{ fontSize: 12, color: r.pods.length > 0 ? 'var(--text-primary)' : 'var(--text-muted)' }}>{r.pods.length}</td>
                  <td style={{ color: r.events > 0 ? 'var(--accent)' : 'var(--text-muted)', fontFamily: 'JetBrains Mono,monospace', fontSize: 12 }}>{r.events || '—'}</td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>→</td>
                </tr>
              ))}
              {!nsRows.length && <EmptyRow cols={5} msg="No namespaces" sensorOnline={sensorOnline} />}
            </tbody>
          </table>
        ) : (
          <table className="data-table">
            <thead><tr><th>Pod</th><th>Node</th><th>Images</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {nsDrill.pods.length === 0
                ? <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32, fontSize: 13 }}>No pods in this namespace</td></tr>
                : nsDrill.pods.map((p, i) => {
                    const phase  = p.status?.phase || 'Unknown';
                    const stType = phase === 'Running' ? 'active' : phase === 'Pending' ? 'warn' : 'error';
                    const images = (p.spec?.containers || []).map(c => c.image).filter(Boolean);
                    return (
                      <tr key={i} style={{ cursor: 'pointer' }} className={selected?.title === p.metadata?.name ? 'selected' : ''}
                        onClick={() => sel(p.metadata?.name, `Pod · ${nsDrill.name}`, p)}>
                        <td className="td-primary mono" style={{ fontSize: 12 }}>{p.metadata?.name}</td>
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{p.spec?.nodeName || '—'}</td>
                        <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{images.join(', ') || '—'}</td>
                        <td><StatusDot type={stType} label={phase} /></td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>→</td>
                      </tr>
                    );
                  })
              }
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export function NodesTab({ nodeRows, pods, q, search, setSearch, sensorOnline, selected, setSelected }) {
  const podsByNode = pods.reduce((acc, p) => { const n = p.spec?.nodeName; if (n) acc[n] = (acc[n]||0)+1; return acc; }, {});
  return (
    <div className="card" style={{ marginTop: 16, marginRight: selected ? 0 : 24 }}>
      <div className="card-header"><div className="card-title">Nodes ({nodeRows.length})</div><FilterInput value={search} onChange={setSearch} /></div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Node</th><th>Role</th><th>OS</th><th>Kernel</th><th>CPU</th><th>Memory</th><th>Pods</th><th>Live Events</th><th>Status</th></tr></thead>
          <tbody>
            {nodeRows.filter(n => !q || n.name.includes(q)).map(n => (
              <tr key={n.name} style={{ cursor: 'pointer' }} className={selected?.title === n.name ? 'selected' : ''}
                onClick={() => setSelected({ title: n.name, sub: `Node · ${n.info.operatingSystem || 'linux'}`, raw: Object.assign({ apiVersion: 'v1', kind: 'Node' }, n.raw) })}>
                <td className="td-primary">{n.name}</td>
                <td><KindBadge kind={n.role === 'control-plane' ? 'ClusterRole' : 'Role'} /></td>
                <td style={{ fontSize: 12 }}>{n.info.osImage || '—'}</td>
                <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{n.info.kernelVersion || '—'}</td>
                <td style={{ fontSize: 12 }}>{n.cpu}</td>
                <td style={{ fontSize: 12 }}>{n.mem}</td>
                <td style={{ fontSize: 12, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono,monospace' }}>{podsByNode[n.name] || 0}</td>
                <td style={{ color: n.events > 0 ? 'var(--accent)' : 'var(--text-muted)', fontFamily: 'JetBrains Mono,monospace', fontSize: 12 }}>{n.events || '—'}</td>
                <td><StatusDot type={n.st.type} label={n.st.label} /></td>
              </tr>
            ))}
            {!nodeRows.length && <EmptyRow cols={9} msg="No nodes found" sensorOnline={sensorOnline} />}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function WorkloadsTab({ workloadRows, q, search, setSearch, sensorOnline, selected, setSelected }) {
  return (
    <div className="card" style={{ marginTop: 16, marginRight: selected ? 0 : 24 }}>
      <div className="card-header"><div className="card-title">Workloads ({workloadRows.length})</div><FilterInput value={search} onChange={setSearch} /></div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Name</th><th>Kind</th><th>Namespace</th><th>Images</th><th>Ready</th><th></th></tr></thead>
          <tbody>
            {workloadRows.filter(w => !q || w.name.includes(q) || w.ns.includes(q) || w.kind.toLowerCase().includes(q)).map((w, i) => (
              <tr key={i} style={{ cursor: 'pointer' }} className={selected?.title === w.name ? 'selected' : ''}
                onClick={() => setSelected({ title: w.name, sub: `${w.kind} · ${w.ns}`, raw: Object.assign({ apiVersion: 'apps/v1', kind: w.kind }, w.raw) })}>
                <td className="td-primary">{w.name}</td>
                <td><KindBadge kind={w.kind} /></td>
                <td style={{ fontSize: 12 }}>{w.ns}</td>
                <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{w.images.join(', ') || '—'}</td>
                <td className="mono" style={{ fontSize: 12 }}>{w.ready}</td>
                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>→</td>
              </tr>
            ))}
            {!workloadRows.length && <EmptyRow cols={6} msg="No workloads found" sensorOnline={sensorOnline} />}
          </tbody>
        </table>
      </div>
    </div>
  );
}
