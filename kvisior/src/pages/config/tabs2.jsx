import { KindBadge, FilterInput, EmptyRow } from './cfgHelpers';

export function ServiceAccountsTab({ saRows, q, search, setSearch, sensorOnline, selected, setSelected }) {
  return (
    <div className="card" style={{ marginTop: 16, marginRight: selected ? 0 : 24 }}>
      <div className="card-header"><div className="card-title">Service Accounts ({saRows.length})</div><FilterInput value={search} onChange={setSearch} /></div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Name</th><th>Namespace</th><th>Bindings</th><th>Auto-mount Token</th><th></th></tr></thead>
          <tbody>
            {saRows.filter(s => !q || s.name.includes(q) || s.ns.includes(q)).map((s, i) => (
              <tr key={i} style={{ cursor: 'pointer' }} className={selected?.title === s.name + '@' + s.ns ? 'selected' : ''}
                onClick={() => setSelected({ title: s.name, sub: `ServiceAccount · ${s.ns}`, raw: Object.assign({ apiVersion: 'v1', kind: 'ServiceAccount' }, s.raw) })}>
                <td className="td-primary">{s.name}</td>
                <td style={{ fontSize: 12 }}>{s.ns}</td>
                <td style={{ fontSize: 12, color: s.bindings > 0 ? 'var(--accent)' : 'var(--text-muted)' }}>{s.bindings}</td>
                <td style={{ color: s.automount ? 'var(--danger)' : 'var(--accent-3)' }}>{s.automount ? '⚠ true' : '✓ false'}</td>
                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>→</td>
              </tr>
            ))}
            {!saRows.length && <EmptyRow cols={5} msg="No service accounts found" sensorOnline={sensorOnline} />}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function RolesTab({ roleRows, q, search, setSearch, sensorOnline, selected, setSelected }) {
  const kindColor = { ServiceAccount: 'var(--accent-3)', User: 'var(--accent)', Group: '#a78bfa' };
  return (
    <div className="card" style={{ marginTop: 16, marginRight: selected ? 0 : 24 }}>
      <div className="card-header"><div className="card-title">RBAC Roles &amp; ClusterRoles ({roleRows.length})</div><FilterInput value={search} onChange={setSearch} /></div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Name</th><th>Kind</th><th>Namespace</th><th>Rules</th><th>Bindings</th><th>Bound To</th><th>Wildcard</th><th></th></tr></thead>
          <tbody>
            {roleRows.filter(r => !q || r.name.includes(q) || r.ns.includes(q)).map((r, i) => (
              <tr key={i} style={{ cursor: 'pointer' }} className={selected?.title === r.name ? 'selected' : ''}
                onClick={() => setSelected({ title: r.name, sub: `${r.kind} · ${r.ns}`, raw: Object.assign({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: r.kind }, r.raw) })}>
                <td className="td-primary">{r.name}</td>
                <td><KindBadge kind={r.kind} /></td>
                <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{r.ns}</td>
                <td className="mono" style={{ fontSize: 12 }}>{r.rules}</td>
                <td style={{ fontSize: 12, color: r.bindings > 0 ? 'var(--accent)' : 'var(--text-muted)' }}>{r.bindings}</td>
                <td style={{ maxWidth: 200, overflow: 'hidden' }}>
                  {r.subjects.length === 0 ? <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
                    : <div style={{ display: 'flex', gap: 3, overflow: 'hidden' }}>
                        {r.subjects.slice(0, 2).map((s, si) => (
                          <span key={si} title={`${s.kind}: ${s.namespace ? s.namespace + '/' : ''}${s.name}`}
                            style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, flexShrink: 1,
                              background: 'rgba(0,0,0,.25)', minWidth: 0,
                              color: kindColor[s.kind] || 'var(--text-muted)',
                              fontFamily: 'JetBrains Mono,monospace', whiteSpace: 'nowrap',
                              overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 120 }}>
                            {s.name}
                          </span>
                        ))}
                        {r.subjects.length > 2 && <span style={{ fontSize: 10, color: 'var(--text-muted)', flexShrink: 0 }}>+{r.subjects.length - 2}</span>}
                      </div>
                  }
                </td>
                <td style={{ color: r.hasWildcard ? 'var(--danger)' : 'var(--accent-3)' }}>{r.hasWildcard ? '⚠ yes' : '—'}</td>
                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>→</td>
              </tr>
            ))}
            {!roleRows.length && <EmptyRow cols={8} msg="No roles found" sensorOnline={sensorOnline} />}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function SecretsTab({ secrets, SYS_NS, q, search, setSearch, sensorOnline, selected, setSelected }) {
  const visible = secrets.filter(s => !SYS_NS.has(s.namespace));
  return (
    <div className="card" style={{ marginTop: 16, marginRight: selected ? 0 : 24 }}>
      <div className="card-header"><div className="card-title">Secrets ({visible.length})</div><FilterInput value={search} onChange={setSearch} /></div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Name</th><th>Namespace</th><th>Type</th><th>Age</th></tr></thead>
          <tbody>
            {visible.filter(s => !q || s.name.includes(q) || s.namespace.includes(q)).map((s, i) => {
              const ageDays = s.created_at ? Math.floor((Date.now() - new Date(s.created_at)) / 86400000) : null;
              const age     = ageDays === null ? '—' : ageDays < 1 ? 'today' : ageDays + 'd';
              return (
                <tr key={i} style={{ cursor: 'pointer' }} className={selected?.title === s.name + '@' + s.namespace ? 'selected' : ''}
                  onClick={() => setSelected({ title: s.name, sub: `Secret · ${s.namespace}`, raw: { apiVersion: 'v1', kind: 'Secret', metadata: { name: s.name, namespace: s.namespace, labels: s.labels, creationTimestamp: s.created_at }, type: s.type, data: '<redacted>' } })}>
                  <td className="td-primary">{s.name}</td>
                  <td style={{ fontSize: 12 }}>{s.namespace}</td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{s.type}</td>
                  <td style={{ fontSize: 12, color: ageDays > 365 ? 'var(--warning)' : 'var(--text-muted)' }}>{age}</td>
                </tr>
              );
            })}
            {!visible.length && <EmptyRow cols={4} msg="No secrets found" sensorOnline={sensorOnline} />}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function CrdsTab({ crds, q, search, setSearch, sensorOnline, selected, setSelected }) {
  return (
    <div className="card" style={{ marginTop: 16, marginRight: selected ? 0 : 24 }}>
      <div className="card-header"><div className="card-title">Custom Resource Definitions ({crds.length})</div><FilterInput value={search} onChange={setSearch} /></div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Name</th><th>Group</th><th>Kind</th><th>Scope</th><th>Versions</th><th>Age</th></tr></thead>
          <tbody>
            {crds.length === 0 ? <EmptyRow cols={6} msg="No CRDs found — sensor may still be loading" sensorOnline={sensorOnline} />
              : crds.filter(c => !q || c.name?.toLowerCase().includes(q) || c.group?.toLowerCase().includes(q) || c.kind?.toLowerCase().includes(q))
                  .sort((a, b) => (a.group || '').localeCompare(b.group || '') || (a.kind || '').localeCompare(b.kind || ''))
                  .map((crd, i) => {
                    const age      = crd.created_at ? Math.floor((Date.now() - new Date(crd.created_at)) / 86400000) : null;
                    const ageStr   = age === null ? '—' : age < 1 ? 'today' : age + 'd';
                    const scope    = crd.scope || '—';
                    const scopeCol = scope === 'Cluster' ? 'var(--accent)' : 'var(--accent-3)';
                    return (
                      <tr key={i} style={{ cursor: 'pointer' }} className={selected?.title === crd.name ? 'selected' : ''}
                        onClick={() => setSelected({ title: crd.name, sub: `CRD · ${crd.group}`, raw: { apiVersion: 'apiextensions.k8s.io/v1', kind: 'CustomResourceDefinition', metadata: { name: crd.name, creationTimestamp: crd.created_at }, spec: { group: crd.group, scope: crd.scope, names: { kind: crd.kind, plural: crd.plural }, versions: (crd.versions || []).map(v => ({ name: v })) } } })}>
                        <td className="td-primary mono" style={{ fontSize: 11 }}>{crd.name}</td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{crd.group}</td>
                        <td style={{ fontSize: 12, fontWeight: 600 }}>{crd.kind}</td>
                        <td><span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, background: 'rgba(0,200,255,.08)', color: scopeCol, fontWeight: 600 }}>{scope}</span></td>
                        <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{(crd.versions || []).join(', ')}</td>
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{ageStr}</td>
                      </tr>
                    );
                  })
            }
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function StaticPodsTab({ staticPods, q, search, setSearch, sensorOnline, selected, setSelected }) {
  return (
    <div className="card" style={{ marginTop: 16, marginRight: selected ? 0 : 24 }}>
      <div className="card-header">
        <div className="card-title">
          Static &amp; Unmanaged Pods ({staticPods.length})
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400, marginLeft: 8 }}>— no Deployment / StatefulSet / DaemonSet controller</span>
        </div>
        <FilterInput value={search} onChange={setSearch} />
      </div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Name</th><th>Namespace</th><th>Node</th><th>Status</th><th>Age</th><th></th></tr></thead>
          <tbody>
            {staticPods.length === 0 ? <EmptyRow cols={6} msg="No static or unmanaged pods found" sensorOnline={sensorOnline} />
              : staticPods.filter(p => !q || p.metadata?.name?.toLowerCase().includes(q) || p.metadata?.namespace?.toLowerCase().includes(q) || p.spec?.nodeName?.toLowerCase().includes(q)).map((p, i) => {
                  const name  = p.metadata?.name || '';
                  const ns    = p.metadata?.namespace || '';
                  const node  = p.spec?.nodeName || '—';
                  const phase = p.status?.phase || 'Unknown';
                  const age   = p.metadata?.creationTimestamp ? Math.floor((Date.now() - new Date(p.metadata.creationTimestamp)) / 86400000) : null;
                  const ageStr = age === null ? '—' : age < 1 ? 'today' : age + 'd';
                  const phaseColor = { Running: 'var(--accent-3)', Pending: 'var(--warning)', Failed: 'var(--danger)', Succeeded: 'var(--text-muted)' }[phase] || 'var(--text-muted)';
                  return (
                    <tr key={i} style={{ cursor: 'pointer' }} className={selected?.title === name ? 'selected' : ''} onClick={() => setSelected({ title: name, sub: `Pod · ${ns}`, raw: p })}>
                      <td className="td-primary mono" style={{ fontSize: 11 }}>{name}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{ns}</td>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>{node}</td>
                      <td><span style={{ fontSize: 11, color: phaseColor, fontWeight: 500 }}>{phase}</span></td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{ageStr}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>→</td>
                    </tr>
                  );
                })
            }
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function WebhooksTab({ isMut, items, q, search, setSearch, sensorOnline, selected, setSelected }) {
  const label = isMut ? 'MutatingWebhookConfiguration' : 'ValidatingWebhookConfiguration';
  const color = isMut ? 'var(--warning)' : 'var(--accent)';
  const rows  = items.flatMap(cfg => (cfg.webhooks || []).map(wh => ({ cfg, wh })));

  return (
    <div className="card" style={{ marginTop: 16, marginRight: selected ? 0 : 24 }}>
      <div className="card-header">
        <div className="card-title">
          {isMut ? 'Mutating' : 'Validating'} Webhooks
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400, marginLeft: 8 }}>
            {items.length} config{items.length !== 1 ? 's' : ''} · {rows.length} webhook{rows.length !== 1 ? 's' : ''}
          </span>
        </div>
        <FilterInput value={search} onChange={setSearch} />
      </div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Configuration</th><th>Webhook Name</th><th>Namespace Selector</th><th>Failure Policy</th><th>Rules</th><th></th></tr></thead>
          <tbody>
            {rows.length === 0 ? <EmptyRow cols={7} msg={`No ${isMut ? 'mutating' : 'validating'} webhooks found`} sensorOnline={sensorOnline} />
              : rows.filter(({ cfg, wh }) => !q || cfg.metadata?.name?.toLowerCase().includes(q) || wh.name?.toLowerCase().includes(q)).map(({ cfg, wh }, i) => {
                  const failPol   = wh.failurePolicy || '—';
                  const failColor = failPol === 'Fail' ? 'var(--danger)' : 'var(--accent-3)';
                  const nsSelector = wh.namespaceSelector?.matchLabels
                    ? Object.entries(wh.namespaceSelector.matchLabels).map(([k, v]) => `${k}=${v}`).join(', ')
                    : wh.namespaceSelector?.matchExpressions?.length ? `${wh.namespaceSelector.matchExpressions.length} expr` : 'all';
                  return (
                    <tr key={i} style={{ cursor: 'pointer' }} className={selected?.title === cfg.metadata?.name + '/' + wh.name ? 'selected' : ''}
                      onClick={() => setSelected({ title: cfg.metadata?.name + '/' + wh.name, sub: `${label} · ${cfg.metadata?.name}`, raw: Object.assign({ apiVersion: 'admissionregistration.k8s.io/v1', kind: isMut ? 'MutatingWebhookConfiguration' : 'ValidatingWebhookConfiguration' }, cfg) })}>
                      <td className="td-primary mono" style={{ fontSize: 11 }}>{cfg.metadata?.name}</td>
                      <td style={{ fontSize: 11, color, fontFamily: 'JetBrains Mono,monospace' }}>{wh.name}</td>
                      <td className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={nsSelector}>{nsSelector}</td>
                      <td><span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, background: `${failColor}18`, color: failColor, fontWeight: 600 }}>{failPol}</span></td>
                      <td className="mono" style={{ fontSize: 12, color: (wh.rules || []).length > 0 ? 'var(--text-primary)' : 'var(--text-muted)' }}>{(wh.rules || []).length}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>→</td>
                    </tr>
                  );
                })
            }
          </tbody>
        </table>
      </div>
    </div>
  );
}
