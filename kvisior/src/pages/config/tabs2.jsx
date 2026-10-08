import { KindBadge, FilterInput, EmptyRow } from './cfgHelpers';
import { Tag, cx } from '../../components/kit';
import { Icon } from '../../components/Icon';
import { PagedWindow } from '../../components/PagedWindow';

const ageOf = ts => {
  if (!ts) return { days: null, label: '—' };
  const days = Math.floor((Date.now() - new Date(ts)) / 86400000);
  return { days, label: days < 1 ? 'today' : `${days}d` };
};

const SUBJECT_TONE = { ServiceAccount: 't-ok', User: 't-accent', Group: 't-violet' };
const PHASE_TONE = { Running: 't-ok', Pending: 't-warning', Failed: 't-danger' };

function Section({ title, meta, search, setSearch, children }) {
  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">{title}{meta && <span className="card-sub">{meta}</span>}</div>
        <FilterInput value={search} onChange={setSearch} />
      </div>
      {children}
    </div>
  );
}

const Open = () => <td className="t-muted"><Icon name="chevron-right" /></td>;

export function ServiceAccountsTab({ saRows, q, search, setSearch, sensorOnline, selected, setSelected }) {
  return (
    <Section title={`Service Accounts (${saRows.length})`} search={search} setSearch={setSearch}>
      <PagedWindow items={saRows.filter(s => !q || s.name.includes(q) || s.ns.includes(q))} storageKey="config.serviceaccounts" label="Service accounts" noun="accounts" resetKey={q}>{rows => (
        <table className="data-table">
          <thead><tr><th>Name</th><th>Namespace</th><th>Bindings</th><th>Auto-mount Token</th><th aria-label="Open" /></tr></thead>
          <tbody>
            {rows.map((s, i) => (
              <tr key={i} className={selected?.title === s.name + '@' + s.ns ? 'selected' : ''}
                onClick={() => setSelected({ title: s.name, sub: `ServiceAccount · ${s.ns}`, raw: Object.assign({ apiVersion: 'v1', kind: 'ServiceAccount' }, s.raw) })}>
                <td className="td-primary">{s.name}</td>
                <td className="t-sm">{s.ns}</td>
                <td className={cx('t-sm', s.bindings > 0 ? 't-accent' : 't-muted')}>{s.bindings}</td>
                <td className={s.automount ? 't-danger' : 't-ok'}>
                  <span className="ic-label">{s.automount ? <><Icon name="alert" /> true</> : <><Icon name="check" /> false</>}</span>
                </td>
                <Open />
              </tr>
            ))}
            {!saRows.length && <EmptyRow cols={5} msg="No service accounts found" sensorOnline={sensorOnline} />}
          </tbody>
        </table>
      )}</PagedWindow>
    </Section>
  );
}

export function RolesTab({ roleRows, q, search, setSearch, sensorOnline, selected, setSelected }) {
  return (
    <Section title={<>RBAC Roles &amp; ClusterRoles ({roleRows.length})</>} search={search} setSearch={setSearch}>
      <PagedWindow items={roleRows.filter(r => !q || r.name.includes(q) || r.ns.includes(q))} storageKey="config.roles" label="Roles" noun="roles" resetKey={q}>{rows => (
        <table className="data-table">
          <thead><tr><th>Name</th><th>Kind</th><th>Namespace</th><th>Rules</th><th>Bindings</th><th>Bound To</th><th>Wildcard</th><th aria-label="Open" /></tr></thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className={selected?.title === r.name ? 'selected' : ''}
                onClick={() => setSelected({ title: r.name, sub: `${r.kind} · ${r.ns}`, raw: Object.assign({ apiVersion: 'rbac.authorization.k8s.io/v1', kind: r.kind }, r.raw) })}>
                <td className="td-primary">{r.name}</td>
                <td><KindBadge kind={r.kind} /></td>
                <td className="t-sm t-muted">{r.ns}</td>
                <td className="mono t-sm">{r.rules}</td>
                <td className={cx('t-sm', r.bindings > 0 ? 't-accent' : 't-muted')}>{r.bindings}</td>
                <td>
                  {r.subjects.length === 0
                    ? <span className="t-muted">—</span>
                    : <span className="row row--tight subjects">
                        {r.subjects.slice(0, 2).map((s, si) => (
                          <span key={si} className={cx('badge clip', SUBJECT_TONE[s.kind])} title={`${s.kind}: ${s.namespace ? s.namespace + '/' : ''}${s.name}`}>{s.name}</span>
                        ))}
                        {r.subjects.length > 2 && <span className="t-2xs t-muted">+{r.subjects.length - 2}</span>}
                      </span>}
                </td>
                <td className={r.hasWildcard ? 't-danger' : 't-ok'}>{r.hasWildcard ? <span className="ic-label"><Icon name="alert" /> yes</span> : '—'}</td>
                <Open />
              </tr>
            ))}
            {!roleRows.length && <EmptyRow cols={8} msg="No roles found" sensorOnline={sensorOnline} />}
          </tbody>
        </table>
      )}</PagedWindow>
    </Section>
  );
}

export function SecretsTab({ secrets, SYS_NS, q, search, setSearch, sensorOnline, selected, setSelected }) {
  const visible = secrets.filter(s => !SYS_NS.has(s.namespace));
  return (
    <Section title={`Secrets (${visible.length})`} search={search} setSearch={setSearch}>
      <PagedWindow items={visible.filter(s => !q || s.name.includes(q) || s.namespace.includes(q))} storageKey="config.secrets" label="Secrets" noun="secrets" resetKey={q}>{rows => (
        <table className="data-table">
          <thead><tr><th>Name</th><th>Namespace</th><th>Type</th><th>Age</th></tr></thead>
          <tbody>
            {rows.map((s, i) => {
              const age = ageOf(s.created_at);
              return (
                <tr key={i} className={selected?.title === s.name + '@' + s.namespace ? 'selected' : ''}
                  onClick={() => setSelected({ title: s.name, sub: `Secret · ${s.namespace}`, raw: { apiVersion: 'v1', kind: 'Secret', metadata: { name: s.name, namespace: s.namespace, labels: s.labels, creationTimestamp: s.created_at }, type: s.type, data: '<redacted>' } })}>
                  <td className="td-primary">{s.name}</td>
                  <td className="t-sm">{s.namespace}</td>
                  <td className="t-xs t-muted">{s.type}</td>
                  <td className={cx('t-sm', age.days > 365 ? 't-warning' : 't-muted')}>{age.label}</td>
                </tr>
              );
            })}
            {!visible.length && <EmptyRow cols={4} msg="No secrets found" sensorOnline={sensorOnline} />}
          </tbody>
        </table>
      )}</PagedWindow>
    </Section>
  );
}

export function CrdsTab({ crds, q, search, setSearch, sensorOnline, selected, setSelected }) {
  const items = crds
    .filter(c => !q || c.name?.toLowerCase().includes(q) || c.group?.toLowerCase().includes(q) || c.kind?.toLowerCase().includes(q))
    .sort((a, b) => (a.group || '').localeCompare(b.group || '') || (a.kind || '').localeCompare(b.kind || ''));
  return (
    <Section title={`Custom Resource Definitions (${crds.length})`} search={search} setSearch={setSearch}>
      <PagedWindow items={items} storageKey="config.crds" label="CRDs" noun="CRDs" resetKey={q}>{rows => (
        <table className="data-table">
          <thead><tr><th>Name</th><th>Group</th><th>Kind</th><th>Scope</th><th>Versions</th><th>Age</th></tr></thead>
          <tbody>
            {crds.length === 0
              ? <EmptyRow cols={6} msg="No CRDs found — sensor may still be loading" sensorOnline={sensorOnline} />
              : rows.map((crd, i) => {
                  const scope = crd.scope || '—';
                  return (
                    <tr key={i} className={selected?.title === crd.name ? 'selected' : ''}
                      onClick={() => setSelected({ title: crd.name, sub: `CRD · ${crd.group}`, raw: { apiVersion: 'apiextensions.k8s.io/v1', kind: 'CustomResourceDefinition', metadata: { name: crd.name, creationTimestamp: crd.created_at }, spec: { group: crd.group, scope: crd.scope, names: { kind: crd.kind, plural: crd.plural }, versions: (crd.versions || []).map(v => ({ name: v })) } } })}>
                      <td className="td-primary mono t-xs">{crd.name}</td>
                      <td className="t-xs t-muted">{crd.group}</td>
                      <td className="t-sm t-strong">{crd.kind}</td>
                      <td><Tag tone={scope === 'Cluster' ? 'accent' : 'ok'}>{scope}</Tag></td>
                      <td className="mono t-xs t-muted">{(crd.versions || []).join(', ')}</td>
                      <td className="t-sm t-muted">{ageOf(crd.created_at).label}</td>
                    </tr>
                  );
                })}
          </tbody>
        </table>
      )}</PagedWindow>
    </Section>
  );
}

export function StaticPodsTab({ staticPods, q, search, setSearch, sensorOnline, selected, setSelected }) {
  const items = staticPods.filter(p => !q || p.metadata?.name?.toLowerCase().includes(q) || p.metadata?.namespace?.toLowerCase().includes(q) || p.spec?.nodeName?.toLowerCase().includes(q));
  return (
    <Section title={<>Static &amp; Unmanaged Pods ({staticPods.length})</>} meta="no Deployment / StatefulSet / DaemonSet controller" search={search} setSearch={setSearch}>
      <PagedWindow items={items} storageKey="config.staticpods" label="Static pods" noun="pods" resetKey={q}>{rows => (
        <table className="data-table">
          <thead><tr><th>Name</th><th>Namespace</th><th>Node</th><th>Status</th><th>Age</th><th aria-label="Open" /></tr></thead>
          <tbody>
            {staticPods.length === 0
              ? <EmptyRow cols={6} msg="No static or unmanaged pods found" sensorOnline={sensorOnline} />
              : rows.map((p, i) => {
                  const name  = p.metadata?.name || '';
                  const ns    = p.metadata?.namespace || '';
                  const phase = p.status?.phase || 'Unknown';
                  return (
                    <tr key={i} className={selected?.title === name ? 'selected' : ''} onClick={() => setSelected({ title: name, sub: `Pod · ${ns}`, raw: p })}>
                      <td className="td-primary mono t-xs">{name}</td>
                      <td className="t-sm t-muted">{ns}</td>
                      <td className="mono t-xs t-muted">{p.spec?.nodeName || '—'}</td>
                      <td className={cx('t-xs t-medium', PHASE_TONE[phase] || 't-muted')}>{phase}</td>
                      <td className="t-sm t-muted">{ageOf(p.metadata?.creationTimestamp).label}</td>
                      <Open />
                    </tr>
                  );
                })}
          </tbody>
        </table>
      )}</PagedWindow>
    </Section>
  );
}

export function WebhooksTab({ isMut, items, q, search, setSearch, sensorOnline, selected, setSelected }) {
  const label = isMut ? 'MutatingWebhookConfiguration' : 'ValidatingWebhookConfiguration';
  const all = items.flatMap(cfg => (cfg.webhooks || []).map(wh => ({ cfg, wh })));
  const filtered = all.filter(({ cfg, wh }) => !q || cfg.metadata?.name?.toLowerCase().includes(q) || wh.name?.toLowerCase().includes(q));

  return (
    <Section
      title={`${isMut ? 'Mutating' : 'Validating'} Webhooks`}
      meta={`${items.length} config${items.length !== 1 ? 's' : ''} · ${all.length} webhook${all.length !== 1 ? 's' : ''}`}
      search={search} setSearch={setSearch}
    >
      <PagedWindow items={filtered} storageKey="config.webhooks" label="Webhooks" noun="webhooks" resetKey={`${isMut}|${q}`}>{rows => (
        <table className="data-table">
          <thead><tr><th>Configuration</th><th>Webhook Name</th><th>Namespace Selector</th><th>Failure Policy</th><th>Rules</th><th aria-label="Open" /></tr></thead>
          <tbody>
            {rows.length === 0
              ? <EmptyRow cols={6} msg={`No ${isMut ? 'mutating' : 'validating'} webhooks found`} sensorOnline={sensorOnline} />
              : rows.map(({ cfg, wh }, i) => {
                  const failPol = wh.failurePolicy || '—';
                  const nsSelector = wh.namespaceSelector?.matchLabels
                    ? Object.entries(wh.namespaceSelector.matchLabels).map(([k, v]) => `${k}=${v}`).join(', ')
                    : wh.namespaceSelector?.matchExpressions?.length ? `${wh.namespaceSelector.matchExpressions.length} expr` : 'all';
                  return (
                    <tr key={i} className={selected?.title === cfg.metadata?.name + '/' + wh.name ? 'selected' : ''}
                      onClick={() => setSelected({ title: cfg.metadata?.name + '/' + wh.name, sub: `${label} · ${cfg.metadata?.name}`, raw: Object.assign({ apiVersion: 'admissionregistration.k8s.io/v1', kind: label }, cfg) })}>
                      <td className="td-primary mono t-xs">{cfg.metadata?.name}</td>
                      <td className={cx('mono t-xs', isMut ? 't-warning' : 't-accent')}>{wh.name}</td>
                      <td className="mono t-2xs t-muted clip clip--md" title={nsSelector}>{nsSelector}</td>
                      <td><Tag tone={failPol === 'Fail' ? 'danger' : 'ok'}>{failPol}</Tag></td>
                      <td className={cx('mono t-sm', (wh.rules || []).length > 0 ? 't-primary' : 't-muted')}>{(wh.rules || []).length}</td>
                      <Open />
                    </tr>
                  );
                })}
          </tbody>
        </table>
      )}</PagedWindow>
    </Section>
  );
}
