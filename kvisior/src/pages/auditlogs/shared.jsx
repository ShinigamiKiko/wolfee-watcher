import { useState } from 'react';

export const KINDS = ['create', 'update', 'delete', 'exec', 'attach', 'portforward', 'get', 'list'];
export const READ_KINDS = ['get', 'list'];
export const RESOURCES = [
  'clusterrolebindings', 'clusterroles', 'configmaps', 'cronjobs', 'daemonsets', 'deployments', 'jobs',
  'mutatingwebhookconfigurations', 'namespaces', 'nodes', 'pods', 'replicasets', 'rolebindings', 'roles',
  'secrets', 'serviceaccounts', 'statefulsets', 'validatingwebhookconfigurations',
];
export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

const pad = n => String(n).padStart(2, '0');
export const fmtTime = ts => { const d = new Date(ts); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
export const fmtDate = ts => { const d = new Date(ts); return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${fmtTime(ts)}`; };
export const num = n => Number(n || 0).toLocaleString('en-US');

export function objText(ev) {
  if (ev.name) return `${ev.resource}/${ev.ns ? ev.ns + '/' : ''}${ev.name}`;
  return `${ev.resource}${ev.ns ? ' in ' + ev.ns : ''}`;
}

export function normalizeEvent(raw, row) {
  const data = raw || {};
  const ts = row?.ts || data.timestamp;
  const sev = (row?.sev || data.sev || '').toLowerCase();
  const chain = data.sourceIPs || [];
  const ip = data.clientIP || chain[chain.length - 1] || '';
  const at = ip ? chain.lastIndexOf(ip) : -1;
  const ipClaims = at > 0 ? chain.slice(0, at).filter(a => a !== ip) : [];
  return {
    key: row?.id != null ? `db-${row.id}` : `live-${data.id}`,
    uid: data.id || '',
    ts: ts ? new Date(ts).getTime() : Date.now(),
    kind: data.kind || '',
    resource: data.resource || '',
    ns: data.namespace || '',
    name: data.name || '',
    user: data.user || '',
    actedAs: data.impersonatedUser || '',
    unconfirmedAuthor: data.attribution === 'unconfirmed',
    actedAsGroups: data.impersonatedGroups || [],
    groups: data.groups || [],
    ip,
    ipChain: chain,
    ipClaims,
    agent: data.userAgent || '',
    allowed: typeof data.allowed === 'boolean' ? data.allowed : null,
    status: data.statusCode || 0,
    origin: row?.origin || (data.source === 'apiserver-log' ? 'apilog' : data.sourceIPs ? 'both' : 'admission'),
    ruleId: row?.ruleId || data.ruleId || '',
    ruleName: data.ruleName || '',
    sev,
    dryRun: !!data.dryRun,
    unchanged: !!data.unchanged,
    container: data.container || '',
    commands: data.commands || null,
    ports: data.ports || null,
    raw: data,
  };
}

export const isDanger = ev => !!ev.ruleId || ev.allowed === false;

export function rowClass(ev) {
  if (SEV_RANK[ev.sev] >= 3) return 'al-row-high';
  if (ev.sev === 'medium' || ev.allowed === false) return 'al-row-medium';
  return '';
}

export function UserCell({ user }) {
  const m = /^system:serviceaccount:([^:]+):(.+)$/.exec(user || '');
  if (!m) return user || <span className="al-empty">unknown</span>;
  return <><span className="al-kind">SA</span> {m[1]}/{m[2]}</>;
}

export const Empty = ({ children = 'not recorded' }) => (
  <span className="al-empty" title="No kube-apiserver record matched">{children}</span>
);

export function RuleTag({ ev, ruleNames }) {
  const name = ev.ruleName || ruleNames?.[ev.ruleId] || ev.ruleId;
  return (
    <>
      {ev.ruleId && <span className={`al-tag al-tag-${ev.sev || 'low'}`}>{name}</span>}
      {ev.allowed === false && <span className="al-tag al-tag-denied">denied{ev.status ? ` ${ev.status}` : ''}</span>}
      {ev.dryRun
        ? <span className="al-tag" title="A dry-run request: the API server validated it and changed nothing">dry run</span>
        : ev.unchanged && <span className="al-tag" title="The request succeeded and the object stayed as it was">no change</span>}
    </>
  );
}

export function EventTable({ events, selectedKey, onSelect, withDate, ruleNames, freshKeys, emptyText }) {
  return (
    <table className="data-table al-events">
      <thead>
        <tr><th>Time</th><th>Action</th><th>Object</th><th>User</th><th>Source IP</th><th>Rule and result</th></tr>
      </thead>
      <tbody>
        {events.length === 0 && (
          <tr className="al-norow"><td colSpan={6}><div className="al-blank">{emptyText}</div></td></tr>
        )}
        {events.map(ev => (
          <tr key={ev.key}
              className={[rowClass(ev), selectedKey === ev.key ? 'selected' : '', freshKeys?.has(ev.key) ? 'al-row-new' : ''].join(' ')}
              tabIndex={0}
              onClick={() => onSelect(ev)}
              onKeyDown={e => { if (e.key === 'Enter') onSelect(ev); }}>
            <td className="al-mono">{withDate ? fmtDate(ev.ts) : fmtTime(ev.ts)}</td>
            <td><span className={`al-kind al-kind-${ev.kind}`}>{ev.kind}</span></td>
            <td className="al-mono al-clip al-obj" title={objText(ev)}>{objText(ev)}</td>
            <td className="al-clip al-usr" title={ev.actedAs ? `${ev.user}, acting as ${ev.actedAs}` : ev.user}>
              <UserCell user={ev.user} />{ev.actedAs && <span className="al-dim"> as {ev.actedAs}</span>}
            </td>
            <td className="al-mono">{ev.ip || <Empty />}</td>
            <td className="al-flags">
              {ev.ipClaims?.length > 0 && <span className="al-tag al-tag-high" title={`The client set X-Forwarded-For: ${ev.ipClaims.join(', ')}`}>XFF</span>}
              {ev.unconfirmedAuthor && <span className="al-tag al-tag-medium" title="The author was matched to this change by time only, and another request on the same object fits as well">Author?</span>}
              <RuleTag ev={ev} ruleNames={ruleNames} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const ORIGIN_LABEL = {
  both: 'Admission webhook, matched to an API log record',
  admission: 'Admission webhook only',
  apilog: 'API log only',
};

const SUBTABS = [['summary', 'Summary'], ['object', 'Object'], ['api', 'API record'], ['raw', 'Raw']];

function objectLines(ev) {
  const lines = [];
  const add = (k, v) => { if (v !== '' && v != null) lines.push(`${k}: ${v}`); };
  add('resource', ev.resource);
  add('namespace', ev.ns);
  add('name', ev.name);
  add('uid', ev.raw.uid);
  add('resourceVersion', ev.raw.resourceVersion);
  add('webhookType', ev.raw.webhookType);
  add('container', ev.container);
  if (ev.commands?.length) lines.push('command:', ...ev.commands.map(c => `  - ${c}`));
  if (ev.ports?.length) lines.push('ports:', ...ev.ports.map(p => `  - ${p}`));
  return lines.join('\n');
}

export function EventDetail({ ev, ruleNames, apiLogConnected, onInvestigate, onCreateRule, onSilence, canEdit }) {
  const [sub, setSub] = useState('summary');
  if (!ev) {
    return <aside className="al-pane"><div className="al-blank">Select an event to see who did it, from where, and what changed.</div></aside>;
  }
  const copy = () => navigator.clipboard?.writeText(JSON.stringify(ev.raw, null, 2)).catch(() => {});
  return (
    <aside className="al-pane">
      <div className="al-pane-head">
        <div className="al-pane-title"><span className={`al-kind al-kind-${ev.kind}`}>{ev.kind}</span> {ev.name || ev.resource}</div>
        <div className="al-pane-sub al-mono">{objText(ev)}</div>
      </div>
      <div className="al-subtabs" role="tablist">
        {SUBTABS.map(([id, label]) => (
          <button key={id} role="tab" aria-selected={sub === id} className={`al-subtab${sub === id ? ' active' : ''}`} onClick={() => setSub(id)}>{label}</button>
        ))}
      </div>
      <div className="al-pane-body">
        {sub === 'summary' && (
          <>
            <dl className="al-kv">
              <dt>Time</dt><dd className="al-mono">{fmtDate(ev.ts)}</dd>
              <dt>User</dt><dd>{ev.user && ev.user !== 'unknown' ? ev.user : <Empty>unknown</Empty>}</dd>
              {ev.unconfirmedAuthor && <><dt>Author</dt><dd title="Without RequestResponse audit logging the change is linked to a request by time. Several requests on this object fit, so the user above may be wrong">
                <span className="al-tag al-tag-medium">unconfirmed</span><span className="al-dim"> matched by time, several requests fit</span>
              </dd></>}
              {ev.actedAs && <><dt>Acted as</dt><dd title="The request was made with impersonation; User is who actually authenticated">
                <span className="al-mono">{ev.actedAs}</span>
                {ev.actedAsGroups.length > 0 && <span className="al-dim"> in {ev.actedAsGroups.join(', ')}</span>}
              </dd></>}
              <dt>Groups</dt><dd className="al-dim">{ev.groups.length ? ev.groups.join(', ') : '—'}</dd>
              <dt>Source IP</dt><dd className="al-mono">{ev.ip || <Empty />}</dd>
              {ev.ipClaims?.length > 0 && <><dt>Spoofed by client</dt>
                <dd title="The client put these addresses into X-Forwarded-For or X-Real-IP. Rules and the Source IP above ignore them">
                  <span className="al-tag al-tag-high">X-Forwarded-For</span><span className="al-mono">{ev.ipClaims.join(', ')}</span>
                </dd></>}
              {ev.ipChain.length > 1 && <><dt>Reported chain</dt>
                <dd className="al-mono al-dim" title="Everything the API server recorded for this request. Addresses before the last come from the X-Forwarded-For header, which the client can set, so rules use only the one above">{ev.ipChain.join(' → ')}</dd></>}
              <dt>Client</dt><dd className="al-mono">{ev.agent || <Empty />}</dd>
              <dt>Result</dt><dd>{ev.allowed == null ? <Empty>not recorded</Empty> : ev.allowed ? 'allowed' : <span className="al-tag al-tag-denied">denied{ev.status ? ` ${ev.status}` : ''}</span>}</dd>
              <dt>Rule</dt><dd>{ev.ruleId ? <RuleTag ev={{ ...ev, allowed: true }} ruleNames={ruleNames} /> : <span className="al-dim">no rule matched</span>}</dd>
              <dt>Source</dt><dd>{ORIGIN_LABEL[ev.origin] || ev.origin}</dd>
            </dl>
            <div className="al-pane-actions">
              <button className="btn btn-outline al-btn-sm" onClick={() => onInvestigate(ev)}>Investigate this user</button>
              {canEdit && <button className="btn btn-outline al-btn-sm" onClick={() => onCreateRule(ev)}>Create rule from event</button>}
              {canEdit && onSilence && <button className="btn btn-outline al-btn-sm" onClick={() => onSilence(ev)}>Silence events like this</button>}
            </div>
          </>
        )}
        {sub === 'object' && <pre className="al-code">{objectLines(ev)}</pre>}
        {sub === 'api' && (ev.origin === 'admission'
          ? <div className="al-blank">{apiLogConnected
              ? 'No kube-apiserver record matched this change yet, so source IP and client are empty.'
              : 'This cluster has no kube-apiserver audit log connected, so source IP and client stay empty.'}</div>
          : <pre className="al-code">{JSON.stringify({
              auditID: ev.raw.auditID, sourceIPs: ev.raw.sourceIPs, clientIP: ev.ip || undefined, userAgent: ev.raw.userAgent,
              responseStatus: ev.status || undefined, allowed: ev.allowed,
            }, null, 2)}</pre>)}
        {sub === 'raw' && (
          <>
            <pre className="al-code">{JSON.stringify(ev.raw, null, 2)}</pre>
            <div className="al-pane-actions"><button className="btn btn-outline al-btn-sm" onClick={copy}>Copy JSON</button></div>
          </>
        )}
      </div>
    </aside>
  );
}
