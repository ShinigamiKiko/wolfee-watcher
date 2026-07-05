import { useState, useMemo, useEffect, useRef } from 'react';
import '../../styles/rbac/rbac.scss';
import { useSensor } from '../../context/SensorContext';

const W  = (rule, v) => rule.verbs      && (rule.verbs.includes('*')     || rule.verbs.includes(v));
const R  = (rule, r) => rule.resources  && (rule.resources.includes('*') || rule.resources.includes(r));
const SR = (rule, s) => rule.resources  && rule.resources.some(x => x==='*' || x===s || x.endsWith('/*'));
const AG = (rule, g) => !rule.apiGroups || rule.apiGroups.includes('*')  || rule.apiGroups.includes(g);
const any = (rules, fn) => (rules || []).some(fn);

const POLICIES = [
  { id:'approve_csrs',       sev:'Critical', desc:'Can approve CSRs - creates new client certificates for cluster access',
    match: r => any(r,x=>W(x,'create')&&SR(x,'certificatesigningrequests')&&AG(x,'certificates.k8s.io')) &&
                any(r,x=>(W(x,'update')||W(x,'patch'))&&SR(x,'certificatesigningrequests/approval')&&AG(x,'certificates.k8s.io')) },
  { id:'escalate_roles',     sev:'Critical', desc:'escalate verb on roles - bypasses RBAC privilege escalation prevention',
    match: r => any(r,x=>W(x,'escalate')&&(R(x,'roles')||R(x,'clusterroles'))&&AG(x,'rbac.authorization.k8s.io')) },
  { id:'bind_roles',         sev:'Critical', desc:'bind verb on ClusterRoles - self-grant any permission in cluster',
    match: r => any(r,x=>W(x,'bind')&&(R(x,'clusterroles')||R(x,'roles'))&&AG(x,'rbac.authorization.k8s.io')) },
  { id:'impersonate',        sev:'Critical', desc:'impersonate users/groups/SAs - gains any identity permissions',
    match: r => any(r,x=>W(x,'impersonate')&&(R(x,'users')||R(x,'groups')||R(x,'serviceaccounts'))&&AG(x,'')) },
  { id:'rce_privileged',     sev:'Critical', desc:'pods/exec or pods/attach - direct RCE with admin-level SA tokens',
    match: r => any(r,x=>(W(x,'create')||W(x,'get'))&&(SR(x,'pods/exec')||SR(x,'pods/attach'))&&AG(x,'')) },
  { id:'nodes_proxy',        sev:'High',     desc:'nodes/proxy subresource - execute code on pods via Kubelet API',
    match: r => any(r,x=>W(x,'create')&&SR(x,'nodes/proxy')&&AG(x,'')) },
  { id:'token_request',      sev:'High',     desc:'serviceaccounts/token - obtain SA tokens without pod creation',
    match: r => any(r,x=>W(x,'create')&&SR(x,'serviceaccounts/token')&&AG(x,'')) },
  { id:'read_secrets',       sev:'High',     desc:'get/list secrets - access to credentials, API keys, TLS certs',
    match: r => any(r,x=>(W(x,'get')||W(x,'list'))&&R(x,'secrets')&&AG(x,'')) },
  { id:'create_rolebindings',sev:'High',     desc:'create RoleBindings - grant arbitrary roles to any subject',
    match: r => any(r,x=>W(x,'create')&&(R(x,'rolebindings')||R(x,'clusterrolebindings'))&&AG(x,'rbac.authorization.k8s.io')) },
  { id:'modify_pods',        sev:'High',     desc:'update/patch pods - inject containers into running workloads',
    match: r => any(r,x=>(W(x,'update')||W(x,'patch'))&&R(x,'pods')&&AG(x,'')) },
  { id:'steal_pods',         sev:'High',     desc:'delete pods + cordon nodes - force powerful pods onto compromised node',
    match: r => any(r,x=>W(x,'delete')&&R(x,'pods')&&AG(x,'')) && any(r,x=>(W(x,'update')||W(x,'patch'))&&R(x,'nodes')&&AG(x,'')) },
  { id:'rce_exec',           sev:'High',     desc:'pods/exec - code execution, lateral movement',
    match: r => any(r,x=>(W(x,'create')||W(x,'get'))&&SR(x,'pods/exec')&&AG(x,'')) },
  { id:'modify_node_status', sev:'Medium',   desc:'update nodes/status - affects cluster-wide scheduling decisions',
    match: r => any(r,x=>(W(x,'update')||W(x,'patch'))&&SR(x,'nodes/status')&&AG(x,'')) },
  { id:'modify_svc_status',  sev:'Medium',   desc:'update services/status (CVE-2020-8554) - potential MITM on cluster traffic',
    match: r => any(r,x=>(W(x,'update')||W(x,'patch'))&&SR(x,'services/status')&&AG(x,'')) },
  { id:'create_pods',        sev:'Medium',   desc:'create pods - may mount host paths, access node resources',
    match: r => any(r,x=>W(x,'create')&&R(x,'pods')&&AG(x,'')) },
  { id:'create_clusterroles',sev:'Medium',   desc:'create/modify ClusterRoles - define overpermissive roles for later binding',
    match: r => any(r,x=>(W(x,'create')||W(x,'update')||W(x,'patch'))&&R(x,'clusterroles')&&AG(x,'rbac.authorization.k8s.io')) },
  { id:'wildcard_verb',      sev:'Low',      desc:'wildcard verb (*) - grants all current and future verbs on resource',
    match: r => any(r,x=>x.verbs&&x.verbs.includes('*')&&x.resources&&!x.resources.includes('*')) },
  { id:'list_secrets',       sev:'Low',      desc:'list/watch secrets - reveals secret names and metadata',
    match: r => any(r,x=>(W(x,'list')||W(x,'watch'))&&R(x,'secrets')&&AG(x,'')) },
];

const SEV_ORDER       = { Critical:0, High:1, Medium:2, Low:3 };
const DANGER_VERBS    = new Set(['*','create','delete','deletecollection','update','patch','escalate','bind','impersonate']);
const SENSITIVE_RES   = new Set(['*','secrets','serviceaccounts','nodes','clusterroles','clusterrolebindings']);

function evaluate(rawRules) {
  const rules = (rawRules || []).map(rl => ({
    verbs:     rl.verbs      || [],
    resources: rl.resources  || [],
    apiGroups: rl.api_groups || rl.apiGroups || [''],
  }));
  const hits = POLICIES.filter(p => p.match(rules));
  const sev  = ['Critical','High','Medium','Low'].find(s => hits.some(h => h.sev === s)) || null;
  return { sev, hits };
}

function roleName(r) { return r?.name || r?.metadata?.name || ''; }
function roleNS(r)   { return r?.namespace || r?.metadata?.namespace || ''; }
function getRoleRefName(b) {
  const ref = b?.role_ref || b?.roleRef || {};
  return ref.name || ref.Name || '';
}
function getSubjects(b) {
  return (b?.subjects || []).map(s => ({ kind: s.kind||s.Kind||'', name: s.name||s.Name||'' }));
}

function SubjectChip({ kind, name }) {
  const cls = kind === 'ServiceAccount' ? 'rbac-subj rbac-subj--sa'
            : kind === 'Group'          ? 'rbac-subj rbac-subj--group'
            :                            'rbac-subj rbac-subj--user';
  const prefix = kind === 'ServiceAccount' ? 'sa:' : kind === 'Group' ? 'grp:' : '';
  return <span className={cls}>{prefix}{name}</span>;
}

function SevBadge({ sev, hits }) {
  const cls = !sev             ? 'rbac-sev rbac-sev--ok'
    : sev === 'Critical'       ? 'rbac-sev rbac-sev--critical'
    : sev === 'High'           ? 'rbac-sev rbac-sev--high'
    : sev === 'Medium'         ? 'rbac-sev rbac-sev--medium'
    :                            'rbac-sev rbac-sev--low';
  const tooltip = hits.length
    ? hits.map(h => `[${h.sev}] ${h.desc}`).join('\n')
    : 'No policy violations';
  return <span className={cls} title={tooltip}>{sev || 'OK'}</span>;
}

const VERB_DOCS = [
  { verb: 'get',              desc: 'Read a single resource by name' },
  { verb: 'list',             desc: 'List all resources of a type' },
  { verb: 'watch',            desc: 'Stream changes to resources in real time' },
  { verb: 'create',           desc: 'Create a new resource' },
  { verb: 'update',           desc: 'Replace an existing resource (full update)' },
  { verb: 'patch',            desc: 'Partially modify an existing resource' },
  { verb: 'delete',           desc: 'Delete a single resource' },
  { verb: 'deletecollection', desc: 'Delete ALL resources of a type at once — bulk wipe' },
  { verb: 'use',              desc: 'Use a PodSecurityPolicy or StorageClass' },
  { verb: 'bind',             desc: 'Bind a Role/ClusterRole to subjects — grants arbitrary permissions' },
  { verb: 'escalate',         desc: 'Create roles with more permissions than you currently have — bypasses RBAC protection' },
  { verb: 'impersonate',      desc: 'Act as another user, group, or service account — gains their full permissions' },
  { verb: 'approve',          desc: 'Approve Certificate Signing Requests — issues new cluster client certificates' },
  { verb: 'sign',             desc: 'Sign Certificate Signing Requests' },
  { verb: 'attest',           desc: 'Attest a Certificate Signing Request' },
  { verb: '*',                desc: 'Wildcard — grants ALL current and future verbs on the resource' },
];

const DANGER_SET = new Set(['*','create','delete','deletecollection','update','patch','escalate','bind','impersonate','approve']);

function VerbsHelp() {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <div className="rbac-help" ref={ref}>
      <button className="rbac-help-btn" onClick={() => setOpen(v => !v)}>
        ? verbs
      </button>
      {open && (
        <div className="rbac-help-drop">
          <div className="rbac-help-title">Kubernetes verbs</div>
          <table className="rbac-help-table">
            <tbody>
              {VERB_DOCS.map(({ verb, desc }) => (
                <tr key={verb}>
                  <td className="rbac-help-verb">{verb}</td>
                  <td className="rbac-help-desc">{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function RuleTable({ rules }) {
  return (
    <div className="rbac-rules">
      {(rules || []).map((rl, i) => {
        const verbs    = rl.verbs     || [];
        const res      = rl.resources || [];
        const apiGroup = (rl.api_groups || rl.apiGroups || [''])[0] || '';
        return (
          <div key={i} className="rbac-rule-group">
            <div className="rbac-rule-api">{apiGroup || '""'}</div>
            <div className="rbac-rule-right">
              <div className="rbac-vlist">
                {verbs.map(v => (
                  <span key={v} className={`rbac-v${DANGER_VERBS.has(v) ? ' rbac-v--d' : ''}`}>{v}</span>
                ))}
              </div>
              {res.length > 0 && (
                <div className="rbac-reslist">
                  {res.map(x => (
                    <span key={x} className={`rbac-res${SENSITIVE_RES.has(x) ? ' rbac-res--s' : ''}`}>{x}</span>
                  ))}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function RoleRow({ role, bindings, open, onToggle }) {
  const name      = roleName(role);
  const ns        = roleNS(role);
  const isCluster = role._kind === 'ClusterRole';

  const { sev, hits } = useMemo(() => evaluate(role.rules), [role]);
  const lvl = !sev ? 'ok' : sev.toLowerCase();

  const boundBindings = useMemo(
    () => bindings.filter(b => getRoleRefName(b) === name),
    [bindings, name]
  );
  const allSubjects = useMemo(
    () => boundBindings.flatMap(b => getSubjects(b)),
    [boundBindings]
  );

  return (
    <>
      <tr className={`rbac-row rbac-row--${lvl}${open ? ' rbac-row--open' : ''}`} onClick={onToggle}>
        <td className="rbac-chev-cell">
          <span className={`rbac-chev${open ? ' rbac-chev--open' : ''}`}>›</span>
        </td>
        <td>
          <div className="rbac-rname">{name}</div>
          {ns && <div className="rbac-rns">{ns}</div>}
        </td>
        <td>
          <span className={`rbac-kbadge${isCluster ? ' rbac-kbadge--cluster' : ''}`}>
            {role._kind}
          </span>
        </td>
        <td>
          <div className="rbac-subj-list">
            {allSubjects.length === 0
              ? <span className="rbac-no-subj">no bindings</span>
              : allSubjects.slice(0, 3).map((s, i) => <SubjectChip key={i} {...s} />)
            }
            {allSubjects.length > 3 && (
              <span className="rbac-subj-more">+{allSubjects.length - 3}</span>
            )}
          </div>
        </td>
        <td><SevBadge sev={sev} hits={hits} /></td>
        <td>
          <div className="rbac-flag-list">
            {hits.slice(0, 3).map(h => (
              <span key={h.id}
                className={`rbac-flag rbac-flag--${h.sev==='Critical'?'c':h.sev==='High'?'h':'m'}`}
                title={h.desc}
              >
                {h.id.replace(/_/g, ' ')}
              </span>
            ))}
            {hits.length > 3 && <span className="rbac-flag rbac-flag--m">+{hits.length - 3}</span>}
          </div>
        </td>
      </tr>

      {open && (
        <tr className="rbac-detail-row">
          <td colSpan={6}>
            <div className="rbac-detail">

              <div className="rbac-detail-cols">
                <div className="rbac-detail-section">
                  <div className="rbac-detail-title">Rules ({(role.rules||[]).length})</div>
                  <RuleTable rules={role.rules} />
                </div>

                {boundBindings.length > 0 && (
                  <div className="rbac-detail-section">
                    <div className="rbac-detail-title">Bindings ({boundBindings.length})</div>
                    <div className="rbac-blist">
                      {boundBindings.map((b, i) => {
                        const subs  = getSubjects(b);
                        const bname = b.name || b.metadata?.name || '';
                        const bns   = b.namespace || b.metadata?.namespace || '';
                        return (
                          <div key={i} className="rbac-bitem">
                            <div className="rbac-bitem-hdr">
                              <span className="rbac-bname">{bname}</span>
                              {bns && <span className="rbac-bns">{bns}</span>}
                            </div>
                            <div className="rbac-subj-list rbac-subj-list--wrap">
                              {subs.map((s, j) => <SubjectChip key={j} {...s} />)}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>

            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export function RBAC() {
  const { allRoles, allBindings, sensorOnline } = useSensor();

  const [search,  setSearch]  = useState('');
  const [nsFilt,  setNsFilt]  = useState('');
  const [sevFilt, setSevFilt] = useState('');
  const [openRow, setOpenRow] = useState(null);

  const namespaces = useMemo(() => {
    const ns = new Set(allRoles.map(r => roleNS(r)).filter(Boolean));
    return [...ns].sort();
  }, [allRoles]);

  const scored = useMemo(() =>
    allRoles.map(role => {
      const { sev, hits } = evaluate(role.rules);
      return { role, sev, hits };
    }),
    [allRoles]
  );

  const stats = useMemo(() => ({
    total:    scored.length,
    cluster:  scored.filter(r => r.role._kind === 'ClusterRole').length,
    critical: scored.filter(r => r.sev === 'Critical').length,
    high:     scored.filter(r => r.sev === 'High').length,
    secrets:  scored.filter(r => r.hits.some(h => h.id === 'read_secrets')).length,
    unbound:  scored.filter(r => {
      const n = roleName(r.role);
      return !allBindings.some(b => getRoleRefName(b) === n);
    }).length,
  }), [scored, allBindings]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return scored
      .filter(({ role, sev }) => {
        const ns = roleNS(role);
        if (nsFilt && ns !== nsFilt) return false;
        if (sevFilt) {
          const match = sevFilt === 'ok' ? !sev : sev === sevFilt;
          if (!match) return false;
        }
        if (q) {
          const name      = roleName(role).toLowerCase();
          const subjMatch = allBindings
            .filter(b => getRoleRefName(b) === roleName(role))
            .flatMap(getSubjects)
            .some(s => s.name.toLowerCase().includes(q));
          if (!name.includes(q) && !subjMatch) return false;
        }
        return true;
      })
      .sort((a, b) => (SEV_ORDER[a.sev] ?? 4) - (SEV_ORDER[b.sev] ?? 4));
  }, [scored, search, nsFilt, sevFilt, allBindings]);

  return (
    <div className="rbac-page">

      <div className="rbac-header">
        <div className="rbac-header-left">
          <span className="rbac-title">RBAC Audit</span>
          <span className="rbac-header-sep">·</span>
          <span className="rbac-header-sub">{stats.total} roles · refresh every 5m</span>
        </div>
        <div className="rbac-header-right">
          {!sensorOnline && <span className="rbac-offline">sensor offline</span>}
          {stats.critical > 0 && <span className="rbac-stat-badge rbac-stat-badge--critical">{stats.critical} critical</span>}
          {stats.high     > 0 && <span className="rbac-stat-badge rbac-stat-badge--high">{stats.high} high</span>}
        </div>
      </div>

      <div className="rbac-stats">
        {[
          { val: stats.total,    lbl: 'Roles',         cls: '' },
          { val: stats.cluster,  lbl: 'ClusterRoles',  cls: 'rbac-stat-num--purple' },
          { val: stats.critical, lbl: 'Critical',      cls: 'rbac-stat-num--critical' },
          { val: stats.high,     lbl: 'High',          cls: 'rbac-stat-num--high' },
          { val: stats.secrets,  lbl: 'Secret access', cls: 'rbac-stat-num--warning' },
          { val: stats.unbound,  lbl: 'Unbound',       cls: 'rbac-stat-num--muted' },
        ].map((s, i) => (
          <div key={i} className="rbac-stat">
            <div className={`rbac-stat-num ${s.cls}`}>{s.val}</div>
            <div className="rbac-stat-lbl">{s.lbl}</div>
          </div>
        ))}
      </div>

      <div className="rbac-toolbar">
        <input
          className="rbac-search"
          placeholder="Search roles, subjects, SAs, groups..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <select className="rbac-select" value={nsFilt} onChange={e => setNsFilt(e.target.value)}>
          <option value="">All namespaces</option>
          {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
        </select>
        <select className="rbac-select" value={sevFilt} onChange={e => setSevFilt(e.target.value)}>
          <option value="">All severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="ok">OK</option>
        </select>
        <VerbsHelp />
        <span className="rbac-count">{filtered.length} shown</span>
      </div>

      <div className="rbac-table-wrap">
        {filtered.length === 0
          ? <div className="rbac-empty">{sensorOnline ? 'No roles match filters' : 'Sensor offline'}</div>
          : (
            <table className="rbac-table">
              <thead>
                <tr>
                  <th style={{ width: 28 }} />
                  <th>Role / ClusterRole</th>
                  <th>Kind</th>
                  <th>Subjects</th>
                  <th style={{ width: 110 }}>Severity</th>
                  <th>Violations</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(({ role }, i) => {
                  const key = `${roleName(role)}-${roleNS(role)}-${i}`;
                  return (
                    <RoleRow
                      key={key}
                      role={role}
                      bindings={allBindings}
                      open={openRow === key}
                      onToggle={() => setOpenRow(prev => prev === key ? null : key)}
                    />
                  );
                })}
              </tbody>
            </table>
          )
        }
      </div>

    </div>
  );
}
