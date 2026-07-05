import { appDeps, appPods, appWorkloads, wlContainers, wlPodSpec, podContainers, appNS } from './complianceHelpers';

const HIPAA = [
  { id:'hipaa-164.308.a', hipaa:'164.308(a)', cat:'Access Mgmt',
    title:'164.308(a) — Information access management: RBAC',
    fn(d) {
      const crbs = d.snap?.cluster_role_bindings || [];
      const crAdminCount = crbs.filter(b=>b.roleRef?.name==='cluster-admin').length;
      const hasRBAC  = (d.snap?.cluster_roles||[]).length > 0;
      const total    = Math.max(crbs.length, 1);
      const bad      = crbs.filter(b=>b.roleRef?.name==='cluster-admin'
        && b.subjects?.some(s=>s.kind!=='ServiceAccount'||!s.namespace?.startsWith('kube-')));
      return { passing: total-bad.length, total,
        entities: bad.map(b=>b.metadata?.name).filter(Boolean),
        fix: 'Implement strict RBAC. Limit cluster-admin to operations team only.' };
    }},
  { id:'hipaa-164.308.a.5', hipaa:'164.308(a)(5)', cat:'Access Mgmt',
    title:'164.308(a)(5) — Security awareness: no secrets in env vars',
    fn(d) {
      const deps = appDeps(d);
      const bad  = deps.filter(dep => dep.spec?.template?.spec?.containers?.some(c =>
        c.env?.some(e => e.valueFrom?.secretKeyRef)));
      return { passing: deps.length-bad.length, total: Math.max(deps.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace}/${dep.metadata?.name}`).filter(Boolean),
        fix: 'Use Kubernetes Secrets mounted as volumes. Never inject secrets as env vars.' };
    }},
  { id:'hipaa-164.312.a', hipaa:'164.312(a)', cat:'Technical Controls',
    title:'164.312(a)(1) — Access control: unique user identification per pod',
    fn(d) {
      const ns     = appNS(d);
      const total  = Math.max(ns.length, 1);
      const sas    = d.snap?.service_accounts || [];
      const nsWithDedicatedSA = new Set(sas.filter(sa=>sa.metadata?.name!=='default').map(sa=>sa.metadata?.namespace));
      const bad    = ns.filter(n => !nsWithDedicatedSA.has(n));
      return { passing: total-bad.length, total,
        entities: bad,
        fix: 'Create dedicated ServiceAccounts per deployment for audit traceability.' };
    }},
  { id:'hipaa-164.312.b', hipaa:'164.312(b)', cat:'Audit Controls',
    title:'164.312(b) — Audit controls: admission webhooks present',
    fn(d) {
      const total = 1;
      const pass  = ((d.snap?.mutating_webhooks||[]).length + (d.snap?.validating_webhooks||[]).length) > 0 ? 1 : 0;
      return { passing: pass, total,
        entities: pass ? [] : ['No admission webhooks — cannot audit cluster changes'],
        fix: 'Deploy admission webhook controllers (OPA/Kyverno) to log all resource mutations.' };
    }},
  { id:'hipaa-164.312.c', hipaa:'164.312(c)', cat:'Integrity',
    title:'164.312(c)(1) — Integrity: detect unauthorized access (anomaly alerts)',
    fn(d) {
      const ns    = appNS(d);
      const total = Math.max(ns.length, 1);
      const alertNS = new Set((d.anomaly?.events||[])
        .filter(e=>e.kind==='unauthorized_flow'||e.kind==='policy_blocked')
        .map(e=>e.src_namespace).filter(Boolean));
      const bad = ns.filter(n => alertNS.has(n));
      return { passing: total-bad.length, total,
        entities: [...alertNS].filter(Boolean),
        fix: 'Investigate and remediate unauthorized network flows. Lock down baselines.' };
    }},
  { id:'hipaa-164.312.e', hipaa:'164.312(e)', cat:'Transmission',
    title:'164.312(e)(1) — Transmission security: network encryption enforced',
    fn(d) {
      const deps      = appDeps(d);
      const coveredNS = new Set((d.snap?.network_policies||[]).map(np=>np.metadata?.namespace));
      const bad       = deps.filter(dep => !coveredNS.has(dep.metadata?.namespace));
      return { passing: deps.length-bad.length, total: Math.max(deps.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace||'?'}/${dep.metadata?.name||'?'}`).filter(Boolean),
        fix: 'Enforce NetworkPolicies with mTLS (e.g. Istio/Linkerd) for PHI data in transit.' };
    }},
];

export { HIPAA };
