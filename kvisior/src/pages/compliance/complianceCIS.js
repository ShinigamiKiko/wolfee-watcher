import { appDeps, appPods, appWorkloads, wlContainers, wlPodSpec, podContainers, appNS } from './complianceHelpers';

const CIS = [
  { id:'cis-5.1.1', cis:'5.1.1', cat:'RBAC',
    title:'cluster-admin role used only where required',
    fn(d) {
      const crbs  = d.snap?.cluster_role_bindings || [];
      const bad   = crbs.filter(b => b.roleRef?.name === 'cluster-admin'
        && b.subjects?.some(s => !(s.namespace?.startsWith('kube-') && s.kind==='ServiceAccount')));
      const total = Math.max(crbs.length, 1);
      return { passing: total-bad.length, total,
        entities: bad.map(b=>`${b.metadata?.name} (${(b.subjects||[]).map(s=>s.name).join(', ')})`).filter(Boolean),
        fix: 'Remove unnecessary cluster-admin bindings. Use namespace-scoped roles.' };
    }},
  { id:'cis-5.1.3', cis:'5.1.3', cat:'RBAC',
    title:'No wildcard verbs in Roles and ClusterRoles',
    fn(d) {
      const SYS_ROLES = /^system:|^cluster-admin$|^admin$|^edit$|^view$/;
      const roles = [...(d.snap?.cluster_roles||[]), ...(d.snap?.roles||[])]
        .filter(r => !SYS_ROLES.test(r.metadata?.name||''));
      const bad   = roles.filter(r => r.rules?.some(ru => ru.verbs?.includes('*') || ru.resources?.includes('*')));
      const total = Math.max(roles.length, 1);
      return { passing: total-bad.length, total,
        entities: bad.map(r=>`${r.metadata?.namespace ? r.metadata.namespace+'/' : ''}${r.metadata?.name}`).filter(Boolean),
        fix: 'Replace wildcard permissions with explicit verbs and resources.' };
    }},
  { id:'cis-5.1.5', cis:'5.1.5', cat:'RBAC',
    title:'Default service accounts not bound to active roles',
    fn(d) {
      const ns   = appNS(d);
      const bad  = (d.snap?.role_bindings||[])
        .filter(rb => rb.subjects?.some(s => s.kind==='ServiceAccount' && s.name==='default'))
        .map(rb => `${rb.metadata?.namespace}/${rb.metadata?.name}`)
        .filter((v,i,a) => v && a.indexOf(v)===i);
      const total = Math.max(ns.length, 1);
      return { passing: total-bad.length, total,
        entities: bad,
        fix: 'Remove RoleBindings that grant the default ServiceAccount permissions.' };
    }},
  { id:'cis-5.2.1', cis:'5.2.1', cat:'Pod Security',
    title:'No privileged containers',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => podContainers(p).some(c => c.securityContext?.privileged===true));
      return { passing: pods.length-bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Set securityContext.privileged=false for all containers.' };
    }},
  { id:'cis-5.2.2', cis:'5.2.2', cat:'Pod Security',
    title:'No containers sharing host PID namespace',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => p.spec?.hostPID===true);
      return { passing: pods.length-bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Set hostPID=false in all pod specs.' };
    }},
  { id:'cis-5.2.4', cis:'5.2.4', cat:'Pod Security',
    title:'No containers sharing host network namespace',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => p.spec?.hostNetwork===true);
      return { passing: pods.length-bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Set hostNetwork=false in all pod specs.' };
    }},
  { id:'cis-5.2.6', cis:'5.2.6', cat:'Pod Security',
    title:'No containers running as root',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p =>
        podContainers(p).some(c => c.securityContext?.runAsUser===0)
        || p.spec?.securityContext?.runAsUser===0);
      return { passing: pods.length-bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Set runAsNonRoot=true or runAsUser > 0.' };
    }},
  { id:'cis-5.2.11', cis:'5.2.11', cat:'Pod Security',
    title:'No containers with added capabilities',
    fn(d) {
      const pods = appPods(d);
      const bad  = pods.filter(p => podContainers(p).some(c => c.securityContext?.capabilities?.add?.length > 0));
      return { passing: pods.length-bad.length, total: Math.max(pods.length,1),
        entities: bad.map(p=>`${p.metadata?.namespace}/${p.metadata?.name}`).filter(Boolean),
        fix: 'Remove capabilities.add from container securityContext. Use drop: [ALL].' };
    }},
  { id:'cis-5.3.2', cis:'5.3.2', cat:'Network',
    title:'All namespaces have NetworkPolicies defined',
    fn(d) {
      const deps      = appDeps(d);
      const coveredNS = new Set((d.snap?.network_policies||[]).map(np=>np.metadata?.namespace));
      const bad       = deps.filter(dep => !coveredNS.has(dep.metadata?.namespace));
      return { passing: deps.length-bad.length, total: Math.max(deps.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace}/${dep.metadata?.name}`).filter(Boolean),
        fix: 'Create NetworkPolicy resources for every application namespace.' };
    }},
  { id:'cis-5.4.1', cis:'5.4.1', cat:'Secrets',
    title:'Prefer Secrets as files over environment variables',
    fn(d) {
      const deps = appDeps(d);
      const bad  = deps.filter(dep => dep.spec?.template?.spec?.containers?.some(c => c.env?.some(e=>e.valueFrom?.secretKeyRef)));
      return { passing: deps.length-bad.length, total: Math.max(deps.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace}/${dep.metadata?.name}`).filter(Boolean),
        fix: 'Mount secrets as files (secretVolume) instead of env vars.' };
    }},
  { id:'cis-5.7.2', cis:'5.7.2', cat:'General',
    title:'Default namespace not used for workloads',
    fn(d) {
      const all = d.snap?.deployments || [];
      const bad = all.filter(dep => dep.metadata?.namespace==='default');
      return { passing: all.length-bad.length, total: Math.max(all.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace}/${dep.metadata?.name}`).filter(Boolean),
        fix: 'Create dedicated namespaces. Do not use the default namespace.' };
    }},
];

export { CIS };
