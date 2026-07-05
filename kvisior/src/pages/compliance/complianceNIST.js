import { appDeps, appPods, appWorkloads, wlContainers, wlPodSpec, podContainers, appNS } from './complianceHelpers';

const NIST = [
  { id:'nist-4.1.1', nist:'4.1.1', cat:'Image Security',
    title:'4.1.1 — Image vulnerability scanning integrated',
    fn(d) {
      const scanned = d.scan?.results?.filter(r=>r.status==='scanned') || [];
      const total   = Math.max(scanned.length, 1);
      const bad     = scanned.filter(r => r.summary?.critical > 0);
      return { passing: total-bad.length, total,
        entities: bad.map(r=>`${r.name}:${r.tag} (${r.summary?.critical} critical)`).filter(Boolean),
        fix: 'Integrate vulnerability scanning. Fix or mitigate all Critical CVEs.' };
    }},
  { id:'nist-4.1.2', nist:'4.1.2', cat:'Image Security',
    title:'4.1.2 — No high-severity CVEs in running images',
    fn(d) {
      const scanned = d.scan?.results?.filter(r=>r.status==='scanned') || [];
      const total   = Math.max(scanned.length, 1);
      const bad     = scanned.filter(r => (r.summary?.high||0) > 5);
      return { passing: total-bad.length, total,
        entities: bad.map(r=>`${r.name}:${r.tag} (${r.summary?.high} high)`).filter(Boolean),
        fix: 'Remediate high-severity CVEs. Enforce a max-high policy in CI/CD.' };
    }},
  { id:'nist-4.2.2', nist:'4.2.2', cat:'Image Config',
    title:'4.2.2 — Images use immutable tags (not :latest)',
    fn(d) {
      const deps = appDeps(d);
      const bad  = deps.filter(dep => dep.spec?.template?.spec?.containers?.some(c => {
        const img = c.image||'';
        return img.endsWith(':latest') || !img.includes(':');
      }));
      return { passing: deps.length-bad.length, total: Math.max(deps.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace}/${dep.metadata?.name}`).filter(Boolean),
        fix: 'Pin images to sha256 digest or specific semver tags. Never use :latest.' };
    }},
  { id:'nist-4.4.1', nist:'4.4.1', cat:'Runtime',
    title:'4.4.1 — Containers run as non-root',
    fn(d) {
      const deps = appDeps(d);
      const bad  = deps.filter(dep =>
        !dep.spec?.template?.spec?.securityContext?.runAsNonRoot &&
        dep.spec?.template?.spec?.containers?.some(c =>
          !c.securityContext?.runAsNonRoot && !(c.securityContext?.runAsUser > 0)));
      return { passing: deps.length-bad.length, total: Math.max(deps.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace}/${dep.metadata?.name}`).filter(Boolean),
        fix: 'Set runAsNonRoot=true in pod or container securityContext.' };
    }},
  { id:'nist-4.4.2', nist:'4.4.2', cat:'Runtime',
    title:'4.4.2 — Read-only root filesystem',
    fn(d) {
      const deps = appDeps(d);
      const bad  = deps.filter(dep => dep.spec?.template?.spec?.containers?.some(c =>
        c.securityContext?.readOnlyRootFilesystem !== true));
      return { passing: deps.length-bad.length, total: Math.max(deps.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace}/${dep.metadata?.name}`).filter(Boolean),
        fix: 'Set readOnlyRootFilesystem=true. Use emptyDir volumes for writable paths.' };
    }},
  { id:'nist-4.5.1', nist:'4.5.1', cat:'Networking',
    title:'4.5.1 — Network segmentation between deployments',
    fn(d) {
      const deps      = appDeps(d);
      const coveredNS = new Set((d.snap?.network_policies||[]).map(np=>np.metadata?.namespace));
      const bad       = deps.filter(dep => !coveredNS.has(dep.metadata?.namespace));
      return { passing: deps.length-bad.length, total: Math.max(deps.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace||'?'}/${dep.metadata?.name||'?'}`).filter(Boolean),
        fix: 'Define NetworkPolicies restricting pod-to-pod communication per namespace.' };
    }},
  { id:'nist-4.6.1', nist:'4.6.1', cat:'Secrets',
    title:'4.6.1 — Secrets not exposed as env vars',
    fn(d) {
      const deps = appDeps(d);
      const bad  = deps.filter(dep => dep.spec?.template?.spec?.containers?.some(c =>
        c.env?.some(e => e.valueFrom?.secretKeyRef
          || ['password','secret','key','token','credential'].some(kw=>e.name?.toLowerCase().includes(kw)))));
      return { passing: deps.length-bad.length, total: Math.max(deps.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace}/${dep.metadata?.name}`).filter(Boolean),
        fix: 'Mount secrets as volumes. Avoid env vars for sensitive data.' };
    }},
];

export { NIST };
