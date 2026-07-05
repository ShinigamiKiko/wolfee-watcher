import { appDeps, appPods, appNS } from './checksCIS';

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

const PCI = [
  { id:'pci-1.1.4', pci:'1.1.4', cat:'Network',
    title:'1.1.4 — Firewall controls between network zones (NetworkPolicy)',
    fn(d) {
      const deps      = appDeps(d);
      const coveredNS = new Set((d.snap?.network_policies||[]).map(np=>np.metadata?.namespace));
      const bad       = deps.filter(dep => !coveredNS.has(dep.metadata?.namespace));
      return { passing: deps.length-bad.length, total: Math.max(deps.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace||'?'}/${dep.metadata?.name||'?'}`).filter(Boolean),
        fix: 'Implement NetworkPolicies as K8s-native firewall rules between namespaces.' };
    }},
  { id:'pci-2.2', pci:'2.2', cat:'Secure Config',
    title:'2.2 — Secure configurations for system components',
    fn(d) {
      const deps = appDeps(d);
      const bad  = deps.filter(dep =>
        dep.spec?.template?.spec?.containers?.some(c =>
          c.securityContext?.privileged===true || !c.resources?.limits));
      return { passing: deps.length-bad.length, total: Math.max(deps.length,1),
        entities: bad.map(dep=>`${dep.metadata?.namespace}/${dep.metadata?.name}`).filter(Boolean),
        fix: 'Enforce non-privileged containers with CPU/memory limits.' };
    }},
  { id:'pci-6.2', pci:'6.2', cat:'Vuln Management',
    title:'6.2 — Address known vulnerabilities by installing security patches',
    fn(d) {
      const scanned = d.scan?.results?.filter(r=>r.status==='scanned') || [];
      const total   = Math.max(scanned.length, 1);
      const bad     = scanned.filter(r => r.cves?.some(c =>
        (c.severity==='Critical'||c.severity==='High') && c.fix?.state==='fixed'));
      return { passing: total-bad.length, total,
        entities: bad.map(r=>`${r.name}:${r.tag}`).filter(Boolean),
        fix: 'Update images to versions with available fixes for Critical/High CVEs.' };
    }},
  { id:'pci-6.3', pci:'6.3', cat:'Vuln Management',
    title:'6.3 — Protect against known vulnerabilities (no critical CVEs)',
    fn(d) {
      const scanned = d.scan?.results?.filter(r=>r.status==='scanned') || [];
      const total   = Math.max(scanned.length, 1);
      const bad     = scanned.filter(r => (r.summary?.critical||0) > 0);
      return { passing: total-bad.length, total,
        entities: bad.map(r=>`${r.name}:${r.tag} (${r.summary?.critical}C/${r.summary?.high}H)`).filter(Boolean),
        fix: 'Rebuild or update images to eliminate critical CVEs before deployment.' };
    }},
  { id:'pci-7.1', pci:'7.1', cat:'Access Control',
    title:'7.1 — Limit access to system components by business need',
    fn(d) {
      const crbs  = d.snap?.cluster_role_bindings || [];
      const bad   = crbs.filter(b => b.roleRef?.name==='cluster-admin');
      const total = Math.max(crbs.length, 1);
      return { passing: total-bad.length, total,
        entities: bad.map(b=>b.metadata?.name).filter(Boolean),
        fix: 'Apply least privilege. Remove cluster-admin from non-essential accounts.' };
    }},
  { id:'pci-8.1', pci:'8.1', cat:'Identity',
    title:'8.1 — Identify and authenticate access to system components',
    fn(d) {
      const ns     = appNS(d);
      const total  = Math.max(ns.length, 1);
      const sas    = d.snap?.service_accounts || [];
      const nsWithSA = new Set(sas.filter(sa=>sa.metadata?.name!=='default').map(sa=>sa.metadata?.namespace));
      const bad    = ns.filter(n => !nsWithSA.has(n));
      return { passing: total-bad.length, total,
        entities: bad,
        fix: 'Create dedicated ServiceAccounts per deployment instead of using the default.' };
    }},
  { id:'pci-10.1', pci:'10.1', cat:'Audit',
    title:'10.1 — Audit trail for access to cardholder data (admission webhooks)',
    fn(d) {
      const m = (d.snap?.mutating_webhooks||[]).length;
      const v = (d.snap?.validating_webhooks||[]).length;
      const total = 1;
      const pass  = (m+v) > 0 ? 1 : 0;
      return { passing: pass, total,
        entities: pass ? [] : ['No admission webhooks present'],
        fix: 'Deploy OPA/Kyverno admission webhooks to audit all cluster changes.' };
    }},
];

export { NIST, PCI };
