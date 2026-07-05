import { AUDIT_CHECKS } from '../../policy/constants';
import { fpKey } from '../violationsConstants';

const push = (arr, v) => { v._fp = fpKey(v, 'Deploy'); arr.push(v); };

export function evalDeployViolations(deployPolicies, workloads, snapshot) {
  const viols = [];
  const netpols    = snapshot?.network_policies || [];
  const namespaces = snapshot?.namespaces       || [];
  const services   = snapshot?.services         || [];
  const SYS_NS = new Set(['kube-system','kube-public','kube-node-lease','calico-system','calico-apiserver','cilium','cert-manager']);
  for (const policy of deployPolicies) {
    if (policy.enabled === false) continue;
    const checks   = policy.deployChecks || [];
    const nsFilter = policy.namespace?.trim();

    for (const w of workloads) {
      const ns   = w.metadata?.namespace || '';
      const name = w.metadata?.name || '';
      const kind = w._kind || 'Deployment';
      if (nsFilter && ns !== nsFilter) continue;

      const spec       = w.spec?.template?.spec || {};
      const containers = [...(spec.containers || []), ...(spec.initContainers || [])];

      for (const checkId of checks) {
        let violated = false, detail = '';
        switch (checkId) {
          case 'no-privileged': { const c = containers.find(c => c.securityContext?.privileged === true); if (c) { violated = true; detail = `Container "${c.name}" has privileged: true`; } break; }
          case 'no-host-pid':   if (spec.hostPID)     { violated = true; detail = 'spec.hostPID is true'; } break;
          case 'no-host-ipc':   if (spec.hostIPC)     { violated = true; detail = 'spec.hostIPC is true'; } break;
          case 'no-host-net':   if (spec.hostNetwork) { violated = true; detail = 'spec.hostNetwork is true'; } break;
          case 'no-priv-esc':   { const c = containers.find(c => c.securityContext?.allowPrivilegeEscalation !== false); if (c) { violated = true; detail = `Container "${c.name}" — allowPrivilegeEscalation not false`; } break; }
          case 'no-root':       { const c = containers.find(c => c.securityContext?.runAsUser === 0 || c.securityContext?.runAsNonRoot === false); if (c) { violated = true; detail = `Container "${c.name}" runs as root`; } break; }
          case 'no-root-group': { const sg = spec.securityContext?.supplementalGroups || [], fg = spec.securityContext?.fsGroup; if (sg.includes(0) || fg === 0) { violated = true; detail = 'supplementalGroups or fsGroup includes GID 0'; } break; }
          case 'drop-net-raw':  { const c = containers.find(c => { const d = c.securityContext?.capabilities?.drop || []; return !d.includes('NET_RAW') && !d.includes('ALL'); }); if (c) { violated = true; detail = `Container "${c.name}" does not drop NET_RAW`; } break; }
          case 'drop-all-caps': { const c = containers.find(c => !(c.securityContext?.capabilities?.drop || []).includes('ALL')); if (c) { violated = true; detail = `Container "${c.name}" does not drop ALL capabilities`; } break; }
          case 'no-seccomp-unconfined': { const t = spec.securityContext?.seccompProfile?.type; const c = containers.find(c => c.securityContext?.seccompProfile?.type === 'Unconfined'); if (t === 'Unconfined' || c) { violated = true; detail = 'seccompProfile is Unconfined'; } break; }
          case 'no-apparmor-unconfined': { const bad = Object.entries(w.metadata?.annotations || {}).find(([k, v]) => k.startsWith('container.apparmor') && v === 'unconfined'); if (bad) { violated = true; detail = `AppArmor annotation ${bad[0]}=unconfined`; } break; }
          case 'readonly-root': { const c = containers.find(c => c.securityContext?.readOnlyRootFilesystem !== true); if (c) { violated = true; detail = `Container "${c.name}" has writable root filesystem`; } break; }
          case 'no-host-path':  { const v = (spec.volumes || []).find(v => v.hostPath); if (v) { violated = true; detail = `Volume "${v.name}" uses hostPath: ${v.hostPath?.path}`; } break; }
          case 'no-host-path-write': { const v = (spec.volumes || []).find(v => v.hostPath); if (v) { const m = containers.flatMap(c => c.volumeMounts || []).find(m => m.name === v.name && !m.readOnly); if (m) { violated = true; detail = `hostPath "${v.name}" mounted writable`; } } break; }
          case 'no-host-port':  { const p = containers.flatMap(c => c.ports || []).find(p => p.hostPort); if (p) { violated = true; detail = `Port ${p.containerPort} exposes hostPort ${p.hostPort}`; } break; }
          case 'resource-limits':   { const c = containers.find(c => !c.resources?.limits?.cpu || !c.resources?.limits?.memory); if (c) { violated = true; detail = `Container "${c.name}" missing CPU/memory limits`; } break; }
          case 'resource-requests': { const c = containers.find(c => !c.resources?.requests?.cpu || !c.resources?.requests?.memory); if (c) { violated = true; detail = `Container "${c.name}" missing CPU/memory requests`; } break; }
          case 'no-latest-tag': { const c = containers.find(c => { const t = (c.image || '').includes(':') ? c.image.split(':').pop() : 'latest'; return t === 'latest' || !(c.image || '').includes(':'); }); if (c) { violated = true; detail = `Container "${c.name}" uses :latest tag: ${c.image}`; } break; }
          case 'no-default-sa': { const sa = spec.serviceAccountName, auto = spec.automountServiceAccountToken; if ((!sa || sa === 'default') && auto !== false) { violated = true; detail = 'Default ServiceAccount with automountServiceAccountToken enabled'; } break; }
          case 'privileged-pod-rt':     { const c = containers.find(c => c.securityContext?.privileged === true); if (c) { violated = true; detail = `Container "${c.name}" has privileged: true`; } break; }
          case 'host-pid-pod-rt':       if (spec.hostPID)     { violated = true; detail = 'spec.hostPID is true'; } break;
          case 'host-network-pod-rt':   if (spec.hostNetwork) { violated = true; detail = 'spec.hostNetwork is true'; } break;
          case 'no-host-path-write-rt': { const v = (spec.volumes || []).find(v => v.hostPath); if (v) { const m = containers.flatMap(c => c.volumeMounts || []).find(m => m.name === v.name && !m.readOnly); if (m) { violated = true; detail = `hostPath "${v.name}" mounted writable at ${v.hostPath?.path}`; } } break; }
          case 'secret-as-env-rt':      { for (const c of containers) { const e = (c.env || []).find(e => e.valueFrom?.secretKeyRef); const ef = (c.envFrom || []).find(e => e.secretRef); if (e) { violated = true; detail = `Container "${c.name}" exposes secret "${e.valueFrom.secretKeyRef.name}" as env var`; break; } if (ef) { violated = true; detail = `Container "${c.name}" exposes all keys of secret "${ef.secretRef.name}" via envFrom`; break; } } break; }
          case 'ns-no-netpol-rt':       break;
          case 'allow-all-ingress-rt':  break;
          case 'allow-all-egress-rt':   break;
          case 'nodeport-exposed-rt':   break;
          default: break;
        }
        if (violated) {
          push(viols, { policy: policy.name, sev: policy.sev || 'HIGH', workload: name, kind, ns, detail, check: checkId, action: policy.action, _policyId: policy.id ,
          _detectedAt: Date.now(),
        });
        }
      }
    }
  }

  for (const policy of deployPolicies) {
    if (policy.enabled === false) continue;
    const checks   = policy.deployChecks || [];
    const nsFilter = policy.namespace?.trim();

    if (checks.includes('ns-no-netpol-rt')) {
      const covered = new Set(netpols.map(np => np.metadata?.namespace));
      for (const ns of namespaces) {
        const name = ns.metadata?.name;
        if (SYS_NS.has(name)) continue;
        if (nsFilter && name !== nsFilter) continue;
        if (!covered.has(name)) {
          push(viols, { policy: policy.name, sev: policy.sev || 'MEDIUM', workload: name, kind: 'Namespace', ns: name, detail: `Namespace "${name}" has no NetworkPolicy`, check: 'ns-no-netpol-rt', action: policy.action, _policyId: policy.id, _detectedAt: Date.now() });
        }
      }
    }
    if (checks.includes('allow-all-ingress-rt')) {
      for (const np of netpols) {
        const ns = np.metadata?.namespace;
        if (SYS_NS.has(ns)) continue;
        if (nsFilter && ns !== nsFilter) continue;
        if ((np.spec?.ingress || []).some(r => !r.from || r.from.length === 0)) {
          push(viols, { policy: policy.name, sev: policy.sev || 'HIGH', workload: np.metadata?.name, kind: 'NetworkPolicy', ns, detail: `NetworkPolicy "${np.metadata?.name}" allows all ingress`, check: 'allow-all-ingress-rt', action: policy.action, _policyId: policy.id, _detectedAt: Date.now() });
        }
      }
    }
    if (checks.includes('allow-all-egress-rt')) {
      for (const np of netpols) {
        const ns = np.metadata?.namespace;
        if (SYS_NS.has(ns)) continue;
        if (nsFilter && ns !== nsFilter) continue;
        if ((np.spec?.egress || []).some(r => !r.to || r.to.length === 0)) {
          push(viols, { policy: policy.name, sev: policy.sev || 'MEDIUM', workload: np.metadata?.name, kind: 'NetworkPolicy', ns, detail: `NetworkPolicy "${np.metadata?.name}" allows all egress`, check: 'allow-all-egress-rt', action: policy.action, _policyId: policy.id, _detectedAt: Date.now() });
        }
      }
    }
    if (checks.includes('nodeport-exposed-rt')) {
      for (const svc of services) {
        const ns = svc.metadata?.namespace;
        if (SYS_NS.has(ns)) continue;
        if (nsFilter && ns !== nsFilter) continue;
        if (svc.spec?.type === 'NodePort') {
          push(viols, { policy: policy.name, sev: policy.sev || 'MEDIUM', workload: svc.metadata?.name, kind: 'Service', ns, detail: `Service "${svc.metadata?.name}" is type NodePort`, check: 'nodeport-exposed-rt', action: policy.action, _policyId: policy.id, _detectedAt: Date.now() });
        }
      }
    }
  }

  return viols;
}
