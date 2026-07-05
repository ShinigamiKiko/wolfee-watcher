import { AUDIT_CHECKS } from '../../policy/constants';

export function evalAuditViolations(auditRules, snapshot) {
  if (!snapshot) return [];
  const viols = [];

  const {
    pods = [], namespaces = [], network_policies: netpols = [],
    cluster_roles: clusterRoles = [], cluster_role_bindings: crbs = [],
    roles = [], role_bindings: rbs = [],
    service_accounts: sas = [],
    mutating_webhooks: mwhs = [],
  } = snapshot;

  const SYS_NS = new Set(['kube-system','kube-public','kube-node-lease','calico-system','calico-apiserver','cilium','cert-manager']);

  for (const policy of auditRules) {
    if (policy.enabled === false) continue;
    const checks   = policy.auditChecks || [];
    const nsFilter = policy.namespace?.trim();

    for (const checkId of checks) {
      switch (checkId) {

        case 'cluster-admin-binding': {
          for (const crb of crbs) {
            if (crb.roleRef?.name !== 'cluster-admin') continue;
            for (const subj of crb.subjects || []) {
              if (nsFilter && subj.namespace && subj.namespace !== nsFilter) continue;
              viols.push({
                policy: policy.name, sev: policy.sev || 'CRITICAL',
                resource: crb.metadata?.name, kind: 'ClusterRoleBinding',
                ns: subj.namespace || '(cluster)',
                detail: `${subj.kind} "${subj.name}" is bound to cluster-admin`,
                check: checkId, action: policy.action, _policyId: policy.id,
                _detectedAt: Date.now(),
        });
            }
          }
          break;
        }

        case 'wildcard-verbs': {
          const allRoles = [
            ...clusterRoles.map(r => ({ ...r, _kind: 'ClusterRole' })),
            ...roles.map(r => ({ ...r, _kind: 'Role' })),
          ];
          for (const role of allRoles) {
            if (nsFilter && role.metadata?.namespace && role.metadata.namespace !== nsFilter) continue;
            const rule = (role.rules || []).find(r => (r.verbs || []).includes('*'));
            if (!rule) continue;
            viols.push({
              policy: policy.name, sev: policy.sev || 'HIGH',
              resource: role.metadata?.name, kind: role._kind,
              ns: role.metadata?.namespace || '(cluster)',
              detail: `Grants verb:"*" on resources: ${(rule.resources || ['*']).join(', ')}`,
              check: checkId, action: policy.action, _policyId: policy.id,
              _detectedAt: Date.now(),
        });
          }
          break;
        }

        case 'wildcard-resources': {
          const allRoles = [
            ...clusterRoles.map(r => ({ ...r, _kind: 'ClusterRole' })),
            ...roles.map(r => ({ ...r, _kind: 'Role' })),
          ];
          for (const role of allRoles) {
            if (nsFilter && role.metadata?.namespace && role.metadata.namespace !== nsFilter) continue;
            const rule = (role.rules || []).find(r => (r.resources || []).includes('*'));
            if (!rule) continue;
            viols.push({
              policy: policy.name, sev: policy.sev || 'HIGH',
              resource: role.metadata?.name, kind: role._kind,
              ns: role.metadata?.namespace || '(cluster)',
              detail: `Grants resource:"*" with verbs: ${(rule.verbs || ['*']).join(', ')}`,
              check: checkId, action: policy.action, _policyId: policy.id,
              _detectedAt: Date.now(),
        });
          }
          break;
        }

        case 'sa-cluster-admin': {
          for (const crb of crbs) {
            if (crb.roleRef?.name !== 'cluster-admin') continue;
            for (const subj of (crb.subjects || []).filter(s => s.kind === 'ServiceAccount')) {
              if (nsFilter && subj.namespace !== nsFilter) continue;
              viols.push({
                policy: policy.name, sev: policy.sev || 'CRITICAL',
                resource: `${subj.namespace}/${subj.name}`, kind: 'ServiceAccount',
                ns: subj.namespace || '(cluster)',
                detail: `ServiceAccount "${subj.name}" in "${subj.namespace}" bound to cluster-admin via "${crb.metadata?.name}"`,
                check: checkId, action: policy.action, _policyId: policy.id,
                _detectedAt: Date.now(),
        });
            }
          }
          break;
        }

        case 'default-sa-bound': {
          const bound = new Set();
          for (const rb of [...crbs, ...rbs]) {
            for (const subj of (rb.subjects || [])) {
              if (subj.kind === 'ServiceAccount' && subj.name === 'default') {
                if (nsFilter && subj.namespace !== nsFilter) continue;
                const key = `${subj.namespace}/default`;
                if (!bound.has(key)) {
                  bound.add(key);
                  viols.push({
                    policy: policy.name, sev: policy.sev || 'MEDIUM',
                    resource: key, kind: 'ServiceAccount',
                    ns: subj.namespace,
                    detail: `Default SA in "${subj.namespace}" has explicit role binding "${rb.metadata?.name}"`,
                    check: checkId, action: policy.action, _policyId: policy.id,
                    _detectedAt: Date.now(),
        });
                }
              }
            }
          }
          break;
        }

        case 'ns-no-netpol': {
          const coveredNs = new Set(netpols.map(np => np.metadata?.namespace));
          for (const ns of namespaces) {
            const name = ns.metadata?.name;
            if (SYS_NS.has(name)) continue;
            if (nsFilter && name !== nsFilter) continue;
            if (!coveredNs.has(name)) {
              viols.push({
                policy: policy.name, sev: policy.sev || 'MEDIUM',
                resource: name, kind: 'Namespace',
                ns: name,
                detail: `Namespace "${name}" has no NetworkPolicy — all pod traffic is allowed`,
                check: checkId, action: policy.action, _policyId: policy.id,
                _detectedAt: Date.now(),
        });
            }
          }
          break;
        }

        case 'allow-all-ingress': {
          for (const np of netpols) {
            const ns = np.metadata?.namespace;
            if (SYS_NS.has(ns)) continue;
            if (nsFilter && ns !== nsFilter) continue;
            const spec = np.spec || {};
            const hasIngress = (spec.policyTypes || []).includes('Ingress') || spec.ingress !== undefined;
            if (hasIngress && Array.isArray(spec.ingress) && spec.ingress.some(r => !r.from || r.from.length === 0)) {
              viols.push({
                policy: policy.name, sev: policy.sev || 'HIGH',
                resource: np.metadata?.name, kind: 'NetworkPolicy',
                ns,
                detail: `NetworkPolicy "${np.metadata?.name}" allows all ingress (empty from rule)`,
                check: checkId, action: policy.action, _policyId: policy.id,
                _detectedAt: Date.now(),
        });
            }
          }
          break;
        }

        case 'allow-all-egress': {
          for (const np of netpols) {
            const ns = np.metadata?.namespace;
            if (SYS_NS.has(ns)) continue;
            if (nsFilter && ns !== nsFilter) continue;
            const spec = np.spec || {};
            const hasEgress = (spec.policyTypes || []).includes('Egress') || spec.egress !== undefined;
            if (hasEgress && Array.isArray(spec.egress) && spec.egress.some(r => !r.to || r.to.length === 0)) {
              viols.push({
                policy: policy.name, sev: policy.sev || 'MEDIUM',
                resource: np.metadata?.name, kind: 'NetworkPolicy',
                ns,
                detail: `NetworkPolicy "${np.metadata?.name}" allows all egress (empty to rule)`,
                check: checkId, action: policy.action, _policyId: policy.id,
                _detectedAt: Date.now(),
        });
            }
          }
          break;
        }

        case 'privileged-pod': {
          for (const pod of pods) {
            const ns = pod.metadata?.namespace;
            if (SYS_NS.has(ns)) continue;
            if (nsFilter && ns !== nsFilter) continue;
            const phase = pod.status?.phase;
            if (phase !== 'Running') continue;
            const spec = pod.spec || {};
            const allContainers = [...(spec.containers || []), ...(spec.initContainers || [])];
            const c = allContainers.find(c => c.securityContext?.privileged === true);
            if (c) {
              viols.push({
                policy: policy.name, sev: policy.sev || 'CRITICAL',
                resource: pod.metadata?.name, kind: 'Pod',
                ns,
                detail: `Container "${c.name}" has privileged: true`,
                check: checkId, action: policy.action, _policyId: policy.id,
                _detectedAt: Date.now(),
        });
            }
          }
          break;
        }

        case 'host-pid-pod': {
          for (const pod of pods) {
            const ns = pod.metadata?.namespace;
            if (SYS_NS.has(ns)) continue;
            if (nsFilter && ns !== nsFilter) continue;
            if (pod.status?.phase !== 'Running') continue;
            if (pod.spec?.hostPID) {
              viols.push({
                policy: policy.name, sev: policy.sev || 'CRITICAL',
                resource: pod.metadata?.name, kind: 'Pod',
                ns,
                detail: `Pod "${pod.metadata?.name}" uses hostPID — can see all host processes`,
                check: checkId, action: policy.action, _policyId: policy.id,
                _detectedAt: Date.now(),
        });
            }
          }
          break;
        }

        case 'host-network-pod': {
          for (const pod of pods) {
            const ns = pod.metadata?.namespace;
            if (SYS_NS.has(ns)) continue;
            if (nsFilter && ns !== nsFilter) continue;
            if (pod.status?.phase !== 'Running') continue;
            if (pod.spec?.hostNetwork) {
              viols.push({
                policy: policy.name, sev: policy.sev || 'HIGH',
                resource: pod.metadata?.name, kind: 'Pod',
                ns,
                detail: `Pod "${pod.metadata?.name}" shares host network stack`,
                check: checkId, action: policy.action, _policyId: policy.id,
                _detectedAt: Date.now(),
        });
            }
          }
          break;
        }

        case 'automount-sa-token': {
          for (const pod of pods) {
            const ns = pod.metadata?.namespace;
            if (SYS_NS.has(ns)) continue;
            if (nsFilter && ns !== nsFilter) continue;
            if (pod.status?.phase !== 'Running') continue;
            const auto = pod.spec?.automountServiceAccountToken;
            if (auto === true || auto === undefined) {
              const hasMounted = (pod.spec?.volumes || []).some(v => v.projected?.sources?.some(s => s.serviceAccountToken));
              if (hasMounted) {
                viols.push({
                  policy: policy.name, sev: policy.sev || 'MEDIUM',
                  resource: pod.metadata?.name, kind: 'Pod',
                  ns,
                  detail: `Pod "${pod.metadata?.name}" auto-mounts SA token (automountServiceAccountToken not false)`,
                  check: checkId, action: policy.action, _policyId: policy.id,
                  _detectedAt: Date.now(),
        });
              }
            }
          }
          break;
        }

        case 'secret-as-env': {
          for (const pod of pods) {
            const ns = pod.metadata?.namespace;
            if (SYS_NS.has(ns)) continue;
            if (nsFilter && ns !== nsFilter) continue;
            const allC = [...(pod.spec?.containers || []), ...(pod.spec?.initContainers || [])];
            for (const c of allC) {
              const secretEnv = (c.env || []).find(e => e.valueFrom?.secretKeyRef);
              if (secretEnv) {
                viols.push({
                  policy: policy.name, sev: policy.sev || 'HIGH',
                  resource: pod.metadata?.name, kind: 'Pod',
                  ns,
                  detail: `Container "${c.name}" exposes secret "${secretEnv.valueFrom.secretKeyRef.name}" as env var "${secretEnv.name}"`,
                  check: checkId, action: policy.action, _policyId: policy.id,
                  _detectedAt: Date.now(),
        });
                break;
              }
              const secretEnvFrom = (c.envFrom || []).find(e => e.secretRef);
              if (secretEnvFrom) {
                viols.push({
                  policy: policy.name, sev: policy.sev || 'HIGH',
                  resource: pod.metadata?.name, kind: 'Pod',
                  ns,
                  detail: `Container "${c.name}" exposes all keys from secret "${secretEnvFrom.secretRef.name}" as env vars`,
                  check: checkId, action: policy.action, _policyId: policy.id,
                  _detectedAt: Date.now(),
        });
                break;
              }
            }
          }
          break;
        }

        case 'mutating-webhook-all': {
          for (const mwh of mwhs) {
            for (const wh of mwh.webhooks || []) {
              const rules = wh.rules || [];
              const catchAll = rules.some(r =>
                (r.resources || []).includes('*') &&
                (r.apiGroups || []).includes('*')
              );
              if (catchAll) {
                viols.push({
                  policy: policy.name, sev: policy.sev || 'HIGH',
                  resource: wh.name, kind: 'MutatingWebhook',
                  ns: '(cluster)',
                  detail: `Webhook "${wh.name}" matches all apiGroups and resources — high blast radius`,
                  check: checkId, action: policy.action, _policyId: policy.id,
                  _detectedAt: Date.now(),
        });
              }
            }
          }
          break;
        }

        default: break;
      }
    }
  }
  return viols;
}
