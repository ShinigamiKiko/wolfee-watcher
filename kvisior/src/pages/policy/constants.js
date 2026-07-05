const BUILD_CHECKS = [
  { id: 'no-latest',      label: 'Disallow :latest tag',          desc: 'Images must use explicit version tags',           sev: 'HIGH'     },
  { id: 'no-debug',       label: 'No debug/dev images',           desc: 'Debug images must not reach production',          sev: 'HIGH'     },
  { id: 'must-user',      label: 'Require non-root USER',         desc: 'Image must declare USER != root',                 sev: 'CRITICAL' },
  { id: 'must-label',     label: 'Require source label',          desc: 'org.opencontainers.image.source required',        sev: 'MEDIUM'   },
  { id: 'no-shell',       label: 'No shell in production image',  desc: 'Disallow bash/sh in image layers',                sev: 'MEDIUM'   },
  { id: 'no-package-mgr', label: 'No package managers (apt/yum)', desc: 'Disallow apt/yum in final image',                 sev: 'MEDIUM'   },
  { id: 'immutable-tag',  label: 'Require digest pinning',        desc: 'Image ref must include @sha256:...',              sev: 'HIGH'     },
];

export const DEPLOY_CHECKS = [
  { id: 'no-privileged',          cis: '5.2.1',  label: 'No privileged containers',          desc: 'containers[].securityContext.privileged must not be true',              sev: 'CRITICAL', group: 'Privilege'  },
  { id: 'no-host-pid',            cis: '5.2.2',  label: 'No hostPID',                        desc: 'spec.hostPID must be false',                                            sev: 'CRITICAL', group: 'Privilege'  },
  { id: 'no-host-ipc',            cis: '5.2.3',  label: 'No hostIPC',                        desc: 'spec.hostIPC must be false',                                            sev: 'HIGH',     group: 'Privilege'  },
  { id: 'no-host-net',            cis: '5.2.4',  label: 'No hostNetwork',                    desc: 'spec.hostNetwork must be false',                                        sev: 'HIGH',     group: 'Privilege'  },
  { id: 'no-priv-esc',            cis: '5.2.5',  label: 'Disallow privilege escalation',     desc: 'allowPrivilegeEscalation: false required',                              sev: 'HIGH',     group: 'Privilege'  },
  { id: 'no-root',                cis: '5.2.6',  label: 'Run as non-root',                   desc: 'runAsNonRoot: true or runAsUser > 0',                                   sev: 'HIGH',     group: 'Privilege'  },
  { id: 'no-root-group',          cis: '5.2.7',  label: 'Non-root supplemental groups',      desc: 'supplementalGroups / fsGroup must not include GID 0',                  sev: 'MEDIUM',   group: 'Privilege'  },
  { id: 'drop-net-raw',           cis: '5.2.8',  label: 'Drop NET_RAW capability',           desc: 'capabilities.drop must include NET_RAW or ALL',                        sev: 'HIGH',     group: 'Privilege'  },
  { id: 'drop-all-caps',          cis: '5.2.9',  label: 'Drop all capabilities',             desc: 'capabilities.drop: [ALL] — only add back what is needed',              sev: 'HIGH',     group: 'Privilege'  },
  { id: 'no-seccomp-unconfined',  cis: '5.2.10', label: 'Seccomp not Unconfined',            desc: 'securityContext.seccompProfile must not be Unconfined',                 sev: 'HIGH',     group: 'Privilege'  },
  { id: 'no-apparmor-unconfined', cis: '5.2.11', label: 'AppArmor not Unconfined',           desc: 'container.apparmor annotation must not be unconfined',                 sev: 'MEDIUM',   group: 'Privilege'  },
  { id: 'readonly-root',          cis: '5.3.1',  label: 'Read-only root filesystem',         desc: 'readOnlyRootFilesystem: true required',                                 sev: 'MEDIUM',   group: 'Filesystem' },
  { id: 'no-host-path',           cis: '5.3.2',  label: 'No hostPath volumes',               desc: 'volumes must not use hostPath mounts',                                  sev: 'HIGH',     group: 'Filesystem' },
  { id: 'no-host-path-write',     cis: '5.3.3',  label: 'No writable hostPath mounts',       desc: 'hostPath volumes must be mounted readOnly: true',                       sev: 'HIGH',     group: 'Filesystem' },
  { id: 'resource-limits',        cis: '5.5.1',  label: 'CPU & memory limits set',           desc: 'resources.limits.cpu and resources.limits.memory must be set',          sev: 'MEDIUM',   group: 'Resources'  },
  { id: 'resource-requests',      cis: '5.5.2',  label: 'CPU & memory requests set',         desc: 'resources.requests.cpu and resources.requests.memory must be set',      sev: 'LOW',      group: 'Resources'  },
  { id: 'no-latest-tag',          cis: '5.6.1',  label: 'No :latest image tag',              desc: 'Image refs must use explicit version tags, not :latest',                sev: 'HIGH',     group: 'Images'     },
  { id: 'no-default-sa',          cis: '5.1.6',  label: 'No automounted default SA token',   desc: 'automountServiceAccountToken: false when using default ServiceAccount', sev: 'MEDIUM',   group: 'RBAC'       },
];

export const DEPLOY_GROUPS = ['Privilege', 'Filesystem', 'Network', 'Resources', 'Images', 'RBAC', 'Workloads'];

export const AUDIT_CHECKS = [

  { id: 'exec-pod',         group: 'Pod Access',    label: 'Exec into pod',          desc: 'kubectl exec used to get a shell inside a running pod',                     kind: 'exec' },
  { id: 'attach-pod',       group: 'Pod Access',    label: 'Attach to pod',          desc: 'kubectl attach used to connect to a running container',                     kind: 'attach' },
  { id: 'portforward-pod',  group: 'Pod Access',    label: 'Port-forward to pod',    desc: 'kubectl port-forward opened a tunnel to a pod port',                        kind: 'portforward' },

  { id: 'pod-create',        group: 'Workloads',    label: 'Pod created',            desc: 'A pod was created directly (not via Deployment) — could be a backdoor',     kind: 'create', resource: 'pods' },
  { id: 'pod-delete',        group: 'Workloads',    label: 'Pod deleted',            desc: 'A pod was deleted — watch for --force deletes hiding evidence',             kind: 'delete', resource: 'pods' },
  { id: 'deploy-create',     group: 'Workloads',    label: 'Deployment created',     desc: 'A new Deployment was created',                                              kind: 'create', resource: 'deployments' },
  { id: 'deploy-update',     group: 'Workloads',    label: 'Deployment updated',     desc: 'A Deployment spec was modified — could inject malicious containers',        kind: 'update', resource: 'deployments' },
  { id: 'daemonset-create',  group: 'Workloads',    label: 'DaemonSet created',      desc: 'A new DaemonSet was created — runs on every node',                         kind: 'create', resource: 'daemonsets' },
  { id: 'daemonset-update',  group: 'Workloads',    label: 'DaemonSet updated',      desc: 'A DaemonSet was modified',                                                  kind: 'update', resource: 'daemonsets' },
  { id: 'job-create',        group: 'Workloads',    label: 'Job created',            desc: 'A Job was created — could be used for lateral movement or data exfil',     kind: 'create', resource: 'jobs' },
  { id: 'cronjob-create',    group: 'Workloads',    label: 'CronJob created',        desc: 'A CronJob was created — persistent scheduled execution',                   kind: 'create', resource: 'cronjobs' },

  { id: 'secret-create',    group: 'Secrets',       label: 'Secret created',         desc: 'A new Secret was created — watch for unexpected secrets in sensitive NS',  kind: 'create', resource: 'secrets' },
  { id: 'secret-delete',    group: 'Secrets',       label: 'Secret deleted',         desc: 'A Secret was deleted — potential evidence cleanup',                        kind: 'delete', resource: 'secrets' },
  { id: 'configmap-update', group: 'Secrets',       label: 'ConfigMap updated',      desc: 'A ConfigMap was modified — could inject malicious config into workloads',  kind: 'update', resource: 'configmaps' },

  { id: 'role-create',      group: 'RBAC',          label: 'Role created',           desc: 'A new Role or ClusterRole was created',                                    kind: 'create', resource: 'roles' },
  { id: 'clusterrole-create', group: 'RBAC',        label: 'ClusterRole created',    desc: 'A new ClusterRole was created — cluster-wide permissions',                 kind: 'create', resource: 'clusterroles' },
  { id: 'rolebinding-create', group: 'RBAC',        label: 'RoleBinding created',    desc: 'A new RoleBinding was created — watch for binding to sensitive roles',     kind: 'create', resource: 'rolebindings' },
  { id: 'rolebinding-delete', group: 'RBAC',        label: 'RoleBinding deleted',    desc: 'A RoleBinding was removed',                                                kind: 'delete', resource: 'rolebindings' },
  { id: 'crb-create',       group: 'RBAC',          label: 'ClusterRoleBinding created', desc: 'A new ClusterRoleBinding was created — cluster-wide access grant',     kind: 'create', resource: 'clusterrolebindings' },
  { id: 'crb-delete',       group: 'RBAC',          label: 'ClusterRoleBinding deleted', desc: 'A ClusterRoleBinding was removed',                                     kind: 'delete', resource: 'clusterrolebindings' },

  { id: 'mwh-create',       group: 'Admission',     label: 'MutatingWebhook created',   desc: 'A new MutatingWebhookConfiguration was registered — can rewrite any resource', kind: 'create', resource: 'mutatingwebhookconfigurations' },
  { id: 'mwh-delete',       group: 'Admission',     label: 'MutatingWebhook deleted',   desc: 'A MutatingWebhookConfiguration was removed',                           kind: 'delete', resource: 'mutatingwebhookconfigurations' },
  { id: 'vwh-create',       group: 'Admission',     label: 'ValidatingWebhook created', desc: 'A new ValidatingWebhookConfiguration was registered',                  kind: 'create', resource: 'validatingwebhookconfigurations' },

  { id: 'ns-create',        group: 'Infrastructure', label: 'Namespace created',      desc: 'A new namespace was created — watch for unexpected namespaces',           kind: 'create', resource: 'namespaces' },
  { id: 'ns-delete',        group: 'Infrastructure', label: 'Namespace deleted',      desc: 'A namespace was deleted',                                                 kind: 'delete', resource: 'namespaces' },
  { id: 'node-create',      group: 'Infrastructure', label: 'Node joined cluster',    desc: 'A new node registered in the cluster',                                    kind: 'create', resource: 'nodes' },
  { id: 'sa-create',        group: 'Infrastructure', label: 'ServiceAccount created', desc: 'A ServiceAccount was created — watch for unexpected SAs in sensitive NS', kind: 'create', resource: 'serviceaccounts' },
  { id: 'sa-delete',        group: 'Infrastructure', label: 'ServiceAccount deleted', desc: 'A ServiceAccount was deleted',                                            kind: 'delete', resource: 'serviceaccounts' },
];

export const AUDIT_GROUPS = ['Pod Access', 'Workloads', 'Secrets', 'RBAC', 'Admission', 'Infrastructure'];
