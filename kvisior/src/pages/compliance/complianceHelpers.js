
const SYS_NS = new Set([
  'kube-system','kube-public','kube-node-lease',
  'openshift-compliance','openshift-operators','openshift-monitoring','openshift-ingress',
  'cert-manager','ingress-nginx','metallb-system','cattle-system','cattle-fleet-system',
  'dex','oauth2-proxy','external-secrets','vault','istio-system','linkerd',
  'monitoring','prometheus','grafana','logging','elastic-system',
  'argocd','flux-system','tekton-pipelines','jenkins',
]);

const appDeps = s => (s.snap?.deployments || []).filter(d => !SYS_NS.has(d.metadata?.namespace));

const appPods = s => (s.snap?.pods || []).filter(p => !SYS_NS.has(p.metadata?.namespace));

const appWorkloads = s => [
  ...(s.snap?.deployments   || []).filter(d => !SYS_NS.has(d.metadata?.namespace)),
  ...(s.snap?.daemon_sets   || []).filter(d => !SYS_NS.has(d.metadata?.namespace)),
  ...(s.snap?.stateful_sets || []).filter(d => !SYS_NS.has(d.metadata?.namespace)),
];

const wlContainers = w => w.spec?.template?.spec?.containers || [];
const wlPodSpec   = w => w.spec?.template?.spec || {};

const podContainers = p => p.spec?.containers || [];

const appNS = s => (s.snap?.namespaces || []).map(n => n.metadata?.name).filter(n => n && !SYS_NS.has(n));

export { SYS_NS, appDeps, appPods, appWorkloads, wlContainers, wlPodSpec, podContainers, appNS };
