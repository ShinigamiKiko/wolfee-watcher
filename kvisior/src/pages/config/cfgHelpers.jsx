import { SearchInput, KindBadge } from '../../components/kit';
import { Icon } from '../../components/Icon';

export { KindBadge };

export function FilterInput({ value, onChange }) {
  return <SearchInput size="sm" value={value} onChange={onChange} placeholder="Filter…" />;
}

export function EmptyRow({ cols, msg, sensorOnline }) {
  return (
    <tr className="empty-row">
      <td colSpan={cols}>{sensorOnline === false ? <span className="ic-label"><Icon name="alert" /> Sensor offline — no data</span> : msg}</td>
    </tr>
  );
}

export function nodeRole(node) {
  const labels = node.metadata?.labels || {};
  if ('node-role.kubernetes.io/control-plane' in labels) return 'control-plane';
  if ('node-role.kubernetes.io/master'         in labels) return 'master';
  return 'worker';
}

export function nodeReady(node) {
  const c = (node.status?.conditions || []).find(c => c.type === 'Ready');
  return c?.status === 'True' ? { type: 'active', label: 'Ready' } : { type: 'error', label: 'NotReady' };
}

export function workloadReady(w) {
  if (w._kind === 'DaemonSet') return `${w.status?.numberReady || 0}/${w.status?.desiredNumberScheduled || 0}`;
  return `${w.status?.readyReplicas || 0}/${w.spec?.replicas || '—'}`;
}

export function workloadImages(w) {
  return (w.spec?.template?.spec?.containers || []).map(c => c.image).filter(Boolean);
}

export function bindingsFor(name, kind, ns, allBindings) {
  if (kind === 'role') return allBindings.filter(b => b.roleRef?.name === name);
  if (kind === 'sa')   return allBindings.filter(b => (b.subjects || []).some(s => s.kind === 'ServiceAccount' && s.name === name && s.namespace === ns));
  return [];
}

export const SYS_NS    = new Set(['kube-system', 'kube-public', 'kube-node-lease', 'cert-manager', 'metallb-system', 'calico-system', 'calico-apiserver', 'cilium', 'ingress-nginx']);
export const SYS_NAMES = ['system:', 'kubeadm:', 'kindnet', 'local-path', 'cilium', 'calico', 'cert-manager', 'metrics-server'];
