import { StatusDot } from '../../components/ui';

export function FilterInput({ value, onChange }) {
  return (
    <input type="text" placeholder="Filter..." value={value} onChange={e => onChange(e.target.value)}
      style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 7,
        padding: '5px 10px', fontSize: 12, color: 'var(--text-primary)', outline: 'none', fontFamily: 'DM Sans,sans-serif' }} />
  );
}

export function KindBadge({ kind }) {
  const colors = {
    Deployment:         ['rgba(0,200,255,.08)',  'var(--accent)'],
    StatefulSet:        ['rgba(124,58,237,.12)', '#a78bfa'],
    DaemonSet:          ['rgba(16,185,129,.1)',  'var(--accent-3)'],
    ClusterRole:        ['rgba(124,58,237,.12)', '#a78bfa'],
    Role:               ['rgba(0,200,255,.08)',  'var(--accent)'],
    ClusterRoleBinding: ['rgba(239,68,68,.1)',   'var(--danger)'],
    RoleBinding:        ['rgba(251,146,60,.1)',  'var(--warning)'],
  };
  const [bg, col] = colors[kind] || ['rgba(0,200,255,.08)', 'var(--accent)'];
  return <span style={{ fontSize: 11, padding: '2px 7px', borderRadius: 4, background: bg, color: col }}>{kind}</span>;
}

export function EmptyRow({ cols, msg, sensorOnline }) {
  return (
    <tr>
      <td colSpan={cols} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40, fontSize: 13 }}>
        {sensorOnline === false ? '⚠ Sensor offline — no data' : msg}
      </td>
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
