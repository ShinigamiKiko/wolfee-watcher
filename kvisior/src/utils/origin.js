const present = x => x != null && x !== '' && x !== '—';

export const containerIdOf = v => v?.containerId || v?.container_id || v?._raw?.containerId || '';

export function originOf(v) {
  if (!v || present(v.pod) || present(v._raw?.pod)) return null;
  const id = containerIdOf(v);
  if (id) {
    return {
      kind: 'container',
      label: 'Outside Kubernetes',
      title: 'Container outside Kubernetes',
      shortId: id.slice(0, 12),
      hint: 'A container started directly on the node by podman, docker or containerd, not by Kubernetes, so it has no pod or namespace. Commands such as podman exec into it also show up here.',
    };
  }
  return {
    kind: 'host',
    label: 'Host process',
    title: 'Host process',
    shortId: '',
    hint: 'The process ran on the node itself, outside any container, so it has no pod or namespace.',
  };
}
